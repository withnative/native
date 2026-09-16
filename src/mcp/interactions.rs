//! Involuntary read-log capture at the registry choke point (fbfaf25 §4).
//!
//! The important property of this module is not that it can find ids in JSON.
//! It is that every shipped tool has an explicit arm in [`extract`].  A tool is
//! registered with [`ToolKind`], not a string, and the match below has no
//! wildcard.  Adding another shipped tool therefore requires deciding what its
//! result means before the crate compiles.
//!
//! Capture is deliberately fail-open.  Extraction is pure and defensive; a
//! failed or dropped capture write is counted on the handle's background
//! stats and reported to stderr, never raised to the caller.
//! The handler result is never changed by this module.

use std::collections::HashSet;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{SecondsFormat, Utc};
use std::collections::BTreeMap;

use futures::FutureExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, Notify};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::instructions::MAX_BOOTSTRAP_PENDING_OBLIGATIONS;

use super::registry::{attach_run_context, Caller};

/// Every tool shipped by native-ce: two seam builtins plus the v1 surface.
/// Names are derived from this enum, so a registration cannot pair a
/// tool's handler with another tool's extraction policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ToolKind {
    Ping,
    EngineInfo,
    StandbyStatus,
    Bootstrap,
    Quickstart,
    ReadGuide,
    SetIntent,
    CloseRun,
    GetStructure,
    GetDashboard,
    DescribeSchema,
    PreviewRecordShape,
    CreateRecord,
    CreateMany,
    CreateExploration,
    GetEventContext,
    GetRecord,
    ResolveMany,
    UpdateRecord,
    ClaimUnownedRecord,
    CorrectRecordType,
    DeleteRecord,
    ArchiveRecord,
    RenderRecord,
    GetHistory,
    WhatsChanged,
    ManageBindings,
    ManageRecordPolicy,
    ResolveExternal,
    ObserveExternal,
    GetRunActivity,
    RenderRecordVersionDiff,
    ManageLinks,
    ManageRelationships,
    ManageMessages,
    ManageInterventions,
    InstantiateArtifact,
    ManageRendererBinding,
    ManageMdxModules,
    ManageArtifactInputs,
    ManageArtifactModuleGrants,
    RenderArtifact,
    VerifyArtifact,
    InvokeArtifactInteraction,
    OpenCollection,
    ManageFacetObservations,
    ResolveFacets,
    SuggestFacetValues,
    QueryRecord,
    ResolveRollup,
    Search,
    QuerySql,
    Scan,
    ManageVocabularies,
    ManageSchemaConfig,
    AttachText,
    AttachFromUrl,
    ReadAttachment,
    ManageAttachments,
    StartWork,
    ResolveSuggestions,
    RenderSuggestionReview,
    ExportSnapshot,
    ResolveCitation,
    ManageCitations,
    CreateAttribution,
    ReadAttributions,
    ManageAttributions,
    ManageInstructions,
    ManageOnboarding,
    ManageMemberships,
    ManageChangeSummaries,
    QueryChangeSummaries,
    ReadCanvas,
    ManageCanvas,
    ReachRead,
    ReachConnect,
}

/// Whether one registered operation is observational or mutating.
///
/// This is deliberately separate from discovery exposure and authorization.
/// The exhaustive [`ToolKind`] match makes every new production tool choose a
/// disposition before it can compile, while mixed tools are admitted
/// only for their explicitly observational selector values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthoritativeDisposition {
    Read,
    Mutation,
    Actions(&'static [&'static str]),
}

impl AuthoritativeDisposition {
    pub fn admits(self, arguments: &Value) -> bool {
        match self {
            Self::Read => true,
            Self::Mutation => false,
            Self::Actions(actions) => arguments
                .get("action")
                .and_then(Value::as_str)
                .is_some_and(|action| actions.contains(&action)),
        }
    }

    pub const fn has_read_operation(self) -> bool {
        !matches!(self, Self::Mutation)
    }

    pub const fn actions(self) -> Option<&'static [&'static str]> {
        match self {
            Self::Actions(actions) => Some(actions),
            Self::Read | Self::Mutation => None,
        }
    }
}

/// Which registered tools MCP discovery advertises.
///
/// This is an exposure choice, never an authorization gate: dispatch still
/// resolves names against the complete registry for the current transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExposureProfile {
    Focused,
    #[default]
    Complete,
}

impl ExposureProfile {
    pub const ALL: [Self; 2] = [Self::Focused, Self::Complete];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Focused => "focused",
            Self::Complete => "complete",
        }
    }

    pub const fn max_descriptor_bytes(self) -> usize {
        match self {
            Self::Focused => super::registry::FOCUSED_PROFILE_MAX_BYTES,
            Self::Complete => super::registry::COMPLETE_PROFILE_MAX_BYTES,
        }
    }
}

impl std::fmt::Display for ExposureProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ExposureProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim() {
            "focused" => Ok(Self::Focused),
            "complete" => Ok(Self::Complete),
            _ => Err("expected `focused` or `complete`"),
        }
    }
}

/// Stable grouping used by generated capability docs and the later hide-only
/// family preference. Families describe discovery; they grant nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolFamily {
    System,
    Records,
    History,
    Identity,
    Coordination,
    Messaging,
    Artifacts,
    Facets,
    Query,
    Schema,
    Attachments,
    Work,
    Suggestions,
    Export,
    Citations,
    Guidance,
    Extension,
}

impl ToolFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Records => "records",
            Self::History => "history",
            Self::Identity => "identity",
            Self::Coordination => "coordination",
            Self::Messaging => "messaging",
            Self::Artifacts => "artifacts",
            Self::Facets => "facets",
            Self::Query => "query",
            Self::Schema => "schema",
            Self::Attachments => "attachments",
            Self::Work => "work",
            Self::Suggestions => "suggestions",
            Self::Export => "export",
            Self::Citations => "citations",
            Self::Guidance => "guidance",
            Self::Extension => "extension",
        }
    }
}

/// A user-scoped discovery override. This changes advertisement only; it is
/// never consulted by dispatch or authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VisibilityOverride {
    Show,
    Hide,
}

impl VisibilityOverride {
    pub const fn is_shown(self) -> bool {
        matches!(self, Self::Show)
    }
}

/// Fully resolved discovery policy for one request.
///
/// String keys are intentional: catalog rows for removed tools and families
/// remain inert historical preferences instead of becoming a compatibility
/// manifest the registry must retain forever.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedToolExposure {
    pub base_profile: ExposureProfile,
    pub family_overrides: BTreeMap<String, VisibilityOverride>,
    pub tool_overrides: BTreeMap<String, VisibilityOverride>,
}

impl ResolvedToolExposure {
    pub fn new(base_profile: ExposureProfile) -> Self {
        Self {
            base_profile,
            family_overrides: BTreeMap::new(),
            tool_overrides: BTreeMap::new(),
        }
    }

    pub fn is_customized(&self) -> bool {
        !self.family_overrides.is_empty() || !self.tool_overrides.is_empty()
    }

    pub fn shows(&self, name: &str, exposure: ToolExposure) -> bool {
        if exposure.always_visible {
            return true;
        }
        let family = exposure.family.as_str();
        let family_visibility = self
            .family_overrides
            .get(family)
            .copied()
            .map(VisibilityOverride::is_shown);
        self.tool_overrides
            .get(name)
            .copied()
            .map(VisibilityOverride::is_shown)
            .or(family_visibility)
            .unwrap_or_else(|| exposure.shown_in(self.base_profile))
    }
}

/// The first-principles reason a tool deserves a model-visible door.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionReason {
    Atomicity,
    CorrectnessUnderIgnorance,
    BoundedContextOrCalls,
    Discoverability,
}

impl AdmissionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Atomicity => "atomicity",
            Self::CorrectnessUnderIgnorance => "correctness-under-ignorance",
            Self::BoundedContextOrCalls => "bounded-context-or-calls",
            Self::Discoverability => "discoverability",
        }
    }
}

/// Exhaustive discovery classification attached to one registered tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolExposure {
    pub family: ToolFamily,
    pub focused: bool,
    pub admission_reason: AdmissionReason,
    pub always_visible: bool,
}

impl ToolExposure {
    pub const fn new(family: ToolFamily, focused: bool, admission_reason: AdmissionReason) -> Self {
        Self {
            family,
            focused,
            admission_reason,
            always_visible: false,
        }
    }

    pub const fn always_visible(mut self) -> Self {
        self.always_visible = true;
        self
    }

    pub const fn shown_in(self, profile: ExposureProfile) -> bool {
        match profile {
            ExposureProfile::Focused => self.focused,
            ExposureProfile::Complete => true,
        }
    }

    /// Explicit classification for embedding-only synthetic tools.
    pub const fn extension(focused: bool) -> Self {
        Self::new(
            ToolFamily::Extension,
            focused,
            AdmissionReason::Discoverability,
        )
    }
}

/// Coarse production authorization contract attached to every shipped tool.
/// Specialized means the handler has multiple or bearer-derived gates whose
/// exact threshold is documented and behavior-tested separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDisposition {
    NoRecord,
    CallerFilteredRead,
    RecordView,
    RecordEdit,
    RecordManage,
    HostOwner,
    Specialized,
}

impl ToolKind {
    pub const ALL: [ToolKind; 77] = [
        ToolKind::Ping,
        ToolKind::EngineInfo,
        ToolKind::StandbyStatus,
        ToolKind::Bootstrap,
        ToolKind::Quickstart,
        ToolKind::ReadGuide,
        ToolKind::SetIntent,
        ToolKind::CloseRun,
        ToolKind::GetStructure,
        ToolKind::GetDashboard,
        ToolKind::DescribeSchema,
        ToolKind::CreateRecord,
        ToolKind::CreateMany,
        ToolKind::CreateExploration,
        ToolKind::GetEventContext,
        ToolKind::GetRecord,
        ToolKind::ResolveMany,
        ToolKind::UpdateRecord,
        ToolKind::ClaimUnownedRecord,
        ToolKind::CorrectRecordType,
        ToolKind::DeleteRecord,
        ToolKind::ArchiveRecord,
        ToolKind::RenderRecord,
        ToolKind::GetHistory,
        ToolKind::WhatsChanged,
        ToolKind::ManageBindings,
        ToolKind::ManageRecordPolicy,
        ToolKind::ResolveExternal,
        ToolKind::ObserveExternal,
        ToolKind::GetRunActivity,
        ToolKind::RenderRecordVersionDiff,
        ToolKind::ManageLinks,
        ToolKind::ManageRelationships,
        ToolKind::ManageMessages,
        ToolKind::ManageInterventions,
        ToolKind::InstantiateArtifact,
        ToolKind::ManageRendererBinding,
        ToolKind::ManageMdxModules,
        ToolKind::ManageArtifactInputs,
        ToolKind::ManageArtifactModuleGrants,
        ToolKind::RenderArtifact,
        ToolKind::VerifyArtifact,
        ToolKind::InvokeArtifactInteraction,
        ToolKind::OpenCollection,
        ToolKind::ManageFacetObservations,
        ToolKind::ResolveFacets,
        ToolKind::SuggestFacetValues,
        ToolKind::QueryRecord,
        ToolKind::ResolveRollup,
        ToolKind::Search,
        ToolKind::QuerySql,
        ToolKind::Scan,
        ToolKind::ManageVocabularies,
        ToolKind::ManageSchemaConfig,
        ToolKind::AttachText,
        ToolKind::AttachFromUrl,
        ToolKind::ReadAttachment,
        ToolKind::ManageAttachments,
        ToolKind::StartWork,
        ToolKind::ResolveSuggestions,
        ToolKind::RenderSuggestionReview,
        ToolKind::ExportSnapshot,
        ToolKind::ResolveCitation,
        ToolKind::ManageCitations,
        ToolKind::CreateAttribution,
        ToolKind::ReadAttributions,
        ToolKind::ManageAttributions,
        ToolKind::ManageInstructions,
        ToolKind::ManageOnboarding,
        ToolKind::ManageMemberships,
        ToolKind::ManageChangeSummaries,
        ToolKind::QueryChangeSummaries,
        ToolKind::PreviewRecordShape,
        ToolKind::ReadCanvas,
        ToolKind::ManageCanvas,
        ToolKind::ReachRead,
        ToolKind::ReachConnect,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            ToolKind::Ping => "ping",
            ToolKind::EngineInfo => "engine_info",
            ToolKind::StandbyStatus => "standby_status",
            ToolKind::Bootstrap => "bootstrap",
            ToolKind::Quickstart => "quickstart",
            ToolKind::ReadGuide => "read_guide",
            ToolKind::SetIntent => "set_intent",
            ToolKind::CloseRun => "close_run",
            ToolKind::GetStructure => "get_structure",
            ToolKind::GetDashboard => "get_dashboard",
            ToolKind::DescribeSchema => "describe_schema",
            ToolKind::PreviewRecordShape => "preview_record_shape",
            ToolKind::CreateRecord => "create_record",
            ToolKind::CreateMany => "create_many",
            ToolKind::CreateExploration => "create_exploration",
            ToolKind::GetEventContext => "get_event_context",
            ToolKind::GetRecord => "get_record",
            ToolKind::ResolveMany => "resolve_many",
            ToolKind::UpdateRecord => "update_record",
            ToolKind::ClaimUnownedRecord => "claim_unowned_record",
            ToolKind::CorrectRecordType => "correct_record_type",
            ToolKind::DeleteRecord => "delete_record",
            ToolKind::ArchiveRecord => "archive_record",
            ToolKind::RenderRecord => "render_record",
            ToolKind::GetHistory => "get_history",
            ToolKind::WhatsChanged => "whats_changed",
            ToolKind::ManageBindings => "manage_bindings",
            ToolKind::ManageRecordPolicy => "manage_record_policy",
            ToolKind::ResolveExternal => "resolve_external",
            ToolKind::ObserveExternal => "observe_external",
            ToolKind::GetRunActivity => "get_run_activity",
            ToolKind::RenderRecordVersionDiff => "render_record_version_diff",
            ToolKind::ManageLinks => "manage_links",
            ToolKind::ManageRelationships => "manage_relationships",
            ToolKind::ManageMessages => "manage_messages",
            ToolKind::ManageInterventions => "manage_interventions",
            ToolKind::InstantiateArtifact => "instantiate_artifact",
            ToolKind::ManageRendererBinding => "manage_renderer_binding",
            ToolKind::ManageMdxModules => "manage_mdx_modules",
            ToolKind::ManageArtifactInputs => "manage_artifact_inputs",
            ToolKind::ManageArtifactModuleGrants => "manage_artifact_module_grants",
            ToolKind::RenderArtifact => "render_artifact",
            ToolKind::VerifyArtifact => "verify_artifact",
            ToolKind::InvokeArtifactInteraction => "invoke_artifact_interaction",
            ToolKind::OpenCollection => "open_collection",
            ToolKind::ManageFacetObservations => "manage_facet_observations",
            ToolKind::ResolveFacets => "resolve_facets",
            ToolKind::SuggestFacetValues => "suggest_facet_values",
            ToolKind::QueryRecord => "query_record",
            ToolKind::ResolveRollup => "resolve_rollup",
            ToolKind::Search => "search",
            ToolKind::QuerySql => "query_sql",
            ToolKind::Scan => "scan",
            ToolKind::ManageVocabularies => "manage_vocabularies",
            ToolKind::ManageSchemaConfig => "manage_schema_config",
            ToolKind::AttachText => "attach_text",
            ToolKind::AttachFromUrl => "attach_from_url",
            ToolKind::ReadAttachment => "read_attachment",
            ToolKind::ManageAttachments => "manage_attachments",
            ToolKind::ResolveSuggestions => "resolve_suggestions",
            ToolKind::RenderSuggestionReview => "render_suggestion_review",
            ToolKind::StartWork => "start_work",
            ToolKind::ExportSnapshot => "export_snapshot",
            ToolKind::ResolveCitation => "resolve_citation",
            ToolKind::ManageCitations => "manage_citations",
            ToolKind::CreateAttribution => "create_attribution",
            ToolKind::ReadAttributions => "read_attributions",
            ToolKind::ManageAttributions => "manage_attributions",
            ToolKind::ManageInstructions => "manage_instructions",
            ToolKind::ManageOnboarding => "manage_onboarding",
            ToolKind::ManageMemberships => "manage_memberships",
            ToolKind::ManageChangeSummaries => "manage_change_summaries",
            ToolKind::QueryChangeSummaries => "query_change_summaries",
            ToolKind::ReadCanvas => "read_canvas",
            ToolKind::ManageCanvas => "manage_canvas",
            ToolKind::ReachRead => "reach_read",
            ToolKind::ReachConnect => "reach_connect",
        }
    }

    /// Tools that issue the canonical run key in their own response payload.
    pub const fn issues_run_key(self) -> bool {
        matches!(self, Self::Bootstrap)
    }

    /// Tools that may be called before Bootstrap has issued a run key.
    pub const fn callable_without_run_key(self) -> bool {
        matches!(self, Self::Bootstrap | Self::Quickstart)
    }

    /// First-contact tools own or deliberately omit session context instead of
    /// receiving the universal cross-cutting response echo.
    pub const fn omits_run_context_echo(self) -> bool {
        matches!(self, Self::Bootstrap | Self::Quickstart)
    }

    /// QuickStart is a static launcher and does not participate in universal
    /// run-context argument injection, resolution, stripping, or echoing.
    pub const fn ignores_run_context_arguments(self) -> bool {
        matches!(self, Self::Quickstart)
    }

    /// Fail-closed read/write classification for every shipped operation.
    pub const fn authoritative_disposition(self) -> AuthoritativeDisposition {
        use AuthoritativeDisposition::{Actions, Mutation, Read};
        match self {
            Self::Ping
            | Self::EngineInfo
            | Self::StandbyStatus
            | Self::Bootstrap
            | Self::ReadGuide
            | Self::GetStructure
            | Self::GetDashboard
            | Self::DescribeSchema
            | Self::PreviewRecordShape
            | Self::GetEventContext
            | Self::GetRecord
            | Self::ResolveMany
            | Self::RenderRecord
            | Self::GetHistory
            | Self::WhatsChanged
            | Self::GetRunActivity
            | Self::RenderRecordVersionDiff
            | Self::RenderArtifact
            | Self::VerifyArtifact
            | Self::OpenCollection
            | Self::ResolveFacets
            | Self::SuggestFacetValues
            | Self::QueryRecord
            | Self::ResolveRollup
            | Self::Search
            | Self::QuerySql
            | Self::Scan
            | Self::ReadAttachment
            | Self::RenderSuggestionReview
            | Self::ResolveCitation
            | Self::ReadCanvas
            | Self::ReadAttributions
            | Self::ReachRead => Read,
            Self::ManageBindings => Actions(&["list", "observations"]),
            Self::ManageRecordPolicy => Actions(&["inspect", "list"]),
            Self::ManageLinks => Actions(&["list"]),
            Self::ManageRelationships => Actions(&["read", "why", "find"]),
            Self::ManageMessages => Actions(&[
                "list_context",
                "list_message_state",
                "list_conversation",
                "list_unclassified",
                "list_my_conversations",
                "list_destinations",
                "list_inbox",
                "list_notification_candidates",
                "get_attention",
            ]),
            Self::ManageInterventions => Actions(&["get", "query"]),
            Self::ManageRendererBinding
            | Self::ManageArtifactInputs
            | Self::ManageArtifactModuleGrants => Actions(&["read"]),
            Self::ManageMdxModules => Actions(&["inspect", "impact"]),
            Self::ManageFacetObservations => Actions(&["list"]),
            Self::ManageVocabularies => Actions(&["list_values"]),
            Self::ManageSchemaConfig => Actions(&["read"]),
            Self::ManageAttachments => Actions(&["list", "inspect"]),
            Self::StartWork => Actions(&["preview"]),
            Self::ManageInstructions => Actions(&["list", "compare_seeded_default"]),
            Self::ManageOnboarding => Actions(&["list_programmes", "preview_generation"]),
            Self::ManageMemberships => {
                Actions(&["list", "invitations_list", "invitations_inspect"])
            }
            Self::ManageChangeSummaries => Actions(&["inspect"]),
            Self::QueryChangeSummaries => Actions(&["list", "get", "drill"]),
            Self::SetIntent
            | Self::Quickstart
            | Self::CloseRun
            | Self::CreateRecord
            | Self::CreateMany
            | Self::CreateExploration
            | Self::UpdateRecord
            | Self::ClaimUnownedRecord
            | Self::CorrectRecordType
            | Self::DeleteRecord
            | Self::ArchiveRecord
            | Self::ResolveExternal
            | Self::ObserveExternal
            | Self::InstantiateArtifact
            | Self::InvokeArtifactInteraction
            | Self::AttachText
            | Self::AttachFromUrl
            | Self::ResolveSuggestions
            | Self::ExportSnapshot
            | Self::ManageCitations
            | Self::CreateAttribution
            | Self::ManageCanvas
            | Self::ManageAttributions
            | Self::ReachConnect => Mutation,
        }
    }

    /// Compatibility spelling for the immutable-standby consumer.
    pub const fn standby_disposition(self) -> AuthoritativeDisposition {
        self.authoritative_disposition()
    }

    /// Complete exposure metadata for every production capability.
    ///
    /// Keeping this as an exhaustive match means adding a `ToolKind` cannot
    /// compile until its family, focused membership and admission reason have
    /// all been decided.
    pub const fn exposure(self) -> ToolExposure {
        use AdmissionReason::*;
        use ToolFamily::*;
        match self {
            ToolKind::Ping => ToolExposure::new(System, false, Discoverability),
            ToolKind::EngineInfo => ToolExposure::new(System, false, Discoverability),
            ToolKind::StandbyStatus => ToolExposure::new(System, false, Discoverability),
            ToolKind::Bootstrap => {
                ToolExposure::new(System, true, Discoverability).always_visible()
            }
            ToolKind::Quickstart => ToolExposure::new(Guidance, false, CorrectnessUnderIgnorance),
            ToolKind::ReadGuide => {
                ToolExposure::new(Guidance, true, CorrectnessUnderIgnorance).always_visible()
            }
            ToolKind::SetIntent => ToolExposure::new(Coordination, true, CorrectnessUnderIgnorance),
            ToolKind::CloseRun => ToolExposure::new(Coordination, false, Atomicity),
            ToolKind::GetStructure => ToolExposure::new(Records, true, BoundedContextOrCalls),
            ToolKind::GetDashboard => ToolExposure::new(Records, false, BoundedContextOrCalls),
            ToolKind::DescribeSchema => ToolExposure::new(Schema, false, CorrectnessUnderIgnorance),
            ToolKind::PreviewRecordShape => {
                ToolExposure::new(Schema, true, CorrectnessUnderIgnorance)
            }
            ToolKind::CreateRecord => ToolExposure::new(Records, true, Atomicity),
            ToolKind::CreateMany => ToolExposure::new(Records, false, Atomicity),
            ToolKind::CreateExploration => ToolExposure::new(Records, false, Atomicity),
            ToolKind::GetEventContext => {
                ToolExposure::new(Coordination, false, BoundedContextOrCalls)
            }
            ToolKind::GetRecord => ToolExposure::new(Records, true, Discoverability),
            ToolKind::ResolveMany => ToolExposure::new(Query, false, BoundedContextOrCalls),
            ToolKind::UpdateRecord => ToolExposure::new(Records, true, Atomicity),
            ToolKind::ClaimUnownedRecord => ToolExposure::new(Records, false, Atomicity),
            ToolKind::CorrectRecordType => ToolExposure::new(Records, false, Atomicity),
            ToolKind::DeleteRecord => ToolExposure::new(Records, true, Atomicity),
            ToolKind::ArchiveRecord => ToolExposure::new(Records, true, Atomicity),
            ToolKind::RenderRecord => ToolExposure::new(Records, false, Discoverability),
            ToolKind::GetHistory => ToolExposure::new(History, true, CorrectnessUnderIgnorance),
            ToolKind::WhatsChanged => ToolExposure::new(History, true, BoundedContextOrCalls),
            ToolKind::ManageBindings => {
                ToolExposure::new(Identity, false, CorrectnessUnderIgnorance)
            }
            ToolKind::ManageRecordPolicy => ToolExposure::new(Records, false, Atomicity),
            ToolKind::ResolveExternal => {
                ToolExposure::new(Identity, false, CorrectnessUnderIgnorance)
            }
            ToolKind::ObserveExternal => {
                ToolExposure::new(Identity, false, CorrectnessUnderIgnorance)
            }
            ToolKind::GetRunActivity => {
                ToolExposure::new(Coordination, false, BoundedContextOrCalls)
            }
            ToolKind::RenderRecordVersionDiff => {
                ToolExposure::new(History, false, BoundedContextOrCalls)
            }
            ToolKind::ManageLinks => ToolExposure::new(Records, true, Atomicity),
            ToolKind::ManageRelationships => ToolExposure::new(Records, false, Atomicity),
            ToolKind::ManageMessages => ToolExposure::new(Messaging, true, Atomicity),
            ToolKind::ManageInterventions => ToolExposure::new(Messaging, false, Atomicity),
            ToolKind::InstantiateArtifact => ToolExposure::new(Artifacts, false, Atomicity),
            ToolKind::ManageRendererBinding => {
                ToolExposure::new(Artifacts, false, CorrectnessUnderIgnorance)
            }
            ToolKind::ManageMdxModules => ToolExposure::new(Artifacts, false, Atomicity),
            ToolKind::ManageArtifactInputs => ToolExposure::new(Artifacts, false, Atomicity),
            ToolKind::ManageArtifactModuleGrants => {
                ToolExposure::new(Artifacts, false, CorrectnessUnderIgnorance)
            }
            ToolKind::RenderArtifact => ToolExposure::new(Artifacts, false, BoundedContextOrCalls),
            ToolKind::VerifyArtifact => {
                ToolExposure::new(Artifacts, false, CorrectnessUnderIgnorance)
            }
            ToolKind::InvokeArtifactInteraction => ToolExposure::new(Artifacts, false, Atomicity),
            ToolKind::OpenCollection => ToolExposure::new(Artifacts, false, BoundedContextOrCalls),
            ToolKind::ManageFacetObservations => {
                ToolExposure::new(Facets, false, CorrectnessUnderIgnorance)
            }
            ToolKind::ResolveFacets => ToolExposure::new(Facets, true, CorrectnessUnderIgnorance),
            ToolKind::SuggestFacetValues => {
                ToolExposure::new(Facets, false, CorrectnessUnderIgnorance)
            }
            ToolKind::QueryRecord => ToolExposure::new(Query, true, BoundedContextOrCalls),
            ToolKind::ResolveRollup => ToolExposure::new(Query, true, BoundedContextOrCalls),
            ToolKind::Search => ToolExposure::new(Query, true, BoundedContextOrCalls),
            ToolKind::QuerySql => ToolExposure::new(Query, false, Discoverability),
            ToolKind::Scan => ToolExposure::new(Query, true, BoundedContextOrCalls),
            ToolKind::ManageVocabularies => {
                ToolExposure::new(Schema, true, CorrectnessUnderIgnorance)
            }
            ToolKind::ManageSchemaConfig => {
                ToolExposure::new(Schema, true, CorrectnessUnderIgnorance)
            }
            ToolKind::AttachText => ToolExposure::new(Attachments, true, Atomicity),
            ToolKind::AttachFromUrl => {
                ToolExposure::new(Attachments, true, CorrectnessUnderIgnorance)
            }
            ToolKind::ReadAttachment => ToolExposure::new(Attachments, true, BoundedContextOrCalls),
            ToolKind::ManageAttachments => ToolExposure::new(Attachments, true, Atomicity),
            ToolKind::StartWork => ToolExposure::new(Work, true, Atomicity),
            ToolKind::ResolveSuggestions => ToolExposure::new(Suggestions, false, Atomicity),
            ToolKind::RenderSuggestionReview => {
                ToolExposure::new(Suggestions, false, BoundedContextOrCalls)
            }
            ToolKind::ExportSnapshot => ToolExposure::new(Export, true, CorrectnessUnderIgnorance),
            ToolKind::ResolveCitation => {
                ToolExposure::new(Citations, false, CorrectnessUnderIgnorance)
            }
            ToolKind::ManageCitations => {
                ToolExposure::new(Citations, false, CorrectnessUnderIgnorance)
            }
            ToolKind::CreateAttribution => ToolExposure::new(Citations, false, Atomicity),
            ToolKind::ReadAttributions => {
                ToolExposure::new(Citations, false, BoundedContextOrCalls)
            }
            ToolKind::ManageAttributions => ToolExposure::new(Citations, false, Atomicity),
            ToolKind::ManageInstructions => {
                ToolExposure::new(Guidance, false, CorrectnessUnderIgnorance)
            }
            ToolKind::ManageOnboarding => {
                ToolExposure::new(Guidance, false, CorrectnessUnderIgnorance)
            }
            ToolKind::ManageMemberships => ToolExposure::new(Identity, false, Atomicity),
            ToolKind::ManageChangeSummaries => ToolExposure::new(Artifacts, false, Atomicity),
            ToolKind::QueryChangeSummaries => {
                ToolExposure::new(Artifacts, false, CorrectnessUnderIgnorance)
            }
            // Complete-only (D14's intent): the canvas is summoned from a
            // record page or an agent that already knows it exists.
            ToolKind::ReadCanvas => ToolExposure::new(Records, false, BoundedContextOrCalls),
            ToolKind::ManageCanvas => ToolExposure::new(Records, false, Atomicity),
            // Hosted-only, like membership: undiscoverable under focused
            // filtering, present in the complete default, callable by exact
            // name. ReachConnect mints consent-ticket state, so it shares the
            // membership admission reason even though it writes no records.
            ToolKind::ReachRead => ToolExposure::new(Identity, false, BoundedContextOrCalls),
            ToolKind::ReachConnect => ToolExposure::new(Identity, false, Atomicity),
        }
    }

    pub const fn authorization(self) -> AuthorizationDisposition {
        use AuthorizationDisposition::*;
        match self {
            ToolKind::Ping
            | ToolKind::EngineInfo
            | ToolKind::StandbyStatus
            | ToolKind::Quickstart
            | ToolKind::ReadGuide
            | ToolKind::SetIntent
            | ToolKind::CloseRun => NoRecord,
            ToolKind::Bootstrap
            | ToolKind::GetDashboard
            | ToolKind::PreviewRecordShape
            | ToolKind::WhatsChanged
            | ToolKind::QueryRecord
            | ToolKind::ResolveMany
            | ToolKind::Search
            | ToolKind::Scan => CallerFilteredRead,
            ToolKind::GetStructure
            | ToolKind::GetRecord
            | ToolKind::RenderRecord
            | ToolKind::RenderRecordVersionDiff
            | ToolKind::ResolveFacets
            | ToolKind::SuggestFacetValues
            | ToolKind::ResolveRollup
            | ToolKind::RenderSuggestionReview
            | ToolKind::ReadCanvas => RecordView,
            ToolKind::CorrectRecordType
            | ToolKind::ManageFacetObservations
            | ToolKind::AttachText
            | ToolKind::AttachFromUrl => RecordEdit,
            ToolKind::DeleteRecord | ToolKind::ArchiveRecord => RecordManage,
            ToolKind::ClaimUnownedRecord
            | ToolKind::ManageVocabularies
            | ToolKind::ExportSnapshot => HostOwner,
            ToolKind::CreateRecord
            | ToolKind::CreateMany
            | ToolKind::CreateExploration
            | ToolKind::GetEventContext
            | ToolKind::UpdateRecord
            | ToolKind::GetHistory
            | ToolKind::GetRunActivity
            | ToolKind::ManageBindings
            | ToolKind::ManageRecordPolicy
            | ToolKind::ResolveExternal
            | ToolKind::ObserveExternal
            | ToolKind::ManageLinks
            | ToolKind::ManageRelationships
            | ToolKind::ManageMessages
            | ToolKind::ManageInterventions
            | ToolKind::InstantiateArtifact
            | ToolKind::ManageRendererBinding
            | ToolKind::ManageMdxModules
            | ToolKind::ManageArtifactInputs
            | ToolKind::ManageArtifactModuleGrants
            | ToolKind::RenderArtifact
            | ToolKind::VerifyArtifact
            | ToolKind::InvokeArtifactInteraction
            | ToolKind::OpenCollection
            | ToolKind::QuerySql
            | ToolKind::DescribeSchema
            | ToolKind::ManageSchemaConfig
            | ToolKind::ManageAttachments
            | ToolKind::StartWork
            | ToolKind::ReadAttachment
            | ToolKind::ResolveCitation
            | ToolKind::ResolveSuggestions
            | ToolKind::ManageCitations
            | ToolKind::CreateAttribution
            | ToolKind::ReadAttributions
            | ToolKind::ManageAttributions
            | ToolKind::ManageInstructions
            | ToolKind::ManageOnboarding
            | ToolKind::ManageMemberships
            | ToolKind::ReachRead
            | ToolKind::ReachConnect => Specialized,
            ToolKind::ManageChangeSummaries | ToolKind::QueryChangeSummaries => Specialized,
            // Edit on the canvas plus View on every record a card names.
            ToolKind::ManageCanvas => Specialized,
        }
    }
}

/// Deliberate policy required by the extension-only registration path.
///
/// The production builtin/surface registrars never use this path; a regression
/// test audits that fact.  It exists for embedders and transport seam tests
/// which register synthetic tools whose payloads do not describe Native
/// records.  Requiring the policy at the call site keeps "no interactions" an
/// explicit decision rather than a catch-all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustomInteractionPolicy {
    NoRecordInteractions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Extractor {
    Shipped(ToolKind),
    Custom(CustomInteractionPolicy),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Interaction {
    Surfaced,
    Opened,
    Mutated,
}

impl Interaction {
    const fn as_str(self) -> &'static str {
        match self {
            Interaction::Surfaced => "surfaced",
            Interaction::Opened => "opened",
            Interaction::Mutated => "mutated",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Touch {
    record_id: String,
    interaction: Interaction,
    result_rank: Option<i64>,
}

#[derive(Default)]
struct Extraction {
    touches: Vec<Touch>,
    seen: HashSet<(String, Interaction)>,
    next_surface_rank: i64,
    result_count: Option<i64>,
}

impl Extraction {
    fn success() -> Self {
        Extraction {
            next_surface_rank: 1,
            result_count: Some(0),
            ..Extraction::default()
        }
    }

    fn touch(&mut self, id: Option<&str>, interaction: Interaction) {
        let Some(id) = id.filter(|id| !id.is_empty()) else {
            return;
        };
        let key = (id.to_string(), interaction);
        if !self.seen.insert(key.clone()) {
            return;
        }
        let result_rank = if interaction == Interaction::Surfaced {
            let rank = self.next_surface_rank;
            self.next_surface_rank += 1;
            Some(rank)
        } else {
            None
        };
        self.touches.push(Touch {
            record_id: key.0,
            interaction,
            result_rank,
        });
    }

    fn surfaced(&mut self, id: Option<&str>) {
        self.touch(id, Interaction::Surfaced);
    }

    fn opened(&mut self, id: Option<&str>) {
        self.touch(id, Interaction::Opened);
    }

    fn mutated(&mut self, id: Option<&str>) {
        self.touch(id, Interaction::Mutated);
    }

    fn count(&mut self, count: usize) {
        self.result_count = i64::try_from(count).ok();
    }

    fn count_value(&mut self, value: Option<i64>) {
        self.result_count = value;
    }

    fn count_surfaced(&mut self) {
        self.result_count = i64::try_from(
            self.touches
                .iter()
                .filter(|touch| touch.interaction == Interaction::Surfaced)
                .count(),
        )
        .ok();
    }
}

fn string_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn array_at<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn surface_id_array(extraction: &mut Extraction, values: &[Value], id_key: &str) {
    for value in values {
        extraction.surfaced(string_at(value, id_key));
    }
}

/// Surface the bounded enrichments around one opened record.  The central
/// record itself is recorded separately as `opened`; these are the lightweight
/// records the response placed around it.
fn surface_enrichments(extraction: &mut Extraction, record: &Value) {
    surface_id_array(extraction, array_at(record, "children"), "id");
    surface_id_array(extraction, array_at(record, "ancestors"), "id");
    for link in array_at(record, "links_out") {
        extraction.surfaced(string_at(link, "target_id"));
    }
    for link in array_at(record, "links_in") {
        extraction.surfaced(string_at(link, "source_id"));
    }
}

fn extract_dashboard(extraction: &mut Extraction, result: &Value) {
    for key in ["active", "stale", "blocked"] {
        for record in array_at(result, key) {
            extraction.surfaced(string_at(record, "id"));
            for relation in ["blocked_by", "waiting_on"] {
                surface_id_array(extraction, array_at(record, relation), "id");
            }
        }
    }
    // The unclassified census names records that are already in the buckets
    // above, so this adds nothing in the common case — `surfaced` deduplicates.
    // It is still read, because the census window and the bucket windows are
    // bounded independently and a censused record can fall outside both.
    if let Some(unclassified) = result.get("unclassified_lifecycle") {
        surface_id_array(extraction, array_at(unclassified, "items"), "id");
    }
    extraction.count_surfaced();
}

fn extract_get_record(extraction: &mut Extraction, result: &Value) {
    let mut found = 0usize;
    for record in array_at(result, "records") {
        if string_at(record, "status") != Some("found") {
            continue;
        }
        found += 1;
        extraction.opened(string_at(record, "id"));
        surface_enrichments(extraction, record);
    }
    extraction.count(found);
}

fn extract_search(extraction: &mut Extraction, result: &Value) {
    surface_id_array(extraction, array_at(result, "hits"), "id");
    if let Some(near_misses) = result.get("near_misses") {
        for key in ["name_prefix", "name_infix", "tree_siblings"] {
            surface_id_array(extraction, array_at(near_misses, key), "id");
        }
    }
    extraction.count_value(result.get("returned").and_then(Value::as_i64));
}

fn extract_scan(extraction: &mut Extraction, result: &Value) {
    // Map insertion order is response order (`serde_json/preserve_order`), so
    // the global rank is the first position at which a record was surfaced
    // across the named axis heads.  `convergence` repeats those same records
    // and is visited last; deduplication keeps the first rank.
    if let Some(axes) = result.get("axes").and_then(Value::as_object) {
        for facet in axes.values() {
            surface_id_array(extraction, array_at(facet, "samples"), "id");
        }
    }
    surface_id_array(extraction, array_at(result, "convergence"), "id");
    extraction.count_surfaced();
}

fn extract_manage_links(extraction: &mut Extraction, arguments: &Value, result: &Value) {
    match string_at(arguments, "action") {
        Some("add" | "remove") => {
            extraction.mutated(string_at(result, "source_id"));
            extraction.mutated(string_at(result, "target_id"));
            extraction.count(1);
        }
        Some("list") => {
            extraction.opened(string_at(result, "record_id"));
            for link in array_at(result, "links_out") {
                extraction.surfaced(string_at(link, "target_id"));
            }
            for link in array_at(result, "links_in") {
                extraction.surfaced(string_at(link, "source_id"));
            }
            extraction
                .count(array_at(result, "links_out").len() + array_at(result, "links_in").len());
        }
        _ => {}
    }
}

fn extract_manage_attachments(extraction: &mut Extraction, arguments: &Value, result: &Value) {
    match string_at(arguments, "action") {
        Some("list") => {
            extraction.opened(string_at(result, "record_id"));
            surface_id_array(extraction, array_at(result, "attachments"), "attachment_id");
            extraction.count(array_at(result, "attachments").len());
        }
        Some("inspect") => {
            extraction.opened(string_at(result, "attachment_id"));
            extraction.count(1);
        }
        Some("detach") => {
            extraction.mutated(string_at(result, "attachment_id"));
            extraction.count(1);
        }
        _ => {}
    }
}

fn extract_start_work(extraction: &mut Extraction, result: &Value) {
    let target = string_at(result, "record_id");
    extraction.opened(target);
    if result.get("changed").and_then(Value::as_bool) == Some(true) {
        extraction.mutated(target);
    }
    if let Some(context) = result.get("context") {
        if let Some(record) = context.get("record") {
            surface_enrichments(extraction, record);
        }
        surface_id_array(extraction, array_at(context, "governance"), "id");
        if let Some(dependencies) = context.get("dependencies") {
            surface_id_array(extraction, array_at(dependencies, "waiting_on"), "id");
            surface_id_array(extraction, array_at(dependencies, "satisfied"), "id");
            surface_id_array(extraction, array_at(dependencies, "blocked_by"), "id");
        }
    }
    extraction.count(1);
}

/// Extract interactions from one successful handler payload.
///
/// There is intentionally no wildcard arm.  Several arms explicitly produce
/// no record touches because their domains are engine/meta rows rather than
/// records; that decision is visible in code instead of being a fallback.
fn extract(kind: ToolKind, arguments: &Value, result: &Value) -> Extraction {
    let mut extraction = Extraction::success();
    match kind {
        ToolKind::Ping
        | ToolKind::EngineInfo
        | ToolKind::StandbyStatus
        | ToolKind::ReadGuide
        | ToolKind::ExportSnapshot
        | ToolKind::SetIntent
        | ToolKind::CloseRun => {}
        ToolKind::Bootstrap => {
            let roots = result
                .pointer("/roots/items")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            surface_id_array(&mut extraction, roots, "id");
            let instruction_entries = result
                .pointer("/instructions/entries")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for entry in instruction_entries {
                let source = entry.get("source").unwrap_or(&Value::Null);
                if source.get("type").and_then(Value::as_str) == Some("record") {
                    extraction.opened(source.get("record_id").and_then(Value::as_str));
                }
            }
            let private_root = result
                .pointer("/principal/private_context/root_record_id")
                .and_then(Value::as_str);
            extraction.surfaced(private_root);
            let starting_context = result
                .pointer("/principal/private_context/starting_context_contract/existing_note_id")
                .and_then(Value::as_str);
            extraction.surfaced(starting_context);
            let pending_obligations = result
                .get("pending_obligations")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for obligation in pending_obligations
                .iter()
                .take(MAX_BOOTSTRAP_PENDING_OBLIGATIONS)
            {
                extraction.surfaced(
                    obligation
                        .get("progress_artifact_id")
                        .and_then(Value::as_str),
                );
            }
            extraction.count((extraction.next_surface_rank - 1) as usize);
        }
        ToolKind::Quickstart => {
            extraction.count(0);
        }
        ToolKind::GetStructure => {
            surface_id_array(&mut extraction, array_at(result, "nodes"), "id");
            extraction.count(array_at(result, "nodes").len());
        }
        ToolKind::GetDashboard => extract_dashboard(&mut extraction, result),
        ToolKind::DescribeSchema => {
            extraction.count(array_at(result, "tables").len());
        }
        ToolKind::PreviewRecordShape => {
            // The preview reports schema facts, never records. Treat one
            // successful response as one result without fabricating touches.
            extraction.count(1);
        }
        ToolKind::CreateRecord => {
            extraction.mutated(string_at(result, "id"));
            // The handler returns a FLATTENED EnrichedRecord, not a mutation
            // acknowledgement. Related records visible beside the mutated root
            // therefore belong in the surfaced denominator exactly as they do
            // for get_record.
            surface_enrichments(&mut extraction, result);
            extraction.count(1);
        }
        ToolKind::UpdateRecord => {
            if let Some(results) = result.get("results").and_then(Value::as_array) {
                for outcome in results {
                    if outcome.get("status").and_then(Value::as_str) == Some("changed") {
                        extraction.mutated(string_at(outcome, "id"));
                    }
                }
                extraction.count(results.len());
            } else {
                extraction.mutated(string_at(result, "id"));
                surface_enrichments(&mut extraction, result);
                extraction.count(1);
            }
        }
        ToolKind::ClaimUnownedRecord => {
            extraction.mutated(string_at(result, "id"));
            extraction.count(1);
        }
        ToolKind::CreateMany => {
            let ids = array_at(result, "ids");
            for id in ids {
                extraction.mutated(id.as_str());
            }
            extraction.count(ids.len());
        }
        ToolKind::CorrectRecordType => {
            extraction.mutated(string_at(result, "record_id").or_else(|| string_at(result, "id")));
            extraction.count(1);
        }
        ToolKind::CreateExploration => {
            // The exploration collection and every candidate are outputs of
            // one admitted transaction, so all of them are mutations of this
            // call rather than incidental context.
            extraction.mutated(string_at(
                result.get("exploration").unwrap_or(&Value::Null),
                "id",
            ));
            let candidates = array_at(result, "candidates");
            for candidate in candidates {
                extraction.mutated(string_at(candidate, "id"));
            }
            extraction.count(candidates.len() + 1);
        }
        ToolKind::GetEventContext => {
            // The event's own target is opened. Records the run merely
            // consulted BEFORE this event are evidence being reported, not
            // records this call itself reached for — recording them as touches
            // would let the projection inflate its own future output.
            extraction.opened(string_at(
                result.get("event").unwrap_or(&Value::Null),
                "record_id",
            ));
            extraction.count(1);
        }
        ToolKind::GetRecord => extract_get_record(&mut extraction, result),
        ToolKind::ResolveMany => {
            let results = array_at(result, "results");
            for resolved in results {
                if let Some(record) = resolved.get("match") {
                    extraction.surfaced(string_at(record, "id"));
                }
                for record in array_at(resolved, "matches") {
                    extraction.surfaced(string_at(record, "id"));
                }
            }
            extraction.count(results.len());
        }
        ToolKind::DeleteRecord => {
            extraction.mutated(string_at(result, "id"));
            extraction.count(1);
        }
        ToolKind::ArchiveRecord => {
            let id = string_at(result, "id");
            if result.get("changed").and_then(Value::as_bool) == Some(true) {
                extraction.mutated(id);
            } else {
                extraction.opened(id);
            }
            extraction.count(1);
        }
        ToolKind::RenderRecord => {
            extraction.opened(string_at(result, "id"));
            extraction.count(1);
        }
        ToolKind::GetHistory => {
            if let Some(record_id) = string_at(arguments, "record_id") {
                extraction.opened(Some(record_id));
            }
            for event in array_at(result, "events") {
                extraction.surfaced(string_at(event, "record_id"));
            }
            extraction.count(array_at(result, "events").len());
        }
        ToolKind::WhatsChanged => {
            if let Some(record_id) = string_at(arguments, "scope_record_id") {
                extraction.opened(Some(record_id));
            }
            for change in array_at(result, "changes") {
                extraction.surfaced(string_at(change, "record_id"));
            }
            extraction.count(array_at(result, "changes").len());
        }
        ToolKind::ManageBindings => {
            let id = string_at(result, "record_id");
            if result.get("changed").and_then(Value::as_bool) == Some(true) {
                extraction.mutated(id);
                extraction.mutated(string_at(result, "from_record_id"));
            } else {
                extraction.opened(id);
                extraction.opened(string_at(result, "from_record_id"));
            }
            extraction.count(1);
        }
        ToolKind::ManageRecordPolicy => {
            let outcomes = array_at(result, "outcomes");
            if !outcomes.is_empty() {
                for outcome in outcomes {
                    let id = string_at(outcome, "record_id");
                    if outcome.get("changed").and_then(Value::as_bool) == Some(true) {
                        extraction.mutated(id);
                    } else {
                        extraction.opened(id);
                    }
                }
                extraction.count(outcomes.len());
                return extraction;
            }
            let id = string_at(result, "record_id");
            if result.get("changed").and_then(Value::as_bool) == Some(true) {
                extraction.mutated(id);
            } else {
                extraction.opened(id);
            }
            extraction.count(1);
        }
        ToolKind::ResolveExternal => {
            if result.get("created").and_then(Value::as_bool) == Some(true)
                || !array_at(result, "bindings_added").is_empty()
            {
                extraction.mutated(string_at(result, "record_id"));
            } else {
                extraction.opened(string_at(result, "record_id"));
            }
            extraction.count(1);
        }
        ToolKind::ObserveExternal => {
            extraction.mutated(string_at(result, "record_id"));
            extraction.mutated(string_at(result, "attachment_id"));
            extraction.count(1);
        }
        // Aggregate counts describe prior interactions; reading that summary
        // must not fabricate a new record touch or recursively inflate itself.
        ToolKind::GetRunActivity => {
            extraction.count(array_at(result, "read_activity").len());
        }
        ToolKind::RenderRecordVersionDiff => {
            extraction.opened(string_at(result, "record_id"));
            extraction.count(1);
        }
        ToolKind::ManageLinks => extract_manage_links(&mut extraction, arguments, result),
        ToolKind::ReadCanvas => {
            extraction.opened(string_at(result, "canvas_id"));
            for object in array_at(result, "objects") {
                extraction.surfaced(object.pointer("/record/id").and_then(Value::as_str));
            }
            extraction.count(
                array_at(result, "objects")
                    .len()
                    .max(array_at(result, "batches").len()),
            );
        }
        ToolKind::ManageCanvas => {
            if matches!(string_at(result, "outcome"), Some("committed" | "replayed")) {
                extraction.mutated(
                    arguments
                        .pointer("/batch/canvas_id")
                        .and_then(Value::as_str),
                );
            }
            extraction.count(1);
        }
        ToolKind::ManageRelationships => match string_at(arguments, "action") {
            Some("assert" | "contest" | "add_evidence" | "retract") => {
                for endpoint in array_at(arguments, "endpoints") {
                    extraction.mutated(string_at(endpoint, "record_id"));
                }
                extraction.mutated(string_at(result, "evidence_id"));
                extraction.count(1);
            }
            Some("read" | "why") => {
                for endpoint in array_at(result, "endpoints") {
                    extraction.opened(string_at(endpoint, "record_id"));
                }
                extraction.count(array_at(result, "assertions").len());
            }
            // `find` surfaces the scoped endpoint plus one counterpart record
            // per returned row, each already authorized for View.
            Some("find") => {
                extraction.opened(
                    result
                        .get("endpoint")
                        .and_then(|endpoint| string_at(endpoint, "record_id")),
                );
                for found in array_at(result, "results") {
                    extraction.opened(
                        found
                            .get("counterpart")
                            .and_then(|counterpart| string_at(counterpart, "record_id")),
                    );
                }
                extraction.count(array_at(result, "results").len());
            }
            _ => {}
        },
        ToolKind::ManageMessages => {
            match string_at(arguments, "action") {
                Some("send") => {
                    extraction.mutated(string_at(result, "id"));
                }
                Some("classify" | "unclassify" | "move" | "share_history") => {
                    extraction.mutated(string_at(result, "message_id"));
                    for id in array_at(result, "message_ids") {
                        extraction.mutated(id.as_str());
                    }
                }
                Some("list_conversation") => {
                    extraction.opened(string_at(result, "conversation_id"));
                    surface_id_array(&mut extraction, array_at(result, "messages"), "id");
                }
                Some("list_context") => {
                    surface_id_array(&mut extraction, array_at(result, "messages"), "id");
                }
                Some("list_unclassified") => {
                    surface_id_array(&mut extraction, array_at(result, "messages"), "id");
                }
                Some("list_my_conversations") => {
                    surface_id_array(
                        &mut extraction,
                        array_at(result, "conversations"),
                        "conversation_id",
                    );
                }
                _ => {}
            }
            extraction.count(1);
        }
        ToolKind::ManageInterventions => {
            match string_at(arguments, "action") {
                Some("cancel" | "resume_delivery") => {
                    extraction.mutated(
                        result
                            .pointer("/trigger/message_id")
                            .and_then(Value::as_str),
                    );
                }
                Some("get") => {
                    extraction.opened(
                        result
                            .pointer("/trigger/message_id")
                            .and_then(Value::as_str),
                    );
                }
                Some("query") => {
                    for item in array_at(result, "items") {
                        extraction
                            .surfaced(item.pointer("/trigger/message_id").and_then(Value::as_str));
                    }
                }
                _ => {}
            }
            extraction.count(if string_at(arguments, "action") == Some("query") {
                array_at(result, "items").len()
            } else {
                1
            });
        }
        ToolKind::InstantiateArtifact => {
            extraction.opened(string_at(result, "source_id"));
            extraction.mutated(string_at(result, "id"));
            extraction.count(1);
        }
        ToolKind::ManageRendererBinding => {
            let id = string_at(result, "artifact_id");
            let changed = matches!(string_at(arguments, "action"), Some("bind" | "unbind"))
                && string_at(result, "status") != Some("unchanged")
                && string_at(result, "changed_collection_id").is_some();
            let changed_collection_id = string_at(result, "changed_collection_id");
            if changed {
                extraction.mutated(id);
                extraction.mutated(changed_collection_id);
                extraction.count(1);
            } else {
                extraction.opened(id);
                extraction.count(array_at(result, "bindings").len());
            }
            for binding in array_at(result, "bindings") {
                let collection_id = string_at(binding, "collection_id");
                if !changed || collection_id != changed_collection_id {
                    extraction.surfaced(collection_id);
                }
            }
        }
        ToolKind::ManageMdxModules => {
            let id = string_at(result, "module_id");
            if matches!(
                string_at(arguments, "action"),
                Some("publish" | "deprecate" | "withdraw")
            ) {
                extraction.mutated(id);
            } else {
                extraction.opened(id);
            }
            extraction.count(array_at(result, "releases").len().max(1));
        }
        ToolKind::ManageArtifactInputs => {
            if matches!(string_at(arguments, "action"), Some("bind" | "unbind")) {
                extraction.mutated(string_at(result, "artifact_id"));
            } else {
                extraction.opened(string_at(result, "artifact_id"));
            }
            for binding in array_at(result, "bindings") {
                extraction.surfaced(string_at(binding, "collection_id"));
            }
            extraction.count(array_at(result, "bindings").len());
        }
        ToolKind::ManageArtifactModuleGrants => {
            if matches!(string_at(arguments, "action"), Some("grant" | "revoke")) {
                extraction.mutated(string_at(result, "artifact_id"));
            } else {
                extraction.opened(string_at(result, "artifact_id"));
            }
            extraction.count(array_at(result, "grants").len());
        }
        ToolKind::RenderArtifact => {
            extraction.opened(string_at(result, "artifact_id"));
            if let Some(collection) = result
                .get("input")
                .and_then(|input| input.get("collection"))
            {
                extraction.surfaced(string_at(collection, "id"));
            }
            let bound = result
                .get("input")
                .and_then(|input| string_at(input, "mode"))
                == Some("bound");
            if bound {
                if let Some(plan) = result.get("plan") {
                    for lane in array_at(plan, "lanes") {
                        surface_id_array(&mut extraction, array_at(lane, "records"), "id");
                    }
                }
            }
            extraction.count(1);
        }
        ToolKind::VerifyArtifact => {
            extraction.opened(string_at(result, "artifact_id"));
            if let Some(input) = result.get("input") {
                if let Some(collection) = input.get("collection") {
                    extraction.surfaced(string_at(collection, "id"));
                }
                for collection in array_at(input, "collections") {
                    extraction.surfaced(string_at(collection, "id"));
                }
                surface_id_array(&mut extraction, array_at(input, "records"), "id");
                surface_id_array(&mut extraction, array_at(input, "modules"), "id");
            }
            extraction.count(1);
        }
        ToolKind::InvokeArtifactInteraction => {
            // The interaction's subject is the record it wrote, which the
            // authoritative result names; a refusal mutates nothing.
            let changes = array_at(result, "changes");
            let changed = changes.len();
            if string_at(result, "status") == Some("committed") {
                for change in changes {
                    extraction.mutated(string_at(change, "record_id"));
                }
            }
            extraction.opened(string_at(arguments, "artifact_id"));
            extraction.count(changed.max(1));
        }
        ToolKind::OpenCollection => {
            if let Some(collection) = result.get("collection") {
                extraction.opened(string_at(collection, "id"));
            }
            if let Some(input) = result.get("input") {
                surface_id_array(&mut extraction, array_at(input, "records"), "id");
                extraction.count(array_at(input, "records").len());
            }
            surface_id_array(&mut extraction, array_at(result, "renderers"), "id");
        }
        ToolKind::ManageFacetObservations => {
            let id = string_at(result, "record_id");
            if matches!(string_at(arguments, "action"), Some("set" | "unset")) {
                extraction.mutated(id);
                extraction.count(1);
            } else {
                extraction.opened(id);
                extraction.count(array_at(result, "observations").len());
            }
        }
        ToolKind::ResolveFacets => {
            if string_at(arguments, "record_id").is_some() {
                extraction.opened(string_at(result, "record_id"));
            }
            extraction.count(1);
        }
        ToolKind::SuggestFacetValues => {
            if let Some(record_id) = string_at(arguments, "record_id") {
                extraction.opened(Some(record_id));
            }
            extraction.count(array_at(result, "suggestions").len());
        }
        ToolKind::QueryRecord => {
            surface_id_array(&mut extraction, array_at(result, "records"), "id");
            let count = if string_at(result, "shape") == Some("aggregate") {
                Some(1)
            } else {
                result.get("returned").and_then(Value::as_i64).or_else(|| {
                    result
                        .get("buckets")
                        .and_then(Value::as_array)
                        .and_then(|v| i64::try_from(v.len()).ok())
                })
            };
            extraction.count_value(count.or(Some(0)));
        }
        ToolKind::ResolveRollup => {
            extraction.opened(string_at(result, "record_id"));
            extraction.count(1);
        }
        ToolKind::Search => extract_search(&mut extraction, result),
        ToolKind::QuerySql => {
            extraction.count_value(result.get("row_count").and_then(Value::as_i64));
        }
        ToolKind::Scan => extract_scan(&mut extraction, result),
        ToolKind::ManageVocabularies => {
            if string_at(arguments, "action") == Some("list_values") {
                extraction.count(array_at(result, "values").len());
            } else {
                extraction.count(1);
            }
        }
        ToolKind::ManageSchemaConfig => {
            if string_at(arguments, "action") == Some("read") {
                extraction.count(array_at(result, "rows").len());
            } else {
                extraction.count(1);
            }
        }
        ToolKind::AttachText | ToolKind::AttachFromUrl => {
            extraction.mutated(string_at(result, "record_id"));
            extraction.mutated(string_at(result, "attachment_id"));
            extraction.count(1);
        }
        ToolKind::ReadAttachment => {
            extraction.opened(string_at(result, "attachment_id"));
            extraction.count(1);
        }
        ToolKind::ManageAttachments => {
            extract_manage_attachments(&mut extraction, arguments, result)
        }
        ToolKind::ResolveSuggestions => {
            match string_at(result, "status") {
                Some("accepted") => {
                    extraction.mutated(string_at(result, "target_id"));
                    for id in array_at(result, "suggestion_ids") {
                        extraction.mutated(id.as_str());
                    }
                }
                Some("rejected" | "stale") => {
                    for id in array_at(result, "suggestion_ids") {
                        extraction.mutated(id.as_str());
                    }
                }
                Some("conflict") | None | Some(_) => {}
            }
            extraction.count(
                extraction
                    .touches
                    .iter()
                    .filter(|touch| touch.interaction == Interaction::Mutated)
                    .count(),
            );
        }
        ToolKind::RenderSuggestionReview => {
            extraction.opened(
                result
                    .get("target")
                    .and_then(|target| string_at(target, "id")),
            );
            extraction.count(1);
        }
        ToolKind::StartWork => extract_start_work(&mut extraction, result),
        ToolKind::ResolveCitation => {
            extraction.opened(string_at(result, "annotation_id"));
            extraction.surfaced(string_at(result, "target_record_id"));
            extraction.count(1);
        }
        ToolKind::ManageCitations => {
            extraction.mutated(string_at(result, "citation_id"));
            extraction.count(1);
        }
        ToolKind::CreateAttribution => {
            extraction.mutated(string_at(result, "annotation_id"));
            extraction.surfaced(string_at(result, "bearer_id"));
            extraction.count(1);
        }
        ToolKind::ReadAttributions => {
            extraction.opened(string_at(result, "bearer_id"));
            for attribution in array_at(result, "attributions") {
                extraction.surfaced(string_at(attribution, "annotation_id"));
            }
            extraction.count_surfaced();
        }
        ToolKind::ManageAttributions => {
            extraction.mutated(string_at(result, "annotation_id"));
            extraction.count(1);
        }
        ToolKind::ManageInstructions => match string_at(arguments, "action") {
            Some("list") => {
                for binding in array_at(result, "bindings") {
                    extraction.surfaced(string_at(binding, "source_record_id"));
                }
                extraction.count_surfaced();
            }
            Some("apply_seeded_default" | "reset_seeded_default") => {
                extraction.mutated(string_at(result, "source_record_id"));
                extraction.count(usize::from(string_at(result, "source_record_id").is_some()));
            }
            Some("create_binding" | "retarget_binding" | "compare_seeded_default") => {
                extraction.opened(string_at(result, "source_record_id"));
                extraction.count(usize::from(string_at(result, "source_record_id").is_some()));
            }
            Some(_) | None => extraction.count(0),
        },
        ToolKind::ManageOnboarding => {
            if string_at(arguments, "action") == Some("record_progress")
                && string_at(arguments, "phase") == Some("artifact_written")
            {
                extraction.opened(string_at(result, "artifact_id"));
                extraction.count(usize::from(string_at(result, "artifact_id").is_some()));
            } else if matches!(
                string_at(arguments, "action"),
                Some("add_source" | "change_source" | "reorder_source" | "remove_source")
            ) {
                extraction.opened(string_at(result, "source_record_id"));
                extraction.count(usize::from(string_at(result, "source_record_id").is_some()));
            } else {
                extraction.count(0);
            }
        }
        ToolKind::ManageMemberships => match string_at(arguments, "action") {
            Some("list") => extraction.count(array_at(result, "members").len()),
            Some("set_role" | "remove") => extraction.count(1),
            Some(_) | None => extraction.count(0),
        },
        // Provider identifiers are external pointers, never Native record
        // ids: count only, so read-log capture can never mistake a Slack
        // timestamp or Notion page id for a surfaced record.
        ToolKind::ReachRead => match string_at(arguments, "action") {
            Some("search_slack" | "search_notion" | "list_linear_projects") => {
                extraction.count(array_at(result, "results").len())
            }
            Some("recent_activity") => extraction.count(array_at(result, "candidates").len()),
            Some("source_status") => extraction.count(array_at(result, "sources").len()),
            Some(_) | None => extraction.count(0),
        },
        ToolKind::ReachConnect => {
            extraction.count(usize::from(string_at(result, "consent_url").is_some()))
        }
        ToolKind::ManageChangeSummaries => {
            if string_at(arguments, "action") == Some("inspect") {
                extraction.opened(string_at(result, "carrier_id"));
            } else {
                extraction.mutated(string_at(result, "carrier_id"));
            }
            extraction.count(usize::from(string_at(result, "carrier_id").is_some()));
        }
        ToolKind::QueryChangeSummaries => match string_at(arguments, "action") {
            Some("list") => {
                for item in array_at(result, "items") {
                    extraction.surfaced(string_at(item, "target_record_id"));
                }
                extraction.count_surfaced();
            }
            Some("get" | "drill") => {
                extraction.opened(string_at(result, "target_record_id"));
                extraction.count(usize::from(string_at(result, "target_record_id").is_some()));
            }
            Some(_) | None => extraction.count(0),
        },
    }
    extraction
}

pub(crate) fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn error_kind(error: &Error) -> &'static str {
    match error {
        Error::Engine(_) => "engine",
        Error::Conflict(_) => "conflict",
        Error::Auth(_) => "auth",
        Error::Delivery(_) => "delivery",
        Error::DeploymentReadOnly(_) => "deployment_read_only",
        Error::Sqlx(_) => "database",
        Error::Json(_) => "json",
        Error::Io(_) => "io",
    }
}

fn response_bytes(
    outcome: std::result::Result<&Value, &Error>,
    run_context: &Value,
) -> Option<i64> {
    let response = match outcome {
        Ok(value) => attach_run_context(value.clone(), run_context.clone()),
        Err(error) => serde_json::json!({
            "error": error.to_string(),
            "run_context": run_context,
        }),
    };
    serde_json::to_vec(&response)
        .ok()
        .and_then(|bytes| i64::try_from(bytes.len()).ok())
}

/// Persist only bounded operational routing for Reach. Provider search text
/// is deliberately outside Native's interaction log, and invalid direct calls
/// must not smuggle arbitrary fields into it before schema validation fails.
fn captured_arguments(extractor: Extractor, original: &Value) -> Value {
    match extractor {
        Extractor::Shipped(ToolKind::ReachRead) => original
            .get("action")
            .and_then(Value::as_str)
            .filter(|action| {
                matches!(
                    *action,
                    "source_status"
                        | "search_slack"
                        | "search_notion"
                        | "recent_activity"
                        | "list_linear_projects"
                )
            })
            .map_or_else(
                || serde_json::json!({}),
                |action| serde_json::json!({"action": action}),
            ),
        Extractor::Shipped(ToolKind::ReachConnect) => original
            .get("provider")
            .and_then(Value::as_str)
            .filter(|provider| matches!(*provider, "slack" | "notion" | "linear"))
            .map_or_else(
                || serde_json::json!({}),
                |provider| serde_json::json!({"provider": provider}),
            ),
        _ => original.clone(),
    }
}

pub(crate) struct PendingCapture {
    db: Db,
    tool_name: String,
    interaction_capability: Option<String>,
    run_key: Option<String>,
    parent_key: Option<String>,
    intent: Option<String>,
    actor: String,
    arguments: String,
    outcome_name: &'static str,
    error: Option<&'static str>,
    extraction: Extraction,
    result_annotation: Option<String>,
    result_bytes: Option<i64>,
    started_at: String,
    ended_at: String,
    _deployment_persistence_lease: Option<super::DeploymentPersistenceLease>,
    #[cfg(test)]
    gate: Option<Arc<CaptureTestGate>>,
    /// Test-only park point before the policy read lease and `BEGIN
    /// IMMEDIATE`. Distinct from `gate` (which parks inside the write
    /// transaction): a capture parked here holds no lease and no write lock,
    /// so a strict policy update can install while it waits.
    #[cfg(test)]
    pre_gate: Option<Arc<CaptureTestGate>>,
}

const WORK_OVERLAP_EMISSION_KIND: &str = "work_overlap_emission";
const WORK_OVERLAP_EMISSION_VERSION: u8 = 1;

/// Produce the bounded, privacy-safe evidence for a notice that the result
/// actually disclosed.  This deliberately reads only record ids and counts
/// from the already-shaped response: holder account/intent/run/timestamp
/// fields never cross the read-log boundary.
fn work_overlap_result_annotation(kind: ToolKind, result: &Value) -> Option<String> {
    let (surface, anchors) = match kind {
        ToolKind::StartWork if string_at(result, "action") == Some("claim") => {
            let overlap = result.get("work_overlap")?;
            let anchor = overlap_annotation_anchor(string_at(result, "record_id")?, overlap)?;
            ("claim", vec![anchor])
        }
        ToolKind::CreateRecord => {
            // `work_overlap` is attached only after a fresh receipt is
            // produced.  A replay has no key, so it cannot acquire a second
            // emission simply by being captured as another call.
            let overlap = result.get("work_overlap")?;
            let anchor = overlap_annotation_anchor(string_at(result, "id")?, overlap)?;
            ("create", vec![anchor])
        }
        ToolKind::SetIntent => {
            let windows = result
                .pointer("/briefing/overlapping_claims/items")?
                .as_array()?;
            let anchors = windows
                .iter()
                .map(|window| {
                    overlap_annotation_anchor(
                        string_at(window, "record_id")?,
                        window.get("overlap")?,
                    )
                })
                .collect::<Option<Vec<_>>>()?;
            if anchors.is_empty() {
                return None;
            }
            ("set_intent", anchors)
        }
        _ => return None,
    };
    serde_json::to_string(&serde_json::json!({
        "kind": WORK_OVERLAP_EMISSION_KIND,
        "version": WORK_OVERLAP_EMISSION_VERSION,
        "surface": surface,
        "anchors": anchors,
    }))
    .ok()
}

fn overlap_annotation_anchor(record_id: &str, overlap: &Value) -> Option<Value> {
    let items = overlap.get("items")?.as_array()?;
    let overlap_record_ids = items
        .iter()
        .map(|item| string_at(item, "record_id").map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let overlap_total_count = overlap.get("total_count")?.as_u64()?;
    let truncated = overlap.get("truncated")?.as_bool()?;
    if overlap_record_ids.is_empty()
        || overlap_total_count < overlap_record_ids.len() as u64
        || truncated != (overlap_total_count > overlap_record_ids.len() as u64)
    {
        return None;
    }
    Some(serde_json::json!({
        "record_id": record_id,
        "overlap_record_ids": overlap_record_ids,
        "overlap_item_count": overlap_record_ids.len(),
        "overlap_total_count": overlap_total_count,
        "truncated": truncated,
    }))
}

#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct CaptureTestGate {
    entered: Notify,
    release: Notify,
    completed: Notify,
}

#[cfg(test)]
impl CaptureTestGate {
    pub(crate) async fn wait_until_entered(&self) {
        self.entered.notified().await;
    }

    pub(crate) fn release(&self) {
        self.release.notify_one();
    }

    pub(crate) async fn wait_until_completed(&self) {
        self.completed.notified().await;
    }
}

#[cfg(test)]
tokio::task_local! {
    static CAPTURE_TEST_GATE: Arc<CaptureTestGate>;
}

#[cfg(test)]
pub(crate) async fn with_capture_test_gate<F>(gate: Arc<CaptureTestGate>, future: F) -> F::Output
where
    F: std::future::Future,
{
    CAPTURE_TEST_GATE.scope(gate, future).await
}

#[cfg(test)]
tokio::task_local! {
    static CAPTURE_PRE_POLICY_GATE: Arc<CaptureTestGate>;
}

/// Test-only scope for the pre-admission park point: the capture waits before
/// taking the policy read lease or beginning its write, holding neither.
/// Never mixed with [`with_capture_test_gate`] on the same request; the two
/// park points are distinct by construction.
#[cfg(test)]
pub(crate) async fn with_capture_pre_policy_gate<F>(
    gate: Arc<CaptureTestGate>,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    CAPTURE_PRE_POLICY_GATE.scope(gate, future).await
}

/// Depth of the per-handle capture queue. Bounded so a stalled writer cannot
/// grow memory without limit: beyond this many queued captures new work is
/// refused and counted, never awaited by the response path.
pub(crate) const CAPTURE_QUEUE_DEPTH: usize = 512;

/// Total time `Db::close` waits for queued captures before closing the pools.
/// Each capture also carries its own [`CAPTURE_BUDGET`]; this caps the
/// shutdown path when the queue is deep.
pub(crate) const CAPTURE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Monotonic counters for one handle's capture queue. Queue counters are
/// queue-only: once settled `enqueued == completed` and `failed <= completed`.
/// Declarations bypass the queue entirely and use the separate
/// `declarations_*` counters, so a declaration completing after shutdown can
/// never satisfy the queue shutdown frontier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CaptureStats {
    pub enqueued: u64,
    pub completed: u64,
    pub failed: u64,
    pub dropped_full: u64,
    pub dropped_shutdown: u64,
    pub declarations_completed: u64,
    pub declarations_failed: u64,
}

/// Completion accounting shared with the worker. Deliberately separate from
/// [`CaptureQueue`] (and holding no sender): the worker must not own the
/// queue, or the channel could never close and every handle would leak.
struct CaptureWorkerState {
    completed: AtomicU64,
    failed: AtomicU64,
    settled: Notify,
}

/// Bounded FIFO capture queue owned by one open handle (clones share it). A
/// single worker executes captures in enqueue order, so at most one capture
/// holds a write-pool slot at a time and global insertion order is preserved.
/// Failures and drops are counted and reported to stderr with a stable
/// prefix; they never fail the call that produced them.
pub(crate) struct CaptureQueue {
    sender: mpsc::Sender<PendingCapture>,
    shutdown: AtomicBool,
    /// Serializes admission, the send, and accepted accounting against
    /// `initiate_shutdown`, so the shutdown frontier provably includes every
    /// accepted capture. Held only across synchronous channel operations,
    /// never across an await.
    admission: std::sync::Mutex<()>,
    depth: usize,
    enqueued: AtomicU64,
    dropped_full: AtomicU64,
    dropped_shutdown: AtomicU64,
    declarations_completed: AtomicU64,
    declarations_failed: AtomicU64,
    worker: Arc<CaptureWorkerState>,
}

impl std::fmt::Debug for CaptureQueue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureQueue")
            .field("stats", &self.stats())
            .field("shutdown", &self.shutdown.load(Ordering::Relaxed))
            .finish()
    }
}

impl CaptureQueue {
    pub(crate) fn spawn() -> Arc<Self> {
        Self::with_depth(CAPTURE_QUEUE_DEPTH)
    }

    fn with_depth(depth: usize) -> Arc<Self> {
        let depth = depth.max(1);
        let (sender, receiver) = mpsc::channel(depth);
        let queue = Arc::new(Self {
            sender,
            shutdown: AtomicBool::new(false),
            admission: std::sync::Mutex::new(()),
            depth,
            enqueued: AtomicU64::new(0),
            dropped_full: AtomicU64::new(0),
            dropped_shutdown: AtomicU64::new(0),
            declarations_completed: AtomicU64::new(0),
            declarations_failed: AtomicU64::new(0),
            worker: Arc::new(CaptureWorkerState {
                completed: AtomicU64::new(0),
                failed: AtomicU64::new(0),
                settled: Notify::new(),
            }),
        });
        tokio::spawn({
            let worker = Arc::clone(&queue.worker);
            async move { drive_captures(receiver, worker).await }
        });
        queue
    }

    /// Enqueue one prepared capture without blocking. Admission, the send,
    /// and accepted accounting happen under one short mutex, so a capture
    /// accepted before shutdown is always inside the shutdown frontier and a
    /// capture refused by shutdown never is. Returns false (counted and
    /// stderr-reported) when shut down or full.
    pub(crate) fn enqueue(&self, capture: PendingCapture) -> bool {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.shutdown.load(Ordering::Acquire) {
            self.dropped_shutdown.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "interaction_capture dropped_shutdown tool={}",
                capture.tool_name
            );
            return false;
        }
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(capture) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(capture)) => {
                self.enqueued.fetch_sub(1, Ordering::Relaxed);
                self.dropped_full.fetch_add(1, Ordering::Relaxed);
                self.worker.settled.notify_waiters();
                let depth = self.depth;
                eprintln!(
                    "interaction_capture dropped_full tool={} depth={depth}",
                    capture.tool_name
                );
                false
            }
            Err(mpsc::error::TrySendError::Closed(capture)) => {
                self.enqueued.fetch_sub(1, Ordering::Relaxed);
                self.dropped_shutdown.fetch_add(1, Ordering::Relaxed);
                self.worker.settled.notify_waiters();
                eprintln!(
                    "interaction_capture dropped_shutdown tool={} reason=worker_gone",
                    capture.tool_name
                );
                false
            }
        }
    }

    pub(crate) fn stats(&self) -> CaptureStats {
        CaptureStats {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            completed: self.worker.completed.load(Ordering::Relaxed),
            failed: self.worker.failed.load(Ordering::Relaxed),
            dropped_full: self.dropped_full.load(Ordering::Relaxed),
            dropped_shutdown: self.dropped_shutdown.load(Ordering::Relaxed),
            declarations_completed: self.declarations_completed.load(Ordering::Relaxed),
            declarations_failed: self.declarations_failed.load(Ordering::Relaxed),
        }
    }

    fn settled_now(&self) -> bool {
        let stats = self.stats();
        stats.completed >= stats.enqueued
    }

    /// Wait until every accepted capture has completed. Returns immediately
    /// when settled. Unbounded on its own; `close` applies the shutdown cap.
    pub(crate) async fn drain(&self) {
        loop {
            let notified = self.worker.settled.notified();
            if self.settled_now() {
                return;
            }
            notified.await;
        }
    }

    /// Drain after shutdown against a stable frontier: `initiate_shutdown`
    /// ran first under the same admission mutex, so `enqueued` can no longer
    /// move and every accepted capture is inside this snapshot. The worker
    /// runs each one exactly once (panics included), so the frontier is
    /// always reachable and the wait always terminates.
    pub(crate) async fn drain_after_shutdown(&self) {
        let frontier = {
            let _admission = self
                .admission
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.enqueued.load(Ordering::Relaxed)
        };
        loop {
            let notified = self.worker.settled.notified();
            if self.worker.completed.load(Ordering::Relaxed) >= frontier {
                return;
            }
            notified.await;
        }
    }

    pub(crate) async fn drain_capped(&self) {
        if tokio::time::timeout(CAPTURE_DRAIN_TIMEOUT, self.drain_after_shutdown())
            .await
            .is_err()
        {
            let stats = self.stats();
            eprintln!(
                "interaction_capture drain_timeout pending={} enqueued={} completed={} failed={} dropped_full={} dropped_shutdown={}",
                stats.enqueued.saturating_sub(stats.completed),
                stats.enqueued,
                stats.completed,
                stats.failed,
                stats.dropped_full,
                stats.dropped_shutdown
            );
        }
    }

    pub(crate) fn initiate_shutdown(&self) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.shutdown.store(true, Ordering::Release);
    }

    /// Run one semantic declaration to durability in an owned task and await
    /// it. The declaration bypasses the lossy queue (which can refuse work
    /// when full or shut down), but like the queue path it never executes on
    /// the cancellable transport task: dropping the awaiting request drops
    /// only this `JoinHandle`, and the declaration still lands. Accounting is
    /// deliberately separate from the queue frontier: declarations increment
    /// only `declarations_*`, so a declaration completing after shutdown can
    /// never satisfy `drain_after_shutdown`'s queue-only frontier early.
    pub(crate) async fn record_declaration(self: &Arc<Self>, capture: PendingCapture) {
        let task = tokio::spawn({
            let this = Arc::clone(self);
            async move { execute_declaration(capture, this).await }
        });
        if task.await.is_err() {
            // `execute_declaration` guards its own panics, so this is the
            // spawn machinery itself failing. Count it on the declaration
            // ledger, never on the queue frontier.
            self.declarations_failed.fetch_add(1, Ordering::Relaxed);
            self.declarations_completed.fetch_add(1, Ordering::Relaxed);
            eprintln!("interaction_capture declaration task failed");
        }
    }
}

async fn drive_captures(
    mut receiver: mpsc::Receiver<PendingCapture>,
    worker: Arc<CaptureWorkerState>,
) {
    while let Some(capture) = receiver.recv().await {
        execute_capture(capture, Arc::clone(&worker)).await;
    }
}

/// Execute one queued capture with panic guard and queue-only completion
/// accounting. A panicking capture is counted and reported and never takes
/// the worker down with it; every accepted queued capture completes exactly
/// once, which is what the shutdown frontier waits on.
async fn execute_capture(capture: PendingCapture, worker: Arc<CaptureWorkerState>) {
    #[cfg(test)]
    let completed_gate = capture.gate.clone();
    // `FutureExt` runs the future to completion inside the `catch_unwind`
    // boundary, so an async panic is caught here rather than unwinding the
    // worker.
    let outcome = AssertUnwindSafe(perform_capture(capture))
        .catch_unwind()
        .await;
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(message)) => {
            worker.failed.fetch_add(1, Ordering::Relaxed);
            eprintln!("{message}");
        }
        Err(_) => {
            worker.failed.fetch_add(1, Ordering::Relaxed);
            eprintln!("interaction_capture panicked");
        }
    }
    worker.completed.fetch_add(1, Ordering::Relaxed);
    worker.settled.notify_waiters();
    #[cfg(test)]
    if let Some(gate) = completed_gate {
        gate.completed.notify_one();
    }
}

/// Execute one semantic declaration with panic guard and declaration-only
/// accounting. Never touches the queue's `completed`/`failed`, so the queue
/// shutdown frontier stays queue-only.
async fn execute_declaration(capture: PendingCapture, queue: Arc<CaptureQueue>) {
    #[cfg(test)]
    let completed_gate = capture.gate.clone();
    let outcome = AssertUnwindSafe(perform_capture(capture))
        .catch_unwind()
        .await;
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(message)) => {
            queue.declarations_failed.fetch_add(1, Ordering::Relaxed);
            eprintln!("{message}");
        }
        Err(_) => {
            queue.declarations_failed.fetch_add(1, Ordering::Relaxed);
            eprintln!("interaction_capture panicked");
        }
    }
    queue.declarations_completed.fetch_add(1, Ordering::Relaxed);
    #[cfg(test)]
    if let Some(gate) = completed_gate {
        gate.completed.notify_one();
    }
}

/// Run one capture write under its budget, returning the stderr-ready outcome.
/// Shared by the queue worker and the declaration path; accounting stays with
/// the caller so the two lifecycles never mix.
async fn perform_capture(capture: PendingCapture) -> std::result::Result<(), String> {
    #[cfg(test)]
    if let Some(pre_gate) = &capture.pre_gate {
        pre_gate.entered.notify_one();
        pre_gate.release.notified().await;
    }
    let tool = capture.tool_name.clone();
    let operation = capture.tool_name.clone();
    let capability = capture.interaction_capability.clone();
    let db = capture.db.clone();
    let budgeted = tokio::time::timeout(
        CAPTURE_BUDGET,
        crate::storage_profile::with_capture_operation(
            &db,
            &operation,
            capability.as_deref(),
            record_call(capture),
        ),
    )
    .await;
    match budgeted {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!(
            "interaction_capture failed tool={tool} error={error}"
        )),
        Err(_) => Err(format!(
            "interaction_capture timeout tool={tool} budget_ms={}",
            CAPTURE_BUDGET.as_millis()
        )),
    }
}

/// Own execution budget for one background capture: the 15 s `BEGIN IMMEDIATE`
/// retry plus inserts and commit must fit inside this, or the capture is
/// counted failed and the single worker moves on. A stuck capture must not
/// wedge the queue behind it.
pub(crate) const CAPTURE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Prepare best-effort capture and hand it to the handle's bounded background
/// queue, returning immediately. The response path never awaits the capture
/// write: a slow or blocked writer delays only later captures, never the
/// caller. Returns false when the queue refused the job (full or shut down);
/// the drop is counted on the handle and reported to stderr there. A `true`
/// return with nothing enqueued means there was nothing to capture
/// (uncapturable serialization), not a successful write — durability is only
/// observable via [`crate::db::Db::capture_stats`] and `drain_captures`.
///
/// Authorization context is snapshotted into owned strings at enqueue time
/// (credential actor, validated run/parent keys, arguments JSON), so the
/// background write carries exactly what the request saw. The deployment
/// persistence lease travels with the job, so a deployment freeze still
/// drains in-flight captures rather than cutting them off.
///
/// Semantic declarations (`set_intent`) never take this path: see
/// [`record_declaration_call`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn enqueue_record_call(
    db: &Db,
    extractor: Extractor,
    tool_name: &str,
    caller: &Caller,
    original_arguments: &Value,
    run_context: &Value,
    outcome: std::result::Result<&Value, &Error>,
    started_at: &str,
    ended_at: &str,
    interaction_capability: Option<&str>,
    deployment_persistence_lease: Option<super::DeploymentPersistenceLease>,
) -> bool {
    let Some(capture) = prepare_capture(
        db,
        extractor,
        tool_name,
        caller,
        original_arguments,
        run_context,
        outcome,
        started_at,
        ended_at,
        interaction_capability,
        deployment_persistence_lease,
    ) else {
        // Unserializable arguments mean there is no envelope to persist.
        // Report enqueue success: no work was lost, there was no work.
        return true;
    };
    // The test gate (if any) was read on this task before the handoff; the
    // queue worker never observes task-locals.
    db.enqueue_capture(capture)
}

/// Run one semantic declaration (`set_intent`) to durability in an owned
/// task, bypassing the lossy queue entirely. The queue can refuse work when
/// full or shut down, and a global drain can stall behind continuous
/// traffic — either would leave an acknowledged intent silently absent, the
/// exact failure the declaration exception exists to prevent. This path has
/// neither property: admission is guaranteed and latency is only the
/// declaration's own write under [`CAPTURE_BUDGET`]. Dropping the awaiting
/// request drops only the task handle, not the declaration.
///
/// Fail-open like the queue: a failed declaration is counted and reported,
/// never raised to the caller. Ordering note: the declaration may sequence
/// ahead of earlier-queued ordinary captures. Consumers do not rely on
/// insertion order across the two paths: episode evidence compares each
/// read's request `started_at` against the declaration's `ended_at` (the
/// boundary `seq` is identity exclusion only), and declaration lookup orders
/// declarations by their own timestamps.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_declaration_call(
    db: &Db,
    extractor: Extractor,
    tool_name: &str,
    caller: &Caller,
    original_arguments: &Value,
    run_context: &Value,
    outcome: std::result::Result<&Value, &Error>,
    started_at: &str,
    ended_at: &str,
    interaction_capability: Option<&str>,
    deployment_persistence_lease: Option<super::DeploymentPersistenceLease>,
) {
    let Some(capture) = prepare_capture(
        db,
        extractor,
        tool_name,
        caller,
        original_arguments,
        run_context,
        outcome,
        started_at,
        ended_at,
        interaction_capability,
        deployment_persistence_lease,
    ) else {
        return;
    };
    db.record_declaration(capture).await;
}

/// Build the owned capture envelope for one finished call, snapshotting the
/// authorization context (credential actor, validated run/parent keys,
/// arguments JSON) on the calling task. `None` means unserializable
/// arguments: there is no envelope to persist.
#[allow(clippy::too_many_arguments)]
fn prepare_capture(
    db: &Db,
    extractor: Extractor,
    tool_name: &str,
    caller: &Caller,
    original_arguments: &Value,
    run_context: &Value,
    outcome: std::result::Result<&Value, &Error>,
    started_at: &str,
    ended_at: &str,
    interaction_capability: Option<&str>,
    deployment_persistence_lease: Option<super::DeploymentPersistenceLease>,
) -> Option<PendingCapture> {
    let extraction = match (extractor, outcome) {
        (Extractor::Shipped(kind), Ok(result)) => extract(kind, original_arguments, result),
        (Extractor::Custom(CustomInteractionPolicy::NoRecordInteractions), Ok(_)) => {
            Extraction::success()
        }
        // A failed handler produced no record result.  The attempted ids remain
        // verbatim in `arguments`; claiming they were opened or mutated would
        // turn an attempt into an interaction that did not happen.
        (_, Err(_)) => Extraction::default(),
    };
    let result_annotation = match (extractor, outcome) {
        (Extractor::Shipped(kind), Ok(result)) => work_overlap_result_annotation(kind, result),
        _ => None,
    };
    let arguments = match serde_json::to_string(&captured_arguments(extractor, original_arguments))
    {
        Ok(arguments) => arguments,
        Err(_) => return None,
    };
    // Only a successfully handled `set_intent` call is a declaration. Other
    // tools may happen to have an argument named `intent`, and a rejected
    // declaration must remain an attempt rather than becoming current state.
    let intent = match (extractor, outcome) {
        (Extractor::Shipped(ToolKind::SetIntent), Ok(_)) => original_arguments
            .get("intent")
            .and_then(Value::as_str)
            .map(String::from),
        _ => None,
    };
    let (outcome_name, error) = match outcome {
        Ok(_) => ("ok", None),
        Err(error) => ("error", Some(error_kind(error))),
    };
    let capture = PendingCapture {
        db: db.clone(),
        tool_name: tool_name.to_string(),
        interaction_capability: interaction_capability.map(str::to_string),
        run_key: caller.run_key().map(String::from),
        parent_key: caller.parent_key().map(String::from),
        intent,
        actor: caller.actor().to_string(),
        arguments,
        outcome_name,
        error,
        extraction,
        result_annotation,
        result_bytes: response_bytes(outcome, run_context),
        started_at: started_at.to_string(),
        ended_at: ended_at.to_string(),
        _deployment_persistence_lease: deployment_persistence_lease,
        #[cfg(test)]
        gate: CAPTURE_TEST_GATE.try_with(Arc::clone).ok(),
        #[cfg(test)]
        pre_gate: CAPTURE_PRE_POLICY_GATE.try_with(Arc::clone).ok(),
    };
    // The deployment persistence lease travels inside the capture, so a
    // deployment freeze still drains in-flight captures rather than cutting
    // them off. The test gate (if any) was read on this task before any
    // handoff; the queue worker never observes task-locals.
    Some(capture)
}

/// Atomically insert one prepared call envelope and all extracted touches.
async fn record_call(capture: PendingCapture) -> Result<()> {
    let begun = crate::db::begin_capture_write(capture.db.write_pool()).await?;
    // Success-path retry counts are intentionally unreported: capture is
    // silent on success. Only exhaustion is reported, via the error string
    // `begin_capture_write` already carries.
    let _ = begun.retry_count;
    let mut tx = begun.transaction;
    #[cfg(test)]
    if let Some(gate) = &capture.gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let inserted = sqlx::query(
        "INSERT INTO read_log_calls
         (id, tool, run_key, parent_key, intent, actor, arguments, outcome,
          error_kind, result_count, result_bytes, started_at, ended_at, result_annotation)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(capture.tool_name)
    .bind(capture.run_key)
    .bind(capture.parent_key)
    .bind(capture.intent)
    .bind(capture.actor)
    .bind(capture.arguments)
    .bind(capture.outcome_name)
    .bind(capture.error)
    .bind(capture.extraction.result_count)
    .bind(capture.result_bytes)
    .bind(capture.started_at)
    .bind(capture.ended_at)
    .bind(capture.result_annotation)
    .execute(&mut *tx)
    .await?;
    // Save the call's sequence BEFORE interning any dictionary row: once the
    // `read_log_record_ids` inserts below run, `last_insert_rowid()` reports a
    // dictionary row rather than the call we just wrote.
    let call_seq = inserted.last_insert_rowid();
    // Multi-row inserts: a read that surfaces a large folder records one touch
    // per child, and one statement round trip per touch held the write lock
    // for the whole walk. Chunked so the bind count stays well inside every
    // SQLite build's parameter limit.
    const TOUCH_INSERT_CHUNK: usize = 200;
    // Intern every distinct exact id in the SAME transaction as the call and
    // its touches. `INSERT OR IGNORE` keeps the first ref ever assigned to a
    // string, so a dangling id (one with no `records` row) still gets a home
    // and case-distinct or non-UUID ids stay distinct rows. The dictionary is
    // per database and shared across runs.
    let mut distinct_ids = capture
        .extraction
        .touches
        .iter()
        .map(|touch| touch.record_id.as_str())
        .collect::<Vec<_>>();
    distinct_ids.sort_unstable();
    distinct_ids.dedup();
    for chunk in distinct_ids.chunks(TOUCH_INSERT_CHUNK) {
        let placeholders = std::iter::repeat_n("(?)", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql =
            format!("INSERT OR IGNORE INTO read_log_record_ids (record_id) VALUES {placeholders}");
        let mut statement = sqlx::query(&sql);
        for record_id in chunk {
            statement = statement.bind(*record_id);
        }
        statement.execute(&mut *tx).await?;
    }
    for chunk in capture.extraction.touches.chunks(TOUCH_INSERT_CHUNK) {
        // The reference is resolved by subquery rather than bound, so a
        // missing mapping yields NULL and trips `record_ref NOT NULL` instead
        // of silently dropping the touch.
        let placeholders = std::iter::repeat_n(
            "(?, (SELECT record_ref FROM read_log_record_ids WHERE record_id = ?), ?, ?)",
            chunk.len(),
        )
        .collect::<Vec<_>>()
        .join(", ");
        let sql = format!(
            "INSERT INTO read_log_touches
             (call_seq, record_ref, interaction, result_rank)
             VALUES {placeholders}"
        );
        let mut statement = sqlx::query(&sql);
        for touch in chunk {
            statement = statement
                .bind(call_seq)
                .bind(&touch.record_id)
                .bind(touch.interaction.as_str())
                .bind(touch.result_rank);
        }
        statement.execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn work_overlap_annotation_keeps_only_disclosed_ids_and_counts() {
        let annotation = work_overlap_result_annotation(
            ToolKind::StartWork,
            &json!({
                "record_id": "anchor",
                "action": "claim",
                "work_overlap": {
                    "items": [{
                        "record_id": "overlap",
                        "holder_tier": "another_principal",
                        "intent": "must never be retained",
                        "run_key": "must-never-be-retained",
                        "claimed_at": "must-never-be-retained"
                    }],
                    "total_count": 2,
                    "truncated": true
                }
            }),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&annotation).unwrap(),
            json!({
                "kind": "work_overlap_emission",
                "version": 1,
                "surface": "claim",
                "anchors": [{
                    "record_id": "anchor",
                    "overlap_record_ids": ["overlap"],
                    "overlap_item_count": 1,
                    "overlap_total_count": 2,
                    "truncated": true
                }]
            })
        );
        assert!(!annotation.contains("another_principal"));
        assert!(!annotation.contains("must-never-be-retained"));
    }

    #[test]
    fn work_overlap_annotation_requires_the_eligible_notice_surface() {
        let overlap = json!({
            "items": [{"record_id": "overlap"}],
            "total_count": 1,
            "truncated": false
        });
        assert!(work_overlap_result_annotation(
            ToolKind::StartWork,
            &json!({"record_id":"anchor","action":"preview","work_overlap":overlap})
        )
        .is_none());
        assert!(work_overlap_result_annotation(
            ToolKind::SetIntent,
            &json!({"briefing":{"overlapping_claims":{"items":[]}}})
        )
        .is_none());
    }

    #[test]
    fn set_intent_overlap_annotation_is_all_or_nothing_across_anchors() {
        let valid_window = json!({
            "items": [{"record_id": "overlap"}],
            "total_count": 1,
            "truncated": false
        });
        assert!(work_overlap_result_annotation(
            ToolKind::SetIntent,
            &json!({"briefing":{"overlapping_claims":{"items":[
                {"record_id":"valid-anchor","overlap":valid_window},
                {"record_id":"malformed-anchor","overlap":{"items":[]}}
            ]}}})
        )
        .is_none());
    }

    #[test]
    fn reach_capture_keeps_only_valid_routing_metadata() {
        assert_eq!(
            captured_arguments(
                Extractor::Shipped(ToolKind::ReachRead),
                &json!({
                    "action":"search_slack",
                    "query":"private query",
                    "token":"private token",
                    "limit":5
                })
            ),
            json!({"action":"search_slack"})
        );
        assert_eq!(
            captured_arguments(
                Extractor::Shipped(ToolKind::ReachRead),
                &json!({"action":"private invalid action", "query":"private query"})
            ),
            json!({})
        );
        assert_eq!(
            captured_arguments(
                Extractor::Shipped(ToolKind::ReachConnect),
                &json!({"provider":"slack", "token":"private token"})
            ),
            json!({"provider":"slack"})
        );
        assert_eq!(
            captured_arguments(
                Extractor::Shipped(ToolKind::ReachConnect),
                &json!({"provider":"private invalid provider", "token":"private token"})
            ),
            json!({})
        );
    }

    #[test]
    fn authoritative_policy_is_exhaustive_and_mixed_actions_fail_closed() {
        for kind in ToolKind::ALL {
            let disposition = kind.authoritative_disposition();
            assert_eq!(
                disposition.has_read_operation(),
                !matches!(disposition, AuthoritativeDisposition::Mutation),
                "{}",
                kind.name()
            );
            assert_eq!(disposition, kind.standby_disposition());
        }

        let links = ToolKind::ManageLinks.standby_disposition();
        assert!(links.admits(&json!({"action":"list"})));
        for arguments in [
            json!({"action":"add"}),
            json!({"action":"future_read_like_name"}),
            json!({"action":7}),
            json!({}),
        ] {
            assert!(!links.admits(&arguments));
        }
        assert!(!ToolKind::CreateRecord
            .standby_disposition()
            .admits(&json!({"malformed":"arguments never reach parsing"})));
    }

    #[test]
    fn reach_read_is_observational_and_reach_connect_is_a_mutation() {
        assert_eq!(
            ToolKind::ReachRead.authoritative_disposition(),
            AuthoritativeDisposition::Read
        );
        assert_eq!(
            ToolKind::ReachConnect.authoritative_disposition(),
            AuthoritativeDisposition::Mutation
        );
        // Consent-ticket minting must never ride the read executor, even
        // though both tools are hosted-only and undiscoverable when focused.
        assert!(!ToolKind::ReachRead
            .exposure()
            .shown_in(ExposureProfile::Focused));
        assert!(!ToolKind::ReachConnect
            .exposure()
            .shown_in(ExposureProfile::Focused));
        assert!(ToolKind::ReachRead
            .exposure()
            .shown_in(ExposureProfile::Complete));
    }

    fn surfaced(id: &str, rank: i64) -> Touch {
        Touch {
            record_id: id.into(),
            interaction: Interaction::Surfaced,
            result_rank: Some(rank),
        }
    }

    fn opened(id: &str) -> Touch {
        Touch {
            record_id: id.into(),
            interaction: Interaction::Opened,
            result_rank: None,
        }
    }

    fn mutated(id: &str) -> Touch {
        Touch {
            record_id: id.into(),
            interaction: Interaction::Mutated,
            result_rank: None,
        }
    }

    fn enriched(id: &str) -> Value {
        json!({
            "id": id,
            "children": [{ "id": "child" }],
            "ancestors": [{ "id": "ancestor" }],
            "links_out": [{ "target_id": "out-target" }],
            "links_in": [{ "source_id": "in-source" }],
        })
    }

    struct Case {
        name: &'static str,
        kind: ToolKind,
        arguments: Value,
        result: Value,
        touches: Vec<Touch>,
        result_count: Option<i64>,
    }

    #[test]
    fn bootstrap_only_opens_instruction_sources_tagged_as_records() {
        let result = json!({
            "roots": { "items": [] },
            "instructions": { "entries": [
                { "source": { "type": "record", "record_id": "portable-source" } },
                { "source": { "type": "engine", "record_id": "engine-record-trap" } },
                { "source": { "type": "future", "record_id": "unknown-record-trap" } },
                { "source": { "type": 7, "record_id": "malformed-record-trap" } },
                { "source": { "record_id": "missing-tag-record-trap" } }
            ] }
        });

        let extraction = extract(ToolKind::Bootstrap, &json!({}), &result);

        assert_eq!(extraction.touches, vec![opened("portable-source")]);
    }

    #[test]
    fn bootstrap_surfaces_private_root_and_reusable_starting_context() {
        let result = json!({
            "roots":{"items":[{"id":"workspace-root"}]},
            "instructions":{"entries":[]},
            "principal":{"private_context":{
                "root_record_id":"private-root",
                "starting_context_contract":{"existing_note_id":"starting-context"}
            }}
        });
        let extraction = extract(ToolKind::Bootstrap, &json!({}), &result);
        assert_eq!(
            extraction.touches,
            vec![
                surfaced("workspace-root", 1),
                surfaced("private-root", 2),
                surfaced("starting-context", 3),
            ]
        );
        assert_eq!(extraction.result_count, Some(3));
    }

    #[test]
    fn bootstrap_surfaces_written_or_deferred_progress_artifacts_after_contract_sanitization() {
        let result = json!({
            "roots":{"items":[]},
            "instructions":{"entries":[]},
            "principal":{"private_context":{
                "root_record_id":"private-root",
                "starting_context_contract":{"mode":"already_written"}
            }},
            "pending_obligations":[
                {"progress_phase":"artifact_written","progress_artifact_id":"starting-context"},
                {"progress_phase":"deferred","progress_artifact_id":"starting-context"}
            ]
        });

        let extraction = extract(ToolKind::Bootstrap, &json!({}), &result);

        assert_eq!(
            extraction.touches,
            vec![surfaced("private-root", 1), surfaced("starting-context", 2),]
        );
        assert_eq!(extraction.result_count, Some(2));
    }

    #[test]
    fn onboarding_written_progress_opens_the_linked_artifact() {
        let extraction = extract(
            ToolKind::ManageOnboarding,
            &json!({"action":"record_progress","phase":"artifact_written"}),
            &json!({"artifact_id":"starting-context"}),
        );
        assert_eq!(extraction.touches, vec![opened("starting-context")]);
        assert_eq!(extraction.result_count, Some(1));
    }

    #[test]
    fn quickstart_static_launcher_has_no_record_interactions() {
        let result = json!({"contract":{"id":"native.quickstart.v1"}});

        let extraction = extract(ToolKind::Quickstart, &json!({}), &result);

        assert!(extraction.touches.is_empty());
        assert_eq!(extraction.result_count, Some(0));
    }

    /// Semantic policy table for the whole registry.
    ///
    /// This is deliberately direct coverage of the private extractor rather
    /// than a handler fixture suite: every row says what a representative
    /// payload MEANS, independent of the database setup needed to produce it.
    /// The final coverage assertion makes adding a ToolKind without a policy
    /// row fail even after the exhaustive production match has been updated.
    #[test]
    fn every_tool_kind_has_a_pinned_interaction_policy() {
        let mut cases = vec![
            Case {
                name: "ping has no record result",
                kind: ToolKind::Ping,
                arguments: json!({}),
                result: json!({ "ok": true }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "engine_info has no record result",
                kind: ToolKind::EngineInfo,
                arguments: json!({}),
                result: json!({ "engine": "native-ce" }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "standby_status has no record result",
                kind: ToolKind::StandbyStatus,
                arguments: json!({}),
                result: json!({ "contract": "native.standby-status.v1" }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "read_guide returns compiled guidance, not record results",
                kind: ToolKind::ReadGuide,
                arguments: json!({ "topic": "capabilities" }),
                result: json!({ "topic": "capabilities", "markdown": "# MCP capabilities" }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "export_snapshot returns bytes, not record results",
                kind: ToolKind::ExportSnapshot,
                arguments: json!({}),
                result: json!({ "export_id": "opaque", "data_base64": "AA==" }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "reach search counts provider results without Native record touches",
                kind: ToolKind::ReachRead,
                arguments: json!({ "action": "search_slack", "query": "release" }),
                result: json!({ "results": [{ "id": "external-message", "record_id": "not-native" }] }),
                touches: vec![],
                result_count: Some(1),
            },
            Case {
                name: "reach recency counts external candidates without Native record touches",
                kind: ToolKind::ReachRead,
                arguments: json!({ "action": "recent_activity", "source": "notion" }),
                result: json!({ "candidates": [{ "id": "external-page" }] }),
                touches: vec![],
                result_count: Some(1),
            },
            Case {
                name: "reach status counts sources without Native record touches",
                kind: ToolKind::ReachRead,
                arguments: json!({ "action": "source_status" }),
                result: json!({ "sources": [{ "provider": "slack" }, { "provider": "notion" }, { "provider": "linear" }] }),
                touches: vec![],
                result_count: Some(3),
            },
            Case {
                name: "reach consent counts the ticket without Native record touches",
                kind: ToolKind::ReachConnect,
                arguments: json!({ "provider": "notion" }),
                result: json!({ "provider": "notion", "consent_url": "https://reach.example/connect/notion?ticket=fixture" }),
                touches: vec![],
                result_count: Some(1),
            },
            Case {
                name: "bootstrap surfaces roots and opens fully inlined instruction sources",
                kind: ToolKind::Bootstrap,
                arguments: json!({}),
                result: json!({
                    "roots": { "items": [{ "id": "a" }, { "id": "b" }] },
                    "instructions": { "entries": [{ "source": {
                        "type": "record", "record_id": "instructions"
                    } }] }
                }),
                touches: vec![surfaced("a", 1), surfaced("b", 2), opened("instructions")],
                result_count: Some(2),
            },
            Case {
                name: "quickstart static launcher has no record interactions",
                kind: ToolKind::Quickstart,
                arguments: json!({}),
                result: json!({"contract":{"id":"native.quickstart.v1"}}),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "set_intent has an explicit no-touch policy",
                kind: ToolKind::SetIntent,
                arguments: json!({ "intent": "Review the work." }),
                result: json!({ "accepted_intent": "Review the work." }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "close_run has an explicit no-touch policy",
                kind: ToolKind::CloseRun,
                arguments: json!({}),
                result: json!({ "activity_id": "activity", "changed": true }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "get_structure surfaces the returned tree",
                kind: ToolKind::GetStructure,
                arguments: json!({ "root_id": "root" }),
                result: json!({ "nodes": [{ "id": "root" }, { "id": "child" }] }),
                touches: vec![surfaced("root", 1), surfaced("child", 2)],
                result_count: Some(2),
            },
            Case {
                name: "get_dashboard deduplicates records across buckets",
                kind: ToolKind::GetDashboard,
                arguments: json!({}),
                result: json!({
                    "active": [{ "id": "active" }],
                    "stale": [{ "id": "stale" }],
                    "blocked": [{
                        "id": "blocked",
                        "blocked_by": [{ "id": "blocker" }],
                        "waiting_on": [{ "id": "active" }],
                    }],
                    // A census entry that is also in `active` must not be
                    // counted twice, and one beyond the bucket window must
                    // still be surfaced.
                    "unclassified_lifecycle": {
                        "items": [
                            { "id": "active", "reason": "no_governing_vocabulary" },
                            { "id": "unclassified", "reason": "no_governing_vocabulary" },
                        ],
                        "total_count": 2,
                    },
                }),
                touches: vec![
                    surfaced("active", 1),
                    surfaced("stale", 2),
                    surfaced("blocked", 3),
                    surfaced("blocker", 4),
                    surfaced("unclassified", 5),
                ],
                result_count: Some(5),
            },
            Case {
                name: "describe_schema counts tables but touches no records",
                kind: ToolKind::DescribeSchema,
                arguments: json!({}),
                result: json!({ "tables": [{ "name": "records" }, { "name": "links" }] }),
                touches: vec![],
                result_count: Some(2),
            },
            Case {
                name: "preview_record_shape counts one schema result but touches no records",
                kind: ToolKind::PreviewRecordShape,
                arguments: json!({ "type": "Document", "kind": "note" }),
                result: json!({
                    "schema": "native.record_shape_preview.v1",
                    "selection": { "type": "Document", "kind": "note" },
                }),
                touches: vec![],
                result_count: Some(1),
            },
            Case {
                name: "create_record mutates root and surfaces flattened enrichment",
                kind: ToolKind::CreateRecord,
                arguments: json!({ "type": "Document" }),
                result: enriched("created"),
                touches: vec![
                    mutated("created"),
                    surfaced("child", 1),
                    surfaced("ancestor", 2),
                    surfaced("out-target", 3),
                    surfaced("in-source", 4),
                ],
                result_count: Some(1),
            },
            Case {
                name: "create_many keeps positional result count and mutates successful ids",
                kind: ToolKind::CreateMany,
                arguments: json!({}),
                result: json!({ "ids": ["first", null, "third"] }),
                touches: vec![mutated("first"), mutated("third")],
                result_count: Some(3),
            },
            Case {
                name: "get_record opens found roots and surfaces enrichment",
                kind: ToolKind::GetRecord,
                arguments: json!({ "ids": ["opened", "missing"] }),
                result: json!({
                    "records": [
                        {
                            "status": "found",
                            "id": "opened",
                            "children": [{ "id": "child" }],
                            "ancestors": [{ "id": "ancestor" }],
                            "links_out": [{ "target_id": "out-target" }],
                            "links_in": [{ "source_id": "in-source" }],
                        },
                        { "status": "not_found", "id": "missing" },
                    ],
                }),
                touches: vec![
                    opened("opened"),
                    surfaced("child", 1),
                    surfaced("ancestor", 2),
                    surfaced("out-target", 3),
                    surfaced("in-source", 4),
                ],
                result_count: Some(1),
            },
            Case {
                name: "update_record mutates root and surfaces flattened enrichment",
                kind: ToolKind::UpdateRecord,
                arguments: json!({ "id": "updated" }),
                result: enriched("updated"),
                touches: vec![
                    mutated("updated"),
                    surfaced("child", 1),
                    surfaced("ancestor", 2),
                    surfaced("out-target", 3),
                    surfaced("in-source", 4),
                ],
                result_count: Some(1),
            },
            Case {
                name: "multi update_record mutates only changed positional outcomes",
                kind: ToolKind::UpdateRecord,
                arguments: json!({ "ids": ["changed", "same"] }),
                result: json!({
                    "requested":2,
                    "changed":1,
                    "unchanged":1,
                    "results":[
                        {"index":0,"id":"changed","status":"changed"},
                        {"index":1,"id":"same","status":"unchanged"}
                    ]
                }),
                touches: vec![mutated("changed")],
                result_count: Some(2),
            },
            Case {
                name: "claim_unowned_record mutates its claimed target",
                kind: ToolKind::ClaimUnownedRecord,
                arguments: json!({ "record_id": "claimed", "reason": "Recovery" }),
                result: json!({ "id": "claimed", "owner_id": "person" }),
                touches: vec![mutated("claimed")],
                result_count: Some(1),
            },
            Case {
                name: "correct_record_type mutates its governed target",
                kind: ToolKind::CorrectRecordType,
                arguments: json!({
                    "record_id": "corrected",
                    "target_type": "Resolution",
                    "target_kind": "decision",
                }),
                result: json!({ "record_id": "corrected", "type": "Resolution", "kind": "decision" }),
                touches: vec![mutated("corrected")],
                result_count: Some(1),
            },
            Case {
                name: "delete_record mutates its target",
                kind: ToolKind::DeleteRecord,
                arguments: json!({ "id": "deleted" }),
                result: json!({ "id": "deleted", "deleted": true }),
                touches: vec![mutated("deleted")],
                result_count: Some(1),
            },
            Case {
                name: "archive_record changed response mutates its target",
                kind: ToolKind::ArchiveRecord,
                arguments: json!({ "id": "archived" }),
                result: json!({ "id": "archived", "changed": true }),
                touches: vec![mutated("archived")],
                result_count: Some(1),
            },
            Case {
                name: "render_record pins opened-only policy for markdown",
                kind: ToolKind::RenderRecord,
                arguments: json!({ "id": "rendered" }),
                result: json!({
                    "id": "rendered",
                    "markdown": "references `related`, but markdown is not a typed record result",
                }),
                touches: vec![opened("rendered")],
                result_count: Some(1),
            },
            Case {
                name: "get_history opens explicit root and surfaces event subjects",
                kind: ToolKind::GetHistory,
                arguments: json!({ "record_id": "history-root" }),
                result: json!({
                    "events": [
                        { "record_id": "history-root" },
                        { "record_id": "other" },
                    ],
                }),
                touches: vec![
                    opened("history-root"),
                    surfaced("history-root", 1),
                    surfaced("other", 2),
                ],
                result_count: Some(2),
            },
            Case {
                name: "whats_changed opens scope and surfaces grouped subjects",
                kind: ToolKind::WhatsChanged,
                arguments: json!({ "scope_record_id": "change-root" }),
                result: json!({
                    "changes": [
                        { "record_id": "change-root" },
                        { "record_id": "other" },
                    ],
                }),
                touches: vec![
                    opened("change-root"),
                    surfaced("change-root", 1),
                    surfaced("other", 2),
                ],
                result_count: Some(2),
            },
            Case {
                name: "get_run_activity reports aggregates without fabricating touches",
                kind: ToolKind::GetRunActivity,
                arguments: json!({ "for_run": "scout-chair-a748b2" }),
                result: json!({
                    "read_activity": [{
                        "run_key": "scout-chair-a748b2",
                        "parent_key": null,
                        "searches": 1,
                        "surfaced": 2,
                        "opened": 3,
                        "mutated": 4,
                    }],
                }),
                touches: vec![],
                result_count: Some(1),
            },
            Case {
                name: "render_record_version_diff opens its target",
                kind: ToolKind::RenderRecordVersionDiff,
                arguments: json!({ "record_id": "versioned", "before_seq": 1 }),
                result: json!({ "record_id": "versioned", "view": "record_version_diff" }),
                touches: vec![opened("versioned")],
                result_count: Some(1),
            },
            Case {
                name: "manage_links list opens root and surfaces endpoints",
                kind: ToolKind::ManageLinks,
                arguments: json!({ "action": "list", "record_id": "link-root" }),
                result: json!({
                    "record_id": "link-root",
                    "links_out": [{ "target_id": "out" }],
                    "links_in": [{ "source_id": "in" }],
                }),
                touches: vec![opened("link-root"), surfaced("out", 1), surfaced("in", 2)],
                result_count: Some(2),
            },
            Case {
                name: "manage_relationships read opens its endpoints",
                kind: ToolKind::ManageRelationships,
                arguments: json!({ "action": "read" }),
                result: json!({
                    "endpoints": [
                        { "record_id": "relationship-subject" },
                        { "record_id": "relationship-object" }
                    ],
                    "assertions": [{ "id": "assertion" }],
                }),
                touches: vec![
                    opened("relationship-subject"),
                    opened("relationship-object"),
                ],
                result_count: Some(1),
            },
            Case {
                name: "manage_messages history share mutates the exact resolved Message set",
                kind: ToolKind::ManageMessages,
                arguments: json!({ "action": "share_history" }),
                result: json!({ "message_ids": ["message-a", "message-b"] }),
                touches: vec![mutated("message-a"), mutated("message-b")],
                result_count: Some(1),
            },
            Case {
                name: "manage_messages send records its created Message as run activity",
                kind: ToolKind::ManageMessages,
                arguments: json!({ "action": "send" }),
                result: json!({ "id": "sent-message" }),
                touches: vec![mutated("sent-message")],
                result_count: Some(1),
            },
            Case {
                name: "manage_interventions resume mutates its Message root",
                kind: ToolKind::ManageInterventions,
                arguments: json!({ "action": "resume_delivery" }),
                result: json!({ "trigger": { "message_id": "message" } }),
                touches: vec![mutated("message")],
                result_count: Some(1),
            },
            Case {
                name: "instantiate_artifact opens only its source and mutates only its copy",
                kind: ToolKind::InstantiateArtifact,
                arguments: json!({ "source_id": "source" }),
                result: json!({
                    "id": "copy",
                    "source_id": "source",
                    "links_out": [{
                        "target_id": "source",
                        "relationship": "instantiated_from",
                    }],
                }),
                touches: vec![opened("source"), mutated("copy")],
                result_count: Some(1),
            },
            Case {
                name: "manage_renderer_binding read opens artifact and surfaces its exact input",
                kind: ToolKind::ManageRendererBinding,
                arguments: json!({ "action": "read", "artifact_id": "renderer" }),
                result: json!({
                    "artifact_id": "renderer",
                    "status": "bound",
                    "bindings": [{ "collection_id": "input", "kind": "folder", "valid": true }],
                }),
                touches: vec![opened("renderer"), surfaced("input", 1)],
                result_count: Some(1),
            },
            Case {
                name: "render_artifact opens renderer and surfaces bound input records",
                kind: ToolKind::RenderArtifact,
                arguments: json!({ "id": "renderer" }),
                result: json!({
                    "status": "rendered",
                    "artifact_id": "renderer",
                    "input": {
                        "mode": "bound",
                        "collection": { "id": "input", "kind": "folder" },
                    },
                    "plan": {
                        "lanes": [
                            { "records": [{ "id": "card-a" }] },
                            { "records": [{ "id": "card-b" }] },
                        ],
                    },
                }),
                touches: vec![
                    opened("renderer"),
                    surfaced("input", 1),
                    surfaced("card-a", 2),
                    surfaced("card-b", 3),
                ],
                result_count: Some(1),
            },
            Case {
                name: "verify_artifact opens renderer and surfaces exact verification input",
                kind: ToolKind::VerifyArtifact,
                arguments: json!({ "id": "renderer" }),
                result: json!({
                    "status": "verified",
                    "artifact_id": "renderer",
                    "input": {
                        "mode": "bound",
                        "collection": { "id": "input", "kind": "folder" },
                        "records": [{ "id": "card-a" }, { "id": "card-b" }],
                    },
                }),
                touches: vec![
                    opened("renderer"),
                    surfaced("input", 1),
                    surfaced("card-a", 2),
                    surfaced("card-b", 3),
                ],
                result_count: Some(1),
            },
            Case {
                name: "verify_artifact surfaces every named MDX input bearer",
                kind: ToolKind::VerifyArtifact,
                arguments: json!({ "id": "renderer" }),
                result: json!({
                    "status": "observed",
                    "artifact_id": "renderer",
                    "input": {
                        "collections": [
                            { "id": "input-a", "kind": "selection" },
                            { "id": "input-b", "kind": "folder" },
                        ],
                        "records": [{ "id": "card-a" }, { "id": "card-b" }],
                        "modules": [{ "id": "module-a" }],
                    },
                }),
                touches: vec![
                    opened("renderer"),
                    surfaced("input-a", 1),
                    surfaced("input-b", 2),
                    surfaced("card-a", 3),
                    surfaced("card-b", 4),
                    surfaced("module-a", 5),
                ],
                result_count: Some(1),
            },
            Case {
                name: "invoke_artifact_interaction mutates what it wrote and opens the artifact",
                kind: ToolKind::InvokeArtifactInteraction,
                arguments: json!({ "artifact_id": "renderer", "entry_id": "mark_triaged" }),
                result: json!({
                    "status": "committed",
                    "idempotency_key": "k",
                    "changes": [{ "record_id": "card-a", "key": "triage" }],
                }),
                touches: vec![mutated("card-a"), opened("renderer")],
                result_count: Some(1),
            },
            Case {
                name: "open_collection opens neutral root and surfaces members and renderer destinations",
                kind: ToolKind::OpenCollection,
                arguments: json!({ "id": "input" }),
                result: json!({
                    "status": "opened",
                    "collection": { "id": "input", "kind": "folder" },
                    "input": { "records": [{ "id": "member-a" }, { "id": "member-b" }] },
                    "renderers": [{ "id": "renderer" }],
                }),
                touches: vec![
                    opened("input"),
                    surfaced("member-a", 1),
                    surfaced("member-b", 2),
                    surfaced("renderer", 3),
                ],
                result_count: Some(2),
            },
            Case {
                name: "manage_facet_observations list opens its record",
                kind: ToolKind::ManageFacetObservations,
                arguments: json!({ "action": "list", "record_id": "metric", "key": "current" }),
                result: json!({
                    "record_id": "metric",
                    "observations": [{ "as_of": "2026-08-01T00:00:00.000Z" }],
                }),
                touches: vec![opened("metric")],
                result_count: Some(1),
            },
            Case {
                name: "resolve_facets opens record-scoped resolution",
                kind: ToolKind::ResolveFacets,
                arguments: json!({ "record_id": "faceted" }),
                result: json!({ "record_id": "faceted" }),
                touches: vec![opened("faceted")],
                result_count: Some(1),
            },
            Case {
                name: "suggest_facet_values opens type source and counts suggestions",
                kind: ToolKind::SuggestFacetValues,
                arguments: json!({ "facet_key": "stage", "record_id": "faceted" }),
                result: json!({ "suggestions": [{ "value": "a" }, { "value": "b" }] }),
                touches: vec![opened("faceted")],
                result_count: Some(2),
            },
            Case {
                name: "query_record ranks returned records",
                kind: ToolKind::QueryRecord,
                arguments: json!({ "steps": [] }),
                result: json!({
                    "shape": "records",
                    "records": [{ "id": "first" }, { "id": "second" }],
                    "returned": 2,
                }),
                touches: vec![surfaced("first", 1), surfaced("second", 2)],
                result_count: Some(2),
            },
            Case {
                name: "resolve_many surfaces visible unique and ambiguous candidates",
                kind: ToolKind::ResolveMany,
                arguments: json!({}),
                result: json!({
                    "results": [
                        { "status": "resolved", "match": { "id": "unique" } },
                        { "status": "not_found" },
                        {
                            "status": "ambiguous",
                            "matches": [{ "id": "first" }, { "id": "second" }]
                        }
                    ]
                }),
                touches: vec![
                    surfaced("unique", 1),
                    surfaced("first", 2),
                    surfaced("second", 3),
                ],
                result_count: Some(3),
            },
            Case {
                name: "resolve_rollup opens its bearer",
                kind: ToolKind::ResolveRollup,
                arguments: json!({ "record_id": "ledger", "rollup_name": "total" }),
                result: json!({ "record_id": "ledger", "value": 42 }),
                touches: vec![opened("ledger")],
                result_count: Some(1),
            },
            Case {
                name: "search ranks hits then near misses but counts strict hits",
                kind: ToolKind::Search,
                arguments: json!({ "query": "needle" }),
                result: json!({
                    "hits": [{ "id": "hit" }],
                    "returned": 1,
                    "near_misses": {
                        "name_prefix": [{ "id": "prefix" }],
                        "name_infix": [{ "id": "infix" }],
                        "tree_siblings": [{ "id": "sibling" }],
                    },
                }),
                touches: vec![
                    surfaced("hit", 1),
                    surfaced("prefix", 2),
                    surfaced("infix", 3),
                    surfaced("sibling", 4),
                ],
                result_count: Some(1),
            },
            Case {
                name: "query_sql counts arbitrary rows but infers no record ids",
                kind: ToolKind::QuerySql,
                arguments: json!({ "sql": "SELECT id FROM records" }),
                result: json!({
                    "columns": ["id"],
                    "rows": [{ "id": "looks-like-a-record" }, { "id": "another" }],
                    "row_count": 2,
                }),
                touches: vec![],
                result_count: Some(2),
            },
            Case {
                name: "scan ranks first appearance across axis samples",
                kind: ToolKind::Scan,
                arguments: json!({}),
                result: json!({
                    "axes": {
                        "lexical": { "samples": [{ "id": "a" }, { "id": "b" }] },
                        "recent": { "samples": [{ "id": "b" }, { "id": "c" }] },
                    },
                    "convergence": [{ "id": "b" }],
                }),
                touches: vec![surfaced("a", 1), surfaced("b", 2), surfaced("c", 3)],
                result_count: Some(3),
            },
            Case {
                name: "manage_vocabularies counts values but touches no records",
                kind: ToolKind::ManageVocabularies,
                arguments: json!({ "action": "list_values" }),
                result: json!({ "values": [{ "id": "vv:1" }, { "id": "vv:2" }] }),
                touches: vec![],
                result_count: Some(2),
            },
            Case {
                name: "manage_schema_config counts rows but touches no records",
                kind: ToolKind::ManageSchemaConfig,
                arguments: json!({ "action": "read" }),
                result: json!({ "rows": [{ "id": "cfg:1" }, { "id": "cfg:2" }] }),
                touches: vec![],
                result_count: Some(2),
            },
            Case {
                name: "attach_text mutates parent attachment relation and attachment",
                kind: ToolKind::AttachText,
                arguments: json!({ "record_id": "parent" }),
                result: json!({ "record_id": "parent", "attachment_id": "attachment" }),
                touches: vec![mutated("parent"), mutated("attachment")],
                result_count: Some(1),
            },
            Case {
                name: "attach_from_url has the same mutation shape as attach_text",
                kind: ToolKind::AttachFromUrl,
                arguments: json!({ "record_id": "parent" }),
                result: json!({ "record_id": "parent", "attachment_id": "attachment" }),
                touches: vec![mutated("parent"), mutated("attachment")],
                result_count: Some(1),
            },
            Case {
                name: "read_attachment opens the attachment record",
                kind: ToolKind::ReadAttachment,
                arguments: json!({ "attachment_id": "attachment" }),
                result: json!({ "attachment_id": "attachment", "content": "body" }),
                touches: vec![opened("attachment")],
                result_count: Some(1),
            },
            Case {
                name: "manage_attachments list opens parent and surfaces attachments",
                kind: ToolKind::ManageAttachments,
                arguments: json!({ "action": "list", "record_id": "parent" }),
                result: json!({
                    "record_id": "parent",
                    "attachments": [
                        { "attachment_id": "a" },
                        { "attachment_id": "b" },
                    ],
                }),
                touches: vec![opened("parent"), surfaced("a", 1), surfaced("b", 2)],
                result_count: Some(2),
            },
            Case {
                name: "resolve_suggestions accepted mutates target and suggestions",
                kind: ToolKind::ResolveSuggestions,
                arguments: json!({ "action": "accept", "suggestion_ids": ["s1", "s2"] }),
                result: json!({
                    "status": "accepted",
                    "target_id": "target",
                    "suggestion_ids": ["s1", "s2"],
                }),
                touches: vec![mutated("target"), mutated("s1"), mutated("s2")],
                result_count: Some(3),
            },
            Case {
                name: "render_suggestion_review opens its target",
                kind: ToolKind::RenderSuggestionReview,
                arguments: json!({ "record_id": "target" }),
                result: json!({ "target": { "id": "target" }, "view": "suggestion_review" }),
                touches: vec![opened("target")],
                result_count: Some(1),
            },
            Case {
                name: "start_work opens target, mutates changed claim, surfaces context",
                kind: ToolKind::StartWork,
                arguments: json!({ "record_id": "work" }),
                result: json!({
                    "record_id": "work",
                    "changed": true,
                    "context": {
                        "record": enriched("work"),
                        "governance": [{ "id": "governance" }],
                        "dependencies": {
                            "waiting_on": [{ "id": "waiting" }],
                            "satisfied": [{ "id": "satisfied" }],
                            "blocked_by": [{ "id": "blocker" }],
                        },
                    },
                }),
                touches: vec![
                    opened("work"),
                    mutated("work"),
                    surfaced("child", 1),
                    surfaced("ancestor", 2),
                    surfaced("out-target", 3),
                    surfaced("in-source", 4),
                    surfaced("governance", 5),
                    surfaced("waiting", 6),
                    surfaced("satisfied", 7),
                    surfaced("blocker", 8),
                ],
                result_count: Some(1),
            },
            Case {
                name: "resolve_citation opens citation and surfaces source",
                kind: ToolKind::ResolveCitation,
                arguments: json!({ "citation_id": "citation" }),
                result: json!({ "annotation_id": "citation", "target_record_id": "source" }),
                touches: vec![opened("citation"), surfaced("source", 1)],
                result_count: Some(1),
            },
            Case {
                name: "manage_citations mutates citation",
                kind: ToolKind::ManageCitations,
                arguments: json!({ "action": "remove", "citation_id": "citation" }),
                result: json!({ "citation_id": "citation", "action": "removed" }),
                touches: vec![mutated("citation")],
                result_count: Some(1),
            },
            Case {
                name: "create_attribution mutates its annotation and surfaces its bearer",
                kind: ToolKind::CreateAttribution,
                arguments: json!({ "bearer_id": "source" }),
                result: json!({
                    "annotation_id": "attribution",
                    "bearer_id": "source",
                    "claim_mode": "assessment",
                    "action_attestation_id": "attestation",
                }),
                touches: vec![mutated("attribution"), surfaced("source", 1)],
                result_count: Some(1),
            },
            Case {
                name: "read_attributions opens its bearer and surfaces bounded claims",
                kind: ToolKind::ReadAttributions,
                arguments: json!({ "bearer_id": "source" }),
                result: json!({
                    "bearer_id": "source",
                    "attribution_count": 2,
                    "attributions": [
                        { "annotation_id": "attribution-a" },
                        { "annotation_id": "attribution-b" },
                    ],
                }),
                touches: vec![
                    opened("source"),
                    surfaced("attribution-a", 1),
                    surfaced("attribution-b", 2),
                ],
                result_count: Some(2),
            },
            Case {
                name: "manage_attributions mutates its annotation",
                kind: ToolKind::ManageAttributions,
                arguments: json!({ "action": "retract", "annotation_id": "attribution" }),
                result: json!({ "annotation_id": "attribution", "action": "retracted" }),
                touches: vec![mutated("attribution")],
                result_count: Some(1),
            },
            Case {
                name: "manage_instructions opens a bound source",
                kind: ToolKind::ManageInstructions,
                arguments: json!({ "action": "create_binding" }),
                result: json!({ "source_record_id": "instructions" }),
                touches: vec![opened("instructions")],
                result_count: Some(1),
            },
            Case {
                name: "manage_onboarding opens a programme source",
                kind: ToolKind::ManageOnboarding,
                arguments: json!({ "action": "add_source" }),
                result: json!({ "source_record_id": "orientation" }),
                touches: vec![opened("orientation")],
                result_count: Some(1),
            },
            Case {
                name: "manage_memberships lists catalog identities without fabricating record touches",
                kind: ToolKind::ManageMemberships,
                arguments: json!({ "action": "list" }),
                result: json!({
                    "members": [
                        { "member_id": "member-a", "account_id": "account-a", "person_id": "person-a" },
                        { "member_id": "member-b", "account_id": null, "person_id": null },
                    ],
                }),
                touches: vec![],
                result_count: Some(2),
            },
            Case {
                name: "manage_change_summaries mutates its stable carrier",
                kind: ToolKind::ManageChangeSummaries,
                arguments: json!({ "action": "confirm" }),
                result: json!({ "carrier_id": "summary" }),
                touches: vec![mutated("summary")],
                result_count: Some(1),
            },
            Case {
                name: "query_change_summaries surfaces confirmed carriers",
                kind: ToolKind::QueryChangeSummaries,
                arguments: json!({ "action": "list" }),
                result: json!({
                    "items": [
                        { "target_record_id": "summary-a" },
                        { "target_record_id": "summary-b" },
                    ],
                }),
                touches: vec![surfaced("summary-a", 1), surfaced("summary-b", 2)],
                result_count: Some(2),
            },
        ];

        // Branch policies whose alternate shapes are easy to accidentally
        // collapse into their neighbouring case.
        cases.extend([
            Case {
                name: "query_record count buckets are results, not record touches",
                kind: ToolKind::QueryRecord,
                arguments: json!({ "steps": [], "count_by": "type" }),
                result: json!({
                    "shape": "counts",
                    "total": 10,
                    "buckets": [{ "key": "WorkItem", "count": 7 }, { "key": "Document", "count": 3 }],
                }),
                touches: vec![],
                result_count: Some(2),
            },
            Case {
                name: "archive_record no-op opens rather than mutates",
                kind: ToolKind::ArchiveRecord,
                arguments: json!({ "id": "archived" }),
                result: json!({ "id": "archived", "changed": false }),
                touches: vec![opened("archived")],
                result_count: Some(1),
            },
            Case {
                name: "manage_links add mutates both endpoints",
                kind: ToolKind::ManageLinks,
                arguments: json!({ "action": "add" }),
                result: json!({ "source_id": "source", "target_id": "target" }),
                touches: vec![mutated("source"), mutated("target")],
                result_count: Some(1),
            },
            Case {
                name: "manage_renderer_binding bind mutates both link endpoints",
                kind: ToolKind::ManageRendererBinding,
                arguments: json!({ "action": "bind", "artifact_id": "renderer", "collection_id": "input" }),
                result: json!({
                    "artifact_id": "renderer",
                    "status": "bound",
                    "bindings": [{ "collection_id": "input", "kind": "folder", "valid": true }],
                    "changed_collection_id": "input",
                }),
                touches: vec![mutated("renderer"), mutated("input")],
                result_count: Some(1),
            },
            Case {
                name: "manage_mdx_modules publication mutates its stable module",
                kind: ToolKind::ManageMdxModules,
                arguments: json!({ "action": "publish" }),
                result: json!({ "status": "published", "module_id": "module" }),
                touches: vec![mutated("module")],
                result_count: Some(1),
            },
            Case {
                name: "manage_artifact_inputs bind mutates the artifact and surfaces current Collections",
                kind: ToolKind::ManageArtifactInputs,
                arguments: json!({ "action": "bind" }),
                result: json!({
                    "artifact_id": "artifact",
                    "bindings": [{ "collection_id": "orders" }],
                }),
                touches: vec![mutated("artifact"), surfaced("orders", 1)],
                result_count: Some(1),
            },
            Case {
                name: "manage_artifact_module_grants grant mutates the artifact",
                kind: ToolKind::ManageArtifactModuleGrants,
                arguments: json!({ "action": "grant" }),
                result: json!({
                    "artifact_id": "artifact",
                    "grants": [{ "subject_kind": "module_release", "subject_event_id": "release" }],
                }),
                touches: vec![mutated("artifact")],
                result_count: Some(1),
            },
            Case {
                name: "manage_renderer_binding implicit unbind mutates both endpoints and counts its removed link",
                kind: ToolKind::ManageRendererBinding,
                arguments: json!({ "action": "unbind", "artifact_id": "renderer" }),
                result: json!({
                    "artifact_id": "renderer",
                    "status": "unbound",
                    "bindings": [],
                    "changed_collection_id": "input",
                }),
                touches: vec![mutated("renderer"), mutated("input")],
                result_count: Some(1),
            },
            Case {
                name: "manage_renderer_binding repair surfaces other remaining bindings",
                kind: ToolKind::ManageRendererBinding,
                arguments: json!({ "action": "unbind", "artifact_id": "renderer", "collection_id": "removed" }),
                result: json!({
                    "artifact_id": "renderer",
                    "status": "bound",
                    "bindings": [{ "collection_id": "remaining", "kind": "folder", "valid": true }],
                    "changed_collection_id": "removed",
                }),
                touches: vec![
                    mutated("renderer"),
                    mutated("removed"),
                    surfaced("remaining", 1),
                ],
                result_count: Some(1),
            },
            Case {
                name: "render_artifact standalone inline cards are not record interactions",
                kind: ToolKind::RenderArtifact,
                arguments: json!({ "id": "renderer" }),
                result: json!({
                    "status": "rendered",
                    "artifact_id": "renderer",
                    "input": { "mode": "standalone", "collection": null },
                    "plan": { "lanes": [{ "records": [{ "id": "explicit-but-inline" }] }] },
                }),
                touches: vec![opened("renderer")],
                result_count: Some(1),
            },
            Case {
                name: "manage_facet_observations set mutates its record",
                kind: ToolKind::ManageFacetObservations,
                arguments: json!({ "action": "set" }),
                result: json!({ "record_id": "metric", "status": "set" }),
                touches: vec![mutated("metric")],
                result_count: Some(1),
            },
            Case {
                name: "manage_attachments detach mutates attachment",
                kind: ToolKind::ManageAttachments,
                arguments: json!({ "action": "detach" }),
                result: json!({ "attachment_id": "attachment", "detached": true }),
                touches: vec![mutated("attachment")],
                result_count: Some(1),
            },
            Case {
                name: "resolve_suggestions stale mutates only failed suggestions",
                kind: ToolKind::ResolveSuggestions,
                arguments: json!({ "action": "accept" }),
                result: json!({
                    "status": "stale",
                    "target_id": "target",
                    "suggestion_ids": ["stale"],
                }),
                touches: vec![mutated("stale")],
                result_count: Some(1),
            },
            Case {
                name: "resolve_suggestions reject mutates only the suggestion",
                kind: ToolKind::ResolveSuggestions,
                arguments: json!({ "action": "reject" }),
                result: json!({
                    "status": "rejected",
                    "target_id": "target",
                    "suggestion_ids": ["rejected"],
                }),
                touches: vec![mutated("rejected")],
                result_count: Some(1),
            },
            Case {
                name: "resolve_suggestions conflict records no mutation",
                kind: ToolKind::ResolveSuggestions,
                arguments: json!({ "action": "accept" }),
                result: json!({
                    "status": "conflict",
                    "target_id": "target",
                    "suggestion_ids": ["terminal"],
                }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "manage_bindings apply mutates both binding owners",
                kind: ToolKind::ManageBindings,
                arguments: json!({ "action": "reconcile", "apply": true }),
                result: json!({
                    "record_id": "target", "from_record_id": "source", "changed": true
                }),
                touches: vec![mutated("target"), mutated("source")],
                result_count: Some(1),
            },
            Case {
                name: "manage_record_policy changed mutation touches its record",
                kind: ToolKind::ManageRecordPolicy,
                arguments: json!({ "action": "grant" }),
                result: json!({"record_id":"policy-record","changed":true}),
                touches: vec![mutated("policy-record")],
                result_count: Some(1),
            },
            Case {
                name: "resolve_external hit opens the resolved record",
                kind: ToolKind::ResolveExternal,
                arguments: json!({}),
                result: json!({
                    "record_id": "shadow", "created": false, "bindings_added": []
                }),
                touches: vec![opened("shadow")],
                result_count: Some(1),
            },
            Case {
                name: "observe_external mutates shadow and snapshot attachment",
                kind: ToolKind::ObserveExternal,
                arguments: json!({}),
                result: json!({"record_id": "shadow", "attachment_id": "snapshot"}),
                touches: vec![mutated("shadow"), mutated("snapshot")],
                result_count: Some(1),
            },
            Case {
                name: "manage_instructions seeded apply mutates its source",
                kind: ToolKind::ManageInstructions,
                arguments: json!({ "action": "apply_seeded_default" }),
                result: json!({ "source_record_id": "instructions" }),
                touches: vec![mutated("instructions")],
                result_count: Some(1),
            },
            Case {
                name: "manage_onboarding non-source commands do not fabricate record touches",
                kind: ToolKind::ManageOnboarding,
                arguments: json!({ "action": "publish_generation" }),
                result: json!({ "programme_id": "orientation", "generation": 2 }),
                touches: vec![],
                result_count: Some(0),
            },
            Case {
                name: "manage_memberships role changes are catalog mutations, not record mutations",
                kind: ToolKind::ManageMemberships,
                arguments: json!({ "action": "set_role", "member_id": "member" }),
                result: json!({ "member_id": "member", "role": "owner", "changed": true }),
                touches: vec![],
                result_count: Some(1),
            },
            Case {
                name: "manage_memberships offboarding is one catalog result without record touches",
                kind: ToolKind::ManageMemberships,
                arguments: json!({ "action": "remove", "member_id": "member" }),
                result: json!({ "operation_id": "operation", "member_id": "member", "status": "completed" }),
                touches: vec![],
                result_count: Some(1),
            },
            Case {
                name: "create_exploration mutates the collection and every candidate it admitted",
                kind: ToolKind::CreateExploration,
                arguments: json!({}),
                result: json!({
                    "exploration": { "id": "exploration" },
                    "candidates": [{ "id": "first" }, { "id": "second" }],
                }),
                touches: vec![
                    mutated("exploration"),
                    mutated("first"),
                    mutated("second"),
                ],
                result_count: Some(3),
            },
            Case {
                name: "get_event_context opens the event target, not the records it reports as consulted",
                kind: ToolKind::GetEventContext,
                arguments: json!({ "event_id": "event" }),
                result: json!({
                    "event": { "record_id": "target" },
                    "consulted": { "records": [{ "record_id": "consulted" }] },
                }),
                // Reporting that a run once opened a record is not this call
                // opening it. Counting it would let the projection inflate its
                // own future output.
                touches: vec![opened("target")],
                result_count: Some(1),
            },
            Case {
                name: "read_canvas opens the canvas and surfaces the record faces it resolved",
                kind: ToolKind::ReadCanvas,
                arguments: json!({ "action": "get_scene", "canvas_id": "canvas" }),
                result: json!({
                    "canvas_id": "canvas",
                    "objects": [
                        { "id": "card", "kind": "record_card", "record": { "id": "face" } },
                        { "id": "card-withheld", "kind": "record_card", "props": { "record_id": "withheld" } },
                        { "id": "note", "kind": "note" }
                    ],
                }),
                touches: vec![opened("canvas"), surfaced("face", 1)],
                result_count: Some(3),
            },
            Case {
                name: "manage_canvas mutates the canvas only when a batch lands",
                kind: ToolKind::ManageCanvas,
                arguments: json!({ "action": "commit_batch", "batch": { "canvas_id": "canvas" } }),
                result: json!({ "outcome": "rejected" }),
                touches: vec![],
                result_count: Some(1),
            },
        ]);

        let mut covered = HashSet::new();
        for case in cases {
            covered.insert(case.kind);
            let actual = extract(case.kind, &case.arguments, &case.result);
            assert_eq!(actual.touches, case.touches, "{}: touches", case.name);
            assert_eq!(
                actual.result_count, case.result_count,
                "{}: result_count",
                case.name
            );
        }
        assert_eq!(
            covered,
            ToolKind::ALL.into_iter().collect(),
            "the semantic policy table must cover every shipped tool kind"
        );
    }

    /// The serving writer interns exact, case-sensitive TEXT ids and resolves
    /// touches by ref in one transaction. This drives the private `record_call`
    /// directly because no shipped handler can emit an arbitrary or
    /// case-distinct id: handlers only ever surface ids they authorized.
    #[tokio::test]
    async fn record_call_interns_arbitrary_case_distinct_ids_and_all_interactions() {
        use sqlx::Row as _;

        fn pending(db: &Db, extraction: Extraction) -> PendingCapture {
            PendingCapture {
                db: db.clone(),
                tool_name: "fixture_capture".to_string(),
                interaction_capability: None,
                run_key: Some("scout-chair-a748b2".to_string()),
                parent_key: None,
                intent: None,
                actor: "local".to_string(),
                arguments: "{}".to_string(),
                outcome_name: "ok",
                error: None,
                extraction,
                result_annotation: None,
                result_bytes: None,
                started_at: "2026-01-01T00:00:00.000Z".to_string(),
                ended_at: "2026-01-01T00:00:00.001Z".to_string(),
                _deployment_persistence_lease: None,
                gate: None,
                pre_gate: None,
            }
        }

        let db = crate::db::create_database(":memory:").await.unwrap();

        let mut extraction = Extraction::success();
        extraction.surfaced(Some("CaseDistinct"));
        extraction.surfaced(Some("caseDistinct"));
        extraction.opened(Some("casedistinct"));
        extraction.mutated(Some("native:root"));
        extraction.mutated(Some("dangling-record-with-no-row"));
        extraction.count(5);
        record_call(pending(&db, extraction)).await.unwrap();

        let rows = sqlx::query(
            "SELECT dictionary.record_id AS record_id,
                    touch.interaction AS interaction,
                    touch.result_rank AS result_rank
               FROM read_log_touches touch
               JOIN read_log_record_ids dictionary
                 ON dictionary.record_ref = touch.record_ref
              ORDER BY dictionary.record_id, touch.interaction",
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
        .iter()
        .map(|row| {
            (
                row.get::<String, _>("record_id"),
                row.get::<String, _>("interaction"),
                row.get::<Option<i64>, _>("result_rank"),
            )
        })
        .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![
                ("CaseDistinct".to_string(), "surfaced".to_string(), Some(1)),
                ("caseDistinct".to_string(), "surfaced".to_string(), Some(2)),
                ("casedistinct".to_string(), "opened".to_string(), None),
                (
                    "dangling-record-with-no-row".to_string(),
                    "mutated".to_string(),
                    None,
                ),
                ("native:root".to_string(), "mutated".to_string(), None),
            ]
        );

        // Case-distinct strings occupy separate rows; the dictionary never
        // folds case, and a dangling id (no `records` row) still gets a home.
        let dictionary_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM read_log_record_ids
              WHERE record_id IN ('CaseDistinct', 'caseDistinct', 'casedistinct')",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(dictionary_rows, 3);

        // A later call reuses the existing ref instead of adding a duplicate.
        let mut repeat = Extraction::success();
        repeat.surfaced(Some("CaseDistinct"));
        record_call(pending(&db, repeat)).await.unwrap();
        let repeat_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM read_log_record_ids WHERE record_id = 'CaseDistinct'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(repeat_rows, 1);
    }

    fn test_capture(db: &Db, tool: &str) -> PendingCapture {
        PendingCapture {
            db: db.clone(),
            tool_name: tool.to_string(),
            interaction_capability: Some("native.interaction-log.v1".to_string()),
            run_key: None,
            parent_key: None,
            intent: None,
            actor: "local".to_string(),
            arguments: "{}".to_string(),
            outcome_name: "ok",
            error: None,
            extraction: Extraction::success(),
            result_annotation: None,
            result_bytes: None,
            started_at: "2026-09-16T00:00:00.000Z".to_string(),
            ended_at: "2026-09-16T00:00:00.001Z".to_string(),
            _deployment_persistence_lease: None,
            gate: None,
            pre_gate: None,
        }
    }

    /// A full queue refuses without blocking: depth 1 with the worker parked
    /// inside the blocker's transaction fits exactly one more capture, and
    /// the overflow is counted, never awaited.
    #[tokio::test]
    async fn full_capture_queue_drops_and_counts_without_blocking() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let queue = CaptureQueue::with_depth(1);
        let gate = Arc::new(CaptureTestGate::default());
        let mut blocker = test_capture(&db, "blocker");
        blocker.gate = Some(Arc::clone(&gate));
        assert!(queue.enqueue(blocker));
        gate.wait_until_entered().await;
        assert!(queue.enqueue(test_capture(&db, "parked")));
        assert!(!queue.enqueue(test_capture(&db, "overflow")));
        let stats = queue.stats();
        assert_eq!(stats.enqueued, 2);
        assert_eq!(stats.dropped_full, 1);
        gate.release();
        queue.drain().await;
        let stats = queue.stats();
        assert_eq!(stats.completed, 2);
        assert_eq!(stats.failed, 0);
        db.close().await;
    }

    /// Shutdown refuses new work while accepted captures still drain:
    /// `drain_after_shutdown` settles on the stable frontier.
    #[tokio::test]
    async fn capture_shutdown_refuses_new_work_and_drain_settles() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let queue = CaptureQueue::with_depth(8);
        assert!(queue.enqueue(test_capture(&db, "one")));
        queue.initiate_shutdown();
        assert!(!queue.enqueue(test_capture(&db, "two")));
        queue.drain_after_shutdown().await;
        assert_eq!(
            queue.stats(),
            CaptureStats {
                enqueued: 1,
                completed: 1,
                failed: 0,
                dropped_full: 0,
                dropped_shutdown: 1,
                declarations_completed: 0,
                declarations_failed: 0,
            }
        );
        db.close().await;
    }

    /// A declaration completing after shutdown must never satisfy the queue
    /// frontier: queue counters stay queue-only on a separate ledger. Park a
    /// queued capture, shut down, complete a declaration on an uncontended
    /// handle, and prove the queue drain is still pending until the parked
    /// capture itself finishes. The declaration uses a second handle so its
    /// write does not block on the parked capture's held write lock; ledger
    /// separation is what is under test, not write-lock queuing.
    #[tokio::test]
    async fn declaration_after_shutdown_does_not_satisfy_queue_frontier() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let declaration_db = crate::db::create_database(":memory:").await.unwrap();
        let queue = CaptureQueue::with_depth(8);
        let gate = Arc::new(CaptureTestGate::default());
        let mut parked = test_capture(&db, "parked");
        parked.gate = Some(Arc::clone(&gate));
        assert!(queue.enqueue(parked));
        gate.wait_until_entered().await;
        queue.initiate_shutdown();

        let draining = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move { queue.drain_after_shutdown().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !draining.is_finished(),
            "queue drain settled with the parked capture still pending"
        );

        queue
            .record_declaration(test_capture(&declaration_db, "declaration"))
            .await;
        let stats = queue.stats();
        assert_eq!(stats.completed, 0);
        assert_eq!(stats.declarations_completed, 1);
        assert_eq!(stats.declarations_failed, 0);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !draining.is_finished(),
            "declaration completion satisfied the queue-only frontier"
        );

        gate.release();
        tokio::time::timeout(std::time::Duration::from_secs(5), draining)
            .await
            .expect("queue drain did not settle after the parked capture")
            .unwrap();
        let stats = queue.stats();
        assert_eq!(stats.enqueued, 1);
        assert_eq!(stats.completed, 1);
        assert_eq!(stats.declarations_completed, 1);
        db.close().await;
        declaration_db.close().await;
    }
}
