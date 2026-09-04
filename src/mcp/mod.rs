//! The server seam (tool-surface finding 3) — the layer *beneath* the v1 tool
//! surface (`docs/tool-surface.md`), not the tools themselves.
//!
//! Three pieces:
//!   - [`registry`] — tools registered ONCE as name + JSON-Schema argument
//!     shape + handler. The one hard rule (decision 2231ad3, option C):
//!     **handlers return structured data (`serde_json::Value`, or `ToolResult`
//!     when they also have transient evidence); transports render.** A handler
//!     that formats text has violated the contract, and
//!     registration knows nothing about MCP response framing.
//!   - [`stdio`] — the local transport: an MCP server speaking JSON-RPC 2.0
//!     over newline-delimited stdio against one local `.db`. Hand-rolled, not
//!     `rmcp` — see `docs/mcp-crate-choice.md`.
//!   - [`render`] — the other side of that rule: text renderings of tool
//!     payloads, dispatched by tool NAME so a renderer stays on the transport
//!     side of the seam. Audited standalone default-text renderings carry
//!     readable `content` alone; explicit JSON, Apps, unrendered tools,
//!     conservative mutation/mixed families, and defensive recovery paths
//!     preserve the `content`/`structuredContent` compatibility pairing. The
//!     ordinary callable schemas advertise `format` with only the values their
//!     selected operation can honour. MCP Apps and fixed browser/lens
//!     transports omit and reject it.
//!   - held `native-held-hosting` composes two authenticated adapters over this
//!     package, resolving a bearer token plus catalog membership to a selected database:
//!       - `POST /mcp/{db_id}` is stateless Streamable HTTP: strict MCP 2026-07-28
//!         plus sessionless legacy initialize compatibility, sharing both
//!         JSON-RPC dispatchers with stdio. Legacy `/mcp` requires at least
//!         one membership and provisionally selects the most recently joined
//!         of several.
//!       - `POST /databases/{db_id}/tools/:name` returns the handler's JSON payload directly,
//!         without MCP framing. This is where the web workbench attaches, and
//!         it is unaffected by rendering — it never sees a `content` block.
//!         Legacy `/tools/:name` resolves its database the same way as
//!         legacy `/mcp`.
//!   - [`snapshot`] — the registration-time capability for the universal
//!     `export_snapshot` tool. `serve` captures a catalog-backed source that
//!     shares `/export`'s coordinator; stdio captures a filesystem-backed
//!     source that creates its verified snapshot beside the local `.db`.
//!
//! Error mapping (engine error *messages* are the stable contract surface):
//!   - HTTP: `Error::Auth` → 401, `Error::Engine` → 400, both carrying the
//!     message verbatim as `{"error": message}`; anything else → 500.
//!   - MCP: tool-execution failures (`Engine`/`Auth`) become a `tools/call`
//!     result with `isError: true` carrying the message verbatim (the
//!     spec-proper shape — the model is allowed to see tool failures);
//!     infrastructure failures become JSON-RPC `-32603` with the message.

pub mod apps;
pub mod builtin;
mod deployment_read_only;
pub mod evidence;
#[cfg(feature = "mcp-executor-prototype")]
#[doc(hidden)]
pub mod executor_prototype;
#[doc(hidden)]
pub mod federated_source;
pub mod fetch;
pub mod guides;
#[doc(hidden)]
pub mod hosted_protocol;
#[doc(hidden)]
pub mod hosted_transport;
pub(crate) mod interactions;
pub mod lens_dispatch;
mod lens_surface;
#[doc(hidden)]
pub mod mdx_verification;
pub mod product_model;
mod protocol;
pub(crate) mod record_ref;
pub mod registry;
pub mod render;
pub mod snapshot;
pub mod status_only;
pub mod stdio;
mod surface;
pub mod tools;

pub use builtin::{register_builtin_tools, register_standby_status_tool};
pub use deployment_read_only::{
    DeploymentAdmission, DeploymentFreezeLease, DeploymentMutationBarrier,
    DeploymentPersistenceLease, OperationAccess, DEPLOYMENT_READ_ONLY_ERROR,
};
pub use evidence::{EvidenceKind, EvidenceStoreOptions, ToolResult, TransientEvidence};
#[cfg(feature = "mcp-executor-prototype")]
pub use executor_prototype::{
    DeploymentPlanKeyring, HostedExecutorAuthority, HostedMembershipPreparation,
    HostedPlanCatalogue, HostedPlanKeyProvider,
};
#[cfg(feature = "mcp-executor-prototype")]
#[doc(hidden)]
pub use executor_prototype::{ExecutorPrototypeStdioServer, HostedExecutorRuntime};
#[cfg(feature = "mcp-executor-prototype")]
pub use executor_prototype::{
    ExecutorTelemetryContext, ExecutorTelemetryHealth, ExecutorTelemetrySink,
    StructuredLogTelemetrySink, DEFAULT_RETENTION_DAYS,
};
pub use guides::{GuideSource, GuideSpec, GUIDE_SPECS};
pub use interactions::{
    AdmissionReason, AuthoritativeDisposition, AuthorizationDisposition, CustomInteractionPolicy,
    ExposureProfile, ResolvedToolExposure, ToolExposure, ToolFamily, ToolKind, VisibilityOverride,
};
#[doc(hidden)]
pub use lens_dispatch::LensDispatch;
#[doc(hidden)]
pub use lens_surface::{
    lens_descriptor_projection, lens_descriptor_projection_for_policy, lens_local_tool_exposures,
    lens_tool_policy, validate_lens_policy_budget, validate_lens_profile_budgets, LensToolPolicy,
};
pub use protocol::PROTOCOL_VERSION;
#[cfg(feature = "mcp-executor-prototype")]
#[doc(hidden)]
pub use registry::HostedMembershipPlanExecution;
pub use registry::{
    descriptor_projection_bytes, governed_request_pipeline_is_exhaustive,
    membership_page_size_is_valid, register_membership_tool_schema, register_membership_tool_with,
    validate_descriptor_projection, AdvertisedTool, AppMetadata, Caller, EngineHandle, EngineKind,
    GovernedRequestOperation, GovernedRequestStage, ToolRegistry, ToolSpec, TrustedAudience,
    COMPLETE_PROFILE_MAX_BYTES, FOCUSED_PROFILE_MAX_BYTES, GOVERNED_REQUEST_PIPELINE,
};
pub use render::Format;
pub use snapshot::{
    SnapshotPage, SnapshotRequest, SnapshotSource, SnapshotSourceRef, SNAPSHOT_COMPLETED_CACHE_CAP,
    SNAPSHOT_DEFAULT_PAGE_BYTES, SNAPSHOT_MAX_PAGE_BYTES,
};
pub use status_only::{StatusOnlyStdioServer, STANDBY_STATUS_ONLY_ERROR};
pub use stdio::StdioServer;
pub use surface::McpSurfaceMode;
#[doc(hidden)]
pub use tools::register_build_enabled_experimental_tools;
#[cfg(feature = "experimental-agent-intents")]
pub use tools::register_experimental_agent_intent_tool;
pub use tools::{register_snapshot_tool, register_surface_tools};
