//! The MCP tool surface: registration, dispatch, authorization and the staged tool suites.
//!
//! Every `mod` below was previously its own `tests/*.rs` target. Cargo links
//! one test binary per target against the whole dependency graph, and those
//! link steps are not cacheable, so the suite is grouped into a few binaries
//! instead of a hundred. The tests themselves are unchanged; they now share a
//! process with their neighbours.

mod common;

#[path = "tools/action_evidence.rs"]
mod action_evidence;
#[path = "tools/alpha_tabs.rs"]
mod alpha_tabs;
#[path = "tools/authoring_context.rs"]
mod authoring_context;

#[path = "tools/authoring_journey.rs"]
mod authoring_journey;

#[path = "tools/authoring_save.rs"]
mod authoring_save;

#[path = "tools/authorization_contract.rs"]
mod authorization_contract;
#[path = "tools/authorization_tools.rs"]
mod authorization_tools;
#[path = "tools/batch_semantic_measurement.rs"]
mod batch_semantic_measurement;
#[path = "tools/batch_write.rs"]
mod batch_write;
#[path = "tools/bootstrap_instructions.rs"]
mod bootstrap_instructions;
#[path = "tools/canvas.rs"]
mod canvas;
#[path = "tools/capability_dispatch.rs"]
mod capability_dispatch;
#[path = "tools/conformance.rs"]
mod conformance;
#[path = "tools/create_idempotency.rs"]
mod create_idempotency;
#[path = "tools/create_many.rs"]
mod create_many;
#[path = "tools/event_context.rs"]
mod event_context;
#[path = "tools/experimental_agent_intents.rs"]
mod experimental_agent_intents;
#[path = "tools/export_snapshot.rs"]
mod export_snapshot;
#[path = "tools/facet_observations_tool.rs"]
mod facet_observations_tool;
#[path = "tools/fetch_guard.rs"]
mod fetch_guard;
#[path = "tools/history_summary.rs"]
mod history_summary;
#[path = "tools/instruction_controls.rs"]
mod instruction_controls;
#[path = "tools/intent.rs"]
mod intent;
#[path = "tools/mcp.rs"]
mod mcp;
#[path = "tools/mcp_apps.rs"]
mod mcp_apps;
#[path = "tools/overlap_measurement.rs"]
mod overlap_measurement;
#[path = "tools/programs.rs"]
mod programs;
#[path = "tools/query_guest_footing.rs"]
mod query_guest_footing;
#[path = "tools/read_log_capture.rs"]
mod read_log_capture;
#[path = "tools/record_policy_tool.rs"]
mod record_policy_tool;
#[path = "tools/record_shape_preflight.rs"]
mod record_shape_preflight;
#[path = "tools/records_read_format.rs"]
mod records_read_format;
#[path = "tools/relationships.rs"]
mod relationships;
#[path = "tools/resolve_many.rs"]
mod resolve_many;
#[path = "tools/similar_existing.rs"]
mod similar_existing;
#[path = "tools/source_basis.rs"]
mod source_basis;
#[path = "tools/standby_stdio.rs"]
mod standby_stdio;
#[path = "tools/suggestions.rs"]
mod suggestions;
#[path = "tools/surface_bindings.rs"]
mod surface_bindings;
#[path = "tools/tools_stage3.rs"]
mod tools_stage3;
#[path = "tools/tools_stage4.rs"]
mod tools_stage4;
#[path = "tools/tools_stage5.rs"]
mod tools_stage5;
#[path = "tools/tools_stage8.rs"]
mod tools_stage8;
#[path = "tools/update_record_links.rs"]
mod update_record_links;
#[path = "tools/workspace_naming.rs"]
mod workspace_naming;
