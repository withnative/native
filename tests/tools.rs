//! The MCP tool surface: registration, dispatch, authorization and the staged tool suites.
//!
//! Every `mod` below was previously its own `tests/*.rs` target. Cargo links
//! one test binary per target against the whole dependency graph, and those
//! link steps are not cacheable, so the suite is grouped into a few binaries
//! instead of a hundred. The tests themselves are unchanged; they now share a
//! process with their neighbours.

mod common;

#[path = "tools/authorization_contract.rs"]
mod authorization_contract;
#[path = "tools/authorization_tools.rs"]
mod authorization_tools;
#[path = "tools/batch_semantic_measurement.rs"]
mod batch_semantic_measurement;
#[path = "tools/bootstrap_instructions.rs"]
mod bootstrap_instructions;
#[path = "tools/canvas.rs"]
mod canvas;
#[path = "tools/capability_dispatch.rs"]
mod capability_dispatch;
#[path = "tools/conformance.rs"]
mod conformance;
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
#[path = "tools/instruction_controls.rs"]
mod instruction_controls;
#[path = "tools/intent.rs"]
mod intent;
#[path = "tools/mcp.rs"]
mod mcp;
#[path = "tools/mcp_apps.rs"]
mod mcp_apps;
#[path = "tools/programs.rs"]
mod programs;
#[path = "tools/record_policy_tool.rs"]
mod record_policy_tool;
#[path = "tools/record_shape_preflight.rs"]
mod record_shape_preflight;
#[path = "tools/relationships.rs"]
mod relationships;
#[path = "tools/resolve_many.rs"]
mod resolve_many;
#[path = "tools/standby_stdio.rs"]
mod standby_stdio;
#[path = "tools/suggestions.rs"]
mod suggestions;
#[path = "tools/tools_stage3.rs"]
mod tools_stage3;
#[path = "tools/tools_stage4.rs"]
mod tools_stage4;
#[path = "tools/tools_stage5.rs"]
mod tools_stage5;
#[path = "tools/tools_stage8.rs"]
mod tools_stage8;
#[path = "tools/workspace_naming.rs"]
mod workspace_naming;
