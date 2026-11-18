//! Aggregated enumeration audit for `ToolKind` (task e1b92df).
//!
//! Adding a tool means joining many lists, each historically enforced by a
//! different suite. The exhaustive matches in `interactions.rs` catch some
//! at compile time; the rest used to surface one CI run at a time. This test
//! iterates every [`ToolKind`] once, checks membership in each Rust-visible
//! list below, and reports every gap together — naming the list and the
//! file that owns it — instead of stopping at the first failure.
//!
//! It is in addition to the existing guards, not a replacement for them:
//! those keep their sharper, list-specific assertions.
//!
//! Covered here (Rust-visible):
//! - `ToolKind::ALL` name uniqueness (`src/mcp/interactions.rs`)
//! - ordinary registry registration (`register_builtin_tools` /
//!   `register_surface_tools`)
//! - authorization contract fixture (`tests/fixtures/authorization-contract.json`)
//! - executor audit projection (`src/mcp/executor_prototype/candidate-audit.public.generated.json`)
//! - `RENDERED_TOOLS` and the renderer default (`src/mcp/render.rs`)
//! - keyed-write allowlists, v1 and KernelV2 (`src/mcp/tools/keyed_replay.rs`,
//!   `KERNEL_V2_ADAPTER_KEYED_WRITES` in `src/mcp/registry.rs`; the KernelV2
//!   half only under `v2-kernel-probe`, which the script's graph enables)
//! - action-evidence surfaces (`src/mcp/action_evidence.rs`)
//! - Complete/Focused profile byte budgets (`src/mcp/registry.rs`)
//!
//! Not covered here (they live in Node, generated files, or other
//! binaries; `scripts/check-new-operation.sh` runs them):
//! - counter-guard allowlists (`tests/tools/counter_guard.rs`)
//! - demo-shell / launcher `APP_CALL_TOOL_NAMES` and the idempotent-write
//!   table (`experiments/demo-shell/check-app-host.mjs`)
//! - generated `web/generated/tools.d.ts`, the tool inventory and the
//!   guide corpus (`tool-types --check-all`)
//! - backend-contract manifest (`backend-contract-manifest --check`)
//! - frozen 62->63 read-log lists and post-freeze accounting
//!   (`migrations::tests` in `src/migrations.rs`, run by the script)
//! - comment-reply contract fixture and the executor catalogue internals
//!   (the `mcp::executor_prototype` test suite)
//! - test-gate and test-map declarations (`scripts/verify-test-gates.py`,
//!   `scripts/check-test-map.py`)

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

use super::action_evidence;
use super::interactions::ToolKind;
use super::render::RENDERED_TOOLS;
use super::tools::keyed_replay::KEYED_REPLAY_WRITES;
use super::{register_builtin_tools, register_surface_tools, ToolRegistry};

/// Kinds the ordinary (builtin + surface) registry deliberately does not
/// register: status tools need a configured provider, and the rest are
/// schema-registered by hosted transports. Twin list: the `missing`
/// assertion in `every_registered_tool_kind_has_an_authorization_disposition`
/// (`tests/tools/authorization_tools.rs`) pins the same set — keep the two
/// in step.
const NOT_IN_ORDINARY_REGISTRY: [ToolKind; 10] = [
    ToolKind::StandbyStatus,
    ToolKind::OutboxStatus,
    ToolKind::ManagePublication,
    ToolKind::ExportSnapshot,
    ToolKind::ManageMemberships,
    ToolKind::WorkspaceRead,
    ToolKind::ReachRead,
    ToolKind::ReachConnect,
    ToolKind::AuthorityActHead,
    ToolKind::AuthorityActDelta,
];

/// Kinds with no row in the authorization fixture or the executor audit:
/// the two status tools and publication management (ordinary-SQLite
/// refusals are pinned elsewhere).
const NOT_IN_FIXTURE_OR_AUDIT: [ToolKind; 3] = [
    ToolKind::StandbyStatus,
    ToolKind::OutboxStatus,
    ToolKind::ManagePublication,
];

/// Surface tools that deliberately offer JSON only. Twin list: the
/// JSON-only match in `tools_with_a_renderer_default_to_text_others_to_json`
/// (`tests/records/render.rs`) pins the same five — keep the two in step.
const JSON_ONLY_SURFACE_TOOLS: [&str; 5] = [
    "manage_account_config",
    "manage_saved_tabs",
    "read_hcp_audit",
    "manage_named_views",
    "read_app_bundle",
];

fn ordinary_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).expect("builtin tools register");
    register_surface_tools(&mut registry).expect("surface tools register");
    registry
}

fn read_json(relative: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn check_all(gaps: &mut Vec<String>, list: &str, file: &str, missing: Vec<String>) {
    for name in missing {
        gaps.push(format!("{name} is missing from {list} ({file})"));
    }
}

/// Whether a tool schema declares an `idempotency_key` property anywhere
/// in its branch structure (top level or inside `oneOf`/`anyOf` branches).
fn schema_advertises_idempotency_key(schema: &Value) -> bool {
    match schema {
        Value::Object(map) => {
            map.get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| properties.contains_key("idempotency_key"))
                || map.values().any(schema_advertises_idempotency_key)
        }
        Value::Array(items) => items.iter().any(schema_advertises_idempotency_key),
        _ => false,
    }
}

/// Tools allowed to differ between the v1 keyed-write list
/// (`KEYED_REPLAY_WRITES`) and the KernelV2 adapter list
/// (`KERNEL_V2_ADAPTER_KEYED_WRITES`). The v1-only names are keyed through
/// the provenance seam on SQLite and refuse plainly on KernelV2;
/// `create_record`, `attach_text` and `merge_body` are the reverse — keyed
/// through the kernel adapter's own receipts, so they never joined the v1
/// seam list. `create_many` and `attach_from_url` are keyed on both engines.
/// The check below compares names only, not actions: this list must equal
/// the symmetric difference of the two lists exactly.
#[cfg(feature = "v2-kernel-probe")]
const KERNEL_V2_KEYED_EXCLUSIONS: [&str; 12] = [
    "manage_facet_observations",
    "claim_unowned_record",
    "manage_citations",
    "manage_attributions",
    "manage_renderer_binding",
    "manage_artifact_inputs",
    "manage_mdx_modules",
    "manage_surface_bindings",
    "instantiate_artifact",
    "create_record",
    "attach_text",
    "merge_body",
];

#[test]
fn every_tool_kind_is_in_every_rust_visible_enumeration() {
    let mut gaps: Vec<String> = Vec::new();
    let all_names: BTreeSet<&str> = ToolKind::ALL.iter().map(|kind| kind.name()).collect();

    // `ToolKind::ALL` itself: no repeated name.
    if all_names.len() != ToolKind::ALL.len() {
        gaps.push(
            "ToolKind::ALL repeats a tool name (src/mcp/interactions.rs, ToolKind::ALL)"
                .to_string(),
        );
    }

    // Ordinary registry registration.
    let registry = ordinary_registry();
    let registered: std::collections::HashSet<ToolKind> =
        registry.specs().filter_map(|spec| spec.kind).collect();
    check_all(
        &mut gaps,
        "the ordinary registry (or the NOT_IN_ORDINARY_REGISTRY exemption list in this file)",
        "src/mcp/registry.rs via register_builtin_tools / register_surface_tools",
        ToolKind::ALL
            .into_iter()
            .filter(|kind| !registered.contains(kind) && !NOT_IN_ORDINARY_REGISTRY.contains(kind))
            .map(|kind| kind.name().to_string())
            .collect(),
    );

    // Authorization contract fixture.
    let fixture = read_json("tests/fixtures/authorization-contract.json");
    let fixture_tools: BTreeSet<&str> = fixture["operations"]
        .as_array()
        .expect("authorization fixture operations")
        .iter()
        .filter_map(|operation| operation["tool"].as_str())
        .collect();
    check_all(
        &mut gaps,
        "the authorization contract fixture (or the NOT_IN_FIXTURE_OR_AUDIT exemption list in this file)",
        "tests/fixtures/authorization-contract.json",
        ToolKind::ALL
            .into_iter()
            .filter(|kind| {
                !fixture_tools.contains(kind.name())
                    && !NOT_IN_FIXTURE_OR_AUDIT.contains(kind)
            })
            .map(|kind| kind.name().to_string())
            .collect(),
    );

    // Executor audit projection.
    let audit = read_json("src/mcp/executor_prototype/candidate-audit.public.generated.json");
    let audit_tools: BTreeSet<&str> = audit["audit_rows"]
        .as_array()
        .expect("executor audit rows")
        .iter()
        .filter_map(|row| row["legacy_tool"].as_str())
        .collect();
    check_all(
        &mut gaps,
        "the executor audit projection (or the NOT_IN_FIXTURE_OR_AUDIT exemption list in this file)",
        "src/mcp/executor_prototype/candidate-audit.public.generated.json; regenerate with scripts/mcp-executor-candidate.mjs and scripts/mcp-executor-audit-projection.mjs",
        ToolKind::ALL
            .into_iter()
            .filter(|kind| {
                !audit_tools.contains(kind.name())
                    && !NOT_IN_FIXTURE_OR_AUDIT.contains(kind)
            })
            .map(|kind| kind.name().to_string())
            .collect(),
    );

    // Renderer list: every entry is a real tool, and every surface tool
    // renders unless it is deliberately JSON-only.
    check_all(
        &mut gaps,
        "ToolKind (stale RENDERED_TOOLS entry)",
        "src/mcp/render.rs, RENDERED_TOOLS",
        RENDERED_TOOLS
            .iter()
            .filter(|name| !all_names.contains(*name))
            .map(|name| (*name).to_string())
            .collect(),
    );
    let mut surface_registry = ToolRegistry::new();
    register_surface_tools(&mut surface_registry).expect("surface tools register");
    check_all(
        &mut gaps,
        "RENDERED_TOOLS (or the JSON_ONLY_SURFACE_TOOLS exemption list in this file)",
        "src/mcp/render.rs, RENDERED_TOOLS",
        surface_registry
            .specs()
            .filter(|spec| {
                !super::render::has_renderer(&spec.name)
                    && !JSON_ONLY_SURFACE_TOOLS.contains(&spec.name.as_str())
            })
            .map(|spec| spec.name.clone())
            .collect(),
    );

    // Keyed-write allowlist: real tools whose schemas take a key.
    for (tool, _actions) in KEYED_REPLAY_WRITES {
        if !all_names.contains(tool) {
            gaps.push(format!(
                "{tool} is in KEYED_REPLAY_WRITES but is not a shipped tool \
                 (src/mcp/tools/keyed_replay.rs)"
            ));
        } else if let Some(spec) = registry.get(tool) {
            if !schema_advertises_idempotency_key(&spec.input_schema) {
                gaps.push(format!(
                    "{tool} is in KEYED_REPLAY_WRITES but its schema does not declare an \
                     idempotency_key property (src/mcp/tools/keyed_replay.rs)"
                ));
            }
        }
    }

    // KernelV2 adapter keyed writes must agree with the v1 list, apart
    // from the commented exclusions: KERNEL_V2_KEYED_EXCLUSIONS must
    // equal the symmetric difference of the two lists exactly, so each
    // exclusion sits on exactly one side and none is stale. Names only,
    // not actions. Only compiled with the probe graph that carries the
    // const (the check script enables it).
    #[cfg(feature = "v2-kernel-probe")]
    {
        use super::registry::KERNEL_V2_ADAPTER_KEYED_WRITES;
        let v1: BTreeSet<&str> = KEYED_REPLAY_WRITES
            .iter()
            .map(|(tool, _actions)| *tool)
            .collect();
        let v2: BTreeSet<&str> = KERNEL_V2_ADAPTER_KEYED_WRITES.iter().copied().collect();
        let difference: BTreeSet<&str> = v1.symmetric_difference(&v2).copied().collect();
        let exclusions: BTreeSet<&str> = KERNEL_V2_KEYED_EXCLUSIONS.iter().copied().collect();
        if difference != exclusions {
            gaps.push(format!(
                "KERNEL_V2_KEYED_EXCLUSIONS must equal the symmetric difference of \
                 KEYED_REPLAY_WRITES and KERNEL_V2_ADAPTER_KEYED_WRITES exactly: \
                 difference {difference:?} vs exclusions {exclusions:?} \
                 (src/mcp/tool_enumeration.rs, src/mcp/registry.rs, \
                 src/mcp/tools/keyed_replay.rs)"
            ));
        }
    }

    // Action-evidence surfaces name shipped tools.
    check_all(
        &mut gaps,
        "ToolKind (stale action-evidence surface)",
        "src/mcp/action_evidence.rs",
        action_evidence::action_evidence_surfaces()
            .into_iter()
            .filter(|name| !all_names.contains(*name))
            .map(str::to_string)
            .collect(),
    );

    // Profile byte budgets (Focused 72,704 B / Complete 307,200 B).
    if let Err(error) = registry.validate_profile_budgets() {
        gaps.push(format!(
            "profile byte budget exceeded: {error} (src/mcp/registry.rs, \
             COMPLETE_PROFILE_MAX_BYTES / FOCUSED_PROFILE_MAX_BYTES)"
        ));
    }

    assert!(
        gaps.is_empty(),
        "tool enumeration gaps ({}):\n{}",
        gaps.len(),
        gaps.iter()
            .map(|gap| format!("  - {gap}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
