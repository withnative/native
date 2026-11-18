//! Build-owned guidance reads: the compiled guide corpus and QuickStart.
//!
//! Both are static in v1 — compiled into the binary, with no workspace data and
//! no caller-relative projection — so v2 serves the same compiled values and
//! there is no kernel state to read or gate. Argument validation and the
//! served value are v1's functions, never a second copy.
//!
//! Admission is not theirs to decide: the registry resolves the caller's
//! principal for every KernelV2 call before any handler runs, so a v2 caller
//! must still be a bound, admitted principal — the same for every tool on this
//! engine. What guidance contributes is that nothing it returns depends on who
//! that principal is.
use super::*;

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler(
        "read_guide",
        EngineKind::KernelV2,
        |_engine, _caller, arguments| async move {
            crate::mcp::guides::read_guide_value(arguments)
        },
    )?;
    registry.register_engine_handler(
        "quickstart",
        EngineKind::KernelV2,
        |_engine, _caller, arguments| async move {
            crate::mcp::tools::quickstart::quickstart_value(arguments)
        },
    )
}
