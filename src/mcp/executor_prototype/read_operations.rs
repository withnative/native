//! Direct-read routes enabled in the test-only executor facade.
//!
//! The read prototype extends this file without touching candidate manifest,
//! contract extraction, transport framing, tracing, or write-plan state.

use serde_json::Value;

use crate::error::{Error, Result};

pub(super) fn supports(executor: &str, operation: &str) -> bool {
    matches!(
        (executor, operation),
        (
            "records_read",
            "query_record" | "get_record" | "resolve_many" | "search" | "get_structure"
        )
    )
}

pub(super) fn validate(executor: &str, operation: &str, arguments: Value) -> Result<()> {
    match (executor, operation) {
        ("records_read", "query_record") => {
            crate::mcp::tools::querying::validate_query_record_operation(arguments)
        }
        // These handlers deserialize deny-unknown-fields argument structs and
        // perform their data-dependent bounds/authorization checks at the
        // original exact-name dispatch seam. Their registered production
        // ToolSpec is therefore the complete side-effect-free preflight; the
        // facade validates against that source-derived schema before calling
        // the unchanged handler exactly once.
        ("records_read", "get_record" | "resolve_many" | "search" | "get_structure") => Ok(()),
        _ => Err(Error::engine(format!(
            "{executor}.{operation} is not an enabled read prototype operation"
        ))),
    }
}
