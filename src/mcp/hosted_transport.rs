//! Narrow package boundary for hosted MCP transport behavior.
//!
//! Hosted adapters use these purpose-specific operations instead of reaching
//! into registry and evidence implementation details. The facade deliberately
//! does not expose a public-origin getter or a general capture switch.

use serde_json::Value;

use crate::{Db, Error, Result};

use super::evidence::{attach_references, EvidenceStore, ToolResult};
use super::lens_surface::{lens_exposure_summary, lens_tool, LensToolDispatch, MAX_PAGE_SIZE};
use super::registry::{attach_run_context, run_context_for, Caller, ToolRegistry};
use super::ResolvedToolExposure;

/// Result of resolving one caller-visible record reference for a hosted
/// adapter. Invisible records remain indistinguishable from absent records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostedReferenceResolution {
    Unresolved,
    Resolved(String),
    Ambiguous,
}

/// Resolve one reference without exposing the private record-reference
/// implementation or its snapshot machinery to the held hosting package.
pub async fn resolve_hosted_reference(
    db: &Db,
    caller: &Caller,
    reference: &str,
) -> Result<HostedReferenceResolution> {
    Ok(
        match super::record_ref::resolve_reference(db, caller, reference).await? {
            super::record_ref::ReferenceResolution::Unresolved => {
                HostedReferenceResolution::Unresolved
            }
            super::record_ref::ReferenceResolution::Resolved(record_id) => {
                HostedReferenceResolution::Resolved(record_id)
            }
            super::record_ref::ReferenceResolution::Ambiguous => {
                HostedReferenceResolution::Ambiguous
            }
        },
    )
}

/// Return the author stylesheet advertised by a hosted artifact render.
///
/// Every refusal remains the same `None`: unreadable, absent, unsupported,
/// uncompilable, unstyled, or stale digest.
pub async fn hosted_artifact_stylesheet(
    db: &Db,
    caller: &Caller,
    artifact_id: &str,
    digest: &str,
) -> Result<Option<String>> {
    super::tools::artifacts::artifact_stylesheet(db, caller, artifact_id, digest).await
}

/// Resolve the one lens-local operation implemented by the hosted federation
/// adapter without exposing its private descriptor or dispatch tables.
pub fn lens_local_materialization_name(name: &str) -> Option<&'static str> {
    let tool = lens_tool(name)?;
    match tool.dispatch {
        LensToolDispatch::MaterializeRecord => Some(tool.name),
    }
}

/// Summarize the exact lens descriptor projection for bootstrap framing.
pub fn hosted_lens_exposure_summary(
    registry: &ToolRegistry,
    policy: &ResolvedToolExposure,
) -> Result<Value> {
    lens_exposure_summary(registry, policy)
}

/// Return the authoritative global page-size limit for federated reads.
pub const fn hosted_lens_page_size_max() -> usize {
    MAX_PAGE_SIZE
}

/// Enforce the core attribution projection bound before a federated
/// `get_record` fans out. The bound remains owned by attribution rather than
/// becoming a hosted transport constant.
pub fn validate_federated_interpretation_bearer_count(
    include_interpretation: bool,
    bearer_count: usize,
) -> Result<()> {
    if include_interpretation
        && bearer_count > super::tools::attribution::MAX_GENERIC_INTERPRETATION_BEARERS
    {
        return Err(Error::engine(format!(
            "get_record: include_interpretation supports at most {} ids per call",
            super::tools::attribution::MAX_GENERIC_INTERPRETATION_BEARERS
        )));
    }
    Ok(())
}

/// Resolve the canonical run context for a hosted validation failure without
/// executing a tool handler.
pub async fn resolve_hosted_run_context(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    arguments: &Value,
) -> Value {
    run_context_for(db, caller, arguments, registry.public_origin()).await
}

/// Attach the canonical run-context envelope to a federated tool result.
pub fn attach_federated_run_context(result: Value, run_context: Value) -> Value {
    attach_run_context(result, run_context)
}

/// Deposit transient evidence and frame one successful plain-HTTP tool result.
///
/// Ordering is part of this transport contract: evidence is deposited first,
/// its references are attached without losing primitive payloads, and only
/// then is the canonical run context attached.
pub fn frame_plain_http_tool_result(
    registry: &ToolRegistry,
    evidence: &EvidenceStore,
    principal: &str,
    database: &str,
    result: ToolResult,
    run_context: Value,
) -> Result<Value> {
    let references = evidence.deposit(
        principal,
        database,
        result.evidence,
        registry.public_origin(),
    )?;
    let result = attach_references(result.structured, references);
    Ok(attach_run_context(result, run_context))
}

/// Dispatch one constituent federated read without persisting the source
/// database's ordinary read-capture envelope.
///
/// This is intentionally not a generic capture toggle. Only the three
/// federated read operations may cross this boundary, and the allowlist is
/// enforced before registry lookup or handler dispatch.
pub async fn call_federated_read_uncaptured(
    registry: &ToolRegistry,
    db: Db,
    caller: Caller,
    name: &str,
    arguments: Value,
) -> Result<ToolResult> {
    require_federated_read(name)?;
    registry
        .call_detailed_uncaptured(db, caller, name, arguments)
        .await?
        .outcome
}

fn require_federated_read(name: &str) -> Result<()> {
    if matches!(name, "get_record" | "query_record" | "search") {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "uncaptured federated dispatch is not permitted for tool: {name}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::mcp::{EvidenceStoreOptions, TransientEvidence};

    #[test]
    fn federated_uncaptured_dispatch_rejects_non_read_names_before_dispatch() {
        for allowed in ["get_record", "query_record", "search"] {
            require_federated_read(allowed).unwrap();
        }
        for rejected in ["create_record", "delete_record", "ping", "Get_Record"] {
            let error = require_federated_read(rejected).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("uncaptured federated dispatch is not permitted for tool: {rejected}")
            );
        }
    }

    #[test]
    fn plain_http_framing_wraps_primitive_after_evidence_before_context() {
        let mut registry = ToolRegistry::new();
        registry.set_public_origin(Some("https://native.example".into()));
        let evidence = EvidenceStore::new(EvidenceStoreOptions::default());
        let result = ToolResult::rich(
            json!("primitive"),
            vec![TransientEvidence::image("preview", "image/png", b"pixels").unwrap()],
        );
        let framed = frame_plain_http_tool_result(
            &registry,
            &evidence,
            "principal-a",
            "database-a",
            result,
            json!({"run_key": "run-a", "intent": null, "notes": []}),
        )
        .unwrap();

        assert_eq!(framed["value"], "primitive");
        assert_eq!(framed["run_context"]["run_key"], "run-a");
        let references = framed["transient_evidence"].as_array().unwrap();
        assert_eq!(references.len(), 1);
        assert_eq!(references[0]["handle"], "preview");
        assert!(references[0]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://native.example/databases/database-a/tool-evidence/"));
    }
}
