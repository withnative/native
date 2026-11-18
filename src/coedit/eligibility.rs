//! Body support is independent of session membership and record authorization.

use crate::generated::kinds::CoreKind;

/// Preserve the ordinary Document surface and admit only governed task/epic
/// WorkItems. A runtime facet always reserves the body for its runtime.
pub(super) async fn markdown_body_supported(
    connection: &mut sqlx::SqliteConnection,
    record_type: &str,
    kind: Option<&str>,
    runtime: bool,
) -> crate::Result<bool> {
    if runtime || !matches!(record_type, "Document" | "WorkItem") {
        return Ok(false);
    }
    let Some(kind) = kind else {
        return Ok(record_type == "Document");
    };
    let resolved = crate::meta::kind::resolve_on(connection, record_type, kind).await?;
    Ok(markdown_kind_supported(record_type, kind, &resolved))
}

/// Shared semantic predicate; each backend supplies its own governed catalogue.
pub(super) fn markdown_kind_supported(
    record_type: &str,
    kind: &str,
    resolved: &crate::meta::kind::KindResolution,
) -> bool {
    match record_type {
        "Document" => {
            kind != "artifact"
                && kind != "instruction"
                && !CoreKind::DocumentArtifact.matches(resolved)
                && resolved.canonical_kind.as_deref() != Some("instruction")
        }
        "WorkItem" => {
            CoreKind::WorkItemTask.matches(resolved) || CoreKind::WorkItemEpic.matches(resolved)
        }
        _ => false,
    }
}
