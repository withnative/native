//! Local development artifact export, not remote authentication or admission.
use super::{facet_resolver, generated};
use crate::{Error, Result};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};

/// A selector, never caller-provided SQL, source evidence or a workspace ID.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub actor: String,
    pub bearer: String,
    pub record_type: String,
    pub kind: Option<String>,
    pub home: String,
    pub selection: Selection,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selection {
    Keys { keys: BTreeSet<String> },
    All,
}

/// Read a quiescent local *copy*, never a live hosted database. File access is
/// the trust boundary: actor selects existing kernel visibility, not an
/// authenticated remote identity. No gate, receipt, proof or effect is emitted.
/// Returns canonical JSON bytes without a clock, random ID or ephemeral proof.
pub async fn export_file(path: &Path, request: Request) -> Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    tokio::time::timeout_at(deadline.into(), async {
        let db = crate::db::open_offline_v2_export_at(path).await?;
        let result = async {
            let workspace = {
                let mut conn = db.pool().acquire().await?;
                generated::workspace_on(&mut conn).await?
            };
            let selection = match request.selection {
                Selection::Keys { keys } => crate::query::generated_facets::Selection::Keys(keys),
                Selection::All => crate::query::generated_facets::Selection::All,
            };
            let candidate = facet_resolver::prepare(
                &db,
                &request.actor,
                &workspace,
                &request.bearer,
                facet_resolver::Request {
                    record_type: request.record_type,
                    kind: request.kind,
                    home: request.home,
                    selection,
                },
                deadline,
            )
            .await?;
            candidate.validate(deadline).await?;
            let value = serde_json::json!({
                "format":"native.named-view-development-export.v1",
                "name":candidate.name,
                "definition_sha256":candidate.revision.definition_sha256,
                "definition":candidate.revision.definition,
            });
            Ok(native_artifact_runtime::mdx_v2::canonical_json_bytes(
                &value,
            ))
        }
        .await;
        db.close().await;
        result
    })
    .await
    .map_err(|_| Error::engine("generated export deadline exceeded"))?
}
