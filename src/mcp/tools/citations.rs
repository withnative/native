//! Citation resolution and explicit audited target mutation.

use serde::Deserialize;
use serde_json::{json, Value};
#[cfg(feature = "mcp-executor-prototype")]
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::authorization::Capability;
use crate::citations::{capture_target_in, CitationTargetInput};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::store::{append_in, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{
    can_record, parse_args, require_nonblank_reason, require_record_in, REASON_DESCRIPTION,
};

fn citation_not_found(tool: &str, citation_id: &str) -> Error {
    Error::engine(format!("{tool}: citation {citation_id} does not exist"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveCitationArgs {
    citation_id: String,
}

async fn resolve_citation(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ResolveCitationArgs = parse_args("resolve_citation", arguments)?;
    let bearer: Option<String> = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of' LIMIT 1",
    )
    .bind(&args.citation_id)
    .fetch_optional(db.write_pool())
    .await?;
    let bearer = bearer.ok_or_else(|| citation_not_found("resolve_citation", &args.citation_id))?;
    if !can_record(&db, &caller, &bearer, Capability::View).await? {
        return Err(citation_not_found("resolve_citation", &args.citation_id));
    }
    let source: Option<String> = sqlx::query_scalar(
        "SELECT target_record_id FROM annotation_targets WHERE annotation_id = ?",
    )
    .bind(&args.citation_id)
    .fetch_optional(db.write_pool())
    .await?;
    if let Some(source) = source {
        if !can_record(&db, &caller, &source, Capability::View).await? {
            return Err(citation_not_found("resolve_citation", &args.citation_id));
        }
    }
    crate::citations::resolve(&db, &args.citation_id).await
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum ManageCitationsArgs {
    Reanchor {
        citation_id: String,
        target: CitationTargetInput,
        reason: String,
    },
    Remove {
        citation_id: String,
        reason: String,
        #[serde(default)]
        if_content_seq: Option<i64>,
    },
}

#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Debug)]
pub(crate) struct CitationRemovePreparation {
    pub canonical_source_arguments: Value,
    pub target_id: String,
    pub target: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect: Value,
    pub effect_summary: String,
    pub operation_evidence: Value,
}

#[cfg(feature = "mcp-executor-prototype")]
struct CitationRemoveState {
    citation_id: String,
    name: Option<String>,
    kind: String,
    bearer_ids: Vec<String>,
    target: Value,
    previous_seq: i64,
}

async fn assert_target_annotation_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
    require_bearer: bool,
) -> Result<String> {
    let row = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine(format!("target-bearing Annotation {id} does not exist")))?;
    if row.try_get::<String, _>("type")? != "Annotation"
        || !matches!(
            row.try_get::<Option<String>, _>("kind")?.as_deref(),
            Some("citation" | "comment")
        )
    {
        return Err(Error::engine(format!(
            "record {id} is not a target-bearing Annotation kind:citation or kind:comment"
        )));
    }
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "target-bearing Annotation {id} is deleted"
        )));
    }
    if require_bearer {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM links WHERE source_id = ? AND relationship = 'part_of'",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        if count != 1 {
            return Err(Error::engine(format!(
                "target-bearing Annotation {id} requires exactly one outgoing part_of bearer before it can be targeted"
            )));
        }
    }
    Ok(row
        .try_get::<Option<String>, _>("kind")?
        .unwrap_or_default())
}

#[cfg(feature = "mcp-executor-prototype")]
async fn citation_remove_state_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    citation_id: &str,
    if_content_seq: Option<i64>,
) -> Result<CitationRemoveState> {
    const TOOL: &str = "manage_citations";
    if !super::is_legacy_local(caller)
        && require_record_in(tx, caller, TOOL, citation_id, Capability::Edit)
            .await
            .is_err()
    {
        return Err(citation_not_found(TOOL, citation_id));
    }
    let kind = assert_target_annotation_in(tx, citation_id, false).await?;
    let record = sqlx::query("SELECT name FROM records WHERE id = ? AND deleted_at IS NULL")
        .bind(citation_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| citation_not_found(TOOL, citation_id))?;
    let target = sqlx::query("SELECT 1 AS present FROM annotation_targets WHERE annotation_id = ?")
        .bind(citation_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "target-bearing Annotation {citation_id} has no target"
            ))
        })?;
    let target = json!({ "present": target.try_get::<i64, _>("present")? == 1 });
    let bearer_ids: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of' ORDER BY target_id",
    )
    .bind(citation_id)
    .fetch_all(&mut **tx)
    .await?;
    let previous_seq = super::previous_record_seq_in(tx, citation_id)
        .await?
        .ok_or_else(|| citation_not_found(TOOL, citation_id))?;
    if if_content_seq.is_some_and(|expected| expected != previous_seq) {
        return Err(Error::engine(format!(
            "{TOOL}: content revision conflict; resolve the citation and prepare again"
        )));
    }
    Ok(CitationRemoveState {
        citation_id: citation_id.into(),
        name: record.try_get("name")?,
        kind,
        bearer_ids,
        target,
        previous_seq,
    })
}

/// Exercise the exact production remove parser, authorization and target
/// lookup without appending an annotation.target.removed event.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_manage_citations_remove(
    db: &Db,
    caller: &Caller,
    arguments: Value,
) -> Result<CitationRemovePreparation> {
    let ManageCitationsArgs::Remove {
        citation_id,
        reason,
        if_content_seq: None,
    } = parse_args("manage_citations", arguments)?
    else {
        return Err(Error::engine(
            "manage_citations: executor preparation only supports action remove without an internal revision",
        ));
    };
    require_nonblank_reason("manage_citations", &reason)?;
    let mut tx = db.write_pool().begin().await?;
    let state = citation_remove_state_in(&mut tx, caller, &citation_id, None).await?;
    let target = state.name.as_deref().map_or_else(
        || format!("citation {}", state.citation_id),
        |name| format!("{name} ({})", state.citation_id),
    );
    let operation_evidence = json!({
        "citation_id": state.citation_id,
        "name": state.name,
        "kind": state.kind,
        "bearer_ids": state.bearer_ids,
        "target": state.target,
        "previous_seq": state.previous_seq,
    });
    let target_state_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&operation_evidence)?));
    let effect = json!({
        "target": {
            "citation_id": state.citation_id,
            "name": state.name,
            "kind": state.kind,
        },
        "before": { "target": state.target },
        "after": { "target": null },
        "changed": true,
        "reason": reason,
    });
    let preparation = CitationRemovePreparation {
        canonical_source_arguments: json!({
            "action": "remove",
            "citation_id": state.citation_id,
            "reason": reason,
            "if_content_seq": state.previous_seq,
        }),
        target_id: state.citation_id.clone(),
        target: target.clone(),
        state_revision: format!("content-seq:{}", state.previous_seq),
        target_state_digest,
        effect,
        effect_summary: format!(
            "remove the anchored target from {target} while retaining the annotation record"
        ),
        operation_evidence,
    };
    tx.rollback().await?;
    Ok(preparation)
}

async fn manage_citations(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "manage_citations";
    let args: ManageCitationsArgs = parse_args(TOOL, arguments)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let (citation_id, event_type, payload, reason) = match args {
        ManageCitationsArgs::Reanchor {
            citation_id,
            target,
            reason,
        } => {
            require_nonblank_reason(TOOL, &reason)?;
            let bearer: Option<String> = sqlx::query_scalar(
                "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of' LIMIT 1",
            )
            .bind(&citation_id)
            .fetch_optional(&mut *tx)
            .await?;
            let bearer = bearer.ok_or_else(|| citation_not_found(TOOL, &citation_id))?;
            if require_record_in(&mut tx, &caller, TOOL, &bearer, Capability::Edit)
                .await
                .is_err()
            {
                return Err(citation_not_found(TOOL, &citation_id));
            }
            let kind = assert_target_annotation_in(&mut tx, &citation_id, true).await?;
            if kind == "comment" {
                let bearer_kind: Option<Option<String>> = sqlx::query_scalar(
                    "SELECT kind FROM records WHERE id = ? AND type = 'Annotation' AND deleted_at IS NULL",
                )
                .bind(&bearer)
                .fetch_optional(&mut *tx)
                .await?;
                let bearer_kind = bearer_kind.flatten();
                if bearer_kind.as_deref() == Some("comment") {
                    return Err(Error::engine(
                        "manage_citations: comment replies must be targetless; quoted context belongs to the root",
                    ));
                }
                if target.source_slot != crate::citations::SourceSlot::Body
                    || target.target_record_id != bearer
                {
                    return Err(Error::engine(
                        "manage_citations: anchored comment root must target its part_of bearer's body",
                    ));
                }
            }
            if require_record_in(
                &mut tx,
                &caller,
                TOOL,
                &target.target_record_id,
                Capability::View,
            )
            .await
            .is_err()
            {
                return Err(citation_not_found(TOOL, &citation_id));
            }
            let mut payload = serde_json::to_value(capture_target_in(&mut tx, target).await?)?;
            payload
                .as_object_mut()
                .expect("target payload")
                .insert("reason".into(), json!(reason));
            (citation_id, "annotation.target.set", payload, reason)
        }
        ManageCitationsArgs::Remove {
            citation_id,
            reason,
            if_content_seq,
        } => {
            require_nonblank_reason(TOOL, &reason)?;
            // Removal remains available as remediation for an older/drifted
            // bearerless or malformed target. Portable callers authorize the
            // citation itself so the shared evaluator enforces its exact-one,
            // live bearer chain; trusted local remains the explicit repair
            // boundary and only requires the citation record to exist.
            if !super::is_legacy_local(&caller)
                && require_record_in(&mut tx, &caller, TOOL, &citation_id, Capability::Edit)
                    .await
                    .is_err()
            {
                return Err(citation_not_found(TOOL, &citation_id));
            }
            assert_target_annotation_in(&mut tx, &citation_id, false).await?;
            let exists: Option<i64> =
                sqlx::query_scalar("SELECT 1 FROM annotation_targets WHERE annotation_id = ?")
                    .bind(&citation_id)
                    .fetch_optional(&mut *tx)
                    .await?;
            if exists.is_none() {
                return Err(Error::engine(format!(
                    "target-bearing Annotation {citation_id} has no target"
                )));
            }
            if let Some(expected) = if_content_seq {
                let actual = super::previous_record_seq_in(&mut tx, &citation_id).await?;
                if actual != Some(expected) {
                    return Err(Error::engine(format!(
                        "{TOOL}: content revision conflict; resolve the citation and prepare again"
                    )));
                }
            }
            (
                citation_id,
                "annotation.target.removed",
                json!({ "reason": reason }),
                reason,
            )
        }
    };
    let event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: citation_id.clone(),
            event_type: event_type.into(),
            payload,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(json!({
        "citation_id": citation_id,
        "action": if event_type.ends_with("removed") { "removed" } else { "reanchored" },
        "event_seq": event.local_seq,
        "reason": reason
    }))
}

pub(crate) fn target_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "target_record_id": { "type": "string" },
            "source_slot": { "type": "string", "enum": ["body", "blob"] },
            "purpose": { "type": "string" },
            "selectors": {
                "type": "array", "minItems": 1,
                "items": { "oneOf": [
                    { "type": "object", "properties": { "type": { "const": "text_quote" }, "exact": { "type": "string", "minLength": 1 }, "prefix": { "type": "string" }, "suffix": { "type": "string" } }, "required": ["type", "exact"], "additionalProperties": false },
                    { "type": "object", "properties": { "type": { "const": "data_position" }, "start": { "type": "integer", "minimum": 0 }, "end": { "type": "integer", "minimum": 1 }, "selected_sha256": { "type": "string" } }, "required": ["type", "start", "end"], "additionalProperties": false },
                    { "type": "object", "description": "Strict v1 CSV fragment: conforms_to must be https://www.rfc-editor.org/rfc/rfc7111 and value must be one positive 1-based row=N or cell=ROW,COLUMN coordinate. Ranges, wildcards, multiple selections, and other conformances are rejected. Row selects raw row bytes without CRLF/LF; cell selects the raw encoded field including quotes. Must pair with data_position and identify exactly the same bytes.", "properties": { "type": { "const": "fragment" }, "conforms_to": { "type": "string" }, "value": { "type": "string", "pattern": "^(row=[1-9][0-9]*|cell=[1-9][0-9]*,[1-9][0-9]*)$" } }, "required": ["type", "conforms_to", "value"], "additionalProperties": false }
                ] }
            }
        },
        "required": ["target_record_id", "source_slot", "selectors"],
        "additionalProperties": false
    })
}

pub fn register_citation_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ResolveCitation,
        "Resolve an Annotation kind:citation without mutating it: returns exact anchored evidence and a separate deterministic current-source comparison (`current`, `relocated`, `stale`, `conflict`, or `unavailable`). `unavailable` means the anchor cannot be recovered or verified; a deleted/detached current source with a verified anchor is `stale`.",
        json!({
            "type": "object",
            "properties": { "citation_id": { "type": "string" } },
            "required": ["citation_id"],
            "additionalProperties": false
        }),
        resolve_citation,
    )?;
    registry.register(
        ToolKind::ManageCitations,
        "Re-anchor or remove citation and anchored-comment targets. Writes are audited; reads never re-anchor. A comment root must target its bearer's body.",
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["reanchor", "remove"] },
                "citation_id": { "type": "string" },
                "target": { "allOf": [target_schema()], "description": "Required for reanchor and forbidden for remove." },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
            },
            "required": ["action", "citation_id", "reason"],
            "additionalProperties": false
        }),
        manage_citations,
    )?;
    Ok(())
}

#[cfg(all(test, feature = "mcp-executor-prototype"))]
mod preparation_tests {
    use super::*;
    use crate::events::LinkAddedPayload;

    #[tokio::test]
    async fn remove_preparation_is_non_mutating_and_handler_cas_fences_stale_replay() {
        let db = crate::create_database(":memory:").await.unwrap();
        for record in [
            json!({ "id": "c17a7000-0000-4000-8000-000000000001", "type": "WorkItem", "kind": "task", "name": "Bearer" }),
            json!({ "id": "c17a7000-0000-4000-8000-000000000002", "type": "Document", "kind": "note", "name": "Source", "body": "alpha beta" }),
            json!({ "id": "c17a7000-0000-4000-8000-000000000003", "type": "Annotation", "kind": "citation", "name": "Prepared citation" }),
        ] {
            crate::store::create_record(&db, record).await.unwrap();
        }
        crate::store::add_link(
            &db,
            LinkAddedPayload {
                id: None,
                source_id: "c17a7000-0000-4000-8000-000000000003".into(),
                target_id: "c17a7000-0000-4000-8000-000000000001".into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        manage_citations(
            db.clone(),
            Caller::local(),
            json!({
                "action": "reanchor",
                "citation_id": "c17a7000-0000-4000-8000-000000000003",
                "target": {
                    "target_record_id": "c17a7000-0000-4000-8000-000000000002",
                    "source_slot": "body",
                    "selectors": [{ "type": "text_quote", "exact": "alpha" }],
                },
                "reason": "Anchor the citation before preparing removal",
            }),
        )
        .await
        .unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE annotation_targets SET selectors = 'legacy:not-json' WHERE annotation_id = ?",
        )
        .bind("c17a7000-0000-4000-8000-000000000003")
        .execute(&mut *connection)
        .await
        .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);
        let arguments = json!({
            "action": "remove",
            "citation_id": "c17a7000-0000-4000-8000-000000000003",
            "reason": "Withdraw the obsolete citation target",
        });
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_manage_citations_remove(&db, &Caller::local(), arguments.clone())
            .await
            .unwrap();
        let events_after_prepare: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_after_prepare, events_before);
        assert!(prepared.effect["after"]["target"].is_null());

        crate::store::update_record(
            &db,
            "c17a7000-0000-4000-8000-000000000003",
            json!({ "summary": "changed after approval" }),
        )
        .await
        .unwrap();
        let stale = manage_citations(
            db.clone(),
            Caller::local(),
            prepared.canonical_source_arguments,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(stale.contains("content revision conflict"), "{stale}");

        let fresh = prepare_manage_citations_remove(&db, &Caller::local(), arguments)
            .await
            .unwrap();
        let result = manage_citations(
            db.clone(),
            Caller::local(),
            fresh.canonical_source_arguments.clone(),
        )
        .await
        .unwrap();
        assert_eq!(result["action"], "removed");
        assert!(manage_citations(
            db.clone(),
            Caller::local(),
            fresh.canonical_source_arguments,
        )
        .await
        .is_err());
        let removals: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_events \
             WHERE record_id='c17a7000-0000-4000-8000-000000000003' \
               AND type='annotation.target.removed'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(removals, 1);
    }
}
