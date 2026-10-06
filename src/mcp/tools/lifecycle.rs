//! Tools 5–10 — the record lifecycle (docs/tool-surface.md §Record lifecycle).
//!
//! The thickest spine coupling on the surface, and deliberately thin over it:
//! every content mutation is append-event → project through `store`, with the
//! stage-1 primitives (open call a54f708) supplying the atomicity finding 5
//! flagged — a multi-event call (`create_record` with facets and links,
//! `update_record` touching fields and facets) runs its guards, appends and
//! projections in ONE write transaction via `store::append_in`, so an
//! interruption can no longer leave a visible partial write.
//!
//! Event granularity is the engine's, verbatim: `update_record` appends ONE
//! `record.updated` carrying only the changed record fields (never per-field),
//! plus a separate `facet.set`/`facet.unset` per open facet touched. Guard
//! semantics the tools do NOT re-implement: the tombstone freeze lives in the
//! projector (ef32e44), and archive/restore set/unset semantics live in the
//! `archived` fold (e035091 guard 3) — tools 8–9 dispatch and stay out of the
//! way.

use std::collections::{BTreeMap, BTreeSet};

use native_artifact_runtime::mdx_v2;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::authorization::{AllowEntry, Capability};
use crate::db::{apply_schema, open_database, Db};
use crate::error::{Error, Result};
use crate::events::{
    ArtifactInputCarriedPayload, ArtifactInputUnboundPayload, ArtifactModuleGrantCarriedPayload,
    ArtifactModuleGrantPayload,
};
use crate::provenance::Channel;
use crate::query::lens::{self, ReadLens};
use crate::query::{cascade, read};
use crate::record_type_correction::Blocker;
use crate::schema::{spine_facet_column, ARCHIVED_FACET_KEY, SPINE_TYPES, SPINE_TYPE_GLOSSES};
use crate::store::{
    append_in, append_record_type_correction_in, append_with_event_id_in, AppendSpec,
};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{
    echo_act, echo_previous_seq, parse_args, previous_record_seq_in, require_nonblank_reason,
    require_record, require_record_in, PREVIOUS_SEQ_DESCRIPTION, REASON_DESCRIPTION,
};

/// Cap on one `get_record` batch.
pub(crate) const MAX_BATCH_GET: usize = 100;

/// Multi-target `update_record` deliberately shares the ordinary read-batch
/// ceiling: the caller names a closed cohort, validation stays bounded, and a
/// successful receipt can preserve one input-correlated row per target.
pub(crate) const MAX_MULTI_UPDATE: usize = 100;

/// Atomic multi-target rejections keep diagnostics useful without echoing an
/// unbounded cohort through the error channel.
const MAX_MULTI_UPDATE_FAILURE_DETAILS: usize = 20;

/// Controls whether a successful single-record write returns the compact
/// continuation receipt or the complete enriched record shape.
#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResponseMode {
    #[default]
    Summary,
    Verbose,
}

#[cfg(test)]
mod response_mode_tests {
    use super::*;

    async fn setup() -> (crate::Db, crate::mcp::ToolRegistry) {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, registry)
    }

    fn assert_summary(result: &Value) {
        for key in [
            "id",
            "type",
            "kind",
            "name",
            "display_reference",
            "version",
            "body_digest",
            "lifecycle_interpretation",
        ] {
            assert!(result.get(key).is_some(), "missing {key}: {result}");
        }
        assert!(result["version"]
            .as_str()
            .is_some_and(|version| version.starts_with("rec:")));
        assert!(result["warnings"].is_array());
        assert!(
            result.get("body").is_none(),
            "summary leaked body: {result}"
        );
        assert!(
            result.get("contribution").is_none(),
            "summary leaked enrichment: {result}"
        );
    }

    #[tokio::test]
    async fn singular_write_response_modes_default_to_summary_and_preserve_verbose_shapes() {
        let (db, registry) = setup().await;
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "compact create",
                    "body": "known prose",
                    "reason": "exercise compact creation",
                }),
            )
            .await
            .unwrap();
        assert_summary(&created);

        let verbose_created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "verbose create",
                    "body": "complete prose",
                    "reason": "exercise verbose creation",
                    "response_mode": "verbose",
                }),
            )
            .await
            .unwrap();
        assert_eq!(verbose_created["body"], json!("complete prose"));
        assert!(verbose_created.get("display_reference").is_none());
        assert!(verbose_created.get("version").is_none());

        let updated = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": created["id"],
                    "body_append": " plus",
                    "reason": "exercise compact update",
                }),
            )
            .await
            .unwrap();
        assert_summary(&updated);
        assert_eq!(updated["body_receipt"]["operation"], json!("body_append"));
        assert!(updated.get("previous_seq").is_some());

        let verbose_updated = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": verbose_created["id"],
                    "body_append": " plus",
                    "reason": "exercise verbose update",
                    "response_mode": "verbose",
                }),
            )
            .await
            .unwrap();
        assert_eq!(verbose_updated["body"], json!("complete prose plus"));
        assert!(verbose_updated.get("display_reference").is_none());
        assert!(verbose_updated.get("version").is_none());
        db.close().await;
    }

    #[tokio::test]
    async fn create_idempotency_ignores_response_mode_and_shapes_the_retry_requested() {
        let (db, registry) = setup().await;
        let base = json!({
            "type": "Document",
            "kind": "note",
            "body": "retry prose",
            "reason": "exercise presentation-only retry",
            "idempotency_key": "response-mode-retry",
        });
        let summary = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                base.clone(),
            )
            .await
            .unwrap();
        assert_summary(&summary);
        let mut verbose_args = base;
        verbose_args["response_mode"] = json!("verbose");
        let verbose = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                verbose_args,
            )
            .await
            .unwrap();
        assert_eq!(verbose["id"], summary["id"]);
        assert_eq!(verbose["body"], json!("retry prose"));
        let creates: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_events WHERE record_id = ? AND type = 'record.created'",
        )
        .bind(summary["id"].as_str().unwrap())
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(creates, 1);
        db.close().await;
    }
}

impl ResponseMode {
    async fn render(self, db: &Db, result: Value, version_seq: i64) -> Result<Value> {
        match self {
            Self::Summary => summarize_write_receipt(db, result, version_seq).await,
            Self::Verbose => Ok(result),
        }
    }
}

/// Keep exactly the information a caller needs to continue a write workflow,
/// while omitting the record body and its expensive enrichments. Operation
/// receipts remain top-level under their established names so a compact
/// response is a projection of the verbose response rather than a second
/// protocol.
async fn summarize_write_receipt(db: &Db, result: Value, version_seq: i64) -> Result<Value> {
    const REQUIRED: [&str; 6] = [
        "id",
        "type",
        "kind",
        "name",
        "body_digest",
        "lifecycle_interpretation",
    ];
    const OPTIONAL_RECEIPTS: [&str; 12] = [
        "previous_seq",
        "act",
        "body_receipt",
        "html_body_write",
        "delivery",
        "action_attestation_ids",
        "artifact_input_continuity",
        "work_overlap",
        // The declared source basis's write-response line, when this call had
        // one to report. Its absence is meaningful: no declaration and no
        // pointer (replay, non-agent channel, or already declared this run).
        "basis",
        // Present only when this call created a body-bearing event: the event
        // id is the exact-source identity artifact grants name as
        // `subject_event_id`, next to the `body_digest` they use as
        // `source_sha256`.
        "source_event_id",
        "similar_existing",
        // Post-commit advisor output (S1). Present only when non-empty, so
        // receipts without a firing advisor stay byte-identical.
        "advisories",
    ];

    let object = result
        .as_object()
        .ok_or_else(|| Error::engine("single-record write returned a non-object result"))?;
    let mut receipt = Map::new();
    for key in REQUIRED {
        let value = object.get(key).ok_or_else(|| {
            Error::engine(format!("single-record write receipt is missing '{key}'"))
        })?;
        receipt.insert(key.into(), value.clone());
    }
    let id = receipt["id"]
        .as_str()
        .ok_or_else(|| Error::engine("single-record write receipt has a non-string id"))?;
    // A display reference is a SQLite-only addressing affordance. Explicit
    // null makes the compact shape stable when this record has no resolvable
    // prefix, while callers on other backends can use the full id.
    receipt.insert(
        "display_reference".into(),
        serde_json::to_value(crate::mcp::record_ref::display_reference(db, id).await?)?,
    );
    receipt.insert("version".into(), json!(format!("rec:{version_seq}")));
    receipt.insert(
        "warnings".into(),
        object
            .get("warnings")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
    );
    for key in OPTIONAL_RECEIPTS {
        if let Some(value) = object.get(key) {
            receipt.insert(key.into(), value.clone());
        }
    }
    Ok(Value::Object(receipt))
}

/// Deterministic write-response confirmation for a declared basis. It depends
/// only on the request, so an idempotent replay reproduces it byte-for-byte.
fn declared_basis_feedback(declared: Option<usize>) -> Option<Value> {
    let count = declared?;
    let (status, message) = match count {
        0 => ("declared_none", "basis: declared as none".to_string()),
        1 => ("declared", "basis: 1 source recorded".to_string()),
        _ => ("declared", format!("basis: {count} sources recorded")),
    };
    Some(json!({
        "status": status,
        "source_count": count,
        "message": message,
    }))
}

/// The one quiet pointer shown on an agent channel when a write declares
/// nothing. Suppressed once the run has declared at least once, read cheaply
/// from that run's own committed events rather than tracked in new
/// run-scoped state. Absent (or non-MCP) channels get nothing.
async fn undeclared_basis_feedback(db: &Db, caller: &Caller) -> Result<Option<Value>> {
    if caller.channel() != Channel::Mcp {
        return Ok(None);
    }
    if let Some(run_key) = caller.run_key() {
        let already: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_events \
             WHERE run_key=? AND json_extract(payload,'$.basis') IS NOT NULL)",
        )
        .bind(run_key)
        .fetch_one(db.write_pool())
        .await?;
        if already {
            return Ok(None);
        }
    }
    Ok(Some(json!({
        "status": "not_declared",
        "source_count": 0,
        "message": "no sources declared",
    })))
}

/// Attach the write-response basis line: the deterministic declaration
/// confirmation when the caller declared (including declared-none), and the
/// quiet absence pointer only when this create is not a replay. A keyed
/// create's replay must return a byte-identical receipt, and the absence
/// pointer is derived from live run history, so it is suppressed there exactly
/// as `similar_existing` is.
///
/// Deliberately infallible. It runs after the write has committed, so an error
/// here must never turn a committed write into an `Err`: on a keyless create a
/// caller's natural retry would then duplicate the record. The absence pointer
/// is an advisory, and every advisory on this path is fail-silent — see
/// `similar::notice_for_create`, which swallows its own lookup the same way.
/// The declared confirmation does not query, so it is unaffected and exact.
pub(super) async fn attach_basis_feedback(
    db: &Db,
    caller: &Caller,
    result: &mut Value,
    declared: Option<usize>,
    replay: bool,
) {
    let feedback = match declared_basis_feedback(declared) {
        Some(feedback) => Some(feedback),
        None if replay => None,
        None => undeclared_basis_feedback(db, caller).await.ok().flatten(),
    };
    if let Some(feedback) = feedback {
        if let Some(object) = result.as_object_mut() {
            object.insert("basis".into(), feedback);
        }
    }
}

async fn current_record_version_in(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    record_id: &str,
) -> Result<i64> {
    sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine(format!("record {record_id} has no content version")))
}

fn html_body_write_result(manifest: &crate::artifact_html::Manifest, source: &str) -> Value {
    let mut receipt = json!({
        "algorithm": "sha256",
        "sha256": manifest.body_digest,
        "utf8_bytes": manifest.body_utf8_bytes,
        "characters": source.chars().count(),
    });
    // Warning-only write-time findings ride the same fixed element shape the
    // render serves, so an agent reading the receipt and a person reading the
    // artifact see the same list. Absent means none; the write always succeeds.
    if !manifest.diagnostics.is_empty() {
        if let Some(object) = receipt.as_object_mut() {
            object.insert(
                "write_diagnostics".into(),
                serde_json::to_value(&manifest.diagnostics)
                    .unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
            );
        }
    }
    receipt
}

/// The governed-HTML write receipt.
///
/// Renamed from `body_digest` when `get_record` and the write responses gained
/// the ordinary record-shape `body_digest` token: one key cannot be both a
/// plain hex string a caller copies into `if_body_digest` and an object
/// describing an HTML validation pass. The receipt keeps every field it had,
/// including `sha256`, which is the same value the plain token now carries.
fn attach_html_body_write(mut result: Value, body_write: Option<Value>) -> Result<Value> {
    if let Some(body_write) = body_write {
        result
            .as_object_mut()
            .ok_or_else(|| Error::engine("HTML record write returned a non-object result"))?
            .insert("html_body_write".into(), body_write);
    }
    Ok(result)
}

fn attach_artifact_input_continuity(mut result: Value, continuity: Option<Value>) -> Result<Value> {
    let Some(continuity) = continuity else {
        return Ok(result);
    };
    let status = continuity["status"]
        .as_str()
        .unwrap_or("artifact_inputs_no_existing_state")
        .to_owned();
    let ports = continuity["ports"].clone();
    // The new exact source this write attested. A caller restoring dropped
    // grants needs exactly these two values for
    // `manage_artifact_module_grants.grant`: the event id as `subject_event_id`
    // and the digest as `source_sha256` (the receipt's `body_digest`).
    let source_event_id = continuity["source_event_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let source_sha256 = continuity["source_sha256"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    // Not every drop is caused by a declaration change: a withdrawn capability
    // request drops its grant while every port declaration stays byte-identical.
    // Say which happened rather than asserting a diff the caller cannot find.
    let declarations_changed = continuity["changed_ports"]
        .as_array()
        .is_some_and(|ports| !ports.is_empty());
    let message = match status.as_str() {
        "artifact_inputs_carried_forward" => {
            "Input bindings and every compatible capability grant were carried to the new exact source.".to_owned()
        }
        "artifact_inputs_partially_carried" => {
            let cause = if declarations_changed {
                "across a declaration change"
            } else {
                "because some grants no longer match the new source"
            };
            format!(
                "Input state was partially carried {cause}; the drops are listed in artifact_input_continuity.dropped; restore them with manage_artifact_inputs and manage_artifact_module_grants.grant using subject_event_id \"{source_event_id}\" and source_sha256 \"{source_sha256}\"."
            )
        }
        "artifact_inputs_dropped" => {
            let cause = if declarations_changed {
                "Input declarations changed, so nothing could be carried"
            } else {
                "Nothing could be carried, because no remaining grant matches the new source"
            };
            format!(
                "{cause}; the drops are listed in artifact_input_continuity.dropped; restore them with manage_artifact_inputs and manage_artifact_module_grants.grant using subject_event_id \"{source_event_id}\" and source_sha256 \"{source_sha256}\"."
            )
        }
        _ => "The artifact body changed, but there was no exact current input state to carry.".to_owned(),
    };
    let object = result
        .as_object_mut()
        .ok_or_else(|| Error::engine("update_record returned a non-object result"))?;
    let mut warning = json!({"code": status, "message": message, "ports": ports});
    // Machine-readable form of the same restoration identity the message
    // names, so a caller re-granting does not have to parse prose.
    if !source_event_id.is_empty() && !source_sha256.is_empty() {
        warning["source_event_id"] = json!(source_event_id);
        warning["source_sha256"] = json!(source_sha256);
    }
    // The per-port carry decision, so a caller restoring drops does not have
    // to diff declarations itself.
    if let Some(changed_ports) = continuity.get("changed_ports") {
        warning["changed_ports"] = changed_ports.clone();
    }
    if let Some(dropped) = continuity.get("dropped") {
        warning["dropped"] = dropped.clone();
    }
    object.insert("artifact_input_continuity".into(), continuity);
    crate::domain_transaction::push_receipt_warning(&mut result, warning)?;
    Ok(result)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorrectRecordTypeArgs {
    pub(crate) record_id: String,
    pub(crate) target_type: String,
    pub(crate) target_kind: String,
    pub(crate) reason: String,
    #[serde(default)]
    pub(crate) if_content_seq: Option<i64>,
    #[serde(default)]
    pub(crate) if_schema_state_revision: Option<String>,
    #[serde(default)]
    pub(crate) if_dependency_digest: Option<String>,
    #[serde(default)]
    pub(crate) plan_id: Option<String>,
    #[serde(default)]
    pub(crate) effect_digest: Option<String>,
    #[serde(default)]
    pub(crate) mode: Option<String>,
    #[serde(default)]
    pub(crate) confirmation_required: Option<bool>,
}

#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Debug)]
pub(crate) struct CorrectRecordTypePreparation {
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
impl From<crate::record_type_correction::PreparedCorrection> for CorrectRecordTypePreparation {
    fn from(prepared: crate::record_type_correction::PreparedCorrection) -> Self {
        Self {
            canonical_source_arguments: prepared.canonical_source_arguments,
            target_id: prepared.target_id,
            target: prepared.target,
            state_revision: prepared.state_revision,
            target_state_digest: prepared.target_state_digest,
            effect: prepared.effect,
            effect_summary: prepared.effect_summary,
            operation_evidence: prepared.operation_evidence,
        }
    }
}

async fn correction_schema_revision_in(tx: &mut Transaction<'_, Sqlite>) -> Result<String> {
    let (meta, content): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE((SELECT MAX(seq) FROM meta_events),0),
                COALESCE((SELECT MAX(seq) FROM content_events),0)",
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(format!("schema-state-v1:meta:{meta}:content:{content}"))
}

async fn dependent_ids_in(
    tx: &mut Transaction<'_, Sqlite>,
    record_id: &str,
) -> Result<BTreeMap<String, Vec<String>>> {
    let queries = [
        ("incoming_links", "SELECT source_id AS id FROM links WHERE target_id=? ORDER BY source_id LIMIT 20"),
        ("outgoing_links", "SELECT target_id AS id FROM links WHERE source_id=? ORDER BY target_id LIMIT 20"),
        ("children", "SELECT id FROM records WHERE home_id=? AND deleted_at IS NULL ORDER BY id LIMIT 20"),
        ("comments", "SELECT r.id FROM links l JOIN records r ON r.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND r.type='Annotation' AND r.kind='comment' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20"),
        ("citations", "SELECT r.id FROM links l JOIN records r ON r.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND r.type='Annotation' AND r.kind='citation' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20"),
        ("attachments", "SELECT r.id FROM links l JOIN records r ON r.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND r.type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20"),
        ("targeted_annotations", "SELECT annotation_id AS id FROM annotation_targets WHERE target_record_id=? ORDER BY annotation_id LIMIT 20"),
        ("attributions", "SELECT annotation_id AS id FROM attribution_targets WHERE target_record_id=? ORDER BY annotation_id LIMIT 20"),
        ("relationships", "SELECT e.relationship_origin_db_id || ':' || e.relationship_id || ':' || r.status || ':' || r.stream_version || ':' || r.last_event_issuer_origin_db_id || ':' || r.last_event_id AS id FROM relationship_endpoints e JOIN relationships r USING (relationship_origin_db_id,relationship_id) WHERE e.record_id=? ORDER BY e.relationship_origin_db_id,e.relationship_id LIMIT 20"),
        ("bindings", "SELECT system || ':' || identifier || ':' || is_canonical AS id FROM bindings WHERE record_id=? ORDER BY system,identifier LIMIT 20"),
    ];
    let mut result = BTreeMap::new();
    for (name, query) in queries {
        let rows = sqlx::query_scalar::<_, String>(query)
            .bind(record_id)
            .fetch_all(&mut **tx)
            .await?;
        result.insert(name.into(), rows);
    }
    Ok(result)
}

async fn correction_snapshot_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    args: &CorrectRecordTypeArgs,
    required: Capability,
) -> Result<crate::record_type_correction::CorrectionPlan> {
    const TOOL: &str = "correct_record_type";
    require_record_in(tx, caller, TOOL, &args.record_id, required).await?;
    require_nonblank_reason(TOOL, &args.reason)?;
    if !SPINE_TYPES.contains(&args.target_type.as_str()) || args.target_kind.trim().is_empty() {
        return Err(Error::engine(format!(
            "correct_record_type: target_type must be a closed spine type ({}) and target_kind must be non-empty",
            SPINE_TYPES.join(", "),
        )));
    }
    let row = sqlx::query(
        "SELECT id,type,kind,name,body,home_id,updated_at,deleted_at FROM records WHERE id=?",
    )
    .bind(&args.record_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{TOOL}: record {} does not exist", args.record_id)))?;
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.record_id
        )));
    }
    let current_type: String = row.try_get("type")?;
    let current_kind: String = row.try_get::<Option<String>, _>("kind")?.ok_or_else(|| {
        Error::engine(
            "correct_record_type: current record has no kind and cannot preserve identity",
        )
    })?;
    let name: String = row.try_get("name")?;
    let body: Option<String> = row.try_get("body")?;
    let home_id: Option<String> = row.try_get("home_id")?;
    let updated_at: String = row.try_get("updated_at")?;
    let previous_seq = previous_record_seq_in(tx, &args.record_id)
        .await?
        .ok_or_else(|| {
            Error::engine(format!("{TOOL}: record {} does not exist", args.record_id))
        })?;
    if args
        .if_content_seq
        .is_some_and(|expected| expected != previous_seq)
    {
        return Err(Error::engine(
            "correct_record_type: content revision conflict; prepare again",
        ));
    }

    let target_resolution =
        crate::meta::kind::resolve_on(tx, &args.target_type, &args.target_kind).await?;
    let target_active = !target_resolution.quarantined;
    let canonical_target_kind = target_resolution
        .canonical_kind
        .clone()
        .unwrap_or_else(|| args.target_kind.clone());
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&args.record_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    let prospective_program_error = validate_prospective_program(
        TOOL,
        &args.target_type,
        Some(&canonical_target_kind),
        runtime.as_deref(),
    )
    .err()
    .map(|error| error.to_string());
    let current_resolution =
        crate::meta::kind::resolve_on(tx, &current_type, &current_kind).await?;
    let mut matching_types = Vec::new();
    for record_type in SPINE_TYPES {
        let resolution = crate::meta::kind::resolve_on(tx, record_type, &current_kind).await?;
        if !resolution.quarantined {
            matching_types.push(record_type);
        }
    }
    let unique_wrong_type_match = current_resolution.quarantined
        && matching_types.as_slice() == [args.target_type.as_str()]
        && target_active
        && canonical_target_kind == current_kind;

    let bounded_ids = dependent_ids_in(tx, &args.record_id).await?;
    let count_queries = [
        ("incoming_links", "SELECT COUNT(*) FROM links WHERE target_id=?"),
        ("outgoing_links", "SELECT COUNT(*) FROM links WHERE source_id=?"),
        ("children", "SELECT COUNT(*) FROM records WHERE home_id=? AND deleted_at IS NULL"),
        ("comments", "SELECT COUNT(*) FROM links l JOIN records r ON r.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND r.type='Annotation' AND r.kind='comment' AND r.deleted_at IS NULL"),
        ("citations", "SELECT COUNT(*) FROM links l JOIN records r ON r.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND r.type='Annotation' AND r.kind='citation' AND r.deleted_at IS NULL"),
        ("attachments", "SELECT COUNT(*) FROM links l JOIN records r ON r.id=l.source_id WHERE l.target_id=? AND l.relationship='part_of' AND r.type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL"),
        ("targeted_annotations", "SELECT COUNT(*) FROM annotation_targets WHERE target_record_id=?"),
        ("attributions", "SELECT COUNT(*) FROM attribution_targets WHERE target_record_id=?"),
        ("relationships", "SELECT COUNT(*) FROM relationship_endpoints WHERE record_id=?"),
        ("bindings", "SELECT COUNT(*) FROM bindings WHERE record_id=?"),
    ];
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    for (key, query) in count_queries {
        counts.insert(
            key.into(),
            sqlx::query_scalar(query)
                .bind(&args.record_id)
                .fetch_one(&mut **tx)
                .await?,
        );
    }
    let facets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM facet_values WHERE record_id=?")
        .bind(&args.record_id)
        .fetch_one(&mut **tx)
        .await?;
    counts.insert("facets".into(), facets);

    let mut relevant_ids = BTreeSet::from([args.record_id.clone()]);
    for (category, ids) in &bounded_ids {
        if !matches!(category.as_str(), "relationships" | "bindings") {
            relevant_ids.extend(ids.iter().cloned());
        }
    }
    let caller_run = caller.run_key();
    let mut same_run_provenance = caller_run.is_some();
    let mut creation_matches = false;
    for id in &relevant_ids {
        let events = sqlx::query(
            "SELECT type,actor,run_key FROM content_events WHERE record_id=? ORDER BY seq",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await?;
        for event in events {
            let event_type: String = event.try_get("type")?;
            let actor: Option<String> = event.try_get("actor")?;
            let run_key: Option<String> = event.try_get("run_key")?;
            let matches =
                actor.as_deref() == Some(caller.actor()) && run_key.as_deref() == caller_run;
            same_run_provenance &= matches;
            if id == &args.record_id && event_type == "record.created" {
                creation_matches = matches;
            }
        }
    }
    same_run_provenance &= creation_matches;
    let replicated: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events e JOIN content_event_sources s ON s.event_id=e.id WHERE e.record_id=?)",
    ).bind(&args.record_id).fetch_one(&mut **tx).await?;
    same_run_provenance &= !replicated;

    let mut blockers = Vec::new();
    let mut block = |blocker: Blocker| blockers.push(blocker);
    if crate::schema::ENGINE_PROVISIONED_RECORD_IDS.contains(&args.record_id.as_str()) {
        block(Blocker::EngineFilingRecord);
    }
    if let Some(detail) = prospective_program_error {
        block(Blocker::ProspectiveProgramShape { detail });
    }
    if args.target_type == "Message" {
        block(Blocker::MessageTargetShape);
    }
    if args.target_type == "Annotation"
        && matches!(
            canonical_target_kind.as_str(),
            "attribution" | "citation" | "comment"
        )
    {
        block(Blocker::GovernedAnnotationTargetShape);
    }
    let specialised: (i64, i64, i64, Option<String>) = sqlx::query_as(
        "SELECT
           EXISTS(SELECT 1 FROM semantic_units WHERE unit_id=?),
           EXISTS(SELECT 1 FROM annotation_targets WHERE annotation_id=?),
           EXISTS(SELECT 1 FROM attribution_assertions WHERE annotation_id=?),
           (SELECT status FROM message_audience_state WHERE message_id=?)",
    )
    .bind(&args.record_id)
    .bind(&args.record_id)
    .bind(&args.record_id)
    .bind(&args.record_id)
    .fetch_one(&mut **tx)
    .await?;
    if specialised.0 != 0 {
        block(Blocker::SemanticUnit);
    }
    if specialised.1 != 0 {
        block(Blocker::TargetedAnnotation);
    }
    if specialised.2 != 0 || (current_type == "Annotation" && current_kind == "attribution") {
        block(Blocker::GovernedAttribution);
    }
    if current_type == "Message" && specialised.3.as_deref() != Some("pending_local") {
        block(Blocker::MessageDeliveryState);
    }
    let specialised_aggregate: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM module_releases WHERE module_record_id=?)
             OR EXISTS(SELECT 1 FROM recipe_releases WHERE program_id=?)
             OR EXISTS(SELECT 1 FROM artifact_source_attestations WHERE artifact_id=?)
             OR EXISTS(SELECT 1 FROM derivation_target_heads WHERE target_kind='record' AND target_record_id=?)
             OR EXISTS(SELECT 1 FROM derivation_artifact_role_heads WHERE target_kind='record' AND target_record_id=?)",
    )
    .bind(&args.record_id)
    .bind(&args.record_id)
    .bind(&args.record_id)
    .bind(&args.record_id)
    .bind(&args.record_id)
    .fetch_one(&mut **tx)
    .await?;
    if specialised_aggregate {
        block(Blocker::SpecialisedAggregate);
    }
    let incompatible_binding: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM bindings b JOIN binding_systems s ON s.system=b.system
              WHERE b.record_id=?
                AND ((s.compatible_type IS NOT NULL AND s.compatible_type<>?)
                  OR (s.compatible_kind IS NOT NULL AND s.compatible_kind<>?)))",
    )
    .bind(&args.record_id)
    .bind(&args.target_type)
    .bind(&canonical_target_kind)
    .fetch_one(&mut **tx)
    .await?;
    if incompatible_binding {
        block(Blocker::IncompatibleIdentityBinding);
    }
    let schema_rows = cascade::schema_config_rows_with(
        &mut crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx),
    )
    .await?;
    let target_facets = cascade::facets_for_record_context(
        &schema_rows,
        &args.target_type,
        Some(&canonical_target_kind),
        home_id.as_deref(),
    );
    let present_open: BTreeSet<String> =
        sqlx::query_scalar("SELECT key FROM facet_values WHERE record_id=? AND value IS NOT NULL")
            .bind(&args.record_id)
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .collect();
    for (key, shape) in target_facets {
        if shape.get("required") != Some(&Value::Bool(true)) {
            continue;
        }
        let present = match spine_facet_column(&key) {
            Some("lifecycle") => {
                sqlx::query_scalar("SELECT lifecycle IS NOT NULL FROM records WHERE id=?")
                    .bind(&args.record_id)
                    .fetch_one(&mut **tx)
                    .await?
            }
            Some("owner_id") => {
                sqlx::query_scalar("SELECT owner_id IS NOT NULL FROM records WHERE id=?")
                    .bind(&args.record_id)
                    .fetch_one(&mut **tx)
                    .await?
            }
            Some("persistence") => {
                sqlx::query_scalar("SELECT persistence IS NOT NULL FROM records WHERE id=?")
                    .bind(&args.record_id)
                    .fetch_one(&mut **tx)
                    .await?
            }
            Some("maturity") => {
                sqlx::query_scalar("SELECT maturity IS NOT NULL FROM records WHERE id=?")
                    .bind(&args.record_id)
                    .fetch_one(&mut **tx)
                    .await?
            }
            Some(other) => {
                return Err(Error::engine(format!(
                    "correct_record_type: unsupported spine facet column '{other}'"
                )))
            }
            None => present_open.contains(&key),
        };
        if !present {
            block(Blocker::RequiredFacetMissing { facet: key });
        }
    }
    let mut preserved_facets =
        resulting_facet_writes_in(tx, &args.record_id, &[], &BTreeSet::new()).await?;
    if let Err(error) = assert_facet_value_predicates_in(
        tx,
        &schema_rows,
        TOOL,
        &args.target_type,
        Some(&canonical_target_kind),
        None,
        &mut preserved_facets,
    )
    .await
    {
        block(Blocker::IncompatibleFacetValue {
            detail: error.to_string(),
        });
    }

    let schema_state_revision = correction_schema_revision_in(tx).await?;
    if args
        .if_schema_state_revision
        .as_deref()
        .is_some_and(|expected| expected != schema_state_revision)
    {
        return Err(Error::engine(
            "correct_record_type: schema state revision conflict; prepare again",
        ));
    }
    let binding_audit_seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq),0) FROM binding_audit WHERE old_record_id=? OR new_record_id=?",
    )
    .bind(&args.record_id)
    .bind(&args.record_id)
    .fetch_one(&mut **tx)
    .await?;
    // Relationship events are a separate append-only domain log. Bind its
    // head as well as the current endpoint/state rows so a status transition,
    // or an add/remove cycle returning to the same projection, invalidates a
    // prepared correction.
    let relationship_event_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM relationship_events")
            .fetch_one(&mut **tx)
            .await?;
    // This adapter can fence on both append-only domain logs it owns. Binding
    // audit and relationship events are separate from `content_events`, so a
    // status transition, or an add/remove cycle returning to the same
    // projection, still invalidates a prepared correction.
    let plan = crate::record_type_correction::CorrectionPlan::new(
        crate::record_type_correction::CorrectionFacts {
            record_id: args.record_id.clone(),
            reason: args.reason.clone(),
            name,
            body_digest: body_digest(body.as_deref()),
            updated_at,
            previous_seq,
            schema_state_revision,
            current: crate::record_type_correction::Identity {
                record_type: current_type,
                kind: current_kind,
            },
            target: crate::record_type_correction::Identity {
                record_type: args.target_type.clone(),
                kind: canonical_target_kind,
            },
            target_active,
            unique_wrong_type_match,
            same_run_provenance,
            preserved_state_counts: counts,
            bounded_identifiers: bounded_ids,
            dependency_fences: BTreeMap::from([
                ("binding_audit_seq".to_string(), json!(binding_audit_seq)),
                (
                    "relationship_event_seq".to_string(),
                    json!(relationship_event_seq),
                ),
            ]),
            blockers,
        },
    )?;
    if args
        .if_dependency_digest
        .as_deref()
        .is_some_and(|expected| expected != plan.dependency_digest())
    {
        return Err(Error::engine(
            "correct_record_type: dependent state changed; prepare again",
        ));
    }
    Ok(plan)
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_correct_record_type(
    db: &Db,
    caller: &Caller,
    arguments: Value,
) -> Result<CorrectRecordTypePreparation> {
    let args: CorrectRecordTypeArgs = parse_args("correct_record_type", arguments)?;
    if args.if_content_seq.is_some()
        || args.if_schema_state_revision.is_some()
        || args.if_dependency_digest.is_some()
        || args.plan_id.is_some()
        || args.effect_digest.is_some()
        || args.mode.is_some()
        || args.confirmation_required.is_some()
    {
        return Err(Error::engine(
            "correct_record_type: preparation does not accept executor-owned fields",
        ));
    }
    let mut tx = db.write_pool().begin().await?;
    let plan = correction_snapshot_in(&mut tx, caller, &args, Capability::Edit).await?;
    let prepared = plan.prepared()?;
    tx.rollback().await?;
    Ok(prepared.into())
}

pub(crate) async fn correct_record_type(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: CorrectRecordTypeArgs = parse_args("correct_record_type", arguments)?;
    require_nonblank_reason("correct_record_type", &args.reason)?;
    let execution = caller.write_plan_execution().ok_or_else(|| {
        Error::engine(
            "correct_record_type: execute only through a claimed records_write.correct_record_type plan",
        )
    })?;
    if execution.executor != "records_write"
        || execution.operation != "correct_record_type"
        || args.plan_id.as_deref() != Some(execution.plan_id.as_str())
        || args.effect_digest.as_deref() != Some(execution.effect_digest.as_str())
    {
        return Err(Error::engine(
            "correct_record_type: executor plan binding does not match the claimed plan",
        ));
    }
    let mode = args.mode.as_deref().ok_or_else(|| {
        Error::engine(
        "correct_record_type: execute only through records_write.correct_record_type preparation"
    )
    })?;
    if mode == "ineligible" {
        return Err(Error::engine("correct_record_type: prepared effect is ineligible; create a new bearer when appropriate"));
    }
    let confirmation_required = args.confirmation_required.unwrap_or(false);
    if (mode == "confirmed") != confirmation_required || !matches!(mode, "autonomous" | "confirmed")
    {
        return Err(Error::engine(
            "correct_record_type: invalid prepared correction mode",
        ));
    }
    let plan_id = args
        .plan_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::engine("correct_record_type: executor plan_id is required"))?;
    let effect_digest = args
        .effect_digest
        .as_deref()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or_else(|| Error::engine("correct_record_type: executor effect_digest is required"))?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    let plan = correction_snapshot_in(
        &mut tx,
        &caller,
        &args,
        if confirmation_required {
            Capability::Manage
        } else {
            Capability::Edit
        },
    )
    .await?;
    let classification = plan.classification();
    let expected_mode = plan.execution_mode();
    if mode != expected_mode {
        return Err(Error::engine(
            "correct_record_type: eligibility changed; prepare again",
        ));
    }
    let event = append_record_type_correction_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: args.record_id.clone(),
            event_type: "record.type_corrected.v1".into(),
            payload: json!({
                "from": classification.current,
                "to": classification.target,
                "mode": mode,
                "reason": args.reason,
                "plan_id": plan_id,
                "effect_digest": format!("sha256:{effect_digest}"),
                "schema_state_revision": plan.schema_state_revision(),
                "confirmation_required": confirmation_required,
            }),
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    db.commit_content(tx).await?;
    echo_act(
        json!({
        "record_id": args.record_id,
        "type": plan.classification().target.record_type,
        "kind": plan.classification().target.kind,
        "mode": mode,
        "event_id": event.id,
        "event_seq": event.local_seq,
        "previous_seq": plan.previous_seq(),
        "body_digest": plan.body_digest(),
        }),
        act_alloc.get(),
    )
}

// ---------------------------------------------------------------------------
// Shared argument plumbing
// ---------------------------------------------------------------------------

/// One outgoing link on `create_record`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NewLink {
    pub(super) target_id: String,
    pub(super) relationship: String,
    pub(super) note: Option<String>,
}

pub(super) use crate::domain_transaction::{facet_set_spec, FacetWrite};

/// Reject facet keys the `facets` argument must not carry: spine facets are
/// record fields (top-level arguments), while engine-reserved facets have
/// dedicated owning tools.
pub(super) fn assert_open_facet_key(tool: &str, key: &str) -> Result<()> {
    crate::domain_transaction::assert_open_facet_key(tool, key)
}

/// Parse one entry of a `facets` map into a set (or, when `allow_unset`, an
/// unset for an explicit null).
pub(crate) fn parse_facet_entry(
    tool: &str,
    key: &str,
    value: &Value,
    allow_unset: bool,
) -> Result<Option<FacetWrite>> {
    assert_open_facet_key(tool, key)?;
    if value.is_null() && allow_unset {
        Ok(None)
    } else if allow_unset
        && !matches!(
            value,
            Value::String(_) | Value::Number(_) | Value::Object(_)
        )
    {
        Err(Error::engine(format!(
            "{tool}: facet '{key}' must be a string, number, object, null (unset), or {{ value, vocab_ref }}"
        )))
    } else {
        crate::domain_transaction::parse_facet_write_value(tool, key, value).map(Some)
    }
}

/// Enforce every absolute facet-value predicate against one authoritative
/// schema/vocabulary snapshot inside the caller-owned write transaction.
///
/// This is intentionally not a `store` guard (decision 37de348): shape types
/// are product-surface promises resolved through `query::cascade`, while
/// `store::append*` remains an explicitly documented bypass. The predicate is
/// still per-event and absolute: every outgoing `facet.set` is judged before
/// any event in the tool-authored batch is appended.
pub(super) async fn assert_facet_value_predicates_in(
    tx: &mut Transaction<'static, Sqlite>,
    schema_rows: &[cascade::SchemaConfigRow],
    tool: &str,
    record_type: &str,
    kind: Option<&str>,
    _bearer_id: Option<&str>,
    facets: &mut [FacetWrite],
) -> Result<()> {
    let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx);
    crate::domain_transaction::govern_facet_writes(
        &mut executor,
        schema_rows,
        tool,
        record_type,
        kind,
        facets,
    )
    .await
}

/// Program is a semantic spine type, not a generic executor. Its admitted
/// initial kinds retain interpreter-owned validators and exact runtime ids.
/// Keeping this guard at the supported record-writing boundary makes invalid
/// Program tuples fail before an event is appended without weakening the
/// projector's general replay contract.
pub(crate) fn validate_prospective_program(
    tool: &str,
    record_type: &str,
    kind: Option<&str>,
    runtime: Option<&str>,
) -> Result<()> {
    if record_type != "Program" {
        return Ok(());
    }
    let (kind, expected_runtime) = match kind {
        Some("module") => ("module", "native.mdx.v2"),
        Some("recipe") => ("recipe", "native.recipe.v1"),
        Some(other) => {
            return Err(Error::engine(format!(
                "{tool}: unsupported Program kind '{other}'; this engine admits module and recipe"
            )))
        }
        None => {
            return Err(Error::engine(format!(
                "{tool}: Program requires a governed kind (module or recipe)"
            )))
        }
    };
    match runtime {
        Some(actual) if actual == expected_runtime => Ok(()),
        Some(actual) => Err(Error::engine(format!(
            "{tool}: Program kind:{kind} requires declared interpreter '{expected_runtime}', not '{actual}'"
        ))),
        None => Err(Error::engine(format!(
            "{tool}: Program kind:{kind} requires declared interpreter '{expected_runtime}' in facet 'runtime'"
        ))),
    }
}

/// Materialise the resulting open-facet set for a shape-context change.
/// Stored numeric values are reconstructed through the same `value_num` lane
/// used by query/type enforcement, and current `zoned`/`when` values (named by
/// their `facet_times` row) are decoded back to objects; everything else
/// remains a JSON string.
/// Incoming sets and unsets then overlay that snapshot before validation.
async fn resulting_facet_writes_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    incoming: &[FacetWrite],
    unsets: &BTreeSet<String>,
) -> Result<Vec<FacetWrite>> {
    let rows = sqlx::query(
        "SELECT f.key, f.value, f.value_num, f.vocab_ref, t.kind AS time_kind
         FROM facet_values AS f
         LEFT JOIN facet_times AS t ON t.record_id = f.record_id AND t.key = f.key
         WHERE f.record_id = ? AND f.value IS NOT NULL
         ORDER BY f.key",
    )
    .bind(record_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut resulting = BTreeMap::new();
    for row in rows {
        let key: String = row.try_get("key")?;
        let stored: String = row.try_get("value")?;
        let value_num: Option<f64> = row.try_get("value_num")?;
        let value = if value_num.is_some() {
            let parsed: Value = serde_json::from_str(&stored).map_err(|_| {
                Error::engine(format!(
                    "update_record: stored numeric facet '{key}' on record {record_id} is not valid JSON"
                ))
            })?;
            if !parsed.is_number() {
                return Err(Error::engine(format!(
                    "update_record: stored facet '{key}' on record {record_id} has a numeric projection but is not a JSON number"
                )));
            }
            parsed
        } else {
            let time_kind: Option<String> = row.try_get("time_kind")?;
            crate::domain_transaction::stored_non_numeric_facet_value(stored, time_kind.as_deref())
        };
        resulting.insert(
            key.clone(),
            FacetWrite {
                key,
                value,
                vocab_ref: row.try_get("vocab_ref")?,
                time_type: None,
            },
        );
    }
    for key in unsets {
        resulting.remove(key);
    }
    for facet in incoming {
        resulting.insert(facet.key.clone(), facet.clone());
    }
    Ok(resulting.into_values().collect())
}

/// Optional fast-fail wrapper used before attachment blob insertion. The
/// authoritative validation still repeats in the event batch transaction.
pub(super) async fn assert_facet_value_predicates(
    db: &Db,
    tool: &str,
    record_type: &str,
    kind: Option<&str>,
    bearer_id: Option<&str>,
    facets: &[FacetWrite],
) -> Result<()> {
    if facets.is_empty() {
        return Ok(());
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
    let mut checked_facets = facets.to_vec();
    assert_facet_value_predicates_in(
        &mut tx,
        &schema_rows,
        tool,
        record_type,
        kind,
        bearer_id,
        &mut checked_facets,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) use crate::domain_transaction::{assert_required_not_worsened, RequiredViolation};

/// Read every required-facet violation for `record_ids` from the projection
/// inside the caller-owned batch transaction.
///
/// This deliberately supports more than today's one-record tool batches. The
/// comparison and diagnostics must remain complete when a supported tool grows
/// a multi-record form: never stop at the first record or first missing key.
pub(super) async fn required_violations_in(
    tx: &mut Transaction<'static, Sqlite>,
    schema_rows: &[cascade::SchemaConfigRow],
    record_ids: &[&str],
) -> Result<BTreeSet<RequiredViolation>> {
    let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx);
    crate::domain_transaction::required_violations(&mut executor, schema_rows, record_ids).await
}

#[cfg(test)]
mod required_guard_tests {
    use super::*;

    #[test]
    fn artifact_continuity_appends_to_existing_warnings() {
        let result = json!({"status": "found", "warnings": [{"code": "existing"}]});
        let continuity = json!({"status": "artifact_inputs_no_existing_state", "ports": []});
        let attached = attach_artifact_input_continuity(result, Some(continuity)).unwrap();
        assert_eq!(attached["warnings"].as_array().unwrap().len(), 2);
        assert_eq!(attached["warnings"][0]["code"], "existing");
        assert_eq!(
            attached["warnings"][1]["code"],
            "artifact_inputs_no_existing_state"
        );
    }

    #[tokio::test]
    async fn record_paths_prefer_the_engine_reference_and_keep_a_full_fallback() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4";
        crate::store::create_record(
            &db,
            json!({
                "id": id,
                "type": "Document",
                "kind": "note",
                "name": "Addressable",
            }),
        )
        .await
        .unwrap();
        let mut items = vec![json!({ "id": id, "status": "found" })];

        annotate_record_paths_batch(&db, &mut items).await.unwrap();

        let item = &items[0];
        assert_eq!(item["display_reference"], json!("0189d4c"));
        assert_eq!(item["record_path"], json!("/0189d4c"));
        assert_eq!(
            item["record_path_full"],
            json!("/0189d4c6-1f2a-7b3c-9d4e-5f60718293a4")
        );
    }

    #[tokio::test]
    async fn record_paths_are_absent_for_caller_chosen_ids_outside_the_root_namespace() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = "caller/path?part#fragment";
        let mut items = vec![json!({ "id": id, "status": "found" })];

        annotate_record_paths_batch(&db, &mut items).await.unwrap();

        let item = &items[0];
        assert!(item.get("display_reference").is_none());
        assert!(item.get("record_path").is_none());
        assert!(item.get("record_path_full").is_none());
    }

    #[tokio::test]
    async fn multi_record_batch_diagnostics_report_every_introduced_violation() {
        let db = crate::create_database(":memory:").await.unwrap();
        let schema_rows = vec![cascade::SchemaConfigRow {
            id: "test-shapes".into(),
            layer: "user".into(),
            name: None,
            data: json!({ "shapes": {
                "Outcome:key_result": { "facets": { "target": { "required": true } } },
                "Document:attachment": {
                    "facets": { "classification": { "required": true } }
                }
            } }),
            applies_to_collection_id: None,
            version_lineage: None,
            created_at: String::new(),
        }];
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        // Pinned fixture record ids. Both appear verbatim inside the expected
        // diagnostic text, so the fixture and the assertions share one literal.
        const FIRST_ID: &str = "11fec000-0000-4000-8000-000000000002";
        const SECOND_ID: &str = "11fec000-0000-4000-8000-000000000003";
        let ids = [FIRST_ID, SECOND_ID];
        let before = required_violations_in(&mut tx, &schema_rows, &ids)
            .await
            .unwrap();
        for (id, record_type, kind) in [
            (FIRST_ID, "Outcome", "key_result"),
            (SECOND_ID, "Document", "attachment"),
        ] {
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: id.into(),
                    event_type: "record.created".into(),
                    payload: json!({ "type": record_type, "kind": kind }),
                    actor: Some("agent:test".into()),
                },
                &mut act_alloc,
            )
            .await
            .unwrap();
        }
        let after = required_violations_in(&mut tx, &schema_rows, &ids)
            .await
            .unwrap();
        let error = assert_required_not_worsened("batch_tool", &before, &after)
            .unwrap_err()
            .to_string();
        assert!(error.contains(&format!(
            "record {FIRST_ID} missing required facet 'target'"
        )));
        assert!(error.contains(&format!(
            "record {SECOND_ID} missing required facet 'classification'"
        )));
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[tokio::test]
    async fn delete_preparation_is_non_mutating_and_handler_cas_fences_stale_replay() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = crate::store::create_record(
            &db,
            json!({
                "id": "11fec000-0000-4000-8000-000000000001",
                "type": "Document",
                "kind": "note",
                "name": "Prepared delete",
            }),
        )
        .await
        .unwrap();
        let caller = Caller::local();
        let arguments = json!({
            "id": id,
            "reason": "Remove the obsolete prepared-delete fixture",
        });
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_delete_record(&db, &caller, arguments.clone())
            .await
            .unwrap();
        let events_after_prepare: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_after_prepare, events_before);
        assert_eq!(prepared.effect["after"]["deleted"], true);

        crate::store::update_record(&db, &id, json!({ "summary": "changed after approval" }))
            .await
            .unwrap();
        let stale = delete_record(
            db.clone(),
            caller.clone(),
            prepared.canonical_source_arguments,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(stale.contains("content revision conflict"), "{stale}");

        let fresh = prepare_delete_record(&db, &caller, arguments)
            .await
            .unwrap();
        let result = delete_record(db.clone(), caller, fresh.canonical_source_arguments.clone())
            .await
            .unwrap();
        assert_eq!(result["deleted"], true);
        assert!(delete_record(
            db.clone(),
            Caller::local(),
            fresh.canonical_source_arguments,
        )
        .await
        .is_err());
        let deletes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.deleted'",
        )
        .bind(&id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(deletes, 1);
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[tokio::test]
    async fn type_correction_keeps_stored_when_and_zoned_facets() {
        // Review finding (fef3469 T2): the correction snapshot rebuilt stored
        // `when`/`zoned` values as strings, which their declared types
        // refused. They are decoded from their `facet_times` kind instead.
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let caller = Caller::local();
        let facets = json!({
            "slot": { "type": "when" },
            "call": { "type": "zoned" },
        });
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_schema_config",
                json!({ "action": "write", "data": { "shapes": {
                    "Document:note": { "facets": facets },
                    "Entity:organization": { "facets": facets },
                } } }),
            )
            .await
            .unwrap();
        let id = "11fec000-0000-4000-8000-0000000000e1";
        registry
            .call(
                db.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "id": id, "type": "Document", "kind": "note", "name": "Typed time",
                    "reason": "Typed time correction fixture.",
                    "facets": {
                        "slot": { "all_day": false, "start": { "local": "2026-10-05T10:00", "tz": "Europe/London" }, "duration": "PT30M" },
                        "call": { "local": "2026-10-05T10:00", "tz": "Europe/London" },
                    },
                }),
            )
            .await
            .unwrap();
        let snapshot = |db: Db| async move {
            let values: Vec<(String, String)> = sqlx::query_as(
                "SELECT key, value FROM facet_values WHERE record_id=? ORDER BY key",
            )
            .bind(id)
            .fetch_all(db.write_pool())
            .await
            .unwrap();
            let times: Vec<(String, String, Option<i64>, Option<i64>)> = sqlx::query_as(
                "SELECT key, kind, start_ms, end_ms FROM facet_times WHERE record_id=? ORDER BY key",
            )
            .bind(id)
            .fetch_all(db.write_pool())
            .await
            .unwrap();
            (values, times)
        };
        let before = snapshot(db.clone()).await;
        assert_eq!(before.1.len(), 2);

        let prepared = prepare_correct_record_type(
            &db,
            &caller,
            json!({
                "record_id": id,
                "target_type": "Entity",
                "target_kind": "organization",
                "reason": "Typed time facets survive a type correction.",
            }),
        )
        .await
        .unwrap();
        let mut execute_arguments = prepared.canonical_source_arguments;
        execute_arguments["plan_id"] = json!("wpl1:typed-time");
        execute_arguments["effect_digest"] = json!("c".repeat(64));
        let execution_caller =
            caller.with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                plan_id: "wpl1:typed-time".into(),
                effect_digest: "c".repeat(64),
                executor: "records_write".into(),
                operation: "correct_record_type".into(),
            });
        let result = correct_record_type(db.clone(), execution_caller, execute_arguments)
            .await
            .unwrap();
        assert_eq!(result["type"], "Entity");
        assert_eq!(snapshot(db.clone()).await, before);
        let replay = crate::conformance::rebuild_and_diff(&db).await.unwrap();
        assert!(replay.equal, "{:?}", replay.tables);
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[tokio::test]
    async fn type_correction_prepares_without_writing_and_executes_only_bound_state() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = crate::store::create_record(
            &db,
            json!({
                "id": "11fec000-0000-4000-8000-000000000004",
                "type": "Document",
                "kind": "note",
                "name": "Misfiled verdict",
                "body": "The bearer stays the same.",
            }),
        )
        .await
        .unwrap();
        let caller = Caller::local();
        let arguments = json!({
            "record_id": id,
            "target_type": "Resolution",
            "target_kind": "decision",
            "reason": "Correct the registry-proven wrong spine type.",
        });
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_correct_record_type(&db, &caller, arguments.clone())
            .await
            .unwrap();
        let events_after_prepare: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_after_prepare, events_before);
        assert_eq!(prepared.effect["eligibility"], "confirmation_required");
        assert_eq!(
            prepared.effect["identity_and_body"]["record_id_unchanged"],
            true
        );

        crate::store::update_record(&db, &id, json!({"summary": "concurrent change"}))
            .await
            .unwrap();
        let mut stale_arguments = prepared.canonical_source_arguments.clone();
        stale_arguments["plan_id"] = json!("wpl1:stale");
        stale_arguments["effect_digest"] = json!("a".repeat(64));
        let forged = correct_record_type(db.clone(), caller.clone(), stale_arguments.clone())
            .await
            .unwrap_err()
            .to_string();
        assert!(forged.contains("claimed records_write.correct_record_type plan"));
        let stale_caller =
            caller
                .clone()
                .with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                    plan_id: "wpl1:stale".into(),
                    effect_digest: "a".repeat(64),
                    executor: "records_write".into(),
                    operation: "correct_record_type".into(),
                });
        let stale = correct_record_type(db.clone(), stale_caller, stale_arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(stale.contains("revision conflict"), "{stale}");

        let fresh = prepare_correct_record_type(&db, &caller, arguments)
            .await
            .unwrap();
        let body_digest = fresh.effect["identity_and_body"]["body_digest_unchanged"]
            .as_str()
            .unwrap()
            .to_string();
        let mut execute_arguments = fresh.canonical_source_arguments;
        execute_arguments["plan_id"] = json!("wpl1:fresh");
        execute_arguments["effect_digest"] = json!("b".repeat(64));
        let execution_caller =
            caller.with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                plan_id: "wpl1:fresh".into(),
                effect_digest: "b".repeat(64),
                executor: "records_write".into(),
                operation: "correct_record_type".into(),
            });
        let result = correct_record_type(db.clone(), execution_caller, execute_arguments)
            .await
            .unwrap();
        assert_eq!(result["record_id"], id);
        assert_eq!(result["type"], "Resolution");
        assert_eq!(result["kind"], "decision");
        assert_eq!(result["body_digest"], body_digest);
        let correction_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.type_corrected.v1'",
        )
        .bind(&id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(correction_events, 1);
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[tokio::test]
    async fn compatible_binding_forces_confirmation_and_stales_an_autonomous_plan() {
        let db = crate::create_database(":memory:").await.unwrap();
        let run_key = "scout-chair-a748b2";
        let caller = Caller::local().with_run_context(Some(run_key.into()), None);
        let id = crate::store::with_event_annotations(
            crate::store::EventAnnotations {
                run_key: Some(run_key.into()),
                parent_key: None,
                intent: None,
            },
            crate::store::create_record_as(
                &db,
                json!({
                    "id": "11fec000-0000-4000-8000-000000000005",
                    "type": "Document",
                    "kind": "decision",
                    "name": "Same-run misfiled decision",
                }),
                Some(caller.actor()),
            ),
        )
        .await
        .unwrap();
        let arguments = json!({
            "record_id": id,
            "target_type": "Resolution",
            "target_kind": "decision",
            "reason": "Correct the registry-proven wrong spine type.",
        });

        let autonomous = prepare_correct_record_type(&db, &caller, arguments.clone())
            .await
            .unwrap();
        assert_eq!(autonomous.effect["eligibility"], "autonomous");
        assert_eq!(autonomous.effect["confirmation_required"], false);

        let origin = crate::identity::database_id(&db).await.unwrap();
        let binding = crate::identity::BindingClaim {
            system: "native-record".into(),
            identifier: crate::identity::encode_native_record(&origin, "remote-decision").unwrap(),
        };
        crate::identity::add_binding(
            &db,
            &crate::identity::MutationContext {
                actor: caller.actor(),
                reason: "Establish a compatible external identity.",
                run_key: Some(run_key),
                parent_key: None,
                intent: None,
                // Seed the already-authorized external dependency directly;
                // this test is about correction classification and CAS, not
                // the binding operation's separate Manage gate.
                is_member: true,
                internal: true,
                source_read_authorized: false,
            },
            &id,
            &binding,
            true,
        )
        .await
        .unwrap();

        let mut stale_arguments = autonomous.canonical_source_arguments;
        stale_arguments["plan_id"] = json!("wpl1:binding-stale");
        stale_arguments["effect_digest"] = json!("c".repeat(64));
        let execution_caller =
            caller
                .clone()
                .with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                    plan_id: "wpl1:binding-stale".into(),
                    effect_digest: "c".repeat(64),
                    executor: "records_write".into(),
                    operation: "correct_record_type".into(),
                });
        let stale = correct_record_type(db.clone(), execution_caller, stale_arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(stale.contains("dependent state changed"), "{stale}");

        let confirmed = prepare_correct_record_type(&db, &caller, arguments)
            .await
            .unwrap();
        assert_eq!(confirmed.effect["eligibility"], "confirmation_required");
        assert_eq!(confirmed.effect["confirmation_required"], true);
        assert_eq!(confirmed.effect["preserved_state_counts"]["bindings"], 1);
    }
}

/// Fast, tool-specific home validation. The projector repeats this invariant so
/// low-level append and replay cannot bypass it.
pub(crate) async fn assert_home_target_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    tool: &str,
    home_id: &str,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT r.type, r.kind, r.persistence, r.deleted_at,
                EXISTS (SELECT 1 FROM facet_values a
                         WHERE a.record_id = r.id AND a.key = ?) AS archived
           FROM records r WHERE r.id = ?",
    )
    .bind(ARCHIVED_FACET_KEY)
    .bind(home_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Err(Error::engine(format!(
            "{tool}: home {home_id} does not exist"
        )));
    };
    if row.try_get::<String, _>("type")? != "Collection"
        || row.try_get::<Option<String>, _>("kind")?.as_deref() != Some("folder")
        || row.try_get::<String, _>("persistence")? != "enduring"
        || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
        || row.try_get::<i64, _>("archived")? != 0
    {
        return Err(Error::engine(format!(
            "{tool}: home {home_id} must be a live, unarchived, enduring Collection kind:folder"
        )));
    }
    Ok(())
}

/// In-transaction containment-cycle check for a rehome: climb the home chain
/// from `new_home` and reject if it reaches `id`. Runs inside the
/// same `BEGIN IMMEDIATE` transaction as the append, so two concurrent
/// cross-rehomes cannot both pass and then both commit. The climb is
/// UNCAPPED by depth (a capped walk — e.g. `tree::ancestors`' 100-level
/// ceiling — would silently under-check a deep chain); the visited-path
/// guard alone bounds it, so a pre-existing cycle terminates rather than
/// spins.
pub(super) async fn assert_no_containment_cycle_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    tool: &str,
    id: &str,
    new_home: &str,
) -> Result<()> {
    let row = sqlx::query(
        "WITH RECURSIVE up(id, path) AS (
            SELECT r.id, ',' || r.id || ',' FROM records r WHERE r.id = ?
            UNION ALL
            SELECT r.home_id, u.path || r.home_id || ','
              FROM records r JOIN up u ON r.id = u.id
              WHERE r.home_id IS NOT NULL
                AND instr(u.path, ',' || r.home_id || ',') = 0
          )
          SELECT 1 FROM up WHERE id = ? LIMIT 1",
    )
    .bind(new_home)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    if row.is_some() {
        return Err(Error::engine(format!(
            "{tool}: homing {id} in {new_home} would create a containment cycle"
        )));
    }
    Ok(())
}

/// Fetch a record enriched, erroring (with the calling tool named) if the id
/// vanished between write and read — which a committed write makes impossible
/// short of a concurrent hard delete, hence `expect`-like phrasing.
pub(super) async fn enriched_or_error(
    db: &Db,
    caller: &Caller,
    tool: &str,
    id: &str,
) -> Result<Value> {
    match enriched_or_none(db, caller, id).await? {
        Some(value) => Ok(value),
        None => Err(Error::engine(format!(
            "{tool}: record {id} not readable after write"
        ))),
    }
}

/// Read only the just-written record projection needed by a compact receipt.
/// This deliberately bypasses ordinary read eligibility: some governed
/// derived records (for example a suggestion before it has a bearer) can be
/// authored successfully but are not yet exposed through `get_record`.
/// Returning their own identity and continuation token is still safe, and
/// keeping the read on this transaction pins the receipt to the write.
async fn compact_record_source_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    tool: &str,
    id: &str,
) -> Result<Value> {
    let sql = format!(
        "SELECT {} FROM records WHERE id = ?",
        crate::query::RECORD_COLUMNS
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine(format!("{tool}: record {id} missing after write")))?;
    let mut record = crate::query::record_from_row(&row)?;
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let schema_rows = cascade::schema_config_rows_for_principal_on(tx, principal).await?;
    let lifecycle_interpreter =
        crate::query::lifecycle::LifecycleInterpreter::load_from_connection(tx, schema_rows)
            .await?;
    record.lifecycle_interpretation = lifecycle_interpreter.interpret(
        &record.record_type,
        record.kind.as_deref(),
        record.home_id.as_deref(),
        record.lifecycle.as_deref(),
    );
    let mut value = serde_json::to_value(record)?;
    annotate_body_digest(&mut value);
    Ok(value)
}

/// The uncommitted half of [`enriched_or_error`]: the same live lens read and
/// visibility filter, returning `Ok(None)` where the wrapper reports the
/// vanished-record diagnostic. Idempotent replay uses this directly so a
/// denied replay maps to the opaque `does not exist` denial rather than an
/// existence-revealing string; every other caller keeps the wrapper, for
/// which "not readable after write" is the correct diagnosis.
pub(super) async fn enriched_or_none(db: &Db, caller: &Caller, id: &str) -> Result<Option<Value>> {
    let lens = ReadLens::live(db);
    let record = if super::is_legacy_local(caller) {
        read::get_record_with_lens(&lens, id, read::EnrichOptions::default()).await?
    } else {
        read::get_record_with_lens_as(
            &lens,
            id,
            read::EnrichOptions::default(),
            super::principal(caller),
        )
        .await?
    };
    match record {
        Some(mut record) => {
            filter_enriched_record(db, caller, &mut record, read::EnrichOptions::default()).await?;
            Ok(Some(serde_json::to_value(record)?))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Tool 5 — create_record
// ---------------------------------------------------------------------------

/// The versioned payload key a declared source basis is stored under, beside
/// `reason`, on the write event itself. One format, shared with the strong
/// `save_account` receipt shape so a reader sees one source vocabulary.
pub(crate) const SOURCE_BASIS_FORMAT: &str = "native.source-basis.v1";

/// One caller-declared source on an ordinary write: either the object form
/// `{record_id, reason, role?, revision_event_id?}`, or a bare record id as
/// shorthand for `{record_id}` with no reason.
#[derive(Debug, Clone)]
pub(crate) enum SourceBasisInput {
    /// The object form.
    Object(SourceBasisObject),
    /// A bare record id, resolved exactly like the object form's `record_id`.
    /// Stored with an absent reason, never an invented placeholder.
    Bare(String),
}

/// The object form of one declared source: a record this write rested on, why,
/// and optionally the exact body revision the caller actually read.
///
/// Lighter than `save_account`'s source line in two ways the spec names:
/// `role` is optional because most ordinary writes have one role ("I read it"),
/// and `revision_event_id` may be omitted so the engine stamps the current body
/// head. A supplied revision must be a real body revision of the cited record
/// but need not be the head — the honest stale-but-real case. `reason` is
/// required and validated non-blank; only the bare-string form may omit it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceBasisObject {
    pub record_id: String,
    pub reason: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub revision_event_id: Option<String>,
}

impl<'de> Deserialize<'de> for SourceBasisInput {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        // Buffer once so a string, an object, and everything else can be told
        // apart with one clear refusal per shape. The object form is parsed by
        // its own `deny_unknown_fields` struct so unknown fields and a missing
        // `reason` fail exactly as they did before.
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(record_id) => {
                if record_id.trim().is_empty() {
                    return Err(D::Error::custom(
                        "a bare source item must be a non-empty record id, or the \
                         {record_id, reason} object form",
                    ));
                }
                Ok(SourceBasisInput::Bare(record_id))
            }
            Value::Object(_) => serde_json::from_value::<SourceBasisObject>(value)
                .map(SourceBasisInput::Object)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom(
                "a source item must be the {record_id, reason} object form or a \
                 bare record-id string",
            )),
        }
    }
}

impl SourceBasisInput {
    fn record_id(&self) -> &str {
        match self {
            SourceBasisInput::Object(object) => &object.record_id,
            SourceBasisInput::Bare(record_id) => record_id,
        }
    }

    /// `None` means no reason was given, which only the bare-string form does.
    fn reason(&self) -> Option<&str> {
        match self {
            SourceBasisInput::Object(object) => Some(&object.reason),
            SourceBasisInput::Bare(_) => None,
        }
    }

    fn role(&self) -> Option<&str> {
        match self {
            SourceBasisInput::Object(object) => object.role.as_deref(),
            SourceBasisInput::Bare(_) => None,
        }
    }

    fn revision_event_id(&self) -> Option<&str> {
        match self {
            SourceBasisInput::Object(object) => object.revision_event_id.as_deref(),
            SourceBasisInput::Bare(_) => None,
        }
    }
}

/// JSON Schema for the optional `sources` declaration, shared verbatim by
/// `create_record`, `update_record` and each `create_many` item.
pub(crate) fn source_basis_input_schema() -> Value {
    json!({
        "type": "array",
        "maxItems": crate::authoring::MAX_SAVE_ACCOUNT_SOURCES,
        "description": "Records this write rests on; [] declares none, omitted means undeclared.",
        "items": {
            "type": ["string", "object"],
            "properties": {
                "record_id": { "type": "string" },
                "reason": { "type": "string", "minLength": 1 },
                "role": { "type": "string" },
                "revision_event_id": {
                    "type": "string",
                    "description": "Body revision; omit for the current head."
                }
            },
            "required": ["record_id", "reason"],
            "additionalProperties": false
        }
    })
}

#[cfg(test)]
mod source_basis_input_tests {
    use super::SourceBasisInput;
    use serde_json::{json, Value};

    fn parse(value: Value) -> Vec<SourceBasisInput> {
        serde_json::from_value(value).expect("sources parse")
    }

    #[test]
    fn bare_string_parses_to_record_id_without_reason() {
        let sources = parse(json!(["619e4732-8dda-444b-93c6-283ffe7b7d32"]));
        assert_eq!(sources.len(), 1);
        assert_eq!(
            sources[0].record_id(),
            "619e4732-8dda-444b-93c6-283ffe7b7d32"
        );
        assert_eq!(sources[0].reason(), None);
        assert_eq!(sources[0].role(), None);
        assert_eq!(sources[0].revision_event_id(), None);
    }

    #[test]
    fn object_without_reason_still_fails() {
        let error = serde_json::from_value::<Vec<SourceBasisInput>>(
            json!([{ "record_id": "619e4732-8dda-444b-93c6-283ffe7b7d32" }]),
        )
        .expect_err("an object item must carry a reason");
        assert!(error.to_string().contains("reason"), "{error}");
    }

    #[test]
    fn empty_bare_string_fails() {
        let error = serde_json::from_value::<Vec<SourceBasisInput>>(json!([""]))
            .expect_err("an empty bare id is refused");
        assert!(error.to_string().contains("non-empty"), "{error}");
    }

    #[test]
    fn number_item_fails() {
        let error = serde_json::from_value::<Vec<SourceBasisInput>>(json!([7]))
            .expect_err("a number is not a source item");
        assert!(error.to_string().contains("record-id string"), "{error}");
    }

    #[test]
    fn mixed_bare_and_object_items_parse() {
        let sources = parse(json!([
            "619e4732-8dda-444b-93c6-283ffe7b7d32",
            {
                "record_id": "11111111-1111-4111-8111-111111111111",
                "reason": "read it",
                "role": "context"
            }
        ]));
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].reason(), None);
        assert_eq!(sources[1].reason(), Some("read it"));
        assert_eq!(sources[1].role(), Some("context"));
    }
}

/// `sources: null` is out of contract, but serde folds it into `None`, which
/// would silently mean "not declared" — the opposite of what a caller reaching
/// for `null` to mean "none" intends, and the absent/declared-none distinction
/// is the point of the feature. Reject it against the raw arguments, before
/// parsing, where the difference is still visible, and point at the empty
/// array.
fn reject_null_sources(tool: &str, arguments: &Value) -> Result<()> {
    if arguments.get("sources").is_some_and(Value::is_null) {
        return Err(Error::engine(format!(
            "{tool}: 'sources' must be an array; pass [] to declare that this write rests on none, or omit it to leave the basis undeclared"
        )));
    }
    Ok(())
}

/// Validate a declared basis and materialize the stored envelope, inside the
/// same `BEGIN IMMEDIATE` transaction the write commits in. `None` means the
/// caller did not declare; `Some` over an empty slice is the distinct
/// "declared as none" state and stores an empty source list rather than
/// nothing at all.
///
/// Every refusal is a whole-call error naming the ordinal, never the cited
/// record: a write that could report *which* unseen id was denied would be an
/// existence oracle.
pub(super) async fn resolve_source_basis_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    tool: &str,
    declared: Option<&[SourceBasisInput]>,
) -> Result<Option<Value>> {
    let Some(sources) = declared else {
        return Ok(None);
    };
    // An explicit empty array is valid and means "declared as none". The bound
    // reuses `save_account`'s; it caps a declaration, it does not require one.
    if sources.len() > crate::authoring::MAX_SAVE_ACCOUNT_SOURCES {
        return Err(Error::engine(format!(
            "{tool}: 'sources' may name at most {} records",
            crate::authoring::MAX_SAVE_ACCOUNT_SOURCES
        )));
    }
    let mut seen = BTreeSet::new();
    let mut stored = Vec::with_capacity(sources.len());
    for (ordinal, source) in sources.iter().enumerate() {
        let record_id = source.record_id();
        if !seen.insert(record_id) {
            return Err(Error::engine(format!(
                "{tool}: sources[{ordinal}] repeats a record_id already declared"
            )));
        }
        // The same source vocabulary `save_account` stores, validated by the
        // same helpers: an identifier is non-blank and control-free, prose is
        // non-blank. A basis line and a save-account source line must not admit
        // different bytes. A bare-string item supplies no reason, so there is
        // no prose to validate and none is invented.
        crate::authoring::validate_identifier(
            tool,
            record_id,
            &format!("sources[{ordinal}].record_id"),
        )?;
        if let Some(reason) = source.reason() {
            crate::authoring::validate_prose(tool, reason, &format!("sources[{ordinal}].reason"))?;
        }
        if let Some(role) = source.role() {
            crate::authoring::validate_prose(tool, role, &format!("sources[{ordinal}].role"))?;
        }
        if let Some(revision) = source.revision_event_id() {
            crate::authoring::validate_identifier(
                tool,
                revision,
                &format!("sources[{ordinal}].revision_event_id"),
            )?;
        }
        // Existence, liveness and View folded into one opaque refusal: the
        // canonical in-transaction guard's own id-naming error is discarded on
        // purpose.
        if require_record_in(tx, caller, tool, record_id, Capability::View)
            .await
            .is_err()
        {
            return Err(Error::engine(format!(
                "{tool}: sources[{ordinal}] names a record that does not exist or is not visible to the caller"
            )));
        }
        let (revision_event_id, revision_supplied_by) = match source.revision_event_id() {
            Some(revision) => {
                let real: bool = sqlx::query_scalar(&format!(
                    "SELECT EXISTS(SELECT 1 FROM content_events WHERE id=? AND record_id=? AND {})",
                    crate::contribution::BODY_PRODUCING_EVENT_SQL
                ))
                .bind(revision)
                .bind(record_id)
                .fetch_one(&mut **tx)
                .await?;
                if !real {
                    return Err(Error::engine(format!(
                        "{tool}: sources[{ordinal}].revision_event_id is not a body revision of the cited record"
                    )));
                }
                (revision.to_string(), "caller")
            }
            None => {
                let head: String = sqlx::query_scalar(&format!(
                    "SELECT id FROM content_events WHERE record_id=? AND {} ORDER BY seq DESC LIMIT 1",
                    crate::contribution::BODY_PRODUCING_EVENT_SQL
                ))
                .bind(record_id)
                .fetch_one(&mut **tx)
                .await?;
                (head, "engine")
            }
        };
        stored.push(json!({
            "ordinal": ordinal,
            "record_id": record_id,
            "revision_event_id": revision_event_id,
            "revision_supplied_by": revision_supplied_by,
            "role": source.role(),
            "reason": source.reason(),
        }));
    }
    Ok(Some(json!({
        "format": SOURCE_BASIS_FORMAT,
        "sources": stored,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRecordArgs {
    #[serde(rename = "type")]
    record_type: String,
    /// Required (fbfaf25 §3.1). `String`, not `Option<String>` — serde's missing
    /// -field error IS the enforcement, so the tool is uncallable without it
    /// rather than merely discouraged.
    reason: String,
    /// Optional declared source basis. Absent means "not declared"; an explicit
    /// empty array means "declared as none". The two states are stored
    /// distinguishably and must not collapse.
    sources: Option<Vec<SourceBasisInput>>,
    id: Option<String>,
    kind: String,
    name: Option<String>,
    body: Option<String>,
    home_id: Option<String>,
    summary: Option<String>,
    lifecycle: Option<String>,
    owner_id: Option<String>,
    persistence: Option<String>,
    maturity: Option<String>,
    facets: Option<Map<String, Value>>,
    links: Option<Vec<NewLink>>,
    /// Required, including when empty, for Message creation. These are
    /// portable Entity:person record ids, not account credentials.
    addressed_to: Option<Vec<String>>,
    /// Delivered Messages only: the explicit communication venue. Person
    /// record ids are resolved to immutable canonical principals before the
    /// origin event is appended; sender-only drafts have no communication
    /// origin because they have not entered a stream.
    origin: Option<MessageOriginInput>,
    /// Message only: structured immutable mention atoms. Literal @text has no
    /// mention semantics.
    mentions: Option<Vec<crate::awareness::MentionInput>>,
    target: Option<crate::citations::CitationTargetInput>,
    /// Optional caller-supplied idempotency key for the ordinary create path.
    /// Absent (or blank) means exactly today's behavior. When present, the
    /// create joins the provenance command-attestation mechanism that
    /// `manage_relationships` uses: same key plus same normalized request
    /// replays the original receipt without appending; same key plus a
    /// materially different request is a conflict error. The artifact and
    /// delivered-Message routes keep their own narrower replay paths and never
    /// set this field.
    idempotency_key: Option<String>,
    #[serde(default)]
    response_mode: ResponseMode,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub(crate) enum MessageOriginInput {
    Collection { collection_id: String },
    Direct { participant_ids: Vec<String> },
}

async fn resolve_message_origin_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    input: &MessageOriginInput,
    sender_id: &str,
    sender_principal: &str,
) -> Result<(crate::events::MessageOriginDeclaredPayload, Vec<String>)> {
    match input {
        MessageOriginInput::Collection { collection_id } => {
            require_record_in(
                tx,
                caller,
                "manage_messages.send",
                collection_id,
                Capability::View,
            )
            .await?;
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM records
                  WHERE id=? AND type='Collection' AND kind='folder' AND deleted_at IS NULL)",
            )
            .bind(collection_id)
            .fetch_one(&mut **tx)
            .await?;
            if !valid {
                return Err(Error::engine(format!(
                    "manage_messages.send: collection origin {collection_id} is not a live Collection folder"
                )));
            }
            Ok((
                crate::events::MessageOriginDeclaredPayload::Collection {
                    collection_id: collection_id.clone(),
                },
                Vec::new(),
            ))
        }
        MessageOriginInput::Direct { participant_ids } => {
            if participant_ids.len() < 2 {
                return Err(Error::engine(
                    "manage_messages.send: a direct origin requires at least two participants",
                ));
            }
            let mut seen_ids = BTreeSet::new();
            let mut principals = Vec::with_capacity(participant_ids.len());
            let mut accounts = Vec::with_capacity(participant_ids.len());
            for participant_id in participant_ids {
                if !seen_ids.insert(participant_id.as_str()) {
                    return Err(Error::engine(format!(
                        "manage_messages.send: duplicate direct participant {participant_id}"
                    )));
                }
                require_record_in(
                    tx,
                    caller,
                    "manage_messages.send",
                    participant_id,
                    Capability::View,
                )
                .await?;
                let valid: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM records
                      WHERE id=? AND type='Entity' AND kind='person' AND deleted_at IS NULL)",
                )
                .bind(participant_id)
                .fetch_one(&mut **tx)
                .await?;
                if !valid {
                    return Err(Error::engine(format!(
                        "manage_messages.send: direct participant {participant_id} is not a live Person"
                    )));
                }
                let principal: String = sqlx::query_scalar(
                    "SELECT identifier FROM bindings
                      WHERE record_id=? AND system='native-principal' AND is_canonical=1",
                )
                .bind(participant_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| {
                    Error::engine(format!(
                        "manage_messages.send: direct participant {participant_id} has no canonical native-principal binding"
                    ))
                })?;
                let account: String = sqlx::query_scalar(
                    "SELECT identifier FROM bindings
                      WHERE record_id=? AND system='account' AND is_canonical=1",
                )
                .bind(participant_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| {
                    Error::engine(format!(
                        "manage_messages.send: direct participant {participant_id} has no canonical local account"
                    ))
                })?;
                principals.push(principal);
                accounts.push(account);
            }
            if !seen_ids.contains(sender_id) {
                return Err(Error::engine(
                    "manage_messages.send: the immutable sender must be a direct-context participant",
                ));
            }
            let principals = crate::events::normalize_direct_origin_principals(principals);
            if principals.len() != participant_ids.len()
                || !principals.iter().any(|value| value == sender_principal)
            {
                return Err(Error::engine(
                    "manage_messages.send: direct participants must resolve to distinct canonical principals including the sender",
                ));
            }
            accounts.sort();
            accounts.dedup();
            Ok((
                crate::events::MessageOriginDeclaredPayload::Direct { principals },
                accounts,
            ))
        }
    }
}

pub(super) async fn create_record(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    create_record_inner(
        db,
        caller,
        arguments,
        None,
        None,
        None,
        CreateRecordResponse {
            mode: None,
            similar_notice: Some(&[]),
        },
    )
    .await
}

/// Internal graph and host-composed creation routes need the pre-existing
/// enriched response even though the public singleton surface now defaults to
/// a compact receipt.
///
/// `create_many`'s singular dispatch. The batch's own reserved ids travel as
/// the similar-records exclusion set so one item's notice can never name a
/// sibling created by the same call, while a genuine match with a record
/// outside the batch is still reported.
pub(super) async fn create_record_verbose_excluding(
    db: Db,
    caller: Caller,
    arguments: Value,
    similar_exclusion: &[String],
) -> Result<Value> {
    create_record_inner(
        db,
        caller,
        arguments,
        None,
        None,
        None,
        CreateRecordResponse {
            mode: Some(ResponseMode::Verbose),
            similar_notice: Some(similar_exclusion),
        },
    )
    .await
}

#[derive(Debug, Clone)]
pub(crate) struct SendMessagePlan {
    pub idempotency_key: String,
    pub intent_digest: String,
    pub disclosure_preview: Option<String>,
}

/// Host-only provenance and idempotency for a record created by one exact
/// compiled artifact interaction entry. None of these fields are accepted by
/// the public `create_record` envelope: the interaction host derives them
/// after resolving the current source, binding and authenticated caller.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactCreatePlan {
    pub artifact_id: String,
    pub entry_id: String,
    pub source_digest: String,
    pub source_event_id: String,
    pub idempotency_key: String,
    pub intent_digest: String,
    pub invocation_digest: String,
    pub gesture: Option<String>,
    pub destination_binding: Option<ArtifactCreateBindingGuard>,
    pub references: Vec<ArtifactCreateReferenceGuard>,
    /// Verified effect-gesture evidence to record on the created event's
    /// origin, when a host token was presented (D7 §4B, G2). Additive.
    pub gesture_evidence: Option<Value>,
}

#[derive(Debug, Clone)]
pub(crate) struct ArtifactCreateBindingGuard {
    pub port: String,
    pub collection_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ArtifactCreateReferenceGuard {
    pub port: String,
    pub collection_id: String,
    pub collection_kind: String,
    pub record_id: String,
}

pub(crate) enum ArtifactCreateOutcome {
    Created(Value),
    Rejected { code: &'static str, message: String },
    Uncertain,
}

/// Run artifact creation through the ordinary governed creation transaction.
///
/// The caller supplies only host-composed `create_record` arguments. The
/// artifact origin is attached to the `record.created` event and used for
/// serialized replay detection inside the same write transaction.
pub(crate) async fn create_record_from_artifact(
    db: Db,
    caller: Caller,
    arguments: Value,
    plan: ArtifactCreatePlan,
) -> Result<ArtifactCreateOutcome> {
    match create_record_inner(
        db.clone(),
        caller.clone(),
        arguments,
        None,
        Some(plan.clone()),
        None,
        CreateRecordResponse {
            mode: Some(ResponseMode::Verbose),
            similar_notice: Some(&[]),
        },
    )
    .await
    {
        Ok(created) => Ok(ArtifactCreateOutcome::Created(created)),
        Err(_) => {
            let row = sqlx::query(
                "SELECT payload FROM content_events
                  WHERE type='record.created' AND actor=?
                    AND json_extract(payload,'$.origin.artifact_id')=?
                    AND json_extract(payload,'$.origin.entry_id')=?
                    AND json_extract(payload,'$.origin.idempotency_key')=?
                  ORDER BY seq LIMIT 1",
            )
            .bind(caller.actor())
            .bind(&plan.artifact_id)
            .bind(&plan.entry_id)
            .bind(&plan.idempotency_key)
            .fetch_optional(db.write_pool())
            .await?;
            let Some(row) = row else {
                return Ok(ArtifactCreateOutcome::Rejected {
                    code: "creation_rejected",
                    message: "current record governance rejected the declared creation".into(),
                });
            };
            let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
            if payload
                .pointer("/origin/invocation_digest")
                .and_then(Value::as_str)
                != Some(plan.invocation_digest.as_str())
            {
                return Ok(ArtifactCreateOutcome::Rejected {
                    code: "idempotency_conflict",
                    message: "the idempotency key was already used for a different creation".into(),
                });
            }
            Ok(ArtifactCreateOutcome::Uncertain)
        }
    }
}

/// Private comment posting plan, task `b9fb9fd` family 1. Composed only by
/// the artifact dispatcher from the engine-parsed manifest entry (resolved
/// from the exact cited source, never frame JSON), the candidate binding
/// scope, and the verified install guard. Carries no destination home: the
/// kernel derives the bearer's stored canonical home fresh inside the
/// write transaction. Package, consent bound and need resolve together at
/// the install guard stage on that transaction. Composition carries none;
/// the kernel overwrites any supplied metadata with its fresh result.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactCommentPlan {
    pub artifact_id: String,
    pub entry_id: String,
    /// The engine-resolved manifest entry this plan was composed from.
    pub entry: mdx_v2::InteractionEntry,
    /// Must equal the guard's source revision; enforced at composition.
    pub source_event_id: String,
    /// Must equal the invocation's cited source digest; enforced at
    /// composition and re-pinned by the install gate in-transaction.
    pub source_digest: String,
    /// The single `part_of` bearer: root parent or thread root.
    pub target_id: String,
    /// Fixed validated manifest position: `root` or `reply`.
    pub position: String,
    /// Exact body from the declared values input. Retained byte-for-byte;
    /// capped by `min(manifest, consent)` in-transaction.
    pub body: String,
    pub manifest_max_bytes: usize,
    /// Candidate binding scope from the entry's explicit bound-input port:
    /// exactly one (port, collection, kind) triple, re-proved
    /// in-transaction after replay, before a fresh append.
    pub scope_port: String,
    pub scope_collection_id: String,
    pub scope_kind: String,
    /// The invocation's `observed[target]["comment_target"]` token, if any.
    /// Checked only for a new append, after replay handling.
    pub observed_token: Option<String>,
    pub idempotency_key: String,
    pub gesture: Option<String>,
    pub guard: native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    /// Admission metadata only (D7 §4C.2 N3c). Every caller composes this
    /// `None`; the comment kernel overwrites package and static admission
    /// together, resolved fresh at the install guard stage on the same write
    /// transaction, so a caller-supplied value is never accepted as
    /// pre-resolved admission. It never enters the persisted envelope, the
    /// command digest, the origin, CAS, the receipt or Undo.
    pub resolved_admission: Option<super::alpha_tabs::ResolvedAlphaAdmission>,
    /// Verified effect-gesture evidence to record on the comment event's
    /// origin, when a host token was presented (D7 §4B, G2). Additive.
    pub gesture_evidence: Option<Value>,
}

/// Typed outcome of the private canonical comment write. Refusals and CAS
/// conflicts are data (the dispatcher maps them to intent results);
/// unexpected and commit errors propagate as `Err` for honest
/// host-unknown handling — never recovered by re-querying history.
#[derive(Debug, Clone)]
pub(crate) enum ArtifactCommentOutcome {
    Created(Value),
    Replayed(Value),
    Conflict {
        current_version: String,
        conflicting_event_id: String,
    },
    Refused {
        code: String,
        message: String,
    },
}

/// Minimal whitelist for a committed comment: ids and thread position
/// only. Replays carry the identical shape plus the retry flag — never an
/// enriched record, version sequence, act, refresh, or account.
pub(crate) fn comment_receipt_value(
    comment_id: &str,
    bearer_id: &str,
    position: &str,
    idempotent_retry: bool,
) -> Value {
    let mut receipt = json!({
        "comment_id": comment_id,
        "bearer_id": bearer_id,
        "position": position,
    });
    if idempotent_retry {
        receipt
            .as_object_mut()
            .expect("comment receipt is an object")
            .insert("idempotent_retry".into(), Value::Bool(true));
    }
    receipt
}

/// Dedicated governed-comment entry point. Builds the fixed creation
/// arguments itself — Annotation/comment, engine default name, exact plan
/// body, one `part_of` link, and the plan reason — so caller-supplied
/// fields can never diverge from the planned command digest, origin, and
/// replay identity. Routes through the ordinary `create_record_inner` with
/// the comment plan; ordinary callers pass no plan and keep their
/// receipts, defaults, and replay paths unchanged.
pub(crate) async fn create_comment_from_artifact(
    db: Db,
    caller: Caller,
    plan: ArtifactCommentPlan,
) -> Result<ArtifactCommentOutcome> {
    // Blank bodies refuse here with explicit rejected semantics: the
    // ordinary validator below would propagate an error (host-unknown),
    // but a blank body is a malformed command, not an uncertain outcome.
    // Pure Unicode-aware normalization; commit and I/O errors still
    // propagate as unknown.
    if plan.body.trim().is_empty() {
        return Ok(ArtifactCommentOutcome::Refused {
            code: "comment_body_blank".to_string(),
            message: "comment body must be nonblank".to_string(),
        });
    }
    let arguments = json!({
        "type": "Annotation",
        "kind": "comment",
        "name": "Comment",
        "body": plan.body,
        "reason": format!(
            "Artifact interaction '{}' posted this comment.",
            plan.entry_id,
        ),
        "links": [{ "target_id": plan.target_id, "relationship": "part_of" }],
    });
    let outcome = create_record_inner(
        db,
        caller,
        arguments,
        None,
        None,
        Some(plan),
        CreateRecordResponse {
            mode: Some(ResponseMode::Verbose),
            similar_notice: Some(&[]),
        },
    )
    .await?;
    decode_comment_outcome(&outcome)
        .ok_or_else(|| Error::engine("create_record_inner returned a non-comment outcome"))
}

/// Private outcome transfer between the canonical comment branch and its
/// wrapper above: the only two parties to this encoding, documented here
/// and pinned by round-trip tests. Ordinary callers never see these
/// shapes — the comment plan that produces them is unreachable to them.
pub(crate) fn decode_comment_outcome(value: &Value) -> Option<ArtifactCommentOutcome> {
    let object = value.as_object()?;
    if object.get("comment_conflict").and_then(Value::as_bool) == Some(true) {
        return Some(ArtifactCommentOutcome::Conflict {
            current_version: object
                .get("current_version")
                .and_then(Value::as_str)?
                .to_string(),
            conflicting_event_id: object
                .get("conflicting_event_id")
                .and_then(Value::as_str)?
                .to_string(),
        });
    }
    if object.get("comment_refused").and_then(Value::as_bool) == Some(true) {
        return Some(ArtifactCommentOutcome::Refused {
            code: object.get("code").and_then(Value::as_str)?.to_string(),
            message: object.get("message").and_then(Value::as_str)?.to_string(),
        });
    }
    let comment_id = object.get("comment_id").and_then(Value::as_str)?;
    let bearer_id = object.get("bearer_id").and_then(Value::as_str)?;
    let position = object.get("position").and_then(Value::as_str)?;
    let receipt = comment_receipt_value(
        comment_id,
        bearer_id,
        position,
        object.get("idempotent_retry").and_then(Value::as_bool) == Some(true),
    );
    if object.get("idempotent_retry").and_then(Value::as_bool) == Some(true) {
        return Some(ArtifactCommentOutcome::Replayed(receipt));
    }
    Some(ArtifactCommentOutcome::Created(receipt))
}

/// Refusal marker for the canonical comment branch. Decoded by
/// `decode_comment_outcome`; never leaves this module except through the
/// comment wrapper.
fn comment_refused_value(code: &str, message: String) -> Value {
    json!({
        "comment_refused": true,
        "code": code,
        "message": message,
    })
}

/// Plan for one governed tab reaction (task `07ae879` I2). The invocation
/// emoji and desired `reacted` state were validated against the manifest
/// subset at composition; the consented subset, need membership, message
/// View, locality and idempotency are re-proved in-transaction below.
pub(crate) struct ArtifactReactPlan {
    pub artifact_id: String,
    pub entry_id: String,
    /// The engine-resolved manifest entry this plan was composed from.
    pub entry: mdx_v2::InteractionEntry,
    /// Must equal the guard's source revision; enforced at composition.
    pub source_event_id: String,
    /// Must equal the invocation's cited source digest; enforced at
    /// composition and re-pinned by the install gate in-transaction.
    pub source_digest: String,
    /// The target message, from the entry's single bound slot.
    pub message_id: String,
    /// The invocation emoji, inside the manifest subset at composition.
    pub emoji: String,
    /// Desired state: true adds the reaction, false removes it.
    pub adding: bool,
    /// Candidate binding scope from the entry's explicit bound-input port:
    /// exactly one (port, collection, kind) triple, re-proved
    /// in-transaction after replay, before a fresh append.
    pub scope_port: String,
    pub scope_collection_id: String,
    pub scope_kind: String,
    pub idempotency_key: String,
    pub gesture: Option<String>,
    pub guard: native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    /// Admission metadata only (D7 §4C.2 N3c). Every caller composes this
    /// `None`; the reaction kernel overwrites package and static admission
    /// together, resolved fresh at the install guard stage on the same write
    /// transaction, so a caller-supplied value is never accepted as
    /// pre-resolved admission. It never enters the persisted event, the
    /// origin, replay matching, CAS, the receipt or Undo.
    pub resolved_admission: Option<super::alpha_tabs::ResolvedAlphaAdmission>,
    /// Verified effect-gesture evidence to record on the reaction event's
    /// origin, when a host token was presented (D7 §4B, G3). Additive: the
    /// origin without it stays byte-identical, and replay matching ignores
    /// it, like the comment path.
    pub gesture_evidence: Option<Value>,
}

/// Typed outcome of the private canonical reaction write. Refusals are
/// data (the dispatcher maps them to intent results); unexpected and
/// commit errors propagate as `Err` for honest host-unknown handling.
#[derive(Debug, Clone)]
pub(crate) enum ArtifactReactOutcome {
    Committed { receipt: Value },
    Refused { code: String, message: String },
}

/// Artifact origin for one governed tab reaction, mirroring the
/// comment/record.create origin shape: effect-tagged for the replay
/// lookup, with the guard context plus the message, emoji and desired
/// state needed to settle a replay receipt without re-reading. D7 Undo
/// locates the reaction through `origin.*`.
fn react_origin_value(plan: &ArtifactReactPlan) -> Value {
    let mut origin = json!({
        "kind": "artifact.interaction",
        "effect": "message.react",
        "artifact_id": plan.artifact_id,
        "entry_id": plan.entry_id,
        "source_digest": plan.source_digest,
        "source_event_id": plan.source_event_id,
        "idempotency_key": plan.idempotency_key,
        "message_id": plan.message_id,
        "emoji": plan.emoji,
        "reacted": plan.adding,
        "gesture": plan.gesture,
        "guard": {
            "package": plan.guard.package,
            "expected_install_event_id": plan.guard.expected_install_event_id,
            "artifact_id": plan.guard.artifact_id,
            "source_revision": plan.guard.source_revision,
            "version": plan.guard.version,
            "digest": plan.guard.digest,
            "declaration_digest": plan.guard.declaration_digest,
        },
    });
    if let Some(evidence) = plan.gesture_evidence.clone() {
        origin["gesture_evidence"] = evidence;
    }
    origin
}

/// Whether a stored reaction origin carries this plan's exact identity:
/// same effect, artifact, entry, key, message, emoji, desired state and
/// guard context. Legacy origin-less rows never match — they conflict, as
/// the comment replay treats them.
fn react_origin_matches(stored_origin: Option<&Value>, plan: &ArtifactReactPlan) -> bool {
    let Some(origin) = stored_origin else {
        return false;
    };
    let field = |key: &str| origin.get(key).and_then(Value::as_str);
    let guard = |key: &str| {
        origin
            .get("guard")
            .and_then(|object| object.get(key))
            .and_then(Value::as_str)
    };
    field("effect") == Some("message.react")
        && field("artifact_id") == Some(plan.artifact_id.as_str())
        && field("entry_id") == Some(plan.entry_id.as_str())
        && field("idempotency_key") == Some(plan.idempotency_key.as_str())
        && field("message_id") == Some(plan.message_id.as_str())
        && field("emoji") == Some(plan.emoji.as_str())
        && origin.get("reacted").and_then(Value::as_bool) == Some(plan.adding)
        && guard("package") == Some(plan.guard.package.as_str())
        && guard("expected_install_event_id") == Some(plan.guard.expected_install_event_id.as_str())
        && guard("artifact_id") == Some(plan.guard.artifact_id.as_str())
        && guard("source_revision") == Some(plan.guard.source_revision.as_str())
        && guard("version") == Some(plan.guard.version.as_str())
        && guard("digest") == Some(plan.guard.digest.as_str())
        && guard("declaration_digest") == Some(plan.guard.declaration_digest.as_str())
}

/// Minimal whitelist for a committed reaction: message, emoji, desired
/// state and whether anything changed — never a sequence, actor list, or
/// ReactionGroup (those wait for b2583dc). Replays carry the identical
/// shape plus the retry flag.
pub(crate) fn react_receipt_value(
    message_id: &str,
    emoji: &str,
    reacted: bool,
    changed: bool,
    idempotent_retry: bool,
) -> Value {
    let mut receipt = json!({
        "message_id": message_id,
        "emoji": emoji,
        "reacted": reacted,
        "changed": changed,
    });
    if idempotent_retry {
        receipt
            .as_object_mut()
            .expect("react receipt is an object")
            .insert("idempotent_retry".into(), Value::Bool(true));
    }
    receipt
}

/// Dedicated governed-reaction entry point (task `07ae879` I2). One
/// caller-owned write transaction re-proves install, consent, binding,
/// need membership, message View, locality and emoji scope, then settles
/// idempotency and desired state through the shared messaging internals.
/// Never touches acknowledgement state: only the explicit
/// `satisfy_acknowledgement_expectation_with_reaction` command does.
pub(crate) async fn react_to_message_from_artifact(
    db: Db,
    caller: Caller,
    mut plan: ArtifactReactPlan,
) -> Result<ArtifactReactOutcome> {
    let refused = |code: &str, message: String| ArtifactReactOutcome::Refused {
        code: code.to_string(),
        message,
    };
    crate::events::validate_message_reaction_emoji(&plan.emoji)?;
    if plan.idempotency_key.trim().is_empty() {
        return Ok(refused(
            "invalid_invocation",
            "react idempotency key must not be blank".to_string(),
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    // Full install guard on this transaction at the same stage (D7 §4C.2
    // N3c): the alpha resolver runs the identical scope-fixed row core —
    // install pins plus object-only consent for the invocation emoji, same
    // order, same codes/texts through `render_refusal` — and yields the
    // already-read row as a neutral package with static admission, without
    // a second install read. Admission metadata only: the package never enters the
    // origin, replay, CAS, receipt or Undo below.
    let resolved = match super::alpha_tabs::resolve_alpha_admission_in(
        &mut tx,
        &caller,
        super::effect_admission::PackageClaim::alpha(&plan.guard),
        &plan.artifact_id,
        &plan.source_digest,
        &plan.entry,
        super::alpha_tabs::GuardScope::React { emoji: &plan.emoji },
    )
    .await?
    {
        Ok(resolved) => resolved,
        Err(refusal) => {
            let (code, message) = super::effect_admission::render_refusal(
                super::effect_admission::AdmissionSource::AlphaTabInstall,
                &refusal,
            );
            tx.rollback().await?;
            return Ok(refused(&code, message));
        }
    };
    // Overwrite all supplied metadata with this transaction's result.
    plan.resolved_admission = Some(resolved);
    let super::effect_bounds::Admitted::React { bound, need } = &plan
        .resolved_admission
        .as_ref()
        .expect("admission resolved immediately above")
        .admitted
    else {
        unreachable!("validated react scope carries its admitted bound");
    };
    let command = if plan.adding {
        "add_reaction"
    } else {
        "remove_reaction"
    };
    let event_type = if plan.adding {
        "message.reaction.added.v1"
    } else {
        "message.reaction.removed.v1"
    };
    // Serialized same-transaction replay, ahead of the dynamic
    // binding/membership gates: an identical retry replays its receipt
    // instead of re-proving mutable membership, following the
    // comment/facet ordering. Static guard/consent above still gate every
    // replay. The same key with a different command conflicts and writes
    // nothing.
    let prior: Option<(String, String, crate::events::MessageReactionPayload)> = sqlx::query(
        "SELECT record_id,type,payload FROM content_events
          WHERE actor=?
            AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')
            AND json_extract(payload,'$.idempotency_key')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(caller.actor())
    .bind(&plan.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    .map(
        |row| -> Result<(String, String, crate::events::MessageReactionPayload)> {
            Ok((
                row.try_get::<String, _>("record_id")?,
                row.try_get::<String, _>("type")?,
                serde_json::from_str::<crate::events::MessageReactionPayload>(
                    &row.try_get::<String, _>("payload")?,
                )?,
            ))
        },
    )
    .transpose()?;
    if let Some((record_id, found_type, payload)) = prior {
        payload.validate(Some(caller.actor()))?;
        // Origin-scoped replay, following the facet-set precedent: the
        // stored origin must carry this plan's exact identity. A legacy
        // origin-less row, or one from another artifact/entry/guard,
        // conflicts rather than replaying.
        let origin_ok = react_origin_matches(payload.origin.as_ref(), &plan);
        if super::messaging::verify_reaction_retry(
            &(found_type, payload.clone()),
            &plan.message_id,
            event_type,
            command,
            &plan.emoji,
            &record_id,
        )
        .is_err()
            || !origin_ok
        {
            tx.rollback().await?;
            return Ok(refused(
                "idempotency_conflict",
                "the idempotency key was already used for a different reaction".to_string(),
            ));
        }
        let reacted = payload.command == "add_reaction";
        // Output View recheck before settling the prior receipt, following
        // the comment precedent: a caller who lost View since the commit
        // gets a refusal, not the replayed receipt — and writes nothing.
        // (One terminal rollback per path: the check runs first.)
        if !super::can_record_in(&mut tx, &caller, &plan.message_id, Capability::View).await? {
            tx.rollback().await?;
            return Ok(refused(
                "permission_denied",
                format!(
                    "the authenticated principal may not react to {}",
                    plan.message_id
                ),
            ));
        }
        tx.rollback().await?;
        return Ok(ArtifactReactOutcome::Committed {
            receipt: react_receipt_value(
                &plan.message_id,
                &payload.emoji,
                reacted,
                payload.changed,
                true,
            ),
        });
    }
    // Binding and delivered-need membership on this snapshot.
    let scope = vec![(
        plan.scope_port.clone(),
        plan.scope_collection_id.clone(),
        plan.scope_kind.clone(),
    )];
    if let Some((code, message)) = super::alpha_tabs::check_react_binding_in(
        &mut tx,
        &caller,
        &plan.artifact_id,
        &plan.source_event_id,
        &plan.source_digest,
        &scope,
        Some(&plan.message_id),
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(refused(&code, message));
    }
    if let Some((code, message)) = super::alpha_tabs::check_react_membership_in(
        &mut tx,
        &caller,
        bound,
        need,
        Some(&plan.message_id),
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(refused(&code, message));
    }
    // Message View, live Message type and locality on this snapshot. View
    // is gated first with its own code; the federated refusal lives in
    // the locality check below, never in the frame.
    if !super::can_record_in(&mut tx, &caller, &plan.message_id, Capability::View).await? {
        tx.rollback().await?;
        return Ok(refused(
            "permission_denied",
            format!(
                "the authenticated principal may not react to {}",
                plan.message_id
            ),
        ));
    }
    if let Err(error) =
        super::messaging::require_local_message_in(&mut tx, &caller, &plan.message_id).await
    {
        tx.rollback().await?;
        let text = error.to_string();
        if text.contains("federated") {
            return Ok(refused("message_federated", text));
        }
        return Ok(refused("message_unavailable", text));
    }
    // Desired-state recheck on this snapshot: an already-matching state
    // settles without appending.
    let present = super::messaging::reaction_present_in(
        &mut tx,
        &plan.message_id,
        caller.actor(),
        &plan.emoji,
    )
    .await?;
    if present == plan.adding {
        tx.rollback().await?;
        return Ok(ArtifactReactOutcome::Committed {
            receipt: react_receipt_value(&plan.message_id, &plan.emoji, plan.adding, false, false),
        });
    }
    let mut act_alloc = crate::act::ActAllocation::new();
    super::messaging::append_reaction_command_in(
        &db,
        &mut tx,
        &caller,
        super::messaging::ReactionCommandSpec {
            message_id: &plan.message_id,
            emoji: &plan.emoji,
            command,
            idempotency_key: &plan.idempotency_key,
            reason: &format!(
                "Artifact interaction '{}' set a message reaction.",
                plan.entry_id
            ),
            adding: plan.adding,
            changed: true,
            origin: Some(react_origin_value(&plan)),
        },
        &mut act_alloc,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(ArtifactReactOutcome::Committed {
        receipt: react_receipt_value(&plan.message_id, &plan.emoji, plan.adding, true, false),
    })
}

/// Observed-map key carrying a title rename's target-state token: a
/// `rec:` token over the record's content-event seq, minted from a fresh
/// render plan. The frame supplies no token authority of its own.
pub(crate) const TITLE_OBSERVED_KEY: &str = "title";

/// Plan for one governed tab title rename (task `da148be`). The new title
/// was validated as nonblank at composition; the consented need, binding,
/// Edit, Message-immutable rule, workspace-rename rule and `rec:` CAS are
/// re-proved in-transaction below.
pub(crate) struct ArtifactTitlePlan {
    pub artifact_id: String,
    pub entry_id: String,
    /// The engine-resolved manifest entry this plan was composed from.
    pub entry: mdx_v2::InteractionEntry,
    /// Must equal the guard's source revision; enforced at composition.
    pub source_event_id: String,
    /// Must equal the invocation's cited source digest; enforced at
    /// composition and re-pinned by the install gate in-transaction.
    pub source_digest: String,
    /// The target record, from the entry's single bound slot.
    pub record_id: String,
    /// The new title, preserved exactly (UTF-8, free text, nonblank).
    pub title: String,
    /// The invocation's `observed[record]["title"]` token, if any.
    /// Compared against a fresh `rec:` recomputation in-transaction.
    pub observed_token: Option<String>,
    /// Candidate binding scope from the entry's explicit bound-input port:
    /// exactly one (port, collection, kind) triple, re-proved
    /// in-transaction after replay, before a fresh append.
    pub scope_port: String,
    pub scope_collection_id: String,
    pub scope_kind: String,
    pub idempotency_key: String,
    pub gesture: Option<String>,
    pub guard: native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    /// Admission metadata only (D7 §4C.2 N3c). Every caller composes this
    /// `None`; the title kernel overwrites package and static admission
    /// together, resolved fresh at the install guard stage on the same write
    /// transaction, so a caller-supplied value is never accepted as
    /// pre-resolved admission. It never enters the persisted event, the
    /// origin, replay matching, CAS, the receipt or Undo.
    pub resolved_admission: Option<super::alpha_tabs::ResolvedAlphaAdmission>,
}

/// Typed outcome of the private canonical title write. Refusals and CAS
/// conflicts are data (the dispatcher maps them to intent results);
/// unexpected and commit errors propagate as `Err` for honest
/// host-unknown handling.
#[derive(Debug, Clone)]
pub(crate) enum ArtifactTitleOutcome {
    Committed {
        receipt: Value,
    },
    Refused {
        code: String,
        message: String,
    },
    Conflict {
        current_version: String,
        conflicting_event_id: String,
    },
}

/// Artifact origin for one governed tab rename, mirroring the
/// comment/record.create origin shape: effect-tagged for the replay
/// lookup, with the guard context plus the before/after titles needed to
/// settle a replay receipt without re-reading. D7 Undo locates the rename
/// through `origin.*`. (No version inside: the replay receipt derives its
/// version from the matched original event's seq.)
fn title_origin_value(plan: &ArtifactTitlePlan, before: &str) -> Value {
    json!({
        "kind": "artifact.interaction",
        "effect": "title.set",
        "artifact_id": plan.artifact_id,
        "entry_id": plan.entry_id,
        "source_digest": plan.source_digest,
        "source_event_id": plan.source_event_id,
        "idempotency_key": plan.idempotency_key,
        "record_id": plan.record_id,
        "title": plan.title,
        "before": before,
        "gesture": plan.gesture,
        "guard": {
            "package": plan.guard.package,
            "expected_install_event_id": plan.guard.expected_install_event_id,
            "artifact_id": plan.guard.artifact_id,
            "source_revision": plan.guard.source_revision,
            "version": plan.guard.version,
            "digest": plan.guard.digest,
            "declaration_digest": plan.guard.declaration_digest,
        },
    })
}

/// Whether a stored title origin carries this plan's exact identity:
/// same effect, artifact, entry, key, record, title and guard context.
/// Legacy origin-less rows never match — they conflict, as the comment
/// replay treats them.
fn title_origin_matches(stored_origin: Option<&Value>, plan: &ArtifactTitlePlan) -> bool {
    let Some(origin) = stored_origin else {
        return false;
    };
    let field = |key: &str| origin.get(key).and_then(Value::as_str);
    let guard = |key: &str| {
        origin
            .get("guard")
            .and_then(|object| object.get(key))
            .and_then(Value::as_str)
    };
    field("effect") == Some("title.set")
        && field("artifact_id") == Some(plan.artifact_id.as_str())
        && field("entry_id") == Some(plan.entry_id.as_str())
        && field("idempotency_key") == Some(plan.idempotency_key.as_str())
        && field("record_id") == Some(plan.record_id.as_str())
        && field("title") == Some(plan.title.as_str())
        && guard("package") == Some(plan.guard.package.as_str())
        && guard("expected_install_event_id") == Some(plan.guard.expected_install_event_id.as_str())
        && guard("artifact_id") == Some(plan.guard.artifact_id.as_str())
        && guard("source_revision") == Some(plan.guard.source_revision.as_str())
        && guard("version") == Some(plan.guard.version.as_str())
        && guard("digest") == Some(plan.guard.digest.as_str())
        && guard("declaration_digest") == Some(plan.guard.declaration_digest.as_str())
}

/// Dedicated governed-title entry point (task `da148be`). One
/// caller-owned write transaction re-proves install, consent, replay,
/// binding, need membership, Edit, Message-immutable scope and the `rec:`
/// CAS, then appends one `record.updated` carrying only the `name` field.
pub(crate) async fn rename_record_from_artifact(
    db: Db,
    caller: Caller,
    mut plan: ArtifactTitlePlan,
) -> Result<ArtifactTitleOutcome> {
    let refused = |code: &str, message: String| ArtifactTitleOutcome::Refused {
        code: code.to_string(),
        message,
    };
    if plan.title.trim().is_empty() {
        return Ok(refused("title_blank", "title must be nonblank".to_string()));
    }
    if plan.idempotency_key.trim().is_empty() {
        return Ok(refused(
            "invalid_invocation",
            "title idempotency key must not be blank".to_string(),
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    // Full install guard on this transaction at the same stage (D7 §4C.2
    // N3c): the alpha resolver runs the identical scope-fixed row core —
    // install pins plus object-only consent for the title bound, same order,
    // same codes/texts through `render_refusal` — and yields the already-read
    // row as a neutral package with static admission, without a second read.
    // Admission metadata only: the package never enters the origin, replay,
    // CAS, receipt or Undo below.
    let resolved = match super::alpha_tabs::resolve_alpha_admission_in(
        &mut tx,
        &caller,
        super::effect_admission::PackageClaim::alpha(&plan.guard),
        &plan.artifact_id,
        &plan.source_digest,
        &plan.entry,
        super::alpha_tabs::GuardScope::Title,
    )
    .await?
    {
        Ok(resolved) => resolved,
        Err(refusal) => {
            let (code, message) = super::effect_admission::render_refusal(
                super::effect_admission::AdmissionSource::AlphaTabInstall,
                &refusal,
            );
            tx.rollback().await?;
            return Ok(refused(&code, message));
        }
    };
    // Overwrite all supplied metadata with this transaction's result.
    plan.resolved_admission = Some(resolved);
    let super::effect_bounds::Admitted::Title { bound, need } = &plan
        .resolved_admission
        .as_ref()
        .expect("admission resolved immediately above")
        .admitted
    else {
        unreachable!("validated title scope carries its admitted bound");
    };
    // Serialized same-transaction replay, ahead of the dynamic
    // binding/membership gates: an identical retry replays its receipt
    // instead of re-proving mutable membership. Static guard/consent
    // above still gate every replay. The same key with a different title
    // conflicts and writes nothing.
    let prior: Option<(String, Value, i64)> = sqlx::query_as(
        "SELECT record_id, payload, seq FROM content_events
          WHERE actor=? AND type='record.updated'
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.entry_id')=?
            AND json_extract(payload,'$.origin.idempotency_key')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(caller.actor())
    .bind(&plan.artifact_id)
    .bind(&plan.entry_id)
    .bind(&plan.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    .map(
        |(record_id, payload, seq): (String, String, i64)| -> Result<(String, Value, i64)> {
            Ok((record_id, serde_json::from_str(&payload)?, seq))
        },
    )
    .transpose()?;
    if let Some((record_id, stored, original_seq)) = prior {
        let origin = stored.get("origin");
        let same = title_origin_matches(origin, &plan)
            && record_id == plan.record_id
            && stored.get("name").and_then(Value::as_str) == Some(plan.title.as_str());
        if !same {
            tx.rollback().await?;
            return Ok(refused(
                "idempotency_conflict",
                "the idempotency key was already used for a different rename".to_string(),
            ));
        }
        // Output View recheck before settling the prior receipt: a caller
        // who lost View since the commit gets a refusal, not the replay.
        if !super::can_record_in(&mut tx, &caller, &plan.record_id, Capability::View).await? {
            tx.rollback().await?;
            return Ok(refused(
                "permission_denied",
                format!(
                    "the authenticated principal may not rename {}",
                    plan.record_id
                ),
            ));
        }
        // The replay receipt mirrors the commit shape; its version derives
        // from the matched original event's seq (as the undo replay does
        // with `undo_seq`), so the receipt stays internally consistent
        // after an intervening change instead of describing live state.
        let version = native_artifact_runtime::artifact_intents::FacetVersion::Record {
            event_seq: original_seq,
        }
        .encode();
        tx.rollback().await?;
        let receipt = json!({
            "record_id": plan.record_id,
            "key": "name",
            "before": origin.and_then(|o| o.get("before")).cloned().unwrap_or(Value::Null),
            "after": origin.and_then(|o| o.get("title")).cloned().unwrap_or(Value::Null),
            "version": version,
        });
        return Ok(ArtifactTitleOutcome::Committed { receipt });
    }
    // Binding and delivered-need membership on this snapshot.
    let scope = vec![(
        plan.scope_port.clone(),
        plan.scope_collection_id.clone(),
        plan.scope_kind.clone(),
    )];
    if let Some((code, message)) = super::alpha_tabs::check_title_binding_in(
        &mut tx,
        &caller,
        &plan.artifact_id,
        &plan.source_event_id,
        &plan.source_digest,
        &scope,
        Some(&plan.record_id),
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(refused(&code, message));
    }
    if let Some((code, message)) = super::alpha_tabs::check_title_membership_in(
        &mut tx,
        &caller,
        bound,
        need,
        Some(&plan.record_id),
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(refused(&code, message));
    }
    // Renaming needs Edit as well as the View proved above.
    if !super::can_record_in(&mut tx, &caller, &plan.record_id, Capability::Edit).await? {
        tx.rollback().await?;
        return Ok(refused(
            "permission_denied",
            format!(
                "the authenticated principal may not rename {}",
                plan.record_id
            ),
        ));
    }
    // Message immutability: only a pending-local draft may be renamed.
    let record_type: Option<String> =
        sqlx::query_scalar("SELECT type FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&plan.record_id)
            .fetch_optional(&mut *tx)
            .await?;
    if record_type.as_deref() == Some("Message") {
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM message_origin_state WHERE message_id=?")
                .bind(&plan.record_id)
                .fetch_optional(&mut *tx)
                .await?;
        if status.as_deref() != Some("pending_local") {
            tx.rollback().await?;
            return Ok(refused(
                "message_immutable",
                "Message name is immutable creation content; create a superseding Message"
                    .to_string(),
            ));
        }
    }
    // Workspace renames stay with the host owner.
    if let Err(error) = super::require_workspace_rename_authority(
        "manage_alpha_tabs",
        &caller,
        &plan.record_id,
        Some(&Value::String(plan.title.clone())),
    ) {
        tx.rollback().await?;
        return Ok(refused("permission_denied", error.to_string()));
    }
    // Coarse `rec:` CAS: any record change since the observed token
    // conflicts. Accepted per contract; the receipt version lets a retry
    // re-read without a fresh render.
    let Some(token) = plan.observed_token.as_deref() else {
        tx.rollback().await?;
        return Ok(refused(
            "invalid_precondition",
            format!(
                "title rename of {} requires the host-issued observed token; re-read the record and retry",
                plan.record_id
            ),
        ));
    };
    let Some(expected) = native_artifact_runtime::artifact_intents::FacetVersion::parse(token)
        .and_then(|version| match version {
            native_artifact_runtime::artifact_intents::FacetVersion::Record { .. } => Some(version),
            _ => None,
        })
    else {
        tx.rollback().await?;
        return Ok(refused(
            "invalid_precondition",
            "title observed token is not a host-issued rec: token; re-read the record and retry"
                .to_string(),
        ));
    };
    let expected_seq = match expected {
        native_artifact_runtime::artifact_intents::FacetVersion::Record { event_seq } => event_seq,
        _ => {
            tx.rollback().await?;
            return Ok(refused(
                "invalid_precondition",
                "title observed token is not a host-issued rec: token; re-read the record and retry"
                    .to_string(),
            ));
        }
    };
    // The token must have been issued for this record: a row at exactly
    // that seq proves the host minted it here.
    let issued: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND seq=?)",
    )
    .bind(&plan.record_id)
    .bind(expected_seq)
    .fetch_one(&mut *tx)
    .await?;
    if !issued {
        tx.rollback().await?;
        return Ok(refused(
            "invalid_precondition",
            format!(
                "observed version for title on record {} was not issued by the host",
                plan.record_id
            ),
        ));
    }
    let current = super::artifact_interactions::current_facet_version(
        &mut tx,
        &plan.record_id,
        "name",
        Some("name"),
    )
    .await?;
    if current != expected {
        let (conflicting_event_id, _) = super::artifact_interactions::conflicting_event_in(
            &mut tx,
            &plan.record_id,
            "name",
            &current,
            Some("name"),
        )
        .await?;
        tx.rollback().await?;
        let current_version = current.encode();
        return Ok(ArtifactTitleOutcome::Conflict {
            current_version,
            conflicting_event_id,
        });
    }
    // Read the prior title on this snapshot for the receipt and origin.
    let before: String =
        sqlx::query_scalar("SELECT name FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&plan.record_id)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or_default();
    let mut act_alloc = crate::act::ActAllocation::new();
    let origin = title_origin_value(&plan, &before);
    crate::store::append_in(
        &db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: plan.record_id.clone(),
            event_type: "record.updated".into(),
            payload: json!({
                "name": plan.title,
                "reason": format!("Artifact interaction '{}' set the record title.", plan.entry_id),
                "origin": origin,
            }),
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    let version = super::artifact_interactions::current_facet_version(
        &mut tx,
        &plan.record_id,
        "name",
        Some("name"),
    )
    .await?
    .encode();
    db.commit_content(tx).await?;
    Ok(ArtifactTitleOutcome::Committed {
        receipt: json!({
            "record_id": plan.record_id,
            "key": "name",
            "before": before,
            "after": plan.title,
            "version": version,
        }),
    })
}

/// CAS-conflict marker for the canonical comment branch. Carries the
/// recomputed opaque token and the actual parent revision event id —
/// never a raw sequence, account, or fabricated identity.
fn comment_conflict_value(current_version: &str, conflicting_event_id: &str) -> Value {
    json!({
        "comment_conflict": true,
        "current_version": current_version,
        "conflicting_event_id": conflicting_event_id,
    })
}

/// Command digest for one comment append: normalized exact body, target,
/// position, source, guard pin, gesture, and caller context. Observed CAS
/// and `include_next_plan` are deliberately excluded — they do not change
/// the intended append, so a retry with a refreshed or omitted token
/// replays the same commit rather than conflicting with it.
fn comment_command_digest(caller_actor: &str, plan: &ArtifactCommentPlan) -> Result<String> {
    let envelope = json!({
        "artifact_id": plan.artifact_id,
        "entry_id": plan.entry_id,
        "source_event_id": plan.source_event_id,
        "source_digest": plan.source_digest,
        "target_id": plan.target_id,
        "position": plan.position,
        "body": plan.body,
        "manifest_max_bytes": plan.manifest_max_bytes,
        "guard": {
            "package": plan.guard.package,
            "expected_install_event_id": plan.guard.expected_install_event_id,
            "artifact_id": plan.guard.artifact_id,
            "source_revision": plan.guard.source_revision,
            "version": plan.guard.version,
            "digest": plan.guard.digest,
            "declaration_digest": plan.guard.declaration_digest,
        },
        "gesture": plan.gesture,
        "idempotency_key": plan.idempotency_key,
        "actor": caller_actor,
    });
    serde_jcs::to_vec(&envelope)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|error| Error::engine(format!("comment command digest failed: {error}")))
}

/// Whether a replayed comment origin carries this plan's exact guard
/// authorization context. Guarded↔unguarded and distinct pins never match;
/// the command digest comparison stays separate.
fn comment_guard_context_matches(stored_origin: &Value, plan: &ArtifactCommentPlan) -> bool {
    let guard = &plan.guard;
    let field = |key: &str| {
        stored_origin
            .get("guard")
            .and_then(|object| object.get(key))
            .and_then(Value::as_str)
    };
    field("package") == Some(guard.package.as_str())
        && field("expected_install_event_id") == Some(guard.expected_install_event_id.as_str())
        && field("artifact_id") == Some(guard.artifact_id.as_str())
        && field("source_revision") == Some(guard.source_revision.as_str())
        && field("version") == Some(guard.version.as_str())
        && field("digest") == Some(guard.digest.as_str())
        && field("declaration_digest") == Some(guard.declaration_digest.as_str())
}

/// Serialized post-gate comment replay, inside the caller-owned write
/// transaction and before any append. Legacy rows (no `effect`
/// discriminator) and changed commands refuse as idempotency conflicts —
/// never a legacy receipt, never an append. A same-command hit rechecks
/// output View, then settles the original minimal receipt without
/// appending, even when the presented CAS has since changed or is omitted.
async fn comment_replay_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    plan: &ArtifactCommentPlan,
    command_digest: &str,
) -> Result<Option<Value>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT record_id, payload FROM content_events
          WHERE type='record.created' AND actor=?
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.entry_id')=?
            AND json_extract(payload,'$.origin.idempotency_key')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(caller.actor())
    .bind(&plan.artifact_id)
    .bind(&plan.entry_id)
    .bind(&plan.idempotency_key)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((record_id, payload)) = row else {
        return Ok(None);
    };
    let stored: Value = serde_json::from_str(&payload)?;
    let origin = stored.get("origin");
    let same = origin
        .and_then(|origin| origin.get("effect"))
        .and_then(Value::as_str)
        == Some("comment.create")
        && origin
            .and_then(|origin| origin.get("command_digest"))
            .and_then(Value::as_str)
            == Some(command_digest)
        && origin.is_some_and(|origin| comment_guard_context_matches(origin, plan));
    if !same {
        return Ok(Some(comment_refused_value(
            "idempotency_conflict",
            "the idempotency key was already used for a different comment command".to_string(),
        )));
    }
    let bearer = origin
        .and_then(|origin| origin.get("target_id"))
        .and_then(Value::as_str);
    let position = origin
        .and_then(|origin| origin.get("position"))
        .and_then(Value::as_str);
    let (Some(bearer), Some(position)) = (bearer, position) else {
        return Ok(Some(comment_refused_value(
            "idempotency_conflict",
            "the idempotency key was already used for a different comment command".to_string(),
        )));
    };
    // Output View recheck before settling the prior receipt: a caller that
    // lost access gets a generic denial with no created id, act, or
    // sequence — never the receipt, and never a no-change assertion (the
    // write may have posted; re-read the thread to settle it).
    super::require_record_in(tx, caller, "create_record", &record_id, Capability::View)
        .await
        .map_err(|_| {
            Error::engine(
                "comment replay output is unavailable; re-read the thread to settle the outcome",
            )
        })?;
    Ok(Some(comment_receipt_value(
        &record_id, bearer, position, true,
    )))
}

/// Dedicated delivered-Message entry point.  `create_record` calls the same
/// append kernel but cannot obtain this capability, so it cannot bypass the
/// policy gate by creating a Message directly.
pub(crate) async fn send_message_record(
    db: Db,
    caller: Caller,
    arguments: Value,
    plan: SendMessagePlan,
) -> Result<Value> {
    create_record_inner(
        db,
        caller,
        arguments,
        Some(plan),
        None,
        None,
        CreateRecordResponse {
            mode: Some(ResponseMode::Verbose),
            // Sending a Message is not a duplication site: the notice is
            // type-blind, so a Message could match unrelated Documents, and this
            // response has no curated rendering for it. Suppress it here.
            similar_notice: None,
        },
    )
    .await
}

struct CreateRecordResponse<'a> {
    mode: Option<ResponseMode>,
    similar_notice: Option<&'a [String]>,
}

async fn create_record_inner(
    db: Db,
    caller: Caller,
    arguments: Value,
    send_plan: Option<SendMessagePlan>,
    artifact_plan: Option<ArtifactCreatePlan>,
    mut comment_plan: Option<ArtifactCommentPlan>,
    response: CreateRecordResponse<'_>,
) -> Result<Value> {
    const TOOL: &str = "create_record";
    reject_null_sources(TOOL, &arguments)?;
    // The provenance digests run over the raw tool arguments, not the parsed
    // shape: a server-minted `id` must never enter the conflict detector, or
    // every retry of a key without a caller-supplied id would conflict with
    // the call it repeats. Run-context keys are already stripped by the
    // request layer before the handler sees them.
    let mut provenance_arguments = arguments.clone();
    // Response representation is not part of the governed command. A retry
    // may ask for a verbose record after receiving a compact receipt (or the
    // reverse) without turning the same idempotency key into a conflict.
    if let Some(arguments) = provenance_arguments.as_object_mut() {
        arguments.remove("response_mode");
    }
    let mut args: CreateRecordArgs = parse_args(TOOL, arguments)?;
    let response_mode = response.mode.unwrap_or(args.response_mode);
    // Only the digest is stored, so an unbounded key is a mild DoS surface:
    // the same 1..=200 bound `manage_relationships` enforces. Blank stays
    // keyless rather than erroring — a create with no key behaves as today.
    if args
        .idempotency_key
        .as_deref()
        .is_some_and(|key| key.len() > 200)
    {
        return Err(Error::engine(
            "create_record: idempotency_key must be 1..200 characters",
        ));
    }
    // The delivered-Message and artifact-interaction routes keep their own
    // narrower replay paths (SendMessagePlan / ArtifactCreatePlan) and never
    // set the ordinary key; the provenance mechanism stays out of their way.
    // The comment route keeps its own post-gate replay the same way.
    let idempotent_create = send_plan.is_none()
        && artifact_plan.is_none()
        && comment_plan.is_none()
        && args
            .idempotency_key
            .as_deref()
            .is_some_and(|key| !key.trim().is_empty());
    require_nonblank_reason(TOOL, &args.reason)?;
    let lifecycle = args.lifecycle.take();
    let source_inputs = args.sources.take();
    if args.kind.is_empty() {
        return Err(Error::engine(format!("{TOOL}: 'kind' must not be empty")));
    }
    crate::freshness::reject_reserved_semantic_unit_kind(&args.kind, TOOL)?;
    if !SPINE_TYPES.contains(&args.record_type.as_str()) {
        return Err(Error::engine(format!(
            "{TOOL}: type '{}' is not a spine type (closed set: {}) — extend through 'kind', not 'type'",
            args.record_type,
            SPINE_TYPES.join(", ")
        )));
    }
    let id = crate::domain_transaction::record_id_for_create(args.id)?;
    let record_type = args.record_type.clone();
    if record_type == "Message"
        && send_plan.is_none()
        && args
            .addressed_to
            .as_ref()
            .is_none_or(|recipients| !recipients.is_empty())
    {
        return Err(Error::engine(
            "create_record: may create only a sender-only Message draft with addressed_to:[]; use manage_messages action:send for delivery",
        ));
    }
    if record_type == "Message" && send_plan.is_some() && args.origin.is_none() {
        return Err(Error::engine(
            "manage_messages.send requires an explicit communication origin",
        ));
    }
    if record_type == "Message" && send_plan.is_none() && args.origin.is_some() {
        return Err(Error::engine(
            "create_record: a sender-only Message draft cannot declare a communication origin; use manage_messages action:send",
        ));
    }
    if record_type != "Message" && send_plan.is_some() {
        return Err(Error::engine(
            "manage_messages.send may create only a Message",
        ));
    }
    let mut record_kind = args.kind.clone();
    let requested_owner = args.owner_id.clone();
    let mut fields = Map::new();
    fields.insert("type".into(), json!(args.record_type));
    // Payload, never a column: structural correlation keys are columns and prose
    // is payload. The projector reads `records` columns from an explicit
    // allowlist, so `reason` rides in the event and is inert to the fold — which
    // is exactly the property that lets it ship with no DDL change of its own.
    //
    // It goes on the record.created event ALONE, not on the facet and link events
    // this same call emits: those are consequences of one authoring act, and
    // copying the prose onto each would inflate one reason into four.
    fields.insert("reason".into(), json!(args.reason));
    let optional = [
        ("name", args.name),
        ("body", args.body),
        ("home_id", args.home_id.clone()),
        ("summary", args.summary),
        ("lifecycle", lifecycle),
        ("persistence", args.persistence),
        ("maturity", args.maturity),
    ];
    fields.insert("kind".into(), json!(record_kind.clone()));
    for (key, value) in optional {
        if let Some(value) = value {
            fields.insert(key.into(), json!(value));
        }
    }

    let mut facets = Vec::new();
    for (key, value) in args.facets.iter().flatten() {
        facets.push(
            parse_facet_entry(TOOL, key, value, false)?
                .expect("allow_unset=false never yields None"),
        );
    }
    if record_type == "Message" {
        if args.addressed_to.is_none() {
            return Err(Error::engine(
                "create_record: Message requires explicit addressed_to (use [] for sender-only)",
            ));
        }
        let expectation = facets
            .iter()
            .find(|facet| facet.key == crate::message_expectation::EXPECTATION_FACET_KEY)
            .ok_or_else(|| {
                Error::engine(format!(
                    "{TOOL}: Message required facet 'expectation' must be one of {}",
                    crate::message_expectation::EXPECTATION_VALUES.join(" | ")
                ))
            })?;
        let value = expectation.stored_value();
        if !crate::message_expectation::EXPECTATION_VALUES.contains(&value.as_str()) {
            return Err(Error::engine(format!(
                "{TOOL}: Message expectation '{value}' is not one of {}",
                crate::message_expectation::EXPECTATION_VALUES.join(" | ")
            )));
        }
    } else if args.addressed_to.is_some() || args.origin.is_some() || args.mentions.is_some() {
        return Err(Error::engine(
            "create_record: addressed_to, origin and mentions are only valid for Message",
        ));
    }
    // One transaction for the whole call (finding 5 / a54f708 option A):
    // home guard, every append and every projection commit together or not
    // at all. Link-target liveness rides on the projector's own in-transaction
    // guard (ef32e44).
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    // Canonical comment home: the frame supplies no destination. The live
    // bearer's stored canonical home populates BOTH the parsed args and the
    // already-built fields before the ordinary destination checks below, so
    // the home Collection Edit enforcement is the shared one. Missing,
    // deleted, or null-homed bearers fail here; ROOT survives only when it
    // is the stored home.
    if let Some(plan) = comment_plan.as_ref() {
        // Target authority first, on this write snapshot: the caller must
        // View and Edit the thread target before any home lookup, append,
        // or replay. Bools only — an IO error still propagates as unknown,
        // and no blanket error catch converts it into a refusal.
        if !crate::mcp::tools::can_record_in(&mut tx, &caller, &plan.target_id, Capability::View)
            .await?
            || !crate::mcp::tools::can_record_in(
                &mut tx,
                &caller,
                &plan.target_id,
                Capability::Edit,
            )
            .await?
        {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "permission_denied",
                "the authenticated principal may not comment on this thread".to_string(),
            ));
        }
        let stored: Option<Option<String>> =
            sqlx::query_scalar("SELECT home_id FROM records WHERE id=? AND deleted_at IS NULL")
                .bind(&plan.target_id)
                .fetch_optional(&mut *tx)
                .await?;
        let home = stored.flatten().filter(|home| !home.is_empty());
        let Some(home) = home else {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "missing_bearer",
                format!(
                    "comment bearer {} is missing, deleted, or has no stored home",
                    plan.target_id
                ),
            ));
        };
        args.home_id = Some(home.clone());
        fields.insert("home_id".into(), json!(home));
    }
    if let Some(plan) = artifact_plan.as_ref() {
        if let Some(existing_id) = artifact_create_replay_in(&mut tx, caller.actor(), plan).await? {
            tx.rollback().await?;
            let mut existing = enriched_or_error(&db, &caller, TOOL, &existing_id).await?;
            existing
                .as_object_mut()
                .expect("enriched record object")
                .insert("idempotent_retry".into(), Value::Bool(true));
            return echo_previous_seq(existing, None);
        }
    }
    let destination = args
        .home_id
        .as_deref()
        .unwrap_or(crate::schema::ROOT_RECORD_ID);
    // Comment destination Edit on the derived home, typed and id-free,
    // before the ordinary assert/require below (which stay as second
    // locks). Ordinary callers are untouched: this block runs only with a
    // comment plan.
    if comment_plan.is_some()
        && !crate::mcp::tools::can_record_in(&mut tx, &caller, destination, Capability::Edit)
            .await?
    {
        tx.rollback().await?;
        return Ok(comment_refused_value(
            "permission_denied",
            "the authenticated principal may not file a comment in this thread's home".to_string(),
        ));
    }
    if let Some(home_id) = &args.home_id {
        // A comment bearer homed at stored ROOT files at ROOT exactly like
        // an unhomed ordinary create: no folder-shape assert, still the
        // Collection Edit enforcement below.
        let comment_root_home = comment_plan.is_some() && home_id == crate::schema::ROOT_RECORD_ID;
        if !comment_root_home {
            if comment_plan.is_some() {
                // Comment-only mapping: the helper's two explicit shape
                // branches (missing home, non-folder shape) are proven
                // deterministic — both follow bare SQL reads with no
                // delegated calls — so they settle as an id-free refusal
                // that never names the derived home. SQL failures propagate
                // as unknown; ordinary callers are untouched.
                if let Err(error) = assert_home_target_in(&mut tx, TOOL, home_id).await {
                    match error {
                        Error::Engine(_) => {
                            tx.rollback().await?;
                            return Ok(comment_refused_value(
                                "invalid_home",
                                "comment thread home is not a live unarchived enduring folder"
                                    .to_string(),
                            ));
                        }
                        other => return Err(other),
                    }
                }
            } else {
                assert_home_target_in(&mut tx, TOOL, home_id).await?;
            }
        }
    }
    require_record_in(&mut tx, &caller, TOOL, destination, Capability::Edit).await?;
    if let Some(plan) = artifact_plan.as_ref() {
        validate_artifact_create_scope_in(&mut tx, &caller, plan).await?;
    }
    let caller_owner: Option<String> = sqlx::query_scalar(
        "SELECT record_id FROM bindings
          WHERE system = 'account' AND identifier = ? AND is_canonical = 1
          ORDER BY record_id LIMIT 1",
    )
    .bind(caller.credential())
    .fetch_optional(&mut *tx)
    .await?;
    if !super::is_legacy_local(&caller) {
        let caller_owner = caller_owner.ok_or_else(|| {
            Error::engine(format!("{TOOL}: caller has no portable account binding"))
        })?;
        if requested_owner
            .as_deref()
            .is_some_and(|owner| owner != caller_owner)
        {
            return Err(Error::engine(format!(
                "{TOOL}: owner_id must be the caller's portable identity"
            )));
        }
        fields.insert("owner_id".into(), json!(caller_owner));
    } else if let Some(owner) = requested_owner {
        fields.insert("owner_id".into(), json!(owner));
    }
    let mut relationship_link_indexes = BTreeSet::new();
    for (index, link) in args.links.iter().flatten().enumerate() {
        if link.relationship == "addressed_to" {
            return Err(Error::engine(
                "create_record: addressed_to must use the Message addressed_to field",
            ));
        }
        require_record_in(&mut tx, &caller, TOOL, &link.target_id, Capability::View).await?;
        let target_type: String =
            sqlx::query_scalar("SELECT type FROM records WHERE id=? AND deleted_at IS NULL")
                .bind(&link.target_id)
                .fetch_one(&mut *tx)
                .await?;
        if crate::relationship::legacy::classify(
            Some(&record_type),
            Some(&target_type),
            None,
            &link.relationship,
        ) == crate::relationship::legacy::LinkOwnership::Relationship
        {
            relationship_link_indexes.insert(index);
        }
    }
    let mut audience_accounts = Vec::new();
    let mut audience_recipients = Vec::new();
    let mut audience_seen = BTreeSet::new();
    for recipient_id in args.addressed_to.iter().flatten() {
        if fields.get("owner_id").and_then(Value::as_str) == Some(recipient_id.as_str()) {
            return Err(Error::engine(
                "create_record: addressed_to must exclude the Message sender",
            ));
        }
        if !audience_seen.insert(recipient_id.as_str()) {
            return Err(Error::engine(format!(
                "create_record: duplicate addressed_to recipient {recipient_id}"
            )));
        }
        require_record_in(&mut tx, &caller, TOOL, recipient_id, Capability::View).await?;
        let principal: Option<String> = sqlx::query_scalar(
            "SELECT identifier FROM bindings
              WHERE record_id=? AND system='native-principal' AND is_canonical=1",
        )
        .bind(recipient_id)
        .fetch_optional(&mut *tx)
        .await?;
        let principal = principal.ok_or_else(|| {
            Error::engine(format!(
                "manage_messages.send: messaging unavailable for recipient {recipient_id}: hosted identity reconciliation has not installed a canonical native-principal binding"
            ))
        })?;
        audience_recipients.push(crate::events::MessageAudienceRecipient {
            recipient_id: recipient_id.clone(),
            principal,
        });
        let account = sqlx::query_scalar::<_, String>(
            "SELECT identifier FROM bindings
              WHERE record_id=? AND system='account' AND is_canonical=1",
        )
        .bind(recipient_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "manage_messages.send: recipient {recipient_id} has no canonical local account; cross-workspace delivery is not supported"
            ))
        })?;
        audience_accounts.push(account);
    }
    let mut validated_mentions = Vec::new();
    let mut mention_ids = BTreeSet::new();
    let body_for_mentions = fields.get("body").and_then(Value::as_str).unwrap_or("");
    let mut origin_db_id: Option<String> = None;
    for mention in args.mentions.iter().flatten() {
        if mention.mention_id.trim().is_empty() || !mention_ids.insert(mention.mention_id.as_str())
        {
            return Err(Error::engine(
                "create_record: mention ids must be non-empty and unique",
            ));
        }
        if mention.span_start >= mention.span_end
            || mention.span_end > body_for_mentions.len()
            || !body_for_mentions.is_char_boundary(mention.span_start)
            || !body_for_mentions.is_char_boundary(mention.span_end)
            || body_for_mentions[mention.span_start..mention.span_end] != mention.authored_label
        {
            return Err(Error::engine(
                "create_record: mention span must exactly match immutable Message prose",
            ));
        }
        require_record_in(&mut tx, &caller, TOOL, &mention.target_id, Capability::View).await?;
        let (target_binding, recipient_account) = match mention.target_kind.as_str() {
            "principal" => {
                if !args
                    .addressed_to
                    .iter()
                    .flatten()
                    .any(|id| id == &mention.target_id)
                {
                    return Err(Error::engine(
                        "create_record: principal mention target must already be addressed",
                    ));
                }
                let principal:String=sqlx::query_scalar("SELECT identifier FROM bindings WHERE record_id=? AND system='native-principal' AND is_canonical=1").bind(&mention.target_id).fetch_optional(&mut *tx).await?.ok_or_else(||Error::engine("create_record: mention target is invalid or unavailable"))?;
                let account:String=sqlx::query_scalar("SELECT identifier FROM bindings WHERE record_id=? AND system='account' AND is_canonical=1").bind(&mention.target_id).fetch_optional(&mut *tx).await?.ok_or_else(||Error::engine("create_record: mention target is invalid or unavailable"))?;
                (principal, Some(account))
            }
            "record" => {
                if origin_db_id.is_none() {
                    origin_db_id = Some(
                        sqlx::query_scalar(
                            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
                        )
                        .fetch_one(&mut *tx)
                        .await?,
                    );
                }
                (
                    crate::identity::encode_native_record(
                        origin_db_id.as_deref().ok_or_else(|| {
                            Error::engine("create_record: database identity is unavailable")
                        })?,
                        &mention.target_id,
                    )?,
                    None,
                )
            }
            _ => {
                return Err(Error::engine(
                    "create_record: mention target_kind must be principal or record",
                ))
            }
        };
        validated_mentions.push(crate::awareness::ValidatedMention {
            input: mention.clone(),
            target_binding,
            recipient_account,
        });
    }
    if !validated_mentions.is_empty() {
        fields.insert("mentions".into(),serde_json::to_value(validated_mentions.iter().map(|m|json!({
            "mention_id":m.input.mention_id,"target_kind":m.input.target_kind,"target_id":m.input.target_id,
            "target_binding":m.target_binding,"span_start":m.input.span_start,"span_end":m.input.span_end,
            "authored_label":m.input.authored_label
        })).collect::<Vec<_>>())?);
    }
    if let Some(target) = args.target.as_ref() {
        require_record_in(
            &mut tx,
            &caller,
            TOOL,
            &target.target_record_id,
            Capability::View,
        )
        .await?;
    }
    let resolution = crate::meta::kind::resolve_on(&mut tx, &record_type, &record_kind).await?;
    if !resolution.quarantined
        && resolution.canonical_value_id.as_deref() == Some("vv:voc:kind:Annotation:attribution")
    {
        return Err(Error::engine(
            "create_record: governed Annotation kind:attribution must be created with create_attribution so bearer, exact target, assertion, evidence, and action attestation commit atomically",
        ));
    }
    if let Some(canonical) = resolution.canonical_kind_for_write() {
        record_kind = canonical.to_string();
        fields.insert("kind".into(), json!(canonical));
    }
    // Governed core work kinds have one supported creation default. Historical
    // rows are not rewritten; only this admitted create path supplies the
    // missing axis. Keep this exact-kind list explicit so future WorkItem kinds
    // do not inherit either the binding or the default.
    if record_type == "WorkItem"
        && matches!(record_kind.as_str(), "task" | "epic")
        && !fields.contains_key("lifecycle")
    {
        fields.insert("lifecycle".into(), json!("open"));
    }
    let is_comment = crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution);
    let is_citation = crate::generated::kinds::CoreKind::AnnotationCitation.matches(&resolution);
    let mut comment_position = None;
    let mut comment_bearers = Vec::new();
    // Deferred expected shape, comment plans only: an expected thread-shape
    // refusal must not preempt a stale-parent Conflict. Infrastructure
    // failures still propagate as unknown here; the recorded shape settles
    // after CAS, where a mismatch has already produced Conflict.
    let mut deferred_comment_shape = false;
    if is_comment {
        let bearer_ids = args
            .links
            .iter()
            .flatten()
            .filter(|link| link.relationship == "part_of")
            .map(|link| link.target_id.clone())
            .collect::<Vec<_>>();
        if comment_plan.is_some() {
            match crate::comments::validate_create_checked_on(
                &mut tx,
                &bearer_ids,
                fields.get("body").and_then(Value::as_str),
                fields.get("lifecycle").and_then(Value::as_str),
                fields.get("summary").and_then(Value::as_str),
            )
            .await?
            {
                Ok(position) => {
                    comment_position = Some(position);
                }
                Err(_) => {
                    deferred_comment_shape = true;
                }
            }
        } else {
            comment_position = Some(
                crate::comments::validate_create_on(
                    &mut tx,
                    TOOL,
                    &bearer_ids,
                    fields.get("body").and_then(Value::as_str),
                    fields.get("lifecycle").and_then(Value::as_str),
                    fields.get("summary").and_then(Value::as_str),
                )
                .await?,
            );
        }
        comment_bearers = bearer_ids;
        // Name the state instead of leaving it to absence: a root created with
        // no lifecycle is an FYI, so it stores `informational` rather than
        // null. Replies keep their null — thread state lives on the root.
        // A deferred comment shape settles post-CAS (where a mismatch has
        // already conflicted), so its default moves there too.
        let lifecycle_default = if deferred_comment_shape {
            None
        } else {
            crate::comments::created_lifecycle(
                comment_position.expect("a validated comment has a position"),
                fields.get("lifecycle").and_then(Value::as_str),
            )
        };
        if let Some(lifecycle) = lifecycle_default {
            fields.insert("lifecycle".into(), json!(lifecycle));
        }
    }
    if is_citation {
        if args.target.is_none() {
            return Err(Error::engine(
                "create_record: Annotation kind:citation requires target",
            ));
        }
        let part_of = args
            .links
            .iter()
            .flatten()
            .filter(|link| link.relationship == "part_of")
            .count();
        if part_of != 1 {
            return Err(Error::engine(
                "create_record: Annotation kind:citation requires exactly one outgoing part_of link to its bearer",
            ));
        }
    } else if is_comment {
        if let Some(target) = args.target.as_ref() {
            if comment_position != Some(crate::comments::Position::Root) {
                return Err(Error::engine(
                    "create_record: comment replies must be targetless; quoted context belongs to the root",
                ));
            }
            if target.source_slot != crate::citations::SourceSlot::Body
                || comment_bearers.first() != Some(&target.target_record_id)
            {
                return Err(Error::engine(
                    "create_record: anchored comment root must target its part_of bearer's body",
                ));
            }
        }
    } else if args.target.is_some() {
        return Err(Error::engine(
            "create_record: target is valid only for Annotation kind:citation or a comment root",
        ));
    }
    // Private canonical comment gates (task `b9fb9fd` family 1). The
    // ordinary checks above proved destination Edit on the derived bearer
    // home, link-target View, and comment shape with its thread position.
    // What remains is comment-specific on this write snapshot: current
    // authority/static consent before replay, binding/membership after it. Refusals and CAS conflicts return
    // minimal marker outcomes (see `decode_comment_outcome`); unexpected
    // errors propagate as `Err` for honest host-unknown handling. On pass,
    // the digest below feeds the origin block and the flow continues
    // through the ordinary append/commit path to the minimal receipt.
    let comment_command_digest: Option<String> = if let Some(plan) = comment_plan.as_mut() {
        // Validated position, if validation produced one. A deferred
        // expected shape settles after CAS (where a mismatch has already
        // conflicted), so every position-dependent check below is skipped
        // while deferred.
        let validated: Option<&str> = match comment_position {
            Some(crate::comments::Position::Root) => Some("root"),
            Some(crate::comments::Position::Reply) => Some("reply"),
            None => None,
        };
        // Position agreement settles after CAS below: a stale parent
        // whose move changed the thread shape must Conflict rather than
        // Refuse here, and a same-command replay must settle without any
        // fresh position proof. Consent and reply authority use the fixed
        // manifest plan position, never the validated one.
        // Target Edit: the link loop proved View; posting needs Edit too.
        if !crate::mcp::tools::can_record_in(&mut tx, &caller, &plan.target_id, Capability::Edit)
            .await?
        {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "permission_denied",
                format!(
                    "the authenticated principal may not comment on {}",
                    plan.target_id
                ),
            ));
        }
        // A fresh, validated ordinary bearer under a reply plan is a pure
        // composer mismatch: it settles post-CAS as invalid_position, so
        // the root-authority checks below stand down for exactly that
        // case. Every other combination — including deferred shapes, where
        // a source-valid root may remain to inspect — runs them.
        let fresh_position_mismatch =
            !deferred_comment_shape && validated.is_some_and(|v| v != plan.position.as_str());
        // Thread-parent View: for a manifest reply, the root comment's
        // exactly-one part_of bearer resolves fresh on this transaction
        // and must be View-visible before replay or append. Keyed on the
        // fixed plan position. This confers no independent authority:
        // canonical Annotation authorization already walks the underlying
        // bearer (authorization_target_on_inner), so the check fulfills
        // the contract explicitly and stands as defense-in-depth.
        // Malformed or missing underlying bearers fail closed here.
        if plan.position == "reply" && !fresh_position_mismatch {
            let parents: Vec<String> = sqlx::query_scalar(
                "SELECT target_id FROM links
                  WHERE source_id=? AND relationship='part_of'
                  ORDER BY target_id",
            )
            .bind(&plan.target_id)
            .fetch_all(&mut *tx)
            .await?;
            let [parent] = parents.as_slice() else {
                tx.rollback().await?;
                return Ok(comment_refused_value(
                    "invalid_parent",
                    format!(
                        "comment thread root {} has no single underlying bearer",
                        plan.target_id
                    ),
                ));
            };
            if !crate::mcp::tools::can_record_in(&mut tx, &caller, parent, Capability::View).await?
            {
                tx.rollback().await?;
                return Ok(comment_refused_value(
                    "permission_denied",
                    format!(
                        "the authenticated principal may not view comment thread parent {parent}"
                    ),
                ));
            }
        }
        // Anchored parents refused in this unanchored slice: a manifest
        // reply whose thread root carries an annotation target, on this
        // snapshot. Keyed on the fixed plan position like the parent
        // check above. Ordinary comment validators stay unchanged.
        if plan.position == "reply" && !fresh_position_mismatch {
            let anchored: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM annotation_targets WHERE annotation_id=?)",
            )
            .bind(&plan.target_id)
            .fetch_one(&mut *tx)
            .await?;
            if anchored {
                tx.rollback().await?;
                return Ok(comment_refused_value(
                    "anchored_parent",
                    format!(
                        "comment thread root {} carries an annotation target; anchored replies are a later slice",
                        plan.target_id
                    ),
                ));
            }
        }
        // Full install guard on this transaction at the same stage (D7 §4C.2
        // N3c): the alpha resolver runs the identical scope-fixed row core —
        // install pins plus object-only consent for the fixed position, same
        // order, same codes/texts through `render_refusal` — and yields the
        // already-read row as a neutral package with static admission, without
        // a second install read. Admission metadata only: the package never
        // enters the command digest, origin, CAS, receipt or Undo below.
        let resolved = match super::alpha_tabs::resolve_alpha_admission_in(
            &mut tx,
            &caller,
            super::effect_admission::PackageClaim::alpha(&plan.guard),
            &plan.artifact_id,
            &plan.source_digest,
            &plan.entry,
            super::alpha_tabs::GuardScope::Comment {
                position: &plan.position,
            },
        )
        .await?
        {
            Ok(resolved) => resolved,
            Err(refusal) => {
                let (code, message) = super::effect_admission::render_refusal(
                    super::effect_admission::AdmissionSource::AlphaTabInstall,
                    &refusal,
                );
                tx.rollback().await?;
                return Ok(comment_refused_value(&code, message));
            }
        };
        // Overwrite all supplied metadata with this transaction's result.
        plan.resolved_admission = Some(resolved);
        let super::effect_bounds::Admitted::Comment { bound, need } = &plan
            .resolved_admission
            .as_ref()
            .expect("admission resolved immediately above")
            .admitted
        else {
            unreachable!("validated comment scope carries its admitted bound");
        };
        // Exact body within min(manifest, consent) UTF-8 bytes. Nonblank is
        // already proved by the ordinary comment validation above.
        let body = fields.get("body").and_then(Value::as_str).unwrap_or("");
        let cap = plan.manifest_max_bytes.min(bound.max_body_bytes);
        if body.len() > cap {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "comment_body_too_large",
                format!(
                    "comment body is {} UTF-8 bytes; the effective cap is {cap}",
                    body.len()
                ),
            ));
        }
        // Current authority/static consent precede replay; mutable binding
        // and membership follow it. Same command settles its receipt,
        // changed commands (and legacy rows) conflict, misses proceed.
        let command_digest = comment_command_digest(caller.actor(), plan)?;
        if let Some(outcome) = comment_replay_in(&mut tx, &caller, plan, &command_digest).await? {
            tx.rollback().await?;
            return Ok(outcome);
        }
        // Binding and delivered-need membership on this snapshot, through
        // the comment wrappers.
        let scope = vec![(
            plan.scope_port.clone(),
            plan.scope_collection_id.clone(),
            plan.scope_kind.clone(),
        )];
        if let Some((code, message)) = super::alpha_tabs::check_comment_binding_in(
            &mut tx,
            &caller,
            &plan.artifact_id,
            &plan.source_event_id,
            &plan.source_digest,
            &scope,
            Some(&plan.target_id),
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(comment_refused_value(&code, message));
        }
        if let Some((code, message)) = super::alpha_tabs::check_comment_membership_in(
            &mut tx,
            &caller,
            bound,
            need,
            Some(&plan.target_id),
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(comment_refused_value(&code, message));
        }
        // CAS for the new append only: the presented token must parse and
        // match a fresh recomputation over current parent state. Missing or
        // malformed tokens refuse; well-shaped mismatches conflict with the
        // current opaque token and the actual parent event id.
        let Some(presented) = plan.observed_token.as_deref() else {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "invalid_precondition",
                format!(
                    "comment on {} requires the host-issued target token; re-read the thread and retry",
                    plan.target_id
                ),
            ));
        };
        if native_artifact_runtime::artifact_intents::parse_comment_token(presented).is_none() {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "invalid_precondition",
                "comment target token is not a host-issued token; re-read the thread and retry"
                    .to_string(),
            ));
        }
        let state = match super::artifact_interactions::read_comment_parent_state_in(
            &mut tx,
            &plan.target_id,
        )
        .await?
        {
            Some(state) => state,
            None => {
                tx.rollback().await?;
                return Ok(comment_refused_value(
                    "missing_record",
                    format!("comment bearer {} does not exist", plan.target_id),
                ));
            }
        };
        let expected = super::artifact_interactions::seal_comment_token(
            &super::artifact_interactions::CommentMintContext {
                caller_credential: caller.credential(),
                artifact_id: &plan.artifact_id,
                source_event_id: &plan.source_event_id,
                source_digest: &plan.source_digest,
            },
            &plan.target_id,
            &state,
        );
        let expected_bytes =
            native_artifact_runtime::artifact_intents::parse_comment_token(&expected)
                .ok_or_else(|| Error::engine("comment token mint produced an unparsable token"))?;
        if !super::artifact_interactions::verify_comment_token(presented, &expected_bytes) {
            tx.rollback().await?;
            return Ok(comment_conflict_value(&expected, &state.revision_event_id));
        }
        // Settle expected shape only on a matching CAS: a stale parent
        // conflicts above even when its move changed the thread shape, and
        // a deferred shape refuses here. Fixed id-free refusals; validator
        // detail never crosses.
        if deferred_comment_shape {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "invalid_thread",
                "comment thread shape is not postable; re-read the thread and retry".to_string(),
            ));
        }
        let Some(validated) = validated else {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "invalid_position",
                "comment position did not validate".to_string(),
            ));
        };
        if plan.position != validated {
            tx.rollback().await?;
            return Ok(comment_refused_value(
                "invalid_position",
                format!(
                    "comment plan position '{}' disagrees with validated position '{validated}'",
                    plan.position
                ),
            ));
        }
        Some(command_digest)
    } else {
        None
    };
    let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
    let mut governed_writes = facets.clone();
    if let Some(lifecycle) = fields.get("lifecycle").and_then(Value::as_str) {
        governed_writes.push(FacetWrite {
            key: "lifecycle".into(),
            value: Value::String(lifecycle.into()),
            vocab_ref: None,
            time_type: None,
        });
    }
    assert_facet_value_predicates_in(
        &mut tx,
        &schema_rows,
        TOOL,
        &record_type,
        Some(&record_kind),
        None,
        &mut governed_writes,
    )
    .await?;
    if crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(&resolution) {
        crate::suggestion_lifecycle::validate_create(
            TOOL,
            fields.get("lifecycle").and_then(Value::as_str),
        )?;
    }
    for facet in &mut facets {
        facet.adopt_governed(
            governed_writes
                .iter()
                .find(|checked| checked.key == facet.key),
        );
    }
    let runtime = facets
        .iter()
        .find(|facet| facet.key == "runtime")
        .map(FacetWrite::stored_value);
    validate_prospective_program(TOOL, &record_type, Some(&record_kind), runtime.as_deref())?;
    let body = fields.get("body").and_then(Value::as_str);
    let html_manifest = super::artifacts::validate_prospective_html(
        TOOL,
        &record_type,
        Some(&record_kind),
        runtime.as_deref(),
        body,
    )?;
    let html_body_write = html_manifest.map(|manifest| {
        html_body_write_result(
            &manifest,
            body.expect("native.html.v1 validation requires a body"),
        )
    });
    let before = required_violations_in(&mut tx, &schema_rows, &[&id]).await?;
    let captured_target = match args.target {
        Some(target) => Some(crate::citations::capture_target_in(&mut tx, target).await?),
        None => None,
    };
    let message_sender = if record_type == "Message" {
        let sender_id = fields
            .get("owner_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("create_record: Message requires sender owner_id"))?
            .to_string();
        let sender_principal: String = sqlx::query_scalar(
            "SELECT identifier FROM bindings
              WHERE record_id=? AND system='native-principal' AND is_canonical=1",
        )
        .bind(&sender_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            Error::engine(
                "manage_messages.send: messaging unavailable for the sender: hosted identity reconciliation has not installed a canonical native-principal binding",
            )
        })?;
        Some((sender_id, sender_principal))
    } else {
        None
    };
    let resolved_origin = match (
        args.origin.as_ref(),
        message_sender.as_ref(),
        send_plan.as_ref(),
    ) {
        (Some(origin), Some((sender_id, sender_principal)), Some(_)) => Some(
            resolve_message_origin_in(&mut tx, &caller, origin, sender_id, sender_principal)
                .await?,
        ),
        (None, _, None) => None,
        _ => {
            return Err(Error::engine(
                "manage_messages.send requires a resolvable explicit communication origin",
            ))
        }
    };
    if let Some((crate::events::MessageOriginDeclaredPayload::Collection { collection_id }, _)) =
        &resolved_origin
    {
        let authored_home = fields.get("home_id").and_then(Value::as_str);
        if authored_home != Some(collection_id.as_str()) {
            return Err(Error::engine(
                "manage_messages.send: a Collection-origin Message must be filed in that Collection",
            ));
        }
    }
    if let Some((crate::events::MessageOriginDeclaredPayload::Direct { principals }, _)) =
        &resolved_origin
    {
        if let Some(outside) = audience_recipients
            .iter()
            .find(|recipient| !principals.contains(&recipient.principal))
        {
            return Err(Error::engine(format!(
                "manage_messages.send: addressed recipient {} is outside the exact direct context",
                outside.recipient_id
            )));
        }
    }
    if let Some((origin, _)) = &resolved_origin {
        for (relationship, role, plural_role) in [
            ("reply_to", "reply", "replies"),
            ("supersedes", "correction", "corrections"),
        ] {
            let targets = args
                .links
                .iter()
                .flatten()
                .filter(|link| link.relationship == relationship)
                .collect::<Vec<_>>();
            if targets.len() > 1 {
                return Err(Error::engine(format!(
                    "manage_messages.send: a Message may have at most one canonical {relationship} target"
                )));
            }
            if let Some(target) = targets.first() {
                let row = sqlx::query(
                    "SELECT status,origin_type,collection_id,direct_set_digest,participant_count
                   FROM message_origin_state WHERE message_id=?",
                )
                .bind(&target.target_id)
                .fetch_optional(&mut *tx)
                .await?;
                let Some(row) = row else {
                    return Err(Error::engine(format!(
                        "manage_messages.send: {role} target has no communication-origin state"
                    )));
                };
                if row.try_get::<String, _>("status")? != "declared" {
                    return Err(Error::engine(format!(
                    "manage_messages.send: cannot create a contextual {role} of an origin-unknown Message"
                )));
                }
                let same = match origin {
                    crate::events::MessageOriginDeclaredPayload::Collection { collection_id } => {
                        row.try_get::<Option<String>, _>("origin_type")?.as_deref()
                            == Some("collection")
                            && row
                                .try_get::<Option<String>, _>("collection_id")?
                                .as_deref()
                                == Some(collection_id.as_str())
                    }
                    crate::events::MessageOriginDeclaredPayload::Direct { principals } => {
                        let projected_principals: Vec<String> = sqlx::query_scalar(
                            "SELECT principal_id FROM message_origin_principals
                          WHERE message_id=? ORDER BY principal_id",
                        )
                        .bind(&target.target_id)
                        .fetch_all(&mut *tx)
                        .await?;
                        row.try_get::<Option<String>, _>("origin_type")?.as_deref()
                            == Some("direct")
                            && row.try_get::<i64, _>("participant_count")?
                                == principals.len() as i64
                            && row
                                .try_get::<Option<String>, _>("direct_set_digest")?
                                .as_deref()
                                == Some(
                                    crate::events::direct_origin_set_digest(principals).as_str(),
                                )
                            && projected_principals == *principals
                    }
                };
                if !same {
                    return Err(Error::engine(format!(
                    "manage_messages.send: {plural_role} must retain the communication origin in which they are authored"
                )));
                }
            }
        }
    }
    let mut send_evaluation = None;
    let mut intervention_id = None;
    let mut delivered = record_type != "Message";
    let intended_recipients = audience_recipients.clone();
    // A channel post is a delivered Message filed in a Collection that
    // addresses nobody: it inherits the Collection's audience and puts an
    // obligation on no one. `manage_messages.send` refuses an empty audience
    // without a home, so this shape only reaches here deliberately.
    let collection_origin = resolved_origin.as_ref().is_some_and(|(origin, _)| {
        matches!(
            origin,
            crate::events::MessageOriginDeclaredPayload::Collection { .. }
        )
    });
    let channel_post = send_plan.is_some() && intended_recipients.is_empty() && collection_origin;
    if let (Some(plan), Some((_, sender_principal))) = (send_plan.as_ref(), message_sender.as_ref())
    {
        if plan.idempotency_key.trim().is_empty() {
            return Err(Error::engine(
                "manage_messages.send: idempotency_key must not be blank",
            ));
        }
        if let Some(row) = sqlx::query(
            "SELECT record_id,payload FROM content_events
              WHERE type='message.send_evaluated.v1'
                AND json_extract(payload,'$.idempotency_key')=?
                AND json_extract(payload,'$.sender_principal_id')=?
              ORDER BY seq LIMIT 1",
        )
        .bind(&plan.idempotency_key)
        .bind(sender_principal)
        .fetch_optional(&mut *tx)
        .await?
        {
            let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
            if payload.get("intent_digest").and_then(Value::as_str)
                != Some(plan.intent_digest.as_str())
            {
                return Err(Error::engine(
                    "manage_messages.send: idempotency_key was reused for different intent",
                ));
            }
            let existing_id: String = row.try_get("record_id")?;
            let existing_intervention_id: Option<String> = sqlx::query_scalar(
                "SELECT json_extract(payload,'$.intervention_id') FROM content_events
                  WHERE record_id=? AND type='intervention.raised.v1'
                  ORDER BY seq LIMIT 1",
            )
            .bind(&existing_id)
            .fetch_optional(&mut *tx)
            .await?;
            let authorized_delivery: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM content_events
                  WHERE record_id=? AND type='message.delivery.authorized.v1')",
            )
            .bind(&existing_id)
            .fetch_one(&mut *tx)
            .await?;
            let cancelled: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM content_events
                  WHERE record_id=? AND type='intervention.cancelled.v1')",
            )
            .bind(&existing_id)
            .fetch_one(&mut *tx)
            .await?;
            let currently_delivered = authorized_delivery
                || payload.get("delivered").and_then(Value::as_bool) == Some(true);
            let database_id = crate::interventions::database_id_in(&mut tx).await?;
            tx.rollback().await?;
            // Re-check readability now, not from the persisted trace's own
            // conflict codes: the same principal may have lost View since the
            // first send, and the retry must not name a source it cannot read.
            let retry_trace = match payload.get("policy_trace") {
                Some(trace) => {
                    crate::interventions::redact_trace_for_caller(&db, &caller, trace).await?
                }
                None => Value::Null,
            };
            let mut existing =
                enriched_or_error(&db, &caller, "manage_messages.send", &existing_id).await?;
            existing.as_object_mut().expect("enriched record object").insert(
                "delivery".into(),
                json!({
                    "status":if currently_delivered{"delivered"}else if cancelled{"cancelled"}else{"blocked"},
                    "delivered":currently_delivered,
                    "execution":if authorized_delivery{"resumed"}else if cancelled{"cancelled"}else if currently_delivered{"proceeded"}else{"blocked"},
                    "disposition":payload.get("disposition").cloned().unwrap_or(Value::Null),
                    "evaluation_digest":payload.get("evaluation_digest").cloned().unwrap_or(Value::Null),
                    "action_digest":payload.get("action_digest").cloned().unwrap_or(Value::Null),
                    "policy_trace":retry_trace,
                    "intervention_id":existing_intervention_id,
                    "canonical_intervention_path":existing_intervention_id.as_deref().map(|intervention_id|crate::interventions::canonical_route(&database_id,intervention_id)),
                    "idempotent_retry":true,
                }),
            );
            return echo_previous_seq(existing, None);
        }
        let correspondents = intended_recipients
            .iter()
            .map(|recipient| recipient.principal.clone())
            .collect::<Vec<_>>();
        let evaluation = crate::interventions::evaluate_in(
            &mut tx,
            &caller,
            sender_principal,
            &correspondents,
            plan.disclosure_preview.as_deref(),
        )
        .await?;
        delivered = evaluation.disposition != "block_and_request_authority";
        if !delivered {
            // The attempted destination is retained only in the policy and
            // intervention facts.  Sealing an empty initial audience ensures
            // intended recipients cannot read the undelivered draft.
            audience_recipients.clear();
            audience_accounts.clear();
        }
        if matches!(
            evaluation.disposition.as_str(),
            "notify_and_proceed" | "block_and_request_authority"
        ) {
            // An intervention names one target person, and a channel post has
            // none: the policy still compiles against the sender and the typed
            // send operation, and its disposition, action digest and full trace
            // are retained on message.send_evaluated.v1 either way. What differs
            // is the leg that needs a recipient. `notify_and_proceed` already
            // delivers, so only its awareness leg has no addressee and is
            // dropped. A blocking disposition must not deliver and has nobody
            // who could grant the authority it asks for, so the send is refused
            // atomically rather than committed as a draft no one can release.
            if channel_post {
                if evaluation.disposition == "block_and_request_authority" {
                    return Err(Error::engine(
                        "manage_messages.send: effective policy blocks this send for recipient authority, and a channel post addresses nobody who could grant it; address the recipients this Message needs, or bind a policy that admits unaddressed sends",
                    ));
                }
            } else {
                if intended_recipients.len() != 1 {
                    return Err(Error::engine(
                        "manage_messages.send: this first slice requires exactly one recipient when policy raises an intervention",
                    ));
                }
                if evaluation.disposition == "block_and_request_authority"
                    && plan
                        .disclosure_preview
                        .as_deref()
                        .is_none_or(|preview| preview.trim().is_empty())
                {
                    return Err(Error::engine(
                        "manage_messages.send: blocking authority requests require a disclosure-safe preview",
                    ));
                }
                intervention_id = Some(Uuid::new_v4().to_string());
            }
        }
        send_evaluation = Some((plan.clone(), sender_principal.clone(), evaluation));
    }
    let artifact_attestation = super::artifacts::validate_prospective_artifact(
        &id,
        &record_type,
        Some(&record_kind),
        fields.get("body").and_then(Value::as_str),
        runtime.as_deref(),
    )
    .await?;
    let source = fields
        .get("body")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(plan) = artifact_plan.as_ref() {
        let mut origin = json!({
                "kind": "artifact.interaction",
                "artifact_id": plan.artifact_id,
                "entry_id": plan.entry_id,
                "source_digest": plan.source_digest,
                "source_event_id": plan.source_event_id,
                "idempotency_key": plan.idempotency_key,
                "intent_digest": plan.intent_digest,
                "invocation_digest": plan.invocation_digest,
                "gesture": plan.gesture,
        });
        if let Some(evidence) = plan.gesture_evidence.clone() {
            origin["gesture_evidence"] = evidence;
        }
        fields.insert("origin".into(), origin);
    }
    // Comment origin: effect-tagged for the post-gate replay lookup, with
    // the command digest plus the bearer and position needed to settle a
    // replay receipt without re-reading. Legacy origins omit `effect`.
    if let Some(plan) = comment_plan.as_ref() {
        let command_digest = comment_command_digest
            .as_deref()
            .expect("comment gates compute the command digest before appends");
        let mut origin = json!({
                "kind": "artifact.interaction",
                "effect": "comment.create",
                "artifact_id": plan.artifact_id,
                "entry_id": plan.entry_id,
                "source_digest": plan.source_digest,
                "source_event_id": plan.source_event_id,
                "idempotency_key": plan.idempotency_key,
                "command_digest": command_digest,
                "target_id": plan.target_id,
                "position": plan.position,
                "gesture": plan.gesture,
                "guard": {
                    "package": plan.guard.package,
                    "expected_install_event_id": plan.guard.expected_install_event_id,
                    "artifact_id": plan.guard.artifact_id,
                    "source_revision": plan.guard.source_revision,
                    "version": plan.guard.version,
                    "digest": plan.guard.digest,
                    "declaration_digest": plan.guard.declaration_digest,
                },
        });
        if let Some(evidence) = plan.gesture_evidence.clone() {
            origin["gesture_evidence"] = evidence;
        }
        fields.insert("origin".into(), origin);
    }
    // Deterministic alias warnings are a pure function of the admitted
    // request (facet keys plus the admitted type and canonical kind), so the
    // first call and every replay compute the same value. Compute before the
    // replay branches so compact and historical
    // receipts carry them exactly as the fresh receipt does; pushing an empty
    // set is a no-op, so non-alias receipts stay byte-identical.
    let alias_warnings = crate::domain_transaction::governed_alias_warnings_for_sets(
        &facets,
        &record_type,
        Some(&record_kind),
    );
    // Idempotent replay, after every authorization and validation check and
    // inside the same BEGIN IMMEDIATE transaction as the mutation — the same
    // ordering contract `manage_relationships` keeps so the tool cannot become
    // a command-existence oracle. A reused key with different normalized input
    // never reaches here: the lookup itself errors.
    //
    // Replays always use pinned content. Returning a live digest would let
    // a guarded write silently clobber an edit the retrying caller never saw.
    // Summary reconstruction has a command-specific dependency closure;
    // verbose/unsupported requests rebuild a bounded historical projection.
    if idempotent_create {
        if let Some(attestation_id) = crate::provenance::lookup_authorized_command_attestation_in(
            &mut tx,
            caller.credential(),
            "create_record",
            &provenance_arguments,
            caller.intent(),
        )
        .await?
        {
            let attested = attested_create_horizons_in(&mut tx, &attestation_id).await?;
            // Non-disclosure for the output: the receipt discloses the created
            // record, so the replaying caller must still view it. A caller
            // that lost access gets the opaque denial, not the receipt.
            require_record_in(
                &mut tx,
                &caller,
                TOOL,
                &attested.record_id,
                Capability::View,
            )
            .await?;
            // Compact receipts have no enrichment dependencies. Reconstruct
            // their pinned fields while the live authorization snapshot is held.
            let compact = if response_mode == ResponseMode::Summary {
                tokio::time::timeout(
                    ATTESTED_REBUILD_EXECUTION,
                    compact_attested_create_in(
                        &mut tx,
                        &caller,
                        &attested,
                        html_body_write.clone(),
                    ),
                )
                .await
                .map_err(|_| Error::engine("create_record: compact replay deadline exceeded"))??
            } else {
                None
            };
            // Historical reconstruction does not hold the writer transaction.
            tx.rollback().await?;
            crate::provenance::note_replayed_action_attestation(attestation_id);
            let mut receipt = match compact {
                Some(receipt) => receipt,
                None => {
                    read_attested_create_receipt(&db, &caller, &attested, html_body_write).await?
                }
            };
            attach_basis_feedback(
                &db,
                &caller,
                &mut receipt,
                source_inputs.as_ref().map(Vec::len),
                true,
            )
            .await;
            crate::domain_transaction::push_receipt_warnings(&mut receipt, alias_warnings.clone())?;
            return response_mode
                .render(
                    &db,
                    echo_act(receipt, attested.act)?,
                    attested.content_horizon,
                )
                .await;
        }
    }
    // The basis rides beside `reason` on the record.created event ALONE, for
    // the same reason `reason` does: it is one authoring act, and copying it
    // onto the facet and link events this call also emits would multiply one
    // declaration into several. Validated here, in the same transaction that
    // appends the event, so existence, liveness, View and the revision check
    // all observe one snapshot.
    if let Some(basis) =
        resolve_source_basis_in(&mut tx, &caller, TOOL, source_inputs.as_deref()).await?
    {
        fields.insert("basis".into(), basis);
    }
    let source_event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "record.created".into(),
            payload: Value::Object(fields),
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    for facet in &facets {
        append_in(
            &db,
            &mut tx,
            facet_set_spec(&id, facet, caller.actor()),
            &mut act_alloc,
        )
        .await?;
    }
    if let Some(compiler_attestation) = artifact_attestation {
        let source = source.as_deref().expect("validated v2 artifact has a body");
        let attestation_event_id = Uuid::new_v4().to_string();
        let payload = super::artifacts::artifact_source_attestation_payload(
            &id,
            &attestation_event_id,
            &source_event.id,
            source,
            compiler_attestation,
        )?;
        append_with_event_id_in(
            &db,
            &mut tx,
            attestation_event_id,
            AppendSpec {
                record_id: id.clone(),
                event_type: "artifact.source_attested".into(),
                payload: serde_json::to_value(payload)?,
                actor: Some(caller.actor().into()),
            },
            &mut act_alloc,
        )
        .await?;
    }
    // One action identity per command. When the ordinary key is present the
    // create's own attestation covers every content and relationship output —
    // the relationship admission binds to this same identity — so a second
    // attestation must never be reserved beside it: the local-authority unique
    // index would reject the duplicate (principal, operation, digest) row.
    let action_draft = if idempotent_create || !relationship_link_indexes.is_empty() {
        Some(crate::provenance::reserve_action_attestation()?)
    } else {
        None
    };
    let relationship_draft: Option<&crate::provenance::ActionAttestationDraft> = action_draft
        .as_ref()
        .filter(|_| !relationship_link_indexes.is_empty());
    let mut specs = Vec::new();
    for (index, link) in args.links.iter().flatten().enumerate() {
        if relationship_link_indexes.contains(&index) {
            crate::relationship::legacy::mutate_from_create_record_in(
                &mut tx,
                &caller,
                &id,
                &link.target_id,
                &link.relationship,
                link.note.clone(),
                relationship_draft
                    .as_ref()
                    .expect("relationship links reserve one action identity"),
                &mut act_alloc,
            )
            .await?;
        } else {
            specs.push(AppendSpec {
                record_id: id.clone(),
                event_type: "link.added".into(),
                payload: serde_json::to_value(crate::events::LinkAddedPayload {
                    id: None,
                    source_id: id.clone(),
                    target_id: link.target_id.clone(),
                    relationship: link.relationship.clone(),
                    note: link.note.clone(),
                })?,
                actor: Some(caller.actor().into()),
            });
        }
    }
    if let Some((sender_id, sender_principal)) = message_sender {
        specs.push(AppendSpec {
            record_id: id.clone(),
            event_type: "message.audience.declared".into(),
            payload: serde_json::to_value(crate::events::MessageAudienceDeclaredPayload {
                sender_id,
                sender_principal,
                addressed_to: audience_recipients,
            })?,
            actor: Some(caller.actor().into()),
        });
    }
    if let Some((origin, _)) = &resolved_origin {
        specs.push(AppendSpec {
            record_id: id.clone(),
            event_type: "message.origin.declared.v1".into(),
            payload: serde_json::to_value(origin)?,
            actor: Some(caller.actor().into()),
        });
    }
    if let Some((plan, sender_principal, evaluation)) = &send_evaluation {
        let recipients = intended_recipients
            .iter()
            .map(|recipient| crate::events::ResolvedMessageRecipient {
                recipient_id: recipient.recipient_id.clone(),
                principal: recipient.principal.clone(),
            })
            .collect::<Vec<_>>();
        specs.push(AppendSpec {
            record_id: id.clone(),
            event_type: "message.send_evaluated.v1".into(),
            payload: serde_json::to_value(crate::events::MessageSendEvaluatedPayload {
                format: "native.message-send-evaluation.v1".into(),
                idempotency_key: plan.idempotency_key.clone(),
                sender_principal_id: sender_principal.clone(),
                intent_digest: plan.intent_digest.clone(),
                action: evaluation.action.clone(),
                action_digest: evaluation.action_digest.clone(),
                disposition: evaluation.disposition.clone(),
                delivered,
                intended_recipients: recipients.clone(),
                disclosure_preview: plan.disclosure_preview.clone(),
                policy_trace: evaluation.trace.clone(),
                evaluation_digest: evaluation.evaluation_digest.clone(),
            })?,
            actor: Some(caller.actor().into()),
        });
        if let Some(intervention_id) = &intervention_id {
            let blocking = evaluation.disposition == "block_and_request_authority";
            specs.push(AppendSpec {
                record_id: id.clone(),
                event_type: "intervention.raised.v1".into(),
                payload: serde_json::to_value(crate::events::InterventionRaisedPayload {
                    format: "native.intervention.raised.v1".into(),
                    intervention_id: intervention_id.clone(),
                    idempotency_key: format!("{}:raise", plan.idempotency_key),
                    target_person_record_id: intended_recipients[0].recipient_id.clone(),
                    target_principal_id: intended_recipients[0].principal.clone(),
                    sender_principal_id: sender_principal.clone(),
                    disposition: evaluation.disposition.clone(),
                    requested_outcome: if blocking { "authority" } else { "awareness" }.into(),
                    request: if blocking {
                        crate::interventions::intervention_request(
                            &evaluation.action_digest,
                            &intended_recipients
                                .iter()
                                .map(|recipient| recipient.recipient_id.clone())
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        Value::Null
                    },
                    disclosure_preview: plan.disclosure_preview.clone(),
                    reason: if blocking {
                        "Effective principal policy requires authority before delivery"
                    } else {
                        "Effective principal policy requires the principal to be notified"
                    }
                    .into(),
                    context_refs: vec![],
                    action: evaluation.action.clone(),
                    action_digest: evaluation.action_digest.clone(),
                    policy_trace: evaluation.trace.clone(),
                    evaluation_digest: evaluation.evaluation_digest.clone(),
                    intended_recipients: recipients,
                })?,
                actor: Some(caller.actor().into()),
            });
        }
    }
    if let Some(target) = captured_target {
        specs.push(AppendSpec {
            record_id: id.clone(),
            event_type: "annotation.target.set".into(),
            payload: serde_json::to_value(target)?,
            actor: Some(caller.actor().into()),
        });
    }
    for spec in specs {
        append_in(&db, &mut tx, spec, &mut act_alloc).await?;
    }
    if record_type == "Message" {
        audience_accounts.sort();
        audience_accounts.dedup();
        // Origin chooses the default visibility boundary; addressing does not.
        // Collection contributions inherit the Collection even when they put
        // an obligation on a person. Direct contributions receive an exact
        // participant policy. A blocked send and a sender-only draft remain
        // sealed from everyone except the independent owner floor.
        let explicit_policy_accounts = match &resolved_origin {
            Some((crate::events::MessageOriginDeclaredPayload::Collection { .. }, _))
                if delivered =>
            {
                None
            }
            Some((crate::events::MessageOriginDeclaredPayload::Direct { .. }, accounts))
                if delivered =>
            {
                Some(accounts.clone())
            }
            Some(_) => Some(Vec::new()),
            None => Some(audience_accounts.clone()),
        };
        if let Some(policy_accounts) = explicit_policy_accounts {
            crate::authorization::replace_explicit_policy_on(
                &mut tx,
                caller.actor(),
                &id,
                policy_accounts
                    .iter()
                    .cloned()
                    .map(|account| AllowEntry::account(account, Capability::View))
                    .collect(),
                &mut act_alloc,
            )
            .await?;
        }
        // Awareness stays audience-derived. A channel post has no addressed
        // account, and `routine_arrival` is reserved for recipient_policy
        // provenance the engine cannot author, so its defined outcome is no
        // obligation candidate at all; an @-mention is the one thing that still
        // proposes one, and mentions must be addressed, which makes such a
        // Message an addressed send rather than a channel post.
        if delivered {
            crate::awareness::apply_delivered_message_awareness_in(
                &mut tx,
                &id,
                &audience_accounts,
                "record.created",
                &source_event.id,
                &mut act_alloc,
            )
            .await?;
        }
        // Sending in a Collection context puts that context on the sender's
        // rail. Filing is deliberately irrelevant: a direct Message filed in
        // Unfiled must not create an Unfiled channel destination, and refiling
        // a Collection contribution must not rewrite where it was said.
        //
        // Reading a Collection, listing its contents, or opening a Message
        // inside it never reaches this path, which is exactly what keeps
        // browsing from joining. A withheld send does not either: `delivered`
        // is false when policy blocked it, and a draft nobody can read should
        // not reshape the sender's rail.
        if delivered && send_plan.is_some() {
            if let Some((
                crate::events::MessageOriginDeclaredPayload::Collection { collection_id },
                _,
            )) = &resolved_origin
            {
                crate::awareness::auto_join_destination_on_send_in(
                    &mut tx,
                    caller.credential(),
                    caller.actor(),
                    collection_id,
                    &source_event.id,
                    &mut act_alloc,
                )
                .await?;
            }
        }
    }
    let after = required_violations_in(&mut tx, &schema_rows, &[&id]).await?;
    assert_required_not_worsened(TOOL, &before, &after)?;
    if let Some(draft) = action_draft {
        crate::provenance::issue_reserved_pending_action_in(&mut tx, draft).await?;
    }
    // Alias shadows warn on success: exact governed names never reach here.
    // `alias_warnings` was computed from the admitted kind before the replay
    // branches so replays carry the identical value; reuse it here rather
    // than recomputing. Independent of any existing relationship so
    // redundancy still warns.
    let compact_result = if response_mode == ResponseMode::Summary {
        Some(compact_record_source_in(&mut tx, &caller, TOOL, &id).await?)
    } else {
        None
    };
    // Pin the continuation token to this exact transactional result.
    let version_seq = current_record_version_in(&mut tx, &id).await?;
    db.commit_content(tx).await?;
    // Canonical comment receipt: ids and thread position only, before any
    // enrichment, version sequence, act, refresh, advisory, or render-mode
    // branching below. Ordinary callers never reach here — the comment plan
    // that produces this shape is unreachable to them.
    if let Some(plan) = comment_plan.as_ref() {
        return Ok(comment_receipt_value(
            &id,
            &plan.target_id,
            &plan.position,
            false,
        ));
    }

    let mut result = match compact_result {
        Some(result) => result,
        None => enriched_or_error(&db, &caller, TOOL, &id).await?,
    };
    if let Some((_, _, evaluation)) = send_evaluation {
        let database_id = sqlx::query_scalar::<_, String>(
            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
        )
        .fetch_one(db.write_pool())
        .await?;
        let trace =
            crate::interventions::redact_trace_for_caller(&db, &caller, &evaluation.trace).await?;
        result.as_object_mut().expect("enriched record object").insert(
            "delivery".into(),
            json!({
                "status":if delivered{"delivered"}else{"blocked"},
                "delivered":delivered,
                "disposition":evaluation.disposition,
                "policy_trace":trace,
                "evaluation_digest":evaluation.evaluation_digest,
                "action_digest":evaluation.action_digest,
                "intervention_id":intervention_id,
                "canonical_intervention_path":intervention_id.as_deref().map(|intervention_id|crate::interventions::canonical_route(&database_id,intervention_id)),
                "idempotent_retry":false,
            }),
        );
    }
    // Creation is the same case as the update success response: a caller that
    // has just written a body should not need a second read to obtain the token
    // for its next guarded write. Carrying it here also keeps the three
    // substrates uniform — Postgres and Turso mint it from their shared read
    // shape — so the corpus can pin it on creation instead of looking away.
    let mut receipt = finish_create_receipt(result, html_body_write)?;
    // The act this write allocated, on the fresh-create path only: every
    // idempotent replay returns above through its own receipt without
    // reaching here, so replays keep byte-identical receipts with no act.
    receipt = echo_act(receipt, act_alloc.get())?;
    // The exact-source identity this create minted, when it minted one: a
    // body-bearing `record.created` is the artifact source event a later
    // `manage_artifact_module_grants.grant` must name as `subject_event_id`.
    // A body-less create mints no source event and leaves the field absent.
    annotate_source_event_id(
        &mut receipt,
        source.is_some().then_some(source_event.id.as_str()),
    );
    attach_basis_feedback(
        &db,
        &caller,
        &mut receipt,
        source_inputs.as_ref().map(Vec::len),
        idempotent_create,
    )
    .await;
    crate::domain_transaction::push_receipt_warnings(&mut receipt, alias_warnings)?;
    // A non-replayed advisory naming active claims in the new record's
    // neighbourhood, attached AFTER the receipt is assembled and only on this
    // fresh-create path: every idempotent replay returns above through its own
    // `finish_create_receipt` (or pinned reconstruction) without reaching
    // here, so putting the window inside the receipt would break the replay
    // identity guarantee the idempotency tests pin. The key is omitted
    // entirely when there is no overlap — or the record is not a WorkItem
    // carrying a `part_of` link — so every other create response stays
    // byte-identical to before this notice existed. The new record itself is
    // unclaimed, so the anchor needs no self-exclusion.
    if record_type == "WorkItem"
        && args
            .links
            .iter()
            .flatten()
            .any(|link| link.relationship == "part_of")
    {
        if let Some(overlap) =
            super::work::work_overlap_for_record(&db, &caller, &id, false).await?
        {
            receipt
                .as_object_mut()
                .expect("create_record receipt is an object")
                .insert("work_overlap".into(), overlap);
        }
    }
    // The similar-records advisory is advisory in the strictest sense. It runs
    // after the write has committed, on the SQLite product path only, over a
    // bounded set of indexed queries (typically 1-2 ms at workspace sizes),
    // and every error is swallowed by `notice_for_create`. There is no
    // enforced deadline: bounded work is not bounded latency, and pool
    // contention or a cold FTS index can still stretch the receipt, but the
    // lookup cannot fail the write. The key is omitted entirely when nothing
    // is similar, so its presence is itself the signal. The exclusion set
    // carries a `create_many` batch's own reserved ids, so batch siblings
    // never point at one another; `None` suppresses the notice entirely (the
    // delivered-Message send path).
    //
    // Suppressed for keyed creates. A keyed create is replayable and the
    // idempotency contract requires the replay to return a byte-identical
    // receipt; both replay branches above return before this point. The notice
    // is computed from the live workspace, so it cannot be reproduced from the
    // pinned event prefix a replay reconstructs from — and persisting it would
    // mean either computing it before the write commits (where a failure could
    // fail the write) or appending advisory data to the immutable log. It is
    // therefore outside the replayed identity: keyed creates carry no notice at
    // all, first call or replay. Keyless creates have no replay and keep it.
    let similar_notice = response.similar_notice.filter(|_| !idempotent_create);
    if let Some(similar_notice) = similar_notice {
        if let Some(similar) =
            super::similar::notice_for_create(&db, &caller, &id, similar_notice).await
        {
            if let Some(object) = receipt.as_object_mut() {
                object.insert("similar_existing".into(), similar);
            }
        }
    }
    // The post-commit advisor hook (S1). Same placement contract as the
    // notices above: this point is reachable only on the fresh-create path —
    // every idempotent replay returns through its own receipt above — and
    // keyed creates skip it for the same reason they carry no
    // `similar_existing`: a replay reconstructs from a pinned event prefix
    // that cannot reproduce advisory output, so advisories stay outside the
    // replayed identity. Fail-silent: the hook never errors.
    if !idempotent_create {
        if let Some(advisories) = crate::mcp::advisors::advisories_for_write(
            &db,
            TOOL,
            &id,
            &record_type,
            &args.kind,
            true,
            caller.run_key().map(str::to_owned),
            Some(0),
            Some(source_event.local_seq),
            true,
        )
        .await
        {
            if let Some(object) = receipt.as_object_mut() {
                object.insert("advisories".into(), Value::Array(advisories));
            }
        }
    }
    response_mode.render(&db, receipt, version_seq).await
}

/// The attested command's pinned position in both event logs: the highest
/// content and relationship sequence numbers its action attestation covers.
/// Both logs are append-only, so rows at or below a committed horizon are
/// immutable — replaying exactly those prefixes reproduces the receipt the
/// first call returned, regardless of later writes.
struct AttestedCreate {
    attestation_id: String,
    record_id: String,
    content_horizon: i64,
    relationship_horizon: Option<i64>,
    /// The act the original create allocated. A keyed replay returns it so the
    /// replay receipt is indistinguishable from the first call; only a true
    /// no-op omits `act`.
    act: Option<i64>,
}

/// Summary's dependency closure is exactly the pinned spine fields plus live
/// schema/vocabulary interpretation. Never use this for verbose enrichment.
/// Only ordinary types and known non-spine-mutating outputs are supported;
/// unknown output semantics require the full historical projection.
async fn compact_attested_create_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    attested: &AttestedCreate,
    html_body_write: Option<Value>,
) -> Result<Option<Value>> {
    let sizes: Vec<i64> = sqlx::query_scalar(
        "SELECT 512 + 6 * (COALESCE(length(CAST(id AS BLOB)),0) + COALESCE(length(CAST(type AS BLOB)),0) + COALESCE(length(CAST(payload AS BLOB)),0)) FROM content_events
         WHERE record_id=? AND seq<=? ORDER BY seq LIMIT 257",
    )
    .bind(&attested.record_id)
    .bind(attested.content_horizon)
    .fetch_all(&mut **tx)
    .await?;
    if sizes.len() > 256
        || sizes.iter().sum::<i64>() > ATTESTED_REBUILD_MAX_BYTES
        || sizes
            .iter()
            .any(|size| *size > ATTESTED_REBUILD_MAX_EVENT_BYTES)
    {
        return Ok(None);
    }
    let mut budget = AttestedReplayBudget::new();
    budget.charge(&sizes)?;
    charge_live_interpretation_in(tx, &mut budget).await?;
    let rows = sqlx::query(
        "SELECT e.id, e.type, e.payload,
                EXISTS(SELECT 1 FROM provenance_action_outputs o
                       WHERE o.action_attestation_id=? AND o.output_domain='content'
                         AND o.output_event_id=e.id) AS covered
           FROM content_events e WHERE e.record_id=? AND e.seq<=?
           ORDER BY e.seq LIMIT 257",
    )
    .bind(&attested.attestation_id)
    .bind(&attested.record_id)
    .bind(attested.content_horizon)
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() || rows.len() > 256 {
        return Ok(None);
    }
    let mut fields = None;
    let mut source_event = None;
    for row in rows {
        if !row.try_get::<bool, _>("covered")? {
            return Ok(None);
        }
        let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
        match row.try_get::<String, _>("type")?.as_str() {
            "record.created" if fields.is_none() => {
                if !matches!(
                    payload["type"].as_str(),
                    Some("Document" | "WorkItem" | "Entity" | "Collection")
                ) {
                    return Ok(None);
                }
                if payload["body"].is_string() {
                    source_event = Some(row.try_get::<String, _>("id")?);
                }
                fields = Some(payload);
            }
            "facet.set" if fields.is_some() => {
                let key = payload["key"].as_str().unwrap_or_default();
                // Spine facets project into records, rather than facet_values.
                if let Some(column) = spine_facet_column(key) {
                    fields.as_mut().unwrap()[column] = payload["value"].clone();
                }
            }
            "link.added" | "artifact.source_attested" if fields.is_some() => {}
            _ => return Ok(None),
        }
    }
    let Some(mut fields) = fields else {
        return Ok(None);
    };
    fields["id"] = json!(attested.record_id);
    // Same defaults as the record.created projector.
    if fields["name"].is_null() {
        fields["name"] = json!("");
    }
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let schema = cascade::schema_config_rows_for_principal_on(tx, principal).await?;
    let interpreter =
        crate::query::lifecycle::LifecycleInterpreter::load_from_connection(tx, schema).await?;
    fields["lifecycle_interpretation"] = serde_json::to_value(
        interpreter.interpret(
            fields["type"]
                .as_str()
                .ok_or_else(|| Error::engine("create_record: incomplete pinned type"))?,
            fields["kind"].as_str(),
            fields["home_id"].as_str(),
            fields["lifecycle"].as_str(),
        ),
    )?;
    // Ensure all summary-required nullable fields are explicit.
    if fields.get("kind").is_none() {
        fields["kind"] = Value::Null;
    }
    let mut receipt = finish_create_receipt(fields, html_body_write)?;
    annotate_source_event_id(&mut receipt, source_event.as_deref());
    Ok(Some(receipt))
}

/// Shared receipt assembly for every create response shape: the previous-seq
/// echo (always null on creation), the governed-HTML receipt when the body
/// validated as HTML, and the whole-body CAS token. Identical on the first
/// call and both pinned reconstruction paths by construction.
fn finish_create_receipt(result: Value, html_body_write: Option<Value>) -> Result<Value> {
    let mut created = attach_html_body_write(echo_previous_seq(result, None)?, html_body_write)?;
    annotate_body_digest(&mut created);
    Ok(created)
}

/// Bound on concurrent pinned reconstructions. Each rebuild holds a full
/// bounded prefix fold in a scratch database. Compact ordinary replay never
/// touches this. Acquired after rollback, with bounded admission, so waiting
/// serializes only historical rebuilds, never writers.
/// Admission, setup, fold, enrichment and graceful close share the existing
/// 10-second execution envelope: queueing consumes time available to rebuild.
/// Physical cleanup may outlive cancellation, retaining capacity until drained.
/// This bounds the historical stage, not the entire tool or cleanup latency.
const ATTESTED_REBUILD_EXECUTION: std::time::Duration = std::time::Duration::from_secs(10);
const ATTESTED_REBUILD_MAX_EVENTS: usize = 10_000;
const ATTESTED_REBUILD_MAX_BYTES: i64 = 16 * 1024 * 1024;
const ATTESTED_REBUILD_MAX_EVENT_BYTES: i64 = 1024 * 1024;

/// One request budget, consumed cumulatively across content, relationships,
/// immutable provenance, binding seeds and live interpretation metadata.
/// Encoded string size is bounded conservatively by 6x raw UTF-8 bytes (the
/// worst JSON escape expansion), plus row overhead, before payload decoding.
struct AttestedReplayBudget {
    rows: usize,
    bytes: i64,
}
impl AttestedReplayBudget {
    fn new() -> Self {
        Self {
            rows: ATTESTED_REBUILD_MAX_EVENTS,
            bytes: ATTESTED_REBUILD_MAX_BYTES,
        }
    }
    fn charge(&mut self, sizes: &[i64]) -> Result<()> {
        let bytes = sizes.iter().sum::<i64>();
        if sizes.len() > self.rows
            || bytes > self.bytes
            || sizes
                .iter()
                .any(|size| *size > ATTESTED_REBUILD_MAX_EVENT_BYTES)
        {
            return Err(Error::engine(
                "create_record: historical replay budget exceeded",
            ));
        }
        self.rows -= sizes.len();
        self.bytes -= bytes;
        Ok(())
    }
}

async fn charge_live_interpretation_in(
    tx: &mut Transaction<'static, Sqlite>,
    budget: &mut AttestedReplayBudget,
) -> Result<()> {
    // The caller holds BEGIN IMMEDIATE during enrichment, so these metadata
    // sizes and the lens's later pool reads describe one stable live state.
    let sizes: Vec<i64> = sqlx::query_scalar(
        "SELECT 512 + 6*(length(CAST(id AS BLOB))+length(CAST(name AS BLOB))) FROM vocabularies
         UNION ALL SELECT 512 + 6*(length(CAST(id AS BLOB))+length(CAST(vocabulary_id AS BLOB))+
            length(CAST(value AS BLOB))+length(CAST(status AS BLOB))+length(CAST(terminality AS BLOB))+
            COALESCE(length(CAST(alias_of AS BLOB)),0)+length(CAST(metadata AS BLOB))+
            COALESCE(length(CAST(gloss AS BLOB)),0)+length(CAST(ordinal AS BLOB))) FROM vocabulary_values
         UNION ALL SELECT 512 + 6*(length(CAST(id AS BLOB))+length(CAST(layer AS BLOB))+
            COALESCE(length(CAST(name AS BLOB)),0)+length(CAST(data AS BLOB))+
            COALESCE(length(CAST(applies_to_collection_id AS BLOB)),0)+
            COALESCE(length(CAST(version_lineage AS BLOB)),0)+length(CAST(created_at AS BLOB))) FROM schema_config
         LIMIT 10001",
    ).fetch_all(&mut **tx).await?;
    budget.charge(&sizes)
}

static ATTESTED_REBUILD_PERMITS: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

fn attested_rebuild_permits() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    ATTESTED_REBUILD_PERMITS.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(2)))
}

async fn admit_attested_rebuild(
    semaphore: &std::sync::Arc<tokio::sync::Semaphore>,
    deadline: tokio::time::Instant,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    // timeout_at can accept a ready future even after expiry. Fail closed at
    // the hard boundary, including when capacity becomes ready on a late poll.
    let exhausted = || Error::engine("create_record: historical replay admission exhausted");
    if tokio::time::Instant::now() >= deadline {
        return Err(exhausted());
    }
    let permit = tokio::time::timeout_at(deadline, semaphore.clone().acquire_owned())
        .await
        .map_err(|_| exhausted())?
        .map_err(|_| Error::engine("attested rebuild permits exhausted"))?;
    if tokio::time::Instant::now() >= deadline {
        return Err(exhausted());
    }
    Ok(permit)
}

async fn with_attested_rebuild_deadline<F, Fut>(
    permits: &std::sync::Arc<tokio::sync::Semaphore>,
    deadline: tokio::time::Instant,
    rebuild: F,
) -> Result<Value>
where
    F: FnOnce(tokio::sync::OwnedSemaphorePermit) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    let permit = admit_attested_rebuild(permits, deadline).await?;
    let result = tokio::time::timeout_at(deadline, rebuild(permit)).await;
    if tokio::time::Instant::now() >= deadline {
        return Err(Error::engine(
            "create_record: historical replay deadline exceeded",
        ));
    }
    result.unwrap_or_else(|_| {
        Err(Error::engine(
            "create_record: historical replay deadline exceeded",
        ))
    })
}

/// Resolve which record an ordinary keyed `create_record` first created and
/// the pinned horizons its attestation covers. Mirrors `reconstruct_retry_in`
/// in the relationships precedent.
async fn attested_create_horizons_in(
    tx: &mut Transaction<'static, Sqlite>,
    attestation_id: &str,
) -> Result<AttestedCreate> {
    let created: Option<String> = sqlx::query_scalar(
        "SELECT e.record_id FROM provenance_action_outputs o
           JOIN content_events e ON e.id=o.output_event_id
          WHERE o.action_attestation_id=? AND o.output_domain='content'
            AND e.type='record.created' ORDER BY o.ordinal LIMIT 1",
    )
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let fallback: Option<String> = if created.is_none() {
        sqlx::query_scalar(
            "SELECT e.record_id FROM provenance_action_outputs o
               JOIN content_events e ON e.id=o.output_event_id
              WHERE o.action_attestation_id=? AND o.output_domain='content'
              ORDER BY o.ordinal LIMIT 1",
        )
        .bind(attestation_id)
        .fetch_optional(&mut **tx)
        .await?
    } else {
        None
    };
    let record_id = created
        .or(fallback)
        .ok_or_else(|| Error::engine("create_record: idempotent receipt is incomplete"))?;
    let content_horizon: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(e.seq) FROM provenance_action_outputs o
           JOIN content_events e ON e.id=o.output_event_id
          WHERE o.action_attestation_id=? AND o.output_domain='content'",
    )
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    let content_horizon = content_horizon
        .ok_or_else(|| Error::engine("create_record: idempotent receipt is incomplete"))?;
    let relationship_horizon: Option<i64> = sqlx::query_scalar(
        // `relationship_events` is UNIQUE `(issuer_origin_db_id, id)`, not `id`
        // alone: a federated peer can ingest an event reusing a canonical UUID
        // a local keyed write already used. Joining on the id alone would let
        // the foreign row's seq win. Qualify by the attestation's issuer
        // origin, as every other relationship-event lookup in the tree does.
        "SELECT MAX(e.seq) FROM provenance_action_outputs o
           JOIN relationship_events e ON e.id=o.output_event_id
          WHERE o.action_attestation_id=? AND o.output_domain='relationship'
            AND e.issuer_origin_db_id=(
                SELECT issuer_origin_database_id FROM provenance_action_attestations WHERE id=?)",
    )
    .bind(attestation_id)
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    Ok(AttestedCreate {
        attestation_id: attestation_id.to_string(),
        record_id,
        content_horizon,
        relationship_horizon,
        act: super::attested_act_in(tx, attestation_id).await?,
    })
}

/// Rebuild the exact receipt the attested create returned, from its pinned
/// event prefixes replayed into a scratch projection — the same machinery
/// `get_record`'s `as_of` path uses, minus the temporal echo the create
/// receipt never carried. Content state is pinned; schema, vocabulary and
/// authorization stay live, which is the documented `as_of` semantic. The
/// single-read assembly (lens read, auth-split filter, previous_seq echo,
/// HTML receipt, body digest) mirrors the creation path exactly.
///
/// A rebuilt record that is no longer visible maps to the opaque denial,
/// never to a "not readable after write" diagnostic: from the caller's side
/// that outcome is indistinguishable from the record never having existed.
async fn read_attested_create_receipt(
    db: &Db,
    caller: &Caller,
    attested: &AttestedCreate,
    html_body_write: Option<Value>,
) -> Result<Value> {
    read_attested_create_receipt_with_limits(
        db,
        caller,
        attested,
        html_body_write,
        attested_rebuild_permits(),
        ATTESTED_REBUILD_EXECUTION,
    )
    .await
}

// Cancellation retires scratch admission synchronously, then holds the owned
// reconstruction permit until physical shutdown finishes. Only resource
// cleanup is detached; the projector future is dropped, never left running.
struct AttestedScratch {
    db: Db,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for AttestedScratch {
    fn drop(&mut self) {
        self.db.close_in_background();
        if let Some(permit) = self.permit.take() {
            let db = self.db.clone();
            tokio::spawn(async move {
                db.close().await;
                drop(permit);
            });
        }
    }
}

async fn open_attested_scratch(
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<AttestedScratch> {
    // Opening may already have created SQLite workers when the deadline fires.
    // The setup task owns the permit until it hands off a complete guard or
    // closes it after the receiver disappears. It never runs reconstruction.
    let (send, receive) = tokio::sync::oneshot::channel();
    #[cfg(test)]
    let failure = crate::db::READ_POOL_OPEN_FAILURE
        .try_with(Clone::clone)
        .ok();
    tokio::spawn(async move {
        #[cfg(test)]
        let opened = match failure {
            Some(failure) => {
                crate::db::READ_POOL_OPEN_FAILURE
                    .scope(failure, open_database(":memory:"))
                    .await
            }
            None => open_database(":memory:").await,
        };
        #[cfg(not(test))]
        let opened = open_database(":memory:").await;
        let result = opened.map(|db| AttestedScratch {
            db,
            permit: Some(permit),
        });
        let _ = send.send(result);
    });
    receive
        .await
        .map_err(|_| Error::engine("create_record: scratch setup failed"))?
}

async fn read_attested_create_receipt_with_limits(
    db: &Db,
    caller: &Caller,
    attested: &AttestedCreate,
    html_body_write: Option<Value>,
    permits: &std::sync::Arc<tokio::sync::Semaphore>,
    budget: std::time::Duration,
) -> Result<Value> {
    const TOOL: &str = "create_record";
    let deadline = tokio::time::Instant::now() + budget;
    // Admission, opening, schema, replay, enrichment AND close share a deadline.
    // On cancellation the guard retires scratch pools without an unbounded wait.
    with_attested_rebuild_deadline(permits, deadline, |permit| async {
        let guard = open_attested_scratch(permit).await?;
        let scratch = &guard.db;
        let mut budget = AttestedReplayBudget::new();
        apply_schema(scratch).await?;
        // A projector failure on an old prefix propagates as an engine
        // error rather than falling back to a live read: a live read would
        // return the CURRENT digest as if it were attested, which is exactly
        // the lost-update vector this reconstruction exists to close. Full
        // history replays through the current projector run in conformance,
        // so skew that breaks old prefixes fails there first.
        replay_bounded_attested_content(db, scratch, attested.content_horizon, &mut budget).await?;
        // The covered attestation's rows back both the admissions refresh
        // below and the contribution byline's event attestation.
        let mut seed = scratch.write_pool().begin().await?;
        seed_attested_provenance_rows(db, &mut seed, &attested.attestation_id, &mut budget).await?;
        seed.commit().await?;
        if let Some(horizon) = attested.relationship_horizon {
            replay_attested_relationship_prefix(
                db,
                scratch,
                &attested.attestation_id,
                horizon,
                &mut budget,
            )
            .await?;
        }
        let resolved = crate::query::lens::resolve_as_of(
            db,
            crate::query::lens::AsOfSelector::ContentSeq(crate::query::lens::ContentSeqSelector {
                content_seq: attested.content_horizon,
            }),
        )
        .await?;
        let mut live_snapshot = crate::db::begin_write(db.write_pool()).await?;
        charge_live_interpretation_in(&mut live_snapshot, &mut budget).await?;
        let lens = crate::query::lens::ReadLens::historical(scratch, db, &resolved);
        let record = if super::is_legacy_local(caller) {
            read::get_record_with_lens(&lens, &attested.record_id, read::EnrichOptions::default())
                .await?
        } else {
            read::get_record_with_lens_as(
                &lens,
                &attested.record_id,
                read::EnrichOptions::default(),
                super::principal(caller),
            )
            .await?
        };
        let mut record = match record {
            Some(record) => record,
            None => {
                return Err(Error::engine(format!(
                    "{TOOL}: record {} does not exist",
                    attested.record_id
                )));
            }
        };
        filter_enriched_record_with_auth(
            scratch,
            db,
            caller,
            &mut record,
            read::EnrichOptions::default(),
        )
        .await?;
        // The shared filter hydrates the contribution byline live, but the
        // attested receipt names the event that produced the body as of the
        // pinned horizon. Recompose the byline from pinned raw facts with
        // live disclosure, mirroring `contribution_for_record_in` exactly.
        record.contribution =
            attested_contribution_for_record(scratch, db, caller, &record.record.id).await?;
        let mut receipt = finish_create_receipt(serde_json::to_value(record)?, html_body_write)?;
        // The pinned horizon bounds the read: later writers may have moved the
        // live source since, but the attested receipt names its own event.
        let attested_source =
            latest_body_event_id(db, &attested.record_id, Some(attested.content_horizon)).await?;
        annotate_source_event_id(&mut receipt, attested_source.as_deref());
        live_snapshot.rollback().await?;
        scratch.close().await;
        Ok(receipt)
    })
    .await
}

#[cfg(test)]
struct AttestedReplayPause {
    reached: tokio::sync::Notify,
    scratch: std::sync::Mutex<Option<Db>>,
    projected: std::sync::atomic::AtomicUsize,
}
#[cfg(test)]
tokio::task_local! {
    static ATTESTED_REPLAY_PAUSE: std::sync::Arc<AttestedReplayPause>;
}

/// Read keyset pages with explicit row/byte budgets before decoding payloads.
/// Every fold awaits SQLite operations; dropping the timed future cancels the
/// remaining pages and rolls back its private transaction (no detached worker).
async fn replay_bounded_attested_content(
    db: &Db,
    scratch: &Db,
    horizon: i64,
    budget: &mut AttestedReplayBudget,
) -> Result<()> {
    // Reject a row-overflow prefix before spending its budget on a fold.
    // LIMIT bounds even this cardinality probe, including sparse seq logs.
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (SELECT seq FROM content_events WHERE seq<=? ORDER BY seq LIMIT ?)",
    )
    .bind(horizon)
    .bind(budget.rows as i64 + 1)
    .fetch_one(db.write_pool())
    .await?;
    if rows as usize > budget.rows {
        return Err(Error::engine(
            "create_record: historical replay budget exceeded",
        ));
    }
    let mut after = 0;
    loop {
        let sizes: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT seq,
                    512 + 6 * (COALESCE(length(CAST(id AS BLOB)),0) + COALESCE(length(CAST(record_id AS BLOB)),0) + COALESCE(length(CAST(type AS BLOB)),0) + COALESCE(length(CAST(payload AS BLOB)),0) + COALESCE(length(CAST(actor AS BLOB)),0) + COALESCE(length(CAST(run_key AS BLOB)),0) + COALESCE(length(CAST(parent_key AS BLOB)),0) + COALESCE(length(CAST(intent AS BLOB)),0) + COALESCE(length(CAST(created_at AS BLOB)),0) + COALESCE(length(CAST(causal_envelope_version AS BLOB)),0) + COALESCE(length(CAST(causal_status AS BLOB)),0) + COALESCE(length(CAST(act AS BLOB)),0)) +
                    (SELECT COALESCE(SUM(6*length(CAST(parent_event_id AS BLOB))+32),0)
                       FROM (SELECT parent_event_id FROM content_event_causal_frontier
                             WHERE event_id=content_events.id LIMIT 257)) +
                    CASE WHEN (SELECT COUNT(*) FROM (SELECT parent_event_id FROM content_event_causal_frontier
                             WHERE event_id=content_events.id LIMIT 257)) > 256 THEN 1048577 ELSE 0 END
               FROM content_events WHERE seq>? AND seq<=? ORDER BY seq LIMIT 128",
        )
        .bind(after)
        .bind(horizon)
        .fetch_all(db.write_pool())
        .await?;
        if sizes.is_empty() {
            break;
        }
        budget.charge(&sizes.iter().map(|(_, size)| *size).collect::<Vec<_>>())?;
        let end = sizes.last().unwrap().0;
        let rows = sqlx::query(
            "SELECT seq, id, record_id, type, payload, actor, run_key, parent_key, intent,
                    created_at, causal_envelope_version, causal_status, act,
                    (SELECT json_group_array(parent_event_id) FROM content_event_causal_frontier
                     WHERE event_id=content_events.id) AS causal_frontier
             FROM content_events WHERE seq>? AND seq<=? ORDER BY seq",
        )
        .bind(after)
        .bind(end)
        .fetch_all(db.write_pool())
        .await?;
        let events = rows
            .iter()
            .map(crate::query::events::event_from_row)
            .collect::<Result<Vec<_>>>()?;
        let mut tx = scratch.write_pool().begin().await?;
        for event in &events {
            crate::projector::replay_with_blob_placeholders(&mut tx, std::slice::from_ref(event))
                .await?;
            #[cfg(test)]
            if let Ok(pause) = ATTESTED_REPLAY_PAUSE.try_with(Clone::clone) {
                pause
                    .projected
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                *pause.scratch.lock().unwrap() = Some(scratch.clone());
                pause.reached.notify_one();
                std::future::pending::<()>().await;
            }
        }
        tx.commit().await?;
        after = end;
        tokio::task::yield_now().await;
    }
    Ok(())
}

/// Recompose one record's contribution byline for an attested receipt: the
/// raw facts (which event produced the body, which created the record, and
/// their attestations) come from the pinned scratch projection, while viewer
/// disclosure, alternative-set and selection context stay live — the same
/// tier split the historical lens applies everywhere else. This mirrors
/// `contribution_for_record_in` piece for piece; only the pools differ.
async fn attested_contribution_for_record(
    record_db: &Db,
    auth_db: &Db,
    caller: &Caller,
    record_id: &str,
) -> Result<Option<crate::contribution::ContributionProvenance>> {
    let mut record_tx = record_db.write_pool().begin().await?;
    let raw = crate::contribution::raw_contribution_in(&mut record_tx, record_id).await?;
    record_tx.rollback().await?;
    let Some(mut raw) = raw else {
        return Ok(None);
    };
    let mut auth_tx = auth_db.write_pool().begin().await?;
    let result = async {
        let disclosure =
            crate::contribution::viewer_disclosure_in(&mut auth_tx, caller, &raw).await?;
        // The client claim is a run-level fact the pinned scratch projection
        // does not carry; read it live, on the same rule as everything else
        // here, and only when the run is this viewer's to see.
        if disclosure.current_run_visible {
            if let Some(run_key) = raw.current.run_key.as_deref() {
                raw.reported_client =
                    crate::contribution::reported_client_for_run_in(&mut auth_tx, run_key).await?;
            }
        }
        let alternative_set =
            crate::contribution::alternative_set_context_in(&mut auth_tx, caller, record_id)
                .await?;
        let selection =
            crate::contribution::selection_context_in(&mut auth_tx, caller, record_id).await?;
        let context = crate::contribution::ContributionContext {
            mode: alternative_set.is_some().then(|| "option".to_string()),
            alternative_set,
            selection,
        };
        Ok(Some(crate::contribution::project(
            &raw,
            &disclosure,
            context,
        )))
    }
    .await;
    auth_tx.rollback().await?;
    result
}
/// Replay the relationship log prefix at or below `horizon` into the scratch
/// projection using the same fold live appends use, so relationship-owned
/// link rows in the rebuilt receipt match the original. Federated prefix
/// events resolve through receiver bindings, which need the database identity
/// and the referenced native-record bindings present; both are seeded from
/// live state, matching the `as_of` tier split (content pinned, the rest
/// live). Causality keeps the seeding sound: anything the prefix resolves
/// committed before the prefix did. The one edge this does not close is a
/// native-record binding whose canonical mapping changed after the horizon:
/// receiver resolution would then follow the live mapping rather than the
/// attested one. That tier-split limitation is shared with every historical
/// read and only affects federated prefixes, which keyed local creates do
/// not produce.
///
/// The covered attestation's immutable provenance rows are seeded by the
/// caller before this runs (see `read_attested_create_receipt`): the
/// admissions refresh below verifies against them exactly as issuance did.
/// Validity rows are deliberately excluded: none existed when the attestation
/// was issued, so a later invalidation must not rewrite the attested receipt.
async fn replay_attested_relationship_prefix(
    db: &Db,
    scratch: &Db,
    attestation_id: &str,
    horizon: i64,
    budget: &mut AttestedReplayBudget,
) -> Result<()> {
    let sizes: Vec<i64> = sqlx::query_scalar(
        "SELECT 512 + 6 * (COALESCE(length(CAST(seq AS BLOB)),0) + COALESCE(length(CAST(id AS BLOB)),0) + COALESCE(length(CAST(stream_kind AS BLOB)),0) + COALESCE(length(CAST(stream_id AS BLOB)),0) + COALESCE(length(CAST(stream_version AS BLOB)),0) + COALESCE(length(CAST(relationship_origin_db_id AS BLOB)),0) + COALESCE(length(CAST(relationship_id AS BLOB)),0) + COALESCE(length(CAST(type AS BLOB)),0) + COALESCE(length(CAST(payload AS BLOB)),0) + COALESCE(length(CAST(actor AS BLOB)),0) + COALESCE(length(CAST(issuer_origin_db_id AS BLOB)),0) + COALESCE(length(CAST(occurred_at AS BLOB)),0) + COALESCE(length(CAST(ingested_at AS BLOB)),0) + COALESCE(length(CAST(act AS BLOB)),0))
         FROM relationship_events WHERE seq<=? ORDER BY seq LIMIT 10001",
    )
    .bind(horizon)
    .fetch_all(db.write_pool())
    .await?;
    budget.charge(&sizes)?;
    let mut conn = db.write_pool().acquire().await?;
    let events = crate::relationship::read_relationship_event_prefix(&mut conn, horizon).await?;
    drop(conn);
    if events.is_empty() {
        return Ok(());
    }
    let covered: Vec<String> = sqlx::query_scalar(
        "SELECT output_event_id FROM provenance_action_outputs
          WHERE action_attestation_id=? AND output_domain='relationship'
          ORDER BY ordinal",
    )
    .bind(attestation_id)
    .fetch_all(db.write_pool())
    .await?;
    let local_origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(db.write_pool())
            .await?;
    let federated = events
        .iter()
        .filter(|event| event.issuer_origin_db_id != local_origin)
        .map(|event| (event.issuer_origin_db_id.clone(), event.event_id.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let mut tx = scratch.write_pool().begin().await?;
    let identity_size: i64 = sqlx::query_scalar("SELECT 512+6*(length(CAST(origin_db_id AS BLOB))+length(CAST(created_at AS BLOB))) FROM database_identity WHERE singleton=1")
        .fetch_one(db.write_pool()).await?;
    budget.charge(&[identity_size])?;
    let identity =
        sqlx::query("SELECT origin_db_id, created_at FROM database_identity WHERE singleton=1")
            .fetch_one(db.write_pool())
            .await?;
    let origin: String = identity.try_get("origin_db_id")?;
    let identity_created_at: String = identity.try_get("created_at")?;
    sqlx::query(
        "INSERT INTO database_identity(singleton, origin_db_id, created_at)
         VALUES(1, ?, ?)",
    )
    .bind(&origin)
    .bind(&identity_created_at)
    .execute(&mut *tx)
    .await?;
    if !federated.is_empty() {
        let mut binding_snapshot = db.write_pool().begin().await?;
        let sizes: Vec<i64> = sqlx::query_scalar(
            "SELECT 512 + 6 * (COALESCE(length(CAST(record_id AS BLOB)),0) + COALESCE(length(CAST(system AS BLOB)),0) + COALESCE(length(CAST(identifier AS BLOB)),0) + COALESCE(length(CAST(is_canonical AS BLOB)),0) + COALESCE(length(CAST(url AS BLOB)),0) + COALESCE(length(CAST(etag AS BLOB)),0) + COALESCE(length(CAST(last_seen_at AS BLOB)),0))
             FROM bindings WHERE system='native-record' LIMIT 10001",
        ).fetch_all(&mut *binding_snapshot).await?;
        budget.charge(&sizes)?;
        let bindings = sqlx::query(
            "SELECT record_id, system, identifier, is_canonical, url, etag, last_seen_at
               FROM bindings WHERE system='native-record'",
        )
        .fetch_all(&mut *binding_snapshot)
        .await?;
        for binding in bindings {
            let record_id: String = binding.try_get("record_id")?;
            let mirrored: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=?)")
                    .bind(&record_id)
                    .fetch_one(&mut *tx)
                    .await?;
            if !mirrored {
                continue;
            }
            sqlx::query(
                "INSERT INTO bindings(record_id, system, identifier, is_canonical, url, etag, last_seen_at)
                 VALUES(?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&record_id)
            .bind(binding.try_get::<String, _>("system")?)
            .bind(binding.try_get::<String, _>("identifier")?)
            .bind(binding.try_get::<i64, _>("is_canonical")?)
            .bind(binding.try_get::<Option<String>, _>("url")?)
            .bind(binding.try_get::<Option<String>, _>("etag")?)
            .bind(binding.try_get::<Option<String>, _>("last_seen_at")?)
            .execute(&mut *tx)
            .await?;
        }
    }
    crate::relationship::replay_relationship_events(&mut tx, &events, &federated).await?;
    let outputs = covered
        .iter()
        .map(crate::provenance::ActionOutput::relationship)
        .collect::<Vec<_>>();
    crate::relationship::project_receiver_local_admissions_for_outputs_in(&mut tx, &outputs)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Copy the covered attestation's immutable provenance rows into the scratch
/// projection so the admissions refresh verifies exactly as it did at
/// issuance. Interaction receipts are immutable once issued, so the live row
/// is the creation-time row.
async fn seed_attested_provenance_rows(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    attestation_id: &str,
    budget: &mut AttestedReplayBudget,
) -> Result<()> {
    let sizes: Vec<i64> = sqlx::query_scalar(
        "SELECT 512 + 6 * (COALESCE(length(CAST(id AS BLOB)),0) + COALESCE(length(CAST(schema_version AS BLOB)),0) + COALESCE(length(CAST(principal AS BLOB)),0) + COALESCE(length(CAST(executor_kind AS BLOB)),0) + COALESCE(length(CAST(channel AS BLOB)),0) + COALESCE(length(CAST(executor_ref AS BLOB)),0) + COALESCE(length(CAST(delegation_ref AS BLOB)),0) + COALESCE(length(CAST(interaction_receipt_id AS BLOB)),0) + COALESCE(length(CAST(operation AS BLOB)),0) + COALESCE(length(CAST(action_commitment AS BLOB)),0) + COALESCE(length(CAST(action_digest AS BLOB)),0) + COALESCE(length(CAST(output_event_set_digest AS BLOB)),0) + COALESCE(length(CAST(issuer AS BLOB)),0) + COALESCE(length(CAST(issuer_origin_database_id AS BLOB)),0) + COALESCE(length(CAST(issued_at AS BLOB)),0) + COALESCE(length(CAST(command_identity_digest AS BLOB)),0) + COALESCE(length(CAST(intent_digest AS BLOB)),0))
         FROM provenance_action_attestations WHERE id=?
         UNION ALL SELECT 512 + 6 * (COALESCE(length(CAST(attestation_id AS BLOB)),0) + COALESCE(length(CAST(issuer_origin_database_id AS BLOB)),0) + COALESCE(length(CAST(principal AS BLOB)),0) + COALESCE(length(CAST(operation AS BLOB)),0) + COALESCE(length(CAST(command_identity_digest AS BLOB)),0) + COALESCE(length(CAST(anchored_at AS BLOB)),0))
         FROM provenance_local_attestation_authority WHERE attestation_id=?
         UNION ALL SELECT 512 + 6 * (COALESCE(length(CAST(id AS BLOB)),0) + COALESCE(length(CAST(schema_version AS BLOB)),0) + COALESCE(length(CAST(principal AS BLOB)),0) + COALESCE(length(CAST(scope_digest AS BLOB)),0) + COALESCE(length(CAST(nonce AS BLOB)),0) + COALESCE(length(CAST(verifier AS BLOB)),0) + COALESCE(length(CAST(verified_at AS BLOB)),0) + COALESCE(length(CAST(evidence_digest AS BLOB)),0) + COALESCE(length(CAST(sealed_evidence_ref AS BLOB)),0) + COALESCE(length(CAST(retention_class AS BLOB)),0))
         FROM provenance_interaction_receipts WHERE id=(SELECT interaction_receipt_id
            FROM provenance_action_attestations WHERE id=?)
         UNION ALL SELECT 512 + 6 * (COALESCE(length(CAST(ordinal AS BLOB)),0) + COALESCE(length(CAST(output_domain AS BLOB)),0) + COALESCE(length(CAST(output_event_id AS BLOB)),0))
         FROM provenance_action_outputs WHERE action_attestation_id=? LIMIT 10001",
    ).bind(attestation_id).bind(attestation_id).bind(attestation_id).bind(attestation_id)
        .fetch_all(db.write_pool()).await?;
    budget.charge(&sizes)?;
    let attestation = sqlx::query(
        "SELECT id, schema_version, principal, executor_kind, channel, executor_ref,
                delegation_ref, interaction_receipt_id, operation, action_commitment,
                action_digest, output_event_set_digest, issuer, issuer_origin_database_id,
                issued_at, command_identity_digest, intent_digest
           FROM provenance_action_attestations WHERE id=?",
    )
    .bind(attestation_id)
    .fetch_one(db.write_pool())
    .await?;
    if let Some(receipt_id) = attestation.try_get::<Option<String>, _>("interaction_receipt_id")? {
        let receipt = sqlx::query(
            "SELECT id, schema_version, principal, scope_digest, nonce, verifier,
                    verified_at, evidence_digest, sealed_evidence_ref, retention_class
               FROM provenance_interaction_receipts WHERE id=?",
        )
        .bind(&receipt_id)
        .fetch_one(db.write_pool())
        .await?;
        sqlx::query(
            "INSERT INTO provenance_interaction_receipts
                (id, schema_version, principal, scope_digest, nonce, verifier,
                 verified_at, evidence_digest, sealed_evidence_ref, retention_class)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(receipt.try_get::<String, _>("id")?)
        .bind(receipt.try_get::<i64, _>("schema_version")?)
        .bind(receipt.try_get::<String, _>("principal")?)
        .bind(receipt.try_get::<String, _>("scope_digest")?)
        .bind(receipt.try_get::<String, _>("nonce")?)
        .bind(receipt.try_get::<String, _>("verifier")?)
        .bind(receipt.try_get::<String, _>("verified_at")?)
        .bind(receipt.try_get::<String, _>("evidence_digest")?)
        .bind(receipt.try_get::<Option<String>, _>("sealed_evidence_ref")?)
        .bind(receipt.try_get::<Option<String>, _>("retention_class")?)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO provenance_action_attestations
            (id, schema_version, principal, executor_kind, channel, executor_ref,
             delegation_ref, interaction_receipt_id, operation, action_commitment,
             action_digest, output_event_set_digest, issuer, issuer_origin_database_id,
             issued_at, command_identity_digest, intent_digest)
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(attestation.try_get::<String, _>("id")?)
    .bind(attestation.try_get::<i64, _>("schema_version")?)
    .bind(attestation.try_get::<String, _>("principal")?)
    .bind(attestation.try_get::<String, _>("executor_kind")?)
    .bind(attestation.try_get::<String, _>("channel")?)
    .bind(attestation.try_get::<Option<String>, _>("executor_ref")?)
    .bind(attestation.try_get::<Option<String>, _>("delegation_ref")?)
    .bind(attestation.try_get::<Option<String>, _>("interaction_receipt_id")?)
    .bind(attestation.try_get::<String, _>("operation")?)
    .bind(attestation.try_get::<String, _>("action_commitment")?)
    .bind(attestation.try_get::<String, _>("action_digest")?)
    .bind(attestation.try_get::<String, _>("output_event_set_digest")?)
    .bind(attestation.try_get::<String, _>("issuer")?)
    .bind(attestation.try_get::<String, _>("issuer_origin_database_id")?)
    .bind(attestation.try_get::<String, _>("issued_at")?)
    .bind(attestation.try_get::<Option<String>, _>("command_identity_digest")?)
    .bind(attestation.try_get::<Option<String>, _>("intent_digest")?)
    .execute(&mut **tx)
    .await?;
    let authority = sqlx::query(
        "SELECT attestation_id, issuer_origin_database_id, principal, operation,
                command_identity_digest, anchored_at
           FROM provenance_local_attestation_authority WHERE attestation_id=?",
    )
    .bind(attestation_id)
    .fetch_one(db.write_pool())
    .await?;
    sqlx::query(
        "INSERT INTO provenance_local_attestation_authority
            (attestation_id, issuer_origin_database_id, principal, operation,
             command_identity_digest, anchored_at)
         VALUES(?, ?, ?, ?, ?, ?)",
    )
    .bind(authority.try_get::<String, _>("attestation_id")?)
    .bind(authority.try_get::<String, _>("issuer_origin_database_id")?)
    .bind(authority.try_get::<String, _>("principal")?)
    .bind(authority.try_get::<String, _>("operation")?)
    .bind(authority.try_get::<Option<String>, _>("command_identity_digest")?)
    .bind(authority.try_get::<String, _>("anchored_at")?)
    .execute(&mut **tx)
    .await?;
    let outputs = sqlx::query(
        "SELECT ordinal, output_domain, output_event_id
           FROM provenance_action_outputs
          WHERE action_attestation_id=? ORDER BY ordinal",
    )
    .bind(attestation_id)
    .fetch_all(db.write_pool())
    .await?;
    for output in outputs {
        sqlx::query(
            "INSERT INTO provenance_action_outputs
                (action_attestation_id, ordinal, output_domain, output_event_id)
             VALUES(?, ?, ?, ?)",
        )
        .bind(attestation_id)
        .bind(output.try_get::<i64, _>("ordinal")?)
        .bind(output.try_get::<String, _>("output_domain")?)
        .bind(output.try_get::<String, _>("output_event_id")?)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn artifact_create_replay_in(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    plan: &ArtifactCreatePlan,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT record_id,payload FROM content_events
          WHERE type='record.created' AND actor=?
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.entry_id')=?
            AND json_extract(payload,'$.origin.idempotency_key')=?
            AND json_extract(payload,'$.origin.reverses') IS NULL
          ORDER BY seq LIMIT 1",
    )
    .bind(actor)
    .bind(&plan.artifact_id)
    .bind(&plan.entry_id)
    .bind(&plan.idempotency_key)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
    if payload
        .pointer("/origin/invocation_digest")
        .and_then(Value::as_str)
        != Some(plan.invocation_digest.as_str())
    {
        return Err(Error::engine(
            "create_record: artifact idempotency_key was reused for different intent",
        ));
    }
    Ok(Some(row.try_get("record_id")?))
}

pub(crate) async fn read_artifact_created_record(
    db: &Db,
    caller: &Caller,
    record_id: &str,
) -> Result<Value> {
    enriched_or_error(db, caller, "invoke_artifact_interaction", record_id).await
}

async fn validate_artifact_create_scope_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    plan: &ArtifactCreatePlan,
) -> Result<()> {
    require_record_in(
        tx,
        caller,
        "invoke_artifact_interaction",
        &plan.artifact_id,
        Capability::View,
    )
    .await?;
    let live_artifact: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records
          WHERE id=? AND type='Document' AND kind='artifact' AND deleted_at IS NULL)",
    )
    .bind(&plan.artifact_id)
    .fetch_one(&mut **tx)
    .await?;
    if !live_artifact {
        return Err(Error::engine(
            "create_record: originating artifact is no longer live",
        ));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&plan.artifact_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    if !matches!(
        runtime.as_deref(),
        Some(mdx_v2::RUNTIME_ID | crate::artifact_html::RUNTIME_ID)
    ) {
        return Err(Error::engine(
            "create_record: originating artifact runtime changed before creation committed",
        ));
    }
    let current_source_event: Option<String> = sqlx::query_scalar(
        "SELECT id FROM content_events
          WHERE record_id=?
            AND type IN ('record.created','record.updated','receipt.committed.v1')
            AND json_type(payload,'$.body') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&plan.artifact_id)
    .fetch_optional(&mut **tx)
    .await?;
    if current_source_event.as_deref() != Some(plan.source_event_id.as_str()) {
        return Err(Error::engine(
            "create_record: artifact source changed before creation committed",
        ));
    }
    let mut guards = Vec::new();
    if let Some(destination) = &plan.destination_binding {
        guards.push((
            destination.port.as_str(),
            destination.collection_id.as_str(),
        ));
    }
    guards.extend(
        plan.references
            .iter()
            .map(|reference| (reference.port.as_str(), reference.collection_id.as_str())),
    );
    guards.sort_unstable();
    guards.dedup();
    for (port, collection_id) in guards {
        let binding_exists: bool = if port == "default" {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM links
                  WHERE source_id=? AND target_id=? AND relationship='renders')",
            )
            .bind(&plan.artifact_id)
            .bind(collection_id)
            .fetch_one(&mut **tx)
            .await?
        } else {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM artifact_inputs
                  WHERE artifact_id=? AND port_name=? AND collection_id=?
                    AND artifact_source_event_id=? AND artifact_source_sha256=?)",
            )
            .bind(&plan.artifact_id)
            .bind(port)
            .bind(collection_id)
            .bind(&plan.source_event_id)
            .bind(&plan.source_digest)
            .fetch_one(&mut **tx)
            .await?
        };
        if !binding_exists {
            return Err(Error::engine(
                "create_record: artifact input binding changed before creation committed",
            ));
        }
        let scope_sha256 = hex::encode(Sha256::digest(serde_jcs::to_vec(
            &json!({ "artifact_port": port }),
        )?));
        let grant_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM artifact_module_grants
              WHERE artifact_id=? AND subject_kind='artifact_source'
                AND subject_record_id=? AND subject_event_id=? AND source_sha256=?
                AND capability='input.read' AND scope_sha256=?)",
        )
        .bind(&plan.artifact_id)
        .bind(&plan.artifact_id)
        .bind(&plan.source_event_id)
        .bind(&plan.source_digest)
        .bind(scope_sha256)
        .fetch_one(&mut **tx)
        .await?;
        if !grant_exists {
            return Err(Error::engine(
                "create_record: artifact input grant changed before creation committed",
            ));
        }
    }
    for reference in &plan.references {
        let records = super::artifacts::resolve_collection_in(
            tx,
            caller,
            &reference.collection_id,
            &reference.collection_kind,
        )
        .await?;
        if !records
            .iter()
            .any(|record| record.id == reference.record_id)
        {
            return Err(Error::engine(
                "create_record: selected reference left its bound input before creation committed",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tool 6 — get_record
// ---------------------------------------------------------------------------

/// Attach body-mention evidence to one already-authorized record, reading the
/// projection from `record_pool` and deciding visibility against `auth_pool`.
///
/// The two pools are deliberately separate: an `as_of` read replays the
/// projection into a scratch database while `View` is decided against live
/// meta, so a historical body is paired with live authorization. Reads happen
/// before visibility, but counts and windows are computed after it, so a hidden
/// source can never move a total or a page.
async fn attach_mentions_in_pools(
    record_pool: &sqlx::SqlitePool,
    auth_pool: &sqlx::SqlitePool,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
) -> Result<()> {
    // Two phases so the record pool never holds a connection while the auth
    // pool checks one out — with record and auth being the same pool on the
    // live path, holding one across the other would reserve two of five
    // connections per concurrent read for no reason.
    let gathered = {
        let mut conn = record_pool.acquire().await?;
        read::gather_mentions(&mut conn, &record.record.id).await?
    };
    let ids = gathered.authorization_ids();
    let visible = super::visible_ids_in_pool(auth_pool, caller, ids).await?;
    let resolved = {
        let mut conn = record_pool.acquire().await?;
        read::finish_mentions(
            &mut conn,
            gathered,
            &visible,
            opts.links_limit,
            opts.links_offset,
        )
        .await?
    };
    record.mentions_out = resolved.out;
    record.mentions_out_count = resolved.out_count;
    record.mentions_in = resolved.incoming;
    record.mentions_in_count = resolved.incoming_count;
    Ok(())
}

async fn attach_mentions_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
) -> Result<()> {
    let gathered = read::gather_mentions(tx, &record.record.id).await?;
    let ids = gathered.authorization_ids();
    let visible = super::visible_ids_in(tx, caller, ids).await?;
    let resolved =
        read::finish_mentions(tx, gathered, &visible, opts.links_limit, opts.links_offset).await?;
    record.mentions_out = resolved.out;
    record.mentions_out_count = resolved.out_count;
    record.mentions_in = resolved.incoming;
    record.mentions_in_count = resolved.incoming_count;
    Ok(())
}

pub(super) async fn filter_enriched_record_with_auth(
    record_db: &Db,
    auth_db: &Db,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
) -> Result<()> {
    // One record, one request: a fresh memo is correct here and keeps this
    // single-record entry point free of a cache parameter its callers do not
    // have. The batch path below threads a shared one instead.
    let mut reported = crate::contribution::ReportedIdentityCache::new();
    filter_enriched_record_with_auth_in_pools(
        record_db.write_pool(),
        auth_db.write_pool(),
        caller,
        record,
        opts,
        &mut reported,
    )
    .await
}

async fn filter_enriched_record_with_auth_in_pools(
    record_pool: &sqlx::SqlitePool,
    auth_pool: &sqlx::SqlitePool,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
    reported: &mut crate::contribution::ReportedIdentityCache,
) -> Result<()> {
    let authored_home = record.record.home_id.clone();
    if caller.is_member_copy() {
        // A member copy ships no anchors; the custody field becomes a marker
        // at the MCP layer (`inject_member_record_markers`).
        record.custody_boundary = false;
    } else {
        record.custody_boundary = crate::query::tree::custody_boundary_in_pool(
            auth_pool,
            &record.record.id,
            authored_home.as_deref(),
        )
        .await?;
    }
    let mut ids = Vec::new();
    ids.extend(record.ancestors.iter().map(|item| item.id.clone()));
    if let Some(home) = record.record.home_id.as_deref() {
        ids.push(home.to_string());
    }
    if let Some(owner) = record.record.owner_id.as_deref() {
        ids.push(owner.to_string());
    }
    if let Some(target) = &record.target {
        ids.push(target.target_record_id.clone());
    }
    let visible = super::visible_ids_in_pool(auth_pool, caller, ids).await?;
    record.containment_path_visible = record.record.id == crate::schema::ROOT_RECORD_ID
        || (record
            .ancestors
            .first()
            .map(|ancestor| ancestor.id.as_str())
            == Some(crate::schema::ROOT_RECORD_ID)
            && record
                .ancestors
                .iter()
                .all(|ancestor| visible.contains(&ancestor.id)));
    let not_hidden = if caller.is_member_copy() {
        crate::query::member_not_hidden_predicate("r")
    } else {
        crate::query::not_hidden_predicate("r")
    };
    let child_rows = sqlx::query(&format!(
        "SELECT r.id, r.type, r.kind, r.name,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r WHERE r.home_id = ? AND r.deleted_at IS NULL AND {}
          ORDER BY r.name, r.id",
        not_hidden
    ))
    .bind(ARCHIVED_FACET_KEY)
    .bind(&record.record.id)
    .fetch_all(record_pool)
    .await?;
    // Set-wise: one visibility fold for every child rather than one
    // authorization walk per child, which made a large folder cost a request
    // per row it contains.
    let child_ids = child_rows
        .iter()
        .map(|row| row.try_get::<String, _>("id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let visible_children = super::visible_ids_in_pool(auth_pool, caller, child_ids).await?;
    let mut authorized_children = Vec::new();
    for row in child_rows {
        let id: String = row.try_get("id")?;
        if visible_children.contains(&id) {
            authorized_children.push(read::ChildSummary {
                id,
                record_type: row.try_get("type")?,
                kind: row.try_get("kind")?,
                name: row.try_get("name")?,
                archived: row.try_get::<i64, _>("archived")? != 0,
            });
        }
    }
    record.child_count = authorized_children.len() as i64;
    record.children = authorized_children
        .into_iter()
        .skip(opts.children_offset as usize)
        .take(opts.children_limit as usize)
        .collect();
    record.ancestors.retain(|item| visible.contains(&item.id));
    if record
        .record
        .home_id
        .as_ref()
        .is_some_and(|home| !visible.contains(home))
    {
        record.record.home_id = None;
    }
    let mut record_snapshot = record_pool.begin().await?;
    let all_links = read::record_links_in(&mut record_snapshot, &record.record.id)
        .await?
        .expect("the enriched record still exists");
    record_snapshot.rollback().await?;
    let link_peers = all_links
        .links_out
        .iter()
        .map(|link| link.target_id.clone())
        .chain(all_links.links_in.iter().map(|link| link.source_id.clone()))
        .collect::<Vec<_>>();
    let visible_peers = super::visible_ids_in_pool(auth_pool, caller, link_peers).await?;
    let mut outbound = Vec::new();
    for link in all_links.links_out {
        if visible_peers.contains(&link.target_id) {
            outbound.push(link);
        }
    }
    record.links_out_count = outbound.len() as i64;
    record.links_out = outbound
        .into_iter()
        .skip(opts.links_offset as usize)
        .take(opts.links_limit as usize)
        .collect();
    let mut inbound = Vec::new();
    for link in all_links.links_in {
        if visible_peers.contains(&link.source_id) {
            inbound.push(link);
        }
    }
    record.links_in_count = inbound.len() as i64;
    record.links_in = inbound
        .into_iter()
        .skip(opts.links_offset as usize)
        .take(opts.links_limit as usize)
        .collect();
    // Succession names through the same visibility fold as links — with the
    // full ordered set reloaded first. The read path carries a capped window,
    // and truncating that window before filtering would let an invisible head
    // hide a nameable tail. An invisible successor stays COUNTED in
    // `total_count` but is never named in `items`: the count is the
    // disclosure, the name would be a leak.
    if record.superseded_by.is_some() {
        let mut grouped =
            read::load_superseded_by_batch(record_pool, std::slice::from_ref(&record.record.id))
                .await?;
        match grouped.remove(&record.record.id) {
            None => record.superseded_by = None,
            Some(successors) => {
                let total_count = successors.len() as i64;
                let successor_ids = successors
                    .iter()
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                let visible_successors =
                    super::visible_ids_in_pool(auth_pool, caller, successor_ids).await?;
                let visible = successors
                    .into_iter()
                    .filter(|(id, _)| visible_successors.contains(id))
                    .collect::<Vec<_>>();
                let items = read::truncate_superseded_items(visible);
                record.superseded_by = Some(read::SupersededBy { items, total_count });
            }
        }
    }
    // Suggestions and citations derive access from this already-authorized
    // bearer. Their independent filing/policy is not another gate.
    if record
        .record
        .owner_id
        .as_ref()
        .is_some_and(|owner| !visible.contains(owner))
    {
        record.record.owner_id = None;
    }
    if record
        .target
        .as_ref()
        .is_some_and(|target| !visible.contains(&target.target_record_id))
    {
        record.target = None;
    }
    attach_mentions_in_pools(record_pool, auth_pool, caller, record, opts).await?;
    if caller.is_member_copy() {
        // Contribution is history-derived; a marker is injected at the MCP
        // layer instead of reading excluded event/run tables.
        record.contribution = None;
        return Ok(());
    }
    let mut snapshot = auth_pool.begin().await?;
    let hydrated = hydrate_contributions_in(&mut snapshot, caller, record, reported).await;
    snapshot.rollback().await?;
    hydrated
}

async fn filter_enriched_record_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
    reported: &mut crate::contribution::ReportedIdentityCache,
) -> Result<()> {
    let authored_home = record.record.home_id.clone();
    if caller.is_member_copy() {
        record.custody_boundary = false;
    } else {
        record.custody_boundary = crate::query::tree::custody_boundary_in(
            tx,
            &record.record.id,
            authored_home.as_deref(),
        )
        .await?;
    }
    let mut ids = Vec::new();
    ids.extend(record.ancestors.iter().map(|item| item.id.clone()));
    if let Some(home) = record.record.home_id.as_deref() {
        ids.push(home.to_string());
    }
    if let Some(owner) = record.record.owner_id.as_deref() {
        ids.push(owner.to_string());
    }
    if let Some(target) = &record.target {
        ids.push(target.target_record_id.clone());
    }
    let visible = super::visible_ids_in(tx, caller, ids).await?;
    record.containment_path_visible = record.record.id == crate::schema::ROOT_RECORD_ID
        || (record
            .ancestors
            .first()
            .map(|ancestor| ancestor.id.as_str())
            == Some(crate::schema::ROOT_RECORD_ID)
            && record
                .ancestors
                .iter()
                .all(|ancestor| visible.contains(&ancestor.id)));
    let not_hidden = if caller.is_member_copy() {
        crate::query::member_not_hidden_predicate("r")
    } else {
        crate::query::not_hidden_predicate("r")
    };
    let child_rows = sqlx::query(&format!(
        "SELECT r.id, r.type, r.kind, r.name,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r WHERE r.home_id = ? AND r.deleted_at IS NULL AND {}
          ORDER BY r.name, r.id",
        not_hidden
    ))
    .bind(ARCHIVED_FACET_KEY)
    .bind(&record.record.id)
    .fetch_all(&mut **tx)
    .await?;
    // Set-wise: one visibility fold for every child rather than one
    // authorization walk per child, which made a large folder cost a request
    // per row it contains.
    let child_ids = child_rows
        .iter()
        .map(|row| row.try_get::<String, _>("id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let visible_children = super::visible_ids_in(tx, caller, child_ids).await?;
    let mut authorized_children = Vec::new();
    for row in child_rows {
        let id: String = row.try_get("id")?;
        if visible_children.contains(&id) {
            authorized_children.push(read::ChildSummary {
                id,
                record_type: row.try_get("type")?,
                kind: row.try_get("kind")?,
                name: row.try_get("name")?,
                archived: row.try_get::<i64, _>("archived")? != 0,
            });
        }
    }
    record.child_count = authorized_children.len() as i64;
    record.children = authorized_children
        .into_iter()
        .skip(opts.children_offset as usize)
        .take(opts.children_limit as usize)
        .collect();
    record.ancestors.retain(|item| visible.contains(&item.id));
    if record
        .record
        .home_id
        .as_ref()
        .is_some_and(|home| !visible.contains(home))
    {
        record.record.home_id = None;
    }
    let all_links = read::record_links_in(tx, &record.record.id)
        .await?
        .expect("the enriched record still exists");
    let link_peers = all_links
        .links_out
        .iter()
        .map(|link| link.target_id.clone())
        .chain(all_links.links_in.iter().map(|link| link.source_id.clone()))
        .collect::<Vec<_>>();
    let visible_peers = super::visible_ids_in(tx, caller, link_peers).await?;
    let mut outbound = Vec::new();
    for link in all_links.links_out {
        if visible_peers.contains(&link.target_id) {
            outbound.push(link);
        }
    }
    record.links_out_count = outbound.len() as i64;
    record.links_out = outbound
        .into_iter()
        .skip(opts.links_offset as usize)
        .take(opts.links_limit as usize)
        .collect();
    let mut inbound = Vec::new();
    for link in all_links.links_in {
        if visible_peers.contains(&link.source_id) {
            inbound.push(link);
        }
    }
    record.links_in_count = inbound.len() as i64;
    record.links_in = inbound
        .into_iter()
        .skip(opts.links_offset as usize)
        .take(opts.links_limit as usize)
        .collect();
    // Same succession rule as the pooled filter above: reload the full
    // ordered set, filter by visibility, then truncate — never the reverse.
    if record.superseded_by.is_some() {
        let mut grouped =
            read::load_superseded_by_batch(&mut **tx, std::slice::from_ref(&record.record.id))
                .await?;
        match grouped.remove(&record.record.id) {
            None => record.superseded_by = None,
            Some(successors) => {
                let total_count = successors.len() as i64;
                let successor_ids = successors
                    .iter()
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                let visible_successors = super::visible_ids_in(tx, caller, successor_ids).await?;
                let visible = successors
                    .into_iter()
                    .filter(|(id, _)| visible_successors.contains(id))
                    .collect::<Vec<_>>();
                let items = read::truncate_superseded_items(visible);
                record.superseded_by = Some(read::SupersededBy { items, total_count });
            }
        }
    }
    if record
        .record
        .owner_id
        .as_ref()
        .is_some_and(|owner| !visible.contains(owner))
    {
        record.record.owner_id = None;
    }
    if record
        .target
        .as_ref()
        .is_some_and(|target| !visible.contains(&target.target_record_id))
    {
        record.target = None;
    }
    attach_mentions_in(tx, caller, record, opts).await?;
    if caller.is_member_copy() {
        record.contribution = None;
        return Ok(());
    }
    hydrate_contributions_in(tx, caller, record, reported).await
}

/// Attach the generic contribution projection to a record and to every comment
/// still visible on it.
///
/// This runs in the visibility-filtering layer on purpose. The projection is
/// viewer-relative — which run, which principal, which alternative set — so it
/// cannot be built by the projection reader that does not know who is asking.
///
/// `reported` is the request's shared per-run memo, threaded in rather than
/// created here: a record and its comments (and every further act the same
/// request hydrates) repeat one run's `agent_runs` read once, not per act.
async fn hydrate_contributions_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    reported: &mut crate::contribution::ReportedIdentityCache,
) -> Result<()> {
    record.contribution =
        crate::contribution::contribution_for_record_in(tx, caller, &record.record.id, reported)
            .await?;
    if let Some(comments) = record.comments.as_mut() {
        for comment in comments.iter_mut() {
            comment.contribution =
                crate::contribution::contribution_for_record_in(tx, caller, &comment.id, reported)
                    .await?;
        }
    }
    Ok(())
}

async fn filter_enriched_record(
    db: &Db,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
) -> Result<()> {
    filter_enriched_record_with_auth(db, db, caller, record, opts).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRecordArgs {
    ids: Vec<String>,
    include_interpretation: Option<bool>,
    resolve: Option<bool>,
    children_limit: Option<i64>,
    children_offset: Option<i64>,
    links_limit: Option<i64>,
    links_offset: Option<i64>,
    include_suggestions: Option<bool>,
    suggestions_limit: Option<i64>,
    suggestions_offset: Option<i64>,
    include_citations: Option<bool>,
    citations_limit: Option<i64>,
    citations_offset: Option<i64>,
    include_comments: Option<bool>,
    comments_limit: Option<i64>,
    comments_offset: Option<i64>,
    include_history_summary: Option<bool>,
}

enum RecordSupplementSource<'a, 'db> {
    Lens(&'a ReadLens<'db>),
    Live(&'a mut Transaction<'db, Sqlite>),
}

impl RecordSupplementSource<'_, '_> {
    async fn record_version(&mut self, record_id: &str) -> Result<String> {
        let event_seq: Option<i64> = match self {
            Self::Lens(lens) => {
                sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
                    .bind(record_id)
                    .fetch_one(lens.projection().snapshot_pool())
                    .await?
            }
            Self::Live(tx) => {
                sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
                    .bind(record_id)
                    .fetch_one(&mut ***tx)
                    .await?
            }
        };
        Ok(
            native_artifact_runtime::artifact_intents::FacetVersion::Record {
                event_seq: event_seq.unwrap_or_default(),
            }
            .encode(),
        )
    }

    async fn expectation(
        &mut self,
        message_id: &str,
        recipient_id: &str,
    ) -> Result<crate::message_expectation::MessageExpectationDerivation> {
        match self {
            Self::Lens(lens) => {
                crate::message_expectation::derive_message_expectation_state_with_lens(
                    lens,
                    message_id,
                    recipient_id,
                )
                .await
            }
            Self::Live(tx) => {
                crate::message_expectation::derive_message_expectation_state_in(
                    tx,
                    message_id,
                    recipient_id,
                )
                .await
            }
        }
    }

    async fn execute_saved_query(&mut self, caller: &Caller, query: Value) -> Result<Value> {
        match self {
            Self::Lens(lens) => {
                super::querying::execute_query_record_args_with_lens_as(
                    lens,
                    caller,
                    "saved query",
                    query,
                )
                .await
            }
            Self::Live(tx) => {
                super::querying::execute_query_record_args_in_as(tx, caller, "saved query", query)
                    .await
            }
        }
    }

    async fn execute_saved_sql(
        &mut self,
        caller: &Caller,
        definition: &super::querying::SavedSqlDefinition,
    ) -> Result<Value> {
        match self {
            Self::Live(tx) => super::querying::execute_saved_sql_in(tx, caller, definition).await,
            Self::Lens(_) => Err(Error::engine(
                "saved governed SQL is live-only; historical execution has no portable snapshot contract",
            )),
        }
    }
}

/// The one member marker shape (contract §2.3(a)): a section the member copy
/// cannot compute. It carries no workspace counter and no record id, and it
/// replaces a section — never a silent absence or a default value.
fn member_section_marker(section: &str) -> Value {
    json!({ "unavailable_offline": { "surface": section, "retry": "when_online" } })
}

/// Replace every member-copy marker section on a serialized found item. The
/// excluded companions (custody anchor walk, contribution/history events,
/// citation resolution, Message audience/provenance) become markers; the
/// slice-derived sections (facets, links, children, mentions, display
/// reference) stay at parity.
fn inject_member_record_markers(
    items: &mut Value,
    include_history_summary: bool,
    include_citations: bool,
    citation_targets: &std::collections::HashSet<String>,
) {
    let Some(items) = items.as_array_mut() else {
        return;
    };
    for item in items {
        if item.get("status").and_then(Value::as_str) != Some("found") {
            continue;
        }
        let Some(object) = item.as_object_mut() else {
            continue;
        };
        object.insert(
            "custody_boundary".into(),
            member_section_marker("custody_boundary"),
        );
        object.insert("contribution".into(), member_section_marker("contribution"));
        // The citation `target` is a marker only where online would resolve
        // one: an Annotation with an `annotation_targets` row. A record with
        // no target online stays without the key.
        if object
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| citation_targets.contains(id))
        {
            object.insert("target".into(), member_section_marker("citation"));
        }
        if include_history_summary {
            object.insert(
                "history_summary".into(),
                member_section_marker("history_summary"),
            );
        }
        if include_citations {
            object.insert("citations".into(), member_section_marker("citations"));
        }
        if object.get("type").and_then(Value::as_str) == Some("Message") {
            object.insert(
                "communication_origin".into(),
                member_section_marker("message_audience"),
            );
            object.insert(
                "federation_provenance".into(),
                member_section_marker("message_provenance"),
            );
            object.insert(
                "mentions_out".into(),
                member_section_marker("message_mentions"),
            );
            object.insert(
                "mentions_in".into(),
                member_section_marker("message_mentions"),
            );
        }
    }
}

async fn supplement_get_record_items(
    source: &mut RecordSupplementSource<'_, '_>,
    caller: &Caller,
    items: Vec<read::BatchGetItem>,
    resolve: bool,
) -> Result<Value> {
    let mut items = serde_json::to_value(items)?;
    for item in items
        .as_array_mut()
        .expect("batch get serializes as an array")
    {
        if item.get("status").and_then(Value::as_str) != Some("found") {
            continue;
        }
        let record_id = item
            .get("id")
            .and_then(Value::as_str)
            .expect("a found record carries its id")
            .to_owned();
        // §2.6: a member copy omits the record version entirely.
        if !caller.is_member_copy() {
            let version = source.record_version(&record_id).await?;
            item.as_object_mut()
                .expect("a batch item is an object")
                .insert("version".into(), Value::String(version));
        }
        let query_facet = item
            .get("facets")
            .and_then(Value::as_array)
            .and_then(|facets| {
                facets
                    .iter()
                    .find(|facet| facet.get("key").and_then(Value::as_str) == Some("query"))
            });
        let inspection = query_facet.map(|facet| {
            let raw = facet.get("value").and_then(Value::as_str);
            if item.get("type").and_then(Value::as_str) == Some("Collection")
                && item.get("kind").and_then(Value::as_str) == Some("query")
            {
                super::querying::inspect_saved_record_query(raw)
            } else {
                super::querying::inspect_saved_query(raw)
            }
        });
        let has_query = matches!(
            &inspection,
            Some(
                super::querying::SavedQueryInspection::Valid { .. }
                    | super::querying::SavedQueryInspection::GovernedSql { .. }
            )
        );
        item.as_object_mut()
            .expect("found batch item serializes as an object")
            .insert("has_query".into(), json!(has_query));
        if item.get("type").and_then(Value::as_str) == Some("Message") {
            let value = if caller.is_member_copy() {
                member_section_marker("message_expectation")
            } else {
                let message_id = item
                    .get("id")
                    .and_then(Value::as_str)
                    .expect("found record always carries id")
                    .to_string();
                serde_json::to_value(source.expectation(&message_id, caller.actor()).await?)?
            };
            item.as_object_mut()
                .expect("found batch item serializes as an object")
                .insert("message_expectation_state".into(), value);
        }
        if !resolve {
            continue;
        }
        if caller.is_member_copy() {
            item.as_object_mut()
                .expect("found batch item serializes as an object")
                .insert(
                    "query_resolution".into(),
                    member_section_marker("query_resolution"),
                );
            continue;
        }
        let resolution = match inspection {
            None => None,
            Some(super::querying::SavedQueryInspection::Invalid { diagnostic }) => Some(json!({
                "status": "invalid",
                "diagnostic": diagnostic,
            })),
            Some(super::querying::SavedQueryInspection::UnsupportedVersion {
                version,
                diagnostic,
            }) => Some(json!({
                "status": "unsupported_version",
                "version": version,
                "diagnostic": diagnostic,
            })),
            Some(super::querying::SavedQueryInspection::Valid { version, query }) => {
                Some(match source.execute_saved_query(caller, query).await {
                    Ok(output) => json!({
                        "status": "resolved",
                        "version": version,
                        "output": output,
                    }),
                    Err(error) => json!({
                        "status": "execution_error",
                        "version": version,
                        "diagnostic": error.to_string(),
                    }),
                })
            }
            Some(super::querying::SavedQueryInspection::GovernedSql { definition }) => {
                Some(match source.execute_saved_sql(caller, &definition).await {
                    Ok(output) => json!({
                        "status": "resolved",
                        "version": definition.v,
                        "kind": definition.kind,
                        "output": output,
                    }),
                    Err(error) => json!({
                        "status": "execution_error",
                        "version": definition.v,
                        "kind": definition.kind,
                        "diagnostic": error.to_string(),
                    }),
                })
            }
        };
        if let Some(resolution) = resolution {
            item.as_object_mut()
                .expect("found batch item serializes as an object")
                .insert("query_resolution".into(), resolution);
        }
    }
    Ok(items)
}

async fn finish_read_snapshot<T>(
    snapshot: Transaction<'_, Sqlite>,
    result: Result<T>,
) -> Result<T> {
    match result {
        Ok(value) => {
            snapshot.rollback().await?;
            Ok(value)
        }
        Err(primary) => {
            let _ = snapshot.rollback().await;
            Err(primary)
        }
    }
}

pub(crate) async fn get_record(db: Db, caller: Caller, mut arguments: Value) -> Result<Value> {
    const TOOL: &str = "get_record";
    let as_of = lens::take_as_of(TOOL, &mut arguments)?;
    let args: GetRecordArgs = parse_args(TOOL, arguments)?;
    if as_of.is_some() && args.include_interpretation.unwrap_or(false) {
        return Err(Error::engine(
            "get_record: include_interpretation is not supported with as_of in v1; use read_attributions with as_of_event_seq",
        ));
    }
    if as_of.is_some() && args.include_history_summary.unwrap_or(false) {
        return Err(Error::engine(
            "get_record: include_history_summary cannot be combined with as_of in v1",
        ));
    }
    let Some(selector) = as_of else {
        return get_record_from_lens(&ReadLens::live(&db), &caller, args, Some(&db)).await;
    };
    let resolved = lens::resolve_as_of(&db, selector).await?;
    let scratch = open_database(":memory:").await?;
    let result = async {
        apply_schema(&scratch).await?;
        lens::replay_projection(&db, &scratch, resolved.resolved_content_seq).await?;
        let read_lens = ReadLens::historical(&scratch, &db, &resolved);
        let mut output = get_record_from_lens(&read_lens, &caller, args, None).await?;
        lens::echo_temporal(&mut output, &resolved);
        Ok(output)
    }
    .await;
    scratch.close().await;
    result
}

async fn get_record_from_lens(
    lens: &ReadLens<'_>,
    caller: &Caller,
    args: GetRecordArgs,
    index_db: Option<&Db>,
) -> Result<Value> {
    const TOOL: &str = "get_record";
    debug_assert_eq!(
        lens.is_member(),
        caller.is_member_copy(),
        "member lens and member caller must agree (dispatch derives both from the Db open mode)"
    );
    if args.ids.is_empty() {
        return Err(Error::engine(format!("{TOOL}: 'ids' must not be empty")));
    }
    if args.ids.len() > MAX_BATCH_GET {
        return Err(Error::engine(format!(
            "{TOOL}: at most {MAX_BATCH_GET} ids per call"
        )));
    }
    let include_interpretation = args.include_interpretation.unwrap_or(false);
    if include_interpretation && lens.temporal().is_some() {
        return Err(Error::engine(
            "get_record: include_interpretation is not supported with as_of in v1; use read_attributions with as_of_event_seq",
        ));
    }
    let include_history_summary = args.include_history_summary.unwrap_or(false);
    if include_history_summary && lens.temporal().is_some() {
        return Err(Error::engine(
            "get_record: include_history_summary cannot be combined with as_of in v1",
        ));
    }
    if include_interpretation
        && args.ids.len() > super::attribution::MAX_GENERIC_INTERPRETATION_BEARERS
    {
        return Err(Error::engine(format!(
            "get_record: include_interpretation supports at most {} ids per call",
            super::attribution::MAX_GENERIC_INTERPRETATION_BEARERS
        )));
    }
    let defaults = read::EnrichOptions::default();
    let opts = read::EnrichOptions {
        children_limit: args.children_limit.unwrap_or(defaults.children_limit),
        children_offset: args.children_offset.unwrap_or(defaults.children_offset),
        links_limit: args.links_limit.unwrap_or(defaults.links_limit),
        links_offset: args.links_offset.unwrap_or(defaults.links_offset),
        include_suggestions: args.include_suggestions.unwrap_or(false),
        suggestions_limit: args.suggestions_limit.unwrap_or(defaults.suggestions_limit),
        suggestions_offset: args
            .suggestions_offset
            .unwrap_or(defaults.suggestions_offset),
        include_citations: args.include_citations.unwrap_or(false),
        citations_limit: args.citations_limit.unwrap_or(defaults.citations_limit),
        citations_offset: args.citations_offset.unwrap_or(defaults.citations_offset),
        include_comments: args.include_comments.unwrap_or(false),
        comments_limit: args.comments_limit.unwrap_or(defaults.comments_limit),
        comments_offset: args.comments_offset.unwrap_or(defaults.comments_offset),
    };
    // A live get_record request writes nothing and carries its own read
    // transaction. Keep the governed body, admission and enrichment on one
    // physically read-only snapshot; historical replay retains its existing
    // projection pool below.
    let record_pool = if lens.temporal().is_none() {
        lens.projection().shared_pool()
    } else {
        lens.projection().snapshot_pool()
    };
    let auth_pool = if lens.temporal().is_none() {
        lens.meta().shared_pool()
    } else {
        lens.meta().snapshot_pool()
    };
    let resolve = args.resolve.unwrap_or(true);
    // One memo for the whole batch: every act hydrated below that names the
    // same run shares a single `agent_runs` read. A run page resolving many
    // acts through one `get_record` call therefore issues one lookup per run.
    let mut reported = crate::contribution::ReportedIdentityCache::new();
    let mut indexed_header_ids = crate::mcp::request_timing::m4_index_measurement_enabled()
        .then(std::collections::HashSet::new);
    // A member copy has no policy/event tables, so it takes the lens path
    // (which the member-aware reader serves) rather than the live batch path.
    let mut items = if lens.temporal().is_none() && !lens.is_member() {
        let indexed_heads = if let Some(db) = index_db {
            db.indexed_record_heads_for(&args.ids).await
        } else {
            None
        };
        let mut snapshot = record_pool.begin().await?;
        let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
        let result = async {
            let mut items = read::get_records_live_with_heads_and_usage_in(
                &mut snapshot,
                &args.ids,
                opts,
                principal,
                indexed_heads.as_ref(),
                indexed_header_ids.as_mut(),
            )
            .await?;
            hide_attribution_batch_items(&mut items);
            // One disclosure memo for every summary on this call: a batch
            // holds many records but few distinct actors.
            let mut history_disclosure = super::history::ActorDisclosure::default();
            for item in &mut items {
                let read::BatchGetItem::Found(record) = item else {
                    continue;
                };
                filter_enriched_record_in(&mut snapshot, caller, record, opts, &mut reported)
                    .await?;
                // Advisory freshness projection, live reads only: the same
                // snapshot transaction keeps the authorization decision and
                // the kernel state on one SQLite snapshot. Records without
                // bound Occurrences keep `freshness: None`, so the key stays
                // absent from their output.
                record.freshness = crate::freshness::freshness_for_artefact_in(
                    &mut snapshot,
                    &record.record.id,
                    principal,
                )
                .await?;
                // Opt-in byline attribution on the same snapshot: oldest and
                // newest visible events in metadata shape. Absent entirely
                // unless asked, so unrelated callers pay nothing.
                if include_history_summary {
                    let record_id = record.record.id.clone();
                    record.history_summary = Some(
                        super::history::history_summary_in(
                            &mut snapshot,
                            caller,
                            &mut history_disclosure,
                            &record_id,
                        )
                        .await?,
                    );
                }
            }
            let mut items = supplement_get_record_items(
                &mut RecordSupplementSource::Live(&mut snapshot),
                caller,
                items,
                resolve,
            )
            .await?;
            if include_interpretation {
                let bearer_window = super::attribution::authorized_get_interpretation_bearers(
                    items.as_array().expect("batch get serializes as an array"),
                );
                let projections = super::attribution::project_generic_interpretations_in(
                    &mut snapshot,
                    caller,
                    bearer_window,
                )
                .await?;
                super::attribution::attach_generic_interpretations(
                    items
                        .as_array_mut()
                        .expect("batch get serializes as an array"),
                    &projections,
                )?;
            }
            Ok(items)
        }
        .await;
        finish_read_snapshot(snapshot, result).await?
    } else {
        let mut items = if super::is_legacy_local(caller) {
            read::get_records_with_lens(lens, &args.ids, opts).await?
        } else {
            read::get_records_with_lens_as(lens, &args.ids, opts, super::principal(caller)).await?
        };
        hide_attribution_batch_items(&mut items);
        for item in &mut items {
            let read::BatchGetItem::Found(record) = item else {
                continue;
            };
            // The member reader already answers from E(m) (slice presence);
            // there is no policy plane to re-check, and the reader returns
            // NotFound for an absent id.
            if !caller.is_member_copy()
                && !super::can_record_in_pool(
                    auth_pool,
                    caller,
                    &record.record.id,
                    Capability::View,
                )
                .await?
            {
                let id = record.record.id.clone();
                *item = read::BatchGetItem::NotFound { id };
                continue;
            }
            filter_enriched_record_with_auth_in_pools(
                record_pool,
                auth_pool,
                caller,
                record,
                opts,
                &mut reported,
            )
            .await?;
        }
        supplement_get_record_items(
            &mut RecordSupplementSource::Lens(lens),
            caller,
            items,
            resolve,
        )
        .await?
    };
    annotate_display_references_in_pool(auth_pool, &mut items, caller.is_member_copy()).await?;
    if caller.is_member_copy() {
        // Which found Annotations would have a citation target online: those
        // with an `annotation_targets` row, read from the shipped table.
        let annotation_ids: Vec<String> = items
            .as_array()
            .expect("batch get serializes as an array")
            .iter()
            .filter(|item| item.get("status").and_then(Value::as_str) == Some("found"))
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("Annotation"))
            .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let citation_targets: std::collections::HashSet<String> = if annotation_ids.is_empty() {
            std::collections::HashSet::new()
        } else {
            let encoded = serde_json::to_string(&annotation_ids)?;
            sqlx::query_scalar(
                "SELECT annotation_id FROM annotation_targets
                  WHERE annotation_id IN (SELECT value FROM json_each(?))",
            )
            .bind(encoded)
            .fetch_all(auth_pool)
            .await?
            .into_iter()
            .collect()
        };
        inject_member_record_markers(
            &mut items,
            include_history_summary,
            opts.include_citations,
            &citation_targets,
        );
    }
    for item in items
        .as_array_mut()
        .expect("batch get serializes as an array")
    {
        annotate_body_digest(item);
    }
    // The windows are echoed back for the same reason `get_structure` echoes
    // its caps: a caller reading `child_count: 1501` next to 200 children needs
    // to know whether it asked for that window or inherited it.
    let mut output = json!({
        "records": items,
        "resolve": resolve,
        "children_limit": opts.children_limit,
        "children_offset": opts.children_offset,
        "links_limit": opts.links_limit,
        "links_offset": opts.links_offset,
        "include_suggestions": opts.include_suggestions,
        "suggestions_limit": opts.suggestions_limit,
        "suggestions_offset": opts.suggestions_offset,
        "include_citations": opts.include_citations,
        "citations_limit": opts.citations_limit,
        "citations_offset": opts.citations_offset,
        "include_comments": opts.include_comments,
        "comments_limit": opts.comments_limit,
        "comments_offset": opts.comments_offset,
        "include_history_summary": include_history_summary,
    });
    if include_interpretation {
        output
            .as_object_mut()
            .expect("get_record response is an object")
            .insert("include_interpretation".into(), Value::Bool(true));
    }
    // One decision per successful tool call. A held head rejected by the
    // read transaction's fence, or a batch with no *returned* indexed record,
    // counts as governed fallback. Later filtering can hide a record whose
    // header was read; only the final found items can establish a hit.
    // Historical replay has no indexed headers and counts as governed.
    let used_indexed_header = output["records"].as_array().is_some_and(|records| {
        records.iter().any(|record| {
            record["status"] == "found"
                && record["id"].as_str().is_some_and(|id| {
                    indexed_header_ids
                        .as_ref()
                        .is_some_and(|ids| ids.contains(id))
                })
        })
    });
    crate::mcp::request_timing::record_m4_index_decision(used_indexed_header);
    Ok(output)
}

/// Stamp each found record with the shortest abbreviation that addresses it.
///
/// This is the read-side half of the prefix affordance: `record_ref` expands an
/// abbreviation on the way in, and this hands one back on the way out, so a
/// surface that wants to *show* a compact reference does not have to derive one
/// — which it could only do by scanning every id in the database.
///
/// The field is absent, never null, when there is no reference to give. Absence
/// is the whole substrate signal: `get_record` on Postgres and Turso is a
/// different handler that never sets it, and prefix resolution is not available
/// there either, so a consumer that keys off presence is automatically correct
/// on every substrate and no caller has to be told which one it is talking to.
/// Advertising a reference form the same engine would refuse to resolve is the
/// one outcome worth engineering against.
///
/// The reference is always computed against the *live* database, even under
/// `as_of`. A historical read still wants an address that works now; a
/// shortest-unique prefix as of last Tuesday is a fact about a database that no
/// longer exists.
/// Q6c: a member copy ships the online display references in
/// `member_display_references`. A member read must use them rather than
/// recompute a shortest-unique prefix over the slice, which could shorten a
/// prefix that only a hidden record keeps unique.
pub(crate) async fn member_display_references_in_pool(
    pool: &sqlx::SqlitePool,
    ids: &[String],
) -> Result<std::collections::HashMap<String, Option<String>>> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let encoded = serde_json::to_string(ids)?;
    let rows = sqlx::query(
        "SELECT record_id, display_reference FROM member_display_references
          WHERE record_id IN (SELECT value FROM json_each(?))",
    )
    .bind(encoded)
    .fetch_all(pool)
    .await?;
    let mut references = std::collections::HashMap::new();
    for row in rows {
        references.insert(
            row.try_get::<String, _>("record_id")?,
            Some(row.try_get::<String, _>("display_reference")?),
        );
    }
    Ok(references)
}

/// Snapshot-scoped form of [`member_display_references_in_pool`], for the
/// search path whose succession annotation shares the caller's transaction.
async fn member_display_references_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ids: &[String],
) -> Result<std::collections::HashMap<String, Option<String>>> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let encoded = serde_json::to_string(ids)?;
    let rows = sqlx::query(
        "SELECT record_id, display_reference FROM member_display_references
          WHERE record_id IN (SELECT value FROM json_each(?))",
    )
    .bind(encoded)
    .fetch_all(&mut **tx)
    .await?;
    let mut references = std::collections::HashMap::new();
    for row in rows {
        references.insert(
            row.try_get::<String, _>("record_id")?,
            Some(row.try_get::<String, _>("display_reference")?),
        );
    }
    Ok(references)
}

async fn annotate_display_references_in_pool(
    pool: &sqlx::SqlitePool,
    items: &mut Value,
    member: bool,
) -> Result<()> {
    let array = items
        .as_array_mut()
        .expect("batch get serializes as an array");
    let ids = collect_record_path_annotation_ids(array);
    let references = if member {
        member_display_references_in_pool(pool, &ids).await?
    } else {
        batch_display_references_in_pool(pool, &ids).await?
    };
    for item in array {
        if item.get("status").and_then(Value::as_str) != Some("found") {
            continue;
        }
        apply_record_path_annotations(item, &references)?;
        apply_enriched_record_path_annotations(item, &references)?;
        apply_superseded_by_reference_annotations(item, &references)?;
    }
    Ok(())
}

fn collect_record_path_annotation_ids(items: &[Value]) -> Vec<String> {
    let mut ids = Vec::new();
    for item in items {
        if item.get("status").and_then(Value::as_str) != Some("found") {
            continue;
        }
        collect_record_path_annotation_ids_from_item(item, &mut ids);
    }
    ids
}

fn collect_record_path_annotation_ids_from_item(item: &Value, ids: &mut Vec<String>) {
    if let Some(id) = item.get("id").and_then(Value::as_str) {
        ids.push(id.to_owned());
    }
    for key in enriched_summary_keys() {
        let Some(summaries) = item.get(*key).and_then(Value::as_array) else {
            continue;
        };
        for summary in summaries {
            if let Some(id) = summary.get("id").and_then(Value::as_str) {
                ids.push(id.to_owned());
            }
        }
    }
    // Named successors need short references for the header line; collect
    // them into the same batch rather than paying a second prefix scan.
    if let Some(successors) = item
        .get("superseded_by")
        .and_then(|superseded| superseded.get("items"))
        .and_then(Value::as_array)
    {
        for successor in successors {
            if let Some(id) = successor.get("id").and_then(Value::as_str) {
                ids.push(id.to_owned());
            }
        }
    }
    if let Some(records) = item
        .get("query_resolution")
        .and_then(|resolution| resolution.get("output"))
        .and_then(|output| output.get("records"))
        .and_then(Value::as_array)
    {
        for record in records {
            if let Some(id) = record.get("id").and_then(Value::as_str) {
                ids.push(id.to_owned());
            }
        }
    }
}

fn enriched_summary_keys() -> &'static [&'static str] {
    &[
        "children",
        "suggestions",
        "citations",
        "comments",
        "ancestors",
    ]
}

fn apply_enriched_record_path_annotations(
    item: &mut Value,
    references: &std::collections::HashMap<String, Option<String>>,
) -> Result<()> {
    for key in enriched_summary_keys() {
        let Some(summaries) = item.get_mut(*key).and_then(Value::as_array_mut) else {
            continue;
        };
        for summary in summaries {
            let Some(id) = summary.get("id").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            apply_record_path_with_reference(summary, &id, references.get(&id).cloned().flatten())?;
        }
    }
    if let Some(records) = item
        .get_mut("query_resolution")
        .and_then(|resolution| resolution.get_mut("output"))
        .and_then(|output| output.get_mut("records"))
        .and_then(Value::as_array_mut)
    {
        for record in records {
            let Some(id) = record.get("id").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            apply_record_path_with_reference(record, &id, references.get(&id).cloned().flatten())?;
        }
    }
    Ok(())
}

/// Stamp short references onto the named successors of one enriched record.
/// The `get_record` JSON path annotates the serialized payload instead; the
/// markdown path here works on the typed struct, so it needs its own stamp —
/// otherwise it would always degrade to the full id.
async fn populate_superseded_references_in_pool(
    pool: &sqlx::SqlitePool,
    record: &mut read::EnrichedRecord,
    member: bool,
) -> Result<()> {
    let Some(superseded) = record.superseded_by.as_mut() else {
        return Ok(());
    };
    let ids = superseded
        .items
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let references = if member {
        member_display_references_in_pool(pool, &ids).await?
    } else {
        batch_display_references_in_pool(pool, &ids).await?
    };
    for item in &mut superseded.items {
        if let Some(reference) = references.get(&item.id).cloned().flatten() {
            item.display_reference = Some(reference);
        }
    }
    Ok(())
}

/// Stamp short references onto named successors in serialized `get_record`
/// payloads. Unlike every other summary this annotates, a successor carries
/// a fixed shape — `id`, `name`, optional `display_reference` — so the shared
/// path annotator (which also writes `record_path`/`record_path_full`)
/// cannot be reused: those keys would leak into the shape. Absent references
/// stay absent; renderers degrade to the full id there.
fn apply_superseded_by_reference_annotations(
    item: &mut Value,
    references: &std::collections::HashMap<String, Option<String>>,
) -> Result<()> {
    let Some(successors) = item
        .get_mut("superseded_by")
        .and_then(|superseded| superseded.get_mut("items"))
        .and_then(Value::as_array_mut)
    else {
        return Ok(());
    };
    for successor in successors {
        let Some(id) = successor
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let Some(reference) = references.get(&id).cloned().flatten() else {
            continue;
        };
        successor
            .as_object_mut()
            .ok_or_else(|| Error::engine("superseded successor is not an object"))?
            .insert("display_reference".into(), json!(reference));
    }
    Ok(())
}

async fn batch_display_references(
    db: &Db,
    ids: &[String],
) -> Result<std::collections::HashMap<String, Option<String>>> {
    batch_display_references_in_pool(db.write_pool(), ids).await
}

async fn batch_display_references_in_pool(
    pool: &sqlx::SqlitePool,
    ids: &[String],
) -> Result<std::collections::HashMap<String, Option<String>>> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let borrowed: Vec<&str> = ids.iter().map(String::as_str).collect();
    crate::mcp::record_ref::display_references_in_pool(pool, &borrowed).await
}

fn apply_record_path_annotations(
    item: &mut Value,
    references: &std::collections::HashMap<String, Option<String>>,
) -> Result<()> {
    let Some(id) = item.get("id").and_then(Value::as_str).map(str::to_owned) else {
        return Ok(());
    };
    apply_record_path_with_reference(item, &id, references.get(&id).cloned().flatten())
}

pub(crate) fn apply_record_path_with_reference(
    item: &mut Value,
    id: &str,
    reference: Option<String>,
) -> Result<()> {
    if !annotate_full_record_path_for_item(item, id)? {
        return Ok(());
    }
    let full_path = item["record_path_full"]
        .as_str()
        .expect("full record path was just inserted")
        .to_owned();
    let object = item
        .as_object_mut()
        .ok_or_else(|| Error::engine("record projection is not an object"))?;
    let Some(reference) = reference else {
        object.insert("record_path".into(), json!(full_path));
        return Ok(());
    };
    object.insert("display_reference".into(), json!(reference.clone()));
    object.insert("record_path".into(), json!(format!("/{reference}")));
    Ok(())
}

pub(crate) async fn annotate_record_paths_batch(db: &Db, items: &mut [Value]) -> Result<()> {
    let ids: Vec<String> = items
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let references = batch_display_references(db, &ids).await?;
    for item in items {
        let Some(id) = item.get("id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        apply_record_path_with_reference(item, &id, references.get(&id).cloned().flatten())?;
    }
    Ok(())
}

/// Stamp the incoming-`supersedes` disclosure onto already-built record JSON —
/// the surfaces whose rows are shaped SQL projections rather than
/// `EnrichedRecord`s (query_record, dashboard, structure, search, scan).
///
/// Content (which successors exist, and their names) reads from
/// `content_pool`; visibility and short references resolve against
/// `auth_pool`, which is the live database whenever the content projection is
/// a historical replay. An invisible successor is counted in `total_count`
/// but never named. Records with no live successor are left untouched, so
/// their text renders byte-identical to before.
pub(crate) async fn annotate_superseded_by_in_pools(
    content_pool: &sqlx::SqlitePool,
    auth_pool: &sqlx::SqlitePool,
    caller: &Caller,
    records: &mut [Value],
) -> Result<()> {
    annotate_superseded_by_inner(content_pool, auth_pool, caller, records, true).await
}

/// World-preview variant: successor entries carry id and short reference but
/// not the title, keeping each preview item under its byte budget.
pub(crate) async fn annotate_superseded_refs_in_pools(
    content_pool: &sqlx::SqlitePool,
    auth_pool: &sqlx::SqlitePool,
    caller: &Caller,
    records: &mut [Value],
) -> Result<()> {
    annotate_superseded_by_inner(content_pool, auth_pool, caller, records, false).await
}

async fn annotate_superseded_by_inner(
    content_pool: &sqlx::SqlitePool,
    auth_pool: &sqlx::SqlitePool,
    caller: &Caller,
    records: &mut [Value],
    include_names: bool,
) -> Result<()> {
    // One statement for the whole row set, grouped in Rust: the rows
    // annotated here are already windowed (page, bucket, sample head), so
    // nothing fetched is discarded.
    let ids = records
        .iter()
        .filter_map(|record| record.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    let grouped = read::load_superseded_by_batch(content_pool, &ids).await?;
    let successor_ids = grouped
        .values()
        .flatten()
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let (visible, references): (
        std::collections::HashSet<String>,
        std::collections::HashMap<String, Option<String>>,
    ) = if successor_ids.is_empty() {
        Default::default()
    } else {
        // Q6c: a member copy ships its display references; never recompute a
        // slice-local prefix, which a hidden record could make too short.
        let references = if caller.is_member_copy() {
            member_display_references_in_pool(auth_pool, &successor_ids).await?
        } else {
            let borrowed: Vec<&str> = successor_ids.iter().map(String::as_str).collect();
            crate::mcp::record_ref::display_references_in_pool(auth_pool, &borrowed).await?
        };
        (
            super::visible_ids_in_pool(auth_pool, caller, successor_ids).await?,
            references,
        )
    };
    emit_superseded_by_annotations(records, &grouped, &visible, &references, include_names);
    Ok(())
}

/// Snapshot-scoped form of [`annotate_superseded_by_in_pools`]: content,
/// visibility and reference reads share the caller's transaction instead of
/// opening their own snapshots. Declared tab reads use this; existing
/// callers keep the pool form.
pub(crate) async fn annotate_superseded_by_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    records: &mut [Value],
) -> Result<()> {
    let ids = records
        .iter()
        .filter_map(|record| record.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    let grouped = read::load_superseded_by_batch(&mut **tx, &ids).await?;
    let successor_ids = grouped
        .values()
        .flatten()
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let (visible, references): (
        std::collections::HashSet<String>,
        std::collections::HashMap<String, Option<String>>,
    ) = if successor_ids.is_empty() {
        Default::default()
    } else {
        // Q6c: a member copy ships its display references; never recompute a
        // slice-local prefix, which a hidden record could make too short.
        let references = if caller.is_member_copy() {
            member_display_references_in_tx(tx, &successor_ids).await?
        } else {
            let borrowed: Vec<&str> = successor_ids.iter().map(String::as_str).collect();
            let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx);
            crate::mcp::record_ref::display_references_in(&mut executor, &borrowed).await?
        };
        (
            super::visible_ids_in(tx, caller, successor_ids).await?,
            references,
        )
    };
    emit_superseded_by_annotations(records, &grouped, &visible, &references, true);
    Ok(())
}

/// Pure emission for succession annotations: visibility first, truncation
/// second — an invisible head never hides a nameable tail. Records with no
/// live successor are left untouched, so their text renders byte-identical
/// to before. Shared by the pool and snapshot readers so the two cannot
/// drift apart.
fn emit_superseded_by_annotations(
    records: &mut [Value],
    grouped: &std::collections::HashMap<String, Vec<(String, String)>>,
    visible: &std::collections::HashSet<String>,
    references: &std::collections::HashMap<String, Option<String>>,
    include_names: bool,
) {
    for record in records.iter_mut() {
        let Some(id) = record.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(successors) = grouped.get(id) else {
            continue;
        };
        let mut items = Vec::new();
        for (successor_id, name) in successors
            .iter()
            .filter(|(successor_id, _)| visible.contains(successor_id))
            .take(read::MAX_SUPERSEDED_ITEMS)
        {
            let mut entry = serde_json::Map::with_capacity(3);
            entry.insert("id".into(), json!(successor_id));
            if include_names {
                entry.insert("name".into(), json!(name));
            }
            if let Some(reference) = references.get(successor_id).cloned().flatten() {
                entry.insert("display_reference".into(), json!(reference));
            }
            items.push(Value::Object(entry));
        }
        let Some(object) = record.as_object_mut() else {
            continue;
        };
        object.insert(
            "superseded_by".into(),
            json!({ "items": items, "total_count": successors.len() }),
        );
    }
}

/// Add the stable UUID root path on substrates that cannot mint short refs.
/// Returns false for caller-chosen ids outside the root record namespace.
pub(crate) fn annotate_full_record_path_for_item(item: &mut Value, id: &str) -> Result<bool> {
    let Ok(parsed_id) = uuid::Uuid::parse_str(id) else {
        return Ok(false);
    };
    let full_path = format!("/{parsed_id}");
    let object = item
        .as_object_mut()
        .ok_or_else(|| Error::engine("record projection is not an object"))?;
    object.insert("record_path_full".into(), json!(full_path.clone()));
    object.insert("record_path".into(), json!(full_path));
    Ok(true)
}

fn hide_attribution_batch_items(items: &mut [read::BatchGetItem]) {
    for item in items {
        let read::BatchGetItem::Found(record) = item else {
            continue;
        };
        if record.record.record_type == "Annotation"
            && record.record.kind.as_deref() == Some(crate::query::ATTRIBUTION_KIND)
        {
            let id = record.record.id.clone();
            *item = read::BatchGetItem::NotFound { id };
        }
    }
}

// ---------------------------------------------------------------------------
// Tool 7 — update_record
// ---------------------------------------------------------------------------

/// The mutable `records` fields `update_record` accepts, absent-vs-null
/// preserved (`Option<Value>`: absent = untouched, `null` = clear).
const UPDATABLE_FIELDS: [&str; 9] = [
    "name",
    "body",
    "kind",
    "home_id",
    "summary",
    "lifecycle",
    "owner_id",
    "persistence",
    "maturity",
];

/// Deserialize a field so that PRESENT-BUT-NULL survives as `Some(Null)`.
/// A plain `Option<Value>` folds `null` into `None` at the `Option` layer,
/// which would make "clear this field" indistinguishable from "leave it" —
/// `deserialize_with` only runs when the key is present, restoring the
/// absent-vs-null distinction the event payload needs.
fn present<'de, D>(deserializer: D) -> std::result::Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRecordArgs {
    id: String,
    /// Required (fbfaf25 §3.1).
    reason: String,
    /// Optional declared source basis, as on `create_record`. The batch form
    /// rejects it: one basis for many records is ambiguous and the batch skips
    /// no-op targets, so it is unclear which events would carry it.
    sources: Option<Vec<SourceBasisInput>>,
    #[serde(default, deserialize_with = "present")]
    name: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    body: Option<Value>,
    /// Explicit full replacement (string or null), matching legacy `body`.
    #[serde(default, deserialize_with = "present")]
    body_set: Option<Value>,
    /// Literal append of exactly the supplied string (null body reads as empty).
    #[serde(default, deserialize_with = "present")]
    body_append: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    kind: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    home_id: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    summary: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    lifecycle: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    owner_id: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    persistence: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    maturity: Option<Value>,
    body_replace: Option<Vec<BodyReplace>>,
    if_body_digest: Option<String>,
    if_unmodified_since: Option<String>,
    facets: Option<Map<String, Value>>,
    links: Option<Vec<NewLink>>,
    #[serde(default)]
    response_mode: ResponseMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiUpdateRecordArgs {
    ids: Vec<String>,
    reason: String,
    facets: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "present")]
    maturity: Option<Value>,
    home_id: Option<String>,
    if_facets: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "present")]
    if_maturity: Option<Value>,
    if_home_id: Option<String>,
}

#[derive(Clone)]
struct PreparedMultiUpdate {
    index: usize,
    id: String,
    fields: Map<String, Value>,
    facet_sets: Vec<FacetWrite>,
    facet_unsets: Vec<String>,
}

impl PreparedMultiUpdate {
    fn changed(&self) -> bool {
        !self.fields.is_empty() || !self.facet_sets.is_empty() || !self.facet_unsets.is_empty()
    }
}

struct MultiUpdateIssue {
    index: usize,
    id: String,
    classification: &'static str,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyReplace {
    old: String,
    new: String,
    expected_count: Option<usize>,
    replace_all: Option<bool>,
}

struct ContinuityBinding {
    port_name: String,
    collection_id: String,
    event_seq: i64,
}

struct ContinuityGrant {
    payload: ArtifactModuleGrantPayload,
    event_seq: i64,
}

struct ArtifactInputContinuitySnapshot {
    source_attestation_event_id: String,
    source_event_id: String,
    source_sha256: String,
    descriptor: Value,
    bindings: Vec<ContinuityBinding>,
    grants: Vec<ContinuityGrant>,
}

async fn snapshot_artifact_input_continuity(
    tx: &mut Transaction<'static, Sqlite>,
    artifact_id: &str,
) -> Result<Option<ArtifactInputContinuitySnapshot>> {
    let source = sqlx::query(
        "SELECT attestation_event_id,source_event_id,source_sha256,descriptor
           FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=(
            SELECT id FROM content_events
             WHERE record_id=? AND type IN ('record.created','record.updated','receipt.committed.v1')
               AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1)",
    )
    .bind(artifact_id)
    .bind(artifact_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(source) = source else {
        return Ok(None);
    };
    let source_attestation_event_id: String = source.try_get("attestation_event_id")?;
    let bindings = sqlx::query(
        "SELECT port_name,collection_id,event_seq FROM artifact_inputs
          WHERE artifact_id=? AND artifact_source_attestation_event_id=? ORDER BY port_name",
    )
    .bind(artifact_id)
    .bind(&source_attestation_event_id)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|row| {
        Ok(ContinuityBinding {
            port_name: row.try_get("port_name")?,
            collection_id: row.try_get("collection_id")?,
            event_seq: row.try_get("event_seq")?,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    let grant_rows = sqlx::query(
        "SELECT subject_kind,subject_record_id,subject_event_id,source_sha256,capability,
                scope_sha256,scope,event_seq FROM artifact_module_grants
          WHERE artifact_id=? AND artifact_source_attestation_event_id=?
          ORDER BY capability,subject_kind,subject_record_id,subject_event_id,
                   source_sha256,scope_sha256",
    )
    .bind(artifact_id)
    .bind(&source_attestation_event_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut grants = Vec::with_capacity(grant_rows.len());
    for row in grant_rows {
        grants.push(ContinuityGrant {
            payload: ArtifactModuleGrantPayload {
                artifact_id: artifact_id.to_owned(),
                subject_kind: row.try_get("subject_kind")?,
                subject_record_id: row.try_get("subject_record_id")?,
                subject_event_id: row.try_get("subject_event_id")?,
                source_sha256: row.try_get("source_sha256")?,
                capability: row.try_get("capability")?,
                scope: serde_json::from_str(&row.try_get::<String, _>("scope")?)?,
                scope_sha256: row.try_get("scope_sha256")?,
                attestation: None,
                attestation_sha256: None,
            },
            event_seq: row.try_get("event_seq")?,
        });
    }
    Ok(Some(ArtifactInputContinuitySnapshot {
        source_attestation_event_id,
        source_event_id: source.try_get("source_event_id")?,
        source_sha256: source.try_get("source_sha256")?,
        descriptor: serde_json::from_str(&source.try_get::<String, _>("descriptor")?)?,
        bindings,
        grants,
    }))
}

impl UpdateRecordArgs {
    fn field(&self, key: &str) -> &Option<Value> {
        match key {
            "name" => &self.name,
            "body" => &self.body,
            "kind" => &self.kind,
            "home_id" => &self.home_id,
            "summary" => &self.summary,
            "lifecycle" => &self.lifecycle,
            "owner_id" => &self.owner_id,
            "persistence" => &self.persistence,
            "maturity" => &self.maturity,
            other => unreachable!("unknown updatable field {other}"),
        }
    }
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// SHA-256 of the exact stored UTF-8 body bytes, with a NULL body hashed as the
/// empty string.
///
/// A record that has never carried a body stores NULL, which is the same
/// *content* as `""`. The `if_body_digest` write guard has always compared them
/// that way (see the shared `null_body_digest_guard` contract scenario), so the
/// read-side token has to agree: returning an absent field for a null body
/// would leave the first body a record ever receives unguardable, and would
/// make the token substrate-dependent for exactly the records where the guard
/// matters most.
pub fn body_digest(body: Option<&str>) -> String {
    sha256_hex(body.unwrap_or(""))
}

/// Stamp `body_digest` onto one ordinary record shape.
///
/// Deliberately applied at `get_record` and at the `create_record` and
/// `update_record` success responses only. `render_record`, `query_record`,
/// `scan` and the history surfaces are unchanged: a caller that read a body
/// through one of those does one `get_record` before a guarded write. The write
/// responses carry it so continuing guarded work never costs an extra read.
///
/// Always present for a readable record, never absent — a null or empty stored
/// body reports `sha256("")`, matching the write guard.
pub fn annotate_body_digest(record: &mut Value) {
    let Some(object) = record.as_object_mut() else {
        return;
    };
    if object
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status != "found")
    {
        return;
    }
    let digest = body_digest(object.get("body").and_then(Value::as_str));
    object.insert("body_digest".into(), json!(digest));
}

/// Stamp `source_event_id` onto a write receipt: the content-event id of the
/// body-bearing event this call created, next to the `body_digest` of that
/// same body. An artifact grant names exactly this value as `subject_event_id`,
/// so publishing it here (and in the grant-invalidation warning) means a
/// caller never has to provoke a failure to learn a required grant input.
///
/// Only called when the write actually created a body-bearing event. A write
/// that touched no body (facet-only edits, body-less creates) leaves the field
/// absent rather than naming a stale event.
fn annotate_source_event_id(receipt: &mut Value, source_event_id: Option<&str>) {
    let Some(source_event_id) = source_event_id else {
        return;
    };
    if let Some(object) = receipt.as_object_mut() {
        object.insert("source_event_id".into(), json!(source_event_id));
    }
}

/// Latest body-bearing content event for `record_id`, optionally bounded by a
/// pinned content sequence. Used only by idempotent-create replays, which must
/// return the original source identity. Historical reconstruction always
/// bounds the read at the attested horizon, irrespective of later writes.
async fn latest_body_event_id(
    db: &Db,
    record_id: &str,
    max_seq: Option<i64>,
) -> Result<Option<String>> {
    const BASE: &str = "SELECT id FROM content_events WHERE record_id=? \
        AND type IN ('record.created','record.updated','receipt.committed.v1') \
        AND json_type(payload,'$.body') IS NOT NULL";
    let row = if let Some(max_seq) = max_seq {
        sqlx::query(&format!("{BASE} AND seq<=? ORDER BY seq DESC LIMIT 1"))
            .bind(record_id)
            .bind(max_seq)
            .fetch_optional(db.write_pool())
            .await?
    } else {
        sqlx::query(&format!("{BASE} ORDER BY seq DESC LIMIT 1"))
            .bind(record_id)
            .fetch_optional(db.write_pool())
            .await?
    };
    match row {
        Some(row) => Ok(Some(row.try_get("id")?)),
        None => Ok(None),
    }
}

/// Everything a refusal needs to identify its target without returning the
/// body. Assembled inside the write transaction that observed the conflict;
/// rendered after that transaction has rolled back, so no error-formatting read
/// runs while a write lock is held.
pub struct BodyGuardTarget {
    pub id: String,
    pub name: Option<String>,
    /// Shortest resolvable abbreviation, where the substrate mints one at all.
    /// Postgres and Turso never do, and `where available` in the spec is that
    /// asymmetry, not an oversight.
    pub display_reference: Option<String>,
    pub body_digest: String,
    pub updated_at: String,
}

impl BodyGuardTarget {
    fn described(&self) -> String {
        let address = self.display_reference.as_deref().unwrap_or(&self.id);
        match self
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            Some(name) => format!("record {address} (\"{name}\")"),
            None => format!("record {address}"),
        }
    }

    /// Shared by all three refusals so a caller reads the same recovery
    /// instruction whichever precondition it tripped.
    fn state(&self) -> String {
        format!(
            "Current body_digest={}, updated_at={}. Reread the record, merge your change into \
             the current state, and retry with the current token.",
            self.body_digest, self.updated_at
        )
    }
}

/// A whole-body replacement arrived with no precondition against existing
/// content. Refused before any event is appended.
///
/// This is an ordinary engine error on purpose. The executor's repair channel
/// may only offer `corrections` for envelope-shaped validation
/// failures, and synthesising `if_body_digest` from current state would hand
/// the caller a token it never read — silently reproducing the lost update the
/// guard exists to prevent. Reconciliation is the caller's judgement.
pub fn unguarded_body_write_error(tool: &str, target: &BodyGuardTarget) -> Error {
    Error::engine(format!(
        "{tool}: unguarded whole-body write refused — {} already has a non-empty body, so 'body_set' \
         (or deprecated alias 'body') must be accompanied by 'if_body_digest' and/or 'if_unmodified_since' (both must match \
         when both are supplied). Nothing was written. {}",
        target.described(),
        target.state()
    ))
}

/// The supplied `if_body_digest` no longer describes the stored body.
pub fn stale_body_digest_error(tool: &str, target: &BodyGuardTarget) -> Error {
    Error::engine(format!(
        "{tool}: body digest conflict — the body of {} changed since the caller read it. Nothing \
         was written. {}",
        target.described(),
        target.state()
    ))
}

/// The supplied `if_unmodified_since` no longer describes the record.
///
/// `if_unmodified_since` is one of the two preconditions that admit a guarded
/// whole-body write, so this is a guard failure a caller can hit in place of
/// the digest conflict and it owes them the same legible content: the record
/// named, the current token and timestamp, and the next step.
///
/// It keeps its pre-existing `Error::conflict` class — the shared contract
/// scenarios pin that, and the record-wide precondition is older than this
/// guard. The class is immaterial to the repair prohibition: every tool failure
/// reaches the executor as `execution_error`, so `corrections` stays absent
/// and `retry_ready` false here exactly as for the other two.
pub fn stale_unmodified_since_error(tool: &str, target: &BodyGuardTarget) -> Error {
    Error::conflict(format!(
        "{tool}: stale write conflict — {} changed since the caller read it. Nothing was \
         written. {}",
        target.described(),
        target.state()
    ))
}

/// True when a whole-body replacement needs a precondition: `body` is present
/// (a string or an explicit null — clearing a written body is a destructive
/// replacement, not an exemption) and the stored body is non-empty.
pub fn whole_body_write_needs_guard(
    body_present: bool,
    current_body: Option<&str>,
    if_body_digest: Option<&str>,
    if_unmodified_since: Option<&str>,
) -> bool {
    body_present
        && current_body.is_some_and(|body| !body.is_empty())
        && if_body_digest.is_none()
        && if_unmodified_since.is_none()
}

/// Minimum partial-anchor length worth reporting on a zero-match
/// `body_replace`: shorter prefixes occur everywhere and re-anchor nothing.
const BODY_REPLACE_PARTIAL_PREFIX_MIN_CHARS: usize = 24;
/// Characters of body shown on each side of a zero-match partial anchor.
const BODY_REPLACE_ZERO_MATCH_WINDOW_CHARS: usize = 200;
/// Characters of body shown around each match on a count mismatch (split
/// evenly before and after the match).
const BODY_REPLACE_COUNT_MISMATCH_WINDOW_CHARS: usize = 80;
/// Cap on per-match contexts in a count-mismatch error; the total count is
/// always stated so the caller knows what was withheld.
const BODY_REPLACE_MAX_MATCH_CONTEXTS: usize = 10;
/// Cap on headings in a zero-match outline; the total is stated when more
/// exist, so a heading-heavy body cannot bloat the rejection.
const BODY_REPLACE_MAX_HEADINGS: usize = 20;
/// Characters shown per heading line; longer headings clip with `...`.
const BODY_REPLACE_MAX_HEADING_CHARS: usize = 120;

/// Floor a byte index to the nearest char boundary at or before it, so
/// window slicing never panics on multi-byte text.
fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// Ceil a byte index to the nearest char boundary at or after it, so window
/// slicing never panics on multi-byte text.
fn ceil_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// Up to `chars` characters of `body` immediately before `byte_index`,
/// with whether older text was clipped away. The index is floored to a char
/// boundary first; callers may pass raw match offsets freely.
fn window_before(body: &str, byte_index: usize, chars: usize) -> (String, bool) {
    let prefix = &body[..floor_char_boundary(body, byte_index)];
    let count = prefix.chars().count();
    if count <= chars {
        (prefix.to_string(), false)
    } else {
        (prefix.chars().skip(count - chars).collect(), true)
    }
}

/// Up to `chars` characters of `body` starting at `byte_index`, with whether
/// later text was clipped away. The index is ceiled to a char boundary
/// first; callers may pass raw match offsets freely.
fn window_after(body: &str, byte_index: usize, chars: usize) -> (String, bool) {
    let suffix = &body[ceil_char_boundary(body, byte_index)..];
    if suffix.chars().count() <= chars {
        (suffix.to_string(), false)
    } else {
        (suffix.chars().take(chars).collect(), true)
    }
}

/// Longest prefix of `old` (in characters, at least
/// [`BODY_REPLACE_PARTIAL_PREFIX_MIN_CHARS`]) that occurs in `body`, as
/// `(byte_offset, prefix_chars)`. Occurrence is monotone in the prefix
/// length — a match for length N contains one for length N-1 at the same
/// spot — so this binary-searches after pinning the minimum. Prefixes are
/// built from chars, never slicing `old` mid-codepoint.
fn longest_matching_prefix(old: &str, body: &str) -> Option<(usize, usize)> {
    let total = old.chars().count();
    if total < BODY_REPLACE_PARTIAL_PREFIX_MIN_CHARS {
        return None;
    }
    let prefix = |chars: usize| old.chars().take(chars).collect::<String>();
    if !body.contains(&prefix(BODY_REPLACE_PARTIAL_PREFIX_MIN_CHARS)) {
        return None;
    }
    let (mut low, mut high) = (BODY_REPLACE_PARTIAL_PREFIX_MIN_CHARS, total);
    while low < high {
        let mid = (low + high).div_ceil(2);
        if body.contains(&prefix(mid)) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    let matched = prefix(low);
    body.find(matched.as_str()).map(|offset| (offset, low))
}

/// `(byte_offset, heading)` for the `#` heading lines in `body`, so a caller
/// whose anchor matches nothing can re-anchor on structure without a full
/// re-read. Offsets are byte offsets into `body`. Capped at
/// [`BODY_REPLACE_MAX_HEADINGS`] headings of
/// [`BODY_REPLACE_MAX_HEADING_CHARS`] chars each (`...` marks clipping);
/// returns the shown entries plus the total heading count.
fn heading_outline(body: &str) -> (Vec<(usize, String)>, usize) {
    let mut outline = Vec::new();
    let mut total = 0;
    let mut offset = 0;
    for line in body.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        if text.starts_with('#') {
            total += 1;
            if outline.len() < BODY_REPLACE_MAX_HEADINGS {
                let clipped = text.chars().count() > BODY_REPLACE_MAX_HEADING_CHARS;
                let mut heading: String =
                    text.chars().take(BODY_REPLACE_MAX_HEADING_CHARS).collect();
                if clipped {
                    heading.push_str("...");
                }
                outline.push((offset, heading));
            }
        }
        offset += line.len();
    }
    (outline, total)
}

/// Byte offset plus an [`BODY_REPLACE_COUNT_MISMATCH_WINDOW_CHARS`]-char
/// window (half before, half after) per match, capped at
/// [`BODY_REPLACE_MAX_MATCH_CONTEXTS`] matches with the total stated, so the
/// caller can pick `expected_count` or a sharper anchor without re-reading.
fn match_contexts(body: &str, old: &str, count: usize) -> String {
    let mut contexts = String::new();
    let half = BODY_REPLACE_COUNT_MISMATCH_WINDOW_CHARS / 2;
    for (offset, matched) in body
        .match_indices(old)
        .take(BODY_REPLACE_MAX_MATCH_CONTEXTS)
    {
        let (before, clipped_before) = window_before(body, offset, half);
        let (after, clipped_after) = window_after(body, offset + matched.len(), half);
        contexts.push_str(&format!(
            "\n  match at byte offset {offset} \
             ({}-char context, `...` marks clipping): {}{}{}{}{}",
            BODY_REPLACE_COUNT_MISMATCH_WINDOW_CHARS,
            if clipped_before { "..." } else { "" },
            before,
            "[MATCH]",
            after,
            if clipped_after { "..." } else { "" },
        ));
    }
    if count > BODY_REPLACE_MAX_MATCH_CONTEXTS {
        contexts.push_str(&format!(
            "\n  showing first {BODY_REPLACE_MAX_MATCH_CONTEXTS} of {count} matches"
        ));
    }
    contexts
}

fn apply_body_replacements(tool: &str, body: &str, ops: &[BodyReplace]) -> Result<String> {
    if ops.is_empty() {
        return Err(Error::engine(format!(
            "{tool}: 'body_replace' must not be empty"
        )));
    }

    let mut result = body.to_string();
    for (index, op) in ops.iter().enumerate() {
        if op.old.is_empty() {
            return Err(Error::engine(format!(
                "{tool}: body_replace[{index}].old must not be empty"
            )));
        }
        if op.expected_count.is_some() && op.replace_all.is_some() {
            return Err(Error::engine(format!(
                "{tool}: body_replace[{index}] cannot set both expected_count and replace_all"
            )));
        }
        if op.expected_count == Some(0) {
            return Err(Error::engine(format!(
                "{tool}: body_replace[{index}].expected_count must be at least 1"
            )));
        }

        // `str::matches` counts non-overlapping occurrences, matching Rust's
        // `replace`/`replacen` semantics. The count and rewrite operate on the
        // same in-memory value, itself read under the write transaction.
        let count = result.matches(&op.old).count();
        if count == 0 {
            let mut message = format!("{tool}: body_replace[{index}].old matched 0 occurrences");
            match longest_matching_prefix(&op.old, &result) {
                Some((offset, prefix_chars)) => {
                    let prefix_len = op.old.chars().take(prefix_chars).collect::<String>().len();
                    let (before, clipped_before) =
                        window_before(&result, offset, BODY_REPLACE_ZERO_MATCH_WINDOW_CHARS);
                    let (after, clipped_after) = window_after(
                        &result,
                        offset + prefix_len,
                        BODY_REPLACE_ZERO_MATCH_WINDOW_CHARS,
                    );
                    message.push_str(&format!(
                        "\n  longest matching prefix of .old: {prefix_chars} chars \
                         at byte offset {offset}; \
                         {}-char window on each side (`...` marks clipping):\
                         \n  {}{}{}{}{}",
                        BODY_REPLACE_ZERO_MATCH_WINDOW_CHARS,
                        if clipped_before { "..." } else { "" },
                        before,
                        "[MATCH]",
                        after,
                        if clipped_after { "..." } else { "" },
                    ));
                }
                None => {
                    let (outline, total) = heading_outline(&result);
                    if outline.is_empty() {
                        message.push_str(&format!(
                            "\n  no prefix of .old ({}+ chars) occurs in the body, \
                             and the body has no `#` headings",
                            BODY_REPLACE_PARTIAL_PREFIX_MIN_CHARS,
                        ));
                    } else {
                        message.push_str(&format!(
                            "\n  no prefix of .old ({}+ chars) occurs in the body; \
                             heading outline (byte offset: heading):",
                            BODY_REPLACE_PARTIAL_PREFIX_MIN_CHARS,
                        ));
                        for (offset, heading) in outline {
                            message.push_str(&format!("\n    {offset}: {heading}"));
                        }
                        if total > BODY_REPLACE_MAX_HEADINGS {
                            message.push_str(&format!(
                                "\n  showing first {BODY_REPLACE_MAX_HEADINGS} of {total} headings"
                            ));
                        }
                    }
                }
            }
            return Err(Error::engine(message));
        }

        if let Some(expected) = op.expected_count {
            if count != expected {
                return Err(Error::engine(format!(
                    "{tool}: body_replace[{index}] expected {expected} occurrences but matched {count}{}",
                    match_contexts(&result, &op.old, count),
                )));
            }
            result = result.replace(&op.old, &op.new);
        } else if op.replace_all == Some(true) {
            result = result.replace(&op.old, &op.new);
        } else {
            if count != 1 {
                return Err(Error::engine(format!(
                    "{tool}: body_replace[{index}].old matched {count} occurrences; set replace_all: true or expected_count: {count}{}",
                    match_contexts(&result, &op.old, count),
                )));
            }
            result = result.replacen(&op.old, &op.new, 1);
        }
    }
    Ok(result)
}

fn validate_multi_maturity(tool: &str, field: &str, value: &Option<Value>) -> Result<()> {
    if let Some(value) = value {
        if !matches!(value, Value::String(_) | Value::Null) {
            return Err(Error::engine(format!(
                "{tool}: '{field}' must be a string or null"
            )));
        }
    }
    Ok(())
}

fn multi_update_rejection(
    requested: usize,
    unchanged: usize,
    issues: Vec<MultiUpdateIssue>,
) -> Error {
    let conflicted = issues
        .iter()
        .filter(|issue| issue.classification == "conflict")
        .count();
    let failed = issues.len() - conflicted;
    let omitted = issues
        .len()
        .saturating_sub(MAX_MULTI_UPDATE_FAILURE_DETAILS);
    let details = issues
        .into_iter()
        .take(MAX_MULTI_UPDATE_FAILURE_DETAILS)
        .collect::<Vec<_>>();
    let mut message = format!(
        "update_record: multi-target preflight rejected the atomic request; nothing was written; requested={requested}, changed=0, unchanged={unchanged}, conflicted={conflicted}, failed={failed}"
    );
    for issue in details {
        message.push_str(&format!(
            "\n  [{}] {} {}: {}",
            issue.index, issue.id, issue.classification, issue.message
        ));
    }
    if omitted > 0 {
        message.push_str(&format!(
            "\n  details truncated; omitted_detail_count={omitted}"
        ));
    }
    if failed == 0 {
        Error::conflict(message)
    } else {
        Error::engine(message)
    }
}

pub(super) async fn facet_state_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    key: &str,
) -> Result<Option<(String, Option<String>)>> {
    let row =
        sqlx::query("SELECT value, vocab_ref FROM facet_values WHERE record_id = ? AND key = ?")
            .bind(record_id)
            .bind(key)
            .fetch_optional(&mut **tx)
            .await?;
    row.map(|row| Ok((row.try_get("value")?, row.try_get("vocab_ref")?)))
        .transpose()
}

async fn update_record_multi(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "update_record";
    // `sources` is unsupported on the batch form in every shape. The parsed
    // field cannot see `sources: null` — serde folds it into `None`, which is
    // exactly the silent no-declaration collapse `reject_null_sources` exists
    // to prevent — so the check runs on the raw arguments, where null survives.
    // Every shape gets the same batch message: on this tool `sources` is
    // unsupported outright, so there is no `[]`-versus-null distinction to draw.
    if arguments.get("sources").is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: 'sources' is not supported on the batch form; call update_record once per record to declare a basis"
        )));
    }
    let args: MultiUpdateRecordArgs = parse_args(TOOL, arguments)?;
    require_nonblank_reason(TOOL, &args.reason)?;
    if args.ids.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'ids' must contain at least one record id"
        )));
    }
    if args.ids.len() > MAX_MULTI_UPDATE {
        return Err(Error::engine(format!(
            "{TOOL}: at most {MAX_MULTI_UPDATE} ids may be updated per call"
        )));
    }
    let mut positions = BTreeMap::new();
    for (index, id) in args.ids.iter().enumerate() {
        if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(id) {
            return Err(Error::engine(format!(
                "{TOOL}: ids[{index}] must be an exact canonical lowercase UUID of version 4 or 7"
            )));
        }
        if let Some(first) = positions.insert(id.as_str(), index) {
            return Err(Error::engine(format!(
                "{TOOL}: ids[{index}] duplicates ids[{first}]; multi-target ids must be unique"
            )));
        }
    }
    validate_multi_maturity(TOOL, "maturity", &args.maturity)?;
    validate_multi_maturity(TOOL, "if_maturity", &args.if_maturity)?;

    let facet_inputs = args.facets.as_ref().cloned().unwrap_or_default();
    if facet_inputs.is_empty() && args.maturity.is_none() && args.home_id.is_none() {
        return Err(Error::engine(format!(
            "{TOOL}: multi-target mode requires at least one non-empty facets patch, maturity, or home_id"
        )));
    }
    let mut facet_sets = Vec::new();
    let mut facet_unsets = Vec::new();
    for (key, value) in &facet_inputs {
        match parse_facet_entry(TOOL, key, value, true)? {
            Some(facet) => facet_sets.push(facet),
            None => facet_unsets.push(key.clone()),
        }
    }
    let expected_facet_inputs = args.if_facets.as_ref().cloned().unwrap_or_default();
    if args.if_facets.is_some() && expected_facet_inputs.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'if_facets' must not be empty when supplied"
        )));
    }
    let mut expected_facet_sets = Vec::new();
    let mut expected_facet_absent = Vec::new();
    for (key, value) in &expected_facet_inputs {
        match parse_facet_entry(TOOL, key, value, true)? {
            Some(facet) => expected_facet_sets.push(facet),
            None => expected_facet_absent.push(key.clone()),
        }
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    if let Some(new_home) = args.home_id.as_deref() {
        require_record_in(&mut tx, &caller, TOOL, new_home, Capability::Edit)
            .await
            .map_err(|_| {
                Error::engine(format!(
                    "{TOOL}: multi-target relocation home {new_home} is unavailable; nothing was written"
                ))
            })?;
        assert_home_target_in(&mut tx, TOOL, new_home).await?;
    }

    // Authorization is completed for the entire cohort before any event is
    // appended. Relocation can change inherited policy anchors, so checking as
    // we mutate would make authority depend on request order.
    let mut authorized = vec![false; args.ids.len()];
    let mut issues = Vec::new();
    for (index, id) in args.ids.iter().enumerate() {
        let current_home: Option<String> =
            sqlx::query_scalar("SELECT home_id FROM records WHERE id = ? AND deleted_at IS NULL")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .flatten();
        let relocates = args
            .home_id
            .as_deref()
            .is_some_and(|desired| current_home.as_deref() != Some(desired));
        let required = if relocates {
            Capability::Manage
        } else {
            Capability::Edit
        };
        match require_record_in(&mut tx, &caller, TOOL, id, required).await {
            Ok(()) => authorized[index] = true,
            Err(_) => issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "unavailable",
                message: "record is unavailable".into(),
            }),
        }
    }

    let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
    let touches_message_expectation =
        facet_inputs.contains_key(crate::message_expectation::EXPECTATION_FACET_KEY);
    let mut prepared = Vec::with_capacity(args.ids.len());
    let mut unchanged = 0usize;
    // Alias warnings per prepared target, correlated by request index like
    // `create_many`. Unsets stay quiet (only `facet_sets` are judged) and
    // kinds the governed relationship does not admit stay quiet.
    let mut batch_warnings = Vec::new();

    for (index, id) in args.ids.iter().enumerate() {
        if !authorized[index] {
            continue;
        }
        let row = sqlx::query(
            "SELECT type, kind, maturity, home_id FROM records WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "unavailable",
                message: "record is unavailable".into(),
            });
            continue;
        };
        let record_type: String = row.try_get("type")?;
        let kind: Option<String> = row.try_get("kind")?;
        let current_maturity: Option<String> = row.try_get("maturity")?;
        let current_home: Option<String> = row.try_get("home_id")?;

        if touches_message_expectation && record_type == "Message" {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "invalid",
                message: "Message expectation is immutable sender-authored content".into(),
            });
            continue;
        }

        let mut governed_sets = facet_sets.clone();
        if let Err(error) = assert_facet_value_predicates_in(
            &mut tx,
            &schema_rows,
            TOOL,
            &record_type,
            kind.as_deref(),
            None,
            &mut governed_sets,
        )
        .await
        {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "invalid",
                message: error.to_string(),
            });
            continue;
        }
        let mut governed_expected = expected_facet_sets.clone();
        if let Err(error) = assert_facet_value_predicates_in(
            &mut tx,
            &schema_rows,
            TOOL,
            &record_type,
            kind.as_deref(),
            None,
            &mut governed_expected,
        )
        .await
        {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "invalid",
                message: error.to_string(),
            });
            continue;
        }

        let mut conflict = None;
        for expected in &governed_expected {
            let current = facet_state_in(&mut tx, id, &expected.key).await?;
            let wanted = (expected.stored_value(), expected.vocab_ref.clone());
            if current.as_ref() != Some(&wanted) {
                conflict = Some(format!(
                    "facet '{}' no longer has the expected current value",
                    expected.key
                ));
                break;
            }
        }
        if conflict.is_none() {
            for key in &expected_facet_absent {
                if facet_state_in(&mut tx, id, key).await?.is_some() {
                    conflict = Some(format!("facet '{key}' is no longer absent"));
                    break;
                }
            }
        }
        if conflict.is_none() {
            if let Some(expected) = args.if_maturity.as_ref() {
                let matches = match expected {
                    Value::String(expected) => current_maturity.as_deref() == Some(expected),
                    Value::Null => current_maturity.is_none(),
                    _ => unreachable!("multi maturity validation ran before the transaction"),
                };
                if !matches {
                    conflict = Some("maturity no longer has the expected current value".into());
                }
            }
        }
        if conflict.is_none() {
            if let Some(expected) = args.if_home_id.as_deref() {
                if current_home.as_deref() != Some(expected) {
                    conflict = Some("home_id no longer has the expected current value".into());
                }
            }
        }
        if let Some(message) = conflict {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "conflict",
                message,
            });
            continue;
        }

        if let Some(new_home) = args.home_id.as_deref() {
            if new_home == id {
                issues.push(MultiUpdateIssue {
                    index,
                    id: id.clone(),
                    classification: "invalid",
                    message: "record cannot be its own home".into(),
                });
                continue;
            }
            let origin = sqlx::query(
                "SELECT status, origin_type, collection_id FROM message_origin_state WHERE message_id = ?",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
            if origin.as_ref().is_some_and(|origin| {
                origin.try_get::<String, _>("status").ok().as_deref() == Some("declared")
                    && origin
                        .try_get::<Option<String>, _>("origin_type")
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some("collection")
                    && origin
                        .try_get::<Option<String>, _>("collection_id")
                        .ok()
                        .flatten()
                        .as_deref()
                        != Some(new_home)
            }) {
                issues.push(MultiUpdateIssue {
                    index,
                    id: id.clone(),
                    classification: "invalid",
                    message:
                        "a Collection-origin Message must remain filed in its authored Collection"
                            .into(),
                });
                continue;
            }
            if let Err(error) = assert_no_containment_cycle_in(&mut tx, TOOL, id, new_home).await {
                issues.push(MultiUpdateIssue {
                    index,
                    id: id.clone(),
                    classification: "invalid",
                    message: error.to_string(),
                });
                continue;
            }
        }

        let mut changed_sets = Vec::new();
        for facet in governed_sets {
            let current = facet_state_in(&mut tx, id, &facet.key).await?;
            let desired = (facet.stored_value(), facet.vocab_ref.clone());
            if current.as_ref() != Some(&desired) {
                changed_sets.push(facet);
            }
        }
        let mut changed_unsets = Vec::new();
        for key in &facet_unsets {
            if facet_state_in(&mut tx, id, key).await?.is_some() {
                changed_unsets.push(key.clone());
            }
        }
        let mut fields = Map::new();
        if let Some(desired) = args.maturity.as_ref() {
            let changed = match desired {
                Value::String(desired) => current_maturity.as_deref() != Some(desired),
                Value::Null => current_maturity.is_some(),
                _ => unreachable!("multi maturity validation ran before the transaction"),
            };
            if changed {
                fields.insert("maturity".into(), desired.clone());
            }
        }
        if let Some(desired) = args.home_id.as_deref() {
            if current_home.as_deref() != Some(desired) {
                fields.insert("home_id".into(), json!(desired));
            }
        }
        let target = PreparedMultiUpdate {
            index,
            id: id.clone(),
            fields,
            facet_sets: changed_sets,
            facet_unsets: changed_unsets,
        };
        if !target.changed() {
            unchanged += 1;
        }
        // Warn on the requested sets with this target's kind, matching the
        // singular write: unsets never warn and ineligible kinds stay quiet.
        for warning in crate::domain_transaction::governed_alias_warnings_for_sets(
            &facet_sets,
            &record_type,
            kind.as_deref(),
        ) {
            batch_warnings.push(crate::domain_transaction::index_warning_for_batch(
                index, id, warning,
            ));
        }
        prepared.push(target);
    }

    if !issues.is_empty() {
        return Err(multi_update_rejection(args.ids.len(), unchanged, issues));
    }

    let id_refs = args.ids.iter().map(String::as_str).collect::<Vec<_>>();
    let before = required_violations_in(&mut tx, &schema_rows, &id_refs).await?;
    let changed = prepared.iter().filter(|target| target.changed()).count();
    for mut target in prepared.iter().filter(|target| target.changed()).cloned() {
        let field_event = !target.fields.is_empty();
        if field_event {
            target
                .fields
                .insert("reason".into(), json!(args.reason.clone()));
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: target.id.clone(),
                    event_type: "record.updated".into(),
                    payload: Value::Object(target.fields),
                    actor: Some(caller.actor().into()),
                },
                &mut act_alloc,
            )
            .await?;
        }
        let mut first_facet = true;
        for facet in target.facet_sets {
            let mut spec = facet_set_spec(&target.id, &facet, caller.actor());
            if !field_event && first_facet {
                spec.payload["reason"] = json!(args.reason.clone());
            }
            first_facet = false;
            append_in(&db, &mut tx, spec, &mut act_alloc).await?;
        }
        for key in target.facet_unsets {
            let mut payload = json!({ "key": key });
            if !field_event && first_facet {
                payload["reason"] = json!(args.reason.clone());
            }
            first_facet = false;
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: target.id.clone(),
                    event_type: "facet.unset".into(),
                    payload,
                    actor: Some(caller.actor().into()),
                },
                &mut act_alloc,
            )
            .await?;
        }
    }
    // Each projected home change already refreshes its subtree. Repeat the
    // refreshes after the complete cohort has reached its final graph so
    // inherited anchors cannot depend on the event order of related targets.
    for target in prepared
        .iter()
        .filter(|target| target.fields.contains_key("home_id"))
    {
        crate::authorization::refresh_policy_anchor_subtree(&mut tx, &target.id).await?;
    }
    let after = required_violations_in(&mut tx, &schema_rows, &id_refs).await?;
    assert_required_not_worsened(TOOL, &before, &after)?;
    db.commit_content(tx).await?;

    let results = prepared
        .into_iter()
        .map(|target| {
            json!({
                "index": target.index,
                "id": target.id,
                "status": if target.changed() { "changed" } else { "unchanged" },
            })
        })
        .collect::<Vec<_>>();
    // Alias warnings ride a top-level `warnings` array correlated by request
    // index, like `create_many`. The key is absent when nothing warned, so
    // existing receipts stay byte-identical.
    let mut batch_response = json!({
    "requested": args.ids.len(),
    "changed": changed,
    "unchanged": args.ids.len() - changed,
    "results": results,
    });
    if !batch_warnings.is_empty() {
        batch_response["warnings"] = Value::Array(batch_warnings);
    }
    echo_act(batch_response, act_alloc.get())
}

async fn update_record(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    if db.is_enrolled() {
        crate::db::enrolled::admit_body_arguments(&arguments)?;
        let job_db = db.clone();
        return crate::db::enrolled::document_job(db, async move {
            update_record_singular(job_db, caller, arguments).await
        })
        .await;
    }

    if arguments.get("ids").is_some() {
        Box::pin(update_record_multi(db, caller, arguments)).await
    } else {
        Box::pin(update_record_singular(db, caller, arguments)).await
    }
}

/// Narrow stage-1 session transaction consumer. The retained owner already
/// holds the lane and captured this snapshot; no recursive document_job.
pub(crate) struct PreparedSessionVersion {
    pub(crate) tx: Transaction<'static, Sqlite>,
    pub(crate) receipt: Value,
}

pub(crate) async fn prepare_session_version(
    db: &Db,
    caller: &Caller,
    cut: &crate::coedit::driver::CutSnapshot,
    mut tx: Transaction<'static, Sqlite>,
) -> Result<PreparedSessionVersion> {
    let prepared: Result<Value> = async {
        const PURPOSE: &str = "session.version";
        cut.validate(db, caller)?;
        let record = cut.record();
        let reason = cut.reason();
        let snapshot = cut.snapshot();
        crate::coedit::driver::authorize_supported(&mut tx, caller, PURPOSE, record, Capability::Edit).await?;
        require_nonblank_reason(PURPOSE, reason)?;
        let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
        let before = required_violations_in(&mut tx, &schema_rows, &[record]).await?;
        let mut act_alloc = crate::act::ActAllocation::new();
        let metadata = crate::coedit::version_metadata::VersionMetadata {
            contributors: snapshot.contributors(), session_ref: &snapshot.session_id().0,
            merged_offline: false,
        };
        let fields = json!({"body": snapshot.body(), "reason": reason}).as_object().expect("object").clone();
        let outcome = record_update_in(RecordUpdateInput {
            db, tx: &mut tx, act_alloc: &mut act_alloc, caller, tool: PURPOSE,
            record_id: record, fields, version_metadata: Some(&metadata),
            has_kind: false, has_lifecycle: false, has_summary: false,
            facet_specs: Vec::new(), facet_writes: &[], facet_unsets: &BTreeSet::new(),
            schema_rows: &schema_rows, links: &[], relationship_link_indexes: &BTreeSet::new(),
            before: &before,
        }).await?;
        crate::db::enrolled::phase(crate::db::enrolled::Phase::AfterAppend).await;
        #[cfg(test)]
        crate::coedit::driver::fail_at(crate::coedit::driver::TestFault::AfterAppend)?;
        let event = outcome.record_event.ok_or_else(|| Error::engine("session version did not append"))?;
        let version = current_record_version_in(&mut tx, record).await?;
        let payload: Value = serde_json::from_str(event.payload.as_deref().ok_or_else(|| Error::engine("session event payload missing"))?)?;
        echo_act(json!({"id":record, "session":snapshot.session_id().0,
            "event_id":event.id, "version":version, "body_digest":body_digest(Some(snapshot.body())),
            "contributors":payload["contributors"]}), act_alloc.get())
    }.await;
    match prepared {
        Ok(receipt) => Ok(PreparedSessionVersion { tx, receipt }),
        Err(error) => {
            crate::db::enrolled::phase(crate::db::enrolled::Phase::BeforeRollback).await;
            tx.rollback().await?;
            Err(error)
        }
    }
}

/// Input context for [`prospective_body_in`]: primitives only, so the helper
/// stays decoupled from `UpdateRecordArgs` and any tool schema.
struct ProspectiveBodyInput<'a> {
    tool: &'static str,
    record_id: &'a str,
    fields: &'a Map<String, Value>,
    has_kind: bool,
    has_lifecycle: bool,
    has_summary: bool,
    facet_unsets: &'a BTreeSet<String>,
    facet_writes: &'a [FacetWrite],
    schema_rows: &'a [cascade::SchemaConfigRow],
}

/// Owned prospective-tuple bindings consumed by the caller after validation.
/// Only bindings used later are returned: intermediates resolved wholly
/// inside the block (current_* row, suggestion flags, runtime, eligibility,
/// HTML manifest) stay local.
struct ProspectiveBody {
    record_type: String,
    resulting_kind: Option<String>,
    resulting_effective_kind: Option<String>,
    resulting_body: Option<String>,
    html_body_write: Option<Value>,
    updates_instruction_body: bool,
    artifact_attestation: Option<Value>,
    source_changed: bool,
    continuity_snapshot: Option<ArtifactInputContinuitySnapshot>,
    continuity_old_surface: Option<String>,
}

/// Prospective-tuple validation for an ordinary record update: current row
/// SELECT, kind resolution, suggestion lifecycle, program, comments, HTML,
/// artifact attestation, and continuity preflight, in the original order.
///
/// Scope: this helper is NOT a safe or complete version seam. It covers only
/// this block; CAS, tombstone, home, required-facet, guard-rollback, append,
/// continuity post-write, and embed stay caller-owned, and a future version
/// path must share that whole applicable path before writing. SQLite
/// ordinary-path only: the transaction-bound pieces cannot run on the
/// Postgres/Turso mirrors, so mirror parity is explicitly unfulfilled.
async fn prospective_body_in(
    tx: &mut Transaction<'static, Sqlite>,
    input: &ProspectiveBodyInput<'_>,
) -> Result<ProspectiveBody> {
    let tool = input.tool;
    let current = sqlx::query(
        "SELECT r.type, r.kind, r.body, r.lifecycle, r.summary, f.value AS runtime
           FROM records r
           LEFT JOIN facet_values f ON f.record_id = r.id AND f.key = 'runtime'
          WHERE r.id = ?",
    )
    .bind(input.record_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{tool}: record {} does not exist", input.record_id)))?;
    let record_type: String = current.try_get("type")?;
    let current_kind: Option<String> = current.try_get("kind")?;
    let current_body: Option<String> = current.try_get("body")?;
    let current_lifecycle: Option<String> = current.try_get("lifecycle")?;
    let current_summary: Option<String> = current.try_get("summary")?;
    let current_runtime: Option<String> = current.try_get("runtime")?;
    let resulting_kind = input
        .fields
        .get("kind")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| current_kind.clone());
    let resulting_effective_kind = if let Some(kind) = resulting_kind.as_deref() {
        let resolution = crate::meta::kind::resolve_on(&mut *tx, &record_type, kind).await?;
        Some(
            resolution
                .canonical_kind_for_write()
                .unwrap_or(kind)
                .to_string(),
        )
    } else {
        None
    };
    let resulting_body = match input.fields.get("body") {
        Some(Value::String(body)) => Some(body.clone()),
        Some(Value::Null) => None,
        _ => current_body.clone(),
    };
    let resulting_lifecycle = match input.fields.get("lifecycle") {
        Some(Value::String(lifecycle)) => Some(lifecycle.clone()),
        Some(Value::Null) => None,
        _ => current_lifecycle.clone(),
    };
    let resulting_summary = match input.fields.get("summary") {
        Some(Value::String(summary)) => Some(summary.clone()),
        Some(Value::Null) => None,
        _ => current_summary,
    };
    let current_is_comment = if let Some(kind) = current_kind.as_deref() {
        let resolution = crate::meta::kind::resolve_on(&mut *tx, &record_type, kind).await?;
        crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution)
    } else {
        false
    };
    let current_is_suggestion = if let Some(kind) = current_kind.as_deref() {
        let resolution = crate::meta::kind::resolve_on(&mut *tx, &record_type, kind).await?;
        crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(&resolution)
    } else {
        false
    };
    let resulting_is_suggestion = if let Some(kind) = resulting_kind.as_deref() {
        let resolution = crate::meta::kind::resolve_on(&mut *tx, &record_type, kind).await?;
        crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(&resolution)
    } else {
        false
    };
    if resulting_is_suggestion && input.has_lifecycle {
        if let Some(lifecycle) = resulting_lifecycle.as_deref() {
            let mut write = [FacetWrite {
                key: "lifecycle".into(),
                value: Value::String(lifecycle.into()),
                vocab_ref: None,
                time_type: None,
            }];
            assert_facet_value_predicates_in(
                &mut *tx,
                input.schema_rows,
                tool,
                "Annotation",
                Some("suggestion"),
                None,
                &mut write,
            )
            .await?;
        }
    }
    let current_lifecycle_is_active = if current_is_suggestion {
        if let Some(current_lifecycle) = current_lifecycle.as_deref() {
            let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut *tx);
            crate::domain_transaction::active_vocabulary_value(
                &mut executor,
                crate::meta::vocabulary::SUGGESTION_LIFECYCLE_VOCABULARY_ID,
                current_lifecycle,
            )
            .await?
        } else {
            false
        }
    } else {
        false
    };
    crate::suggestion_lifecycle::validate_update(
        tool,
        current_is_suggestion,
        resulting_is_suggestion,
        current_lifecycle.as_deref(),
        resulting_lifecycle.as_deref(),
        input.has_lifecycle,
        current_lifecycle_is_active,
    )?;
    let resulting_runtime = if input.facet_unsets.contains("runtime") {
        None
    } else {
        input
            .facet_writes
            .iter()
            .find(|facet| facet.key == "runtime")
            .map(FacetWrite::stored_value)
            .or(current_runtime.clone())
    };
    validate_prospective_program(
        tool,
        &record_type,
        resulting_kind.as_deref(),
        resulting_runtime.as_deref(),
    )?;
    crate::comments::validate_update_on(
        &mut *tx,
        tool,
        input.record_id,
        &record_type,
        current_kind.as_deref(),
        resulting_kind.as_deref(),
        resulting_body.as_deref(),
        current_lifecycle.as_deref(),
        resulting_lifecycle.as_deref(),
        resulting_summary.as_deref(),
        input.has_kind,
        input.has_lifecycle,
        input.has_summary,
    )
    .await?;
    if current_is_comment && (input.has_kind || input.has_lifecycle) {
        if let Some(lifecycle) = resulting_lifecycle.as_deref() {
            let mut write = [FacetWrite {
                key: "lifecycle".into(),
                value: Value::String(lifecycle.into()),
                vocab_ref: None,
                time_type: None,
            }];
            assert_facet_value_predicates_in(
                &mut *tx,
                input.schema_rows,
                tool,
                &record_type,
                resulting_effective_kind.as_deref(),
                None,
                &mut write,
            )
            .await?;
        }
    }
    let html_manifest = super::artifacts::validate_prospective_html(
        tool,
        &record_type,
        resulting_kind.as_deref(),
        resulting_runtime.as_deref(),
        resulting_body.as_deref(),
    )?;
    let html_body_write = html_manifest
        .map(|manifest| html_body_write_result(&manifest, resulting_body.as_deref().unwrap()));
    let updates_instruction_body = input.fields.contains_key("body");
    let artifact_attestation = super::artifacts::validate_prospective_artifact(
        input.record_id,
        &record_type,
        resulting_kind.as_deref(),
        resulting_body.as_deref(),
        resulting_runtime.as_deref(),
    )
    .await?;
    let source_changed = input.fields.get("body").is_some();
    let continuity_eligible = source_changed
        && artifact_attestation.is_some()
        && record_type == "Document"
        && current_kind.as_deref() == Some("artifact")
        && current_runtime
            .as_deref()
            .is_some_and(super::artifacts::supports_named_input_runtime);
    let continuity_snapshot = if continuity_eligible {
        snapshot_artifact_input_continuity(&mut *tx, input.record_id).await?
    } else {
        None
    };
    let continuity_old_surface = if continuity_eligible {
        if let Some(snapshot) = continuity_snapshot.as_ref() {
            Some(super::artifacts::declaration_surface_sha256(
                &snapshot.descriptor,
            )?)
        } else {
            let current_compiler = super::artifacts::validate_prospective_artifact(
                input.record_id,
                &record_type,
                current_kind.as_deref(),
                current_body.as_deref(),
                current_runtime.as_deref(),
            )
            .await?
            .ok_or_else(|| Error::engine("current v2 artifact attestation is missing"))?;
            Some(super::artifacts::declaration_surface_sha256(
                &current_compiler,
            )?)
        }
    } else {
        None
    };
    Ok(ProspectiveBody {
        record_type,
        resulting_kind,
        resulting_effective_kind,
        resulting_body,
        html_body_write,
        updates_instruction_body,
        artifact_attestation,
        source_changed,
        continuity_snapshot,
        continuity_old_surface,
    })
}
// Dormant S3-A prerequisite. No registry/dispatcher calls this module. S3-B
// must supply install admission, replay, membership, gesture and commit; none
// of these private prepared values is an authorization credential.
#[allow(dead_code)]
mod body_effect_preparation {
    use super::*;
    use native_artifact_runtime::artifact_intents::{
        AlphaTabInstallGuard, ArtifactIntentResult, ArtifactInvocation, IntentChange,
        INTENT_RESULT_VERSION, INVOCATION_VERSION,
    };

    const TOOL: &str = "artifact.body.prepare";
    const BODY_BYTES: usize = native_artifact_runtime::mdx_v2::BODY_SET_MAX_BODY_BYTES; // Provisional, independent of encoded limits.
    const BODY_ENCODED_BYTES: usize = 4 * 1024 * 1024;
    const ORIGIN_SCHEMA: &str = "native.body-effect-origin.v1";
    const SEMANTIC_SCHEMA: &str = "native.body-effect-semantic.v1";

    fn refuse(code: &str) -> Error {
        Error::engine(format!("{TOOL}: {code}"))
    }

    fn identity(value: &str) -> Result<()> {
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(refuse("invalid_identity"));
        }
        Ok(())
    }

    fn digest(value: &str) -> Result<()> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(refuse("invalid_digest"));
        }
        Ok(())
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum BodyValue {
        Null,
        Text(String),
    }

    impl BodyValue {
        fn from_nullable(value: Option<String>) -> Self {
            value.map_or(Self::Null, Self::Text)
        }

        fn as_nullable(&self) -> Option<&str> {
            match self {
                Self::Null => None,
                Self::Text(text) => Some(text),
            }
        }

        fn json(&self) -> Value {
            match self {
                Self::Null => Value::Null,
                Self::Text(text) => json!(text),
            }
        }

        fn qualify(&self) -> Result<()> {
            if self
                .as_nullable()
                .is_some_and(|text| text.len() > BODY_BYTES)
            {
                return Err(refuse("body_or_inverse_oversize"));
            }
            Ok(())
        }

        fn summary(&self) -> BodySummary {
            match self {
                Self::Null => BodySummary::Null {},
                Self::Text(text) => BodySummary::Text {
                    sha256: body_digest(Some(text)),
                    utf8_bytes: text.len() as u64,
                },
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum BodySummary {
        Null {},
        Text { sha256: String, utf8_bytes: u64 },
    }

    impl BodySummary {
        fn validate(&self) -> Result<()> {
            if let Self::Text { sha256, utf8_bytes } = self {
                digest(sha256)?;
                if *utf8_bytes > BODY_BYTES as u64 {
                    return Err(refuse("summary_oversize"));
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EventRef {
        event_id: String,
        seq: i64,
        event_type: String,
    }

    impl EventRef {
        fn validate(&self) -> Result<()> {
            identity(&self.event_id)?;
            if self.seq <= 0
                || !matches!(
                    self.event_type.as_str(),
                    "record.created"
                        | "record.updated"
                        | "receipt.committed.v1"
                        | "unit.revision.recorded.v1"
                )
            {
                return Err(refuse("invalid_history_reference"));
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SourceIdentity {
        artifact_id: String,
        source_digest: String,
        entry_id: String,
        record_id: String,
    }

    impl SourceIdentity {
        fn validate(&self) -> Result<()> {
            for value in [&self.artifact_id, &self.entry_id, &self.record_id] {
                identity(value)?;
            }
            if self.record_id.len() > 128 {
                return Err(refuse("target_oversize"));
            }
            digest(&self.source_digest)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reverses {
        event_id: String,
        seq: i64,
        entry_id: String,
        idempotency_key: String,
    }

    impl Reverses {
        fn validate(&self) -> Result<()> {
            for value in [&self.event_id, &self.entry_id, &self.idempotency_key] {
                identity(value)?;
            }
            if self.seq <= 0 {
                return Err(refuse("invalid_reverse_reference"));
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum BodyGestureKind {
        Click,
        Drop,
        Key,
        Grant,
    }

    impl<'de> Deserialize<'de> for BodyGestureKind {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            match String::deserialize(deserializer)?.as_str() {
                "click" => Ok(Self::Click),
                "drop" => Ok(Self::Drop),
                "key" => Ok(Self::Key),
                "grant" => Ok(Self::Grant),
                _ => Err(serde::de::Error::custom("invalid body gesture kind")),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    enum BodyGestureVerifier {
        #[serde(rename = "effect_gesture.v1")]
        EffectGestureV1,
    }

    impl<'de> Deserialize<'de> for BodyGestureVerifier {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            match String::deserialize(deserializer)?.as_str() {
                "effect_gesture.v1" => Ok(Self::EffectGestureV1),
                _ => Err(serde::de::Error::custom("invalid body gesture verifier")),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BodyGestureEvidence {
        kind: BodyGestureKind,
        verifier: BodyGestureVerifier,
    }

    fn present_audit<'de, D>(
        deserializer: D,
    ) -> std::result::Result<Option<BodyGestureEvidence>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        BodyGestureEvidence::deserialize(deserializer).map(Some)
    }

    fn verified_audit(value: Value) -> Result<BodyGestureEvidence> {
        serde_json::from_value(value).map_err(|_| refuse("body_gesture_evidence"))
    }

    fn largest_audit() -> BodyGestureEvidence {
        BodyGestureEvidence {
            kind: BodyGestureKind::Click,
            verifier: BodyGestureVerifier::EffectGestureV1,
        }
    }

    // Explicit fields, not flatten/Value: cross-variant keys are forbidden.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SaveOrigin {
        schema: String,
        artifact_id: String,
        source_digest: String,
        entry_id: String,
        record_id: String,
        idempotency_key: String,
        semantic_digest: String,
        admission_pins: AlphaTabInstallGuard,
        before: BodySummary,
        after: BodySummary,
        expected_body_digest: String,
        creation: EventRef,
        inverse: EventRef,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_audit"
        )]
        gesture_evidence: Option<BodyGestureEvidence>,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct UndoOrigin {
        schema: String,
        artifact_id: String,
        source_digest: String,
        entry_id: String,
        record_id: String,
        idempotency_key: String,
        semantic_digest: String,
        admission_pins: AlphaTabInstallGuard,
        before: BodySummary,
        after: BodySummary,
        reverses: Reverses,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "present_audit"
        )]
        gesture_evidence: Option<BodyGestureEvidence>,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    enum BodyOrigin {
        Save(SaveOrigin),
        Undo(UndoOrigin),
    }

    impl BodyOrigin {
        fn source(&self) -> SourceIdentity {
            let (artifact_id, source_digest, entry_id, record_id) = match self {
                Self::Save(o) => (&o.artifact_id, &o.source_digest, &o.entry_id, &o.record_id),
                Self::Undo(o) => (&o.artifact_id, &o.source_digest, &o.entry_id, &o.record_id),
            };
            SourceIdentity {
                artifact_id: artifact_id.clone(),
                source_digest: source_digest.clone(),
                entry_id: entry_id.clone(),
                record_id: record_id.clone(),
            }
        }

        fn key(&self) -> &str {
            match self {
                Self::Save(o) => &o.idempotency_key,
                Self::Undo(o) => &o.idempotency_key,
            }
        }

        fn summaries(&self) -> (&BodySummary, &BodySummary) {
            match self {
                Self::Save(o) => (&o.before, &o.after),
                Self::Undo(o) => (&o.before, &o.after),
            }
        }

        fn validate(&self) -> Result<()> {
            self.source().validate()?;
            identity(self.key())?;
            let (schema, semantic, pins) = match self {
                Self::Save(o) => {
                    digest(&o.expected_body_digest)?;
                    o.creation.validate()?;
                    o.inverse.validate()?;
                    if o.creation.event_type != "record.created" || o.creation.seq > o.inverse.seq {
                        return Err(refuse("invalid_creation_reference"));
                    }
                    (&o.schema, &o.semantic_digest, &o.admission_pins)
                }
                Self::Undo(o) => {
                    o.reverses.validate()?;
                    (&o.schema, &o.semantic_digest, &o.admission_pins)
                }
            };
            if schema != ORIGIN_SCHEMA || pins.artifact_id != self.source().artifact_id {
                return Err(refuse("invalid_origin_binding"));
            }
            digest(semantic)?;
            pins.validate_shape().map_err(refuse)?;
            let (before, after) = self.summaries();
            before.validate()?;
            after.validate()
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    enum BodySemantic {
        Save {
            schema: String,
            actor: String,
            version: String,
            artifact_id: String,
            entry_id: String,
            source_digest: String,
            record_id: String,
            scope_port: String,
            idempotency_key: String,
            body: String,
            expected_body_digest: String,
            alpha_install_guard: AlphaTabInstallGuard,
        },
        Undo {
            schema: String,
            actor: String,
            version: String,
            artifact_id: String,
            entry_id: String,
            source_digest: String,
            record_id: String,
            idempotency_key: String,
            reverses: Reverses,
            original_semantic_digest: String,
        },
    }

    impl BodySemantic {
        fn source(&self) -> SourceIdentity {
            let (artifact_id, entry_id, source_digest, record_id) = match self {
                Self::Save {
                    artifact_id,
                    entry_id,
                    source_digest,
                    record_id,
                    ..
                }
                | Self::Undo {
                    artifact_id,
                    entry_id,
                    source_digest,
                    record_id,
                    ..
                } => (artifact_id, entry_id, source_digest, record_id),
            };
            SourceIdentity {
                artifact_id: artifact_id.clone(),
                entry_id: entry_id.clone(),
                source_digest: source_digest.clone(),
                record_id: record_id.clone(),
            }
        }

        fn key(&self) -> &str {
            match self {
                Self::Save {
                    idempotency_key, ..
                }
                | Self::Undo {
                    idempotency_key, ..
                } => idempotency_key,
            }
        }

        fn validate(&self, caller: &Caller) -> Result<()> {
            self.source().validate()?;
            identity(self.key())?;
            let (schema, actor, version) = match self {
                Self::Save {
                    schema,
                    actor,
                    version,
                    body,
                    scope_port,
                    expected_body_digest,
                    alpha_install_guard,
                    ..
                } => {
                    identity(scope_port)?;
                    digest(expected_body_digest)?;
                    BodyValue::Text(body.clone()).qualify()?;
                    alpha_install_guard.validate_shape().map_err(refuse)?;
                    if alpha_install_guard.artifact_id != self.source().artifact_id {
                        return Err(refuse("invalid_guard_binding"));
                    }
                    (schema, actor, version)
                }
                Self::Undo {
                    schema,
                    actor,
                    version,
                    reverses,
                    original_semantic_digest,
                    ..
                } => {
                    reverses.validate()?;
                    digest(original_semantic_digest)?;
                    if reverses.entry_id != self.source().entry_id {
                        return Err(refuse("invalid_reverse_binding"));
                    }
                    (schema, actor, version)
                }
            };
            if schema != SEMANTIC_SCHEMA || actor != caller.actor() || version != INVOCATION_VERSION
            {
                return Err(refuse("invalid_semantic_binding"));
            }
            identity(actor)
        }

        fn canonical_digest(&self, caller: &Caller) -> Result<String> {
            self.validate(caller)?;
            let bytes = serde_jcs::to_vec(self).map_err(|_| refuse("semantic_encoding"))?;
            Ok(format!("{:x}", Sha256::digest(bytes)))
        }
    }

    // serde_json::Value erases duplicates. Reject them recursively BEFORE
    // typed deserialization, including nested admission pins and summaries.
    struct UniqueJson(Value);

    impl<'de> Deserialize<'de> for UniqueJson {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = UniqueJson;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("unique-key JSON")
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    v: bool,
                ) -> std::result::Result<UniqueJson, E> {
                    Ok(UniqueJson(json!(v)))
                }
                fn visit_i64<E: serde::de::Error>(
                    self,
                    v: i64,
                ) -> std::result::Result<UniqueJson, E> {
                    Ok(UniqueJson(json!(v)))
                }
                fn visit_u64<E: serde::de::Error>(
                    self,
                    v: u64,
                ) -> std::result::Result<UniqueJson, E> {
                    Ok(UniqueJson(json!(v)))
                }
                fn visit_f64<E: serde::de::Error>(
                    self,
                    v: f64,
                ) -> std::result::Result<UniqueJson, E> {
                    serde_json::Number::from_f64(v)
                        .map(|n| UniqueJson(Value::Number(n)))
                        .ok_or_else(|| E::custom("nonfinite JSON"))
                }
                fn visit_str<E: serde::de::Error>(
                    self,
                    v: &str,
                ) -> std::result::Result<UniqueJson, E> {
                    Ok(UniqueJson(json!(v)))
                }
                fn visit_string<E: serde::de::Error>(
                    self,
                    v: String,
                ) -> std::result::Result<UniqueJson, E> {
                    Ok(UniqueJson(Value::String(v)))
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<UniqueJson, E> {
                    Ok(UniqueJson(Value::Null))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<UniqueJson, A::Error> {
                    let mut values = Vec::new();
                    while let Some(UniqueJson(v)) = seq.next_element()? {
                        values.push(v);
                    }
                    Ok(UniqueJson(Value::Array(values)))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<UniqueJson, A::Error> {
                    let mut values = Map::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if values.contains_key(&key) {
                            return Err(serde::de::Error::custom("duplicate JSON key"));
                        }
                        let UniqueJson(value) = map.next_value()?;
                        values.insert(key, value);
                    }
                    Ok(UniqueJson(Value::Object(values)))
                }
            }
            deserializer.deserialize_any(Visitor)
        }
    }

    fn parse_origin(text: &str) -> Result<BodyOrigin> {
        if text.len() > 262_144 {
            return Err(refuse("origin_oversize"));
        }
        let UniqueJson(value) = serde_json::from_str(text).map_err(|_| refuse("origin_json"))?;
        let origin: BodyOrigin =
            serde_json::from_value(value).map_err(|_| refuse("origin_shape"))?;
        origin.validate()?;
        Ok(origin)
    }

    fn parse_semantic(text: &str, caller: &Caller) -> Result<BodySemantic> {
        if text.len() > BODY_ENCODED_BYTES {
            return Err(refuse("semantic_oversize"));
        }
        let UniqueJson(value) = serde_json::from_str(text).map_err(|_| refuse("semantic_json"))?;
        let semantic: BodySemantic =
            serde_json::from_value(value).map_err(|_| refuse("semantic_shape"))?;
        semantic.validate(caller)?;
        Ok(semantic)
    }

    #[derive(Debug)]
    struct PreparedSnapshot {
        target: String,
        current_body: BodyValue,
        current_rec: i64,
        creation_ref: EventRef,
        inverse_ref: EventRef,
        before_summary: BodySummary,
    }

    struct PreparedBodyWrite {
        snapshot: PreparedSnapshot,
        semantic: BodySemantic,
        audit: Option<BodyGestureEvidence>,
        origin: BodyOrigin,
        resulting_body: BodyValue,
        fields: Map<String, Value>,
        schema_rows: Vec<cascade::SchemaConfigRow>,
        before: BTreeSet<RequiredViolation>,
    }

    struct AppliedBodyWrite {
        event: crate::events::EventRow,
        receipt: ArtifactIntentResult,
        payload_bytes: usize,
        event_bytes: usize,
        prospective_undo_payload_bytes: Option<usize>,
    }

    fn refuse_enrolled(db: &Db) -> Result<()> {
        if db.is_enrolled() {
            return Err(refuse("enrolled_unsupported"));
        }
        Ok(())
    }

    async fn target_in(
        db: &Db,
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        target: &str,
    ) -> Result<BodyValue> {
        refuse_enrolled(db)?;
        identity(target)?;
        if target.len() > 128 || target.starts_with("native:") {
            return Err(refuse("unsupported_target"));
        }
        require_record_in(tx, caller, TOOL, target, Capability::View).await?;
        require_record_in(tx, caller, TOOL, target, Capability::Edit).await?;
        let row = sqlx::query("SELECT type,kind,deleted_at,
            EXISTS(SELECT 1 FROM facet_values WHERE record_id=r.id AND key='runtime') AS runtime_present,
            length(CAST(body AS BLOB)) AS body_bytes,
            CASE WHEN length(CAST(body AS BLOB))<=? THEN body ELSE NULL END AS body
            FROM records r WHERE id=?")
            .bind(BODY_BYTES as i64).bind(target).fetch_optional(&mut **tx).await?.ok_or_else(|| refuse("unsupported_target"))?;
        if row.try_get::<String, _>("type")? != "Document"
            || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
            || row.try_get::<bool, _>("runtime_present")?
        {
            return Err(refuse("unsupported_target"));
        }
        if let Some(kind) = row.try_get::<Option<String>, _>("kind")? {
            let resolved = crate::meta::kind::resolve_on(tx, "Document", &kind).await?;
            if kind == "artifact"
                || kind == "instruction"
                || crate::generated::kinds::CoreKind::DocumentArtifact.matches(&resolved)
                || resolved.canonical_kind.as_deref() == Some("instruction")
            {
                return Err(refuse("unsupported_target"));
            }
            crate::freshness::reject_reserved_semantic_unit_kind(&kind, TOOL)?;
        }
        if crate::instructions::source_is_active_in(tx, target).await? {
            return Err(refuse("instruction_source"));
        }
        if row
            .try_get::<Option<i64>, _>("body_bytes")?
            .is_some_and(|n| n > BODY_BYTES as i64)
        {
            return Err(refuse("body_or_inverse_oversize"));
        }
        Ok(BodyValue::from_nullable(row.try_get("body")?))
    }

    // No raw payload crosses the SQL cell boundary. BLOB lengths count UTF8
    // bytes even across NUL; SQLite text length would truncate that proof.
    // Malformed candidate families participate in selection and then refuse.
    async fn history_in(
        tx: &mut Transaction<'static, Sqlite>,
        target: &str,
        through: i64,
    ) -> Result<(EventRef, EventRef, BodyValue)> {
        let creations: i64 = sqlx::query_scalar("SELECT count(*) FROM
            (SELECT seq FROM content_events WHERE record_id=? AND type='record.created' AND seq<=? LIMIT 2)")
            .bind(target).bind(through).fetch_one(&mut **tx).await?;
        if creations != 1 {
            return Err(refuse("creation_missing_or_ambiguous"));
        }
        let creation_row = sqlx::query("SELECT id,seq,type,
            CASE WHEN json_valid(payload) THEN json_type(payload) ELSE 'invalid' END AS root_type,
            CASE WHEN json_valid(payload) THEN (SELECT count(*) FROM json_each(payload) WHERE key='body') ELSE 0 END AS body_keys
            FROM content_events WHERE record_id=? AND type='record.created' AND seq<=? LIMIT 1")
            .bind(target).bind(through).fetch_one(&mut **tx).await?;
        if creation_row.try_get::<String, _>("root_type")? != "object"
            || creation_row.try_get::<i64, _>("body_keys")? > 1
        {
            return Err(refuse("malformed_creation"));
        }
        let creation = EventRef {
            event_id: creation_row.try_get("id")?,
            seq: creation_row.try_get("seq")?,
            event_type: creation_row.try_get("type")?,
        };
        let row = sqlx::query("WITH candidate AS (
            SELECT id,seq,type,payload FROM content_events WHERE record_id=? AND seq<=?
            AND type IN ('record.created','record.updated','receipt.committed.v1','unit.revision.recorded.v1')
            AND CASE WHEN json_valid(payload) THEN
                CASE WHEN json_type(payload)='object' THEN
                    type IN ('record.created','unit.revision.recorded.v1') OR json_type(payload,'$.body') IS NOT NULL
                ELSE 1 END ELSE 1 END
            ORDER BY seq DESC LIMIT 1
        ), classified AS (
            SELECT id,seq,type,payload,
            CASE WHEN json_valid(payload) THEN json_type(payload) ELSE 'invalid' END AS root_type,
            CASE WHEN json_valid(payload) THEN
                CASE WHEN type='unit.revision.recorded.v1' THEN json_type(payload,'$.content.content') ELSE json_type(payload,'$.body') END
            ELSE 'invalid' END AS body_type
            FROM candidate
        ), fragments AS (
            SELECT *, CASE WHEN body_type='text' THEN
                CASE WHEN type='unit.revision.recorded.v1' THEN json_extract(payload,'$.content.content') ELSE json_extract(payload,'$.body') END
            END AS fragment FROM classified
        ) SELECT id,seq,type,root_type,body_type,
            CASE WHEN body_type='text' THEN length(CAST(fragment AS BLOB)) END AS body_bytes,
            CASE WHEN body_type='text' AND length(CAST(fragment AS BLOB))<=? THEN fragment END AS body,
            CASE WHEN root_type='object' THEN
                (SELECT count(*) FROM json_each(payload) WHERE key=CASE WHEN f.type='unit.revision.recorded.v1' THEN 'content' ELSE 'body' END)
            ELSE 0 END AS key_count,
            CASE WHEN root_type='object' AND type='unit.revision.recorded.v1' AND json_type(payload,'$.content')='object' THEN
                (SELECT count(*) FROM json_each(payload,'$.content') WHERE key='content')
            ELSE 0 END AS nested_count,
            CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' AND body_type='text'
                AND length(CAST(fragment AS BLOB))<=?
                AND length(CAST(payload -> '$.content' AS BLOB))<=? THEN payload -> '$.content' END AS unit_content,
            CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' AND json_type(payload,'$.format')='text'
                AND length(CAST(json_extract(payload,'$.format') AS BLOB))<=256 THEN
                json_extract(payload,'$.format') END AS unit_format,
            CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' AND json_type(payload,'$.semantic_contract_version')='text'
                AND length(CAST(json_extract(payload,'$.semantic_contract_version') AS BLOB))<=256 THEN
                json_extract(payload,'$.semantic_contract_version') END AS unit_semantic,
            CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' AND json_type(payload,'$.content_sha256')='text'
                AND length(CAST(json_extract(payload,'$.content_sha256') AS BLOB))=64 THEN
                json_extract(payload,'$.content_sha256') END AS unit_sha256,
            CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' THEN
                (SELECT count(*)=3 AND count(DISTINCT key)=3 FROM json_each(payload)
                    WHERE key IN ('format','semantic_contract_version','content_sha256'))
            ELSE 0 END AS unit_headers_valid
            FROM fragments AS f")
            .bind(target).bind(through).bind(BODY_BYTES as i64).bind(BODY_BYTES as i64).bind(BODY_ENCODED_BYTES as i64).fetch_optional(&mut **tx).await?.ok_or_else(|| refuse("inverse_missing"))?;
        let reference = EventRef {
            event_id: row.try_get("id")?,
            seq: row.try_get("seq")?,
            event_type: row.try_get("type")?,
        };
        creation.validate()?;
        reference.validate()?;
        if reference.seq < creation.seq || row.try_get::<String, _>("root_type")? != "object" {
            return Err(refuse("malformed_history"));
        }
        let kind: Option<String> = row.try_get("body_type")?;
        let keys: i64 = row.try_get("key_count")?;
        let unit = reference.event_type == "unit.revision.recorded.v1";
        if keys > 1 || (unit && (keys != 1 || row.try_get::<i64, _>("nested_count")? != 1)) {
            return Err(refuse("malformed_history"));
        }
        let body = match kind.as_deref() {
            None if reference.event_type == "record.created" && keys == 0 => BodyValue::Null,
            Some("null") if !unit && keys == 1 => BodyValue::Null,
            Some("text") if keys == 1 => {
                let bytes: i64 = row.try_get("body_bytes")?;
                if bytes > BODY_BYTES as i64 {
                    return Err(refuse("body_or_inverse_oversize"));
                }
                let text: String = row.try_get("body")?;
                if text.len() as i64 != bytes {
                    return Err(refuse("history_transport_incomplete"));
                }
                BodyValue::Text(text)
            }
            _ => return Err(refuse("malformed_history")),
        };
        if unit {
            let content_json: String = row.try_get("unit_content")?;
            let UniqueJson(value) = serde_json::from_str(&content_json)
                .map_err(|_| refuse("malformed_unit_content"))?;
            let content: crate::freshness::UnitContent =
                serde_json::from_value(value).map_err(|_| refuse("malformed_unit_content"))?;
            content.validate()?;
            if body.as_nullable() != Some(content.content.as_str())
                || !row.try_get::<bool, _>("unit_headers_valid")?
                || row.try_get::<Option<String>, _>("unit_format")?.as_deref()
                    != Some(crate::freshness::UNIT_REVISION_FORMAT)
                || row
                    .try_get::<Option<String>, _>("unit_semantic")?
                    .as_deref()
                    != Some(crate::freshness::SEMANTIC_CONTRACT_VERSION)
                || row.try_get::<Option<String>, _>("unit_sha256")?.as_deref()
                    != Some(content.sha256().as_str())
            {
                return Err(refuse("malformed_unit_content"));
            }
        }
        Ok((creation, reference, body))
    }

    async fn prepare_snapshot_in(
        db: &Db,
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        target: &str,
    ) -> Result<PreparedSnapshot> {
        refuse_enrolled(db)?;
        let current_body = target_in(db, tx, caller, target).await?;
        let current_rec = current_record_version_in(tx, target).await?;
        let (creation_ref, inverse_ref, historical) = history_in(tx, target, current_rec).await?;
        if historical != current_body {
            return Err(refuse("history_projection_mismatch"));
        }
        Ok(PreparedSnapshot {
            target: target.into(),
            before_summary: current_body.summary(),
            current_body,
            current_rec,
            creation_ref,
            inverse_ref,
        })
    }

    fn receipt(origin: &BodyOrigin, seq: i64) -> Result<ArtifactIntentResult> {
        if seq <= 0 {
            return Err(refuse("invalid_receipt_seq"));
        }
        origin.validate()?;
        let (before, after) = origin.summaries();
        let result = ArtifactIntentResult::Committed {
            version: INTENT_RESULT_VERSION.into(),
            idempotency_key: origin.key().into(),
            refresh: None,
            changes: vec![IntentChange {
                record_id: origin.source().record_id,
                key: "body".into(),
                before: Some(serde_json::to_value(before)?),
                after: Some(serde_json::to_value(after)?),
                version: Some(format!("rec:{seq}")),
            }],
        };
        result.validate_shape().map_err(refuse)?;
        // Real public result serializer, not an excerpt or a new ActResult.
        serde_json::to_vec(&result)?;
        Ok(result)
    }

    // Use the actual public invocation value validator (its bounded-value
    // helper is private). This is shape preflight ONLY, never admission.
    fn encoded_values(semantic: &BodySemantic, values: BTreeMap<String, Value>) -> Result<()> {
        let source = semantic.source();
        let invocation = ArtifactInvocation {
            version: INVOCATION_VERSION.into(),
            artifact_id: source.artifact_id,
            entry_id: source.entry_id,
            source_digest: source.source_digest,
            slots: BTreeMap::new(),
            values,
            observed: BTreeMap::new(),
            idempotency_key: semantic.key().into(),
            gesture: None,
            include_next_plan: false,
            alpha_install_guard: None,
            reverses: None,
        };
        invocation.validate_shape().map_err(refuse)
    }

    fn ordinary_fields(body: &BodyValue, origin: &BodyOrigin) -> Result<Map<String, Value>> {
        let mut fields = Map::new();
        fields.insert("body".into(), body.json());
        fields.insert("origin".into(), serde_json::to_value(origin)?);
        fields.insert(
            "reason".into(),
            json!(match origin {
                BodyOrigin::Save(_) => "explicit artifact body save",
                BodyOrigin::Undo(_) => "explicit artifact body undo",
            }),
        );
        crate::coedit::version_metadata::record_updated_payload(fields, None)
    }

    async fn original_in(
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        semantic: &BodySemantic,
    ) -> Result<SaveOrigin> {
        let BodySemantic::Undo {
            reverses,
            original_semantic_digest,
            ..
        } = semantic
        else {
            return Err(refuse("undo_shape"));
        };
        let source = semantic.source();
        let row = sqlx::query("SELECT actor,
            CASE WHEN json_valid(payload) AND length(CAST(payload -> '$.origin' AS BLOB))<=262144 THEN payload -> '$.origin' END AS origin,
            CASE WHEN json_valid(payload) THEN (SELECT count(*) FROM json_each(payload) WHERE key='origin') ELSE 0 END AS origin_count,
            CASE WHEN json_valid(payload) THEN (SELECT count(*) FROM json_each(payload) WHERE key='body') ELSE 0 END AS body_count,
            CASE WHEN json_valid(payload) THEN json_type(payload,'$.body') END AS body_type,
            CASE WHEN json_valid(payload) AND json_type(payload,'$.body')='text' THEN length(CAST(json_extract(payload,'$.body') AS BLOB)) END AS body_bytes,
            CASE WHEN json_valid(payload) AND json_type(payload,'$.body')='text' AND length(CAST(json_extract(payload,'$.body') AS BLOB))<=? THEN json_extract(payload,'$.body') END AS body
            FROM content_events WHERE id=? AND seq=? AND record_id=? AND type='record.updated'")
            .bind(BODY_BYTES as i64).bind(&reverses.event_id).bind(reverses.seq).bind(&source.record_id).fetch_optional(&mut **tx).await?.ok_or_else(|| refuse("original_missing"))?;
        if row.try_get::<Option<String>, _>("actor")?.as_deref() != Some(caller.actor())
            || row.try_get::<i64, _>("origin_count")? != 1
            || row.try_get::<i64, _>("body_count")? != 1
        {
            return Err(refuse("original_actor"));
        }
        let origin_text: String = row.try_get("origin")?;
        let BodyOrigin::Save(origin) = parse_origin(&origin_text)? else {
            return Err(refuse("undo_of_undo"));
        };
        if BodyOrigin::Save(origin.clone()).source() != source
            || origin.idempotency_key != reverses.idempotency_key
            || &origin.semantic_digest != original_semantic_digest
            || row.try_get::<Option<String>, _>("body_type")?.as_deref() != Some("text")
            || row
                .try_get::<Option<i64>, _>("body_bytes")?
                .is_none_or(|n| n > BODY_BYTES as i64)
        {
            return Err(refuse("original_binding"));
        }
        let after = BodyValue::Text(row.try_get("body")?);
        if after.summary() != origin.after {
            return Err(refuse("original_after"));
        }
        Ok(origin)
    }

    // Conservative typed encoding witness, NOT an allocated future event or
    // runnable Undo. Quotes bound permitted identity escaping; max seq bounds
    // width. Actual postappend EventRow and inverse checks remain mandatory.
    fn preflight_prospective_undo_encoding(
        caller: &Caller,
        snapshot: &PreparedSnapshot,
        original: &SaveOrigin,
    ) -> Result<usize> {
        let reverses = Reverses {
            event_id: "\"".repeat(256),
            seq: i64::MAX,
            entry_id: original.entry_id.clone(),
            idempotency_key: original.idempotency_key.clone(),
        };
        let semantic = BodySemantic::Undo {
            schema: SEMANTIC_SCHEMA.into(),
            actor: caller.actor().into(),
            version: INVOCATION_VERSION.into(),
            artifact_id: original.artifact_id.clone(),
            source_digest: original.source_digest.clone(),
            entry_id: original.entry_id.clone(),
            record_id: original.record_id.clone(),
            idempotency_key: "\"".repeat(256),
            reverses: reverses.clone(),
            original_semantic_digest: original.semantic_digest.clone(),
        };
        let origin = BodyOrigin::Undo(UndoOrigin {
            schema: ORIGIN_SCHEMA.into(),
            artifact_id: original.artifact_id.clone(),
            source_digest: original.source_digest.clone(),
            entry_id: original.entry_id.clone(),
            record_id: original.record_id.clone(),
            idempotency_key: semantic.key().into(),
            semantic_digest: semantic.canonical_digest(caller)?,
            admission_pins: original.admission_pins.clone(),
            before: original.after.clone(),
            after: original.before.clone(),
            reverses,
            gesture_evidence: Some(largest_audit()),
        });
        origin.validate()?;
        let payload = crate::domain_transaction::normalize_event_payload(
            &snapshot.target,
            "record.updated",
            Value::Object(ordinary_fields(&snapshot.current_body, &origin)?),
        );
        encoded_values(
            &semantic,
            BTreeMap::from([
                ("prospective_undo".into(), payload.clone()),
                ("origin".into(), serde_json::to_value(&origin)?),
            ]),
        )?;
        receipt(&origin, i64::MAX)?;
        Ok(serde_json::to_vec(&payload)?.len())
    }

    async fn prepare_body_write_in(
        db: &Db,
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        snapshot: PreparedSnapshot,
        semantic: BodySemantic,
        audit: Option<BodyGestureEvidence>,
    ) -> Result<PreparedBodyWrite> {
        refuse_enrolled(db)?;
        semantic.validate(caller)?;
        if semantic.source().record_id != snapshot.target {
            return Err(refuse("target_diverge"));
        }
        let fresh = prepare_snapshot_in(db, tx, caller, &snapshot.target).await?;
        if fresh.current_rec != snapshot.current_rec
            || fresh.current_body != snapshot.current_body
            || fresh.before_summary != snapshot.before_summary
            || fresh.creation_ref != snapshot.creation_ref
            || fresh.inverse_ref != snapshot.inverse_ref
        {
            return Err(refuse("prepared_snapshot_stale"));
        }
        let source = semantic.source();
        let semantic_digest = semantic.canonical_digest(caller)?;
        let (resulting_body, origin) = match &semantic {
            BodySemantic::Save {
                body,
                expected_body_digest,
                alpha_install_guard,
                ..
            } => {
                if expected_body_digest != &body_digest(snapshot.current_body.as_nullable()) {
                    return Err(refuse("body_digest_conflict"));
                }
                let resulting = BodyValue::Text(body.clone());
                let origin = BodyOrigin::Save(SaveOrigin {
                    schema: ORIGIN_SCHEMA.into(),
                    artifact_id: source.artifact_id,
                    source_digest: source.source_digest,
                    entry_id: source.entry_id,
                    record_id: source.record_id,
                    idempotency_key: semantic.key().into(),
                    semantic_digest,
                    admission_pins: alpha_install_guard.clone(),
                    before: snapshot.before_summary.clone(),
                    after: resulting.summary(),
                    expected_body_digest: expected_body_digest.clone(),
                    creation: snapshot.creation_ref.clone(),
                    inverse: snapshot.inverse_ref.clone(),
                    gesture_evidence: audit.clone(),
                });
                (resulting, origin)
            }
            BodySemantic::Undo { reverses, .. } => {
                let original = original_in(tx, caller, &semantic).await?;
                if snapshot.current_rec != reverses.seq || snapshot.before_summary != original.after
                {
                    return Err(refuse("undo_record_conflict"));
                }
                let (creation, inverse, body) =
                    history_in(tx, &snapshot.target, reverses.seq - 1).await?;
                if creation != original.creation
                    || inverse != original.inverse
                    || body.summary() != original.before
                {
                    return Err(refuse("inverse_binding"));
                }
                let origin = BodyOrigin::Undo(UndoOrigin {
                    schema: ORIGIN_SCHEMA.into(),
                    artifact_id: source.artifact_id,
                    source_digest: source.source_digest,
                    entry_id: source.entry_id,
                    record_id: source.record_id,
                    idempotency_key: semantic.key().into(),
                    semantic_digest,
                    admission_pins: original.admission_pins,
                    before: snapshot.before_summary.clone(),
                    after: body.summary(),
                    reverses: reverses.clone(),
                    gesture_evidence: audit.clone(),
                });
                (body, origin)
            }
        };
        snapshot.current_body.qualify()?;
        resulting_body.qualify()?;
        origin.validate()?;
        let fields = ordinary_fields(&resulting_body, &origin)?;
        let normalized = crate::domain_transaction::normalize_event_payload(
            &snapshot.target,
            "record.updated",
            Value::Object(fields.clone()),
        );
        let mut values = BTreeMap::from([
            ("origin".into(), serde_json::to_value(&origin)?),
            ("ordinary_payload".into(), normalized),
            ("inverse".into(), snapshot.current_body.json()),
        ]);
        // The runtime deliberately forbids a null invocation value. NULL is
        // qualified by its tagged summary instead, not coerced into text.
        if snapshot.current_body == BodyValue::Null {
            values.insert("inverse".into(), json!({"kind":"null"}));
        }
        encoded_values(&semantic, values)?;
        receipt(&origin, i64::MAX)?; // Real receipt shape at maximum seq width.
        if let BodyOrigin::Save(original) = &origin {
            preflight_prospective_undo_encoding(caller, &snapshot, original)?;
        }
        let schema_rows = cascade::schema_config_rows_in(tx).await?;
        let before = required_violations_in(tx, &schema_rows, &[&snapshot.target]).await?;
        let prospective = prospective_body_in(
            tx,
            &ProspectiveBodyInput {
                tool: TOOL,
                record_id: &snapshot.target,
                fields: &fields,
                has_kind: false,
                has_lifecycle: false,
                has_summary: false,
                facet_unsets: &BTreeSet::new(),
                facet_writes: &[],
                schema_rows: &schema_rows,
            },
        )
        .await?;
        if BodyValue::from_nullable(prospective.resulting_body) != resulting_body {
            return Err(refuse("prospective_diverge"));
        }
        Ok(PreparedBodyWrite {
            snapshot,
            semantic,
            audit,
            origin,
            resulting_body,
            fields,
            schema_rows,
            before,
        })
    }

    // No commit, replay, dispatch or public authority. On ANY Err the caller
    // must roll back the entire transaction, including possible private append.
    async fn apply_prepared_body_in(
        db: &Db,
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        act_alloc: &mut crate::act::ActAllocation,
        prepared: PreparedBodyWrite,
    ) -> Result<AppliedBodyWrite> {
        refuse_enrolled(db)?;
        // Reprepare rather than trusting cached schema/ACL/required checks.
        let prepared = prepare_body_write_in(
            db,
            tx,
            caller,
            prepared.snapshot,
            prepared.semantic,
            prepared.audit,
        )
        .await?;
        let outcome = record_update_in(RecordUpdateInput {
            db,
            tx,
            act_alloc,
            caller,
            tool: TOOL,
            record_id: &prepared.snapshot.target,
            fields: prepared.fields,
            version_metadata: None,
            has_kind: false,
            has_lifecycle: false,
            has_summary: false,
            facet_specs: Vec::new(),
            facet_writes: &[],
            facet_unsets: &BTreeSet::new(),
            schema_rows: &prepared.schema_rows,
            links: &[],
            relationship_link_indexes: &BTreeSet::new(),
            before: &prepared.before,
        })
        .await?;
        let event = outcome
            .record_event
            .ok_or_else(|| refuse("body_append_missing"))?;
        let payload: Value = serde_json::from_str(
            event
                .payload
                .as_deref()
                .ok_or_else(|| refuse("body_payload_missing"))?,
        )?;
        if payload.get("body") != Some(&prepared.resulting_body.json())
            || payload.get("origin") != Some(&serde_json::to_value(&prepared.origin)?)
        {
            return Err(refuse("body_append_diverge"));
        }
        encoded_values(
            &prepared.semantic,
            BTreeMap::from([("ordinary_payload".into(), payload.clone())]),
        )?;
        let result = receipt(&prepared.origin, event.local_seq)?;
        let event_bytes = serde_json::to_vec(&event)?.len(); // Actual append envelope.
        let mut prospective_undo_payload_bytes = None;
        if let BodyOrigin::Save(original) = &prepared.origin {
            // Prospective Undo uses the REAL closed variant and original refs.
            // Future key is bounded256 bytes; quotes maximize permitted JSON
            // escaping. This is an encoding bound, not a runnable Undo command.
            let reverses = Reverses {
                event_id: event.id.clone(),
                seq: event.local_seq,
                entry_id: original.entry_id.clone(),
                idempotency_key: original.idempotency_key.clone(),
            };
            let inverse_semantic = BodySemantic::Undo {
                schema: SEMANTIC_SCHEMA.into(),
                actor: caller.actor().into(),
                version: INVOCATION_VERSION.into(),
                artifact_id: original.artifact_id.clone(),
                source_digest: original.source_digest.clone(),
                entry_id: original.entry_id.clone(),
                record_id: original.record_id.clone(),
                idempotency_key: "\"".repeat(256),
                reverses: reverses.clone(),
                original_semantic_digest: original.semantic_digest.clone(),
            };
            let inverse_origin = BodyOrigin::Undo(UndoOrigin {
                schema: ORIGIN_SCHEMA.into(),
                artifact_id: original.artifact_id.clone(),
                source_digest: original.source_digest.clone(),
                entry_id: original.entry_id.clone(),
                record_id: original.record_id.clone(),
                idempotency_key: inverse_semantic.key().into(),
                semantic_digest: inverse_semantic.canonical_digest(caller)?,
                admission_pins: original.admission_pins.clone(),
                before: original.after.clone(),
                after: original.before.clone(),
                reverses,
                // Encoding allowance only, never actual future provenance.
                gesture_evidence: Some(largest_audit()),
            });
            let inverse_fields = ordinary_fields(&prepared.snapshot.current_body, &inverse_origin)?;
            let inverse_payload = crate::domain_transaction::normalize_event_payload(
                &prepared.snapshot.target,
                "record.updated",
                Value::Object(inverse_fields),
            );
            encoded_values(
                &prepared.semantic,
                BTreeMap::from([("prospective_undo".into(), inverse_payload.clone())]),
            )?;
            receipt(&inverse_origin, i64::MAX)?;
            prospective_undo_payload_bytes = Some(serde_json::to_vec(&inverse_payload)?.len());
        }
        Ok(AppliedBodyWrite {
            event,
            receipt: result,
            payload_bytes: serde_json::to_vec(&payload)?.len(),
            event_bytes,
            prospective_undo_payload_bytes,
        })
    }

    /// Dormant command facade, never a prepared-authority credential.
    #[derive(Clone, Debug)]
    pub(crate) struct ArtifactBodySavePlan {
        pub invocation: ArtifactInvocation,
        pub source_event_id: String,
    }

    #[derive(Debug)]
    pub(crate) enum ArtifactBodyOutcome {
        Committed { receipt: Box<ArtifactIntentResult> },
        Refused { code: String, message: String },
    }

    enum Attempt {
        Append(ArtifactIntentResult),
        Replay(ArtifactIntentResult),
        Refused { code: String, message: String },
    }

    async fn structural_in(tx: &mut Transaction<'static, Sqlite>) -> Result<()> {
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut **tx)
            .await?;
        if version != crate::db::CURRENT_ENGINE_SCHEMA_VERSION
            || !crate::db::validate_engine_shape_on(tx, version).await?
        {
            return Err(refuse("structural_admission"));
        }
        Ok(())
    }

    // Fixed bounded full payload; no projected/excerpt receipt or unbounded cell.
    async fn candidates_in(
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        artifact: &str,
        entry: &str,
        key: &str,
    ) -> Result<Vec<(String, String, i64, String)>> {
        let rows = sqlx::query("SELECT id,record_id,seq,type,
            CASE WHEN length(CAST(payload AS BLOB))<=? THEN payload END AS payload
            FROM content_events WHERE actor=?
            AND CASE WHEN json_valid(payload) THEN json_extract(payload,'$.origin.artifact_id')=? ELSE 0 END
            AND CASE WHEN json_valid(payload) THEN json_extract(payload,'$.origin.entry_id')=? ELSE 0 END
            AND CASE WHEN json_valid(payload) THEN json_extract(payload,'$.origin.idempotency_key')=? ELSE 0 END
            ORDER BY seq LIMIT 2")
            .bind(BODY_ENCODED_BYTES as i64).bind(caller.actor()).bind(artifact).bind(entry).bind(key).fetch_all(&mut **tx).await?;
        if rows.len() > 1 {
            return Err(refuse("idempotency_conflict"));
        }
        rows.into_iter()
            .map(|row| {
                if row.try_get::<String, _>("type")? != "record.updated" {
                    return Err(refuse("body_original_type"));
                }
                let payload = row
                    .try_get::<Option<String>, _>("payload")?
                    .ok_or_else(|| refuse("body_stored_oversize"))?;
                Ok((
                    row.try_get("id")?,
                    row.try_get("record_id")?,
                    row.try_get("seq")?,
                    payload,
                ))
            })
            .collect()
    }

    fn stored_origin(payload: &str, target: &str) -> Result<(BodyOrigin, BodyValue)> {
        let UniqueJson(value) =
            serde_json::from_str(payload).map_err(|_| refuse("body_stored_json"))?;
        let origin = parse_origin(&serde_json::to_string(
            value
                .get("origin")
                .ok_or_else(|| refuse("body_origin_missing"))?,
        )?)?;
        if origin.source().record_id != target {
            return Err(refuse("body_stored_target"));
        }
        let stored_body = match value.get("body") {
            Some(Value::String(text)) => BodyValue::Text(text.clone()),
            Some(Value::Null) => BodyValue::Null,
            _ => return Err(refuse("body_stored_value")),
        };
        stored_body.qualify()?;
        if stored_body.summary() != *origin.summaries().1 {
            return Err(refuse("body_stored_summary"));
        }
        Ok((origin, stored_body))
    }

    // A stored digest string is not proof of its operation fields. Rebuild
    // Save identity from the actual caller, immutable parsed entry and exact
    // stored value before replay or Undo relies on that digest.
    fn stored_save_digest(
        caller: &Caller,
        entry: &mdx_v2::InteractionEntry,
        saved: &SaveOrigin,
        stored_body: &BodyValue,
    ) -> Result<String> {
        let BodyValue::Text(body) = stored_body else {
            return Err(refuse("body_stored_value"));
        };
        let semantic = BodySemantic::Save {
            schema: SEMANTIC_SCHEMA.into(),
            actor: caller.actor().into(),
            version: INVOCATION_VERSION.into(),
            artifact_id: saved.artifact_id.clone(),
            entry_id: saved.entry_id.clone(),
            source_digest: saved.source_digest.clone(),
            record_id: saved.record_id.clone(),
            scope_port: body_port(entry)?.into(),
            idempotency_key: saved.idempotency_key.clone(),
            body: body.clone(),
            expected_body_digest: saved.expected_body_digest.clone(),
            alpha_install_guard: saved.admission_pins.clone(),
        };
        let digest = semantic.canonical_digest(caller)?;
        if digest != saved.semantic_digest {
            return Err(refuse("idempotency_conflict"));
        }
        Ok(digest)
    }

    async fn pinned_entry_in(
        tx: &mut Transaction<'static, Sqlite>,
        pins: &AlphaTabInstallGuard,
        source_digest: &str,
        entry_id: &str,
    ) -> Result<mdx_v2::InteractionEntry> {
        let source: String = sqlx::query_scalar::<_, Option<String>>(
            "SELECT CASE WHEN json_valid(payload)
            AND json_type(payload,'$.body')='text'
            AND length(CAST(json_extract(payload,'$.body') AS BLOB))<=524288
            AND (SELECT count(*) FROM json_each(payload) WHERE key='body')=1
            THEN json_extract(payload,'$.body') END
            FROM content_events WHERE id=? AND record_id=?
            AND type IN ('record.created','record.updated','receipt.committed.v1')",
        )
        .bind(&pins.source_revision)
        .bind(&pins.artifact_id)
        .fetch_optional(&mut **tx)
        .await?
        .flatten()
        .ok_or_else(|| refuse("body_source_missing"))?;
        if super::super::alpha_tabs::alpha_tab_bundle_digest(&source) != source_digest {
            return Err(refuse("body_source_digest"));
        }
        let manifest = crate::artifact_html::validate_cached(&source)
            .map_err(|_| refuse("body_source_not_html"))?
            .interaction_manifest();
        let entry = manifest
            .interaction(entry_id)
            .cloned()
            .ok_or_else(|| refuse("body_entry_missing"))?;
        if entry.effect != mdx_v2::InteractionEffect::BodySet || entry.body.is_none() {
            return Err(refuse("body_entry_mismatch"));
        }
        body_port(&entry)?;
        Ok(entry)
    }

    fn body_port(entry: &mdx_v2::InteractionEntry) -> Result<&str> {
        if entry.slots.len() != 1 {
            return Err(refuse("body_slot_shape"));
        }
        match &entry
            .slots
            .values()
            .next()
            .ok_or_else(|| refuse("body_slot_shape"))?
            .domain
        {
            mdx_v2::SlotDomain::BoundInput { port: Some(port) }
                if !port.is_empty() && port != "default" =>
            {
                Ok(port)
            }
            _ => Err(refuse("body_slot_shape")),
        }
    }

    async fn view_in(
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        artifact: &str,
        target: &str,
    ) -> Result<()> {
        require_record_in(tx, caller, TOOL, artifact, Capability::View).await?;
        require_record_in(tx, caller, TOOL, target, Capability::View).await
    }

    // Capture optional verified origin audit, never semantic identity.
    // Activation, required enforcement and reader rollout remain held.
    fn gesture(
        caller: &Caller,
        invocation: &ArtifactInvocation,
        target: &str,
        undo: bool,
    ) -> Result<Option<BodyGestureEvidence>> {
        let action = if undo {
            crate::awareness::EFFECT_GESTURE_REVERSAL_ACTION
        } else {
            crate::awareness::EFFECT_GESTURE_ACTION
        };
        let package = if undo {
            None
        } else {
            invocation
                .alpha_install_guard
                .as_ref()
                .map(|g| ("alpha", g.package.as_str()))
        };
        let generation = if undo {
            None
        } else {
            invocation
                .alpha_install_guard
                .as_ref()
                .map(|g| g.expected_install_event_id.as_str())
        };
        let entry = invocation
            .reverses
            .as_ref()
            .map(|r| r.entry_id.as_str())
            .unwrap_or(&invocation.entry_id);
        match super::super::artifact_interactions::verify_effect_gesture(
            caller,
            action,
            &invocation.artifact_id,
            package,
            generation,
            entry,
            &[target.to_owned()],
            &invocation.idempotency_key,
            &super::super::artifact_interactions::invocation_values_digest(invocation),
            true,
        ) {
            super::super::artifact_interactions::GestureCheck::Refused { .. } => {
                Err(refuse("body_gesture_refused"))
            }
            super::super::artifact_interactions::GestureCheck::Absent => Ok(None),
            super::super::artifact_interactions::GestureCheck::Evidence(value) => {
                verified_audit(value).map(Some)
            }
        }
    }

    async fn save_in(
        db: &Db,
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        plan: &ArtifactBodySavePlan,
    ) -> Result<Attempt> {
        let invocation = &plan.invocation;
        invocation.validate_shape().map_err(refuse)?;
        if invocation.reverses.is_some()
            || !invocation.observed.is_empty()
            || invocation.include_next_plan
        {
            return Err(refuse("body_invocation_shape"));
        }
        let pins = invocation
            .alpha_install_guard
            .as_ref()
            .ok_or_else(|| refuse("alpha_guard_required"))?;
        if pins.artifact_id != invocation.artifact_id
            || pins.source_revision != plan.source_event_id
        {
            return Err(refuse("body_source_binding"));
        }
        require_record_in(tx, caller, TOOL, &invocation.artifact_id, Capability::View).await?;
        let entry =
            pinned_entry_in(tx, pins, &invocation.source_digest, &invocation.entry_id).await?;
        let (slot, _) = entry
            .slots
            .iter()
            .next()
            .ok_or_else(|| refuse("body_slot_shape"))?;
        if invocation.slots.len() != 1
            || !invocation.slots.contains_key(slot)
            || invocation.values.len() != 2
        {
            return Err(refuse("body_invocation_shape"));
        }
        let target = invocation
            .slots
            .get(slot)
            .ok_or_else(|| refuse("body_slot_shape"))?;
        let body = invocation
            .values
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("body_value_shape"))?;
        let expected = invocation
            .values
            .get("expected_body_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("body_value_shape"))?;
        let audit = gesture(caller, invocation, target, false)?;
        let resolved = match super::super::alpha_tabs::resolve_alpha_admission_in(
            tx,
            caller,
            super::super::effect_admission::PackageClaim::alpha(pins),
            &invocation.artifact_id,
            &invocation.source_digest,
            &entry,
            super::super::alpha_tabs::GuardScope::Body,
        )
        .await?
        {
            Ok(resolved) => resolved,
            Err(refusal) => {
                let (code, message) = super::super::effect_admission::render_refusal(
                    super::super::effect_admission::AdmissionSource::AlphaTabInstall,
                    &refusal,
                );
                return Ok(Attempt::Refused { code, message });
            }
        };
        let super::super::effect_bounds::Admitted::Body { bound, need } = resolved.admitted else {
            return Err(refuse("body_static_admission"));
        };
        if body.len() > bound.max_body_bytes
            || body.len()
                > entry
                    .body
                    .as_ref()
                    .ok_or_else(|| refuse("body_entry_mismatch"))?
                    .max_bytes
        {
            return Err(refuse("body_or_inverse_oversize"));
        }
        let port = body_port(&entry)?.to_owned();
        let semantic = BodySemantic::Save {
            schema: SEMANTIC_SCHEMA.into(),
            actor: caller.actor().into(),
            version: invocation.version.clone(),
            artifact_id: invocation.artifact_id.clone(),
            entry_id: invocation.entry_id.clone(),
            source_digest: invocation.source_digest.clone(),
            record_id: target.clone(),
            scope_port: port.clone(),
            idempotency_key: invocation.idempotency_key.clone(),
            body: body.into(),
            expected_body_digest: expected.into(),
            alpha_install_guard: pins.clone(),
        };
        let semantic_digest = semantic.canonical_digest(caller)?;
        if let Some((_, record, seq, payload)) = candidates_in(
            tx,
            caller,
            &invocation.artifact_id,
            &invocation.entry_id,
            &invocation.idempotency_key,
        )
        .await?
        .pop()
        {
            let (origin, stored_body) = stored_origin(&payload, &record)?;
            let BodyOrigin::Save(saved) = &origin else {
                return Err(refuse("idempotency_conflict"));
            };
            if origin.source() != semantic.source()
                || stored_save_digest(caller, &entry, saved, &stored_body)? != semantic_digest
                || stored_body != BodyValue::Text(body.into())
                || saved.expected_body_digest != expected
                || saved.admission_pins != *pins
            {
                return Err(refuse("idempotency_conflict"));
            }
            view_in(tx, caller, &invocation.artifact_id, &record).await?;
            return Ok(Attempt::Replay(receipt(&origin, seq)?));
        }
        let row = sqlx::query("SELECT i.collection_id,r.kind FROM artifact_inputs i JOIN records r ON r.id=i.collection_id
            WHERE i.artifact_id=? AND i.port_name=? AND i.artifact_source_event_id=? AND i.artifact_source_sha256=?")
            .bind(&invocation.artifact_id).bind(&port).bind(&plan.source_event_id).bind(&invocation.source_digest)
            .fetch_optional(&mut **tx).await?.ok_or_else(|| refuse("named_input_unbound"))?;
        let scope = vec![(port, row.try_get("collection_id")?, row.try_get("kind")?)];
        if let Some((code, message)) = super::super::alpha_tabs::check_body_binding_in(
            tx,
            caller,
            &invocation.artifact_id,
            &plan.source_event_id,
            &invocation.source_digest,
            &scope,
            target,
        )
        .await?
        {
            return Ok(Attempt::Refused { code, message });
        }
        if let Some((code, message)) =
            super::super::alpha_tabs::check_body_membership_in(tx, caller, &bound, &need, target)
                .await?
        {
            return Ok(Attempt::Refused { code, message });
        }
        let snapshot = prepare_snapshot_in(db, tx, caller, target).await?;
        let prepared = prepare_body_write_in(db, tx, caller, snapshot, semantic, audit).await?;
        let applied = apply_prepared_body_in(
            db,
            tx,
            caller,
            &mut crate::act::ActAllocation::new(),
            prepared,
        )
        .await?;
        Ok(Attempt::Append(applied.receipt))
    }

    async fn undo_in(
        db: &Db,
        tx: &mut Transaction<'static, Sqlite>,
        caller: &Caller,
        invocation: &ArtifactInvocation,
    ) -> Result<Attempt> {
        invocation.validate_shape().map_err(refuse)?;
        let reverse = invocation
            .reverses
            .as_ref()
            .ok_or_else(|| refuse("body_reverse_shape"))?;
        require_record_in(tx, caller, TOOL, &invocation.artifact_id, Capability::View).await?;
        let (event_id, target, seq, payload) = candidates_in(
            tx,
            caller,
            &invocation.artifact_id,
            &reverse.entry_id,
            &reverse.idempotency_key,
        )
        .await?
        .pop()
        .ok_or_else(|| refuse("body_original_missing"))?;
        let (origin, stored_body) = stored_origin(&payload, &target)?;
        let BodyOrigin::Save(original) = origin else {
            return Err(refuse("undo_of_undo"));
        };
        if original.source_digest != invocation.source_digest {
            return Err(refuse("body_source_binding"));
        }
        view_in(tx, caller, &invocation.artifact_id, &target).await?;
        let audit = gesture(caller, invocation, &target, true)?;
        // ORIGINAL source and committed admission, never current installation.
        let original_entry = pinned_entry_in(
            tx,
            &original.admission_pins,
            &original.source_digest,
            &original.entry_id,
        )
        .await?;
        let original_digest = stored_save_digest(caller, &original_entry, &original, &stored_body)?;
        let reverses = Reverses {
            event_id: event_id.clone(),
            seq,
            entry_id: reverse.entry_id.clone(),
            idempotency_key: reverse.idempotency_key.clone(),
        };
        let semantic = BodySemantic::Undo {
            schema: SEMANTIC_SCHEMA.into(),
            actor: caller.actor().into(),
            version: invocation.version.clone(),
            artifact_id: invocation.artifact_id.clone(),
            entry_id: reverse.entry_id.clone(),
            source_digest: invocation.source_digest.clone(),
            record_id: target.clone(),
            idempotency_key: invocation.idempotency_key.clone(),
            reverses: reverses.clone(),
            original_semantic_digest: original_digest,
        };
        let digest = semantic.canonical_digest(caller)?;
        if let Some((_, record, undo_seq, saved_payload)) = candidates_in(
            tx,
            caller,
            &invocation.artifact_id,
            &reverse.entry_id,
            &invocation.idempotency_key,
        )
        .await?
        .pop()
        {
            let (origin, _) = stored_origin(&saved_payload, &record)?;
            let BodyOrigin::Undo(saved) = &origin else {
                return Err(refuse("idempotency_conflict"));
            };
            if origin.source() != semantic.source()
                || saved.semantic_digest != digest
                || saved.admission_pins != original.admission_pins
                || saved.reverses != reverses
                || saved.before != original.after
                || saved.after != original.before
            {
                return Err(refuse("idempotency_conflict"));
            }
            return Ok(Attempt::Replay(receipt(&origin, undo_seq)?));
        }
        let used: Option<i64> = sqlx::query_scalar("SELECT seq FROM content_events WHERE actor=?
            AND CASE WHEN json_valid(payload) THEN json_extract(payload,'$.origin.schema')=? ELSE 0 END
            AND CASE WHEN json_valid(payload) THEN json_extract(payload,'$.origin.reverses.event_id')=? ELSE 0 END
            ORDER BY seq LIMIT 1").bind(caller.actor()).bind(ORIGIN_SCHEMA).bind(&event_id).fetch_optional(&mut **tx).await?;
        if used.is_some() {
            return Err(refuse("already_reversed"));
        }
        let snapshot = prepare_snapshot_in(db, tx, caller, &target).await?;
        let prepared = prepare_body_write_in(db, tx, caller, snapshot, semantic, audit).await?;
        let applied = apply_prepared_body_in(
            db,
            tx,
            caller,
            &mut crate::act::ActAllocation::new(),
            prepared,
        )
        .await?;
        Ok(Attempt::Append(applied.receipt))
    }

    /// Completion boundary: before handoff we own rollback; after handoff
    /// commit_content owns completion. Commit/rollback Err is uncertainty.
    async fn complete(
        db: &Db,
        tx: Transaction<'static, Sqlite>,
        attempt: Result<Attempt>,
    ) -> Result<ArtifactBodyOutcome> {
        match attempt {
            Ok(Attempt::Refused { code, message }) => {
                tx.rollback()
                    .await
                    .map_err(|_| refuse("body_rollback_uncertain"))?;
                Ok(ArtifactBodyOutcome::Refused { code, message })
            }
            Err(error) => {
                if tx.rollback().await.is_err() {
                    return Err(refuse("body_rollback_uncertain"));
                }
                match error {
                    Error::Engine(message) => {
                        let code = message
                            .strip_prefix(&format!("{TOOL}: "))
                            .filter(|code| {
                                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                            })
                            .unwrap_or("body_precommit_refused")
                            .to_owned();
                        Ok(ArtifactBodyOutcome::Refused { code, message })
                    }
                    other => Err(other),
                }
            }
            Ok(Attempt::Replay(receipt)) => {
                let receipt = Box::new(receipt);
                tx.rollback()
                    .await
                    .map_err(|_| refuse("body_rollback_uncertain"))?;
                Ok(ArtifactBodyOutcome::Committed { receipt })
            }
            Ok(Attempt::Append(receipt)) => {
                let receipt = Box::new(receipt);
                // No fallible receipt work is permitted after consuming commit.
                db.commit_content(tx)
                    .await
                    .map_err(|_| refuse("body_commit_uncertain"))?;
                Ok(ArtifactBodyOutcome::Committed { receipt })
            }
        }
    }

    pub(crate) async fn save_body_from_artifact(
        db: &Db,
        caller: &Caller,
        plan: ArtifactBodySavePlan,
    ) -> Result<ArtifactBodyOutcome> {
        refuse_enrolled(db)?; // Before job/transaction/replay.
        let mut tx = crate::db::enrolled::begin_document_write(db).await?;
        let result = async {
            structural_in(&mut tx).await?;
            save_in(db, &mut tx, caller, &plan).await
        }
        .await;
        complete(db, tx, result).await
    }

    pub(crate) async fn undo_body_from_artifact(
        db: &Db,
        caller: &Caller,
        invocation: &ArtifactInvocation,
    ) -> Result<ArtifactBodyOutcome> {
        refuse_enrolled(db)?;
        let mut tx = crate::db::enrolled::begin_document_write(db).await?;
        let result = async {
            structural_in(&mut tx).await?;
            undo_in(db, &mut tx, caller, invocation).await
        }
        .await;
        complete(db, tx, result).await
    }

    // Exact production precommit/cleanup boundary, with a test-only error
    // AFTER the real ordinary append. No production callback/fault credential.
    #[cfg(test)]
    pub(super) async fn save_body_with_postappend_failure(
        db: &Db,
        caller: &Caller,
        plan: ArtifactBodySavePlan,
    ) -> Result<ArtifactBodyOutcome> {
        refuse_enrolled(db)?;
        let mut tx = crate::db::enrolled::begin_document_write(db).await?;
        let result = async {
            structural_in(&mut tx).await?;
            match save_in(db, &mut tx, caller, &plan).await? {
                Attempt::Append(_) => Err(Error::Conflict("test-only postappend failure".into())),
                Attempt::Replay(receipt) => Ok(Attempt::Replay(receipt)),
                Attempt::Refused { code, message } => Ok(Attempt::Refused { code, message }),
            }
        }
        .await;
        complete(db, tx, result).await
    }

    // Build a genuine kernel append as an INSERT-only corruption template,
    // then roll it back. No protected row is edited/deleted or projected by
    // the corruption fixtures, and no test authority enters a production API.
    #[cfg(test)]
    pub(super) async fn body_payload_without_commit(
        db: &Db,
        caller: &Caller,
        plan: &ArtifactBodySavePlan,
    ) -> Result<(String, String, i64)> {
        refuse_enrolled(db)?;
        let mut tx = crate::db::enrolled::begin_document_write(db).await?;
        let result = async {
            structural_in(&mut tx).await?;
            let attempt = if plan.invocation.reverses.is_some() {
                undo_in(db, &mut tx, caller, &plan.invocation).await?
            } else {
                save_in(db, &mut tx, caller, plan).await?
            };
            if !matches!(attempt, Attempt::Append(_)) {
                return Err(refuse("test_template_not_append"));
            }
            sqlx::query_as(
                "SELECT payload,id,seq FROM content_events WHERE actor=?
                AND json_extract(payload,'$.origin.artifact_id')=?
                AND json_extract(payload,'$.origin.idempotency_key')=? ORDER BY seq DESC LIMIT 1",
            )
            .bind(caller.actor())
            .bind(&plan.invocation.artifact_id)
            .bind(&plan.invocation.idempotency_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(Error::from)
        }
        .await;
        tx.rollback()
            .await
            .map_err(|_| refuse("body_rollback_uncertain"))?;
        result
    }

    #[cfg(test)]
    pub(super) fn validate_closed_body_candidate(payload: &str, target: &str) -> Result<()> {
        stored_origin(payload, target).map(|_| ())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct Fixture {
            directory: tempfile::TempDir,
            path: std::path::PathBuf,
            db: Db,
            caller: Caller,
            target: String,
        }

        impl Fixture {
            async fn new(body: Option<&str>) -> Self {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("body.sqlite");
                let db = crate::create_database(path.to_str().unwrap())
                    .await
                    .unwrap();
                let mut tools = ToolRegistry::new();
                crate::mcp::register_surface_tools(&mut tools).unwrap();
                let mut args = json!({"type":"Document", "kind":"note", "name":"body fixture", "reason":"test bootstrap"});
                if let Some(body) = body {
                    args["body"] = json!(body);
                }
                // Local authority is test bootstrap only. Every adapter call
                // below uses a real authenticated Caller and current policy.
                let created = tools
                    .call(db.clone(), Caller::local(), "create_record", args)
                    .await
                    .unwrap();
                let target = created["id"].as_str().unwrap().to_owned();
                crate::authorization::replace_explicit_policy(
                    &db,
                    "test:body-bootstrap",
                    &target,
                    vec![AllowEntry::account("acct:body-editor", Capability::Edit)],
                )
                .await
                .unwrap();
                Self {
                    directory,
                    path,
                    db,
                    caller: Caller::authenticated("acct:body-editor"),
                    target,
                }
            }

            fn save(&self, body: &str, expected: Option<&str>) -> BodySemantic {
                BodySemantic::Save {
                    schema: SEMANTIC_SCHEMA.into(),
                    actor: self.caller.actor().into(),
                    version: INVOCATION_VERSION.into(),
                    artifact_id: "artifact-fixture".into(),
                    entry_id: "save".into(),
                    source_digest: "a".repeat(64),
                    record_id: self.target.clone(),
                    scope_port: "document".into(),
                    idempotency_key: "fixture-save".into(),
                    body: body.into(),
                    expected_body_digest: body_digest(expected),
                    alpha_install_guard: pins(),
                }
            }

            async fn count(&self) -> i64 {
                sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=?")
                    .bind(&self.target)
                    .fetch_one(self.db.pool())
                    .await
                    .unwrap()
            }

            async fn prepared(
                &self,
                tx: &mut Transaction<'static, Sqlite>,
                semantic: BodySemantic,
            ) -> Result<PreparedBodyWrite> {
                let snapshot =
                    prepare_snapshot_in(&self.db, tx, &self.caller, &self.target).await?;
                prepare_body_write_in(&self.db, tx, &self.caller, snapshot, semantic, None).await
            }

            async fn apply(
                &self,
                tx: &mut Transaction<'static, Sqlite>,
                semantic: BodySemantic,
            ) -> Result<AppliedBodyWrite> {
                let prepared = self.prepared(tx, semantic).await?;
                apply_prepared_body_in(
                    &self.db,
                    tx,
                    &self.caller,
                    &mut crate::act::ActAllocation::new(),
                    prepared,
                )
                .await
            }

            // INSERT-only corruption fixture; it deliberately does not project
            // the row. Production appends MUST still use the ordinary kernel.
            async fn corrupt_candidate(
                &self,
                tx: &mut Transaction<'static, Sqlite>,
                family: &str,
                payload: &str,
            ) {
                sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,1,'legacy_unknown')")
                    .bind(Uuid::new_v4().to_string()).bind(&self.target).bind(family).bind(payload)
                    .bind(self.caller.actor()).bind("2026-10-03T00:00:00Z").execute(&mut **tx).await.unwrap();
            }
        }

        // These are shape fixtures, NOT installed consent or S3-B admission.
        fn pins() -> AlphaTabInstallGuard {
            AlphaTabInstallGuard {
                package: "fixture".into(),
                expected_install_event_id: "install".into(),
                artifact_id: "artifact-fixture".into(),
                source_revision: "revision".into(),
                version: "1".into(),
                digest: format!("sha256:{}", "b".repeat(64)),
                declaration_digest: "c".repeat(64),
            }
        }

        fn undo(fixture: &Fixture, applied: &AppliedBodyWrite, key: &str) -> BodySemantic {
            let payload: Value =
                serde_json::from_str(applied.event.payload.as_ref().unwrap()).unwrap();
            let BodyOrigin::Save(origin) =
                parse_origin(&serde_json::to_string(&payload["origin"]).unwrap()).unwrap()
            else {
                panic!("forward fixture must be Save");
            };
            BodySemantic::Undo {
                schema: SEMANTIC_SCHEMA.into(),
                actor: fixture.caller.actor().into(),
                version: INVOCATION_VERSION.into(),
                artifact_id: origin.artifact_id,
                source_digest: origin.source_digest,
                entry_id: origin.entry_id.clone(),
                record_id: fixture.target.clone(),
                idempotency_key: key.into(),
                reverses: Reverses {
                    event_id: applied.event.id.clone(),
                    seq: applied.event.local_seq,
                    entry_id: origin.entry_id,
                    idempotency_key: origin.idempotency_key,
                },
                original_semantic_digest: origin.semantic_digest,
            }
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn dormant_facades_refuse_real_enrollment_before_shape_job_or_replay() {
            let f = Fixture::new(Some("seed")).await;
            f.db.drain_captures_for_tests().await;
            crate::db::checkpoint_and_close_hosted_adoption_database(f.db.clone())
                .await
                .unwrap();
            std::fs::create_dir(f.directory.path().join("databases")).unwrap();
            let generation = Uuid::new_v4().to_string();
            let path = f
                .directory
                .path()
                .join("databases")
                .join(format!("{generation}.db"));
            let enrollment = crate::managed_custody::reserve_fresh_adoption(
                f.directory.path(),
                &path,
                &generation,
            )
            .unwrap();
            std::fs::copy(&f.path, &path).unwrap();
            enrollment.finalize().unwrap();
            let enrolled = crate::db::open_existing_database_at(&path).await.unwrap();
            assert!(enrolled.is_enrolled());
            let before = std::fs::read(&path).unwrap();
            let invocation = ArtifactInvocation {
                version: INVOCATION_VERSION.into(),
                artifact_id: "missing-artifact".into(),
                entry_id: "save".into(),
                source_digest: "a".repeat(64),
                slots: BTreeMap::new(),
                values: BTreeMap::new(),
                observed: BTreeMap::new(),
                idempotency_key: "enrolled:body".into(),
                gesture: None,
                include_next_plan: false,
                alpha_install_guard: None,
                reverses: None,
            };
            // Shape is deliberately unusable; enrollment must win BEFORE
            // validation, job acquisition, BEGIN or any receipt lookup.
            let error = save_body_from_artifact(
                &enrolled,
                &f.caller,
                ArtifactBodySavePlan {
                    invocation: invocation.clone(),
                    source_event_id: "missing-source".into(),
                },
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("enrolled_unsupported"));
            assert!(undo_body_from_artifact(&enrolled, &f.caller, &invocation)
                .await
                .unwrap_err()
                .to_string()
                .contains("enrolled_unsupported"));
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }

        #[test]
        fn summary_null_empty_and_exact_unicode_bytes_are_distinct() {
            assert_ne!(
                BodyValue::Null.summary(),
                BodyValue::Text(String::new()).summary()
            );
            assert_eq!(body_digest(None), body_digest(Some(""))); // Legacy helper unchanged.
            let raw = " \"null\"\r\n汉🦀e\u{301}\0tail ";
            let text = BodyValue::Text(raw.into());
            let BodySummary::Text { utf8_bytes, sha256 } = text.summary() else {
                panic!("text");
            };
            assert_eq!(utf8_bytes, raw.len() as u64);
            assert_eq!(sha256, format!("{:x}", Sha256::digest(raw.as_bytes())));
            assert_eq!(text.json(), json!(raw));
            assert_eq!(
                serde_json::to_string(&BodySummary::Null {}).unwrap(),
                r#"{"kind":"null"}"#
            );
        }

        #[test]
        fn semantic_has_a_fixed_ordered_byte_oracle_without_renewable_evidence() {
            let caller = Caller::authenticated("acct:body-editor");
            let semantic = BodySemantic::Save {
                schema: SEMANTIC_SCHEMA.into(),
                actor: caller.actor().into(),
                version: INVOCATION_VERSION.into(),
                artifact_id: "artifact-fixture".into(),
                entry_id: "save".into(),
                source_digest: "a".repeat(64),
                record_id: "document".into(),
                scope_port: "document".into(),
                idempotency_key: "key".into(),
                body: "text".into(),
                expected_body_digest: "d".repeat(64),
                alpha_install_guard: pins(),
            };
            let expected = format!(concat!(
                "{{\"actor\":\"acct:body-editor\",\"alpha_install_guard\":{{\"artifact_id\":\"artifact-fixture\",",
                "\"declaration_digest\":\"{}\",\"digest\":\"sha256:{}\",\"expected_install_event_id\":\"install\",",
                "\"package\":\"fixture\",\"source_revision\":\"revision\",\"version\":\"1\"}},",
                "\"artifact_id\":\"artifact-fixture\",\"body\":\"text\",\"entry_id\":\"save\",",
                "\"expected_body_digest\":\"{}\",\"idempotency_key\":\"key\",\"operation\":\"save\",",
                "\"record_id\":\"document\",\"schema\":\"native.body-effect-semantic.v1\",\"scope_port\":\"document\",",
                "\"source_digest\":\"{}\",\"version\":\"native.artifact-invocation.v1\"}}"
            ), "c".repeat(64), "b".repeat(64), "d".repeat(64), "a".repeat(64));
            assert_eq!(serde_jcs::to_vec(&semantic).unwrap(), expected.as_bytes());
            assert_eq!(
                semantic.canonical_digest(&caller).unwrap(),
                format!("{:x}", Sha256::digest(expected.as_bytes()))
            );
        }

        #[tokio::test]
        async fn semantic_canonical_identity_refuses_unknown_duplicates_actor_and_normalization() {
            let f = Fixture::new(Some("base")).await;
            let intent = f.save(" \r\n汉e\u{301}", Some("base"));
            let text = serde_json::to_string(&intent).unwrap();
            let parsed = parse_semantic(&text, &f.caller).unwrap();
            let canonical = serde_jcs::to_vec(&parsed).unwrap();
            assert_eq!(
                parsed.canonical_digest(&f.caller).unwrap(),
                format!("{:x}", Sha256::digest(canonical))
            );
            let mut value: Value = serde_json::from_str(&text).unwrap();
            value["gesture"] = json!("renewed");
            assert!(parse_semantic(&value.to_string(), &f.caller).is_err());
            let duplicate = text.replacen("{", r#"{"actor":"acct:body-editor","#, 1);
            assert!(parse_semantic(&duplicate, &f.caller).is_err());
            let nested_duplicate = text.replace(
                r#""package":"fixture""#,
                r#""package":"fixture","package":"fixture""#,
            );
            assert!(parse_semantic(&nested_duplicate, &f.caller).is_err());
            assert!(parse_semantic(&text, &Caller::authenticated("acct:other")).is_err());
            assert_ne!(
                intent.canonical_digest(&f.caller).unwrap(),
                f.save("\n汉é", Some("base"))
                    .canonical_digest(&f.caller)
                    .unwrap()
            );
        }

        #[tokio::test]
        async fn closed_origin_rejects_cross_variant_unknown_duplicate_and_invalid_refs() {
            let f = Fixture::new(Some("base")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let prepared = f
                .prepared(&mut tx, f.save("next", Some("base")))
                .await
                .unwrap();
            let text = serde_json::to_string(&prepared.origin).unwrap();
            assert_eq!(parse_origin(&text).unwrap(), prepared.origin);
            for (key, invalid) in [
                ("reverses", json!({})),
                ("gesture", json!("x")),
                ("semantic_digest", json!("A".repeat(64))),
            ] {
                let mut v: Value = serde_json::from_str(&text).unwrap();
                v[key] = invalid;
                assert!(parse_origin(&v.to_string()).is_err());
            }
            let duplicate = text.replace(r#""kind":"text""#, r#""kind":"text","kind":"text""#);
            assert!(parse_origin(&duplicate).is_err());
            let mut v: Value = serde_json::from_str(&text).unwrap();
            v["inverse"]["seq"] = json!(0);
            assert!(parse_origin(&v.to_string()).is_err());
            v["inverse"]["seq"] = json!(1.5);
            assert!(parse_origin(&v.to_string()).is_err());
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn body_audit_closed_wire_legacy_absence_and_duplicate_fields() {
            let f = Fixture::new(None).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let prepared = f.prepared(&mut tx, f.save("next", None)).await.unwrap();
            let applied = f.apply(&mut tx, f.save("next", None)).await.unwrap();
            let inverse = f
                .prepared(&mut tx, undo(&f, &applied, "audit-wire-undo"))
                .await
                .unwrap();
            for origin in [&prepared.origin, &inverse.origin] {
                let legacy = serde_json::to_string(origin).unwrap();
                assert!(!legacy.contains("gesture_evidence"));
                assert_eq!(
                    serde_json::to_string(&parse_origin(&legacy).unwrap()).unwrap(),
                    legacy
                );
                let base: Value = serde_json::from_str(&legacy).unwrap();
                for kind in ["click", "drop", "key", "grant"] {
                    let evidence = json!({"kind":kind,"verifier":"effect_gesture.v1"});
                    let mut audited = base.clone();
                    audited["gesture_evidence"] = evidence.clone();
                    let text = audited.to_string();
                    let parsed = parse_origin(&text).unwrap();
                    assert_eq!(serde_json::to_value(parsed).unwrap(), audited);
                    assert!(verified_audit(evidence.clone()).is_ok());
                    for invalid in [
                        json!({"kind":{(kind):null},"verifier":"effect_gesture.v1"}),
                        json!({"kind":kind,"verifier":{"effect_gesture.v1":null}}),
                        json!({"kind":{(kind):null},"verifier":{"effect_gesture.v1":null}}),
                        json!({"kind":[kind],"verifier":"effect_gesture.v1"}),
                        json!({"kind":kind,"verifier":["effect_gesture.v1"]}),
                        json!({"kind":true,"verifier":"effect_gesture.v1"}),
                        json!({"kind":kind,"verifier":true}),
                        json!({"kind":1,"verifier":1}),
                    ] {
                        let mut malformed = base.clone();
                        malformed["gesture_evidence"] = invalid.clone();
                        assert!(parse_origin(&malformed.to_string()).is_err(), "{invalid}");
                        assert!(verified_audit(invalid).is_err());
                    }
                    for raw in [
                        format!(
                            r#"{{"kind":"{kind}","kind":"drop","verifier":"effect_gesture.v1"}}"#
                        ),
                        format!(
                            r#"{{"kind":"drop","kind":"{kind}","verifier":"effect_gesture.v1"}}"#
                        ),
                        format!(
                            r#"{{"kind":"{kind}","verifier":"effect_gesture.v1","verifier":"effect_gesture.v1"}}"#
                        ),
                    ] {
                        let raw = format!(
                            "{},\"gesture_evidence\":{raw}}}",
                            &legacy[..legacy.len() - 1]
                        );
                        assert!(parse_origin(&raw).is_err());
                    }
                    for fields in [
                        format!(r#""gesture_evidence":{evidence},"gesture_evidence":null"#),
                        format!(r#""gesture_evidence":null,"gesture_evidence":{evidence}"#),
                    ] {
                        let raw = format!("{},{fields}}}", &legacy[..legacy.len() - 1]);
                        assert!(parse_origin(&raw).is_err());
                    }
                }
                for invalid in [
                    Value::Null,
                    json!([]),
                    json!("click"),
                    json!(1),
                    json!({}),
                    json!({"kind":"CLICK","verifier":"effect_gesture.v1"}),
                    json!({"kind":"click","verifier":"other"}),
                    json!({"kind":null,"verifier":"effect_gesture.v1"}),
                    json!({"kind":"click"}),
                    json!({"verifier":"effect_gesture.v1"}),
                    json!({"kind":"click","verifier":"effect_gesture.v1","token":"secret"}),
                    json!({"kind":"click","verifier":"effect_gesture.v1","bearer":"secret"}),
                    json!({"kind":"click","verifier":"effect_gesture.v1","text":"click"}),
                ] {
                    let mut malformed = base.clone();
                    malformed["gesture_evidence"] = invalid.clone();
                    assert!(parse_origin(&malformed.to_string()).is_err(), "{invalid}");
                    assert!(verified_audit(invalid).is_err());
                }
            }
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn body_audit_reprepare_keeps_evidence_and_semantic_digest() {
            let f = Fixture::new(Some("base")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let semantic = f.save("next", Some("base"));
            let digest = semantic.canonical_digest(&f.caller).unwrap();
            let snapshot = prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                .await
                .unwrap();
            let prepared = prepare_body_write_in(
                &f.db,
                &mut tx,
                &f.caller,
                snapshot,
                semantic.clone(),
                Some(largest_audit()),
            )
            .await
            .unwrap();
            let origin = serde_json::to_value(&prepared.origin).unwrap();
            assert_eq!(origin["semantic_digest"], json!(digest));
            let applied = apply_prepared_body_in(
                &f.db,
                &mut tx,
                &f.caller,
                &mut crate::act::ActAllocation::new(),
                prepared,
            )
            .await
            .unwrap();
            let payload: Value =
                serde_json::from_str(applied.event.payload.as_ref().unwrap()).unwrap();
            assert_eq!(payload["origin"], origin);
            assert_eq!(
                payload["origin"]["gesture_evidence"],
                json!({"kind":"click","verifier":"effect_gesture.v1"})
            );
            assert_eq!(semantic.canonical_digest(&f.caller).unwrap(), digest);
            tx.rollback().await.unwrap();
            // Actual later ordinary append invalidates an audited preparation.
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let snapshot = prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                .await
                .unwrap();
            let stale = prepare_body_write_in(
                &f.db,
                &mut tx,
                &f.caller,
                snapshot,
                semantic,
                Some(largest_audit()),
            )
            .await
            .unwrap();
            f.apply(&mut tx, f.save("other", Some("base")))
                .await
                .unwrap();
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert!(apply_prepared_body_in(
                &f.db,
                &mut tx,
                &f.caller,
                &mut crate::act::ActAllocation::new(),
                stale
            )
            .await
            .is_err());
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap(),
                count
            );
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn larger_body_save_replay_and_undo_reconstruct_exact_escaped_source() {
            for original in [
                "\u{1}".repeat(BODY_BYTES),
                "\"".repeat(BODY_BYTES),
                "🦀".repeat(BODY_BYTES / 4),
            ] {
                let f = Fixture::new(Some(&original)).await;
                let draft = "\u{2}".repeat(BODY_BYTES);
                let semantic = f.save(&draft, Some(&original));
                let encoded = serde_json::to_string(&semantic).unwrap();
                assert!(encoded.len() > 262_144);
                assert_eq!(
                    serde_json::to_value(parse_semantic(&encoded, &f.caller).unwrap()).unwrap(),
                    serde_json::to_value(&semantic).unwrap()
                );
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                let applied = f.apply(&mut tx, semantic).await.unwrap();
                let candidates = candidates_in(
                    &mut tx,
                    &f.caller,
                    "artifact-fixture",
                    "save",
                    "fixture-save",
                )
                .await
                .unwrap();
                assert_eq!(candidates.len(), 1);
                let (origin, body) = stored_origin(&candidates[0].3, &f.target).unwrap();
                assert_eq!(body, BodyValue::Text(draft.clone()));
                assert_eq!(origin.summaries().1, &body.summary());
                let restored = f
                    .apply(&mut tx, undo(&f, &applied, "large-body-undo"))
                    .await
                    .unwrap();
                restored.receipt.validate_shape().unwrap();
                assert_eq!(
                    serde_json::to_value(&restored.receipt).unwrap()["changes"][0]["after"],
                    serde_json::to_value(BodyValue::Text(original.clone()).summary()).unwrap()
                );
                let stored: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
                    .bind(&f.target)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                assert_eq!(stored, original);
                tx.rollback().await.unwrap();
            }
        }

        #[tokio::test]
        async fn body_audit_real_preappend_inverse_and_postappend_serializers() {
            for initial in [
                None,
                Some("".to_owned()),
                Some("\u{1}".repeat(BODY_BYTES)),
                Some("\"".repeat(BODY_BYTES)),
                Some("🦀".repeat(BODY_BYTES / 4)),
            ] {
                let f = Fixture::new(initial.as_deref()).await;
                for kind in [
                    BodyGestureKind::Click,
                    BodyGestureKind::Drop,
                    BodyGestureKind::Key,
                    BodyGestureKind::Grant,
                ] {
                    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                    let before = current_record_version_in(&mut tx, &f.target).await.unwrap();
                    let snapshot = prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                        .await
                        .unwrap();
                    let prepared = prepare_body_write_in(
                        &f.db,
                        &mut tx,
                        &f.caller,
                        snapshot,
                        f.save(&"\u{1}".repeat(BODY_BYTES), initial.as_deref()),
                        Some(BodyGestureEvidence {
                            kind,
                            verifier: BodyGestureVerifier::EffectGestureV1,
                        }),
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        current_record_version_in(&mut tx, &f.target).await.unwrap(),
                        before
                    );
                    let BodyOrigin::Save(original) = &prepared.origin else {
                        panic!("save");
                    };
                    let bound = preflight_prospective_undo_encoding(
                        &f.caller,
                        &prepared.snapshot,
                        original,
                    )
                    .unwrap();
                    let applied = apply_prepared_body_in(
                        &f.db,
                        &mut tx,
                        &f.caller,
                        &mut crate::act::ActAllocation::new(),
                        prepared,
                    )
                    .await
                    .unwrap();
                    assert!(bound >= applied.prospective_undo_payload_bytes.unwrap());
                    assert_eq!(
                        applied.event_bytes,
                        serde_json::to_vec(&applied.event).unwrap().len()
                    );
                    let payload: Value =
                        serde_json::from_str(applied.event.payload.as_ref().unwrap()).unwrap();
                    assert_eq!(
                        applied.payload_bytes,
                        serde_json::to_vec(&payload).unwrap().len()
                    );
                    applied.receipt.validate_shape().unwrap();
                    tx.rollback().await.unwrap();
                }
            }
            let f = Fixture::new(Some("base")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let frontier = current_record_version_in(&mut tx, &f.target).await.unwrap();
            for raw in ["x".repeat(BODY_BYTES + 1), "🦀".repeat(BODY_BYTES / 4 + 1)] {
                let snapshot = prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                    .await
                    .unwrap();
                assert!(prepare_body_write_in(
                    &f.db,
                    &mut tx,
                    &f.caller,
                    snapshot,
                    f.save(&raw, Some("base")),
                    Some(largest_audit())
                )
                .await
                .is_err());
                assert_eq!(
                    current_record_version_in(&mut tx, &f.target).await.unwrap(),
                    frontier
                );
            }
            let mut maximal = f.save("next", Some("base"));
            if let BodySemantic::Save {
                artifact_id,
                entry_id,
                idempotency_key,
                alpha_install_guard,
                ..
            } = &mut maximal
            {
                *artifact_id = "\"".repeat(256);
                alpha_install_guard.artifact_id = artifact_id.clone();
                *entry_id = "\"".repeat(256);
                *idempotency_key = "\"".repeat(256);
            }
            let snapshot = prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                .await
                .unwrap();
            let prepared = prepare_body_write_in(
                &f.db,
                &mut tx,
                &f.caller,
                snapshot,
                maximal,
                Some(largest_audit()),
            )
            .await
            .unwrap();
            let BodyOrigin::Save(origin) = &prepared.origin else {
                panic!("save");
            };
            preflight_prospective_undo_encoding(&f.caller, &prepared.snapshot, origin).unwrap();
            let semantic = f.save("next", Some("base"));
            for (raw, allowed) in [
                ("\u{1}".repeat((BODY_ENCODED_BYTES - 2) / 6), true),
                ("\u{1}".repeat((BODY_ENCODED_BYTES - 2) / 6 + 1), false),
            ] {
                assert_eq!(
                    encoded_values(&semantic, BTreeMap::from([("value".into(), json!(raw))]))
                        .is_ok(),
                    allowed
                );
            }
            assert_eq!(
                current_record_version_in(&mut tx, &f.target).await.unwrap(),
                frontier
            );
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn prepared_nullable_save_and_undo_origins_reject_extra_null_summary_fields() {
            let f = Fixture::new(None).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let save = f.save("next", None);
            let prepared_save = f.prepared(&mut tx, save.clone()).await.unwrap();
            let applied = f.apply(&mut tx, save).await.unwrap();
            let prepared_undo = f
                .prepared(&mut tx, undo(&f, &applied, "nullable-summary-undo"))
                .await
                .unwrap();
            for (origin, null_field, text_field) in [
                (&prepared_save.origin, "before", "after"),
                (&prepared_undo.origin, "after", "before"),
            ] {
                let text = serde_json::to_string(origin).unwrap();
                assert_eq!(parse_origin(&text).unwrap(), *origin);
                let value: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(value[null_field], json!({"kind": "null"}));
                assert_eq!(value[text_field]["kind"], json!("text"));
                for (key, extra) in [
                    ("body", json!("untrusted")),
                    ("sha256", json!("a".repeat(64))),
                    ("utf8_bytes", json!(0)),
                    ("gesture", json!("untrusted")),
                    ("other", json!(null)),
                ] {
                    let mut invalid = value.clone();
                    invalid[null_field][key] = extra;
                    assert!(
                        parse_origin(&invalid.to_string()).is_err(),
                        "{null_field}.{key}"
                    );
                }
                let duplicate = text.replace(r#""kind":"null""#, r#""kind":"null","kind":"null""#);
                assert_ne!(duplicate, text);
                assert!(parse_origin(&duplicate).is_err());
            }
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn full_history_preserves_creation_null_empty_json_nul_and_four_families() {
            for raw in [
                None,
                Some(""),
                Some("null"),
                Some("{\"x\":1}"),
                Some("abc\0tail"),
                Some("\0"),
                Some("汉🦀\r\n"),
            ] {
                let f = Fixture::new(raw).await;
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                let s = prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                    .await
                    .unwrap();
                assert_eq!(
                    s.current_body,
                    BodyValue::from_nullable(raw.map(str::to_owned))
                );
                assert_eq!(s.creation_ref, s.inverse_ref);
                tx.rollback().await.unwrap();
            }
            let content = crate::freshness::UnitContent::text("unit\0tail").unwrap();
            let unit = serde_json::to_string(&crate::events::UnitRevisionRecordedPayload {
                format: crate::freshness::UNIT_REVISION_FORMAT.into(),
                semantic_contract_version: crate::freshness::SEMANTIC_CONTRACT_VERSION.into(),
                content_sha256: content.sha256(),
                content,
                based_on_revision_event_id: None,
                rationale: None,
                command: None,
            })
            .unwrap();
            for (family, payload) in [
                ("record.updated", r#"{"body":"literal JSON: {\"a\":1}"}"#),
                ("receipt.committed.v1", r#"{"body":"receipt\r\n"}"#),
                ("unit.revision.recorded.v1", unit.as_str()),
            ] {
                let f = Fixture::new(Some("seed")).await;
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                f.corrupt_candidate(&mut tx, family, payload).await;
                let through = current_record_version_in(&mut tx, &f.target).await.unwrap();
                let (_, reference, body) = history_in(&mut tx, &f.target, through).await.unwrap();
                assert_eq!(reference.event_type, family);
                let value: Value = serde_json::from_str(payload).unwrap();
                let expected = if family == "unit.revision.recorded.v1" {
                    value["content"]["content"].as_str()
                } else {
                    value["body"].as_str()
                };
                assert_eq!(body.as_nullable(), expected);
                // Unprojected fixture cannot authorize a write on old records.body.
                assert!(prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                    .await
                    .is_err());
                tx.rollback().await.unwrap();
            }
        }

        #[tokio::test]
        async fn latest_null_terminates_and_malformed_candidate_never_falls_back() {
            let f = Fixture::new(Some("older valid")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            f.corrupt_candidate(&mut tx, "record.updated", r#"{"body":null}"#)
                .await;
            let through = current_record_version_in(&mut tx, &f.target).await.unwrap();
            assert_eq!(
                history_in(&mut tx, &f.target, through).await.unwrap().2,
                BodyValue::Null
            );
            tx.rollback().await.unwrap();
            for (family, payload) in [
                ("record.updated", "[]"),
                ("record.updated", r#"{"body":17}"#),
                ("record.updated", r#"{"body":"first","body":"second"}"#),
                ("unit.revision.recorded.v1", "{}"),
                (
                    "unit.revision.recorded.v1",
                    r#"{"content":{"content":null}}"#,
                ),
                (
                    "unit.revision.recorded.v1",
                    r#"{"content":{"content":"x","content":"y"}}"#,
                ),
                ("receipt.committed.v1", r#"{"body":true}"#),
            ] {
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                f.corrupt_candidate(&mut tx, family, payload).await;
                let through = current_record_version_in(&mut tx, &f.target).await.unwrap();
                assert!(
                    history_in(&mut tx, &f.target, through).await.is_err(),
                    "{family}"
                );
                tx.rollback().await.unwrap();
            }

            let before_count = f.count().await;
            let trigger_sql: String = sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='content_event_claim_meta_insert'")
                .fetch_one(f.db.pool()).await.unwrap();
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let before_frontier = current_record_version_in(&mut tx, &f.target).await.unwrap();
            // Current claim metadata extraction rejects this raw malformed INSERT.
            let rejected = sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,1,'legacy_unknown')")
                .bind(Uuid::new_v4().to_string()).bind(&f.target).bind("record.updated").bind("broken JSON")
                .bind(f.caller.actor()).bind("2026-10-03T00:00:00Z").execute(&mut *tx).await;
            assert!(rejected.is_err());
            assert_eq!(
                current_record_version_in(&mut tx, &f.target).await.unwrap(),
                before_frontier
            );
            let count: i64 =
                sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=?")
                    .bind(&f.target)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert_eq!(count, before_count);

            // Isolated legacy/pre-trigger fixture only: no body write or projection.
            sqlx::query("DROP TRIGGER content_event_claim_meta_insert")
                .execute(&mut *tx)
                .await
                .unwrap();
            f.corrupt_candidate(&mut tx, "record.updated", "broken JSON")
                .await;
            let through = current_record_version_in(&mut tx, &f.target).await.unwrap();
            assert!(through > before_frontier);
            assert!(history_in(&mut tx, &f.target, through).await.is_err());
            tx.rollback().await.unwrap();

            assert_eq!(f.count().await, before_count);
            let restored_trigger: String = sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='content_event_claim_meta_insert'")
                .fetch_one(f.db.pool()).await.unwrap();
            assert_eq!(restored_trigger, trigger_sql);
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            assert_eq!(
                current_record_version_in(&mut tx, &f.target).await.unwrap(),
                before_frontier
            );
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn bounded_history_skips_huge_metadata_but_not_missing_duplicate_or_oversized_body() {
            let f = Fixture::new(Some("seed")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            f.corrupt_candidate(
                &mut tx,
                "record.updated",
                &json!({"summary":"x".repeat(300_000)}).to_string(),
            )
            .await;
            let s = prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                .await
                .unwrap();
            assert_eq!(s.current_body.as_nullable(), Some("seed"));
            assert!(s.inverse_ref.seq < s.current_rec);
            // Before creation there is no reconstructable inverse.
            assert!(history_in(&mut tx, &f.target, s.creation_ref.seq - 1)
                .await
                .is_err());
            f.corrupt_candidate(&mut tx, "record.created", "{}").await;
            let through = current_record_version_in(&mut tx, &f.target).await.unwrap();
            assert!(history_in(&mut tx, &f.target, through).await.is_err());
            tx.rollback().await.unwrap();
            for raw in [
                "x".repeat(BODY_BYTES + 1),
                format!("\0{}", "x".repeat(BODY_BYTES)),
            ] {
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                f.corrupt_candidate(&mut tx, "record.updated", &json!({"body":raw}).to_string())
                    .await;
                let through = current_record_version_in(&mut tx, &f.target).await.unwrap();
                assert!(history_in(&mut tx, &f.target, through).await.is_err());
                tx.rollback().await.unwrap();
            }
        }

        #[tokio::test]
        async fn forward_and_inverse_caps_are_independent_no_truncation() {
            let f = Fixture::new(Some(&"x".repeat(BODY_BYTES + 1))).await;
            let before = f.count().await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            assert!(f
                .prepared(&mut tx, f.save("small", Some(&"x".repeat(BODY_BYTES + 1))))
                .await
                .is_err());
            tx.rollback().await.unwrap();
            assert_eq!(f.count().await, before);
            let f = Fixture::new(Some("small")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            assert!(f
                .prepared(
                    &mut tx,
                    f.save(&"汉".repeat(BODY_BYTES / 3 + 1), Some("small"))
                )
                .await
                .is_err());
            assert!(f
                .prepared(&mut tx, f.save(&"x".repeat(BODY_BYTES + 1), Some("small")))
                .await
                .is_err());
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn digest_conflict_stale_preparation_and_revoked_edit_do_not_append() {
            let f = Fixture::new(Some("seed")).await;
            let before = f.count().await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            assert!(f
                .prepared(&mut tx, f.save("next", Some("wrong opening")))
                .await
                .is_err());
            let prepared = f
                .prepared(&mut tx, f.save("next", Some("seed")))
                .await
                .unwrap();
            f.corrupt_candidate(&mut tx, "record.updated", r#"{"summary":"later metadata"}"#)
                .await;
            assert!(apply_prepared_body_in(
                &f.db,
                &mut tx,
                &f.caller,
                &mut crate::act::ActAllocation::new(),
                prepared
            )
            .await
            .is_err());
            tx.rollback().await.unwrap();
            assert_eq!(f.count().await, before);
            crate::authorization::replace_explicit_policy(
                &f.db,
                "test:revoke-edit",
                &f.target,
                vec![AllowEntry::account("acct:body-editor", Capability::View)],
            )
            .await
            .unwrap();
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            assert!(f
                .prepared(&mut tx, f.save("next", Some("seed")))
                .await
                .is_err());
            tx.rollback().await.unwrap();
            assert_eq!(f.count().await, before);
        }

        #[tokio::test]
        async fn ordinary_preparation_refuses_instruction_artifact_runtime_and_non_document() {
            let f = Fixture::new(Some("seed")).await;
            for (column, value) in [
                ("kind", "instruction"),
                ("kind", "artifact"),
                ("kind", "semantic-unit"),
                ("type", "Annotation"),
            ] {
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                sqlx::query(&format!("UPDATE records SET {column}=? WHERE id=?"))
                    .bind(value)
                    .bind(&f.target)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                assert!(prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                    .await
                    .is_err());
                tx.rollback().await.unwrap();
            }
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            sqlx::query(
                "INSERT INTO facet_values(record_id,key,value) VALUES(?,'runtime','unsupported')",
            )
            .bind(&f.target)
            .execute(&mut *tx)
            .await
            .unwrap();
            assert!(prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                .await
                .is_err());
            tx.rollback().await.unwrap();
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            sqlx::query("INSERT INTO instruction_bindings(id,scope_kind,scope_id,source_record_id,position,created_by,created_at,updated_at)
                VALUES('body-test-instruction','database','body-test',?,0,'test','2026-10-03T00:00:00Z','2026-10-03T00:00:00Z')")
                .bind(&f.target).execute(&mut *tx).await.unwrap();
            assert!(prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                .await
                .is_err());
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn actual_ordinary_append_nullable_undo_and_receipts_survive_reopen() {
            for initial in [None, Some(""), Some("{\"raw\":true}\r\n\0tail")] {
                let f = Fixture::new(initial).await;
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                let applied = f
                    .apply(&mut tx, f.save("new 汉🦀\r\n", initial))
                    .await
                    .unwrap();
                let inverse = undo(&f, &applied, "undo-key");
                let payload: Value =
                    serde_json::from_str(applied.event.payload.as_ref().unwrap()).unwrap();
                for absent in ["contributors", "session", "merged_offline"] {
                    assert!(payload.get(absent).is_none());
                }
                assert_eq!(payload["body"], json!("new 汉🦀\r\n"));
                assert!(applied.event_bytes > applied.payload_bytes);
                assert!(applied.prospective_undo_payload_bytes.is_some());
                f.db.commit_content(tx).await.unwrap();
                let reopened = crate::db::open_existing_database_at(&f.path).await.unwrap();
                let mut tx = crate::db::enrolled::begin_document_write(&reopened)
                    .await
                    .unwrap();
                let s = prepare_snapshot_in(&reopened, &mut tx, &f.caller, &f.target)
                    .await
                    .unwrap();
                let prepared =
                    prepare_body_write_in(&reopened, &mut tx, &f.caller, s, inverse.clone(), None)
                        .await
                        .unwrap();
                let undone = apply_prepared_body_in(
                    &reopened,
                    &mut tx,
                    &f.caller,
                    &mut crate::act::ActAllocation::new(),
                    prepared,
                )
                .await
                .unwrap();
                reopened.commit_content(tx).await.unwrap();
                let stored: Option<String> =
                    sqlx::query_scalar("SELECT body FROM records WHERE id=?")
                        .bind(&f.target)
                        .fetch_one(reopened.pool())
                        .await
                        .unwrap();
                assert_eq!(stored.as_deref(), initial);
                let value = serde_json::to_value(&undone.receipt).unwrap();
                assert_eq!(
                    value["changes"][0]["after"],
                    serde_json::to_value(
                        BodyValue::from_nullable(initial.map(str::to_owned)).summary()
                    )
                    .unwrap()
                );
                assert_eq!(
                    value["changes"][0]["version"],
                    json!(format!("rec:{}", undone.event.local_seq))
                );
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                assert!(f.prepared(&mut tx, inverse).await.is_err()); // Once-only CAS, not replay.
                tx.rollback().await.unwrap();
                // Receipt object is immutable despite the restored projection.
                assert_eq!(
                    serde_json::to_value(&applied.receipt).unwrap()["changes"][0]["after"],
                    payload["origin"]["after"]
                );
            }
        }

        #[tokio::test]
        async fn required_schema_before_after_is_real_and_preserved_by_body_only_update() {
            let f = Fixture::new(Some("seed")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            // A pre-existing required violation is not permission to worsen
            // it, nor a reason to falsify an empty before-capture.
            sqlx::query(
                "INSERT INTO schema_config(id,layer,data) VALUES('test-body-required','user',?)",
            )
            .bind(
                json!({"shapes":{"Document:note":{"facets":{"classification":{"required":true}}}}})
                    .to_string(),
            )
            .execute(&mut *tx)
            .await
            .unwrap();
            let prepared = f
                .prepared(&mut tx, f.save("next", Some("seed")))
                .await
                .unwrap();
            assert!(!prepared.before.is_empty());
            let rows = prepared.schema_rows.clone();
            let before = prepared.before.clone();
            let applied = apply_prepared_body_in(
                &f.db,
                &mut tx,
                &f.caller,
                &mut crate::act::ActAllocation::new(),
                prepared,
            )
            .await
            .unwrap();
            let after = required_violations_in(&mut tx, &rows, &[&f.target])
                .await
                .unwrap();
            assert_eq!(before, after);
            // The shared ordinary post-write validator must reject a claimed
            // clean baseline against these actual missing required facets.
            assert!(assert_required_not_worsened(TOOL, &BTreeSet::new(), &after).is_err());
            assert_eq!(applied.receipt.validate_shape(), Ok(()));
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn undo_references_actor_and_original_after_are_revalidated_not_caller_authority() {
            let f = Fixture::new(Some("seed")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let applied = f
                .apply(&mut tx, f.save("next", Some("seed")))
                .await
                .unwrap();
            let valid = undo(&f, &applied, "undo-key");
            for changed in 0..4 {
                let mut value = serde_json::to_value(&valid).unwrap();
                match changed {
                    0 => value["reverses"]["event_id"] = json!(Uuid::new_v4().to_string()),
                    1 => value["original_semantic_digest"] = json!("d".repeat(64)),
                    2 => value["actor"] = json!("acct:forged"),
                    _ => value["reverses"]["idempotency_key"] = json!("other-forward-key"),
                }
                let semantic: BodySemantic = serde_json::from_value(value).unwrap();
                assert!(f.prepared(&mut tx, semantic).await.is_err());
            }
            // A direct mutation of current projection in this isolated test
            // cannot turn null into empty or silently substitute a new base.
            sqlx::query("UPDATE records SET body=NULL WHERE id=?")
                .bind(&f.target)
                .execute(&mut *tx)
                .await
                .unwrap();
            assert!(f.prepared(&mut tx, valid).await.is_err());
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn undo_any_later_record_event_even_same_body_refuses() {
            for (family, payload) in [
                ("record.updated", json!({"summary":"metadata"})),
                ("record.updated", json!({"body":"next"})),
                ("facet.set", json!({"key":"triage","value":"same"})),
                (
                    "link.added",
                    json!({"target_id":"other","relationship":"references"}),
                ),
            ] {
                let f = Fixture::new(Some("seed")).await;
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                let applied = f
                    .apply(&mut tx, f.save("next", Some("seed")))
                    .await
                    .unwrap();
                let inverse = undo(&f, &applied, "undo-key");
                f.db.commit_content(tx).await.unwrap();
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                f.corrupt_candidate(&mut tx, family, &payload.to_string())
                    .await;
                assert!(f.prepared(&mut tx, inverse).await.is_err());
                tx.rollback().await.unwrap();
            }
        }

        #[tokio::test]
        async fn actual_encoding_expansion_depth_nodes_and_postappend_rollback_are_bounded() {
            let f = Fixture::new(Some("seed")).await;
            let semantic = f.save("next", Some("seed"));
            let mut deep = json!("leaf");
            for _ in 0..10 {
                deep = json!({"nested":deep});
            }
            for invalid in [
                deep,
                json!((0..1_025).collect::<Vec<_>>()),
                json!("x".repeat(BODY_ENCODED_BYTES)),
            ] {
                assert!(
                    encoded_values(&semantic, BTreeMap::from([("value".into(), invalid)])).is_err()
                );
            }
            let text = "\u{1}".repeat(BODY_BYTES);
            assert_eq!(
                serde_json::to_string(&text).unwrap().len(),
                6 * BODY_BYTES + 2
            );
            let before = f.count().await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let prepared = f
                .prepared(&mut tx, f.save(&text, Some("seed")))
                .await
                .unwrap();
            let applied = apply_prepared_body_in(
                &f.db,
                &mut tx,
                &f.caller,
                &mut crate::act::ActAllocation::new(),
                prepared,
            )
            .await
            .unwrap();
            assert!(applied.payload_bytes > BODY_BYTES);
            // Even a successful private append is NOT durable before caller commit.
            tx.rollback().await.unwrap();
            assert_eq!(f.count().await, before);
            let stored: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
                .bind(&f.target)
                .fetch_one(f.db.pool())
                .await
                .unwrap();
            assert_eq!(stored.as_deref(), Some("seed"));
        }

        #[tokio::test]
        async fn real_append_only_triggers_and_missing_trigger_structural_admission_refusal() {
            let f = Fixture::new(Some("seed")).await;
            let before = f.count().await;
            for sql in [
                "UPDATE content_events SET actor='tampered' WHERE record_id=?",
                "DELETE FROM content_events WHERE record_id=?",
            ] {
                assert!(sqlx::query(sql)
                    .bind(&f.target)
                    .execute(f.db.write_pool())
                    .await
                    .is_err());
            }
            assert_eq!(f.count().await, before);
            assert!(crate::db::validate_current_engine_shape_read_only(&f.path)
                .await
                .is_ok());
            // Isolated fixture breaks structural admission, not ordinary open.
            // This is not universal restore-lifetime proof or an adapter guard.
            sqlx::query("DROP TRIGGER content_events_no_delete")
                .execute(f.db.write_pool())
                .await
                .unwrap();
            assert!(crate::db::validate_current_engine_shape_read_only(&f.path)
                .await
                .is_err());
            let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE type='trigger' AND name='content_events_no_delete'")
                .fetch_one(f.db.pool()).await.unwrap();
            assert_eq!(remaining, 0); // Read-only validation did not repair it.
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn direct_enrolled_entry_refuses_before_sql_or_job_allocation() {
            let f = Fixture::new(Some("seed")).await;
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let snapshot = prepare_snapshot_in(&f.db, &mut tx, &f.caller, &f.target)
                .await
                .unwrap();
            let prepared = f
                .prepared(&mut tx, f.save("next", Some("seed")))
                .await
                .unwrap();
            tx.rollback().await.unwrap();
            f.db.drain_captures_for_tests().await;
            crate::db::checkpoint_and_close_hosted_adoption_database(f.db.clone())
                .await
                .unwrap();
            std::fs::create_dir(f.directory.path().join("databases")).unwrap();
            let generation = Uuid::new_v4().to_string();
            let path = f
                .directory
                .path()
                .join("databases")
                .join(format!("{generation}.db"));
            let enrollment = crate::managed_custody::reserve_fresh_adoption(
                f.directory.path(),
                &path,
                &generation,
            )
            .unwrap();
            std::fs::copy(&f.path, &path).unwrap();
            enrollment.finalize().unwrap();
            let enrolled = crate::db::open_existing_database_at(&path).await.unwrap();
            assert!(enrolled.is_enrolled());
            assert!(refuse_enrolled(&enrolled)
                .unwrap_err()
                .to_string()
                .contains("enrolled_unsupported"));
            // An unrelated unenrolled transaction must not sneak the enrolled
            // Db through a direct internal call; guard precedes any SQL use.
            let plain = crate::create_database(":memory:").await.unwrap();
            let mut tx = crate::db::begin_write(plain.write_pool()).await.unwrap();
            assert!(
                prepare_snapshot_in(&enrolled, &mut tx, &f.caller, &f.target)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("enrolled_unsupported")
            );
            assert!(prepare_body_write_in(
                &enrolled,
                &mut tx,
                &f.caller,
                snapshot,
                f.save("next", Some("seed")),
                None
            )
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("enrolled_unsupported"));
            let mut act = crate::act::ActAllocation::new();
            assert!(
                apply_prepared_body_in(&enrolled, &mut tx, &f.caller, &mut act, prepared)
                    .await
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("enrolled_unsupported")
            );
            assert!(act.get().is_none());
            tx.rollback().await.unwrap();
        }
    }
}

pub(crate) use body_effect_preparation::{
    save_body_from_artifact, undo_body_from_artifact, ArtifactBodyOutcome, ArtifactBodySavePlan,
};

/// Input context for [`record_update_in`]: the ordinary record-update
/// mutation and post-write validation inputs, primitives only (no
/// `UpdateRecordArgs`), so a later trusted caller can reuse the seam.
struct RecordUpdateInput<'a> {
    db: &'a Db,
    tx: &'a mut sqlx::Transaction<'static, sqlx::Sqlite>,
    act_alloc: &'a mut crate::act::ActAllocation,
    caller: &'a Caller,
    tool: &'static str,
    record_id: &'a str,
    fields: Map<String, Value>,
    // Reserved metadata is assembled only after ordinary change classification.
    // Ordinary updates supply None; the inactive scoped session driver supplies
    // snapshot-derived metadata after its own authenticated admission.
    version_metadata: Option<&'a crate::coedit::version_metadata::VersionMetadata<'a>>,
    has_kind: bool,
    has_lifecycle: bool,
    has_summary: bool,
    facet_specs: Vec<AppendSpec>,
    facet_writes: &'a [FacetWrite],
    facet_unsets: &'a BTreeSet<String>,
    schema_rows: &'a [cascade::SchemaConfigRow],
    links: &'a [NewLink],
    relationship_link_indexes: &'a BTreeSet<usize>,
    before: &'a BTreeSet<RequiredViolation>,
}

/// Owned outputs of [`record_update_in`] used after the seam returns. The
/// caller keeps authorization, ordinary CAS/guard, home/cycle checks, the
/// pre-seam `before` capture, and compact/version/commit/response shaping.
struct RecordUpdateOutcome {
    record_event: Option<crate::events::EventRow>,
    html_body_write: Option<Value>,
    source_changed: bool,
    artifact_input_continuity: Option<Value>,
    record_type: String,
    resulting_kind: Option<String>,
    resulting_effective_kind: Option<String>,
    non_body_changed: bool,
}

/// Ordinary SQLite record-update mutation + post-write validation seam.
///
/// Scope: this is a private ordinary-path prerequisite, NOT a safe or
/// complete version seam, and NOT an authority or mirror-parity boundary.
/// `prospective_body_in` and the transaction-bound validators are
/// SQLite-typed, so Postgres/Turso parity is unmet. Authority decisions
/// (`require_record_in`), ordinary CAS/guard, home/cycle checks, commit and
/// response shaping deliberately stay in the caller.
async fn record_update_in(input: RecordUpdateInput<'_>) -> Result<RecordUpdateOutcome> {
    let RecordUpdateInput {
        db,
        tx,
        act_alloc,
        caller,
        tool,
        record_id,
        fields,
        version_metadata,
        has_kind,
        has_lifecycle,
        has_summary,
        facet_specs,
        facet_writes,
        facet_unsets,
        schema_rows,
        links,
        relationship_link_indexes,
        before,
    } = input;
    let ProspectiveBody {
        record_type,
        resulting_kind,
        resulting_effective_kind,
        resulting_body,
        html_body_write,
        updates_instruction_body,
        artifact_attestation,
        source_changed,
        continuity_snapshot,
        continuity_old_surface,
    } = prospective_body_in(
        tx,
        &ProspectiveBodyInput {
            tool,
            record_id,
            fields: &fields,
            has_kind,
            has_lifecycle,
            has_summary,
            facet_unsets,
            facet_writes,
            schema_rows,
        },
    )
    .await?;
    let mut artifact_input_continuity = None;
    // S1 advisor no-op signal: whether this call observably changes anything
    // besides the body (judged separately via `body_content_changed`).
    // Non-body field, facet and link writes always append — the engine does
    // no content dedup on them — so their presence is the signal, even when
    // the value is identical to current: that over-firing is the accepted
    // boundary (the receipt carries an act for those writes too). `reason`
    // and `basis` ride along on the first event and are not changes
    // themselves.
    let non_body_changed = fields
        .keys()
        .any(|key| !matches!(key.as_str(), "body" | "reason" | "basis"))
        || !facet_specs.is_empty()
        // Links-alone never reaches here (rejected as no-changes above), but
        // links alongside a content-identical body still change the record,
        // so the arm stays.
        || !links.is_empty();
    let record_event = if !fields.is_empty() {
        Some(
            append_in(
                db,
                tx,
                AppendSpec {
                    record_id: record_id.to_string(),
                    event_type: "record.updated".into(),
                    payload: Value::Object(
                        crate::coedit::version_metadata::record_updated_payload(
                            fields,
                            version_metadata,
                        )?,
                    ),
                    actor: Some(caller.actor().into()),
                },
                act_alloc,
            )
            .await?,
        )
    } else {
        None
    };
    for spec in facet_specs {
        append_in(db, tx, spec, act_alloc).await?;
    }
    // Links emit after the record/facet events in the same transaction, never
    // carrying reason or basis (those rode on the first event above). A
    // relationship-owned link routes through the sealed legacy adapter under
    // one reserved action identity for the whole call, exactly as
    // create_record does; everything else appends link.added.
    let link_draft = if relationship_link_indexes.is_empty() {
        None
    } else {
        Some(crate::provenance::reserve_action_attestation()?)
    };
    for (index, link) in links.iter().enumerate() {
        if relationship_link_indexes.contains(&index) {
            crate::relationship::legacy::mutate_from_update_record_in(
                tx,
                caller,
                record_id,
                &link.target_id,
                &link.relationship,
                link.note.clone(),
                link_draft
                    .as_ref()
                    .expect("relationship links reserve one action identity"),
                act_alloc,
            )
            .await?;
        } else {
            append_in(
                db,
                tx,
                AppendSpec {
                    record_id: record_id.to_string(),
                    event_type: "link.added".into(),
                    payload: serde_json::to_value(crate::events::LinkAddedPayload {
                        id: None,
                        source_id: record_id.to_string(),
                        target_id: link.target_id.clone(),
                        relationship: link.relationship.clone(),
                        note: link.note.clone(),
                    })?,
                    actor: Some(caller.actor().into()),
                },
                act_alloc,
            )
            .await?;
        }
    }
    if let Some(draft) = link_draft {
        crate::provenance::issue_reserved_pending_action_in(tx, draft).await?;
    }
    if let Some(compiler_attestation) = artifact_attestation {
        let (source_event_id, source) = if source_changed {
            (
                record_event
                    .as_ref()
                    .expect("a body change emits record.updated")
                    .id
                    .clone(),
                resulting_body
                    .as_deref()
                    .expect("validated v2 artifact has a body")
                    .to_owned(),
            )
        } else {
            let row = sqlx::query(
                "SELECT id,json_extract(payload,'$.body') AS body FROM content_events
                  WHERE record_id=? AND type IN ('record.created','record.updated','receipt.committed.v1')
                    AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
            )
            .bind(record_id)
            .fetch_one(&mut **tx)
            .await?;
            (row.try_get("id")?, row.try_get("body")?)
        };
        let already_attested: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM artifact_source_attestations
              WHERE artifact_id=? AND source_event_id=?)",
        )
        .bind(record_id)
        .bind(&source_event_id)
        .fetch_one(&mut **tx)
        .await?;
        if !already_attested {
            let attestation_event_id = Uuid::new_v4().to_string();
            let payload = super::artifacts::artifact_source_attestation_payload(
                record_id,
                &attestation_event_id,
                &source_event_id,
                &source,
                compiler_attestation,
            )?;
            let new_descriptor = payload.artifact_source.clone();
            let new_source_sha256 = new_descriptor["source_sha256"]
                .as_str()
                .expect("artifact source payload has a verified digest")
                .to_owned();
            append_with_event_id_in(
                db,
                tx,
                attestation_event_id.clone(),
                AppendSpec {
                    record_id: record_id.to_string(),
                    event_type: "artifact.source_attested".into(),
                    payload: serde_json::to_value(payload)?,
                    actor: Some(caller.actor().into()),
                },
                act_alloc,
            )
            .await?;
            let new_surface = super::artifacts::declaration_surface_sha256(&new_descriptor)?;
            if continuity_snapshot.is_none() {
                if let Some(old_surface) = continuity_old_surface.clone() {
                    artifact_input_continuity = Some(json!({
                        "status": "artifact_inputs_no_existing_state",
                        "ports": [],
                        "carried_binding_count": 0,
                        "dropped_binding_count": 0,
                        "carried_grant_count": 0,
                        "dropped_grant_count": 0,
                        "changed_ports": [],
                        "dropped": [],
                        "old_declaration_surface_sha256": old_surface,
                        "new_declaration_surface_sha256": new_surface,
                        "restoration_tools": [],
                        "source_event_id": source_event_id.clone(),
                        "source_sha256": new_source_sha256.clone(),
                    }));
                }
            }
            if let Some(snapshot) = continuity_snapshot {
                let old_surface = continuity_old_surface
                    .expect("a continuity snapshot has an old surface digest");
                let mut ports = snapshot
                    .bindings
                    .iter()
                    .map(|binding| binding.port_name.clone())
                    .collect::<BTreeSet<_>>();
                for grant in &snapshot.grants {
                    if let Some(port) = grant
                        .payload
                        .scope
                        .get("artifact_port")
                        .and_then(Value::as_str)
                    {
                        ports.insert(port.to_owned());
                    }
                }
                let binding_count = snapshot.bindings.len();
                let grant_count = snapshot.grants.len();
                let mut carried_bindings = 0usize;
                let mut dropped_bindings = 0usize;
                let mut carried_grants = 0usize;
                let mut dropped_grants = 0usize;
                // Per-port carry: a binding survives iff its own port
                // declaration is unchanged; a grant naming an `artifact_port`
                // survives iff that port is unchanged and the new source still
                // declares the identical capability request; a grant with no
                // port in scope (navigation) is gated only on the request. A
                // renamed port is a different port and drops; adding a port
                // drops nothing.
                let changed =
                    super::artifacts::changed_ports(&snapshot.descriptor, &new_descriptor)?;
                let changed_list = changed.iter().cloned().collect::<Vec<_>>();
                let mut dropped: Vec<Value> = Vec::new();
                for binding in snapshot.bindings {
                    let port_name = binding.port_name.clone();
                    let collection_id = binding.collection_id.clone();
                    if changed.contains(&port_name) {
                        append_in(
                            db,
                            tx,
                            AppendSpec {
                                record_id: record_id.to_string(),
                                event_type: "artifact.input_unbound".into(),
                                payload: serde_json::to_value(ArtifactInputUnboundPayload {
                                    artifact_id: record_id.to_string(),
                                    port_name: port_name.clone(),
                                })?,
                                actor: Some(caller.actor().into()),
                            },
                            act_alloc,
                        )
                        .await?;
                        dropped_bindings += 1;
                        dropped.push(json!({
                            "kind": "binding",
                            "port": port_name,
                            "capability": Value::Null,
                            "scope": Value::Null,
                            "collection_id": collection_id,
                        }));
                        continue;
                    }
                    let new_binding = super::artifacts::carried_input_payload(
                        record_id,
                        &binding.port_name,
                        &binding.collection_id,
                        &attestation_event_id,
                        &source_event_id,
                        &new_source_sha256,
                        &new_descriptor,
                    )?;
                    append_in(
                        db,
                        tx,
                        AppendSpec {
                            record_id: record_id.to_string(),
                            event_type: "artifact.input_carried".into(),
                            payload: serde_json::to_value(ArtifactInputCarriedPayload {
                                binding: new_binding,
                                predecessor_binding_event_seq: binding.event_seq,
                                predecessor_source_attestation_event_id: snapshot
                                    .source_attestation_event_id
                                    .clone(),
                                predecessor_source_event_id: snapshot.source_event_id.clone(),
                                predecessor_source_sha256: snapshot.source_sha256.clone(),
                                old_declaration_surface_sha256: old_surface.clone(),
                                new_declaration_surface_sha256: new_surface.clone(),
                            })?,
                            actor: Some(caller.actor().into()),
                        },
                        act_alloc,
                    )
                    .await?;
                    carried_bindings += 1;
                }
                for predecessor in snapshot.grants {
                    let port = predecessor
                        .payload
                        .scope
                        .get("artifact_port")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let dropped_grant = json!({
                        "kind": "grant",
                        "port": port.clone(),
                        "capability": predecessor.payload.capability.clone(),
                        "scope": predecessor.payload.scope.clone(),
                    });
                    if port.as_ref().is_some_and(|port| changed.contains(port)) {
                        append_in(
                            db,
                            tx,
                            AppendSpec {
                                record_id: record_id.to_string(),
                                event_type: "artifact.module_grant_unset".into(),
                                payload: serde_json::to_value(predecessor.payload)?,
                                actor: Some(caller.actor().into()),
                            },
                            act_alloc,
                        )
                        .await?;
                        dropped_grants += 1;
                        dropped.push(dropped_grant.clone());
                        continue;
                    }
                    let mut grant = predecessor.payload.clone();
                    if grant.subject_kind == "artifact_source" {
                        grant.subject_event_id = source_event_id.clone();
                        grant.source_sha256 = new_source_sha256.clone();
                    }
                    match super::artifacts::try_build_carried_grant_attestation_in(
                        tx, caller, &grant,
                    )
                    .await?
                    {
                        Some((attestation, digest)) => {
                            grant.attestation = Some(attestation);
                            grant.attestation_sha256 = Some(digest);
                            append_in(
                                db,
                                tx,
                                AppendSpec {
                                    record_id: record_id.to_string(),
                                    event_type: "artifact.module_grant_carried".into(),
                                    payload: serde_json::to_value(
                                        ArtifactModuleGrantCarriedPayload {
                                            grant,
                                            predecessor: predecessor.payload,
                                            predecessor_grant_event_seq: predecessor.event_seq,
                                            predecessor_source_attestation_event_id: snapshot
                                                .source_attestation_event_id
                                                .clone(),
                                            predecessor_source_event_id: snapshot
                                                .source_event_id
                                                .clone(),
                                            predecessor_source_sha256: snapshot
                                                .source_sha256
                                                .clone(),
                                            old_declaration_surface_sha256: old_surface.clone(),
                                            new_declaration_surface_sha256: new_surface.clone(),
                                        },
                                    )?,
                                    actor: Some(caller.actor().into()),
                                },
                                act_alloc,
                            )
                            .await?;
                            carried_grants += 1;
                        }
                        None => {
                            append_in(
                                db,
                                tx,
                                AppendSpec {
                                    record_id: record_id.to_string(),
                                    event_type: "artifact.module_grant_unset".into(),
                                    payload: serde_json::to_value(predecessor.payload)?,
                                    actor: Some(caller.actor().into()),
                                },
                                act_alloc,
                            )
                            .await?;
                            dropped_grants += 1;
                            dropped.push(dropped_grant.clone());
                        }
                    }
                }
                // The status reports how much survived, and nothing about why.
                // Naming a cause here is what made the old
                // artifact_inputs_dropped_by_declaration_change false in both
                // directions: a total drop with identical declarations does not
                // deserve the name, and adding a port sets changed_ports without
                // dropping anything. Cause lives in changed_ports and dropped[].
                let status = if binding_count == 0 && grant_count == 0 {
                    "artifact_inputs_no_existing_state"
                } else if carried_bindings == 0 && carried_grants == 0 {
                    "artifact_inputs_dropped"
                } else if dropped_bindings > 0 || dropped_grants > 0 {
                    "artifact_inputs_partially_carried"
                } else {
                    "artifact_inputs_carried_forward"
                };
                artifact_input_continuity = Some(json!({
                    "status": status,
                    "ports": ports.into_iter().collect::<Vec<_>>(),
                    "carried_binding_count": carried_bindings,
                    "dropped_binding_count": dropped_bindings,
                    "carried_grant_count": carried_grants,
                    "dropped_grant_count": dropped_grants,
                    "changed_ports": changed_list,
                    "dropped": dropped,
                    "old_declaration_surface_sha256": old_surface,
                    "new_declaration_surface_sha256": new_surface,
                    "restoration_tools": if dropped_bindings > 0 {
                        json!(["manage_artifact_inputs", "manage_artifact_module_grants"])
                    } else if dropped_grants > 0 {
                        json!(["manage_artifact_module_grants"])
                    } else {
                        json!([])
                    },
                    "source_event_id": source_event_id.clone(),
                    "source_sha256": new_source_sha256.clone(),
                }));
            }
        }
    }
    if updates_instruction_body && crate::instructions::source_is_active_in(tx, record_id).await? {
        crate::instructions::validate_all_known_stacks_in(
            tx,
            tool,
            caller.credential(),
            caller.is_host_member(),
            caller.is_host_owner(),
        )
        .await?;
    }
    let after = required_violations_in(tx, schema_rows, &[record_id]).await?;
    assert_required_not_worsened(tool, before, &after)?;
    Ok(RecordUpdateOutcome {
        record_event,
        html_body_write,
        source_changed,
        artifact_input_continuity,
        record_type,
        resulting_kind,
        resulting_effective_kind,
        non_body_changed,
    })
}

async fn update_record_singular(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "update_record";
    reject_null_sources(TOOL, &arguments)?;
    // `body_replace: null` would fold to `None` through `Option<Vec<..>>`
    // and silently vanish — including alongside another body op. Reject the
    // explicit null up front so malformed input cannot bypass exclusivity.
    if arguments.get("body_replace").is_some_and(Value::is_null) {
        return Err(Error::engine(format!(
            "{TOOL}: 'body_replace' must be an array of {{old, new}} edits, got null"
        )));
    }
    let mut args: UpdateRecordArgs = parse_args(TOOL, arguments)?;
    let response_mode = args.response_mode;
    require_nonblank_reason(TOOL, &args.reason)?;
    let source_inputs = args.sources.take();
    let touches_message_expectation = args.facets.as_ref().is_some_and(|facets| {
        facets.contains_key(crate::message_expectation::EXPECTATION_FACET_KEY)
    });

    // `body` (deprecated full-replacement alias), `body_set` (full
    // replacement), `body_append` (literal append) and `body_replace`
    // (surgical edits) are mutually exclusive — even when null. Presence,
    // not value, decides: an explicit null still names the operation.
    let present_body_ops = [
        ("body", args.body.is_some()),
        ("body_set", args.body_set.is_some()),
        ("body_append", args.body_append.is_some()),
        ("body_replace", args.body_replace.is_some()),
    ]
    .into_iter()
    .filter(|(_, present)| *present)
    .map(|(name, _)| name)
    .collect::<Vec<_>>();
    if present_body_ops.len() > 1 {
        return Err(Error::engine(format!(
            "{TOOL}: {} are mutually exclusive (got {})",
            present_body_ops.join(", "),
            present_body_ops.join(" + "),
        )));
    }
    if let Some(value) = &args.body_set {
        match value {
            Value::String(_) | Value::Null => {}
            other => {
                return Err(Error::engine(format!(
                    "{TOOL}: 'body_set' must be a string or null, got {other}"
                )));
            }
        }
    }
    if let Some(value) = &args.body_append {
        match value {
            Value::String(_) => {}
            Value::Null => {
                return Err(Error::engine(format!(
                    "{TOOL}: 'body_append' must be a string; clearing the body is a replacement, use 'body_set' with null"
                )));
            }
            other => {
                return Err(Error::engine(format!(
                    "{TOOL}: 'body_append' must be a string, got {other}"
                )));
            }
        }
    }

    let mut fields = Map::new();
    for key in UPDATABLE_FIELDS {
        let Some(value) = args.field(key) else {
            continue;
        };
        match value {
            Value::String(_) | Value::Null => {}
            other => {
                return Err(Error::engine(format!(
                    "{TOOL}: '{key}' must be a string or null, got {other}"
                )));
            }
        }
        if key == "home_id" && value.is_null() {
            return Err(Error::engine(format!(
                "{TOOL}: cannot clear home_id — only the engine root has a null home"
            )));
        }
        if key == "persistence" && value.is_null() {
            // Mirrors the projector's facet.unset guard: persistence is the
            // required spine facet (2e5ed3e Am.2 §3).
            return Err(Error::engine(format!(
                "{TOOL}: cannot clear persistence — it is a required spine facet (set enduring|occurrent)"
            )));
        }
        if key == "name" && value.is_null() {
            return Err(Error::engine(format!(
                "{TOOL}: 'name' cannot be null — set an empty string to clear it"
            )));
        }
        if key == "kind" && !matches!(value, Value::String(kind) if !kind.is_empty()) {
            return Err(Error::engine(format!(
                "{TOOL}: 'kind' must be a non-empty string; kind is replaceable but cannot be cleared"
            )));
        }
        if key == "kind" {
            crate::freshness::reject_reserved_semantic_unit_kind(
                value.as_str().expect("kind was checked as a string above"),
                TOOL,
            )?;
        }
        fields.insert(key.into(), value.clone());
    }
    // `body_set` is the explicit full-replacement verb: same payload shape as
    // legacy `body`, carried under the `body` event key.
    if let Some(value) = &args.body_set {
        fields.insert("body".into(), value.clone());
    }

    // The root's `name` is the only mutable field on it — `kind`, `home_id`
    // and `persistence` are refused by the projector's engine-filing guard —
    // so gating the name is gating the workspace rename. The rule itself lives
    // in one place for every backend.
    super::require_workspace_rename_authority(TOOL, &caller, &args.id, fields.get("name"))?;

    let mut facet_specs = Vec::new();
    let mut facet_writes = Vec::new();
    let mut facet_unsets = BTreeSet::new();
    for (key, value) in args.facets.iter().flatten() {
        match parse_facet_entry(TOOL, key, value, true)? {
            Some(facet) => {
                facet_specs.push(facet_set_spec(&args.id, &facet, caller.actor()));
                facet_writes.push(facet);
            }
            None => {
                facet_unsets.insert(key.clone());
                facet_specs.push(AppendSpec {
                    record_id: args.id.clone(),
                    event_type: "facet.unset".into(),
                    payload: json!({ "key": key }),
                    actor: Some(caller.actor().into()),
                });
            }
        }
    }
    let links = args.links.unwrap_or_default();
    // Add-only links in the create_record-compatible shape. Links ride along
    // with a record edit — they do not satisfy the no-changes guard on their
    // own (manage_links.add remains the links-only path). This keeps the
    // reason/basis placement below untouched: the first emitted event is
    // always the record.updated field event or the first facet event, never
    // a link event.
    for link in &links {
        if link.relationship.trim().is_empty() {
            return Err(Error::engine(format!(
                "{TOOL}: link relationship must contain non-whitespace text"
            )));
        }
        if link.relationship == "addressed_to" {
            return Err(Error::engine(format!(
                "{TOOL}: addressed_to must use the Message addressed_to field"
            )));
        }
    }
    if fields.is_empty()
        && facet_specs.is_empty()
        && args.body_replace.is_none()
        && args.body_append.is_none()
    {
        return Err(Error::engine(format!(
            "{TOOL}: no changes — pass at least one field or facet"
        )));
    }
    // AFTER the no-changes guard, deliberately: `reason` must not be able to make
    // an empty update look like a real one. A call carrying prose and nothing
    // else is still a call that changes nothing, and it should say so.
    //
    // The reason rides on the FIRST event this call emits, and on exactly one —
    // a facet-only update emits no `record.updated`, so attaching it there
    // unconditionally would silently drop the prose the caller was required to
    // supply, while copying it onto every event would inflate one reason into
    // several and corrupt any later count of them.
    if !fields.is_empty() || args.body_replace.is_some() || args.body_append.is_some() {
        fields.insert("reason".into(), json!(args.reason));
    } else if let Some(first) = facet_specs.first_mut() {
        if let Some(payload) = first.payload.as_object_mut() {
            payload.insert("reason".into(), json!(args.reason));
        }
    }

    if let Some(Value::String(new_home)) = &args.home_id {
        if *new_home == args.id {
            return Err(Error::engine(format!(
                "{TOOL}: record {} cannot be its own home",
                args.id
            )));
        }
    }

    // ONE record.updated carrying the changed-field object (never per-field —
    // tool-surface §event granularity), plus one facet event per facet
    // touched, all in one write transaction. Tombstone rejection comes from
    // the projector's live-record guard. The rehome guards (liveness AND
    // the cycle check) run inside the transaction: `BEGIN IMMEDIATE`
    // serializes writers, so a concurrent cross-rehome cannot slip a cycle
    // past a check that already committed.
    let mut tx = crate::db::enrolled::begin_document_write(&db).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    let structural = args.home_id.is_some();
    require_record_in(
        &mut tx,
        &caller,
        TOOL,
        &args.id,
        if structural {
            Capability::Manage
        } else {
            Capability::Edit
        },
    )
    .await?;
    if db.is_enrolled() {
        let row = sqlx::query("SELECT type,kind,deleted_at,EXISTS(SELECT 1 FROM facet_values WHERE record_id=records.id AND key='runtime') AS runtime_present FROM records WHERE id=?")
            .bind(&args.id).fetch_one(&mut *tx).await?;
        let (artifact, instruction) = if let Some(kind) =
            row.try_get::<Option<String>, _>("kind")?
        {
            let resolved = crate::meta::kind::resolve_on(&mut tx, "Document", &kind).await?;
            (
                kind == "artifact"
                    || crate::generated::kinds::CoreKind::DocumentArtifact.matches(&resolved),
                kind == "instruction" || resolved.canonical_kind.as_deref() == Some("instruction"),
            )
        } else {
            (false, false)
        };
        if row.try_get::<String, _>("type")? != "Document"
            || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
            || row.try_get::<bool, _>("runtime_present")?
            || artifact
            || instruction
        {
            tx.rollback().await?;
            return Err(Error::engine(
                "enrolled body update requires a live non-artifact, non-instruction Document without runtime",
            ));
        }
    }
    if db.is_enrolled() {
        if let Err(error) = crate::coedit::driver::refuse_ordinary_write(&db, &args.id) {
            tx.rollback().await?;
            return Err(error);
        }
    }
    // Link preflight, before any event is appended: the source Edit above
    // already covers manage_links' source side, so each link needs only its
    // target View, bearer-immutability, reserved-relationship refusal, and
    // relationship-ownership classification. Every failure here rolls the
    // whole call back — the record edit and the links commit together or not
    // at all.
    let mut relationship_link_indexes = BTreeSet::new();
    for (index, link) in links.iter().enumerate() {
        crate::surface_binding::refuse_reserved_surface_binding(TOOL, &link.relationship)?;
        require_record_in(&mut tx, &caller, TOOL, &link.target_id, Capability::View).await?;
        crate::comments::assert_bearer_immutable_on(&mut tx, TOOL, &args.id, &link.relationship)
            .await?;
        if super::links::relationship_owned_in(
            &mut tx,
            &args.id,
            &link.target_id,
            &link.relationship,
        )
        .await?
        {
            relationship_link_indexes.insert(index);
        }
    }
    if let Some(Value::String(new_home)) = &args.home_id {
        let origin = sqlx::query(
            "SELECT status,origin_type,collection_id
               FROM message_origin_state WHERE message_id=?",
        )
        .bind(&args.id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(origin) = origin {
            if origin.try_get::<String, _>("status")? == "declared"
                && origin
                    .try_get::<Option<String>, _>("origin_type")?
                    .as_deref()
                    == Some("collection")
                && origin
                    .try_get::<Option<String>, _>("collection_id")?
                    .as_deref()
                    != Some(new_home.as_str())
            {
                return Err(Error::engine(
                    "update_record: a Collection-origin Message must remain filed in its authored Collection",
                ));
            }
        }
    }
    if let Some(owner_value) = args.owner_id.as_ref() {
        let new_owner = owner_value.as_str().ok_or_else(|| {
            Error::engine(format!("{TOOL}: owner_id must be a portable identity id"))
        })?;
        if !super::is_legacy_local(&caller) {
            let current_owner: Option<String> = sqlx::query_scalar(
                "SELECT owner_id FROM records WHERE id = ? AND deleted_at IS NULL",
            )
            .bind(&args.id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
            let owns: bool = match current_owner {
                Some(owner) => {
                    sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM bindings
                      WHERE record_id = ? AND system = 'account'
                        AND identifier = ? AND is_canonical = 1)",
                    )
                    .bind(owner)
                    .bind(caller.credential())
                    .fetch_one(&mut *tx)
                    .await?
                }
                None => false,
            };
            if !owns {
                return Err(Error::engine(
                    "update_record: changing owner_id is reserved to the record's current owner",
                ));
            }
            let target_bound: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM bindings
                  WHERE record_id = ? AND system = 'account' AND is_canonical = 1)",
            )
            .bind(new_owner)
            .fetch_one(&mut *tx)
            .await?;
            if !target_bound {
                return Err(Error::engine(format!(
                    "{TOOL}: owner_id must name a verified portable identity"
                )));
            }
        }
    }
    if let Some(Value::String(new_home)) = &args.home_id {
        require_record_in(&mut tx, &caller, TOOL, new_home, Capability::Edit).await?;
    }
    // Assembled inside the transaction and rendered after it rolls back, for
    // the same reason the other two refusals are: minting a display reference
    // scans the id space and must not run while the write lock is held.
    let mut timestamp_conflict: Option<BodyGuardTarget> = None;
    if let Some(expected_raw) = args.if_unmodified_since.as_deref() {
        let expected = chrono::DateTime::parse_from_rfc3339(expected_raw).map_err(|_| {
            Error::engine(format!(
                "{TOOL}: 'if_unmodified_since' must be an RFC3339 timestamp"
            ))
        })?;
        let row = sqlx::query(
            "SELECT body, name, updated_at FROM records WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(&args.id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: record {} does not exist", args.id)))?;
        let current_raw: String = row.try_get("updated_at")?;
        let current = chrono::DateTime::parse_from_rfc3339(&current_raw).map_err(|_| {
            Error::engine(format!(
                "{TOOL}: record {} has an invalid stored updated_at timestamp",
                args.id
            ))
        })?;
        if expected != current {
            timestamp_conflict = Some(BodyGuardTarget {
                id: args.id.clone(),
                name: row.try_get("name")?,
                display_reference: None,
                body_digest: body_digest(row.try_get::<Option<String>, _>("body")?.as_deref()),
                updated_at: current_raw,
            });
        }
    }
    if let Some(mut target) = timestamp_conflict {
        if db.is_enrolled() {
            crate::db::enrolled::phase(crate::db::enrolled::Phase::BeforeRollback).await;
            tx.rollback().await?;
        } else {
            drop(tx);
        }
        target.display_reference = crate::mcp::record_ref::display_reference(&db, &args.id).await?;
        return Err(stale_unmodified_since_error(TOOL, &target));
    }
    if touches_message_expectation {
        let record_type: Option<String> =
            sqlx::query_scalar("SELECT type FROM records WHERE id = ?")
                .bind(&args.id)
                .fetch_optional(&mut *tx)
                .await?;
        if record_type.as_deref() == Some("Message") {
            return Err(Error::engine(
                "update_record: Message expectation is immutable sender-authored content; create a superseding Message to correct it",
            ));
        }
    }
    if let Some(Value::String(raw_kind)) = fields.get("kind").cloned() {
        let record_type: String = sqlx::query_scalar("SELECT type FROM records WHERE id = ?")
            .bind(&args.id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| Error::engine(format!("{TOOL}: record {} does not exist", args.id)))?;
        let resolution = crate::meta::kind::resolve_on(&mut tx, &record_type, &raw_kind).await?;
        if !resolution.quarantined
            && resolution.canonical_value_id.as_deref()
                == Some("vv:voc:kind:Annotation:attribution")
        {
            let current_kind: Option<String> =
                sqlx::query_scalar("SELECT kind FROM records WHERE id = ?")
                    .bind(&args.id)
                    .fetch_one(&mut *tx)
                    .await?;
            if current_kind.as_deref() != Some("attribution") {
                return Err(Error::engine(
                    "update_record: governed attribution identity cannot be added in place; use create_attribution",
                ));
            }
        }
        if let Some(canonical) = resolution.canonical_kind_for_write() {
            fields.insert("kind".into(), json!(canonical));
        }
    }
    // The basis follows the `reason` rule exactly: on the first event this call
    // emits — the `record.updated` field event when there is one, else the
    // first facet event — and never on the link or later facet events the same
    // call emits. `reason` was placed before the transaction opened; the basis
    // must be resolved inside it, so it is placed here under the identical
    // condition.
    if let Some(basis) =
        resolve_source_basis_in(&mut tx, &caller, TOOL, source_inputs.as_deref()).await?
    {
        if !fields.is_empty() || args.body_replace.is_some() || args.body_append.is_some() {
            fields.insert("basis".into(), basis);
        } else if let Some(first) = facet_specs.first_mut() {
            if let Some(payload) = first.payload.as_object_mut() {
                payload.insert("basis".into(), basis);
            }
        }
    }
    let previous_seq = previous_record_seq_in(&mut tx, &args.id).await?;
    let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
    let shape_context_may_change = args.kind.is_some();
    if !facet_writes.is_empty() || shape_context_may_change || args.lifecycle.is_some() {
        let current = sqlx::query("SELECT type, kind, lifecycle FROM records WHERE id = ?")
            .bind(&args.id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(current) = current else {
            return Err(Error::engine(format!(
                "{TOOL}: record {} does not exist",
                args.id
            )));
        };
        let record_type: String = current.try_get("type")?;
        let current_kind: Option<String> = current.try_get("kind")?;
        let current_lifecycle: Option<String> = current.try_get("lifecycle")?;
        let current_effective_kind = if let Some(kind) = current_kind.as_deref() {
            let resolution = crate::meta::kind::resolve_on(&mut tx, &record_type, kind).await?;
            Some(
                resolution
                    .canonical_kind_for_write()
                    .unwrap_or(kind)
                    .to_string(),
            )
        } else {
            None
        };
        let resulting_kind = match fields.get("kind") {
            Some(Value::String(kind)) => Some(kind.clone()),
            Some(_) => unreachable!("field validation rejects non-string kind"),
            None => current_kind.clone(),
        };
        let resulting_effective_kind = if let Some(kind) = resulting_kind.as_deref() {
            let resolution = crate::meta::kind::resolve_on(&mut tx, &record_type, kind).await?;
            Some(
                resolution
                    .canonical_kind_for_write()
                    .unwrap_or(kind)
                    .to_string(),
            )
        } else {
            None
        };
        let current_is_comment = if let Some(kind) = current_kind.as_deref() {
            let resolution = crate::meta::kind::resolve_on(&mut tx, &record_type, kind).await?;
            crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution)
        } else {
            false
        };
        if !current_is_comment {
            if let Some(Value::String(lifecycle)) = &args.lifecycle {
                let mut lifecycle_write = [FacetWrite {
                    key: "lifecycle".into(),
                    value: Value::String(lifecycle.clone()),
                    vocab_ref: None,
                    time_type: None,
                }];
                assert_facet_value_predicates_in(
                    &mut tx,
                    &schema_rows,
                    TOOL,
                    &record_type,
                    resulting_effective_kind.as_deref(),
                    None,
                    &mut lifecycle_write,
                )
                .await?;
            }
        }
        let shape_context_changed = resulting_effective_kind != current_effective_kind;
        if shape_context_changed && !current_is_comment {
            let resulting_lifecycle = match &args.lifecycle {
                Some(Value::String(lifecycle)) => Some(lifecycle.clone()),
                Some(Value::Null) => None,
                Some(_) => unreachable!("field validation rejects non-string lifecycle"),
                None => current_lifecycle,
            };
            if let Some(lifecycle) = resulting_lifecycle {
                let mut lifecycle_write = [FacetWrite {
                    key: "lifecycle".into(),
                    value: Value::String(lifecycle),
                    vocab_ref: None,
                    time_type: None,
                }];
                assert_facet_value_predicates_in(
                    &mut tx,
                    &schema_rows,
                    TOOL,
                    &record_type,
                    resulting_effective_kind.as_deref(),
                    None,
                    &mut lifecycle_write,
                )
                .await?;
            }
            let mut resulting_facets =
                resulting_facet_writes_in(&mut tx, &args.id, &facet_writes, &facet_unsets).await?;
            assert_facet_value_predicates_in(
                &mut tx,
                &schema_rows,
                TOOL,
                &record_type,
                resulting_effective_kind.as_deref(),
                None,
                &mut resulting_facets,
            )
            .await?;
            let checked: BTreeMap<&str, &FacetWrite> = resulting_facets
                .iter()
                .map(|facet| (facet.key.as_str(), facet))
                .collect();
            for facet in &mut facet_writes {
                facet.adopt_governed(checked.get(facet.key.as_str()).copied());
            }
        } else {
            assert_facet_value_predicates_in(
                &mut tx,
                &schema_rows,
                TOOL,
                &record_type,
                resulting_kind.as_deref(),
                None,
                &mut facet_writes,
            )
            .await?;
        }
        let mut checked = facet_writes.iter();
        for spec in &mut facet_specs {
            if spec.event_type != "facet.set" {
                continue;
            }
            let facet = checked
                .next()
                .expect("each facet.set spec has one parsed facet write");
            facet.stamp_governed_payload(&mut spec.payload);
        }
    }
    let before = required_violations_in(&mut tx, &schema_rows, &[&args.id]).await?;

    // Targeted replacement and its optional digest precondition are resolved
    // from the CURRENT projection under the same BEGIN IMMEDIATE transaction
    // that appends/projects the event. A failed match/count/digest therefore
    // cannot race a writer and cannot leave either an event or projection
    // change behind.
    // A whole-body replacement is the one write path that could previously
    // discard a concurrent edit without noticing, so it joins the targeted
    // paths under the same in-transaction resolution: the guard requirement is
    // evaluated against CURRENT state, which is why two concurrent first
    // writers against an empty body cannot both pass.
    let mut guard_failure: Option<(bool, BodyGuardTarget)> = None;
    // The body receipt carries Unicode scalar counts with an explicit unit,
    // so a destructive replacement is visible at the point it happens. The
    // operation is the requested verb — an equal-length replacement still
    // reports itself as a replacement, never as a no-op.
    let mut body_receipt: Option<Value> = None;
    let mut legacy_body_alias = false;
    // S1 advisor no-op signal: whether a body op observably changes the body.
    // `None` when no body op is present (judged by the other changes below).
    // The engine appends even content-identical bodies; advisors only care
    // about observable change.
    let mut body_content_changed: Option<bool> = None;
    if args.body.is_some()
        || args.body_set.is_some()
        || args.body_append.is_some()
        || args.body_replace.is_some()
        || args.if_body_digest.is_some()
    {
        let row =
            sqlx::query("SELECT body, name, updated_at, deleted_at FROM records WHERE id = ?")
                .bind(&args.id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(row) = row else {
            return Err(Error::engine(format!(
                "cannot apply record.updated: record {} does not exist",
                args.id
            )));
        };
        if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
            return Err(Error::engine(format!(
                "cannot apply record.updated: record {} is deleted (tombstoned)",
                args.id
            )));
        }
        let current_body: Option<String> = row.try_get("body")?;

        if let Some(expected) = &args.if_body_digest {
            if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Error::engine(format!(
                    "{TOOL}: 'if_body_digest' must be a 64-character hexadecimal SHA-256 digest"
                )));
            }
        }

        // Built eagerly so the refusal can name the record and its current
        // token; `display_reference` is filled in once the transaction has
        // rolled back, because minting one reads the whole id space.
        let target = || BodyGuardTarget {
            id: args.id.clone(),
            name: row.try_get::<Option<String>, _>("name").unwrap_or_default(),
            display_reference: None,
            body_digest: body_digest(current_body.as_deref()),
            updated_at: row
                .try_get::<Option<String>, _>("updated_at")
                .unwrap_or_default()
                .unwrap_or_default(),
        };

        if whole_body_write_needs_guard(
            args.body.is_some() || args.body_set.is_some(),
            current_body.as_deref(),
            args.if_body_digest.as_deref(),
            args.if_unmodified_since.as_deref(),
        ) {
            guard_failure = Some((true, target()));
        } else if let Some(expected) = &args.if_body_digest {
            // A record that has never carried a body stores NULL, which is the
            // same *content* as the empty string. Hashing it as "" keeps the
            // guard usable for the first body a record ever receives, and keeps
            // this precondition identical to the Postgres adapter's — see the
            // shared `null_body_digest_guard` contract scenario. The comparison
            // stays inside the write transaction, so a genuinely stale digest
            // still fails without appending an event.
            if !expected.eq_ignore_ascii_case(&body_digest(current_body.as_deref())) {
                guard_failure = Some((false, target()));
            }
        }

        if guard_failure.is_none() {
            let current_str = current_body.as_deref().unwrap_or("");
            let before_chars = current_str.chars().count() as u64;
            if let Some(append) = args.body_append.as_ref().and_then(Value::as_str) {
                // Literal append against the CURRENT body under the same BEGIN
                // IMMEDIATE transaction: no digest required, but a supplied
                // digest/timestamp was already checked above. Null reads as
                // empty; exactly the supplied text is added, no separator.
                let new_body = format!("{current_str}{append}");
                body_content_changed = Some(!append.is_empty());
                let after_chars = new_body.chars().count() as u64;
                body_receipt = Some(json!({
                    "operation": "body_append",
                    "requested_as": "body_append",
                    "before_chars": before_chars,
                    "after_chars": after_chars,
                    "delta_chars": after_chars as i64 - before_chars as i64,
                    "unit": "unicode_scalars",
                }));
                fields.insert("body".into(), Value::String(new_body));
            } else if let Some(ops) = &args.body_replace {
                let new_body = apply_body_replacements(TOOL, current_str, ops)?;
                body_content_changed = Some(new_body.as_str() != current_str);
                let after_chars = new_body.chars().count() as u64;
                body_receipt = Some(json!({
                    "operation": "body_replace",
                    "requested_as": "body_replace",
                    "before_chars": before_chars,
                    "after_chars": after_chars,
                    "delta_chars": after_chars as i64 - before_chars as i64,
                    "unit": "unicode_scalars",
                }));
                fields.insert("body".into(), Value::String(new_body));
            } else if args.body.is_some() || args.body_set.is_some() {
                // Full replacement: the new value is already in `fields`
                // under `body` (legacy alias and `body_set` share the shape).
                legacy_body_alias = args.body.is_some();
                let requested_as = if args.body.is_some() {
                    "body"
                } else {
                    "body_set"
                };
                let after_chars = match fields.get("body") {
                    Some(Value::String(next)) => {
                        body_content_changed = Some(next.as_str() != current_str);
                        next.chars().count() as u64
                    }
                    Some(Value::Null) => {
                        body_content_changed = Some(current_body.is_some());
                        0
                    }
                    _ => {
                        body_content_changed = Some(true);
                        0
                    }
                };
                body_receipt = Some(json!({
                    "operation": "body_set",
                    "requested_as": requested_as,
                    "before_chars": before_chars,
                    "after_chars": after_chars,
                    "delta_chars": after_chars as i64 - before_chars as i64,
                    "unit": "unicode_scalars",
                }));
            }
        }
    }
    if let Some((missing, mut target)) = guard_failure {
        // Roll the write transaction back BEFORE minting the display reference:
        // the refusal must not hold `BEGIN IMMEDIATE` open while it scans the
        // id space to make its own error message nicer.
        if db.is_enrolled() {
            crate::db::enrolled::phase(crate::db::enrolled::Phase::BeforeRollback).await;
            tx.rollback().await?;
        } else {
            drop(tx);
        }
        target.display_reference = crate::mcp::record_ref::display_reference(&db, &args.id).await?;
        return Err(if missing {
            unguarded_body_write_error(TOOL, &target)
        } else {
            stale_body_digest_error(TOOL, &target)
        });
    }

    if let Some(Value::String(new_home)) = &args.home_id {
        assert_home_target_in(&mut tx, TOOL, new_home).await?;
        assert_no_containment_cycle_in(&mut tx, TOOL, &args.id, new_home).await?;
    }
    // Evaluate HTML and MDX policy over the complete prospective tuple under
    // the same write transaction. This catches body-only, runtime-only and
    // kind-changing updates before any event is appended.
    // Evaluate HTML and MDX policy over the complete prospective tuple under
    // the same write transaction. This catches body-only, runtime-only and
    // kind-changing updates before any event is appended.
    let RecordUpdateOutcome {
        record_event,
        html_body_write,
        source_changed,
        artifact_input_continuity,
        record_type,
        resulting_kind,
        resulting_effective_kind,
        non_body_changed,
    } = record_update_in(RecordUpdateInput {
        db: &db,
        tx: &mut tx,
        act_alloc: &mut act_alloc,
        caller: &caller,
        tool: TOOL,
        record_id: &args.id,
        fields,
        version_metadata: None,
        has_kind: args.kind.is_some(),
        has_lifecycle: args.lifecycle.is_some(),
        has_summary: args.summary.is_some(),
        facet_specs,
        facet_writes: &facet_writes,
        facet_unsets: &facet_unsets,
        schema_rows: &schema_rows,
        links: &links,
        relationship_link_indexes: &relationship_link_indexes,
        before: &before,
    })
    .await?;
    // Alias shadows warn on success, silent on unsets and on kinds the
    // governed relationship does not admit. Uses the resulting kind so a
    // kind-changing update judges the record it leaves behind.
    let alias_kind = resulting_effective_kind
        .as_deref()
        .or(resulting_kind.as_deref());
    let alias_warnings = crate::domain_transaction::governed_alias_warnings_for_sets(
        &facet_writes,
        &record_type,
        alias_kind,
    );
    let compact_result = if response_mode == ResponseMode::Summary {
        Some(compact_record_source_in(&mut tx, &caller, TOOL, &args.id).await?)
    } else {
        None
    };
    // Capture the version from the same transaction and snapshot.
    let version_seq = current_record_version_in(&mut tx, &args.id).await?;
    crate::db::enrolled::phase(crate::db::enrolled::Phase::AfterAppend).await;
    db.commit_content(tx).await?;

    // The success response reports the digest of the body it just wrote, so a
    // caller continuing guarded work does not need a second read to obtain the
    // next token.
    let mut updated = attach_artifact_input_continuity(
        attach_html_body_write(
            echo_previous_seq(
                match compact_result {
                    Some(result) => result,
                    None => enriched_or_error(&db, &caller, TOOL, &args.id).await?,
                },
                previous_seq,
            )?,
            html_body_write,
        )?,
        artifact_input_continuity,
    )?;
    updated = echo_act(updated, act_alloc.get())?;
    annotate_body_digest(&mut updated);
    // The event id of the body this call just wrote, when it wrote one: the
    // exact-source identity a re-grant must name as `subject_event_id`.
    // `record_event` exists for every field-bearing update, but only a body
    // change mints a new source event; anything else leaves the field absent.
    if source_changed {
        annotate_source_event_id(
            &mut updated,
            record_event.as_ref().map(|event| event.id.as_str()),
        );
    }
    if let Some(receipt) = body_receipt {
        updated
            .as_object_mut()
            .expect("enriched record object")
            .insert("body_receipt".into(), receipt);
    }
    // Legacy `body` stays functional but always warns — including on
    // content-identical (no-op) successes — directing callers to `body_set`.
    if legacy_body_alias {
        let warning = json!({
            "code": "deprecated_body_alias",
            "message": "update_record 'body' is a deprecated alias for full replacement; use 'body_set' for new calls.",
        });
        match updated.get_mut("warnings") {
            Some(Value::Array(warnings)) => warnings.push(warning),
            Some(existing) => {
                *existing = Value::Array(vec![existing.clone(), warning]);
            }
            None => {
                updated
                    .as_object_mut()
                    .expect("enriched record object")
                    .insert("warnings".into(), Value::Array(vec![warning]));
            }
        }
    }
    crate::domain_transaction::push_receipt_warnings(&mut updated, alias_warnings)?;
    // The long task-body nudge moved to the post-commit advisor hook
    // (`crate::mcp::advisors::long_record`, installed by default): it rides
    // `advisories` below, not `warnings` here.
    attach_basis_feedback(
        &db,
        &caller,
        &mut updated,
        source_inputs.as_ref().map(Vec::len),
        false,
    )
    .await;
    // The post-commit advisor hook (S1). The singular update has no keyed
    // replay path, so reaching here means a fresh, successful write; the key
    // is omitted entirely when no advisor fires, keeping other receipts
    // byte-identical. Fail-silent: the hook never errors. The pre-write body
    // length is reused from the write path's own body receipt (same Unicode
    // scalar unit) rather than re-queried; facet-only updates carry no body
    // receipt and pass None (body untouched).
    // No-op updates don't fire advisors. The first half mirrors the
    // receipt's own `act` omission: no allocated act means the transaction
    // appended nothing. The second half covers what the engine still
    // appends: a content-identical body write changes nothing observable,
    // so advisors stay silent even though the receipt carries an act.
    let write_changed =
        act_alloc.get().is_some() && (non_body_changed || body_content_changed.unwrap_or(false));
    if write_changed {
        // The watches gate judges the record left behind, like the alias
        // shadows above: the resulting (effective) kind, with the raw kind
        // as fallback. Type/kind ride along so the gate needs no query.
        let advisor_kind = resulting_effective_kind
            .as_deref()
            .or(resulting_kind.as_deref())
            .unwrap_or("");
        if let Some(advisories) = crate::mcp::advisors::advisories_for_write(
            &db,
            TOOL,
            &args.id,
            &record_type,
            advisor_kind,
            body_content_changed.unwrap_or(false),
            caller.run_key().map(str::to_owned),
            updated
                .get("body_receipt")
                .and_then(|receipt| receipt.get("before_chars"))
                .and_then(Value::as_u64)
                .and_then(|chars| chars.try_into().ok()),
            record_event.as_ref().map(|event| event.local_seq),
            args.lifecycle.is_some(),
        )
        .await
        {
            if let Some(object) = updated.as_object_mut() {
                object.insert("advisories".into(), Value::Array(advisories));
            }
        }
    }
    response_mode.render(&db, updated, version_seq).await
}

// ---------------------------------------------------------------------------
// Exceptional ownership recovery
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimUnownedRecordArgs {
    record_id: String,
    reason: String,
}

fn claim_unowned_record_ineligible() -> Error {
    Error::engine("claim_unowned_record: record is not eligible for ownership recovery")
}

async fn claim_unowned_record(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "claim_unowned_record";
    // Host authority is checked before any target-dependent read, so a hosted
    // non-owner cannot use this exceptional recovery surface as an oracle.
    if !caller.is_host_owner() {
        return Err(Error::engine(
            "claim_unowned_record: host-owner authority is required",
        ));
    }
    let args: ClaimUnownedRecordArgs = parse_args(TOOL, arguments)?;
    if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(&args.record_id) {
        return Err(Error::engine(
            "claim_unowned_record: record_id must be an exact canonical lowercase UUID of version 4 or 7",
        ));
    }
    require_nonblank_reason(TOOL, &args.reason)?;

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_record_in(&mut tx, &caller, TOOL, &args.record_id, Capability::View).await?;

    let claimant_ids = sqlx::query_scalar::<_, String>(
        "SELECT b.record_id
           FROM bindings b
           JOIN records r ON r.id = b.record_id
          WHERE b.system = 'account' AND b.identifier = ?
            AND b.is_canonical = 1 AND r.deleted_at IS NULL
            AND r.type = 'Entity' AND r.kind = 'person'",
    )
    .bind(caller.credential())
    .fetch_all(&mut *tx)
    .await?;
    let [owner_id] = claimant_ids.as_slice() else {
        return Err(Error::engine(
            "claim_unowned_record: caller must have exactly one live canonical person binding",
        ));
    };

    let target = sqlx::query("SELECT type, owner_id, deleted_at FROM records WHERE id = ?")
        .bind(&args.record_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(claim_unowned_record_ineligible)?;
    let record_type: String = target.try_get("type")?;
    let current_owner: Option<String> = target.try_get("owner_id")?;
    let deleted_at: Option<String> = target.try_get("deleted_at")?;
    let authorization_target =
        crate::authorization::authorization_target_on(&mut tx, &args.record_id)
            .await
            .map_err(|_| claim_unowned_record_ineligible())?;
    let semantic_unit: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM semantic_units WHERE unit_id = ?)")
            .bind(&args.record_id)
            .fetch_one(&mut *tx)
            .await?;
    if args.record_id.starts_with("native:")
        || deleted_at.is_some()
        || current_owner.is_some()
        || record_type == "Message"
        || semantic_unit
        || authorization_target != args.record_id
    {
        return Err(claim_unowned_record_ineligible());
    }

    let previous_seq = previous_record_seq_in(&mut tx, &args.record_id)
        .await?
        .ok_or_else(claim_unowned_record_ineligible)?;
    let event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: args.record_id.clone(),
            event_type: "record.updated".into(),
            payload: json!({
                "owner_id": owner_id,
                "reason": args.reason,
                "ownership_recovery": "host_owner_self_claim.v1",
            }),
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    db.commit_content(tx).await?;
    echo_act(
        json!({
        "id": args.record_id,
        "owner_id": owner_id,
        "event_id": event.id,
        "event_seq": event.local_seq,
        "previous_seq": previous_seq,
        }),
        act_alloc.get(),
    )
}

// ---------------------------------------------------------------------------
// Tool 8 — delete_record
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteRecordArgs {
    id: String,
    /// Required (fbfaf25 §3.1). Delete is one of the two small acts that carry
    /// `reason` anyway: it is where the reasoning is least recoverable
    /// afterwards, because the record that would have explained it is gone.
    reason: String,
    /// Internal executor CAS populated only by signed preparation. Legacy and
    /// ordinary production callers omit it and retain the existing behavior.
    #[serde(default)]
    if_content_seq: Option<i64>,
}

#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Debug)]
pub(crate) struct DeleteRecordPreparation {
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
struct DeleteRecordState {
    id: String,
    name: Option<String>,
    record_type: String,
    kind: Option<String>,
    home_id: Option<String>,
    updated_at: String,
    previous_seq: i64,
}

#[cfg(feature = "mcp-executor-prototype")]
async fn delete_record_state_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    id: &str,
    if_content_seq: Option<i64>,
) -> Result<DeleteRecordState> {
    const TOOL: &str = "delete_record";
    require_record_in(tx, caller, TOOL, id, Capability::Manage).await?;
    crate::instructions::assert_source_deletable_in(tx, TOOL, id).await?;
    let previous_seq = previous_record_seq_in(tx, id)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: record {id} does not exist")))?;
    if if_content_seq.is_some_and(|expected| expected != previous_seq) {
        return Err(Error::engine(format!(
            "{TOOL}: content revision conflict; get the record and prepare again"
        )));
    }
    let row = sqlx::query(
        "SELECT id,name,type,kind,home_id,updated_at FROM records WHERE id=? AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{TOOL}: record {id} does not exist")))?;
    Ok(DeleteRecordState {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        record_type: row.try_get("type")?,
        kind: row.try_get("kind")?,
        home_id: row.try_get("home_id")?,
        updated_at: row.try_get("updated_at")?,
        previous_seq,
    })
}

/// Exercise the exact production parser, authorization, instruction-source
/// guard and target lookup without appending the tombstone.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_delete_record(
    db: &Db,
    caller: &Caller,
    arguments: Value,
) -> Result<DeleteRecordPreparation> {
    let DeleteRecordArgs {
        id,
        reason,
        if_content_seq: None,
    } = parse_args("delete_record", arguments)?
    else {
        return Err(Error::engine(
            "delete_record: executor preparation does not accept an internal revision",
        ));
    };
    require_nonblank_reason("delete_record", &reason)?;
    let mut tx = db.write_pool().begin().await?;
    let state = delete_record_state_in(&mut tx, caller, &id, None).await?;
    let target = state.name.as_deref().map_or_else(
        || format!("record {}", state.id),
        |name| format!("{name} ({})", state.id),
    );
    let operation_evidence = json!({
        "id": state.id,
        "name": state.name,
        "type": state.record_type,
        "kind": state.kind,
        "home_id": state.home_id,
        "updated_at": state.updated_at,
        "previous_seq": state.previous_seq,
        "active_instruction_references": 0,
    });
    let target_state_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&operation_evidence)?));
    let effect = json!({
        "target": {
            "record_id": state.id,
            "name": state.name,
            "type": state.record_type,
            "kind": state.kind,
        },
        "before": { "deleted": false },
        "after": { "deleted": true, "frozen": true },
        "message_candidates_withdrawn": state.record_type == "Message",
        "changed": true,
        "reason": reason,
    });
    let preparation = DeleteRecordPreparation {
        canonical_source_arguments: json!({
            "id": state.id,
            "reason": reason,
            "if_content_seq": state.previous_seq,
        }),
        target_id: state.id.clone(),
        target: target.clone(),
        state_revision: format!("content-seq:{}", state.previous_seq),
        target_state_digest,
        effect,
        effect_summary: format!(
            "soft-delete {target} and freeze it against all further record mutation"
        ),
        operation_evidence,
    };
    tx.rollback().await?;
    Ok(preparation)
}

async fn delete_record(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "delete_record";
    let args: DeleteRecordArgs = parse_args(TOOL, arguments)?;
    require_nonblank_reason(TOOL, &args.reason)?;
    // Soft-delete only in v1: the projector sets the tombstone and freezes the
    // record against all further mutation events (ef32e44). Missing and
    // already-tombstoned ids error through the same guard.
    //
    // Appended here rather than through `store::delete_record_as` only so the
    // event can carry the reason payload; the event type, guard and projection
    // are identical.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_record_in(&mut tx, &caller, TOOL, &args.id, Capability::Manage).await?;
    crate::instructions::assert_source_deletable_in(&mut tx, TOOL, &args.id).await?;
    let previous_seq = previous_record_seq_in(&mut tx, &args.id).await?;
    if args
        .if_content_seq
        .is_some_and(|expected| previous_seq != Some(expected))
    {
        return Err(Error::engine(format!(
            "{TOOL}: content revision conflict; get the record and prepare again"
        )));
    }
    let record_type: String = sqlx::query_scalar("SELECT type FROM records WHERE id=?")
        .bind(&args.id)
        .fetch_one(&mut *tx)
        .await?;
    let deletion = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: args.id.clone(),
            event_type: "record.deleted".into(),
            payload: json!({ "reason": args.reason }),
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    if record_type == "Message" {
        crate::awareness::withdraw_message_candidates_in(
            &mut tx,
            &args.id,
            "record.deleted",
            &deletion.id,
            &mut act_alloc,
        )
        .await?;
    }
    db.commit_content(tx).await?;
    let deleted_at = sqlx::query("SELECT deleted_at FROM records WHERE id = ?")
        .bind(&args.id)
        .fetch_one(db.write_pool())
        .await?
        .try_get::<Option<String>, _>("deleted_at")?;
    echo_act(
        json!({
        "id": args.id,
        "deleted": true,
        "deleted_at": deleted_at,
        "previous_seq": previous_seq,
        }),
        act_alloc.get(),
    )
}

// ---------------------------------------------------------------------------
// Tool 9 — archive_record
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveRecordArgs {
    id: String,
    /// `true` (default) archives; `false` restores.
    archived: Option<bool>,
    /// Required (fbfaf25 §3.1). In scope despite archiving being a small act,
    /// for the same reason as delete: it is consequential and the reasoning is
    /// hard to recover once the record has dropped out of default queries.
    reason: String,
}

async fn archive_record(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "archive_record";
    let args: ArchiveRecordArgs = parse_args(TOOL, arguments)?;
    require_nonblank_reason(TOOL, &args.reason)?;
    let want_archived = args.archived.unwrap_or(true);

    // State check and event share one write transaction, so the no-op answer
    // cannot race the write it declined: an already-archived archive (or an
    // unarchived restore) returns changed:false WITHOUT committing a
    // meaningless authoritative event.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_record_in(&mut tx, &caller, TOOL, &args.id, Capability::Manage).await?;
    let previous_seq = previous_record_seq_in(&mut tx, &args.id).await?;
    let row = sqlx::query(
        "SELECT r.deleted_at,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r WHERE r.id = ?",
    )
    .bind(ARCHIVED_FACET_KEY)
    .bind(&args.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.id
        )));
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: record {} is deleted (tombstoned)",
            args.id
        )));
    }
    let is_archived = row.try_get::<i64, _>("archived")? != 0;
    if is_archived == want_archived {
        return Ok(json!({
            "id": args.id,
            "archived": want_archived,
            "changed": false,
            "previous_seq": previous_seq,
        }));
    }
    // Set/unset semantics live in the projector's `archived` fold (e035091
    // guard 3): 'true' archives, UNSET restores, `lifecycle` untouched either
    // way. The tool dispatches; it does not re-implement.
    // `reason` rides in the facet payload. `FacetSetPayload` / `FacetUnsetPayload`
    // ignore unknown keys on deserialization, so the fold is unaffected — the
    // prose is carried by the event and read by humans and history tools, never
    // by the projector.
    let spec = if want_archived {
        AppendSpec {
            record_id: args.id.clone(),
            event_type: "facet.set".into(),
            payload: json!({
                "key": ARCHIVED_FACET_KEY,
                "value": "true",
                "reason": args.reason,
            }),
            actor: Some(caller.actor().into()),
        }
    } else {
        AppendSpec {
            record_id: args.id.clone(),
            event_type: "facet.unset".into(),
            payload: json!({ "key": ARCHIVED_FACET_KEY, "reason": args.reason }),
            actor: Some(caller.actor().into()),
        }
    };
    append_in(&db, &mut tx, spec, &mut act_alloc).await?;
    db.commit_content(tx).await?;
    echo_act(
        json!({
        "id": args.id,
        "archived": want_archived,
        "changed": true,
        "previous_seq": previous_seq,
        }),
        act_alloc.get(),
    )
}

// ---------------------------------------------------------------------------
// Tool 10 — render_record
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenderRecordArgs {
    id: String,
    include_interpretation: Option<bool>,
}

/// Names for the far endpoints of a record's links, for readable rendering.
async fn endpoint_names(
    db: &Db,
    record: &read::EnrichedRecord,
) -> Result<std::collections::HashMap<String, String>> {
    let mut ids: Vec<&str> = Vec::new();
    for link in &record.links_out {
        ids.push(&link.target_id);
    }
    for link in &record.links_in {
        ids.push(&link.source_id);
    }
    let mut names = std::collections::HashMap::new();
    for chunk in ids.chunks(400) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!("SELECT id, name FROM records WHERE id IN ({placeholders})");
        let mut query = sqlx::query(&sql);
        for id in chunk {
            query = query.bind(*id);
        }
        for row in query.fetch_all(db.write_pool()).await? {
            names.insert(row.try_get("id")?, row.try_get("name")?);
        }
    }
    Ok(names)
}

async fn endpoint_names_in(
    tx: &mut Transaction<'_, Sqlite>,
    record: &read::EnrichedRecord,
) -> Result<std::collections::HashMap<String, String>> {
    let mut ids: Vec<&str> = Vec::new();
    for link in &record.links_out {
        ids.push(&link.target_id);
    }
    for link in &record.links_in {
        ids.push(&link.source_id);
    }
    let mut names = std::collections::HashMap::new();
    for chunk in ids.chunks(400) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!("SELECT id, name FROM records WHERE id IN ({placeholders})");
        let mut query = sqlx::query(&sql);
        for id in chunk {
            query = query.bind(*id);
        }
        for row in query.fetch_all(&mut **tx).await? {
            names.insert(row.try_get("id")?, row.try_get("name")?);
        }
    }
    Ok(names)
}

fn push_interpretation_markdown(
    out: &mut String,
    projection: &crate::interpretation::InterpretationProjection,
) -> Result<()> {
    let value = serde_json::to_value(projection)?;
    out.push_str("\n## Interpretation\n\n");
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let count = value
        .get("attribution_count")
        .and_then(Value::as_i64)
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unavailable".into());
    out.push_str(&format!(
        "Status: {status} · caller-visible claims: {count}\n"
    ));
    for group in value
        .get("groups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let headline = group
            .get("headline")
            .and_then(Value::as_str)
            .unwrap_or("Interpretation details are unavailable.");
        let target = group
            .pointer("/target/state")
            .and_then(Value::as_str)
            .unwrap_or("unavailable");
        let group_status = group
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unavailable");
        out.push_str(&format!("- {headline} [{group_status}; target {target}]\n"));
    }
    if !projection.complete {
        out.push_str("- Projection is incomplete; unavailable or withheld details are not counted as absent.\n");
    }
    out.push_str(
        "\nDelegation, confidence, and claim counts do not establish endorsement, truth, or consensus.\n",
    );
    Ok(())
}

/// The heading for a windowed section. A render that shows 200 of 1,501 says
/// so in the heading, because a deterministic render that quietly drops 1,301
/// children is not a render of the record — it is a render of a different,
/// smaller record. Decision 5055a9c's "never silently truncate" rule applies to
/// its own consumers first.
fn section_heading(heading: &str, shown: usize, total: i64) -> String {
    if (shown as i64) < total {
        format!("\n## {heading} — showing {shown} of {total}\n\n")
    } else {
        format!("\n## {heading}\n\n")
    }
}

fn push_link_lines(
    out: &mut String,
    heading: &str,
    links: &[crate::query::LinkRow],
    total: i64,
    other_id: impl Fn(&crate::query::LinkRow) -> &str,
    names: &std::collections::HashMap<String, String>,
    arrow: &str,
) {
    if links.is_empty() && total == 0 {
        return;
    }
    out.push_str(&section_heading(heading, links.len(), total));
    for link in links {
        let other = other_id(link);
        let name = names.get(other).map(String::as_str).unwrap_or("?");
        out.push_str(&format!(
            "- {arrow} {} — {name} (`{other}`)",
            link.relationship
        ));
        if let Some(note) = &link.note {
            out.push_str(&format!(" — {note}"));
        }
        out.push('\n');
    }
}

/// Body mentions are parser evidence, kept visually distinct from the
/// asserted `Links` sections above. Outgoing resolution shows its state
/// honestly; an ambiguous reference names only the visible match count.
fn push_mention_out_lines(out: &mut String, record: &read::EnrichedRecord) {
    let Some(entries) = record.mentions_out.as_ref() else {
        return;
    };
    let total = record.mentions_out_count.unwrap_or(entries.len() as i64);
    if total == 0 {
        return;
    }
    out.push_str(&section_heading("Mentions", entries.len(), total));
    for entry in entries {
        let reference = crate::mcp::render::display_inline(&entry.authored_reference);
        let tail = match &entry.resolution {
            read::MentionResolution::Unresolved => "unresolved".to_string(),
            read::MentionResolution::Resolved { id, name } => format!(
                "resolved to {} (`{id}`)",
                crate::mcp::render::display_inline(name)
            ),
            read::MentionResolution::Ambiguous {
                visible_candidate_count,
            } => format!("ambiguous ({visible_candidate_count} visible matches)"),
        };
        out.push_str(&format!(
            "- → {reference} ({}, ×{}) — {tail}\n",
            entry.form, entry.occurrence_count
        ));
    }
}

fn push_mention_in_lines(out: &mut String, record: &read::EnrichedRecord) {
    let Some(entries) = record.mentions_in.as_ref() else {
        return;
    };
    let total = record.mentions_in_count.unwrap_or(entries.len() as i64);
    if total == 0 {
        return;
    }
    out.push_str(&section_heading("Mentioned by", entries.len(), total));
    for entry in entries {
        let name = crate::mcp::render::display_inline(&entry.source_name);
        out.push_str(&format!(
            "- ← {name} (`{}`) ×{}\n",
            entry.source_id, entry.occurrence_count
        ));
    }
}

/// Canonical deterministic record Markdown for adapters that have already
/// assembled the ordinary enriched-record contract in their own snapshot.
/// Interpretation is deliberately separate: portable adapters reject that
/// opt-in until its attribution projection is qualified.
pub(crate) fn render_enriched_record_markdown(
    record: &read::EnrichedRecord,
    names: &std::collections::HashMap<String, String>,
) -> String {
    let r = &record.record;
    let mut out = String::new();
    let title = if r.name.is_empty() {
        "(unnamed)"
    } else {
        &r.name
    };
    out.push_str(&format!("# {title}\n\n"));
    let mut headline = format!("**{}**", r.record_type);
    if let Some(kind) = &r.kind {
        headline.push_str(&format!(" / {kind}"));
    }
    headline.push_str(&format!(" — `{}`", r.id));
    out.push_str(&headline);
    out.push('\n');
    if !record.ancestors.is_empty() {
        let path: Vec<&str> = record.ancestors.iter().map(|a| a.name.as_str()).collect();
        out.push_str(&format!("\nPath: {}\n", path.join(" → ")));
    }
    let mut status: Vec<String> = Vec::new();
    if let Some(lifecycle) = &r.lifecycle {
        status.push(format!("lifecycle: {lifecycle}"));
    }
    status.push(format!("persistence: {}", r.persistence));
    if let Some(maturity) = &r.maturity {
        status.push(format!("maturity: {maturity}"));
    }
    if let Some(owner) = &r.owner_id {
        status.push(format!("owner: {owner}"));
    }
    // Succession disclosure on the status line: the markdown read names the
    // successor without the reader inspecting links. Names are escaped for
    // the shared summariser, whose contract is pre-escaped input; a short
    // reference degrades to the full id where none was annotated.
    if let Some(superseded) = record.superseded_by.as_ref() {
        let items = superseded
            .items
            .iter()
            .map(|item| {
                (
                    crate::mcp::render::display_inline(&item.name),
                    crate::mcp::render::display_inline(
                        item.display_reference.as_deref().unwrap_or(&item.id),
                    ),
                )
            })
            .collect::<Vec<_>>();
        if let Some(summary) =
            crate::mcp::render::summarize_superseded_items(&items, superseded.total_count)
        {
            status.push(summary);
        }
    }
    if record.archived {
        status.push("ARCHIVED".into());
    }
    if let Some(deleted_at) = &r.deleted_at {
        status.push(format!("DELETED {deleted_at}"));
    }
    out.push_str(&format!("\n{}\n", status.join(" · ")));
    if let Some(summary) = &r.summary {
        out.push_str(&format!("\n> {summary}\n"));
    }
    if let Some(body) = &r.body {
        if !body.is_empty() {
            out.push_str(&format!("\n{body}\n"));
        }
    }
    if !record.facets.is_empty() {
        out.push_str("\n## Facets\n\n");
        for facet in &record.facets {
            let value = match facet.value.as_ref() {
                Some(Value::String(value)) => value.clone(),
                Some(value) => value.to_string(),
                None => String::new(),
            };
            out.push_str(&format!("- {}: {value}", facet.key));
            if let Some(vocab_ref) = &facet.vocab_ref {
                out.push_str(&format!(" ({vocab_ref})"));
            }
            out.push('\n');
        }
    }
    push_link_lines(
        &mut out,
        "Links (outgoing)",
        &record.links_out,
        record.links_out_count,
        |link| &link.target_id,
        names,
        "→",
    );
    push_link_lines(
        &mut out,
        "Links (incoming)",
        &record.links_in,
        record.links_in_count,
        |link| &link.source_id,
        names,
        "←",
    );
    push_mention_out_lines(&mut out, record);
    push_mention_in_lines(&mut out, record);
    if !record.children.is_empty() {
        out.push_str(&section_heading(
            "Children",
            record.children.len(),
            record.child_count,
        ));
        for child in &record.children {
            let name = if child.name.is_empty() {
                "(unnamed)"
            } else {
                &child.name
            };
            out.push_str(&format!("- {name} ({}", child.record_type));
            if let Some(kind) = &child.kind {
                out.push_str(&format!(" / {kind}"));
            }
            out.push_str(&format!(", `{}`)", child.id));
            if child.archived {
                out.push_str(" [archived]");
            }
            out.push('\n');
        }
        if (record.children.len() as i64) < record.child_count {
            out.push_str(
                "\nPage the rest with `get_record` and `children_offset` \
                 (offset is unbounded).\n",
            );
        }
    }
    if record.suggestion_count > 0 {
        out.push_str(&format!(
            "\n## Suggestions\n\n{} suggestion(s) hidden from ordinary children. Read with `get_record(include_suggestions:true)` or query `kind:suggestion`.\n",
            record.suggestion_count
        ));
    }
    out
}

async fn render_record(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "render_record";
    debug_assert_eq!(
        db.open_mode() == crate::db::DatabaseOpenMode::MemberReadOnly,
        caller.is_member_copy(),
        "member Db and member caller must agree (dispatch derives both from the Db open mode)"
    );
    let args: RenderRecordArgs = parse_args(TOOL, arguments)?;
    let include_interpretation = args.include_interpretation.unwrap_or(false);
    if caller.is_member_copy() {
        // A member copy has no policy/attribution/history tables, so it skips
        // `require_record` and the interpretation projection. The reader
        // answers from E(m) (slice presence); an unsupported interpretation
        // becomes a marker rather than an absent section.
        let lens = ReadLens::live(&db);
        let Some(mut record) = read::get_record_with_lens_as(
            &lens,
            &args.id,
            read::EnrichOptions::default(),
            super::principal(&caller),
        )
        .await?
        else {
            return Err(Error::engine(format!(
                "{TOOL}: record {} does not exist",
                args.id
            )));
        };
        filter_enriched_record(&db, &caller, &mut record, read::EnrichOptions::default()).await?;
        populate_superseded_references_in_pool(db.write_pool(), &mut record, true).await?;
        let names = endpoint_names(&db, &record).await?;
        let out = render_enriched_record_markdown(&record, &names);
        let mut output = json!({ "id": args.id, "markdown": out });
        if include_interpretation {
            output
                .as_object_mut()
                .expect("render_record response is an object")
                .insert(
                    "interpretation".into(),
                    member_section_marker("render_interpretation"),
                );
        }
        return Ok(output);
    }
    let (record, names, interpretation) = if include_interpretation {
        let mut snapshot = db.write_pool().begin().await?;
        let result = async {
            require_record_in(&mut snapshot, &caller, TOOL, &args.id, Capability::View).await?;
            let principal = (!super::is_legacy_local(&caller)).then(|| super::principal(&caller));
            let mut items = read::get_records_live_in(
                &mut snapshot,
                std::slice::from_ref(&args.id),
                read::EnrichOptions::default(),
                principal,
            )
            .await?;
            let mut reported = crate::contribution::ReportedIdentityCache::new();
            let record = match items.pop() {
                Some(read::BatchGetItem::Found(mut record)) => {
                    filter_enriched_record_in(
                        &mut snapshot,
                        &caller,
                        &mut record,
                        read::EnrichOptions::default(),
                        &mut reported,
                    )
                    .await?;
                    *record
                }
                _ => {
                    return Err(Error::engine(format!(
                        "{TOOL}: record {} does not exist",
                        args.id
                    )))
                }
            };
            let names = endpoint_names_in(&mut snapshot, &record).await?;
            let mut projections = super::attribution::project_generic_interpretations_in(
                &mut snapshot,
                &caller,
                super::attribution::authorized_render_interpretation_bearer(&args.id),
            )
            .await?;
            let interpretation = projections.remove(&args.id).ok_or_else(|| {
                Error::engine("render_record: interpretation projection is unavailable")
            })?;
            Ok((record, names, interpretation))
        }
        .await;
        let (mut record, names, interpretation) = finish_read_snapshot(snapshot, result).await?;
        // After the snapshot releases: successor display references resolve
        // through their own pool checkout, never nested inside the handler's
        // snapshot the way the in-transaction call above did. Same ordering
        // as `get_record_from_lens`, which annotates after its snapshot.
        populate_superseded_references_in_pool(
            db.write_pool(),
            &mut record,
            caller.is_member_copy(),
        )
        .await?;
        (record, names, Some(interpretation))
    } else {
        require_record(&db, &caller, TOOL, &args.id, Capability::View).await?;
        let lens = ReadLens::live(&db);
        let record = if super::is_legacy_local(&caller) {
            read::get_record_with_lens(&lens, &args.id, read::EnrichOptions::default()).await?
        } else {
            read::get_record_with_lens_as(
                &lens,
                &args.id,
                read::EnrichOptions::default(),
                super::principal(&caller),
            )
            .await?
        };
        let Some(mut record) = record else {
            return Err(Error::engine(format!(
                "{TOOL}: record {} does not exist",
                args.id
            )));
        };
        filter_enriched_record(&db, &caller, &mut record, read::EnrichOptions::default()).await?;
        populate_superseded_references_in_pool(
            db.write_pool(),
            &mut record,
            caller.is_member_copy(),
        )
        .await?;
        let names = endpoint_names(&db, &record).await?;
        (record, names, None)
    };
    let mut out = render_enriched_record_markdown(&record, &names);

    if let Some(interpretation) = &interpretation {
        push_interpretation_markdown(&mut out, interpretation)?;
    }
    let mut output = json!({ "id": args.id, "markdown": out });
    if let Some(interpretation) = interpretation {
        output
            .as_object_mut()
            .expect("render_record response is an object")
            .insert(
                "interpretation".into(),
                serde_json::to_value(interpretation)?,
            );
    }
    Ok(output)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register tools 5–10.
fn update_record_input_schema() -> Value {
    // The base singular shape carries every property. Mutual exclusivity of
    // the four body operations lives in sibling `allOf` branches — never as
    // sibling keys — because the TypeScript generator resolves `allOf` first
    // and ignores sibling properties (see `tool_types.rs` `schema_to_ts`).
    let singular_body = json!({
        "type": "object",
        "description": "non-empty body guard: if_body_digest (get_record.body_digest) or if_unmodified_since.",
        "properties": {
            "id": { "type": "string" },
            "record_id": { "type": "string", "description": "Alias for id; ids selects batch mode." },
            "reason": { "type": "string", "minLength": 1 },
            "sources": source_basis_input_schema(),
            "name": { "type": "string" },
            "body": { "type": ["string", "null"], "description": "Deprecated body_set alias." },
            "body_set": { "type": ["string", "null"], "description": "Replace all; null clears." },
            "body_append": { "type": "string", "description": "Small additions only; re-stores whole body." },
            "body_replace": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "old": { "type": "string", "minLength": 1 },
                        "new": { "type": "string" },
                        "expected_count": { "type": "integer", "minimum": 1 },
                        "replace_all": { "type": "boolean" }
                    },
                    "required": ["old", "new"],
                    "not": { "required": ["expected_count", "replace_all"] },
                    "additionalProperties": false
                }
            },
            "if_body_digest": { "type": "string", "pattern": "^[0-9a-fA-F]{64}$" },
            "if_unmodified_since": { "type": "string", "format": "date-time" },
            "response_mode": { "type": "string", "enum": ["summary", "verbose"], "default": "summary" },
            "kind": { "type": "string", "minLength": 1 },
            "home_id": { "type": "string", "description": "Move to a canonical browse home. Only the engine root may have null." },
            "summary": { "type": ["string", "null"] },
            "lifecycle": { "type": ["string", "null"] },
            "owner_id": { "type": ["string", "null"] },
            "persistence": { "type": "string", "enum": ["enduring", "occurrent"] },
            "maturity": { "type": ["string", "null"] },
            "facets": {
                "type": "object",
                "description": "Open facets; use observations for evidence.",
                "additionalProperties": true
            },
            "links": {
                "type": "array",
                "description": "Add outgoing links with edits; links-only: manage_links.add.",
                "items": {
                    "type": "object",
                    "properties": {
                        "target_id": { "type": "string" },
                        "relationship": { "type": "string" },
                        "note": { "type": "string" }
                    },
                    "required": ["target_id", "relationship"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["reason"],
        "additionalProperties": false
    });
    let singular = json!({
        "allOf": [
            singular_body,
            { "oneOf": [{ "required": ["id"] }, { "required": ["record_id"] }] },
            { "not": { "required": ["body", "body_set"] } },
            { "not": { "required": ["body", "body_append"] } },
            { "not": { "required": ["body", "body_replace"] } },
            { "not": { "required": ["body_set", "body_append"] } },
            { "not": { "required": ["body_set", "body_replace"] } },
            { "not": { "required": ["body_append", "body_replace"] } }
        ]
    });
    let multi_base = json!({
        "type": "object",
        "properties": {
            "ids": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_MULTI_UPDATE,
                "uniqueItems": true,
                "items": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                }
            },
            "reason": { "type": "string", "minLength": 1 },
            "facets": {
                "type": "object",
                "minProperties": 1,
                "additionalProperties": true
            },
            "maturity": { "type": ["string", "null"] },
            "home_id": { "type": "string" },
            "if_facets": {
                "type": "object",
                "minProperties": 1,
                "additionalProperties": true
            },
            "if_maturity": { "type": ["string", "null"] },
            "if_home_id": { "type": "string" }
        },
        "required": ["ids", "reason"],
        "additionalProperties": false
    });
    let multi_patch = json!({
        "anyOf": [
            { "required": ["facets"] },
            { "required": ["maturity"] },
            { "required": ["home_id"] }
        ]
    });
    json!({
        "type": "object",
        "properties": {
            "reason": { "description": REASON_DESCRIPTION }
        },
        "required": ["reason"],
        "oneOf": [
            singular,
            { "allOf": [multi_base, multi_patch] }
        ]
    })
}

pub fn register_lifecycle_tools(registry: &mut ToolRegistry) -> Result<()> {
    let type_description = SPINE_TYPE_GLOSSES
        .iter()
        .map(|(record_type, gloss)| format!("{record_type}={gloss}"))
        .collect::<Vec<_>>()
        .join(";");
    registry.register(
        ToolKind::CreateRecord,
        "Create atomically. Compact default; response_mode=verbose gives full record. Requires spine type/open kind; preview_record_shape advises; create revalidates. Use manage_relationships.assert, not facets; assignment is assigned_to (WorkItem/task to Entity/person), not assignee. Artifacts: Document/artifact, source body, facets.runtime; see compositions guide. Messages require fixed audience. Comments require type Annotation, kind comment, nonblank body and exactly one outgoing part_of link. Roots default informational/open. A reply bears directly on the root comment; inherits context/null lifecycle. Targets require text_quote + canonical UTF-8 data_position. Replies stay targetless. Omit summary until resolution. Name what it rests on in sources; [] says none.",
        json!({
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": SPINE_TYPES,
                    "description": type_description
                },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION },
                "sources": source_basis_input_schema(),
                "id": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                    "description": "Optional caller-supplied record id. Must be a canonical lowercase UUIDv4 or UUIDv7; omit it and the engine mints one. Deterministic UUID versions (v1/v3/v5) and any other id shape are rejected, because a derived id collides across databases. The native: prefix is reserved for engine-owned records."
                },
                "kind": { "type": "string", "minLength": 1, "description": "Required non-empty open subtype; use a governed kind or an honest new token." },
                "name": { "type": "string" },
                "body": { "type": "string" },
                "home_id": { "type": "string", "description": "Live enduring folder; defaults to Unfiled." },
                "summary": { "type": "string" },
                "lifecycle": { "type": "string" },
                "owner_id": { "type": "string" },
                "persistence": { "type": "string", "enum": ["enduring", "occurrent"] },
                "maturity": { "type": "string" },
                "facets": {
                    "type": "object",
                    "description": "Open facets: scalar values or schema-validated atomic objects; objects require type:object.",
                    "additionalProperties": true
                },
                "links": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "target_id": { "type": "string" },
                            "relationship": { "type": "string" },
                            "note": { "type": "string" }
                        },
                        "required": ["target_id", "relationship"],
                        "additionalProperties": false
                    }
                },
                "addressed_to": {
                    "type": "array",
                    "uniqueItems": true,
                    "description": "Message-only immutable Entity:person audience; required even when empty.",
                    "items": { "type": "string" }
                },
                "mentions": {
                    "type":"array","uniqueItems":true,
                    "description":"Message-only immutable mentions; principal targets must be addressed.",
                    "items":{"type":"object","properties":{"mention_id":{"type":"string"},"target_kind":{"type":"string","enum":["principal","record"]},"target_id":{"type":"string"},"span_start":{"type":"integer","minimum":0},"span_end":{"type":"integer","minimum":1},"authored_label":{"type":"string"}},"required":["mention_id","target_kind","target_id","span_start","span_end","authored_label"],"additionalProperties":false}
                },
                "target": crate::mcp::tools::citations::target_schema(),
                "idempotency_key": { "type": "string", "description": "Retry-safety key: on ambiguous failure, retry with the SAME key, never a fresh one. An identical retry returns the record you already created rather than a second one; the same key with different content is rejected. With no key, every call creates a new record." },
                "response_mode": { "type": "string", "enum": ["summary", "verbose"], "default": "summary" }
            },
            "required": ["type", "kind", "reason"],
            "additionalProperties": false
        }),
        create_record,
    )?;
    registry.register(
        ToolKind::GetRecord,
        "Batch get by full ids or short record references: partial success, visible totals, paged enrichments. \
         Comments expose comment_count; include_comments pages direct roots from comments_offset \
         with each exact anchored passage. resolve:false skips saved queries. \
         as_of pins content; authorization/schema stay live. Interpretation overflow returns \
         unavailable without count. Only this read returns body_digest: SHA-256 of stored body \
         (empty/null -> sha256(\"\")); use update_record.if_body_digest for safe whole-body replacement.",
        crate::mcp::record_ref::with_record_selector_aliases("get_record", json!({
            "type": "object",
            "properties": {
                "ids": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1,
                    "maxItems": MAX_BATCH_GET,
                    "description": "IDs or short record references; search.query for unknown text."
                },
                "resolve": {
                    "type": "boolean",
                    "description": "Run saved queries one level (default true); false returns has_query only."
                },
                "include_interpretation": {
                    "type": "boolean",
                    "description": "Live caller-authorized typed projection; default false, <=50 ids, rejects as_of."
                },
                "children_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": read::MAX_ENRICH_LIMIT,
                    "description": "Children page; default 200, 0 returns count only."
                },
                "children_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Children offset; default 0."
                },
                "links_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": read::MAX_ENRICH_LIMIT,
                    "description": "Links per direction; default 200, 0 returns counts only."
                },
                "links_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Links offset per direction; default 0."
                },
                "include_suggestions": {
                    "type": "boolean",
                    "description": "Suggestion summaries; default false. Count is always returned and excluded from child_count."
                },
                "suggestions_limit": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": read::MAX_SUGGESTIONS_LIMIT,
                    "description": "Suggestions page; default 100, 0 returns count only."
                },
                "suggestions_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Suggestions offset; default 0."
                },
                "include_citations": {
                    "type": "boolean",
                    "description": "Citation summaries; default false. Count is always returned."
                },
                "citations_limit": {
                    "type": "integer", "minimum": 0, "maximum": read::MAX_CITATIONS_LIMIT,
                    "description": "Citations page; default 100."
                },
                "citations_offset": {
                    "type": "integer", "minimum": 0,
                    "description": "Citations offset."
                },
                "include_comments": {
                    "type": "boolean",
                    "description": "Direct comments; default false. Count is always returned."
                },
                "comments_limit": {
                    "type": "integer", "minimum": 0, "maximum": read::MAX_COMMENTS_LIMIT,
                    "description": "Comments page; default 50, 0 returns count only."
                },
                "comments_offset": {
                    "type": "integer", "minimum": 0,
                    "description": "Comments offset; roots newest-first, replies oldest-first."
                },
                "include_history_summary": {
                    "type": "boolean",
                    "description": "Oldest/newest visible-event attribution; default false; rejects as_of."
                },
                "as_of": lens::as_of_input_schema()
            },
            "required": ["ids"],
            "additionalProperties": false
        })),
        get_record,
    )?;
    registry.register(
        ToolKind::UpdateRecord,
        "Summary default; verbose full. body_set replaces (write finished documents once), body_append small additions only, body_replace edits spans. Guard: if_body_digest. Batch 1–100 ids; skips no-ops. facets=current; observations=evidence. Use manage_relationships.assert; assigned_to: WorkItem/task -> Entity/person. Resolve comments: lifecycle:\"resolved\", nonblank summary (open -> resolved). Tombstones reject. previous_seq -> get_record as_of.content_seq; compensation: record fields only, non-destructive and not atomic; do not create a v2 copy. Declare sources; [] means none.",
        update_record_input_schema(),
        update_record,
    )?;
    registry.register(
        ToolKind::ClaimUnownedRecord,
        "Exceptional ownership recovery for one exact, full record id naming a visible, live, ordinary record whose owner_id is null; abbreviated ids are not resolved. Host owners (or the standalone filesystem operator) may claim only for their own uniquely bound portable person identity. Engine records, Messages, semantic Units, derived annotations and attachments are excluded. Already-owned records and retries are refused without writing.",
        crate::mcp::record_ref::with_record_selector_aliases("claim_unowned_record", json!({
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                    "description": "Exact full canonical lowercase UUIDv4 or UUIDv7; abbreviations are deliberately not resolved on this high-risk surface."
                },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
            },
            "required": ["record_id", "reason"],
            "additionalProperties": false
        })),
        claim_unowned_record,
    )?;
    registry.register(
        ToolKind::CorrectRecordType,
        "Correct a live record's mistaken spine type through a governed plan. Preparation requires ordinary record edit authority; an autonomous same-run correction retains that authority, while an established or shared-use correction requires explicit record-manage confirmation. The target kind must be supplied explicitly, and execution fails without writing if the record changed after preparation.",
        crate::mcp::record_ref::with_record_selector_aliases("correct_record_type", json!({
            "type": "object",
            "properties": {
                "record_id": { "type": "string" },
                "target_type": { "type": "string", "enum": SPINE_TYPES },
                "target_kind": { "type": "string", "minLength": 1 },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
            },
            "required": ["record_id", "target_type", "target_kind", "reason"],
            "additionalProperties": false
        })),
        correct_record_type,
    )?;
    registry.register(
        ToolKind::DeleteRecord,
        &format!(
            "Soft-delete: sets the deleted_at tombstone; the record is frozen \
         (the projector rejects all further mutation events). No hard delete \
         in v1. {PREVIOUS_SEQ_DESCRIPTION}"
        ),
        crate::mcp::record_ref::with_record_selector_aliases("delete_record", json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
            },
            "required": ["id", "reason"],
            "additionalProperties": false
        })),
        delete_record,
    )?;
    registry.register(
        ToolKind::ArchiveRecord,
        &format!("Archive (archived: true, the default) or restore (archived: false) a \
         record via the engine-reserved archived facet. Archived records drop \
         out of default queries but stay mutable; lifecycle is preserved \
         across the round trip. {PREVIOUS_SEQ_DESCRIPTION}"),
        crate::mcp::record_ref::with_record_selector_aliases("archive_record", json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "archived": { "type": "boolean", "description": "true archives (default), false restores." },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
            },
            "required": ["id", "reason"],
            "additionalProperties": false
        })),
        archive_record,
    )?;
    registry.register(
        ToolKind::RenderRecord,
        "Deterministic record/enrichment Markdown, with no model. \
         include_interpretation:true (default false) adds the same bounded live \
         caller-authorized typed projection and summary.",
        crate::mcp::record_ref::with_record_selector_aliases(
            "render_record",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" },
                    "include_interpretation": {
                        "type": "boolean",
                        "description": "Bounded live interpretation plus Markdown; default false."
                    }
                },
                "required": ["id"],
                "additionalProperties": false
            }),
        ),
        render_record,
    )?;
    Ok(())
}

#[cfg(test)]
mod body_replace_context_tests {
    use super::*;

    fn replace(old: &str, new: &str) -> BodyReplace {
        BodyReplace {
            old: old.to_string(),
            new: new.to_string(),
            expected_count: None,
            replace_all: None,
        }
    }

    fn error_message(tool: &str, body: &str, ops: &[BodyReplace]) -> String {
        apply_body_replacements(tool, body, ops)
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn zero_match_with_long_partial_prefix_returns_window() {
        let body = format!(
            "{}greeting from the old world{}",
            "x".repeat(500),
            "y".repeat(500),
        );
        // The anchor's tail changed, but its 30-char head still occurs.
        let old = "greeting from the old world — edited tail".to_string();
        let message = error_message("update_record", &body, &[replace(&old, "new")]);
        let first_line = message.lines().next().unwrap();
        assert_eq!(
            first_line,
            "update_record: body_replace[0].old matched 0 occurrences"
        );
        assert!(message.contains("27 chars"), "{message}");
        let offset: usize = body.find("greeting").unwrap();
        assert!(
            message.contains(&format!("byte offset {offset}")),
            "{message}"
        );
        // 200 chars on each side of the anchor, clipped on both ends.
        assert!(message.contains(&"x".repeat(200)), "{message}");
        assert!(message.contains(&"y".repeat(200)), "{message}");
        assert!(message.contains("[MATCH]"), "{message}");
        assert!(message.contains("..."), "{message}");
    }

    #[test]
    fn zero_match_without_partial_prefix_returns_heading_outline() {
        let body = "# Alpha\nbody text\n## Beta\nmore text\n# Gamma\n";
        let message = error_message(
            "update_record",
            body,
            &[replace("zzz-no-such-anchor", "new")],
        );
        let first_line = message.lines().next().unwrap();
        assert_eq!(
            first_line,
            "update_record: body_replace[0].old matched 0 occurrences"
        );
        assert!(message.contains("heading outline"), "{message}");
        assert!(message.contains("0: # Alpha"), "{message}");
        assert!(message.contains("18: ## Beta"), "{message}");
        assert!(message.contains("36: # Gamma"), "{message}");
    }

    #[test]
    fn zero_match_heading_outline_stays_bounded() {
        // Ten thousand headings: only the first 20 travel, with the total
        // stated — the record body must not control rejection size.
        let body = (0..10_000)
            .map(|index| format!("# heading {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let message = error_message(
            "update_record",
            &body,
            &[replace("zzz-no-such-anchor-anywhere", "new")],
        );
        assert!(
            message
                .lines()
                .next()
                .unwrap()
                .ends_with("matched 0 occurrences"),
            "{message}"
        );
        assert!(
            message.contains("showing first 20 of 10000 headings"),
            "{message}"
        );
        assert!(message.contains("0: # heading 0"), "{message}");
        assert!(!message.contains("# heading 20"), "{message}");
        assert!(
            message.len() < 8192,
            "10,000 headings must not bloat the rejection: {} bytes",
            message.len()
        );
        // One 1MB heading line: clipped to 120 chars with a marker.
        let body = format!("# {}", "z".repeat(1_000_000));
        let message = error_message(
            "update_record",
            &body,
            &[replace("zzz-no-such-anchor-anywhere", "new")],
        );
        assert!(!message.contains(&"z".repeat(121)), "{message}");
        assert!(
            message.contains(&format!("0: # {}...", "z".repeat(118))),
            "{message}"
        );
        assert!(
            message.len() < 1024,
            "a 1MB heading must not bloat the rejection: {} bytes",
            message.len()
        );
    }

    #[test]
    fn count_mismatch_reports_each_match_with_context() {
        let body = "see dog one, see dog two, see dog three";
        let mut op = replace("dog", "cat");
        op.expected_count = Some(2);
        let message = error_message("update_record", body, &[op]);
        let first_line = message.lines().next().unwrap();
        assert_eq!(
            first_line,
            "update_record: body_replace[0] expected 2 occurrences but matched 3"
        );
        for matched in body.match_indices("dog").map(|(offset, _)| offset) {
            assert!(
                message.contains(&format!("byte offset {matched}")),
                "{message}"
            );
        }
        assert!(message.contains("[MATCH]"), "{message}");
    }

    #[test]
    fn count_mismatch_caps_contexts_at_ten_and_states_total() {
        let body = (0..12)
            .map(|index| format!("token{index} dog"))
            .collect::<Vec<_>>()
            .join(" ");
        let message = error_message("update_record", &body, &[replace("dog", "cat")]);
        let first_line = message.lines().next().unwrap();
        assert!(first_line.contains("matched 12 occurrences"), "{message}");
        assert_eq!(message.matches("byte offset").count(), 10, "{message}");
        assert!(
            message.contains("showing first 10 of 12 matches"),
            "{message}"
        );
    }

    #[test]
    fn windows_are_utf8_safe_at_window_edges() {
        // Multi-byte text straddling every window edge: clipping must floor
        // and ceil to char boundaries rather than panic on raw byte ranges.
        let body = format!(
            "{}needle-haystack-{}-anchor{}",
            "é".repeat(300),
            "🦮".repeat(100),
            "您".repeat(300),
        );
        // Zero-match path with a long partial prefix deep in multi-byte text.
        let old = format!("needle-haystack-{}-anchor-CHANGED", "🦮".repeat(100));
        let message = error_message("update_record", &body, &[replace(&old, "new")]);
        assert!(
            message
                .lines()
                .next()
                .unwrap()
                .ends_with("matched 0 occurrences"),
            "{message}"
        );
        assert!(message.contains("[MATCH]"), "{message}");
        // Count-mismatch path over multi-byte matches.
        let body = format!("{} dog {} dog", "é".repeat(100), "🦮".repeat(100));
        let mut op = replace("dog", "cat");
        op.expected_count = Some(5);
        let message = error_message("update_record", &body, &[op]);
        assert!(message.contains("but matched 2"), "{message}");
        assert!(message.contains("[MATCH]"), "{message}");
        // The helpers themselves never slice mid-codepoint, even when handed
        // interior byte indices.
        for index in 0..body.len() {
            let _ = window_before(&body, index, 200);
            let _ = window_after(&body, index, 200);
            let _ = floor_char_boundary(&body, index);
            let _ = ceil_char_boundary(&body, index);
        }
    }
}

#[cfg(test)]
mod create_idempotency_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test(start_paused = true)]
    async fn historical_admission_accepts_release_after_former_cutoff() {
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let occupied = permits.clone().acquire_many_owned(2).await.unwrap();
        let deadline = tokio::time::Instant::now() + ATTESTED_REBUILD_EXECUTION;
        let queued = permits.clone();
        let admission =
            tokio::spawn(async move { admit_attested_rebuild(&queued, deadline).await });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_millis(300)).await;
        assert!(
            !admission.is_finished(),
            "queue survives the former 250ms cutoff"
        );
        drop(occupied);
        let admitted = admission.await.unwrap().unwrap();
        assert_eq!(permits.available_permits(), 1);
        drop(admitted);
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn historical_admission_fails_closed_at_shared_deadline() {
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let occupied = permits.clone().acquire_many_owned(2).await.unwrap();
        let deadline = tokio::time::Instant::now() + ATTESTED_REBUILD_EXECUTION;
        let queued = permits.clone();
        let admission =
            tokio::spawn(async move { admit_attested_rebuild(&queued, deadline).await });
        tokio::task::yield_now().await;
        tokio::time::advance(ATTESTED_REBUILD_EXECUTION).await;
        let error = admission.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("admission exhausted"), "{error}");
        assert_eq!(permits.available_permits(), 0);
        drop(occupied);
        assert_eq!(permits.available_permits(), 2);
        // Even immediately available capacity cannot admit expired work.
        let error = admit_attested_rebuild(&permits, deadline)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("admission exhausted"), "{error}");
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn historical_admission_cancellation_removes_waiter_without_leaking() {
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let occupied = permits.clone().acquire_many_owned(2).await.unwrap();
        let deadline = tokio::time::Instant::now() + ATTESTED_REBUILD_EXECUTION;
        let queued = permits.clone();
        let admission =
            tokio::spawn(async move { admit_attested_rebuild(&queued, deadline).await });
        tokio::task::yield_now().await;
        assert!(!admission.is_finished());
        admission.abort();
        assert!(admission.await.unwrap_err().is_cancelled());
        assert_eq!(permits.available_permits(), 0);
        drop(occupied);
        let next = admit_attested_rebuild(&permits, deadline).await.unwrap();
        assert_eq!(permits.available_permits(), 1);
        drop(next);
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn historical_admission_wait_consumes_execution_budget() {
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let occupied = permits.clone().acquire_many_owned(2).await.unwrap();
        let deadline = tokio::time::Instant::now() + ATTESTED_REBUILD_EXECUTION;
        let queued = permits.clone();
        let reached = Arc::new(tokio::sync::Notify::new());
        let started = reached.clone();
        let replay = tokio::spawn(async move {
            with_attested_rebuild_deadline(&queued, deadline, |permit| async move {
                let _permit = permit;
                started.notify_one();
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                Ok(json!({"unexpected": "fresh execution budget"}))
            })
            .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(9)).await;
        drop(occupied);
        reached.notified().await;
        assert_eq!(permits.available_permits(), 1);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let error = replay.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("deadline exceeded"), "{error}");
        assert_eq!(tokio::time::Instant::now(), deadline);
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn historical_deadline_rejects_ready_result_at_expiry() {
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let deadline = tokio::time::Instant::now() + ATTESTED_REBUILD_EXECUTION;
        let (release, wait) = tokio::sync::oneshot::channel();
        let mut replay = Box::pin(with_attested_rebuild_deadline(
            &permits,
            deadline,
            |permit| async move {
                let _permit = permit;
                wait.await.unwrap();
                Ok(json!({"unexpected": "late completion"}))
            },
        ));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(replay.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(permits.available_permits(), 1);
        // Make the work ready, but only poll it after expiry. Tokio polls
        // work before its timer, so the explicit completion check is needed.
        tokio::time::advance(ATTESTED_REBUILD_EXECUTION).await;
        release.send(()).unwrap();
        let error = replay.await.unwrap_err().to_string();
        assert!(error.contains("deadline exceeded"), "{error}");
        assert_eq!(permits.available_permits(), 2);
    }

    /// Two concurrent creates with the same key must not both append. The
    /// rendezvous parks the spawned racer inside `begin_write` — both writers
    /// are then in flight at once, and `BEGIN IMMEDIATE` serializes them: the
    /// loser begins after the winner commits, sees the attestation in its
    /// in-transaction lookup, and replays. The partial unique index
    /// underneath is the backstop, not the mechanism under test. This lives
    /// in-crate (rather than in `tests/`) because the rendezvous seam
    /// `with_before_begin_write_notification` is `pub(crate)`.
    #[tokio::test]
    async fn concurrent_keyed_creates_serialize_on_begin_and_append_once() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let args = json!({
            "type": "Document",
            "kind": "note",
            "name": "race",
            "body": "durable prose",
            "reason": "race two keyed creates through one write lock",
            "idempotency_key": "race-key",
        });

        let before_begin = Arc::new(tokio::sync::Notify::new());
        let racer_db = db.clone();
        let racer_registry = registry.clone();
        let racer_args = args.clone();
        let racer = tokio::spawn(crate::db::with_before_begin_write_notification(
            before_begin.clone(),
            async move {
                racer_registry
                    .call(
                        racer_db,
                        crate::mcp::Caller::local(),
                        "create_record",
                        racer_args,
                    )
                    .await
            },
        ));
        // The racer has reached `begin_write`; run the twin to completion
        // while it is parked there, then release it into the overlap.
        before_begin.notified().await;
        let first = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                args,
            )
            .await
            .unwrap();
        let second = racer.await.unwrap().unwrap();
        assert_eq!(first, second, "both racers converge on one receipt");
        let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE name='race'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(records, 1, "exactly one record was appended");
        let attestations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM provenance_local_attestation_authority
              WHERE principal='local' AND operation='create_record'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            attestations, 1,
            "exactly one command attestation was issued"
        );
        db.close().await;
    }
    async fn fixture() -> (Db, ToolRegistry) {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, registry)
    }

    async fn attested(db: &Db, receipt: &Value) -> AttestedCreate {
        let mut tx = db.write_pool().begin().await.unwrap();
        let result = attested_create_horizons_in(
            &mut tx,
            receipt["action_attestation_ids"][0].as_str().unwrap(),
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        result
    }

    #[tokio::test]
    async fn compact_replay_matches_verbose_summary_for_supported_spine_shapes() {
        let (db, registry) = fixture().await;
        let kind_alias = crate::meta::propose_value_with_kind_metadata_as(
            &db,
            "kind:Document",
            "replay-note",
            None,
            0.0,
            crate::meta::VocabularyValueTerminality::Open,
            Some(crate::meta::kind::KindMetadataV1::legacy(
                "Document",
                "replay-note",
            )),
            None,
        )
        .await
        .unwrap();
        crate::meta::promote_value(&db, &kind_alias).await.unwrap();
        let note: String = sqlx::query_scalar("SELECT id FROM vocabulary_values WHERE vocabulary_id='voc:kind:Document' AND value='note'").fetch_one(db.write_pool()).await.unwrap();
        crate::meta::alias_value(&db, &kind_alias, &note)
            .await
            .unwrap();
        let owner = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type":"Entity", "kind":"person", "name":"shape owner", "reason":"fixture"
                }),
            )
            .await
            .unwrap();
        for (index, mut args) in [
            json!({"type":"Document","kind":"replay-note","body":null,"lifecycle":null,"facets":{"numeric_probe":42,"object_probe":{"nested":"value"}}}),
            json!({"type":"WorkItem","kind":"task","body":"body","lifecycle":"open","persistence":"occurrent","maturity":"draft","owner_id":owner["id"]}),
            json!({"type":"Entity","kind":"person"}),
            json!({"type":"Collection","kind":"folder","body":"collection prose"}),
        ].into_iter().enumerate() {
            args["name"] = json!(format!("shape {index}"));
            args["reason"] = json!("compare compact dependency closure with full pinned projection");
            args["idempotency_key"] = json!(format!("shape-{index}"));
            args["response_mode"] = json!("verbose");
            let first = registry.call(db.clone(), Caller::local(), "create_record", args.clone()).await.unwrap();
            if index == 1 {
                // Admit an active canonical lifecycle first. The historical lens
                // deliberately interprets that pinned raw value using live aliases.
                let open: String = sqlx::query_scalar("SELECT id FROM vocabulary_values WHERE vocabulary_id='voc:lifecycle' AND value='open'").fetch_one(db.write_pool()).await.unwrap();
                let progress: String = sqlx::query_scalar("SELECT id FROM vocabulary_values WHERE vocabulary_id='voc:lifecycle' AND value='in_progress'").fetch_one(db.write_pool()).await.unwrap();
                crate::meta::alias_value(&db, &open, &progress).await.unwrap();
            }
            let pin = attested(&db, &first).await;
            // A later mutation must never enter either reconstruction.
            registry.call(db.clone(), Caller::local(), "update_record", json!({"id":first["id"],"name":"later name","reason":"move live state"})).await.unwrap();
            let verbose = read_attested_create_receipt(&db, &Caller::local(), &pin, None).await.unwrap();
            let mut tx = db.write_pool().begin().await.unwrap();
            let compact = compact_attested_create_in(&mut tx, &Caller::local(), &pin, None).await.unwrap().expect("supported shape must have narrow closure");
            tx.rollback().await.unwrap();
            assert_eq!(summarize_write_receipt(&db, compact, pin.content_horizon).await.unwrap(),
                summarize_write_receipt(&db, verbose, pin.content_horizon).await.unwrap(), "shape {index}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn compact_bypasses_saturated_fallback_and_oversized_unrelated_history() {
        let (db, registry) = fixture().await;
        let unrelated = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({"type":"Document","kind":"note","name":"history","reason":"fixture"}),
            )
            .await
            .unwrap();
        // Valid inert updates in the log, fixture-inserted in one statement so
        // this tests the budget rather than spending 10,001 write transactions.
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10001)
            INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status)
            SELECT 'budget-'||x,?,'record.updated','{}','2026-01-01T00:00:00.000Z',1,'legacy_unknown' FROM n")
            .bind(unrelated["id"].as_str().unwrap()).execute(db.write_pool()).await.unwrap();
        let args = json!({"type":"Document","kind":"note","name":"bounded","body":"original","reason":"fixture","idempotency_key":"bounded"});
        let first = registry
            .call(db.clone(), Caller::local(), "create_record", args.clone())
            .await
            .unwrap();
        let pin = attested(&db, &first).await;
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let occupied = permits.acquire_many(2).await.unwrap();
        let error = read_attested_create_receipt_with_limits(
            &db,
            &Caller::local(),
            &pin,
            None,
            &permits,
            std::time::Duration::from_millis(250),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("admission exhausted"), "{error}");
        // Same pinned receipt's compact path has no dependency on admission.
        let mut tx = db.write_pool().begin().await.unwrap();
        let compact = compact_attested_create_in(&mut tx, &Caller::local(), &pin, None)
            .await
            .unwrap()
            .unwrap();
        tx.rollback().await.unwrap();
        assert_eq!(compact["body_digest"], first["body_digest"]);
        assert_eq!(
            registry
                .call(db.clone(), Caller::local(), "create_record", args)
                .await
                .unwrap(),
            first
        );
        drop(occupied);
        let error = read_attested_create_receipt_with_limits(
            &db,
            &Caller::local(),
            &pin,
            None,
            &permits,
            ATTESTED_REBUILD_EXECUTION,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("budget exceeded"), "{error}");
        let settled = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            permits.clone().acquire_many_owned(2),
        )
        .await
        .unwrap()
        .unwrap();
        drop(settled);
        db.close().await;
    }

    #[tokio::test]
    async fn validity_only_change_preserves_original_act_and_historical_admissions() {
        let (db, registry) = fixture().await;
        let target = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({"type":"Outcome","kind":"target","name":"target","reason":"fixture"}),
            )
            .await
            .unwrap();
        let args = json!({"type":"Document","kind":"note","name":"linked","body":"original","reason":"fixture","idempotency_key":"validity", "response_mode":"verbose",
            "links":[{"target_id":target["id"],"relationship":"depends_on"}]});
        let first = registry
            .call(db.clone(), Caller::local(), "create_record", args.clone())
            .await
            .unwrap();
        assert_eq!(first["links_out"].as_array().unwrap().len(), 1);
        let pin = attested(&db, &first).await;
        let heads: (i64,i64) = sqlx::query_as("SELECT (SELECT MAX(seq) FROM content_events),(SELECT MAX(seq) FROM relationship_events)").fetch_one(db.write_pool()).await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act = crate::act::ActAllocation::new();
        crate::provenance::append_validity_event_in(
            &mut tx,
            &mut act,
            &pin.attestation_id,
            crate::provenance::ValidityChange::Invalidated,
            "test invalidation",
            "test",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let after: (i64,i64) = sqlx::query_as("SELECT (SELECT MAX(seq) FROM content_events),(SELECT MAX(seq) FROM relationship_events)").fetch_one(db.write_pool()).await.unwrap();
        assert_eq!(heads, after, "validity refresh appends neither log");
        let live_links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id=?")
            .bind(&pin.record_id)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            live_links, 0,
            "fixture must invalidate live relationship admission"
        );
        let verbose = registry
            .call(db.clone(), Caller::local(), "create_record", args.clone())
            .await
            .unwrap();
        assert_eq!(
            verbose["links_out"], first["links_out"],
            "issuance-time admissions stay pinned"
        );
        assert_eq!(verbose["act"], first["act"]);
        let mut compact_args = args;
        compact_args["response_mode"] = json!("summary");
        let compact = registry
            .call(db.clone(), Caller::local(), "create_record", compact_args)
            .await
            .unwrap();
        assert_eq!(
            summarize_write_receipt(&db, compact.clone(), pin.content_horizon)
                .await
                .unwrap(),
            summarize_write_receipt(&db, verbose, pin.content_horizon)
                .await
                .unwrap()
        );
        assert_eq!(compact["act"], first["act"]);
        db.close().await;
    }

    #[tokio::test]
    async fn cancellation_during_scratch_close_retires_pools_without_waiting() {
        let db = open_database(":memory:").await.unwrap();
        let held = db.write_pool().acquire().await.unwrap();
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let scratch = AttestedScratch {
            db: db.clone(),
            permit: Some(permits.clone().acquire_owned().await.unwrap()),
        };
        let result = tokio::time::timeout(std::time::Duration::from_millis(10), async move {
            scratch.db.close().await;
            drop(scratch);
        })
        .await;
        assert!(
            result.is_err(),
            "held checkout must force the graceful close to wait"
        );
        assert!(
            db.write_pool().is_closed(),
            "cancellation retires scratch admission synchronously"
        );
        assert_eq!(
            permits.available_permits(),
            0,
            "close wait retains fallback capacity"
        );
        drop(held);
        let settled = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            permits.clone().acquire_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(settled);
        tokio::time::timeout(std::time::Duration::from_secs(1), db.close())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn later_scratch_setup_failure_drains_partial_pools_before_releasing_permit() {
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = permits.clone().acquire_owned().await.unwrap();
        let failure = Arc::new(crate::db::ReadPoolOpenFailure::default());
        let setup = tokio::spawn(
            crate::db::READ_POOL_OPEN_FAILURE.scope(failure.clone(), open_attested_scratch(permit)),
        );
        failure.reached.notified().await;
        let pool = failure.write_pool.lock().unwrap().take().unwrap();
        let held = pool.acquire().await.unwrap();
        failure.release.notify_one();
        // Failed read-pool setup must now be waiting on physical write-pool drain.
        assert!(admit_attested_rebuild(
            &permits,
            tokio::time::Instant::now() + std::time::Duration::from_millis(250),
        )
        .await
        .is_err());
        assert!(
            !setup.is_finished(),
            "setup failure cannot return while a prior worker is held"
        );
        assert!(
            pool.is_closed(),
            "partial pool retires admission before draining"
        );
        assert_eq!(permits.available_permits(), 0);
        drop(held);
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), setup)
            .await
            .unwrap()
            .unwrap()
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("injected read-pool setup failure"),
            "{error}"
        );
        assert_eq!(
            pool.size(),
            0,
            "physical workers drain before setup returns Err"
        );
        assert_eq!(permits.available_permits(), 1);
    }

    #[test]
    fn content_and_relationship_sizes_consume_one_shared_budget() {
        let mut budget = AttestedReplayBudget::new();
        let phase = vec![512 * 1024; 18]; // 9 MiB, every row below the 1 MiB ceiling.
        budget.charge(&phase).unwrap();
        assert_eq!(budget.bytes, 7 * 1024 * 1024);
        assert!(
            budget.charge(&phase).is_err(),
            "9+9 MiB must not pass a 16 MiB request budget"
        );
        assert_eq!(
            budget.bytes,
            7 * 1024 * 1024,
            "rejection leaves the remaining budget intact"
        );
    }

    #[tokio::test]
    async fn deadline_mid_page_cancels_fold_and_keeps_permit_until_scratch_drains() {
        let (db, registry) = fixture().await;
        let first = registry.call(db.clone(), Caller::local(), "create_record", json!({"type":"Document","kind":"note","name":"cancel mid page","body":"original","reason":"fixture","idempotency_key":"mid-page"})).await.unwrap();
        let pin = attested(&db, &first).await;
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let pause = Arc::new(AttestedReplayPause {
            reached: tokio::sync::Notify::new(),
            scratch: std::sync::Mutex::new(None),
            projected: std::sync::atomic::AtomicUsize::new(0),
        });
        let replay_db = db.clone();
        let replay_permits = permits.clone();
        let replay_pause = pause.clone();
        let task = tokio::spawn(ATTESTED_REPLAY_PAUSE.scope(replay_pause, async move {
            read_attested_create_receipt_with_limits(
                &replay_db,
                &Caller::local(),
                &pin,
                None,
                &replay_permits,
                std::time::Duration::from_secs(2),
            )
            .await
        }));
        tokio::time::timeout(std::time::Duration::from_secs(2), pause.reached.notified())
            .await
            .unwrap();
        let scratch = pause.scratch.lock().unwrap().take().unwrap();
        let held = scratch.write_pool().acquire().await.unwrap();
        let error = task.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("deadline exceeded"), "{error}");
        assert_eq!(
            pause.projected.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "no detached fold reaches the next event"
        );
        assert!(
            scratch.write_pool().is_closed(),
            "new scratch admission is retired"
        );
        assert_eq!(
            permits.available_permits(),
            0,
            "draining scratch still owns capacity"
        );
        assert!(
            admit_attested_rebuild(
                &permits,
                tokio::time::Instant::now() + std::time::Duration::from_millis(250),
            )
            .await
            .is_err(),
            "replacement cannot multiply draining resources"
        );
        // Cancellation also releases the live writer and rolls back scratch's
        // partially folded page; independent writes can continue while draining.
        registry.call(db.clone(), Caller::local(), "create_record", json!({"type":"Document","kind":"note","name":"writer after cancel","reason":"fixture"})).await.unwrap();
        drop(held);
        let settled = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            permits.clone().acquire_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(settled);
        db.close().await;
    }

    #[tokio::test]
    async fn historical_deadline_cancels_work_and_releases_admission() {
        let (db, registry) = fixture().await;
        let first = registry.call(db.clone(), Caller::local(), "create_record", json!({"type":"Document","kind":"note","name":"deadline","body":"original","reason":"fixture","idempotency_key":"deadline"})).await.unwrap();
        let pin = attested(&db, &first).await;
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let error = read_attested_create_receipt_with_limits(
            &db,
            &Caller::local(),
            &pin,
            None,
            &permits,
            std::time::Duration::ZERO,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("admission exhausted"), "{error}");
        let settled = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            permits.clone().acquire_many_owned(2),
        )
        .await
        .unwrap()
        .unwrap();
        drop(settled);
        // Cancellation must not poison the live store or queue another fold.
        let rebuilt = read_attested_create_receipt_with_limits(
            &db,
            &Caller::local(),
            &pin,
            None,
            &permits,
            ATTESTED_REBUILD_EXECUTION,
        )
        .await
        .unwrap();
        assert_eq!(rebuilt["body_digest"], first["body_digest"]);
        db.close().await;
    }
}

#[cfg(test)]
mod body_set_append_tests {
    use super::*;
    use std::sync::Arc;

    async fn setup() -> (crate::Db, Arc<crate::mcp::ToolRegistry>) {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, Arc::new(registry))
    }

    async fn create_note(
        registry: &crate::mcp::ToolRegistry,
        db: &crate::Db,
        body: Option<&str>,
    ) -> String {
        let mut args = json!({
            "type": "Document",
            "kind": "note",
            "name": "body probe",
            "reason": "body_set/append fixture",
        });
        if let Some(body) = body {
            args["body"] = json!(body);
        }
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                args,
            )
            .await
            .unwrap();
        created["id"].as_str().unwrap().to_string()
    }

    async fn stored_body(db: &crate::Db, id: &str) -> Option<String> {
        sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn event_count(db: &crate::Db, id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id = ?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    fn receipt(result: &Value) -> &Value {
        result
            .get("body_receipt")
            .expect("a body operation must return a body_receipt")
    }

    fn has_deprecation_warning(result: &Value) -> bool {
        result
            .get("warnings")
            .and_then(Value::as_array)
            .is_some_and(|warnings| {
                warnings.iter().any(|warning| {
                    warning.get("code").and_then(Value::as_str) == Some("deprecated_body_alias")
                })
            })
    }

    #[tokio::test]
    async fn set_replaces_with_unicode_scalar_receipt() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("Hello")).await;
        let new_body = "Hello, world 🌍";
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_set": new_body,
                    "if_body_digest": body_digest(Some("Hello")),
                    "reason": "explicit replacement",
                }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some(new_body));
        let expected_after = new_body.chars().count() as u64;
        assert_eq!(receipt(&result)["operation"], json!("body_set"));
        assert_eq!(receipt(&result)["requested_as"], json!("body_set"));
        assert_eq!(receipt(&result)["before_chars"], json!(5));
        assert_eq!(receipt(&result)["after_chars"], json!(expected_after));
        assert_eq!(
            receipt(&result)["delta_chars"],
            json!(expected_after as i64 - 5)
        );
        assert_eq!(receipt(&result)["unit"], json!("unicode_scalars"));
        assert!(!has_deprecation_warning(&result));
        db.close().await;
    }

    #[tokio::test]
    async fn set_null_clears_with_zero_after_chars() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("abc")).await;
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_set": null,
                    "if_body_digest": body_digest(Some("abc")),
                    "reason": "clear the body",
                }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await, None);
        assert_eq!(receipt(&result)["operation"], json!("body_set"));
        assert_eq!(receipt(&result)["before_chars"], json!(3));
        assert_eq!(receipt(&result)["after_chars"], json!(0));
        assert_eq!(receipt(&result)["delta_chars"], json!(-3));
        db.close().await;
    }

    #[tokio::test]
    async fn legacy_body_warns_including_content_identical_noop() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("same")).await;
        // Content-identical write still succeeds and still warns.
        let noop = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body": "same",
                    "if_body_digest": body_digest(Some("same")),
                    "reason": "legacy no-op",
                }),
            )
            .await
            .unwrap();
        assert!(has_deprecation_warning(&noop), "{noop}");
        assert_eq!(receipt(&noop)["operation"], json!("body_set"));
        assert_eq!(receipt(&noop)["requested_as"], json!("body"));
        assert_eq!(receipt(&noop)["delta_chars"], json!(0));
        // A real change through the alias warns the same way.
        let changed = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body": "changed",
                    "if_body_digest": body_digest(Some("same")),
                    "reason": "legacy replacement",
                }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("changed"));
        assert!(has_deprecation_warning(&changed));
        assert_eq!(receipt(&changed)["requested_as"], json!("body"));
        db.close().await;
    }

    #[tokio::test]
    async fn unguarded_set_refused_but_append_needs_no_digest() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("nonempty")).await;
        let before = event_count(&db, &id).await;
        let err = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "body_set": "other", "reason": "unguarded" }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unguarded whole-body write refused"), "{err}");
        assert!(err.contains("body_set"), "{err}");
        assert_eq!(event_count(&db, &id).await, before);
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("nonempty"));
        // Append against a non-empty body needs no digest.
        let appended = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "body_append": "!", "reason": "append" }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("nonempty!"));
        assert_eq!(receipt(&appended)["operation"], json!("body_append"));
        assert_eq!(receipt(&appended)["before_chars"], json!(8));
        assert_eq!(receipt(&appended)["after_chars"], json!(9));
        assert_eq!(receipt(&appended)["delta_chars"], json!(1));
        db.close().await;
    }

    #[tokio::test]
    async fn append_is_literal_with_caller_separator_and_unicode() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("Hello")).await;
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "body_append": ", world", "reason": "append" }),
            )
            .await
            .unwrap();
        // The separator travelled inside the caller's text; nothing was added.
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("Hello, world"));
        assert_eq!(receipt(&result)["delta_chars"], json!(7));
        // Unicode scalars, not bytes: café is 4, the append is 3.
        let unicode = create_note(&registry, &db, Some("café")).await;
        let appended = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": unicode, "body_append": " 🦮🌍", "reason": "append" }),
            )
            .await
            .unwrap();
        assert_eq!(
            stored_body(&db, &unicode).await.as_deref(),
            Some("café 🦮🌍")
        );
        assert_eq!(receipt(&appended)["before_chars"], json!(4));
        assert_eq!(receipt(&appended)["after_chars"], json!(7));
        assert_eq!(receipt(&appended)["delta_chars"], json!(3));
        assert_eq!(receipt(&appended)["unit"], json!("unicode_scalars"));
        db.close().await;
    }

    #[tokio::test]
    async fn append_to_null_body_reads_as_empty() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, None).await;
        assert_eq!(stored_body(&db, &id).await, None);
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "body_append": "seed", "reason": "append" }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("seed"));
        assert_eq!(receipt(&result)["before_chars"], json!(0));
        assert_eq!(receipt(&result)["after_chars"], json!(4));
        db.close().await;
    }

    #[tokio::test]
    async fn all_six_exclusive_pairs_reject_without_mutation() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("stable")).await;
        let replacement = json!([{ "old": "stable", "new": "other" }]);
        let pairs = [
            ("body", json!("x"), "body_set", json!("x")),
            ("body", json!("x"), "body_append", json!("x")),
            ("body", json!("x"), "body_replace", replacement.clone()),
            ("body_set", json!("x"), "body_append", json!("x")),
            ("body_set", json!("x"), "body_replace", replacement.clone()),
            ("body_append", json!("x"), "body_replace", replacement),
        ];
        for (first, first_value, second, second_value) in pairs {
            let before = event_count(&db, &id).await;
            let mut obj = serde_json::Map::new();
            obj.insert("id".into(), json!(id));
            obj.insert("reason".into(), json!("conflicting body ops"));
            obj.insert(first.into(), first_value);
            obj.insert(second.into(), second_value);
            let err = registry
                .call(
                    db.clone(),
                    crate::mcp::Caller::local(),
                    "update_record",
                    Value::Object(obj),
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("mutually exclusive"), "{err}");
            assert_eq!(event_count(&db, &id).await, before, "{err}");
        }
        // Explicit nulls still name the operation: null + null conflicts.
        let null_err = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "reason": "null pair", "body": null, "body_set": null }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(null_err.contains("mutually exclusive"), "{null_err}");
        // An explicit null body_replace cannot fold away beside another op.
        let folded_err = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "reason": "null replace", "body_set": "x", "body_replace": null }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(folded_err.contains("body_replace"), "{folded_err}");
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("stable"));
        db.close().await;
    }

    #[tokio::test]
    async fn stale_digest_rejects_append_and_set_without_mutation() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("v1")).await;
        let stale = body_digest(Some("v1"));
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_set": "v2",
                    "if_body_digest": stale.clone(),
                    "reason": "advance",
                }),
            )
            .await
            .unwrap();
        for args in [
            json!({ "id": id, "body_append": "!", "if_body_digest": stale, "reason": "stale append" }),
            json!({ "id": id, "body_set": "v3", "if_body_digest": stale, "reason": "stale set" }),
        ] {
            let before = event_count(&db, &id).await;
            let err = registry
                .call(
                    db.clone(),
                    crate::mcp::Caller::local(),
                    "update_record",
                    args,
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("digest conflict"), "{err}");
            assert_eq!(event_count(&db, &id).await, before, "{err}");
        }
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("v2"));
        db.close().await;
    }

    #[tokio::test]
    async fn fresh_digest_append_succeeds() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("a")).await;
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_append": "b",
                    "if_body_digest": body_digest(Some("a")),
                    "reason": "guarded append",
                }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("ab"));
        assert_eq!(receipt(&result)["operation"], json!("body_append"));
        db.close().await;
    }

    #[tokio::test]
    async fn equal_length_replacement_reports_operation_with_zero_delta() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("ab")).await;
        let set = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_set": "cd",
                    "if_body_digest": body_digest(Some("ab")),
                    "reason": "equal length set",
                }),
            )
            .await
            .unwrap();
        assert_eq!(receipt(&set)["operation"], json!("body_set"));
        assert_eq!(receipt(&set)["delta_chars"], json!(0));
        let replaced = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_replace": [{ "old": "cd", "new": "ef" }],
                    "reason": "equal length surgical",
                }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("ef"));
        assert_eq!(receipt(&replaced)["operation"], json!("body_replace"));
        assert_eq!(receipt(&replaced)["delta_chars"], json!(0));
        db.close().await;
    }

    #[tokio::test]
    async fn separate_writer_appends_both_land() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("start")).await;
        let first = registry.call(
            db.clone(),
            crate::mcp::Caller::local(),
            "update_record",
            json!({ "id": id, "body_append": "-one", "reason": "writer one" }),
        );
        let second = registry.call(
            db.clone(),
            crate::mcp::Caller::local(),
            "update_record",
            json!({ "id": id, "body_append": "-two", "reason": "writer two" }),
        );
        let (first, second) = tokio::join!(first, second);
        first.unwrap();
        second.unwrap();
        let body = stored_body(&db, &id).await.expect("body present");
        assert!(
            body == "start-one-two" || body == "start-two-one",
            "both appends must land exactly once: {body}"
        );
        assert_eq!(body.chars().count(), 13);
        db.close().await;
    }

    #[tokio::test]
    async fn singular_schema_nests_exclusivity_in_allof() {
        let (_, registry) = setup().await;
        let schema = &registry
            .specs()
            .find(|spec| spec.name == "update_record")
            .expect("update_record registered")
            .input_schema;
        let singular = &schema["oneOf"][0];
        let base = &singular["allOf"][0];
        for field in ["body", "body_set", "body_append", "body_replace"] {
            assert!(
                base["properties"].get(field).is_some(),
                "singular base must declare {field}"
            );
        }
        // One base shape, six body exclusions, and one selector clause.
        let clauses = singular["allOf"].as_array().unwrap();
        assert_eq!(clauses.len(), 8);
        assert_eq!(
            clauses
                .iter()
                .filter(|clause| clause.get("not").is_some())
                .count(),
            6
        );
        assert_eq!(
            clauses
                .iter()
                .filter(|clause| clause.get("oneOf").is_some())
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn stale_timestamp_rejects_both_new_ops_without_mutation() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("v1")).await;
        for args in [
            json!({ "id": id, "body_set": "v2", "if_unmodified_since": "2000-01-01T00:00:00Z", "reason": "stale set" }),
            json!({ "id": id, "body_append": "!", "if_unmodified_since": "2000-01-01T00:00:00Z", "reason": "stale append" }),
        ] {
            let before = event_count(&db, &id).await;
            let err = registry
                .call(
                    db.clone(),
                    crate::mcp::Caller::local(),
                    "update_record",
                    args,
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("stale write conflict"), "{err}");
            assert_eq!(event_count(&db, &id).await, before, "{err}");
        }
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("v1"));
        db.close().await;
    }

    #[tokio::test]
    async fn append_empty_string_succeeds_with_zero_delta() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("kept")).await;
        let before = event_count(&db, &id).await;
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "body_append": "", "reason": "empty append" }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("kept"));
        assert_eq!(receipt(&result)["operation"], json!("body_append"));
        assert_eq!(receipt(&result)["delta_chars"], json!(0));
        assert_eq!(
            receipt(&result)["before_chars"],
            receipt(&result)["after_chars"]
        );
        // Content-identical append still commits its event under current behavior.
        assert_eq!(event_count(&db, &id).await, before + 1);
        db.close().await;
    }

    #[tokio::test]
    async fn set_empty_string_needs_guard_then_clears_to_empty() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("abc")).await;
        let before = event_count(&db, &id).await;
        let err = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "body_set": "", "reason": "unguarded clear" }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unguarded whole-body write refused"), "{err}");
        assert_eq!(event_count(&db, &id).await, before, "{err}");
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({
                    "id": id,
                    "body_set": "",
                    "if_body_digest": body_digest(Some("abc")),
                    "reason": "guarded clear",
                }),
            )
            .await
            .unwrap();
        // Empty string persists as empty, distinct from null.
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some(""));
        assert_eq!(receipt(&result)["operation"], json!("body_set"));
        assert_eq!(receipt(&result)["after_chars"], json!(0));
        assert_eq!(receipt(&result)["delta_chars"], json!(-3));
        db.close().await;
    }

    #[tokio::test]
    async fn both_new_ops_reject_on_tombstoned_record() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("epitaph")).await;
        let digest = body_digest(Some("epitaph"));
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "delete_record",
                json!({ "id": id, "reason": "tombstone fixture" }),
            )
            .await
            .unwrap();
        let before = event_count(&db, &id).await;
        for args in [
            json!({ "id": id, "body_set": "resurrect", "if_body_digest": digest.clone(), "reason": "set on tombstone" }),
            json!({ "id": id, "body_append": "!", "reason": "append on tombstone" }),
        ] {
            let err = registry
                .call(
                    db.clone(),
                    crate::mcp::Caller::local(),
                    "update_record",
                    args,
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("tombstoned"), "{err}");
            assert_eq!(event_count(&db, &id).await, before, "{err}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn body_op_combines_with_name_in_one_event() {
        let (db, registry) = setup().await;
        let id = create_note(&registry, &db, Some("base")).await;
        let before = event_count(&db, &id).await;
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "name": "renamed", "body_append": "+", "reason": "both at once" }),
            )
            .await
            .unwrap();
        assert_eq!(stored_body(&db, &id).await.as_deref(), Some("base+"));
        assert_eq!(result["name"], json!("renamed"));
        assert_eq!(event_count(&db, &id).await, before + 1);
        let payload: String = sqlx::query_scalar(
            "SELECT payload FROM content_events WHERE record_id=? AND type='record.updated' ORDER BY seq DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let payload: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(payload["body"], json!("base+"));
        assert_eq!(payload["name"], json!("renamed"));
        assert_eq!(payload["reason"], json!("both at once"));
        db.close().await;
    }
}

// The long task-body scenarios (fifth-revision crossing, revision gate,
// field-only/non-task silence, recross/next-milestone, lookup failure) run
// through the default-installed advisor now: see
// `crate::mcp::advisors::long_record::tests`.

#[cfg(all(test, feature = "mcp-executor-prototype"))]
mod correction_spine_tests {
    use super::*;
    use crate::schema::SPINE_TYPES;

    /// The direct `correct_record_type` tool only executes through a claimed
    /// plan, so the closed-spine-type refusal in `correction_snapshot_in` is
    /// reachable from the surface only via preparation. This drives the real
    /// prepare entry point against a live database.
    #[tokio::test]
    async fn prepare_with_unknown_target_type_lists_the_closed_spine_set() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "subject",
                    "reason": "Seed for an unknown-target-type refusal.",
                }),
            )
            .await
            .unwrap();
        let record_id = created["id"].as_str().unwrap().to_string();
        let err = prepare_correct_record_type(
            &db,
            &crate::mcp::Caller::local(),
            json!({
                "record_id": record_id,
                "target_type": "Nope",
                "target_kind": "note",
                "reason": "Exercise the unknown-type refusal.",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        for spine in SPINE_TYPES {
            assert!(err.contains(spine), "refusal must name {spine}: {err}");
        }
        db.close().await;
    }
}

/// Private canonical comment kernel tests (task `b9fb9fd` family 1). Real
/// installs, bindings, needs, tokens and the ordinary creation path — no
/// public dispatch, no hosted acceptance. Fixture installs go through the
/// registry; account bindings and binding rows are seeded like the
/// alpha_tabs fixtures (helper reads, never authority).
#[cfg(test)]
mod comment_kernel_tests {
    use super::*;
    use native_artifact_runtime::artifact_intents::AlphaTabInstallGuard;
    use native_artifact_runtime::mdx_v2::{
        CommentBodyDecl, CommentCreateDecl, CommentPosition, InteractionEffect, InteractionEntry,
        MessageReactDecl, TitleSetDecl,
    };

    const KERNEL_ACCOUNT: &str = "alice";
    const KERNEL_ARTIFACT: &str = "e0000000-0000-4000-8000-0000000000a1";
    const KERNEL_COLLECTION: &str = "e0000000-0000-4000-8000-0000000000a2";
    const KERNEL_BEARER: &str = "e0000000-0000-4000-8000-0000000000a3";
    const KERNEL_PERSON: &str = "e0000000-0000-4000-8000-0000000000a4";
    const KERNEL_QUERY: &str = "e0000000-0000-4000-8000-0000000000a5";
    const KERNEL_BODY: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Kernel</title></head><body><main><h1>Kernel</h1></main></body></html>";

    fn configure_preview_launch() {
        // Sample-only preview launch tickets need the HTML runtime origins;
        // the values are test-local and idempotent across parallel tests in
        // this binary (mirrors tests/tools/alpha_tabs.rs).
        crate::artifact_html::configure(
            crate::artifact_html::RuntimeConfig::new(
                "http://localhost:8080",
                "http://artifact.localhost:8080",
            )
            .expect("preview test HTML runtime configuration"),
        );
    }

    fn kernel_need() -> Value {
        json!({"need": "sql.snapshot.v1", "key": "thread.items", "label": "Thread",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL AND name LIKE 'thread-%' ORDER BY id ASC LIMIT 40"})
    }

    fn kernel_declaration(positions: Value) -> Value {
        json!({"needs": [kernel_need()], "effects": [{
            "effect": "comment.create.v1", "positions": positions,
            "max_body_bytes": 100, "target": {"need": "thread.items"}}]})
    }

    fn kernel_entry(id: &str, position: CommentPosition) -> InteractionEntry {
        InteractionEntry {
            id: id.into(),
            label: "Post".into(),
            effect: InteractionEffect::CommentCreate,
            slots: [(
                "bearer".to_string(),
                native_artifact_runtime::mdx_v2::SlotDecl {
                    domain: native_artifact_runtime::mdx_v2::SlotDomain::BoundInput {
                        port: Some("orders".to_string()),
                    },
                },
            )]
            .into_iter()
            .collect(),
            facet: String::new(),
            value: None,
            create: None,
            comment: Some(CommentCreateDecl {
                position,
                body: CommentBodyDecl {
                    input: "text".into(),
                    max_bytes: 500,
                },
            }),
            react: None,
            title: None,
            body: None,
        }
    }

    /// A minimal valid message.react entry for the reaction-kernel
    /// regression below: only the shape the guard scope checks (effect,
    /// envelope, admitted emoji) and the id are used; slots are irrelevant
    /// because the plan is built directly rather than composed.
    fn react_kernel_entry(id: &str) -> InteractionEntry {
        InteractionEntry {
            id: id.into(),
            label: "React".into(),
            effect: InteractionEffect::MessageReact,
            slots: Default::default(),
            facet: String::new(),
            value: None,
            create: None,
            comment: None,
            react: Some(MessageReactDecl {
                emoji: vec!["👍".into()],
            }),
            title: None,
            body: None,
        }
    }

    /// A minimal valid title.set entry for the title-kernel regression
    /// below: only the shape the guard scope checks (effect plus title
    /// envelope) and the id are used; slots are irrelevant because the plan
    /// is built directly rather than composed.
    fn title_kernel_entry(id: &str) -> InteractionEntry {
        InteractionEntry {
            id: id.into(),
            label: "Rename".into(),
            effect: InteractionEffect::TitleSet,
            slots: Default::default(),
            facet: String::new(),
            value: None,
            create: None,
            comment: None,
            react: None,
            title: Some(TitleSetDecl {}),
            body: None,
        }
    }

    struct KernelFixture {
        db: crate::Db,
        registry: crate::mcp::ToolRegistry,
        guard: AlphaTabInstallGuard,
        body_digest: String,
    }

    async fn kernel_fixture(declaration: Value, package: &str, adopt: bool) -> KernelFixture {
        configure_preview_launch();
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        let local = crate::mcp::Caller::local();
        // Account binding for the viewer (person record plus binding row).
        sqlx::query(
            "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id,persistence) \
             VALUES (?,'Entity','person','Kernel viewer',?,?,'enduring')",
        )
        .bind(KERNEL_PERSON)
        .bind(crate::schema::UNFILED_RECORD_ID)
        .bind(crate::schema::ROOT_RECORD_ID)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id,system,identifier,is_canonical) VALUES (?,'account',?,1)",
        )
        .bind(KERNEL_PERSON)
        .bind(KERNEL_ACCOUNT)
        .execute(db.write_pool())
        .await
        .unwrap();
        for (id, type_, kind, name, home) in [
            // Enduring folder home: assert_home_target_in requires a live,
            // unarchived, enduring Collection kind:folder. It stays the
            // filing home, never the binding scope: folder-bound ordinary
            // query_record excludes governed comments by default, so a
            // reply root could never resolve inside it.
            // Persistence is set explicitly rather than relying on a
            // create-path default.
            (KERNEL_COLLECTION, "Collection", "folder", "Threads", None),
            (
                KERNEL_BEARER,
                "Document",
                "note",
                "thread-target",
                Some(KERNEL_COLLECTION),
            ),
            (KERNEL_ARTIFACT, "Document", "artifact", "Kernel tab", None),
        ] {
            let mut args = json!({
                "id": id, "type": type_, "kind": kind, "name": name,
                "reason": "Comment kernel fixture.",
            });
            if let Some(home) = home {
                args.as_object_mut()
                    .unwrap()
                    .insert("home_id".into(), json!(home));
            }
            if id == KERNEL_ARTIFACT {
                args.as_object_mut()
                    .unwrap()
                    .insert("body".into(), json!(KERNEL_BODY));
                args.as_object_mut()
                    .unwrap()
                    .insert("facets".into(), json!({ "runtime": "native.html.v1" }));
            }
            if id == KERNEL_COLLECTION {
                args.as_object_mut()
                    .unwrap()
                    .insert("persistence".into(), json!("enduring"));
            }
            registry
                .call(db.clone(), local.clone(), "create_record", args)
                .await
                .unwrap();
        }
        // Separate binding scope: a versioned record query (NOT governed
        // SQL, which Record ports refuse) with explicit kinds note+comment
        // over the folder home, so thread roots resolve inside the port
        // cohort. The folder above stays the filing home.
        let thread_query = json!({
            "v": "0.2",
            "query": { "steps": [{
                "step": "filter",
                "kinds": ["note", "comment"],
                "home_id": KERNEL_COLLECTION,
            }]},
        })
        .to_string();
        registry
            .call(
                db.clone(),
                local.clone(),
                "create_record",
                json!({
                    "id": KERNEL_QUERY, "type": "Collection", "kind": "query",
                    "name": "Threads", "home_id": KERNEL_COLLECTION,
                    "facets": { "query": thread_query },
                    "reason": "Comment kernel fixture.",
                }),
            )
            .await
            .unwrap();
        // replace_explicit_policy replaces the whole policy per record,
        // so each record's full grant set is written in one call.
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            KERNEL_ARTIFACT,
            vec![AllowEntry::account(KERNEL_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            KERNEL_COLLECTION,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            KERNEL_QUERY,
            vec![AllowEntry::account(KERNEL_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        let source_revision: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
        )
        .bind(KERNEL_ARTIFACT)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let declaration_digest =
            crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration).unwrap();
        let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
            &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(KERNEL_BODY),
            &declaration_digest,
            "native.html.v1",
        );
        let base_args = json!({
            "package": package, "version": "0.1.0", "digest": digest,
            "artifact_id": KERNEL_ARTIFACT, "source_revision": source_revision,
            "declaration": declaration,
        });
        let viewer = Caller::authenticated(KERNEL_ACCOUNT);
        let mut install_args = base_args.as_object().cloned().unwrap();
        install_args.insert("action".into(), json!("install"));
        install_args.insert("reason".into(), json!("Install comment kernel fixture."));
        let installed = registry
            .call(
                db.clone(),
                viewer.clone(),
                "manage_alpha_tabs",
                Value::Object(install_args),
            )
            .await
            .unwrap();
        assert_eq!(installed["changed"], true, "{installed:#}");
        let install_event = installed["install"]["event_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut verified_event = install_event.clone();
        if adopt {
            let authority_for = || {
                crate::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for(
                    KERNEL_ACCOUNT,
                    package,
                    "0.1.0",
                    &digest,
                    KERNEL_ARTIFACT,
                    &source_revision,
                    &declaration,
                )
                .expect("fixture declaration is well-formed")
            };
            let mut preview_args = base_args.as_object().cloned().unwrap();
            preview_args.insert("action".into(), json!("preview"));
            preview_args.insert("reason".into(), json!("Preview comment kernel fixture."));
            let preview = registry
                .call(
                    db.clone(),
                    viewer
                        .clone()
                        .with_verified_alpha_tab_preview(authority_for()),
                    "manage_alpha_tabs",
                    Value::Object(preview_args),
                )
                .await
                .unwrap();
            let mut adopt_args = base_args.as_object().cloned().unwrap();
            adopt_args.insert("action".into(), json!("adopt"));
            adopt_args.insert(
                "receipt_id".into(),
                preview["receipt"]["receipt_id"].clone(),
            );
            adopt_args.insert("nonce".into(), preview["receipt"]["nonce"].clone());
            adopt_args.insert(
                "preview_session".into(),
                preview["receipt"]["preview_session"].clone(),
            );
            adopt_args.insert("expected_install_event_id".into(), json!(install_event));
            adopt_args.insert("reason".into(), json!("Adopt comment kernel fixture."));
            let adopted = registry
                .call(
                    db.clone(),
                    viewer
                        .clone()
                        .with_verified_alpha_tab_adopt(authority_for()),
                    "manage_alpha_tabs",
                    Value::Object(adopt_args),
                )
                .await
                .unwrap();
            assert_eq!(
                adopted["install"]["adoption"], "shell_adopt.v1",
                "{adopted:#}"
            );
            verified_event = adopted["install"]["event_id"].as_str().unwrap().to_string();
        }
        // The ordinary artifact create above already persisted this source
        // event's attestation row. Reuse the actual row — never a
        // counterfeit duplicate (source_event_id is unique) — and reference
        // its real id in the seeded mapping/grant below. Seeded mapping and
        // grant rows stay helper-read fixtures, never authority.
        let bundle_digest = crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(KERNEL_BODY);
        let attestation: String = sqlx::query_scalar(
            "SELECT attestation_event_id FROM artifact_source_attestations
              WHERE artifact_id=? AND source_event_id=? AND source_sha256=?",
        )
        .bind(KERNEL_ARTIFACT)
        .bind(&source_revision)
        .bind(&bundle_digest)
        .fetch_optional(db.pool())
        .await
        .unwrap()
        .expect("genuine artifact create persists the source attestation");
        sqlx::query(
            "INSERT INTO artifact_inputs
                (artifact_id, port_name, collection_id,
                 artifact_source_attestation_event_id, artifact_source_event_id,
                 artifact_source_sha256, event_seq)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(KERNEL_ARTIFACT)
        .bind("orders")
        .bind(KERNEL_QUERY)
        .bind(&attestation)
        .bind(&source_revision)
        .bind(&bundle_digest)
        .bind(0_i64)
        .execute(db.write_pool())
        .await
        .unwrap();
        let scope_sha256 = crate::mcp::tools::artifacts::mdx_sha256_for_projection(
            &json!({"artifact_port": "orders"}),
        );
        sqlx::query(
            "INSERT INTO artifact_module_grants
                (artifact_id, subject_kind, subject_record_id, subject_event_id,
                 source_sha256, artifact_source_attestation_event_id,
                 artifact_source_event_id, artifact_source_sha256, capability,
                 scope_sha256, scope, event_seq)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(KERNEL_ARTIFACT)
        .bind("artifact_source")
        .bind(KERNEL_ARTIFACT)
        .bind(&source_revision)
        .bind(&bundle_digest)
        .bind(&attestation)
        .bind(&source_revision)
        .bind(&bundle_digest)
        .bind("input.read")
        .bind(&scope_sha256)
        .bind("{\"artifact_port\":\"orders\"}")
        .bind(0_i64)
        .execute(db.write_pool())
        .await
        .unwrap();
        let guard = AlphaTabInstallGuard {
            package: package.to_string(),
            expected_install_event_id: verified_event,
            artifact_id: KERNEL_ARTIFACT.to_string(),
            source_revision: source_revision.clone(),
            version: "0.1.0".to_string(),
            digest,
            declaration_digest,
        };
        KernelFixture {
            db,
            registry,
            guard,
            body_digest: crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(KERNEL_BODY),
        }
    }

    // S3-B-only fixtures: real installed/adopted Alpha descriptor and ordinary
    // writers; mapping/grant seeds are the same explicit helper-read fixtures
    // as existing kernel tests, never runtime authority or hosted acceptance.
    fn body_kernel_source() -> String {
        let descriptor = json!({
            "schema":"native.html.artifact.v2",
            "inputs":{"orders":{"envelope":"native.collection-envelope.v1","required":true,"expose_to_root":true}},
            "capability_requests":[{"capability":"input.read","scope":{"port":"orders"}}],
            "interactions":[{"id":"save","label":"Save","effect":"body.set",
                "slots":{"page":{"domain":{"kind":"bound_input","port":"orders"}}},"body":{"max_bytes":32768}}]
        });
        format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Body</title></head><body><main><h1>Body</h1><script type="application/json" id="native-artifact-manifest">{descriptor}</script></main></body></html>"#
        )
    }

    fn body_kernel_declaration() -> Value {
        json!({"needs":[{"need":"sql.snapshot.v1","key":"docs.body","label":"Document",
            "sql":"SELECT id FROM records WHERE id=?1 AND deleted_at IS NULL",
            "params":[{"name":"record_id","type":"text","required":true,"max_len":128}]}],
            "effects":[{"effect":"records.body-set.v1","max_body_bytes":32768,"target":{"need":"docs.body"}}]})
    }

    fn body_plan(
        f: &KernelFixture,
        body: &str,
        expected: Option<&str>,
        key: &str,
    ) -> ArtifactBodySavePlan {
        ArtifactBodySavePlan {
            invocation: native_artifact_runtime::artifact_intents::ArtifactInvocation {
                version: native_artifact_runtime::artifact_intents::INVOCATION_VERSION.into(),
                artifact_id: KERNEL_ARTIFACT.into(),
                entry_id: "save".into(),
                source_digest: f.body_digest.clone(),
                slots: BTreeMap::from([("page".into(), KERNEL_BEARER.into())]),
                values: BTreeMap::from([
                    ("body".into(), json!(body)),
                    ("expected_body_digest".into(), json!(body_digest(expected))),
                ]),
                observed: BTreeMap::new(),
                idempotency_key: key.into(),
                gesture: Some("click".into()),
                include_next_plan: false,
                alpha_install_guard: Some(f.guard.clone()),
                reverses: None,
            },
            source_event_id: f.guard.source_revision.clone(),
        }
    }

    fn body_undo(
        f: &KernelFixture,
        original: &str,
        key: &str,
    ) -> native_artifact_runtime::artifact_intents::ArtifactInvocation {
        let mut invocation = body_plan(f, "", None, key).invocation;
        invocation.slots.clear();
        invocation.values.clear();
        invocation.alpha_install_guard = None;
        invocation.reverses = Some(
            native_artifact_runtime::artifact_intents::ReversalReference {
                entry_id: "save".into(),
                idempotency_key: original.into(),
            },
        );
        invocation
    }

    fn body_receipt(outcome: ArtifactBodyOutcome) -> Value {
        let ArtifactBodyOutcome::Committed { receipt } = outcome else {
            panic!("expected committed: {outcome:?}");
        };
        serde_json::to_value(receipt).unwrap()
    }

    fn body_refused(result: Result<ArtifactBodyOutcome>) {
        assert!(
            matches!(result, Ok(ArtifactBodyOutcome::Refused { .. })),
            "expected confirmed precommit refusal: {result:?}"
        );
    }

    async fn body_durable_state(db: &Db) -> (i64, i64, i64, Option<String>) {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let frontier: i64 = sqlx::query_scalar("SELECT COALESCE(max(seq),0) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let act: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let body = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(KERNEL_BEARER)
            .fetch_one(db.pool())
            .await
            .unwrap();
        (count, frontier, act, body)
    }

    async fn body_kernel_fixture(
        declaration: Value,
        package: &str,
        initial: Option<&str>,
    ) -> KernelFixture {
        let source = body_kernel_source();
        let adopt = true;
        configure_preview_launch();
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        let local = crate::mcp::Caller::local();
        // Account binding for the viewer (person record plus binding row).
        sqlx::query(
            "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id,persistence) \
             VALUES (?,'Entity','person','Kernel viewer',?,?,'enduring')",
        )
        .bind(KERNEL_PERSON)
        .bind(crate::schema::UNFILED_RECORD_ID)
        .bind(crate::schema::ROOT_RECORD_ID)
        .execute(db.write_pool())
        .await
        .unwrap();
        // Use the audited identity writer so this fixture can also reopen as
        // an enrolled file; a raw live binding fails ordinary open validation.
        crate::identity::add_binding(
            &db,
            &crate::identity::MutationContext {
                actor: "test:body-viewer",
                reason: "Body fixture account binding",
                run_key: None,
                parent_key: None,
                intent: None,
                is_member: true,
                internal: true,
                source_read_authorized: false,
            },
            KERNEL_PERSON,
            &crate::identity::BindingClaim {
                system: "account".into(),
                identifier: KERNEL_ACCOUNT.into(),
            },
            true,
        )
        .await
        .unwrap();
        for (id, type_, kind, name, home) in [
            // Enduring folder home: assert_home_target_in requires a live,
            // unarchived, enduring Collection kind:folder. It stays the
            // filing home, never the binding scope: folder-bound ordinary
            // query_record excludes governed comments by default, so a
            // reply root could never resolve inside it.
            // Persistence is set explicitly rather than relying on a
            // create-path default.
            (KERNEL_COLLECTION, "Collection", "folder", "Threads", None),
            (
                KERNEL_BEARER,
                "Document",
                "note",
                "thread-target",
                Some(KERNEL_COLLECTION),
            ),
            (KERNEL_ARTIFACT, "Document", "artifact", "Kernel tab", None),
        ] {
            let mut args = json!({
                "id": id, "type": type_, "kind": kind, "name": name,
                "reason": "Comment kernel fixture.",
            });
            if let Some(home) = home {
                args.as_object_mut()
                    .unwrap()
                    .insert("home_id".into(), json!(home));
            }
            if let (true, Some(body)) = (id == KERNEL_BEARER, initial) {
                args["body"] = json!(body);
            }
            if id == KERNEL_ARTIFACT {
                args.as_object_mut()
                    .unwrap()
                    .insert("body".into(), json!(&source));
                args.as_object_mut()
                    .unwrap()
                    .insert("facets".into(), json!({ "runtime": "native.html.v1" }));
            }
            if id == KERNEL_COLLECTION {
                args.as_object_mut()
                    .unwrap()
                    .insert("persistence".into(), json!("enduring"));
            }
            registry
                .call(db.clone(), local.clone(), "create_record", args)
                .await
                .unwrap();
        }
        // Separate binding scope: a versioned record query (NOT governed
        // SQL, which Record ports refuse) with explicit kinds note+comment
        // over the folder home, so thread roots resolve inside the port
        // cohort. The folder above stays the filing home.
        let thread_query = json!({
            "v": "0.2",
            "query": { "steps": [{
                "step": "filter",
                "kinds": ["note", "comment"],
                "home_id": KERNEL_COLLECTION,
            }]},
        })
        .to_string();
        registry
            .call(
                db.clone(),
                local.clone(),
                "create_record",
                json!({
                    "id": KERNEL_QUERY, "type": "Collection", "kind": "query",
                    "name": "Threads", "home_id": KERNEL_COLLECTION,
                    "facets": { "query": thread_query },
                    "reason": "Comment kernel fixture.",
                }),
            )
            .await
            .unwrap();
        // replace_explicit_policy replaces the whole policy per record,
        // so each record's full grant set is written in one call.
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            KERNEL_ARTIFACT,
            vec![AllowEntry::account(KERNEL_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            KERNEL_COLLECTION,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            KERNEL_QUERY,
            vec![AllowEntry::account(KERNEL_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        let source_revision: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
        )
        .bind(KERNEL_ARTIFACT)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let declaration_digest =
            crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration).unwrap();
        let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
            &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&source),
            &declaration_digest,
            "native.html.v1",
        );
        let base_args = json!({
            "package": package, "version": "0.1.0", "digest": digest,
            "artifact_id": KERNEL_ARTIFACT, "source_revision": source_revision,
            "declaration": declaration,
        });
        let viewer = Caller::authenticated(KERNEL_ACCOUNT);
        let mut install_args = base_args.as_object().cloned().unwrap();
        install_args.insert("action".into(), json!("install"));
        install_args.insert("reason".into(), json!("Install comment kernel fixture."));
        let installed = registry
            .call(
                db.clone(),
                viewer.clone(),
                "manage_alpha_tabs",
                Value::Object(install_args),
            )
            .await
            .unwrap();
        assert_eq!(installed["changed"], true, "{installed:#}");
        let install_event = installed["install"]["event_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut verified_event = install_event.clone();
        if adopt {
            let authority_for = || {
                crate::mcp::tools::alpha_tabs::alpha_tab_preview_authority_for(
                    KERNEL_ACCOUNT,
                    package,
                    "0.1.0",
                    &digest,
                    KERNEL_ARTIFACT,
                    &source_revision,
                    &declaration,
                )
                .expect("fixture declaration is well-formed")
            };
            let mut preview_args = base_args.as_object().cloned().unwrap();
            preview_args.insert("action".into(), json!("preview"));
            preview_args.insert("reason".into(), json!("Preview comment kernel fixture."));
            let preview = registry
                .call(
                    db.clone(),
                    viewer
                        .clone()
                        .with_verified_alpha_tab_preview(authority_for()),
                    "manage_alpha_tabs",
                    Value::Object(preview_args),
                )
                .await
                .unwrap();
            let mut adopt_args = base_args.as_object().cloned().unwrap();
            adopt_args.insert("action".into(), json!("adopt"));
            adopt_args.insert(
                "receipt_id".into(),
                preview["receipt"]["receipt_id"].clone(),
            );
            adopt_args.insert("nonce".into(), preview["receipt"]["nonce"].clone());
            adopt_args.insert(
                "preview_session".into(),
                preview["receipt"]["preview_session"].clone(),
            );
            adopt_args.insert("expected_install_event_id".into(), json!(install_event));
            adopt_args.insert("reason".into(), json!("Adopt comment kernel fixture."));
            let adopted = registry
                .call(
                    db.clone(),
                    viewer
                        .clone()
                        .with_verified_alpha_tab_adopt(authority_for()),
                    "manage_alpha_tabs",
                    Value::Object(adopt_args),
                )
                .await
                .unwrap();
            assert_eq!(
                adopted["install"]["adoption"], "shell_adopt.v1",
                "{adopted:#}"
            );
            verified_event = adopted["install"]["event_id"].as_str().unwrap().to_string();
        }
        // The ordinary artifact create above already persisted this source
        // event's attestation row. Reuse the actual row — never a
        // counterfeit duplicate (source_event_id is unique) — and reference
        // its real id in the seeded mapping/grant below. Seeded mapping and
        // grant rows stay helper-read fixtures, never authority.
        let bundle_digest = crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&source);
        let attestation: String = sqlx::query_scalar(
            "SELECT attestation_event_id FROM artifact_source_attestations
              WHERE artifact_id=? AND source_event_id=? AND source_sha256=?",
        )
        .bind(KERNEL_ARTIFACT)
        .bind(&source_revision)
        .bind(&bundle_digest)
        .fetch_optional(db.pool())
        .await
        .unwrap()
        .expect("genuine artifact create persists the source attestation");
        sqlx::query(
            "INSERT INTO artifact_inputs
                (artifact_id, port_name, collection_id,
                 artifact_source_attestation_event_id, artifact_source_event_id,
                 artifact_source_sha256, event_seq)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(KERNEL_ARTIFACT)
        .bind("orders")
        .bind(KERNEL_QUERY)
        .bind(&attestation)
        .bind(&source_revision)
        .bind(&bundle_digest)
        .bind(0_i64)
        .execute(db.write_pool())
        .await
        .unwrap();
        let scope_sha256 = crate::mcp::tools::artifacts::mdx_sha256_for_projection(
            &json!({"artifact_port": "orders"}),
        );
        sqlx::query(
            "INSERT OR IGNORE INTO artifact_module_grants
                (artifact_id, subject_kind, subject_record_id, subject_event_id,
                 source_sha256, artifact_source_attestation_event_id,
                 artifact_source_event_id, artifact_source_sha256, capability,
                 scope_sha256, scope, event_seq)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(KERNEL_ARTIFACT)
        .bind("artifact_source")
        .bind(KERNEL_ARTIFACT)
        .bind(&source_revision)
        .bind(&bundle_digest)
        .bind(&attestation)
        .bind(&source_revision)
        .bind(&bundle_digest)
        .bind("input.read")
        .bind(&scope_sha256)
        .bind("{\"artifact_port\":\"orders\"}")
        .bind(0_i64)
        .execute(db.write_pool())
        .await
        .unwrap();
        let guard = AlphaTabInstallGuard {
            package: package.to_string(),
            expected_install_event_id: verified_event,
            artifact_id: KERNEL_ARTIFACT.to_string(),
            source_revision: source_revision.clone(),
            version: "0.1.0".to_string(),
            digest,
            declaration_digest,
        };
        crate::authorization::replace_explicit_policy(
            &db,
            "test:body-target",
            KERNEL_BEARER,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        KernelFixture {
            db,
            registry,
            guard,
            body_digest: crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&source),
        }
    }

    // Public registry calls reuse the real adopted-install fixture; the private
    // kernel suite below remains the evidence for its deeper invariants.
    async fn public_body_call(
        f: &KernelFixture,
        caller: Caller,
        invocation: native_artifact_runtime::artifact_intents::ArtifactInvocation,
    ) -> Result<Value> {
        f.registry
            .call(
                f.db.clone(),
                caller,
                "invoke_artifact_interaction",
                serde_json::to_value(invocation).unwrap(),
            )
            .await
    }

    #[tokio::test]
    async fn body_public_save_receipt_digest_replay_and_nullable_undo() {
        for initial in [None, Some("base")] {
            let f =
                body_kernel_fixture(body_kernel_declaration(), "agent.body-public", initial).await;
            let invocation = body_plan(&f, "next汉\r\n", initial, "public:save").invocation;
            let caller = body_audit_caller(
                &invocation,
                crate::awareness::EffectGestureKind::Click,
                false,
            );
            let before = body_durable_state(&f.db).await;
            let receipt = public_body_call(&f, caller.clone(), invocation.clone())
                .await
                .unwrap();
            assert_eq!(receipt["status"], "committed", "{receipt:#}");
            assert!(receipt.get("refresh").is_none());
            assert_eq!(receipt["changes"][0]["record_id"], KERNEL_BEARER);
            assert_eq!(receipt["changes"][0]["key"], "body");
            assert_eq!(
                receipt["changes"][0]["after"]["sha256"],
                body_digest(Some("next汉\r\n"))
            );
            let saved = body_durable_state(&f.db).await;
            assert_eq!(
                saved.0,
                before.0 + 1,
                "one domain event, no registry wrapper receipt"
            );
            assert_eq!(saved.3.as_deref(), Some("next汉\r\n"));
            assert_eq!(receipt["changes"][0]["version"], format!("rec:{}", saved.1));
            assert!(
                body_audit_payload(&f.db, "public:save").await["origin"]["gesture_evidence"]
                    .is_object()
            );
            assert_eq!(
                public_body_call(&f, caller, invocation).await.unwrap(),
                receipt
            );
            assert_eq!(body_durable_state(&f.db).await, saved);
            let undo = body_undo(&f, "public:save", "public:undo");
            let undo_caller =
                body_audit_caller(&undo, crate::awareness::EffectGestureKind::Click, true);
            let inverse = public_body_call(&f, undo_caller.clone(), undo.clone())
                .await
                .unwrap();
            assert_eq!(inverse["status"], "committed", "{inverse:#}");
            assert_eq!(
                inverse["changes"][0]["after"],
                match initial {
                    None => json!({"kind":"null"}),
                    Some(text) =>
                        json!({"kind":"text","sha256":body_digest(Some(text)),"utf8_bytes":text.len()}),
                }
            );
            let restored = body_durable_state(&f.db).await;
            assert_eq!(restored.0, saved.0 + 1);
            assert_eq!(restored.3.as_deref(), initial);
            assert_eq!(
                public_body_call(&f, undo_caller, undo).await.unwrap(),
                inverse
            );
            assert_eq!(body_durable_state(&f.db).await, restored);
        }
    }

    #[tokio::test]
    async fn body_public_stale_malformed_oversize_foreign_and_revoked_zero_write() {
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-public-refuse",
            Some("base"),
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let invocation = body_plan(&f, "next", Some("base"), "public:save").invocation;
        let before = body_durable_state(&f.db).await;
        for case in 0..4 {
            let mut invalid = invocation.clone();
            match case {
                0 => {
                    invalid.values.insert(
                        "expected_body_digest".into(),
                        json!(body_digest(Some("stale"))),
                    );
                }
                1 => {
                    invalid
                        .values
                        .insert("body".into(), json!("🦀".repeat(8193)));
                }
                2 => {
                    invalid.values.insert("body".into(), json!(null));
                }
                _ => {
                    invalid
                        .observed
                        .insert(KERNEL_BEARER.into(), BTreeMap::new());
                }
            }
            let result = public_body_call(&f, caller.clone(), invalid).await;
            if case < 2 {
                let result = result.unwrap();
                assert_eq!(result["status"], "rejected", "{result:#}");
                assert_eq!(
                    result["error"]["code"],
                    if case == 0 {
                        "body_digest_conflict"
                    } else {
                        "body_or_inverse_oversize"
                    }
                );
            } else {
                match result {
                    Err(Error::Engine(message)) => {
                        assert!(message.starts_with("body "), "{message}")
                    }
                    Ok(result) => {
                        assert_eq!(result["status"], "invalid", "{result:#}");
                        assert_eq!(result["error"]["code"], "invalid_invocation");
                    }
                    other => panic!("expected closed envelope refusal: {other:?}"),
                }
            }
            assert_eq!(body_durable_state(&f.db).await, before);
        }
        assert!(
            public_body_call(&f, Caller::authenticated("foreign"), invocation.clone())
                .await
                .is_err()
        );
        assert_eq!(body_durable_state(&f.db).await, before);
        crate::authorization::replace_explicit_policy(
            &f.db,
            "test:public-edit-revoke",
            KERNEL_BEARER,
            vec![AllowEntry::account(KERNEL_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        let revoked = body_durable_state(&f.db).await;
        let result = public_body_call(&f, caller.clone(), invocation.clone()).await;
        assert!(result.is_err() || result.unwrap()["status"] == "rejected");
        assert_eq!(body_durable_state(&f.db).await, revoked);
        crate::authorization::replace_explicit_policy(
            &f.db,
            "test:public-view-revoke",
            KERNEL_ARTIFACT,
            vec![AllowEntry::account("foreign", Capability::View)],
        )
        .await
        .unwrap();
        let invisible = body_durable_state(&f.db).await;
        assert!(public_body_call(&f, caller, invocation).await.is_err());
        assert_eq!(body_durable_state(&f.db).await, invisible);
    }

    #[tokio::test]
    async fn body_public_enrolled_save_and_undo_refuse_zero_write() {
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-public-enrolled",
            Some("base"),
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let first = body_plan(&f, "next", Some("base"), "public:first").invocation;
        assert_eq!(
            public_body_call(&f, caller.clone(), first).await.unwrap()["status"],
            "committed"
        );
        let directory = tempfile::tempdir().unwrap();
        let generation = uuid::Uuid::new_v4().to_string();
        let path = directory
            .path()
            .join("databases")
            .join(format!("{generation}.db"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let enrollment =
            crate::managed_custody::reserve_fresh_adoption(directory.path(), &path, &generation)
                .unwrap();
        sqlx::query("VACUUM INTO ?")
            .bind(path.to_str().unwrap())
            .execute(f.db.write_pool())
            .await
            .unwrap();
        enrollment.finalize().unwrap();
        let enrolled = crate::db::open_existing_database_at(&path).await.unwrap();
        assert!(enrolled.is_enrolled());
        let before = body_durable_state(&enrolled).await;
        for invocation in [
            body_plan(&f, "other", Some("next"), "public:enrolled").invocation,
            body_undo(&f, "public:first", "public:enrolled-undo"),
        ] {
            let error = f
                .registry
                .call(
                    enrolled.clone(),
                    caller.clone(),
                    "invoke_artifact_interaction",
                    serde_json::to_value(invocation).unwrap(),
                )
                .await
                .unwrap_err();
            // Public registry admission refuses before the private kernel's
            // own enrolled_unsupported guard. Keep both boundaries intact.
            assert_eq!(error.to_string(),
                "enrolled storage supports only singular Document body updates; mutation not admitted");
            assert_eq!(body_durable_state(&enrolled).await, before);
        }
    }

    #[tokio::test]
    async fn body_kernel_nullable_literals_save_undo_and_immutable_replay() {
        for initial in [
            None,
            Some(""),
            Some("null"),
            Some("{\"x\":1}"),
            Some("a\0tail汉🦀\r\n"),
        ] {
            let f = body_kernel_fixture(body_kernel_declaration(), "agent.body-nullable", initial)
                .await;
            let caller = Caller::authenticated(KERNEL_ACCOUNT);
            let plan = body_plan(&f, "next\0汉\r\n", initial, "body:save");
            let receipt = body_receipt(
                save_body_from_artifact(&f.db, &caller, plan.clone())
                    .await
                    .unwrap(),
            );
            let after_save = body_durable_state(&f.db).await;
            let replay = body_receipt(save_body_from_artifact(&f.db, &caller, plan).await.unwrap());
            assert_eq!(receipt, replay);
            assert_eq!(body_durable_state(&f.db).await, after_save);
            let undo = body_undo(&f, "body:save", "body:undo");
            let inverse = body_receipt(
                undo_body_from_artifact(&f.db, &caller, &undo)
                    .await
                    .unwrap(),
            );
            assert_eq!(body_durable_state(&f.db).await.3.as_deref(), initial);
            if initial.is_none() {
                assert_eq!(inverse["changes"][0]["after"], json!({"kind":"null"}));
            } else {
                assert_eq!(inverse["changes"][0]["after"]["kind"], "text");
            }
            let after_undo = body_durable_state(&f.db).await;
            assert_eq!(
                body_receipt(
                    undo_body_from_artifact(&f.db, &caller, &undo)
                        .await
                        .unwrap()
                ),
                inverse
            );
            assert_eq!(body_durable_state(&f.db).await, after_undo);
            body_refused(
                undo_body_from_artifact(
                    &f.db,
                    &caller,
                    &body_undo(&f, "body:save", "body:other-undo"),
                )
                .await,
            );
            body_refused(
                undo_body_from_artifact(
                    &f.db,
                    &caller,
                    &body_undo(&f, "body:undo", "body:undo-of-undo"),
                )
                .await,
            );
            assert_eq!(body_durable_state(&f.db).await, after_undo);
        }
    }

    #[tokio::test]
    async fn body_kernel_replay_skips_dynamic_binding_but_checks_static_and_output_view() {
        let f =
            body_kernel_fixture(body_kernel_declaration(), "agent.body-replay", Some("base")).await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let plan = body_plan(&f, "next", Some("base"), "body:save");
        let original = body_receipt(
            save_body_from_artifact(&f.db, &caller, plan.clone())
                .await
                .unwrap(),
        );
        f.registry.call(f.db.clone(), Caller::local(), "update_record",
            json!({"id":KERNEL_BEARER,"body_set":"later","if_body_digest":body_digest(Some("next")),"reason":"actual later edit"})).await.unwrap();
        sqlx::query("DELETE FROM artifact_inputs WHERE artifact_id=?")
            .bind(KERNEL_ARTIFACT)
            .execute(f.db.write_pool())
            .await
            .unwrap();
        let before = body_durable_state(&f.db).await;
        assert_eq!(
            body_receipt(
                save_body_from_artifact(&f.db, &caller, plan.clone())
                    .await
                    .unwrap()
            ),
            original
        );
        let new_plan = body_plan(&f, "new", Some("later"), "body:new");
        body_refused(save_body_from_artifact(&f.db, &caller, new_plan).await);
        let mut wrong = plan.clone();
        wrong
            .invocation
            .values
            .insert("body".into(), json!("different"));
        body_refused(save_body_from_artifact(&f.db, &caller, wrong).await);
        let mut stale = plan.clone();
        stale
            .invocation
            .alpha_install_guard
            .as_mut()
            .unwrap()
            .expected_install_event_id = "stale".into();
        body_refused(save_body_from_artifact(&f.db, &caller, stale).await);
        assert_eq!(body_durable_state(&f.db).await, before);
        crate::authorization::replace_explicit_policy(
            &f.db,
            "test:revoke",
            KERNEL_BEARER,
            vec![AllowEntry::account("other", Capability::View)],
        )
        .await
        .unwrap();
        let revoked = body_durable_state(&f.db).await;
        body_refused(save_body_from_artifact(&f.db, &caller, plan).await);
        assert_eq!(body_durable_state(&f.db).await, revoked);
    }

    #[tokio::test]
    async fn body_kernel_undo_original_pins_survive_uninstall_and_replay_later_edit() {
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-uninstall",
            Some("base"),
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let plan = body_plan(&f, "next", Some("base"), "body:save");
        body_receipt(
            save_body_from_artifact(&f.db, &caller, plan.clone())
                .await
                .unwrap(),
        );
        f.registry.call(f.db.clone(),caller.clone(),"manage_alpha_tabs",
            json!({"action":"remove","package":f.guard.package,"expected_install_event_id":f.guard.expected_install_event_id,"reason":"remove test install"})).await.unwrap();
        body_refused(save_body_from_artifact(&f.db, &caller, plan).await);
        let undo = body_undo(&f, "body:save", "body:undo");
        let original = body_receipt(
            undo_body_from_artifact(&f.db, &caller, &undo)
                .await
                .unwrap(),
        );
        f.registry.call(f.db.clone(),Caller::local(),"update_record",
            json!({"id":KERNEL_BEARER,"body_set":"later","if_body_digest":body_digest(Some("base")),"reason":"later after undo"})).await.unwrap();
        let before = body_durable_state(&f.db).await;
        assert_eq!(
            body_receipt(
                undo_body_from_artifact(&f.db, &caller, &undo)
                    .await
                    .unwrap()
            ),
            original
        );
        assert_eq!(body_durable_state(&f.db).await, before);
        let mut wrong = undo.clone();
        wrong.source_digest = "a".repeat(64);
        body_refused(undo_body_from_artifact(&f.db, &caller, &wrong).await);
        assert_eq!(body_durable_state(&f.db).await, before);
    }

    #[tokio::test]
    async fn body_kernel_any_later_metadata_or_equal_body_event_blocks_new_undo() {
        // Pure equal-body writes can be deduplicated by the ordinary writer.
        // A metadata write carrying the identical body creates a real later
        // record event; its unchanged body must not exempt Undo's rec CAS.
        for update in [
            json!({"name":"metadata changed"}),
            json!({"name":"equal body event","body_set":"next","if_body_digest":body_digest(Some("next"))}),
            json!({"name":"outgoing link event","links":[{"target_id":KERNEL_ARTIFACT,"relationship":"relates_to"}]}),
        ] {
            let f = body_kernel_fixture(
                body_kernel_declaration(),
                "agent.body-any-event",
                Some("base"),
            )
            .await;
            let caller = Caller::authenticated(KERNEL_ACCOUNT);
            body_receipt(
                save_body_from_artifact(
                    &f.db,
                    &caller,
                    body_plan(&f, "next", Some("base"), "body:save"),
                )
                .await
                .unwrap(),
            );
            let mut args = update;
            args["id"] = json!(KERNEL_BEARER);
            args["reason"] = json!("any later event");
            f.registry
                .call(f.db.clone(), Caller::local(), "update_record", args)
                .await
                .unwrap();
            let before = body_durable_state(&f.db).await;
            body_refused(
                undo_body_from_artifact(&f.db, &caller, &body_undo(&f, "body:save", "body:undo"))
                    .await,
            );
            assert_eq!(body_durable_state(&f.db).await, before);
        }
    }

    // Test-only trusted ingress: issue a real action-scoped token for the
    // exact invocation. No token/client gesture is ever stored in an origin.
    fn body_audit_caller(
        invocation: &native_artifact_runtime::artifact_intents::ArtifactInvocation,
        kind: crate::awareness::EffectGestureKind,
        undo: bool,
    ) -> Caller {
        let issuer = crate::awareness::HumanInteractionTokenIssuer::random("body-audit-test");
        let action = if undo {
            crate::awareness::EFFECT_GESTURE_REVERSAL_ACTION
        } else {
            crate::awareness::EFFECT_GESTURE_ACTION
        };
        let package = if undo {
            None
        } else {
            invocation
                .alpha_install_guard
                .as_ref()
                .map(|g| ("alpha", g.package.as_str()))
        };
        let generation = if undo {
            None
        } else {
            invocation
                .alpha_install_guard
                .as_ref()
                .map(|g| g.expected_install_event_id.as_str())
        };
        let entry = invocation
            .reverses
            .as_ref()
            .map(|r| r.entry_id.as_str())
            .unwrap_or(&invocation.entry_id);
        let ids = crate::awareness::effect_gesture_binding_ids(
            KERNEL_ACCOUNT,
            &invocation.artifact_id,
            package,
            generation,
            entry,
            &[KERNEL_BEARER.into()],
            &invocation.idempotency_key,
            &crate::mcp::tools::artifact_interactions::invocation_values_digest(invocation),
            kind,
        );
        let token = issuer.issue(KERNEL_ACCOUNT, action, &ids, 300).unwrap();
        Caller::authenticated(KERNEL_ACCOUNT)
            .with_effect_gesture_token(&issuer, token, kind)
            .with_effect_gesture_enforcement(true)
    }

    async fn body_audit_payload(db: &Db, key: &str) -> Value {
        let text: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND json_extract(payload,'$.origin.idempotency_key')=? ORDER BY seq DESC LIMIT 1")
            .bind(KERNEL_BEARER).bind(key).fetch_one(db.pool()).await.unwrap();
        serde_json::from_str(&text).unwrap()
    }

    // ONE issued token: matching and rewrapped callers differ only in the
    // attached kind. Issuing another token would not exercise this regression.
    fn body_audit_same_token_callers(
        invocation: &native_artifact_runtime::artifact_intents::ArtifactInvocation,
        minted_kind: crate::awareness::EffectGestureKind,
        attached_kind: crate::awareness::EffectGestureKind,
        undo: bool,
    ) -> (Caller, Caller) {
        let issuer =
            crate::awareness::HumanInteractionTokenIssuer::random("body-audit-rewrap-test");
        let action = if undo {
            crate::awareness::EFFECT_GESTURE_REVERSAL_ACTION
        } else {
            crate::awareness::EFFECT_GESTURE_ACTION
        };
        let package = if undo {
            None
        } else {
            invocation
                .alpha_install_guard
                .as_ref()
                .map(|g| ("alpha", g.package.as_str()))
        };
        let generation = if undo {
            None
        } else {
            invocation
                .alpha_install_guard
                .as_ref()
                .map(|g| g.expected_install_event_id.as_str())
        };
        let entry = invocation
            .reverses
            .as_ref()
            .map(|r| r.entry_id.as_str())
            .unwrap_or(&invocation.entry_id);
        let ids = crate::awareness::effect_gesture_binding_ids(
            KERNEL_ACCOUNT,
            &invocation.artifact_id,
            package,
            generation,
            entry,
            &[KERNEL_BEARER.into()],
            &invocation.idempotency_key,
            &crate::mcp::tools::artifact_interactions::invocation_values_digest(invocation),
            minted_kind,
        );
        let token = issuer.issue(KERNEL_ACCOUNT, action, &ids, 300).unwrap();
        let matching = Caller::authenticated(KERNEL_ACCOUNT)
            .with_effect_gesture_token(&issuer, token.clone(), minted_kind)
            .with_effect_gesture_enforcement(true);
        let rewrapped = Caller::authenticated(KERNEL_ACCOUNT)
            .with_effect_gesture_token(&issuer, token, attached_kind)
            .with_effect_gesture_enforcement(true);
        (matching, rewrapped)
    }

    #[tokio::test]
    async fn body_audit_same_token_different_attached_kind_refuses_save_undo_and_replay() {
        use crate::awareness::EffectGestureKind::{Click, Drop};
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-audit-rewrap",
            Some("base"),
        )
        .await;
        let plan = body_plan(&f, "next", Some("base"), "audit:rewrap-save");
        let (matching, rewrapped) =
            body_audit_same_token_callers(&plan.invocation, Click, Drop, false);
        let before = body_durable_state(&f.db).await;
        body_refused(save_body_from_artifact(&f.db, &rewrapped, plan.clone()).await);
        assert_eq!(body_durable_state(&f.db).await, before);
        let save_receipt = body_receipt(
            save_body_from_artifact(&f.db, &matching, plan.clone())
                .await
                .unwrap(),
        );
        let original = body_audit_payload(&f.db, "audit:rewrap-save").await;
        assert_eq!(
            original["origin"]["gesture_evidence"],
            json!({"kind":"click","verifier":"effect_gesture.v1"})
        );
        let saved_state = body_durable_state(&f.db).await;
        body_refused(save_body_from_artifact(&f.db, &rewrapped, plan.clone()).await);
        assert_eq!(body_durable_state(&f.db).await, saved_state);
        assert_eq!(
            body_audit_payload(&f.db, "audit:rewrap-save").await,
            original
        );
        assert_eq!(
            body_receipt(
                save_body_from_artifact(&f.db, &matching, plan)
                    .await
                    .unwrap()
            ),
            save_receipt
        );
        assert_eq!(body_durable_state(&f.db).await, saved_state);
        assert_eq!(
            body_audit_payload(&f.db, "audit:rewrap-save").await,
            original
        );

        let invocation = body_undo(&f, "audit:rewrap-save", "audit:rewrap-undo");
        let (matching_undo, rewrapped_undo) =
            body_audit_same_token_callers(&invocation, Click, Drop, true);
        body_refused(undo_body_from_artifact(&f.db, &rewrapped_undo, &invocation).await);
        assert_eq!(body_durable_state(&f.db).await, saved_state);
        assert_eq!(
            body_audit_payload(&f.db, "audit:rewrap-save").await,
            original
        );
        let undo_receipt = body_receipt(
            undo_body_from_artifact(&f.db, &matching_undo, &invocation)
                .await
                .unwrap(),
        );
        let undone = body_audit_payload(&f.db, "audit:rewrap-undo").await;
        assert_eq!(
            undone["origin"]["gesture_evidence"],
            json!({"kind":"click","verifier":"effect_gesture.v1"})
        );
        assert_eq!(undone["body"], json!("base"));
        let undone_state = body_durable_state(&f.db).await;
        body_refused(undo_body_from_artifact(&f.db, &rewrapped_undo, &invocation).await);
        assert_eq!(body_durable_state(&f.db).await, undone_state);
        assert_eq!(
            body_audit_payload(&f.db, "audit:rewrap-save").await,
            original
        );
        assert_eq!(body_audit_payload(&f.db, "audit:rewrap-undo").await, undone);
        assert_eq!(
            body_receipt(
                undo_body_from_artifact(&f.db, &matching_undo, &invocation)
                    .await
                    .unwrap()
            ),
            undo_receipt
        );
        assert_eq!(body_durable_state(&f.db).await, undone_state);
        assert_eq!(
            body_audit_payload(&f.db, "audit:rewrap-save").await,
            original
        );
        assert_eq!(body_audit_payload(&f.db, "audit:rewrap-undo").await, undone);
    }

    #[tokio::test]
    async fn body_audit_enforced_tokens_bind_actual_forward_and_never_client_gesture() {
        use crate::awareness::EffectGestureKind::{Click, Drop, Grant, Key};
        for kind in [Click, Drop, Key, Grant] {
            let f = body_kernel_fixture(
                body_kernel_declaration(),
                "agent.body-audit-forward",
                Some("base"),
            )
            .await;
            let mut plan = body_plan(&f, "next", Some("base"), "audit:save");
            plan.invocation.gesture = Some("untrusted-client-text".into());
            let caller = body_audit_caller(&plan.invocation, kind, false);
            let before = body_durable_state(&f.db).await;
            body_refused(
                save_body_from_artifact(
                    &f.db,
                    &Caller::authenticated(KERNEL_ACCOUNT).with_effect_gesture_enforcement(true),
                    plan.clone(),
                )
                .await,
            );
            assert_eq!(body_durable_state(&f.db).await, before);
            let bad_issuer =
                crate::awareness::HumanInteractionTokenIssuer::random("invalid-audit-test");
            let invalid = Caller::authenticated(KERNEL_ACCOUNT)
                .with_effect_gesture_token(&bad_issuer, "not-a-token", kind)
                .with_effect_gesture_enforcement(true);
            body_refused(save_body_from_artifact(&f.db, &invalid, plan.clone()).await);
            assert_eq!(body_durable_state(&f.db).await, before);
            for changed in 0..6 {
                let mut swapped = plan.clone();
                match changed {
                    0 => {
                        swapped.invocation.idempotency_key = "other-key".into();
                    }
                    1 => {
                        swapped
                            .invocation
                            .values
                            .insert("body".into(), json!("other"));
                    }
                    2 => {
                        swapped
                            .invocation
                            .slots
                            .insert("page".into(), KERNEL_ARTIFACT.into());
                    }
                    3 => {
                        swapped.invocation.artifact_id = KERNEL_BEARER.into();
                    }
                    4 => {
                        swapped
                            .invocation
                            .alpha_install_guard
                            .as_mut()
                            .unwrap()
                            .expected_install_event_id = Uuid::new_v4().to_string();
                    }
                    _ => {
                        swapped
                            .invocation
                            .alpha_install_guard
                            .as_mut()
                            .unwrap()
                            .package = "other-package".into();
                    }
                }
                body_refused(save_body_from_artifact(&f.db, &caller, swapped).await);
                assert_eq!(body_durable_state(&f.db).await, before);
            }
            // Valid token with the WRONG action still cannot authorize Save.
            body_refused(
                save_body_from_artifact(
                    &f.db,
                    &body_audit_caller(&plan.invocation, kind, true),
                    plan.clone(),
                )
                .await,
            );
            assert_eq!(body_durable_state(&f.db).await, before);
            body_receipt(save_body_from_artifact(&f.db, &caller, plan).await.unwrap());
            let payload = body_audit_payload(&f.db, "audit:save").await;
            assert_eq!(
                payload["origin"]["gesture_evidence"],
                json!({"kind":kind.as_str(),"verifier":"effect_gesture.v1"})
            );
            assert!(!payload["origin"]
                .to_string()
                .contains("untrusted-client-text"));
            assert!(payload["origin"]["gesture_evidence"].get("token").is_none());
        }
        let f =
            body_kernel_fixture(body_kernel_declaration(), "agent.body-audit-absent", None).await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        body_receipt(
            save_body_from_artifact(&f.db, &caller, body_plan(&f, "next", None, "audit:legacy"))
                .await
                .unwrap(),
        );
        assert!(body_audit_payload(&f.db, "audit:legacy").await["origin"]
            .get("gesture_evidence")
            .is_none());
    }

    #[tokio::test]
    async fn body_audit_first_replay_preserved_and_undo_has_own_reversal_kind() {
        use crate::awareness::EffectGestureKind::{Click, Drop, Key};
        for (save_kind, undo_kind) in [(Click, Key), (Drop, Click)] {
            for initial in [None, Some("{\"literal\":true}\r\n")] {
                let f = body_kernel_fixture(
                    body_kernel_declaration(),
                    "agent.body-audit-undo",
                    initial,
                )
                .await;
                let plan = body_plan(&f, "next", initial, "audit:save");
                let receipt = body_receipt(
                    save_body_from_artifact(
                        &f.db,
                        &body_audit_caller(&plan.invocation, save_kind, false),
                        plan.clone(),
                    )
                    .await
                    .unwrap(),
                );
                let original = body_audit_payload(&f.db, "audit:save").await;
                let before = body_durable_state(&f.db).await;
                assert_eq!(
                    body_receipt(
                        save_body_from_artifact(
                            &f.db,
                            &body_audit_caller(&plan.invocation, Key, false),
                            plan
                        )
                        .await
                        .unwrap()
                    ),
                    receipt
                );
                assert_eq!(body_durable_state(&f.db).await, before);
                assert_eq!(body_audit_payload(&f.db, "audit:save").await, original);
                let invocation = body_undo(&f, "audit:save", "audit:undo");
                body_refused(
                    undo_body_from_artifact(
                        &f.db,
                        &body_audit_caller(&invocation, undo_kind, false),
                        &invocation,
                    )
                    .await,
                );
                assert_eq!(body_durable_state(&f.db).await, before);
                let undo_receipt = body_receipt(
                    undo_body_from_artifact(
                        &f.db,
                        &body_audit_caller(&invocation, undo_kind, true),
                        &invocation,
                    )
                    .await
                    .unwrap(),
                );
                let undone = body_audit_payload(&f.db, "audit:undo").await;
                assert_eq!(undone["body"], initial.map_or(Value::Null, |s| json!(s)));
                assert_eq!(
                    undone["origin"]["gesture_evidence"],
                    json!({"kind":undo_kind.as_str(),"verifier":"effect_gesture.v1"})
                );
                assert_eq!(
                    original["origin"]["gesture_evidence"],
                    json!({"kind":save_kind.as_str(),"verifier":"effect_gesture.v1"})
                );
                assert_eq!(body_audit_payload(&f.db, "audit:save").await, original);
                let before_replay = body_durable_state(&f.db).await;
                assert_eq!(
                    body_receipt(
                        undo_body_from_artifact(
                            &f.db,
                            &body_audit_caller(&invocation, Drop, true),
                            &invocation
                        )
                        .await
                        .unwrap()
                    ),
                    undo_receipt
                );
                assert_eq!(body_audit_payload(&f.db, "audit:undo").await, undone);
                assert_eq!(body_durable_state(&f.db).await, before_replay);
                let alternate = body_undo(&f, "audit:save", "audit:alternate");
                body_refused(
                    undo_body_from_artifact(
                        &f.db,
                        &body_audit_caller(&alternate, Click, true),
                        &alternate,
                    )
                    .await,
                );
                assert_eq!(body_durable_state(&f.db).await, before_replay);
            }
        }
    }

    #[tokio::test]
    async fn body_audit_valid_renewed_token_replay_still_requires_output_view() {
        use crate::awareness::EffectGestureKind::{Click, Drop};
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-audit-view",
            Some("base"),
        )
        .await;
        let plan = body_plan(&f, "next", Some("base"), "audit:save");
        body_receipt(
            save_body_from_artifact(
                &f.db,
                &body_audit_caller(&plan.invocation, Click, false),
                plan.clone(),
            )
            .await
            .unwrap(),
        );
        let original = body_audit_payload(&f.db, "audit:save").await;
        crate::authorization::replace_explicit_policy(
            &f.db,
            "test:audit-view-revoke",
            KERNEL_BEARER,
            vec![AllowEntry::account("other", Capability::View)],
        )
        .await
        .unwrap();
        let before = body_durable_state(&f.db).await;
        body_refused(
            save_body_from_artifact(
                &f.db,
                &body_audit_caller(&plan.invocation, Drop, false),
                plan,
            )
            .await,
        );
        assert_eq!(body_durable_state(&f.db).await, before);
        assert_eq!(body_audit_payload(&f.db, "audit:save").await, original);
    }

    #[tokio::test]
    async fn body_audit_legacy_undo_and_audited_postappend_failure_keep_durable_state() {
        use crate::awareness::EffectGestureKind::{Click, Key};
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-audit-rollback",
            Some("base"),
        )
        .await;
        let plan = body_plan(&f, "next", Some("base"), "audit:save");
        let caller = body_audit_caller(&plan.invocation, Click, false);
        let before = body_durable_state(&f.db).await;
        let error = body_effect_preparation::save_body_with_postappend_failure(
            &f.db,
            &caller,
            plan.clone(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, Error::Conflict(_)));
        assert_eq!(body_durable_state(&f.db).await, before);
        let original_receipt = body_receipt(
            save_body_from_artifact(&f.db, &Caller::authenticated(KERNEL_ACCOUNT), plan.clone())
                .await
                .unwrap(),
        );
        let unaudited = body_audit_payload(&f.db, "audit:save").await;
        assert!(unaudited["origin"].get("gesture_evidence").is_none());
        let state = body_durable_state(&f.db).await;
        assert_eq!(
            body_receipt(save_body_from_artifact(&f.db, &caller, plan).await.unwrap()),
            original_receipt
        );
        assert_eq!(body_durable_state(&f.db).await, state);
        assert_eq!(body_audit_payload(&f.db, "audit:save").await, unaudited);
        let invocation = body_undo(&f, "audit:save", "audit:undo");
        body_receipt(
            undo_body_from_artifact(
                &f.db,
                &body_audit_caller(&invocation, Key, true),
                &invocation,
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            body_audit_payload(&f.db, "audit:undo").await["origin"]["gesture_evidence"]["kind"],
            json!("key")
        );
        assert_eq!(body_audit_payload(&f.db, "audit:save").await, unaudited);
    }

    #[tokio::test]
    async fn body_kernel_real_postappend_failure_rolls_back_projection_events_and_act() {
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-rollback",
            Some("base"),
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let plan = body_plan(&f, "next", Some("base"), "body:save");
        let before = body_durable_state(&f.db).await;
        let error = body_effect_preparation::save_body_with_postappend_failure(
            &f.db,
            &caller,
            plan.clone(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, Error::Conflict(_)));
        assert_eq!(body_durable_state(&f.db).await, before);
        // Same immutable request is still absent, and can now commit once.
        body_receipt(save_body_from_artifact(&f.db, &caller, plan).await.unwrap());
        assert_eq!(body_durable_state(&f.db).await.0, before.0 + 1);
    }

    #[tokio::test]
    async fn body_kernel_full_shape_refuses_missing_or_altered_protection_before_replay() {
        for ddl in ["DROP TRIGGER content_events_no_delete",
            "DROP TRIGGER content_events_no_delete; CREATE TRIGGER content_events_no_delete BEFORE DELETE ON content_events BEGIN SELECT 1; END"] {
            let f = body_kernel_fixture(body_kernel_declaration(),"agent.body-shape",Some("base")).await;
            let caller = Caller::authenticated(KERNEL_ACCOUNT);
            let plan = body_plan(&f,"next",Some("base"),"body:save");
            body_receipt(save_body_from_artifact(&f.db,&caller,plan.clone()).await.unwrap());
            sqlx::raw_sql(ddl).execute(f.db.write_pool()).await.unwrap();
            let before = body_durable_state(&f.db).await;
            body_refused(save_body_from_artifact(&f.db,&caller,plan).await);
            body_refused(undo_body_from_artifact(&f.db,&caller,&body_undo(&f,"body:save","body:undo")).await);
            assert_eq!(body_durable_state(&f.db).await,before);
        }
    }

    #[tokio::test]
    async fn body_kernel_new_instruction_source_refuses_inverse_without_target_event() {
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-instruction",
            Some("base"),
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        body_receipt(
            save_body_from_artifact(
                &f.db,
                &caller,
                body_plan(&f, "next", Some("base"), "body:save"),
            )
            .await
            .unwrap(),
        );
        let forward: i64 =
            sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
                .bind(KERNEL_BEARER)
                .fetch_one(f.db.pool())
                .await
                .unwrap();
        f.registry.call(f.db.clone(),caller.clone(),"manage_instructions",
            json!({"action":"create_binding","scope":"member","source_record_id":KERNEL_BEARER,"position":0,
                "enabled":true,"idempotency_key":"body:instruction-binding","reason":"new ordinary exclusion"})).await.unwrap();
        let latest: i64 =
            sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
                .bind(KERNEL_BEARER)
                .fetch_one(f.db.pool())
                .await
                .unwrap();
        assert_eq!(latest, forward); // Refusal must come from current eligibility, not rec CAS.
        let before = body_durable_state(&f.db).await;
        body_refused(
            undo_body_from_artifact(&f.db, &caller, &body_undo(&f, "body:save", "body:undo")).await,
        );
        assert_eq!(body_durable_state(&f.db).await, before);
    }

    #[tokio::test]
    async fn body_kernel_real_encoded_forward_inverse_caps_and_literal_refusals() {
        for body in ["x".repeat(32769), "🦀".repeat(8193)] {
            let f = body_kernel_fixture(
                body_kernel_declaration(),
                "agent.body-encoding",
                Some("base"),
            )
            .await;
            let caller = Caller::authenticated(KERNEL_ACCOUNT);
            let before = body_durable_state(&f.db).await;
            body_refused(
                save_body_from_artifact(
                    &f.db,
                    &caller,
                    body_plan(&f, &body, Some("base"), "body:save"),
                )
                .await,
            );
            assert_eq!(body_durable_state(&f.db).await, before);
        }
        let inverse = "x".repeat(native_artifact_runtime::mdx_v2::BODY_SET_MAX_BODY_BYTES + 1);
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-inverse-encoding",
            Some(&inverse),
        )
        .await;
        let before = body_durable_state(&f.db).await;
        body_refused(
            save_body_from_artifact(
                &f.db,
                &Caller::authenticated(KERNEL_ACCOUNT),
                body_plan(&f, "next", Some(&inverse), "body:save"),
            )
            .await,
        );
        assert_eq!(body_durable_state(&f.db).await, before);
        let escaped = "\u{1}".repeat(32768);
        let f = body_kernel_fixture(
            body_kernel_declaration(),
            "agent.body-real-expansion",
            Some("base"),
        )
        .await;
        let receipt = body_receipt(
            save_body_from_artifact(
                &f.db,
                &Caller::authenticated(KERNEL_ACCOUNT),
                body_plan(&f, &escaped, Some("base"), "body:escaped"),
            )
            .await
            .unwrap(),
        );
        let payload: String = sqlx::query_scalar(
            "SELECT payload FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(KERNEL_BEARER)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
        assert!(payload.len() > escaped.len() * 5);
        assert_eq!(receipt["changes"][0]["after"]["utf8_bytes"], 32768);
        assert!(serde_json::to_vec(&receipt).unwrap().len() < 4096);
    }

    #[tokio::test]
    async fn body_kernel_direct_shapes_gesture_and_actor_cannot_bypass() {
        let f =
            body_kernel_fixture(body_kernel_declaration(), "agent.body-shapes", Some("base")).await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let plan = body_plan(&f, "next", Some("base"), "body:save");
        let before = body_durable_state(&f.db).await;
        let mut extra = plan.clone();
        extra
            .invocation
            .values
            .insert("gesture".into(), json!("forged"));
        body_refused(save_body_from_artifact(&f.db, &caller, extra).await);
        let mut observed = plan.clone();
        observed
            .invocation
            .observed
            .insert(KERNEL_BEARER.into(), BTreeMap::new());
        body_refused(save_body_from_artifact(&f.db, &caller, observed).await);
        let mut target = plan.clone();
        target
            .invocation
            .slots
            .insert("page".into(), "native:root".into());
        body_refused(save_body_from_artifact(&f.db, &caller, target).await);
        body_refused(
            save_body_from_artifact(
                &f.db,
                &caller.clone().with_effect_gesture_enforcement(true),
                plan.clone(),
            )
            .await,
        );
        body_refused(save_body_from_artifact(&f.db, &Caller::authenticated("other"), plan).await);
        assert_eq!(body_durable_state(&f.db).await, before);
    }

    #[tokio::test]
    async fn body_kernel_revoked_edit_skips_replay_but_refuses_new_write() {
        let f =
            body_kernel_fixture(body_kernel_declaration(), "agent.body-edit", Some("base")).await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let plan = body_plan(&f, "next", Some("base"), "body:save");
        let original = body_receipt(
            save_body_from_artifact(&f.db, &caller, plan.clone())
                .await
                .unwrap(),
        );
        crate::authorization::replace_explicit_policy(
            &f.db,
            "test:edit-revoke",
            KERNEL_BEARER,
            vec![AllowEntry::account(KERNEL_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        let before = body_durable_state(&f.db).await;
        assert_eq!(
            body_receipt(save_body_from_artifact(&f.db, &caller, plan).await.unwrap()),
            original
        );
        body_refused(
            save_body_from_artifact(
                &f.db,
                &caller,
                body_plan(&f, "new", Some("next"), "body:new"),
            )
            .await,
        );
        assert_eq!(body_durable_state(&f.db).await, before);
    }

    #[tokio::test]
    async fn body_kernel_malformed_duplicates_ambiguity_and_generic_reversal_refuse() {
        let f = body_kernel_fixture(body_kernel_declaration(), "agent.body-malformed", None).await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        body_receipt(
            save_body_from_artifact(&f.db, &caller, body_plan(&f, "next", None, "body:save"))
                .await
                .unwrap(),
        );
        let saved: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='record.updated' ORDER BY seq DESC LIMIT 1")
            .bind(KERNEL_BEARER).fetch_one(f.db.pool()).await.unwrap();
        for (key, mutate) in [
            ("body:bad-null", 0),
            ("body:bad-duplicate", 1),
            ("body:bad-truncated", 2),
        ] {
            let mut value: Value = serde_json::from_str(&saved).unwrap();
            value["origin"]["idempotency_key"] = json!(key);
            if mutate == 0 {
                value["origin"]["before"]["gesture"] = json!("not admitted");
            }
            let mut payload = value.to_string();
            if mutate == 1 {
                payload = payload.replace(r#""kind":"null""#, r#""kind":"null","kind":"null""#);
            }
            if mutate == 2 {
                value["untrusted_padding"] = json!("x".repeat(262144));
                payload = value.to_string();
            }
            // INSERT-only legacy/corruption fixture, never a projected write.
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,'record.updated',?,?,?,1,'legacy_unknown')")
                .bind(Uuid::new_v4().to_string()).bind(KERNEL_BEARER).bind(payload)
                .bind(caller.actor()).bind("2026-10-03T00:00:00Z").execute(f.db.write_pool()).await.unwrap();
            let before = body_durable_state(&f.db).await;
            body_refused(
                save_body_from_artifact(&f.db, &caller, body_plan(&f, "next", Some("next"), key))
                    .await,
            );
            body_refused(
                undo_body_from_artifact(&f.db, &caller, &body_undo(&f, key, "body:bad-undo")).await,
            );
            assert_eq!(body_durable_state(&f.db).await, before);
        }
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,'record.updated',?,?,?,1,'legacy_unknown')")
            .bind(Uuid::new_v4().to_string()).bind(KERNEL_BEARER).bind(saved)
            .bind(caller.actor()).bind("2026-10-03T00:00:00Z").execute(f.db.write_pool()).await.unwrap();
        let before = body_durable_state(&f.db).await;
        body_refused(
            save_body_from_artifact(&f.db, &caller, body_plan(&f, "next", None, "body:save")).await,
        );
        body_refused(
            undo_body_from_artifact(&f.db, &caller, &body_undo(&f, "body:save", "body:undo")).await,
        );
        let generic = super::super::artifact_reversal::revert_in(
            &f.db,
            &caller,
            super::super::artifact_reversal::ReversalRequest {
                artifact_id: KERNEL_ARTIFACT.into(),
                record_id: KERNEL_BEARER.into(),
                entry_id: "save".into(),
                original_key: "body:save".into(),
                idempotency_key: "body:generic".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            serde_json::to_value(generic).unwrap()["error"]["code"],
            "body_unavailable"
        );
        assert_eq!(body_durable_state(&f.db).await, before);
    }

    // Genuine kernel-generated templates are rolled back, then inserted as
    // labelled corruption rows without changing protected events/projection.
    async fn insert_body_corruption(f: &KernelFixture, caller: &Caller, id: &str, payload: &Value) {
        let text = payload.to_string();
        body_effect_preparation::validate_closed_body_candidate(&text, KERNEL_BEARER).unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,'record.updated',?,?,?,1,'legacy_unknown')")
            .bind(id).bind(KERNEL_BEARER).bind(text).bind(caller.actor()).bind("2026-10-03T00:00:00Z")
            .execute(f.db.write_pool()).await.unwrap();
    }

    fn body_semantic_conflict(result: Result<ArtifactBodyOutcome>) {
        let Ok(ArtifactBodyOutcome::Refused { code, .. }) = result else {
            panic!("expected confirmed semantic refusal: {result:?}");
        };
        assert_eq!(code, "idempotency_conflict");
    }

    #[tokio::test]
    async fn body_kernel_closed_save_fields_and_original_digest_corruption_refuse() {
        for mutation in 0..3 {
            let f = body_kernel_fixture(
                body_kernel_declaration(),
                "agent.body-save-corruption",
                None,
            )
            .await;
            let caller = Caller::authenticated(KERNEL_ACCOUNT);
            let plan = body_plan(&f, "next", None, "body:save");
            let before_template = body_durable_state(&f.db).await;
            let (text, id, _) =
                body_effect_preparation::body_payload_without_commit(&f.db, &caller, &plan)
                    .await
                    .unwrap();
            assert_eq!(body_durable_state(&f.db).await, before_template);
            let mut payload: Value = serde_json::from_str(&text).unwrap();
            let original_digest = payload["origin"]["semantic_digest"].clone();
            match mutation {
                0 => {
                    payload["body"] = json!("tampered");
                    payload["origin"]["after"] = json!({"kind":"text","sha256":body_digest(Some("tampered")),"utf8_bytes":8});
                }
                1 => {
                    payload["origin"]["expected_body_digest"] =
                        json!(body_digest(Some("wrong opening")));
                }
                _ => {
                    payload["origin"]["semantic_digest"] = json!("a".repeat(64));
                }
            }
            if mutation < 2 {
                assert_eq!(payload["origin"]["semantic_digest"], original_digest);
            }
            insert_body_corruption(&f, &caller, &id, &payload).await;
            let before = body_durable_state(&f.db).await;
            body_semantic_conflict(save_body_from_artifact(&f.db, &caller, plan).await);
            // Undo must reconstruct original Save identity BEFORE relying on
            // that original's digest or attempting inverse/history/CAS.
            body_semantic_conflict(
                undo_body_from_artifact(&f.db, &caller, &body_undo(&f, "body:save", "body:undo"))
                    .await,
            );
            assert_eq!(body_durable_state(&f.db).await, before);
        }
    }

    #[tokio::test]
    async fn body_kernel_closed_undo_references_and_nullable_summaries_corruption_refuse() {
        for initial in [None, Some("")] {
            for mutation in 0..6 {
                let f = body_kernel_fixture(
                    body_kernel_declaration(),
                    "agent.body-undo-corruption",
                    initial,
                )
                .await;
                let caller = Caller::authenticated(KERNEL_ACCOUNT);
                body_receipt(
                    save_body_from_artifact(
                        &f.db,
                        &caller,
                        body_plan(&f, "next", initial, "body:save"),
                    )
                    .await
                    .unwrap(),
                );
                let undo = body_undo(&f, "body:save", "body:undo");
                let template_plan = ArtifactBodySavePlan {
                    invocation: undo.clone(),
                    source_event_id: f.guard.source_revision.clone(),
                };
                let before_template = body_durable_state(&f.db).await;
                let (text, id, _) = body_effect_preparation::body_payload_without_commit(
                    &f.db,
                    &caller,
                    &template_plan,
                )
                .await
                .unwrap();
                assert_eq!(body_durable_state(&f.db).await, before_template);
                let mut payload: Value = serde_json::from_str(&text).unwrap();
                let original_digest = payload["origin"]["semantic_digest"].clone();
                match mutation {
                    0 => {
                        payload["origin"]["reverses"]["event_id"] =
                            json!(Uuid::new_v4().to_string());
                    }
                    1 => {
                        let seq = payload["origin"]["reverses"]["seq"].as_i64().unwrap();
                        payload["origin"]["reverses"]["seq"] = json!(seq + 1);
                    }
                    2 => {
                        payload["origin"]["reverses"]["entry_id"] = json!("other-entry");
                    }
                    3 => {
                        payload["origin"]["reverses"]["idempotency_key"] = json!("other-forward");
                    }
                    4 => {
                        // NULL and empty share the legacy digest but are
                        // different exact inverse values/closed summaries.
                        if initial.is_none() {
                            payload["body"] = json!("");
                            payload["origin"]["after"] = json!({"kind":"text","sha256":body_digest(Some("")),"utf8_bytes":0});
                        } else {
                            payload["body"] = Value::Null;
                            payload["origin"]["after"] = json!({"kind":"null"});
                        }
                    }
                    _ => {
                        payload["origin"]["before"] = json!({"kind":"text","sha256":body_digest(Some("not-next")),"utf8_bytes":8});
                    }
                }
                assert_eq!(payload["origin"]["semantic_digest"], original_digest);
                insert_body_corruption(&f, &caller, &id, &payload).await;
                let before = body_durable_state(&f.db).await;
                body_semantic_conflict(undo_body_from_artifact(&f.db, &caller, &undo).await);
                assert_eq!(body_durable_state(&f.db).await, before);
            }
        }
    }

    #[tokio::test]
    async fn body_kernel_both_duplicate_root_origin_orders_never_reach_legacy_name_reversal() {
        for body_first in [false, true] {
            let f = body_kernel_fixture(
                body_kernel_declaration(),
                "agent.body-root-duplicates",
                Some("base"),
            )
            .await;
            let caller = Caller::authenticated(KERNEL_ACCOUNT);
            // Actual ordinary title writer supplies a current legacy-restorable
            // name. The mixed corruption row is INSERT-only and unprojected.
            f.registry
                .call(
                    f.db.clone(),
                    Caller::local(),
                    "update_record",
                    json!({"id":KERNEL_BEARER,"name":"mixed title","reason":"legacy name fixture"}),
                )
                .await
                .unwrap();
            let plan = body_plan(&f, "next", Some("base"), "body:save");
            let before_template = body_durable_state(&f.db).await;
            let (text, id, _) =
                body_effect_preparation::body_payload_without_commit(&f.db, &caller, &plan)
                    .await
                    .unwrap();
            assert_eq!(body_durable_state(&f.db).await, before_template);
            body_effect_preparation::validate_closed_body_candidate(&text, KERNEL_BEARER).unwrap();
            let value: Value = serde_json::from_str(&text).unwrap();
            let body_origin = &value["origin"];
            // Same legacy title_origin_value shape/identity/guard at the
            // pinned source, without pretending a Title entry was admitted.
            let legacy_origin = json!({"kind":"artifact.interaction","effect":"title.set",
                "artifact_id":KERNEL_ARTIFACT,"entry_id":"save","source_digest":f.body_digest,
                "source_event_id":f.guard.source_revision,"idempotency_key":"body:save","record_id":KERNEL_BEARER,
                "title":"mixed title","before":"thread-target","gesture":"click","guard":f.guard});
            let (first, second) = if body_first {
                (body_origin, &legacy_origin)
            } else {
                (&legacy_origin, body_origin)
            };
            let payload = format!(
                r#"{{"body":{},"name":"mixed title","origin":{},"origin":{}}}"#,
                value["body"], first, second
            );
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,'record.updated',?,?,?,1,'legacy_unknown')")
                .bind(id).bind(KERNEL_BEARER).bind(payload).bind(caller.actor()).bind("2026-10-03T00:00:00Z")
                .execute(f.db.write_pool()).await.unwrap();
            let before = body_durable_state(&f.db).await;
            let guarded = super::super::artifact_reversal::revert_invocation_in(
                &f.db,
                &caller,
                &body_undo(&f, "body:save", "body:undo"),
            )
            .await
            .unwrap();
            let result = serde_json::to_value(guarded).unwrap();
            assert_eq!(result["status"], "rejected");
            assert_eq!(result["error"]["code"], "body_stored_json");
            let direct = super::super::artifact_reversal::revert_in(
                &f.db,
                &caller,
                super::super::artifact_reversal::ReversalRequest {
                    artifact_id: KERNEL_ARTIFACT.into(),
                    record_id: KERNEL_BEARER.into(),
                    entry_id: "save".into(),
                    original_key: "body:save".into(),
                    idempotency_key: "body:direct".into(),
                },
            )
            .await
            .unwrap();
            assert_eq!(
                serde_json::to_value(direct).unwrap()["error"]["code"],
                "body_unavailable"
            );
            assert_eq!(body_durable_state(&f.db).await, before);
            assert_eq!(
                sqlx::query_scalar::<_, String>("SELECT name FROM records WHERE id=?")
                    .bind(KERNEL_BEARER)
                    .fetch_one(f.db.pool())
                    .await
                    .unwrap(),
                "mixed title"
            );
        }
    }

    async fn comment_token_for(
        db: &crate::Db,
        target: &str,
        guard: &AlphaTabInstallGuard,
        body_digest: &str,
    ) -> String {
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let state =
            crate::mcp::tools::artifact_interactions::read_comment_parent_state_in(&mut tx, target)
                .await
                .unwrap()
                .expect("fixture bearer has state");
        let token = crate::mcp::tools::artifact_interactions::seal_comment_token(
            &crate::mcp::tools::artifact_interactions::CommentMintContext {
                caller_credential: KERNEL_ACCOUNT,
                artifact_id: KERNEL_ARTIFACT,
                source_event_id: &guard.source_revision,
                source_digest: body_digest,
            },
            target,
            &state,
        );
        tx.rollback().await.unwrap();
        token
    }

    #[allow(clippy::too_many_arguments)]
    fn comment_plan(
        installed: &KernelFixture,
        entry: InteractionEntry,
        target: &str,
        position: &str,
        body: &str,
        token: Option<String>,
        key: &str,
    ) -> ArtifactCommentPlan {
        ArtifactCommentPlan {
            artifact_id: KERNEL_ARTIFACT.to_string(),
            entry_id: "post".to_string(),
            entry,
            source_event_id: installed.guard.source_revision.clone(),
            source_digest: installed.body_digest.clone(),
            target_id: target.to_string(),
            position: position.to_string(),
            body: body.to_string(),
            manifest_max_bytes: 500,
            scope_port: "orders".to_string(),
            scope_collection_id: KERNEL_QUERY.to_string(),
            scope_kind: "query".to_string(),
            observed_token: token,
            idempotency_key: key.to_string(),
            gesture: Some("click".to_string()),
            guard: installed.guard.clone(),
            // The kernel resolves admission fresh; fixtures never
            // pre-resolve (no bypass).
            resolved_admission: None,
            gesture_evidence: None,
        }
    }

    async fn comment_count(db: &crate::Db) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM records WHERE type='Annotation' AND kind='comment' AND deleted_at IS NULL",
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    fn assert_whitelist_shape(receipt: &Value, retry: bool) {
        let object = receipt.as_object().expect("comment receipt is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = vec!["bearer_id", "comment_id", "position"];
        if retry {
            expected.push("idempotent_retry");
            expected.sort_unstable();
        }
        assert_eq!(keys, expected, "{receipt:#}");
        for forbidden in [
            "body",
            "version",
            "act",
            "refresh",
            "contribution",
            "enriched",
            "seq",
            "account",
        ] {
            assert!(
                object.get(forbidden).is_none(),
                "receipt leaks {forbidden}: {receipt:#}"
            );
        }
    }

    #[tokio::test]
    async fn comment_root_posts_through_canonical_kernel() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-a",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "hello thread",
            Some(token),
            "kernel:root:one",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Created(receipt) = outcome else {
            panic!("root must post: {outcome:?}");
        };
        assert_whitelist_shape(&receipt, false);
        assert_eq!(receipt["bearer_id"], KERNEL_BEARER);
        assert_eq!(receipt["position"], "root");
        let comment_id = receipt["comment_id"].as_str().unwrap().to_string();
        // The thread reads back through governed reads.
        let read = installed
            .registry
            .call(
                installed.db.clone(),
                caller,
                "get_record",
                json!({ "ids": [KERNEL_BEARER], "include_comments": true }),
            )
            .await
            .unwrap();
        let comments = read["records"][0]["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["id"], comment_id);
        assert_eq!(comments[0]["body"], "hello thread");
    }

    #[tokio::test]
    async fn comment_plan_pre_resolved_admission_is_ignored() {
        // D7 §4C.2 N2b2 no-bypass: every caller composes the plan's
        // admission field `None`, and the kernel resolves the declaring
        // package fresh at its guard stage, overwriting anything supplied.
        // A plan arriving with a foreign pre-resolved package must not
        // change admission — the stored install declaration governs. The
        // forged declaration consents to nothing and its supplied admitted
        // comment cap is one byte with a foreign need. Trusting either would
        // refuse; the real same-TX bound permits this post.
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-bypass",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "ignored admission",
            Some(token),
            "kernel:bypass:one",
        );
        let forged = crate::mcp::tools::effect_admission::DeclaringPackage {
            source: crate::mcp::tools::effect_admission::AdmissionSource::AppDeclaration,
            consent: crate::mcp::tools::effect_admission::PackageConsent {
                reads: crate::mcp::tools::effect_admission::ConsentMode::Declared,
                effects: crate::mcp::tools::effect_admission::ConsentMode::Declared,
            },
            package: "forged.package".to_string(),
            generation: "forged-generation".to_string(),
            artifact_id: "forged-artifact".to_string(),
            source_revision: "forged-revision".to_string(),
            declaration: json!({"needs": [], "effects": []}),
            declaration_digest: "forged-declaration".to_string(),
        };
        let plan = ArtifactCommentPlan {
            resolved_admission: Some(crate::mcp::tools::alpha_tabs::ResolvedAlphaAdmission {
                package: forged,
                admitted: crate::mcp::tools::effect_bounds::Admitted::Comment {
                    bound: crate::mcp::tools::effect_bounds::CommentCreateBound {
                        positions: vec!["root".into()],
                        max_body_bytes: 1,
                        need: "foreign.need".into(),
                    },
                    need: crate::mcp::tools::alpha_tabs::SqlNeed {
                        key: "foreign.need".into(),
                        label: "Foreign".into(),
                        sql: "SELECT id FROM records WHERE id='foreign' LIMIT 1".into(),
                        params: vec![],
                        relations: Default::default(),
                    },
                },
            }),
            ..plan
        };
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Created(receipt) = outcome else {
            panic!("the stored install must govern, not the forged package: {outcome:?}");
        };
        assert_eq!(receipt["bearer_id"], KERNEL_BEARER);
    }

    #[tokio::test]
    async fn react_plan_pre_resolved_admission_is_ignored() {
        // D7 §4C.2 N2c1 no-bypass: every caller composes the reaction plan's
        // admission field `None`, and the kernel resolves the declaring
        // package fresh at its guard stage, overwriting anything supplied.
        // A plan that arrives with a foreign pre-resolved package must not
        // short-circuit that guard: the real guard's stale generation still
        // refuses, byte-identically to the migrated guard stage. A kernel
        // that trusted the supplied package would skip the guard and settle
        // some other outcome.
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.react-kernel-bypass",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let mut stale = installed.guard.clone();
        stale.expected_install_event_id = "stale-token".into();
        let forged = crate::mcp::tools::effect_admission::DeclaringPackage {
            source: crate::mcp::tools::effect_admission::AdmissionSource::AppDeclaration,
            consent: crate::mcp::tools::effect_admission::PackageConsent {
                reads: crate::mcp::tools::effect_admission::ConsentMode::Declared,
                effects: crate::mcp::tools::effect_admission::ConsentMode::Declared,
            },
            package: "forged.react-package".to_string(),
            generation: "forged-generation".to_string(),
            artifact_id: "forged-artifact".to_string(),
            source_revision: "forged-revision".to_string(),
            declaration: json!({"needs": [], "effects": []}),
            declaration_digest: "forged-declaration".to_string(),
        };
        let plan = ArtifactReactPlan {
            artifact_id: KERNEL_ARTIFACT.to_string(),
            entry_id: "react".to_string(),
            entry: react_kernel_entry("react"),
            source_event_id: installed.guard.source_revision.clone(),
            source_digest: installed.body_digest.clone(),
            message_id: KERNEL_BEARER.to_string(),
            emoji: "👍".to_string(),
            adding: true,
            scope_port: "orders".to_string(),
            scope_collection_id: KERNEL_QUERY.to_string(),
            scope_kind: "query".to_string(),
            idempotency_key: "kernel:react:bypass".to_string(),
            gesture: Some("click".to_string()),
            guard: stale,
            resolved_admission: Some(crate::mcp::tools::alpha_tabs::ResolvedAlphaAdmission {
                package: forged,
                admitted: crate::mcp::tools::effect_bounds::Admitted::TasksLifecycle,
            }),
            gesture_evidence: None,
        };
        let outcome = react_to_message_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactReactOutcome::Refused { code, message } = outcome else {
            panic!("the real guard must govern, not the forged package: {outcome:?}");
        };
        assert_eq!(code, "alpha_guard_cas_mismatch");
        assert_eq!(
            message,
            format!(
                "installation changed; the guarded generation stale-token is stale (current {})",
                installed.guard.expected_install_event_id
            )
        );
        assert_eq!(comment_count(&installed.db).await, 0);
    }

    #[tokio::test]
    async fn title_plan_pre_resolved_admission_is_ignored() {
        // D7 §4C.2 N2c2 no-bypass: every caller composes the title plan's
        // admission field `None`, and the kernel resolves the declaring
        // package fresh at its guard stage, overwriting anything supplied.
        // A plan that arrives with a foreign pre-resolved package must not
        // short-circuit that guard: the real guard's stale generation still
        // refuses, byte-identically to the migrated guard stage. A kernel
        // that trusted the supplied package would skip the guard and settle
        // some other outcome.
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.title-kernel-bypass",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let mut stale = installed.guard.clone();
        stale.expected_install_event_id = "stale-token".into();
        let forged = crate::mcp::tools::effect_admission::DeclaringPackage {
            source: crate::mcp::tools::effect_admission::AdmissionSource::AppDeclaration,
            consent: crate::mcp::tools::effect_admission::PackageConsent {
                reads: crate::mcp::tools::effect_admission::ConsentMode::Declared,
                effects: crate::mcp::tools::effect_admission::ConsentMode::Declared,
            },
            package: "forged.title-package".to_string(),
            generation: "forged-generation".to_string(),
            artifact_id: "forged-artifact".to_string(),
            source_revision: "forged-revision".to_string(),
            declaration: json!({"needs": [], "effects": []}),
            declaration_digest: "forged-declaration".to_string(),
        };
        let plan = ArtifactTitlePlan {
            artifact_id: KERNEL_ARTIFACT.to_string(),
            entry_id: "rename".to_string(),
            entry: title_kernel_entry("rename"),
            source_event_id: installed.guard.source_revision.clone(),
            source_digest: installed.body_digest.clone(),
            record_id: KERNEL_BEARER.to_string(),
            title: "Renamed by forged package".to_string(),
            observed_token: None,
            scope_port: "orders".to_string(),
            scope_collection_id: KERNEL_QUERY.to_string(),
            scope_kind: "query".to_string(),
            idempotency_key: "kernel:title:bypass".to_string(),
            gesture: Some("click".to_string()),
            guard: stale,
            resolved_admission: Some(crate::mcp::tools::alpha_tabs::ResolvedAlphaAdmission {
                package: forged,
                admitted: crate::mcp::tools::effect_bounds::Admitted::TasksLifecycle,
            }),
        };
        let outcome = rename_record_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactTitleOutcome::Refused { code, message } = outcome else {
            panic!("the real guard must govern, not the forged package: {outcome:?}");
        };
        assert_eq!(code, "alpha_guard_cas_mismatch");
        assert_eq!(
            message,
            format!(
                "installation changed; the guarded generation stale-token is stale (current {})",
                installed.guard.expected_install_event_id
            )
        );
        assert_eq!(comment_count(&installed.db).await, 0);
    }

    #[tokio::test]
    async fn comment_reply_posts_flat_with_null_lifecycle() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root", "reply"])),
            "agent.comment-kernel-b",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "root note",
            Some(token),
            "kernel:reply:root",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Created(root) = outcome else {
            panic!("root must post");
        };
        let root_id = root["comment_id"].as_str().unwrap().to_string();
        // Thread roots are editable targets by fixture grant, matching the
        // inherited target-editable acceptance.
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            &root_id,
            vec![
                crate::authorization::AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                crate::authorization::AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        // The delivered need only covers thread-named rows: rename the
        // root through the governed path (which also moves its revision,
        // so the reply token below is minted over fresh state).
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": root_id, "name": "thread-root",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        // Replies target the thread root comment itself.
        let token = comment_token_for(
            &installed.db,
            &root_id,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &root_id,
            "reply",
            "flat reply",
            Some(token),
            "kernel:reply:one",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Created(receipt) = outcome else {
            panic!("reply must post: {outcome:?}");
        };
        assert_whitelist_shape(&receipt, false);
        assert_eq!(receipt["bearer_id"], root_id);
        assert_eq!(receipt["position"], "reply");
        // Flat reply carries a null thread lifecycle of its own.
        let read = installed
            .registry
            .call(
                installed.db.clone(),
                Caller::authenticated(KERNEL_ACCOUNT),
                "get_record",
                json!({ "ids": [root_id], "include_comments": true }),
            )
            .await
            .unwrap();
        let replies = read["records"][0]["comments"].as_array().unwrap();
        assert_eq!(replies.len(), 1);
        assert!(replies[0].get("lifecycle").is_none() || replies[0]["lifecycle"].is_null());
    }

    #[tokio::test]
    async fn comment_body_bounds_and_blankness_fail_safely() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-c",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        // Consent cap is 100 against manifest 500: 101 bytes refuse.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            &"x".repeat(101),
            Some(token.clone()),
            "kernel:bounds:over",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
            panic!("over-cap body must refuse: {outcome:?}");
        };
        assert_eq!(code, "comment_body_too_large");
        // Exactly the effective cap posts, multibyte bytes counted as bytes.
        let exact = format!("{}{}", "é".repeat(49), "zz");
        assert_eq!(exact.len(), 100);
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            &exact,
            Some(token.clone()),
            "kernel:bounds:exact",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        assert!(
            matches!(outcome, ArtifactCommentOutcome::Created(_)),
            "{outcome:?}"
        );
        // Blank bodies refuse explicitly with zero writes. Unicode
        // parity: NEL trims to blank and refuses, while BOM is not
        // trimmable whitespace and posts like any nonblank body.
        for (body, refused) in [
            ("   ".to_string(), true),
            ("\u{85}".to_string(), true),
            ("\u{feff}".to_string(), false),
        ] {
            let plan = comment_plan(
                &installed,
                kernel_entry("post", CommentPosition::Root),
                KERNEL_BEARER,
                "root",
                &body,
                Some(token.clone()),
                "kernel:bounds:blank",
            );
            let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
                .await
                .unwrap();
            if refused {
                let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
                    panic!("blank body must refuse: {outcome:?}");
                };
                assert_eq!(code, "comment_body_blank");
            } else {
                assert!(
                    matches!(outcome, ArtifactCommentOutcome::Created(_)),
                    "{outcome:?}"
                );
            }
        }
        assert_eq!(comment_count(&installed.db).await, 2);
    }

    #[tokio::test]
    async fn comment_cas_mismatch_conflicts_and_missing_token_refuses() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-d",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let before = comment_count(&installed.db).await;
        // Well-shaped but foreign token: conflict with current opaque
        // token plus the actual parent event, zero writes.
        let foreign = format!("ct:{}", "f".repeat(32));
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "cas probe",
            Some(foreign),
            "kernel:cas:foreign",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Conflict {
            current_version,
            conflicting_event_id,
        } = outcome
        else {
            panic!("foreign token must conflict: {outcome:?}");
        };
        assert!(current_version.starts_with("ct:"), "{current_version}");
        assert!(!current_version.contains("seq"), "{current_version}");
        assert!(
            !conflicting_event_id.contains("seq"),
            "{conflicting_event_id}"
        );
        // Malformed token refuses rather than conflicting.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "cas probe",
            Some("obs:41".to_string()),
            "kernel:cas:malformed",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
            panic!("malformed token must refuse: {outcome:?}");
        };
        assert_eq!(code, "invalid_precondition");
        // Omitted token refuses the same way.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "cas probe",
            None,
            "kernel:cas:omitted",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        assert!(
            matches!(outcome, ArtifactCommentOutcome::Refused { .. }),
            "{outcome:?}"
        );
        assert_eq!(comment_count(&installed.db).await, before);
    }

    #[tokio::test]
    async fn comment_replay_settles_without_appending_and_changed_command_rejects() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-e",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "once",
            Some(token.clone()),
            "kernel:replay:key",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Created(first) = outcome else {
            panic!("first post must commit: {outcome:?}");
        };
        let first_id = first["comment_id"].as_str().unwrap().to_string();
        // Same key with a refreshed token settles the original receipt.
        let refreshed = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "once",
            Some(refreshed),
            "kernel:replay:key",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Replayed(replayed) = outcome else {
            panic!("same command must replay: {outcome:?}");
        };
        assert_whitelist_shape(&replayed, true);
        assert_eq!(replayed["comment_id"], first_id);
        // Same key with the token omitted still settles: replay never
        // checks CAS.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "once",
            None,
            "kernel:replay:key",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Replayed(again) = outcome else {
            panic!("omitted CAS must still replay: {outcome:?}");
        };
        assert_eq!(again["comment_id"], first_id);
        // Same key with a different command rejects; nothing appends.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "twice",
            Some(token),
            "kernel:replay:key",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
            panic!("changed command must reject: {outcome:?}");
        };
        assert_eq!(code, "idempotency_conflict");
        assert_eq!(comment_count(&installed.db).await, 1);
    }

    #[tokio::test]
    async fn comment_update_carry_refuses_old_frame_before_replay_or_fresh_effect() {
        let declaration = kernel_declaration(json!(["root"]));
        let installed = kernel_fixture(declaration.clone(), "agent.comment-update", true).await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "before update",
            Some(token),
            "kernel:update:old",
        );
        assert!(matches!(
            create_comment_from_artifact(installed.db.clone(), caller.clone(), plan.clone())
                .await
                .unwrap(),
            ArtifactCommentOutcome::Created(_)
        ));
        let updated = installed.registry.call(installed.db.clone(), caller.clone(), "manage_alpha_tabs",
            json!({"action": "update", "package": installed.guard.package,
                "version": "0.1.1", "digest": installed.guard.digest,
                "artifact_id": installed.guard.artifact_id, "source_revision": installed.guard.source_revision,
                "declaration": declaration, "expected_install_event_id": installed.guard.expected_install_event_id,
                "reason": "Update the generation without carrying frame authority."})).await.unwrap();
        assert_eq!(updated["adoption_carried"], true);
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(installed.db.pool())
            .await
            .unwrap();
        for key in ["kernel:update:old", "kernel:update:fresh"] {
            let stale = ArtifactCommentPlan {
                idempotency_key: key.into(),
                ..plan.clone()
            };
            let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), stale)
                .await
                .unwrap();
            let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
                panic!("old frame must refuse: {outcome:?}");
            };
            assert_eq!(code, "alpha_guard_cas_mismatch");
        }
        // Other guarded kernels must also refuse this actual superseded frame.
        let react = ArtifactReactPlan {
            artifact_id: KERNEL_ARTIFACT.into(),
            entry_id: "react".into(),
            entry: react_kernel_entry("react"),
            source_event_id: installed.guard.source_revision.clone(),
            source_digest: installed.body_digest.clone(),
            message_id: KERNEL_BEARER.into(),
            emoji: "👍".into(),
            adding: true,
            scope_port: "orders".into(),
            scope_collection_id: KERNEL_QUERY.into(),
            scope_kind: "query".into(),
            idempotency_key: "kernel:update:react".into(),
            gesture: Some("click".into()),
            guard: installed.guard.clone(),
            resolved_admission: None,
            gesture_evidence: None,
        };
        let outcome = react_to_message_from_artifact(installed.db.clone(), caller.clone(), react)
            .await
            .unwrap();
        let ArtifactReactOutcome::Refused { code, .. } = outcome else {
            panic!("old reaction frame must refuse: {outcome:?}");
        };
        assert_eq!(code, "alpha_guard_cas_mismatch");
        let title = ArtifactTitlePlan {
            artifact_id: KERNEL_ARTIFACT.into(),
            entry_id: "rename".into(),
            entry: title_kernel_entry("rename"),
            source_event_id: installed.guard.source_revision.clone(),
            source_digest: installed.body_digest.clone(),
            record_id: KERNEL_BEARER.into(),
            title: "Stale rename".into(),
            observed_token: None,
            scope_port: "orders".into(),
            scope_collection_id: KERNEL_QUERY.into(),
            scope_kind: "query".into(),
            idempotency_key: "kernel:update:title".into(),
            gesture: Some("click".into()),
            guard: installed.guard.clone(),
            resolved_admission: None,
        };
        let outcome = rename_record_from_artifact(installed.db.clone(), caller.clone(), title)
            .await
            .unwrap();
        let ArtifactTitleOutcome::Refused { code, .. } = outcome else {
            panic!("old title frame must refuse: {outcome:?}");
        };
        assert_eq!(code, "alpha_guard_cas_mismatch");
        let facet = InteractionEntry {
            id: "mark".into(),
            label: "Mark".into(),
            effect: InteractionEffect::FacetSet,
            slots: Default::default(),
            facet: "triage".into(),
            value: None,
            create: None,
            comment: None,
            react: None,
            title: None,
            body: None,
        };
        let mut tx = crate::db::begin_write(installed.db.write_pool())
            .await
            .unwrap();
        let (code, _) = crate::mcp::tools::alpha_tabs::check_alpha_install_guard_in(
            &mut tx,
            &caller,
            &installed.guard,
            KERNEL_ARTIFACT,
            &installed.body_digest,
            &facet,
        )
        .await
        .unwrap()
        .expect("old facet frame must refuse");
        assert_eq!(code, "alpha_guard_cas_mismatch");
        tx.rollback().await.unwrap();
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(installed.db.pool())
            .await
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(comment_count(&installed.db).await, 1);
    }

    #[tokio::test]
    async fn comment_replay_skips_changed_membership_and_binding_but_keeps_current_pins() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-carried-replay",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "carried once",
            Some(token),
            "kernel:carried:replay",
        );
        let first =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), plan.clone())
                .await
                .unwrap();
        let ArtifactCommentOutcome::Created(first) = first else {
            panic!("initial post must create");
        };
        let created_id = first["comment_id"].as_str().unwrap();
        // Move only the mutable need cohort, retaining View/Edit and the
        // bound-input query's home/kind scope. The installed SQL is fixed.
        sqlx::query("UPDATE records SET name='outside-cohort' WHERE id=?")
            .bind(KERNEL_BEARER)
            .execute(installed.db.write_pool())
            .await
            .unwrap();
        let retry = ArtifactCommentPlan {
            observed_token: None,
            ..plan.clone()
        };
        let replay =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), retry.clone())
                .await
                .unwrap();
        let ArtifactCommentOutcome::Replayed(receipt) = replay else {
            panic!("membership drift must still replay");
        };
        assert_eq!(
            receipt,
            json!({"comment_id": created_id, "bearer_id": KERNEL_BEARER,
            "position": "root", "idempotent_retry": true})
        );
        let fresh = ArtifactCommentPlan {
            idempotency_key: "kernel:carried:fresh-need".into(),
            ..retry.clone()
        };
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), fresh)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("fresh post must prove membership");
        };
        assert_eq!(code, "record_outside_need");
        assert_eq!(message, "record e0000000-0000-4000-8000-0000000000a3 is not among the delivered rows of need 'thread.items' (bound 'thread.items')");
        // Revoke only the source's mutable input grant. Static install pins
        // remain intact; kernel replay must still settle the original id.
        sqlx::query(
            "DELETE FROM artifact_module_grants WHERE artifact_id=? AND capability='input.read'",
        )
        .bind(KERNEL_ARTIFACT)
        .execute(installed.db.write_pool())
        .await
        .unwrap();
        let replay =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), retry.clone())
                .await
                .unwrap();
        let ArtifactCommentOutcome::Replayed(receipt) = replay else {
            panic!("binding drift must still replay");
        };
        assert_eq!(
            receipt,
            json!({"comment_id": created_id, "bearer_id": KERNEL_BEARER,
            "position": "root", "idempotent_retry": true})
        );
        let fresh = ArtifactCommentPlan {
            idempotency_key: "kernel:carried:fresh-binding".into(),
            ..retry.clone()
        };
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), fresh)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("fresh post must prove binding first");
        };
        assert_eq!(code, "module_capability_denied");
        assert_eq!(message, "input port 'orders' is not exposed to the artifact root with an exact input.read grant");
        // A same-key retry still traverses current generation pins before
        // replay, despite both mutable failures above.
        let mut stale = retry;
        stale.guard.expected_install_event_id = "stale-token".into();
        let outcome = create_comment_from_artifact(installed.db.clone(), caller, stale)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("stale generation must refuse replay");
        };
        assert_eq!(code, "alpha_guard_cas_mismatch");
        assert_eq!(
            message,
            format!(
                "installation changed; the guarded generation stale-token is stale (current {})",
                installed.guard.expected_install_event_id
            )
        );
        assert_eq!(comment_count(&installed.db).await, 1);
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type='record.created' AND json_extract(payload,'$.origin.idempotency_key')='kernel:carried:replay'")
            .fetch_one(installed.db.pool()).await.unwrap();
        assert_eq!(events, 1);
    }

    #[tokio::test]
    async fn comment_revocations_reject_with_zero_writes() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-f",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        // Stale generation refuses before any write.
        let mut stale = installed.guard.clone();
        stale.expected_install_event_id = "stale-token".into();
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "revoked",
            None,
            "kernel:revoke:stale",
        );
        let plan = ArtifactCommentPlan {
            guard: stale,
            ..plan
        };
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = ArtifactCommentPlan {
            observed_token: Some(token),
            ..plan
        };
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
            panic!("stale generation must refuse: {outcome:?}");
        };
        assert_eq!(code, "alpha_guard_cas_mismatch");
        // Target Edit revoked: View alone cannot post.
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            KERNEL_BEARER,
            vec![AllowEntry::account(KERNEL_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "revoked",
            Some(token),
            "kernel:revoke:edit",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
            panic!("revoked Edit must refuse: {outcome:?}");
        };
        assert_eq!(code, "permission_denied");
        assert_eq!(comment_count(&installed.db).await, 0);
    }

    #[tokio::test]
    async fn comment_reply_hidden_thread_parent_refuses_at_target_gate() {
        // The private kernel checks target View+Edit on the write snapshot
        // before any home lookup, replay, or append: hiding the bearer
        // refuses typed and id-free here. (Canonical authorization would
        // also resolve the root comment onto its bearer downstream; the
        // early gate fires first.) This leg proves the refusal, the
        // absence of leaked ids, and zero writes.
        let installed = kernel_fixture(
            kernel_declaration(json!(["root", "reply"])),
            "agent.comment-kernel-i",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "hidden thread",
            Some(token),
            "kernel:hidden:root",
        );
        let ArtifactCommentOutcome::Created(root) =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
                .await
                .unwrap()
        else {
            panic!("root must post");
        };
        let root_id = root["comment_id"].as_str().unwrap().to_string();
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            &root_id,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        // Hide the underlying thread parent from the only viewer: the
        // target-Edit gate on the root comment fires first.
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            KERNEL_BEARER,
            vec![],
        )
        .await
        .unwrap();
        let token = comment_token_for(
            &installed.db,
            &root_id,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &root_id,
            "reply",
            "hidden reply",
            Some(token),
            "kernel:hidden:reply",
        );
        let before = comment_count(&installed.db).await;
        let outcome = create_comment_from_artifact(installed.db.clone(), caller, plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("hidden parent must refuse: {outcome:?}");
        };
        assert_eq!(code, "permission_denied");
        assert!(!message.contains(&root_id), "{message}");
        assert!(!message.contains(KERNEL_COLLECTION), "{message}");
        assert_eq!(comment_count(&installed.db).await, before);
    }

    #[tokio::test]
    async fn comment_hidden_root_and_revoked_home_edit_refuse_id_free() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-j",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        // Hidden root: with the bearer invisible, a root post refuses
        // typed and id-free before any home lookup or append.
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            KERNEL_BEARER,
            vec![],
        )
        .await
        .unwrap();
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "hidden root",
            Some(token),
            "kernel:hidden-root:one",
        );
        let before = comment_count(&installed.db).await;
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("hidden root must refuse: {outcome:?}");
        };
        assert_eq!(code, "permission_denied");
        assert!(!message.contains(KERNEL_BEARER), "{message}");
        assert!(!message.contains(KERNEL_COLLECTION), "{message}");
        assert_eq!(comment_count(&installed.db).await, before);
        // Home Edit revoked (View kept, a legitimate grant shape): the
        // derived-home destination gate refuses without naming the home.
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            KERNEL_BEARER,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            KERNEL_COLLECTION,
            vec![AllowEntry::account(KERNEL_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "homeless post",
            Some(token),
            "kernel:hidden-root:two",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller, plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("revoked home Edit must refuse: {outcome:?}");
        };
        assert_eq!(code, "permission_denied");
        assert!(!message.contains(KERNEL_COLLECTION), "{message}");
        assert_eq!(comment_count(&installed.db).await, before);
    }

    #[tokio::test]
    async fn comment_replay_without_output_view_is_denied() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-g",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "visible once",
            Some(token),
            "kernel:visibility:key",
        );
        let ArtifactCommentOutcome::Created(first) =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
                .await
                .unwrap()
        else {
            panic!("first post must commit");
        };
        let comment_id = first["comment_id"].as_str().unwrap().to_string();
        // Governed delete of the created output: derived authorization
        // ignores a local policy on the Annotation itself, so Manage goes
        // on the underlying bearer — then the comment resolves Manage too.
        // Assert that positive before deleting; policy removal alone
        // cannot deny an owner floor, so deletion is the honest
        // output-loss fixture.
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            KERNEL_BEARER,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Manage),
            ],
        )
        .await
        .unwrap();
        assert!(
            crate::mcp::tools::can_record(&installed.db, &caller, &comment_id, Capability::Manage,)
                .await
                .unwrap(),
            "bearer Manage must resolve onto the comment"
        );
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "delete_record",
                json!({ "id": comment_id, "reason": "Comment kernel test." }),
            )
            .await
            .unwrap();
        assert_eq!(comment_count(&installed.db).await, 0);
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "visible once",
            None,
            "kernel:visibility:key",
        );
        let error = create_comment_from_artifact(installed.db.clone(), caller, plan)
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&comment_id), "{error}");
        assert_eq!(comment_count(&installed.db).await, 0);
    }

    #[tokio::test]
    async fn comment_reply_to_anchored_root_refuses() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root", "reply"])),
            "agent.comment-kernel-h",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "anchored root",
            Some(token),
            "kernel:anchored:root",
        );
        let ArtifactCommentOutcome::Created(root) =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
                .await
                .unwrap()
        else {
            panic!("root must post");
        };
        let root_id = root["comment_id"].as_str().unwrap().to_string();
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            &root_id,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        // Delivered need covers thread-named rows only; rename first so
        // the reply bearer is deliverable, then seed the anchor below.
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": root_id, "name": "thread-root",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        // Genuine governed body write on the bearer first, then seed the
        // anchor row with its actual event seq and body hash — the exact
        // values the projector would persist. Seeded row shape only, never
        // authority; no constraint disabled.
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": KERNEL_BEARER, "body_append": " quoted",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        let bearer_body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(KERNEL_BEARER)
            .fetch_one(installed.db.pool())
            .await
            .unwrap();
        let bearer_seq: i64 =
            sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
                .bind(KERNEL_BEARER)
                .fetch_one(installed.db.pool())
                .await
                .unwrap();
        let bearer_hash = hex::encode(Sha256::digest(bearer_body.as_bytes()));
        sqlx::query(
            "INSERT INTO annotation_targets
                (annotation_id, target_record_id, source_slot, source_event_seq, blob_id,
                 source_sha256, selectors, created_at, updated_at)
             VALUES (?,?, 'body', ?, NULL, ?, '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(&root_id)
        .bind(KERNEL_BEARER)
        .bind(bearer_seq)
        .bind(bearer_hash)
        .execute(installed.db.write_pool())
        .await
        .unwrap();
        let token = comment_token_for(
            &installed.db,
            &root_id,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &root_id,
            "reply",
            "anchored reply",
            Some(token),
            "kernel:anchored:reply",
        );
        let before = comment_count(&installed.db).await;
        let outcome = create_comment_from_artifact(installed.db.clone(), caller, plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
            panic!("anchored parent must refuse: {outcome:?}");
        };
        assert_eq!(code, "anchored_parent");
        assert_eq!(comment_count(&installed.db).await, before);
    }

    /// Stale token helper for replay legs: mints over current parent state
    /// without asserting freshness, since replay must settle regardless.
    async fn stale_token_for_replay(installed: &KernelFixture, target: &str) -> String {
        comment_token_for(
            &installed.db,
            target,
            &installed.guard,
            &installed.body_digest,
        )
        .await
    }

    #[tokio::test]
    async fn comment_reply_to_reply_refuses_as_invalid_thread() {
        // Nesting is detected by the ordinary validator (the reply bearer's
        // own bearer is a governed comment): with a fresh matching CAS the
        // kernel settles it as a typed refusal with zero writes.
        let installed = kernel_fixture(
            kernel_declaration(json!(["root", "reply"])),
            "agent.comment-kernel-nested",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "nest root",
            Some(token),
            "kernel:nested:root",
        );
        let ArtifactCommentOutcome::Created(root) =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
                .await
                .unwrap()
        else {
            panic!("root must post");
        };
        let root_id = root["comment_id"].as_str().unwrap().to_string();
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            &root_id,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": root_id, "name": "thread-nest-root",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        let token = comment_token_for(
            &installed.db,
            &root_id,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &root_id,
            "reply",
            "first reply",
            Some(token),
            "kernel:nested:reply",
        );
        let ArtifactCommentOutcome::Created(reply) =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
                .await
                .unwrap()
        else {
            panic!("reply must post");
        };
        let reply_id = reply["comment_id"].as_str().unwrap().to_string();
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            &reply_id,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": reply_id, "name": "thread-nest-reply",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        let token = comment_token_for(
            &installed.db,
            &reply_id,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &reply_id,
            "reply",
            "nested reply",
            Some(token),
            "kernel:nested:nested",
        );
        let before = comment_count(&installed.db).await;
        let outcome = create_comment_from_artifact(installed.db.clone(), caller, plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("nested reply must refuse: {outcome:?}");
        };
        assert_eq!(code, "invalid_thread");
        assert!(!message.contains(&reply_id), "{message}");
        assert_eq!(comment_count(&installed.db).await, before);
    }

    #[tokio::test]
    async fn comment_resolved_root_conflicts_on_stale_token() {
        // Genuine open root via the ordinary path, replied once, then
        // resolved through the governed transition: a stale reply token
        // conflicts with the actual parent event even though the thread
        // shape changed, with zero appends. A fresh token posts.
        let installed = kernel_fixture(
            kernel_declaration(json!(["root", "reply"])),
            "agent.comment-kernel-resolve",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let created = installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "type": "Annotation", "kind": "comment", "lifecycle": "open",
                    "name": "thread-open-root", "body": "resolvable",
                    "home_id": KERNEL_COLLECTION,
                    "links": [{ "target_id": KERNEL_BEARER, "relationship": "part_of" }],
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        let open_root = created["id"].as_str().unwrap().to_string();
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            &open_root,
            vec![
                AllowEntry::account(KERNEL_ACCOUNT, Capability::View),
                AllowEntry::account(KERNEL_ACCOUNT, Capability::Edit),
            ],
        )
        .await
        .unwrap();
        let token = comment_token_for(
            &installed.db,
            &open_root,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &open_root,
            "reply",
            "first reply",
            Some(token.clone()),
            "kernel:resolve:reply-one",
        );
        let ArtifactCommentOutcome::Created(first) =
            create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
                .await
                .unwrap()
        else {
            panic!("first reply must post");
        };
        let first_id = first["comment_id"].as_str().unwrap().to_string();
        // Governed resolve: open -> resolved with a nonblank summary.
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": open_root, "lifecycle": "resolved", "summary": "settled",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        // Stale token, new key: Conflict carries the live token and the
        // actual parent event, with zero appends.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &open_root,
            "reply",
            "late reply",
            Some(token),
            "kernel:resolve:reply-two",
        );
        let before = comment_count(&installed.db).await;
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Conflict {
            current_version,
            conflicting_event_id,
        } = outcome
        else {
            panic!("stale token must conflict: {outcome:?}");
        };
        let parent_event: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(&open_root)
        .fetch_one(installed.db.pool())
        .await
        .unwrap();
        assert_eq!(conflicting_event_id, parent_event);
        let fresh = comment_token_for(
            &installed.db,
            &open_root,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        assert_eq!(current_version, fresh);
        assert_eq!(comment_count(&installed.db).await, before);
        // Fresh token posts the second reply.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &open_root,
            "reply",
            "late reply",
            Some(fresh),
            "kernel:resolve:reply-three",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        assert!(
            matches!(outcome, ArtifactCommentOutcome::Created(_)),
            "{outcome:?}"
        );
        // Same-key replay of the first reply settles its original id even
        // though the parent has since resolved: replay needs fresh
        // authority, never a fresh CAS.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            &open_root,
            "reply",
            "first reply",
            Some(stale_token_for_replay(&installed, &open_root).await),
            "kernel:resolve:reply-one",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Replayed(replayed) = outcome else {
            panic!("same key must replay: {outcome:?}");
        };
        assert_eq!(replayed["comment_id"], first_id);
    }

    #[tokio::test]
    async fn comment_archived_home_refuses_without_naming_it() {
        // A malformed archived filing home (synthetic fixture below):
        // the derived-home shape gate refuses id-free with zero writes.
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-archive",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        // Synthetic malformed/imported archived-home fixture, explicitly
        // labelled: the governed archive_record path refuses an archive
        // while live members remain homed (projector invariant), so no
        // genuine governed mutation can produce this state while the
        // bearer stays filed. The raw row exercises exactly the
        // assert_home_target_in archived branch the kernel maps.
        sqlx::query(
            "INSERT INTO facet_values (id, record_id, key, value)
             VALUES ('synthetic-archived-home-marker', ?, 'archived', 'true')",
        )
        .bind(KERNEL_COLLECTION)
        .execute(installed.db.write_pool())
        .await
        .unwrap();
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "archived home post",
            Some(token),
            "kernel:archive:one",
        );
        let before = comment_count(&installed.db).await;
        let outcome = create_comment_from_artifact(installed.db.clone(), caller, plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("archived home must refuse: {outcome:?}");
        };
        assert_eq!(code, "invalid_home");
        assert!(!message.contains(KERNEL_COLLECTION), "{message}");
        assert!(!message.contains(KERNEL_BEARER), "{message}");
        assert_eq!(comment_count(&installed.db).await, before);
    }

    #[tokio::test]
    async fn comment_checked_validation_keeps_delegated_failures_outer() {
        // Same-transaction vocabulary fault (rolled back): the kind
        // resolver's delegated storage failure stays an outer error —
        // even in its Error::engine mapping — and is never converted to
        // an expected shape refusal. Then the healthy path still
        // validates, proving the fault left no damage.
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        let bearer = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type": "Document", "kind": "note", "name": "fault bearer",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        sqlx::query("ALTER TABLE vocabulary_values RENAME TO vocabulary_values_broken")
            .execute(&mut *tx)
            .await
            .unwrap();
        let outcome = crate::comments::validate_create_checked_on(
            &mut tx,
            std::slice::from_ref(&bearer),
            Some("hello"),
            None,
            None,
        )
        .await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("resolve kind"),
                "delegated failure must keep its provenance: {error}"
            ),
            Ok(_) => panic!("vocabulary fault must not validate"),
        }
        tx.rollback().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let position = crate::comments::validate_create_checked_on(
            &mut tx,
            &[bearer],
            Some("hello"),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            position,
            Ok(crate::comments::Position::Root),
            "healthy validation still positions"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn comment_plan_position_mismatch_refuses_after_cas() {
        // A declared Reply entry aimed at an ordinary bearer — legitimate
        // input mismatch (compose_comment_plan takes any bound record id
        // against the fixed manifest position), not composer forgery —
        // still passes every authority gate with a fresh matching CAS,
        // then refuses on the position agreement the stale path would
        // have conflicted on. Zero writes; no impossible governed
        // mutation involved.
        let installed = kernel_fixture(
            kernel_declaration(json!(["reply"])),
            "agent.comment-kernel-mismatch",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        let token = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            KERNEL_BEARER,
            "reply",
            "mismatched post",
            Some(token.clone()),
            "kernel:mismatch:one",
        );
        let before = comment_count(&installed.db).await;
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, message } = outcome else {
            panic!("position mismatch must refuse: {outcome:?}");
        };
        assert_eq!(code, "invalid_position");
        assert!(message.contains("disagrees"), "{message}");
        assert_eq!(comment_count(&installed.db).await, before);
        // Genuine bearer update staying inside the query cohort and the
        // thread-% need: the pre-update token goes stale. Same key and
        // command miss replay, then Conflict with zero writes — the stale
        // path never reaches the position agreement above.
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": KERNEL_BEARER, "name": "thread-target-v2",
                    "body_append": " still on topic",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            KERNEL_BEARER,
            "reply",
            "mismatched post",
            Some(token),
            "kernel:mismatch:one",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Conflict {
            current_version,
            conflicting_event_id,
        } = outcome
        else {
            panic!("stale token must conflict: {outcome:?}");
        };
        assert!(current_version.starts_with("ct:"), "{current_version}");
        assert!(!conflicting_event_id.is_empty());
        assert_eq!(comment_count(&installed.db).await, before);
        // Fresh token over the moved bearer returns to the position
        // refusal: same key, same command, zero writes.
        let fresh = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Reply),
            KERNEL_BEARER,
            "reply",
            "mismatched post",
            Some(fresh),
            "kernel:mismatch:one",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller, plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Refused { code, .. } = outcome else {
            panic!("position mismatch must refuse: {outcome:?}");
        };
        assert_eq!(code, "invalid_position");
        assert_eq!(comment_count(&installed.db).await, before);
    }

    #[tokio::test]
    async fn comment_cas_tracks_parent_edits_and_child_appends_leave_it_stable() {
        let installed = kernel_fixture(
            kernel_declaration(json!(["root"])),
            "agent.comment-kernel-cas",
            true,
        )
        .await;
        let caller = Caller::authenticated(KERNEL_ACCOUNT);
        // Token over the current parent revision.
        let stale = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        // Governed parent edit while the target stays within need and
        // binding: the body change keeps the thread name deliverable.
        installed
            .registry
            .call(
                installed.db.clone(),
                caller.clone(),
                "update_record",
                json!({
                    "id": KERNEL_BEARER, "body_append": " edited",
                    "reason": "Comment kernel test.",
                }),
            )
            .await
            .unwrap();
        // Posting with the pre-edit token conflicts against the actual
        // parent event, with zero comment appends.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "stale post",
            Some(stale),
            "kernel:cas:stale",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Conflict {
            current_version,
            conflicting_event_id,
        } = outcome
        else {
            panic!("stale token must conflict: {outcome:?}");
        };
        let parent_event: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(KERNEL_BEARER)
        .fetch_one(installed.db.pool())
        .await
        .unwrap();
        assert_eq!(conflicting_event_id, parent_event);
        // The conflict carries the live token: a fresh mint agrees.
        let fresh = comment_token_for(
            &installed.db,
            KERNEL_BEARER,
            &installed.guard,
            &installed.body_digest,
        )
        .await;
        assert_eq!(current_version, fresh);
        assert_eq!(comment_count(&installed.db).await, 0);
        // Two distinct genuine comments under the same fresh token both
        // append once: child appends leave the parent revision stable.
        // The first created id is saved for the replay identity check.
        let mut first_id = String::new();
        for (body, key) in [
            ("first note", "kernel:cas:first"),
            ("second note", "kernel:cas:second"),
        ] {
            let plan = comment_plan(
                &installed,
                kernel_entry("post", CommentPosition::Root),
                KERNEL_BEARER,
                "root",
                body,
                Some(fresh.clone()),
                key,
            );
            let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
                .await
                .unwrap();
            let ArtifactCommentOutcome::Created(created) = outcome else {
                panic!("genuine post must commit: {outcome:?}");
            };
            if key == "kernel:cas:first" {
                first_id = created["comment_id"].as_str().unwrap().to_string();
            }
        }
        assert_eq!(comment_count(&installed.db).await, 2);
        // Same-key replay of the first settles its minimal id with no
        // third append, even though the token is still current.
        let plan = comment_plan(
            &installed,
            kernel_entry("post", CommentPosition::Root),
            KERNEL_BEARER,
            "root",
            "first note",
            Some(fresh),
            "kernel:cas:first",
        );
        let outcome = create_comment_from_artifact(installed.db.clone(), caller.clone(), plan)
            .await
            .unwrap();
        let ArtifactCommentOutcome::Replayed(replayed) = outcome else {
            panic!("same key must replay: {outcome:?}");
        };
        assert_whitelist_shape(&replayed, true);
        assert_eq!(replayed["comment_id"], first_id);
        assert_eq!(comment_count(&installed.db).await, 2);
    }

    #[test]
    fn comment_outcome_markers_round_trip() {
        let created = comment_receipt_value("c1", "b1", "root", false);
        let ArtifactCommentOutcome::Created(back) =
            decode_comment_outcome(&created).expect("created decodes")
        else {
            panic!("created must decode");
        };
        assert_eq!(back["comment_id"], "c1");
        let replayed = comment_receipt_value("c1", "b1", "reply", true);
        assert!(matches!(
            decode_comment_outcome(&replayed),
            Some(ArtifactCommentOutcome::Replayed(_))
        ));
        let conflict = comment_conflict_value("ct:00000000000000000000000000000000", "evt-1");
        let ArtifactCommentOutcome::Conflict {
            current_version,
            conflicting_event_id,
        } = decode_comment_outcome(&conflict).expect("conflict decodes")
        else {
            panic!("conflict must decode");
        };
        assert!(current_version.starts_with("ct:"));
        assert_eq!(conflicting_event_id, "evt-1");
        let refused = comment_refused_value("some_code", "some message".to_string());
        let ArtifactCommentOutcome::Refused { code, message } =
            decode_comment_outcome(&refused).expect("refused decodes")
        else {
            panic!("refused must decode");
        };
        assert_eq!(code, "some_code");
        assert_eq!(message, "some message");
        assert!(decode_comment_outcome(&json!({"id": "x"})).is_none());
    }
}

#[cfg(test)]
mod retraction_reserved_seam_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_facet_entry_refuses_retraction_for_set_and_clear() {
        // R2a1: the shared caller seam refuses `retraction` before looking at
        // the value, so set and clear fail identically. Exhaustive caller-API
        // coverage belongs to R2a2; this pins the shared seam itself.
        for (value, allow_unset) in [
            (json!("author"), false),
            (json!("author"), true),
            (json!(Value::Null), true),
        ] {
            let Err(error) = parse_facet_entry("update_record", "retraction", &value, allow_unset)
            else {
                panic!("retraction must be refused for set and clear");
            };
            let error = error.to_string();
            assert!(
                error.contains(
                    "facet 'retraction' is engine-reserved — only archive_record writes it"
                ),
                "{error}"
            );
        }
        // Ordinary open keys still parse for set and (when allowed) clear.
        assert!(parse_facet_entry("update_record", "triage", &json!("x"), false).is_ok());
        assert!(parse_facet_entry("update_record", "triage", &json!(Value::Null), true).is_ok());
    }
}

#[cfg(test)]
mod session_version_roundtrip_tests {
    use super::*;
    use crate::coedit::version_metadata::VersionMetadata;
    use crate::coedit::{
        AcknowledgedContributor, DrainOutcome, OpenOk, OpenParams, PeerKind, SessionRegistry,
        VersionSnapshot,
    };
    use yrs::updates::decoder::Decode;
    use yrs::updates::encoder::Encode;
    use yrs::{Doc, GetString, OffsetKind, Options, ReadTxn, Text, Transact, Update};

    // Test-owned, isolated SQLite composition only: one Db and one registry,
    // no competing writers. This does not implement production ownership,
    // peer Caller ingress, live ordinary-write fencing, or cancellation safety.
    struct Fixture {
        _directory: tempfile::TempDir,
        db: Db,
        tools: ToolRegistry,
        caller: Caller,
        id: String,
    }

    type EventFingerprint = (i64, String, String, Option<String>, Option<String>);
    type LedgerFingerprint = (
        String,
        Vec<u8>,
        Vec<AcknowledgedContributor>,
        Option<AcknowledgedContributor>,
    );

    // Exact committed state, including the event token and action allocation.
    #[derive(Debug, PartialEq, Eq)]
    struct Durable {
        body: String,
        events: Vec<EventFingerprint>,
        version: i64,
        act: i64,
    }

    impl Fixture {
        async fn new(body: &str, html: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("version-proof.sqlite");
            let db = crate::create_database(path.to_str().unwrap())
                .await
                .unwrap();
            let mut tools = ToolRegistry::new();
            crate::mcp::register_surface_tools(&mut tools).unwrap();
            let mut args = json!({
                "type": "Document", "kind": if html { "artifact" } else { "note" },
                "name": "isolated version composition", "body": body,
                "reason": "bootstrap isolated test record"
            });
            if html {
                args["facets"] = json!({"runtime": "native.html.v1"});
            }
            // Legacy-local authority is used ONLY for fixture creation. It
            // proves neither authenticated create nor a production grant.
            let created = tools
                .call(db.clone(), Caller::local(), "create_record", args)
                .await
                .unwrap();
            let id = created["id"].as_str().unwrap().to_owned();
            crate::authorization::replace_explicit_policy(
                &db,
                "test:version-proof-bootstrap",
                &id,
                vec![AllowEntry::account("acct:alice", Capability::Edit)],
            )
            .await
            .unwrap();
            Self {
                _directory: directory,
                db,
                tools,
                caller: Caller::authenticated("acct:alice"),
                id,
            }
        }

        async fn ordinary_set(&self, body: &str, digest: &str) -> Result<Value> {
            self.tools
                .call(
                    self.db.clone(),
                    self.caller.clone(),
                    "update_record",
                    json!({
                        "id": self.id, "body_set": body, "if_body_digest": digest,
                        "reason": "ordinary authenticated body replacement"
                    }),
                )
                .await
        }

        async fn durable(&self) -> Durable {
            let body = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
                .bind(&self.id)
                .fetch_one(self.db.pool())
                .await
                .unwrap();
            let events: Vec<EventFingerprint> =
                sqlx::query_as("SELECT seq, id, type, payload, actor FROM content_events WHERE record_id = ? ORDER BY seq")
                    .bind(&self.id).fetch_all(self.db.pool()).await.unwrap();
            let version = events.last().unwrap().0;
            Durable {
                body,
                events,
                version,
                act: self.db.current_act().await.unwrap(),
            }
        }

        fn open(&self, core: &mut SessionRegistry, body: &str) -> Peer {
            let joined = core
                .open(OpenParams {
                    database_id: "isolated-fixture-db".into(),
                    record_id: self.id.clone(),
                    committed_body: body.into(),
                    kind: PeerKind::Edit,
                    record_supported: true,
                })
                .unwrap();
            let mut options =
                Options::with_client_id(yrs::ClientID::new(u64::from(joined.client_ids[0])));
            options.offset_kind = OffsetKind::Bytes;
            let doc = Doc::with_options(options);
            doc.get_or_insert_text("body");
            doc.transact_mut()
                .apply_update(Update::decode_v1(&joined.sync_step2).unwrap())
                .unwrap();
            Peer { joined, doc }
        }
    }

    struct Peer {
        joined: OpenOk,
        doc: Doc,
    }

    impl Peer {
        fn replace(&self, core: &mut SessionRegistry, body: &str, who: &AcknowledgedContributor) {
            // Catch up from the REAL registry, retaining this peer's author
            // clock rather than manufacturing a fresh clock-zero document.
            let vector = self.doc.transact().state_vector().encode_v1();
            let diff = core.encode_diff(&self.joined.session_id, &vector).unwrap();
            self.doc
                .transact_mut()
                .apply_update(Update::decode_v1(&diff).unwrap())
                .unwrap();
            let before = self.doc.transact().state_vector();
            let text = self.doc.get_or_insert_text("body");
            {
                let mut tx = self.doc.transact_mut();
                let length = text.len(&tx);
                text.remove_range(&mut tx, 0, length);
                text.insert(&mut tx, 0, body);
            }
            let update = self.doc.transact().encode_diff_v1(&before);
            core.apply_update_attributed(
                &self.joined.session_id,
                &self.joined.peer_id,
                &update,
                who,
            )
            .unwrap();
            assert_eq!(text.get_string(&self.doc.transact()), body);
            assert_eq!(core.live_body(&self.joined.session_id).unwrap(), body);
        }
    }

    fn contributor(principal: &str, executor_kind: &str) -> AcknowledgedContributor {
        // Correlation facts only. The separate authenticated request Caller
        // and its actual SQLite policy authorize the append.
        AcknowledgedContributor {
            principal: principal.into(),
            executor_kind: executor_kind.into(),
        }
    }

    fn metadata(snapshot: &VersionSnapshot) -> VersionMetadata<'_> {
        VersionMetadata {
            contributors: snapshot.contributors(),
            session_ref: &snapshot.session_id().0,
            merged_offline: false,
        }
    }

    fn ledger(core: &SessionRegistry, peer: &Peer) -> LedgerFingerprint {
        let session = &peer.joined.session_id;
        (
            core.live_body(session).unwrap(),
            core.state_vector(session).unwrap(),
            core.acknowledged_contributors(session).unwrap(),
            core.last_accepted_contributor(session).unwrap(),
        )
    }

    struct Prepared {
        tx: Transaction<'static, Sqlite>,
        event: crate::events::EventRow,
        version: i64,
    }

    // Private test consumer: no public ingress, CAS bypass for the ordinary
    // path, or automatic actor. Explicit cuts have no version-token CAS.
    async fn prepare_cut(
        fixture: &Fixture,
        caller: &Caller,
        snapshot: &VersionSnapshot,
        metadata: &VersionMetadata<'_>,
    ) -> Result<Prepared> {
        let mut tx = crate::db::begin_write(fixture.db.write_pool()).await?;
        let result: Result<(crate::events::EventRow, i64)> = async {
            require_record_in(
                &mut tx,
                caller,
                "update_record",
                &fixture.id,
                Capability::Edit,
            )
            .await?;
            let reason = "explicit isolated test version";
            require_nonblank_reason("update_record", reason)?;
            let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
            let before = required_violations_in(&mut tx, &schema_rows, &[&fixture.id]).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            let fields = json!({"body": snapshot.body(), "reason": reason})
                .as_object()
                .unwrap()
                .clone();
            let outcome = record_update_in(RecordUpdateInput {
                db: &fixture.db,
                tx: &mut tx,
                act_alloc: &mut act_alloc,
                caller,
                tool: "update_record",
                record_id: &fixture.id,
                fields,
                version_metadata: Some(metadata),
                has_kind: false,
                has_lifecycle: false,
                has_summary: false,
                facet_specs: Vec::new(),
                facet_writes: &[],
                facet_unsets: &BTreeSet::new(),
                schema_rows: &schema_rows,
                links: &[],
                relationship_link_indexes: &BTreeSet::new(),
                before: &before,
            })
            .await?;
            assert!(
                !outcome.non_body_changed,
                "reserved metadata must be assembled after ordinary change classification"
            );
            let event = outcome
                .record_event
                .expect("body cut appended a real event");
            let version = current_record_version_in(&mut tx, &fixture.id).await?;
            Ok((event, version))
        }
        .await;
        match result {
            Ok((event, version)) => Ok(Prepared { tx, event, version }),
            Err(error) => {
                tx.rollback().await?;
                Err(error)
            }
        }
    }

    #[tokio::test]
    async fn ordinary_cas_then_authenticated_snapshot_commit_and_drain() {
        let fixture = Fixture::new("seed", false).await;
        let ordinary = "A😀漢e\u{301}\r\nZ";
        let ordinary_result = fixture
            .ordinary_set(ordinary, &body_digest(Some("seed")))
            .await
            .unwrap();
        assert_eq!(
            ordinary_result["body_digest"],
            json!(body_digest(Some(ordinary)))
        );
        let before = fixture.durable().await;
        assert_eq!(before.body, ordinary);
        let payload: Value =
            serde_json::from_str(before.events.last().unwrap().3.as_ref().unwrap()).unwrap();
        for key in ["contributors", "session", "merged_offline"] {
            assert!(payload.get(key).is_none());
        }
        assert_eq!(
            before.events.last().unwrap().4.as_deref(),
            Some("acct:alice")
        );
        let error = fixture
            .ordinary_set("stale intent", &body_digest(Some("seed")))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("body_digest"));
        assert_eq!(fixture.durable().await, before);

        // Both ordinary requests completed BEFORE opening a live session.
        let mut core = SessionRegistry::new();
        let first = fixture.open(&mut core, ordinary);
        let second = fixture.open(&mut core, ordinary);
        let zoe = contributor("acct:zoe", "agent");
        let bea = contributor("acct:bea", "human");
        first.replace(&mut core, "A😀漢e\u{301}\r\nZ / first", &zoe);
        let body = "A😀漢e\u{301}\r\nZ / second🧪";
        second.replace(&mut core, body, &bea);
        let snapshot = core.version_snapshot(&first.joined.session_id).unwrap();
        assert_eq!(snapshot.body(), body);
        assert_eq!(snapshot.contributors(), &[bea.clone(), zoe.clone()]);
        assert_eq!(snapshot.last_accepted(), Some(&bea));
        let prepared = prepare_cut(&fixture, &fixture.caller, &snapshot, &metadata(&snapshot))
            .await
            .unwrap();
        assert_eq!(prepared.event.actor.as_deref(), Some("acct:alice"));
        for who in snapshot.contributors() {
            assert_ne!(
                prepared.event.actor.as_deref(),
                Some(who.principal.as_str())
            );
        }
        assert_ne!(
            prepared.event.actor.as_deref(),
            Some(snapshot.last_accepted().unwrap().principal.as_str())
        );
        assert_eq!(prepared.event.event_type, "record.updated");
        assert_eq!(prepared.event.record_id, fixture.id);
        assert_eq!(prepared.version, prepared.event.local_seq);
        let event = prepared.event.clone();
        let token = prepared.version;
        fixture.db.commit_content(prepared.tx).await.unwrap();
        // The exclusively borrowed test registry cannot interleave another
        // writer. Drain synchronously ONLY after commit_content succeeds.
        assert_eq!(
            core.drain_version_snapshot(&snapshot).unwrap(),
            DrainOutcome::Drained
        );
        let after = fixture.durable().await;
        assert_eq!(after.body.as_bytes(), body.as_bytes());
        assert_eq!(
            body_digest(Some(&after.body)),
            body_digest(Some(snapshot.body()))
        );
        assert_eq!(after.version, token);
        assert_eq!(after.events.len(), before.events.len() + 1);
        assert_eq!(after.events.last().unwrap().1, event.id);
        let payload: Value =
            serde_json::from_str(after.events.last().unwrap().3.as_ref().unwrap()).unwrap();
        assert_eq!(payload["body"], json!(body));
        assert_eq!(payload["reason"], json!("explicit isolated test version"));
        assert_eq!(payload["session"], json!(snapshot.session_id().0));
        assert_eq!(
            payload["contributors"],
            json!([
                {"principal":"acct:bea", "executor_kind":"human"},
                {"principal":"acct:zoe", "executor_kind":"agent"}
            ])
        );
        assert!(payload.get("merged_offline").is_none());
        assert!(payload["contributors"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row.get("run_key").is_none()));
        assert_eq!(core.live_body(&first.joined.session_id).unwrap(), body);
        assert!(core
            .acknowledged_contributors(&first.joined.session_id)
            .unwrap()
            .is_empty());
        assert_eq!(
            core.last_accepted_contributor(&first.joined.session_id)
                .unwrap(),
            Some(bea)
        );
        first.replace(&mut core, &format!("{body}!"), &zoe);
        assert_eq!(
            core.acknowledged_contributors(&first.joined.session_id)
                .unwrap(),
            vec![zoe.clone()]
        );
        assert_eq!(
            core.last_accepted_contributor(&first.joined.session_id)
                .unwrap(),
            Some(zoe)
        );
        assert_eq!(
            fixture.durable().await,
            after,
            "next live mutation is not durable until another cut"
        );
        fixture.db.close().await;
    }

    #[tokio::test]
    async fn denied_caller_and_invalid_metadata_preserve_durable_state_and_ledger() {
        let fixture = Fixture::new("seed", false).await;
        let before = fixture.durable().await;
        let mut core = SessionRegistry::new();
        let peer = fixture.open(&mut core, &before.body);
        peer.replace(&mut core, "pending漢😀", &contributor("acct:zoe", "agent"));
        let snapshot = core.version_snapshot(&peer.joined.session_id).unwrap();
        let pending = ledger(&core, &peer);
        let stranger = Caller::authenticated("acct:stranger");
        let error = prepare_cut(&fixture, &stranger, &snapshot, &metadata(&snapshot))
            .await
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            format!("update_record: record {} does not exist", fixture.id)
        );
        assert_eq!(fixture.durable().await, before);
        assert_eq!(ledger(&core, &peer), pending);
        let invalid = VersionMetadata {
            contributors: snapshot.contributors(),
            session_ref: "",
            merged_offline: false,
        };
        let error = prepare_cut(&fixture, &fixture.caller, &snapshot, &invalid)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("session"));
        assert_eq!(fixture.durable().await, before);
        assert_eq!(ledger(&core, &peer), pending);
        fixture.db.close().await;
    }

    #[tokio::test]
    async fn native_html_validator_rejects_ordinary_none_and_snapshot_some_identically() {
        // Named minimal HTML precedent: artifacts::html_parent_origin_binds_live_and_historical_legacy_and_named_delivery,
        // the "Parent fixture" document (no renderer/configuration needed).
        let valid = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Parent fixture</title></head><body><main><h1>Parent fixture</h1></main></body></html>";
        let fixture = Fixture::new(valid, true).await;
        let shape: (String, String, String) = sqlx::query_as(
            "SELECT r.type, r.kind, f.value FROM records r JOIN facet_values f ON f.record_id=r.id AND f.key='runtime' WHERE r.id=?")
            .bind(&fixture.id).fetch_one(fixture.db.pool()).await.unwrap();
        assert_eq!(
            shape,
            (
                "Document".into(),
                "artifact".into(),
                "native.html.v1".into()
            )
        );
        let before = fixture.durable().await;
        let invalid = "not an HTML document";
        let ordinary = fixture
            .ordinary_set(invalid, &body_digest(Some(valid)))
            .await
            .unwrap_err();
        assert!(ordinary.to_string().contains("[html_invalid_document]"));
        assert_eq!(fixture.durable().await, before);
        let mut core = SessionRegistry::new();
        let peer = fixture.open(&mut core, valid);
        peer.replace(&mut core, invalid, &contributor("acct:zoe", "agent"));
        let snapshot = core.version_snapshot(&peer.joined.session_id).unwrap();
        let pending = ledger(&core, &peer);
        let cut = prepare_cut(&fixture, &fixture.caller, &snapshot, &metadata(&snapshot))
            .await
            .err()
            .unwrap();
        assert_eq!(cut.to_string(), ordinary.to_string());
        assert_eq!(fixture.durable().await, before);
        assert_eq!(ledger(&core, &peer), pending);
        fixture.db.close().await;
    }

    #[tokio::test]
    async fn successful_private_append_then_explicit_rollback_does_not_drain() {
        // Ordering/rollback proof, explicitly NOT commit-failure coverage.
        let fixture = Fixture::new("durable", false).await;
        let before = fixture.durable().await;
        let mut core = SessionRegistry::new();
        let peer = fixture.open(&mut core, &before.body);
        peer.replace(
            &mut core,
            "uncommitted😀\r\n漢",
            &contributor("acct:zoe", "agent"),
        );
        let snapshot = core.version_snapshot(&peer.joined.session_id).unwrap();
        let pending = ledger(&core, &peer);
        let mut prepared = prepare_cut(&fixture, &fixture.caller, &snapshot, &metadata(&snapshot))
            .await
            .unwrap();
        let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(&fixture.id)
            .fetch_one(&mut *prepared.tx)
            .await
            .unwrap();
        assert_eq!(body, snapshot.body());
        assert!(prepared.version > before.version);
        let event_id: String = sqlx::query_scalar("SELECT id FROM content_events WHERE seq=?")
            .bind(prepared.version)
            .fetch_one(&mut *prepared.tx)
            .await
            .unwrap();
        assert_eq!(
            event_id, prepared.event.id,
            "append genuinely happened inside the transaction"
        );
        prepared.tx.rollback().await.unwrap();
        assert_eq!(fixture.durable().await, before);
        assert_eq!(ledger(&core, &peer), pending);
        fixture.db.close().await;
    }
}
