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
    echo_previous_seq, parse_args, previous_record_seq_in, require_nonblank_reason, require_record,
    require_record_in, PREVIOUS_SEQ_DESCRIPTION, REASON_DESCRIPTION,
};

/// Cap on one `get_record` batch.
const MAX_BATCH_GET: usize = 100;

/// Multi-target `update_record` deliberately shares the ordinary read-batch
/// ceiling: the caller names a closed cohort, validation stays bounded, and a
/// successful receipt can preserve one input-correlated row per target.
const MAX_MULTI_UPDATE: usize = 100;

/// Atomic multi-target rejections keep diagnostics useful without echoing an
/// unbounded cohort through the error channel.
const MAX_MULTI_UPDATE_FAILURE_DETAILS: usize = 20;

fn html_body_write_result(manifest: &crate::artifact_html::Manifest, source: &str) -> Value {
    json!({
        "algorithm": "sha256",
        "sha256": manifest.body_digest,
        "utf8_bytes": manifest.body_utf8_bytes,
        "characters": source.chars().count(),
    })
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
    let message = match status.as_str() {
        "artifact_inputs_carried_forward" => {
            "Input bindings and every compatible capability grant were carried to the new exact source."
        }
        "artifact_inputs_partially_carried" => {
            "Input bindings were carried, but grants whose exact request or module path no longer verified were dropped; restore them with manage_artifact_module_grants."
        }
        "artifact_inputs_dropped_by_declaration_change" => {
            "Input declarations changed, so all bindings and capability grants were dropped; restore them with manage_artifact_inputs and manage_artifact_module_grants."
        }
        _ => "The artifact body changed, but there was no exact current input state to carry.",
    };
    let object = result
        .as_object_mut()
        .ok_or_else(|| Error::engine("update_record returned a non-object result"))?;
    object.insert("artifact_input_continuity".into(), continuity);
    let warning = json!({"code": status, "message": message, "ports": ports});
    match object.get_mut("warnings") {
        Some(Value::Array(warnings)) => warnings.push(warning),
        Some(existing) => {
            *existing = Value::Array(vec![existing.clone(), warning]);
        }
        None => {
            object.insert("warnings".into(), Value::Array(vec![warning]));
        }
    }
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
        return Err(Error::engine(
            "correct_record_type: target_type must be a closed spine type and target_kind must be non-empty",
        ));
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
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(json!({
        "record_id": args.record_id,
        "type": plan.classification().target.record_type,
        "kind": plan.classification().target.kind,
        "mode": mode,
        "event_id": event.id,
        "event_seq": event.local_seq,
        "previous_seq": plan.previous_seq(),
        "body_digest": plan.body_digest(),
    }))
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
/// used by query/type enforcement; everything else remains a JSON string.
/// Incoming sets and unsets then overlay that snapshot before validation.
async fn resulting_facet_writes_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    incoming: &[FacetWrite],
    unsets: &BTreeSet<String>,
) -> Result<Vec<FacetWrite>> {
    let rows = sqlx::query(
        "SELECT key, value, value_num, vocab_ref
         FROM facet_values
         WHERE record_id = ? AND value IS NOT NULL
         ORDER BY key",
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
            Value::String(stored)
        };
        resulting.insert(
            key.clone(),
            FacetWrite {
                key,
                value,
                vocab_ref: row.try_get("vocab_ref")?,
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
pub(super) async fn assert_home_target_in(
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
async fn assert_no_containment_cycle_in(
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
            Ok(serde_json::to_value(record)?)
        }
        None => Err(Error::engine(format!(
            "{tool}: record {id} not readable after write"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tool 5 — create_record
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRecordArgs {
    #[serde(rename = "type")]
    record_type: String,
    /// Required (fbfaf25 §3.1). `String`, not `Option<String>` — serde's missing
    /// -field error IS the enforcement, so the tool is uncallable without it
    /// rather than merely discouraged.
    reason: String,
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
    create_record_inner(db, caller, arguments, None, None).await
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

/// Dedicated delivered-Message entry point.  `create_record` calls the same
/// append kernel but cannot obtain this capability, so it cannot bypass the
/// policy gate by creating a Message directly.
pub(crate) async fn send_message_record(
    db: Db,
    caller: Caller,
    arguments: Value,
    plan: SendMessagePlan,
) -> Result<Value> {
    create_record_inner(db, caller, arguments, Some(plan), None).await
}

async fn create_record_inner(
    db: Db,
    caller: Caller,
    arguments: Value,
    send_plan: Option<SendMessagePlan>,
    artifact_plan: Option<ArtifactCreatePlan>,
) -> Result<Value> {
    const TOOL: &str = "create_record";
    let mut args: CreateRecordArgs = parse_args(TOOL, arguments)?;
    require_nonblank_reason(TOOL, &args.reason)?;
    let lifecycle = args.lifecycle.take();
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
    if let Some(home_id) = &args.home_id {
        assert_home_target_in(&mut tx, TOOL, home_id).await?;
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
    if is_comment {
        let bearer_ids = args
            .links
            .iter()
            .flatten()
            .filter(|link| link.relationship == "part_of")
            .map(|link| link.target_id.clone())
            .collect::<Vec<_>>();
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
        comment_bearers = bearer_ids;
        // Name the state instead of leaving it to absence: a root created with
        // no lifecycle is an FYI, so it stores `informational` rather than
        // null. Replies keep their null — thread state lives on the root.
        if let Some(lifecycle) = crate::comments::created_lifecycle(
            comment_position.expect("a validated comment has a position"),
            fields.get("lifecycle").and_then(Value::as_str),
        ) {
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
    let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
    let mut governed_writes = facets.clone();
    if let Some(lifecycle) = fields.get("lifecycle").and_then(Value::as_str) {
        governed_writes.push(FacetWrite {
            key: "lifecycle".into(),
            value: Value::String(lifecycle.into()),
            vocab_ref: None,
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
        facet.vocab_ref = governed_writes
            .iter()
            .find(|checked| checked.key == facet.key)
            .and_then(|checked| checked.vocab_ref.clone());
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
                    "policy_trace":payload.get("policy_trace").cloned().unwrap_or(Value::Null),
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
        fields.insert(
            "origin".into(),
            json!({
                "kind": "artifact.interaction",
                "artifact_id": plan.artifact_id,
                "entry_id": plan.entry_id,
                "source_digest": plan.source_digest,
                "source_event_id": plan.source_event_id,
                "idempotency_key": plan.idempotency_key,
                "intent_digest": plan.intent_digest,
                "invocation_digest": plan.invocation_digest,
                "gesture": plan.gesture,
            }),
        );
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
    )
    .await?;
    for facet in &facets {
        append_in(&db, &mut tx, facet_set_spec(&id, facet, caller.actor())).await?;
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
        )
        .await?;
    }
    let relationship_draft = if relationship_link_indexes.is_empty() {
        None
    } else {
        Some(crate::provenance::reserve_action_attestation()?)
    };
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
        append_in(&db, &mut tx, spec).await?;
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
                )
                .await?;
            }
        }
    }
    let after = required_violations_in(&mut tx, &schema_rows, &[&id]).await?;
    assert_required_not_worsened(TOOL, &before, &after)?;
    if let Some(draft) = relationship_draft {
        crate::provenance::issue_reserved_pending_action_in(&mut tx, draft).await?;
    }
    db.commit_content(tx).await?;

    let mut result = enriched_or_error(&db, &caller, TOOL, &id).await?;
    if let Some((_, _, evaluation)) = send_evaluation {
        let database_id = sqlx::query_scalar::<_, String>(
            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
        )
        .fetch_one(db.write_pool())
        .await?;
        result.as_object_mut().expect("enriched record object").insert(
            "delivery".into(),
            json!({
                "status":if delivered{"delivered"}else{"blocked"},
                "delivered":delivered,
                "disposition":evaluation.disposition,
                "policy_trace":evaluation.trace,
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
    let mut created = attach_html_body_write(echo_previous_seq(result, None)?, html_body_write)?;
    annotate_body_digest(&mut created);
    Ok(created)
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
    if runtime.as_deref() != Some(mdx_v2::RUNTIME_ID) {
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

pub(super) async fn filter_enriched_record_with_auth(
    record_db: &Db,
    auth_db: &Db,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
) -> Result<()> {
    filter_enriched_record_with_auth_in_pools(
        record_db.write_pool(),
        auth_db.write_pool(),
        caller,
        record,
        opts,
    )
    .await
}

async fn filter_enriched_record_with_auth_in_pools(
    record_pool: &sqlx::SqlitePool,
    auth_pool: &sqlx::SqlitePool,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
) -> Result<()> {
    let authored_home = record.record.home_id.clone();
    record.custody_boundary = crate::query::tree::custody_boundary_in_pool(
        auth_pool,
        &record.record.id,
        authored_home.as_deref(),
    )
    .await?;
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
    let child_rows = sqlx::query(&format!(
        "SELECT r.id, r.type, r.kind, r.name,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r WHERE r.home_id = ? AND r.deleted_at IS NULL AND {}
          ORDER BY r.name, r.id",
        crate::query::not_hidden_predicate("r")
    ))
    .bind(ARCHIVED_FACET_KEY)
    .bind(&record.record.id)
    .fetch_all(record_pool)
    .await?;
    let mut authorized_children = Vec::new();
    for row in child_rows {
        let id: String = row.try_get("id")?;
        if super::can_record_in_pool(auth_pool, caller, &id, Capability::View).await? {
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
    let mut outbound = Vec::new();
    for link in all_links.links_out {
        if super::can_record_in_pool(auth_pool, caller, &link.target_id, Capability::View).await? {
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
        if super::can_record_in_pool(auth_pool, caller, &link.source_id, Capability::View).await? {
            inbound.push(link);
        }
    }
    record.links_in_count = inbound.len() as i64;
    record.links_in = inbound
        .into_iter()
        .skip(opts.links_offset as usize)
        .take(opts.links_limit as usize)
        .collect();
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
    let mut snapshot = auth_pool.begin().await?;
    let hydrated = hydrate_contributions_in(&mut snapshot, caller, record).await;
    snapshot.rollback().await?;
    hydrated
}

async fn filter_enriched_record_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
    opts: read::EnrichOptions,
) -> Result<()> {
    let authored_home = record.record.home_id.clone();
    record.custody_boundary =
        crate::query::tree::custody_boundary_in(tx, &record.record.id, authored_home.as_deref())
            .await?;
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
    let child_rows = sqlx::query(&format!(
        "SELECT r.id, r.type, r.kind, r.name,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r WHERE r.home_id = ? AND r.deleted_at IS NULL AND {}
          ORDER BY r.name, r.id",
        crate::query::not_hidden_predicate("r")
    ))
    .bind(ARCHIVED_FACET_KEY)
    .bind(&record.record.id)
    .fetch_all(&mut **tx)
    .await?;
    let mut authorized_children = Vec::new();
    for row in child_rows {
        let id: String = row.try_get("id")?;
        if super::can_record_in(tx, caller, &id, Capability::View).await? {
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
    let mut outbound = Vec::new();
    for link in all_links.links_out {
        if super::can_record_in(tx, caller, &link.target_id, Capability::View).await? {
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
        if super::can_record_in(tx, caller, &link.source_id, Capability::View).await? {
            inbound.push(link);
        }
    }
    record.links_in_count = inbound.len() as i64;
    record.links_in = inbound
        .into_iter()
        .skip(opts.links_offset as usize)
        .take(opts.links_limit as usize)
        .collect();
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
    hydrate_contributions_in(tx, caller, record).await
}

/// Attach the generic contribution projection to a record and to every comment
/// still visible on it.
///
/// This runs in the visibility-filtering layer on purpose. The projection is
/// viewer-relative — which run, which principal, which alternative set — so it
/// cannot be built by the projection reader that does not know who is asking.
async fn hydrate_contributions_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    record: &mut read::EnrichedRecord,
) -> Result<()> {
    record.contribution =
        crate::contribution::contribution_for_record_in(tx, caller, &record.record.id).await?;
    if let Some(comments) = record.comments.as_mut() {
        for comment in comments.iter_mut() {
            comment.contribution =
                crate::contribution::contribution_for_record_in(tx, caller, &comment.id).await?;
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
        let version = source.record_version(&record_id).await?;
        item.as_object_mut()
            .expect("a batch item is an object")
            .insert("version".into(), Value::String(version));
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
            let message_id = item
                .get("id")
                .and_then(Value::as_str)
                .expect("found record always carries id")
                .to_string();
            let derivation = source.expectation(&message_id, caller.actor()).await?;
            item.as_object_mut()
                .expect("found batch item serializes as an object")
                .insert(
                    "message_expectation_state".into(),
                    serde_json::to_value(derivation)?,
                );
        }
        if !resolve {
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

async fn get_record(db: Db, caller: Caller, mut arguments: Value) -> Result<Value> {
    const TOOL: &str = "get_record";
    let as_of = lens::take_as_of(TOOL, &mut arguments)?;
    let args: GetRecordArgs = parse_args(TOOL, arguments)?;
    if as_of.is_some() && args.include_interpretation.unwrap_or(false) {
        return Err(Error::engine(
            "get_record: include_interpretation is not supported with as_of in v1; use read_attributions with as_of_event_seq",
        ));
    }
    let Some(selector) = as_of else {
        return get_record_from_lens(&ReadLens::live(&db), &caller, args).await;
    };
    let resolved = lens::resolve_as_of(&db, selector).await?;
    let scratch = open_database(":memory:").await?;
    let result = async {
        apply_schema(&scratch).await?;
        lens::replay_projection(&db, &scratch, resolved.resolved_content_seq).await?;
        let read_lens = ReadLens::historical(&scratch, &db, &resolved);
        let mut output = get_record_from_lens(&read_lens, &caller, args).await?;
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
) -> Result<Value> {
    const TOOL: &str = "get_record";
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
    let record_pool = lens.projection().snapshot_pool();
    let auth_pool = lens.meta().snapshot_pool();
    let resolve = args.resolve.unwrap_or(true);
    let mut items = if lens.temporal().is_none() {
        let mut snapshot = record_pool.begin().await?;
        let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
        let result = async {
            let mut items =
                read::get_records_live_in(&mut snapshot, lens, &args.ids, opts, principal).await?;
            hide_attribution_batch_items(&mut items);
            for item in &mut items {
                let read::BatchGetItem::Found(record) = item else {
                    continue;
                };
                filter_enriched_record_in(&mut snapshot, caller, record, opts).await?;
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
            if !super::can_record_in_pool(auth_pool, caller, &record.record.id, Capability::View)
                .await?
            {
                let id = record.record.id.clone();
                *item = read::BatchGetItem::NotFound { id };
                continue;
            }
            filter_enriched_record_with_auth_in_pools(record_pool, auth_pool, caller, record, opts)
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
    annotate_display_references_in_pool(auth_pool, &mut items).await?;
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
    });
    if include_interpretation {
        output
            .as_object_mut()
            .expect("get_record response is an object")
            .insert("include_interpretation".into(), Value::Bool(true));
    }
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
async fn annotate_display_references_in_pool(
    pool: &sqlx::SqlitePool,
    items: &mut Value,
) -> Result<()> {
    let array = items
        .as_array_mut()
        .expect("batch get serializes as an array");
    let ids = collect_record_path_annotation_ids(array);
    let references = batch_display_references_in_pool(pool, &ids).await?;
    for item in array {
        if item.get("status").and_then(Value::as_str) != Some("found") {
            continue;
        }
        apply_record_path_annotations(item, &references)?;
        apply_enriched_record_path_annotations(item, &references)?;
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
    #[serde(default, deserialize_with = "present")]
    name: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    body: Option<Value>,
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
/// may only offer a `corrected_envelope` for envelope-shaped validation
/// failures, and synthesising `if_body_digest` from current state would hand
/// the caller a token it never read — silently reproducing the lost update the
/// guard exists to prevent. Reconciliation is the caller's judgement.
pub fn unguarded_body_write_error(tool: &str, target: &BodyGuardTarget) -> Error {
    Error::engine(format!(
        "{tool}: unguarded whole-body write refused — {} already has a non-empty body, so 'body' \
         must be accompanied by 'if_body_digest' and/or 'if_unmodified_since' (both must match \
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
/// reaches the executor as `execution_error`, so `corrected_envelope` stays
/// null and `retry_ready` false here exactly as for the other two.
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
            return Err(Error::engine(format!(
                "{tool}: body_replace[{index}].old matched 0 occurrences"
            )));
        }

        if let Some(expected) = op.expected_count {
            if count != expected {
                return Err(Error::engine(format!(
                    "{tool}: body_replace[{index}] expected {expected} occurrences but matched {count}"
                )));
            }
            result = result.replace(&op.old, &op.new);
        } else if op.replace_all == Some(true) {
            result = result.replace(&op.old, &op.new);
        } else {
            if count != 1 {
                return Err(Error::engine(format!(
                    "{tool}: body_replace[{index}].old matched {count} occurrences; set replace_all: true or expected_count: {count}"
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

async fn facet_state_in(
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
            append_in(&db, &mut tx, spec).await?;
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
    Ok(json!({
        "requested": args.ids.len(),
        "changed": changed,
        "unchanged": args.ids.len() - changed,
        "results": results,
    }))
}

async fn update_record(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    if arguments.get("ids").is_some() {
        Box::pin(update_record_multi(db, caller, arguments)).await
    } else {
        Box::pin(update_record_singular(db, caller, arguments)).await
    }
}

async fn update_record_singular(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "update_record";
    let args: UpdateRecordArgs = parse_args(TOOL, arguments)?;
    require_nonblank_reason(TOOL, &args.reason)?;
    let touches_message_expectation = args.facets.as_ref().is_some_and(|facets| {
        facets.contains_key(crate::message_expectation::EXPECTATION_FACET_KEY)
    });

    if args.body.is_some() && args.body_replace.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: 'body' and 'body_replace' are mutually exclusive"
        )));
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
                )))
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
    if fields.is_empty() && facet_specs.is_empty() && args.body_replace.is_none() {
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
    if !fields.is_empty() || args.body_replace.is_some() {
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
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
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
        drop(tx);
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
                facet.vocab_ref = checked
                    .get(facet.key.as_str())
                    .and_then(|checked| checked.vocab_ref.clone());
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
            if let Some(vocab_ref) = &facet.vocab_ref {
                spec.payload["vocab_ref"] = json!(vocab_ref);
            }
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
    if args.body.is_some() || args.body_replace.is_some() || args.if_body_digest.is_some() {
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
            args.body.is_some(),
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
            if let Some(ops) = &args.body_replace {
                let current_body = current_body.as_deref().unwrap_or("");
                fields.insert(
                    "body".into(),
                    Value::String(apply_body_replacements(TOOL, current_body, ops)?),
                );
            }
        }
    }
    if let Some((missing, mut target)) = guard_failure {
        // Roll the write transaction back BEFORE minting the display reference:
        // the refusal must not hold `BEGIN IMMEDIATE` open while it scans the
        // id space to make its own error message nicer.
        drop(tx);
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
    let current = sqlx::query(
        "SELECT r.type, r.kind, r.body, r.lifecycle, r.summary, f.value AS runtime
           FROM records r
           LEFT JOIN facet_values f ON f.record_id = r.id AND f.key = 'runtime'
          WHERE r.id = ?",
    )
    .bind(&args.id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{TOOL}: record {} does not exist", args.id)))?;
    let record_type: String = current.try_get("type")?;
    let current_kind: Option<String> = current.try_get("kind")?;
    let current_body: Option<String> = current.try_get("body")?;
    let current_lifecycle: Option<String> = current.try_get("lifecycle")?;
    let current_summary: Option<String> = current.try_get("summary")?;
    let current_runtime: Option<String> = current.try_get("runtime")?;
    let resulting_kind = fields
        .get("kind")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| current_kind.clone());
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
    let resulting_body = match fields.get("body") {
        Some(Value::String(body)) => Some(body.clone()),
        Some(Value::Null) => None,
        _ => current_body.clone(),
    };
    let resulting_lifecycle = match fields.get("lifecycle") {
        Some(Value::String(lifecycle)) => Some(lifecycle.clone()),
        Some(Value::Null) => None,
        _ => current_lifecycle.clone(),
    };
    let resulting_summary = match fields.get("summary") {
        Some(Value::String(summary)) => Some(summary.clone()),
        Some(Value::Null) => None,
        _ => current_summary,
    };
    let current_is_comment = if let Some(kind) = current_kind.as_deref() {
        let resolution = crate::meta::kind::resolve_on(&mut tx, &record_type, kind).await?;
        crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution)
    } else {
        false
    };
    let current_is_suggestion = if let Some(kind) = current_kind.as_deref() {
        let resolution = crate::meta::kind::resolve_on(&mut tx, &record_type, kind).await?;
        crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(&resolution)
    } else {
        false
    };
    let resulting_is_suggestion = if let Some(kind) = resulting_kind.as_deref() {
        let resolution = crate::meta::kind::resolve_on(&mut tx, &record_type, kind).await?;
        crate::generated::kinds::CoreKind::AnnotationSuggestion.matches(&resolution)
    } else {
        false
    };
    if resulting_is_suggestion && args.lifecycle.is_some() {
        if let Some(lifecycle) = resulting_lifecycle.as_deref() {
            let mut write = [FacetWrite {
                key: "lifecycle".into(),
                value: Value::String(lifecycle.into()),
                vocab_ref: None,
            }];
            assert_facet_value_predicates_in(
                &mut tx,
                &schema_rows,
                TOOL,
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
            let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut tx);
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
        TOOL,
        current_is_suggestion,
        resulting_is_suggestion,
        current_lifecycle.as_deref(),
        resulting_lifecycle.as_deref(),
        args.lifecycle.is_some(),
        current_lifecycle_is_active,
    )?;
    let resulting_runtime = if facet_unsets.contains("runtime") {
        None
    } else {
        facet_writes
            .iter()
            .find(|facet| facet.key == "runtime")
            .map(FacetWrite::stored_value)
            .or(current_runtime.clone())
    };
    validate_prospective_program(
        TOOL,
        &record_type,
        resulting_kind.as_deref(),
        resulting_runtime.as_deref(),
    )?;
    crate::comments::validate_update_on(
        &mut tx,
        TOOL,
        &args.id,
        &record_type,
        current_kind.as_deref(),
        resulting_kind.as_deref(),
        resulting_body.as_deref(),
        current_lifecycle.as_deref(),
        resulting_lifecycle.as_deref(),
        resulting_summary.as_deref(),
        args.kind.is_some(),
        args.lifecycle.is_some(),
        args.summary.is_some(),
    )
    .await?;
    if current_is_comment && (args.kind.is_some() || args.lifecycle.is_some()) {
        if let Some(lifecycle) = resulting_lifecycle.as_deref() {
            let mut write = [FacetWrite {
                key: "lifecycle".into(),
                value: Value::String(lifecycle.into()),
                vocab_ref: None,
            }];
            assert_facet_value_predicates_in(
                &mut tx,
                &schema_rows,
                TOOL,
                &record_type,
                resulting_effective_kind.as_deref(),
                None,
                &mut write,
            )
            .await?;
        }
    }
    let html_manifest = super::artifacts::validate_prospective_html(
        TOOL,
        &record_type,
        resulting_kind.as_deref(),
        resulting_runtime.as_deref(),
        resulting_body.as_deref(),
    )?;
    let html_body_write = html_manifest
        .map(|manifest| html_body_write_result(&manifest, resulting_body.as_deref().unwrap()));
    let updates_instruction_body = fields.contains_key("body");
    let artifact_attestation = super::artifacts::validate_prospective_artifact(
        &args.id,
        &record_type,
        resulting_kind.as_deref(),
        resulting_body.as_deref(),
        resulting_runtime.as_deref(),
    )
    .await?;
    let source_changed = fields.get("body").is_some();
    let continuity_eligible = source_changed
        && artifact_attestation.is_some()
        && record_type == "Document"
        && current_kind.as_deref() == Some("artifact")
        && current_runtime
            .as_deref()
            .is_some_and(super::artifacts::supports_named_input_runtime);
    let continuity_snapshot = if continuity_eligible {
        snapshot_artifact_input_continuity(&mut tx, &args.id).await?
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
                &args.id,
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
    let mut artifact_input_continuity = None;
    let record_event = if !fields.is_empty() {
        Some(
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: args.id.clone(),
                    event_type: "record.updated".into(),
                    payload: Value::Object(fields),
                    actor: Some(caller.actor().into()),
                },
            )
            .await?,
        )
    } else {
        None
    };
    for spec in facet_specs {
        append_in(&db, &mut tx, spec).await?;
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
            .bind(&args.id)
            .fetch_one(&mut *tx)
            .await?;
            (row.try_get("id")?, row.try_get("body")?)
        };
        let already_attested: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM artifact_source_attestations
              WHERE artifact_id=? AND source_event_id=?)",
        )
        .bind(&args.id)
        .bind(&source_event_id)
        .fetch_one(&mut *tx)
        .await?;
        if !already_attested {
            let attestation_event_id = Uuid::new_v4().to_string();
            let payload = super::artifacts::artifact_source_attestation_payload(
                &args.id,
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
                &db,
                &mut tx,
                attestation_event_id.clone(),
                AppendSpec {
                    record_id: args.id.clone(),
                    event_type: "artifact.source_attested".into(),
                    payload: serde_json::to_value(payload)?,
                    actor: Some(caller.actor().into()),
                },
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
                        "old_declaration_surface_sha256": old_surface,
                        "new_declaration_surface_sha256": new_surface,
                        "restoration_tools": [],
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
                if old_surface == new_surface {
                    for binding in snapshot.bindings {
                        let new_binding = super::artifacts::carried_input_payload(
                            &args.id,
                            &binding.port_name,
                            &binding.collection_id,
                            &attestation_event_id,
                            &source_event_id,
                            &new_source_sha256,
                            &new_descriptor,
                        )?;
                        append_in(
                            &db,
                            &mut tx,
                            AppendSpec {
                                record_id: args.id.clone(),
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
                        )
                        .await?;
                        carried_bindings += 1;
                    }
                    for predecessor in snapshot.grants {
                        let mut grant = predecessor.payload.clone();
                        if grant.subject_kind == "artifact_source" {
                            grant.subject_event_id = source_event_id.clone();
                            grant.source_sha256 = new_source_sha256.clone();
                        }
                        match super::artifacts::try_build_carried_grant_attestation_in(
                            &mut tx, &caller, &grant,
                        )
                        .await?
                        {
                            Some((attestation, digest)) => {
                                grant.attestation = Some(attestation);
                                grant.attestation_sha256 = Some(digest);
                                append_in(
                                    &db,
                                    &mut tx,
                                    AppendSpec {
                                        record_id: args.id.clone(),
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
                                )
                                .await?;
                                carried_grants += 1;
                            }
                            None => {
                                append_in(
                                    &db,
                                    &mut tx,
                                    AppendSpec {
                                        record_id: args.id.clone(),
                                        event_type: "artifact.module_grant_unset".into(),
                                        payload: serde_json::to_value(predecessor.payload)?,
                                        actor: Some(caller.actor().into()),
                                    },
                                )
                                .await?;
                                dropped_grants += 1;
                            }
                        }
                    }
                } else {
                    for binding in snapshot.bindings {
                        append_in(
                            &db,
                            &mut tx,
                            AppendSpec {
                                record_id: args.id.clone(),
                                event_type: "artifact.input_unbound".into(),
                                payload: serde_json::to_value(ArtifactInputUnboundPayload {
                                    artifact_id: args.id.clone(),
                                    port_name: binding.port_name,
                                })?,
                                actor: Some(caller.actor().into()),
                            },
                        )
                        .await?;
                        dropped_bindings += 1;
                    }
                    for grant in snapshot.grants {
                        append_in(
                            &db,
                            &mut tx,
                            AppendSpec {
                                record_id: args.id.clone(),
                                event_type: "artifact.module_grant_unset".into(),
                                payload: serde_json::to_value(grant.payload)?,
                                actor: Some(caller.actor().into()),
                            },
                        )
                        .await?;
                        dropped_grants += 1;
                    }
                }
                let status = if binding_count == 0 && grant_count == 0 {
                    "artifact_inputs_no_existing_state"
                } else if old_surface != new_surface {
                    "artifact_inputs_dropped_by_declaration_change"
                } else if dropped_grants > 0 {
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
                    "old_declaration_surface_sha256": old_surface,
                    "new_declaration_surface_sha256": new_surface,
                    "restoration_tools": if dropped_bindings > 0 {
                        json!(["manage_artifact_inputs", "manage_artifact_module_grants"])
                    } else if dropped_grants > 0 {
                        json!(["manage_artifact_module_grants"])
                    } else {
                        json!([])
                    },
                }));
            }
        }
    }
    if updates_instruction_body
        && crate::instructions::source_is_active_in(&mut tx, &args.id).await?
    {
        crate::instructions::validate_all_known_stacks_in(&mut tx, TOOL).await?;
    }
    let after = required_violations_in(&mut tx, &schema_rows, &[&args.id]).await?;
    assert_required_not_worsened(TOOL, &before, &after)?;
    db.commit_content(tx).await?;

    // The success response reports the digest of the body it just wrote, so a
    // caller continuing guarded work does not need a second read to obtain the
    // next token.
    let mut updated = attach_artifact_input_continuity(
        attach_html_body_write(
            echo_previous_seq(
                enriched_or_error(&db, &caller, TOOL, &args.id).await?,
                previous_seq,
            )?,
            html_body_write,
        )?,
        artifact_input_continuity,
    )?;
    annotate_body_digest(&mut updated);
    Ok(updated)
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
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(json!({
        "id": args.record_id,
        "owner_id": owner_id,
        "event_id": event.id,
        "event_seq": event.local_seq,
        "previous_seq": previous_seq,
    }))
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
    )
    .await?;
    if record_type == "Message" {
        crate::awareness::withdraw_message_candidates_in(
            &mut tx,
            &args.id,
            "record.deleted",
            &deletion.id,
        )
        .await?;
    }
    db.commit_content(tx).await?;
    let deleted_at = sqlx::query("SELECT deleted_at FROM records WHERE id = ?")
        .bind(&args.id)
        .fetch_one(db.write_pool())
        .await?
        .try_get::<Option<String>, _>("deleted_at")?;
    Ok(json!({
        "id": args.id,
        "deleted": true,
        "deleted_at": deleted_at,
        "previous_seq": previous_seq,
    }))
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
    append_in(&db, &mut tx, spec).await?;
    db.commit_content(tx).await?;
    Ok(json!({
        "id": args.id,
        "archived": want_archived,
        "changed": true,
        "previous_seq": previous_seq,
    }))
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
    let args: RenderRecordArgs = parse_args(TOOL, arguments)?;
    let include_interpretation = args.include_interpretation.unwrap_or(false);
    let (record, names, interpretation) = if include_interpretation {
        let read_lens = ReadLens::live(&db);
        let mut snapshot = db.write_pool().begin().await?;
        let result = async {
            require_record_in(&mut snapshot, &caller, TOOL, &args.id, Capability::View).await?;
            let principal = (!super::is_legacy_local(&caller)).then(|| super::principal(&caller));
            let mut items = read::get_records_live_in(
                &mut snapshot,
                &read_lens,
                std::slice::from_ref(&args.id),
                read::EnrichOptions::default(),
                principal,
            )
            .await?;
            let record = match items.pop() {
                Some(read::BatchGetItem::Found(mut record)) => {
                    filter_enriched_record_in(
                        &mut snapshot,
                        &caller,
                        &mut record,
                        read::EnrichOptions::default(),
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
        let (record, names, interpretation) = finish_read_snapshot(snapshot, result).await?;
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
    let singular = json!({
        "type": "object",
        "description": "Singular update. Replacing a non-empty body requires if_body_digest (copy get_record.body_digest) and/or if_unmodified_since.",
        "properties": {
            "id": { "type": "string" },
            "reason": { "type": "string", "minLength": 1 },
            "name": { "type": "string" },
            "body": { "type": ["string", "null"] },
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
            "kind": { "type": "string", "minLength": 1 },
            "home_id": { "type": "string", "description": "Move to a canonical browse home. Only the engine root may have null." },
            "summary": { "type": ["string", "null"] },
            "lifecycle": { "type": ["string", "null"] },
            "owner_id": { "type": ["string", "null"] },
            "persistence": { "type": "string", "enum": ["enduring", "occurrent"] },
            "maturity": { "type": ["string", "null"] },
            "facets": {
                "type": "object",
                "description": "Open facets: scalar values, schema-validated atomic objects, or null to unset; objects require type:object.",
                "additionalProperties": true
            }
        },
        "required": ["id", "reason"],
        "not": { "required": ["body", "body_replace"] },
        "additionalProperties": false
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
        "Create one record atomically; requires spine type/open kind. preview_record_shape gives \
         optional shape and facet-value advice; creation revalidates live state without a preview token. Messages require \
         immutable audience. Comments require type Annotation, kind comment, nonblank body and \
         exactly one outgoing part_of link. Roots default to informational lifecycle; open is \
         allowed. A reply bears directly on the root comment, inherits context and has null \
         lifecycle. Passage targets require exact text_quote and canonical UTF-8 data_position. \
         Replies stay targetless. Omit summary until resolution.",
        json!({
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": SPINE_TYPES,
                    "description": type_description
                },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION },
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
                "target": crate::mcp::tools::citations::target_schema()
            },
            "required": ["type", "kind", "reason"],
            "additionalProperties": false
        }),
        create_record,
    )?;
    registry.register(
        ToolKind::GetRecord,
        "Batch get by full ids or short record references, with partial \
         success, caller-visible totals, and independently \
         paged enrichments. Comments expose comment_count; include_comments pages \
         direct roots from comments_offset and returns each exact anchored passage. \
         resolve:false skips saved queries; as_of pins content while \
         authorization/schema stay live. include_interpretation:true (default false) \
         adds a live caller-authorized typed projection for <=50 ids; it rejects \
         as_of and request overflow is unavailable without a count. Each found record \
         carries body_digest, the SHA-256 of its stored body (sha256(\"\") when empty or \
         null); copy it into update_record.if_body_digest to replace a whole body safely. \
         No other read surface returns it.",
        json!({
            "type": "object",
            "properties": {
                "ids": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1,
                    "maxItems": MAX_BATCH_GET,
                    "description": "Full ids or short record references to read directly. Use search.query for unknown text or concepts instead."
                },
                "resolve": {
                    "type": "boolean",
                    "description": "Run saved queries one level (default true); false returns has_query only."
                },
                "include_interpretation": {
                    "type": "boolean",
                    "description": "Bounded live interpretation; default false, <=50 ids, rejects as_of."
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
                "as_of": lens::as_of_input_schema()
            },
            "required": ["ids"],
            "additionalProperties": false
        }),
        get_record,
    )?;
    registry.register(
        ToolKind::UpdateRecord,
        &format!("Update one record or atomically patch facets/maturity/home_id for 1–100 exact unique ids; preflight, skip no-ops, ordered. facets=current state; observations: manage_facet_observations.set. if_body_digest guard. Comments: open -> resolved: lifecycle:\"resolved\" + nonblank summary. Tombstones reject. For non-destructive recovery, do not create a v2 copy: compensating updates restore record fields only and are not atomic. {PREVIOUS_SEQ_DESCRIPTION}"),
        update_record_input_schema(),
        update_record,
    )?;
    registry.register(
        ToolKind::ClaimUnownedRecord,
        "Exceptional ownership recovery for one exact, full record id naming a visible, live, ordinary record whose owner_id is null; abbreviated ids are not resolved. Host owners (or the standalone filesystem operator) may claim only for their own uniquely bound portable person identity. Engine records, Messages, semantic Units, derived annotations and attachments are excluded. Already-owned records and retries are refused without writing.",
        json!({
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
        }),
        claim_unowned_record,
    )?;
    registry.register(
        ToolKind::CorrectRecordType,
        "Correct a live record's mistaken spine type through a governed plan. Preparation requires ordinary record edit authority; an autonomous same-run correction retains that authority, while an established or shared-use correction requires explicit record-manage confirmation. The target kind must be supplied explicitly, and execution fails without writing if the record changed after preparation.",
        json!({
            "type": "object",
            "properties": {
                "record_id": { "type": "string" },
                "target_type": { "type": "string", "enum": SPINE_TYPES },
                "target_kind": { "type": "string", "minLength": 1 },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
            },
            "required": ["record_id", "target_type", "target_kind", "reason"],
            "additionalProperties": false
        }),
        correct_record_type,
    )?;
    registry.register(
        ToolKind::DeleteRecord,
        &format!(
            "Soft-delete: sets the deleted_at tombstone; the record is frozen \
         (the projector rejects all further mutation events). No hard delete \
         in v1. {PREVIOUS_SEQ_DESCRIPTION}"
        ),
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
            },
            "required": ["id", "reason"],
            "additionalProperties": false
        }),
        delete_record,
    )?;
    registry.register(
        ToolKind::ArchiveRecord,
        &format!("Archive (archived: true, the default) or restore (archived: false) a \
         record via the engine-reserved archived facet. Archived records drop \
         out of default queries but stay mutable; lifecycle is preserved \
         across the round trip. {PREVIOUS_SEQ_DESCRIPTION}"),
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "archived": { "type": "boolean", "description": "true archives (default), false restores." },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
            },
            "required": ["id", "reason"],
            "additionalProperties": false
        }),
        archive_record,
    )?;
    registry.register(
        ToolKind::RenderRecord,
        "Deterministic record/enrichment Markdown, with no model. \
         include_interpretation:true (default false) adds the same bounded live \
         caller-authorized typed projection and summary.",
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
        render_record,
    )?;
    Ok(())
}
