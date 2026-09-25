#![cfg_attr(
    not(any(feature = "postgres", feature = "turso-local")),
    allow(dead_code, unused_imports)
)]

use std::cmp::Ordering;
use std::collections::BTreeSet;

use chrono::{DateTime, SecondsFormat, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::authorization::{Capability, Principal};
use crate::mcp::registry::Caller;
use crate::portable_sql::{
    BindValue, ColumnSpec, DomainStatementExecutor, ExecutionControl, LogicalType, NormalizedRow,
    NormalizedValue, StatementKind, StatementTemplate,
};
use crate::query::cascade;
use crate::schema::{spine_facet_column, ARCHIVED_FACET_KEY, SPINE_FACET_KEYS};
use crate::store::AppendSpec;
use crate::{Error, Result};

const DEFAULT_OBSERVATION_LIMIT: i64 = 200;
const MAX_OBSERVATION_LIMIT: i64 = 1_000;
const MAX_RESOLVED_VALUES: i64 = 10_000;
const MAX_VOCABULARY_SUGGESTIONS: i64 = 10_000;
const SHAPE_GUARANTEE: &str = "Supported record-writing tools enforce global declared type, values, and governing vocabulary membership absolutely for every outgoing open-facet value, using the resulting kind and the same write-transaction snapshot; global required is enforced post-batch and comparatively (new missing facets are refused, unchanged legacy gaps remain editable); multi is rejected at schema authoring. Collection-scoped declarations are discoverability metadata: resolve_facets on the bearing record may display them, but filing home never contributes schema to a child's product facet context and writers do not enforce them in V1. These checks are forward-only, are not re-run during replay, do not retroactively certify stored values, and can be bypassed through store::append* or direct trusted-filesystem mutation of the ejectable SQLite file; Db::pool() is physically read-only. This response is not a standing data-invariant certificate. V1 rejects declared type on string-carried spine facets.";

/// Physical publication seam for one already governed observation event.
/// The shared fold owns admission and payload meaning; adapters own event
/// position allocation and projection inside their admitted transaction.
pub(crate) trait FacetObservationPort {
    fn lock_facet_revision<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn append_facet_observation<'a>(
        &'a mut self,
        spec: AppendSpec,
        control: &'a ExecutionControl,
    ) -> BoxFuture<'a, Result<i64>>;

    /// The act this transaction allocated, if it has appended anything
    /// canonical yet. The append above allocates exactly once per
    /// transaction; this exposes the value so the write response can echo
    /// the coordinate of the write it just performed.
    fn allocated_act(&self) -> Option<i64> {
        None
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageFacetObservationsArgs {
    Set {
        record_id: String,
        key: String,
        value: Value,
        vocab_ref: Option<String>,
        as_of: String,
        reason: String,
    },
    Unset {
        record_id: String,
        key: String,
        as_of: String,
        reason: String,
    },
    List {
        record_id: String,
        key: String,
        from_as_of: Option<String>,
        to_as_of: Option<String>,
        after_as_of: Option<String>,
        limit: Option<i64>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveFacetsArgs {
    record_id: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuggestFacetValuesArgs {
    facet_key: String,
    record_id: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    kind: Option<String>,
}

fn parse_arguments<T: serde::de::DeserializeOwned>(tool: &str, arguments: Value) -> Result<T> {
    serde_json::from_value(arguments)
        .map_err(|error| Error::engine(format!("invalid arguments for {tool}: {error}")))
}

fn caller_principal(caller: &Caller) -> Principal<'_> {
    if caller.is_trusted_local() && caller.hosting_database().is_none() {
        Principal::trusted_local()
    } else {
        Principal::bound(caller.credential(), caller.is_host_member())
    }
}

fn normalize_timestamp(tool: &str, field: &str, value: &str) -> Result<String> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| {
        Error::engine(format!(
            "{tool}: '{field}' must be an RFC3339 timestamp (for example 2026-08-01T09:30:00Z)"
        ))
    })?;
    Ok(parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn require_nonblank_reason(tool: &str, reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        return Err(Error::engine(format!(
            "{tool}: 'reason' must contain at least one non-whitespace character"
        )));
    }
    Ok(())
}

/// Stable preflight issue code for an exact governed-relationship name used
/// as a facet key. Human-readable text is presentation and may change; this
/// code is API, like `spine_facet_wrong_carrier`.
pub(crate) const GOVERNED_RELATIONSHIP_ISSUE: &str = "governed_relationship_wrong_carrier";
/// Stable preflight issue and receipt-warning code for a listed alias (such
/// as `assignee`) that shadows a governed relationship. Warns, never refuses.
pub(crate) const GOVERNED_ALIAS_ISSUE: &str = "governed_relationship_alias";
/// The one governed carrier for relationship shadows.
pub(crate) const GOVERNED_RELATIONSHIP_SUGGESTED_OPERATION: &str = "manage_relationships.assert";
/// Material behavioural difference between a facet and a governed
/// relationship, surfaced in preflight details and write warnings.
pub(crate) const GOVERNED_RELATIONSHIP_FACET_DIFFERENCE: &str = "A facet does not participate in relationship reads such as assigned-to-me, does not preserve the claimant, cannot be contested, and does not resolve its value to a person record.";

/// The embedded core relationship manifest, parsed and validated once. The
/// manifest is compiled into the binary, so a parse or validation failure is
/// an impossible build-time defect: fail loudly rather than silently
/// disabling the exact-name refusal and alias-warning protections.
fn core_relationship_manifest() -> &'static crate::relationship::CoreRelationshipTypeManifest {
    static MANIFEST: std::sync::OnceLock<crate::relationship::CoreRelationshipTypeManifest> =
        std::sync::OnceLock::new();
    MANIFEST.get_or_init(|| {
        crate::relationship::core_relationship_type_manifest()
            .expect("embedded core relationship manifest is valid")
    })
}

fn governed_relationship_names() -> &'static [String] {
    static NAMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        core_relationship_manifest()
            .relationship_types
            .iter()
            .map(|definition| definition.relationship_type.clone())
            .collect::<Vec<_>>()
    })
}

/// Exact core-manifest relationship name for `key`, derived from
/// `src/relationship/core_relationship_types.json` rather than a hardcoded
/// list, so a new relationship type gets the protection without a code
/// change. No fuzzy matching: substrings and edit-distance neighbours stay
/// honest open facets.
pub(crate) fn governed_relationship_type_for_key(key: &str) -> Option<String> {
    governed_relationship_names()
        .iter()
        .find(|name| name.as_str() == key)
        .cloned()
}

/// Evidence-led alias list. Initially only `assignee -> assigned_to`. Do not
/// add `assigned` without measurement showing it in use as an assignment key
/// (it could honestly be a boolean or a date), and apply the same evidence
/// test to candidates such as `blocked_by` for `blocks`.
pub(crate) fn governed_alias_target(key: &str) -> Option<&'static str> {
    match key {
        "assignee" => Some("assigned_to"),
        _ => None,
    }
}

/// Whether `relationship_type` admits `(record_type, kind)` as its subject.
/// Derived from the core manifest's subject-endpoint allowlist, so a new
/// relationship type's admission travels with its definition. Symmetric types
/// check the participant role; directed types check the subject role.
pub(crate) fn governed_relationship_admits_subject(
    relationship_type: &str,
    record_type: &str,
    kind: Option<&str>,
) -> bool {
    let manifest = core_relationship_manifest();
    let Some(definition) = manifest
        .relationship_types
        .iter()
        .find(|definition| definition.relationship_type == relationship_type)
    else {
        return false;
    };
    let role = if definition.endpoint_semantics == crate::relationship::EndpointSemantics::Symmetric
    {
        "participant"
    } else {
        "subject"
    };
    let Some(rule) = definition
        .endpoints
        .iter()
        .find(|endpoint| endpoint.role == role)
    else {
        return false;
    };
    let kind = kind.unwrap_or_default();
    rule.allowed_record_kinds.iter().any(|allowed| {
        (allowed.record_type == "*" || allowed.record_type == record_type)
            && (allowed.kind == "*" || allowed.kind == kind)
    })
}

/// Structured alias warning for a successful write. Returns `None` for unsets
/// and for subject kinds the governed relationship does not admit.
pub(crate) fn governed_alias_warning(
    facet_key: &str,
    record_type: &str,
    kind: Option<&str>,
    is_unset: bool,
) -> Option<Value> {
    if is_unset {
        return None;
    }
    let relationship_type = governed_alias_target(facet_key)?;
    if !governed_relationship_admits_subject(relationship_type, record_type, kind) {
        return None;
    }
    Some(governed_alias_warning_value(facet_key, relationship_type))
}

pub(crate) fn governed_alias_warning_value(facet_key: &str, relationship_type: &str) -> Value {
    json!({
        "code": GOVERNED_ALIAS_ISSUE,
        "facet_key": facet_key,
        "relationship_type": relationship_type,
        "suggested_operation": GOVERNED_RELATIONSHIP_SUGGESTED_OPERATION,
        "message": format!(
            "Facet '{facet_key}' shadows governed relationship '{relationship_type}': this write did not establish the relationship. Assert it with {op} instead. {diff}",
            op = GOVERNED_RELATIONSHIP_SUGGESTED_OPERATION,
            diff = GOVERNED_RELATIONSHIP_FACET_DIFFERENCE,
        ),
        "facet_behavior_difference": GOVERNED_RELATIONSHIP_FACET_DIFFERENCE,
    })
}

pub(crate) fn governed_relationship_guidance(facet_key: &str, relationship_type: &str) -> String {
    format!(
        "Facet '{facet_key}' shadows governed relationship '{relationship_type}': governed relationships are asserted with {op}, never as facets. {diff}",
        op = GOVERNED_RELATIONSHIP_SUGGESTED_OPERATION,
        diff = GOVERNED_RELATIONSHIP_FACET_DIFFERENCE,
    )
}

/// Alias warnings for one successful facet write batch. Exact governed names
/// never reach here: `parse_facet_entry` refuses them before commit. Unsets
/// are quiet, kinds the relationship does not admit are quiet, and an
/// existing governed relationship does not suppress the warning — the
/// redundancy is the problem, not only the absence.
///
/// Backend-neutral: it reads only the parsed writes and the admitted
/// type/kind, so the SQLite, Postgres and Turso adapters share it.
pub(crate) fn governed_alias_warnings_for_sets(
    facets: &[FacetWrite],
    record_type: &str,
    kind: Option<&str>,
) -> Vec<Value> {
    facets
        .iter()
        .filter_map(|facet| governed_alias_warning(&facet.key, record_type, kind, false))
        .collect()
}

/// Append one structured warning to a write receipt's `warnings` array,
/// creating the array when absent. Mirrors the artifact-continuity precedent.
/// Backend-neutral over the JSON receipt: every adapter's summary projection
/// preserves a `warnings` array, and verbose shapes return the receipt as is.
pub(crate) fn push_receipt_warning(result: &mut Value, warning: Value) -> Result<()> {
    let object = result
        .as_object_mut()
        .ok_or_else(|| Error::engine("write receipt returned a non-object result"))?;
    match object.get_mut("warnings") {
        Some(Value::Array(warnings)) => warnings.push(warning),
        Some(existing) => {
            *existing = Value::Array(vec![existing.clone(), warning]);
        }
        None => {
            object.insert("warnings".into(), Value::Array(vec![warning]));
        }
    }
    Ok(())
}

pub(crate) fn push_receipt_warnings(result: &mut Value, warnings: Vec<Value>) -> Result<()> {
    for warning in warnings {
        push_receipt_warning(result, warning)?;
    }
    Ok(())
}

/// Correlate one alias warning with its batch position, following the
/// `create_many` precedent of index-tagged warnings. `id` names the target
/// record; batch cohorts have no stable `ref` of their own.
pub(crate) fn index_warning_for_batch(index: usize, id: &str, mut warning: Value) -> Value {
    if let Some(object) = warning.as_object_mut() {
        object.insert("index".into(), json!(index));
        object.insert("id".into(), json!(id));
    }
    warning
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FacetKeyClassification {
    Open,
    Spine { create_record_path: &'static str },
    EngineReserved,
    GovernedRelationship { relationship_type: String },
}

pub(crate) fn classify_facet_key(key: &str) -> FacetKeyClassification {
    if key == ARCHIVED_FACET_KEY
        || key == crate::blob::BLOB_REF_FACET_KEY
        || key == crate::canvas::PROMOTED_FROM_FACET_KEY
    {
        FacetKeyClassification::EngineReserved
    } else if let Some(create_record_path) = spine_facet_column(key) {
        FacetKeyClassification::Spine { create_record_path }
    } else if let Some(relationship_type) = governed_relationship_type_for_key(key) {
        FacetKeyClassification::GovernedRelationship { relationship_type }
    } else {
        FacetKeyClassification::Open
    }
}

pub(crate) fn assert_open_facet_key(tool: &str, key: &str) -> Result<()> {
    if key == ARCHIVED_FACET_KEY {
        return Err(Error::engine(format!(
            "{tool}: facet '{ARCHIVED_FACET_KEY}' is engine-reserved — archive and restore via the archive_record tool"
        )));
    }
    if key == crate::blob::BLOB_REF_FACET_KEY {
        return Err(Error::engine(format!(
            "{tool}: facet '{}' is engine-reserved — create attachment bindings via the attach_text or attach_from_url tool",
            crate::blob::BLOB_REF_FACET_KEY
        )));
    }
    if key == crate::canvas::PROMOTED_FROM_FACET_KEY {
        return Err(Error::engine(format!(
            "{tool}: facet '{}' is engine-reserved — it records that a record was promoted from a canvas, and only manage_canvas.promote writes it",
            crate::canvas::PROMOTED_FROM_FACET_KEY
        )));
    }
    if let Some(column) = spine_facet_column(key) {
        return Err(Error::engine(format!(
            "{tool}: '{key}' is a spine facet — set it via the top-level '{column}' argument, not 'facets'"
        )));
    }
    if let Some(relationship_type) = governed_relationship_type_for_key(key) {
        return Err(Error::engine(format!(
            "{tool}: facet '{key}' shadows governed relationship '{relationship_type}' — {guidance}",
            guidance = governed_relationship_guidance(key, &relationship_type),
        )));
    }
    Ok(())
}

/// One canonical open-facet mutation after MCP shape parsing but before
/// vocabulary governance. Keeping the caller's JSON type is load-bearing for
/// number and object promises.
#[derive(Clone)]
pub(crate) struct FacetWrite {
    pub(crate) key: String,
    pub(crate) value: Value,
    pub(crate) vocab_ref: Option<String>,
}

impl FacetWrite {
    pub(crate) fn stored_value(&self) -> String {
        match &self.value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            Value::Object(_) => {
                serde_json::to_string(&self.value).expect("a serde_json::Value always serializes")
            }
            _ => unreachable!("facet parsing admits only strings, numbers and objects"),
        }
    }
}

/// Parse the value carrier shared by every `facets` map. Key eligibility and
/// update-only null handling remain with the caller, but the admitted scalar,
/// atomic-object and `{ value, vocab_ref }` grammar has one implementation.
pub(crate) fn parse_facet_write_value(tool: &str, key: &str, value: &Value) -> Result<FacetWrite> {
    match value {
        Value::String(_) | Value::Number(_) => Ok(FacetWrite {
            key: key.into(),
            value: value.clone(),
            vocab_ref: None,
        }),
        Value::Object(object)
            if object
                .keys()
                .all(|key| key == "value" || key == "vocab_ref")
                && object.contains_key("value") =>
        {
            let Some(facet_value @ (Value::String(_) | Value::Number(_) | Value::Object(_))) =
                object.get("value")
            else {
                return Err(Error::engine(format!(
                    "{tool}: facet '{key}' needs a string, number or object 'value'"
                )));
            };
            let vocab_ref = match object.get("vocab_ref") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) => Some(value.clone()),
                Some(_) => {
                    return Err(Error::engine(format!(
                        "{tool}: facet '{key}' vocab_ref must be a string"
                    )))
                }
            };
            Ok(FacetWrite {
                key: key.into(),
                value: facet_value.clone(),
                vocab_ref,
            })
        }
        Value::Object(_) => Ok(FacetWrite {
            key: key.into(),
            value: value.clone(),
            vocab_ref: None,
        }),
        _ => Err(Error::engine(format!(
            "{tool}: facet '{key}' must be a string, number, object or {{ value, vocab_ref }}"
        ))),
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FacetPredicateIssue {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FacetVocabularyIdentity {
    pub(crate) id: String,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FacetVocabularyValueResolution {
    pub(crate) classification: &'static str,
    pub(crate) id: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) canonical_id: Option<String>,
    pub(crate) canonical_value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FacetPredicateAssessment {
    pub(crate) declared: bool,
    pub(crate) accepted: bool,
    pub(crate) declared_type: Option<String>,
    pub(crate) governing_vocabulary: Option<FacetVocabularyIdentity>,
    pub(crate) value_resolution: Option<FacetVocabularyValueResolution>,
    pub(crate) issues: Vec<FacetPredicateIssue>,
}

pub(crate) fn facet_set_spec(record_id: &str, facet: &FacetWrite, actor: &str) -> AppendSpec {
    let mut payload = json!({ "key": facet.key, "value": facet.stored_value() });
    if let Some(vocab_ref) = &facet.vocab_ref {
        payload["vocab_ref"] = json!(vocab_ref);
    }
    AppendSpec {
        record_id: record_id.into(),
        event_type: "facet.set".into(),
        payload,
        actor: Some(actor.into()),
    }
}

fn statement(
    operation: &str,
    relation: &'static str,
    fragments: &'static [&'static str],
) -> Result<StatementTemplate> {
    StatementTemplate::new(StatementKind::Select, relation, fragments)
        .map_err(|error| super::stable_storage_error(operation, &error))
}

async fn fetch<E: DomainStatementExecutor>(
    executor: &mut E,
    operation: &str,
    statement: &StatementTemplate,
    bindings: &[BindValue],
    columns: &[ColumnSpec],
) -> Result<Vec<NormalizedRow>> {
    executor
        .fetch_all(statement, bindings, columns)
        .await
        .map_err(|error| super::stable_storage_error(operation, &error))
}

fn text(row: &NormalizedRow, column: &str, context: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn optional_text(row: &NormalizedRow, column: &str, context: &str) -> Result<Option<String>> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn boolean(row: &NormalizedRow, column: &str, context: &str) -> Result<bool> {
    match row.get(column) {
        Some(NormalizedValue::Bool(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn integer(row: &NormalizedRow, column: &str, context: &str) -> Result<i64> {
    match row.get(column) {
        Some(NormalizedValue::Integer(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

fn real(row: &NormalizedRow, column: &str, context: &str) -> Result<f64> {
    match row.get(column) {
        Some(NormalizedValue::Real(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "{context} state column '{column}' is invalid"
        ))),
    }
}

async fn visible_schema_rows<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
) -> Result<Vec<cascade::SchemaConfigRow>> {
    let rows = cascade::schema_config_rows_with(executor).await?;
    let mut visible = Vec::with_capacity(rows.len());
    for row in rows {
        let allowed = match row.applies_to_collection_id.as_deref() {
            None => true,
            Some(record_id) => {
                crate::authorization::allows_record_with(
                    executor,
                    caller_principal(caller),
                    record_id,
                    Capability::View,
                )
                .await?
            }
        };
        if allowed {
            visible.push(row);
        }
    }
    Ok(visible)
}

async fn require_record<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    tool: Option<&str>,
    record_id: &str,
    capability: Capability,
) -> Result<()> {
    // Governed derived identities are not ordinary record surfaces. Resolve
    // that identity (and the minimum readable shape for comments) before ACL
    // evaluation so an exact id cannot become an existence oracle.
    let eligible = ordinary_record_eligible(executor, record_id).await?;
    if eligible
        && crate::authorization::allows_record_with(
            executor,
            caller_principal(caller),
            record_id,
            capability,
        )
        .await?
    {
        return Ok(());
    }
    let prefix = tool.map(|tool| format!("{tool}: ")).unwrap_or_default();
    Err(Error::engine(format!(
        "{prefix}record {record_id} does not exist"
    )))
}

async fn ordinary_record_eligible<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<bool> {
    let record = statement(
        "read governed facet identity",
        "records",
        &[
            "SELECT type,kind,body,lifecycle,summary,deleted_at FROM {{relation}} WHERE id=",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "read governed facet identity",
        &record,
        &[BindValue::Text(record_id.into())],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::nullable("body", LogicalType::Text),
            ColumnSpec::nullable("lifecycle", LogicalType::Text),
            ColumnSpec::nullable("summary", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
        ],
    )
    .await?;
    let Some(row) = rows.first() else {
        return Ok(false);
    };
    let record_type = text(row, "type", "governed facet identity")?;
    let Some(kind) = optional_text(row, "kind", "governed facet identity")? else {
        return Ok(true);
    };
    let resolution = crate::meta::kind::resolve_with(executor, &record_type, &kind).await?;
    if crate::generated::kinds::CoreKind::AnnotationAttribution.matches(&resolution) {
        return Ok(false);
    }
    if !crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution) {
        return Ok(true);
    }
    if optional_text(row, "deleted_at", "governed facet identity")?.is_some() {
        return Ok(false);
    }
    let body = optional_text(row, "body", "governed facet identity")?;
    let lifecycle = optional_text(row, "lifecycle", "governed facet identity")?;
    let summary = optional_text(row, "summary", "governed facet identity")?;
    let bearer_query = statement(
        "read governed facet identity",
        "links",
        &[
            "SELECT target_id FROM {{relation}} WHERE source_id=",
            " AND relationship='part_of' ORDER BY target_id LIMIT 2",
        ],
    )?;
    let bearers = fetch(
        executor,
        "read governed facet identity",
        &bearer_query,
        &[BindValue::Text(record_id.into())],
        &[ColumnSpec::required("target_id", LogicalType::Text)],
    )
    .await?;
    if bearers.len() != 1 {
        return Ok(false);
    }
    let bearer_id = text(&bearers[0], "target_id", "governed facet identity")?;
    let bearer = fetch(
        executor,
        "read governed facet identity",
        &record,
        &[BindValue::Text(bearer_id.clone())],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::nullable("body", LogicalType::Text),
            ColumnSpec::nullable("lifecycle", LogicalType::Text),
            ColumnSpec::nullable("summary", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
        ],
    )
    .await?;
    let Some(bearer) = bearer.first() else {
        return Ok(false);
    };
    if optional_text(bearer, "deleted_at", "governed facet bearer")?.is_some() {
        return Ok(false);
    }
    let bearer_type = text(bearer, "type", "governed facet bearer")?;
    let bearer_kind = optional_text(bearer, "kind", "governed facet bearer")?;
    let bearer_is_comment = if let Some(kind) = bearer_kind {
        let resolution = crate::meta::kind::resolve_with(executor, &bearer_type, &kind).await?;
        crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution)
    } else {
        false
    };
    let position = if bearer_is_comment {
        let bearer_body = optional_text(bearer, "body", "governed facet bearer")?;
        let bearer_lifecycle = optional_text(bearer, "lifecycle", "governed facet bearer")?;
        let bearer_summary = optional_text(bearer, "summary", "governed facet bearer")?;
        if crate::comments::validate_prospective(
            "get_record",
            crate::comments::Position::Root,
            bearer_body.as_deref(),
            bearer_lifecycle.as_deref(),
            bearer_summary.as_deref(),
        )
        .is_err()
        {
            return Ok(false);
        }
        let root_bearers = fetch(
            executor,
            "read governed facet identity",
            &bearer_query,
            &[BindValue::Text(bearer_id.clone())],
            &[ColumnSpec::required("target_id", LogicalType::Text)],
        )
        .await?;
        if root_bearers.len() != 1 {
            return Ok(false);
        }
        let root_target_id = text(&root_bearers[0], "target_id", "governed facet root bearer")?;
        let root_target = fetch(
            executor,
            "read governed facet identity",
            &record,
            &[BindValue::Text(root_target_id.clone())],
            &[
                ColumnSpec::required("type", LogicalType::Text),
                ColumnSpec::nullable("kind", LogicalType::Text),
                ColumnSpec::nullable("body", LogicalType::Text),
                ColumnSpec::nullable("lifecycle", LogicalType::Text),
                ColumnSpec::nullable("summary", LogicalType::Text),
                ColumnSpec::nullable("deleted_at", LogicalType::Text),
            ],
        )
        .await?;
        let Some(root_target) = root_target.first() else {
            return Ok(false);
        };
        if optional_text(root_target, "deleted_at", "governed facet root bearer")?.is_some() {
            return Ok(false);
        }
        let root_target_type = text(root_target, "type", "governed facet root bearer")?;
        if let Some(root_target_kind) =
            optional_text(root_target, "kind", "governed facet root bearer")?
        {
            let resolution =
                crate::meta::kind::resolve_with(executor, &root_target_type, &root_target_kind)
                    .await?;
            if crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution) {
                return Ok(false);
            }
        }
        if !portable_comment_target_valid(
            executor,
            &bearer_id,
            crate::comments::Position::Root,
            &root_target_id,
        )
        .await?
        {
            return Ok(false);
        }
        crate::comments::Position::Reply
    } else {
        crate::comments::Position::Root
    };
    if !portable_comment_target_valid(executor, record_id, position, &bearer_id).await? {
        return Ok(false);
    }
    Ok(crate::comments::validate_prospective(
        "get_record",
        position,
        body.as_deref(),
        lifecycle.as_deref(),
        summary.as_deref(),
    )
    .is_ok())
}

async fn portable_comment_target_valid<E: DomainStatementExecutor>(
    executor: &mut E,
    comment_id: &str,
    position: crate::comments::Position,
    bearer_id: &str,
) -> Result<bool> {
    let query = statement(
        "read governed comment target",
        "annotation_targets",
        &[
            "SELECT target_record_id,source_slot FROM {{relation}} WHERE annotation_id=",
            " ORDER BY target_record_id,source_slot LIMIT 2",
        ],
    )?;
    let rows = fetch(
        executor,
        "read governed comment target",
        &query,
        &[BindValue::Text(comment_id.into())],
        &[
            ColumnSpec::required("target_record_id", LogicalType::Text),
            ColumnSpec::required("source_slot", LogicalType::Text),
        ],
    )
    .await?;
    if rows.len() > 1 {
        return Ok(false);
    }
    let target = rows
        .first()
        .map(|row| {
            Ok::<_, Error>((
                text(row, "target_record_id", "governed comment target")?,
                text(row, "source_slot", "governed comment target")?,
            ))
        })
        .transpose()?;
    Ok(crate::comments::validate_target_shape(
        "get_record",
        position,
        bearer_id,
        target.as_ref().map(|(target_record_id, source_slot)| {
            (target_record_id.as_str(), source_slot.as_str())
        }),
    )
    .is_ok())
}

async fn record_shape_context<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<(String, Option<String>)> {
    let query = statement(
        "read facet record context",
        "records",
        &["SELECT type,kind FROM {{relation}} WHERE id=", ""],
    )?;
    let rows = fetch(
        executor,
        "read facet record context",
        &query,
        &[BindValue::Text(record_id.into())],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
        ],
    )
    .await?;
    let row = rows.first().ok_or_else(|| {
        Error::engine(format!(
            "manage_facet_observations: record {record_id} does not exist"
        ))
    })?;
    Ok((
        text(row, "type", "facet record")?,
        optional_text(row, "kind", "facet record")?,
    ))
}

async fn previous_record_seq<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<i64> {
    let query = statement(
        "read previous record revision",
        "content_events",
        &[
            "SELECT COALESCE(MAX(seq),0) AS seq FROM {{relation}} WHERE record_id=",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "read previous record revision",
        &query,
        &[BindValue::Text(record_id.into())],
        &[ColumnSpec::required("seq", LogicalType::Integer)],
    )
    .await?;
    integer(&rows[0], "seq", "record revision")
}

#[allow(clippy::too_many_arguments)]
async fn write_observation<E>(
    executor: &mut E,
    caller: &Caller,
    record_id: String,
    key: String,
    value: Option<(Value, Option<String>)>,
    as_of: String,
    reason: String,
    control: &ExecutionControl,
) -> Result<Value>
where
    E: DomainStatementExecutor + FacetObservationPort,
{
    const TOOL: &str = "manage_facet_observations";
    require_nonblank_reason(TOOL, &reason)?;
    let as_of = normalize_timestamp(TOOL, "as_of", &as_of)?;
    assert_open_facet_key(TOOL, &key)?;
    let mut facet = match value {
        Some((value @ (Value::String(_) | Value::Number(_)), vocab_ref)) => Some(FacetWrite {
            key: key.clone(),
            value,
            vocab_ref,
        }),
        Some((_value, _)) => {
            return Err(Error::engine(format!(
                "{TOOL}: facet '{key}' must be a string or number"
            )))
        }
        None => None,
    };

    // The physical adapter serializes the authoritative content revision
    // before any eligibility, previous-seq, schema, or vocabulary read. This
    // makes same-time corrections a single-snapshot compare-and-append fold.
    executor.lock_facet_revision().await?;
    require_record(executor, caller, Some(TOOL), &record_id, Capability::Edit).await?;
    let previous_seq = previous_record_seq(executor, &record_id).await?;
    let (record_type, kind) = record_shape_context(executor, &record_id).await?;
    if let Some(facet) = facet.as_mut() {
        let schema_rows = cascade::schema_config_rows_with(executor).await?;
        govern_facet_writes(
            executor,
            &schema_rows,
            TOOL,
            &record_type,
            kind.as_deref(),
            std::slice::from_mut(facet),
        )
        .await?;
    }

    let (event_type, mut payload, status) = match facet {
        Some(facet) => {
            let mut payload = json!({
                "key": key,
                "value": facet.stored_value(),
                "as_of": as_of,
                "observation_only": true,
            });
            if let Some(vocab_ref) = facet.vocab_ref {
                payload["vocab_ref"] = json!(vocab_ref);
            }
            ("facet.set", payload, "set")
        }
        None => (
            "facet.unset",
            json!({
                "key": key,
                "as_of": as_of,
                "observation_only": true,
            }),
            "unset",
        ),
    };
    payload["reason"] = json!(reason);
    let event_seq = executor
        .append_facet_observation(
            AppendSpec {
                record_id: record_id.clone(),
                event_type: event_type.into(),
                payload,
                actor: Some(caller.actor().into()),
            },
            control,
        )
        .await?;
    Ok(observation_write_response(
        status,
        &record_id,
        &key,
        &as_of,
        event_seq,
        previous_seq,
        executor.allocated_act(),
    ))
}

/// The response every observation write returns, on every backend.
///
/// Both write paths — the SQLite MCP handler and this engine-dispatched one —
/// build it here rather than each assembling its own object. They diverged
/// once already: the disclosure markers below landed on one path and not the
/// other, and nothing caught it because the cross-backend scenarios assert
/// `as_of`, `event_seq` and the series contents but never the response key
/// set.
pub(crate) fn observation_write_response(
    status: &str,
    record_id: &str,
    key: &str,
    as_of: &str,
    event_seq: impl Into<Value>,
    previous_seq: impl Into<Value>,
    act: Option<i64>,
) -> Value {
    let mut response = json!({
        "status": status,
        "record_id": record_id,
        "key": key,
        "as_of": as_of,
        "event_seq": event_seq.into(),
        "previous_seq": previous_seq.into(),
        // The write landed in the valid-time series and deliberately did not
        // move the current-state fold, so `get_record` and `resolve_facets`
        // still report the prior value. `status` alone reads as a
        // current-state write, which is how five separate sessions came to
        // believe a facet had been changed when it had not. Cheap structured
        // markers only on a push surface: a boolean and an operation name,
        // never prose.
        "current_value_unchanged": true,
        "current_value_written_by": "update_record.facets",
    });
    // A write that appended nothing canonical allocates no act; omit the
    // field rather than reporting null or the workspace's current act.
    if let Some(act) = act {
        response["act"] = act.into();
    }
    response
}

#[allow(clippy::too_many_arguments)]
async fn list_observations<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    record_id: String,
    key: String,
    from_as_of: Option<String>,
    to_as_of: Option<String>,
    after_as_of: Option<String>,
    limit: Option<i64>,
) -> Result<Value> {
    const TOOL: &str = "manage_facet_observations";
    if key.is_empty() {
        return Err(Error::engine(format!("{TOOL}: 'key' must not be empty")));
    }
    let from_as_of = from_as_of
        .map(|value| normalize_timestamp(TOOL, "from_as_of", &value))
        .transpose()?;
    let to_as_of = to_as_of
        .map(|value| normalize_timestamp(TOOL, "to_as_of", &value))
        .transpose()?;
    if matches!((&from_as_of, &to_as_of), (Some(from), Some(to)) if from > to) {
        return Err(Error::engine(format!(
            "{TOOL}: 'from_as_of' must be earlier than or equal to 'to_as_of'"
        )));
    }
    let limit = limit.unwrap_or(DEFAULT_OBSERVATION_LIMIT);
    if !(1..=MAX_OBSERVATION_LIMIT).contains(&limit) {
        return Err(Error::engine(format!(
            "{TOOL}: 'limit' must be between 1 and {MAX_OBSERVATION_LIMIT}"
        )));
    }
    require_record(executor, caller, Some(TOOL), &record_id, Capability::View).await?;
    let query = statement(
        "list facet observations",
        "facet_observations",
        &[
            "SELECT value,op,vocab_ref,as_of,observed_at,event_seq FROM {{relation}} WHERE record_id=",
            " AND key=",
            " AND (",
            " IS NULL OR as_of>=",
            ") AND (",
            " IS NULL OR as_of<=",
            ") AND (",
            " IS NULL OR as_of>",
            ") ORDER BY as_of ASC LIMIT ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "list facet observations",
        &query,
        &[
            BindValue::Text(record_id.clone()),
            BindValue::Text(key.clone()),
            from_as_of
                .clone()
                .map(BindValue::Text)
                .unwrap_or(BindValue::Null(LogicalType::Text)),
            from_as_of
                .clone()
                .map(BindValue::Text)
                .unwrap_or(BindValue::Null(LogicalType::Text)),
            to_as_of
                .clone()
                .map(BindValue::Text)
                .unwrap_or(BindValue::Null(LogicalType::Text)),
            to_as_of
                .map(BindValue::Text)
                .unwrap_or(BindValue::Null(LogicalType::Text)),
            after_as_of
                .clone()
                .map(BindValue::Text)
                .unwrap_or(BindValue::Null(LogicalType::Text)),
            after_as_of
                .map(BindValue::Text)
                .unwrap_or(BindValue::Null(LogicalType::Text)),
            BindValue::Integer(limit + 1),
        ],
        &[
            ColumnSpec::nullable("value", LogicalType::Text),
            ColumnSpec::required("op", LogicalType::Text),
            ColumnSpec::nullable("vocab_ref", LogicalType::Text),
            ColumnSpec::required("as_of", LogicalType::Text),
            ColumnSpec::required("observed_at", LogicalType::Text),
            ColumnSpec::required("event_seq", LogicalType::Integer),
        ],
    )
    .await?;
    let has_more = rows.len() > limit as usize;
    let items = rows
        .iter()
        .take(limit as usize)
        .map(|row| {
            Ok(json!({
                "value": optional_text(row, "value", "facet observation")?,
                "op": text(row, "op", "facet observation")?,
                "vocab_ref": optional_text(row, "vocab_ref", "facet observation")?,
                "as_of": text(row, "as_of", "facet observation")?,
                "observed_at": text(row, "observed_at", "facet observation")?,
                "event_seq": integer(row, "event_seq", "facet observation")?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let next_after_as_of = if has_more {
        items
            .last()
            .and_then(|item| item.get("as_of"))
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Ok(json!({
        "record_id": record_id,
        "key": key,
        "observations": items,
        "next_after_as_of": next_after_as_of,
    }))
}

pub(crate) async fn execute_manage_facet_observations<E>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
    control: &ExecutionControl,
) -> Result<Value>
where
    E: DomainStatementExecutor + FacetObservationPort,
{
    match parse_arguments("manage_facet_observations", arguments)? {
        ManageFacetObservationsArgs::Set {
            record_id,
            key,
            value,
            vocab_ref,
            as_of,
            reason,
        } => {
            write_observation(
                executor,
                caller,
                record_id,
                key,
                Some((value, vocab_ref)),
                as_of,
                reason,
                control,
            )
            .await
        }
        ManageFacetObservationsArgs::Unset {
            record_id,
            key,
            as_of,
            reason,
        } => {
            write_observation(
                executor, caller, record_id, key, None, as_of, reason, control,
            )
            .await
        }
        ManageFacetObservationsArgs::List {
            record_id,
            key,
            from_as_of,
            to_as_of,
            after_as_of,
            limit,
        } => {
            list_observations(
                executor,
                caller,
                record_id,
                key,
                from_as_of,
                to_as_of,
                after_as_of,
                limit,
            )
            .await
        }
    }
}

async fn resolve_record_facets<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    record_id: String,
    rows: &[cascade::SchemaConfigRow],
) -> Result<Value> {
    require_record(executor, caller, None, &record_id, Capability::View).await?;
    let record_query = statement(
        "resolve facets",
        "records",
        &[
            "SELECT type,kind,lifecycle,owner_id,persistence,maturity,deleted_at FROM {{relation}} WHERE id=",
            "",
        ],
    )?;
    let record_rows = fetch(
        executor,
        "resolve facets",
        &record_query,
        &[BindValue::Text(record_id.clone())],
        &[
            ColumnSpec::required("type", LogicalType::Text),
            ColumnSpec::nullable("kind", LogicalType::Text),
            ColumnSpec::nullable("lifecycle", LogicalType::Text),
            ColumnSpec::nullable("owner_id", LogicalType::Text),
            ColumnSpec::required("persistence", LogicalType::Text),
            ColumnSpec::nullable("maturity", LogicalType::Text),
            ColumnSpec::nullable("deleted_at", LogicalType::Text),
        ],
    )
    .await?;
    let record = record_rows
        .first()
        .ok_or_else(|| Error::engine(format!("record {record_id} does not exist")))?;
    let record_type = text(record, "type", "facet record")?;
    let kind = optional_text(record, "kind", "facet record")?;
    let owner = optional_text(record, "owner_id", "facet record")?;
    let owner = match owner {
        Some(owner)
            if crate::authorization::allows_record_with(
                executor,
                caller_principal(caller),
                &owner,
                Capability::View,
            )
            .await? =>
        {
            Some(owner)
        }
        _ => None,
    };
    let archived_query = statement(
        "resolve facets",
        "facet_values",
        &[
            "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE record_id=",
            " AND key='archived') AS archived",
        ],
    )?;
    let archived_rows = fetch(
        executor,
        "resolve facets",
        &archived_query,
        &[BindValue::Text(record_id.clone())],
        &[ColumnSpec::required("archived", LogicalType::Bool)],
    )
    .await?;
    let archived = boolean(&archived_rows[0], "archived", "facet record")?;
    let shape =
        cascade::facets_for_record_context(rows, &record_type, kind.as_deref(), Some(&record_id));
    let values_query = statement(
        "resolve facets",
        "facet_values",
        &[
            "SELECT key,value,vocab_ref FROM {{relation}} WHERE record_id=",
            " AND key<>'archived' LIMIT ",
            "",
        ],
    )?;
    let value_rows = fetch(
        executor,
        "resolve facets",
        &values_query,
        &[
            BindValue::Text(record_id.clone()),
            BindValue::Integer(MAX_RESOLVED_VALUES + 1),
        ],
        &[
            ColumnSpec::required("key", LogicalType::Text),
            ColumnSpec::nullable("value", LogicalType::Text),
            ColumnSpec::nullable("vocab_ref", LogicalType::Text),
        ],
    )
    .await?;
    if value_rows.len() > MAX_RESOLVED_VALUES as usize {
        return Err(Error::engine(format!(
            "resolve_facets: value set exceeds {MAX_RESOLVED_VALUES} rows"
        )));
    }
    let mut value_rows = value_rows;
    value_rows.sort_by(|left, right| {
        let left = text(left, "key", "facet value").unwrap_or_default();
        let right = text(right, "key", "facet value").unwrap_or_default();
        left.as_bytes().cmp(right.as_bytes())
    });
    let values = value_rows
        .iter()
        .map(|row| {
            let key = text(row, "key", "facet value")?;
            let stored = optional_text(row, "value", "facet value")?;
            // Engine-reserved keys can never appear in schema config
            // (assert_no_reserved_facet_keys refuses them), so the cascade
            // has no shape for them and an object-valued reserved facet
            // would otherwise decode as a raw JSON string with no error.
            let object_typed = shape
                .get(&key)
                .and_then(|shape| shape.get("type"))
                .and_then(Value::as_str)
                == Some("object")
                || key == crate::canvas::PROMOTED_FROM_FACET_KEY;
            let value = stored.map(|stored| {
                if object_typed {
                    serde_json::from_str::<Value>(&stored)
                        .ok()
                        .filter(Value::is_object)
                        .unwrap_or(Value::String(stored))
                } else {
                    Value::String(stored)
                }
            });
            Ok(json!({
                "key": key,
                "value": value,
                "vocab_ref": optional_text(row, "vocab_ref", "facet value")?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "record_id": record_id,
        "type": record_type,
        "kind": kind,
        "bears_shape": cascade::bears_shape_from_rows(rows, &record_id),
        "spine": {
            "lifecycle": optional_text(record, "lifecycle", "facet record")?,
            "owner": owner,
            "persistence": text(record, "persistence", "facet record")?,
            "maturity": optional_text(record, "maturity", "facet record")?,
        },
        "archived": archived,
        "shape": shape,
        "pack_shape": cascade::pack_facets_for_record_context(rows, &record_type, kind.as_deref(), Some(&record_id)),
        "provenance": cascade::provenance_for_record_context(rows, &record_type, kind.as_deref(), Some(&record_id)),
        "values": values,
        "shape_guarantee": SHAPE_GUARANTEE,
    }))
}

pub(crate) async fn execute_resolve_facets<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    let args: ResolveFacetsArgs = parse_arguments("resolve_facets", arguments)?;
    let rows = visible_schema_rows(executor, caller).await?;
    match (args.record_id, args.record_type) {
        (Some(record_id), None) => resolve_record_facets(executor, caller, record_id, &rows).await,
        (None, Some(record_type)) => {
            let resolved = cascade::resolve_from_rows(&rows);
            let kind = args.kind;
            let mut response = json!({
                "type": record_type,
                "kind": kind,
                "spine": SPINE_FACET_KEYS,
                "shape": cascade::facets_for_type(&resolved.resolved, &record_type, kind.as_deref()),
                "pack_shape": cascade::facets_for_type(&resolved.pack, &record_type, kind.as_deref()),
                "provenance": cascade::provenance_for_type(&rows, &record_type, kind.as_deref()),
                "shape_guarantee": SHAPE_GUARANTEE,
            });
            if kind.is_none() {
                response["kind_shapes"] =
                    json!(cascade::kind_shapes(&resolved.resolved, &record_type));
            }
            Ok(response)
        }
        _ => Err(Error::engine(
            "resolve_facets takes exactly one of record_id or type",
        )),
    }
}

async fn vocabulary_and_active_values<E: DomainStatementExecutor>(
    executor: &mut E,
    designator: &str,
) -> Result<(Value, Vec<Value>)> {
    let Some(vocabulary_id) = vocabulary_id(executor, designator).await? else {
        return Err(Error::engine(format!(
            "vocabulary {designator} does not exist"
        )));
    };
    let vocabulary_query = statement(
        "suggest facet values",
        "vocabularies",
        &["SELECT id,name FROM {{relation}} WHERE id=", ""],
    )?;
    let vocabulary_rows = fetch(
        executor,
        "suggest facet values",
        &vocabulary_query,
        &[BindValue::Text(vocabulary_id.clone())],
        &[
            ColumnSpec::required("id", LogicalType::Text),
            ColumnSpec::required("name", LogicalType::Text),
        ],
    )
    .await?;
    let vocabulary_row = &vocabulary_rows[0];
    let vocabulary = json!({
        "id": text(vocabulary_row, "id", "facet vocabulary")?,
        "name": text(vocabulary_row, "name", "facet vocabulary")?,
    });
    let values_query = statement(
        "suggest facet values",
        "vocabulary_values",
        &[
            "SELECT v.id,v.vocabulary_id,v.value,v.gloss,v.status,v.ordinal,v.terminality,v.metadata,v.alias_of,c.id AS canonical_id,c.value AS canonical_value FROM {{relation}} v LEFT JOIN {{relation}} c ON c.id=v.alias_of WHERE v.vocabulary_id=",
            " AND v.status='active' LIMIT ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "suggest facet values",
        &values_query,
        &[
            BindValue::Text(vocabulary_id),
            BindValue::Integer(MAX_VOCABULARY_SUGGESTIONS + 1),
        ],
        &[
            ColumnSpec::required("id", LogicalType::Text),
            ColumnSpec::required("vocabulary_id", LogicalType::Text),
            ColumnSpec::required("value", LogicalType::Text),
            ColumnSpec::nullable("gloss", LogicalType::Text),
            ColumnSpec::required("status", LogicalType::Text),
            ColumnSpec::required("ordinal", LogicalType::Real),
            ColumnSpec::required("terminality", LogicalType::Text),
            ColumnSpec::required("metadata", LogicalType::Text),
            ColumnSpec::nullable("alias_of", LogicalType::Text),
            ColumnSpec::nullable("canonical_id", LogicalType::Text),
            ColumnSpec::nullable("canonical_value", LogicalType::Text),
        ],
    )
    .await?;
    if rows.len() > MAX_VOCABULARY_SUGGESTIONS as usize {
        return Err(Error::engine(format!(
            "suggest_facet_values: suggestion set exceeds {MAX_VOCABULARY_SUGGESTIONS} rows"
        )));
    }
    let mut rows = rows;
    rows.sort_by(|left, right| {
        let left_ordinal = real(left, "ordinal", "vocabulary value").unwrap_or_default();
        let right_ordinal = real(right, "ordinal", "vocabulary value").unwrap_or_default();
        left_ordinal
            .partial_cmp(&right_ordinal)
            .unwrap_or(Ordering::Equal)
            .then_with(|| {
                text(left, "value", "vocabulary value")
                    .unwrap_or_default()
                    .as_bytes()
                    .cmp(
                        text(right, "value", "vocabulary value")
                            .unwrap_or_default()
                            .as_bytes(),
                    )
            })
            .then_with(|| {
                text(left, "id", "vocabulary value")
                    .unwrap_or_default()
                    .as_bytes()
                    .cmp(
                        text(right, "id", "vocabulary value")
                            .unwrap_or_default()
                            .as_bytes(),
                    )
            })
    });
    let suggestions = rows
        .iter()
        .map(|row| {
            let metadata = text(row, "metadata", "vocabulary value")?;
            let metadata = serde_json::from_str::<Value>(&metadata).map_err(|_| {
                Error::engine("suggest_facet_values: vocabulary value metadata is invalid")
            })?;
            let alias_of = optional_text(row, "alias_of", "vocabulary value")?;
            let canonical_id = optional_text(row, "canonical_id", "vocabulary value")?;
            let canonical_value = optional_text(row, "canonical_value", "vocabulary value")?;
            let mut item = json!({
                "id": text(row, "id", "vocabulary value")?,
                "vocabulary_id": text(row, "vocabulary_id", "vocabulary value")?,
                "value": text(row, "value", "vocabulary value")?,
                "gloss": optional_text(row, "gloss", "vocabulary value")?,
                "status": text(row, "status", "vocabulary value")?,
                "ordinal": real(row, "ordinal", "vocabulary value")?,
                "terminality": text(row, "terminality", "vocabulary value")?,
                "metadata": metadata,
                "alias_of": alias_of,
            });
            if let Some((id, value)) = canonical_id.zip(canonical_value) {
                item["canonical"] = json!({"id": id, "value": value});
            }
            Ok(item)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((vocabulary, suggestions))
}

pub(crate) async fn execute_suggest_facet_values<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    let args: SuggestFacetValuesArgs = parse_arguments("suggest_facet_values", arguments)?;
    let (record_type, kind, bearer_id) = match (args.record_id, args.record_type) {
        (Some(record_id), None) => {
            require_record(
                executor,
                caller,
                Some("suggest_facet_values"),
                &record_id,
                Capability::View,
            )
            .await?;
            let (record_type, kind) = record_shape_context(executor, &record_id).await?;
            (record_type, kind, Some(record_id))
        }
        (None, Some(record_type)) => (record_type, args.kind, None),
        _ => {
            return Err(Error::engine(
                "suggest_facet_values takes exactly one of record_id or type",
            ))
        }
    };
    let rows = visible_schema_rows(executor, caller).await?;
    let shape = cascade::facets_for_record_context(
        &rows,
        &record_type,
        kind.as_deref(),
        bearer_id.as_deref(),
    );
    let declared_type = shape
        .get(&args.facet_key)
        .and_then(|facet| facet.get("type"))
        .cloned()
        .unwrap_or(Value::Null);
    let Some(governing) = shape.get(&args.facet_key).and_then(|shape| {
        shape
            .get("vocab")
            .or_else(|| shape.get("vocab_ref"))
            .and_then(Value::as_str)
            .map(String::from)
    }) else {
        return Ok(json!({
            "facet_key": args.facet_key,
            "type": record_type,
            "kind": kind,
            "declared_type": declared_type,
            "vocabulary": Value::Null,
            "suggestions": [],
            "shape_guarantee": SHAPE_GUARANTEE,
        }));
    };
    let designator = crate::meta::resolve_vocab_ref(&governing);
    let (vocabulary, suggestions) = vocabulary_and_active_values(executor, designator).await?;
    Ok(json!({
        "facet_key": args.facet_key,
        "type": record_type,
        "kind": kind,
        "declared_type": declared_type,
        "vocabulary": vocabulary,
        "suggestions": suggestions,
        "shape_guarantee": SHAPE_GUARANTEE,
    }))
}

async fn vocabulary_id<E: DomainStatementExecutor>(
    executor: &mut E,
    designator: &str,
) -> Result<Option<String>> {
    Ok(vocabulary_identity(executor, designator)
        .await?
        .map(|identity| identity.id))
}

async fn vocabulary_exists_by_id<E: DomainStatementExecutor>(
    executor: &mut E,
    vocabulary_id: &str,
) -> Result<bool> {
    let statement = statement(
        "assess exact facet vocabulary reference",
        "vocabularies",
        &[
            "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE id=",
            ") AS found",
        ],
    )?;
    let rows = fetch(
        executor,
        "assess exact facet vocabulary reference",
        &statement,
        &[BindValue::Text(vocabulary_id.into())],
        &[ColumnSpec::required("found", LogicalType::Bool)],
    )
    .await?;
    boolean(&rows[0], "found", "facet vocabulary reference")
}

async fn vocabulary_identity<E: DomainStatementExecutor>(
    executor: &mut E,
    designator: &str,
) -> Result<Option<FacetVocabularyIdentity>> {
    let statement = statement(
        "govern facet",
        "vocabularies",
        &[
            "SELECT id,name FROM {{relation}} WHERE id = ",
            " OR name = ",
            " ORDER BY id LIMIT 1",
        ],
    )?;
    let rows = fetch(
        executor,
        "govern facet",
        &statement,
        &[
            BindValue::Text(designator.into()),
            BindValue::Text(designator.into()),
        ],
        &[
            ColumnSpec::required("id", LogicalType::Text),
            ColumnSpec::required("name", LogicalType::Text),
        ],
    )
    .await?;
    rows.first()
        .map(|row| {
            Ok(FacetVocabularyIdentity {
                id: text(row, "id", "facet vocabulary")?,
                name: text(row, "name", "facet vocabulary")?,
            })
        })
        .transpose()
}

async fn vocabulary_value_resolution<E: DomainStatementExecutor>(
    executor: &mut E,
    vocabulary_id: &str,
    value: &str,
) -> Result<FacetVocabularyValueResolution> {
    let statement = statement(
        "assess facet vocabulary value",
        "vocabulary_values",
        &[
            "SELECT candidate.id,candidate.status,candidate.alias_of,canonical.id AS canonical_id,canonical.value AS canonical_value FROM {{relation}} candidate LEFT JOIN {{relation}} canonical ON canonical.id=candidate.alias_of WHERE candidate.vocabulary_id=",
            " AND candidate.value=",
            " ORDER BY candidate.id LIMIT 1",
        ],
    )?;
    let rows = fetch(
        executor,
        "assess facet vocabulary value",
        &statement,
        &[
            BindValue::Text(vocabulary_id.into()),
            BindValue::Text(value.into()),
        ],
        &[
            ColumnSpec::required("id", LogicalType::Text),
            ColumnSpec::required("status", LogicalType::Text),
            ColumnSpec::nullable("alias_of", LogicalType::Text),
            ColumnSpec::nullable("canonical_id", LogicalType::Text),
            ColumnSpec::nullable("canonical_value", LogicalType::Text),
        ],
    )
    .await?;
    let Some(row) = rows.first() else {
        return Ok(FacetVocabularyValueResolution {
            classification: "not_member",
            id: None,
            status: None,
            canonical_id: None,
            canonical_value: None,
        });
    };
    let status = text(row, "status", "facet vocabulary value")?;
    let canonical_id = optional_text(row, "canonical_id", "facet vocabulary value")?;
    let canonical_value = optional_text(row, "canonical_value", "facet vocabulary value")?;
    let classification = if canonical_id.is_some() && status == "active" {
        "active_alias"
    } else if canonical_id.is_some() {
        "inactive_alias"
    } else if status == "active" {
        "active_member"
    } else {
        "inactive_member"
    };
    Ok(FacetVocabularyValueResolution {
        classification,
        id: Some(text(row, "id", "facet vocabulary value")?),
        status: Some(status),
        canonical_id,
        canonical_value,
    })
}

pub(crate) async fn active_vocabulary_value<E: DomainStatementExecutor>(
    executor: &mut E,
    vocabulary_id: &str,
    value: &str,
) -> Result<bool> {
    let statement = statement(
        "govern facet",
        "vocabulary_values",
        &[
            "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE vocabulary_id = ",
            " AND value = ",
            " AND status = 'active') AS active",
        ],
    )?;
    let rows = fetch(
        executor,
        "govern facet",
        &statement,
        &[
            BindValue::Text(vocabulary_id.into()),
            BindValue::Text(value.into()),
        ],
        &[ColumnSpec::required("active", LogicalType::Bool)],
    )
    .await?;
    boolean(&rows[0], "active", "facet vocabulary")
}

/// Active values of one governing vocabulary, oldest-first, capped at
/// `limit_plus_one` rows so callers can tell "small, list inline" from
/// "large, point at the listing call" without reading the whole set.
async fn active_vocabulary_value_names<E: DomainStatementExecutor>(
    executor: &mut E,
    vocabulary_id: &str,
    limit_plus_one: i64,
) -> Result<Vec<String>> {
    let statement = statement(
        "list active facet vocabulary values",
        "vocabulary_values",
        &[
            "SELECT value FROM {{relation}} WHERE vocabulary_id = ",
            " AND status = 'active' ORDER BY ordinal, value, id LIMIT ",
            "",
        ],
    )?;
    let rows = fetch(
        executor,
        "list active facet vocabulary values",
        &statement,
        &[
            BindValue::Text(vocabulary_id.into()),
            BindValue::Integer(limit_plus_one),
        ],
        &[ColumnSpec::required("value", LogicalType::Text)],
    )
    .await?;
    rows.iter()
        .map(|row| text(row, "value", "facet vocabulary value"))
        .collect()
}

fn predicate_issue(code: &'static str, message: String) -> FacetPredicateIssue {
    FacetPredicateIssue { code, message }
}

fn lifecycle_governance_issue(
    tool: &str,
    record_type: &str,
    kind: Option<&str>,
) -> FacetPredicateIssue {
    predicate_issue(
        "lifecycle_not_governed",
        format!(
            "{tool}: lifecycle is not governed for {record_type}{}; ordinary non-null lifecycle writes require an effective lifecycle axis and vocabulary",
            kind.map(|kind| format!(":{kind}")).unwrap_or_default(),
        ),
    )
}

/// Assess the exact deterministic predicates used by supported record writers
/// without converting an unacceptable proposed value into a tool failure.
/// Storage/query failures still fail closed through `Result`.
pub(crate) async fn assess_facet_write<E: DomainStatementExecutor>(
    executor: &mut E,
    shape: Option<&Value>,
    tool: &str,
    record_type: &str,
    kind: Option<&str>,
    facet: &FacetWrite,
) -> Result<FacetPredicateAssessment> {
    let Some(shape) = shape else {
        let mut issues = Vec::new();
        if facet.key == "lifecycle" {
            issues.push(lifecycle_governance_issue(tool, record_type, kind));
        }
        if let Some(caller_ref) = &facet.vocab_ref {
            let caller_designator = crate::meta::resolve_vocab_ref(caller_ref);
            if !vocabulary_exists_by_id(executor, caller_designator).await? {
                issues.push(predicate_issue(
                    "dangling_vocabulary_reference",
                    format!(
                        "vocab_ref '{caller_ref}' does not resolve to a vocabulary — create the vocabulary first"
                    ),
                ));
            }
        }
        return Ok(FacetPredicateAssessment {
            declared: false,
            accepted: issues.is_empty(),
            declared_type: None,
            governing_vocabulary: None,
            value_resolution: None,
            issues,
        });
    };
    let shape_suffix = kind.map(|kind| format!(":{kind}")).unwrap_or_default();
    let declared_type = shape.get("type").and_then(Value::as_str).map(String::from);
    let mut issues = Vec::new();
    let lifecycle_axis_is_interpretable = facet.key != "lifecycle"
        || shape
            .get("axis")
            .and_then(Value::as_object)
            .is_some_and(|axis| {
                axis.len() == 2
                    && ["key", "label"].into_iter().all(|member| {
                        axis.get(member)
                            .and_then(Value::as_str)
                            .is_some_and(|value| !value.trim().is_empty())
                    })
            });
    if !lifecycle_axis_is_interpretable {
        issues.push(lifecycle_governance_issue(tool, record_type, kind));
    }

    match declared_type.as_deref() {
        Some("number") if !facet.value.is_number() => issues.push(predicate_issue(
            "declared_type_mismatch",
            format!(
                "{tool}: facet '{}' is declared type 'number' for {record_type}{shape_suffix} and requires a JSON number; got {}. Shape enforcement is forward-only at supported record-writing tools and does not make stored data a standing invariant",
                facet.key,
                if facet.value.is_string() { "a JSON string" } else { "a non-number" },
            ),
        )),
        Some("object") if facet.value.is_object() => {
            if let Err(error) =
                crate::meta::schema_config::validate_object_facet_value(shape, &facet.value)
            {
                issues.push(predicate_issue(
                    "object_value_invalid",
                    format!(
                        "{tool}: facet '{}' does not conform for {record_type}{shape_suffix}: {error}",
                        facet.key,
                    ),
                ));
            }
        }
        Some("object") => issues.push(predicate_issue(
            "declared_type_mismatch",
            format!(
                "{tool}: facet '{}' is declared type 'object' for {record_type}{shape_suffix} and requires a JSON object",
                facet.key,
            ),
        )),
        Some("number") | None => {}
        Some(other) => issues.push(predicate_issue(
            "unsupported_declared_type",
            format!(
                "{tool}: facet '{}' declares unsupported type '{other}' (supported: 'number', 'object')",
                facet.key
            ),
        )),
    }
    if declared_type.is_none() && facet.value.is_object() {
        issues.push(predicate_issue(
            "undeclared_object_value",
            format!(
                "{tool}: facet '{}' carries a JSON object but {record_type}{shape_suffix} does not declare type 'object'",
                facet.key,
            ),
        ));
    }
    if let Some(allowed) = shape.get("values").and_then(Value::as_array) {
        if !allowed.contains(&facet.value) {
            issues.push(predicate_issue(
                "not_in_declared_values",
                format!(
                    "{tool}: facet '{}' value {} is not in the declared values set {} for {record_type}{shape_suffix}",
                    facet.key,
                    facet.value,
                    Value::Array(allowed.clone()),
                ),
            ));
        }
    }

    let governing = shape
        .get("vocab")
        .or_else(|| shape.get("vocab_ref"))
        .and_then(Value::as_str);
    let mut governing_vocabulary = None;
    let mut value_resolution = None;
    if let Some(governing) = governing {
        let designator = crate::meta::resolve_vocab_ref(governing);
        match vocabulary_identity(executor, designator).await? {
            None => issues.push(predicate_issue(
                "governing_vocabulary_missing",
                format!(
                    "{tool}: facet '{}' is governed by vocabulary '{governing}', but that vocabulary does not exist",
                    facet.key
                ),
            )),
            Some(identity) => {
                if let Some(caller_ref) = &facet.vocab_ref {
                    let caller_designator = crate::meta::resolve_vocab_ref(caller_ref);
                    let caller_id = vocabulary_id(executor, caller_designator).await?;
                    if caller_id.as_deref() != Some(identity.id.as_str()) {
                        issues.push(predicate_issue(
                            "conflicting_vocabulary_reference",
                            format!(
                                "{tool}: facet '{}' is governed by vocabulary '{governing}' (id {}), but the caller supplied conflicting vocab_ref '{caller_ref}'",
                                facet.key, identity.id
                            ),
                        ));
                    }
                }
                let resolution = vocabulary_value_resolution(
                    executor,
                    &identity.id,
                    &facet.stored_value(),
                )
                .await?;
                if resolution.status.as_deref() != Some("active") {
                    let limit = crate::schema::GOVERNANCE_INLINE_ALTERNATIVES_LIMIT as i64;
                    let mut names =
                        active_vocabulary_value_names(executor, &identity.id, limit + 1).await?;
                    // SQLite/Turso order text bytewise; Postgres follows the
                    // database locale. Sort here so the message is identical
                    // on every backend.
                    names.sort();
                    // Name the resolved vocabulary, not the raw caller
                    // designator: `manage_vocabularies.list_values` matches
                    // exact id or name, so a `rec:`-prefixed spelling would
                    // advertise an unusable call.
                    let detail = if names.len() as i64 <= limit && !names.is_empty() {
                        format!(
                            "active values of '{}': {}",
                            identity.name,
                            names.join(", ")
                        )
                    } else {
                        let list_arguments = serde_json::json!({
                            "vocabulary": identity.name,
                            "status": "active",
                        });
                        let mut preview =
                            serde_json::Map::from_iter([(String::from("type"), Value::String(record_type.into()))]);
                        if let Some(kind) = kind {
                            preview.insert(String::from("kind"), Value::String(kind.into()));
                        }
                        preview.insert(
                            String::from("facets"),
                            Value::Object(serde_json::Map::from_iter([(
                                facet.key.clone(),
                                facet.value.clone(),
                            )])),
                        );
                        format!(
                            "list the active values with schema_read manage_vocabularies.list_values arguments {list_arguments} or schema_read preview_record_shape arguments {}",
                            Value::Object(preview),
                        )
                    };
                    issues.push(predicate_issue(
                        "not_active_vocabulary_member",
                        format!(
                            "{tool}: facet '{}' value {} is not an active member of governing vocabulary '{governing}'; {detail}",
                            facet.key, facet.value
                        ),
                    ));
                }
                governing_vocabulary = Some(identity);
                value_resolution = Some(resolution);
            }
        }
    } else {
        if facet.key == "lifecycle" && lifecycle_axis_is_interpretable {
            issues.push(lifecycle_governance_issue(tool, record_type, kind));
        }
        if let Some(caller_ref) = &facet.vocab_ref {
            let caller_designator = crate::meta::resolve_vocab_ref(caller_ref);
            if !vocabulary_exists_by_id(executor, caller_designator).await? {
                issues.push(predicate_issue(
                    "dangling_vocabulary_reference",
                    format!(
                        "vocab_ref '{caller_ref}' does not resolve to a vocabulary — create the vocabulary first"
                    ),
                ));
            }
        }
    }

    Ok(FacetPredicateAssessment {
        declared: true,
        accepted: issues.is_empty(),
        declared_type,
        governing_vocabulary,
        value_resolution,
        issues,
    })
}

/// Canonical facet shape and vocabulary fold. Every supported record writer
/// calls this before publishing any event in its admitted transaction.
pub(crate) async fn govern_facet_writes<E: DomainStatementExecutor>(
    executor: &mut E,
    schema_rows: &[cascade::SchemaConfigRow],
    tool: &str,
    record_type: &str,
    kind: Option<&str>,
    facets: &mut [FacetWrite],
) -> Result<()> {
    if facets.is_empty() {
        return Ok(());
    }
    // Collection-scoped rows advertise a capability borne by that collection;
    // filing is deliberately not a product facet inheritance mechanism in V1.
    let shapes = cascade::facets_for_record_context(schema_rows, record_type, kind, None);
    for facet in facets {
        let assessment = assess_facet_write(
            executor,
            shapes.get(&facet.key),
            tool,
            record_type,
            kind,
            facet,
        )
        .await?;
        if let Some(issue) = assessment.issues.first() {
            return Err(Error::engine(issue.message.clone()));
        }
        if let Some(vocabulary) = assessment.governing_vocabulary {
            facet.vocab_ref = Some(crate::meta::vocab_ref(&vocabulary.id));
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct RequiredViolation {
    record_id: String,
    record_type: String,
    kind: Option<String>,
    key: String,
}

impl PartialEq for RequiredViolation {
    fn eq(&self, other: &Self) -> bool {
        (self.record_id.as_str(), self.key.as_str())
            == (other.record_id.as_str(), other.key.as_str())
    }
}

impl Eq for RequiredViolation {}

impl PartialOrd for RequiredViolation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RequiredViolation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.record_id.as_str(), self.key.as_str())
            .cmp(&(other.record_id.as_str(), other.key.as_str()))
    }
}

pub(crate) async fn required_violations<E: DomainStatementExecutor>(
    executor: &mut E,
    schema_rows: &[cascade::SchemaConfigRow],
    record_ids: &[&str],
) -> Result<BTreeSet<RequiredViolation>> {
    let record_statement = statement(
        "validate required facets",
        "records",
        &[
            "SELECT type, kind, home_id, lifecycle, owner_id, persistence, maturity FROM {{relation}} WHERE id = ",
            "",
        ],
    )?;
    let facet_statement = statement(
        "validate required facets",
        "facet_values",
        &[
            "SELECT key FROM {{relation}} WHERE record_id = ",
            " AND value IS NOT NULL ORDER BY key",
        ],
    )?;
    let mut violations = BTreeSet::new();
    for record_id in record_ids {
        let rows = fetch(
            executor,
            "validate required facets",
            &record_statement,
            &[BindValue::Text((*record_id).into())],
            &[
                ColumnSpec::required("type", LogicalType::Text),
                ColumnSpec::nullable("kind", LogicalType::Text),
                ColumnSpec::nullable("home_id", LogicalType::Text),
                ColumnSpec::nullable("lifecycle", LogicalType::Text),
                ColumnSpec::nullable("owner_id", LogicalType::Text),
                ColumnSpec::required("persistence", LogicalType::Text),
                ColumnSpec::nullable("maturity", LogicalType::Text),
            ],
        )
        .await?;
        let Some(row) = rows.first() else { continue };
        let record_type = text(row, "type", "required facet")?;
        let kind = optional_text(row, "kind", "required facet")?;
        let open_values: BTreeSet<String> = fetch(
            executor,
            "validate required facets",
            &facet_statement,
            &[BindValue::Text((*record_id).into())],
            &[ColumnSpec::required("key", LogicalType::Text)],
        )
        .await?
        .iter()
        .map(|row| text(row, "key", "required facet"))
        .collect::<Result<_>>()?;
        let shapes =
            cascade::facets_for_record_context(schema_rows, &record_type, kind.as_deref(), None);
        for (key, shape) in shapes {
            if shape.get("required") != Some(&Value::Bool(true)) {
                continue;
            }
            let present = match spine_facet_column(&key) {
                Some(column) => optional_text(row, column, "required facet")?.is_some(),
                None => open_values.contains(&key),
            };
            if !present {
                violations.insert(RequiredViolation {
                    record_id: (*record_id).to_string(),
                    record_type: record_type.clone(),
                    kind: kind.clone(),
                    key,
                });
            }
        }
    }
    Ok(violations)
}

pub(crate) fn assert_required_not_worsened(
    tool: &str,
    before: &BTreeSet<RequiredViolation>,
    after: &BTreeSet<RequiredViolation>,
) -> Result<()> {
    let introduced: Vec<&RequiredViolation> = after.difference(before).collect();
    if introduced.is_empty() {
        return Ok(());
    }
    let details = introduced
        .iter()
        .map(|violation| {
            format!(
                "record {} missing required facet '{}' for {}{}",
                violation.record_id,
                violation.key,
                violation.record_type,
                violation
                    .kind
                    .as_deref()
                    .map(|kind| format!(":{kind}"))
                    .unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    Err(Error::engine(format!(
        "{tool}: batch would worsen required-facet conformance: {details}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_backend_discloses_that_an_observation_left_current_state_alone() {
        // Both write paths route through this builder, so asserting on it
        // covers SQLite, Postgres and Turso at once. Previously each path
        // assembled its own object and the disclosure reached only one of
        // them.
        let response = observation_write_response(
            "set",
            "rec-1",
            "triage",
            "2026-08-01T00:00:00.000Z",
            42,
            41,
            Some(9),
        );
        assert_eq!(response["status"], "set");
        assert_eq!(response["event_seq"], 42);
        assert_eq!(response["previous_seq"], 41);
        assert_eq!(response["act"], 9);
        assert_eq!(response["current_value_unchanged"], true);
        assert_eq!(response["current_value_written_by"], "update_record.facets");

        // The SQLite path carries an Option for a record with no prior event.
        let first = observation_write_response(
            "unset",
            "rec-2",
            "area",
            "2026-08-01T00:00:00.000Z",
            7,
            Option::<i64>::None,
            Some(10),
        );
        assert_eq!(first["status"], "unset");
        assert_eq!(first["previous_seq"], Value::Null);
        assert_eq!(first["act"], 10);
        assert_eq!(first["current_value_unchanged"], true);

        // A write that allocated no act omits the field entirely: "no act"
        // and "act unchanged" are different facts.
        let noop = observation_write_response(
            "set",
            "rec-3",
            "triage",
            "2026-08-01T00:00:00.000Z",
            43,
            42,
            None,
        );
        assert!(noop.get("act").is_none());
    }

    fn facet_write(key: &str) -> FacetWrite {
        FacetWrite {
            key: key.into(),
            value: Value::String("someone".into()),
            vocab_ref: None,
        }
    }

    #[test]
    fn exact_manifest_names_classify_as_governed_without_a_hardcoded_list() {
        // Derived from the core manifest: every exact relationship name
        // classifies as wrong-carrier, including ones this test never names.
        let manifest = crate::relationship::core_relationship_type_manifest().unwrap();
        assert!(!manifest.relationship_types.is_empty());
        for definition in &manifest.relationship_types {
            let key = definition.relationship_type.as_str();
            assert!(
                matches!(
                    classify_facet_key(key),
                    FacetKeyClassification::GovernedRelationship { .. }
                ),
                "{key} must classify as a governed relationship"
            );
            assert_eq!(
                governed_relationship_type_for_key(key).as_deref(),
                Some(key)
            );
            let error = assert_open_facet_key("create_record", key)
                .unwrap_err()
                .to_string();
            assert!(error.contains("manage_relationships.assert"), "{error}");
        }
        // Near-misses stay honest open facets: no fuzzy matching.
        for key in [
            "assignees",
            "assigned",
            "Assigned_to",
            "ASSIGNED_TO",
            "blocked_by",
        ] {
            assert_eq!(classify_facet_key(key), FacetKeyClassification::Open);
            assert_open_facet_key("create_record", key).unwrap();
        }
    }

    #[test]
    fn alias_warnings_fire_only_for_admitted_subjects() {
        // assignee warns on a task, the one admitted subject kind.
        let warnings =
            governed_alias_warnings_for_sets(&[facet_write("assignee")], "WorkItem", Some("task"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0]["code"], GOVERNED_ALIAS_ISSUE);
        assert_eq!(warnings[0]["facet_key"], "assignee");
        assert_eq!(warnings[0]["relationship_type"], "assigned_to");
        assert_eq!(
            warnings[0]["suggested_operation"],
            GOVERNED_RELATIONSHIP_SUGGESTED_OPERATION
        );
        assert!(warnings[0]["message"]
            .as_str()
            .unwrap()
            .contains("did not establish the relationship"));
        // Silence on kinds the relationship does not admit, on unrelated
        // keys, and on epic/task-adjacent non-task kinds.
        for (record_type, kind) in [
            ("Document", Some("note")),
            ("WorkItem", Some("epic")),
            ("WorkItem", None),
            ("Entity", Some("person")),
        ] {
            assert!(
                governed_alias_warnings_for_sets(&[facet_write("assignee")], record_type, kind)
                    .is_empty(),
                "assignee must stay silent on {record_type}:{kind:?}"
            );
        }
        assert!(governed_alias_warnings_for_sets(
            &[facet_write("triage")],
            "WorkItem",
            Some("task")
        )
        .is_empty());
        // Unsets never warn.
        assert!(governed_alias_warning("assignee", "WorkItem", Some("task"), true).is_none());
    }

    #[test]
    fn receipt_warning_helpers_keep_absent_arrays_absent() {
        let mut receipt = json!({"id": "rec-1"});
        push_receipt_warnings(&mut receipt, Vec::new()).unwrap();
        assert!(receipt.get("warnings").is_none());
        push_receipt_warnings(
            &mut receipt,
            governed_alias_warnings_for_sets(&[facet_write("assignee")], "WorkItem", Some("task")),
        )
        .unwrap();
        assert_eq!(receipt["warnings"].as_array().unwrap().len(), 1);
        let indexed = index_warning_for_batch(3, "rec-9", receipt["warnings"][0].clone());
        assert_eq!(indexed["index"], 3);
        assert_eq!(indexed["id"], "rec-9");
        assert_eq!(indexed["code"], GOVERNED_ALIAS_ISSUE);
    }
}
