//! Portable, read-only record-shape preview.
//!
//! The caller owns the admitted snapshot. This fold deliberately performs all
//! live kind, schema and vocabulary reads through that one executor. Proposed
//! open-facet values are assessed as bounded deterministic facts; the fold
//! remains advisory and cannot become a second write-admission path or a
//! disguised whole-record dry run.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::mcp::registry::Caller;
use crate::portable_sql::{
    ColumnSpec, DomainStatementExecutor, LogicalType, NormalizedValue, StatementKind,
    StatementTemplate,
};
use crate::query::cascade;
use crate::schema::{
    SpineRelationshipDirection, SPINE_FACET_KEYS, SPINE_RELATIONSHIP_MEANINGS, SPINE_TYPES,
    SPINE_TYPE_MEANINGS,
};
use crate::{Error, Result, CURRENT_ENGINE_SCHEMA_VERSION};

const RESPONSE_SCHEMA: &str = "native.record_shape_preview.v1";
const SEMANTIC_CONTRACT_REVISION: &str = "record-shape-preview-v2-facet-values";
const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_PROPOSED_FACETS: usize = 100;
const GUARANTEE: &str = "This advisory preview reports deterministic schema and kind facts read through one caller-owned executor snapshot. It performs zero authoritative writes; ordinary disposable read-call telemetry may still be captured.";
const NOT_CHECKED: [&str; 7] = [
    "proposed_spine_values",
    "proposed_links",
    "permissions_for_a_future_write",
    "write_admission",
    "dry_run_verdict",
    "collection_scoped_shape",
    "state_after_this_snapshot",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRecordShapeArgs {
    #[serde(rename = "type")]
    record_type: Option<String>,
    kind: Option<String>,
    facets: Option<Map<String, Value>>,
}

fn parse_arguments(arguments: Value) -> Result<PreviewRecordShapeArgs> {
    if arguments
        .as_object()
        .and_then(|arguments| arguments.get("facets"))
        .is_some_and(Value::is_null)
    {
        return Err(Error::engine(
            "preview_record_shape: 'facets' must be an object when supplied",
        ));
    }
    let args: PreviewRecordShapeArgs = serde_json::from_value(arguments).map_err(|error| {
        Error::engine(format!(
            "invalid arguments for preview_record_shape: {error}"
        ))
    })?;
    if args
        .kind
        .as_ref()
        .is_some_and(|kind| kind.trim().is_empty())
    {
        return Err(Error::engine(
            "preview_record_shape: 'kind' must contain at least one non-whitespace character",
        ));
    }
    match (&args.record_type, &args.kind) {
        (None, Some(_)) => {
            return Err(Error::engine(
                "preview_record_shape: 'kind' requires 'type'",
            ));
        }
        (Some(record_type), _) if !SPINE_TYPES.contains(&record_type.as_str()) => {
            return Err(Error::engine(format!(
                "preview_record_shape: unknown closed spine type '{record_type}'"
            )));
        }
        _ => {}
    }
    if args.facets.is_some() && args.record_type.is_none() {
        return Err(Error::engine(
            "preview_record_shape: 'facets' requires 'type'",
        ));
    }
    if args
        .facets
        .as_ref()
        .is_some_and(|facets| facets.len() > MAX_PROPOSED_FACETS)
    {
        return Err(Error::engine(format!(
            "preview_record_shape: 'facets' accepts at most {MAX_PROPOSED_FACETS} entries"
        )));
    }
    Ok(args)
}

fn static_catalogs() -> Value {
    let types = SPINE_TYPE_MEANINGS.map(|meaning| {
        json!({
            "type": meaning.name,
            "short_gloss": meaning.short_gloss,
            "gloss": meaning.gloss,
        })
    });
    let relationships = SPINE_RELATIONSHIP_MEANINGS.map(|meaning| {
        let direction = match meaning.direction {
            SpineRelationshipDirection::Directed => "directed",
        };
        json!({
            "relationship": meaning.name,
            "direction": direction,
            "gloss": meaning.gloss,
        })
    });
    json!({ "types": types, "relationships": relationships })
}

fn semantic_contract(catalogs: &Value) -> Value {
    let contract = json!({
        "revision": SEMANTIC_CONTRACT_REVISION,
        "catalogs": catalogs,
        "guarantee": GUARANTEE,
        "not_checked": NOT_CHECKED,
    });
    json!({
        "revision": SEMANTIC_CONTRACT_REVISION,
        "sha256": hex::encode(Sha256::digest(canonical_serialized(&contract))),
    })
}

async fn event_head<E: DomainStatementExecutor>(
    executor: &mut E,
    relation: &'static str,
) -> Result<i64> {
    let statement = StatementTemplate::new(
        StatementKind::Select,
        relation,
        &["SELECT COALESCE(MAX(seq),0) AS head FROM {{relation}}"],
    )
    .map_err(|error| super::stable_storage_error("preview record shape revision", &error))?;
    let rows = executor
        .fetch_all(
            &statement,
            &[],
            &[ColumnSpec::required("head", LogicalType::Integer)],
        )
        .await
        .map_err(|error| super::stable_storage_error("preview record shape revision", &error))?;
    match rows.first().and_then(|row| row.get("head")) {
        Some(NormalizedValue::Integer(head)) => Ok(*head),
        _ => Err(Error::engine(
            "preview record shape revision state is invalid",
        )),
    }
}

fn serialized(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("a serde_json::Value always serializes")
}

fn canonical_serialized(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).expect("a serde_json::Value always has a JCS representation")
}

fn omission(identity: String, fragment: Value, continuation: Value) -> Value {
    let bytes = serialized(&fragment);
    json!({
        "omitted": {
            "identity": identity,
            "sha256": hex::encode(Sha256::digest(&bytes)),
            "utf8_bytes": bytes.len(),
            "continuation": continuation,
        }
    })
}

fn omission_with_continuations(
    identity: String,
    fragment: Value,
    continuations: Vec<Value>,
) -> Value {
    let bytes = serialized(&fragment);
    json!({
        "omitted": {
            "identity": identity,
            "sha256": hex::encode(Sha256::digest(&bytes)),
            "utf8_bytes": bytes.len(),
            "continuations": continuations,
        }
    })
}

fn kind_continuation(record_type: &str) -> Value {
    json!({
        "executor": "schema_read",
        "operation": "manage_vocabularies.list_values",
        "arguments": {
            "vocabulary": format!("kind:{record_type}"),
            "resolve_aliases": true,
        },
    })
}

fn selection_continuations(selection: &Value, record_type: &str) -> Vec<Value> {
    let mut continuations = vec![kind_continuation(record_type)];
    let cross_type_matches = selection
        .get("cross_type_matches")
        .and_then(Value::as_array);
    let existing_continuations = selection
        .pointer("/details/omitted/continuations")
        .and_then(Value::as_array);
    for cross_type in SPINE_TYPES {
        if cross_type == record_type {
            continue;
        }
        let has_direct_match = cross_type_matches.is_some_and(|matches| {
            matches.iter().any(|kind_match| {
                kind_match.get("type").and_then(Value::as_str) == Some(cross_type)
            })
        });
        let vocabulary = format!("kind:{cross_type}");
        let has_existing_continuation = existing_continuations.is_some_and(|existing| {
            existing.iter().any(|continuation| {
                continuation
                    .pointer("/arguments/vocabulary")
                    .and_then(Value::as_str)
                    == Some(vocabulary.as_str())
            })
        });
        if has_direct_match || has_existing_continuation {
            continuations.push(kind_continuation(cross_type));
        }
    }
    continuations.push(schema_continuation());
    continuations
}

fn schema_continuation() -> Value {
    json!({
        "executor": "schema_read",
        "operation": "manage_schema_config.read",
        "arguments": {},
    })
}

fn identity_component(value: &str) -> String {
    if value.len() <= 128 {
        value.to_string()
    } else {
        format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
    }
}

fn bounded_identity_component(value: &str) -> String {
    if value.len() <= 64 {
        value.to_string()
    } else {
        format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
    }
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn bounded_value_identity(value: &Value) -> Value {
    let bytes = canonical_serialized(value);
    json!({
        "json_type": json_type(value),
        "sha256": hex::encode(Sha256::digest(&bytes)),
        "utf8_bytes": bytes.len(),
    })
}

fn bounded_predicate_assessment(
    key: &str,
    facet: &crate::domain_transaction::FacetWrite,
    assessment: crate::domain_transaction::FacetPredicateAssessment,
) -> Value {
    let vocabulary = assessment.governing_vocabulary.map(|vocabulary| {
        json!({
            "id": bounded_identity_component(&vocabulary.id),
            "name": bounded_identity_component(&vocabulary.name),
        })
    });
    let resolution = assessment.value_resolution.map(|resolution| {
        json!({
            "classification": resolution.classification,
            "id": resolution.id.as_deref().map(bounded_identity_component),
            "status": resolution.status,
            "canonical_id": resolution.canonical_id.as_deref().map(bounded_identity_component),
            "canonical_value": resolution.canonical_value.as_deref().map(bounded_identity_component),
        })
    });
    json!({
        "key": bounded_identity_component(key),
        "create_record_input": {
            "field": "facets",
            "key": bounded_identity_component(key),
        },
        "declaration": if assessment.declared { "declared" } else { "open" },
        "status": if assessment.accepted { "accepted" } else { "rejected" },
        "value": bounded_value_identity(&facet.value),
        "declared_type": assessment.declared_type,
        "governing_vocabulary": vocabulary,
        "value_resolution": resolution,
        "issues": assessment.issues.into_iter().map(|issue| issue.code).collect::<Vec<_>>(),
    })
}

fn carrier_assessment(key: &str, facet: &crate::domain_transaction::FacetWrite) -> Option<Value> {
    use crate::domain_transaction::FacetKeyClassification;
    let key_identity = bounded_identity_component(key);
    match crate::domain_transaction::classify_facet_key(key) {
        FacetKeyClassification::Open => None,
        FacetKeyClassification::Spine { create_record_path } => Some(json!({
            "key": key_identity,
            "create_record_input": { "field": create_record_path },
            "declaration": "spine",
            "status": "rejected",
            "value": bounded_value_identity(&facet.value),
            "declared_type": Value::Null,
            "governing_vocabulary": Value::Null,
            "value_resolution": Value::Null,
            "issues": ["spine_facet_wrong_carrier"],
        })),
        FacetKeyClassification::EngineReserved => Some(json!({
            "key": key_identity,
            "create_record_input": Value::Null,
            "declaration": "engine_reserved",
            "status": "rejected",
            "value": bounded_value_identity(&facet.value),
            "declared_type": Value::Null,
            "governing_vocabulary": Value::Null,
            "value_resolution": Value::Null,
            "issues": ["engine_reserved_facet"],
        })),
    }
}

fn required_declarations(
    effective_shape: &Map<String, Value>,
    supplied: &std::collections::BTreeSet<String>,
) -> (Vec<Value>, usize) {
    let required = effective_shape
        .iter()
        .filter(|(_, shape)| shape.get("required").and_then(Value::as_bool) == Some(true))
        .collect::<Vec<_>>();
    let omitted_count = required.len().saturating_sub(MAX_PROPOSED_FACETS);
    let declarations = required
        .into_iter()
        .take(MAX_PROPOSED_FACETS)
        .map(|(key, _)| {
            let key_identity = bounded_identity_component(key);
            if let Some(path) = crate::schema::spine_facet_column(key) {
                json!({
                    "key": key_identity,
                    "create_record_input": { "field": path },
                    "carrier": "top_level",
                    "candidate_presence": "outside_facet_only_preview_input",
                    "status": "informational",
                    "issues": [],
                })
            } else {
                let supplied = supplied.contains(key);
                json!({
                    "key": key_identity.clone(),
                    "create_record_input": { "field": "facets", "key": key_identity },
                    "carrier": "facets",
                    "candidate_presence": if supplied { "supplied" } else { "not_supplied" },
                    "status": if supplied { "accepted" } else { "rejected" },
                    "issues": if supplied { json!([]) } else { json!(["required_facet_not_supplied"]) },
                })
            }
        })
        .collect();
    (declarations, omitted_count)
}

fn compact_proposed_facet_details(response: &mut Value) {
    let Some(assessments) = response
        .pointer_mut("/proposed_facets/assessments")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for assessment in assessments {
        if let Some(object) = assessment.as_object_mut() {
            object.remove("declared_type");
            if let Some(vocabulary) = object
                .get_mut("governing_vocabulary")
                .and_then(Value::as_object_mut)
            {
                vocabulary.remove("name");
            }
            if let Some(resolution) = object
                .get_mut("value_resolution")
                .and_then(Value::as_object_mut)
            {
                resolution.remove("canonical_value");
            }
        }
    }
}

fn omit_required_declarations(response: &mut Value) {
    let Some(proposed) = response
        .get_mut("proposed_facets")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let declarations = proposed
        .get_mut("required_declarations")
        .map(Value::take)
        .unwrap_or_else(|| json!([]));
    let count = declarations.as_array().map_or(0, Vec::len);
    if count == 0 {
        proposed.insert("required_declarations".into(), json!([]));
        return;
    }
    let bytes = canonical_serialized(&declarations);
    let already_omitted = proposed
        .get("required_declarations_omitted_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    proposed.insert("required_declarations".into(), json!([]));
    proposed.insert(
        "required_declarations_omitted_count".into(),
        json!(already_omitted + count as u64),
    );
    proposed.insert(
        "required_declarations_omission".into(),
        json!({
            "sha256": hex::encode(Sha256::digest(&bytes)),
            "utf8_bytes": bytes.len(),
            "returned_entries": count,
        }),
    );
}

fn omit_kind_metadata(selection: &mut Value, record_type: &str, kind: Option<&str>) {
    let continuation = kind_continuation(record_type);
    let Some(kinds) = selection
        .get_mut("active_kinds")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for definition in kinds {
        let token = definition
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let value_id = definition
            .get("value_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        if let Some(metadata) = definition.get_mut("metadata") {
            if metadata.get("omitted").is_some() {
                continue;
            }
            let fragment = metadata.take();
            *metadata = omission(
                format!(
                    "kind_definition:{record_type}:{}:{}",
                    identity_component(&token),
                    identity_component(&value_id)
                ),
                fragment,
                continuation.clone(),
            );
        }
    }
    if let Some(metadata) = selection
        .get_mut("kind_resolution")
        .and_then(|resolution| resolution.get_mut("metadata"))
        .filter(|metadata| !metadata.is_null())
    {
        let fragment = metadata.take();
        *metadata = omission(
            format!(
                "kind_resolution:{record_type}:{}",
                identity_component(kind.unwrap_or("unknown"))
            ),
            fragment,
            continuation,
        );
    }
}

fn omit_facet_shapes(selection: &mut Value, record_type: &str, kind: Option<&str>) {
    let continuation = schema_continuation();
    let Some(facets) = selection
        .get_mut("effective_facet_shape")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    for (key, shape) in facets {
        if shape.get("omitted").is_some() {
            continue;
        }
        let fragment = shape.take();
        *shape = omission(
            format!(
                "facet_shape:{record_type}:{}:{}",
                identity_component(kind.unwrap_or("base")),
                identity_component(key)
            ),
            fragment,
            continuation.clone(),
        );
    }
}

fn omit_section(selection: &mut Value, key: &str, identity: String, continuation: &Value) {
    let Some(fragment) = selection.get_mut(key) else {
        return;
    };
    if fragment.get("omitted").is_some() {
        return;
    }
    let value = fragment.take();
    *fragment = omission(identity, value, continuation.clone());
}

/// Enforce the transport boundary against the exact serialized response. The
/// reduction order is fixed and authored fragments are always replaced whole:
/// no prefix can be mistaken for a complete definition or schema declaration.
fn serialized_response_len(response: &Value, run_context: Option<&Value>) -> usize {
    let Some(run_context) = run_context.filter(|context| !context.is_null()) else {
        return serialized(response).len();
    };
    let mut decorated = response.clone();
    if let Some(object) = decorated.as_object_mut() {
        object.insert("run_context".into(), run_context.clone());
    } else {
        decorated = json!({ "value": decorated, "run_context": run_context });
    }
    serialized(&decorated).len()
}

fn bound_response(
    mut response: Value,
    record_type: Option<&str>,
    kind: Option<&str>,
    run_context: Option<&Value>,
) -> Result<Value> {
    if serialized_response_len(&response, run_context) <= MAX_RESPONSE_BYTES {
        return Ok(response);
    }
    let Some(record_type) = record_type else {
        // The catalog-only form contains no user-authored fragments and is
        // statically far below the boundary.
        return (serialized_response_len(&response, run_context) <= MAX_RESPONSE_BYTES)
            .then_some(response)
            .ok_or_else(|| {
                Error::engine("preview_record_shape: static response exceeds 65536 bytes")
            });
    };
    let kind_continuation = kind_continuation(record_type);
    let schema_continuation = schema_continuation();
    let selection = response
        .get_mut("selection")
        .expect("selected response has a selection object");
    omit_kind_metadata(selection, record_type, kind);
    omit_facet_shapes(selection, record_type, kind);
    if serialized_response_len(&response, run_context) <= MAX_RESPONSE_BYTES {
        return Ok(response);
    }

    // A database can contain many individually small definitions. Compact the
    // remaining authored collections as whole fragments so their marker count
    // cannot itself violate the response boundary.
    for (key, identity) in [
        (
            "active_kinds",
            format!("active_kind_definitions:{record_type}"),
        ),
        (
            "effective_facet_shape",
            format!(
                "effective_facet_shape:{record_type}:{}",
                identity_component(kind.unwrap_or("base"))
            ),
        ),
        (
            "facet_provenance",
            format!(
                "facet_provenance:{record_type}:{}",
                identity_component(kind.unwrap_or("base"))
            ),
        ),
        ("kind_shapes", format!("kind_shapes:{record_type}")),
    ] {
        let selection = response
            .get_mut("selection")
            .expect("selected response has a selection object");
        let continuation = if key == "active_kinds" {
            &kind_continuation
        } else {
            &schema_continuation
        };
        omit_section(selection, key, identity, continuation);
        if serialized_response_len(&response, run_context) <= MAX_RESPONSE_BYTES {
            return Ok(response);
        }
    }

    // Exact resolution can itself carry an authored warning or unusually long
    // raw token. Preserve its complete identity through the same marker.
    let selection = response
        .get_mut("selection")
        .expect("selected response has a selection object");
    omit_section(
        selection,
        "kind_resolution",
        format!(
            "kind_resolution:{record_type}:{}",
            identity_component(kind.unwrap_or("none"))
        ),
        &kind_continuation,
    );

    if serialized_response_len(&response, run_context) > MAX_RESPONSE_BYTES {
        let selection = response
            .get_mut("selection")
            .expect("selected response has a selection object");
        omit_section(
            selection,
            "kind",
            format!(
                "requested_kind:{record_type}:{}",
                identity_component(kind.unwrap_or("none"))
            ),
            &kind_continuation,
        );
    }
    if serialized_response_len(&response, run_context) > MAX_RESPONSE_BYTES {
        let fragment = response["selection"].take();
        let continuations = selection_continuations(&fragment, record_type);
        response["selection"] = json!({
            "type": record_type,
            "details": omission_with_continuations(
                format!("record_shape_selection:{record_type}"),
                fragment,
                continuations,
            ),
        });
    }
    if serialized_response_len(&response, run_context) > MAX_RESPONSE_BYTES {
        compact_proposed_facet_details(&mut response);
    }
    if serialized_response_len(&response, run_context) > MAX_RESPONSE_BYTES {
        omit_required_declarations(&mut response);
    }
    (serialized_response_len(&response, run_context) <= MAX_RESPONSE_BYTES)
        .then_some(response)
        .ok_or_else(|| Error::engine("preview_record_shape: static response exceeds 65536 bytes"))
}

/// Re-apply the preview's transport bound after the governed request wrapper
/// has resolved the exact run context that every ordinary MCP response echoes.
/// This makes 65,536 bytes a bound on successful structuredContent, rather
/// than merely on the handler payload before universal decoration.
pub(crate) fn bound_preview_response_for_run_context(
    response: Value,
    run_context: &Value,
) -> Result<Value> {
    let record_type = response
        .pointer("/selection/type")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let kind = response
        .pointer("/selection/kind")
        .and_then(Value::as_str)
        .map(str::to_owned);
    bound_response(
        response,
        record_type.as_deref(),
        kind.as_deref(),
        Some(run_context),
    )
}

pub(crate) async fn execute_preview_record_shape<E: DomainStatementExecutor>(
    executor: &mut E,
    _caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    let args = parse_arguments(arguments)?;
    let proposed_facets = args
        .facets
        .as_ref()
        .map(|facets| {
            let mut entries = facets.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            entries
                .into_iter()
                .map(|(key, value)| {
                    crate::domain_transaction::parse_facet_write_value(
                        "preview_record_shape",
                        key,
                        value,
                    )
                    .map(|facet| (key.clone(), facet))
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let catalogs = static_catalogs();
    let semantic_contract = semantic_contract(&catalogs);
    let meta_head = event_head(executor, "meta_events").await?;
    let content_head = event_head(executor, "content_events").await?;
    let mut response = json!({
        "schema": RESPONSE_SCHEMA,
        "catalogs": catalogs,
        "selection": Value::Null,
        "advisory_basis": {
            "engine_schema_version": CURRENT_ENGINE_SCHEMA_VERSION,
            "schema_state_revision": format!("schema-state-v1:meta:{meta_head}:content:{content_head}"),
            "event_heads": { "meta": meta_head, "content": content_head },
            "semantic_contract": semantic_contract,
            "shape_scope": "global schema declarations only; global governance is caller-visible and collection-scoped declarations do not govern create_record",
        },
        "advisory_only": true,
        "accepted_by_create_record": false,
        "accepted_by_create_record_meaning": "This preview is not a whole-record write-admission verdict or commit token; scoped proposed_facets assessments report only deterministic facet-specific predicates.",
        "zero_authoritative_writes": true,
        "guarantee": GUARANTEE,
        "not_checked": NOT_CHECKED,
    });

    if let Some(record_type) = args.record_type.as_deref() {
        // All three reads use the executor borrowed by this call. The backend
        // wrapper owns snapshot admission and completion.
        let rows = cascade::schema_config_rows_with(executor).await?;
        let resolved = cascade::resolve_from_rows(&rows);
        let mut active_kinds = crate::meta::kind::list_active_with(executor, record_type).await?;
        active_kinds.sort_by(|left, right| {
            left.token
                .as_bytes()
                .cmp(right.token.as_bytes())
                .then_with(|| left.value_id.as_bytes().cmp(right.value_id.as_bytes()))
        });
        let kind_resolution = match args.kind.as_deref() {
            Some(kind) => Some(crate::meta::kind::resolve_with(executor, record_type, kind).await?),
            None => None,
        };
        let cross_type_matches = match args.kind.as_deref() {
            Some(kind) => crate::meta::kind::governed_matches_for_token_with(executor, kind)
                .await?
                .into_iter()
                .filter(|kind_match| kind_match.record_type != record_type)
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };
        let raw_kind = args.kind.as_deref();
        let effective_kind = kind_resolution
            .as_ref()
            .and_then(|resolution| resolution.canonical_kind_for_write())
            .or(raw_kind);
        let global_rows: Vec<_> = rows
            .iter()
            .filter(|row| row.applies_to_collection_id.is_none())
            .collect();
        let global_rows_bytes = canonical_serialized(&json!(global_rows));
        let global_row_count = global_rows.len();
        let global_rows_sha256 = hex::encode(Sha256::digest(&global_rows_bytes));
        let effective_facet_shape =
            cascade::facets_for_type(&resolved.resolved, record_type, effective_kind);
        response["selection"] = json!({
            "type": record_type,
            "kind": raw_kind,
            "effective_kind": effective_kind,
            "spine_facets": SPINE_FACET_KEYS,
            "active_kinds": active_kinds,
            "kind_resolution": kind_resolution,
            "cross_type_matches": cross_type_matches,
            "effective_facet_shape": effective_facet_shape,
            "facet_provenance": cascade::provenance_for_type(&rows, record_type, effective_kind),
            "kind_shapes": cascade::kind_shapes(&resolved.resolved, record_type),
        });
        response["advisory_basis"]["global_schema"] = json!({
            "row_count": global_row_count,
            "sha256": global_rows_sha256,
            "utf8_bytes": global_rows_bytes.len(),
        });

        if let Some(proposed_facets) = proposed_facets.as_ref() {
            let supplied = proposed_facets
                .iter()
                .map(|(key, _)| key.clone())
                .collect::<std::collections::BTreeSet<_>>();
            let effective_shape = response["selection"]["effective_facet_shape"]
                .as_object()
                .expect("effective facet shape is an object")
                .clone();
            let mut assessments = Vec::with_capacity(proposed_facets.len());
            for (key, facet) in proposed_facets {
                if let Some(assessment) = carrier_assessment(key, facet) {
                    assessments.push(assessment);
                    continue;
                }
                let assessment = crate::domain_transaction::assess_facet_write(
                    executor,
                    effective_shape.get(key),
                    "preview_record_shape",
                    record_type,
                    effective_kind,
                    facet,
                )
                .await?;
                assessments.push(bounded_predicate_assessment(key, facet, assessment));
            }
            let supplied_values_accepted = assessments
                .iter()
                .all(|assessment| assessment.get("status") == Some(&json!("accepted")));
            let (required_declarations, required_declarations_omitted_count) =
                required_declarations(&effective_shape, &supplied);
            let required_facets_supplied = effective_shape.iter().all(|(key, declaration)| {
                declaration.get("required").and_then(Value::as_bool) != Some(true)
                    || crate::schema::spine_facet_column(key).is_some()
                    || supplied.contains(key)
            });
            let accepted = supplied_values_accepted && required_facets_supplied;
            response["proposed_facets"] = json!({
                "status": if accepted { "accepted" } else { "rejected" },
                "assessment_scope": "facet-specific deterministic create_record predicates only",
                "context": {
                    "type": record_type,
                    "kind": effective_kind.map(bounded_identity_component),
                },
                "assessments": assessments,
                "required_declarations": required_declarations,
                "required_declarations_omitted_count": required_declarations_omitted_count,
            });
        }
    }

    // Pin the complete decision before transport compaction. A caller can
    // therefore compare the exact advisory facts even when one or more
    // user-authored fragments are returned as omission markers.
    let (decision_scope, decision) = if response.get("proposed_facets").is_some() {
        (
            "selection_and_proposed_facets",
            json!({
                "selection": response["selection"].clone(),
                "proposed_facets": response["proposed_facets"].clone(),
            }),
        )
    } else if response["selection"].is_null() {
        ("catalogs", response["catalogs"].clone())
    } else {
        ("selection", response["selection"].clone())
    };
    let decision_bytes = canonical_serialized(&decision);
    response["advisory_basis"]["decision_digest"] = json!({
        "scope": decision_scope,
        "sha256": hex::encode(Sha256::digest(&decision_bytes)),
        "utf8_bytes": decision_bytes.len(),
    });

    bound_response(
        response,
        args.record_type.as_deref(),
        args.kind.as_deref(),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_closed_and_kind_requires_type() {
        assert!(parse_arguments(json!({})).is_ok());
        assert!(parse_arguments(json!({ "type": "Document" })).is_ok());
        assert!(parse_arguments(json!({ "type": "Document", "kind": "note" })).is_ok());
        assert!(parse_arguments(json!({ "kind": "note" })).is_err());
        assert!(parse_arguments(json!({ "type": "document" })).is_err());
        assert!(parse_arguments(json!({ "type": "Document", "kind": " \n" })).is_err());
        assert!(parse_arguments(json!({ "extra": true })).is_err());
    }

    #[test]
    fn omission_hashes_the_complete_utf8_fragment_without_slicing() {
        let fragment = json!({ "definition": "évidence".repeat(10_000) });
        let expected = serialized(&fragment);
        let marker = omission(
            "kind_definition:Document:large:vv:large".into(),
            fragment,
            kind_continuation("Document"),
        );
        assert_eq!(marker["omitted"]["utf8_bytes"], expected.len());
        assert_eq!(
            marker["omitted"]["sha256"],
            hex::encode(Sha256::digest(&expected))
        );
        assert!(marker.to_string().len() < expected.len());
    }

    #[test]
    fn exact_serialized_boundary_compacts_authored_sections() {
        let large = "x".repeat(MAX_RESPONSE_BYTES);
        let response = json!({
            "schema": RESPONSE_SCHEMA,
            "catalogs": static_catalogs(),
            "selection": {
                "type": "Document",
                "kind": "note",
                "active_kinds": [{
                    "token": "note",
                    "value_id": "vv:note",
                    "metadata": { "definition": large },
                }],
                "kind_resolution": Value::Null,
                "effective_facet_shape": { "body": { "description": "y".repeat(MAX_RESPONSE_BYTES) } },
                "facet_provenance": { "body": "user:Document" },
                "kind_shapes": ["note"],
            },
            "advisory_basis": { "engine_schema_version": CURRENT_ENGINE_SCHEMA_VERSION },
            "guarantee": GUARANTEE,
            "not_checked": NOT_CHECKED,
        });
        let bounded = bound_response(response, Some("Document"), Some("note"), None).unwrap();
        assert!(serialized(&bounded).len() <= MAX_RESPONSE_BYTES);
        assert!(bounded["selection"]["active_kinds"][0]["metadata"]["omitted"].is_object());
        assert!(bounded["selection"]["effective_facet_shape"]["body"]["omitted"].is_object());
    }

    #[test]
    fn decorated_boundary_uses_the_exact_run_context_size() {
        let response = json!({
            "schema": RESPONSE_SCHEMA,
            "catalogs": static_catalogs(),
            "selection": {
                "type": "Document",
                "kind": "note",
                "active_kinds": [{
                    "token": "note",
                    "value_id": "vv:note",
                    "metadata": { "definition": "x".repeat(MAX_RESPONSE_BYTES) },
                }],
                "kind_resolution": Value::Null,
                "effective_facet_shape": {},
                "facet_provenance": {},
                "kind_shapes": [],
            },
            "advisory_basis": {},
        });
        let run_context = json!({
            "run_key": "scout-chair-a748b2",
            "intent": "bounded transport".repeat(100),
        });
        let bounded = bound_preview_response_for_run_context(response, &run_context).unwrap();
        assert!(serialized_response_len(&bounded, Some(&run_context)) <= MAX_RESPONSE_BYTES);
    }

    #[test]
    fn whole_selection_marker_preserves_all_kind_and_schema_continuations() {
        let response = json!({
            "schema": RESPONSE_SCHEMA,
            "catalogs": static_catalogs(),
            "selection": {
                "type": "Document",
                "kind": "note",
                "active_kinds": [],
                "kind_resolution": Value::Null,
                "cross_type_matches": [
                    { "type": "Resolution", "canonical_kind": "decision" },
                    { "type": "Program", "canonical_kind": "decision" },
                    { "type": "Resolution", "canonical_kind": "decision-alias" },
                ],
                "effective_facet_shape": {},
                "facet_provenance": {},
                "kind_shapes": [],
                "unhandled_authored_fact": "x".repeat(MAX_RESPONSE_BYTES),
            },
            "advisory_basis": {},
        });
        let bounded = bound_response(response, Some("Document"), Some("note"), None).unwrap();
        let continuations = bounded["selection"]["details"]["omitted"]["continuations"]
            .as_array()
            .unwrap();
        assert_eq!(continuations.len(), 4);
        assert_eq!(
            continuations[0]["operation"],
            "manage_vocabularies.list_values"
        );
        assert_eq!(continuations[0]["arguments"]["vocabulary"], "kind:Document");
        assert_eq!(continuations[1]["arguments"]["vocabulary"], "kind:Program");
        assert_eq!(
            continuations[2]["arguments"]["vocabulary"],
            "kind:Resolution"
        );
        assert_eq!(continuations[3]["operation"], "manage_schema_config.read");

        let rebound_continuations = selection_continuations(&bounded["selection"], "Document");
        assert_eq!(rebound_continuations.len(), 4);
        assert_eq!(
            rebound_continuations[1]["arguments"]["vocabulary"],
            "kind:Program"
        );
        assert_eq!(
            rebound_continuations[2]["arguments"]["vocabulary"],
            "kind:Resolution"
        );
    }
}
