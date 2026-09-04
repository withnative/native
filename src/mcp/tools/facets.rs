//! Tools 15–16 — the facet pair, the first consumers of stage 1's
//! `query::cascade` resolver (finding 4).
//!
//! `resolve_facets` answers "what facet shape is in effect here": the four
//! spine columns, the resolved pack → user cascade for the type, and (when
//! asked about a record) its current values. Both the pack view and the
//! resolved view are returned — the interop-floor judgement (tool 21,
//! rejection (a)) is a comparison BETWEEN the two, and this tool's output is
//! where a caller sees the same distinction.
//!
//! `suggest_facet_values` is a pure vocabulary lookup in CE (no LLM): facet
//! key → governing vocabulary via the resolved cascade, then the active,
//! alias-resolved value listing from `meta::vocabulary::list_values`.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::meta::vocabulary::{get_vocabulary, list_values, resolve_vocab_ref, ListValuesOptions};
use crate::query::{cascade, read};
use crate::schema::SPINE_FACET_KEYS;

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{can_record, parse_args, require_record};

const SHAPE_GUARANTEE: &str = "Supported record-writing tools enforce global declared type, values, and governing vocabulary membership absolutely for every outgoing open-facet value, using the resulting kind and the same write-transaction snapshot; global required is enforced post-batch and comparatively (new missing facets are refused, unchanged legacy gaps remain editable); multi is rejected at schema authoring. Collection-scoped declarations are discoverability metadata: resolve_facets on the bearing record may display them, but filing home never contributes schema to a child's product facet context and writers do not enforce them in V1. These checks are forward-only, are not re-run during replay, do not retroactively certify stored values, and can be bypassed through store::append* or direct trusted-filesystem mutation of the ejectable SQLite file; Db::pool() is physically read-only. This response is not a standing data-invariant certificate. V1 rejects declared type on string-carried spine facets.";
const MAX_RESOLVED_VALUES: usize = 10_000;
const MAX_VOCABULARY_SUGGESTIONS: usize = 10_000;

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

async fn visible_schema_rows(
    db: &Db,
    caller: &Caller,
) -> Result<Vec<crate::query::cascade::SchemaConfigRow>> {
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    cascade::schema_config_rows_for_principal(db, principal).await
}

async fn resolve_facets(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ResolveFacetsArgs = parse_args("resolve_facets", arguments)?;
    let rows = visible_schema_rows(&db, &caller).await?;
    match (args.record_id, args.record_type) {
        (Some(record_id), None) => {
            if !can_record(&db, &caller, &record_id, Capability::View).await? {
                return Err(Error::engine(format!("record {record_id} does not exist")));
            }
            let Some(record) = read::get_record(&db, &record_id).await? else {
                return Err(Error::engine(format!("record {record_id} does not exist")));
            };
            if record.facets.len() > MAX_RESOLVED_VALUES {
                return Err(Error::engine(format!(
                    "resolve_facets: value set exceeds {MAX_RESOLVED_VALUES} rows"
                )));
            }
            let record_type = record.record.record_type.clone();
            let kind = record.record.kind.clone();
            let owner = match record.record.owner_id.as_deref() {
                Some(owner) if can_record(&db, &caller, owner, Capability::View).await? => {
                    Some(owner.to_string())
                }
                _ => None,
            };
            let response = json!({
                "record_id": record_id,
                "type": record_type,
                "kind": kind,
                "bears_shape": cascade::bears_shape_from_rows(&rows, &record_id),
                "spine": {
                    "lifecycle": record.record.lifecycle,
                    "owner": owner,
                    "persistence": record.record.persistence,
                    "maturity": record.record.maturity,
                },
                "archived": record.archived,
                "shape": cascade::facets_for_record_context(&rows, &record_type, kind.as_deref(), Some(&record_id)),
                "pack_shape": cascade::pack_facets_for_record_context(&rows, &record_type, kind.as_deref(), Some(&record_id)),
                "provenance": cascade::provenance_for_record_context(&rows, &record_type, kind.as_deref(), Some(&record_id)),
                "values": record.facets,
                "shape_guarantee": SHAPE_GUARANTEE,
            });
            Ok(response)
        }
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

async fn suggest_facet_values(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: SuggestFacetValuesArgs = parse_args("suggest_facet_values", arguments)?;
    let (record_type, kind, bearer_id) = match (args.record_id, args.record_type) {
        (Some(record_id), None) => {
            require_record(
                &db,
                &caller,
                "suggest_facet_values",
                &record_id,
                Capability::View,
            )
            .await?;
            let Some(record) = read::get_record(&db, &record_id).await? else {
                return Err(Error::engine(format!("record {record_id} does not exist")));
            };
            (
                record.record.record_type,
                record.record.kind,
                Some(record_id),
            )
        }
        (None, Some(record_type)) => (record_type, args.kind, None),
        _ => Err(Error::engine(
            "suggest_facet_values takes exactly one of record_id or type",
        ))?,
    };
    let rows = visible_schema_rows(&db, &caller).await?;
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
    let vocabulary = resolve_vocab_ref(&governing);
    let suggestions = list_values(
        &db,
        vocabulary,
        ListValuesOptions {
            status: Some("active".into()),
            resolve_aliases: true,
        },
    )
    .await?;
    if suggestions.len() > MAX_VOCABULARY_SUGGESTIONS {
        return Err(Error::engine(format!(
            "suggest_facet_values: suggestion set exceeds {MAX_VOCABULARY_SUGGESTIONS} rows"
        )));
    }
    // `list_values` errored if the vocabulary were missing, so this is `Some`.
    let vocab = get_vocabulary(&db, vocabulary).await?;
    Ok(json!({
        "facet_key": args.facet_key,
        "type": record_type,
        "kind": kind,
        "declared_type": declared_type,
        "vocabulary": vocab,
        "suggestions": suggestions,
        "shape_guarantee": SHAPE_GUARANTEE,
    }))
}

/// Register tools 14–15.
pub fn register_facet_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ResolveFacets,
        "Resolve the effective facet shape for a record or a type: spine \
         columns, the pack → user schema_config cascade (both the pack view \
         and the resolved view), and — for a record — its current values, \
         derived bears_shape capability. Filing home never contributes schema.",
        json!({
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "description": "Resolve for this record (its type, plus current values)."
                },
                "type": {
                    "type": "string",
                    "description": "Resolve for a type alone (e.g. \"WorkItem\")."
                },
                "kind": {
                    "type": "string",
                    "description": "Optional kind when resolving by type. A record_id uses the record's own kind."
                }
            },
            "additionalProperties": false
        }),
        resolve_facets,
    )?;
    registry.register(
        ToolKind::SuggestFacetValues,
        "Valid values for a facet key from its governing vocabulary (active, \
         alias-resolved). No governing vocabulary is an empty answer, not an \
         error.",
        json!({
            "type": "object",
            "properties": {
                "facet_key": { "type": "string" },
                "record_id": {
                    "type": "string",
                    "description": "Take the type from this record."
                },
                "type": {
                    "type": "string",
                    "description": "Or name the type directly."
                },
                "kind": {
                    "type": "string",
                    "description": "Optional kind when resolving by type. A record_id uses the record's own kind."
                }
            },
            "required": ["facet_key"],
            "additionalProperties": false
        }),
        suggest_facet_values,
    )?;
    Ok(())
}
