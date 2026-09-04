//! Tools 16–19 plus the computed-rollup read — query & search
//! (docs/tool-surface.md §Query & search).
//!
//! `query_record` is a thin argument seam over `query::pipeline` — the engine
//! is stage 1's; this module only parses steps. `query_sql` wraps the
//! validated read-only path; its rejection messages ARE the user surface.
//! `scan` samples the file along orientation axes via the pipeline's count
//! terminal. `search` is the one tool whose behaviour is a decided spec
//! requirement (3bc7fd0 as amended by 6694126): strict FTS first, and when
//! results are thin, the three Layer-1 near-miss mechanisms (prefix
//! neighbours, the bounded `LIKE` infix pass of ea7e5bd, tree siblings) plus
//! an explicit reformulation prompt in the payload — agents do not reformulate
//! reliably unprompted.

use std::collections::{BTreeMap, HashMap, HashSet};

use schemars::r#gen::SchemaSettings;
use schemars::schema::Schema;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::db::{apply_schema, open_database, Db};
use crate::error::{Error, Result};
use crate::query::fts::{self, FtsOptions, SearchHit, NEAR_MISS_CAP, THIN_RESULTS_THRESHOLD};
use crate::query::lens::{self, ReadLens};
use crate::query::{activity, events, pipeline, sql};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::parse_args;

/// Per-axis sample size for `scan` (fixed, not caller-settable — the axis
/// payload always carries the full pool `count`, so the cap hides no depth).
const SCAN_SAMPLE_LIMIT: usize = 3;
/// A `scan` axis whose pool covers this share of the corpus is labelled
/// `saturated` — the filter, not the axis, is what needs tightening.
const SCAN_SATURATION_THRESHOLD: f64 = 0.10;
const DEFAULT_RECENT_WINDOW_DAYS: i64 = 14;
const MAX_RECENT_WINDOW_DAYS: i64 = 36_500;
const DEFAULT_HIGH_DEGREE_MIN: i64 = 8;

fn activity_requires_pinned_lens(tool: &str) -> Error {
    Error::engine(format!(
        "{tool}: activity execution requires its pinned historical membership lens"
    ))
}

// ---------------------------------------------------------------------------
// Tool 16 — query_record
// ---------------------------------------------------------------------------

const FACET_OPERATORS: [&str; 12] = [
    "value",
    "eq",
    "ne",
    "lt",
    "lte",
    "gt",
    "gte",
    "in",
    "lt_facet",
    "lte_facet",
    "gt_facet",
    "gte_facet",
];

struct ScalarFacetOperandSchema;

impl JsonSchema for ScalarFacetOperandSchema {
    fn schema_name() -> String {
        "ScalarFacetOperand".into()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(_generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        serde_json::from_value(json!({ "type": ["number", "string"] }))
            .expect("scalar facet schema is valid schemars output")
    }
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(untagged)]
enum LegacyFacetOperandSchema {
    String(String),
    Null(()),
}

// Runtime parsing deliberately stays on `Value` so every rejection can retain
// its step and facet indexes.
#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(deny_unknown_fields)]
struct FacetArgumentPropertiesSchema {
    key: String,
    /// Exact legacy value; null means existence.
    value: LegacyFacetOperandSchema,
    /// Exact equality.
    eq: String,
    /// Exact inequality.
    ne: String,
    /// Less than.
    lt: ScalarFacetOperandSchema,
    /// Less than or equal.
    lte: ScalarFacetOperandSchema,
    /// Greater than.
    gt: ScalarFacetOperandSchema,
    /// Greater than or equal.
    gte: ScalarFacetOperandSchema,
    /// Membership values.
    #[serde(rename = "in")]
    values: Vec<ScalarFacetOperandSchema>,
    /// Compare to another numeric facet.
    lt_facet: String,
    /// Compare to another numeric facet.
    lte_facet: String,
    /// Compare to another numeric facet.
    gt_facet: String,
    /// Compare to another numeric facet.
    gte_facet: String,
}

/// Adds the facet parser's arity and same-lane range constraints to the
/// schema derived from its typed property vocabulary.
struct FacetArgumentSchema;

impl JsonSchema for FacetArgumentSchema {
    fn schema_name() -> String {
        "FacetArgument".into()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        let schema = FacetArgumentPropertiesSchema::json_schema(generator);
        let mut value = serde_json::to_value(schema).expect("schema serializes");
        let object = value
            .as_object_mut()
            .expect("derived struct schema is an object");
        object.insert("required".into(), json!(["key"]));
        object.insert(
            "oneOf".into(),
            json!([
                { "minProperties": 1, "maxProperties": 1 },
                { "minProperties": 2, "maxProperties": 2 },
                {
                    "minProperties": 3,
                    "maxProperties": 3,
                    "allOf": [
                        {
                            "anyOf": [
                                { "required": ["gt", "lt"] },
                                { "required": ["gt", "lte"] },
                                { "required": ["gte", "lt"] },
                                { "required": ["gte", "lte"] }
                            ]
                        },
                        {
                            "anyOf": [
                                {
                                    "properties": {
                                        "gt": { "type": "number" },
                                        "gte": { "type": "number" },
                                        "lt": { "type": "number" },
                                        "lte": { "type": "number" }
                                    }
                                },
                                {
                                    "properties": {
                                        "gt": { "type": "string" },
                                        "gte": { "type": "string" },
                                        "lt": { "type": "string" },
                                        "lte": { "type": "string" }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]),
        );
        serde_json::from_value(value).expect("facet schema is valid schemars output")
    }
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum TraverseTargetSchema {
    Links,
    Children,
    Parents,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum TraverseDirectionSchema {
    Out,
    In,
    Both,
}

fn nullable_schema<T: JsonSchema>(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
    let value = serde_json::to_value(T::json_schema(generator)).expect("schema serializes");
    serde_json::from_value(json!({
        "anyOf": [value, { "type": "null" }]
    }))
    .expect("nullable enum schema is valid schemars output")
}

fn nullable_traverse_direction_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
    nullable_schema::<TraverseDirectionSchema>(generator)
}

#[derive(Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FilterStepArgs {
    /// Exact record IDs.
    ids: Option<Vec<String>>,
    /// Any record types.
    types: Option<Vec<String>>,
    /// Any kinds; suggestion/citation opts the whole pipeline into only that hidden family.
    kinds: Option<Vec<String>>,
    /// Direct home folder.
    home_id: Option<String>,
    /// Ancestor at any depth.
    ancestor_id: Option<String>,
    /// Any lifecycle tokens.
    lifecycle: Option<Vec<String>>,
    /// Any maturity tokens.
    maturity: Option<Vec<String>>,
    persistence: Option<String>,
    owner_id: Option<String>,
    /// Whether the record bears anchored schema.
    bears_shape: Option<bool>,
    /// True for a supported, valid saved-query envelope; validation does not execute saved queries.
    has_query: Option<bool>,
    /// ANDed facets: bare key means existence; number uses the numeric lane, string uses the exact-string/lexical lane; one same-key lower+upper bound range is allowed.
    #[schemars(with = "Option<Vec<FacetArgumentSchema>>")]
    facets: Option<Vec<Value>>,
    /// Case-insensitive name substring.
    name_contains: Option<String>,
    /// Inclusive update timestamp floor.
    updated_since: Option<String>,
    /// Inclusive activity timestamp floor.
    last_activity_since: Option<String>,
    /// Include archived records.
    include_archived: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct TraverseStepArgs {
    /// `links`, `children`, or `parents`.
    #[schemars(with = "TraverseTargetSchema")]
    target: String,
    /// Optional exact link relationship.
    relationship: Option<String>,
    /// Link direction; defaults to `both`.
    #[serde(default)]
    #[schemars(schema_with = "nullable_traverse_direction_schema")]
    direction: Option<String>,
}

#[allow(dead_code)]
#[allow(clippy::large_enum_variant)] // schema-only; no value is ever instantiated
#[derive(JsonSchema)]
#[serde(tag = "step", rename_all = "snake_case")]
enum QueryStepSchemaDerived {
    Filter(FilterStepArgs),
    Traverse(TraverseStepArgs),
}

struct QueryStepSchema;

impl JsonSchema for QueryStepSchema {
    fn schema_name() -> String {
        "QueryStep".into()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
        let schema = QueryStepSchemaDerived::json_schema(generator);
        let mut value = serde_json::to_value(schema).expect("schema serializes");
        for branch in value
            .get_mut("oneOf")
            .and_then(Value::as_array_mut)
            .expect("internally tagged enum has oneOf branches")
        {
            branch
                .as_object_mut()
                .expect("step branch is an object schema")
                .insert("additionalProperties".into(), Value::Bool(false));
        }
        serde_json::from_value(value).expect("step schema is valid schemars output")
    }
}

fn parse_facet_op(
    tool: &str,
    step_index: usize,
    facet_index: usize,
    operator: &str,
    argument: Value,
) -> Result<pipeline::FacetOp> {
    let scalar = |argument: &Value| {
        if argument.is_number() || argument.is_string() {
            Ok(argument.clone())
        } else {
            Err(Error::engine(format!(
                "{tool}: step {step_index} (filter), facet {facet_index}: \
                 '{operator}' requires a JSON number or string"
            )))
        }
    };
    let exact = |argument: Value| {
        if argument.is_number() {
            let guidance = if operator == "ne" {
                "use {ne: \"50\"} for token inequality; numeric quantity inequality \
                 is not expressible as one ANDed facet filter — run separate \
                 queries {lt: 50} and {gt: 50}, then union their results"
                    .to_string()
            } else {
                format!(
                    "use {{{operator}: \"50\"}} for the token, or \
                     {{gte: 50, lte: 50}} for the quantity"
                )
            };
            return Err(Error::engine(format!(
                "{tool}: step {step_index} (filter), facet {facet_index}: \
                 facet '{operator}' is string-exact and does not accept a JSON number; \
                 {guidance}"
            )));
        }
        argument.as_str().map(|_| argument.clone()).ok_or_else(|| {
            Error::engine(format!(
                "{tool}: step {step_index} (filter), facet {facet_index}: \
                 '{operator}' requires a JSON string"
            ))
        })
    };
    let other_key = |argument: Value| {
        argument.as_str().map(String::from).ok_or_else(|| {
            Error::engine(format!(
                "{tool}: step {step_index} (filter), facet {facet_index}: \
                 '{operator}' requires another facet key as a string"
            ))
        })
    };
    let op = match operator {
        // Historical `{key,value:null}` meant existence because `Option<String>`
        // deserialized JSON null as None. Preserve that edge as well as the
        // ordinary `{key}` and `{key,value:"..."}` forms.
        "value" if argument.is_null() => pipeline::FacetOp::Exists,
        "value" | "eq" => pipeline::FacetOp::Eq(exact(argument)?),
        "ne" => pipeline::FacetOp::Ne(exact(argument)?),
        "lt" => pipeline::FacetOp::Lt(scalar(&argument)?),
        "lte" => pipeline::FacetOp::Lte(scalar(&argument)?),
        "gt" => pipeline::FacetOp::Gt(scalar(&argument)?),
        "gte" => pipeline::FacetOp::Gte(scalar(&argument)?),
        "in" => {
            let values = argument.as_array().ok_or_else(|| {
                Error::engine(format!(
                    "{tool}: step {step_index} (filter), facet {facet_index}: \
                     'in' requires an array of JSON numbers or strings"
                ))
            })?;
            let values = values.iter().map(scalar).collect::<Result<Vec<_>>>()?;
            pipeline::FacetOp::In(values)
        }
        "lt_facet" => pipeline::FacetOp::CompareFacet {
            op: pipeline::CmpOp::Lt,
            other_key: other_key(argument)?,
        },
        "lte_facet" => pipeline::FacetOp::CompareFacet {
            op: pipeline::CmpOp::Lte,
            other_key: other_key(argument)?,
        },
        "gt_facet" => pipeline::FacetOp::CompareFacet {
            op: pipeline::CmpOp::Gt,
            other_key: other_key(argument)?,
        },
        "gte_facet" => pipeline::FacetOp::CompareFacet {
            op: pipeline::CmpOp::Gte,
            other_key: other_key(argument)?,
        },
        _ => unreachable!("operator allowlist checked above"),
    };
    Ok(op)
}

fn parse_facet_arg(
    tool: &str,
    step_index: usize,
    facet_index: usize,
    raw: Value,
) -> Result<Vec<pipeline::FacetFilter>> {
    let Some(mut object) = raw.as_object().cloned() else {
        return Err(Error::engine(format!(
            "{tool}: step {step_index} (filter), facet {facet_index}: must be an object"
        )));
    };
    let key = object
        .remove("key")
        .and_then(|value| value.as_str().map(String::from))
        .ok_or_else(|| {
            Error::engine(format!(
                "{tool}: step {step_index} (filter), facet {facet_index}: \
                 'key' must be a string"
            ))
        })?;
    if let Some(unknown) = object
        .keys()
        .find(|field| !FACET_OPERATORS.contains(&field.as_str()))
    {
        return Err(Error::engine(format!(
            "{tool}: step {step_index} (filter), facet {facet_index}: unknown field \
             '{unknown}'"
        )));
    }
    if object.is_empty() {
        return Ok(vec![pipeline::FacetFilter {
            key,
            op: pipeline::FacetOp::Exists,
        }]);
    }
    if object.len() > 2 {
        return Err(Error::engine(format!(
            "{tool}: step {step_index} (filter), facet {facet_index}: expected one \
             operator or one lower+upper range pair"
        )));
    }
    if object.len() == 2 {
        let lower = ["gt", "gte"]
            .into_iter()
            .find(|operator| object.contains_key(*operator));
        let upper = ["lt", "lte"]
            .into_iter()
            .find(|operator| object.contains_key(*operator));
        let (Some(lower), Some(upper)) = (lower, upper) else {
            let mut fields: Vec<&str> = object.keys().map(String::as_str).collect();
            fields.sort_unstable();
            return Err(Error::engine(format!(
                "{tool}: step {step_index} (filter), facet {facet_index}: only one \
                 lower bound ('gt' or 'gte') and one upper bound ('lt' or 'lte') \
                 may be combined, got {}",
                fields.join(", ")
            )));
        };
        let lower_value = object.get(lower).expect("lower key was found");
        let upper_value = object.get(upper).expect("upper key was found");
        let same_lane = (lower_value.is_number() && upper_value.is_number())
            || (lower_value.is_string() && upper_value.is_string());
        if !same_lane {
            return Err(Error::engine(format!(
                "{tool}: step {step_index} (filter), facet {facet_index}: combined \
                 range bounds must both be JSON numbers or both be JSON strings"
            )));
        }
        let lower_op = parse_facet_op(tool, step_index, facet_index, lower, lower_value.clone())?;
        let upper_op = parse_facet_op(tool, step_index, facet_index, upper, upper_value.clone())?;
        return Ok(vec![
            pipeline::FacetFilter {
                key: key.clone(),
                op: lower_op,
            },
            pipeline::FacetFilter { key, op: upper_op },
        ]);
    }

    let (operator, argument) = object.into_iter().next().expect("one operator");
    let op = parse_facet_op(tool, step_index, facet_index, &operator, argument)?;
    Ok(vec![pipeline::FacetFilter { key, op }])
}

fn filter_from_args(
    tool: &str,
    step_index: usize,
    args: FilterStepArgs,
) -> Result<pipeline::Filter> {
    let facets = args
        .facets
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(facet_index, facet)| parse_facet_arg(tool, step_index, facet_index, facet))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    Ok(pipeline::Filter {
        ids: args.ids.unwrap_or_default(),
        types: args.types.unwrap_or_default(),
        kinds: args.kinds.unwrap_or_default(),
        home_id: args.home_id,
        ancestor_id: args.ancestor_id,
        lifecycle: args.lifecycle.unwrap_or_default(),
        maturity: args.maturity.unwrap_or_default(),
        persistence: args.persistence,
        owner_id: args.owner_id,
        bears_shape: args.bears_shape,
        shape_capability_ids: None,
        has_query: args.has_query,
        query_capability_ids: None,
        facets,
        name_contains: args.name_contains,
        updated_since: args.updated_since,
        last_activity_since: args.last_activity_since,
        include_archived: args.include_archived.unwrap_or(false),
    })
}

/// Parse one step. Steps are dispatched on a `"step"` discriminator by hand so
/// every rejection names the step index and the rule it broke — the messages
/// are the tool's user surface, and validation happens for the WHOLE spec
/// before anything executes.
fn parse_step(tool: &str, index: usize, raw: &Value) -> Result<pipeline::Step> {
    let Some(object) = raw.as_object() else {
        return Err(Error::engine(format!(
            "{tool}: step {index} must be an object with a 'step' field"
        )));
    };
    let mut rest = object.clone();
    let Some(kind) = rest
        .remove("step")
        .and_then(|v| v.as_str().map(String::from))
    else {
        return Err(Error::engine(format!(
            "{tool}: step {index} has no 'step' field — expected 'filter' or 'traverse'"
        )));
    };
    let rest = Value::Object(rest);
    match kind.as_str() {
        "filter" => {
            let args: FilterStepArgs = serde_json::from_value(rest)
                .map_err(|err| Error::engine(format!("{tool}: step {index} (filter): {err}")))?;
            Ok(pipeline::Step::filter(filter_from_args(tool, index, args)?))
        }
        "traverse" => {
            let args: TraverseStepArgs = serde_json::from_value(rest)
                .map_err(|err| Error::engine(format!("{tool}: step {index} (traverse): {err}")))?;
            let traverse = match args.target.as_str() {
                "children" | "parents" => {
                    if args.relationship.is_some() || args.direction.is_some() {
                        return Err(Error::engine(format!(
                            "{tool}: step {index} (traverse): 'relationship' and \
                             'direction' apply to target 'links' only"
                        )));
                    }
                    if args.target == "children" {
                        pipeline::Traverse::Children
                    } else {
                        pipeline::Traverse::Parents
                    }
                }
                "links" => {
                    let direction = match args.direction.as_deref() {
                        None | Some("both") => pipeline::Direction::Both,
                        Some("out") => pipeline::Direction::Out,
                        Some("in") => pipeline::Direction::In,
                        Some(other) => {
                            return Err(Error::engine(format!(
                                "{tool}: step {index} (traverse): unknown direction \
                                 '{other}' — expected 'out', 'in' or 'both'"
                            )))
                        }
                    };
                    pipeline::Traverse::Links {
                        relationship: args.relationship,
                        direction,
                    }
                }
                other => {
                    return Err(Error::engine(format!(
                        "{tool}: step {index} (traverse): unknown target '{other}' — \
                         expected 'links', 'children' or 'parents'"
                    )))
                }
            };
            Ok(pipeline::Step::traverse(traverse))
        }
        other => Err(Error::engine(format!(
            "{tool}: step {index} has unknown step kind '{other}' — expected \
             'filter' or 'traverse'"
        ))),
    }
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum CountBySchema {
    Type,
    Kind,
    Lifecycle,
    Maturity,
    Persistence,
    Facet,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum RecordOrderSchema {
    UpdatedDesc,
    CreatedDesc,
    LastActivityDesc,
    NameAsc,
}

fn nullable_count_by_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
    nullable_schema::<CountBySchema>(generator)
}

fn nullable_record_order_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> Schema {
    nullable_schema::<RecordOrderSchema>(generator)
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum AggregateOpSchema {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum FacetOrderLaneSchema {
    Number,
    Text,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum SortDirectionSchema {
    Asc,
    Desc,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct QueryRecordArgs {
    #[schemars(with = "Vec<QueryStepSchema>", length(min = 1))]
    steps: Vec<Value>,
    /// Event activity over `steps`; exclusive with other terminals and paging.
    activity: Option<activity::ActivityArgs>,
    #[serde(default)]
    #[schemars(schema_with = "nullable_count_by_schema")]
    count_by: Option<String>,
    aggregate: Option<AggregateArgs>,
    facet_key: Option<String>,
    #[serde(default)]
    #[schemars(schema_with = "nullable_record_order_schema")]
    order: Option<String>,
    facet_order: Option<FacetOrderArgs>,
    #[schemars(range(min = 1, max = 500))]
    limit: Option<i64>,
    #[schemars(range(min = 0))]
    offset: Option<i64>,
}

#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AggregateArgs {
    #[schemars(with = "AggregateOpSchema")]
    op: pipeline::AggregateOp,
    #[schemars(length(min = 1))]
    facet_key: Option<String>,
}

fn aggregate_spec(tool: &str, args: AggregateArgs) -> Result<pipeline::AggregateSpec> {
    match args.op {
        pipeline::AggregateOp::Count if args.facet_key.is_some() => Err(Error::engine(format!(
            "{tool}: aggregate op 'count' does not take 'facet_key'"
        ))),
        pipeline::AggregateOp::Count => Ok(pipeline::AggregateSpec {
            op: args.op,
            facet_key: None,
        }),
        _ => {
            let key = args.facet_key.ok_or_else(|| {
                Error::engine(format!(
                    "{tool}: aggregate op '{}' requires 'facet_key'",
                    serde_json::to_value(args.op)
                        .ok()
                        .and_then(|value| value.as_str().map(String::from))
                        .unwrap_or_else(|| "numeric".into())
                ))
            })?;
            if key.trim().is_empty() {
                return Err(Error::engine(format!(
                    "{tool}: aggregate 'facet_key' must be a non-empty string"
                )));
            }
            Ok(pipeline::AggregateSpec {
                op: args.op,
                facet_key: Some(key),
            })
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FacetOrderArgs {
    #[schemars(length(min = 1))]
    key: String,
    #[schemars(with = "FacetOrderLaneSchema")]
    lane: String,
    #[schemars(with = "SortDirectionSchema")]
    direction: String,
}

enum QueryPlan {
    Aggregate {
        steps: Vec<pipeline::Step>,
        spec: pipeline::AggregateSpec,
    },
    Pipeline {
        steps: Vec<pipeline::Step>,
        count_by: Option<pipeline::CountAxis>,
        opts: pipeline::PipelineOptions,
    },
    Activity {
        steps: Vec<pipeline::Step>,
        args: activity::ActivityArgs,
        request: Value,
    },
}

impl QueryPlan {
    fn steps(&self) -> &[pipeline::Step] {
        match self {
            Self::Aggregate { steps, .. }
            | Self::Pipeline { steps, .. }
            | Self::Activity { steps, .. } => steps,
        }
    }

    fn steps_mut(&mut self) -> &mut [pipeline::Step] {
        match self {
            Self::Aggregate { steps, .. }
            | Self::Pipeline { steps, .. }
            | Self::Activity { steps, .. } => steps,
        }
    }
}

/// Parse and validate the complete `query_record` grammar without touching the
/// database. Saved-query capability derivation uses this exact seam, so a
/// record cannot acquire `has_query` under a weaker interpretation than a
/// direct call.
fn parse_query_plan(tool: &str, arguments: Value) -> Result<QueryPlan> {
    let request = arguments.clone();
    let args: QueryRecordArgs = parse_args(tool, arguments)?;
    if args.steps.is_empty() {
        return Err(Error::engine(format!(
            "{tool}: 'steps' must have at least one step (use an empty filter \
             step to select all live records)"
        )));
    }
    let steps = args
        .steps
        .iter()
        .enumerate()
        .map(|(index, raw)| parse_step(tool, index, raw))
        .collect::<Result<Vec<_>>>()?;
    if matches!(steps.first(), Some(pipeline::Step::Traverse(_))) {
        return Err(Error::engine(format!(
            "{tool}: pipeline cannot start with a traverse step — seed with a filter first"
        )));
    }
    if let Some(activity_args) = args.activity {
        if args.count_by.is_some() || args.aggregate.is_some() || args.facet_key.is_some() {
            return Err(Error::engine(format!(
                "{tool}: 'activity' cannot be combined with count_by, aggregate, or facet_key"
            )));
        }
        if args.order.is_some()
            || args.facet_order.is_some()
            || args.limit.is_some()
            || args.offset.is_some()
        {
            return Err(Error::engine(format!(
                "{tool}: activity terminals reject record ordering and paging fields; use activity.limit and activity.after_local_seq"
            )));
        }
        activity::validate(&activity_args)?;
        return Ok(QueryPlan::Activity {
            steps,
            args: activity_args,
            request,
        });
    }
    if let Some(aggregate) = args.aggregate {
        if args.count_by.is_some() || args.facet_key.is_some() {
            return Err(Error::engine(format!(
                "{tool}: 'aggregate' cannot be combined with 'count_by' or its 'facet_key'"
            )));
        }
        if args.order.is_some()
            || args.facet_order.is_some()
            || args.limit.is_some()
            || args.offset.is_some()
        {
            return Err(Error::engine(format!(
                "{tool}: aggregate terminals reject ordering and paging fields in v1"
            )));
        }
        return Ok(QueryPlan::Aggregate {
            steps,
            spec: aggregate_spec(tool, aggregate)?,
        });
    }
    if args.limit.is_some_and(|limit| limit <= 0) {
        return Err(Error::engine(format!(
            "{tool}: 'limit' must be a positive integer"
        )));
    }
    if args.offset.is_some_and(|offset| offset < 0) {
        return Err(Error::engine(format!(
            "{tool}: 'offset' must be a non-negative integer"
        )));
    }
    let count_by = match args.count_by.as_deref() {
        None => {
            if args.facet_key.is_some() {
                return Err(Error::engine(format!(
                    "{tool}: 'facet_key' requires count_by 'facet'"
                )));
            }
            None
        }
        Some("type") => Some(pipeline::CountAxis::Type),
        Some("kind") => Some(pipeline::CountAxis::Kind),
        Some("lifecycle") => Some(pipeline::CountAxis::Lifecycle),
        Some("maturity") => Some(pipeline::CountAxis::Maturity),
        Some("persistence") => Some(pipeline::CountAxis::Persistence),
        Some("facet") => {
            let Some(key) = args.facet_key.clone() else {
                return Err(Error::engine(format!(
                    "{tool}: count_by 'facet' requires 'facet_key'"
                )));
            };
            Some(pipeline::CountAxis::FacetKey(key))
        }
        Some(other) => {
            return Err(Error::engine(format!(
                "{tool}: unknown count_by '{other}' — expected 'type', 'kind', \
                 'lifecycle', 'maturity', 'persistence' or 'facet'"
            )))
        }
    };
    if count_by.is_some()
        && matches!(args.count_by.as_deref(), Some(c) if c != "facet")
        && args.facet_key.is_some()
    {
        return Err(Error::engine(format!(
            "{tool}: 'facet_key' requires count_by 'facet'"
        )));
    }
    if count_by.is_some() && args.facet_order.is_some() {
        return Err(Error::engine(format!(
            "{tool}: 'facet_order' cannot be used with 'count_by' because a count terminal returns buckets, not records"
        )));
    }
    let order = match args.order.as_deref() {
        None | Some("updated_desc") => pipeline::Order::UpdatedDesc,
        Some("created_desc") => pipeline::Order::CreatedDesc,
        Some("last_activity_desc") => pipeline::Order::LastActivityDesc,
        Some("name_asc") => pipeline::Order::NameAsc,
        Some(other) => {
            return Err(Error::engine(format!(
                "{tool}: unknown order '{other}' — expected 'updated_desc', \
                 'created_desc', 'last_activity_desc' or 'name_asc'"
            )))
        }
    };
    let defaults = pipeline::PipelineOptions::default();
    let facet_order = args
        .facet_order
        .map(|facet_order| {
            if facet_order.key.trim().is_empty() {
                return Err(Error::engine(format!(
                    "{tool}: facet_order 'key' must be a non-empty string"
                )));
            }
            let lane = match facet_order.lane.as_str() {
                "number" => pipeline::FacetOrderLane::Number,
                "text" => pipeline::FacetOrderLane::Text,
                other => {
                    return Err(Error::engine(format!(
                        "{tool}: unknown facet_order lane '{other}' — expected 'number' or 'text'"
                    )))
                }
            };
            let direction = match facet_order.direction.as_str() {
                "asc" => pipeline::FacetOrderDirection::Asc,
                "desc" => pipeline::FacetOrderDirection::Desc,
                other => {
                    return Err(Error::engine(format!(
                        "{tool}: unknown facet_order direction '{other}' — expected 'asc' or 'desc'"
                    )))
                }
            };
            Ok(pipeline::FacetOrder {
                key: facet_order.key,
                lane,
                direction,
            })
        })
        .transpose()?;
    Ok(QueryPlan::Pipeline {
        steps,
        count_by,
        opts: pipeline::PipelineOptions {
            facet_order,
            order,
            limit: args.limit.unwrap_or(defaults.limit),
            offset: args.offset.unwrap_or(defaults.offset),
        },
    })
}

fn validate_saved_query_args(tool: &str, arguments: Value) -> Result<()> {
    match parse_query_plan(tool, arguments)? {
        QueryPlan::Activity { .. } => Err(Error::engine(format!(
            "{tool}: activity is direct-call-only and is not supported in saved query v{SAVED_QUERY_VERSION}"
        ))),
        QueryPlan::Pipeline { .. } | QueryPlan::Aggregate { .. } => Ok(()),
    }
}

fn validate_saved_record_query_args(tool: &str, arguments: Value) -> Result<()> {
    match parse_query_plan(tool, arguments)? {
        QueryPlan::Pipeline {
            count_by: None, ..
        } => Ok(()),
        QueryPlan::Pipeline { .. } | QueryPlan::Aggregate { .. } | QueryPlan::Activity { .. } => {
            Err(Error::engine(format!(
                "{tool}: Collection kind:query v{SAVED_QUERY_VERSION} must return records; non-record terminals are not supported"
            )))
        }
    }
}

pub(crate) async fn execute_query_record_args_as(
    db: &Db,
    caller: &Caller,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    execute_query_record_args_with_lens_as(&ReadLens::live(db), caller, tool, arguments).await
}

/// Execute the live, structured portion of `query_record` over an already
/// admitted portable backend snapshot. Historical replay, event activity and
/// interpretation and federated-Message provenance enrichment remain explicit
/// qualification gaps; every other grammar branch reuses the canonical parser
/// before entering the shared logical fold.
#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) async fn execute_portable_live_query_record<
    E: crate::portable_sql::DomainStatementExecutor,
>(
    executor: &mut E,
    caller: &Caller,
    mut arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "query_record";
    let (as_of, include_interpretation, include_coordination, page_basis_digest) =
        validate_query_record_envelope(TOOL, &mut arguments)?;
    if as_of.is_some() {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "portable-domain",
            "query_record historical projection",
        ));
    }
    if include_interpretation {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "portable-domain",
            "query_record interpretation projection",
        ));
    }
    if include_coordination {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "portable-domain",
            "query_record coordination projection",
        ));
    }
    if page_basis_digest.is_some() {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "portable-domain",
            "query_record guarded continuation",
        ));
    }
    match parse_query_plan(TOOL, arguments)? {
        QueryPlan::Activity { .. } => {
            Err(crate::domain_transaction::unsupported_backend_operation(
                "portable-domain",
                "query_record activity terminal",
            ))
        }
        QueryPlan::Aggregate { steps, spec } => {
            crate::domain_transaction::logical_query::run_aggregate(
                executor, caller, TOOL, &steps, &spec,
            )
            .await
        }
        QueryPlan::Pipeline {
            steps,
            count_by,
            opts,
        } => {
            crate::domain_transaction::logical_query::run_pipeline(
                executor, caller, TOOL, &steps, count_by, &opts,
            )
            .await
        }
    }
}

/// Evaluate a stored live rollup in the same admitted portable snapshot as
/// its bearer authorization and logical query. The adapter intentionally
/// reports `cache_hit:false`; backend-neutral cache/revision fencing remains a
/// qualification gap rather than process-local state disguised as parity.
#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) async fn execute_portable_live_rollup<
    E: crate::portable_sql::DomainStatementExecutor,
>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    use crate::portable_sql::{BindValue, ColumnSpec, LogicalType, NormalizedValue};

    const TOOL: &str = "resolve_rollup";
    let args: ResolveRollupArgs = parse_args(TOOL, arguments)?;
    if args.record_id.trim().is_empty() || args.rollup_name.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'record_id' and 'rollup_name' must be non-empty strings"
        )));
    }
    if !crate::authorization::allows_record_with(
        executor,
        super::principal(caller),
        &args.record_id,
        crate::authorization::Capability::View,
    )
    .await?
    {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.record_id
        )));
    }
    let query = crate::domain_transaction::views_history::statement(
        "records",
        &[
            "SELECT f.value FROM {{relation}} r JOIN facet_values f ON f.record_id=r.id AND f.key='rollup' WHERE r.id=",
            " AND r.deleted_at IS NULL",
        ],
    )?;
    let rows = executor
        .fetch_all(
            &query,
            &[BindValue::Text(args.record_id.clone())],
            &[ColumnSpec::required("value", LogicalType::Text)],
        )
        .await
        .map_err(crate::domain_transaction::views_history::storage_error)?;
    let raw = rows
        .first()
        .and_then(|row| row.get("value"))
        .and_then(|value| match value {
            NormalizedValue::Text(value) => Some(value.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: record '{}' is not live or does not carry a 'rollup' facet",
                args.record_id
            ))
        })?;
    let envelope: RollupEnvelope = serde_json::from_str(&raw).map_err(|error| {
        Error::engine(format!(
            "{TOOL}: record '{}' has an invalid rollup envelope: {error}",
            args.record_id
        ))
    })?;
    if envelope.v != "0.1" {
        return Err(Error::engine(format!(
            "{TOOL}: unsupported rollup envelope version '{}' (expected '0.1')",
            envelope.v
        )));
    }
    if envelope.outputs.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: rollup envelope 'outputs' must not be empty"
        )));
    }
    let output = envelope.outputs.get(&args.rollup_name).ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: rollup '{}' is not defined on record '{}'",
            args.rollup_name, args.record_id
        ))
    })?;
    if output.query.steps.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: rollup '{}' query must have at least one step",
            args.rollup_name
        )));
    }
    let spec = aggregate_spec(TOOL, output.fold.clone())?;
    let steps = output
        .query
        .steps
        .iter()
        .enumerate()
        .map(|(index, raw)| parse_step(TOOL, index, raw))
        .collect::<Result<Vec<_>>>()?;
    let spec_digest = hex::encode(Sha256::digest(raw.as_bytes()));
    let mut payload = crate::domain_transaction::logical_query::run_aggregate(
        executor, caller, TOOL, &steps, &spec,
    )
    .await?;
    let object = payload
        .as_object_mut()
        .expect("aggregate output is an object");
    object.insert("record_id".into(), json!(args.record_id));
    object.insert("rollup_name".into(), json!(args.rollup_name));
    object.insert("spec_digest".into(), json!(spec_digest));
    object.insert("cache_hit".into(), json!(false));
    Ok(payload)
}

enum QueryExecutionSource<'a, 'db> {
    Lens(&'a ReadLens<'db>),
    Live(&'a mut sqlx::Transaction<'db, sqlx::Sqlite>),
}

impl QueryExecutionSource<'_, '_> {
    async fn annotate_record_versions(&mut self, payload: &mut Value) -> Result<()> {
        let Some(records) = payload.get_mut("records").and_then(Value::as_array_mut) else {
            return Ok(());
        };
        let ids = records
            .iter()
            .filter_map(|record| record.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(());
        }

        let rows: Vec<(String, i64)> = match self {
            Self::Lens(lens) => {
                let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
                    "SELECT record_id, MAX(seq) FROM content_events WHERE record_id IN (",
                );
                let mut separated = query.separated(", ");
                for id in &ids {
                    separated.push_bind(id);
                }
                separated.push_unseparated(") GROUP BY record_id");
                query
                    .build_query_as()
                    .fetch_all(lens.projection().snapshot_pool())
                    .await?
            }
            Self::Live(tx) => {
                let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
                    "SELECT record_id, MAX(seq) FROM content_events WHERE record_id IN (",
                );
                let mut separated = query.separated(", ");
                for id in &ids {
                    separated.push_bind(id);
                }
                separated.push_unseparated(") GROUP BY record_id");
                query.build_query_as().fetch_all(&mut ***tx).await?
            }
        };
        let versions = rows.into_iter().collect::<HashMap<_, _>>();
        for record in records {
            let Some(object) = record.as_object_mut() else {
                continue;
            };
            let Some(event_seq) = object
                .get("id")
                .and_then(Value::as_str)
                .and_then(|id| versions.get(id))
            else {
                continue;
            };
            let version = native_artifact_runtime::artifact_intents::FacetVersion::Record {
                event_seq: *event_seq,
            }
            .encode();
            object.insert("version".into(), Value::String(version));
        }
        Ok(())
    }

    async fn annotate_work_states(
        &mut self,
        live_target_pool: &sqlx::SqlitePool,
        caller: &Caller,
        payload: &mut Value,
    ) -> Result<()> {
        let Some(records) = payload.get_mut("records").and_then(Value::as_array_mut) else {
            return Ok(());
        };
        let ids = records
            .iter()
            .filter_map(|record| record.get("id").and_then(Value::as_str).map(str::to_owned))
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(());
        }
        let mut states = match self {
            Self::Lens(lens) => {
                let mut conn = lens.projection().snapshot_pool().acquire().await?;
                super::work::project_work_states_in(&mut conn, live_target_pool, caller, &ids)
                    .await?
            }
            Self::Live(tx) => {
                super::work::project_work_states_in(tx, live_target_pool, caller, &ids).await?
            }
        };
        for record in records {
            let Some(object) = record.as_object_mut() else {
                continue;
            };
            let Some(record_id) = object.get("id").and_then(Value::as_str) else {
                continue;
            };
            if let Some(state) = states.remove(record_id) {
                object.insert("work_state".into(), state);
            }
        }
        Ok(())
    }

    async fn require_record(&mut self, caller: &Caller, tool: &str, record_id: &str) -> Result<()> {
        match self {
            Self::Lens(lens) => {
                super::require_record_in_pool(
                    lens.meta().snapshot_pool(),
                    caller,
                    tool,
                    record_id,
                    crate::authorization::Capability::View,
                )
                .await
            }
            Self::Live(tx) => {
                super::require_record_in(
                    tx,
                    caller,
                    tool,
                    record_id,
                    crate::authorization::Capability::View,
                )
                .await
            }
        }
    }

    async fn hydrate_has_query_filters(&mut self, steps: &mut [pipeline::Step]) -> Result<()> {
        match self {
            Self::Lens(lens) => hydrate_has_query_filters(lens.projection(), steps).await,
            Self::Live(tx) => hydrate_has_query_filters_in(tx, steps).await,
        }
    }

    async fn execute_activity(
        &mut self,
        caller: &Caller,
        tool: &str,
        steps: Vec<pipeline::Step>,
        args: activity::ActivityArgs,
        request: Value,
    ) -> Result<Value> {
        match self {
            Self::Lens(lens) => {
                execute_activity_with_lens(lens, Some(caller), tool, steps, args, request).await
            }
            Self::Live(_) => Err(activity_requires_pinned_lens(tool)),
        }
    }

    async fn run_aggregate(
        &mut self,
        principal: crate::authorization::Principal<'_>,
        steps: &[pipeline::Step],
        spec: &pipeline::AggregateSpec,
    ) -> Result<(pipeline::AggregateOutput, Vec<(String, i64)>)> {
        match self {
            Self::Lens(lens) => {
                pipeline::run_aggregate_with_lens_diagnostics_as(lens, principal, steps, spec).await
            }
            Self::Live(tx) => {
                pipeline::run_aggregate_with_diagnostics_in_as(tx, principal, steps, spec).await
            }
        }
    }

    async fn run_pipeline(
        &mut self,
        principal: crate::authorization::Principal<'_>,
        steps: &[pipeline::Step],
        count_by: Option<pipeline::CountAxis>,
        opts: &pipeline::PipelineOptions,
    ) -> Result<(pipeline::PipelineOutput, Vec<(String, i64)>)> {
        match self {
            Self::Lens(lens) => {
                pipeline::run_with_lens_diagnostics_as(lens, principal, steps, count_by, opts).await
            }
            Self::Live(tx) => {
                pipeline::run_with_diagnostics_in_as(tx, principal, steps, count_by, opts).await
            }
        }
    }

    async fn visible_ids(&mut self, caller: &Caller, ids: Vec<String>) -> Result<HashSet<String>> {
        match self {
            Self::Lens(lens) => {
                super::visible_ids_in_pool(lens.meta().snapshot_pool(), caller, ids).await
            }
            Self::Live(tx) => super::visible_ids_in(tx, caller, ids).await,
        }
    }

    async fn custody_boundary(
        &mut self,
        record_id: &str,
        authored_home: Option<&str>,
    ) -> Result<bool> {
        match self {
            Self::Lens(lens) => {
                crate::query::tree::custody_boundary_in_pool(
                    lens.meta().snapshot_pool(),
                    record_id,
                    authored_home,
                )
                .await
            }
            Self::Live(tx) => {
                crate::query::tree::custody_boundary_in(tx, record_id, authored_home).await
            }
        }
    }

    async fn containment_path_visible(&mut self, caller: &Caller, record_id: &str) -> Result<bool> {
        if super::is_legacy_local(caller) {
            return Ok(true);
        }
        match self {
            Self::Lens(lens) => {
                crate::query::tree::containment_path_visible(
                    lens.projection(),
                    lens.meta().snapshot_pool(),
                    record_id,
                    super::principal(caller),
                )
                .await
            }
            Self::Live(tx) => {
                crate::query::tree::containment_path_visible_in(
                    tx,
                    record_id,
                    super::principal(caller),
                )
                .await
            }
        }
    }
}

pub(crate) async fn execute_query_record_args_with_lens_as(
    lens: &ReadLens<'_>,
    caller: &Caller,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    execute_query_record_args_from(
        &mut QueryExecutionSource::Lens(lens),
        caller,
        tool,
        arguments,
        false,
    )
    .await
}

async fn execute_query_record_args_with_lens_as_with_page_basis(
    lens: &ReadLens<'_>,
    caller: &Caller,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    execute_query_record_args_from(
        &mut QueryExecutionSource::Lens(lens),
        caller,
        tool,
        arguments,
        true,
    )
    .await
}

pub(crate) async fn execute_query_record_args_in_as(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    execute_query_record_args_from(
        &mut QueryExecutionSource::Live(tx),
        caller,
        tool,
        arguments,
        false,
    )
    .await
}

async fn execute_query_record_args_in_as_with_page_basis(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    execute_query_record_args_from(
        &mut QueryExecutionSource::Live(tx),
        caller,
        tool,
        arguments,
        true,
    )
    .await
}

async fn execute_query_record_args_from(
    source: &mut QueryExecutionSource<'_, '_>,
    caller: &Caller,
    tool: &str,
    arguments: Value,
    include_page_basis: bool,
) -> Result<Value> {
    let mut plan = parse_query_plan(tool, arguments)?;
    authorize_query_reference_selectors(source, caller, tool, plan.steps()).await?;
    source.hydrate_has_query_filters(plan.steps_mut()).await?;
    let principal = super::principal(caller);
    let mut payload = match plan {
        QueryPlan::Activity {
            steps,
            args,
            request,
        } => {
            return source
                .execute_activity(caller, tool, steps, args, request)
                .await
        }
        QueryPlan::Aggregate { steps, spec } => {
            let (output, lane_misses) = source.run_aggregate(principal, &steps, &spec).await?;
            let mut payload = serde_json::to_value(output)?;
            add_lane_messages(&mut payload, lane_misses, None);
            payload
        }
        QueryPlan::Pipeline {
            steps,
            count_by,
            opts,
        } => {
            let (output, lane_misses) = source
                .run_pipeline(principal, &steps, count_by, &opts)
                .await?;
            let mut payload = serde_json::to_value(&output)?;
            add_lane_messages(&mut payload, lane_misses, opts.facet_order.as_ref());
            if let (
                pipeline::PipelineOutput::Records {
                    total,
                    records,
                    page_basis_digest,
                },
                Some(object),
            ) = (&output, payload.as_object_mut())
            {
                if include_page_basis {
                    object.insert("page_basis_digest".into(), json!(page_basis_digest));
                }
                object.insert("returned".into(), json!(records.len()));
                object.insert(
                    "has_more".into(),
                    json!(opts.offset + (records.len() as i64) < *total),
                );
                object.insert("offset".into(), json!(opts.offset));
            }
            payload
        }
    };
    redact_query_record_references(source, caller, &mut payload).await?;
    Ok(payload)
}

async fn activity_event_for_caller(
    pool: &sqlx::SqlitePool,
    caller: Option<&Caller>,
    mut event: crate::events::EventRow,
) -> Result<(crate::events::EventRow, Value)> {
    let actor_names = if let Some(caller) = caller {
        let mut actor_disclosure = super::history::ActorDisclosure::default();
        let mut snapshot = pool.begin().await?;
        super::history::redact_event_in(&mut snapshot, caller, &mut actor_disclosure, &mut event)
            .await?;
        let names =
            super::history::resolve_actor_names_in(&mut snapshot, std::slice::from_ref(&event))
                .await;
        snapshot.rollback().await?;
        names
    } else {
        HashMap::new()
    };
    let rendered = super::history::event_to_value(&event, &actor_names);
    Ok((event, rendered))
}

async fn execute_activity_with_lens(
    lens: &ReadLens<'_>,
    caller: Option<&Caller>,
    tool: &str,
    steps: Vec<pipeline::Step>,
    args: activity::ActivityArgs,
    mut request: Value,
) -> Result<Value> {
    let Some(temporal) = lens.temporal() else {
        return Err(activity_requires_pinned_lens(tool));
    };
    if args.through_local_seq != Some(temporal.resolved_content_seq) {
        return Err(Error::engine(format!(
            "{tool}: activity through_local_seq must equal its subject membership sequence"
        )));
    }
    if let Some(caller) = caller {
        let mut checked = HashSet::new();
        for record_id in args
            .actions
            .any
            .iter()
            .flat_map(activity::ActionClause::reference_selectors)
        {
            if checked.insert(record_id) {
                super::require_record_in_pool(
                    lens.meta().snapshot_pool(),
                    caller,
                    tool,
                    record_id,
                    crate::authorization::Capability::View,
                )
                .await?;
            }
        }
    }
    let subjects = if let Some(caller) = caller {
        pipeline::select_ids_with_lens_as(lens, super::principal(caller), &steps).await?
    } else {
        pipeline::select_ids_with_lens(lens, &steps).await?
    };
    let subjects = subjects.into_iter().collect::<HashSet<_>>();
    let authority_pool = lens.meta().snapshot_pool();
    let page = activity::query_in_pools(
        lens.content_log().snapshot_pool(),
        authority_pool,
        subjects,
        &args,
        caller.map(super::principal),
        |event| activity_event_for_caller(authority_pool, caller, event),
    )
    .await?;
    let mut payload = serde_json::to_value(&page)?;
    let next_request = if page.has_more {
        let last_local_seq = page
            .activities
            .last()
            .and_then(|item| item.event.get("local_seq"))
            .and_then(Value::as_i64)
            .expect("a non-empty full activity page has a local sequence");
        request["activity"]["after_local_seq"] = json!(last_local_seq);
        request["activity"]["through_local_seq"] = json!(page.high_water_local_seq);
        if let Some(activity) = request.get_mut("activity").and_then(Value::as_object_mut) {
            activity.remove("after_seq");
            activity.remove("through_seq");
        }
        request
    } else {
        Value::Null
    };
    payload
        .as_object_mut()
        .expect("activity page serializes as an object")
        .insert("next_request".into(), next_request);
    if let Some(caller) = caller {
        redact_activity_match_references_in_pool(authority_pool, caller, &mut payload).await?;
    }
    Ok(payload)
}

async fn redact_activity_match_references_in_pool(
    pool: &sqlx::SqlitePool,
    caller: &Caller,
    payload: &mut Value,
) -> Result<()> {
    let Some(activities) = payload.get_mut("activities").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    let mut ids = Vec::new();
    for item in activities.iter() {
        for evidence in item
            .get("matches")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match evidence.get("kind").and_then(Value::as_str) {
                Some("link_change") => {
                    ids.extend(
                        ["source_id", "target_id"]
                            .into_iter()
                            .filter_map(|key| evidence.get(key).and_then(Value::as_str))
                            .map(String::from),
                    );
                }
                Some("field_transition")
                    if matches!(
                        evidence.get("field").and_then(Value::as_str),
                        Some("home_id" | "owner_id")
                    ) =>
                {
                    ids.extend(
                        ["before", "after"]
                            .into_iter()
                            .filter_map(|key| evidence.get(key).and_then(Value::as_str))
                            .map(String::from),
                    );
                }
                _ => {}
            }
        }
    }
    let visible = super::visible_ids_in_pool(pool, caller, ids).await?;
    for item in activities {
        for evidence in item
            .get_mut("matches")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            let keys: &[&str] = match evidence.get("kind").and_then(Value::as_str) {
                Some("link_change") => &["source_id", "target_id"],
                Some("field_transition")
                    if matches!(
                        evidence.get("field").and_then(Value::as_str),
                        Some("home_id" | "owner_id")
                    ) =>
                {
                    &["before", "after"]
                }
                _ => &[],
            };
            let Some(object) = evidence.as_object_mut() else {
                continue;
            };
            for key in keys {
                if object
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(|id| !visible.contains(id))
                {
                    object.insert((*key).into(), Value::Null);
                }
            }
        }
    }
    Ok(())
}

/// Reference selectors are authority-bearing roots, not merely predicates.
/// A visible exception below a hidden home/ancestor, or owned by a hidden
/// principal, must not turn the hidden reference into a query oracle.
async fn authorize_query_reference_selectors(
    source: &mut QueryExecutionSource<'_, '_>,
    caller: &Caller,
    tool: &str,
    steps: &[pipeline::Step],
) -> Result<()> {
    let mut checked = HashSet::new();
    for step in steps {
        let pipeline::Step::Filter(filter) = step else {
            continue;
        };
        for record_id in [
            filter.home_id.as_deref(),
            filter.ancestor_id.as_deref(),
            filter.owner_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if checked.insert(record_id) {
                source.require_record(caller, tool, record_id).await?;
            }
        }
    }
    Ok(())
}

async fn redact_query_record_references(
    source: &mut QueryExecutionSource<'_, '_>,
    caller: &Caller,
    payload: &mut Value,
) -> Result<()> {
    let Some(records) = payload.get_mut("records").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    let ids = records
        .iter()
        .flat_map(|record| {
            ["home_id", "owner_id"]
                .into_iter()
                .filter_map(move |key| record.get(key).and_then(Value::as_str).map(String::from))
        })
        .collect();
    let visible = source.visible_ids(caller, ids).await?;
    for record in records {
        let Some(object) = record.as_object_mut() else {
            continue;
        };
        let record_id = object.get("id").and_then(Value::as_str).map(str::to_owned);
        let authored_home = object
            .get("home_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(record_id) = record_id.as_deref() {
            let custody_boundary = source
                .custody_boundary(record_id, authored_home.as_deref())
                .await?;
            let containment_path_visible =
                source.containment_path_visible(caller, record_id).await?;
            object.insert("custody_boundary".into(), json!(custody_boundary));
            object.insert(
                "containment_path_visible".into(),
                json!(containment_path_visible),
            );
        }
        for key in ["home_id", "owner_id"] {
            if object
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|id| !visible.contains(id))
            {
                object.insert(key.into(), Value::Null);
            }
        }
    }
    Ok(())
}

fn take_include_interpretation(tool: &str, arguments: &mut Value) -> Result<bool> {
    let Some(value) = arguments
        .as_object_mut()
        .and_then(|object| object.remove("include_interpretation"))
    else {
        return Ok(false);
    };
    value
        .as_bool()
        .ok_or_else(|| Error::engine(format!("{tool}: include_interpretation must be a boolean")))
}

fn take_include_coordination(tool: &str, arguments: &mut Value) -> Result<bool> {
    let Some(value) = arguments
        .as_object_mut()
        .and_then(|object| object.remove("include_coordination"))
    else {
        return Ok(false);
    };
    value
        .as_bool()
        .ok_or_else(|| Error::engine(format!("{tool}: include_coordination must be a boolean")))
}

fn take_page_basis_digest(tool: &str, arguments: &mut Value) -> Result<Option<String>> {
    let Some(value) = arguments
        .as_object_mut()
        .and_then(|object| object.remove("if_page_basis_digest"))
    else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| Error::engine(format!("{tool}: if_page_basis_digest must be a string")))?;
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit());
    if !valid {
        return Err(Error::engine(format!(
            "{tool}: if_page_basis_digest must be sha256: followed by 64 hexadecimal characters"
        )));
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn validate_interpretation_query(tool: &str, arguments: Value) -> Result<()> {
    match parse_query_plan(tool, arguments)? {
        QueryPlan::Pipeline {
            count_by: None,
            opts,
            ..
        } if opts.limit <= super::attribution::MAX_GENERIC_INTERPRETATION_BEARERS as i64 => Ok(()),
        QueryPlan::Pipeline { count_by: None, .. } => Err(Error::engine(format!(
            "{tool}: include_interpretation requires limit <= {}",
            super::attribution::MAX_GENERIC_INTERPRETATION_BEARERS
        ))),
        QueryPlan::Pipeline { .. } | QueryPlan::Aggregate { .. } | QueryPlan::Activity { .. } => {
            Err(Error::engine(format!(
                "{tool}: include_interpretation is supported only for record-producing queries"
            )))
        }
    }
}

fn validate_coordination_query(tool: &str, arguments: Value) -> Result<()> {
    match parse_query_plan(tool, arguments)? {
        QueryPlan::Pipeline {
            count_by: None,
            opts,
            ..
        } if opts.limit <= 50 => Ok(()),
        QueryPlan::Pipeline { count_by: None, .. } => Err(Error::engine(format!(
            "{tool}: include_coordination requires limit <= 50"
        ))),
        QueryPlan::Pipeline { .. } | QueryPlan::Aggregate { .. } | QueryPlan::Activity { .. } => {
            Err(Error::engine(format!(
                "{tool}: include_coordination is supported only for record-producing queries"
            )))
        }
    }
}

fn validate_query_record_envelope(
    tool: &str,
    arguments: &mut Value,
) -> Result<(Option<lens::AsOfSelector>, bool, bool, Option<String>)> {
    let as_of = lens::take_as_of(tool, arguments)?;
    let include_interpretation = take_include_interpretation(tool, arguments)?;
    let include_coordination = take_include_coordination(tool, arguments)?;
    let page_basis_digest = take_page_basis_digest(tool, arguments)?;
    if include_interpretation {
        if as_of.is_some() {
            return Err(Error::engine(format!(
                "{tool}: include_interpretation is not supported with as_of in v1; use read_attributions with as_of_event_seq"
            )));
        }
        validate_interpretation_query(tool, arguments.clone())?;
    }
    if include_coordination {
        validate_coordination_query(tool, arguments.clone())?;
    }
    if arguments.get("activity").is_some() && as_of.is_some() {
        return Err(Error::engine(format!(
            "{tool}: top-level as_of cannot be combined with activity; activity pins membership through activity.through_local_seq"
        )));
    }
    Ok((
        as_of,
        include_interpretation,
        include_coordination,
        page_basis_digest,
    ))
}

fn verify_page_basis(tool: &str, output: &Value, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual = output
        .get("page_basis_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::engine(format!("{tool}: record page basis was not reported")))?;
    if actual != expected {
        return Err(Error::engine(format!(
            "{tool}: record page basis changed under current authorization or schema; restart from offset 0"
        )));
    }
    Ok(())
}

fn record_producing_query(tool: &str, arguments: Value) -> Result<bool> {
    Ok(matches!(
        parse_query_plan(tool, arguments)?,
        QueryPlan::Pipeline { count_by: None, .. }
    ))
}

fn annotate_record_page_snapshot(
    output: &mut Value,
    request: &Value,
    local_database_id: &str,
    observed_at: &str,
    resolved_content_seq: i64,
    content_head_seq: i64,
    continuation_supported: bool,
) {
    let Some(object) = output.as_object_mut() else {
        return;
    };
    if !object.get("records").is_some_and(Value::is_array) {
        return;
    }
    object.insert("local_database_id".into(), json!(local_database_id));
    object.entry("as_of").or_insert_with(|| {
        json!({
            "content_seq": resolved_content_seq,
        })
    });
    object.insert("observed_at".into(), json!(observed_at));
    object.insert("resolved_content_seq".into(), json!(resolved_content_seq));
    object.insert("content_head_seq".into(), json!(content_head_seq));

    let next_request = if continuation_supported
        && object
            .get("has_more")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        let mut next = request.clone();
        let offset = object.get("offset").and_then(Value::as_i64).unwrap_or(0);
        let returned = object.get("returned").and_then(Value::as_i64).unwrap_or(0);
        if let Some(next) = next.as_object_mut() {
            next.insert("offset".into(), json!(offset + returned));
            next.insert(
                "as_of".into(),
                json!({ "content_seq": resolved_content_seq }),
            );
            if let Some(page_basis_digest) = object.get("page_basis_digest").and_then(Value::as_str)
            {
                next.insert("if_page_basis_digest".into(), json!(page_basis_digest));
            }
        }
        next
    } else {
        Value::Null
    };
    object.insert("next_request".into(), next_request);
}

fn coordination_page_request(mut request: Value, include_coordination: bool) -> Value {
    if include_coordination {
        if let Some(object) = request.as_object_mut() {
            object.insert("include_coordination".into(), json!(true));
        }
    }
    request
}

fn annotate_coordination_observation(output: &mut Value, observed_at: &str) {
    let Some(object) = output.as_object_mut() else {
        return;
    };
    object.insert(
        "coordination_observation".into(),
        json!({
            "observed_at": observed_at,
            "claim_content_boundary": "response_as_of",
            "run_target_boundary": "live",
            "authorization_boundary": "current",
        }),
    );
}

async fn execute_live_record_query(
    db: &Db,
    caller: &Caller,
    tool: &str,
    arguments: Value,
    include_interpretation: bool,
    include_coordination: bool,
    expected_page_basis_digest: Option<&str>,
) -> Result<Value> {
    let local_database_id = crate::identity::database_id(db).await?;
    let mut snapshot = db.write_pool().begin().await?;
    let result = async {
        // This first read establishes the SQLite snapshot used by selection,
        // authorization, per-record versions and the returned content fence.
        let head = sqlx::query("SELECT seq FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *snapshot)
            .await?;
        let content_head_seq = match head {
            Some(row) => row.try_get::<i64, _>("seq")?,
            None => 0,
        };
        let content_observed_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut output = execute_query_record_args_in_as_with_page_basis(
            &mut snapshot,
            caller,
            tool,
            arguments.clone(),
        )
        .await?;
        verify_page_basis(tool, &output, expected_page_basis_digest)?;
        QueryExecutionSource::Live(&mut snapshot)
            .annotate_record_versions(&mut output)
            .await?;
        if include_interpretation {
            let bearer_window = super::attribution::authorized_query_interpretation_bearers(
                output
                    .get("records")
                    .and_then(Value::as_array)
                    .expect("validated interpretation query returns records"),
            );
            let projections = super::attribution::project_generic_interpretations_in(
                &mut snapshot,
                caller,
                bearer_window,
            )
            .await?;
            super::attribution::attach_generic_interpretations(
                output
                    .get_mut("records")
                    .and_then(Value::as_array_mut)
                    .expect("validated interpretation query returns records"),
                &projections,
            )?;
        }
        if include_coordination {
            QueryExecutionSource::Live(&mut snapshot)
                .annotate_work_states(db.write_pool(), caller, &mut output)
                .await?;
        }
        // Content and live coordination are separately timed observations.
        // The content fence is repeatable; the page execution timestamp is not.
        if include_coordination {
            let coordination_observed_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            annotate_coordination_observation(&mut output, &coordination_observed_at);
        }
        let continuation_request =
            coordination_page_request(arguments.clone(), include_coordination);
        annotate_record_page_snapshot(
            &mut output,
            &continuation_request,
            &local_database_id,
            &content_observed_at,
            content_head_seq,
            content_head_seq,
            !include_interpretation,
        );
        Ok(output)
    }
    .await;
    match result {
        Ok(output) => {
            snapshot.rollback().await?;
            Ok(output)
        }
        Err(error) => {
            let _ = snapshot.rollback().await;
            Err(error)
        }
    }
}

/// Validation-only seam for the test-only progressive-contract fixture.
/// Production execution calls [`validate_query_record_envelope`] too, so
/// describe/repair parity cannot silently drift from runtime acceptance.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) fn validate_query_record_operation(mut arguments: Value) -> Result<()> {
    validate_query_record_envelope("query_record", &mut arguments)?;
    // Use the same parser called at the existing production execution point;
    // do not move or duplicate that parse in the production handler.
    parse_query_plan("query_record", arguments).map(|_| ())
}

async fn query_record(db: Db, caller: Caller, mut arguments: Value) -> Result<Value> {
    const TOOL: &str = "query_record";
    let (as_of, include_interpretation, include_coordination, page_basis_digest) =
        validate_query_record_envelope(TOOL, &mut arguments)?;
    let record_producing = record_producing_query(TOOL, arguments.clone())?;
    if page_basis_digest.is_some() && !record_producing {
        return Err(Error::engine(
            "query_record: if_page_basis_digest is supported only for record-producing continuations",
        ));
    }
    if arguments.get("activity").is_some() {
        let supplied_through = arguments.get("activity").and_then(|activity| {
            activity
                .get("through_local_seq")
                .or_else(|| activity.get("through_seq"))
        });
        let through_seq = match supplied_through {
            None | Some(Value::Null) => events::content_high_water(&db).await?,
            Some(value) => value.as_i64().ok_or_else(|| {
                Error::engine(
                    "query_record: activity.through_local_seq must be a non-negative integer",
                )
            })?,
        };
        let activity_object = arguments
            .get_mut("activity")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| Error::engine("query_record: activity must be an object"))?;
        activity_object.remove("through_seq");
        activity_object.insert("through_local_seq".into(), json!(through_seq));
        let resolved = lens::resolve_as_of(
            &db,
            lens::AsOfSelector::ContentSeq(lens::ContentSeqSelector {
                content_seq: through_seq,
            }),
        )
        .await?;
        let scratch = open_database(":memory:").await?;
        let result = async {
            apply_schema(&scratch).await?;
            lens::replay_projection(&db, &scratch, through_seq).await?;
            let read_lens = ReadLens::historical(&scratch, &db, &resolved);
            execute_query_record_args_with_lens_as(&read_lens, &caller, TOOL, arguments).await
        }
        .await;
        scratch.close().await;
        let mut output = result?;
        output
            .as_object_mut()
            .expect("activity output is an object")
            .insert(
                "local_database_id".into(),
                json!(crate::identity::database_id(&db).await?),
            );
        annotate_query_record_paths(&db, &mut output).await?;
        return Ok(output);
    }
    let Some(selector) = as_of else {
        if record_producing {
            let mut output = execute_live_record_query(
                &db,
                &caller,
                TOOL,
                arguments,
                include_interpretation,
                include_coordination,
                page_basis_digest.as_deref(),
            )
            .await?;
            annotate_query_record_paths(&db, &mut output).await?;
            return Ok(output);
        }
        let mut output = execute_query_record_args_as(&db, &caller, TOOL, arguments).await?;
        annotate_query_record_paths(&db, &mut output).await?;
        return Ok(output);
    };
    let resolved = lens::resolve_as_of(&db, selector).await?;
    let content_observed_at =
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let local_database_id = crate::identity::database_id(&db).await?;
    let request = coordination_page_request(arguments.clone(), include_coordination);
    let scratch = open_database(":memory:").await?;
    let result = async {
        apply_schema(&scratch).await?;
        lens::replay_projection(&db, &scratch, resolved.resolved_content_seq).await?;
        let read_lens = ReadLens::historical(&scratch, &db, &resolved);
        let mut output = execute_query_record_args_with_lens_as_with_page_basis(
            &read_lens, &caller, TOOL, arguments,
        )
        .await?;
        verify_page_basis(TOOL, &output, page_basis_digest.as_deref())?;
        QueryExecutionSource::Lens(&read_lens)
            .annotate_record_versions(&mut output)
            .await?;
        if include_coordination {
            QueryExecutionSource::Lens(&read_lens)
                .annotate_work_states(db.write_pool(), &caller, &mut output)
                .await?;
        }
        annotate_query_record_paths(&db, &mut output).await?;
        if include_coordination {
            let coordination_observed_at =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            annotate_coordination_observation(&mut output, &coordination_observed_at);
        }
        lens::echo_temporal(&mut output, &resolved);
        if record_producing {
            annotate_record_page_snapshot(
                &mut output,
                &request,
                &local_database_id,
                &content_observed_at,
                resolved.resolved_content_seq,
                resolved.content_head_seq,
                true,
            );
        }
        Ok(output)
    }
    .await;
    scratch.close().await;
    result
}

async fn annotate_query_record_paths(db: &Db, payload: &mut Value) -> Result<()> {
    let Some(records) = payload.get_mut("records").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    super::lifecycle::annotate_record_paths_batch(db, records).await
}

pub(crate) const SAVED_QUERY_VERSION: &str = "0.2";
/// v1.1 pins each dependency's semantic identity as well as its version.
/// v1.0 used a name-to-integer map and remains recognizable as an unsupported
/// durable envelope instead of being reinterpreted with the stronger shape.
pub(crate) const SAVED_SQL_VERSION: &str = "1.1";

/// Generate the one query grammar used by both direct tool registration and
/// saved-query compatibility checks. References are inlined because the
/// registry's TypeScript consumer intentionally supports a small schema
/// subset and rejects `$ref` rather than silently widening it.
fn query_record_grammar_schema() -> Value {
    let generator = SchemaSettings::draft07()
        .with(|settings| settings.inline_subschemas = true)
        .into_generator();
    serde_json::to_value(generator.into_root_schema_for::<QueryRecordArgs>())
        .expect("QueryRecordArgs JSON Schema serializes")
}

/// The persisted v0.2 grammar predates and deliberately excludes the direct
/// activity terminal. Its outer schema remains byte-for-byte compatible while
/// semantic validation below restricts it to record-producing plans.
#[cfg(test)]
fn saved_query_grammar_schema() -> Value {
    let mut schema = query_record_grammar_schema();
    schema["properties"]
        .as_object_mut()
        .expect("query grammar properties are an object")
        .remove("activity");
    schema
}

fn query_record_input_schema() -> Value {
    let mut schema = query_record_grammar_schema();
    schema["properties"]["as_of"] = lens::as_of_input_schema();
    schema["properties"]["include_interpretation"] = json!({
        "type": "boolean",
        "description": "Bounded live interpretation; default false, limit <=50, rejects saved/as_of use."
    });
    schema["properties"]["include_coordination"] = json!({
        "type": "boolean",
        "description": "Work state (record pages, limit 50): claims pinned; authorized targets live; others withheld."
    });
    schema["properties"]["if_page_basis_digest"] = json!({
        "type": "string",
        "description": "Prior page basis; rejects when current visibility changed."
    });
    schema
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) fn query_record_operation_schema() -> Value {
    query_record_input_schema()
}

#[cfg(test)]
const DOCUMENTATION_SCHEMA_KEYS: [&str; 9] = [
    "$comment",
    "$schema",
    "default",
    "deprecated",
    "description",
    "examples",
    "readOnly",
    "title",
    "writeOnly",
];

#[cfg(test)]
const SET_LIKE_SCHEMA_ARRAYS: [&str; 6] = ["allOf", "anyOf", "enum", "oneOf", "required", "type"];

/// Remove annotation-only metadata and deterministically order schema
/// structures without discarding any validation-bearing keyword.
#[cfg(test)]
fn canonical_query_record_schema() -> Value {
    canonicalize_schema(saved_query_grammar_schema(), None)
}

#[cfg(test)]
fn canonicalize_schema(value: Value, parent_key: Option<&str>) -> Value {
    match value {
        Value::Object(object) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in object {
                if DOCUMENTATION_SCHEMA_KEYS.contains(&key.as_str()) {
                    continue;
                }
                sorted.insert(key.clone(), canonicalize_schema(value, Some(&key)));
            }
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => {
            let mut values = values
                .into_iter()
                .map(|value| canonicalize_schema(value, None))
                .collect::<Vec<_>>();
            if parent_key.is_some_and(|key| SET_LIKE_SCHEMA_ARRAYS.contains(&key)) {
                values.sort_by_cached_key(|value| {
                    serde_json::to_string(value).expect("canonical JSON value serializes")
                });
            }
            Value::Array(values)
        }
        scalar => scalar,
    }
}

#[derive(Debug)]
pub(crate) enum SavedQueryInspection {
    Valid { version: String, query: Value },
    GovernedSql { definition: SavedSqlDefinition },
    Invalid { diagnostic: String },
    UnsupportedVersion { version: String, diagnostic: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedQueryEnvelope {
    v: String,
    query: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSqlProfile {
    pub(crate) id: String,
    pub(crate) revision: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SavedSqlColumnType {
    /// A globally stable application identifier. Unlike arbitrary text, this
    /// semantic type is eligible for row identity and total-order tie-breaks.
    Identifier,
    Boolean,
    Integer,
    Real,
    Text,
    Bytes,
    Json,
    Timestamp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSqlColumn {
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) column_type: SavedSqlColumnType,
    pub(crate) nullable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SavedSqlDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSqlOrder {
    pub(crate) column: String,
    pub(crate) direction: SavedSqlDirection,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSqlOutput {
    pub(crate) columns: Vec<SavedSqlColumn>,
    pub(crate) schema_sha256: String,
    pub(crate) row_identity: Vec<String>,
    pub(crate) order: Vec<SavedSqlOrder>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSqlBounds {
    pub(crate) rows: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSqlRelationDependency {
    pub(crate) identity: String,
    pub(crate) semantic_version: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedSqlDefinition {
    pub(crate) v: String,
    pub(crate) kind: String,
    pub(crate) profile: SavedSqlProfile,
    pub(crate) catalog_revision: u32,
    pub(crate) relations: BTreeMap<String, SavedSqlRelationDependency>,
    pub(crate) sql: String,
    #[serde(default)]
    pub(crate) parameters: Vec<crate::query::sql_contract::QuerySqlParameter>,
    pub(crate) output: SavedSqlOutput,
    pub(crate) bounds: SavedSqlBounds,
}

/// Recognition-only shape for durable governed-SQL v1.0 envelopes. That
/// version pinned relation names to numeric versions but had no semantic
/// identity, so it cannot execute under v1.1's stronger dependency contract.
#[derive(Deserialize)]
struct LegacySavedSqlV1Envelope {
    v: String,
    kind: String,
    relations: BTreeMap<String, u32>,
}

fn saved_sql_schema_sha256(columns: &[SavedSqlColumn]) -> Result<String> {
    let bytes =
        native_artifact_runtime::mdx_v2::canonical_json_bytes(&serde_json::to_value(columns)?);
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn valid_saved_sql_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn logical_cte_shadow(sql: &str) -> Option<String> {
    #[derive(Clone, Copy)]
    enum State {
        Normal,
        Quoted(u8),
        LineComment,
        BlockComment(usize),
    }
    let bytes = sql.as_bytes();
    let mut state = State::Normal;
    let mut tokens = Vec::<String>::new();
    let mut word = String::new();
    let flush = |tokens: &mut Vec<String>, word: &mut String| {
        if !word.is_empty() {
            tokens.push(std::mem::take(word));
        }
    };
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match state {
            State::Normal if byte == b'\'' => {
                flush(&mut tokens, &mut word);
                state = State::Quoted(b'\'');
            }
            State::Normal if byte == b'"' => {
                flush(&mut tokens, &mut word);
                state = State::Quoted(b'"');
            }
            State::Normal if byte == b'`' => {
                flush(&mut tokens, &mut word);
                state = State::Quoted(b'`');
            }
            State::Normal if byte == b'[' => {
                flush(&mut tokens, &mut word);
                state = State::Quoted(b']');
            }
            State::Normal if byte == b'-' && bytes.get(index + 1) == Some(&b'-') => {
                flush(&mut tokens, &mut word);
                state = State::LineComment;
                index += 1;
            }
            State::Normal if byte == b'/' && bytes.get(index + 1) == Some(&b'*') => {
                flush(&mut tokens, &mut word);
                state = State::BlockComment(1);
                index += 1;
            }
            State::Normal if byte.is_ascii_alphanumeric() || byte == b'_' => {
                word.push((byte as char).to_ascii_lowercase());
            }
            State::Normal => {
                flush(&mut tokens, &mut word);
                if matches!(byte, b'(' | b')' | b',') {
                    tokens.push((byte as char).to_string());
                }
            }
            State::Quoted(terminator)
                if byte == terminator && bytes.get(index + 1) == Some(&terminator) =>
            {
                word.push(terminator as char);
                index += 1;
            }
            State::Quoted(terminator) if byte == terminator => {
                flush(&mut tokens, &mut word);
                state = State::Normal;
            }
            State::Quoted(_) => word.push((byte as char).to_ascii_lowercase()),
            State::LineComment if matches!(byte, b'\n' | b'\r') => state = State::Normal,
            State::LineComment => {}
            State::BlockComment(depth) if byte == b'/' && bytes.get(index + 1) == Some(&b'*') => {
                state = State::BlockComment(depth + 1);
                index += 1;
            }
            State::BlockComment(depth) if byte == b'*' && bytes.get(index + 1) == Some(&b'/') => {
                state = if depth == 1 {
                    State::Normal
                } else {
                    State::BlockComment(depth - 1)
                };
                index += 1;
            }
            State::BlockComment(_) => {}
        }
        index += 1;
    }
    flush(&mut tokens, &mut word);
    let mut cursor = 0;
    if tokens.get(cursor).map(String::as_str) != Some("with") {
        return None;
    }
    cursor += 1;
    if tokens.get(cursor).map(String::as_str) == Some("recursive") {
        cursor += 1;
    }
    loop {
        let name = tokens.get(cursor)?;
        if crate::query::sql_contract::is_logical_relation(name) {
            return Some(name.clone());
        }
        cursor += 1;
        let as_offset = tokens[cursor..].iter().position(|token| token == "as")?;
        cursor += as_offset + 1;
        let open_offset = tokens[cursor..].iter().position(|token| token == "(")?;
        cursor += open_offset;
        let mut depth = 0usize;
        while cursor < tokens.len() {
            match tokens[cursor].as_str() {
                "(" => depth += 1,
                ")" => {
                    depth -= 1;
                    if depth == 0 {
                        cursor += 1;
                        break;
                    }
                }
                _ => {}
            }
            cursor += 1;
        }
        if tokens.get(cursor).map(String::as_str) != Some(",") {
            return None;
        }
        cursor += 1;
    }
}

fn validate_saved_sql(definition: &SavedSqlDefinition) -> Result<()> {
    use crate::query::sql_contract as contract;
    if definition.v != SAVED_SQL_VERSION || definition.kind != "governed_sql" {
        return Err(Error::engine(
            "saved governed SQL envelope/version mismatch",
        ));
    }
    let active = contract::QuerySqlProfile::SqliteLocal.contract();
    if definition.profile.id != active.id || definition.profile.revision != active.revision {
        return Err(Error::engine(format!(
            "saved governed SQL requires profile {}@{}",
            active.id, active.revision
        )));
    }
    if definition.catalog_revision != contract::LOGICAL_CATALOG_REVISION {
        return Err(Error::engine(format!(
            "saved governed SQL catalog revision {} is incompatible with {}",
            definition.catalog_revision,
            contract::LOGICAL_CATALOG_REVISION
        )));
    }
    let request = contract::QuerySqlRequest {
        sql: definition.sql.clone(),
        parameters: definition.parameters.clone(),
    };
    request.validate().map_err(Error::from)?;
    sql::validate(&definition.sql)?;
    if let Some(name) = logical_cte_shadow(&definition.sql) {
        return Err(Error::engine(format!(
            "saved governed SQL cannot shadow logical relation '{name}' with a CTE"
        )));
    }
    let used_relations = sql::validated_relation_dependencies(&definition.sql)?;
    if definition.relations.is_empty() {
        return Err(Error::engine(
            "saved governed SQL must declare relation dependencies",
        ));
    }
    for relation in contract::LOGICAL_RELATIONS {
        let mentioned = used_relations.contains(relation.name);
        match definition.relations.get(relation.name) {
            Some(dependency)
                if dependency.identity == relation.identity
                    && dependency.semantic_version == relation.semantic_version
                    && mentioned
                    && relation.profiles.contains(&active.id) => {}
            Some(_) if mentioned && !relation.profiles.contains(&active.id) => {
                return Err(Error::engine(format!(
                    "saved governed SQL relation '{}' is unavailable in profile {}",
                    relation.name, active.id
                )))
            }
            Some(dependency)
                if dependency.identity != relation.identity
                    || dependency.semantic_version != relation.semantic_version =>
            {
                return Err(Error::engine(format!(
                    "saved governed SQL relation '{}' identity/version is incompatible with {}@{}",
                    relation.name, relation.identity, relation.semantic_version
                )))
            }
            Some(_) => {
                return Err(Error::engine(format!(
                    "saved governed SQL declares unused relation '{}'",
                    relation.name
                )))
            }
            None if mentioned => {
                return Err(Error::engine(format!(
                    "saved governed SQL omits dependency identity/version for relation '{}'",
                    relation.name
                )))
            }
            None => {}
        }
    }
    if let Some(unknown) = definition
        .relations
        .keys()
        .find(|name| !contract::is_logical_relation(name))
    {
        return Err(Error::engine(format!(
            "saved governed SQL names unaudited relation '{unknown}'"
        )));
    }
    if definition.output.columns.is_empty()
        || definition.output.columns.len() > contract::MAX_COLUMNS
        || definition.bounds.rows == 0
        || definition.bounds.rows > contract::MAX_ROWS
    {
        return Err(Error::engine(
            "saved governed SQL output/bounds are outside query_sql limits",
        ));
    }
    let mut labels = HashSet::new();
    for column in &definition.output.columns {
        if !valid_saved_sql_identifier(&column.name) || !labels.insert(column.name.as_str()) {
            return Err(Error::engine(
                "saved governed SQL output columns must have unique portable identifiers",
            ));
        }
    }
    let declared_labels = definition
        .output
        .columns
        .iter()
        .map(|column| column.name.clone())
        .collect::<Vec<_>>();
    let prepared_labels = sql::validated_output_columns(&definition.sql)?;
    if prepared_labels != declared_labels {
        return Err(Error::engine(format!(
            "saved governed SQL output columns do not match the statement (declared {}, statement {})",
            declared_labels.join(", "),
            prepared_labels.join(", ")
        )));
    }
    if saved_sql_schema_sha256(&definition.output.columns)? != definition.output.schema_sha256 {
        return Err(Error::engine(
            "saved governed SQL output schema digest mismatch",
        ));
    }
    if definition.output.row_identity.len() != 1 || definition.output.order.is_empty() {
        return Err(Error::engine(
            "saved governed SQL v1.1 requires exactly one stable row identifier and deterministic order",
        ));
    }
    for identity in &definition.output.row_identity {
        let column = definition
            .output
            .columns
            .iter()
            .find(|column| &column.name == identity)
            .ok_or_else(|| {
                Error::engine("saved governed SQL row identity names an unknown column")
            })?;
        if column.nullable || !matches!(column.column_type, SavedSqlColumnType::Identifier) {
            return Err(Error::engine(
                "saved governed SQL row identity columns must be non-null stable identifiers",
            ));
        }
    }
    for order in &definition.output.order {
        if !labels.contains(order.column.as_str()) {
            return Err(Error::engine(
                "saved governed SQL order names an unknown column",
            ));
        }
    }
    if definition.output.order.last().map(|order| &order.column)
        != definition.output.row_identity.last()
    {
        return Err(Error::engine(
            "saved governed SQL final order key must be the final stable row identifier",
        ));
    }
    Ok(())
}

/// Decode a present `query` facet and validate its inner arguments against the
/// persisted v0.2 grammar. The record-set planner remains shared with direct
/// calls, while the direct-only activity terminal is rejected here. Presence
/// alone never confers the capability.
pub(crate) fn inspect_saved_query(raw: Option<&str>) -> SavedQueryInspection {
    inspect_saved_query_with(raw, false)
}

/// Collection kind:query is computed record membership, not a generic saved
/// computation. Other query-capable bearers retain the pre-existing saved
/// aggregate/count contract.
pub(crate) fn inspect_saved_record_query(raw: Option<&str>) -> SavedQueryInspection {
    inspect_saved_query_with(raw, true)
}

fn inspect_saved_query_with(raw: Option<&str>, records_only: bool) -> SavedQueryInspection {
    let Some(raw) = raw else {
        return SavedQueryInspection::Invalid {
            diagnostic: "query facet has no string value".into(),
        };
    };
    let decoded: Value = match serde_json::from_str(raw) {
        Ok(decoded) => decoded,
        Err(error) => {
            return SavedQueryInspection::Invalid {
                diagnostic: format!("invalid saved-query envelope: {error}"),
            }
        }
    };
    if decoded.get("v").and_then(Value::as_str) == Some("1.0")
        && decoded.get("kind").and_then(Value::as_str) == Some("governed_sql")
    {
        let legacy: LegacySavedSqlV1Envelope = match serde_json::from_value(decoded) {
            Ok(legacy) => legacy,
            Err(error) => {
                return SavedQueryInspection::Invalid {
                    diagnostic: format!("invalid saved governed SQL v1.0 envelope: {error}"),
                }
            }
        };
        debug_assert_eq!(legacy.v, "1.0");
        debug_assert_eq!(legacy.kind, "governed_sql");
        let dependency_count = legacy.relations.len();
        return SavedQueryInspection::UnsupportedVersion {
            diagnostic: format!(
                "saved governed SQL v1.0 has {dependency_count} name/version dependencies without semantic identities and is incompatible with v1.1"
            ),
            version: legacy.v,
        };
    }
    if decoded.get("v").and_then(Value::as_str) == Some(SAVED_SQL_VERSION) {
        let definition: SavedSqlDefinition = match serde_json::from_value(decoded) {
            Ok(definition) => definition,
            Err(error) => {
                return SavedQueryInspection::Invalid {
                    diagnostic: format!("invalid saved governed SQL envelope: {error}"),
                }
            }
        };
        if records_only && definition.output.row_identity != ["id"] {
            return SavedQueryInspection::Invalid {
                diagnostic: "saved governed SQL Collection output must use 'id' as its first stable row identity".into(),
            };
        }
        return match validate_saved_sql(&definition) {
            Ok(()) => SavedQueryInspection::GovernedSql { definition },
            Err(error) => SavedQueryInspection::Invalid {
                diagnostic: error.to_string(),
            },
        };
    }
    if decoded.get("kind").and_then(Value::as_str) == Some("governed_sql") {
        let version = decoded
            .get("v")
            .and_then(Value::as_str)
            .unwrap_or("missing")
            .to_string();
        return SavedQueryInspection::UnsupportedVersion {
            diagnostic: format!(
                "unsupported saved governed SQL version '{version}' (expected '{SAVED_SQL_VERSION}')"
            ),
            version,
        };
    }
    let envelope: SavedQueryEnvelope = match serde_json::from_value(decoded) {
        Ok(envelope) => envelope,
        Err(error) => {
            return SavedQueryInspection::Invalid {
                diagnostic: format!("invalid saved-query envelope: {error}"),
            }
        }
    };
    if envelope.v != SAVED_QUERY_VERSION {
        // Rejection is the deliberate pre-migration posture. Revisit it before
        // shipping the first breaking grammar version after an older supported
        // version has been persisted in either Views or smart Collections.
        let version = envelope.v;
        return SavedQueryInspection::UnsupportedVersion {
            diagnostic: format!(
                "unsupported saved-query version '{version}' (expected '{SAVED_QUERY_VERSION}')"
            ),
            version,
        };
    }
    let validation = if records_only {
        validate_saved_record_query_args("saved query", envelope.query.clone())
    } else {
        validate_saved_query_args("saved query", envelope.query.clone())
    };
    match validation {
        Ok(()) => SavedQueryInspection::Valid {
            version: envelope.v,
            query: envelope.query,
        },
        Err(error) => SavedQueryInspection::Invalid {
            diagnostic: error.to_string(),
        },
    }
}

/// Hydrate derived capability membership for execution without executing any
/// stored query. Parsing and direct execution still share `parse_query_plan`.
async fn hydrate_has_query_filters(
    projection: crate::query::lens::ProjectionRead<'_>,
    steps: &mut [pipeline::Step],
) -> Result<()> {
    if !steps
        .iter()
        .any(|step| matches!(step, pipeline::Step::Filter(filter) if filter.has_query.is_some()))
    {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT f.record_id, f.value, r.type, r.kind
           FROM facet_values f
           JOIN records r ON r.id = f.record_id
          WHERE f.key = 'query'",
    )
    .fetch_all(projection.shared_pool())
    .await?;
    hydrate_has_query_filters_from_rows(rows, steps)
}

async fn hydrate_has_query_filters_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    steps: &mut [pipeline::Step],
) -> Result<()> {
    if !steps
        .iter()
        .any(|step| matches!(step, pipeline::Step::Filter(filter) if filter.has_query.is_some()))
    {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT f.record_id, f.value, r.type, r.kind
           FROM facet_values f
           JOIN records r ON r.id = f.record_id
          WHERE f.key = 'query'",
    )
    .fetch_all(&mut **tx)
    .await?;
    hydrate_has_query_filters_from_rows(rows, steps)
}

fn hydrate_has_query_filters_from_rows(
    rows: Vec<sqlx::sqlite::SqliteRow>,
    steps: &mut [pipeline::Step],
) -> Result<()> {
    let mut capable = HashSet::new();
    for row in rows {
        let id: String = row.try_get("record_id")?;
        let raw: Option<String> = row.try_get("value")?;
        let record_type: String = row.try_get("type")?;
        let kind: Option<String> = row.try_get("kind")?;
        let inspection = if record_type == "Collection" && kind.as_deref() == Some("query") {
            inspect_saved_record_query(raw.as_deref())
        } else {
            inspect_saved_query(raw.as_deref())
        };
        if matches!(
            inspection,
            SavedQueryInspection::Valid { .. } | SavedQueryInspection::GovernedSql { .. }
        ) {
            capable.insert(id);
        }
    }
    for step in steps {
        if let pipeline::Step::Filter(filter) = step {
            if filter.has_query.is_some() {
                filter.query_capability_ids = Some(capable.clone());
            }
        }
    }
    Ok(())
}

fn add_lane_messages(
    payload: &mut Value,
    lane_misses: Vec<(String, i64)>,
    facet_order: Option<&pipeline::FacetOrder>,
) {
    if lane_misses.is_empty() {
        return;
    }
    let messages: Vec<String> = lane_misses
        .into_iter()
        .map(|(key, count)| {
            let order_guidance = if facet_order.is_some_and(|order| order.key == key) {
                "; they sort with missing values — use lane 'text' or store JSON numbers"
            } else {
                ""
            };
            format!("{count} records have `{key}` set but no numeric projection{order_guidance}")
        })
        .collect();
    payload
        .as_object_mut()
        .expect("query output serializes as an object")
        .insert("messages".into(), json!(messages));
}

// ---------------------------------------------------------------------------
// Stored named rollups
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RollupEnvelope {
    v: String,
    outputs: BTreeMap<String, StoredRollupOutput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRollupOutput {
    query: StoredRollupQuery,
    fold: AggregateArgs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRollupQuery {
    steps: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRollupArgs {
    record_id: String,
    rollup_name: String,
}

#[cfg(test)]
#[derive(Clone)]
struct RollupAfterInitialRequireHook {
    record_id: String,
    reached: std::sync::Arc<tokio::sync::Notify>,
    resume: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(test)]
static ROLLUP_AFTER_INITIAL_REQUIRE_HOOK: std::sync::Mutex<Option<RollupAfterInitialRequireHook>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
async fn pause_rollup_after_initial_require(record_id: &str) {
    let hook = ROLLUP_AFTER_INITIAL_REQUIRE_HOOK
        .lock()
        .expect("rollup test hook lock")
        .clone()
        .filter(|hook| hook.record_id == record_id);
    if let Some(hook) = hook {
        hook.reached.notify_one();
        hook.resume.notified().await;
    }
}

async fn revision(db: &Db) -> Result<(i64, i64, i64)> {
    let (content, meta) = sqlx::query_as(
        "SELECT COALESCE((SELECT MAX(seq) FROM content_events), 0), \
                COALESCE((SELECT MAX(seq) FROM meta_events), 0)",
    )
    .fetch_one(db.write_pool())
    .await?;
    Ok((
        content,
        meta,
        crate::authorization::authorization_revision(db).await?,
    ))
}

async fn resolve_rollup(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "resolve_rollup";
    let args: ResolveRollupArgs = parse_args(TOOL, arguments)?;
    if args.record_id.trim().is_empty() || args.rollup_name.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'record_id' and 'rollup_name' must be non-empty strings"
        )));
    }
    // A revision is checked again after every hit/evaluation. If a supported
    // write raced the read, repeat from the bearer so neither an old cached
    // answer nor an old recipe can be returned for the new revision.
    for _ in 0..3 {
        super::require_record(
            &db,
            &caller,
            TOOL,
            &args.record_id,
            crate::authorization::Capability::View,
        )
        .await?;
        #[cfg(test)]
        pause_rollup_after_initial_require(&args.record_id).await;
        let mut payload = resolve_rollup_once(&db, &caller, &args).await?;
        let expected = (
            payload["revision"]["content_event_seq"]
                .as_i64()
                .expect("rollup revision is numeric"),
            payload["revision"]["meta_event_seq"]
                .as_i64()
                .expect("rollup revision is numeric"),
            payload["revision"]["authorization_revision"]
                .as_i64()
                .expect("rollup authorization revision is numeric"),
        );
        // Reauthorize against the result's sampled authorization epoch. The
        // following revision fence closes the window where policy changes
        // after this check but before return: a changed epoch retries, while a
        // stable denial is surfaced as the ordinary not-found boundary.
        super::require_record(
            &db,
            &caller,
            TOOL,
            &args.record_id,
            crate::authorization::Capability::View,
        )
        .await?;
        if revision(&db).await? == expected {
            if !caller.is_host_owner() {
                payload
                    .as_object_mut()
                    .expect("rollup payload is an object")
                    .remove("revision");
            }
            return Ok(payload);
        }
    }
    Err(Error::engine(format!(
        "{TOOL}: database changed repeatedly during resolution; retry the read"
    )))
}

async fn resolve_rollup_once(db: &Db, caller: &Caller, args: &ResolveRollupArgs) -> Result<Value> {
    const TOOL: &str = "resolve_rollup";
    let source: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT f.value, \
                COALESCE((SELECT MAX(seq) FROM content_events), 0), \
                COALESCE((SELECT MAX(seq) FROM meta_events), 0) \
         FROM records r \
         JOIN facet_values f ON f.record_id = r.id AND f.key = 'rollup' \
         WHERE r.id = ? AND r.deleted_at IS NULL",
    )
    .bind(&args.record_id)
    .fetch_optional(db.write_pool())
    .await?;
    let (raw, content_event_seq, meta_event_seq) = source.ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: record '{}' is not live or does not carry a 'rollup' facet",
            args.record_id
        ))
    })?;
    let envelope: RollupEnvelope = serde_json::from_str(&raw).map_err(|error| {
        Error::engine(format!(
            "{TOOL}: record '{}' has an invalid rollup envelope: {error}",
            args.record_id
        ))
    })?;
    if envelope.v != "0.1" {
        return Err(Error::engine(format!(
            "{TOOL}: unsupported rollup envelope version '{}' (expected '0.1')",
            envelope.v
        )));
    }
    if envelope.outputs.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: rollup envelope 'outputs' must not be empty"
        )));
    }
    let output = envelope.outputs.get(&args.rollup_name).ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: rollup '{}' is not defined on record '{}'",
            args.rollup_name, args.record_id
        ))
    })?;
    if output.query.steps.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: rollup '{}' query must have at least one step",
            args.rollup_name
        )));
    }
    let spec = aggregate_spec(TOOL, output.fold.clone())?;
    let steps = output
        .query
        .steps
        .iter()
        .enumerate()
        .map(|(index, raw)| parse_step(TOOL, index, raw))
        .collect::<Result<Vec<_>>>()?;
    authorize_query_reference_selectors(
        &mut QueryExecutionSource::Lens(&ReadLens::live(db)),
        caller,
        TOOL,
        &steps,
    )
    .await?;
    let spec_digest = hex::encode(Sha256::digest(raw.as_bytes()));
    let authorization_revision = crate::authorization::authorization_revision(db).await?;
    let key = crate::db::RollupCacheKey {
        principal: caller.credential().to_string(),
        trusted_local_bypass: super::is_legacy_local(caller),
        spec_digest: spec_digest.clone(),
        bearer_id: args.record_id.clone(),
        rollup_name: args.rollup_name.clone(),
        content_event_seq,
        meta_event_seq,
        authorization_revision,
    };
    if let Some(mut cached) = db.rollup_cache_get(&key) {
        let object = cached
            .as_object_mut()
            .expect("cached rollup result is an object");
        object.insert("cache_hit".into(), json!(true));
        return Ok(cached);
    }
    let (aggregate, lane_misses) =
        pipeline::run_aggregate_with_diagnostics_as(db, super::principal(caller), &steps, &spec)
            .await?;
    let mut payload = serde_json::to_value(aggregate)?;
    add_lane_messages(&mut payload, lane_misses, None);
    let object = payload
        .as_object_mut()
        .expect("aggregate output serializes as an object");
    object.insert("record_id".into(), json!(args.record_id));
    object.insert("rollup_name".into(), json!(args.rollup_name));
    object.insert("spec_digest".into(), json!(spec_digest));
    object.insert("cache_hit".into(), json!(false));
    object.insert(
        "revision".into(),
        json!({
            "content_event_seq": content_event_seq,
            "meta_event_seq": meta_event_seq,
            "authorization_revision": authorization_revision,
        }),
    );
    // Only successful evaluations are inserted. If a write raced this read,
    // its newer revision makes this key unreachable on the next request.
    db.rollup_cache_insert(key, payload.clone());
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Tool 17 — search
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    /// Restrict to the subtree rooted at this record (the tree is the
    /// search-confidence hedge, 4da80fa).
    scope: Option<String>,
    limit: Option<i64>,
    include_archived: Option<bool>,
}

fn hit_json(hit: &SearchHit) -> Value {
    json!({
        "id": hit.id,
        "type": hit.record_type,
        "kind": hit.kind,
        "name": hit.name,
        "home_id": hit.home_id,
        "score": hit.score,
        "snippet": hit.snippet,
    })
}

/// Live, unarchived siblings of the hits' parents — the third near-miss
/// mechanism (tree-scoping hedge 4da80fa): a thin hit's neighbours often hold
/// what the query was really after.
///
/// `scope` is the subtree id set when the search was scoped: a hit that IS the
/// scope root has siblings outside the requested subtree, and the scope
/// contract binds near-misses as much as strict hits — so sibling rows are
/// membership-filtered, not assumed in-scope by construction.
async fn tree_siblings(
    db: &Db,
    credential: &str,
    trusted_local_bypass: bool,
    hits: &[SearchHit],
    exclude: &HashSet<String>,
    scope: Option<&HashSet<String>>,
    include_archived: bool,
) -> Result<Vec<Value>> {
    let home_ids: Vec<String> = {
        let mut seen = HashSet::new();
        hits.iter()
            .filter_map(|h| h.raw_home_id.clone())
            .filter(|p| seen.insert(p.clone()))
            .collect()
    };
    if home_ids.is_empty() {
        return Ok(Vec::new());
    }
    let archived_filter = if include_archived {
        ""
    } else {
        "AND NOT EXISTS (SELECT 1 FROM facet_values av
                          WHERE av.record_id = r.id AND av.key = 'archived')"
    };
    let placeholders = vec!["?"; home_ids.len()].join(", ");
    let not_hidden = crate::query::not_hidden_predicate("r");
    let view_filter = crate::query::fts::view_predicate("r");
    let name_chars = crate::query::fts::TRUSTED_NAME_CHARS;
    let scope_filter = if scope.is_some() {
        "AND r.id IN (SELECT value FROM json_each(?))"
    } else {
        ""
    };
    let sql = format!(
        "SELECT r.id, r.type, r.kind,
                substr(r.name, 1, {name_chars}) AS name, r.home_id
          FROM records r
          WHERE r.home_id IN ({placeholders})
            AND r.deleted_at IS NULL
            AND {not_hidden}
            AND {view_filter}
            {archived_filter}
            AND r.id NOT IN (SELECT value FROM json_each(?))
            {scope_filter}
          ORDER BY r.name, r.id
          LIMIT ?"
    );
    let mut query = sqlx::query(&sql);
    for id in &home_ids {
        query = query.bind(id);
    }
    query = query
        .bind(trusted_local_bypass)
        .bind(credential)
        .bind(credential);
    query = query.bind(json!(exclude.iter().collect::<Vec<_>>()).to_string());
    if let Some(scope) = scope {
        query = query.bind(json!(scope.iter().collect::<Vec<_>>()).to_string());
    }
    query = query.bind(NEAR_MISS_CAP);
    let rows = query.fetch_all(db.write_pool()).await?;
    let visible_parents = crate::query::fts::independently_visible_ids(
        db,
        credential,
        trusted_local_bypass,
        &home_ids,
    )
    .await?;
    let mut out = Vec::new();
    for row in &rows {
        let id: String = row.try_get("id")?;
        let raw_home_id: Option<String> = row.try_get("home_id")?;
        out.push(json!({
            "id": id,
            "type": row.try_get::<String, _>("type")?,
            "kind": row.try_get::<Option<String>, _>("kind")?,
            "name": row.try_get::<String, _>("name")?,
            "home_id": raw_home_id.filter(|parent| visible_parents.contains(parent)),
        }));
    }
    Ok(out)
}

async fn search(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "search";
    let args: SearchArgs = parse_args(TOOL, arguments)?;
    if args.query.trim().is_empty() {
        return Err(Error::engine(format!("{TOOL}: 'query' must be non-empty")));
    }
    let limit = fts::effective_limit(args.limit)?;
    let opts = FtsOptions {
        scope: args.scope.clone(),
        include_archived: args.include_archived.unwrap_or(false),
        limit: Some(limit),
        types: Vec::new(),
    };
    let trusted_local_bypass = super::is_legacy_local(&caller);
    let scope_set: Option<HashSet<String>> = match &args.scope {
        Some(root) => {
            super::require_record(
                &db,
                &caller,
                TOOL,
                root,
                crate::authorization::Capability::View,
            )
            .await?;
            Some(
                crate::query::tree::subtree_ids(&db, root)
                    .await?
                    .into_iter()
                    .collect(),
            )
        }
        None => None,
    };
    let hits = fts::search_with_policy_bypass(
        &db,
        caller.credential(),
        trusted_local_bypass,
        &args.query,
        &opts,
    )
    .await?;
    let thin = hits.len() < THIN_RESULTS_THRESHOLD;

    let mut payload = json!({
        "query": args.query,
        "scope": args.scope,
        "hits": hits.iter().map(hit_json).collect::<Vec<_>>(),
        "total": hits.len(),
        "returned": hits.len(),
        "limit": limit,
        "limit_reached": hits.len() as i64 == limit,
        "thin": thin,
    });
    let object = payload.as_object_mut().expect("search payload");

    // Layer 1 — near-miss surfacing, thin results only (the bound: threshold
    // THIN_RESULTS_THRESHOLD, NEAR_MISS_CAP rows per mechanism, one capped
    // scan each — see query::fts).
    if thin {
        let near_opts = FtsOptions {
            scope: args.scope.clone(),
            include_archived: opts.include_archived,
            limit: Some(NEAR_MISS_CAP),
            types: Vec::new(),
        };
        let mut seen: HashSet<String> = hits.iter().map(|h| h.id.clone()).collect();
        let mut dedup = |mechanism_hits: Vec<SearchHit>| -> Vec<Value> {
            mechanism_hits
                .into_iter()
                .filter(|h| seen.insert(h.id.clone()))
                .map(|h| hit_json(&h))
                .collect()
        };
        let prefix = dedup(
            fts::name_prefix_with_policy_bypass(
                &db,
                caller.credential(),
                trusted_local_bypass,
                &args.query,
                &near_opts,
            )
            .await?,
        );
        let infix = dedup(
            fts::name_infix_with_policy_bypass(
                &db,
                caller.credential(),
                trusted_local_bypass,
                &args.query,
                &near_opts,
            )
            .await?,
        );
        let siblings = tree_siblings(
            &db,
            caller.credential(),
            trusted_local_bypass,
            &hits,
            &seen,
            scope_set.as_ref(),
            opts.include_archived,
        )
        .await?;
        let any_near_miss = !(prefix.is_empty() && infix.is_empty() && siblings.is_empty());
        object.insert(
            "near_misses".into(),
            json!({
                "name_prefix": prefix,
                "name_infix": infix,
                "tree_siblings": siblings,
            }),
        );
        // The payload does the prompting — agents do not reformulate reliably
        // unprompted (3bc7fd0). Say the results are thin, say what to try.
        let mut guidance = if hits.is_empty() {
            format!("No full-text matches for {:?}.", args.query)
        } else {
            format!(
                "Only {} full-text match(es) for {:?} — likely not exhaustive.",
                hits.len(),
                args.query
            )
        };
        guidance.push_str(
            " Consider reformulating: try synonyms or alternative phrasings, \
             fewer or more specific terms, or query_record for structured \
             filtering.",
        );
        if any_near_miss {
            guidance.push_str(
                " Near-miss candidates are listed under 'near_misses' — \
                 name_prefix (typed-prefix neighbours), name_infix (mid-word \
                 name matches, e.g. camelCase identifiers), and tree_siblings \
                 (records adjacent to the hits).",
            );
        }
        object.insert("guidance".into(), json!(guidance));
    }
    annotate_search_record_paths(&db, &mut payload).await?;
    Ok(payload)
}

async fn annotate_search_record_paths(db: &Db, payload: &mut Value) -> Result<()> {
    let mut ids = Vec::new();
    for pointer in [
        "/hits",
        "/near_misses/name_prefix",
        "/near_misses/name_infix",
        "/near_misses/tree_siblings",
    ] {
        let Some(records) = payload.pointer(pointer).and_then(Value::as_array) else {
            continue;
        };
        for record in records {
            if let Some(id) = record.get("id").and_then(Value::as_str) {
                ids.push(id.to_owned());
            }
        }
    }
    let references = {
        let borrowed: Vec<&str> = ids.iter().map(String::as_str).collect();
        crate::mcp::record_ref::display_references(db, &borrowed).await?
    };
    for pointer in [
        "/hits",
        "/near_misses/name_prefix",
        "/near_misses/name_infix",
        "/near_misses/tree_siblings",
    ] {
        let Some(records) = payload.pointer_mut(pointer).and_then(Value::as_array_mut) else {
            continue;
        };
        for record in records {
            let Some(id) = record.get("id").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            super::lifecycle::apply_record_path_with_reference(
                record,
                &id,
                references.get(&id).cloned().flatten(),
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tool 18 — query_sql
// ---------------------------------------------------------------------------

async fn query_sql(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let request = parse_args::<crate::query::sql_contract::QuerySqlRequest>("query_sql", arguments)
        .map_err(|error| {
            crate::query::sql_contract::categorized_error(
                crate::query::sql_contract::QuerySqlErrorCategory::InvalidArguments,
                error.to_string(),
            )
        })?;
    let result = sql::query_sql_request_owned(db, (&caller).into(), request)
        .await
        .map_err(crate::query::sql_contract::ensure_categorized)?;
    Ok(json!({
        "columns": result.columns,
        "rows": result.rows,
        "row_count": result.row_count,
        "truncated": result.truncated,
    }))
}

fn saved_sql_value_matches(value: &Value, column: &SavedSqlColumn) -> bool {
    if value.is_null() {
        return column.nullable;
    }
    match column.column_type {
        SavedSqlColumnType::Boolean => value.is_boolean() || matches!(value.as_i64(), Some(0 | 1)),
        SavedSqlColumnType::Integer => value.as_i64().is_some(),
        SavedSqlColumnType::Real => value.as_f64().is_some(),
        SavedSqlColumnType::Identifier | SavedSqlColumnType::Text => value.is_string(),
        SavedSqlColumnType::Bytes => value.as_str().is_some_and(|value| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .is_ok()
        }),
        SavedSqlColumnType::Json => value
            .as_str()
            .is_some_and(|value| serde_json::from_str::<Value>(value).is_ok()),
        SavedSqlColumnType::Timestamp => value
            .as_str()
            .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok()),
    }
}

/// Execute a previously admitted governed-SQL definition through the exact
/// caller-filtered query_sql path. The outer order is authoritative: authored
/// SQL cannot merely claim deterministic ordering in metadata.
#[cfg(test)]
pub(crate) async fn execute_saved_sql(
    db: Db,
    caller: &Caller,
    definition: &SavedSqlDefinition,
    parameter_override: Option<Vec<crate::query::sql_contract::QuerySqlParameter>>,
) -> Result<Value> {
    use sqlx::Acquire as _;

    validate_saved_sql(definition)?;
    let parameters = parameter_override.unwrap_or_else(|| definition.parameters.clone());
    if parameters.len() != definition.parameters.len()
        || parameters
            .iter()
            .zip(&definition.parameters)
            .any(|(actual, declared)| {
                std::mem::discriminant(actual) != std::mem::discriminant(declared)
            })
    {
        return Err(Error::engine(
            "saved governed SQL parameter count/type does not match its definition",
        ));
    }
    for parameter in &parameters {
        parameter.validate().map_err(Error::from)?;
    }
    let mut effective = definition.clone();
    effective.parameters = parameters;
    let mut connection = db.write_pool().acquire().await?;
    let mut transaction = connection.begin().await?;
    let output = execute_saved_sql_in(&mut transaction, caller, &effective).await;
    transaction.rollback().await?;
    output
}

fn finish_saved_sql(
    definition: &SavedSqlDefinition,
    parameters: &[crate::query::sql_contract::QuerySqlParameter],
    origin: &str,
    observation: crate::query::sql::GovernedSqlObservation,
    result: crate::query::sql_contract::QuerySqlResult,
) -> Result<Value> {
    let expected = definition
        .output
        .columns
        .iter()
        .map(|column| column.name.clone())
        .collect::<Vec<_>>();
    if !result.columns.is_empty() && result.columns != expected {
        return Err(Error::engine(format!(
            "saved governed SQL output columns changed (expected {}, got {})",
            expected.join(", "),
            result.columns.join(", ")
        )));
    }
    let mut rows = result.rows;
    let requested = definition.bounds.rows;
    let truncated = result.truncated || rows.len() > requested;
    let mut identities = HashSet::new();
    for row in &mut rows {
        let object = row
            .as_object_mut()
            .ok_or_else(|| Error::engine("saved governed SQL returned a non-object row"))?;
        for column in &definition.output.columns {
            let value = object.get_mut(&column.name).ok_or_else(|| {
                Error::engine(format!(
                    "saved governed SQL output omitted column '{}'",
                    column.name
                ))
            })?;
            // SQLite has no distinct runtime boolean storage class: governed
            // logical relations therefore arrive as signed 0/1. The saved
            // envelope is the typed boundary and normalizes those two exact
            // values to JSON booleans before schema validation and hashing.
            if matches!(column.column_type, SavedSqlColumnType::Boolean) {
                match value.as_i64() {
                    Some(0) => *value = Value::Bool(false),
                    Some(1) => *value = Value::Bool(true),
                    _ => {}
                }
            }
            if !saved_sql_value_matches(value, column) {
                return Err(Error::engine(format!(
                    "saved governed SQL output column '{}' violated its declared type/nullability",
                    column.name
                )));
            }
        }
        let identity = definition
            .output
            .row_identity
            .iter()
            .map(|column| {
                object
                    .get(column)
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        Error::engine("saved governed SQL returned an invalid row identity")
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        if !identities.insert(identity) {
            return Err(Error::engine(
                "saved governed SQL returned duplicate row identity",
            ));
        }
    }
    // The bounds+1 probe participates in identity validation. Otherwise a
    // duplicate exactly across the truncation boundary could make an ordering
    // tie appear valid merely because the second row was hidden from output.
    rows.truncate(requested);
    let activity_dependent = definition
        .relations
        .keys()
        .any(|name| matches!(name.as_str(), "agent_activity" | "agent_activity_claims"));
    let definition_bytes = serde_json::to_vec(definition)?;
    let parameters_bytes = serde_json::to_vec(&parameters)?;
    let rows_bytes = serde_json::to_vec(&rows)?;
    let mut boundary = serde_json::Map::new();
    if let Some(sequence) = observation.content_event_seq {
        boundary.insert("content_event_seq".into(), sequence.into());
    }
    if let Some(sequence) = observation.lifecycle_event_seq {
        boundary.insert("lifecycle_event_seq".into(), sequence.into());
    }
    boundary.insert(
        "authorization".into(),
        observation.authorization_boundary.clone().into(),
    );
    if activity_dependent {
        boundary.insert(
            "transient_available".into(),
            observation.transient_available.into(),
        );
        if let Some(watermark) = observation.transient_watermark {
            boundary.insert("transient_watermark".into(), watermark.into());
        }
    }
    let boundary_bytes = serde_json::to_vec(&boundary)?;
    let mut token_digest = Sha256::new();
    for part in [
        origin.as_bytes(),
        &definition_bytes,
        &parameters_bytes,
        observation.observed_at.as_bytes(),
        &boundary_bytes,
        &rows_bytes,
    ] {
        token_digest.update((part.len() as u64).to_be_bytes());
        token_digest.update(part);
    }
    let snapshot = format!("native.snapshot.v1.{:x}", token_digest.finalize());
    let row_count = rows.len();
    let completeness = if definition.relations.keys().any(|name| {
        crate::query::sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == name)
            .is_some_and(|relation| relation.completeness == "best_effort")
    }) {
        "best_effort"
    } else if truncated {
        "truncated"
    } else {
        "complete"
    };
    let relation_receipts = definition
        .relations
        .keys()
        .map(|name| {
            let contract = crate::query::sql_contract::LOGICAL_RELATIONS
                .iter()
                .find(|relation| relation.name == name)
                .expect("saved SQL validation admitted only catalog relations");
            json!({
                "name": name,
                "identity": contract.identity,
                "semantic_version": contract.semantic_version,
            })
        })
        .collect::<Vec<_>>();
    let degraded_sources = if activity_dependent && !observation.transient_available {
        vec!["transient_activity_capture"]
    } else {
        Vec::new()
    };
    let transient_activity = activity_dependent.then(|| {
        json!({
            "available": observation.transient_available,
            "watermark": observation.transient_watermark,
        })
    });
    Ok(json!({
        "columns": expected,
        "rows": rows,
        "row_count": row_count,
        "truncated": truncated,
        "receipt": {
            "version": "native.governed-sql-receipt.v1",
            "snapshot": snapshot,
            "observed_at": observation.observed_at,
            "row_count": row_count,
            "truncated": truncated,
            "completeness": completeness,
            "replayable": !activity_dependent,
            "observation_window_hours": activity_dependent.then_some(24),
            "catalog_revision": definition.catalog_revision,
            "relations": relation_receipts,
            "boundary": boundary,
            "transient_activity": transient_activity,
            "degraded_sources": degraded_sources,
            "cursor": Value::Null,
        }
    }))
}

pub(crate) async fn execute_saved_sql_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    caller: &Caller,
    definition: &SavedSqlDefinition,
) -> Result<Value> {
    validate_saved_sql(definition)?;
    let parameters = definition.parameters.clone();
    let order = definition
        .output
        .order
        .iter()
        .map(|order| {
            format!(
                "\"{}\" {}",
                order.column,
                match order.direction {
                    SavedSqlDirection::Asc => "ASC",
                    SavedSqlDirection::Desc => "DESC",
                }
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let wrapped = format!(
        "SELECT * FROM ({}) AS saved_governed_projection ORDER BY {order} LIMIT {}",
        definition.sql,
        definition.bounds.rows.saturating_add(1)
    );
    let (result, observation) = sql::query_sql_request_in_for_saved(
        tx,
        caller.into(),
        crate::query::sql_contract::QuerySqlRequest {
            sql: wrapped,
            parameters: parameters.clone(),
        },
    )
    .await
    .map_err(crate::query::sql_contract::ensure_categorized)?;
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    finish_saved_sql(definition, &parameters, &origin, observation, result)
}

// ---------------------------------------------------------------------------
// Tool 19 — scan
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanArgs {
    /// Free text — enables the `lexical` axis (FTS over name + body).
    query: Option<String>,
    /// Restrict every axis to the subtree rooted at this record.
    scope: Option<String>,
    /// Restrict every axis to these record types.
    types: Option<Vec<String>>,
    recent_window_days: Option<i64>,
    high_degree_min: Option<i64>,
    include_archived: Option<bool>,
    /// Account token whose attributed events form the `authored_by` axis.
    /// Defaults to the authenticated caller.
    authored_by: Option<String>,
}

#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) async fn execute_portable_nonlexical_scan<
    E: crate::portable_sql::DomainStatementExecutor,
>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "scan";
    let args: ScanArgs = parse_args(TOOL, arguments)?;
    if args
        .query
        .as_deref()
        .is_some_and(|query| !query.trim().is_empty())
    {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "portable-domain",
            "scan lexical axis",
        ));
    }
    let recent_window_days = args
        .recent_window_days
        .unwrap_or(DEFAULT_RECENT_WINDOW_DAYS);
    if !(1..=MAX_RECENT_WINDOW_DAYS).contains(&recent_window_days) {
        return Err(Error::engine(format!(
            "{TOOL}: 'recent_window_days' must be between 1 and {MAX_RECENT_WINDOW_DAYS}"
        )));
    }
    let high_degree_min = args.high_degree_min.unwrap_or(DEFAULT_HIGH_DEGREE_MIN);
    if high_degree_min < 1 {
        return Err(Error::engine(format!(
            "{TOOL}: 'high_degree_min' must be positive"
        )));
    }
    crate::domain_transaction::logical_query::run_scan(
        executor,
        caller,
        crate::domain_transaction::logical_query::ScanOptions {
            scope: args.scope,
            types: args.types.unwrap_or_default(),
            recent_window_days,
            high_degree_min,
            include_archived: args.include_archived.unwrap_or(false),
            authored_by: args.authored_by,
        },
    )
    .await
}

/// One axis facet: the FULL pool size plus a bounded sample — the cap never
/// hides depth, because `count` is the uncapped pool.
struct AxisFacet {
    count: i64,
    samples: Vec<AxisSample>,
}

/// One described record at an axis's sample head, including the evidence that
/// put it there. Evidence keys vary by axis, but always trail the shared
/// identity fields in the emitted object.
struct AxisSample {
    id: String,
    record_type: String,
    name: String,
    evidence: Vec<(String, Value)>,
}

impl AxisSample {
    fn to_json(&self) -> Value {
        let mut sample = serde_json::Map::new();
        sample.insert("id".into(), json!(self.id));
        sample.insert("type".into(), json!(self.record_type));
        sample.insert("name".into(), json!(self.name));
        for (key, value) in &self.evidence {
            sample.insert(key.clone(), value.clone());
        }
        Value::Object(sample)
    }
}

#[derive(Clone, Copy)]
enum AxisMetricKind {
    Text,
}

/// A metric already selected by an axis query. The SQL alias says where to
/// read it; the JSON key says how the axis explains its own ordering.
#[derive(Clone, Copy)]
struct AxisMetricColumn {
    sql_alias: &'static str,
    json_key: &'static str,
    kind: AxisMetricKind,
}

impl AxisFacet {
    fn to_json(&self, corpus_size: i64) -> Value {
        let quality = if self.count == 0 {
            "empty"
        } else if corpus_size > 0
            && (self.count as f64) / (corpus_size as f64) >= SCAN_SATURATION_THRESHOLD
        {
            "saturated"
        } else {
            "focused"
        };
        json!({
            "count": self.count,
            "samples": self.samples.iter().map(AxisSample::to_json).collect::<Vec<_>>(),
            "quality": quality,
        })
    }
}

/// Run one axis query: `sql` must select `id`, `type`, `name` and order by the
/// axis's own relevance. When supplied, `metric` names an already-selected SQL
/// column to surface as evidence. The pool is counted uncapped; the sample is
/// the head.
async fn axis(
    db: &Db,
    caller: &Caller,
    sql: &str,
    binds: &[String],
    metric: Option<AxisMetricColumn>,
) -> Result<AxisFacet> {
    let mut query = sqlx::query(sql);
    for bind in binds {
        query = query.bind(bind);
    }
    let rows = query.fetch_all(db.write_pool()).await?;
    let mut visible_rows = Vec::new();
    for row in &rows {
        let id: String = row.try_get("id")?;
        if super::can_record(db, caller, &id, crate::authorization::Capability::View).await? {
            visible_rows.push(row);
        }
    }
    let samples = visible_rows
        .iter()
        .take(SCAN_SAMPLE_LIMIT)
        .map(|row| {
            let evidence = match metric {
                Some(metric) => {
                    let value = match metric.kind {
                        AxisMetricKind::Text => {
                            json!(row.try_get::<String, _>(metric.sql_alias)?)
                        }
                    };
                    vec![(metric.json_key.to_string(), value)]
                }
                None => Vec::new(),
            };
            Ok(AxisSample {
                id: row.try_get("id")?,
                record_type: row.try_get("type")?,
                name: row.try_get("name")?,
                evidence,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(AxisFacet {
        count: visible_rows.len() as i64,
        samples,
    })
}

#[derive(Clone, Copy)]
enum DerivedAxisMetric {
    Degree,
    ChildCount,
}

/// Relationship metrics cannot be computed from raw SQL counts: hidden link
/// endpoints and children must disappear before thresholds, ordering, samples,
/// and totals. Materialize the visible corpus, then derive each metric from
/// independently visible related records.
async fn derived_relationship_axis(
    db: &Db,
    caller: &Caller,
    corpus_where: &str,
    binds: &[String],
    metric: DerivedAxisMetric,
    minimum: i64,
) -> Result<AxisFacet> {
    let sql =
        format!("SELECT r.id, r.type, r.name FROM records r WHERE {corpus_where} ORDER BY r.id");
    let mut query = sqlx::query(&sql);
    for bind in binds {
        query = query.bind(bind);
    }
    let rows = query.fetch_all(db.write_pool()).await?;
    let mut matches = Vec::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        if !super::can_record(db, caller, &id, crate::authorization::Capability::View).await? {
            continue;
        }
        let related: Vec<String> = match metric {
            DerivedAxisMetric::Degree => {
                sqlx::query_scalar(
                    "SELECT CASE WHEN source_id = ? THEN target_id ELSE source_id END
                       FROM links WHERE source_id = ? OR target_id = ?",
                )
                .bind(&id)
                .bind(&id)
                .bind(&id)
                .fetch_all(db.write_pool())
                .await?
            }
            DerivedAxisMetric::ChildCount => {
                let sql = format!(
                    "SELECT c.id FROM records c
                      WHERE c.home_id = ? AND c.deleted_at IS NULL AND {}",
                    crate::query::not_hidden_predicate("c")
                );
                sqlx::query_scalar(&sql)
                    .bind(&id)
                    .fetch_all(db.write_pool())
                    .await?
            }
        };
        let mut visible_metric = 0i64;
        for related_id in related {
            if super::can_record(
                db,
                caller,
                &related_id,
                crate::authorization::Capability::View,
            )
            .await?
            {
                visible_metric += 1;
            }
        }
        if visible_metric < minimum {
            continue;
        }
        let json_key = match metric {
            DerivedAxisMetric::Degree => "degree",
            DerivedAxisMetric::ChildCount => "child_count",
        };
        matches.push((
            visible_metric,
            AxisSample {
                id,
                record_type: row.try_get("type")?,
                name: row.try_get("name")?,
                evidence: vec![(json_key.into(), json!(visible_metric))],
            },
        ));
    }
    matches.sort_by(|(left_metric, left), (right_metric, right)| {
        right_metric
            .cmp(left_metric)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(AxisFacet {
        count: matches.len() as i64,
        samples: matches
            .into_iter()
            .take(SCAN_SAMPLE_LIMIT)
            .map(|(_, sample)| sample)
            .collect(),
    })
}

async fn annotate_scan_axes_record_paths(
    db: &Db,
    axes: &mut serde_json::Map<String, Value>,
) -> Result<()> {
    let mut ids = Vec::new();
    for facet in axes.values() {
        let Some(samples) = facet.get("samples").and_then(Value::as_array) else {
            continue;
        };
        for sample in samples {
            if let Some(id) = sample.get("id").and_then(Value::as_str) {
                ids.push(id.to_owned());
            }
        }
    }
    let borrowed: Vec<&str> = ids.iter().map(String::as_str).collect();
    let references = crate::mcp::record_ref::display_references(db, &borrowed).await?;
    for facet in axes.values_mut() {
        let Some(samples) = facet.get_mut("samples").and_then(Value::as_array_mut) else {
            continue;
        };
        for sample in samples {
            let Some(id) = sample.get("id").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            super::lifecycle::apply_record_path_with_reference(
                sample,
                &id,
                references.get(&id).cloned().flatten(),
            )?;
        }
    }
    Ok(())
}

async fn annotate_scan_axes_lifecycle(
    db: &Db,
    caller: &Caller,
    axes: &mut serde_json::Map<String, Value>,
) -> Result<()> {
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let interpreter = crate::query::lifecycle::LifecycleInterpreter::load(db, principal).await?;
    let mut interpretations = std::collections::HashMap::new();
    for facet in axes.values_mut() {
        let Some(samples) = facet.get_mut("samples").and_then(Value::as_array_mut) else {
            continue;
        };
        for sample in samples {
            let Some(id) = sample.get("id").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            if !interpretations.contains_key(&id) {
                let row =
                    sqlx::query("SELECT type, kind, home_id, lifecycle FROM records WHERE id = ?")
                        .bind(&id)
                        .fetch_optional(db.write_pool())
                        .await?;
                let Some(row) = row else { continue };
                let record_type: String = row.try_get("type")?;
                let kind: Option<String> = row.try_get("kind")?;
                let home_id: Option<String> = row.try_get("home_id")?;
                let lifecycle: Option<String> = row.try_get("lifecycle")?;
                interpretations.insert(
                    id.clone(),
                    interpreter.interpret(
                        &record_type,
                        kind.as_deref(),
                        home_id.as_deref(),
                        lifecycle.as_deref(),
                    ),
                );
            }
            if let Some(interpretation) = interpretations.get(&id) {
                sample["lifecycle_interpretation"] = serde_json::to_value(interpretation)?;
            }
        }
    }
    Ok(())
}

fn build_scan_convergence(axes: &serde_json::Map<String, Value>) -> Vec<Value> {
    struct ConvergenceRecord {
        id: String,
        record_type: String,
        name: String,
        axes: Vec<String>,
        display_reference: Option<Value>,
        record_path: Option<Value>,
        record_path_full: Option<Value>,
        lifecycle_interpretation: Option<Value>,
    }

    let mut appearances: std::collections::HashMap<String, ConvergenceRecord> =
        std::collections::HashMap::new();
    for (axis_name, facet) in axes {
        let Some(samples) = facet.get("samples").and_then(Value::as_array) else {
            continue;
        };
        for sample in samples {
            let (Some(id), Some(record_type), Some(name)) = (
                sample.get("id").and_then(Value::as_str),
                sample.get("type").and_then(Value::as_str),
                sample.get("name").and_then(Value::as_str),
            ) else {
                continue;
            };
            appearances
                .entry(id.to_string())
                .or_insert_with(|| ConvergenceRecord {
                    id: id.to_string(),
                    record_type: record_type.to_string(),
                    name: name.to_string(),
                    axes: Vec::new(),
                    display_reference: sample.get("display_reference").cloned(),
                    record_path: sample.get("record_path").cloned(),
                    record_path_full: sample.get("record_path_full").cloned(),
                    lifecycle_interpretation: sample.get("lifecycle_interpretation").cloned(),
                })
                .axes
                .push(axis_name.clone());
        }
    }
    let mut convergence: Vec<ConvergenceRecord> = appearances
        .into_values()
        .filter(|record| record.axes.len() >= 2)
        .collect();
    convergence.sort_by(|a, b| {
        b.axes
            .len()
            .cmp(&a.axes.len())
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.id.cmp(&b.id))
    });
    convergence
        .into_iter()
        .map(|record| {
            let axis_count = record.axes.len();
            let mut value = json!({
                "id": record.id,
                "type": record.record_type,
                "name": record.name,
                "axes": record.axes,
                "axis_count": axis_count,
            });
            let Some(object) = value.as_object_mut() else {
                return value;
            };
            if let Some(display_reference) = record.display_reference {
                object.insert("display_reference".into(), display_reference);
            }
            if let Some(record_path) = record.record_path {
                object.insert("record_path".into(), record_path);
            }
            if let Some(record_path_full) = record.record_path_full {
                object.insert("record_path_full".into(), record_path_full);
            }
            if let Some(lifecycle_interpretation) = record.lifecycle_interpretation {
                object.insert("lifecycle_interpretation".into(), lifecycle_interpretation);
            }
            value
        })
        .collect()
}

async fn scan(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "scan";
    let args: ScanArgs = parse_args(TOOL, arguments)?;
    let recent_window_days = args
        .recent_window_days
        .unwrap_or(DEFAULT_RECENT_WINDOW_DAYS);
    if !(1..=MAX_RECENT_WINDOW_DAYS).contains(&recent_window_days) {
        return Err(Error::engine(format!(
            "{TOOL}: 'recent_window_days' must be between 1 and {MAX_RECENT_WINDOW_DAYS}"
        )));
    }
    let high_degree_min = args.high_degree_min.unwrap_or(DEFAULT_HIGH_DEGREE_MIN);
    if high_degree_min < 1 {
        return Err(Error::engine(format!(
            "{TOOL}: 'high_degree_min' must be positive"
        )));
    }
    let include_archived = args.include_archived.unwrap_or(false);

    // The corpus predicate every axis shares: live, unarchived (unless asked),
    // in scope, of the named types. Built once, appended per axis.
    let mut corpus_clauses: Vec<String> = vec![
        "r.deleted_at IS NULL".into(),
        crate::query::not_hidden_predicate("r"),
    ];
    let mut corpus_binds: Vec<String> = Vec::new();
    if !include_archived {
        corpus_clauses.push(
            "NOT EXISTS (SELECT 1 FROM facet_values av
               WHERE av.record_id = r.id AND av.key = 'archived')"
                .into(),
        );
    }
    if let Some(types) = &args.types {
        if !types.is_empty() {
            let placeholders = vec!["?"; types.len()].join(", ");
            corpus_clauses.push(format!("r.type IN ({placeholders})"));
            corpus_binds.extend(types.iter().cloned());
        }
    }
    if let Some(root) = &args.scope {
        if !super::can_record(&db, &caller, root, crate::authorization::Capability::View).await? {
            return Err(Error::engine(format!(
                "{TOOL}: scope record {root} does not exist"
            )));
        }
        let ids = crate::query::tree::subtree_ids(&db, root).await?;
        if ids.is_empty() {
            return Err(Error::engine(format!(
                "{TOOL}: scope record {root} does not exist"
            )));
        }
        let placeholders = vec!["?"; ids.len()].join(", ");
        corpus_clauses.push(format!("r.id IN ({placeholders})"));
        corpus_binds.extend(ids);
    }
    let corpus_where = corpus_clauses.join(" AND ");

    let corpus_size: i64 = {
        let sql = format!("SELECT r.id FROM records r WHERE {corpus_where}");
        let mut query = sqlx::query(&sql);
        for bind in &corpus_binds {
            query = query.bind(bind);
        }
        let rows = query.fetch_all(db.write_pool()).await?;
        let mut count = 0i64;
        for row in rows {
            let id: String = row.try_get("id")?;
            if super::can_record(&db, &caller, &id, crate::authorization::Capability::View).await? {
                count += 1;
            }
        }
        count
    };

    // Census: bucket counts along the spine axes (the type/kind/lifecycle
    // orientation the contract names), via the pipeline's count terminal.
    let census_filter = pipeline::Filter {
        types: args.types.clone().unwrap_or_default(),
        ancestor_id: args.scope.clone(),
        include_archived,
        ..pipeline::Filter::default()
    };
    let mut census = serde_json::Map::new();
    for (label, axis_kind) in [
        ("by_type", pipeline::CountAxis::Type),
        ("by_kind", pipeline::CountAxis::Kind),
        ("by_lifecycle", pipeline::CountAxis::Lifecycle),
    ] {
        let census_steps = [pipeline::Step::filter(census_filter.clone())];
        let census_options = pipeline::PipelineOptions::default();
        let (output, _) = pipeline::run_with_diagnostics_as(
            &db,
            super::principal(&caller),
            &census_steps,
            Some(axis_kind),
            &census_options,
        )
        .await?;
        census.insert(label.into(), serde_json::to_value(&output)?);
    }

    // Provenance is derived from each record's genesis event. The correlated
    // MIN(seq) is an indexed first-row lookup through
    // idx_content_events_record(record_id, seq), not a corpus-wide GROUP BY
    // over the event log, so keeping authorship out of the records projection
    // avoids schema/rebuild churn without turning the unconditional census
    // into a full-log scan.
    //
    // The CASE order makes the origin classes disjoint: an agent run is the
    // strongest signal, then an external binding, then the genesis account.
    // `local` deliberately remains unknown even for Caller::local(): it is
    // legacy fixture/pre-account history, not a portable account identity.
    let provenance_sql = format!(
        "SELECT record_id, provenance
           FROM (
             SELECT r.id AS record_id, CASE
               WHEN genesis.run_key IS NOT NULL THEN 'agent'
               WHEN EXISTS (
                 SELECT 1 FROM bindings external
                  WHERE external.record_id = r.id
                    AND external.system NOT IN ('account', 'email')
               ) THEN 'ingested'
               WHEN genesis.actor IS NULL OR genesis.actor = 'local' THEN 'unknown'
               WHEN caller_account.record_id IS NOT NULL
                    AND account.record_id = caller_account.record_id THEN 'you'
               WHEN account.record_id IS NOT NULL
                    AND person.type = 'Entity' AND person.kind = 'person'
                 THEN 'other_account'
               ELSE 'unknown'
             END AS provenance
               FROM records r
               JOIN content_events genesis
                 ON genesis.record_id = r.id
                AND genesis.seq = (
                  SELECT MIN(first.seq) FROM content_events first
                   WHERE first.record_id = r.id
                )
               LEFT JOIN bindings account
                 ON account.system = 'account' AND account.identifier = genesis.actor
               LEFT JOIN bindings caller_account
                 ON caller_account.system = 'account' AND caller_account.identifier = ?
               LEFT JOIN records person ON person.id = account.record_id
              WHERE {corpus_where}
           ) classified
          ORDER BY provenance, record_id"
    );
    let mut provenance_query = sqlx::query(&provenance_sql).bind(caller.credential());
    for bind in &corpus_binds {
        provenance_query = provenance_query.bind(bind);
    }
    let provenance_rows = provenance_query.fetch_all(db.write_pool()).await?;
    let mut provenance_counts = std::collections::BTreeMap::<String, i64>::new();
    for row in &provenance_rows {
        let id: String = row.try_get("record_id")?;
        if super::can_record(&db, &caller, &id, crate::authorization::Capability::View).await? {
            *provenance_counts
                .entry(row.try_get("provenance")?)
                .or_default() += 1;
        }
    }
    let provenance_buckets = provenance_counts
        .into_iter()
        .map(|(key, count)| json!({ "key": key, "count": count }))
        .collect::<Vec<_>>();
    census.insert(
        "provenance".into(),
        json!({
            "shape": "counts",
            "total": corpus_size,
            "buckets": provenance_buckets,
        }),
    );

    // The sampled axes. Each query orders by its own relevance; the head is
    // the sample, the full row count is the pool.
    let mut axes = serde_json::Map::new();

    // Resolve aliases through the account binding rather than comparing only
    // the canonical token. That keeps pre-account actor aliases attributable
    // without rewriting history. An explicit selector must be a known account;
    // the implicit caller falls back to exact matching for legacy `local`
    // fixtures and other pre-binding callers.
    let authored_selector = args.authored_by.as_deref().unwrap_or(caller.credential());
    if !caller.is_host_owner()
        && args.authored_by.is_some()
        && authored_selector != caller.credential()
    {
        return Err(Error::engine(format!(
            "{TOOL}: authored_by may name only the current caller"
        )));
    }
    let authored_person: Option<String> = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system = 'account' AND identifier = ?",
    )
    .bind(authored_selector)
    .fetch_optional(db.write_pool())
    .await?;
    if args.authored_by.is_some() && authored_person.is_none() {
        return Err(Error::engine(format!(
            "{TOOL}: 'authored_by' must be an account token present in this file"
        )));
    }
    let (authored_predicate, authored_binds) = match authored_person {
        Some(person_id) => (
            "e.actor IN (SELECT identifier FROM bindings WHERE system = 'account' AND record_id = ?)".to_string(),
            vec![person_id],
        ),
        None => ("e.actor = ?".to_string(), vec![authored_selector.to_string()]),
    };
    let authored_sql = format!(
        "SELECT r.id, r.type, r.name, latest.created_at AS authored_at
           FROM records r
           JOIN content_events latest
             ON latest.seq = (
               SELECT MAX(e.seq) FROM content_events e
                WHERE e.record_id = r.id AND {authored_predicate}
             )
          WHERE {corpus_where}
          ORDER BY latest.seq DESC, r.id"
    );
    let mut authored_axis_binds = authored_binds;
    authored_axis_binds.extend(corpus_binds.iter().cloned());
    axes.insert(
        "authored_by".into(),
        axis(
            &db,
            &caller,
            &authored_sql,
            &authored_axis_binds,
            Some(AxisMetricColumn {
                sql_alias: "authored_at",
                json_key: "authored_at",
                kind: AxisMetricKind::Text,
            }),
        )
        .await?
        .to_json(corpus_size),
    );

    if let Some(query_text) = args.query.as_deref().filter(|q| !q.trim().is_empty()) {
        // Count and sample are two queries over the SAME filters: the pool
        // count is uncapped by contract (the axis promise is that the cap
        // hides no depth), the sample fetch is capped at what it shows.
        let fts_opts = FtsOptions {
            scope: args.scope.clone(),
            include_archived,
            limit: Some(SCAN_SAMPLE_LIMIT as i64),
            types: args.types.clone().unwrap_or_default(),
        };
        let trusted_local_bypass = super::is_legacy_local(&caller);
        let count = fts::search_pool_count_with_policy_bypass(
            &db,
            caller.credential(),
            trusted_local_bypass,
            query_text,
            &fts_opts,
        )
        .await?;
        let hits = fts::search_with_policy_bypass(
            &db,
            caller.credential(),
            trusted_local_bypass,
            query_text,
            &fts_opts,
        )
        .await?;
        let facet = AxisFacet {
            count,
            samples: hits
                .iter()
                .map(|h| AxisSample {
                    id: h.id.clone(),
                    record_type: h.record_type.clone(),
                    name: h.name.clone(),
                    evidence: vec![
                        ("score".into(), json!(h.score)),
                        ("snippet".into(), json!(h.snippet)),
                    ],
                })
                .collect(),
        };
        axes.insert("lexical".into(), facet.to_json(corpus_size));
    }

    let cutoff = (chrono::Utc::now() - chrono::Duration::days(recent_window_days))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let recent_sql = format!(
        "SELECT r.id, r.type, r.name, r.last_activity_at FROM records r
          WHERE {corpus_where} AND r.last_activity_at >= ?
          ORDER BY r.last_activity_at DESC, r.id"
    );
    let mut recent_binds = corpus_binds.clone();
    recent_binds.push(cutoff.clone());
    axes.insert(
        "recent".into(),
        axis(
            &db,
            &caller,
            &recent_sql,
            &recent_binds,
            Some(AxisMetricColumn {
                sql_alias: "last_activity_at",
                json_key: "last_activity_at",
                kind: AxisMetricKind::Text,
            }),
        )
        .await?
        .to_json(corpus_size),
    );

    axes.insert(
        "high_degree".into(),
        derived_relationship_axis(
            &db,
            &caller,
            &corpus_where,
            &corpus_binds,
            DerivedAxisMetric::Degree,
            high_degree_min,
        )
        .await?
        .to_json(corpus_size),
    );

    // Tree region: the corpus's largest live containers — where the mass of
    // the subtree sits, before walking it with get_structure.
    axes.insert(
        "containers".into(),
        derived_relationship_axis(
            &db,
            &caller,
            &corpus_where,
            &corpus_binds,
            DerivedAxisMetric::ChildCount,
            1,
        )
        .await?
        .to_json(corpus_size),
    );

    annotate_scan_axes_lifecycle(&db, &caller, &mut axes).await?;
    annotate_scan_axes_record_paths(&db, &mut axes).await?;

    // Convergence: described records surfacing in the SAMPLES of two or more
    // axes — the strongest orientation signal a stateless scan can give.
    let convergence = build_scan_convergence(&axes);

    Ok(json!({
        "corpus_size": corpus_size,
        "scope": args.scope,
        "census": census,
        "axes": axes,
        "convergence": convergence,
        "thresholds": {
            "recent_window_days": recent_window_days,
            "recent_cutoff": cutoff,
            "high_degree_min": high_degree_min,
            "sample_limit": SCAN_SAMPLE_LIMIT,
            "saturation_threshold": SCAN_SATURATION_THRESHOLD,
        },
    }))
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register query tools (surface order: query_record, resolve_rollup, search,
/// query_sql, scan).
pub fn register_query_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::QueryRecord,
        "Structured query; as_of pins content, not authorization/schema. SQLite pages \
         include local fences, versions, and continuation. include_coordination \
         adds pinned claims plus live authorized targets (limit 50; not portable). \
         include_interpretation is live/direct only, with no continuation. See \
         read_guide(query-dsl).",
        query_record_input_schema(),
        query_record,
    )?;
    registry.register(
        ToolKind::ResolveRollup,
        "Resolve one live named rollup stored in a record's string-valued \
         'rollup' facet. The stable address is record_id + rollup_name. \
         Successful results use the opened database's bounded revision-keyed \
         in-memory cache; derived values are never written back.",
        json!({
            "type": "object",
            "properties": {
                "record_id": { "type": "string", "minLength": 1 },
                "rollup_name": { "type": "string", "minLength": 1 }
            },
            "required": ["record_id", "rollup_name"],
            "additionalProperties": false
        }),
        resolve_rollup,
    )?;
    registry.register(
        ToolKind::Search,
        "Full-text search over record names and bodies (FTS5, stemmed, \
         caller-filtered and corpus-independently ranked), optionally scoped to a subtree. \
         The query is lexical text, not a record address: when you have a full or short \
         record reference, use get_record with ids:[reference]. \
         Raw BM25/IDF is unavailable because hidden corpus rows affect it. \
         Lexical, not semantic: \
         if results are thin, the payload says so and surfaces near-miss \
         candidates (prefix / mid-word name matches, tree siblings) — \
         REFORMULATE with synonyms or alternative terms rather than concluding \
         the record does not exist.",
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Lexical free text over record names and bodies, not a record address. Terms are ANDed and FTS5 syntax is neutralized. For a known full or short record reference, use get_record.ids instead." },
                "scope": { "type": "string", "description": "Record address whose subtree bounds the lexical search; full ids and short record references are accepted." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "description": "Max hits (default 20)." },
                "include_archived": { "type": "boolean", "description": "Include archived records (default false)." }
            },
            "required": ["query"],
            "additionalProperties": false
        }),
        search,
    )?;
    registry.register(
        ToolKind::QuerySql,
        "Caller-filtered engine-native read-only SQL: one validated SELECT/WITH \
         against audited logical relations, with optional lossless tagged positional \
         parameters. Call engine_info and read_guide(topic='query-sql') before use. \
         Unsupported profiles fail closed. SQL is capped at 64 KiB; rows at 1000, \
         columns at 64, encoded cells at 256 KiB, and encoded results at 4 MiB.",
        crate::query::sql_contract::request_schema(),
        query_sql,
    )?;
    registry.register(
        ToolKind::Scan,
        "Cross-axis orientation before querying: a census (counts by type/kind/\
         lifecycle/provenance) plus sampled axes — authored-by account, lexical \
         (with a query), recent activity, high link degree, largest containers — \
         each with its FULL pool count \
         and a 3-record sample carrying evidence: authored_by has authored_at; \
         lexical has score + snippet; recent has last_activity_at; high_degree \
         has degree; containers has child_count. Convergence is an array of \
         {id, type, name, axes, \
         axis_count} for records surfacing in two or more sample heads, not the \
         full axis pools, ordered by axis_count DESC, name, id. Stateless: \
         refine by re-issuing with tighter filters, then drill in with \
         query_record. The optional query is lexical text, not a record address: \
         when you have a full or short record reference, use get_record with \
         ids:[reference].",
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Lexical free text over record names and bodies, not a record address; enables the lexical axis. For a known full or short record reference, use get_record.ids instead." },
                "scope": { "type": "string", "description": "Record address whose subtree bounds every axis; full ids and short record references are accepted." },
                "types": { "type": "array", "items": { "type": "string" }, "description": "Restrict every axis to these record types." },
                "recent_window_days": { "type": "integer", "minimum": 1, "description": "Recency window for the 'recent' axis (default 14)." },
                "high_degree_min": { "type": "integer", "minimum": 1, "description": "Link-count floor for the 'high_degree' axis (default 8)." },
                "include_archived": { "type": "boolean", "description": "Include archived records (default false)." },
                "authored_by": { "type": "string", "description": "Account token for the authored_by axis (defaults to the authenticated caller)." }
            },
            "additionalProperties": false
        }),
        scan,
    )?;
    Ok(())
}

#[cfg(test)]
mod saved_query_snapshot_tests {
    use serde_json::json;

    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::db::create_database;
    use crate::store::create_record;

    // Pinned fixture record ids. Nothing here depends on their text: ordering
    // in these tests is by `name`, and no assertion reads an id back.
    const WORK_A_ID: &str = "9ee40000-0000-4000-8000-000000000001";
    const WORK_B_ID: &str = "9ee40000-0000-4000-8000-000000000002";
    const WORK_BEFORE_ID: &str = "9ee40000-0000-4000-8000-000000000003";
    const WORK_AFTER_ID: &str = "9ee40000-0000-4000-8000-000000000004";
    const SNAPSHOT_PARENT_ID: &str = "9ee40000-0000-4000-8000-000000000005";
    const SNAPSHOT_CHILD_ID: &str = "9ee40000-0000-4000-8000-000000000006";

    async fn database_with_work_items() -> Db {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({ "id": WORK_A_ID, "type": "WorkItem", "kind": "task", "name": "A" }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({ "id": WORK_B_ID, "type": "WorkItem", "kind": "task", "name": "B" }),
        )
        .await
        .unwrap();
        db
    }

    async fn assert_live_lens_parity(db: &Db, query: Value) {
        let caller = Caller::local();
        let lens = execute_query_record_args_with_lens_as(
            &ReadLens::live(db),
            &caller,
            "saved query",
            query.clone(),
        )
        .await
        .unwrap();
        let mut snapshot = db.write_pool().begin().await.unwrap();
        let live = execute_query_record_args_in_as(&mut snapshot, &caller, "saved query", query)
            .await
            .unwrap();
        snapshot.rollback().await.unwrap();
        assert_eq!(live, lens);
    }

    #[tokio::test]
    async fn live_and_lens_pipeline_outputs_are_identical() {
        let db = database_with_work_items().await;
        assert_live_lens_parity(
            &db,
            json!({
                "steps": [{ "step": "filter", "types": ["WorkItem"] }],
                "order": "name_asc",
                "limit": 1
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn live_and_lens_aggregate_outputs_are_identical() {
        let db = database_with_work_items().await;
        assert_live_lens_parity(
            &db,
            json!({
                "steps": [{ "step": "filter", "types": ["WorkItem"] }],
                "aggregate": { "op": "count" }
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn live_activity_retains_its_pinned_lens_diagnostic() {
        let db = create_database(":memory:").await.unwrap();
        let caller = Caller::local();
        let mut snapshot = db.write_pool().begin().await.unwrap();
        let error = execute_query_record_args_in_as(
            &mut snapshot,
            &caller,
            "saved query",
            json!({
                "steps": [{ "step": "filter" }],
                "activity": {
                    "actions": { "any": [{
                        "kind": "event",
                        "event_types": ["record.created"]
                    }] }
                }
            }),
        )
        .await
        .unwrap_err();
        snapshot.rollback().await.unwrap();
        assert_eq!(
            error.to_string(),
            "saved query: activity execution requires its pinned historical membership lens"
        );
    }

    #[tokio::test]
    async fn saved_query_results_stay_on_the_caller_snapshot() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({ "id": WORK_BEFORE_ID, "type": "WorkItem", "kind": "task", "name": "Before" }),
        )
        .await
        .unwrap();
        let query = json!({
            "steps": [{ "step": "filter", "types": ["WorkItem"] }],
            "order": "name_asc"
        });
        let caller = Caller::local();
        let mut snapshot = db.write_pool().begin().await.unwrap();
        let before =
            execute_query_record_args_in_as(&mut snapshot, &caller, "saved query", query.clone())
                .await
                .unwrap();
        assert_eq!(before["total"], 1);

        create_record(
            &db,
            json!({ "id": WORK_AFTER_ID, "type": "WorkItem", "kind": "task", "name": "After" }),
        )
        .await
        .unwrap();
        let pinned =
            execute_query_record_args_in_as(&mut snapshot, &caller, "saved query", query.clone())
                .await
                .unwrap();
        assert_eq!(pinned["total"], 1);
        snapshot.rollback().await.unwrap();

        let current = execute_query_record_args_as(&db, &caller, "saved query", query)
            .await
            .unwrap();
        assert_eq!(current["total"], 2);
    }

    #[tokio::test]
    async fn custody_and_containment_disclosure_stay_on_the_query_snapshot() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id":SNAPSHOT_PARENT_ID, "type":"Collection", "kind":"folder",
                "name":"Parent", "home_id":crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id":SNAPSHOT_CHILD_ID, "type":"WorkItem", "kind":"task",
                "name":"Child", "home_id":SNAPSHOT_PARENT_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "agent:test",
            SNAPSHOT_PARENT_ID,
            vec![AllowEntry::account("acct:reader", Capability::View)],
        )
        .await
        .unwrap();

        let caller = Caller::authenticated("acct:reader");
        let query = json!({
            "steps":[{"step":"filter", "ids":[SNAPSHOT_CHILD_ID]}]
        });
        let mut snapshot = db.write_pool().begin().await.unwrap();
        let before =
            execute_query_record_args_in_as(&mut snapshot, &caller, "saved query", query.clone())
                .await
                .unwrap();
        assert_eq!(before["records"][0]["custody_boundary"], false);
        assert_eq!(before["records"][0]["containment_path_visible"], true);

        replace_explicit_policy(
            &db,
            "agent:test",
            SNAPSHOT_CHILD_ID,
            vec![AllowEntry::account("acct:reader", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "agent:test", SNAPSHOT_PARENT_ID, vec![])
            .await
            .unwrap();

        let pinned =
            execute_query_record_args_in_as(&mut snapshot, &caller, "saved query", query.clone())
                .await
                .unwrap();
        assert_eq!(pinned["records"][0]["custody_boundary"], false);
        assert_eq!(pinned["records"][0]["containment_path_visible"], true);
        snapshot.rollback().await.unwrap();

        let current = execute_query_record_args_as(&db, &caller, "saved query", query)
            .await
            .unwrap();
        assert_eq!(current["records"][0]["custody_boundary"], true);
        assert_eq!(current["records"][0]["containment_path_visible"], false);
    }
}

#[cfg(test)]
mod governed_sql_tests {
    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::db::create_database;
    use crate::store::create_record;

    fn definition(sql: &str, rows: usize) -> SavedSqlDefinition {
        let columns = vec![
            SavedSqlColumn {
                name: "name".into(),
                column_type: SavedSqlColumnType::Text,
                nullable: false,
            },
            SavedSqlColumn {
                name: "id".into(),
                column_type: SavedSqlColumnType::Identifier,
                nullable: false,
            },
        ];
        SavedSqlDefinition {
            v: SAVED_SQL_VERSION.into(),
            kind: "governed_sql".into(),
            profile: SavedSqlProfile {
                id: "sqlite-local".into(),
                revision: 1,
            },
            catalog_revision: crate::query::sql_contract::LOGICAL_CATALOG_REVISION,
            relations: BTreeMap::from([(
                "records".into(),
                SavedSqlRelationDependency {
                    identity: "native.query-sql.records".into(),
                    semantic_version: 1,
                },
            )]),
            sql: sql.into(),
            parameters: vec![crate::query::sql_contract::QuerySqlParameter::Text {
                value: Some("WorkItem".into()),
            }],
            output: SavedSqlOutput {
                schema_sha256: saved_sql_schema_sha256(&columns).unwrap(),
                columns,
                row_identity: vec!["id".into()],
                order: vec![
                    SavedSqlOrder {
                        column: "name".into(),
                        direction: SavedSqlDirection::Asc,
                    },
                    SavedSqlOrder {
                        column: "id".into(),
                        direction: SavedSqlDirection::Asc,
                    },
                ],
            },
            bounds: SavedSqlBounds { rows },
        }
    }

    #[test]
    fn saved_sql_admission_pins_versions_schema_identity_order_and_relations() {
        let valid = definition("SELECT name,id FROM records WHERE type=?1", 10);
        validate_saved_sql(&valid).unwrap();

        let mut wrong_relation = valid.clone();
        wrong_relation.relations.insert(
            "records".into(),
            SavedSqlRelationDependency {
                identity: "native.query-sql.records".into(),
                semantic_version: 2,
            },
        );
        assert!(validate_saved_sql(&wrong_relation)
            .unwrap_err()
            .to_string()
            .contains("identity/version is incompatible"));

        let mut wrong_identity = valid.clone();
        wrong_identity.relations.insert(
            "records".into(),
            SavedSqlRelationDependency {
                identity: "native.semantic.not-records".into(),
                semantic_version: 1,
            },
        );
        assert!(validate_saved_sql(&wrong_identity)
            .unwrap_err()
            .to_string()
            .contains("identity/version is incompatible"));

        let mut local_sequence_identity = valid.clone();
        local_sequence_identity.output.columns[1].column_type = SavedSqlColumnType::Integer;
        local_sequence_identity.output.schema_sha256 =
            saved_sql_schema_sha256(&local_sequence_identity.output.columns).unwrap();
        assert!(validate_saved_sql(&local_sequence_identity)
            .unwrap_err()
            .to_string()
            .contains("stable identifiers"));

        let mut timestamp_tiebreak = valid.clone();
        timestamp_tiebreak.output.order.pop();
        assert!(validate_saved_sql(&timestamp_tiebreak)
            .unwrap_err()
            .to_string()
            .contains("final order key"));

        let mut composite_identity = definition("SELECT name,id FROM records WHERE type=?1", 10);
        composite_identity.output.columns[0].column_type = SavedSqlColumnType::Identifier;
        composite_identity.output.schema_sha256 =
            saved_sql_schema_sha256(&composite_identity.output.columns).unwrap();
        composite_identity.output.row_identity = vec!["name".into(), "id".into()];
        assert!(validate_saved_sql(&composite_identity)
            .unwrap_err()
            .to_string()
            .contains("exactly one stable row identifier"));

        let mut wrong_collection_identity =
            definition("SELECT name,id FROM records WHERE type=?1", 10);
        wrong_collection_identity.output.columns[0].column_type = SavedSqlColumnType::Identifier;
        wrong_collection_identity.output.schema_sha256 =
            saved_sql_schema_sha256(&wrong_collection_identity.output.columns).unwrap();
        wrong_collection_identity.output.row_identity = vec!["name".into()];
        wrong_collection_identity.output.order = vec![SavedSqlOrder {
            column: "name".into(),
            direction: SavedSqlDirection::Asc,
        }];
        let raw = serde_json::to_string(&wrong_collection_identity).unwrap();
        assert!(matches!(
            inspect_saved_record_query(Some(&raw)),
            SavedQueryInspection::Invalid { diagnostic }
                if diagnostic.contains("must use 'id'")
        ));

        let mut wrong_output = definition("SELECT id,name FROM records WHERE type=?1", 10);
        assert!(validate_saved_sql(&wrong_output)
            .unwrap_err()
            .to_string()
            .contains("output columns do not match"));
        wrong_output = definition(
            "SELECT name,id FROM records WHERE type=?1",
            crate::query::sql_contract::MAX_ROWS + 1,
        );
        assert!(validate_saved_sql(&wrong_output)
            .unwrap_err()
            .to_string()
            .contains("outside query_sql limits"));

        let mut legacy = serde_json::to_value(&valid).unwrap();
        legacy["v"] = json!("1.0");
        legacy["relations"] = json!({"records": 1});
        let unsupported = serde_json::to_string(&legacy).unwrap();
        assert!(matches!(
            inspect_saved_query(Some(&unsupported)),
            SavedQueryInspection::UnsupportedVersion { version, diagnostic }
                if version == "1.0" && diagnostic.contains("without semantic identities")
        ));

        let literal_and_comment = definition(
            "SELECT name,id FROM records WHERE type=?1 AND 'agent_activity'='agent_activity' /* links */",
            10,
        );
        validate_saved_sql(&literal_and_comment)
            .expect("comments and literals do not create relation dependencies");
        let cte_shadow = definition(
            "WITH records(name,id) AS (VALUES('fake','stable')) SELECT name,id FROM records",
            10,
        );
        assert!(validate_saved_sql(&cte_shadow)
            .unwrap_err()
            .to_string()
            .contains("cannot shadow logical relation 'records'"));
        for quoted in ["'records'", "`records`", "[records]", "\"records\""] {
            let shadow = definition(
                &format!(
                    "WITH {quoted}(name,id) AS (VALUES('fake','stable')) SELECT name,id FROM {quoted}"
                ),
                10,
            );
            assert!(
                validate_saved_sql(&shadow)
                    .unwrap_err()
                    .to_string()
                    .contains("cannot shadow logical relation 'records'"),
                "quote style {quoted} must not bypass logical-relation shadowing"
            );
        }
    }

    #[test]
    fn saved_sql_receipt_folds_best_effort_dependency_completeness() {
        let mut definition = definition(
            "SELECT r.name,r.id FROM records r WHERE r.type=?1 AND EXISTS (SELECT 1 FROM agent_activity a WHERE a.activity_id=r.id)",
            10,
        );
        definition.relations.insert(
            "agent_activity".into(),
            SavedSqlRelationDependency {
                identity: "native.semantic.agent_activity".into(),
                semantic_version: 1,
            },
        );
        assert!(validate_saved_sql(&definition)
            .unwrap_err()
            .to_string()
            .contains("identity/version is incompatible"));
        definition
            .relations
            .get_mut("agent_activity")
            .unwrap()
            .semantic_version = crate::query::sql_contract::AGENT_ACTIVITY_RELATION_VERSION;
        validate_saved_sql(&definition).unwrap();
        let result = crate::query::sql_contract::QuerySqlResult {
            columns: vec!["name".into(), "id".into()],
            rows: vec![],
            row_count: 0,
            truncated: false,
        };
        let output = finish_saved_sql(
            &definition,
            &definition.parameters,
            "ndb_00000000000000000000000000000000",
            crate::query::sql::GovernedSqlObservation {
                observed_at: "2026-08-31T00:00:00.000Z".into(),
                content_event_seq: Some(17),
                lifecycle_event_seq: Some(9),
                authorization_boundary: "native.authorization-snapshot.v1.test".into(),
                transient_watermark: None,
                transient_available: false,
            },
            result,
        )
        .unwrap();
        assert_eq!(output["receipt"]["completeness"], "best_effort");
        assert_eq!(output["receipt"]["replayable"], false);
        assert_eq!(output["receipt"]["observation_window_hours"], 24);
        assert_eq!(output["receipt"]["boundary"]["content_event_seq"], 17);
        assert_eq!(
            output["receipt"]["degraded_sources"],
            json!(["transient_activity_capture"])
        );
        assert_eq!(
            output["receipt"]["relations"][0]["identity"],
            "native.semantic.agent_activity"
        );
        assert_eq!(output["columns"], json!(["name", "id"]));

        let boolean_columns = vec![
            SavedSqlColumn {
                name: "appears_active".into(),
                column_type: SavedSqlColumnType::Boolean,
                nullable: false,
            },
            SavedSqlColumn {
                name: "id".into(),
                column_type: SavedSqlColumnType::Identifier,
                nullable: false,
            },
        ];
        let mut boolean_definition = definition.clone();
        boolean_definition.output.columns = boolean_columns.clone();
        boolean_definition.output.schema_sha256 =
            saved_sql_schema_sha256(&boolean_columns).unwrap();
        boolean_definition.output.row_identity = vec!["id".into()];
        boolean_definition.output.order = vec![SavedSqlOrder {
            column: "id".into(),
            direction: SavedSqlDirection::Asc,
        }];
        let normalized = finish_saved_sql(
            &boolean_definition,
            &boolean_definition.parameters,
            "ndb_00000000000000000000000000000000",
            crate::query::sql::GovernedSqlObservation {
                observed_at: "2026-08-31T00:00:00.000Z".into(),
                content_event_seq: Some(17),
                lifecycle_event_seq: Some(9),
                authorization_boundary: "native.authorization-snapshot.v1.test".into(),
                transient_watermark: None,
                transient_available: false,
            },
            crate::query::sql_contract::QuerySqlResult {
                columns: vec!["appears_active".into(), "id".into()],
                rows: vec![json!({"appears_active":1,"id":"activity"})],
                row_count: 1,
                truncated: false,
            },
        )
        .unwrap();
        assert_eq!(normalized["rows"][0]["appears_active"], true);

        let duplicate_probe = crate::query::sql_contract::QuerySqlResult {
            columns: vec!["name".into(), "id".into()],
            rows: vec![
                json!({"name":"first", "id":"same"}),
                json!({"name":"boundary", "id":"same"}),
            ],
            row_count: 2,
            truncated: false,
        };
        let mut one_row = definition;
        one_row.bounds.rows = 1;
        assert!(finish_saved_sql(
            &one_row,
            &one_row.parameters,
            "ndb_00000000000000000000000000000000",
            crate::query::sql::GovernedSqlObservation {
                observed_at: "2026-08-31T00:00:00.000Z".into(),
                content_event_seq: Some(17),
                lifecycle_event_seq: Some(9),
                authorization_boundary: "native.authorization-snapshot.v1.test".into(),
                transient_watermark: Some(3),
                transient_available: true,
            },
            duplicate_probe,
        )
        .unwrap_err()
        .to_string()
        .contains("duplicate row identity"));
    }

    #[tokio::test]
    async fn records_only_receipt_omits_activity_boundaries() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id": "00000000-0000-4000-8000-000000000123",
                "type": "WorkItem",
                "kind": "task",
                "name": "Boundary",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": "00000000-0000-4000-8000-000000000124",
                "type": "WorkItem",
                "kind": "task",
                "name": "Hidden",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "agent:test",
            "00000000-0000-4000-8000-000000000123",
            vec![AllowEntry::account("receipt-reader", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "agent:test",
            "00000000-0000-4000-8000-000000000124",
            vec![AllowEntry::account("other-reader", Capability::View)],
        )
        .await
        .unwrap();
        let definition = definition("SELECT name,id FROM records WHERE type=?1", 10);
        let caller = Caller::authenticated("receipt-reader");
        let before = execute_saved_sql(db.clone(), &caller, &definition, None)
            .await
            .unwrap();

        crate::control::ensure_agent_run(&db, "scout-chair-a748b2", "hidden-account")
            .await
            .unwrap();
        replace_explicit_policy(
            &db,
            "agent:test",
            "00000000-0000-4000-8000-000000000124",
            vec![AllowEntry::account("third-reader", Capability::View)],
        )
        .await
        .unwrap();

        let after = execute_saved_sql(db, &caller, &definition, None)
            .await
            .unwrap();
        assert_eq!(before["receipt"]["boundary"], after["receipt"]["boundary"]);
        assert!(before["receipt"]["boundary"]
            .get("lifecycle_event_seq")
            .is_none());
        assert!(before["receipt"]["boundary"]
            .get("transient_watermark")
            .is_none());
        assert!(before["receipt"]["transient_activity"].is_null());
    }

    #[tokio::test]
    async fn saved_executor_retains_boundary_probe_for_identity_validation() {
        use sqlx::Acquire as _;

        let db = create_database(":memory:").await.unwrap();
        let request = crate::query::sql_contract::QuerySqlRequest {
            sql: "WITH RECURSIVE n(value) AS (
                    VALUES(1) UNION ALL SELECT value+1 FROM n WHERE value<1001
                  )
                  SELECT 'Row' AS name,
                         CASE WHEN value>=1000 THEN 'zzzz-boundary-duplicate' ELSE 'id-' || value END AS id
                  FROM n ORDER BY id"
                .into(),
            parameters: vec![],
        };
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let (saved, observation) = sql::query_sql_request_in_for_saved(
            &mut tx,
            // SAFETY: test-only construction of the same trusted local caller
            // accepted by the MCP registry; no untrusted input reaches it.
            unsafe { crate::query::principal::QueryPrincipal::trusted_local_unchecked("local") },
            request.clone(),
        )
        .await
        .unwrap();
        assert_eq!(saved.rows.len(), crate::query::sql_contract::MAX_ROWS + 1);
        let public = sql::query_sql_request_in(
            &mut tx,
            // SAFETY: same test-only trusted local caller as above.
            unsafe { crate::query::principal::QueryPrincipal::trusted_local_unchecked("local") },
            request,
        )
        .await
        .unwrap();
        assert_eq!(public.rows.len(), crate::query::sql_contract::MAX_ROWS);
        assert!(public.truncated);
        tx.rollback().await.unwrap();

        let mut definition = definition("SELECT name,id FROM records WHERE type=?1", 1000);
        definition.output.order = vec![SavedSqlOrder {
            column: "id".into(),
            direction: SavedSqlDirection::Asc,
        }];
        let error = finish_saved_sql(
            &definition,
            &definition.parameters,
            "ndb_00000000000000000000000000000000",
            observation,
            saved,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("duplicate row identity"), "{error}");
        db.close().await;
    }

    #[tokio::test]
    async fn saved_sql_enforces_engine_order_bound_and_opaque_unpaged_receipt() {
        let db = create_database(":memory:").await.unwrap();
        for (id, name) in [
            ("71000000-0000-4000-8000-000000000002", "same"),
            ("71000000-0000-4000-8000-000000000001", "same"),
        ] {
            create_record(
                &db,
                json!({ "id":id, "type":"WorkItem", "kind":"task", "name":name }),
            )
            .await
            .unwrap();
        }
        // The authored inner order is deliberately opposite; the governed
        // declaration owns the total order and stable identifier tie-break.
        let definition = definition(
            "SELECT name,id FROM records WHERE type=?1 ORDER BY id DESC",
            1,
        );
        let output = execute_saved_sql(db, &Caller::local(), &definition, None)
            .await
            .unwrap();
        assert_eq!(
            output["rows"][0]["id"],
            "71000000-0000-4000-8000-000000000001"
        );
        assert_eq!(output["row_count"], 1);
        assert_eq!(output["truncated"], true);
        assert_eq!(output["receipt"]["completeness"], "truncated");
        assert_eq!(output["receipt"]["cursor"], Value::Null);
        let token = output["receipt"]["snapshot"].as_str().unwrap();
        assert!(token.starts_with("native.snapshot.v1."));
        assert!(!token.contains("content_seq"));
    }

    #[tokio::test]
    async fn saved_sql_parameter_override_must_preserve_declared_types() {
        let db = create_database(":memory:").await.unwrap();
        let error = execute_saved_sql(
            db,
            &Caller::local(),
            &definition("SELECT name,id FROM records WHERE type=?1", 10),
            Some(vec![
                crate::query::sql_contract::QuerySqlParameter::Integer {
                    value: Some("1".into()),
                },
            ]),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("count/type"));
    }
}

#[cfg(test)]
mod grammar_tests {
    use super::*;

    const GRAMMAR_FIXTURE: &str = include_str!("../../../tests/fixtures/query-record-grammar.json");
    const DRIFT_POLICY: &str = "query_record saved-query grammar drifted. Classify the change in the pull request as additive or breaking and explain why. Adding an optional field or broadening an accepted shape is additive and does not bump the 0.x minor. Removing or renaming a field, making one required, narrowing a type, enum, or range, or changing the meaning selected by an existing JSON shape is breaking and bumps the 0.x minor. Semantic compatibility is an author/reviewer judgement; this test deliberately does not infer it. Refresh tests/fixtures/query-record-grammar.json only after that decision.";

    #[test]
    fn saved_query_grammar_matches_the_versioned_fixture() {
        let fixture: Value = serde_json::from_str(GRAMMAR_FIXTURE).expect("valid grammar fixture");
        assert_eq!(
            fixture.get("version").and_then(Value::as_str),
            Some(SAVED_QUERY_VERSION),
            "fixture version must equal SAVED_QUERY_VERSION; {DRIFT_POLICY}"
        );
        let expected = fixture.get("schema").cloned().unwrap_or(Value::Null);
        let actual = canonical_query_record_schema();
        assert_eq!(
            expected,
            actual,
            "{DRIFT_POLICY}\ncurrent canonical fixture:\n{}",
            serde_json::to_string(&json!({
                "version": SAVED_QUERY_VERSION,
                "schema": actual
            }))
            .expect("fixture serializes")
        );
    }

    #[test]
    fn direct_projections_never_enter_saved_v02() {
        let direct = query_record_input_schema();
        assert_eq!(
            direct["properties"]["include_interpretation"]["type"],
            "boolean"
        );
        assert_eq!(
            direct["properties"]["include_coordination"]["type"],
            "boolean"
        );
        let saved = saved_query_grammar_schema();
        assert!(saved["properties"].get("include_interpretation").is_none());
        assert!(saved["properties"].get("include_coordination").is_none());
        let error = validate_saved_record_query_args(
            "saved query",
            json!({
                "steps":[{"step":"filter"}],
                "include_interpretation":false
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown field `include_interpretation`"));
        let error = validate_saved_record_query_args(
            "saved query",
            json!({
                "steps":[{"step":"filter"}],
                "include_coordination":false
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown field `include_coordination`"));
    }

    #[test]
    fn canonicalization_ignores_documentation_annotations() {
        let schema = query_record_input_schema();
        let expected = canonicalize_schema(schema.clone(), None);
        let mut annotated = schema;
        let object = annotated.as_object_mut().expect("root object schema");
        object.insert("description".into(), json!("changed prose"));
        object.insert("title".into(), json!("renamed schema"));
        object.insert("examples".into(), json!([{"steps": []}]));
        object.insert("$comment".into(), json!("review note"));
        object
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .and_then(|properties| properties.get_mut("steps"))
            .and_then(Value::as_object_mut)
            .expect("steps schema")
            .insert("description".into(), json!("different field docs"));

        assert_eq!(canonicalize_schema(annotated, None), expected);
    }

    #[test]
    fn advertised_schema_keeps_load_bearing_query_guidance() {
        let schema = query_record_input_schema();
        let filter = &schema["properties"]["steps"]["items"]["oneOf"][0]["properties"];
        let kinds = filter["kinds"]["description"]
            .as_str()
            .expect("kinds description");
        assert!(kinds.contains("suggestion"), "{kinds}");
        assert!(kinds.contains("citation"), "{kinds}");
        assert!(kinds.contains("whole pipeline"), "{kinds}");

        let facets = filter["facets"]["description"]
            .as_str()
            .expect("facets description");
        for guidance in [
            "ANDed",
            "bare key",
            "exact-string",
            "numeric lane",
            "upper bound",
        ] {
            assert!(facets.contains(guidance), "missing {guidance:?}: {facets}");
        }

        let has_query = filter["has_query"]["description"]
            .as_str()
            .expect("has_query description");
        assert!(has_query.contains("supported, valid saved-query envelope"));
        assert!(has_query.contains("does not execute saved queries"));
    }

    #[test]
    fn optional_enums_advertise_the_explicit_null_that_serde_accepts() {
        let schema = query_record_input_schema();
        let direction =
            &schema["properties"]["steps"]["items"]["oneOf"][1]["properties"]["direction"];
        for (name, property) in [
            ("count_by", &schema["properties"]["count_by"]),
            ("order", &schema["properties"]["order"]),
            ("direction", direction),
        ] {
            let branches = property["anyOf"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} must use enum-or-null: {property}"));
            assert!(
                branches
                    .iter()
                    .any(|branch| branch["type"] == Value::String("null".into())),
                "{name} has no null branch: {property}"
            );
            assert!(
                branches.iter().any(|branch| branch.get("enum").is_some()),
                "{name} has no enum branch: {property}"
            );
        }
        assert_eq!(schema["required"], json!(["steps"]));
        assert_eq!(
            schema["properties"]["steps"]["items"]["oneOf"][1]["required"],
            json!(["step", "target"])
        );
    }

    #[test]
    fn facet_schema_and_parser_share_the_operator_vocabulary() {
        let generator = SchemaSettings::draft07()
            .with(|settings| settings.inline_subschemas = true)
            .into_generator();
        let schema =
            serde_json::to_value(generator.into_root_schema_for::<FacetArgumentPropertiesSchema>())
                .expect("facet schema serializes");
        let mut advertised = schema["properties"]
            .as_object()
            .expect("facet properties")
            .keys()
            .filter(|field| field.as_str() != "key")
            .map(String::as_str)
            .collect::<Vec<_>>();
        advertised.sort_unstable();
        let mut parsed = FACET_OPERATORS.to_vec();
        parsed.sort_unstable();
        assert_eq!(advertised, parsed);

        for operator in ["lt", "lte", "gt", "gte"] {
            assert_eq!(
                schema["properties"][operator]["type"],
                json!(["number", "string"]),
                "{operator} must describe JSON lanes without a Rust numeric format"
            );
            assert!(schema["properties"][operator].get("format").is_none());
        }
    }
}

#[cfg(test)]
mod rollup_authorization_race_tests {
    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::events::FacetSetPayload;

    #[tokio::test]
    async fn revocation_between_initial_gate_and_result_revision_is_denied() {
        let db = crate::create_database(":memory:").await.unwrap();
        let person = crate::store::create_record(
            &db,
            json!({ "type": "Entity", "kind": "person", "name": "Rollup reader" }),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', 'local', 1)",
        )
        .bind(person)
        .execute(db.write_pool())
        .await
        .unwrap();
        let bearer = crate::store::create_record(
            &db,
            json!({ "type": "Collection", "kind": "folder", "name": "Race bearer" }),
        )
        .await
        .unwrap();
        let child = crate::store::create_record(
            &db,
            json!({
                "type": "WorkItem",
                "kind": "task",
                "name": "Visible contributor",
                "home_id": bearer
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &bearer,
            vec![AllowEntry::account("local", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &child,
            vec![AllowEntry::account("local", Capability::View)],
        )
        .await
        .unwrap();
        let rollup = json!({
            "v": "0.1",
            "outputs": {
                "count": {
                    "query": { "steps": [{ "step": "filter", "home_id": bearer }] },
                    "fold": { "op": "count" }
                }
            }
        })
        .to_string();
        crate::store::set_facet(
            &db,
            &bearer,
            FacetSetPayload {
                key: "rollup".into(),
                value: Some(rollup),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();

        let reached = std::sync::Arc::new(tokio::sync::Notify::new());
        let resume = std::sync::Arc::new(tokio::sync::Notify::new());
        *ROLLUP_AFTER_INITIAL_REQUIRE_HOOK
            .lock()
            .expect("rollup test hook lock") = Some(RollupAfterInitialRequireHook {
            record_id: bearer.clone(),
            reached: reached.clone(),
            resume: resume.clone(),
        });
        let resolving = tokio::spawn(resolve_rollup(
            db.clone(),
            Caller::authenticated("local"),
            json!({ "record_id": bearer, "rollup_name": "count" }),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(5), reached.notified())
            .await
            .expect("rollup reached the post-gate test seam");
        replace_explicit_policy(
            &db,
            "test:policy",
            &bearer,
            vec![AllowEntry::account("another-account", Capability::Manage)],
        )
        .await
        .unwrap();
        resume.notify_one();

        let error = tokio::time::timeout(std::time::Duration::from_secs(5), resolving)
            .await
            .expect("rollup completed after the test seam resumed")
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exist"), "{error}");
        *ROLLUP_AFTER_INITIAL_REQUIRE_HOOK
            .lock()
            .expect("rollup test hook lock") = None;
        db.close().await;
    }
}

#[cfg(test)]
mod scan_record_path_tests {
    use super::*;
    use crate::db::create_database;
    use crate::store::create_record;

    const RECORD_ID: &str = "0189d4c6-1f2a-4a1b-9c3d-5e6f70819293";

    #[tokio::test]
    async fn scan_axis_samples_carry_display_reference_when_mintable() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id": RECORD_ID,
                "type": "Document",
                "kind": "note",
                "name": "Scan sample",
            }),
        )
        .await
        .unwrap();

        let mut axes = serde_json::Map::new();
        axes.insert(
            "recent".into(),
            json!({
                "count": 1,
                "samples": [{
                    "id": RECORD_ID,
                    "type": "Document",
                    "name": "Scan sample",
                    "last_activity_at": "2026-08-12"
                }],
                "quality": "focused"
            }),
        );

        annotate_scan_axes_record_paths(&db, &mut axes)
            .await
            .unwrap();

        let sample = &axes["recent"]["samples"][0];
        assert_eq!(sample["display_reference"], json!("0189d4c"));
        assert_eq!(sample["record_path"], json!("/0189d4c"));
        assert!(!sample["display_reference"].is_null());
        db.close().await;
    }

    #[tokio::test]
    async fn scan_axis_samples_omit_paths_for_caller_chosen_ids() {
        let db = create_database(":memory:").await.unwrap();
        sqlx::query(
            "INSERT INTO records (id, type, name, created_at, updated_at) \
             VALUES (?, 'Document', 'Legacy', '2026-08-12', '2026-08-12')",
        )
        .bind("order-one")
        .execute(db.write_pool())
        .await
        .unwrap();

        let mut axes = serde_json::Map::new();
        axes.insert(
            "recent".into(),
            json!({
                "count": 1,
                "samples": [{
                    "id": "order-one",
                    "type": "Document",
                    "name": "Legacy"
                }],
                "quality": "focused"
            }),
        );

        annotate_scan_axes_record_paths(&db, &mut axes)
            .await
            .unwrap();

        let sample = &axes["recent"]["samples"][0];
        assert!(sample.get("display_reference").is_none());
        assert!(sample.get("record_path").is_none());
        assert!(sample.get("record_path_full").is_none());
        db.close().await;
    }

    #[tokio::test]
    async fn scan_convergence_carries_display_reference_when_mintable() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id": RECORD_ID,
                "type": "Document",
                "kind": "note",
                "name": "Scan sample",
            }),
        )
        .await
        .unwrap();

        let sample = json!({
            "id": RECORD_ID,
            "type": "Document",
            "name": "Scan sample",
            "last_activity_at": "2026-08-12"
        });
        let mut axes = serde_json::Map::new();
        axes.insert(
            "recent".into(),
            json!({
                "count": 1,
                "samples": [sample.clone()],
                "quality": "focused"
            }),
        );
        axes.insert(
            "high_degree".into(),
            json!({
                "count": 1,
                "samples": [sample],
                "quality": "focused"
            }),
        );

        annotate_scan_axes_record_paths(&db, &mut axes)
            .await
            .unwrap();

        let convergence = build_scan_convergence(&axes);
        assert_eq!(convergence.len(), 1);
        let record = &convergence[0];
        assert_eq!(record["display_reference"], json!("0189d4c"));
        assert_eq!(record["record_path"], json!("/0189d4c"));
        assert_eq!(
            record["record_path_full"],
            json!("/0189d4c6-1f2a-4a1b-9c3d-5e6f70819293")
        );
        db.close().await;
    }
}
