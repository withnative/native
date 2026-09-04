//! Bounded live logical-query fold shared by Postgres and Turso-local.
//!
//! Physical adapters own one repeatable snapshot and reviewed relation views.
//! This module loads a bounded normalized corpus through `portable_sql`, then
//! applies the canonical typed query plan without backend-native SQL or a
//! SQLite execution fallback.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Value};

use super::views_history::{self, PortableRecord, SnapshotRows, MAX_VIEW_CANDIDATES};
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;
use crate::portable_sql::{
    BindValue, ColumnSpec, DomainStatementExecutor, LogicalType, NormalizedRow, NormalizedValue,
};
use crate::query::pipeline::{
    AggregateOp, AggregateSpec, CmpOp, CountAxis, Direction, FacetFilter, FacetOp, FacetOrder,
    FacetOrderDirection, FacetOrderLane, Order, PipelineOptions, Step, Traverse,
};
use crate::query::LinkRow;

const MAX_RELATION_ROWS: i64 = 100_000;

#[derive(Clone)]
struct FacetRow {
    key: String,
    value: Option<String>,
    value_num: Option<f64>,
}

struct LogicalSnapshot {
    rows: SnapshotRows,
    facets: HashMap<String, Vec<FacetRow>>,
    shape_ids: HashSet<String>,
    visible: HashSet<String>,
    hidden: HashSet<String>,
    suggestions: HashSet<String>,
    citations: HashSet<String>,
    comments: HashSet<String>,
    lifecycle_interpreter: crate::query::lifecycle::LifecycleInterpreter,
}

fn real(row: &NormalizedRow, field: &str) -> Result<Option<f64>> {
    match row.get(field) {
        Some(NormalizedValue::Real(value)) => Ok(Some(*value)),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "portable logical query returned invalid '{field}'"
        ))),
    }
}

async fn load_snapshot<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
) -> Result<LogicalSnapshot> {
    let record_query = views_history::statement(
        "records",
        &[
            "SELECT r.id,r.type,r.kind,r.name,NULL AS body,r.home_id,r.lifecycle,r.owner_id,r.policy_anchor_id,r.persistence,r.maturity,r.summary,r.last_activity_at,r.created_at,r.updated_at,r.deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r ORDER BY r.id LIMIT ",
            "",
        ],
    )?;
    let record_rows = executor
        .fetch_all(
            &record_query,
            &[BindValue::Integer(MAX_VIEW_CANDIDATES + 1)],
            &views_history::record_columns(),
        )
        .await
        .map_err(views_history::storage_error)?;
    if record_rows.len() > MAX_VIEW_CANDIDATES as usize {
        return Err(Error::engine(format!(
            "portable logical query candidate set exceeds {MAX_VIEW_CANDIDATES} records"
        )));
    }
    let mut records = HashMap::with_capacity(record_rows.len());
    for row in &record_rows {
        let record = views_history::record_from_row(row)?;
        records.insert(record.row.id.clone(), record);
    }

    let facet_query = views_history::statement(
        "facet_values",
        &[
            "SELECT record_id,key,value,value_num FROM {{relation}} ORDER BY record_id,key LIMIT ",
            "",
        ],
    )?;
    let facet_rows = executor
        .fetch_all(
            &facet_query,
            &[BindValue::Integer(MAX_RELATION_ROWS + 1)],
            &[
                ColumnSpec::required("record_id", LogicalType::Text),
                ColumnSpec::required("key", LogicalType::Text),
                ColumnSpec::nullable("value", LogicalType::Text),
                ColumnSpec::nullable("value_num", LogicalType::Real),
            ],
        )
        .await
        .map_err(views_history::storage_error)?;
    if facet_rows.len() > MAX_RELATION_ROWS as usize {
        return Err(Error::engine(format!(
            "portable logical query facet set exceeds {MAX_RELATION_ROWS} rows"
        )));
    }
    let mut facets: HashMap<String, Vec<FacetRow>> = HashMap::new();
    for row in &facet_rows {
        facets
            .entry(views_history::text(row, "record_id")?)
            .or_default()
            .push(FacetRow {
                key: views_history::text(row, "key")?,
                value: views_history::optional_text(row, "value")?,
                value_num: real(row, "value_num")?,
            });
    }

    let link_query = views_history::statement(
        "links",
        &[
            "SELECT id,source_id,target_id,relationship,note,created_at FROM {{relation}} ORDER BY id LIMIT ",
            "",
        ],
    )?;
    let link_rows = executor
        .fetch_all(
            &link_query,
            &[BindValue::Integer(MAX_RELATION_ROWS + 1)],
            &[
                ColumnSpec::required("id", LogicalType::Text),
                ColumnSpec::required("source_id", LogicalType::Text),
                ColumnSpec::required("target_id", LogicalType::Text),
                ColumnSpec::required("relationship", LogicalType::Text),
                ColumnSpec::nullable("note", LogicalType::Text),
                ColumnSpec::required("created_at", LogicalType::Text),
            ],
        )
        .await
        .map_err(views_history::storage_error)?;
    if link_rows.len() > MAX_RELATION_ROWS as usize {
        return Err(Error::engine(format!(
            "portable logical query link set exceeds {MAX_RELATION_ROWS} rows"
        )));
    }
    let links = link_rows
        .iter()
        .map(|row| {
            Ok(LinkRow {
                id: views_history::text(row, "id")?,
                source_id: views_history::text(row, "source_id")?,
                target_id: views_history::text(row, "target_id")?,
                relationship: views_history::text(row, "relationship")?,
                note: views_history::optional_text(row, "note")?,
                created_at: views_history::text(row, "created_at")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let shape_query = views_history::statement(
        "schema_config",
        &[
            "SELECT applies_to_collection_id FROM {{relation}} WHERE applies_to_collection_id IS NOT NULL ORDER BY applies_to_collection_id LIMIT ",
            "",
        ],
    )?;
    let shape_rows = executor
        .fetch_all(
            &shape_query,
            &[BindValue::Integer(MAX_VIEW_CANDIDATES + 1)],
            &[ColumnSpec::required(
                "applies_to_collection_id",
                LogicalType::Text,
            )],
        )
        .await
        .map_err(views_history::storage_error)?;
    if shape_rows.len() > MAX_VIEW_CANDIDATES as usize {
        return Err(Error::engine(format!(
            "portable logical query schema-bearing set exceeds {MAX_VIEW_CANDIDATES} rows"
        )));
    }
    let shape_ids = shape_rows
        .iter()
        .map(|row| views_history::text(row, "applies_to_collection_id"))
        .collect::<Result<HashSet<_>>>()?;

    let rows = SnapshotRows { records, links };
    let visible = views_history::visible_ids(executor, caller, &rows).await?;
    let (hidden, suggestions) = views_history::hidden_ids(executor, &rows.records).await?;
    let mut citations = HashSet::new();
    let mut comments = HashSet::new();
    for record in rows.records.values() {
        let Some(kind) = record.row.kind.as_deref() else {
            continue;
        };
        if record.row.record_type != "Annotation" {
            continue;
        }
        let resolution = crate::meta::kind::resolve_with(executor, "Annotation", kind).await?;
        if crate::generated::kinds::CoreKind::AnnotationCitation.matches(&resolution) {
            citations.insert(record.row.id.clone());
        }
        if crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution) {
            comments.insert(record.row.id.clone());
        }
    }
    let lifecycle_interpreter = crate::query::lifecycle::LifecycleInterpreter::load_visible_with(
        executor,
        crate::mcp::tools::principal(caller),
    )
    .await?;
    Ok(LogicalSnapshot {
        rows,
        facets,
        shape_ids,
        visible,
        hidden,
        suggestions,
        citations,
        comments,
        lifecycle_interpreter,
    })
}

async fn selected_body<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: &str,
) -> Result<Option<String>> {
    let query = views_history::statement(
        "records",
        &[
            "SELECT body FROM {{relation}} WHERE id=",
            " AND deleted_at IS NULL",
        ],
    )?;
    let rows = executor
        .fetch_all(
            &query,
            &[BindValue::Text(record_id.into())],
            &[ColumnSpec::nullable("body", LogicalType::Text)],
        )
        .await
        .map_err(views_history::storage_error)?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => views_history::optional_text(row, "body"),
        _ => Err(Error::engine(
            "portable logical query returned duplicate record bodies",
        )),
    }
}

fn dedup(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn is_descendant(
    snapshot: &LogicalSnapshot,
    id: &str,
    root: &str,
    include_archived: bool,
    include_suggestions: bool,
    include_citations: bool,
) -> bool {
    let allowed_hidden = |candidate: &str| {
        (include_suggestions && snapshot.suggestions.contains(candidate))
            || (include_citations && snapshot.citations.contains(candidate))
    };
    let mut current = Some(id);
    let mut seen = HashSet::new();
    let mut depth = 0_i64;
    while let Some(candidate) = current {
        if depth > crate::query::tree::MAX_WALK_DEPTH || !seen.insert(candidate) {
            return false;
        }
        let Some(record) = snapshot.rows.records.get(candidate) else {
            return false;
        };
        if record.row.deleted_at.is_some()
            || (!include_archived && record.archived)
            || (snapshot.hidden.contains(candidate) && !allowed_hidden(candidate))
        {
            return false;
        }
        if candidate == root {
            return true;
        }
        current = record.row.home_id.as_deref();
        depth += 1;
    }
    false
}

fn facet_rows<'a>(snapshot: &'a LogicalSnapshot, id: &str, key: &str) -> Vec<&'a FacetRow> {
    snapshot
        .facets
        .get(id)
        .into_iter()
        .flatten()
        .filter(|facet| facet.key == key)
        .collect()
}

fn numeric(value: &Value) -> Option<f64> {
    value.as_f64().filter(|value| value.is_finite())
}

fn facet_matches(snapshot: &LogicalSnapshot, id: &str, facet: &FacetFilter) -> bool {
    let values = facet_rows(snapshot, id, &facet.key);
    match &facet.op {
        FacetOp::Exists => !values.is_empty(),
        FacetOp::Eq(value) => value.as_str().is_some_and(|expected| {
            values
                .iter()
                .any(|row| row.value.as_deref() == Some(expected))
        }),
        FacetOp::Ne(value) => value.as_str().is_some_and(|expected| {
            values.iter().any(|row| {
                row.value
                    .as_deref()
                    .is_some_and(|actual| actual != expected)
            })
        }),
        FacetOp::Lt(value) | FacetOp::Lte(value) | FacetOp::Gt(value) | FacetOp::Gte(value) => {
            values.iter().any(|row| {
                let ordering = if let Some(expected) = numeric(value) {
                    row.value_num
                        .and_then(|actual| actual.partial_cmp(&expected))
                } else {
                    value.as_str().and_then(|expected| {
                        row.value.as_deref().map(|actual| actual.cmp(expected))
                    })
                };
                ordering.is_some_and(|ordering| match facet.op {
                    FacetOp::Lt(_) => ordering == Ordering::Less,
                    FacetOp::Lte(_) => ordering != Ordering::Greater,
                    FacetOp::Gt(_) => ordering == Ordering::Greater,
                    FacetOp::Gte(_) => ordering != Ordering::Less,
                    _ => false,
                })
            })
        }
        FacetOp::In(expected) => values.iter().any(|row| {
            expected.iter().any(|expected| {
                expected
                    .as_str()
                    .is_some_and(|value| row.value.as_deref() == Some(value))
                    || numeric(expected).is_some_and(|value| row.value_num == Some(value))
            })
        }),
        FacetOp::CompareFacet { op, other_key } => {
            let other = facet_rows(snapshot, id, other_key);
            values.iter().any(|left| {
                other.iter().any(|right| {
                    left.value_num
                        .zip(right.value_num)
                        .is_some_and(|(left, right)| match op {
                            CmpOp::Lt => left < right,
                            CmpOp::Lte => left <= right,
                            CmpOp::Gt => left > right,
                            CmpOp::Gte => left >= right,
                        })
                })
            })
        }
    }
}

fn query_capable(snapshot: &LogicalSnapshot, record: &PortableRecord) -> bool {
    let raw = facet_rows(snapshot, &record.row.id, "query")
        .first()
        .and_then(|row| row.value.as_deref());
    let inspection =
        if record.row.record_type == "Collection" && record.row.kind.as_deref() == Some("query") {
            crate::mcp::tools::querying::inspect_saved_record_query(raw)
        } else {
            crate::mcp::tools::querying::inspect_saved_query(raw)
        };
    // This fold is used only by the Postgres/Turso portable adapters. Saved
    // governed SQL v1 pins sqlite-local@1, so it is not a capability here.
    matches!(
        inspection,
        crate::mcp::tools::querying::SavedQueryInspection::Valid { .. }
    )
}

fn matches_filter(
    snapshot: &LogicalSnapshot,
    record: &PortableRecord,
    filter: &crate::query::pipeline::Filter,
    include_suggestions: bool,
    include_citations: bool,
) -> bool {
    let row = &record.row;
    if row.deleted_at.is_some()
        || (!filter.include_archived && record.archived)
        || (!filter.ids.is_empty() && !filter.ids.contains(&row.id))
        || (!filter.types.is_empty() && !filter.types.contains(&row.record_type))
        || (!filter.kinds.is_empty()
            && row
                .kind
                .as_ref()
                .is_none_or(|kind| !filter.kinds.contains(kind)))
        || filter
            .home_id
            .as_ref()
            .is_some_and(|home| row.home_id.as_ref() != Some(home))
        || !snapshot.lifecycle_interpreter.matches_filter(
            &row.record_type,
            row.kind.as_deref(),
            row.home_id.as_deref(),
            row.lifecycle.as_deref(),
            &filter.lifecycle,
        )
        || (!filter.maturity.is_empty()
            && row
                .maturity
                .as_ref()
                .is_none_or(|value| !filter.maturity.contains(value)))
        || filter
            .persistence
            .as_ref()
            .is_some_and(|value| &row.persistence != value)
        || filter
            .owner_id
            .as_ref()
            .is_some_and(|value| row.owner_id.as_ref() != Some(value))
        || filter
            .bears_shape
            .is_some_and(|expected| snapshot.shape_ids.contains(&row.id) != expected)
        || filter
            .has_query
            .is_some_and(|expected| query_capable(snapshot, record) != expected)
        || filter.name_contains.as_ref().is_some_and(|needle| {
            !row.name
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase())
        })
        || filter
            .updated_since
            .as_ref()
            .is_some_and(|floor| &row.updated_at < floor)
        || filter.last_activity_since.as_ref().is_some_and(|floor| {
            row.last_activity_at
                .as_ref()
                .is_none_or(|actual| actual < floor)
        })
        || filter.ancestor_id.as_ref().is_some_and(|root| {
            !is_descendant(
                snapshot,
                &row.id,
                root,
                filter.include_archived,
                include_suggestions,
                include_citations,
            )
        })
    {
        return false;
    }
    filter
        .facets
        .iter()
        .all(|facet| facet_matches(snapshot, &row.id, facet))
}

async fn hidden_family_for_kind<E: DomainStatementExecutor>(
    executor: &mut E,
    kind: &str,
) -> Result<Option<&'static str>> {
    let resolution = crate::meta::kind::resolve_with(executor, "Annotation", kind).await?;
    for (family, identity) in [
        (
            "suggestion",
            crate::generated::kinds::CoreKind::AnnotationSuggestion,
        ),
        (
            "citation",
            crate::generated::kinds::CoreKind::AnnotationCitation,
        ),
        (
            "comment",
            crate::generated::kinds::CoreKind::AnnotationComment,
        ),
    ] {
        if identity.matches(&resolution) {
            return Ok(Some(family));
        }
    }
    Ok(None)
}

async fn select_ids<E: DomainStatementExecutor>(
    executor: &mut E,
    snapshot: &LogicalSnapshot,
    tool: &str,
    steps: &[Step],
) -> Result<(Vec<String>, Vec<(String, i64)>)> {
    let mut resolved_steps = steps.to_vec();
    let mut allow_suggestions = false;
    let mut allow_citations = false;
    let mut allow_comments = false;
    for step in &mut resolved_steps {
        let Step::Filter(filter) = step else { continue };
        let mut families = HashSet::new();
        for kind in &filter.kinds {
            if let Some(family) = hidden_family_for_kind(executor, kind).await? {
                families.insert(family);
            }
        }
        for family in families {
            let ids = match family {
                "suggestion" => {
                    allow_suggestions = true;
                    &snapshot.suggestions
                }
                "citation" => {
                    allow_citations = true;
                    &snapshot.citations
                }
                "comment" => {
                    allow_comments = true;
                    &snapshot.comments
                }
                _ => continue,
            };
            for kind in ids.iter().filter_map(|id| {
                snapshot
                    .rows
                    .records
                    .get(id)
                    .and_then(|record| record.row.kind.clone())
            }) {
                if !filter.kinds.contains(&kind) {
                    filter.kinds.push(kind);
                }
            }
        }
    }
    if allow_comments {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "portable-domain",
            "query_record governed-comment validation",
        ));
    }
    let allowed_hidden = |id: &str| {
        (allow_suggestions && snapshot.suggestions.contains(id))
            || (allow_citations && snapshot.citations.contains(id))
    };
    let eligible = |id: &str| {
        snapshot.visible.contains(id)
            && (!snapshot.hidden.contains(id) || allowed_hidden(id))
            && !snapshot.comments.contains(id)
    };

    for filter in resolved_steps.iter().filter_map(|step| match step {
        Step::Filter(filter) => Some(filter),
        Step::Traverse(_) => None,
    }) {
        for selector in [
            filter.home_id.as_deref(),
            filter.ancestor_id.as_deref(),
            filter.owner_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !snapshot.visible.contains(selector) || snapshot.hidden.contains(selector) {
                return Err(Error::engine(format!(
                    "{tool}: record {selector} does not exist"
                )));
            }
        }
    }

    let mut current: Option<Vec<String>> = None;
    let mut lane_misses = Vec::new();
    for step in &resolved_steps {
        let entering = current.clone();
        let selected = match step {
            Step::Filter(filter) => {
                let candidates: Vec<String> = match current.take() {
                    Some(ids) => ids,
                    None => {
                        let mut ids = snapshot.rows.records.keys().cloned().collect::<Vec<_>>();
                        ids.sort();
                        ids
                    }
                };
                candidates
                    .into_iter()
                    .filter(|id| {
                        eligible(id)
                            && snapshot.rows.records.get(id).is_some_and(|record| {
                                matches_filter(
                                    snapshot,
                                    record,
                                    filter,
                                    allow_suggestions,
                                    allow_citations,
                                )
                            })
                    })
                    .collect::<Vec<_>>()
            }
            Step::Traverse(traverse) => {
                let ids = current.take().unwrap_or_default();
                let set = ids.iter().collect::<HashSet<_>>();
                let values = match traverse {
                    Traverse::Children => snapshot
                        .rows
                        .records
                        .values()
                        .filter(|record| {
                            record
                                .row
                                .home_id
                                .as_ref()
                                .is_some_and(|home| set.contains(home))
                        })
                        .map(|record| record.row.id.clone())
                        .collect(),
                    Traverse::Parents => ids
                        .iter()
                        .filter_map(|id| snapshot.rows.records.get(id)?.row.home_id.clone())
                        .collect(),
                    Traverse::Links {
                        relationship,
                        direction,
                    } => {
                        let mut out = Vec::new();
                        for link in &snapshot.rows.links {
                            if relationship
                                .as_ref()
                                .is_some_and(|expected| &link.relationship != expected)
                            {
                                continue;
                            }
                            if matches!(direction, Direction::Out | Direction::Both)
                                && set.contains(&link.source_id)
                            {
                                out.push(link.target_id.clone());
                            }
                            if matches!(direction, Direction::In | Direction::Both)
                                && set.contains(&link.target_id)
                            {
                                out.push(link.source_id.clone());
                            }
                        }
                        out
                    }
                };
                dedup(values)
                    .into_iter()
                    .filter(|id| eligible(id))
                    .collect()
            }
        };
        if selected.is_empty() && entering.as_ref().is_none_or(|ids| !ids.is_empty()) {
            if let Step::Filter(filter) = step {
                let numeric_keys = dedup(filter.facets.iter().filter_map(|facet| match facet.op {
                    FacetOp::Lt(ref value)
                    | FacetOp::Lte(ref value)
                    | FacetOp::Gt(ref value)
                    | FacetOp::Gte(ref value)
                        if value.is_number() =>
                    {
                        Some(facet.key.clone())
                    }
                    FacetOp::In(ref values) if values.iter().any(Value::is_number) => {
                        Some(facet.key.clone())
                    }
                    FacetOp::CompareFacet { .. } => Some(facet.key.clone()),
                    _ => None,
                }));
                let diagnostic_candidates = entering
                    .clone()
                    .unwrap_or_else(|| snapshot.rows.records.keys().cloned().collect());
                let mut diagnostic_filter = (**filter).clone();
                for facet in &mut diagnostic_filter.facets {
                    if matches!(
                        facet.op,
                        FacetOp::Lt(ref value)
                            | FacetOp::Lte(ref value)
                            | FacetOp::Gt(ref value)
                            | FacetOp::Gte(ref value)
                            if value.is_number()
                    ) || matches!(
                        facet.op,
                        FacetOp::In(ref values) if values.iter().any(Value::is_number)
                    ) || matches!(facet.op, FacetOp::CompareFacet { .. })
                    {
                        facet.op = FacetOp::Exists;
                    }
                }
                let diagnostic_candidates = diagnostic_candidates
                    .into_iter()
                    .filter(|id| {
                        eligible(id)
                            && snapshot.rows.records.get(id).is_some_and(|record| {
                                matches_filter(
                                    snapshot,
                                    record,
                                    &diagnostic_filter,
                                    allow_suggestions,
                                    allow_citations,
                                )
                            })
                    })
                    .collect::<Vec<_>>();
                for key in numeric_keys {
                    let misses = diagnostic_candidates
                        .iter()
                        .filter(|id| {
                            facet_rows(snapshot, id, &key)
                                .iter()
                                .any(|row| row.value_num.is_none())
                        })
                        .count() as i64;
                    if misses > 0 {
                        lane_misses.push((key, misses));
                    }
                }
            }
        }
        current = Some(selected);
        if current.as_ref().is_some_and(Vec::is_empty) {
            break;
        }
    }
    Ok((current.unwrap_or_default(), lane_misses))
}

fn facet_sort_value(
    snapshot: &LogicalSnapshot,
    id: &str,
    order: &FacetOrder,
) -> Option<FacetSortValue> {
    let row = facet_rows(snapshot, id, &order.key).into_iter().next()?;
    match order.lane {
        FacetOrderLane::Number => row.value_num.map(FacetSortValue::Number),
        FacetOrderLane::Text => row.value.clone().map(FacetSortValue::Text),
    }
}

enum FacetSortValue {
    Number(f64),
    Text(String),
}

fn compare_records(
    snapshot: &LogicalSnapshot,
    left: &str,
    right: &str,
    opts: &PipelineOptions,
) -> Ordering {
    let left_record = &snapshot.rows.records[left].row;
    let right_record = &snapshot.rows.records[right].row;
    let facet = opts.facet_order.as_ref().map_or(Ordering::Equal, |order| {
        let left = facet_sort_value(snapshot, left, order);
        let right = facet_sort_value(snapshot, right, order);
        let present = match (&left, &right) {
            (Some(FacetSortValue::Number(left)), Some(FacetSortValue::Number(right))) => {
                left.total_cmp(right)
            }
            (Some(FacetSortValue::Text(left)), Some(FacetSortValue::Text(right))) => {
                left.cmp(right)
            }
            (Some(_), None) => return Ordering::Less,
            (None, Some(_)) => return Ordering::Greater,
            (None, None) => Ordering::Equal,
            _ => Ordering::Equal,
        };
        match order.direction {
            FacetOrderDirection::Asc => present,
            FacetOrderDirection::Desc => present.reverse(),
        }
    });
    let secondary = match opts.order {
        Order::UpdatedDesc => right_record.updated_at.cmp(&left_record.updated_at),
        Order::CreatedDesc => right_record.created_at.cmp(&left_record.created_at),
        Order::LastActivityDesc => right_record
            .last_activity_at
            .cmp(&left_record.last_activity_at),
        Order::NameAsc => left_record.name.cmp(&right_record.name),
    };
    facet.then(secondary).then(left.cmp(right))
}

fn add_messages(
    payload: &mut Value,
    messages: Vec<(String, i64)>,
    facet_order: Option<&FacetOrder>,
) {
    if messages.is_empty() {
        return;
    }
    payload["messages"] = json!(messages
        .into_iter()
        .map(|(key, count)| {
            let guidance = if facet_order.is_some_and(|order| order.key == key) {
                "; they sort with missing values — use lane 'text' or store JSON numbers"
            } else {
                ""
            };
            format!("{count} records have `{key}` set but no numeric projection{guidance}")
        })
        .collect::<Vec<_>>());
}

pub(crate) async fn run_pipeline<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    tool: &str,
    steps: &[Step],
    count_by: Option<CountAxis>,
    opts: &PipelineOptions,
) -> Result<Value> {
    let snapshot = load_snapshot(executor, caller).await?;
    let (mut ids, mut messages) = select_ids(executor, &snapshot, tool, steps).await?;
    if let Some(axis) = count_by {
        let mut counts: BTreeMap<Option<String>, i64> = BTreeMap::new();
        for id in &ids {
            let record = &snapshot.rows.records[id];
            let key = match &axis {
                CountAxis::Type => Some(record.row.record_type.clone()),
                CountAxis::Kind => record.row.kind.clone(),
                CountAxis::Lifecycle => record.row.lifecycle.clone(),
                CountAxis::Maturity => record.row.maturity.clone(),
                CountAxis::Persistence => Some(record.row.persistence.clone()),
                CountAxis::FacetKey(key) => facet_rows(&snapshot, id, key)
                    .first()
                    .and_then(|row| row.value.clone()),
            };
            *counts.entry(key).or_default() += 1;
        }
        let mut buckets = counts.into_iter().collect::<Vec<_>>();
        buckets.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        let mut payload = json!({"shape":"counts","total":ids.len(),"buckets":buckets.into_iter().map(|(key,count)| json!({"key":key,"count":count})).collect::<Vec<_>>()});
        add_messages(&mut payload, messages, None);
        return Ok(payload);
    }
    ids.sort_by(|left, right| compare_records(&snapshot, left, right, opts));
    let total = ids.len() as i64;
    if let Some(order) = opts.facet_order.as_ref() {
        let misses = ids
            .iter()
            .filter(|id| {
                !facet_rows(&snapshot, id, &order.key).is_empty()
                    && facet_sort_value(&snapshot, id, order).is_none()
            })
            .count() as i64;
        if misses > 0 {
            messages.push((order.key.clone(), misses));
        }
    }
    let limit = opts.limit.min(500) as usize;
    let selected = ids
        .into_iter()
        .skip(opts.offset as usize)
        .take(limit)
        .collect::<Vec<_>>();
    let mut records = Vec::with_capacity(selected.len());
    for id in selected {
        let record = &snapshot.rows.records[&id];
        let mut row = record.row.clone();
        row.hydrate_lifecycle(&snapshot.lifecycle_interpreter);
        let mut value = serde_json::to_value(&row)?;
        value["body"] = json!(selected_body(executor, &id).await?);
        value["custody_boundary"] = json!(views_history::custody_boundary(
            &snapshot.rows.records,
            record
        ));
        value["containment_path_visible"] = json!(views_history::containment_path_visible(
            &snapshot.rows.records,
            &snapshot.visible,
            &id
        ));
        for key in ["home_id", "owner_id"] {
            if value
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|reference| !snapshot.visible.contains(reference))
            {
                value[key] = Value::Null;
            }
        }
        records.push(value);
    }
    let returned = records.len() as i64;
    let mut payload = json!({
        "shape":"records",
        "total":total,
        "records":records,
        "returned":returned,
        "has_more":opts.offset + returned < total,
        "offset":opts.offset,
    });
    add_messages(&mut payload, messages, opts.facet_order.as_ref());
    Ok(payload)
}

fn scaled_fold(values: &[f64], divisor: f64) -> f64 {
    let scale = values.iter().map(|value| value.abs()).fold(0.0, f64::max);
    if scale == 0.0 {
        return 0.0;
    }
    (values.iter().map(|value| value / scale).sum::<f64>() / divisor) * scale
}

fn aggregate_op_label(op: AggregateOp) -> &'static str {
    match op {
        AggregateOp::Count => "count",
        AggregateOp::Sum => "sum",
        AggregateOp::Avg => "avg",
        AggregateOp::Min => "min",
        AggregateOp::Max => "max",
    }
}

pub(crate) async fn run_aggregate<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    tool: &str,
    steps: &[Step],
    spec: &AggregateSpec,
) -> Result<Value> {
    let snapshot = load_snapshot(executor, caller).await?;
    let (ids, messages) = select_ids(executor, &snapshot, tool, steps).await?;
    let matched_records = ids.len() as i64;
    let (value, contributing_values, missing_values, non_numeric_values) = if spec.op
        == AggregateOp::Count
    {
        (json!(matched_records), matched_records, 0, 0)
    } else {
        let key = spec
            .facet_key
            .as_deref()
            .expect("validated numeric aggregate has key");
        let mut values = Vec::new();
        let mut present = 0_i64;
        let mut non_numeric = 0_i64;
        for id in &ids {
            let rows = facet_rows(&snapshot, id, key);
            if let Some(row) = rows.first() {
                present += 1;
                if let Some(value) = row.value_num {
                    if !value.is_finite() {
                        return Err(Error::engine(format!(
                            "{tool}: aggregate '{}' over facet '{key}' encountered a non-finite numeric value",
                            aggregate_op_label(spec.op)
                        )));
                    }
                    values.push((id.clone(), value));
                } else {
                    non_numeric += 1;
                }
            }
        }
        values.sort_by(|(left, _), (right, _)| left.cmp(right));
        let numbers = values.iter().map(|(_, value)| *value).collect::<Vec<_>>();
        let folded = if numbers.is_empty() {
            None
        } else {
            Some(match spec.op {
                AggregateOp::Sum => scaled_fold(&numbers, 1.0),
                AggregateOp::Avg => scaled_fold(&numbers, numbers.len() as f64),
                AggregateOp::Min => numbers.iter().copied().reduce(f64::min).unwrap(),
                AggregateOp::Max => numbers.iter().copied().reduce(f64::max).unwrap(),
                AggregateOp::Count => unreachable!(),
            })
        };
        let value = match folded {
            None => Value::Null,
            Some(value) if !value.is_finite() => {
                return Err(Error::engine(format!(
                    "{tool}: aggregate '{}' over facet '{key}' produced a non-finite result",
                    aggregate_op_label(spec.op)
                )))
            }
            Some(value) => Value::Number(
                serde_json::Number::from_f64(value)
                    .expect("a finite f64 always has a JSON number representation"),
            ),
        };
        (
            value,
            numbers.len() as i64,
            matched_records - present,
            non_numeric,
        )
    };
    let mut payload = json!({
        "shape":"aggregate",
        "op":spec.op,
        "facet_key":spec.facet_key,
        "value":value,
        "matched_records":matched_records,
        "contributing_values":contributing_values,
        "missing_values":missing_values,
        "non_numeric_values":non_numeric_values,
    });
    add_messages(&mut payload, messages, None);
    Ok(payload)
}

#[derive(Clone)]
struct ScanEvent {
    seq: i64,
    record_id: String,
    actor: Option<String>,
    run_key: Option<String>,
    created_at: String,
}

#[derive(Clone)]
struct ScanBinding {
    record_id: String,
    system: String,
    identifier: String,
}

fn integer(row: &NormalizedRow, field: &str) -> Result<i64> {
    match row.get(field) {
        Some(NormalizedValue::Integer(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "portable scan returned invalid '{field}'"
        ))),
    }
}

async fn scan_events<E: DomainStatementExecutor>(executor: &mut E) -> Result<Vec<ScanEvent>> {
    let query = views_history::statement(
        "content_events",
        &[
            "SELECT seq,record_id,actor,run_key,created_at FROM {{relation}} ORDER BY seq LIMIT ",
            "",
        ],
    )?;
    let rows = executor
        .fetch_all(
            &query,
            &[BindValue::Integer(MAX_RELATION_ROWS + 1)],
            &[
                ColumnSpec::required("seq", LogicalType::Integer),
                ColumnSpec::required("record_id", LogicalType::Text),
                ColumnSpec::nullable("actor", LogicalType::Text),
                ColumnSpec::nullable("run_key", LogicalType::Text),
                ColumnSpec::required("created_at", LogicalType::Text),
            ],
        )
        .await
        .map_err(views_history::storage_error)?;
    if rows.len() > MAX_RELATION_ROWS as usize {
        return Err(Error::engine(format!(
            "portable scan event set exceeds {MAX_RELATION_ROWS} rows"
        )));
    }
    rows.iter()
        .map(|row| {
            Ok(ScanEvent {
                seq: integer(row, "seq")?,
                record_id: views_history::text(row, "record_id")?,
                actor: views_history::optional_text(row, "actor")?,
                run_key: views_history::optional_text(row, "run_key")?,
                created_at: views_history::text(row, "created_at")?,
            })
        })
        .collect()
}

async fn scan_bindings<E: DomainStatementExecutor>(executor: &mut E) -> Result<Vec<ScanBinding>> {
    let query = views_history::statement(
        "bindings",
        &[
            "SELECT record_id,system,identifier FROM {{relation}} ORDER BY record_id,system,identifier LIMIT ",
            "",
        ],
    )?;
    let rows = executor
        .fetch_all(
            &query,
            &[BindValue::Integer(MAX_RELATION_ROWS + 1)],
            &[
                ColumnSpec::required("record_id", LogicalType::Text),
                ColumnSpec::required("system", LogicalType::Text),
                ColumnSpec::required("identifier", LogicalType::Text),
            ],
        )
        .await
        .map_err(views_history::storage_error)?;
    if rows.len() > MAX_RELATION_ROWS as usize {
        return Err(Error::engine(format!(
            "portable scan binding set exceeds {MAX_RELATION_ROWS} rows"
        )));
    }
    rows.iter()
        .map(|row| {
            Ok(ScanBinding {
                record_id: views_history::text(row, "record_id")?,
                system: views_history::text(row, "system")?,
                identifier: views_history::text(row, "identifier")?,
            })
        })
        .collect()
}

fn axis_json(mut samples: Vec<Value>, count: usize, corpus_size: usize) -> Value {
    samples.truncate(3);
    let quality = if count == 0 {
        "empty"
    } else if corpus_size > 0 && (count as f64) / (corpus_size as f64) >= 0.10 {
        "saturated"
    } else {
        "focused"
    };
    json!({"count":count,"samples":samples,"quality":quality})
}

fn scan_sample(snapshot: &LogicalSnapshot, record: &PortableRecord) -> Value {
    json!({
        "id": record.row.id,
        "type": record.row.record_type,
        "name": record.row.name,
        "lifecycle_interpretation": snapshot.lifecycle_interpreter.interpret(
            &record.row.record_type,
            record.row.kind.as_deref(),
            record.row.home_id.as_deref(),
            record.row.lifecycle.as_deref(),
        ),
    })
}

fn count_axis(snapshot: &LogicalSnapshot, ids: &[String], axis: CountAxis) -> Value {
    let mut counts: BTreeMap<Option<String>, i64> = BTreeMap::new();
    for id in ids {
        let record = &snapshot.rows.records[id];
        let key = match &axis {
            CountAxis::Type => Some(record.row.record_type.clone()),
            CountAxis::Kind => record.row.kind.clone(),
            CountAxis::Lifecycle => record.row.lifecycle.clone(),
            CountAxis::Maturity => record.row.maturity.clone(),
            CountAxis::Persistence => Some(record.row.persistence.clone()),
            CountAxis::FacetKey(key) => facet_rows(snapshot, id, key)
                .first()
                .and_then(|row| row.value.clone()),
        };
        *counts.entry(key).or_default() += 1;
    }
    let mut buckets = counts.into_iter().collect::<Vec<_>>();
    buckets.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    json!({"shape":"counts","total":ids.len(),"buckets":buckets.into_iter().map(|(key,count)| json!({"key":key,"count":count})).collect::<Vec<_>>()})
}

pub(crate) struct ScanOptions {
    pub(crate) scope: Option<String>,
    pub(crate) types: Vec<String>,
    pub(crate) recent_window_days: i64,
    pub(crate) high_degree_min: i64,
    pub(crate) include_archived: bool,
    pub(crate) authored_by: Option<String>,
}

pub(crate) async fn run_scan<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    options: ScanOptions,
) -> Result<Value> {
    let ScanOptions {
        scope,
        types,
        recent_window_days,
        high_degree_min,
        include_archived,
        authored_by,
    } = options;
    let snapshot = load_snapshot(executor, caller).await?;
    if let Some(root) = scope.as_deref() {
        if !snapshot.visible.contains(root)
            || !is_descendant(&snapshot, root, root, false, false, false)
        {
            return Err(Error::engine(format!(
                "scan: scope record {root} does not exist"
            )));
        }
    }
    let mut ids = snapshot
        .rows
        .records
        .values()
        .filter(|record| {
            record.row.deleted_at.is_none()
                && (include_archived || !record.archived)
                && snapshot.visible.contains(&record.row.id)
                && !snapshot.hidden.contains(&record.row.id)
                && (types.is_empty() || types.contains(&record.row.record_type))
                && scope.as_deref().is_none_or(|root| {
                    is_descendant(&snapshot, &record.row.id, root, false, false, false)
                })
        })
        .map(|record| record.row.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    let corpus = ids.iter().cloned().collect::<HashSet<_>>();
    let events = scan_events(executor).await?;
    let bindings = scan_bindings(executor).await?;

    let selector = authored_by.as_deref().unwrap_or(caller.credential());
    if !caller.is_host_owner() && authored_by.is_some() && selector != caller.credential() {
        return Err(Error::engine(
            "scan: authored_by may name only the current caller",
        ));
    }
    let authored_person = bindings
        .iter()
        .find(|binding| binding.system == "account" && binding.identifier == selector)
        .map(|binding| binding.record_id.clone());
    if authored_by.is_some() && authored_person.is_none() {
        return Err(Error::engine(
            "scan: 'authored_by' must be an account token present in this file",
        ));
    }
    let authored_aliases = authored_person.as_ref().map(|person| {
        bindings
            .iter()
            .filter(|binding| binding.system == "account" && &binding.record_id == person)
            .map(|binding| binding.identifier.as_str())
            .collect::<HashSet<_>>()
    });
    let authored = |event: &&ScanEvent| {
        event.actor.as_deref().is_some_and(|actor| {
            authored_aliases
                .as_ref()
                .map_or(actor == selector, |aliases| aliases.contains(actor))
        })
    };
    let mut latest_authored: HashMap<String, &ScanEvent> = HashMap::new();
    for event in events
        .iter()
        .filter(authored)
        .filter(|event| corpus.contains(&event.record_id))
    {
        latest_authored
            .entry(event.record_id.clone())
            .and_modify(|current| {
                if event.seq > current.seq {
                    *current = event;
                }
            })
            .or_insert(event);
    }
    let mut authored_rows = latest_authored.into_values().collect::<Vec<_>>();
    authored_rows.sort_by(|left, right| {
        right
            .seq
            .cmp(&left.seq)
            .then(left.record_id.cmp(&right.record_id))
    });
    let authored_samples = authored_rows
        .iter()
        .map(|event| {
            let record = &snapshot.rows.records[&event.record_id];
            let mut sample = scan_sample(&snapshot, record);
            sample["authored_at"] = json!(event.created_at);
            sample
        })
        .collect::<Vec<_>>();

    let cutoff = (chrono::Utc::now() - chrono::Duration::days(recent_window_days))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let mut recent = ids
        .iter()
        .filter_map(|id| {
            let record = &snapshot.rows.records[id];
            record
                .row
                .last_activity_at
                .as_ref()
                .filter(|at| *at >= &cutoff)
                .map(|at| (id, at))
        })
        .collect::<Vec<_>>();
    recent.sort_by(|(left_id, left_at), (right_id, right_at)| {
        right_at.cmp(left_at).then(left_id.cmp(right_id))
    });
    let recent_samples = recent
        .iter()
        .map(|(id, at)| {
            let record = &snapshot.rows.records[*id];
            let mut sample = scan_sample(&snapshot, record);
            sample["last_activity_at"] = json!(at);
            sample
        })
        .collect::<Vec<_>>();

    let mut degree = Vec::new();
    let mut containers = Vec::new();
    for id in &ids {
        let record = &snapshot.rows.records[id];
        let related = snapshot
            .rows
            .links
            .iter()
            .filter_map(|link| {
                if &link.source_id == id {
                    Some(&link.target_id)
                } else if &link.target_id == id {
                    Some(&link.source_id)
                } else {
                    None
                }
            })
            .filter(|other| snapshot.visible.contains(*other))
            .count() as i64;
        if related >= high_degree_min {
            let mut sample = scan_sample(&snapshot, record);
            sample["degree"] = json!(related);
            degree.push((related, sample));
        }
        let children = snapshot
            .rows
            .records
            .values()
            .filter(|child| {
                child.row.home_id.as_ref() == Some(id)
                    && child.row.deleted_at.is_none()
                    && snapshot.visible.contains(&child.row.id)
                    && !snapshot.hidden.contains(&child.row.id)
            })
            .count() as i64;
        if children >= 1 {
            let mut sample = scan_sample(&snapshot, record);
            sample["child_count"] = json!(children);
            containers.push((children, sample));
        }
    }
    let metric_order = |left: &(i64, Value), right: &(i64, Value)| {
        right
            .0
            .cmp(&left.0)
            .then(left.1["name"].as_str().cmp(&right.1["name"].as_str()))
            .then(left.1["id"].as_str().cmp(&right.1["id"].as_str()))
    };
    degree.sort_by(metric_order);
    containers.sort_by(metric_order);

    let mut provenance: BTreeMap<String, i64> = BTreeMap::new();
    for id in &ids {
        let genesis = events
            .iter()
            .filter(|event| &event.record_id == id)
            .min_by_key(|event| event.seq);
        let class = if genesis.is_some_and(|event| event.run_key.is_some()) {
            "agent"
        } else if bindings.iter().any(|binding| {
            &binding.record_id == id && !matches!(binding.system.as_str(), "account" | "email")
        }) {
            "ingested"
        } else if genesis
            .is_none_or(|event| event.actor.as_deref().is_none_or(|actor| actor == "local"))
        {
            "unknown"
        } else {
            let actor_person = genesis
                .and_then(|event| {
                    bindings.iter().find(|binding| {
                        binding.system == "account"
                            && event.actor.as_deref() == Some(binding.identifier.as_str())
                    })
                })
                .map(|binding| &binding.record_id);
            if actor_person
                == bindings
                    .iter()
                    .find(|binding| {
                        binding.system == "account" && binding.identifier == caller.credential()
                    })
                    .map(|binding| &binding.record_id)
            {
                "you"
            } else if actor_person.is_some_and(|person| {
                snapshot.rows.records.get(person).is_some_and(|record| {
                    record.row.record_type == "Entity"
                        && record.row.kind.as_deref() == Some("person")
                })
            }) {
                "other_account"
            } else {
                "unknown"
            }
        };
        *provenance.entry(class.into()).or_default() += 1;
    }

    let corpus_size = ids.len();
    let mut axes = serde_json::Map::new();
    axes.insert(
        "authored_by".into(),
        axis_json(authored_samples, authored_rows.len(), corpus_size),
    );
    axes.insert(
        "recent".into(),
        axis_json(recent_samples, recent.len(), corpus_size),
    );
    axes.insert(
        "high_degree".into(),
        axis_json(
            degree.iter().map(|(_, value)| value.clone()).collect(),
            degree.len(),
            corpus_size,
        ),
    );
    axes.insert(
        "containers".into(),
        axis_json(
            containers.iter().map(|(_, value)| value.clone()).collect(),
            containers.len(),
            corpus_size,
        ),
    );

    let mut appearances: HashMap<String, (String, String, Vec<String>)> = HashMap::new();
    for (axis, value) in &axes {
        for sample in value["samples"].as_array().into_iter().flatten() {
            let id = sample["id"].as_str().unwrap().to_string();
            appearances
                .entry(id)
                .or_insert_with(|| {
                    (
                        sample["type"].as_str().unwrap().into(),
                        sample["name"].as_str().unwrap().into(),
                        Vec::new(),
                    )
                })
                .2
                .push(axis.clone());
        }
    }
    let mut convergence = appearances
        .into_iter()
        .filter(|(_, (_, _, axes))| axes.len() >= 2)
        .map(|(id, (_, _, axes))| {
            let mut sample = scan_sample(&snapshot, &snapshot.rows.records[&id]);
            sample["axis_count"] = json!(axes.len());
            sample["axes"] = json!(axes);
            sample
        })
        .collect::<Vec<_>>();
    convergence.sort_by(|left, right| {
        right["axis_count"]
            .as_u64()
            .cmp(&left["axis_count"].as_u64())
            .then(left["name"].as_str().cmp(&right["name"].as_str()))
            .then(left["id"].as_str().cmp(&right["id"].as_str()))
    });

    Ok(json!({
        "corpus_size":corpus_size,
        "scope":scope,
        "census":{
            "by_type":count_axis(&snapshot,&ids,CountAxis::Type),
            "by_kind":count_axis(&snapshot,&ids,CountAxis::Kind),
            "by_lifecycle":count_axis(&snapshot,&ids,CountAxis::Lifecycle),
            "provenance":{"shape":"counts","total":corpus_size,"buckets":provenance.into_iter().map(|(key,count)| json!({"key":key,"count":count})).collect::<Vec<_>>()}
        },
        "axes":axes,
        "convergence":convergence,
        "thresholds":{"recent_window_days":recent_window_days,"recent_cutoff":cutoff,"high_degree_min":high_degree_min,"sample_limit":3,"saturation_threshold":0.10}
    }))
}
