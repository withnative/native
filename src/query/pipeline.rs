//! `query::pipeline` — the structured filter/traversal/count engine. Backs
//! tools 3 (`get_dashboard`), 16 (`query_record`) and 19 (`scan`).
//!
//! A pipeline is a sequence of typed steps folded over a working set of record
//! ids: `Filter` narrows (the first one seeds from the whole file), `Traverse`
//! replaces the set with link neighbours / children / parents. The terminal
//! shape is the records themselves (ordered, paged, with the pre-page total),
//! counts bucketed along one axis, or one scalar aggregate. Enum-per-step by design — the TS
//! reference leans on dynamic typing; this is the compile-time-feedback
//! rewrite, not a transliteration.
//!
//! Default visibility rule (see module docs on [`super`]): tombstoned records
//! never traverse or match; archived records are excluded from `Filter` unless
//! `include_archived`. Traversal itself does not archive-filter — a link to an
//! archived record is still a link; say `include_archived` on the next filter
//! or don't, per step. Suggestions, citations, and comments are different: an
//! explicit kind filter opts the whole pipeline into that hidden family only;
//! without its own opt-in, every filter and traversal keeps that family hidden.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use super::{record_from_row, tree, RecordRow, NOT_ARCHIVED, RECORD_COLUMNS};
use crate::db::Db;
use crate::error::Result;
use crate::generated::kinds::CoreKind;
use crate::query::lens::ReadLens;

use super::error::contract_violation;

/// SQLite's default variable cap is 999; stay under it when binding id sets.
const CHUNK: usize = 400;

const MAX_LIMIT: i64 = 500;

#[derive(Debug, Clone, Copy, Default)]
struct HiddenVisibility {
    suggestions: bool,
    citations: bool,
    comments: bool,
}

/// An ordered comparison between two facets on the same record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Lt,
    Lte,
    Gt,
    Gte,
}

/// The operation applied by a facet constraint.
#[derive(Debug, Clone, Default)]
pub enum FacetOp {
    /// The key is present at any value.
    #[default]
    Exists,
    /// Exact token equality/inequality. These are string-only by contract.
    Eq(Value),
    Ne(Value),
    /// Ordered comparisons. A JSON number selects `value_num`; a JSON string
    /// selects the stored TEXT value.
    Lt(Value),
    Lte(Value),
    Gt(Value),
    Gte(Value),
    /// Membership; each JSON scalar selects its own numeric or string lane.
    In(Vec<Value>),
    /// Numeric comparison with another facet on the same record.
    CompareFacet {
        op: CmpOp,
        other_key: String,
    },
}

/// A facet constraint: key present, with one optional operation.
#[derive(Debug, Clone, Default)]
pub struct FacetFilter {
    pub key: String,
    pub op: FacetOp,
}

/// One filter over records. All populated constraints AND together; a `Vec`
/// constraint ORs within itself (`types: [WorkItem, Outcome]` = either).
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub ids: Vec<String>,
    pub types: Vec<String>,
    pub kinds: Vec<String>,
    pub home_id: Option<String>,
    /// Restrict to the subtree rooted here (ancestor at any depth).
    pub ancestor_id: Option<String>,
    pub lifecycle: Vec<String>,
    pub maturity: Vec<String>,
    pub persistence: Option<String>,
    pub owner_id: Option<String>,
    /// Derived capability predicate: whether any schema row is anchored here.
    pub bears_shape: Option<bool>,
    /// Live schema membership hydrated by the lens-aware executor. The
    /// projection SQL never queries `schema_config` directly.
    #[doc(hidden)]
    pub shape_capability_ids: Option<HashSet<String>>,
    /// Derived capability predicate: whether the record carries a supported,
    /// structurally valid saved-query envelope. This is never a stored flag.
    pub has_query: Option<bool>,
    /// Valid saved-query bearers hydrated by the shared query executor before
    /// pipeline execution. Kept separate from `has_query` so pure validation
    /// never reads or executes stored queries.
    #[doc(hidden)]
    pub query_capability_ids: Option<HashSet<String>>,
    pub facets: Vec<FacetFilter>,
    /// Case-insensitive substring match on `name`.
    pub name_contains: Option<String>,
    /// ISO timestamp floors (inclusive).
    pub updated_since: Option<String>,
    pub last_activity_since: Option<String>,
    pub include_archived: bool,
}

/// Traversal direction over `links`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Out,
    In,
    Both,
}

/// One traversal step: replace the working set with its neighbours.
#[derive(Debug, Clone)]
pub enum Traverse {
    /// Follow `links` rows (optionally one relationship) outward, inward or both.
    Links {
        relationship: Option<String>,
        direction: Direction,
    },
    /// One containment level down.
    Children,
    /// One containment level up.
    Parents,
}

/// One pipeline step. (`Filter` is boxed for variant-size parity; build steps
/// with [`Step::filter`] / [`Step::traverse`].)
#[derive(Debug, Clone)]
pub enum Step {
    Filter(Box<Filter>),
    Traverse(Traverse),
}

impl Step {
    pub fn filter(filter: Filter) -> Step {
        Step::Filter(Box::new(filter))
    }

    pub fn traverse(traverse: Traverse) -> Step {
        Step::Traverse(traverse)
    }
}

/// The bucketing axis for a counting pipeline.
#[derive(Debug, Clone)]
pub enum CountAxis {
    Type,
    Kind,
    Lifecycle,
    Maturity,
    Persistence,
    /// Bucket by the values of one open facet key.
    FacetKey(String),
}

/// A scalar fold over the complete logical pipeline match set.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AggregateOp {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

impl AggregateOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Sum => "sum",
            Self::Avg => "avg",
            Self::Min => "min",
            Self::Max => "max",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AggregateSpec {
    pub op: AggregateOp,
    pub facet_key: Option<String>,
}

/// Scalar aggregate output. `value` is an integer for count, a JSON number for
/// populated numeric folds, and null for an empty numeric input.
#[derive(Debug, Clone, Serialize)]
pub struct AggregateOutput {
    pub shape: &'static str,
    pub op: AggregateOp,
    pub facet_key: Option<String>,
    pub value: Value,
    pub matched_records: i64,
    pub contributing_values: i64,
    pub missing_values: i64,
    pub non_numeric_values: i64,
}

/// Result ordering for a record-returning pipeline.
#[derive(Debug, Clone, Copy, Default)]
pub enum Order {
    #[default]
    UpdatedDesc,
    CreatedDesc,
    LastActivityDesc,
    NameAsc,
}

/// The stored facet projection used as the primary record order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FacetOrderLane {
    Number,
    Text,
}

/// Direction for the facet primary order. Missing values are kept last
/// independently of this direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FacetOrderDirection {
    Asc,
    Desc,
}

/// One facet primary order. The existing [`Order`] remains the secondary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetOrder {
    pub key: String,
    pub lane: FacetOrderLane,
    pub direction: FacetOrderDirection,
}

/// Paging + ordering for a record-returning pipeline.
#[derive(Debug, Clone)]
pub struct PipelineOptions {
    pub facet_order: Option<FacetOrder>,
    pub order: Order,
    pub limit: i64,
    pub offset: i64,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        PipelineOptions {
            facet_order: None,
            order: Order::default(),
            limit: 50,
            offset: 0,
        }
    }
}

/// One bucket of a counting pipeline. `key: None` is the NULL bucket (e.g.
/// records with no lifecycle).
#[derive(Debug, Serialize)]
pub struct CountBucket {
    pub key: Option<String>,
    pub count: i64,
}

/// Terminal output of a pipeline.
#[derive(Debug, Serialize)]
#[serde(tag = "shape", rename_all = "snake_case")]
pub enum PipelineOutput {
    Records {
        /// Total matches BEFORE limit/offset.
        total: i64,
        /// Digest of the complete authorized, ordered pre-page id sequence.
        #[serde(skip)]
        page_basis_digest: String,
        records: Vec<RecordRow>,
    },
    Counts {
        total: i64,
        buckets: Vec<CountBucket>,
    },
}

fn uses_numeric_lane(op: &FacetOp) -> bool {
    match op {
        FacetOp::Lt(value) | FacetOp::Lte(value) | FacetOp::Gt(value) | FacetOp::Gte(value) => {
            value.is_number()
        }
        FacetOp::In(values) => values.iter().any(Value::is_number),
        FacetOp::CompareFacet { .. } => true,
        FacetOp::Exists | FacetOp::Eq(_) | FacetOp::Ne(_) => false,
    }
}

/// Dedup while preserving first-seen order.
fn dedup(ids: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::with_capacity(ids.len());
    ids.into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect()
}

/// Run `sql_for_chunk` per CHUNK of `ids` (the chunk bound as trailing `?`s)
/// and concatenate the single-string-column results.
async fn per_chunk(
    pool: &sqlx::SqlitePool,
    ids: &[String],
    sql_for_chunk: impl Fn(&str) -> String,
    leading_binds: &[&str],
) -> Result<Vec<String>> {
    let mut conn = pool.acquire().await?;
    per_chunk_on(&mut conn, ids, sql_for_chunk, leading_binds).await
}

async fn per_chunk_on(
    conn: &mut SqliteConnection,
    ids: &[String],
    sql_for_chunk: impl Fn(&str) -> String,
    leading_binds: &[&str],
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for chunk in ids.chunks(CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = sql_for_chunk(&placeholders);
        let mut query = sqlx::query(&sql);
        for bind in leading_binds {
            query = query.bind(*bind);
        }
        for id in chunk {
            query = query.bind(id);
        }
        let rows = query.fetch_all(&mut *conn).await?;
        for row in rows {
            out.push(sqlx::Row::try_get::<String, _>(&row, 0)?);
        }
    }
    Ok(out)
}

/// Build the WHERE fragment + binds for a [`Filter`] (excluding the working-set
/// and ancestor constraints, which the caller applies).
fn facet_scalar(value: &Value, operator: &str) -> Result<(&'static str, String)> {
    match value {
        Value::Number(number) => Ok(("value_num", number.to_string())),
        Value::String(string) => Ok(("value", string.clone())),
        _ => Err(contract_violation(format!(
            "facet operator '{operator}' requires a JSON number or string"
        ))),
    }
}

fn exact_string(value: &Value, operator: &str) -> Result<String> {
    match value {
        Value::String(string) => Ok(string.clone()),
        Value::Number(_) => {
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
            Err(contract_violation(format!(
                "facet '{operator}' is string-exact and does not accept a JSON number; \
                 {guidance}"
            )))
        }
        _ => Err(contract_violation(format!(
            "facet operator '{operator}' requires a JSON string"
        ))),
    }
}

fn filter_sql(filter: &Filter, visibility: HiddenVisibility) -> Result<(String, Vec<String>)> {
    let mut clauses: Vec<String> = vec!["r.deleted_at IS NULL".into()];
    let mut binds: Vec<String> = Vec::new();
    let any_of =
        |column: &str, values: &[String], clauses: &mut Vec<String>, binds: &mut Vec<String>| {
            if !values.is_empty() {
                let placeholders = vec!["?"; values.len()].join(", ");
                clauses.push(format!("r.{column} IN ({placeholders})"));
                binds.extend(values.iter().cloned());
            }
        };
    any_of("id", &filter.ids, &mut clauses, &mut binds);
    any_of("type", &filter.types, &mut clauses, &mut binds);
    any_of("kind", &filter.kinds, &mut clauses, &mut binds);
    clauses.push(super::hidden_visibility_predicate(
        "r",
        visibility.suggestions,
        visibility.citations,
        visibility.comments,
    ));
    any_of("lifecycle", &filter.lifecycle, &mut clauses, &mut binds);
    any_of("maturity", &filter.maturity, &mut clauses, &mut binds);
    if let Some(home_id) = &filter.home_id {
        clauses.push("r.home_id = ?".into());
        binds.push(home_id.clone());
    }
    if let Some(persistence) = &filter.persistence {
        clauses.push("r.persistence = ?".into());
        binds.push(persistence.clone());
    }
    if let Some(owner_id) = &filter.owner_id {
        clauses.push("r.owner_id = ?".into());
        binds.push(owner_id.clone());
    }
    if let Some(bears_shape) = filter.bears_shape {
        if filter.shape_capability_ids.is_none() {
            clauses.push(format!(
                "{}EXISTS (SELECT 1 FROM schema_config sc WHERE sc.applies_to_collection_id = r.id)",
                if bears_shape { "" } else { "NOT " }
            ));
        }
    }
    if let Some(name) = &filter.name_contains {
        clauses.push("r.name LIKE ? ESCAPE '\\'".into());
        let escaped = name
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        binds.push(format!("%{escaped}%"));
    }
    if let Some(ts) = &filter.updated_since {
        clauses.push("r.updated_at >= ?".into());
        binds.push(ts.clone());
    }
    if let Some(ts) = &filter.last_activity_since {
        clauses.push("r.last_activity_at >= ?".into());
        binds.push(ts.clone());
    }
    for facet in &filter.facets {
        match &facet.op {
            FacetOp::Exists => {
                clauses.push(
                    "EXISTS (SELECT 1 FROM facet_values f \
                       WHERE f.record_id = r.id AND f.key = ?)"
                        .into(),
                );
                binds.push(facet.key.clone());
            }
            FacetOp::Eq(value) | FacetOp::Ne(value) => {
                let (operator, sql_operator) = if matches!(&facet.op, FacetOp::Eq(_)) {
                    ("eq", "=")
                } else {
                    ("ne", "!=")
                };
                let value = exact_string(value, operator)?;
                clauses.push(format!(
                    "EXISTS (SELECT 1 FROM facet_values f \
                         WHERE f.record_id = r.id AND f.key = ? AND f.value {sql_operator} ?)"
                ));
                binds.push(facet.key.clone());
                binds.push(value);
            }
            FacetOp::Lt(value) | FacetOp::Lte(value) | FacetOp::Gt(value) | FacetOp::Gte(value) => {
                let (operator, sql_operator) = match &facet.op {
                    FacetOp::Lt(_) => ("lt", "<"),
                    FacetOp::Lte(_) => ("lte", "<="),
                    FacetOp::Gt(_) => ("gt", ">"),
                    FacetOp::Gte(_) => ("gte", ">="),
                    _ => unreachable!(),
                };
                let (column, value) = facet_scalar(value, operator)?;
                clauses.push(format!(
                    "EXISTS (SELECT 1 FROM facet_values f \
                     WHERE f.record_id = r.id AND f.key = ? AND f.{column} {sql_operator} ?)"
                ));
                binds.push(facet.key.clone());
                binds.push(value);
            }
            FacetOp::In(values) => {
                let mut strings = Vec::new();
                let mut numbers = Vec::new();
                for value in values {
                    let (column, value) = facet_scalar(value, "in")?;
                    if column == "value" {
                        strings.push(value);
                    } else {
                        numbers.push(value);
                    }
                }
                let mut lane_clauses = Vec::new();
                if !strings.is_empty() {
                    lane_clauses.push(format!(
                        "f.value IN ({})",
                        vec!["?"; strings.len()].join(", ")
                    ));
                }
                if !numbers.is_empty() {
                    lane_clauses.push(format!(
                        "f.value_num IN ({})",
                        vec!["?"; numbers.len()].join(", ")
                    ));
                }
                let membership = if lane_clauses.is_empty() {
                    "0".into()
                } else {
                    format!("({})", lane_clauses.join(" OR "))
                };
                clauses.push(format!(
                    "EXISTS (SELECT 1 FROM facet_values f \
                     WHERE f.record_id = r.id AND f.key = ? AND {membership})"
                ));
                binds.push(facet.key.clone());
                binds.extend(strings);
                binds.extend(numbers);
            }
            FacetOp::CompareFacet { op, other_key } => {
                let sql_operator = match op {
                    CmpOp::Lt => "<",
                    CmpOp::Lte => "<=",
                    CmpOp::Gt => ">",
                    CmpOp::Gte => ">=",
                };
                clauses.push(format!(
                    "EXISTS (SELECT 1 FROM facet_values a \
                     JOIN facet_values b ON b.record_id = a.record_id \
                     WHERE a.record_id = r.id AND a.key = ? AND b.key = ? \
                       AND a.value_num IS NOT NULL AND b.value_num IS NOT NULL \
                       AND a.value_num {sql_operator} b.value_num)"
                ));
                binds.push(facet.key.clone());
                binds.push(other_key.clone());
            }
        }
    }
    if !filter.include_archived {
        clauses.push(NOT_ARCHIVED.into());
    }
    Ok((clauses.join(" AND "), binds))
}

/// Apply one filter: seed from the whole file when `current` is `None`,
/// intersect with the working set otherwise.
async fn apply_filter(
    pool: &sqlx::SqlitePool,
    current: Option<Vec<String>>,
    filter: &Filter,
    visibility: HiddenVisibility,
) -> Result<Vec<String>> {
    let mut conn = pool.acquire().await?;
    apply_filter_on(&mut conn, current, filter, visibility).await
}

async fn apply_filter_on(
    conn: &mut SqliteConnection,
    current: Option<Vec<String>>,
    filter: &Filter,
    visibility: HiddenVisibility,
) -> Result<Vec<String>> {
    let (where_sql, binds) = filter_sql(filter, visibility)?;
    let ancestor_set: Option<HashSet<String>> = match &filter.ancestor_id {
        Some(root) => Some(
            tree::subtree_ids_with_hidden_in(
                conn,
                root,
                visibility.suggestions,
                visibility.citations,
                filter.include_archived,
            )
            .await?
            .into_iter()
            .collect(),
        ),
        None => None,
    };
    let matched = match &current {
        None => {
            let sql = format!("SELECT r.id FROM records r WHERE {where_sql} ORDER BY r.rowid");
            let mut query = sqlx::query(&sql);
            for bind in &binds {
                query = query.bind(bind);
            }
            query
                .fetch_all(&mut *conn)
                .await?
                .iter()
                .map(|row| Ok(sqlx::Row::try_get::<String, _>(row, 0)?))
                .collect::<Result<Vec<_>>>()?
        }
        Some(ids) => {
            let bind_refs: Vec<&str> = binds.iter().map(String::as_str).collect();
            let hits = per_chunk_on(
                conn,
                ids,
                |placeholders| {
                    format!(
                        "SELECT r.id FROM records r WHERE {where_sql} AND r.id IN ({placeholders})"
                    )
                },
                &bind_refs,
            )
            .await?;
            let hit_set: HashSet<String> = hits.into_iter().collect();
            ids.iter()
                .filter(|id| hit_set.contains(*id))
                .cloned()
                .collect()
        }
    };
    let matched = match ancestor_set {
        Some(subtree) => matched
            .into_iter()
            .filter(|id| subtree.contains(id))
            .collect(),
        None => matched,
    };
    let matched = match (filter.bears_shape, &filter.shape_capability_ids) {
        (Some(expected), Some(capable)) => matched
            .into_iter()
            .filter(|id| capable.contains(id) == expected)
            .collect(),
        (None, _) | (Some(_), None) => matched,
    };
    match (filter.has_query, &filter.query_capability_ids) {
        (Some(expected), Some(capable)) => Ok(matched
            .into_iter()
            .filter(|id| capable.contains(id) == expected)
            .collect()),
        (Some(_), None) => Err(contract_violation(
            "pipeline has_query filter was not hydrated by the query executor",
        )),
        (None, _) => Ok(matched),
    }
}

/// Apply one traversal: the working set is replaced by its live neighbours.
async fn apply_traverse(
    pool: &sqlx::SqlitePool,
    current: &[String],
    traverse: &Traverse,
    visibility: HiddenVisibility,
) -> Result<Vec<String>> {
    let mut conn = pool.acquire().await?;
    apply_traverse_on(&mut conn, current, traverse, visibility).await
}

async fn apply_traverse_on(
    conn: &mut SqliteConnection,
    current: &[String],
    traverse: &Traverse,
    visibility: HiddenVisibility,
) -> Result<Vec<String>> {
    if current.is_empty() {
        return Ok(Vec::new());
    }
    let hidden_filter = format!(
        "AND {}",
        super::hidden_visibility_predicate(
            "r",
            visibility.suggestions,
            visibility.citations,
            visibility.comments,
        )
    );
    let live = format!("JOIN records r ON r.id = %COL% AND r.deleted_at IS NULL {hidden_filter}");
    let neighbours = match traverse {
        Traverse::Links {
            relationship,
            direction,
        } => {
            let mut out = Vec::new();
            let rel_clause = if relationship.is_some() {
                "AND l.relationship = ?"
            } else {
                ""
            };
            let rel_binds: Vec<&str> = relationship.iter().map(String::as_str).collect();
            if *direction == Direction::Out || *direction == Direction::Both {
                let join = live.replace("%COL%", "l.target_id");
                out.extend(
                    per_chunk_on(
                        conn,
                        current,
                        |p| {
                            format!(
                                "SELECT l.target_id FROM links l {join} \
                                 WHERE 1=1 {rel_clause} AND l.source_id IN ({p})"
                            )
                        },
                        &rel_binds,
                    )
                    .await?,
                );
            }
            if *direction == Direction::In || *direction == Direction::Both {
                let join = live.replace("%COL%", "l.source_id");
                out.extend(
                    per_chunk_on(
                        conn,
                        current,
                        |p| {
                            format!(
                                "SELECT l.source_id FROM links l {join} \
                                 WHERE 1=1 {rel_clause} AND l.target_id IN ({p})"
                            )
                        },
                        &rel_binds,
                    )
                    .await?,
                );
            }
            out
        }
        Traverse::Children => {
            per_chunk_on(
                conn,
                current,
                |p| {
                    format!(
                        "SELECT r.id FROM records r \
                         WHERE r.deleted_at IS NULL {hidden_filter} AND r.home_id IN ({p})"
                    )
                },
                &[],
            )
            .await?
        }
        Traverse::Parents => {
            per_chunk_on(
                conn,
                current,
                |p| {
                    format!(
                        "SELECT c.home_id FROM records c \
                         JOIN records r ON r.id = c.home_id AND r.deleted_at IS NULL \
                           {hidden_filter} \
                         WHERE c.home_id IS NOT NULL AND c.id IN ({p})"
                    )
                },
                &[],
            )
            .await?
        }
    };
    Ok(dedup(neighbours))
}

enum FacetSortValue {
    Number(f64),
    Text(String),
}

async fn facet_sort_values_on(
    conn: &mut SqliteConnection,
    ids: &[String],
    facet_order: &FacetOrder,
) -> Result<(HashMap<String, FacetSortValue>, i64)> {
    let mut values = HashMap::new();
    let mut numeric_lane_misses = 0;
    for chunk in ids.chunks(CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT record_id, value, value_num FROM facet_values \
             WHERE key = ? AND record_id IN ({placeholders})"
        );
        let mut query = sqlx::query(&sql).bind(&facet_order.key);
        for id in chunk {
            query = query.bind(id);
        }
        for row in query.fetch_all(&mut *conn).await? {
            let record_id: String = sqlx::Row::try_get(&row, "record_id")?;
            match facet_order.lane {
                FacetOrderLane::Number => {
                    let value: Option<f64> = sqlx::Row::try_get(&row, "value_num")?;
                    if let Some(value) = value {
                        values.insert(record_id, FacetSortValue::Number(value));
                    } else {
                        numeric_lane_misses += 1;
                    }
                }
                FacetOrderLane::Text => {
                    let value: Option<String> = sqlx::Row::try_get(&row, "value")?;
                    if let Some(value) = value {
                        values.insert(record_id, FacetSortValue::Text(value));
                    }
                }
            }
        }
    }
    Ok((values, numeric_lane_misses))
}

fn compare_secondary(a: &RecordRow, b: &RecordRow, order: Order) -> Ordering {
    match order {
        Order::UpdatedDesc => b.updated_at.cmp(&a.updated_at),
        Order::CreatedDesc => b.created_at.cmp(&a.created_at),
        Order::LastActivityDesc => b.last_activity_at.cmp(&a.last_activity_at),
        Order::NameAsc => a.name.cmp(&b.name),
    }
}

fn compare_facet_values(
    a: Option<&FacetSortValue>,
    b: Option<&FacetSortValue>,
    direction: FacetOrderDirection,
) -> Ordering {
    // Missing values (including numeric lane misses) are last in both
    // directions. Direction only reverses comparisons within the value lane.
    let present = match (a, b) {
        (Some(a), Some(b)) => match (a, b) {
            (FacetSortValue::Number(a), FacetSortValue::Number(b)) => a.total_cmp(b),
            (FacetSortValue::Text(a), FacetSortValue::Text(b)) => a.cmp(b),
            _ => unreachable!("facet sort values are decorated for one lane"),
        },
        (Some(_), None) => return Ordering::Less,
        (None, Some(_)) => return Ordering::Greater,
        (None, None) => return Ordering::Equal,
    };
    match direction {
        FacetOrderDirection::Asc => present,
        FacetOrderDirection::Desc => present.reverse(),
    }
}

async fn fetch_records(
    pool: &sqlx::SqlitePool,
    ids: &[String],
    opts: &PipelineOptions,
    lifecycle_interpreter: &super::lifecycle::LifecycleInterpreter,
) -> Result<(PipelineOutput, Option<(String, i64)>)> {
    let mut conn = pool.acquire().await?;
    fetch_records_on(&mut conn, ids, opts, lifecycle_interpreter).await
}

async fn fetch_records_on(
    conn: &mut SqliteConnection,
    ids: &[String],
    opts: &PipelineOptions,
    lifecycle_interpreter: &super::lifecycle::LifecycleInterpreter,
) -> Result<(PipelineOutput, Option<(String, i64)>)> {
    if opts.limit <= 0 || opts.offset < 0 {
        return Err(contract_violation(
            "pipeline limit must be positive and offset non-negative",
        ));
    }
    let limit = opts.limit.min(MAX_LIMIT);
    let order_sql = match opts.order {
        Order::UpdatedDesc => "r.updated_at DESC, r.id",
        Order::CreatedDesc => "r.created_at DESC, r.id",
        Order::LastActivityDesc => "r.last_activity_at DESC, r.id",
        Order::NameAsc => "r.name, r.id",
    };
    let mut rows = Vec::new();
    for chunk in ids.chunks(CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM records r WHERE r.id IN ({placeholders}) ORDER BY {order_sql}"
        );
        let mut query = sqlx::query(&sql);
        for id in chunk {
            query = query.bind(id);
        }
        for row in query.fetch_all(&mut *conn).await? {
            rows.push(record_from_row(&row)?);
        }
    }
    let (facet_values, order_lane_miss) = match &opts.facet_order {
        Some(facet_order) => {
            let (values, misses) = facet_sort_values_on(conn, ids, facet_order).await?;
            let diagnostic = (misses > 0).then(|| (facet_order.key.clone(), misses));
            (Some(values), diagnostic)
        }
        None => (None, None),
    };
    rows.sort_by(|a, b| {
        let facet_cmp = match (&opts.facet_order, &facet_values) {
            (Some(facet_order), Some(values)) => {
                compare_facet_values(values.get(&a.id), values.get(&b.id), facet_order.direction)
            }
            _ => Ordering::Equal,
        };
        facet_cmp
            .then_with(|| compare_secondary(a, b, opts.order))
            .then_with(|| a.id.cmp(&b.id))
    });
    let total = rows.len() as i64;
    let page_basis_digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(&rows.iter().map(|row| &row.id).collect::<Vec<_>>())
                .expect("record id sequence serializes"),
        ))
    );
    let mut records: Vec<RecordRow> = rows
        .into_iter()
        .skip(opts.offset as usize)
        .take(limit as usize)
        .collect();
    for record in &mut records {
        super::hydrate_communication_origin_on(conn, record).await?;
        super::hydrate_federation_provenance_on(conn, record).await?;
        record.hydrate_lifecycle(lifecycle_interpreter);
    }
    Ok((
        PipelineOutput::Records {
            total,
            page_basis_digest,
            records,
        },
        order_lane_miss,
    ))
}

async fn count_records(
    pool: &sqlx::SqlitePool,
    ids: &[String],
    axis: &CountAxis,
) -> Result<PipelineOutput> {
    let mut conn = pool.acquire().await?;
    count_records_on(&mut conn, ids, axis).await
}

async fn count_records_on(
    conn: &mut SqliteConnection,
    ids: &[String],
    axis: &CountAxis,
) -> Result<PipelineOutput> {
    use std::collections::BTreeMap;
    let mut buckets: BTreeMap<Option<String>, i64> = BTreeMap::new();
    let (select, leading): (String, Vec<&str>) = match axis {
        CountAxis::Type => (
            "SELECT r.type FROM records r WHERE r.id IN (%P%)".into(),
            vec![],
        ),
        CountAxis::Kind => (
            "SELECT r.kind FROM records r WHERE r.id IN (%P%)".into(),
            vec![],
        ),
        CountAxis::Lifecycle => (
            "SELECT r.lifecycle FROM records r WHERE r.id IN (%P%)".into(),
            vec![],
        ),
        CountAxis::Maturity => (
            "SELECT r.maturity FROM records r WHERE r.id IN (%P%)".into(),
            vec![],
        ),
        CountAxis::Persistence => (
            "SELECT r.persistence FROM records r WHERE r.id IN (%P%)".into(),
            vec![],
        ),
        CountAxis::FacetKey(key) => (
            "SELECT (SELECT f.value FROM facet_values f \
               WHERE f.record_id = r.id AND f.key = ?) \
             FROM records r WHERE r.id IN (%P%)"
                .into(),
            vec![key.as_str()],
        ),
    };
    for chunk in ids.chunks(CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = select.replace("%P%", &placeholders);
        let mut query = sqlx::query(&sql);
        for bind in &leading {
            query = query.bind(*bind);
        }
        for id in chunk {
            query = query.bind(id);
        }
        for row in query.fetch_all(&mut *conn).await? {
            let key: Option<String> = sqlx::Row::try_get(&row, 0)?;
            *buckets.entry(key).or_insert(0) += 1;
        }
    }
    let mut buckets: Vec<CountBucket> = buckets
        .into_iter()
        .map(|(key, count)| CountBucket { key, count })
        .collect();
    buckets.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
    Ok(PipelineOutput::Counts {
        total: ids.len() as i64,
        buckets,
    })
}

async fn aggregate_records(
    pool: &sqlx::SqlitePool,
    ids: &[String],
    spec: &AggregateSpec,
) -> Result<AggregateOutput> {
    let mut conn = pool.acquire().await?;
    aggregate_records_on(&mut conn, ids, spec).await
}

async fn aggregate_records_on(
    conn: &mut SqliteConnection,
    ids: &[String],
    spec: &AggregateSpec,
) -> Result<AggregateOutput> {
    let matched_records = ids.len() as i64;
    if spec.op == AggregateOp::Count {
        return Ok(AggregateOutput {
            shape: "aggregate",
            op: spec.op,
            facet_key: None,
            value: Value::from(matched_records),
            matched_records,
            contributing_values: matched_records,
            missing_values: 0,
            non_numeric_values: 0,
        });
    }
    let key = spec
        .facet_key
        .as_deref()
        .ok_or_else(|| contract_violation("numeric aggregate requires a facet key"))?;
    let mut values = Vec::new();
    let mut present = 0_i64;
    let mut non_numeric_values = 0_i64;
    for chunk in ids.chunks(CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT f.record_id, f.value_num FROM facet_values f \
             WHERE f.key = ? AND f.record_id IN ({placeholders})"
        );
        let mut query = sqlx::query(&sql).bind(key);
        for id in chunk {
            query = query.bind(id);
        }
        for row in query.fetch_all(&mut *conn).await? {
            present += 1;
            let record_id: String = sqlx::Row::try_get(&row, 0)?;
            match sqlx::Row::try_get::<Option<f64>, _>(&row, 1)? {
                Some(value) if value.is_finite() => values.push((record_id, value)),
                Some(_) => {
                    return Err(contract_violation(format!(
                        "aggregate '{}' over facet '{key}' encountered a non-finite numeric value",
                        spec.op.as_str()
                    )))
                }
                None => non_numeric_values += 1,
            }
        }
    }
    values.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    let contributing_values = values.len() as i64;
    let missing_values = matched_records - present;
    let value = if values.is_empty() {
        Value::Null
    } else {
        let ordered_values: Vec<f64> = values.iter().map(|(_, value)| *value).collect();
        let folded = match spec.op {
            AggregateOp::Sum => scaled_fold(&ordered_values, 1.0),
            AggregateOp::Avg => scaled_fold(&ordered_values, ordered_values.len() as f64),
            AggregateOp::Min => ordered_values
                .iter()
                .copied()
                .reduce(f64::min)
                .expect("non-empty"),
            AggregateOp::Max => ordered_values
                .iter()
                .copied()
                .reduce(f64::max)
                .expect("non-empty"),
            AggregateOp::Count => unreachable!("count returned above"),
        };
        if !folded.is_finite() {
            return Err(contract_violation(format!(
                "aggregate '{}' over facet '{key}' produced a non-finite result",
                spec.op.as_str()
            )));
        }
        Value::Number(
            serde_json::Number::from_f64(folded)
                .expect("a finite f64 always has a JSON number representation"),
        )
    };
    Ok(AggregateOutput {
        shape: "aggregate",
        op: spec.op,
        facet_key: Some(key.to_string()),
        value,
        matched_records,
        contributing_values,
        missing_values,
        non_numeric_values,
    })
}

/// Fold finite values without overflowing an intermediate sum. Scaling by the
/// largest magnitude keeps every summand in [-1, 1]. Dividing before restoring
/// the scale gives AVG the same property; SUM still reports a genuinely
/// unrepresentable final result.
fn scaled_fold(values: &[f64], divisor: f64) -> f64 {
    let scale = values.iter().map(|value| value.abs()).fold(0.0, f64::max);
    if scale == 0.0 {
        return 0.0;
    }
    let scaled_sum: f64 = values.iter().map(|value| value / scale).sum();
    (scaled_sum / divisor) * scale
}

/// Run a pipeline. `count_by: Some(axis)` makes the terminal shape counts;
/// otherwise records, ordered and paged per `opts`. An empty `steps` list is
/// rejected — say `Filter::default()` to mean "everything live".
pub async fn run(
    db: &Db,
    steps: &[Step],
    count_by: Option<CountAxis>,
    opts: &PipelineOptions,
) -> Result<PipelineOutput> {
    Ok(run_with_diagnostics(db, steps, count_by, opts).await?.0)
}

async fn numeric_lane_misses_for_filter(
    projection_pool: &sqlx::SqlitePool,
    authorization_pool: &sqlx::SqlitePool,
    current: Option<Vec<String>>,
    filter: &Filter,
    visibility: HiddenVisibility,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<(String, i64)>> {
    let numeric_keys: Vec<String> = dedup(
        filter
            .facets
            .iter()
            .filter(|facet| uses_numeric_lane(&facet.op))
            .map(|facet| facet.key.clone())
            .collect(),
    );
    if numeric_keys.is_empty() {
        return Ok(Vec::new());
    }

    let mut diagnostic_filter = filter.clone();
    for facet in &mut diagnostic_filter.facets {
        if uses_numeric_lane(&facet.op) {
            facet.op = FacetOp::Exists;
        }
    }
    let candidate_ids = authorize_ids(
        authorization_pool,
        apply_filter(projection_pool, current, &diagnostic_filter, visibility).await?,
        principal,
    )
    .await;
    let mut totals = Vec::new();
    for key in numeric_keys {
        let hits = per_chunk(
            projection_pool,
            &candidate_ids,
            |placeholders| {
                format!(
                    "SELECT r.id FROM records r \
                     JOIN facet_values f ON f.record_id = r.id \
                     WHERE f.key = ? AND f.value_num IS NULL \
                       AND r.id IN ({placeholders})"
                )
            },
            &[key.as_str()],
        )
        .await?;
        let count = hits.len() as i64;
        if count > 0 {
            totals.push((key, count));
        }
    }
    Ok(totals)
}

/// Run a pipeline and report numeric-lane misses. Filter diagnostics are
/// emitted only for the stage that actually empties the working set and reuse
/// the real set entering that stage. A numeric facet order reports misses
/// across the materialised terminal ID set it decorates.
pub async fn run_with_diagnostics(
    db: &Db,
    steps: &[Step],
    count_by: Option<CountAxis>,
    opts: &PipelineOptions,
) -> Result<(PipelineOutput, Vec<(String, i64)>)> {
    run_with_lens_diagnostics(&ReadLens::live(db), steps, count_by, opts).await
}

pub async fn run_with_lens_diagnostics(
    lens: &ReadLens<'_>,
    steps: &[Step],
    count_by: Option<CountAxis>,
    opts: &PipelineOptions,
) -> Result<(PipelineOutput, Vec<(String, i64)>)> {
    run_with_session(
        &mut SelectionSession::Lens {
            lens,
            principal: None,
        },
        steps,
        count_by,
        opts,
    )
    .await
}

/// Caller-relative pipeline terminal. Selection grammar stays shared; the
/// complete candidate set is capability-filtered before paging, counting or
/// aggregation so totals and offsets cannot disclose hidden rows.
pub async fn run_with_diagnostics_as(
    db: &Db,
    principal: crate::authorization::Principal<'_>,
    steps: &[Step],
    count_by: Option<CountAxis>,
    opts: &PipelineOptions,
) -> Result<(PipelineOutput, Vec<(String, i64)>)> {
    run_with_lens_diagnostics_as(&ReadLens::live(db), principal, steps, count_by, opts).await
}

/// Historical-aware caller-relative pipeline. Candidate content comes from
/// the lens projection, while capability checks always use its live tier.
pub async fn run_with_lens_diagnostics_as(
    lens: &ReadLens<'_>,
    principal: crate::authorization::Principal<'_>,
    steps: &[Step],
    count_by: Option<CountAxis>,
    opts: &PipelineOptions,
) -> Result<(PipelineOutput, Vec<(String, i64)>)> {
    run_with_session(
        &mut SelectionSession::Lens {
            lens,
            principal: Some(principal),
        },
        steps,
        count_by,
        opts,
    )
    .await
}

async fn authorize_ids(
    pool: &sqlx::SqlitePool,
    ids: Vec<String>,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Vec<String> {
    if principal.is_none() {
        return ids;
    }
    let Ok(mut snapshot) = pool.begin().await else {
        return Vec::new();
    };
    let authorized = authorize_ids_in(&mut snapshot, ids, principal).await;
    if snapshot.rollback().await.is_ok() {
        authorized
    } else {
        Vec::new()
    }
}

async fn authorize_ids_in(
    tx: &mut Transaction<'_, Sqlite>,
    ids: Vec<String>,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Vec<String> {
    let Some(principal) = principal else {
        return ids;
    };
    crate::authorization::ids_with_capability_preloaded_on(
        tx,
        principal,
        ids,
        crate::authorization::Capability::View,
        false,
    )
    .await
    .unwrap_or_default()
}

type LifecycleCandidate = (String, Option<String>, Option<String>, Option<String>);

async fn lifecycle_candidates(
    pool: &sqlx::SqlitePool,
    ids: &[String],
) -> Result<HashMap<String, LifecycleCandidate>> {
    let mut candidates = HashMap::with_capacity(ids.len());
    for chunk in ids.chunks(CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT id, type, kind, home_id, lifecycle FROM records WHERE id IN ({placeholders})"
        );
        let mut query = sqlx::query(&sql);
        for id in chunk {
            query = query.bind(id);
        }
        for row in query.fetch_all(pool).await? {
            candidates.insert(
                row.try_get("id")?,
                (
                    row.try_get("type")?,
                    row.try_get("kind")?,
                    row.try_get("home_id")?,
                    row.try_get("lifecycle")?,
                ),
            );
        }
    }
    Ok(candidates)
}

async fn lifecycle_candidates_in(
    tx: &mut Transaction<'_, Sqlite>,
    ids: &[String],
) -> Result<HashMap<String, LifecycleCandidate>> {
    let mut candidates = HashMap::with_capacity(ids.len());
    for chunk in ids.chunks(CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT id, type, kind, home_id, lifecycle FROM records WHERE id IN ({placeholders})"
        );
        let mut query = sqlx::query(&sql);
        for id in chunk {
            query = query.bind(id);
        }
        for row in query.fetch_all(&mut **tx).await? {
            candidates.insert(
                row.try_get("id")?,
                (
                    row.try_get("type")?,
                    row.try_get("kind")?,
                    row.try_get("home_id")?,
                    row.try_get("lifecycle")?,
                ),
            );
        }
    }
    Ok(candidates)
}

async fn numeric_lane_misses_for_filter_in(
    tx: &mut Transaction<'_, Sqlite>,
    current: Option<Vec<String>>,
    filter: &Filter,
    visibility: HiddenVisibility,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<(String, i64)>> {
    let numeric_keys: Vec<String> = dedup(
        filter
            .facets
            .iter()
            .filter(|facet| uses_numeric_lane(&facet.op))
            .map(|facet| facet.key.clone())
            .collect(),
    );
    if numeric_keys.is_empty() {
        return Ok(Vec::new());
    }
    let mut diagnostic_filter = filter.clone();
    for facet in &mut diagnostic_filter.facets {
        if uses_numeric_lane(&facet.op) {
            facet.op = FacetOp::Exists;
        }
    }
    let candidate_ids = apply_filter_on(tx, current, &diagnostic_filter, visibility).await?;
    let candidate_ids = authorize_ids_in(tx, candidate_ids, principal).await;
    let mut totals = Vec::new();
    for key in numeric_keys {
        let hits = per_chunk_on(
            tx,
            &candidate_ids,
            |placeholders| {
                format!(
                    "SELECT r.id FROM records r \
                     JOIN facet_values f ON f.record_id = r.id \
                     WHERE f.key = ? AND f.value_num IS NULL \
                       AND r.id IN ({placeholders})"
                )
            },
            &[key.as_str()],
        )
        .await?;
        let count = hits.len() as i64;
        if count > 0 {
            totals.push((key, count));
        }
    }
    Ok(totals)
}

enum SelectionSession<'a, 'db, 'principal> {
    Lens {
        lens: &'a ReadLens<'db>,
        principal: Option<crate::authorization::Principal<'principal>>,
    },
    Live {
        tx: &'a mut Transaction<'db, Sqlite>,
        principal: Option<crate::authorization::Principal<'principal>>,
    },
}

impl SelectionSession<'_, '_, '_> {
    async fn identity_tokens(&mut self, family: CoreKind) -> Result<Vec<String>> {
        match self {
            Self::Lens { lens, .. } => {
                crate::meta::kind::active_identity_tokens_in_pool(
                    lens.meta().snapshot_pool(),
                    family.record_type(),
                    family.value_id(),
                )
                .await
            }
            Self::Live { tx, .. } => {
                crate::meta::kind::active_identity_tokens_on(
                    tx,
                    family.record_type(),
                    family.value_id(),
                )
                .await
            }
        }
    }

    async fn historical_shape_ids(&mut self, steps: &[Step]) -> Result<Option<HashSet<String>>> {
        let Self::Lens { lens, .. } = self else {
            return Ok(None);
        };
        if lens.temporal().is_none()
            || !steps
                .iter()
                .any(|step| matches!(step, Step::Filter(filter) if filter.bears_shape.is_some()))
        {
            return Ok(None);
        }
        let rows = sqlx::query(
            "SELECT DISTINCT applies_to_collection_id FROM schema_config
              WHERE applies_to_collection_id IS NOT NULL",
        )
        .fetch_all(lens.meta().shared_pool())
        .await?;
        Ok(Some(
            rows.iter()
                .map(|row| row.try_get::<String, _>(0).map_err(Into::into))
                .collect::<Result<HashSet<_>>>()?,
        ))
    }

    async fn filter(
        &mut self,
        current: Option<Vec<String>>,
        filter: &Filter,
        visibility: HiddenVisibility,
    ) -> Result<Vec<String>> {
        match self {
            Self::Lens { lens, .. } => {
                apply_filter(
                    lens.projection().snapshot_pool(),
                    current,
                    filter,
                    visibility,
                )
                .await
            }
            Self::Live { tx, .. } => apply_filter_on(tx, current, filter, visibility).await,
        }
    }

    async fn traverse(
        &mut self,
        current: &[String],
        traverse: &Traverse,
        visibility: HiddenVisibility,
    ) -> Result<Vec<String>> {
        match self {
            Self::Lens { lens, .. } => {
                apply_traverse(
                    lens.projection().snapshot_pool(),
                    current,
                    traverse,
                    visibility,
                )
                .await
            }
            Self::Live { tx, .. } => apply_traverse_on(tx, current, traverse, visibility).await,
        }
    }

    async fn authorize(&mut self, ids: Vec<String>) -> Vec<String> {
        match self {
            Self::Lens { lens, principal } => {
                authorize_ids(lens.meta().snapshot_pool(), ids, *principal).await
            }
            Self::Live { tx, principal } => authorize_ids_in(tx, ids, *principal).await,
        }
    }

    /// Apply lifecycle tokens after ordinary candidate selection so aliases
    /// resolve inside each candidate's effective vocabulary rather than being
    /// expanded globally across unrelated lifecycle axes.
    async fn filter_lifecycle(
        &mut self,
        ids: Vec<String>,
        requested: &[String],
    ) -> Result<Vec<String>> {
        if requested.is_empty() {
            return Ok(ids);
        }
        match self {
            Self::Lens { lens, principal } => {
                let schema_rows = super::cascade::schema_config_rows_for_principal_in_pool(
                    lens.meta().snapshot_pool(),
                    *principal,
                )
                .await?;
                let interpreter = super::lifecycle::LifecycleInterpreter::load_from_pool(
                    lens.meta().snapshot_pool(),
                    schema_rows,
                )
                .await?;
                let mut candidates =
                    lifecycle_candidates(lens.projection().snapshot_pool(), &ids).await?;
                let mut matched = Vec::with_capacity(ids.len());
                for id in ids {
                    let Some((record_type, kind, home_id, lifecycle)) = candidates.remove(&id)
                    else {
                        continue;
                    };
                    if interpreter.matches_filter(
                        &record_type,
                        kind.as_deref(),
                        home_id.as_deref(),
                        lifecycle.as_deref(),
                        requested,
                    ) {
                        matched.push(id);
                    }
                }
                Ok(matched)
            }
            Self::Live { tx, principal } => {
                let schema_rows =
                    super::cascade::schema_config_rows_for_principal_on(tx, *principal).await?;
                let interpreter =
                    super::lifecycle::LifecycleInterpreter::load_from_connection(tx, schema_rows)
                        .await?;
                let mut candidates = lifecycle_candidates_in(tx, &ids).await?;
                let mut matched = Vec::with_capacity(ids.len());
                for id in ids {
                    let Some((record_type, kind, home_id, lifecycle)) = candidates.remove(&id)
                    else {
                        continue;
                    };
                    if interpreter.matches_filter(
                        &record_type,
                        kind.as_deref(),
                        home_id.as_deref(),
                        lifecycle.as_deref(),
                        requested,
                    ) {
                        matched.push(id);
                    }
                }
                Ok(matched)
            }
        }
    }

    /// Governed comment opt-in is not permission to surface corrupt imported
    /// rows. Keep ordinary records intact when a mixed pipeline reaches this
    /// seam, but validate every governed comment before it can participate in
    /// a later traversal or terminal result. Kind resolution stays alias-aware
    /// through the lens's live meta tier.
    async fn fail_closed_comments(
        &mut self,
        ids: Vec<String>,
        visibility: HiddenVisibility,
    ) -> Result<Vec<String>> {
        if !visibility.comments {
            return Ok(ids);
        }
        let mut valid = Vec::with_capacity(ids.len());
        for id in ids {
            let keep = match self {
                Self::Lens { lens, .. } => {
                    let row = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
                        .bind(&id)
                        .fetch_optional(lens.projection().snapshot_pool())
                        .await?;
                    let Some(row) = row else { continue };
                    let record_type: String = row.try_get("type")?;
                    let kind: Option<String> = row.try_get("kind")?;
                    !super::read::resolves_comment(lens, &record_type, kind.as_deref()).await?
                        || super::read::valid_comment_with_lens(lens, &id).await?
                }
                Self::Live { tx, .. } => {
                    let row = sqlx::query(
                        "SELECT type, kind, body, lifecycle, summary FROM records WHERE id = ?",
                    )
                    .bind(&id)
                    .fetch_optional(&mut ***tx)
                    .await?;
                    let Some(row) = row else { continue };
                    let record_type: String = row.try_get("type")?;
                    let kind: Option<String> = row.try_get("kind")?;
                    !crate::comments::is_governed_comment_on(tx, &record_type, kind.as_deref())
                        .await?
                        || super::read::valid_comment_live_in(tx, &id, &row).await?
                }
            };
            if keep {
                valid.push(id);
            }
        }
        Ok(valid)
    }

    async fn numeric_lane_misses(
        &mut self,
        current: Option<Vec<String>>,
        filter: &Filter,
        visibility: HiddenVisibility,
    ) -> Result<Vec<(String, i64)>> {
        match self {
            Self::Lens { lens, principal } => {
                numeric_lane_misses_for_filter(
                    lens.projection().snapshot_pool(),
                    lens.meta().snapshot_pool(),
                    current,
                    filter,
                    visibility,
                    *principal,
                )
                .await
            }
            Self::Live { tx, principal } => {
                numeric_lane_misses_for_filter_in(tx, current, filter, visibility, *principal).await
            }
        }
    }

    async fn terminal(
        &mut self,
        ids: &[String],
        count_by: Option<CountAxis>,
        opts: &PipelineOptions,
    ) -> Result<(PipelineOutput, Option<(String, i64)>)> {
        match (self, count_by) {
            (Self::Lens { lens, .. }, Some(axis)) => Ok((
                count_records(lens.projection().snapshot_pool(), ids, &axis).await?,
                None,
            )),
            (Self::Lens { lens, principal }, None) => {
                let schema_rows = super::cascade::schema_config_rows_for_principal_in_pool(
                    lens.meta().snapshot_pool(),
                    *principal,
                )
                .await?;
                let lifecycle_interpreter = super::lifecycle::LifecycleInterpreter::load_from_pool(
                    lens.meta().snapshot_pool(),
                    schema_rows,
                )
                .await?;
                fetch_records(
                    lens.projection().snapshot_pool(),
                    ids,
                    opts,
                    &lifecycle_interpreter,
                )
                .await
            }
            (Self::Live { tx, .. }, Some(axis)) => {
                Ok((count_records_on(tx, ids, &axis).await?, None))
            }
            (Self::Live { tx, principal }, None) => {
                let schema_rows =
                    super::cascade::schema_config_rows_for_principal_on(tx, *principal).await?;
                let lifecycle_interpreter =
                    super::lifecycle::LifecycleInterpreter::load_from_connection(tx, schema_rows)
                        .await?;
                fetch_records_on(tx, ids, opts, &lifecycle_interpreter).await
            }
        }
    }

    async fn aggregate(&mut self, ids: &[String], spec: &AggregateSpec) -> Result<AggregateOutput> {
        match self {
            Self::Lens { lens, .. } => {
                aggregate_records(lens.projection().snapshot_pool(), ids, spec).await
            }
            Self::Live { tx, .. } => aggregate_records_on(tx, ids, spec).await,
        }
    }
}

async fn select_ids_with_diagnostics_from(
    source: &mut SelectionSession<'_, '_, '_>,
    steps: &[Step],
) -> Result<(Vec<String>, Vec<(String, i64)>)> {
    if steps.is_empty() {
        return Err(contract_violation(
            "pipeline requires at least one step (use an empty filter to select all live records)",
        ));
    }
    let suggestion_tokens = source
        .identity_tokens(CoreKind::AnnotationSuggestion)
        .await?;
    let citation_tokens = source.identity_tokens(CoreKind::AnnotationCitation).await?;
    let comment_tokens = source.identity_tokens(CoreKind::AnnotationComment).await?;
    let shape_capability_ids = source.historical_shape_ids(steps).await?;
    let visibility = HiddenVisibility {
        suggestions: steps.iter().any(|step| {
            matches!(step, Step::Filter(filter) if filter.kinds.iter().any(|kind| suggestion_tokens.contains(kind)))
        }),
        citations: steps.iter().any(|step| {
            matches!(step, Step::Filter(filter) if filter.kinds.iter().any(|kind| citation_tokens.contains(kind)))
        }),
        comments: steps.iter().any(|step| {
            matches!(step, Step::Filter(filter) if filter.kinds.iter().any(|kind| comment_tokens.contains(kind)))
        }),
    };
    let mut current: Option<Vec<String>> = None;
    let mut lane_misses = Vec::new();
    for step in steps {
        current = Some(match step {
            Step::Filter(filter) => {
                let mut resolved_filter = filter.clone();
                let lifecycle_filter = std::mem::take(&mut resolved_filter.lifecycle);
                if filter.bears_shape.is_some() {
                    resolved_filter.shape_capability_ids = shape_capability_ids.clone();
                }
                for identity_tokens in [&suggestion_tokens, &citation_tokens, &comment_tokens] {
                    if filter
                        .kinds
                        .iter()
                        .any(|kind| identity_tokens.contains(kind))
                    {
                        for token in identity_tokens {
                            if !resolved_filter.kinds.contains(token) {
                                resolved_filter.kinds.push(token.clone());
                            }
                        }
                    }
                }
                let entering = current.clone();
                let matched = source.filter(current, &resolved_filter, visibility).await?;
                let matched = source.filter_lifecycle(matched, &lifecycle_filter).await?;
                let matched = source.authorize(matched).await;
                let matched = source.fail_closed_comments(matched, visibility).await?;
                if matched.is_empty() && entering.as_ref().is_none_or(|ids| !ids.is_empty()) {
                    lane_misses = source
                        .numeric_lane_misses(entering, &resolved_filter, visibility)
                        .await?;
                }
                matched
            }
            Step::Traverse(traverse) => {
                let Some(ids) = &current else {
                    return Err(contract_violation(
                        "pipeline cannot start with a traverse step — seed with a filter first",
                    ));
                };
                let matched = source.traverse(ids, traverse, visibility).await?;
                let matched = source.authorize(matched).await;
                source.fail_closed_comments(matched, visibility).await?
            }
        });
        if current.as_ref().is_some_and(Vec::is_empty) {
            break;
        }
    }
    Ok((current.unwrap_or_default(), lane_misses))
}

async fn run_with_session(
    source: &mut SelectionSession<'_, '_, '_>,
    steps: &[Step],
    count_by: Option<CountAxis>,
    opts: &PipelineOptions,
) -> Result<(PipelineOutput, Vec<(String, i64)>)> {
    if count_by.is_some() && opts.facet_order.is_some() {
        return Err(contract_violation(
            "pipeline facet order cannot be used with a count terminal",
        ));
    }
    let (ids, mut lane_misses) = select_ids_with_diagnostics_from(source, steps).await?;
    let (output, order_lane_miss) = source.terminal(&ids, count_by, opts).await?;
    if let Some((key, count)) = order_lane_miss {
        if let Some((_, existing)) = lane_misses.iter_mut().find(|(k, _)| *k == key) {
            *existing = (*existing).max(count);
        } else {
            lane_misses.push((key, count));
        }
    }
    Ok((output, lane_misses))
}

async fn run_aggregate_with_session(
    source: &mut SelectionSession<'_, '_, '_>,
    steps: &[Step],
    aggregate: &AggregateSpec,
) -> Result<(AggregateOutput, Vec<(String, i64)>)> {
    let (ids, lane_misses) = select_ids_with_diagnostics_from(source, steps).await?;
    Ok((source.aggregate(&ids, aggregate).await?, lane_misses))
}

async fn select_ids_with_diagnostics(
    lens: &ReadLens<'_>,
    steps: &[Step],
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<(Vec<String>, Vec<(String, i64)>)> {
    select_ids_with_diagnostics_from(&mut SelectionSession::Lens { lens, principal }, steps).await
}

/// Materialize the complete logical record-set plan without applying a record,
/// count, or aggregate terminal. Activity queries use this seam so subject
/// membership is never affected by record ordering or paging.
pub async fn select_ids_with_lens_as(
    lens: &ReadLens<'_>,
    principal: crate::authorization::Principal<'_>,
    steps: &[Step],
) -> Result<Vec<String>> {
    let (ids, _) = select_ids_with_diagnostics(lens, steps, Some(principal)).await?;
    Ok(ids)
}

/// Unfiltered compatibility form of [`select_ids_with_lens_as`]. Public MCP
/// paths always use the caller-relative variant.
pub async fn select_ids_with_lens(lens: &ReadLens<'_>, steps: &[Step]) -> Result<Vec<String>> {
    let (ids, _) = select_ids_with_diagnostics(lens, steps, None).await?;
    Ok(ids)
}

/// Run the same selection grammar as [`run_with_diagnostics`], then fold the
/// complete match set to one scalar. Paging and ordering do not participate.
pub async fn run_aggregate_with_diagnostics(
    db: &Db,
    steps: &[Step],
    aggregate: &AggregateSpec,
) -> Result<(AggregateOutput, Vec<(String, i64)>)> {
    run_aggregate_with_lens_diagnostics(&ReadLens::live(db), steps, aggregate).await
}

pub async fn run_aggregate_with_lens_diagnostics(
    lens: &ReadLens<'_>,
    steps: &[Step],
    aggregate: &AggregateSpec,
) -> Result<(AggregateOutput, Vec<(String, i64)>)> {
    run_aggregate_with_session(
        &mut SelectionSession::Lens {
            lens,
            principal: None,
        },
        steps,
        aggregate,
    )
    .await
}

pub async fn run_aggregate_with_diagnostics_as(
    db: &Db,
    principal: crate::authorization::Principal<'_>,
    steps: &[Step],
    aggregate: &AggregateSpec,
) -> Result<(AggregateOutput, Vec<(String, i64)>)> {
    run_aggregate_with_lens_diagnostics_as(&ReadLens::live(db), principal, steps, aggregate).await
}

pub async fn run_aggregate_with_lens_diagnostics_as(
    lens: &ReadLens<'_>,
    principal: crate::authorization::Principal<'_>,
    steps: &[Step],
    aggregate: &AggregateSpec,
) -> Result<(AggregateOutput, Vec<(String, i64)>)> {
    run_aggregate_with_session(
        &mut SelectionSession::Lens {
            lens,
            principal: Some(principal),
        },
        steps,
        aggregate,
    )
    .await
}

/// Live caller-relative pipeline on a caller-owned snapshot. Saved-query
/// expansion uses this form so selection, authorization, terminal paging and
/// returned rows cannot cross a concurrent commit boundary.
pub(crate) async fn run_with_diagnostics_in_as(
    tx: &mut Transaction<'_, Sqlite>,
    principal: crate::authorization::Principal<'_>,
    steps: &[Step],
    count_by: Option<CountAxis>,
    opts: &PipelineOptions,
) -> Result<(PipelineOutput, Vec<(String, i64)>)> {
    run_with_session(
        &mut SelectionSession::Live {
            tx,
            principal: Some(principal),
        },
        steps,
        count_by,
        opts,
    )
    .await
}

pub(crate) async fn run_aggregate_with_diagnostics_in_as(
    tx: &mut Transaction<'_, Sqlite>,
    principal: crate::authorization::Principal<'_>,
    steps: &[Step],
    aggregate: &AggregateSpec,
) -> Result<(AggregateOutput, Vec<(String, i64)>)> {
    run_aggregate_with_session(
        &mut SelectionSession::Live {
            tx,
            principal: Some(principal),
        },
        steps,
        aggregate,
    )
    .await
}

#[cfg(test)]
mod bulk_authorization_tests {
    use serde_json::json;

    use super::*;
    use crate::authorization::{AllowEntry, Capability, Principal};
    use crate::schema::ROOT_RECORD_ID;

    const ALLOWED: &str = "ba710000-0000-4000-8000-000000000001";
    const DENIED: &str = "ba710000-0000-4000-8000-000000000002";

    #[tokio::test]
    async fn pipeline_bulk_authorization_preserves_order_duplicates_and_denials() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        for (id, name) in [(ALLOWED, "allowed"), (DENIED, "denied")] {
            crate::store::create_record(
                &db,
                json!({"id":id,"type":"Document","kind":"note","name":name,"home_id":ROOT_RECORD_ID}),
            )
            .await
            .unwrap();
        }
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            ALLOWED,
            vec![AllowEntry::account("acct:pipeline", Capability::View)],
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(&db, "test:policy", DENIED, vec![])
            .await
            .unwrap();
        let input = [ALLOWED, DENIED, ALLOWED]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        let expected = vec![ALLOWED.to_string(), ALLOWED.to_string()];
        let principal = Principal::bound("acct:pipeline", true);

        let mut tx = db.write_pool().begin().await.unwrap();
        assert_eq!(
            authorize_ids_in(&mut tx, input.clone(), Some(principal)).await,
            expected
        );
        tx.rollback().await.unwrap();
        assert_eq!(
            authorize_ids(db.write_pool(), input, Some(principal)).await,
            expected
        );
        db.close().await;
    }
}
