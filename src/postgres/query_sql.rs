//! PostgreSQL-native admission and execution for caller-supplied `query_sql`.
//!
//! The raw PostgreSQL protobuf is serialized and walked recursively because
//! `pg_query::protobuf::nodes()` is explicitly non-exhaustive. The exact crate
//! version is pinned: every serialized node is visited, unknown variants fail
//! closed, and relation resolution is checked with lexical CTE scopes.

use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use futures::TryStreamExt;
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use sqlx::postgres::{PgArguments, PgRow, PgTypeInfo};
use sqlx::types::{BigDecimal, Json};
use sqlx::{Acquire, Arguments, Column, Executor, Row, Statement, TypeInfo, ValueRef};
use tokio::time::Instant;

use super::PostgresDb;
use crate::query::sql_contract::{
    self, QuerySqlErrorCategory, QuerySqlParameter, QuerySqlRequest, QuerySqlResult,
    MAX_CELL_ENCODED_BYTES, MAX_COLUMNS, MAX_RESULT_ENCODED_BYTES, MAX_ROWS,
};
use crate::query::QueryPrincipal;
use crate::{Error, Result};

const SAFE_FUNCTIONS: &[&str] = &[
    "abs",
    "avg",
    "ceil",
    "ceiling",
    "char_length",
    "count",
    "cume_dist",
    "dense_rank",
    "floor",
    "greatest",
    "least",
    "length",
    "lower",
    "max",
    "min",
    "ntile",
    "nullif",
    "octet_length",
    "percent_rank",
    "rank",
    "round",
    "row_number",
    "sum",
    "upper",
];

const SAFE_TYPES: &[&str] = &[
    "bool",
    "boolean",
    "int2",
    "smallint",
    "int4",
    "integer",
    "int8",
    "bigint",
    "float4",
    "real",
    "float8",
    "double precision",
    "numeric",
    "decimal",
    "text",
    "varchar",
    "character varying",
    "bpchar",
    "character",
    "bytea",
    "json",
    "jsonb",
    "timestamptz",
];

const SAFE_OPERATORS: &[&str] = &[
    "+", "-", "*", "/", "%", "=", "<>", "!=", "<", ">", "<=", ">=", "~~", "~~*", "!~~", "!~~*",
];

const SAFE_NODE_VARIANTS: &[&str] = &[
    "Alias",
    "RangeVar",
    "JoinExpr",
    "TypeName",
    "ColumnRef",
    "ParamRef",
    "AExpr",
    "TypeCast",
    "FuncCall",
    "AStar",
    "ResTarget",
    "SortBy",
    "WindowDef",
    "RangeSubselect",
    "WithClause",
    "CommonTableExpr",
    "SelectStmt",
    "Integer",
    "Float",
    "Boolean",
    "String",
    "List",
    "AConst",
    "BoolExpr",
    "NullTest",
    "BooleanTest",
    "CaseExpr",
    "CaseWhen",
    "CaseTestExpr",
    "CoalesceExpr",
    "MinMaxExpr",
    "SubLink",
    "RowExpr",
    "ArrayExpr",
    "AArrayExpr",
    "GroupingSet",
];

fn reject(category: QuerySqlErrorCategory, detail: impl AsRef<str>) -> Error {
    sql_contract::categorized_error(category, detail)
}

fn object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| {
        reject(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("malformed PostgreSQL AST at {context}"),
        )
    })
}

fn node_variant(value: &Value) -> Option<(&str, &Value)> {
    let wrapper = value.as_object()?;
    let oneof = wrapper.get("node")?.as_object()?;
    (oneof.len() == 1)
        .then(|| {
            oneof
                .iter()
                .next()
                .map(|(name, value)| (name.as_str(), value))
        })
        .flatten()
}

fn oneof_variant(value: &Value) -> Option<(&str, &Value)> {
    let object = value.as_object()?;
    (object.len() == 1)
        .then(|| {
            object
                .iter()
                .next()
                .map(|(name, value)| (name.as_str(), value))
        })
        .flatten()
}

fn node_strings(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| {
            reject(
                QuerySqlErrorCategory::UnsafeStatement,
                "malformed name list",
            )
        })?
        .iter()
        .map(|node| {
            let (variant, data) = node_variant(node).ok_or_else(|| {
                reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "malformed name component",
                )
            })?;
            if variant != "String" {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "non-string name component",
                ));
            }
            object(data, "String")?
                .get("sval")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    reject(
                        QuerySqlErrorCategory::UnsafeStatement,
                        "empty name component",
                    )
                })
        })
        .collect()
}

fn validate_variant(name: &str, data: &Value, parameters: &mut HashSet<usize>) -> Result<()> {
    if !SAFE_NODE_VARIANTS.contains(&name) {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("PostgreSQL AST node {name} is outside the closed allowlist"),
        ));
    }
    let fields = object(data, name)?;
    let expected_fields: &[&str] = match name {
        "Integer" => &["ival"],
        "Float" => &["fval"],
        "Boolean" => &["boolval"],
        "String" => &["sval"],
        "List" => &["items"],
        "AConst" => &["isnull", "location", "val"],
        "Alias" => &["aliasname", "colnames"],
        "RangeVar" => &[
            "catalogname",
            "schemaname",
            "relname",
            "inh",
            "relpersistence",
            "alias",
            "location",
        ],
        "BoolExpr" => &["xpr", "boolop", "args", "location"],
        "SubLink" => &[
            "xpr",
            "sub_link_type",
            "sub_link_id",
            "testexpr",
            "oper_name",
            "subselect",
            "location",
        ],
        "CaseExpr" => &[
            "xpr",
            "casetype",
            "casecollid",
            "arg",
            "args",
            "defresult",
            "location",
        ],
        "CaseWhen" => &["xpr", "expr", "result", "location"],
        "CaseTestExpr" => &["xpr", "type_id", "type_mod", "collation"],
        "ArrayExpr" => &[
            "xpr",
            "array_typeid",
            "array_collid",
            "element_typeid",
            "elements",
            "multidims",
            "location",
        ],
        "AArrayExpr" => &["elements", "location"],
        "RowExpr" => &[
            "xpr",
            "args",
            "row_typeid",
            "row_format",
            "colnames",
            "location",
        ],
        "CoalesceExpr" => &["xpr", "coalescetype", "coalescecollid", "args", "location"],
        "MinMaxExpr" => &[
            "xpr",
            "minmaxtype",
            "minmaxcollid",
            "inputcollid",
            "op",
            "args",
            "location",
        ],
        "NullTest" => &["xpr", "arg", "nulltesttype", "argisrow", "location"],
        "BooleanTest" => &["xpr", "arg", "booltesttype", "location"],
        "JoinExpr" => &[
            "jointype",
            "is_natural",
            "larg",
            "rarg",
            "using_clause",
            "join_using_alias",
            "quals",
            "alias",
            "rtindex",
        ],
        "TypeName" => &[
            "names",
            "type_oid",
            "setof",
            "pct_type",
            "typmods",
            "typemod",
            "array_bounds",
            "location",
        ],
        "ColumnRef" => &["fields", "location"],
        "ParamRef" => &["number", "location"],
        "AExpr" => &["kind", "name", "lexpr", "rexpr", "location"],
        "TypeCast" => &["arg", "type_name", "location"],
        "FuncCall" => &[
            "funcname",
            "args",
            "agg_order",
            "agg_filter",
            "over",
            "agg_within_group",
            "agg_star",
            "agg_distinct",
            "func_variadic",
            "funcformat",
            "location",
        ],
        "AStar" => &[],
        "ResTarget" => &["name", "indirection", "val", "location"],
        "SortBy" => &["node", "sortby_dir", "sortby_nulls", "use_op", "location"],
        "WindowDef" => &[
            "name",
            "refname",
            "partition_clause",
            "order_clause",
            "frame_options",
            "start_offset",
            "end_offset",
            "location",
        ],
        "RangeSubselect" => &["lateral", "subquery", "alias"],
        "GroupingSet" => &["kind", "content", "location"],
        "WithClause" => &["ctes", "recursive", "location"],
        "CommonTableExpr" => &[
            "ctename",
            "aliascolnames",
            "ctematerialized",
            "ctequery",
            "search_clause",
            "cycle_clause",
            "location",
            "cterecursive",
            "cterefcount",
            "ctecolnames",
            "ctecoltypes",
            "ctecoltypmods",
            "ctecolcollations",
        ],
        "SelectStmt" => &[
            "distinct_clause",
            "into_clause",
            "target_list",
            "from_clause",
            "where_clause",
            "group_clause",
            "group_distinct",
            "having_clause",
            "window_clause",
            "values_lists",
            "sort_clause",
            "limit_offset",
            "limit_count",
            "limit_option",
            "locking_clause",
            "with_clause",
            "op",
            "all",
            "larg",
            "rarg",
        ],
        _ => unreachable!("closed node allowlist and field allowlist must remain exhaustive"),
    };
    if fields.len() != expected_fields.len()
        || fields
            .keys()
            .any(|field| !expected_fields.contains(&field.as_str()))
    {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("unknown {name} field in pinned PostgreSQL AST"),
        ));
    }
    match name {
        "FuncCall" => {
            let names = node_strings(fields.get("funcname").unwrap_or(&Value::Null))?;
            if names.len() != 1
                || !SAFE_FUNCTIONS
                    .iter()
                    .any(|safe| names[0].eq_ignore_ascii_case(safe))
            {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "function is outside the pure function allowlist",
                ));
            }
            if fields
                .get("func_variadic")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "variadic function calls are prohibited",
                ));
            }
        }
        "TypeName" => validate_type_name(fields)?,
        "TypeCast" => {
            let type_name = fields
                .get("type_name")
                .filter(|value| !value.is_null())
                .ok_or_else(|| {
                    reject(
                        QuerySqlErrorCategory::SyntaxOrType,
                        "cast has no target type",
                    )
                })?;
            validate_type_name(object(type_name, "TypeCast.type_name")?)?;
        }
        "AExpr" => {
            let names = node_strings(fields.get("name").unwrap_or(&Value::Null))?;
            if !names.is_empty()
                && (names.len() != 1 || !SAFE_OPERATORS.contains(&names[0].as_str()))
            {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "operator is outside the closed operator allowlist",
                ));
            }
        }
        "SortBy" => {
            let names = node_strings(fields.get("use_op").unwrap_or(&Value::Null))?;
            if !names.is_empty()
                && (names.len() != 1 || !SAFE_OPERATORS.contains(&names[0].as_str()))
            {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "sort operator is outside the closed operator allowlist",
                ));
            }
        }
        "SubLink" => {
            let names = node_strings(fields.get("oper_name").unwrap_or(&Value::Null))?;
            if !names.is_empty()
                && (names.len() != 1 || !SAFE_OPERATORS.contains(&names[0].as_str()))
            {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "sublink operator is outside the closed operator allowlist",
                ));
            }
        }
        "ParamRef" => {
            let number = fields.get("number").and_then(Value::as_i64).unwrap_or(0);
            if number <= 0 {
                return Err(reject(
                    QuerySqlErrorCategory::InvalidArguments,
                    "parameter positions must be positive",
                ));
            }
            parameters.insert(number as usize);
        }
        "SelectStmt" => {
            validate_select_fields(fields)?;
            for field in ["larg", "rarg"] {
                if let Some(nested) = fields.get(field).filter(|value| !value.is_null()) {
                    let nested = object(nested, "nested SelectStmt")?;
                    validate_select_fields(nested)?;
                }
            }
        }
        "WithClause"
            if fields
                .get("recursive")
                .and_then(Value::as_bool)
                .unwrap_or(false) =>
        {
            return Err(reject(
                QuerySqlErrorCategory::UnsafeStatement,
                "recursive CTEs are prohibited",
            ));
        }
        "CommonTableExpr"
            if fields
                .get("search_clause")
                .is_some_and(|value| !value.is_null())
                || fields
                    .get("cycle_clause")
                    .is_some_and(|value| !value.is_null())
                || fields
                    .get("cterecursive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false) =>
        {
            return Err(reject(
                QuerySqlErrorCategory::UnsafeStatement,
                "recursive SEARCH/CYCLE CTEs are prohibited",
            ));
        }
        _ => {}
    }
    for value in fields.values() {
        walk_ast(value, parameters)?;
    }
    Ok(())
}

fn validate_select_fields(fields: &Map<String, Value>) -> Result<()> {
    if fields
        .get("into_clause")
        .is_some_and(|value| !value.is_null())
        || fields
            .get("locking_clause")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty())
    {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            "SELECT INTO and row locking are prohibited",
        ));
    }
    // These fields are expression-bearing and are deliberately enumerated so
    // additions to the pinned protobuf cannot be silently forgotten.
    const FIELDS: &[&str] = &[
        "distinct_clause",
        "into_clause",
        "target_list",
        "from_clause",
        "where_clause",
        "group_clause",
        "group_distinct",
        "having_clause",
        "window_clause",
        "values_lists",
        "sort_clause",
        "limit_offset",
        "limit_count",
        "limit_option",
        "locking_clause",
        "with_clause",
        "op",
        "all",
        "larg",
        "rarg",
    ];
    if fields.len() != FIELDS.len() || fields.keys().any(|field| !FIELDS.contains(&field.as_str()))
    {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            "unknown SelectStmt field in pinned PostgreSQL AST",
        ));
    }
    Ok(())
}

fn validate_type_name(fields: &Map<String, Value>) -> Result<()> {
    if fields
        .get("setof")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || fields
            .get("pct_type")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || fields
            .get("array_bounds")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty())
        || fields
            .get("typmods")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty())
    {
        return Err(reject(
            QuerySqlErrorCategory::SyntaxOrType,
            "set, array, percent, and typmod casts are prohibited",
        ));
    }
    let names = node_strings(fields.get("names").unwrap_or(&Value::Null))?;
    let rendered = names.join(" ");
    if names.is_empty()
        || names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("pg_catalog"))
        || !SAFE_TYPES
            .iter()
            .any(|safe| rendered.eq_ignore_ascii_case(safe))
    {
        return Err(reject(
            QuerySqlErrorCategory::SyntaxOrType,
            "cast target is outside the closed result type set",
        ));
    }
    Ok(())
}

fn walk_ast(value: &Value, parameters: &mut HashSet<usize>) -> Result<()> {
    if let Some((name, data)) = node_variant(value) {
        return validate_variant(name, data, parameters);
    }
    if let Some((name, data)) = oneof_variant(value) {
        if ["Ival", "Fval", "Boolval", "Sval"].contains(&name) {
            return walk_ast(data, parameters);
        }
        if name.chars().next().is_some_and(char::is_uppercase) {
            if SAFE_NODE_VARIANTS.contains(&name) {
                return validate_variant(name, data, parameters);
            }
            return Err(reject(
                QuerySqlErrorCategory::UnsafeStatement,
                format!("unknown PostgreSQL AST variant {name}"),
            ));
        }
    }
    match value {
        Value::Array(values) => {
            for value in values {
                walk_ast(value, parameters)?;
            }
        }
        Value::Object(fields) => {
            for value in fields.values() {
                walk_ast(value, parameters)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn relation_in_scope(name: &str, scopes: &[HashSet<String>]) -> bool {
    sql_contract::LOGICAL_RELATIONS.iter().any(|relation| {
        relation.name == name
            && relation
                .profiles
                .contains(&sql_contract::QuerySqlProfile::PostgresServer.contract().id)
    }) || scopes.iter().rev().any(|scope| scope.contains(name))
}

fn walk_scopes(value: &Value, scopes: &[HashSet<String>]) -> Result<()> {
    if let Some((name, data)) = node_variant(value) {
        if name == "SelectStmt" {
            return validate_select_scope(object(data, "SelectStmt")?, scopes);
        }
        if name == "RangeVar" {
            let fields = object(data, "RangeVar")?;
            let catalog = fields
                .get("catalogname")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let schema = fields
                .get("schemaname")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let relation = fields
                .get("relname")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if sql_contract::LOGICAL_RELATIONS.iter().any(|candidate| {
                candidate.name == relation
                    && !candidate
                        .profiles
                        .contains(&sql_contract::QuerySqlProfile::PostgresServer.contract().id)
            }) {
                return Err(reject(
                    QuerySqlErrorCategory::UnauthorizedRelation,
                    format!("relation '{relation}' is unavailable in profile postgres-server"),
                ));
            }
            if !catalog.is_empty() || !schema.is_empty() || !relation_in_scope(relation, scopes) {
                return Err(reject(
                    QuerySqlErrorCategory::UnauthorizedRelation,
                    format!("relation '{relation}' is outside the caller-visible logical catalog"),
                ));
            }
        }
    }
    match value {
        Value::Array(values) => {
            for value in values {
                walk_scopes(value, scopes)?;
            }
        }
        Value::Object(fields) => {
            for value in fields.values() {
                walk_scopes(value, scopes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_select_scope(
    select: &Map<String, Value>,
    outer_scopes: &[HashSet<String>],
) -> Result<()> {
    let mut scopes = outer_scopes.to_vec();
    let mut local = HashSet::new();
    if let Some(with) = select.get("with_clause").filter(|value| !value.is_null()) {
        let with = object(with, "WithClause")?;
        if with
            .get("recursive")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(reject(
                QuerySqlErrorCategory::UnsafeStatement,
                "recursive CTEs are prohibited",
            ));
        }
        for cte in with
            .get("ctes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (variant, data) = node_variant(cte)
                .ok_or_else(|| reject(QuerySqlErrorCategory::UnsafeStatement, "malformed CTE"))?;
            if variant != "CommonTableExpr" {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "WITH contains a non-CTE node",
                ));
            }
            let cte = object(data, "CommonTableExpr")?;
            let name = cte
                .get("ctename")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if name.is_empty() || sql_contract::is_logical_relation(name) || local.contains(name) {
                return Err(reject(
                    QuerySqlErrorCategory::UnauthorizedRelation,
                    "CTE names may not be empty, duplicated, or shadow logical relations",
                ));
            }
            let mut visible = scopes.clone();
            visible.push(local.clone());
            walk_scopes(cte.get("ctequery").unwrap_or(&Value::Null), &visible)?;
            local.insert(name.to_owned());
        }
    }
    scopes.push(local);
    for (field, value) in select {
        if field == "with_clause" {
            continue;
        }
        if matches!(field.as_str(), "larg" | "rarg") && !value.is_null() {
            validate_select_scope(object(value, "nested SelectStmt")?, &scopes)?;
        } else {
            walk_scopes(value, &scopes)?;
        }
    }
    Ok(())
}

/// Parse and validate exactly one PostgreSQL SELECT using a fully exhaustive
/// traversal of the pinned protobuf representation.
pub fn validate(request: &QuerySqlRequest) -> Result<String> {
    request.validate()?;
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::PostgresServer,
        &request.sql,
    )?;
    let parsed = pg_query::parse(&statement).map_err(|_| {
        reject(
            QuerySqlErrorCategory::SyntaxOrType,
            "PostgreSQL rejected the statement syntax",
        )
    })?;
    if parsed.protobuf.stmts.len() != 1 || !parsed.warnings.is_empty() {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            "exactly one warning-free SELECT is required",
        ));
    }
    let tree = serde_json::to_value(&parsed.protobuf).map_err(|_| {
        reject(
            QuerySqlErrorCategory::Engine,
            "could not inspect PostgreSQL AST",
        )
    })?;
    let root = tree
        .get("stmts")
        .and_then(Value::as_array)
        .and_then(|statements| statements.first())
        .and_then(|raw| raw.get("stmt"))
        .ok_or_else(|| reject(QuerySqlErrorCategory::UnsafeStatement, "missing parse root"))?;
    if !matches!(node_variant(root), Some(("SelectStmt", _))) {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            "the PostgreSQL parse root must be SelectStmt",
        ));
    }
    let mut parameters = HashSet::new();
    walk_ast(root, &mut parameters)?;
    walk_scopes(root, &[])?;
    if parameters
        .iter()
        .any(|number| *number > request.parameters.len())
        || (1..=request.parameters.len()).any(|number| !parameters.contains(&number))
    {
        return Err(reject(
            QuerySqlErrorCategory::InvalidArguments,
            "ordered parameters and $n placeholders must match exactly",
        ));
    }
    Ok(statement)
}

fn quote_identifier(identifier: &str) -> Result<String> {
    if identifier.is_empty()
        || identifier.len() > 63
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(reject(
            QuerySqlErrorCategory::Engine,
            "invalid generated PostgreSQL identifier",
        ));
    }
    Ok(format!("\"{identifier}\""))
}

fn projection_statements(db: &PostgresDb) -> Result<Vec<String>> {
    let schema = quote_identifier(db.schema())?;
    let relations = |name: &str| format!("{schema}.\"{name}\"");
    let records = relations("records");
    let events = relations("content_events");
    let links = relations("links");
    let bindings = relations("bindings");
    let policies = relations("record_policies");
    let entries = relations("policy_entries");
    let vocabularies = relations("vocabularies");
    let vocabulary_values = relations("vocabulary_values");
    let schema_config = relations("schema_config");
    let max_bearer_depth = crate::authorization::MAX_DERIVED_BEARER_DEPTH;
    Ok(vec![
        "CREATE TEMP TABLE _query_sql_principal(singleton boolean PRIMARY KEY CHECK(singleton), account_id text NOT NULL, trusted_local_bypass boolean NOT NULL)".into(),
        // Bearer-first (subject -> derived artifact), matching the SQLite
        // contract in src/query/sql.rs verbatim in meaning. See the long
        // comment there for why the two directions describe the same relation
        // and why the artifact-first form was quadratic in chain depth. The
        // depth counter is unchanged, so an artifact more than
        // MAX_DERIVED_BEARER_DEPTH edges from its bearer stays invisible.
        format!(
            "CREATE TEMP VIEW _query_sql_authorization_subjects WITH (security_barrier=true) AS \
             WITH RECURSIVE bearer_walk(record_id,subject_id,depth) AS ( \
               SELECT ordinary.id,ordinary.id,0 FROM {records} ordinary \
               WHERE ordinary.deleted_at IS NULL \
                 AND NOT(ordinary.record_type='Annotation' OR (ordinary.record_type='Document' AND ordinary.kind='attachment')) \
               UNION ALL \
               SELECT derived.id,walk.subject_id,walk.depth+1 \
               FROM bearer_walk walk \
               JOIN {links} part ON part.target_id=walk.record_id AND part.relationship='part_of' \
               JOIN {records} derived ON derived.id=part.source_id \
               WHERE derived.deleted_at IS NULL \
                 AND (derived.record_type='Annotation' OR (derived.record_type='Document' AND derived.kind='attachment')) \
                 AND (SELECT count(*) FROM {links} all_parts WHERE all_parts.source_id=derived.id AND all_parts.relationship='part_of')=1 \
                 AND walk.depth<{max_bearer_depth}) \
             SELECT walk.record_id AS record_id,walk.subject_id AS subject_id FROM bearer_walk walk"
        ),
        format!(
            "CREATE TEMP VIEW _query_sql_visible_records WITH (security_barrier=true) AS \
             SELECT record.id FROM {records} record \
             JOIN pg_temp._query_sql_authorization_subjects resolved ON resolved.record_id=record.id \
             JOIN {records} authorization_subject ON authorization_subject.id=resolved.subject_id \
             CROSS JOIN pg_temp._query_sql_principal principal \
             WHERE record.deleted_at IS NULL \
               AND NOT(record.record_type='Annotation' AND record.kind='attribution') \
               AND NOT(record.record_type='Entity' AND record.kind='semantic-unit') \
               AND NOT(authorization_subject.record_type='Entity' AND authorization_subject.kind='semantic-unit') \
               AND EXISTS(SELECT 1 FROM {policies} policy WHERE policy.record_id=authorization_subject.policy_anchor_id) \
               AND (principal.trusted_local_bypass OR EXISTS(SELECT 1 FROM {bindings} own WHERE own.record_id=authorization_subject.owner_id AND own.system='account' AND own.identifier=principal.account_id AND own.is_canonical) \
                    OR EXISTS(SELECT 1 FROM {entries} entry WHERE entry.policy_anchor_id=authorization_subject.policy_anchor_id AND entry.effect='allow' AND entry.capability IN ('view','edit','manage') AND ((entry.subject_kind='members' AND entry.subject_id='native:members') OR (entry.subject_kind='account' AND entry.subject_id=principal.account_id))))"
        ),
        format!(
            "CREATE TEMP VIEW records WITH (security_barrier=true) AS \
             SELECT record.id, record.record_type AS type, record.kind, record.name, record.body, \
                    CASE WHEN parent.id IS NULL THEN NULL ELSE record.home_id END AS home_id, \
                    record.lifecycle, record.persistence, record.maturity, record.summary, \
                    COALESCE((SELECT event.created_at FROM {events} event WHERE event.record_id=record.id AND event.type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1') ORDER BY event.seq DESC LIMIT 1), record.created_at) AS last_activity_at, \
                    record.created_at, record.updated_at, record.deleted_at \
             FROM {records} record JOIN pg_temp._query_sql_visible_records visible ON visible.id=record.id \
             LEFT JOIN pg_temp._query_sql_visible_records parent ON parent.id=record.home_id"
        ),
        format!(
            "CREATE TEMP VIEW content_events WITH (security_barrier=true) AS \
             SELECT event.seq AS local_seq,event.id,event.record_id, \
                    CASE WHEN event.type='receipt.committed.v1' THEN 'record.updated' ELSE event.type END AS type, \
                    event.created_at FROM {events} event \
             JOIN pg_temp._query_sql_visible_records visible ON visible.id=event.record_id \
             WHERE event.type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1')"
        ),
        format!(
            "CREATE TEMP VIEW links WITH (security_barrier=true) AS \
             SELECT link.id,link.source_id,link.target_id,link.relationship,link.note,link.created_at FROM {links} link \
             JOIN pg_temp._query_sql_visible_records source ON source.id=link.source_id \
             JOIN pg_temp._query_sql_visible_records target ON target.id=link.target_id"
        ),
        format!(
            "CREATE TEMP VIEW facet_values WITH (security_barrier=true) AS \
             WITH mutations AS ( \
                    SELECT event.record_id,event.seq,event.type,event.payload,event.created_at \
                    FROM {events} event \
                    JOIN pg_temp._query_sql_visible_records visible ON visible.id=event.record_id \
                    WHERE event.type IN ('facet.set','facet.unset') \
                      AND event.payload->>'key' IS NOT NULL \
                      AND event.payload->>'key' NOT IN ('lifecycle','owner','persistence','maturity') \
                      AND COALESCE((event.payload->>'observation_only')::boolean,FALSE)=FALSE), \
                  latest AS (SELECT DISTINCT ON(record_id,payload->>'key') record_id,seq,type,payload \
                    FROM mutations ORDER BY record_id,payload->>'key',seq DESC) \
             SELECT 'fv:'||current.record_id||':'||(current.payload->>'key') AS id, current.record_id, \
                    current.payload->>'key' AS key,current.payload->>'value' AS value, \
                    CASE WHEN current.payload->>'value' ~ '^-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?$' \
                         THEN (current.payload->>'value')::double precision ELSE NULL END AS value_num, \
                    current.payload->>'vocab_ref' AS vocab_ref, epoch.created_at \
             FROM latest current \
             JOIN LATERAL (SELECT event.created_at FROM mutations event \
                 WHERE event.record_id=current.record_id AND event.type='facet.set' \
                   AND event.payload->>'key'=current.payload->>'key' \
                   AND event.seq > COALESCE((SELECT max(unset.seq) FROM mutations unset \
                       WHERE unset.record_id=current.record_id AND unset.type='facet.unset' \
                         AND unset.payload->>'key'=current.payload->>'key' AND unset.seq<current.seq),0) \
                 ORDER BY event.seq LIMIT 1) epoch ON TRUE \
             WHERE current.type='facet.set'"
        ),
        format!(
            "CREATE TEMP VIEW facet_observations WITH (security_barrier=true) AS \
             WITH candidates AS (SELECT event.record_id,event.seq,event.type,event.payload,event.created_at, \
                    COALESCE(event.payload->>'as_of', rtrim(rtrim(to_char(event.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z') AS as_of \
                    FROM {events} event JOIN pg_temp._query_sql_visible_records visible ON visible.id=event.record_id \
                    WHERE event.type IN ('facet.set','facet.unset') AND event.payload->>'key' IS NOT NULL \
                      AND event.payload->>'key' NOT IN ('lifecycle','owner','persistence','maturity')), \
                  corrected AS (SELECT DISTINCT ON(record_id,payload->>'key',as_of) record_id,seq,type,payload,created_at,as_of FROM candidates ORDER BY record_id,payload->>'key',as_of,seq DESC) \
             SELECT 'fo:'||record_id||':'||(payload->>'key')||':'||as_of AS id,record_id,payload->>'key' AS key, \
                    CASE WHEN type='facet.set' THEN payload->>'value' ELSE NULL END AS value, \
                    CASE WHEN type='facet.set' THEN 'set' ELSE 'unset' END AS op, \
                    CASE WHEN type='facet.set' THEN payload->>'vocab_ref' ELSE NULL END AS vocab_ref, \
                    as_of,created_at AS observed_at,seq AS event_seq FROM corrected"
        ),
        format!(
            "CREATE TEMP VIEW bindings WITH (security_barrier=true) AS \
             SELECT binding.record_id,binding.system,binding.identifier,binding.is_canonical,binding.url,binding.etag,binding.last_seen_at \
             FROM {bindings} binding CROSS JOIN pg_temp._query_sql_principal principal \
             JOIN pg_temp._query_sql_visible_records visible ON visible.id=binding.record_id \
             WHERE binding.system IN ('account','email') AND EXISTS(SELECT 1 FROM {bindings} own WHERE own.record_id=binding.record_id AND own.system='account' AND own.identifier=principal.account_id AND own.is_canonical)"
        ),
        format!(
            "CREATE TEMP VIEW blobs WITH (security_barrier=true) AS \
             SELECT blob.id,blob.bytes,blob.mime,blob.size_bytes,blob.sha256,blob.original_filename,blob.storage_tier,blob.external_ref,blob.created_at \
             FROM {blobs} blob WHERE EXISTS(SELECT 1 FROM {records} attachment \
               JOIN pg_temp._query_sql_visible_records attachment_visible ON attachment_visible.id=attachment.id \
               JOIN {facet_values} blob_ref ON blob_ref.record_id=attachment.id AND blob_ref.key='blob_ref' \
               JOIN {links} bearer ON bearer.source_id=attachment.id AND bearer.relationship='part_of' \
               JOIN pg_temp._query_sql_visible_records bearer_visible ON bearer_visible.id=bearer.target_id \
               WHERE attachment.record_type='Document' AND attachment.kind='attachment' \
                 AND jsonb_typeof(blob_ref.value)='string' AND blob_ref.value#>>'{{}}'=blob.id)",
            blobs=relations("blobs"),
            facet_values=relations("facet_values")
        ),
        format!("CREATE TEMP VIEW vocabularies WITH (security_barrier=true) AS SELECT id,name,created_at FROM {vocabularies}"),
        format!("CREATE TEMP VIEW vocabulary_values WITH (security_barrier=true) AS SELECT id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of FROM {vocabulary_values}"),
        format!("CREATE TEMP VIEW schema_config WITH (security_barrier=true) AS SELECT config.id,config.layer,config.name,config.data,config.applies_to_collection_id,config.version_lineage,config.created_at FROM {schema_config} config WHERE config.applies_to_collection_id IS NULL OR EXISTS(SELECT 1 FROM pg_temp._query_sql_visible_records visible WHERE visible.id=config.applies_to_collection_id)"),
    ])
}

fn parameter_types(parameters: &[QuerySqlParameter]) -> Vec<PgTypeInfo> {
    parameters
        .iter()
        .map(|parameter| {
            PgTypeInfo::with_name(match parameter {
                QuerySqlParameter::Boolean { .. } => "BOOL",
                QuerySqlParameter::Integer { .. } => "INT8",
                QuerySqlParameter::Real { .. } => "FLOAT8",
                QuerySqlParameter::Text { .. } => "TEXT",
                QuerySqlParameter::Bytes { .. } => "BYTEA",
                QuerySqlParameter::Json { .. } => "JSONB",
                QuerySqlParameter::Timestamp { .. } => "TIMESTAMPTZ",
            })
        })
        .collect()
}

fn parameter_arguments(parameters: &[QuerySqlParameter]) -> Result<PgArguments> {
    let mut arguments = PgArguments::default();
    for parameter in parameters {
        match parameter {
            QuerySqlParameter::Boolean { value } => arguments.add(*value),
            QuerySqlParameter::Integer { value } => arguments.add(
                value
                    .as_deref()
                    .map(str::parse::<i64>)
                    .transpose()
                    .map_err(|_| {
                        reject(
                            QuerySqlErrorCategory::InvalidArguments,
                            "integer parameter must be signed i64",
                        )
                    })?,
            ),
            QuerySqlParameter::Real { value } => arguments.add(*value),
            QuerySqlParameter::Text { value } => arguments.add(value.clone()),
            QuerySqlParameter::Bytes { value } => arguments.add(
                value
                    .as_deref()
                    .map(|value| base64::engine::general_purpose::STANDARD.decode(value))
                    .transpose()
                    .map_err(|_| {
                        reject(
                            QuerySqlErrorCategory::InvalidArguments,
                            "bytes parameter must be canonical base64",
                        )
                    })?,
            ),
            QuerySqlParameter::Json { value } => {
                let parsed = value
                    .clone()
                    .map(RawValue::from_string)
                    .transpose()
                    .map_err(|_| {
                        reject(
                            QuerySqlErrorCategory::InvalidArguments,
                            "json parameter must be valid JSON",
                        )
                    })?;
                arguments.add(parsed.map(Json))
            }
            QuerySqlParameter::Timestamp { value } => {
                let parsed = value
                    .as_deref()
                    .map(DateTime::parse_from_rfc3339)
                    .transpose()
                    .map_err(|_| {
                        reject(
                            QuerySqlErrorCategory::InvalidArguments,
                            "timestamp parameter must be RFC3339",
                        )
                    })?
                    .map(|value| value.with_timezone(&Utc));
                arguments.add(parsed)
            }
        }
        .map_err(|_| {
            reject(
                QuerySqlErrorCategory::InvalidArguments,
                "parameter encoding failed",
            )
        })?;
    }
    Ok(arguments)
}

fn row_cell(row: &PgRow, index: usize) -> Result<Value> {
    let raw = row.try_get_raw(index)?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    let name = raw.type_info().name().to_ascii_lowercase();
    let value = match name.as_str() {
        "bool" => Value::Bool(row.try_get(index)?),
        "int2" => Value::from(row.try_get::<i16, _>(index)?),
        "int4" => Value::from(row.try_get::<i32, _>(index)?),
        "int8" => Value::from(row.try_get::<i64, _>(index)?),
        "float4" => serde_json::Number::from_f64(row.try_get::<f32, _>(index)? as f64)
            .map(Value::Number)
            .ok_or_else(|| {
                reject(
                    QuerySqlErrorCategory::SyntaxOrType,
                    "non-finite float result",
                )
            })?,
        "float8" => serde_json::Number::from_f64(row.try_get::<f64, _>(index)?)
            .map(Value::Number)
            .ok_or_else(|| {
                reject(
                    QuerySqlErrorCategory::SyntaxOrType,
                    "non-finite float result",
                )
            })?,
        "numeric" => {
            let number: BigDecimal = row.try_get(index)?;
            let text = number.normalized().to_string();
            if matches!(text.as_str(), "NaN" | "Infinity" | "-Infinity") {
                return Err(reject(
                    QuerySqlErrorCategory::SyntaxOrType,
                    "non-finite numeric result",
                ));
            }
            Value::String(text)
        }
        "text" | "varchar" | "bpchar" | "char" | "name" => Value::String(row.try_get(index)?),
        "bytea" => Value::String(
            base64::engine::general_purpose::STANDARD.encode(row.try_get::<Vec<u8>, _>(index)?),
        ),
        "json" | "jsonb" => Value::String(
            row.try_get::<Json<Box<RawValue>>, _>(index)?
                .0
                .get()
                .to_owned(),
        ),
        "timestamptz" => Value::String(
            row.try_get::<DateTime<Utc>, _>(index)?
                .to_rfc3339_opts(SecondsFormat::AutoSi, true),
        ),
        _ => {
            return Err(reject(
                QuerySqlErrorCategory::SyntaxOrType,
                format!("result type '{name}' is outside the closed codec"),
            ))
        }
    };
    if serde_json::to_vec(&value)?.len() > MAX_CELL_ENCODED_BYTES {
        return Err(reject(
            QuerySqlErrorCategory::ResultTooLarge,
            "a cell exceeds the encoded byte limit",
        ));
    }
    Ok(value)
}

async fn within_setup_deadline<T, F>(deadline: Instant, future: F) -> Result<T>
where
    F: Future<Output = std::result::Result<T, sqlx::Error>>,
{
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| {
            reject(
                QuerySqlErrorCategory::Timeout,
                "PostgreSQL query setup exceeded the wall-clock limit",
            )
        })?
        .map_err(Error::from)
}

pub async fn query_sql_request_owned(
    db: PostgresDb,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<QuerySqlResult> {
    sql_contract::require_available(sql_contract::QuerySqlProfile::PostgresServer)?;
    execute_qualified(db, principal, request, None).await
}

#[cfg(feature = "postgres-tests")]
pub async fn qualification_query_sql(
    db: PostgresDb,
    principal: impl Into<QueryPrincipal>,
    request: QuerySqlRequest,
) -> Result<QuerySqlResult> {
    execute_qualified(db, principal.into(), request, None).await
}

/// Test-only execution observer proving which physical backend actually runs
/// a cancellable `query_sql` request. The sender fires after the read-only role
/// boundary is established and immediately before the caller statement is
/// prepared on that same transaction.
#[cfg(feature = "postgres-tests")]
#[doc(hidden)]
pub async fn qualification_query_sql_with_backend_pid(
    db: PostgresDb,
    principal: impl Into<QueryPrincipal>,
    request: QuerySqlRequest,
    backend_pid: tokio::sync::oneshot::Sender<i32>,
) -> Result<QuerySqlResult> {
    execute_qualified(db, principal.into(), request, Some(backend_pid)).await
}

async fn execute_qualified(
    db: PostgresDb,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    mut backend_pid: Option<tokio::sync::oneshot::Sender<i32>>,
) -> Result<QuerySqlResult> {
    let statement = validate(&request)?;
    let mut connection = db.query_pool().acquire().await.map_err(Error::from)?;
    // This boundary is intentionally one physical session per call. In
    // particular, no temp object, role state, cancellation, or caller datum
    // can survive into another caller's execution.
    connection.close_on_drop();
    let setup_deadline = Instant::now() + Duration::from_millis(2_500);
    within_setup_deadline(
        setup_deadline,
        sqlx::query("DISCARD ALL").execute(&mut *connection),
    )
    .await?;
    for setting in [
        "SET statement_timeout='2000ms'",
        "SET lock_timeout='250ms'",
        "SET idle_in_transaction_session_timeout='2500ms'",
    ] {
        within_setup_deadline(setup_deadline, connection.execute(setting)).await?;
    }
    for ddl in projection_statements(&db)? {
        within_setup_deadline(setup_deadline, sqlx::query(&ddl).execute(&mut *connection)).await?;
    }
    let principal_insert =
        sqlx::query("INSERT INTO pg_temp._query_sql_principal VALUES(true,$1,$2)")
            .bind(principal.credential().to_string())
            .bind(principal.trusted_local_bypass())
            .execute(&mut *connection);
    within_setup_deadline(setup_deadline, principal_insert).await?;
    let query_role = quote_identifier(db.query_role())?;
    let temp_schema: String = within_setup_deadline(
        setup_deadline,
        sqlx::query_scalar("SELECT nspname FROM pg_namespace WHERE oid=pg_my_temp_schema()")
            .fetch_one(&mut *connection),
    )
    .await?;
    let temp_schema = quote_identifier(&temp_schema)?;
    within_setup_deadline(
        setup_deadline,
        connection.execute(format!("GRANT USAGE ON SCHEMA {temp_schema} TO {query_role}").as_str()),
    )
    .await?;
    within_setup_deadline(
        setup_deadline,
        connection.execute(
            format!("GRANT SELECT ON ALL TABLES IN SCHEMA {temp_schema} TO {query_role}").as_str(),
        ),
    )
    .await?;
    let result = async {
        let mut transaction = connection.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *transaction)
            .await?;
        for setting in [
            "SET LOCAL statement_timeout='2000ms'",
            "SET LOCAL lock_timeout='250ms'",
            "SET LOCAL idle_in_transaction_session_timeout='2500ms'",
            "SET LOCAL search_path=pg_temp,pg_catalog",
        ] {
            transaction.execute(setting).await?;
        }
        transaction
            .execute(format!("SET LOCAL ROLE {query_role}").as_str())
            .await?;
        if let Some(backend_pid) = backend_pid.take() {
            let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *transaction)
                .await?;
            let _ = backend_pid.send(pid);
        }
        let capped = format!(
            "SELECT * FROM ({statement}) AS _native_query LIMIT {}",
            MAX_ROWS + 1
        );
        let types = parameter_types(&request.parameters);
        let prepared = transaction
            .prepare_with(&capped, &types)
            .await
            .map_err(|_| {
                reject(
                    QuerySqlErrorCategory::SyntaxOrType,
                    "PostgreSQL could not type-check the query",
                )
            })?;
        if prepared.columns().len() > MAX_COLUMNS {
            return Err(reject(
                QuerySqlErrorCategory::ResultTooLarge,
                "result exceeds the column limit",
            ));
        }
        let columns = prepared
            .columns()
            .iter()
            .map(|column| column.name().to_owned())
            .collect::<Vec<_>>();
        let mut labels = HashSet::new();
        if let Some(duplicate) = columns
            .iter()
            .find(|column| !labels.insert(column.as_str()))
        {
            return Err(reject(
                QuerySqlErrorCategory::DuplicateColumns,
                format!("duplicate output column label '{duplicate}'"),
            ));
        }
        let arguments = parameter_arguments(&request.parameters)?;
        let mut stream = prepared.query_with(arguments).fetch(&mut *transaction);
        let mut rows = Vec::new();
        let mut encoded_bytes = serde_json::to_vec(&columns)?.len() + 2;
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(|error| {
            let category = if error.to_string().contains("statement timeout")
                || error.to_string().contains("canceling statement")
            {
                QuerySqlErrorCategory::Timeout
            } else {
                QuerySqlErrorCategory::SyntaxOrType
            };
            reject(category, "PostgreSQL query execution failed")
        })? {
            if rows.len() == MAX_ROWS {
                truncated = true;
                break;
            }
            let mut object = Map::new();
            for (index, column) in columns.iter().enumerate() {
                object.insert(column.clone(), row_cell(&row, index)?);
            }
            let value = Value::Object(object);
            encoded_bytes = encoded_bytes.saturating_add(serde_json::to_vec(&value)?.len() + 1);
            if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
                return Err(reject(
                    QuerySqlErrorCategory::ResultTooLarge,
                    "encoded result exceeds the byte limit",
                ));
            }
            rows.push(value);
        }
        drop(stream);
        transaction.rollback().await?;
        let row_count = rows.len();
        Ok(QuerySqlResult {
            columns,
            rows,
            row_count,
            truncated,
        })
    }
    .await;
    // PostgreSQL records schema/table grants as dependencies of the persistent
    // query role, even though the grantee and objects live at very different
    // lifetimes. Revoke them deterministically before the physical session is
    // discarded so role cleanup cannot be obstructed by dead temp namespaces.
    let cleanup = async {
        connection
            .execute(
                format!(
                    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {temp_schema} FROM {query_role}"
                )
                .as_str(),
            )
            .await?;
        connection
            .execute(format!("REVOKE USAGE ON SCHEMA {temp_schema} FROM {query_role}").as_str())
            .await?;
        Result::<()>::Ok(())
    }
    .await;
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::sql_contract::QuerySqlParameter;

    fn request(sql: &str) -> QuerySqlRequest {
        QuerySqlRequest {
            sql: sql.into(),
            parameters: Vec::new(),
        }
    }

    #[test]
    fn exhaustive_parser_admits_scoped_read_only_queries() {
        for sql in [
            "SELECT id, lower(name) FROM records WHERE name IS NOT NULL ORDER BY id LIMIT 10 OFFSET 1",
            "WITH chosen AS (SELECT id FROM records) SELECT count(*) FROM chosen",
            "SELECT row_number() OVER (ORDER BY id), id FROM records",
            "SELECT * FROM records WHERE id IN (SELECT record_id FROM facet_values)",
            "SELECT * FROM (VALUES (1), (2)) AS values_fixture(value)",
        ] {
            validate(&request(sql)).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
    }

    #[test]
    fn exhaustive_parser_rejects_review_bypasses_and_scope_spoofing() {
        for sql in [
            "SELECT * FROM pg_catalog.pg_roles",
            "SELECT * FROM public.records",
            "SELECT current_setting('role')",
            "SELECT 1 LIMIT current_setting('role')::int",
            "SELECT 1 OFFSET current_setting('role')::int",
            "SELECT sum(id) FILTER (WHERE current_setting('role')='x') FROM records",
            "SELECT sum(id) OVER (ORDER BY current_setting('role')) FROM records",
            "SELECT 1::pg_catalog.int4",
            "SELECT 1 OPERATOR(pg_catalog.+) 2",
            "SELECT id FROM records ORDER BY id USING OPERATOR(pg_catalog.<)",
            "SELECT * FROM records FOR UPDATE",
            "WITH records AS (SELECT 1) SELECT * FROM records",
            "WITH first AS (SELECT * FROM second), second AS (SELECT 1) SELECT * FROM first",
            "WITH outer_cte AS (WITH hidden AS (SELECT 1) SELECT * FROM hidden) SELECT * FROM hidden",
            "WITH RECURSIVE walk AS (SELECT * FROM walk) SELECT * FROM walk",
            "WITH changed AS (DELETE FROM records RETURNING id) SELECT * FROM changed",
            "SELECT * FROM records TABLESAMPLE SYSTEM (1)",
        ] {
            assert!(validate(&request(sql)).is_err(), "admitted {sql}");
        }
    }

    #[test]
    fn sqlite_only_relations_fail_with_explicit_profile_diagnostic() {
        for relation in [
            "agent_activity",
            "agent_activity_claims",
            "messages_awaiting_reply",
        ] {
            let error = validate(&request(&format!("SELECT * FROM {relation}")))
                .expect_err("SQLite-only relation must not be advertised by PostgreSQL");
            assert!(
                error.to_string().contains(&format!(
                    "relation '{relation}' is unavailable in profile postgres-server"
                )),
                "unexpected diagnostic for {relation}: {error}"
            );
        }
    }

    #[test]
    fn parameter_positions_are_typed_and_exact() {
        let request = QuerySqlRequest {
            sql: "SELECT $1::text FROM records WHERE id=$2".into(),
            parameters: vec![
                QuerySqlParameter::Text {
                    value: Some("label".into()),
                },
                QuerySqlParameter::Text {
                    value: Some("record".into()),
                },
            ],
        };
        validate(&request).unwrap();
        let missing = QuerySqlRequest {
            sql: "SELECT $2 FROM records".into(),
            parameters: vec![QuerySqlParameter::Text {
                value: Some("x".into()),
            }],
        };
        assert!(validate(&missing).is_err());
    }
}
