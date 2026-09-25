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
use sqlx::postgres::{PgArguments, PgDatabaseError, PgErrorPosition, PgRow, PgTypeInfo};
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

/// I2: function admission is the shared portable subset
/// (`sql_contract::is_portable_function`); the closed AST walk below is
/// defence in depth behind the classifier, which already rejected dropped
/// names with their portable repair.
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

/// Map a 1-based PG character position in the capped wrapper text back to
/// a 1-based position in the caller's statement. The `?N`→`$N` rewrite
/// swaps one sigil character for another, so rewritten and caller text
/// have equal character counts and the mapping is exact. Returns `None`
/// for positions inside the wrapper itself.
///
/// E2 I-5: carry the sanitised engine message plus the caller-text position
/// instead of discarding both. Positions index the prepared (capped, `$N`)
/// text; the `?N`→`$N` rewrite swaps one sigil character for another, so it
/// preserves length and subtracting the wrapper prefix maps positions back
/// onto the caller's statement exactly.
fn caller_position(pg_position: usize, statement: &str) -> Option<usize> {
    const WRAPPER_PREFIX_LEN: usize = "SELECT * FROM (".len();
    if pg_position <= WRAPPER_PREFIX_LEN {
        return None;
    }
    let position = pg_position - WRAPPER_PREFIX_LEN;
    if position == 0 || position > statement.chars().count() + 1 {
        return None;
    }
    Some(position)
}

fn type_check_error(error: sqlx::Error, statement: &str) -> Error {
    const HEADLINE: &str = "PostgreSQL could not type-check the query";
    let sqlx::Error::Database(database) = &error else {
        return reject(QuerySqlErrorCategory::SyntaxOrType, HEADLINE);
    };
    let Some(pg_error) = database.try_downcast_ref::<PgDatabaseError>() else {
        return reject(QuerySqlErrorCategory::SyntaxOrType, HEADLINE);
    };
    let message = sanitize_type_message(pg_error.message());
    let mut detail = String::from(HEADLINE);
    if let Some(PgErrorPosition::Original(position)) = pg_error.position() {
        if let Some(caller_position) = caller_position(position, statement) {
            detail.push_str(&format!(" at position {caller_position}"));
        }
    }
    if !message.is_empty() {
        detail.push_str(": ");
        detail.push_str(&message);
    }
    if message.contains("must be type boolean") {
        detail.push_str(
            ". Hint: Catalog booleans are 0/1 integers: write `WHERE is_canonical = 1`, \
             not `WHERE is_canonical`; same for CASE WHEN.",
        );
    }
    reject(QuerySqlErrorCategory::SyntaxOrType, detail)
}

/// First meaningful line only, redacted then capped at 300 chars.
/// Never emits PG detail/hint/where text, internal view names, physical
/// table names, or DDL: only the message head with internals scrubbed.
/// Redaction is quote-aware: engine-inserted identifiers never appear
/// inside caller string literals, so balanced quoted caller text (which may
/// legitimately mention `_query_sql_` or `pg_temp`) is left intact.
/// Double-quoted identifiers are tracked separately so an apostrophe inside
/// `"a'b"` cannot suppress later redaction; when quotes do not balance at
/// all, the pass falls back to scrubbing the internal tokens everywhere.
fn sanitize_type_message(message: &str) -> String {
    let head = message
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("");
    let redacted = redact_outside_literals(head);
    redacted.chars().take(300).collect()
}

fn redact_outside_literals(message: &str) -> String {
    match redact_quote_aware(message) {
        Some(redacted) => redacted,
        // A stray apostrophe (an unbalanced engine contraction, or a quote
        // the scanner cannot pair) would otherwise suppress every later
        // redaction, so fall back to scrubbing the internal tokens
        // everywhere. A caller literal may be rewritten on this path; that
        // is the price of a redactor one quote character cannot silence.
        None => redact_everywhere(message),
    }
}

/// Single internal-token replacement at the head of `rest`, quote-unaware.
/// Returns the replacement text and the bytes to skip.
fn match_internal_token(rest: &str) -> Option<(&'static str, usize)> {
    if rest.starts_with("_native_query") {
        return Some(("(query)", "_native_query".len()));
    }
    if rest.starts_with("pg_temp") {
        let mut skip = "pg_temp".len();
        let digits: usize = rest[skip..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '_')
            .map(|c| c.len_utf8())
            .sum();
        // Accept pg_temp. and pg_temp_N. (digits/underscores then a dot).
        if rest[skip + digits..].starts_with('.') {
            skip += digits + 1;
            return Some(("", skip));
        }
        return None;
    }
    if let Some(tail) = rest.strip_prefix("_query_sql_") {
        let skip = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        return Some(("(internal relation)", "_query_sql_".len() + skip));
    }
    None
}

/// Quote-aware pass: `None` when a quote never closes. Single-quoted
/// string literals are copied verbatim (with `''` escape): engine-inserted
/// identifiers never appear inside caller literals, so balanced quoted
/// caller text (which may legitimately mention `_query_sql_` or `pg_temp`)
/// is intact. Double-quoted identifiers are tracked separately but their
/// contents are still scrubbed: PostgreSQL engine inserts its own names
/// double-quoted (`relation "_query_sql_…" does not exist`), while the
/// tracking keeps an apostrophe inside `"a'b"` from flipping the literal
/// state and suppressing later redaction.
fn redact_quote_aware(message: &str) -> Option<String> {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while !rest.is_empty() {
        // Normal span up to the next quote character; scrub tokens in it.
        let mut next = rest.len();
        let mut quote = None;
        if let Some(index) = rest.find('\'') {
            next = index;
            quote = Some('\'');
        }
        if let Some(index) = rest.find('"') {
            if index < next {
                next = index;
                quote = Some('"');
            }
        }
        out.push_str(&redact_everywhere(&rest[..next]));
        rest = &rest[next..];
        match quote {
            None => break,
            Some('\'') => {
                // Caller literal: copy verbatim through the closing quote.
                out.push('\'');
                rest = &rest[1..];
                loop {
                    if rest.is_empty() {
                        return None;
                    }
                    if rest.starts_with("''") {
                        out.push_str("''");
                        rest = &rest[2..];
                    } else if rest.starts_with('\'') {
                        out.push('\'');
                        rest = &rest[1..];
                        break;
                    } else {
                        let end = rest.find('\'').unwrap_or(rest.len());
                        out.push_str(&rest[..end]);
                        rest = &rest[end..];
                    }
                }
            }
            Some('"') => {
                // Engine identifier: scrub the contents, keep the quoting.
                // A single quote inside is literal text, not a literal.
                out.push('"');
                rest = &rest[1..];
                loop {
                    if rest.is_empty() {
                        return None;
                    }
                    if rest.starts_with("\"\"") {
                        out.push_str("\"\"");
                        rest = &rest[2..];
                    } else if rest.starts_with('"') {
                        out.push('"');
                        rest = &rest[1..];
                        break;
                    } else {
                        let end = rest.find('"').unwrap_or(rest.len());
                        out.push_str(&redact_everywhere(&rest[..end]));
                        rest = &rest[end..];
                    }
                }
            }
            _ => break,
        }
    }
    Some(out)
}

/// Unconditional internal-token scrub, used only when the quote-aware pass
/// reports unbalanced quotes and literal boundaries cannot be trusted.
fn redact_everywhere(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while !rest.is_empty() {
        if let Some((replacement, skip)) = match_internal_token(rest) {
            out.push_str(replacement);
            rest = &rest[skip..];
            continue;
        }
        let mut chars = rest.chars();
        out.push(chars.next().expect("non-empty rest has a first char"));
        rest = chars.as_str();
    }
    out
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
            // I2: plain `trim(x)` desugars to qualified `pg_catalog.btrim`
            // with one argument, and `trim(x, chars)` — the SQLite
            // two-argument form — to `btrim` with two. Both shapes are the
            // portable call; modifier forms (`trim(leading …)`) and bare
            // `btrim` stay rejected. Admission never skips the field
            // recursion below, which still collects `$n` ParamRefs.
            let portable_trim = names.len() == 2
                && names[0].eq_ignore_ascii_case("pg_catalog")
                && names[1].eq_ignore_ascii_case("btrim")
                && fields
                    .get("args")
                    .and_then(Value::as_array)
                    .is_some_and(|args| args.len() == 1 || args.len() == 2);
            if !portable_trim
                && (names.len() != 1 || !sql_contract::is_portable_function(&names[0]))
            {
                if names.len() == 1 {
                    if let Some(detail) = sql_contract::unavailable_function_detail(&names[0]) {
                        return Err(reject(QuerySqlErrorCategory::UnsafeStatement, detail));
                    }
                    return Err(reject(
                        QuerySqlErrorCategory::UnsafeStatement,
                        format!(
                            "function '{}' is unavailable",
                            names[0].to_ascii_lowercase()
                        ),
                    ));
                }
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
                let base =
                    format!("relation '{relation}' is outside the caller-visible logical catalog");
                // Keep a schema qualifier for the repair: pg_catalog and
                // information_schema arrive split off from the relation name.
                let probe_target = [catalog, schema, relation]
                    .into_iter()
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join(".");
                let detail = match sql_contract::blocked_relation_repair(
                    &probe_target,
                    sql_contract::QuerySqlProfile::PostgresServer,
                ) {
                    Some(repair) => format!("{base}. {repair}"),
                    None => base,
                };
                return Err(reject(QuerySqlErrorCategory::UnauthorizedRelation, detail));
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
    // I1b: callers write `?N`; Postgres executes `$N`. The rewrite reuses
    // the classifier's own token spans, so placeholders inside literals,
    // comments and quoted forms are untouched. Everything downstream —
    // `pg_query` parse, the AST walk and the exact-`$n`-set check — runs on
    // the rewritten text, and the rewritten statement is what executes.
    let statement = sql_contract::rewrite_placeholders_for_postgres(
        sql_contract::QuerySqlProfile::PostgresServer,
        &statement,
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

/// Portable value-model timestamp pair (E1 M1 slice B): fixed UTC millis
/// text plus integer epoch millis, matching the SQLite governed views and
/// the Turso projection. NULL in, NULL out on both arms.
fn portable_ts(column: &str) -> String {
    format!("to_char({column} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')")
}

fn portable_ts_ms(column: &str) -> String {
    format!("floor(extract(epoch from {column}) * 1000)::bigint")
}

pub(crate) fn projection_statements(db: &PostgresDb) -> Result<Vec<String>> {
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
    // The records view's last_activity_at falls back to the record's own
    // creation time when no content event exists. The subselect is built
    // with format! here so the qualified events table is interpolated:
    // passing it as a plain literal into portable_ts would ship a verbatim
    // `{events}` to Postgres (42601), since portable_ts only substitutes
    // its own {column}.
    let last_activity_src = format!(
        "COALESCE((SELECT event.created_at FROM {events} event \
          WHERE event.record_id=record.id \
            AND event.type NOT IN \
              ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1') \
          ORDER BY event.seq DESC LIMIT 1), record.created_at)"
    );
    let mut statements: Vec<String> = vec![
        "CREATE TEMP TABLE _query_sql_principal(singleton boolean PRIMARY KEY CHECK(singleton), account_id text NOT NULL, trusted_local_bypass boolean NOT NULL, is_member boolean NOT NULL)".into(),        // Bearer-first (subject -> derived artifact), matching the SQLite
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
                    OR EXISTS(SELECT 1 FROM {entries} entry WHERE entry.policy_anchor_id=authorization_subject.policy_anchor_id AND entry.effect='allow' AND entry.capability IN ('view','edit','manage') AND ((entry.subject_kind='members' AND entry.subject_id='native:members' AND principal.is_member) OR (entry.subject_kind='account' AND entry.subject_id=principal.account_id))))"
        ),
        format!(
            "CREATE TEMP VIEW records WITH (security_barrier=true) AS \
             SELECT record.id COLLATE \"C\" AS id, record.record_type COLLATE \"C\" AS type, record.kind COLLATE \"C\" AS kind, record.name COLLATE \"C\" AS name, record.body COLLATE \"C\" AS body, \
                    CASE WHEN parent.id IS NULL THEN NULL ELSE record.home_id END COLLATE \"C\" AS home_id, \
                    record.lifecycle COLLATE \"C\" AS lifecycle, record.persistence COLLATE \"C\" AS persistence, record.maturity COLLATE \"C\" AS maturity, record.summary COLLATE \"C\" AS summary, \
                    {last_activity_at} AS last_activity_at, {last_activity_at_ms} AS last_activity_at_ms, \
                    {record_created_at} AS created_at, {record_created_at_ms} AS created_at_ms, \
                    {record_updated_at} AS updated_at, {record_updated_at_ms} AS updated_at_ms, \
                    {deleted_at} AS deleted_at, {deleted_at_ms} AS deleted_at_ms \
             FROM {records} record JOIN pg_temp._query_sql_visible_records visible ON visible.id=record.id \
             LEFT JOIN pg_temp._query_sql_visible_records parent ON parent.id=record.home_id",
            last_activity_at = portable_ts(&last_activity_src),
            last_activity_at_ms = portable_ts_ms(&last_activity_src),
            record_created_at = portable_ts("record.created_at"),
            record_created_at_ms = portable_ts_ms("record.created_at"),
            record_updated_at = portable_ts("record.updated_at"),
            record_updated_at_ms = portable_ts_ms("record.updated_at"),
            deleted_at = portable_ts("record.deleted_at"),
            deleted_at_ms = portable_ts_ms("record.deleted_at"),
        ),
        format!(
            "CREATE TEMP VIEW content_events WITH (security_barrier=true) AS \
             SELECT event.seq AS local_seq,event.id COLLATE \"C\" AS id,event.record_id COLLATE \"C\" AS record_id, \
                    CASE WHEN event.type='receipt.committed.v1' THEN 'record.updated' ELSE event.type END COLLATE \"C\" AS type, \
                    {created_at} AS created_at, {created_at_ms} AS created_at_ms FROM {events} event \
             JOIN pg_temp._query_sql_visible_records visible ON visible.id=event.record_id \
             WHERE event.type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1')",
            created_at = portable_ts("event.created_at"),
            created_at_ms = portable_ts_ms("event.created_at"),
        ),
        format!(
            "CREATE TEMP VIEW links WITH (security_barrier=true) AS \
             SELECT link.id COLLATE \"C\" AS id,link.source_id COLLATE \"C\" AS source_id,link.target_id COLLATE \"C\" AS target_id,link.relationship COLLATE \"C\" AS relationship,link.note COLLATE \"C\" AS note,{created_at} AS created_at,{created_at_ms} AS created_at_ms FROM {links} link \
             JOIN pg_temp._query_sql_visible_records source ON source.id=link.source_id \
             JOIN pg_temp._query_sql_visible_records target ON target.id=link.target_id",
            created_at = portable_ts("link.created_at"),
            created_at_ms = portable_ts_ms("link.created_at"),
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
             SELECT 'fv:'||current.record_id||':'||(current.payload->>'key') AS id, current.record_id COLLATE \"C\" AS record_id, \
                    current.payload->>'key' COLLATE \"C\" AS key,current.payload->>'value' COLLATE \"C\" AS value, \
                    CASE WHEN current.payload->>'value' ~ '^-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?$' \
                         THEN (current.payload->>'value')::double precision ELSE NULL END AS value_num, \
                    current.payload->>'vocab_ref' COLLATE \"C\" AS vocab_ref, {created_at} AS created_at, {created_at_ms} AS created_at_ms \
             FROM latest current \
             JOIN LATERAL (SELECT event.created_at FROM mutations event \
                 WHERE event.record_id=current.record_id AND event.type='facet.set' \
                   AND event.payload->>'key'=current.payload->>'key' \
                   AND event.seq > COALESCE((SELECT max(unset.seq) FROM mutations unset \
                       WHERE unset.record_id=current.record_id AND unset.type='facet.unset' \
                         AND unset.payload->>'key'=current.payload->>'key' AND unset.seq<current.seq),0) \
                 ORDER BY event.seq LIMIT 1) epoch ON TRUE \
             WHERE current.type='facet.set'",
            created_at = portable_ts("epoch.created_at"),
            created_at_ms = portable_ts_ms("epoch.created_at"),
        ),
        format!(
            "CREATE TEMP VIEW facet_observations WITH (security_barrier=true) AS \
             WITH candidates AS (SELECT event.record_id,event.seq,event.type,event.payload,event.created_at, \
                    COALESCE(event.payload->>'as_of', rtrim(rtrim(to_char(event.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US'),'0'),'.')||'Z') AS as_of \
                    FROM {events} event JOIN pg_temp._query_sql_visible_records visible ON visible.id=event.record_id \
                    WHERE event.type IN ('facet.set','facet.unset') AND event.payload->>'key' IS NOT NULL \
                      AND event.payload->>'key' NOT IN ('lifecycle','owner','persistence','maturity')), \
                  corrected AS (SELECT DISTINCT ON(record_id,payload->>'key',as_of) record_id,seq,type,payload,created_at,as_of FROM candidates ORDER BY record_id,payload->>'key',as_of,seq DESC) \
             SELECT 'fo:'||record_id||':'||(payload->>'key')||':'||as_of AS id,record_id COLLATE \"C\" AS record_id,payload->>'key' COLLATE \"C\" AS key, \
                    CASE WHEN type='facet.set' THEN payload->>'value' ELSE NULL END COLLATE \"C\" AS value, \
                    CASE WHEN type='facet.set' THEN 'set' ELSE 'unset' END COLLATE \"C\" AS op, \
                    CASE WHEN type='facet.set' THEN payload->>'vocab_ref' ELSE NULL END COLLATE \"C\" AS vocab_ref, \
                    as_of COLLATE \"C\" AS as_of,{observed_at} AS observed_at,{observed_at_ms} AS observed_at_ms,seq AS event_seq FROM corrected",
            observed_at = portable_ts("created_at"),
            observed_at_ms = portable_ts_ms("created_at"),
        ),
        format!(
            "CREATE TEMP VIEW bindings WITH (security_barrier=true) AS \
             SELECT binding.record_id COLLATE \"C\" AS record_id,binding.system COLLATE \"C\" AS system,binding.identifier COLLATE \"C\" AS identifier,CASE WHEN binding.is_canonical THEN 1 ELSE 0 END AS is_canonical,binding.url COLLATE \"C\" AS url,binding.etag COLLATE \"C\" AS etag,{last_seen_at} AS last_seen_at,{last_seen_at_ms} AS last_seen_at_ms \
             FROM {bindings} binding CROSS JOIN pg_temp._query_sql_principal principal \
             JOIN pg_temp._query_sql_visible_records visible ON visible.id=binding.record_id \
             WHERE binding.system IN ('account','email') AND EXISTS(SELECT 1 FROM {bindings} own WHERE own.record_id=binding.record_id AND own.system='account' AND own.identifier=principal.account_id AND own.is_canonical)",
            last_seen_at = portable_ts("binding.last_seen_at"),
            last_seen_at_ms = portable_ts_ms("binding.last_seen_at"),
        ),
        format!(
            "CREATE TEMP VIEW blobs WITH (security_barrier=true) AS \
             SELECT blob.id COLLATE \"C\" AS id,blob.bytes,blob.mime COLLATE \"C\" AS mime,blob.size_bytes,blob.sha256 COLLATE \"C\" AS sha256,blob.original_filename COLLATE \"C\" AS original_filename,blob.storage_tier COLLATE \"C\" AS storage_tier,blob.external_ref COLLATE \"C\" AS external_ref,{created_at} AS created_at,{created_at_ms} AS created_at_ms \
             FROM {blobs} blob WHERE EXISTS(SELECT 1 FROM {records} attachment \
               JOIN pg_temp._query_sql_visible_records attachment_visible ON attachment_visible.id=attachment.id \
               JOIN {facet_values} blob_ref ON blob_ref.record_id=attachment.id AND blob_ref.key='blob_ref' \
               JOIN {links} bearer ON bearer.source_id=attachment.id AND bearer.relationship='part_of' \
               JOIN pg_temp._query_sql_visible_records bearer_visible ON bearer_visible.id=bearer.target_id \
               WHERE attachment.record_type='Document' AND attachment.kind='attachment' \
                 AND jsonb_typeof(blob_ref.value)='string' AND blob_ref.value#>>'{{}}'=blob.id)",
            blobs=relations("blobs"),
            facet_values=relations("facet_values"),
            created_at=portable_ts("blob.created_at"),
            created_at_ms=portable_ts_ms("blob.created_at"),
        ),
        format!(
            "CREATE TEMP VIEW vocabularies WITH (security_barrier=true) AS SELECT id COLLATE \"C\" AS id,name COLLATE \"C\" AS name,{created_at} AS created_at,{created_at_ms} AS created_at_ms FROM {vocabularies}",
            created_at=portable_ts("created_at"),
            created_at_ms=portable_ts_ms("created_at"),
        ),
        format!("CREATE TEMP VIEW vocabulary_values WITH (security_barrier=true) AS SELECT id COLLATE \"C\" AS id,vocabulary_id COLLATE \"C\" AS vocabulary_id,value COLLATE \"C\" AS value,gloss COLLATE \"C\" AS gloss,status COLLATE \"C\" AS status,ordinal,terminality COLLATE \"C\" AS terminality,metadata,alias_of COLLATE \"C\" AS alias_of FROM {vocabulary_values}"),
        format!(
            "CREATE TEMP VIEW schema_config WITH (security_barrier=true) AS SELECT config.id COLLATE \"C\" AS id,config.layer COLLATE \"C\" AS layer,config.name COLLATE \"C\" AS name,config.data COLLATE \"C\" AS data,config.applies_to_collection_id COLLATE \"C\" AS applies_to_collection_id,config.version_lineage COLLATE \"C\" AS version_lineage,{created_at} AS created_at,{created_at_ms} AS created_at_ms FROM {schema_config} config WHERE config.applies_to_collection_id IS NULL OR EXISTS(SELECT 1 FROM pg_temp._query_sql_visible_records visible WHERE visible.id=config.applies_to_collection_id)",
            created_at=portable_ts("config.created_at"),
            created_at_ms=portable_ts_ms("config.created_at"),
        ),
    ];
    // Served catalog views, generated from LOGICAL_RELATIONS so Postgres
    // returns the same rows every other engine serves. Static metadata
    // needs no security barrier and no collation override: agents order by
    // the integer `column_position`, and equality filters are
    // collation-neutral.
    statements.extend(sql_contract::catalog_view_statements(false));
    Ok(statements)
}

/// Portable value-model encoding for Postgres `numeric` results
/// (E1 M1 slice B). Stored numerics in the catalog are already doubles,
/// so only computed values (notably `avg`/`sum`/`round`) take this path:
/// - integer-valued numerics that fit in i64 encode as JSON integers, so
///   `sum()` over integers matches SQLite's integer sum exactly;
/// - integer-valued numerics outside the i64 range are refused legibly,
///   never silently rounded (2^53 would already lose precision as f64);
/// - non-integral numerics encode as finite doubles, matching `avg()` on
///   every engine; non-finite or out-of-double-range values are refused.
fn numeric_cell(number: &BigDecimal) -> Result<Value> {
    let normalized = number.normalized();
    let text = normalized.to_string();
    if matches!(text.as_str(), "NaN" | "Infinity" | "-Infinity") {
        return Err(reject(
            QuerySqlErrorCategory::SyntaxOrType,
            "non-finite numeric result",
        ));
    }
    if normalized.is_integer() {
        // `{:.0}` renders the exact plain integer (never exponent form),
        // which `parse` then bounds-checks against i64.
        match format!("{normalized:.0}").parse::<i64>() {
            Ok(int) => return Ok(Value::from(int)),
            Err(_) => {
                return Err(reject(
                    QuerySqlErrorCategory::SyntaxOrType,
                    "integer numeric result is outside the i64 range; narrow the aggregation",
                ));
            }
        }
    }
    let value: f64 = text.parse().map_err(|_| {
        reject(
            QuerySqlErrorCategory::SyntaxOrType,
            "numeric result is not a finite decimal",
        )
    })?;
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .ok_or_else(|| {
            reject(
                QuerySqlErrorCategory::SyntaxOrType,
                "numeric result is outside the JSON number range",
            )
        })
}

/// Portable value-model encoding for Postgres `bool` results (E1 M2,
/// Option N). SQLite and Turso surface comparison results as integers
/// (`1`/`0`), while Postgres decodes them as JSON booleans, so the
/// encoder normalises here: `true`/`false` become `1`/`0`. This extends
/// the E1 M1 catalog 0/1 casts (e.g. `bindings.is_canonical`) from stored
/// columns to computed expressions. `NULL` never reaches this path —
/// `row_cell` returns `Value::Null` for null cells above.
fn bool_cell(value: bool) -> Value {
    Value::from(i64::from(value))
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
        "bool" => bool_cell(row.try_get(index)?),
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
        "numeric" => numeric_cell(&row.try_get(index)?)?,
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
            // Fixed UTC millis, matching the catalog views (E1 M1 slice B).
            // Computed timestamps take the same shape; sub-millisecond
            // precision is truncated, never rounded.
            row.try_get::<DateTime<Utc>, _>(index)?
                .to_rfc3339_opts(SecondsFormat::Millis, true),
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
        sqlx::query("INSERT INTO pg_temp._query_sql_principal VALUES(true,$1,$2,$3)")
            .bind(principal.credential().to_string())
            .bind(principal.trusted_local_bypass())
            .bind(principal.is_member())
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
        // REPEATABLE READ pins one snapshot for every statement below, so
        // the freshness stamp and the caller rows cannot straddle a
        // concurrent commit. READ ONLY keeps the serialization guarantee
        // free: a read-only transaction can never fail with a serialization
        // error on SELECTs.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
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
        // Freshness stamp (E1 M1 slice A): the workspace content head, read
        // as the owning runtime role before SET LOCAL ROLE drops to the
        // least-privilege query role, which can see only the temp-schema
        // projection and never the physical log. Schema-qualified on
        // purpose: the bare name would resolve to the caller-filtered temp
        // view. Hidden writes advance this head.
        //
        // Snapshot placement: SET and SET LOCAL take no snapshot, so under
        // REPEATABLE READ this SELECT is the transaction's first
        // snapshot-taking statement — the snapshot it establishes is the one
        // the caller statement below shares. A write committed after it is
        // invisible to both.
        let events_table = format!("{}.\"content_events\"", quote_identifier(db.schema())?);
        let as_of_seq: i64 =
            sqlx::query_scalar(&format!("SELECT COALESCE(MAX(seq),0) FROM {events_table}"))
                .fetch_one(&mut *transaction)
                .await?;
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
            .map_err(|error| type_check_error(error, &statement))?;
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
            // 57014 is query_canceled for statement, lock and idle timeouts
            // alike: match the text too, so a 250ms lock timeout is never
            // reported as the 2000ms governed deadline.
            let text = error.to_string();
            let canceled = match &error {
                sqlx::Error::Database(database) => database.code().as_deref() == Some("57014"),
                _ => false,
            };
            if canceled && text.contains("statement timeout") {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::Timeout,
                    sql_contract::deadline_hint(),
                )
            } else if canceled && text.contains("lock timeout") {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::Timeout,
                    "PostgreSQL canceled the statement on a lock timeout; \
                     retry the read once the conflicting writer commits.",
                )
            } else {
                reject(
                    QuerySqlErrorCategory::SyntaxOrType,
                    "PostgreSQL query execution failed",
                )
            }
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
            truncation_hint: sql_contract::truncation_hint_for(truncated),
            as_of_seq,
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

    #[test]
    fn numeric_encoder_keeps_integers_exact_and_refuses_unrepresentable() {
        use std::str::FromStr;
        // sum() over integers: exact JSON integer, matching SQLite.
        assert_eq!(
            numeric_cell(&BigDecimal::from(100)).unwrap(),
            serde_json::json!(100)
        );
        // 2^53+1 is exactly representable as i64 but not as f64: the
        // integer path must keep it exact rather than rounding it away.
        assert_eq!(
            numeric_cell(&BigDecimal::from(9007199254740993_i64)).unwrap(),
            serde_json::json!(9007199254740993_i64)
        );
        // i64::MAX+1 is refused legibly instead of silently rounding.
        let overflow = numeric_cell(&(BigDecimal::from(i64::MAX) + BigDecimal::from(1)))
            .unwrap_err()
            .to_string();
        assert!(
            overflow.contains("outside the i64 range"),
            "unexpected refusal: {overflow}"
        );
        // Non-integral numerics (notably avg()) encode as finite doubles.
        assert_eq!(
            numeric_cell(&BigDecimal::from_str("1.5").unwrap()).unwrap(),
            serde_json::json!(1.5)
        );
    }

    #[test]
    fn bool_encoder_normalises_to_zero_one() {
        // Computed comparisons (e.g. `SELECT id = 'x'`) must match
        // SQLite/Turso, which surface them as integers. NULL never
        // reaches bool_cell: row_cell returns Value::Null first.
        assert_eq!(bool_cell(true), serde_json::json!(1));
        assert_eq!(bool_cell(false), serde_json::json!(0));
    }

    #[tokio::test]
    async fn temp_view_ddl_has_no_uninterpolated_placeholders() {
        // No-server guard for the 42601 that broke every Postgres
        // query_sql: a verbatim `{events}` shipped when a qualified table
        // was passed as a plain literal into a helper instead of through
        // format!. Lazy pools never connect; rendering only reads the
        // schema name. The only legitimate braces in emitted DDL are the
        // `#>>'{}'` JSON operators.
        let lazy = || {
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://localhost:5432/test")
                .expect("lazy pool parses without connecting")
        };
        let db = PostgresDb {
            pool: lazy(),
            query_pool: lazy(),
            query_role: "test_query_role".to_string(),
            schema: "test_schema".to_string(),
            schema_tag: None,
            runtime: None,
            portability_policy_gate: std::sync::Arc::new(tokio::sync::RwLock::new(())),
            realtime_hub: std::sync::Arc::new(super::super::PostgresRealtimeHub::new()),
            #[cfg(feature = "postgres-tests")]
            intent_persist_checkpoint: std::sync::Arc::new(
                super::super::PostgresIntentPersistCheckpoint::default(),
            ),
            #[cfg(test)]
            request_lifecycle_test_bypass: false,
        };
        let statements = projection_statements(&db).expect("projection statements build");
        assert!(!statements.is_empty());
        for statement in &statements {
            let scrubbed = statement.replace("#>>'{}'", "");
            assert!(
                !scrubbed.contains('{') && !scrubbed.contains('}'),
                "uninterpolated placeholder in: {statement}"
            );
        }
    }

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
    fn widened_functions_validate_and_dropped_ones_name_the_repair() {
        // I2: the classifier rejects dropped names first with the shared
        // repair; the closed AST walk below is defence in depth. `~~`
        // (LIKE/ILIKE) is untouched — the ILIKE translation is I4.
        for sql in [
            "SELECT lower(name), upper(name) FROM records",
            "SELECT trim(name), replace(name, 'a', 'b') FROM records",
            // I2 review: two-argument `trim(x, chars)` desugars to
            // two-argument `pg_catalog.btrim`, matching SQLite exactly.
            "SELECT trim(name, 'x') FROM records",
            "SELECT substr(name, 1, 2) FROM records",
            "SELECT coalesce(name, 'z'), nullif(name, 'z') FROM records",
            "SELECT abs(id), length(name), round(1.5) FROM records",
            "SELECT avg(id), count(*), sum(id), min(id), max(id) FROM records",
            "SELECT rank() OVER (ORDER BY id) FROM records",
            "SELECT CASE WHEN id = 1 THEN 'one' ELSE 'other' END FROM records",
            "SELECT CAST(id AS TEXT) FROM records",
            "SELECT id FROM records WHERE name LIKE 'conf:%'",
        ] {
            validate(&request(sql)).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        for (sql, repair) in [
            (
                "SELECT instr(body, 'x') FROM records",
                "use substr() or LIKE",
            ),
            ("SELECT glob('*', name) FROM records", "use LIKE"),
            (
                "SELECT date(created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT json_type(body) FROM records",
                "facet_values, facet_observations",
            ),
            ("SELECT typeof(name) FROM records", "catalog column types"),
            (
                "SELECT group_concat(name) FROM records",
                "aggregate client-side",
            ),
            ("SELECT total(id) FROM records", "use sum"),
            ("SELECT floor(value) FROM records", "CAST(x AS INTEGER)"),
            ("SELECT char_length(name) FROM records", "use length"),
            ("SELECT greatest(a, b) FROM records", "CASE"),
            (
                "SELECT round(avg(id), 2) FROM records",
                "catalog numeric type",
            ),
            // I2 review: quoting the name bypasses nothing — the shared
            // classifier runs the same dropped-name and arity checks on
            // `"name"(` calls before the AST walk.
            (
                "SELECT \"round\"(1.5::float8, 2) FROM records",
                "catalog numeric type",
            ),
            (
                "SELECT \"instr\"(body, 'x') FROM records",
                "use substr() or LIKE",
            ),
        ] {
            let error = validate(&request(sql)).unwrap_err().to_string();
            assert!(error.contains(repair), "{sql}: missing repair: {error}");
        }
    }

    #[test]
    fn blocked_probes_name_the_catalog_fix() {
        let rendered = |sql: &str| validate(&request(sql)).unwrap_err().to_string();
        let probe = rendered("SELECT * FROM pg_catalog.pg_tables");
        assert!(probe.contains("catalog introspection"), "{probe}");
        let schema = rendered("SELECT * FROM information_schema.tables");
        assert!(schema.contains("catalog introspection"), "{schema}");
        let mapped = rendered("SELECT * FROM relationships");
        // effective_relationships is sqlite-only: Postgres falls through
        // to the profile-filtered list instead of mis-pointing at it.
        assert!(!mapped.contains("effective_relationships"), "{mapped}");
        assert!(
            mapped.contains("Queryable relations on postgres-server:"),
            "{mapped}"
        );
        assert!(!mapped.contains("agent_activity"), "{mapped}");
        let unmapped = rendered("SELECT * FROM member_contexts");
        assert!(
            unmapped.contains("Queryable relations on postgres-server:"),
            "{unmapped}"
        );
    }

    #[test]
    fn sanitize_type_message_keeps_first_line_and_scrubs_internals() {
        assert_eq!(
            sanitize_type_message("argument of WHERE must be type boolean, not type integer"),
            "argument of WHERE must be type boolean, not type integer"
        );
        assert_eq!(
            sanitize_type_message(
                "relation \"_query_sql_visible_records\" does not exist\nHINT: nope"
            ),
            "relation \"(internal relation)\" does not exist"
        );
        assert_eq!(
            sanitize_type_message("column _native_query.id does not exist"),
            "column (query).id does not exist"
        );
        assert_eq!(
            sanitize_type_message("x FROM pg_temp._query_sql_visible_records y"),
            "x FROM _query_sql_visible_records y"
                .replace("_query_sql_visible_records", "(internal relation)")
        );
        let long = "e".repeat(400);
        assert_eq!(sanitize_type_message(&long).len(), 300);
        assert_eq!(sanitize_type_message(""), "");
        // Redaction runs before the cap: a long internal token still fits.
        let padded = format!(
            "{}_query_sql_visible_records{}",
            "e".repeat(290),
            "e".repeat(50)
        );
        let capped = sanitize_type_message(&padded);
        assert!(capped.len() <= 300, "{capped}");
        assert!(!capped.contains("_query_sql_"), "{capped}");
        // Numbered temp schemas and blank first lines.
        assert_eq!(
            sanitize_type_message("x FROM pg_temp_3._query_sql_visible_records y"),
            "x FROM (internal relation) y"
        );
        assert_eq!(
            sanitize_type_message("\n  argument of WHERE must be type boolean"),
            "argument of WHERE must be type boolean"
        );
        // Caller literals are quoted text, not engine identifiers; an
        // unquoted pg_temp qualification is still scrubbed.
        assert_eq!(
            sanitize_type_message("value '_query_sql_foo' and pg_temp.bar"),
            "value '_query_sql_foo' and bar"
        );
        assert_eq!(
            sanitize_type_message("it''s _query_sql_foo"),
            "it''s (internal relation)"
        );
        // An apostrophe inside a double-quoted identifier must not flip the
        // literal state and suppress later redaction.
        assert_eq!(
            sanitize_type_message("column \"a'b\" does not exist and _query_sql_visible_records"),
            "column \"a'b\" does not exist and (internal relation)"
        );
        // A stray apostrophe with no closing quote falls back to scrubbing
        // the internal tokens everywhere rather than passing them through.
        assert_eq!(
            sanitize_type_message("o'brien _native_query _query_sql_x"),
            "o'brien (query) (internal relation)"
        );
    }

    #[test]
    fn caller_position_maps_wrapper_offsets_in_characters() {
        let statement = "SELECT id FROM records WHERE name = 'Äpfel' AND id = 1";
        // 'Ä' is 2 bytes but 1 character: byte math would overshoot.
        let char_len = statement.chars().count();
        assert!(statement.len() > char_len);
        // 1-based: first statement character sits at wrapper offset 16.
        assert_eq!(caller_position(16, statement), Some(1));
        assert_eq!(caller_position(15, statement), None);
        // One past the end (e.g. a problem at the closing paren) still maps.
        assert_eq!(
            caller_position(15 + char_len + 1, statement),
            Some(char_len + 1)
        );
        assert_eq!(caller_position(15 + char_len + 2, statement), None);
        // Position of the multibyte literal itself maps exactly.
        let literal_at = statement.find("Äpfel").unwrap();
        let literal_char = statement[..literal_at].chars().count() + 1;
        assert_eq!(
            caller_position(15 + statement[..literal_at].chars().count() + 1, statement),
            Some(literal_char)
        );
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
    fn dollar_placeholders_are_rejected_with_the_portable_repair() {
        // I1 (E1 M2): callers use `?N`; `$n` is not accepted from callers.
        // The exact `$n`-match check in `validate` stays as defence in depth
        // for the future `?N`-to-`$N` rewrite. A `$1` inside a string
        // literal is data and stays admitted.
        validate(&request("SELECT id FROM records WHERE name = '$1'")).unwrap();
        let bare = validate(&request("SELECT id FROM records WHERE id = ?"))
            .unwrap_err()
            .to_string();
        assert!(
            bare.contains("Postgres `?`/`?|`/`?&` operators"),
            "missing jsonb note: {bare}"
        );
        for sql in [
            "SELECT $1::text FROM records WHERE id=$2",
            "SELECT $2 FROM records",
            "SELECT id FROM records WHERE id = :name",
        ] {
            let error = validate(&request(sql)).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("use positional `?N` placeholders"),
                "{sql}: missing repair: {error}"
            );
        }
    }
}
