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

use super::determinism;
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

pub(crate) const SAFE_NODE_VARIANTS: &[&str] = &[
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
    // E1 M2 I6: name the valid columns when a known logical relation is
    // read with an unknown column (pg code 42703, undefined_column).
    // Rewords an already-rejected type-check; the shared contract repair
    // keeps the message identical on every engine by construction. The
    // extraction runs on the sanitised message so internal relation names
    // can never leak through the repair.
    if pg_error.code() == "42703" {
        if let Some(column) = sql_contract::unknown_column_in_detail(&message) {
            let scope = sql_contract::statement_scope(statement);
            let relations: Vec<&str> = sql_contract::resolve_column_scope(column.as_str(), &scope);
            if let Some(repair) = sql_contract::unknown_column_repair(
                column.as_str(),
                &relations,
                sql_contract::QuerySqlProfile::PostgresServer,
            ) {
                detail = sql_contract::join_detail_repair(&detail, &repair);
            }
        }
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
            // E1 M3: `regexp` lowers to `regexp_like(haystack, pattern)`
            // in determinism::normalise; the call must carry exactly two
            // arguments here too, mirroring the classifier arity repair.
            if names.len() == 1
                && names[0].eq_ignore_ascii_case("regexp")
                && fields.get("args").and_then(Value::as_array).map(Vec::len) != Some(2)
            {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    sql_contract::REGEXP_ARITY_REPAIR,
                ));
            }
            // Native e25665c: `utc_date_label(ms)` lowers to a
            // `to_timestamp`/`EXTRACT` expression after validation; the call
            // must carry exactly one argument here too, mirroring the
            // classifier arity repair.
            if names.len() == 1
                && names[0].eq_ignore_ascii_case("utc_date_label")
                && fields.get("args").and_then(Value::as_array).map(Vec::len) != Some(1)
            {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    sql_contract::UTC_DATE_LABEL_ARITY_REPAIR,
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

/// I3 (AST design): LIMIT, OFFSET and FETCH cut rows before any ordering,
/// so each needs ORDER BY in its own query level. The walk is generic over
/// the JSON tree (complete by construction): every SelectStmt with a set
/// `limit_count` (LIMIT/FETCH) or `limit_offset` (OFFSET) and an empty
/// `sort_clause` is rejected, at every nesting level.
fn reject_limit_without_order(root: &Value) -> Result<()> {
    if let Some(("SelectStmt", data)) = node_variant(root) {
        let fields = object(data, "SelectStmt")?;
        let ordered = fields
            .get("sort_clause")
            .and_then(Value::as_array)
            .is_some_and(|clause| !clause.is_empty());
        let limited = ["limit_count", "limit_offset"]
            .iter()
            .any(|key| fields.get(*key).is_some_and(|value| !value.is_null()));
        if limited && !ordered {
            return Err(reject(
                QuerySqlErrorCategory::UnsafeStatement,
                "LIMIT without ORDER BY: add ORDER BY over a unique key",
            ));
        }
    }
    match root {
        Value::Array(values) => {
            for value in values {
                reject_limit_without_order(value)?;
            }
        }
        Value::Object(fields) => {
            for value in fields.values() {
                reject_limit_without_order(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// E2 ad-hoc default ORDER BY gate: true when the parse root is a plain
/// LIMIT (not FETCH, not bare OFFSET) with no ORDER BY. Runs on the `$N`
/// execution spelling. The AST limbs confirm a row limit with no sort;
/// the lexical limb confirms a LIMIT clause word, which is what excludes
/// FETCH (Postgres parses both to a set `limit_count`, so the AST alone
/// cannot tell them apart — verified by unit test). Parse failures and all
/// other shapes return false so `validate()` decides exactly as today.
fn top_level_unordered_limit(statement: &str) -> bool {
    use pg_query::protobuf::node::Node as NodeVariant;
    let parsed = match pg_query::parse(statement) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    if parsed.protobuf.stmts.len() != 1 {
        return false;
    }
    let Some(root) = parsed
        .protobuf
        .stmts
        .first()
        .and_then(|raw| raw.stmt.as_ref())
    else {
        return false;
    };
    let Some(NodeVariant::SelectStmt(select)) = root.node.as_ref() else {
        return false;
    };
    select.limit_count.is_some()
        && select.sort_clause.is_empty()
        && sql_contract::has_top_level_limit(
            sql_contract::QuerySqlProfile::PostgresServer,
            statement,
        )
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
    // E1 M3: bound `?N` regexp patterns meet the same subset and cap as
    // literals. Runs on the caller's `?N` text: the `$N` rewrite below is
    // execution spelling, never a second validation surface.
    sql_contract::validate_regexp_bound_patterns(
        sql_contract::QuerySqlProfile::PostgresServer,
        &statement,
        &request.parameters,
    )?;
    // Native e25665c: bound `?N` label arguments meet the integer contract.
    // Runs on the caller's `?N` text alongside the regexp check above.
    sql_contract::validate_utc_date_label_bound_args(
        sql_contract::QuerySqlProfile::PostgresServer,
        &statement,
        &request.parameters,
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
    let mut parsed = pg_query::parse(&statement).map_err(|_| {
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
    reject_limit_without_order(root)?;
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
    // I3 (AST design): the admitted checks above ran on the rewritten text;
    // normalise determinism on the typed tree (explicit NULLS ordering,
    // NULLIF zero-divisor guards) and execute the deparsed SQL — or the
    // input verbatim when there was nothing to normalise. SQLite and
    // Turso already carry the target semantics, so their text is untouched.
    if determinism::normalise(&mut parsed.protobuf)? {
        determinism::deparse(&parsed.protobuf)
    } else {
        Ok(statement)
    }
}

/// Admission has already rejected shadowing of logical relation names. Read
/// dependencies from the parsed tree so a string/comment cannot trigger the
/// expensive caller-relative projection or a different transaction mode.
fn uses_lifecycle_relation(statement: &str) -> Result<bool> {
    fn contains_relation(node: &Value) -> bool {
        if let Some(("RangeVar", data)) = node_variant(node) {
            if data.get("relname").and_then(Value::as_str)
                == Some("record_lifecycle_interpretations")
            {
                return true;
            }
        }
        match node {
            Value::Array(items) => items.iter().any(contains_relation),
            Value::Object(fields) => fields.values().any(contains_relation),
            _ => false,
        }
    }
    let parsed = pg_query::parse(statement).map_err(|_| {
        reject(
            QuerySqlErrorCategory::Engine,
            "could not inspect admitted PostgreSQL SQL",
        )
    })?;
    let tree = serde_json::to_value(&parsed.protobuf).map_err(|_| {
        reject(
            QuerySqlErrorCategory::Engine,
            "could not inspect admitted PostgreSQL AST",
        )
    })?;
    Ok(contains_relation(&tree))
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
    let body_task_items = relations("body_task_items");
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
        "CREATE TEMP TABLE _query_sql_lifecycle_interpretations(\
           record_id text PRIMARY KEY,status text NOT NULL,raw text,axis_key text,axis_label text,\
           vocabulary_id text,vocabulary_name text,value_id text,canonical text,terminality text,reason text)".into(),
        "CREATE TEMP VIEW record_lifecycle_interpretations WITH (security_barrier=true) AS \
           SELECT record_id COLLATE \"C\" AS record_id,status COLLATE \"C\" AS status,\
                  raw COLLATE \"C\" AS raw,axis_key COLLATE \"C\" AS axis_key,\
                  axis_label COLLATE \"C\" AS axis_label,vocabulary_id COLLATE \"C\" AS vocabulary_id,\
                  vocabulary_name COLLATE \"C\" AS vocabulary_name,value_id COLLATE \"C\" AS value_id,\
                  canonical COLLATE \"C\" AS canonical,terminality COLLATE \"C\" AS terminality,\
                  reason COLLATE \"C\" AS reason \
             FROM pg_temp._query_sql_lifecycle_interpretations WHERE record_id IS NOT NULL".into(),
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
                    CASE WHEN record.is_current IS NULL THEN NULL WHEN record.is_current THEN 1 ELSE 0 END AS is_current, \
                    record.successor_count AS successor_count, \
                    {last_activity_at} AS last_activity_at, {last_activity_at_ms} AS last_activity_at_ms, \
                    {record_created_at} AS created_at, {record_created_at_ms} AS created_at_ms, \
                    {record_updated_at} AS updated_at, {record_updated_at_ms} AS updated_at_ms, \
                    {deleted_at} AS deleted_at, {deleted_at_ms} AS deleted_at_ms, \
                    CASE WHEN record.archived THEN 1 ELSE 0 END AS archived \
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
        // Claim-shape is key existence, not a non-null value: `get_history`
        // treats `{"claimed_by_account": null}` as claim-shaped
        // (`.get(..).is_some()`), and `->>` would return SQL NULL for that
        // JSON null and disclose the run. `payload` is JSONB, so `?` tests
        // existence exactly.
        format!(
            "CREATE TEMP VIEW content_events WITH (security_barrier=true) AS \
             SELECT event.seq AS local_seq,event.id COLLATE \"C\" AS id,event.record_id COLLATE \"C\" AS record_id, \
                    CASE WHEN event.type='receipt.committed.v1' THEN 'record.updated' ELSE event.type END COLLATE \"C\" AS type, \
                    CASE WHEN principal.trusted_local_bypass \
                              OR event.actor=principal.account_id \
                              OR EXISTS(SELECT 1 FROM {bindings} actor_binding \
                                         JOIN pg_temp._query_sql_visible_records person_visible ON person_visible.id=actor_binding.record_id \
                                         WHERE actor_binding.system='account' AND actor_binding.identifier=event.actor) \
                         THEN event.actor ELSE NULL END COLLATE \"C\" AS actor, \
                    CASE WHEN (principal.trusted_local_bypass \
                              OR event.actor=principal.account_id \
                              OR EXISTS(SELECT 1 FROM {bindings} actor_binding \
                                         JOIN pg_temp._query_sql_visible_records person_visible ON person_visible.id=actor_binding.record_id \
                                         WHERE actor_binding.system='account' AND actor_binding.identifier=event.actor)) \
                               AND (principal.trusted_local_bypass \
                                    OR NOT (((event.payload ? 'claimed_by_account') \
                                              OR (event.payload ? 'claimed_run_key') \
                                              OR (event.payload ? 'released_from_run_key')) \
                                            AND event.actor IS DISTINCT FROM principal.account_id)) \
                         THEN event.run_key ELSE NULL END COLLATE \"C\" AS run_key, \
                    CASE WHEN (principal.trusted_local_bypass \
                              OR event.actor=principal.account_id \
                              OR EXISTS(SELECT 1 FROM {bindings} actor_binding \
                                         JOIN pg_temp._query_sql_visible_records person_visible ON person_visible.id=actor_binding.record_id \
                                         WHERE actor_binding.system='account' AND actor_binding.identifier=event.actor)) \
                               AND (principal.trusted_local_bypass \
                                    OR NOT (((event.payload ? 'claimed_by_account') \
                                              OR (event.payload ? 'claimed_run_key') \
                                              OR (event.payload ? 'released_from_run_key')) \
                                            AND event.actor IS DISTINCT FROM principal.account_id)) \
                         THEN event.parent_key ELSE NULL END COLLATE \"C\" AS parent_key, \
                    CASE WHEN principal.trusted_local_bypass \
                              OR event.actor=principal.account_id \
                              OR EXISTS(SELECT 1 FROM {bindings} actor_binding \
                                         JOIN pg_temp._query_sql_visible_records person_visible ON person_visible.id=actor_binding.record_id \
                                         WHERE actor_binding.system='account' AND actor_binding.identifier=event.actor) \
                         THEN 'unknown' ELSE NULL END COLLATE \"C\" AS channel_kind, \
                    {created_at} AS created_at, {created_at_ms} AS created_at_ms FROM {events} event \
             CROSS JOIN pg_temp._query_sql_principal principal \
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
        // Match SQLite/Turso's integer flags and withhold event provenance.
        // The security barrier and visible-record join keep physical rows
        // outside the caller's policy scope from reaching governed SQL.
        format!(
            "CREATE TEMP VIEW body_task_items WITH (security_barrier=true) AS \
             SELECT task.record_id COLLATE \"C\" AS record_id, task.item_index, \
                    task.marker COLLATE \"C\" AS marker, \
                    CASE WHEN task.checked THEN 1 ELSE 0 END AS checked, \
                    CASE WHEN task.in_quote THEN 1 ELSE 0 END AS in_quote, \
                    task.start_offset, task.end_offset \
             FROM {body_task_items} task \
             JOIN pg_temp._query_sql_visible_records visible ON visible.id=task.record_id"
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
            format!(
                "a cell exceeds the encoded byte limit.{}",
                sql_contract::projection_cell_cap_repair()
            ),
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

const MAX_LIFECYCLE_VISIBLE_RECORDS: i64 = 20_000;

/// Stage only the rows the caller could already read. The physical record
/// carrier, filtered schema and vocabulary index are all read from the same
/// REPEATABLE READ snapshot that supplies `as_of_seq` and caller SQL.
async fn populate_lifecycle_interpretations(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    db: &PostgresDb,
) -> Result<()> {
    use crate::query::lifecycle::{LifecycleInterpretation, LifecycleInterpreter};
    // Each live record resolves through one bearer chain. Stop after the
    // first over-cap row rather than counting an arbitrarily large workspace.
    let visible_count: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM (SELECT id FROM pg_temp._query_sql_visible_records LIMIT {}) bounded",
        MAX_LIFECYCLE_VISIBLE_RECORDS + 1,
    ))
    .fetch_one(&mut **transaction)
    .await?;
    if visible_count > MAX_LIFECYCLE_VISIBLE_RECORDS {
        return Err(reject(
            QuerySqlErrorCategory::ResultTooLarge,
            format!(
                "record_lifecycle_interpretations requires materializing at least {visible_count} visible records, above its {MAX_LIFECYCLE_VISIBLE_RECORDS}-record limit; use get_record for a specific record"
            ),
        ));
    }
    let interpreter = {
        let mut executor =
            crate::portable_sql::BorrowedPostgresStatementExecutor::new(transaction, "pg_temp");
        // The caller-filtered TEMP schema_config view already applies the same
        // visible bearer fence as the relation. Do not resolve hidden anchors via
        // an unfiltered physical catalog.
        let schema_rows = crate::query::cascade::schema_config_rows_with(&mut executor).await?;
        LifecycleInterpreter::load_from_rows_with(&mut executor, schema_rows).await?
    };

    let records = db.qualified_table("records")?;
    let rows = sqlx::query(&format!(
        "SELECT DISTINCT r.id,r.record_type,r.kind,r.home_id,r.lifecycle \
           FROM {records} r JOIN pg_temp._query_sql_visible_records visible ON visible.id=r.id \
          ORDER BY r.id,r.record_type,r.kind,r.home_id,r.lifecycle"
    ))
    .fetch_all(&mut **transaction)
    .await?;
    let mut staged = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id")?;
        let record_type: String = row.try_get("record_type")?;
        let kind: String = row.try_get("kind")?;
        let home_id: Option<String> = row.try_get("home_id")?;
        let lifecycle: Option<String> = row.try_get("lifecycle")?;
        let (
            status,
            raw,
            axis_key,
            axis_label,
            vocabulary_id,
            vocabulary_name,
            value_id,
            canonical,
            terminality,
            reason,
        ) = match interpreter.interpret(
            &record_type,
            Some(&kind),
            home_id.as_deref(),
            lifecycle.as_deref(),
        ) {
            LifecycleInterpretation::Governed(value) => (
                "governed",
                Some(value.value.raw),
                Some(value.axis.key),
                Some(value.axis.label),
                Some(value.vocabulary.id),
                Some(value.vocabulary.name),
                Some(value.value.id),
                Some(value.value.canonical),
                Some(value.terminality),
                None,
            ),
            LifecycleInterpretation::Absent(value) => (
                "absent",
                None,
                value.axis.as_ref().map(|axis| axis.key.clone()),
                value.axis.map(|axis| axis.label),
                value
                    .vocabulary
                    .as_ref()
                    .map(|vocabulary| vocabulary.id.clone()),
                value.vocabulary.map(|vocabulary| vocabulary.name),
                None,
                None,
                None,
                None,
            ),
            LifecycleInterpretation::Unclassified(value) => (
                "unclassified",
                Some(value.raw),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(value.reason.to_owned()),
            ),
        };
        staged.push((
            id,
            status,
            raw,
            axis_key,
            axis_label,
            vocabulary_id,
            vocabulary_name,
            value_id,
            canonical,
            terminality,
            reason,
        ));
    }
    // Networked PostgreSQL needs bounded multi-row statements here: one
    // round trip per visible record would turn the 20k admission cap into
    // an unbounded preparation delay. 256 rows use only 2,816 binds.
    for batch in staged.chunks(256) {
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO pg_temp._query_sql_lifecycle_interpretations \
             (record_id,status,raw,axis_key,axis_label,vocabulary_id,vocabulary_name, \
              value_id,canonical,terminality,reason) ",
        );
        builder.push_values(batch, |mut values, row| {
            values
                .push_bind(row.0.as_str())
                .push_bind(row.1)
                .push_bind(row.2.as_deref())
                .push_bind(row.3.as_deref())
                .push_bind(row.4.as_deref())
                .push_bind(row.5.as_deref())
                .push_bind(row.6.as_deref())
                .push_bind(row.7.as_deref())
                .push_bind(row.8.as_deref())
                .push_bind(row.9.as_deref())
                .push_bind(row.10.as_deref());
        });
        builder.build().execute(&mut **transaction).await?;
    }
    Ok(())
}

/// Ad-hoc `query_sql` entry: the server default ORDER BY is enabled, so an
/// unordered top-level LIMIT executes disclosed instead of refusing. The
/// only caller is the Postgres MCP handler; test qualification below
/// enables it explicitly for the same reason.
pub async fn query_sql_request_owned(
    db: PostgresDb,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<QuerySqlResult> {
    sql_contract::require_available(sql_contract::QuerySqlProfile::PostgresServer)?;
    execute_qualified(db, principal, request, None, true).await
}

#[cfg(feature = "postgres-tests")]
pub async fn qualification_query_sql(
    db: PostgresDb,
    principal: impl Into<QueryPrincipal>,
    request: QuerySqlRequest,
) -> Result<QuerySqlResult> {
    // Ad-hoc-equivalent execution for conformance/qualification: the
    // default is on, like the MCP entry above.
    execute_qualified(db, principal.into(), request, None, true).await
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
    execute_qualified(db, principal.into(), request, Some(backend_pid), false).await
}

async fn execute_qualified(
    db: PostgresDb,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    mut backend_pid: Option<tokio::sync::oneshot::Sender<i32>>,
    apply_default_order: bool,
) -> Result<QuerySqlResult> {
    // E1 M3: every `now_ms()` becomes one hidden positional
    // (`?{parameters.len() + 1}`) before anything else runs. The exact-set
    // check on the caller text refuses any caller use of that index, so the
    // hidden value is unspoofable; every use shares it. The AST walk below
    // then sees only `$N` parameters, never the function name, so no
    // allowlist or determinism change is needed on this path. The value is
    // captured here at admission; rows and `as_of_seq` still share one
    // REPEATABLE READ snapshot below (the clock itself is not snapshot
    // data).
    request.validate()?;
    let classified = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::PostgresServer,
        &request.sql,
    )?;
    sql_contract::validate_regexp_bound_patterns(
        sql_contract::QuerySqlProfile::PostgresServer,
        &classified,
        &request.parameters,
    )?;
    // Native e25665c: bound `?N` label arguments meet the integer contract
    // (mirrors validate()'s check below, which re-runs after the clock
    // rewrite; both see `?N` text).
    sql_contract::validate_utc_date_label_bound_args(
        sql_contract::QuerySqlProfile::PostgresServer,
        &classified,
        &request.parameters,
    )?;
    let hidden_index = request.parameters.len() + 1;
    let (rewritten, now_ms_uses) = sql_contract::rewrite_now_ms_calls(
        sql_contract::QuerySqlProfile::PostgresServer,
        &classified,
        &format!("?{hidden_index}"),
    )?;
    // The caller-text check is needed only when adding the hidden bind.
    // Clock-free statements retain validate()'s existing PostgreSQL `$n`
    // mismatch repair, which is part of that adapter's public contract.
    if now_ms_uses > 0 {
        sql_contract::check_positional_arguments(
            sql_contract::QuerySqlProfile::PostgresServer,
            &classified,
            request.parameters.len(),
        )?;
    }
    let time_dependent = now_ms_uses > 0;
    let now_ms_ms: Option<i64> = time_dependent.then(|| chrono::Utc::now().timestamp_millis());
    let mut effective_parameters = request.parameters.clone();
    if let Some(now_ms) = now_ms_ms {
        effective_parameters.push(sql_contract::QuerySqlParameter::Integer {
            value: Some(now_ms.to_string()),
        });
    }
    let request = QuerySqlRequest {
        sql: rewritten,
        parameters: effective_parameters,
    };
    // E2 ad-hoc default ORDER BY: an unordered top-level LIMIT is spliced
    // after label discovery inside the transaction below (describe-only
    // prepare); the full validation then runs on the rewritten text, so
    // nested unordered LIMITs keep their refusal. All other statements
    // validate here unchanged. The pre-validation error travels along: a
    // failed describe falls back to exactly today's refusal.
    enum Validated {
        Ready(String),
        SpliceOr { error: Error, pg_spelling: String },
    }
    // E2 ad-hoc default ORDER BY: enabled only when the caller passes
    // `apply_default_order` (the ad-hoc entry and test qualification do;
    // every other caller leaves it off). Otherwise validation runs here
    // exactly as before, with no deferral.
    let validated = if !apply_default_order {
        Validated::Ready(validate(&request)?)
    } else {
        match validate(&request) {
            Ok(statement) => Validated::Ready(statement),
            Err(error) => {
                let pg_spelling = sql_contract::classify_single_read_statement(
                    sql_contract::QuerySqlProfile::PostgresServer,
                    &request.sql,
                )
                .and_then(|classified| {
                    sql_contract::rewrite_placeholders_for_postgres(
                        sql_contract::QuerySqlProfile::PostgresServer,
                        &classified,
                    )
                })
                .ok()
                .filter(|pg_spelling| top_level_unordered_limit(pg_spelling));
                match pg_spelling {
                    Some(pg_spelling) => Validated::SpliceOr { error, pg_spelling },
                    None => return Err(error),
                }
            }
        }
    };
    // Native e25665c: `utc_date_label(ms)` is lowered to the Postgres
    // `to_timestamp`/`EXTRACT` expression inside the transaction below,
    // after validation (the validator sees the portable name). It runs on
    // the validated text whether validation happened above or, for the
    // E2 default, on the spliced text after describe.
    let needs_lifecycle = match &validated {
        Validated::Ready(statement) => uses_lifecycle_relation(statement)?,
        Validated::SpliceOr { pg_spelling, .. } => uses_lifecycle_relation(pg_spelling)?,
    };

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
        // concurrent commit. Only lifecycle-dependent statements require a
        // write-capable transaction to stage TEMP rows after pinning the
        // snapshot. Caller SQL still runs with the SELECT-only query role.
        let isolation = if needs_lifecycle {
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
        } else {
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        };
        sqlx::query(isolation).execute(&mut *transaction).await?;
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
        if needs_lifecycle {
            populate_lifecycle_interpretations(&mut transaction, &db).await?;
        }
        // JIT startup can consume the two-second governed read budget. Disable
        // it before caller planning, after freshness and lifecycle staging;
        // LOCAL restores the session setting when the transaction ends.
        transaction.execute("SET LOCAL jit=off").await?;
        transaction
            .execute(format!("SET LOCAL ROLE {query_role}").as_str())
            .await?;
        if let Some(backend_pid) = backend_pid.take() {
            let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *transaction)
                .await?;
            let _ = backend_pid.send(pid);
        }
        let types = parameter_types(&request.parameters);
        // E2 ad-hoc default ORDER BY (deferred from above): describe labels
        // with a prepare-only round trip, splice `ORDER BY 1, .., n`, and
        // run the full validation on the rewritten text. A failed describe
        // or a lexical miss falls back to the pre-validation refusal, so
        // non-spliceable defects keep exactly today's error.
        let mut assumed_order = None;
        let statement = match validated {
            Validated::Ready(statement) => statement,
            Validated::SpliceOr { error, pg_spelling } => {
                let labels = match transaction.prepare_with(&pg_spelling, &types).await {
                    Ok(described) => described
                        .columns()
                        .iter()
                        .map(|column| column.name().to_owned())
                        .collect::<Vec<_>>(),
                    Err(_) => return Err(error),
                };
                match sql_contract::apply_default_order(
                    sql_contract::QuerySqlProfile::PostgresServer,
                    &pg_spelling,
                    &labels,
                ) {
                    Some((rewritten, assumed)) => {
                        assumed_order = Some(assumed);
                        validate(&QuerySqlRequest {
                            sql: rewritten,
                            parameters: request.parameters.clone(),
                        })?
                    }
                    None => return Err(error),
                }
            }
        };
        // Native e25665c: lower `utc_date_label(ms)` to the Postgres
        // `to_timestamp`/`EXTRACT` expression now that the text is
        // validated. The lowering introduces no placeholder and exposes no
        // engine clock; the validated `$N` placeholders survive verbatim
        // inside the embedded argument.
        let (statement, _) = sql_contract::rewrite_utc_date_label_calls(
            sql_contract::QuerySqlProfile::PostgresServer,
            &statement,
            sql_contract::UtcDateLabelEngine::Postgres,
        )?;
        let capped = format!(
            "SELECT * FROM ({statement}) AS _native_query LIMIT {}",
            MAX_ROWS + 1
        );
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
            now_ms_ms,
            time_dependent,
            assumed_order,
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

    /// Normalise via the real entry point (parse → checks → normalise →
    /// deparse) on `$N`-rewritten text, mirroring `validate()` order.
    fn normalised(sql: &str) -> String {
        let mut parsed = pg_query::parse(sql).expect("spike input must parse");
        determinism::normalise(&mut parsed.protobuf).expect("normalise");
        let out = determinism::deparse(&parsed.protobuf).expect("deparse");
        pg_query::parse(&out).expect("deparsed SQL must re-parse");
        out
    }

    #[test]
    fn mutator_covers_allowlist() {
        // Fail loudly if SAFE_NODE_VARIANTS ever grows without the mutator:
        // every allowlisted variant is either recursed or a leaf.
        for variant in SAFE_NODE_VARIANTS {
            assert!(
                determinism::MUTATOR_HANDLED.contains(variant)
                    || determinism::MUTATOR_LEAF.contains(variant),
                "mutator has no classification for allowlisted {variant}"
            );
        }
    }

    #[test]
    fn normalise_reports_change_accurately() {
        // The changed flag decides deparse-vs-verbatim in validate(): a
        // missed flag ships un-normalised SQL to Postgres (division by zero
        // errors instead of yielding NULL).
        let changed = |sql: &str| {
            let mut parsed = pg_query::parse(sql).unwrap();
            determinism::normalise(&mut parsed.protobuf).unwrap()
        };
        for sql in [
            "SELECT a FROM t ORDER BY a",
            "SELECT a FROM t ORDER BY a DESC",
            "SELECT a / b FROM t",
            "SELECT 1 / 0 FROM t",
            "SELECT a % b FROM t",
            // I4: LIKE normalises to ILIKE on Postgres (case-insensitive
            // on every engine); already-ILIKE is clean. F1/F2: the direct
            // operator spellings (`~~`, ANY/ALL, subquery sublinks) report
            // change too; their ILIKE spellings stay verbatim.
            "SELECT a FROM t WHERE a LIKE 'x'",
            "SELECT a FROM t WHERE a NOT LIKE 'x'",
            "SELECT a FROM t WHERE a ~~ 'x'",
            "SELECT a FROM t WHERE a !~~ 'x'",
            "SELECT a FROM t WHERE a OPERATOR(~~) 'x'",
            "SELECT a FROM t WHERE a LIKE ANY (ARRAY['x'])",
            "SELECT a FROM t WHERE a NOT LIKE ALL (ARRAY['x'])",
            "SELECT a FROM t WHERE a LIKE ANY (SELECT b FROM u)",
        ] {
            assert!(changed(sql), "should report change: {sql}");
        }
        for sql in [
            "SELECT a FROM t ORDER BY a NULLS LAST",
            "SELECT id FROM t ORDER BY x USING >",
            "SELECT a / NULLIF(b, 0) FROM t",
            "SELECT a FROM t",
            "SELECT a FROM t WHERE a ILIKE 'x'",
            "SELECT a FROM t WHERE a NOT ILIKE 'x'",
            "SELECT a FROM t WHERE a ~~* 'x'",
            "SELECT a FROM t WHERE a !~~* 'x'",
            "SELECT a FROM t WHERE a ILIKE ANY (ARRAY['x'])",
            "SELECT a FROM t WHERE a NOT ILIKE ALL (SELECT b FROM u)",
        ] {
            assert!(!changed(sql), "should report clean: {sql}");
        }
    }

    #[test]
    fn nullif_wrapper_uses_postgres_own_aexpr_shape() {
        // A hand-built FuncCall SIGABRTs deparse; the wrapper must be
        // A_Expr{kind: Nullif, name: ["="]} exactly as pg parses NULLIF.
        let mut parsed = pg_query::parse("SELECT a / b FROM t").unwrap();
        determinism::normalise(&mut parsed.protobuf).unwrap();
        let tree = serde_json::to_value(&parsed.protobuf).unwrap();
        let divide = &tree["stmts"][0]["stmt"]["node"]["SelectStmt"]["target_list"][0]["node"]
            ["ResTarget"]["val"]["node"]["AExpr"];
        assert_eq!(divide["kind"], 1);
        let rexpr = &divide["rexpr"]["node"]["AExpr"];
        assert_eq!(rexpr["kind"], 6);
        assert_eq!(rexpr["name"][0]["node"]["String"]["sval"], "=");
        assert_eq!(rexpr["rexpr"]["node"]["AConst"]["val"]["Ival"]["ival"], 0);
    }

    #[test]
    fn limit_offset_fetch_require_order_by_at_every_level() {
        // I3 (AST design, F9): LIMIT, OFFSET and FETCH cut rows before any
        // ordering, so each query level carrying one needs its own ORDER BY.
        for sql in [
            "SELECT id FROM records ORDER BY id LIMIT 5",
            "SELECT id FROM records ORDER BY id LIMIT 5 OFFSET 2",
            "SELECT id FROM records ORDER BY id FETCH FIRST 5 ROWS ONLY",
            "SELECT id FROM records ORDER BY id OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY",
            "SELECT id FROM records",
            "SELECT * FROM (SELECT id FROM records ORDER BY id LIMIT 5) s ORDER BY id",
            "WITH c AS (SELECT id FROM records ORDER BY id LIMIT 5) SELECT id FROM c ORDER BY id",
        ] {
            validate(&request(sql)).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        for sql in [
            "SELECT id FROM records LIMIT 5",
            "SELECT id FROM records LIMIT 5 OFFSET 2",
            "SELECT id FROM records OFFSET 5",
            "SELECT id FROM records FETCH FIRST 5 ROWS ONLY",
            "SELECT * FROM (SELECT id FROM records LIMIT 5) s ORDER BY id",
            "WITH c AS (SELECT id FROM records LIMIT 5) SELECT id FROM c ORDER BY id",
            "SELECT id FROM records UNION ALL SELECT id FROM records LIMIT 5",
        ] {
            let error = validate(&request(sql)).unwrap_err().to_string();
            assert!(
                error.contains("add ORDER BY over a unique key"),
                "{sql}: missing repair: {error}"
            );
        }
        // The ordered UNION twin is admitted.
        validate(&request(
            "SELECT id FROM records UNION ALL SELECT id FROM records ORDER BY id LIMIT 5",
        ))
        .unwrap();
    }

    #[test]
    fn default_order_gate_sees_only_plain_top_level_limit() {
        // E2 ad-hoc default gate: fires exactly for a plain top-level LIMIT
        // with no ORDER BY. FETCH, bare OFFSET, ordered and nested-only
        // shapes, EXPLAIN and multi-statements never trigger it.
        for sql in [
            "SELECT id, name FROM records LIMIT 2",
            "SELECT id FROM records LIMIT 5 OFFSET 2",
            "SELECT id FROM records UNION ALL SELECT id FROM records LIMIT 5",
            "WITH c AS (SELECT id FROM records LIMIT 5) SELECT id FROM c LIMIT 3",
            "SELECT * FROM (SELECT id FROM records LIMIT 5) s LIMIT 3",
        ] {
            assert!(top_level_unordered_limit(sql), "{sql}");
        }
        for sql in [
            "SELECT id FROM records",
            "SELECT id FROM records ORDER BY id LIMIT 5",
            "SELECT * FROM (SELECT id FROM records LIMIT 5) s ORDER BY id",
            "SELECT id FROM records OFFSET 5",
            "SELECT id FROM records FETCH FIRST 5 ROWS ONLY",
            "SELECT id FROM records ORDER BY id OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY",
            "EXPLAIN SELECT id FROM records LIMIT 5",
            "SELECT id FROM records LIMIT 5; SELECT id FROM records",
        ] {
            assert!(!top_level_unordered_limit(sql), "{sql}");
        }
    }

    #[test]
    fn default_order_rewrite_validates_with_nulls_first_ordering() {
        // E2: the injected ordinals normalise like any explicit ORDER BY —
        // NULLS FIRST on every key — so cross-engine identity needs no new
        // lowering. Proves the splice+validate shape execute_qualified runs
        // (live row proof comes from the advisory PG lane).
        let (rewritten, assumed) = sql_contract::apply_default_order(
            sql_contract::QuerySqlProfile::PostgresServer,
            "SELECT id, name FROM records LIMIT 2",
            &["id".to_owned(), "name".to_owned()],
        )
        .expect("unordered top-level LIMIT splices");
        assert_eq!(assumed.order_by, "ORDER BY 1, 2");
        let statement = validate(&request(&rewritten)).expect("spliced text validates");
        assert!(statement.contains("1 NULLS FIRST"), "{statement}");
        assert!(statement.contains("2 NULLS FIRST"), "{statement}");
    }

    #[test]
    fn default_order_rewrite_keeps_nested_refusal() {
        // The spliced top level passes; the unordered nest still refuses
        // with today's repair.
        let (rewritten, _) = sql_contract::apply_default_order(
            sql_contract::QuerySqlProfile::PostgresServer,
            "SELECT id FROM (SELECT id FROM records LIMIT 1) s LIMIT 2",
            &["id".to_owned()],
        )
        .expect("outer LIMIT splices over an unordered nest");
        let error = validate(&request(&rewritten)).unwrap_err().to_string();
        assert!(error.contains("LIMIT without ORDER BY"), "{error}");
    }

    #[test]
    fn vocabulary_json_nodes_are_unavailable_in_postgres() {
        for sql in [
            "SELECT count(*) FROM schema_config_json_nodes",
            "SELECT config_id, ordinal FROM schema_config_json_nodes ORDER BY config_id, ordinal",
            "SELECT config_id FROM schema_config_json_nodes LIMIT 2",
            "SELECT count(*) FROM vocabulary_value_json_nodes",
            "SELECT value_id, ordinal FROM vocabulary_value_json_nodes ORDER BY value_id, ordinal",
            "SELECT value_id FROM vocabulary_value_json_nodes LIMIT 2",
        ] {
            let error = validate(&request(sql)).unwrap_err().to_string();
            assert!(error.contains("unauthorized_relation"), "{sql}: {error}");
            assert!(
                error.contains("unavailable in profile postgres-server"),
                "{sql}: {error}"
            );
        }
    }

    #[test]
    fn default_order_gate_defers_to_relation_refusal() {
        // An unordered top level over a SQLite-only relation fires the
        // gate, but validation refuses the relation first — and the
        // deferred execute path falls back to exactly this error when the
        // describe prepare fails.
        let sql = "SELECT activity_id FROM agent_activity LIMIT 2";
        assert!(top_level_unordered_limit(sql), "{sql}");
        let error = validate(&request(sql)).unwrap_err().to_string();
        assert!(
            error.contains("unavailable in profile postgres-server"),
            "{error}"
        );
    }

    #[test]
    fn determinism_normalisation_matches_review_hard_inputs() {
        // Reviewer hard inputs from the blocked text-rewrite attempt: each
        // pair is (input, exact normalised output). Live semantics run in
        // the postgres advisory e2e; this pins the rendering.
        for (input, expected) in [
            ("SELECT a FROM t ORDER BY 1", "SELECT a FROM t ORDER BY 1 NULLS FIRST"),
            ("SELECT a FROM t ORDER BY a + 1", "SELECT a FROM t ORDER BY a + 1 NULLS FIRST"),
            ("SELECT $1 / $2 FROM t", "SELECT $1 / (NULLIF($2, 0)) FROM t"),
            ("SELECT 1 / 2e3 FROM t", "SELECT 1 / (NULLIF(2e3, 0)) FROM t"),
            ("SELECT a / b * c FROM t", "SELECT (a / (NULLIF(b, 0))) * c FROM t"),
            ("SELECT id FROM t ORDER BY x USING >", "SELECT id FROM t ORDER BY x USING >"),
            ("SELECT string_agg(x, ',' ORDER BY y) FROM t", "SELECT string_agg(x, ',' ORDER BY y NULLS FIRST) FROM t"),
            ("SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY x) FROM t", "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY x NULLS FIRST) FROM t"),
            (
                "SELECT sum(x) OVER (ORDER BY y ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM t",
                "SELECT sum(x) OVER (ORDER BY y NULLS FIRST ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM t",
            ),
            // DISTINCT ON divisors normalise like every other `/`.
            (
                "SELECT DISTINCT ON (id / 2) id FROM t ORDER BY id / 2",
                "SELECT DISTINCT ON (id / (NULLIF(2, 0))) id FROM t ORDER BY id / (NULLIF(2, 0)) NULLS FIRST",
            ),
        ] {
            assert_eq!(normalised(input), expected, "input: {input}");
        }
    }

    #[test]
    fn regexp_lowers_to_regexp_like_with_swapped_arguments() {
        // E1 M3: portable regexp(pattern, haystack) rewrites to pg's own
        // regexp_like(haystack, pattern) shape — funcname rename plus arg
        // swap only, never a hand-built node (cf. the NULLIF quirk above).
        let mut parsed =
            pg_query::parse("SELECT regexp('a+', name) FROM records").expect("input must parse");
        assert!(determinism::normalise(&mut parsed.protobuf).expect("normalise"));
        let tree = serde_json::to_value(&parsed.protobuf).unwrap();
        let call = &tree["stmts"][0]["stmt"]["node"]["SelectStmt"]["target_list"][0]["node"]
            ["ResTarget"]["val"]["node"]["FuncCall"];
        assert_eq!(
            call["funcname"][0]["node"]["String"]["sval"],
            Value::String("regexp_like".into()),
            "{call}"
        );
        assert_eq!(
            call["args"][0]["node"]["ColumnRef"]["fields"][0]["node"]["String"]["sval"],
            Value::String("name".into()),
            "{call}"
        );
        assert_eq!(
            call["args"][1]["node"]["AConst"]["val"]["Sval"]["sval"],
            Value::String("a+".into()),
            "{call}"
        );
        // Case-insensitive spelling lowers the same way; other calls and
        // wrong-arity forms stay untouched here (the validator rejects the
        // latter with the arity repair first).
        let mut parsed =
            pg_query::parse("SELECT REGEXP('a', name) FROM records").expect("input must parse");
        assert!(determinism::normalise(&mut parsed.protobuf).expect("normalise"));
        let tree = serde_json::to_value(&parsed.protobuf).unwrap();
        let call = &tree["stmts"][0]["stmt"]["node"]["SelectStmt"]["target_list"][0]["node"]
            ["ResTarget"]["val"]["node"]["FuncCall"];
        assert_eq!(
            call["funcname"][0]["node"]["String"]["sval"],
            Value::String("regexp_like".into()),
            "{call}"
        );
        let mut parsed = pg_query::parse("SELECT upper(name), regexp('a') FROM records")
            .expect("input must parse");
        determinism::normalise(&mut parsed.protobuf).expect("normalise");
        let tree = serde_json::to_value(&parsed.protobuf).unwrap();
        let targets = &tree["stmts"][0]["stmt"]["node"]["SelectStmt"]["target_list"];
        assert_eq!(
            targets[0]["node"]["ResTarget"]["val"]["node"]["FuncCall"]["funcname"][0]["node"]
                ["String"]["sval"],
            Value::String("upper".into())
        );
        assert_eq!(
            targets[1]["node"]["ResTarget"]["val"]["node"]["FuncCall"]["funcname"][0]["node"]
                ["String"]["sval"],
            Value::String("regexp".into())
        );
    }

    #[test]
    fn regexp_bound_patterns_meet_literal_rules() {
        // E1 M3 repair: bound `?N` patterns are validated against the same
        // subset and cap as literals during Postgres validation, before
        // the lowering or execution can see them.
        for (parameter, repair) in [
            (
                QuerySqlParameter::Text {
                    value: Some("(?=".into()),
                },
                "outside the portable subset",
            ),
            (
                QuerySqlParameter::Text {
                    value: Some("a".repeat(1025)),
                },
                "1024-byte",
            ),
            (
                QuerySqlParameter::Integer {
                    value: Some("3".into()),
                },
                "must be text",
            ),
        ] {
            let error = validate(&QuerySqlRequest {
                sql: "SELECT id FROM records WHERE regexp(?1, name) ORDER BY id".into(),
                parameters: vec![parameter],
            })
            .unwrap_err()
            .to_string();
            assert!(error.contains(repair), "unexpected refusal: {error}");
        }
    }

    #[test]
    fn now_ms_is_admitted_and_keyword_clocks_refused() {
        // E1 M3: the portable clock passes Postgres validation (no server
        // needed — this is the classifier plus AST walk); execution binds
        // it as a hidden `$N` in `execute_qualified`, so the walk never
        // sees the name. Keyword clocks fail with the portable repair.
        for sql in [
            "SELECT now_ms() FROM records",
            "SELECT now_ms() AS a, now_ms() AS b FROM records",
            "SELECT id FROM records WHERE updated_at_ms >= now_ms() - 7*86400000 ORDER BY id",
        ] {
            validate(&request(sql)).unwrap_or_else(|error| panic!("{sql}: {error}"));
            assert!(
                sql_contract::statement_uses_now_ms(
                    sql_contract::QuerySqlProfile::PostgresServer,
                    sql
                )
                .unwrap(),
                "{sql}"
            );
        }
        for sql in [
            "SELECT now_ms(1) FROM records",
            "SELECT CURRENT_TIMESTAMP FROM records",
            "SELECT current_date FROM records",
        ] {
            let error = validate(&request(sql)).unwrap_err().to_string();
            assert!(
                error.contains("takes no arguments") || error.contains("now_ms()"),
                "{sql}: unexpected refusal: {error}"
            );
        }
    }

    #[test]
    fn utc_date_label_is_admitted_with_exact_arity() {
        // Native e25665c: the portable UTC label passes Postgres validation
        // with no server (classifier plus AST walk); execution lowers it to
        // the `to_timestamp`/`EXTRACT` expression in `execute_qualified`, so
        // the walk sees only the portable name. Arity mirrors the classifier
        // repair on every surface. The `?1` placeholder form is covered
        // below with an Integer binding (an unbound `?1` with zero
        // parameters is correctly refused by the exact-set check).
        for sql in [
            "SELECT utc_date_label(0) FROM records",
            "SELECT UTC_DATE_LABEL(created_at_ms) FROM records",
            "SELECT utc_date_label(NULL) FROM records",
        ] {
            validate(&request(sql)).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        for sql in [
            "SELECT utc_date_label() FROM records",
            "SELECT utc_date_label(1, 2) FROM records",
        ] {
            let error = validate(&request(sql)).unwrap_err().to_string();
            assert!(
                error.contains("exactly one argument"),
                "{sql}: unexpected refusal: {error}"
            );
        }
        // Text inputs are refused with the integer repair: a literal fails
        // at classification, a `Text`-typed bound fails at execution
        // validation, so neither reaches an engine to fork on.
        for sql in [
            "SELECT utc_date_label('abc') FROM records",
            "SELECT utc_date_label('123') FROM records",
        ] {
            let error = validate(&request(sql)).unwrap_err().to_string();
            assert!(
                error.contains("integer epoch milliseconds"),
                "{sql}: unexpected refusal: {error}"
            );
        }
        let error = validate(&QuerySqlRequest {
            sql: "SELECT utc_date_label(?1) FROM records".into(),
            parameters: vec![QuerySqlParameter::Text {
                value: Some("abc".into()),
            }],
        })
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("integer epoch milliseconds"),
            "unexpected refusal: {error}"
        );
        // The lowering itself is a pure text rewrite after validation: the
        // portable name disappears, the UTC expression appears, and the
        // validated `$N` placeholder survives verbatim.
        let validated = validate(&QuerySqlRequest {
            sql: "SELECT utc_date_label(?1) FROM records".into(),
            parameters: vec![QuerySqlParameter::Integer {
                value: Some("0".into()),
            }],
        })
        .unwrap();
        assert!(validated.contains("$1"), "{validated}");
        let (lowered, count) = sql_contract::rewrite_utc_date_label_calls(
            sql_contract::QuerySqlProfile::PostgresServer,
            &validated,
            sql_contract::UtcDateLabelEngine::Postgres,
        )
        .unwrap();
        assert_eq!(count, 1);
        assert!(!lowered.contains("utc_date_label"), "{lowered}");
        assert!(lowered.contains("to_timestamp"), "{lowered}");
        assert!(lowered.contains("AT TIME ZONE 'UTC'"), "{lowered}");
        assert!(lowered.contains("$1"), "{lowered}");
        // NOTE (27 Sep 2026 follow-on): live-Postgres execution of the same
        // eight vectors (+NULL) runs through the shared seed-free corpus
        // case `utc_date_label_vectors_agree`, added to the
        // `pg_runs_conformance_seed_free_subset` wanted list in this slice
        // via the real `qualification_query_sql` path — nightly in
        // `pg-corpus-report.yml` and `ci-all-features-defence.yml`. It gates
        // nothing, so the Slate migration must confirm that advisory lane is
        // green on the migration head first. This sandbox has no disposable
        // server (and `pg_query` will not bindgen here), so no live-PG run
        // happens locally; identical results are pinned here by admission +
        // lowering shape, and in CI by the shared case.
    }

    #[test]
    fn like_rewrite_mirrors_postgres_own_ilike_shape() {
        // I4: the LIKE→ILIKE rewrite must produce exactly what pg itself
        // parses ILIKE into — kind plus operator only, never a hand-built
        // FuncCall (which SIGABRTs deparse, per the NULLIF quirk above).
        fn aexpr(sql: &str) -> Value {
            let parsed = pg_query::parse(sql).expect("shape input must parse");
            let tree = serde_json::to_value(&parsed.protobuf).unwrap();
            tree["stmts"][0]["stmt"]["node"]["SelectStmt"]["target_list"][0]["node"]["ResTarget"]
                ["val"]["node"]["AExpr"]
                .clone()
        }
        for (like_sql, ilike_sql, operator) in [
            (
                "SELECT 'a' LIKE 'A' FROM t",
                "SELECT 'a' ILIKE 'A' FROM t",
                "~~*",
            ),
            (
                "SELECT 'a' NOT LIKE 'A' FROM t",
                "SELECT 'a' NOT ILIKE 'A' FROM t",
                "!~~*",
            ),
        ] {
            let mut parsed = pg_query::parse(like_sql).expect("shape input must parse");
            assert!(determinism::normalise(&mut parsed.protobuf).expect("normalise"));
            let rewritten = serde_json::to_value(&parsed.protobuf).unwrap();
            let rewritten = &rewritten["stmts"][0]["stmt"]["node"]["SelectStmt"]["target_list"][0]
                ["node"]["ResTarget"]["val"]["node"]["AExpr"];
            let native = aexpr(ilike_sql);
            assert_eq!(rewritten["kind"], native["kind"], "{like_sql}");
            assert_eq!(rewritten["name"], native["name"], "{like_sql}");
            assert_eq!(rewritten["kind"], 9, "{like_sql}");
            assert_eq!(
                rewritten["name"][0]["node"]["String"]["sval"],
                Value::String(operator.into()),
                "{like_sql}"
            );
        }
    }

    #[test]
    fn like_operator_rewrite_mirrors_postgres_own_ilike_shapes() {
        // F1/F2: the direct-operator spellings must rewrite to exactly
        // what pg itself parses the ILIKE spellings into — name only
        // (kind stays AexprOp(/Any/All); SubLink keeps everything but
        // oper_name), never a hand-built node.
        fn where_node(sql: &str) -> Value {
            let parsed = pg_query::parse(sql).expect("shape input must parse");
            let tree = serde_json::to_value(&parsed.protobuf).unwrap();
            tree["stmts"][0]["stmt"]["node"]["SelectStmt"]["where_clause"].clone()
        }
        fn rewritten_where(sql: &str) -> Value {
            let mut parsed = pg_query::parse(sql).expect("shape input must parse");
            assert!(determinism::normalise(&mut parsed.protobuf).expect("normalise"));
            let tree = serde_json::to_value(&parsed.protobuf).unwrap();
            tree["stmts"][0]["stmt"]["node"]["SelectStmt"]["where_clause"].clone()
        }
        for (like_sql, ilike_sql, kind, operator) in [
            (
                "SELECT a FROM t WHERE a ~~ 'x'",
                "SELECT a FROM t WHERE a ~~* 'x'",
                1,
                "~~*",
            ),
            (
                "SELECT a FROM t WHERE a !~~ 'x'",
                "SELECT a FROM t WHERE a !~~* 'x'",
                1,
                "!~~*",
            ),
            (
                "SELECT a FROM t WHERE a OPERATOR(~~) 'x'",
                "SELECT a FROM t WHERE a ~~* 'x'",
                1,
                "~~*",
            ),
            (
                "SELECT a FROM t WHERE a LIKE ANY (ARRAY['x'])",
                "SELECT a FROM t WHERE a ILIKE ANY (ARRAY['x'])",
                2,
                "~~*",
            ),
            (
                "SELECT a FROM t WHERE a NOT LIKE ANY (ARRAY['x'])",
                "SELECT a FROM t WHERE a NOT ILIKE ANY (ARRAY['x'])",
                2,
                "!~~*",
            ),
            (
                "SELECT a FROM t WHERE a LIKE ALL (ARRAY['x'])",
                "SELECT a FROM t WHERE a ILIKE ALL (ARRAY['x'])",
                3,
                "~~*",
            ),
            (
                "SELECT a FROM t WHERE a NOT LIKE ALL (ARRAY['x'])",
                "SELECT a FROM t WHERE a NOT ILIKE ALL (ARRAY['x'])",
                3,
                "!~~*",
            ),
        ] {
            let rewritten = rewritten_where(like_sql);
            let native = where_node(ilike_sql);
            let rewritten = &rewritten["node"]["AExpr"];
            let native = &native["node"]["AExpr"];
            assert_eq!(rewritten["kind"], native["kind"], "{like_sql}");
            assert_eq!(rewritten["name"], native["name"], "{like_sql}");
            assert_eq!(rewritten["kind"], Value::from(kind), "{like_sql}");
            assert_eq!(
                rewritten["name"][0]["node"]["String"]["sval"],
                Value::String(operator.into()),
                "{like_sql}"
            );
        }
        for (like_sql, ilike_sql, operator) in [
            (
                "SELECT a FROM t WHERE a LIKE ANY (SELECT b FROM u)",
                "SELECT a FROM t WHERE a ILIKE ANY (SELECT b FROM u)",
                "~~*",
            ),
            (
                "SELECT a FROM t WHERE a NOT LIKE ALL (SELECT b FROM u)",
                "SELECT a FROM t WHERE a NOT ILIKE ALL (SELECT b FROM u)",
                "!~~*",
            ),
        ] {
            let rewritten = rewritten_where(like_sql);
            let native = where_node(ilike_sql);
            let rewritten = &rewritten["node"]["SubLink"];
            let native = &native["node"]["SubLink"];
            assert_eq!(rewritten["oper_name"], native["oper_name"], "{like_sql}");
            assert_eq!(
                rewritten["oper_name"][0]["node"]["String"]["sval"],
                Value::String(operator.into()),
                "{like_sql}"
            );
            // The pre-keyword operand survives byte-identical (locations
            // past the lengthened keyword shift, so only testexpr compares
            // exactly against pg's own parse).
            assert_eq!(rewritten["testexpr"], native["testexpr"], "{like_sql}");
        }
    }

    #[test]
    fn qualified_like_operators_stay_rejected() {
        // F3: multi-element operator names are never rewritten (the rename
        // requires a single-element name) and the validator rejects them.
        for sql in [
            "SELECT a FROM t WHERE a OPERATOR(pg_catalog.~~) 'x'",
            "SELECT a FROM t WHERE a OPERATOR(pg_catalog.~~*) 'x'",
        ] {
            let error = validate(&request(sql)).unwrap_err().to_string();
            assert!(
                error.contains("outside the closed operator allowlist"),
                "{sql}: {error}"
            );
        }
    }

    #[test]
    fn like_normalisation_matches_review_hard_inputs() {
        // I4: bare LIKE renders as ILIKE everywhere the walker reaches —
        // WHERE, subqueries, aggregate FILTER, window PARTITION, DISTINCT
        // ON — with ESCAPE preserved byte-identical. Live semantics run
        // in the postgres advisory e2e; this pins the rendering.
        for (input, expected) in [
            (
                "SELECT a FROM t WHERE a LIKE 'x'",
                "SELECT a FROM t WHERE a ILIKE 'x'",
            ),
            (
                "SELECT a FROM t WHERE a NOT LIKE 'x'",
                "SELECT a FROM t WHERE a NOT ILIKE 'x'",
            ),
            // ESCAPE parses as pg's own `like_escape` wrapper on the
            // pattern; the rewrite keeps it byte-identical (admission
            // still rejects `like_escape` on Postgres, as before).
            (
                "SELECT a FROM t WHERE a LIKE 'x' ESCAPE '\\'",
                "SELECT a FROM t WHERE a ILIKE pg_catalog.like_escape('x', E'\\\\')",
            ),
            (
                "SELECT a FROM (SELECT a FROM t WHERE b LIKE 'x') s",
                "SELECT a FROM (SELECT a FROM t WHERE b ILIKE 'x') s",
            ),
            (
                "SELECT count(*) FILTER (WHERE a LIKE 'x') FROM t",
                "SELECT count(*) FILTER (WHERE a ILIKE 'x') FROM t",
            ),
            (
                "SELECT sum(a) OVER (PARTITION BY b LIKE 'x' ORDER BY c) FROM t",
                "SELECT sum(a) OVER (PARTITION BY b ILIKE 'x' ORDER BY c NULLS FIRST) FROM t",
            ),
            (
                "SELECT DISTINCT ON (a) a FROM t WHERE b LIKE 'x' ORDER BY a",
                "SELECT DISTINCT ON (a) a FROM t WHERE b ILIKE 'x' ORDER BY a NULLS FIRST",
            ),
            // F1: bare operators rewrite in place (OPERATOR(~~) parses to
            // the same single-element name, so the keyword is gone).
            (
                "SELECT a FROM t WHERE a ~~ 'x'",
                "SELECT a FROM t WHERE a ~~* 'x'",
            ),
            (
                "SELECT a FROM t WHERE a !~~ 'x'",
                "SELECT a FROM t WHERE a !~~* 'x'",
            ),
            (
                "SELECT a FROM t WHERE a OPERATOR(~~) 'x'",
                "SELECT a FROM t WHERE a ~~* 'x'",
            ),
            // F2: ANY/ALL over arrays and subqueries.
            (
                "SELECT a FROM t WHERE a LIKE ANY (ARRAY['x', 'y'])",
                "SELECT a FROM t WHERE a ILIKE ANY(ARRAY['x', 'y'])",
            ),
            (
                "SELECT a FROM t WHERE a NOT LIKE ALL (ARRAY['x'])",
                "SELECT a FROM t WHERE a NOT ILIKE ALL(ARRAY['x'])",
            ),
            (
                "SELECT a FROM t WHERE a LIKE ANY (SELECT b FROM u)",
                "SELECT a FROM t WHERE a ILIKE ANY (SELECT b FROM u)",
            ),
            (
                "SELECT a FROM t WHERE a NOT LIKE ALL (SELECT b FROM u)",
                "SELECT a FROM t WHERE a NOT ILIKE ALL (SELECT b FROM u)",
            ),
            // F8: CASE, CTE and JOIN ON positions.
            (
                "SELECT CASE WHEN a LIKE 'x' THEN 1 ELSE 0 END FROM t",
                "SELECT CASE WHEN a ILIKE 'x' THEN 1 ELSE 0 END FROM t",
            ),
            (
                "WITH c AS (SELECT a FROM t WHERE b LIKE 'x') SELECT a FROM c",
                "WITH c AS (SELECT a FROM t WHERE b ILIKE 'x') SELECT a FROM c",
            ),
            (
                "SELECT a FROM t JOIN u ON t.a LIKE u.b",
                "SELECT a FROM t JOIN u ON t.a ILIKE u.b",
            ),
            // Review R1: bytea has `~~` but no `~~*`, and bytes have no
            // case, so a visibly binary operand (a `bytes` column or a bytea
            // cast) keeps LIKE as written in every shape.
            (
                "SELECT id FROM blobs WHERE bytes LIKE 'a'::bytea",
                "SELECT id FROM blobs WHERE bytes LIKE 'a'::bytea",
            ),
            (
                "SELECT id FROM blobs b WHERE b.bytes NOT LIKE 'a'",
                "SELECT id FROM blobs b WHERE b.bytes NOT LIKE 'a'",
            ),
            (
                "SELECT id FROM blobs WHERE bytes ~~ 'a'::bytea",
                "SELECT id FROM blobs WHERE bytes ~~ 'a'::bytea",
            ),
            (
                "SELECT id FROM blobs WHERE bytes LIKE ANY (ARRAY['a'::bytea])",
                "SELECT id FROM blobs WHERE bytes LIKE ANY(ARRAY['a'::bytea])",
            ),
            (
                "SELECT id FROM blobs WHERE bytes LIKE ANY (SELECT 'a'::bytea)",
                "SELECT id FROM blobs WHERE bytes LIKE ANY (SELECT 'a'::bytea)",
            ),
            (
                "SELECT id FROM t WHERE 'a'::bytea LIKE x",
                "SELECT id FROM t WHERE 'a'::bytea LIKE x",
            ),
        ] {
            assert_eq!(normalised(input), expected, "input: {input}");
        }
    }

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
        assert!(statements.iter().any(|statement| statement.starts_with(
            "CREATE TEMP VIEW record_lifecycle_interpretations WITH (security_barrier=true)"
        )));
    }

    fn request(sql: &str) -> QuerySqlRequest {
        QuerySqlRequest {
            sql: sql.into(),
            parameters: Vec::new(),
        }
    }

    #[test]
    fn lifecycle_dependency_is_ast_based_and_profile_admitted() {
        let contract = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "record_lifecycle_interpretations")
            .unwrap();
        assert!(contract.profiles.contains(&"postgres-server"));
        assert!(contract.caller_relative);
        assert_eq!(contract.columns.len(), 11);
        let real = validate(&request(
            "SELECT record_id,status FROM record_lifecycle_interpretations ORDER BY record_id LIMIT 1",
        ))
        .unwrap();
        assert!(uses_lifecycle_relation(&real).unwrap());
        let literal = validate(&request(
            "SELECT 'record_lifecycle_interpretations' AS value FROM records",
        ))
        .unwrap();
        assert!(!uses_lifecycle_relation(&literal).unwrap());
        let denied = validate(&request(
            "SELECT * FROM _query_sql_lifecycle_interpretations",
        ))
        .unwrap_err();
        assert!(denied
            .to_string()
            .contains("outside the caller-visible logical catalog"));
        let denied = validate(&request(
            "SELECT * FROM pg_temp._query_sql_lifecycle_interpretations",
        ))
        .unwrap_err();
        assert!(denied
            .to_string()
            .contains("outside the caller-visible logical catalog"));
    }

    #[tokio::test]
    async fn content_events_view_discloses_attribution_by_history_rule() {
        // No-server guard for the governed content_events projection: actor,
        // run_key and parent_key travel under the SQLite get_history rule
        // (actor gate plus claim-holder gate with the trusted-local bypass),
        // resolved against main bindings rather than the caller-filtered
        // governed bindings view. Rendering only reads the schema name, so
        // no server is required; execution is covered by the postgres-tests
        // matrix in tests/postgres/postgres_contract.rs.
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
        let view = statements
            .iter()
            .find(|statement| {
                statement
                    .starts_with("CREATE TEMP VIEW content_events WITH (security_barrier=true)")
            })
            .expect("governed content_events view is projected");
        for fragment in [
            "AS actor",
            "AS run_key",
            "AS parent_key",
            "pg_temp._query_sql_principal",
            "actor_binding",
            "claimed_by_account",
            "claimed_run_key",
            "released_from_run_key",
            "payload ? 'claimed_by_account'",
            "payload ? 'claimed_run_key'",
            "payload ? 'released_from_run_key'",
            // The holder gate is NOT (claim-shaped AND not the caller); a
            // regrouping to (NOT claim-shaped) AND not the caller hides the
            // caller's own runs.
            "OR NOT (((event.payload ? 'claimed_by_account')",
            "AND event.actor IS DISTINCT FROM principal.account_id))",
            "IS DISTINCT FROM",
            "reconciliation.recorded.v1",
        ] {
            assert!(
                view.contains(fragment),
                "content_events view is missing {fragment:?}"
            );
        }
        // `->>` returns SQL NULL for an explicit-JSON-null claim key, which
        // would treat `{"claimed_by_account": null}` as NOT claim-shaped and
        // disclose the run; key existence (`?`) matches the history rule.
        for fragment in [
            "->>'claimed_by_account'",
            "->>'claimed_run_key'",
            "->>'released_from_run_key'",
        ] {
            assert!(
                !view.contains(fragment),
                "content_events view must test claim-key existence, not value: {fragment:?}"
            );
        }
        assert!(
            !view.contains(" intent") && !view.contains(",intent"),
            "intent must stay out of the governed relation"
        );
    }

    #[test]
    fn exhaustive_parser_admits_scoped_read_only_queries() {
        for sql in [
            "SELECT id, lower(name) FROM records WHERE name IS NOT NULL ORDER BY id LIMIT 10 OFFSET 1",
            "WITH chosen AS (SELECT id FROM records) SELECT count(*) FROM chosen",
            "SELECT row_number() OVER (ORDER BY id), id FROM records",
            "SELECT * FROM records WHERE id IN (SELECT record_id FROM facet_values)",
            "SELECT * FROM (VALUES (1), (2)) AS values_fixture(value)",
            // E1 M3: portable regexp in both positions; the lowering to
            // regexp_like happens in determinism::normalise.
            "SELECT id FROM records WHERE regexp('^a', name) ORDER BY id",
            "SELECT regexp('a+', name) AS hit FROM records ORDER BY id",
        ] {
            validate(&request(sql)).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        // Wrong arity fails here too, mirroring the classifier repair.
        let error = validate(&request("SELECT regexp('a') FROM records"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("exactly two arguments"),
            "unexpected refusal: {error}"
        );
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
        // (LIKE, including bare-operator and ANY/ALL/sublink spellings)
        // normalises to `~~*` (ILIKE) in I4's determinism pass; both
        // operators stay admitted so the rewrite needs no allowlist
        // change.
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
            ("SELECT max(a, b) FROM records", "CASE"),
            ("SELECT min(a, b) FROM records", "CASE"),
            ("SELECT max(a, b, c) FROM records", "CASE"),
            ("SELECT min(a, b, c) FROM records", "CASE"),
            (
                "SELECT id, max(length(name), 5) AS m FROM records WHERE id = ?1",
                "CASE",
            ),
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
            !mapped.contains("effective_relationship_endpoints"),
            "{mapped}"
        );
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
            "body_block_headings",
            "effective_relationship_endpoints",
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

    #[test]
    fn pg_validator_refuses_bounded_containment_recipe() {
        for case in crate::query::sql_conformance::containment_corpus() {
            let error = validate(&case.request()).unwrap_err().to_string();
            // The full recipe reaches the closed operator check first.
            assert_eq!(
                error,
                "query_sql [unsafe_statement]: operator is outside the closed operator allowlist",
                "{}",
                case.name,
            );
        }
        // Pin recursive refusal independently of earlier operator syntax.
        let recursive = request(
            "WITH RECURSIVE reachable(id) AS (SELECT id FROM records \
             UNION ALL SELECT r.id FROM records r JOIN reachable t ON r.home_id=t.id) \
             SELECT id FROM reachable",
        );
        assert_eq!(
            validate(&recursive).unwrap_err().to_string(),
            "query_sql [unsafe_statement]: recursive CTEs are prohibited",
        );
    }

    #[test]
    fn pg_validator_refuses_shared_rejection_corpus() {
        // E1 M4 negative-case parity without a server: the Postgres closed
        // walk must refuse every shared rejection with its repair. The
        // SQLite runner proves end-to-end refusal; Turso proves its own
        // gate; this proves the PG classifier agrees. Full execution
        // parity (seeded rows) lives in the server-backed runner below.
        for case in crate::query::sql_conformance::rejection_corpus() {
            let error = validate(&crate::query::sql_contract::QuerySqlRequest {
                sql: case.sql.into(),
                parameters: case.parameters,
            })
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(case.expected_repair_substring),
                "{}: expected repair {:?} in PG refusal: {error}",
                case.name,
                case.expected_repair_substring
            );
        }
    }

    /// E1 M4 Postgres advisory corpus runner (seed-free subset). Selects the
    /// shared `sql_conformance::corpus()` cases that need no `conf:` seed
    /// rows by name and runs them through the real PG execution path
    /// (`qualification_query_sql`), asserting with the shared `check_case`
    /// against a stable read-back head. No SQL or expected rows are
    /// duplicated here: the shared corpus is the single source of truth.
    /// Needs `NATIVE_CE_POSTGRES_TEST_URL`; returns early without it
    /// (advisory pattern). Covered nightly by `pg-corpus-report.yml` and
    /// `ci-all-features-defence.yml` (`--all-features` includes
    /// `postgres-tests`); it gates nothing — failures file the nightly
    /// advisory incident, they never block a release. Seeded visibility
    /// cases (records/links/facet_* on `conf:` rows) are the follow-on:
    /// they need qualified-table seeding plus policy grants per
    /// `tests/postgres/postgres_contract.rs`, not attempted here.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn pg_runs_conformance_seed_free_subset() {
        let Some(url) = std::env::var_os("NATIVE_CE_POSTGRES_TEST_URL") else {
            return;
        };
        let cluster = crate::postgres::PostgresCluster::connect(
            url.to_str()
                .expect("NATIVE_CE_POSTGRES_TEST_URL must be valid UTF-8"),
        )
        .await
        .unwrap();
        let db = cluster.fresh_logical_database().await.unwrap();
        let principal = crate::query::QueryPrincipal::authenticated("alice", true);
        // Seed-free only: literals, VALUES/UNION, and catalog views.
        let wanted = [
            "computed_booleans_encode_as_zero_one",
            "widened_scalar_functions_agree",
            "utc_date_label_vectors_agree",
            "zero_divisors_yield_null",
            "catalog_relations_describes_records",
        ];
        let corpus = crate::query::sql_conformance::corpus();
        let selected: Vec<&crate::query::sql_conformance::ConformanceCase> = wanted
            .iter()
            .map(|name| {
                corpus
                    .iter()
                    .find(|case| case.name == *name)
                    .unwrap_or_else(|| panic!("shared corpus has no case named '{name}'"))
            })
            .collect();
        assert_eq!(
            selected.iter().map(|case| case.name).collect::<Vec<_>>(),
            wanted,
            "pg seed-free subset must be exactly the intended five shared cases"
        );
        // Stable read-back head: no writes happen between the probe and the
        // cases, so every execution must stamp the same head.
        let probe = qualification_query_sql(
            db.clone(),
            principal.clone(),
            QuerySqlRequest {
                sql: "SELECT 1 AS one".into(),
                parameters: Vec::new(),
            },
        )
        .await
        .expect("pg probe query must execute");
        let head = probe.as_of_seq;
        for case in selected {
            let result = qualification_query_sql(db.clone(), principal.clone(), case.request())
                .await
                .unwrap_or_else(|error| panic!("pg failed {}: {error}", case.name));
            crate::query::sql_conformance::check_case(&result, case, head);
        }
        // E2 default ORDER BY, seed-free cases: each unordered spelling
        // discloses the assumed order and returns exactly the explicit
        // spelling's rows. The seeded `conf:sort` case runs in the seeded
        // runner below; Postgres proves the rest here.
        let default_wanted = [
            "default_order_nulls_first",
            "default_order_duplicate_rows",
            "default_order_compound",
            "default_order_cte_prefixed",
            "default_order_offset",
        ];
        let default_corpus = crate::query::sql_conformance::default_order_corpus();
        let default_selected: Vec<&crate::query::sql_conformance::DefaultOrderCase> =
            default_wanted
                .iter()
                .map(|name| {
                    default_corpus
                        .iter()
                        .find(|case| case.name == *name)
                        .unwrap_or_else(|| {
                            panic!("default-order corpus has no case named '{name}'")
                        })
                })
                .collect();
        for case in default_selected {
            let unordered = qualification_query_sql(
                db.clone(),
                principal.clone(),
                QuerySqlRequest {
                    sql: case.sql.into(),
                    parameters: case.parameters.clone(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("pg failed {}: {error}", case.name));
            let explicit = qualification_query_sql(
                db.clone(),
                principal.clone(),
                QuerySqlRequest {
                    sql: case.explicit_sql.into(),
                    parameters: case.parameters.clone(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("pg failed explicit {}: {error}", case.name));
            crate::query::sql_conformance::check_default_order_case(
                &unordered, &explicit, case, head,
            );
        }
        db.drop_schema().await.unwrap();
        cluster.close().await;
    }

    /// Translate the shared `conf:` fixture (`sql_conformance::SEED_SQL`,
    /// verbatim on SQLite/Turso) through real Postgres physical tables.
    ///
    /// The SQLite seed cannot run verbatim here: Postgres stores
    /// `records.record_type` (not `type`), `facet_values.value` as JSONB,
    /// `content_events` as a payload-JSONB log, and derives both
    /// `facet_values` and `facet_observations` qualification views from
    /// `facet.set` events rather than base tables
    /// (`projection_statements`). So each SQLite row becomes its physical
    /// counterpart below — same ids, same text, same timestamps — and
    /// visibility flows through the sanctioned projector paths, never
    /// hand-written policy rows: `append_policy_event` per anchor (the
    /// SQLite runner's `replace_explicit_policy` grants, verbatim) and
    /// `append_meta_event` for vocabularies, values and schema_config.
    ///
    /// Two deliberate fixture translations, both commented at the site:
    /// - `conf:common` owns itself: the Postgres bindings view is
    ///   ownership-gated (no policy-entry fallback), while the shared seed
    ///   carries no owner. Self-ownership admits conf:common's own account
    ///   binding without adding rows any `conf:%` case could observe.
    /// - Facet state lives in `content_events` on this path, so the seven
    ///   `facet.set` events below also appear in record history: the
    ///   `worked_recent_history_of_one_record` verbatim expectation (exactly
    ///   two `record.updated` rows) is SQLite-shape and stays out of the
    ///   seeded selection for that reason.
    #[cfg(feature = "postgres-tests")]
    async fn seed_pg_conformance_fixture(db: &PostgresDb) {
        let records = db.qualified_table("records").unwrap();
        let links = db.qualified_table("links").unwrap();
        let events = db.qualified_table("content_events").unwrap();
        let bindings = db.qualified_table("bindings").unwrap();
        for statement in [
            format!(
                "INSERT INTO {records}(id,record_type,kind,name,body,created_at,updated_at) VALUES \
                ('conf:common','Document','note','Common','common body quoting `- [ ]` inline','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'), \
                ('conf:alice','Document','note','Alice note',E'alice body\\n- [ ] buy milk\\n> * [ ] quoted\\n- [x] done\\n```\\n- [ ] fenced\\n```','2026-01-02T00:00:00.000Z','2026-01-02T00:00:00.000Z'), \
                ('conf:bea','Document','note','Bea note',E'bea body\\n- [ ] private','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'), \
                ('conf:tomb','Document','note','Tomb','tomb body','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'), \
                ('conf:sort-a','Document','note','apple',NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'), \
                ('conf:sort-b','Document','note','Banana',NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'), \
                ('conf:sort-c','Document','note','Äpfel',NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')"
            ),
            format!(
                "UPDATE {records} SET policy_anchor_id=id, \
                owner_id=CASE WHEN id='conf:common' THEN 'conf:common' ELSE NULL END \
                WHERE id LIKE 'conf:%'"
            ),
            format!(
                "UPDATE {records} SET record_type='WorkItem',lifecycle='open' WHERE id='conf:alice'"
            ),
            format!(
                "UPDATE {records} SET record_type='WorkItem',lifecycle='in_progress' WHERE id='conf:common'"
            ),
            format!("UPDATE {records} SET home_id='conf:common' WHERE id='conf:alice'"),
            format!(
                "UPDATE {records} SET deleted_at='2026-01-02T00:00:00.000Z' WHERE id='conf:tomb'"
            ),
            format!(
                "INSERT INTO {links}(id,source_id,target_id,relationship,note,created_at) VALUES \
                ('conf:link-open','conf:common','conf:alice','relates_to',NULL,'2026-01-01T00:00:00.000Z'), \
                ('conf:link-part','conf:common','conf:alice','part_of',NULL,'2026-01-01T00:00:00.000Z'), \
                ('conf:link-sealed','conf:common','conf:bea','relates_to',NULL,'2026-01-01T00:00:00.000Z'), \
                ('currency:edge','conf:alice','conf:common','supersedes',NULL,'2026-01-01T00:00:00.000Z')"
            ),
            format!(
                "UPDATE {records} SET is_current=NULL,successor_count=1 WHERE id='conf:common'"
            ),
            format!("UPDATE {records} SET archived=TRUE WHERE id IN ('conf:common','conf:alice','conf:bea')"),
            format!(
                "INSERT INTO {links}(id,source_id,target_id,relationship,note,created_at) VALUES \
                ('currency:cited-unknown','conf:sort-a','conf:common','cites',NULL,'2026-01-01T00:00:00.000Z'), \
                ('currency:cited-current','conf:sort-a','conf:alice','cites',NULL,'2026-01-01T00:00:00.000Z')"
            ),
            format!(
                "INSERT INTO {events}(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES \
                (91001,'conf:event-common','conf:common','record.updated','{{}}'::jsonb,NULL,'2026-01-01T00:00:00.000Z',1,'legacy_unknown'), \
                (91002,'conf:event-hidden','conf:bea','record.updated','{{}}'::jsonb,NULL,'2026-01-02T00:00:00Z',1,'legacy_unknown'), \
                (91004,'conf:event-common-2','conf:common','record.updated','{{}}'::jsonb,NULL,'2026-01-05T00:00:00Z',1,'legacy_unknown'), \
                (91003,'task:event-alice','conf:alice','record.updated','{{}}'::jsonb,NULL,'2026-01-03T00:00:00Z',1,'legacy_unknown')"
            ),
            // Mirror the shared fixture's physical task rows. These exact
            // source events own the bodies; the governed view withholds seq.
            format!(
                "INSERT INTO {}(record_id,item_index,source_event_seq,marker,checked,in_quote,start_offset,end_offset) VALUES \
                ('conf:alice',0,91003,'-',FALSE,FALSE,11,25), \
                ('conf:alice',1,91003,'*',FALSE,TRUE,28,40), \
                ('conf:alice',2,91003,'-',TRUE,FALSE,41,51), \
                ('conf:bea',0,91002,'-',FALSE,FALSE,9,22)",
                db.qualified_table("body_task_items").unwrap()
            ),
            // Facet state as `facet.set` events: the qualification
            // `facet_values` view reads the latest event per (record, key)
            // (text value plus a float8 `value_num` cast), so scores land
            // as 10.0/20.0/30.0 exactly like the SQLite REAL column. The
            // hidden bea event stays invisible through the visible-records
            // join. Seq assignment is load-bearing, not chronological: the
            // records view derives last_activity_at from the highest-seq
            // event, so these seqs sit BELOW the 91004 record.updated event
            // to keep conf:common's last_activity_at at 01-05 (a higher
            // facet seq would drag it back to 01-01 and reorder the
            // recency case). One event per (record, key) keeps latest
            // deterministic regardless of position.
            format!(
                "INSERT INTO {events}(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES \
                (90991,'conf:facet-event-1','conf:common','facet.set','{{\"key\":\"color\",\"value\":\"blue\",\"as_of\":\"2026-01-01T00:00:00Z\"}}'::jsonb,NULL,'2026-01-01T00:00:00.000Z',1,'legacy_unknown'), \
                (90992,'conf:facet-event-2','conf:common','facet.set','{{\"key\":\"shape\",\"value\":\"round\",\"as_of\":\"2026-01-01T00:00:00Z\"}}'::jsonb,NULL,'2026-01-01T00:00:00.000Z',1,'legacy_unknown'), \
                (90993,'conf:facet-event-3','conf:common','facet.set','{{\"key\":\"score\",\"value\":\"10\",\"as_of\":\"2026-01-01T00:00:00Z\"}}'::jsonb,NULL,'2026-01-01T00:00:00.000Z',1,'legacy_unknown'), \
                (90994,'conf:facet-event-4','conf:alice','facet.set','{{\"key\":\"color\",\"value\":\"green\",\"as_of\":\"2026-01-01T00:00:00Z\"}}'::jsonb,NULL,'2026-01-01T00:00:00.000Z',1,'legacy_unknown'), \
                (90995,'conf:facet-event-5','conf:alice','facet.set','{{\"key\":\"score\",\"value\":\"20\",\"as_of\":\"2026-01-01T00:00:00Z\"}}'::jsonb,NULL,'2026-01-01T00:00:00.000Z',1,'legacy_unknown'), \
                (90996,'conf:facet-event-6','conf:sort-a','facet.set','{{\"key\":\"score\",\"value\":\"30\",\"as_of\":\"2026-01-01T00:00:00Z\"}}'::jsonb,NULL,'2026-01-01T00:00:00.000Z',1,'legacy_unknown'), \
                (90997,'conf:facet-event-7','conf:bea','facet.set','{{\"key\":\"color\",\"value\":\"red\",\"as_of\":\"2026-01-01T00:00:00Z\"}}'::jsonb,NULL,'2026-01-01T00:00:00.000Z',1,'legacy_unknown')"
            ),
            format!(
                "INSERT INTO {bindings}(record_id,system,identifier,is_canonical,url,etag,last_seen_at) VALUES \
                ('conf:common','account','alice',TRUE,NULL,NULL,'2026-01-01T00:00:00.000Z'), \
                ('conf:common','email','alice@example.test',TRUE,NULL,NULL,'2026-01-02T12:30:45.123Z'), \
                ('conf:common','email','stale@example.test',FALSE,NULL,NULL,NULL)"
            ),
        ] {
            sqlx::query(&statement)
                .execute(db.pool())
                .await
                .unwrap_or_else(|error| panic!("pg conformance seed failed: {error}"));
        }
        // Visibility through the sanctioned projector path: the exact
        // SQLite-runner grants (conf:common to alice+bea, conf:alice to
        // alice, conf:bea to bea, sort rows to alice; tombstone ungranted).
        // conf:bea's grant proves the negative: alice still sees nothing
        // of bea's through the visible-records join.
        for (anchor, accounts) in [
            ("conf:common", vec!["alice", "bea"]),
            ("conf:alice", vec!["alice"]),
            ("conf:bea", vec!["bea"]),
            ("conf:sort-a", vec!["alice"]),
            ("conf:sort-b", vec!["alice"]),
            ("conf:sort-c", vec!["alice"]),
        ] {
            let entries: Vec<Value> = accounts
                .into_iter()
                .map(|account| {
                    serde_json::json!({
                        "subject_kind": "account",
                        "subject_id": account,
                        "effect": "allow",
                        "capability": "view",
                    })
                })
                .collect();
            db.append_policy_event(crate::postgres::PostgresPolicyEvent {
                id: format!("conf:policy:{anchor}"),
                record_id: anchor.into(),
                event_type: "policy.replaced".into(),
                payload: Some(serde_json::json!({"entries": entries})),
                actor: "test:pg-conformance-seed".into(),
                reason: "Grant the shared conformance fixture on Postgres.".into(),
                created_at: "2026-01-01T00:00:00.000Z".into(),
                act: None,
            })
            .await
            .unwrap_or_else(|error| {
                panic!("pg conformance policy grant failed for {anchor}: {error}")
            });
        }
        // Caller-independent rows through the sanctioned meta projector:
        // one vocabulary, two values, one null-scope schema config.
        db.append_meta_event(crate::postgres::PostgresMetaEvent {
            id: "conf:meta-vocab".into(),
            subject_id: "conf:vocab".into(),
            event_type: "vocabulary.created".into(),
            payload: serde_json::json!({"name": "Conf vocabulary"}),
            actor: Some("test:pg-conformance-seed".into()),
            created_at: "2026-01-01T00:00:00.000Z".into(),
            act: None,
        })
        .await
        .unwrap();
        for (id, value, gloss, ordinal) in [
            ("conf:vv-blue", "blue", Some("Conf blue"), 1.0),
            ("conf:vv-green", "green", None, 2.0),
        ] {
            let mut payload = serde_json::json!({
                "vocabulary_id": "conf:vocab",
                "value": value,
                "status": "active",
                "ordinal": ordinal,
                "terminality": "open",
                "metadata": {},
            });
            if let Some(gloss) = gloss {
                payload["gloss"] = gloss.into();
            }
            db.append_meta_event(crate::postgres::PostgresMetaEvent {
                id: format!("conf:meta-{id}"),
                subject_id: id.into(),
                event_type: "vocab_value.proposed".into(),
                payload,
                actor: Some("test:pg-conformance-seed".into()),
                created_at: "2026-01-01T00:00:00.000Z".into(),
                act: None,
            })
            .await
            .unwrap_or_else(|error| panic!("pg conformance vocab value failed for {id}: {error}"));
        }
        db.append_meta_event(crate::postgres::PostgresMetaEvent {
            id: "conf:meta-cfg".into(),
            subject_id: "conf:cfg".into(),
            event_type: "schema_config.set".into(),
            payload: serde_json::json!({
                "layer": "user",
                "name": "conf-test",
                "data": "{}",
                "applies_to_collection_id": null,
                "version_lineage": "v1",
            }),
            actor: Some("test:pg-conformance-seed".into()),
            created_at: "2026-01-01T00:00:00.000Z".into(),
            act: None,
        })
        .await
        .unwrap();
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn pg_lifecycle_relation_is_caller_relative_and_snapshot_pinned() {
        let Some(url) = std::env::var_os("NATIVE_CE_POSTGRES_TEST_URL") else {
            return;
        };
        let cluster = crate::postgres::PostgresCluster::connect(
            url.to_str().expect("Postgres test URL must be UTF-8"),
        )
        .await
        .unwrap();
        let db = cluster.fresh_logical_database().await.unwrap();
        seed_pg_conformance_fixture(&db).await;
        let records = db.qualified_table("records").unwrap();
        sqlx::query(&format!(
            "UPDATE {records} SET record_type='Collection',kind='folder' WHERE id='conf:alice'"
        ))
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {records}(id,record_type,kind,name,home_id,lifecycle,policy_anchor_id,created_at,updated_at) VALUES \
             ('conf:lifecycle','Document','lifecycle-test','Shared task','conf:alice','open','conf:lifecycle',now(),now()), \
             ('conf:lifecycle-absent','Document','lifecycle-test','Absent task','conf:alice',NULL,'conf:lifecycle-absent',now(),now())"
        )).execute(db.pool()).await.unwrap();
        for id in ["conf:lifecycle", "conf:lifecycle-absent"] {
            db.append_policy_event(crate::postgres::PostgresPolicyEvent {
                id: format!("{id}:policy"), record_id: id.into(),
                event_type: "policy.replaced".into(),
                payload: Some(serde_json::json!({"entries": [
                    {"subject_kind":"account","subject_id":"alice","effect":"allow","capability":"view"},
                    {"subject_kind":"account","subject_id":"bea","effect":"allow","capability":"view"}
                ]})), actor: "test:lifecycle".into(), reason: "Caller-relative fixture".into(),
                created_at: "2026-01-02T00:00:00.000Z".into(), act: None,
            }).await.unwrap();
        }
        db.append_meta_event(crate::postgres::PostgresMetaEvent {
            id: "conf:lifecycle-value-event".into(),
            subject_id: "conf:lifecycle-value".into(),
            event_type: "vocab_value.proposed".into(),
            payload: serde_json::json!({"vocabulary_id":"conf:vocab","value":"open", "status":"active", "ordinal":3, "terminality":"open", "metadata":{}}),
            actor: Some("test:lifecycle".into()), created_at: "2026-01-02T00:00:00.000Z".into(), act: None,
        }).await.unwrap();
        db.append_meta_event(crate::postgres::PostgresMetaEvent {
            id: "conf:lifecycle-schema-event".into(),
            subject_id: "conf:lifecycle-schema".into(),
            event_type: "schema_config.set".into(),
            payload: serde_json::json!({
                "layer":"user", "name":"private lifecycle", "version_lineage":"v1",
                "applies_to_collection_id":"conf:alice",
                "data": serde_json::json!({"shapes":{"Document:lifecycle-test":{"facets":{"lifecycle":{
                    "axis":{"key":"work_status","label":"Work status"}, "vocab_ref":"conf:vocab"
                }}}}}).to_string()
            }),
            actor: Some("test:lifecycle".into()),
            created_at: "2026-01-02T00:00:00.000Z".into(),
            act: None,
        })
        .await
        .unwrap();
        let sql = "SELECT record_id,status,raw,axis_key,value_id,terminality,reason FROM record_lifecycle_interpretations WHERE record_id LIKE 'conf:lifecycle%' ORDER BY record_id";
        let alice = qualification_query_sql(
            db.clone(),
            crate::query::QueryPrincipal::authenticated("alice", true),
            request(sql),
        )
        .await
        .unwrap();
        let bea = qualification_query_sql(
            db.clone(),
            crate::query::QueryPrincipal::authenticated("bea", true),
            request(sql),
        )
        .await
        .unwrap();
        assert_eq!(alice.rows.len(), 2);
        assert_eq!(alice.rows[0]["status"], "governed");
        assert_eq!(alice.rows[0]["value_id"], "conf:lifecycle-value");
        assert_eq!(alice.rows[1]["status"], "absent");
        assert_eq!(bea.rows.len(), 2);
        assert_eq!(bea.rows[0]["status"], "unclassified");
        assert_eq!(bea.rows[0]["reason"], "no_governing_vocabulary");
        assert_eq!(bea.rows[1]["status"], "absent");
        assert_eq!(alice.as_of_seq, bea.as_of_seq);
        let joined = qualification_query_sql(
            db.clone(),
            crate::query::QueryPrincipal::authenticated("alice", true),
            request("SELECT r.lifecycle,l.raw,l.status FROM records r JOIN record_lifecycle_interpretations l ON l.record_id=r.id WHERE r.id='conf:lifecycle'"),
        ).await.unwrap();
        assert_eq!(joined.rows[0]["lifecycle"], joined.rows[0]["raw"]);
        assert_eq!(joined.rows[0]["status"], "governed");
        assert_eq!(joined.as_of_seq, alice.as_of_seq);
        let hidden_schema = qualification_query_sql(
            db.clone(),
            crate::query::QueryPrincipal::authenticated("bea", true),
            request("SELECT id FROM schema_config WHERE id='conf:lifecycle-schema'"),
        )
        .await
        .unwrap();
        assert!(hidden_schema.rows.is_empty());
        let hidden = qualification_query_sql(
            db.clone(), crate::query::QueryPrincipal::authenticated("bea", true),
            request("SELECT record_id FROM record_lifecycle_interpretations WHERE record_id='conf:alice'"),
        ).await.unwrap();
        assert!(hidden.rows.is_empty());
        let deleted = qualification_query_sql(
            db.clone(),
            crate::query::QueryPrincipal::authenticated("alice", true),
            request("SELECT record_id FROM record_lifecycle_interpretations WHERE record_id='conf:tomb'"),
        ).await.unwrap();
        assert!(deleted.rows.is_empty());
        sqlx::query(&format!(
            "INSERT INTO {records}(id,record_type,kind,name,home_id,policy_anchor_id,created_at,updated_at) \
             SELECT 'conf:bulk:' || n::text,'Document','note','Bulk','conf:common','conf:common',now(),now() \
             FROM generate_series(1,20001) AS n"
        )).execute(db.pool()).await.unwrap();
        let too_large = qualification_query_sql(
            db.clone(), crate::query::QueryPrincipal::authenticated("alice", true),
            request("SELECT record_id FROM record_lifecycle_interpretations WHERE record_id='conf:lifecycle'"),
        ).await.unwrap_err();
        assert!(
            too_large.to_string().contains("result_too_large"),
            "{too_large}"
        );
        assert!(too_large.to_string().contains("20000"), "{too_large}");
        let unrelated = qualification_query_sql(
            db.clone(),
            crate::query::QueryPrincipal::authenticated("alice", true),
            request("SELECT 1 AS ok"),
        )
        .await
        .unwrap();
        assert_eq!(unrelated.rows[0]["ok"], 1);
        db.drop_schema().await.unwrap();
        cluster.close().await;
    }

    /// E1 M4 seeded Postgres corpus runner: the non-divergent shared
    /// `sql_conformance::corpus()` cases, by name, over the translated
    /// `conf:` fixture above, through the real PG execution path
    /// (`qualification_query_sql`) and the shared `check_case` — the same
    /// single-source-of-truth pattern as the seed-free subset. The
    /// seed-free literal cases (including main's `utc_date_label_vectors_agree`,
    /// e25665c) run here too: a literal-only SELECT cannot observe the
    /// seed. Needs `NATIVE_CE_POSTGRES_TEST_URL`; returns early without it
    /// (advisory pattern). Covered nightly by `pg-corpus-report.yml` and
    /// `ci-all-features-defence.yml`; it gates nothing.
    ///
    /// Explicitly out of the selection, with reasons (follow-ons, not
    /// silent skips):
    /// - `facet_values_follow_record_visibility` and
    ///   `facet_observations_follow_record_visibility`: the qualification
    ///   views synthesize `fv:`/`fo:`-prefixed ids, which never match the
    ///   cases' `conf:` id filters. Needs a corpus id-filter convention or
    ///   a PG id-synthesis decision.
    /// - `worked_recent_history_of_one_record`: facet state lives in
    ///   `content_events` on this path, so the `facet.set` rows join the
    ///   history and the verbatim two-row expectation is SQLite-shape.
    ///
    /// Also out of this slice by brief: blobs (attachment + blob_ref +
    /// part_of seeder), avg/round-over-INTEGER semantics, NaN, window
    /// functions, and now_ms cases.
    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn pg_runs_conformance_seeded_corpus() {
        let Some(url) = std::env::var_os("NATIVE_CE_POSTGRES_TEST_URL") else {
            return;
        };
        let cluster = crate::postgres::PostgresCluster::connect(
            url.to_str()
                .expect("NATIVE_CE_POSTGRES_TEST_URL must be valid UTF-8"),
        )
        .await
        .unwrap();
        let db = cluster.fresh_logical_database().await.unwrap();
        seed_pg_conformance_fixture(&db).await;
        let principal = crate::query::QueryPrincipal::authenticated("alice", true);
        let wanted = [
            "records_project_stable_columns",
            "records_currency_counts_match_physical_projection",
            "records_archived_currency_orthogonal",
            "records_archived_does_not_disclose_hidden_rows",
            "links_require_both_endpoints_visible",
            "hidden_row_not_counted",
            "hidden_row_direct_lookup_empty",
            "timestamp_ms_integer_arithmetic",
            "boolean_filter_uses_zero_one",
            "text_sorts_in_binary_order",
            "avg_returns_one_number",
            "sum_returns_one_number",
            "nulls_sort_first_on_asc",
            "nulls_sort_last_on_desc",
            "like_matches_ascii_case_insensitively",
            "like_leaves_non_ascii_case_unfolded",
            "trim_with_chars_agrees",
            "regexp_matches_text",
            "regexp_subset_constructs_agree",
            "regexp_placeholder_pattern_is_runtime",
            "regexp_null_inputs_yield_null",
            "regexp_null_haystack_filters_rows",
            "catalog_columns_lists_links_columns_in_position",
            "catalog_columns_lists_content_events_columns_in_position",
            "content_events_attribution_is_null_when_unstamped",
            "catalog_columns_lists_full_catalog",
            "catalog_relations_lists_full_catalog",
            "worked_current_work_orders_by_recency",
            "worked_direct_children_of_a_record",
            "worked_parts_of_a_record",
            "worked_unchecked_checklist_items",
            "body_task_items_keep_typed_shape_and_visibility",
            "body_task_items_strict_unchecked_candidates",
            "body_task_items_hidden_direct_lookup_empty",
            "vocabularies_are_caller_independent",
            "vocabulary_values_join_vocabularies",
            "schema_config_null_scope_visible",
            "scalar_min_max_agree",
            "computed_booleans_encode_as_zero_one",
            "widened_scalar_functions_agree",
            "utc_date_label_vectors_agree",
            "zero_divisors_yield_null",
            "catalog_relations_describes_records",
        ];
        let corpus = crate::query::sql_conformance::corpus();
        let selected: Vec<&crate::query::sql_conformance::ConformanceCase> = wanted
            .iter()
            .map(|name| {
                corpus
                    .iter()
                    .find(|case| case.name == *name)
                    .unwrap_or_else(|| panic!("shared corpus has no case named '{name}'"))
            })
            .collect();
        assert_eq!(
            selected.iter().map(|case| case.name).collect::<Vec<_>>(),
            wanted,
            "pg seeded selection must be exactly the intended shared cases"
        );
        // Stable read-back head: the explicit 91xxx seed seqs own the
        // workspace head, and no writes happen between the probe and the
        // cases, so every execution must stamp the same head.
        let probe = qualification_query_sql(
            db.clone(),
            principal.clone(),
            QuerySqlRequest {
                sql: "SELECT 1 AS one".into(),
                parameters: Vec::new(),
            },
        )
        .await
        .expect("pg probe query must execute");
        let head = probe.as_of_seq;
        assert!(
            head >= crate::query::sql_conformance::SEED_MIN_HEAD,
            "seed must own the head, got {head}"
        );
        for case in selected {
            let result = qualification_query_sql(db.clone(), principal.clone(), case.request())
                .await
                .unwrap_or_else(|error| panic!("pg failed {}: {error}", case.name));
            crate::query::sql_conformance::check_case(&result, case, head);
        }
        // Alice's shared corpus expects no Bea row. Bea's own policy grant
        // proves the physical task row exists and the view is caller-relative.
        let bea_tasks = qualification_query_sql(
            db.clone(),
            crate::query::QueryPrincipal::authenticated("bea", true),
            QuerySqlRequest {
                sql: "SELECT record_id,item_index,marker,checked,in_quote,start_offset,end_offset FROM body_task_items WHERE record_id='conf:bea' ORDER BY item_index".into(),
                parameters: Vec::new(),
            },
        )
        .await
        .expect("Bea sees her own projected task");
        assert_eq!(
            bea_tasks.rows,
            vec![serde_json::json!({
                "record_id":"conf:bea","item_index":0,"marker":"-",
                "checked":0,"in_quote":0,"start_offset":9,"end_offset":22
            })]
        );
        // E2 default ORDER BY, seeded case: the `conf:sort` spelling needs
        // the translated fixture, so it runs here rather than seed-free.
        let default_case = crate::query::sql_conformance::default_order_corpus()
            .into_iter()
            .find(|case| case.name == "default_order_binary_text")
            .expect("default-order corpus has default_order_binary_text");
        let unordered = qualification_query_sql(
            db.clone(),
            principal.clone(),
            QuerySqlRequest {
                sql: default_case.sql.into(),
                parameters: default_case.parameters.clone(),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("pg failed {}: {error}", default_case.name));
        let explicit = qualification_query_sql(
            db.clone(),
            principal.clone(),
            QuerySqlRequest {
                sql: default_case.explicit_sql.into(),
                parameters: default_case.parameters.clone(),
            },
        )
        .await
        .unwrap_or_else(|error| panic!("pg failed explicit {}: {error}", default_case.name));
        crate::query::sql_conformance::check_default_order_case(
            &unordered,
            &explicit,
            &default_case,
            head,
        );
        // Negative cases end-to-end (mirrors the Turso runner): every
        // shared rejection must fail closed with its repair on the seeded
        // database too, never execute.
        for case in crate::query::sql_conformance::rejection_corpus() {
            let error = qualification_query_sql(
                db.clone(),
                principal.clone(),
                QuerySqlRequest {
                    sql: case.sql.into(),
                    parameters: case.parameters,
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(case.expected_repair_substring),
                "{}: expected repair {:?} in PG refusal: {error}",
                case.name,
                case.expected_repair_substring
            );
        }
        db.drop_schema().await.unwrap();
        cluster.close().await;
    }
}
