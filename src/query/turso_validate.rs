//! Exact Turso 0.7.2 parser admission for caller SQL.

use std::collections::BTreeSet;

use turso_parser::ast::{
    Cmd, Expr, FrameBound, FrameClause, FromClause, FunctionTail, GroupBy, JoinConstraint, Limit,
    Name, OneSelect, Over, ResultColumn, Select, SelectTable, SortedColumn, Stmt, Type, TypeSize,
    Window, With,
};
use turso_parser::parser::Parser;

use super::sql_contract::{self, QuerySqlErrorCategory};
use crate::Result;

const SAFE_FUNCTIONS: [&str; 29] = [
    "abs",
    "avg",
    "count",
    "cume_dist",
    "date",
    "datetime",
    "dense_rank",
    "glob",
    "instr",
    "json_array_length",
    "json_type",
    "json_valid",
    "julianday",
    "length",
    "like",
    "max",
    "min",
    "ntile",
    "percent_rank",
    "rank",
    "round",
    "row_number",
    "strftime",
    "sum",
    "time",
    "total",
    "typeof",
    "unicode",
    "unixepoch",
];

const SAFE_CAST_TYPES: [&str; 8] = [
    "", "blob", "integer", "numeric", "real", "text", "none", "boolean",
];
const SAFE_COLLATIONS: [&str; 3] = ["binary", "nocase", "rtrim"];
const HIDDEN_ROWIDS: [&str; 3] = ["rowid", "_rowid_", "oid"];

fn reject(category: QuerySqlErrorCategory, detail: impl AsRef<str>) -> crate::Error {
    sql_contract::categorized_error(category, detail)
}

pub(crate) fn validate(sql: &str) -> Result<()> {
    let mut parser = Parser::new(sql.as_bytes());
    let cmd = parser
        .next()
        .transpose()
        .map_err(|error| reject(QuerySqlErrorCategory::SyntaxOrType, error.to_string()))?
        .ok_or_else(|| reject(QuerySqlErrorCategory::UnsafeStatement, "empty SQL"))?;
    if parser.next().is_some() {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            "a single statement only",
        ));
    }
    let Cmd::Stmt(Stmt::Select(select)) = cmd else {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            "Turso query_sql accepts one SELECT statement only",
        ));
    };
    validate_select(&select, &[])
}

fn validate_select(select: &Select, outer: &[BTreeSet<String>]) -> Result<()> {
    let mut scopes = outer.to_vec();
    if let Some(with) = &select.with {
        validate_with(with, &mut scopes)?;
    }
    validate_one_select(&select.body.select, &scopes)?;
    for compound in &select.body.compounds {
        validate_one_select(&compound.select, &scopes)?;
    }
    validate_sorted(&select.order_by, &scopes)?;
    if let Some(limit) = &select.limit {
        validate_limit(limit, &scopes)?;
    }
    Ok(())
}

fn validate_with(with: &With, scopes: &mut Vec<BTreeSet<String>>) -> Result<()> {
    let mut local = BTreeSet::new();
    for cte in &with.ctes {
        let name = checked_name(&cte.tbl_name)?;
        if is_logical_relation(name) || !local.insert(name.to_ascii_lowercase()) {
            return Err(reject(
                QuerySqlErrorCategory::UnauthorizedRelation,
                "CTE names cannot collide with logical relations or each other",
            ));
        }
        for column in &cte.columns {
            checked_name(&column.col_name)?;
            if column.collation_name.is_some() {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    "CTE column collations are unavailable",
                ));
            }
        }
    }
    scopes.push(local);
    for cte in &with.ctes {
        validate_select(&cte.select, scopes)?;
    }
    Ok(())
}

fn validate_one_select(select: &OneSelect, scopes: &[BTreeSet<String>]) -> Result<()> {
    match select {
        OneSelect::Select {
            distinctness: _,
            columns,
            from,
            where_clause,
            group_by,
            window_clause,
        } => {
            for column in columns {
                match column {
                    ResultColumn::Expr(expr, alias) => {
                        validate_expr(expr, scopes)?;
                        if let Some(alias) = alias {
                            checked_name(alias.name())?;
                        }
                    }
                    ResultColumn::Star => {}
                    ResultColumn::TableStar(name) => {
                        checked_name(name)?;
                    }
                }
            }
            if let Some(from) = from {
                validate_from(from, scopes)?;
            }
            if let Some(expr) = where_clause {
                validate_expr(expr, scopes)?;
            }
            if let Some(group) = group_by {
                validate_group(group, scopes)?;
            }
            for window in window_clause {
                checked_name(&window.name)?;
                validate_window(&window.window, scopes)?;
            }
        }
        OneSelect::Values(rows) => {
            for row in rows {
                for expr in row {
                    validate_expr(expr, scopes)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_from(from: &FromClause, scopes: &[BTreeSet<String>]) -> Result<()> {
    validate_table(&from.select, scopes)?;
    for join in &from.joins {
        validate_table(&join.table, scopes)?;
        match &join.constraint {
            Some(JoinConstraint::On(expr)) => validate_expr(expr, scopes)?,
            Some(JoinConstraint::Using(names)) => {
                for name in names {
                    checked_name(name)?;
                }
            }
            None => {}
        }
    }
    Ok(())
}

fn validate_table(table: &SelectTable, scopes: &[BTreeSet<String>]) -> Result<()> {
    match table {
        SelectTable::Table(name, alias, indexed) => {
            if name.db_name.is_some() || name.alias.is_some() || indexed.is_some() {
                return Err(reject(
                    QuerySqlErrorCategory::UnauthorizedRelation,
                    "qualified, catalog, or indexed relation access is unavailable",
                ));
            }
            let relation = checked_name(&name.name)?;
            let in_scope = scopes
                .iter()
                .rev()
                .any(|scope| scope.contains(&relation.to_ascii_lowercase()));
            if !is_logical_relation(relation) && !in_scope {
                return Err(reject(
                    QuerySqlErrorCategory::UnauthorizedRelation,
                    format!("relation '{relation}' is outside the logical catalog"),
                ));
            }
            if let Some(alias) = alias {
                checked_name(alias.name())?;
            }
        }
        SelectTable::TableCall(_, _, _) => {
            return Err(reject(
                QuerySqlErrorCategory::UnauthorizedRelation,
                "table-valued functions are unavailable",
            ))
        }
        SelectTable::Select(select, alias) => {
            validate_select(select, scopes)?;
            if let Some(alias) = alias {
                checked_name(alias.name())?;
            }
        }
        SelectTable::Sub(from, alias) => {
            validate_from(from, scopes)?;
            if let Some(alias) = alias {
                checked_name(alias.name())?;
            }
        }
    }
    Ok(())
}

fn validate_expr(expr: &Expr, scopes: &[BTreeSet<String>]) -> Result<()> {
    match expr {
        Expr::Between {
            lhs, start, end, ..
        } => {
            validate_expr(lhs, scopes)?;
            validate_expr(start, scopes)?;
            validate_expr(end, scopes)?;
        }
        Expr::Binary(lhs, _, rhs) => {
            validate_expr(lhs, scopes)?;
            validate_expr(rhs, scopes)?;
        }
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => {
            if let Some(base) = base {
                validate_expr(base, scopes)?;
            }
            for (when, then) in when_then_pairs {
                validate_expr(when, scopes)?;
                validate_expr(then, scopes)?;
            }
            if let Some(expr) = else_expr {
                validate_expr(expr, scopes)?;
            }
        }
        Expr::Cast { expr, type_name } => {
            validate_expr(expr, scopes)?;
            validate_type(type_name.as_ref())?;
        }
        Expr::Collate(expr, name) => {
            validate_expr(expr, scopes)?;
            let name = checked_name(name)?;
            if !SAFE_COLLATIONS
                .iter()
                .any(|safe| name.eq_ignore_ascii_case(safe))
            {
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    format!("collation '{name}' is unavailable"),
                ));
            }
        }
        Expr::Exists(select) | Expr::Subquery(select) => validate_select(select, scopes)?,
        Expr::FunctionCall {
            name,
            args,
            order_by,
            within_group,
            filter_over,
            ..
        } => {
            validate_function(name)?;
            for arg in args {
                validate_expr(arg, scopes)?;
            }
            validate_sorted(order_by, scopes)?;
            validate_sorted(within_group, scopes)?;
            validate_function_tail(filter_over, scopes)?;
        }
        Expr::FunctionCallStar { name, filter_over } => {
            validate_function(name)?;
            validate_function_tail(filter_over, scopes)?;
        }
        Expr::Id(name) | Expr::Name(name) => {
            checked_name(name)?;
        }
        Expr::InList { lhs, rhs, .. } => {
            validate_expr(lhs, scopes)?;
            for expr in rhs {
                validate_expr(expr, scopes)?;
            }
        }
        Expr::InSelect { lhs, rhs, .. } => {
            validate_expr(lhs, scopes)?;
            validate_select(rhs, scopes)?;
        }
        Expr::IsNull(expr) | Expr::NotNull(expr) | Expr::Unary(_, expr) => {
            validate_expr(expr, scopes)?
        }
        Expr::Like {
            lhs, rhs, escape, ..
        } => {
            validate_expr(lhs, scopes)?;
            validate_expr(rhs, scopes)?;
            if let Some(escape) = escape {
                validate_expr(escape, scopes)?;
            }
        }
        Expr::Literal(_) | Expr::Variable(_) => {}
        Expr::Parenthesized(exprs) => {
            for expr in exprs {
                validate_expr(expr, scopes)?;
            }
        }
        Expr::Qualified(table, column) => {
            checked_name(table)?;
            checked_name(column)?;
        }
        Expr::DoublyQualified(_, _, _)
        | Expr::InTable { .. }
        | Expr::Raise(_, _)
        | Expr::Register(_)
        | Expr::Column { .. }
        | Expr::RowId { .. }
        | Expr::FieldAccess { .. }
        | Expr::SubqueryResult { .. }
        | Expr::Default
        | Expr::Array { .. }
        | Expr::Subscript { .. } => {
            return Err(reject(
                QuerySqlErrorCategory::UnsafeStatement,
                "unsupported Turso expression form",
            ))
        }
    }
    Ok(())
}

fn validate_function(name: &Name) -> Result<()> {
    let name = checked_name(name)?;
    if SAFE_FUNCTIONS
        .iter()
        .any(|safe| name.eq_ignore_ascii_case(safe))
    {
        Ok(())
    } else {
        Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("function '{name}' is unavailable"),
        ))
    }
}

fn validate_type(typ: Option<&Type>) -> Result<()> {
    let name = typ.map(|typ| typ.name.as_str()).unwrap_or_default();
    if !SAFE_CAST_TYPES
        .iter()
        .any(|safe| name.eq_ignore_ascii_case(safe))
        || typ.is_some_and(|typ| typ.array_dimensions != 0)
    {
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            format!("cast type '{name}' is unavailable"),
        ));
    }
    if let Some(typ) = typ {
        match &typ.size {
            Some(TypeSize::MaxSize(expr)) => validate_expr(expr, &[])?,
            Some(TypeSize::TypeSize(first, second)) => {
                validate_expr(first, &[])?;
                validate_expr(second, &[])?;
            }
            None => {}
        }
    }
    Ok(())
}

fn validate_function_tail(tail: &FunctionTail, scopes: &[BTreeSet<String>]) -> Result<()> {
    if let Some(filter) = &tail.filter_clause {
        validate_expr(filter, scopes)?;
    }
    if let Some(over) = &tail.over_clause {
        match over {
            Over::Window(window) => validate_window(window, scopes)?,
            Over::Name(name) => {
                checked_name(name)?;
            }
        }
    }
    Ok(())
}

fn validate_window(window: &Window, scopes: &[BTreeSet<String>]) -> Result<()> {
    if let Some(base) = &window.base {
        checked_name(base)?;
    }
    for expr in &window.partition_by {
        validate_expr(expr, scopes)?;
    }
    validate_sorted(&window.order_by, scopes)?;
    if let Some(frame) = &window.frame_clause {
        validate_frame(frame, scopes)?;
    }
    Ok(())
}

fn validate_frame(frame: &FrameClause, scopes: &[BTreeSet<String>]) -> Result<()> {
    validate_frame_bound(&frame.start, scopes)?;
    if let Some(end) = &frame.end {
        validate_frame_bound(end, scopes)?;
    }
    Ok(())
}

fn validate_frame_bound(bound: &FrameBound, scopes: &[BTreeSet<String>]) -> Result<()> {
    match bound {
        FrameBound::Following(expr) | FrameBound::Preceding(expr) => validate_expr(expr, scopes),
        FrameBound::CurrentRow
        | FrameBound::UnboundedFollowing
        | FrameBound::UnboundedPreceding => Ok(()),
    }
}

fn validate_group(group: &GroupBy, scopes: &[BTreeSet<String>]) -> Result<()> {
    for expr in &group.exprs {
        validate_expr(expr, scopes)?;
    }
    if let Some(having) = &group.having {
        validate_expr(having, scopes)?;
    }
    Ok(())
}

fn validate_sorted(columns: &[SortedColumn], scopes: &[BTreeSet<String>]) -> Result<()> {
    for column in columns {
        validate_expr(&column.expr, scopes)?;
    }
    Ok(())
}

fn validate_limit(limit: &Limit, scopes: &[BTreeSet<String>]) -> Result<()> {
    validate_expr(&limit.expr, scopes)?;
    if let Some(offset) = &limit.offset {
        validate_expr(offset, scopes)?;
    }
    Ok(())
}

fn checked_name(name: &Name) -> Result<&str> {
    let value = name.as_str();
    if HIDDEN_ROWIDS
        .iter()
        .any(|hidden| value.eq_ignore_ascii_case(hidden))
        || value.to_ascii_lowercase().starts_with("sqlite_")
        || value.to_ascii_lowercase().starts_with("pragma_")
    {
        Err(reject(
            QuerySqlErrorCategory::UnauthorizedRelation,
            format!("identifier '{value}' is unavailable"),
        ))
    } else {
        Ok(value)
    }
}

fn is_logical_relation(name: &str) -> bool {
    sql_contract::LOGICAL_RELATIONS
        .iter()
        .any(|relation| relation.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_nested_read_only_logical_queries() {
        validate("WITH visible AS (SELECT id FROM records) SELECT count(*) AS n FROM visible WHERE id IN (SELECT record_id FROM facet_values)").unwrap();
        validate("SELECT ID FROM RECORDS").unwrap();
    }

    #[test]
    fn rejects_escape_and_exotic_forms() {
        for sql in [
            "SELECT * FROM main.records",
            "SELECT * FROM pragma_table_info('records')",
            "SELECT * FROM records INDEXED BY anything",
            "SELECT rowid FROM records",
            "SELECT load_extension('x')",
            "SELECT id IN records FROM records",
            "WITH records AS (SELECT 1) SELECT * FROM records",
            "WITH ReCoRdS AS (SELECT 1) SELECT * FROM ReCoRdS",
            "ATTACH ':memory:' AS aux",
            "EXPLAIN SELECT * FROM records",
            "SELECT * FROM records; SELECT * FROM links",
        ] {
            assert!(validate(sql).is_err(), "accepted {sql}");
        }
    }
}
