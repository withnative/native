//! Exact Turso 0.8.0 parser admission for caller SQL.

use std::collections::BTreeSet;

use turso_parser::ast::{
    Cmd, Expr, FrameBound, FrameClause, FromClause, FunctionTail, GroupBy, JoinConstraint, Limit,
    Name, OneSelect, Operator, Over, ResultColumn, Select, SelectTable, SortedColumn, Stmt, Type,
    TypeSize, Window, With,
};
use turso_parser::parser::Parser;

use super::sql_contract::{self, QuerySqlErrorCategory};
use crate::Result;

/// I2: function admission is the shared portable subset
/// (`sql_contract::is_portable_function`, plus function-form `like`);
/// the local AST walk below is defence in depth behind the classifier.
const SAFE_CAST_TYPES: [&str; 8] = [
    "", "blob", "integer", "numeric", "real", "text", "none", "boolean",
];
const SAFE_COLLATIONS: [&str; 3] = ["binary", "nocase", "rtrim"];
const HIDDEN_ROWIDS: [&str; 3] = ["rowid", "_rowid_", "oid"];

fn reject(category: QuerySqlErrorCategory, detail: impl AsRef<str>) -> crate::Error {
    sql_contract::categorized_error(category, detail)
}

pub(crate) fn validate(sql: &str) -> Result<()> {
    // I1 (E1 M2): the Turso AST normalises every parameter spelling to a
    // bare index, so the `?N`-only spelling check cannot live on
    // `Expr::Variable`. Run the shared classifier first — the same check
    // that gates the SQLite and Postgres validates.
    sql_contract::classify_single_read_statement(sql_contract::QuerySqlProfile::TursoLocal, sql)?;
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
    // I3 (AST design): shared determinism rules on the already-parsed AST.
    check_determinism_rules(&select)?;
    validate_select(&select, &[])
}

/// Parse one SELECT the way the Turso profile does (single statement).
/// Test-only, for the rules-agreement differential: a parse failure fails
/// closed here (this parser IS the Turso engine's), unlike the SQLite
/// path's fail-open to its engine gate.
#[cfg(test)]
pub(crate) fn parse_for_rules(sql: &str) -> Result<Select> {
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
    Ok(select)
}

/// Shared I3 determinism rules on an already-parsed statement, sans the
/// Turso relation/function gates below.
pub(crate) fn check_determinism_rules(select: &Select) -> Result<()> {
    super::turso_ast_rules::check_limit_order(select)?;
    super::turso_ast_rules::check_group_columns(select)?;
    Ok(())
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
        // Only relations this profile serves are reserved. A relation outside
        // it has no table here to shadow, and reserving every catalog name
        // would break a working statement each time a relation is added.
        if is_turso_relation(name) || !local.insert(name.to_ascii_lowercase()) {
            return Err(reject(
                QuerySqlErrorCategory::UnauthorizedRelation,
                "CTE names cannot collide with this profile's logical relations or each other",
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
                let base = format!("relation '{relation}' is outside the logical catalog");
                let detail = match sql_contract::blocked_relation_repair(
                    relation,
                    sql_contract::QuerySqlProfile::TursoLocal,
                ) {
                    Some(repair) => format!("{base}. {repair}"),
                    None => base,
                };
                return Err(reject(QuerySqlErrorCategory::UnauthorizedRelation, detail));
            }
            // Refuse a reference to a relation this profile does not serve by
            // name, not by dependency: a statement reading no column of it
            // never enters the dependency set the later profile gate checks.
            if !in_scope && !is_turso_relation(relation) {
                return Err(reject(
                    QuerySqlErrorCategory::UnauthorizedRelation,
                    format!(
                        "query_sql relation '{relation}' is unavailable in profile turso-local"
                    ),
                ));
            }
            if let Some(alias) = alias {
                checked_name(alias.name())?;
            }
        }
        SelectTable::TableCall(name, _, _) => {
            let called = name.name.as_str();
            let base = "table-valued functions are unavailable".to_string();
            let detail = match sql_contract::blocked_relation_repair(
                called,
                sql_contract::QuerySqlProfile::TursoLocal,
            ) {
                Some(repair) => format!("{base}. {repair}"),
                None => base,
            };
            return Err(reject(QuerySqlErrorCategory::UnauthorizedRelation, detail));
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
        Expr::Binary(lhs, operator, rhs) => {
            // I2 review: `->` / `->>` are JSON access, which the portable
            // profile drops like `json_*` (SQLite and Postgres both deny
            // them). The operator was previously ignored, admitting JSON
            // extraction on Turso alone.
            if matches!(operator, Operator::ArrowRight | Operator::ArrowRightShift) {
                let spelling = match operator {
                    Operator::ArrowRight => "->",
                    _ => "->>",
                };
                let repair = sql_contract::portable_function_repair("json_extract")
                    .unwrap_or("unavailable on the portable profile");
                return Err(reject(
                    QuerySqlErrorCategory::UnsafeStatement,
                    format!("operator '{spelling}' is unavailable — {repair}"),
                ));
            }
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
    // Per-engine scope is the shared registry's single source
    // (`function_supported_on`), so this gate cannot drift from the contract
    // metadata. `like` is not a registry row and keeps its function-form
    // admission (Postgres spells it `~~`).
    if name.eq_ignore_ascii_case("like") {
        return Ok(());
    }
    if sql_contract::function_decl(name).is_some() {
        if sql_contract::function_supported_on(name, sql_contract::QuerySqlProfile::TursoLocal) {
            return Ok(());
        }
        // Plain caller advice only. The engine-internal reason the six
        // window rows are scoped off TursoLocal (exact 0.8.0 resolves the
        // names but compiles every window program as non-read-only, refused
        // by the isolated query-only projection) lives in the evidence and
        // tests, not in the user-facing repair.
        return Err(reject(
            QuerySqlErrorCategory::UnsafeStatement,
            format!(
                "function '{name}' is unavailable on turso-local; run it on SQLite-local or compute it in the caller"
            ),
        ));
    }
    // I2: dropped names carry a shared repair (defence in depth behind the
    // classifier, which reports the identical message first).
    if let Some(detail) = sql_contract::unavailable_function_detail(name) {
        return Err(reject(QuerySqlErrorCategory::UnsafeStatement, detail));
    }
    Err(reject(
        QuerySqlErrorCategory::UnsafeStatement,
        format!("function '{name}' is unavailable"),
    ))
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
            match sql_contract::blocked_relation_repair(
                value,
                sql_contract::QuerySqlProfile::TursoLocal,
            ) {
                Some(repair) => {
                    format!("identifier '{value}' is unavailable. {repair}")
                }
                None => format!("identifier '{value}' is unavailable"),
            },
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

fn is_turso_relation(name: &str) -> bool {
    let profile = sql_contract::QuerySqlProfile::TursoLocal.contract().id;
    sql_contract::LOGICAL_RELATIONS.iter().any(|relation| {
        relation.name.eq_ignore_ascii_case(name) && relation.profiles.contains(&profile)
    })
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
    fn shared_rules_wiring_and_repair_wording() {
        // What this checks, honestly: (1) the SQLite and Turso entry
        // points stay wired to the same shared rules — `check_statement`
        // versus `parse_for_rules` + `check_determinism_rules` agree on
        // every comparable statement, so a future per-profile wiring
        // divergence fails loudly; (2) every rejection over the corpus
        // names an intended repair (LIMIT needs ORDER BY, GROUP BY needs
        // keys). What it does NOT check: rule semantics themselves. Both
        // arms call the same `check_limit_order` + `check_group_columns`,
        // so agreement is true by construction and cannot catch
        // rule-logic classes (false admits/rejects live in the shared
        // rules both arms call — those are pinned by the
        // `turso_ast_rules` unit tests, not here). Parse failures differ
        // by design (SQLite fail-opens to its engine gate; this parser IS
        // the Turso engine's, so it fail-closes) and are skipped here.
        // Universe: the shared conformance corpus plus the 75 distinct
        // logged census statements.
        use super::super::sql_contract::{classify_single_read_statement, QuerySqlProfile};
        let census: Vec<String> =
            serde_json::from_str(include_str!("sql_census_fixture.json")).unwrap();
        let corpus = super::super::sql_conformance::corpus();
        let mut compared = 0;
        for sql in corpus
            .iter()
            .map(|case| case.sql)
            .chain(census.iter().map(String::as_str))
        {
            if classify_single_read_statement(QuerySqlProfile::SqliteLocal, sql).is_err()
                || classify_single_read_statement(QuerySqlProfile::TursoLocal, sql).is_err()
            {
                continue;
            }
            let Ok(parsed) = parse_for_rules(sql) else {
                continue;
            };
            let sqlite = super::super::turso_ast_rules::check_statement(sql).is_ok();
            let turso = check_determinism_rules(&parsed);
            assert_eq!(
                sqlite,
                turso.is_ok(),
                "shared rules wiring diverged across profiles: {sql}"
            );
            if let Err(error) = turso {
                let message = error.to_string();
                assert!(
                    message.contains("ORDER BY") || message.contains("GROUP BY"),
                    "unintended rule rejection: {sql}: {message}"
                );
            }
            compared += 1;
        }
        assert!(compared > 0, "wiring check ran on nothing");
        println!("rules wiring: {compared} statements compared");
    }

    #[test]
    fn determinism_rules_reject_and_admit() {
        // I3 (AST design): LIMIT needs ORDER BY and bare GROUP BY columns
        // fail; NULLS ordering and division are native here, never rejected.
        for sql in [
            "SELECT id FROM records ORDER BY id LIMIT 5",
            "SELECT kind, count(*) FROM records GROUP BY kind",
            "SELECT id FROM records ORDER BY id",
            "SELECT 1 / 0 FROM records",
            "SELECT created_at_ms / 604800000 AS week, count(*) AS n FROM records GROUP BY week ORDER BY week",
            "SELECT created_at_ms / 604800000 AS week, count(*) AS n FROM records GROUP BY 1 ORDER BY 1",
            "SELECT kind, count(*) AS n FROM records GROUP BY kind HAVING n > 0",
            // Correlated unqualified outer refs resolve outside, where
            // GROUP BY fixes their value.
            "SELECT (SELECT count(*) + kind FROM facet_values) FROM records GROUP BY kind",
            "SELECT kind, count(*) FROM records GROUP BY kind HAVING count(*) > (SELECT count(*) + kind FROM facet_values)",
            // Qualification spelling never decides grouping.
            "SELECT records.kind, count(*) FROM records GROUP BY kind",
            "SELECT kind, count(*) FROM records GROUP BY records.kind",
            "SELECT r.kind, count(*) FROM records r GROUP BY kind",
            // ORDER BY under grouping: keys, aggregates, aliases, ordinals.
            "SELECT kind, count(*) FROM records GROUP BY kind ORDER BY kind",
            "SELECT kind, count(*) AS n FROM records GROUP BY kind ORDER BY n DESC",
            // Qualified outer group key admits.
            "SELECT kind, (SELECT count(*) + t.kind FROM facet_values) FROM records t GROUP BY kind",
        ] {
            validate(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        for (sql, repair) in [
            (
                "SELECT id FROM records LIMIT 5",
                "add ORDER BY over a unique key",
            ),
            (
                "SELECT kind, count(*) FROM records GROUP BY type",
                "must appear in GROUP BY or inside an aggregate",
            ),
            // Genuinely bare inner column (not an outer group key).
            (
                "SELECT (SELECT count(*) + other FROM facet_values) FROM records GROUP BY kind",
                "must appear in GROUP BY or inside an aggregate",
            ),
            // ORDER BY on a non-grouped column fails with the same repair.
            (
                "SELECT kind, count(*) FROM records GROUP BY kind ORDER BY created_at_ms",
                "must appear in GROUP BY or inside an aggregate",
            ),
            // Self-join: the other alias's column is not grouped.
            (
                "SELECT b.kind, count(*) FROM records a JOIN records b ON a.id = b.id GROUP BY a.kind",
                "must appear in GROUP BY or inside an aggregate",
            ),
            // Shadowed inner reference (SQLite binds innermost): qualify
            // the outer table or group it.
            (
                "SELECT (SELECT count(*) + kind FROM records) FROM records GROUP BY kind",
                "may resolve to the subquery's own FROM",
            ),
            // Qualified outer non-key: the repair points at the enclosing query.
            (
                "SELECT kind, (SELECT count(*) + t.name FROM facet_values) FROM records t GROUP BY kind",
                "belongs to an enclosing query that groups by other columns",
            ),
        ] {
            let error = validate(sql).unwrap_err().to_string();
            assert!(error.contains(repair), "{sql}: missing repair: {error}");
        }
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

    /// Relations outside the turso-local profile are refused by name, so a
    /// statement that reads none of their columns cannot slip past the
    /// dependency-based profile gate. Their names stay free for CTEs, nested
    /// or at top level, while names this profile serves stay reserved.
    #[test]
    fn relations_outside_the_profile_are_refused_by_name_and_free_for_ctes() {
        for sql in [
            "SELECT config_id FROM schema_config_json_nodes",
            "SELECT count(*) AS n FROM schema_config_json_nodes",
            "SELECT count(*) AS n FROM schema_config_json_nodes WHERE 0",
            "SELECT * FROM schema_config_json_nodes WHERE 0 ORDER BY ordinal LIMIT 0",
            "SELECT EXISTS(SELECT 1 FROM schema_config_json_nodes) AS n",
            "SELECT ordinal FROM effective_relationship_endpoints",
            "SELECT count(*) AS n FROM effective_relationship_endpoints",
            "SELECT count(*) AS n FROM actors",
            "SELECT count(*) AS n FROM actors a1, actors a2",
            "SELECT actor FROM actors",
            "SELECT e.id FROM content_events e JOIN actors a USING (actor)",
            "SELECT count(*) AS n FROM agent_activity",
            "SELECT id FROM records WHERE EXISTS (SELECT 1 FROM messages_awaiting_reply)",
            "SELECT id FROM records WHERE EXISTS (WITH other(x) AS (VALUES(1)) SELECT 1 FROM actors)",
            "SELECT run_key FROM runs",
            "SELECT count(*) AS n FROM runs",
            "SELECT count(*) AS n FROM run_intents",
            "SELECT r.run_key, i.intent FROM runs r JOIN run_intents i USING (run_key)",
            "SELECT unread FROM my_message_state",
            "SELECT count(*) AS n FROM my_message_state",
            "SELECT count(*) AS n FROM my_mentions",
            "SELECT count(*) AS n FROM vocabulary_value_json_nodes",
            "SELECT value_id, ordinal FROM vocabulary_value_json_nodes ORDER BY value_id, ordinal",
        ] {
            let error = validate(sql).expect_err(sql).to_string();
            assert!(
                error.contains("is unavailable in profile turso-local"),
                "{sql}: {error}"
            );
        }
        for sql in [
            "WITH schema_config_json_nodes AS (SELECT 1 AS x) SELECT x FROM schema_config_json_nodes",
            "SELECT 'effective_relationship_endpoints' AS v",
            "WITH effective_relationship_endpoints AS (SELECT 1 AS x) SELECT x FROM effective_relationship_endpoints",
            "SELECT 'schema_config_json_nodes' AS v",
            "SELECT id FROM records -- schema_config_json_nodes",
            "WITH actors AS (SELECT id FROM records) SELECT id FROM actors",
            "WITH agent_activity AS (SELECT id FROM records) SELECT id FROM agent_activity",
            "SELECT id FROM records WHERE EXISTS (WITH actors(x) AS (VALUES(1)), tally AS (SELECT count(*) AS n FROM actors) SELECT n FROM tally)",
            "WITH runs AS (SELECT id FROM records) SELECT id FROM runs",
            "WITH run_intents AS (SELECT id FROM records) SELECT id FROM run_intents",
            "WITH my_message_state AS (SELECT id FROM records) SELECT id FROM my_message_state",
            "WITH my_mentions AS (SELECT id FROM records) SELECT id FROM my_mentions",
        ] {
            validate(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
        assert!(validate("WITH links AS (SELECT 1 AS x) SELECT x FROM links").is_err());
    }

    #[test]
    fn widened_functions_validate_and_dropped_ones_name_the_repair() {
        // I2: the classifier rejects dropped names first with the shared
        // repair; the AST walk below is defence in depth.
        for sql in [
            "SELECT lower(name), upper(name) FROM records",
            "SELECT trim(name), replace(name, 'a', 'b') FROM records",
            // I2 review: two-argument `trim(x, chars)` matches Postgres
            // `btrim(x, chars)` exactly, so it validates on every engine.
            "SELECT trim(name, 'x') FROM records",
            "SELECT substr(name, 1, 2) FROM records",
            "SELECT coalesce(name, 'z'), nullif(name, 'z') FROM records",
            "SELECT abs(id), length(name), round(1.5) FROM records",
            "SELECT avg(id), count(*), sum(id), min(id), max(id) FROM records",
            "SELECT CASE WHEN id = 1 THEN 'one' ELSE 'other' END FROM records",
            "SELECT CAST(id AS TEXT) FROM records",
            "SELECT id FROM records WHERE name LIKE 'conf:%'",
        ] {
            validate(sql).unwrap_or_else(|error| panic!("{sql}: {error}"));
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
            // quoted calls before the AST walk.
            // The six registry window rows are scoped off TursoLocal, so
            // these fail closed with plain per-engine advice.
            (
                "SELECT rank() OVER (ORDER BY id) FROM records",
                "unavailable on turso-local",
            ),
            (
                "SELECT row_number() OVER (ORDER BY id) FROM records",
                "unavailable on turso-local",
            ),
            (
                "SELECT dense_rank() OVER (ORDER BY id) FROM records",
                "unavailable on turso-local",
            ),
            (
                "SELECT \"round\"(1.5, 2) FROM records",
                "catalog numeric type",
            ),
            (
                "SELECT \"instr\"(body, 'x') FROM records",
                "use substr() or LIKE",
            ),
        ] {
            let error = validate(sql).unwrap_err().to_string();
            assert!(error.contains(repair), "{sql}: missing repair: {error}");
        }
    }

    #[test]
    fn json_access_operators_are_rejected_with_the_json_repair() {
        // I2 review: `->` / `->>` are JSON access, dropped like `json_*`
        // (SQLite and Postgres deny them). They previously slipped past
        // the AST walk, which ignored the binary operator.
        for (sql, spelling) in [
            ("SELECT body->>'$.a' FROM records", "->>"),
            ("SELECT body->'$.a' FROM records", "->"),
        ] {
            let error = validate(sql).unwrap_err().to_string();
            assert!(
                error.contains(&format!("operator '{spelling}' is unavailable")),
                "{sql}: missing operator refusal: {error}"
            );
            assert!(
                error.contains("facet_values, facet_observations"),
                "{sql}: missing JSON repair: {error}"
            );
        }
    }

    #[test]
    fn rejects_non_positional_placeholders_with_the_portable_repair() {
        // I1 (E1 M2): `?N` is the only admitted spelling. The parser would
        // normalise every other spelling to a bare index, so the shared
        // classifier runs first and names the fix.
        let bare = validate("SELECT id FROM records WHERE id = ?").unwrap_err();
        assert!(
            bare.to_string()
                .contains("Postgres `?`/`?|`/`?&` operators"),
            "missing jsonb note: {bare}"
        );
        for sql in [
            "SELECT id FROM records WHERE id = $1",
            "SELECT id FROM records WHERE id = ?0",
            "SELECT id FROM records WHERE id = :name",
            "SELECT id FROM records WHERE id = @name",
            "SELECT id FROM records WHERE id = $name",
        ] {
            let error = validate(sql).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("use positional `?N` placeholders"),
                "{sql}: missing repair: {error}"
            );
        }
        validate("SELECT id FROM records WHERE id = ?1").unwrap();
        validate("SELECT '$1' AS value").unwrap();
    }

    #[test]
    fn refuses_window_functions_with_the_per_engine_scope() {
        // The six window rows are scoped off TursoLocal by the shared
        // registry; the validator fails closed with plain caller advice.
        // Exact-0.8.0 reason (engine-internal, evidence only): the engine
        // resolves the names but compiles every window program as
        // non-read-only, refused by the isolated query-only projection.
        for sql in [
            "SELECT rank() OVER (ORDER BY id) FROM records",
            "SELECT row_number() OVER (ORDER BY id) FROM records",
            "SELECT dense_rank() OVER (ORDER BY id) FROM records",
            "SELECT ntile(2) OVER (ORDER BY id) FROM records",
            "SELECT cume_dist() OVER (ORDER BY id) FROM records",
            "SELECT percent_rank() OVER (ORDER BY id) FROM records",
            "SELECT RANK() OVER (PARTITION BY type ORDER BY id) FROM records",
        ] {
            let error = validate(sql).unwrap_err().to_string();
            assert!(
                error.contains("unavailable on turso-local") && error.contains("SQLite-local"),
                "{sql}: missing per-engine refusal: {error}"
            );
        }
        // Non-window rankings stay admitted.
        validate("SELECT id FROM records ORDER BY id").unwrap();
        validate("SELECT count(*) AS n FROM records").unwrap();
    }

    #[test]
    fn blocked_probes_name_the_catalog_fix() {
        let rendered = |sql: &str| validate(sql).unwrap_err().to_string();
        let probe = rendered("SELECT * FROM sqlite_master");
        assert!(probe.contains("catalog introspection"), "{probe}");
        let pragma = rendered("SELECT * FROM pragma_table_info('records')");
        assert!(pragma.contains("catalog introspection"), "{pragma}");
        let mapped = rendered("SELECT * FROM relationships");
        // effective_relationships is sqlite-only: Turso falls through to
        // the profile-filtered list instead of mis-pointing at it.
        assert!(!mapped.contains("effective_relationships"), "{mapped}");
        assert!(
            !mapped.contains("effective_relationship_endpoints"),
            "{mapped}"
        );
        assert!(
            mapped.contains("Queryable relations on turso-local:"),
            "{mapped}"
        );
        let unmapped = rendered("SELECT * FROM member_contexts");
        assert!(
            unmapped.contains("Queryable relations on turso-local:"),
            "{unmapped}"
        );
    }
}
