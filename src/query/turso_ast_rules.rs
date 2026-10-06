//! Shared SQLite-dialect AST determinism rules (E1 M2 I3, AST design).
//!
//! `turso_parser` (now non-optional; the `turso` engine stays behind
//! `turso-local`) parses what the SQLite path admits — historically
//! verified 17/17 on the conformance corpus and 47/49 on a SQLite-shape
//! battery (the 2 failures were SQLite syntax errors too); the 0.8.0 pin
//! re-evidences agreement through the shared-rules differential tests,
//! which run the current corpus plus the logged census on every run. Both
//! the SQLite (`sql.rs`) and
//! Turso (`turso_validate.rs`) validators run these rules on the parsed
//! statement; SQLite/Turso text is never rewritten (both engines already
//! carry the target NULL/division semantics).
//!
//! Rules: LIMIT without ORDER BY is rejected (OFFSET needs LIMIT
//! syntactically in SQLite, so `limit.is_some()` covers it; FETCH is not
//! SQLite syntax), and bare GROUP BY columns are rejected with aggregate,
//! FILTER, window and grouped-expression exemptions.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use turso_parser::ast::{
    CommonTableExpr, Expr, FromClause, FunctionTail, JoinConstraint, Literal, OneSelect, Over,
    ResultColumn, Select, SelectTable, Window,
};
use turso_parser::ast::{JoinOperator, JoinType};

use super::sql_contract::{self, QuerySqlErrorCategory};

/// Statements the AST layer could not parse and deferred to the engine.
/// Fail-open by design (the engine gate still decides); counted so the
/// differential test and reviews can see the path is exercised.
static FAIL_OPEN_PARSES: AtomicU64 = AtomicU64::new(0);

/// How many statements this process deferred to the engine unparsed.
#[cfg(test)]
pub fn fail_open_count() -> u64 {
    FAIL_OPEN_PARSES.load(Ordering::Relaxed)
}

fn reject(detail: impl AsRef<str>) -> crate::Error {
    sql_contract::categorized_error(QuerySqlErrorCategory::UnsafeStatement, detail)
}

/// Why the AST layer deferred a statement to the engine (fail-open).
/// Logged as a bounded kind, never with the SQL text.
enum FailOpenReason {
    Empty,
    MultiStatement,
    NonSelect,
    // Parser detail is kept for `parse_select` error fidelity (test-only
    // callers); production logs the kind via `as_str`, never this text.
    #[allow(dead_code)]
    Parse(String),
}

impl FailOpenReason {
    fn as_str(&self) -> &'static str {
        match self {
            FailOpenReason::Empty => "empty",
            FailOpenReason::MultiStatement => "multi_statement",
            FailOpenReason::NonSelect => "non_select",
            FailOpenReason::Parse(_) => "parse_error",
        }
    }
}

/// Parse one SELECT statement (single-statement gate included).
/// Test-only: production goes through [`check_statement`] (fail-open).
#[cfg(test)]
pub fn parse_select(sql: &str) -> crate::Result<Select> {
    parse_select_inner(sql).map_err(|reason| match reason {
        FailOpenReason::Parse(detail) => reject(detail),
        FailOpenReason::Empty => reject("empty SQL"),
        FailOpenReason::MultiStatement => reject("a single statement only"),
        FailOpenReason::NonSelect => reject("SQLite query_sql accepts one SELECT statement only"),
    })
}

fn parse_select_inner(sql: &str) -> Result<Select, FailOpenReason> {
    use turso_parser::ast::{Cmd, Stmt};
    use turso_parser::parser::Parser;
    let mut parser = Parser::new(sql.as_bytes());
    let cmd = parser
        .next()
        .transpose()
        .map_err(|error| FailOpenReason::Parse(error.to_string()))?
        .ok_or(FailOpenReason::Empty)?;
    if parser.next().is_some() {
        return Err(FailOpenReason::MultiStatement);
    }
    match cmd {
        Cmd::Stmt(Stmt::Select(select)) => Ok(select),
        _ => Err(FailOpenReason::NonSelect),
    }
}

/// Ad-hoc E2 default-ORDER gate: true when the top-level statement carries
/// LIMIT with no ORDER BY. Fail-open (false) when the text does not parse as
/// one SELECT, so the existing refusal path decides — never rewrite what the
/// AST cannot see (`EXPLAIN`, keyword-as-identifier shapes, unparseable
/// text). Nested levels are irrelevant here: they keep their own refusal in
/// `check_limit_order`, which still runs on the rewritten text.
pub fn top_level_unordered_limit(sql: &str) -> bool {
    match parse_select_inner(sql) {
        Ok(select) => select.limit.is_some() && select.order_by.is_empty(),
        Err(_) => false,
    }
}

/// Run every shared rule on one caller statement. A statement the parser
/// cannot handle is admitted for the engine to decide (fail-open); the
/// deferral is counted and warned (bounded kind + length only, never the
/// SQL text) so the differential fuzz promised by the design has signal.
pub fn check_statement(sql: &str) -> crate::Result<()> {
    let select = match parse_select_inner(sql) {
        Ok(select) => select,
        Err(reason) => {
            FAIL_OPEN_PARSES.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                sql_len = sql.len(),
                reason = reason.as_str(),
                "turso AST rules deferred a statement to the engine gate"
            );
            return Ok(());
        }
    };
    check_limit_order(&select)?;
    check_group_columns(&select)
}

/// Reject LIMIT without ORDER BY at every nesting level (subqueries,
/// compounds, CTEs).
pub fn check_limit_order(select: &Select) -> crate::Result<()> {
    if select.limit.is_some() && select.order_by.is_empty() {
        return Err(reject(
            "LIMIT without ORDER BY: add ORDER BY over a unique key",
        ));
    }
    if let Some(with) = &select.with {
        for cte in &with.ctes {
            check_limit_order(&cte.select)?;
        }
    }
    check_one_limit(&select.body.select)?;
    for compound in &select.body.compounds {
        check_one_limit(&compound.select)?;
    }
    for sorted in &select.order_by {
        check_expr_selects(&sorted.expr, &check_limit_order)?;
    }
    if let Some(limit) = &select.limit {
        check_expr_selects(&limit.expr, &check_limit_order)?;
        if let Some(offset) = &limit.offset {
            check_expr_selects(offset, &check_limit_order)?;
        }
    }
    Ok(())
}

fn check_one_limit(one: &OneSelect) -> crate::Result<()> {
    if let OneSelect::Select {
        columns,
        from,
        where_clause,
        group_by,
        window_clause,
        ..
    } = one
    {
        for column in columns {
            if let ResultColumn::Expr(expr, _) = column {
                check_expr_selects(expr, &check_limit_order)?;
            }
        }
        if let Some(from) = from {
            check_from_limit(&from.select)?;
            for join in &from.joins {
                check_from_limit(&join.table)?;
            }
        }
        if let Some(where_clause) = where_clause {
            check_expr_selects(where_clause, &check_limit_order)?;
        }
        if let Some(having) = group_by.as_ref().and_then(|group| group.having.as_ref()) {
            check_expr_selects(having, &check_limit_order)?;
        }
        for definition in window_clause {
            check_window_selects(&definition.window, &check_limit_order)?;
        }
    } else if let OneSelect::Values(rows) = one {
        for row in rows {
            for expr in row {
                check_expr_selects(expr, &check_limit_order)?;
            }
        }
    }
    Ok(())
}

fn check_from_limit(table: &SelectTable) -> crate::Result<()> {
    match table {
        SelectTable::Select(select, _) => check_limit_order(select),
        SelectTable::Sub(from, _) => {
            check_from_limit(&from.select)?;
            for join in &from.joins {
                check_from_limit(&join.table)?;
            }
            Ok(())
        }
        SelectTable::Table(..) | SelectTable::TableCall(..) => Ok(()),
    }
}

/// Rule-input shape gate (task 81c1d95, pure slice): the conservative subset
/// whose dependencies the authorizer proves completely. Unlike
/// [`check_statement`] (fail-open: the engine decides what the parser cannot),
/// this is fail-CLOSED: an unparseable statement is rejected, because the
/// authorizer alone cannot prove completeness — USING/NATURAL joins hide reads
/// the callback never sees. Runs on the parsed AST, so quoting, comments and
/// string literals cannot smuggle past it. Shared by the SQLite and Turso
/// validators through the same entry point (no rule-local copy).
pub fn check_rule_statement(sql: &str) -> crate::Result<()> {
    parse_rule_select(sql).map(|_| ())
}

/// Shared fail-closed AST entry for registry-owned semantic proofs.
pub(super) fn parse_rule_select(sql: &str) -> crate::Result<Select> {
    let select = parse_select_inner(sql).map_err(|reason| match reason {
        FailOpenReason::Parse(detail) => reject(detail),
        FailOpenReason::Empty => reject("empty SQL"),
        FailOpenReason::MultiStatement => reject("a single statement only"),
        FailOpenReason::NonSelect => reject("rule inputs accept one SELECT statement only"),
    })?;
    check_rule_select(&select)?;
    Ok(select)
}

fn check_rule_select(select: &Select) -> crate::Result<()> {
    if let Some(with) = &select.with {
        for cte in &with.ctes {
            // Every logical name is reserved here (unlike saved SQL's guarded
            // subset): a same-name CTE's column-less reads could fake a
            // population dependency the rule never earned.
            let name = cte.tbl_name.as_str().to_ascii_lowercase();
            if sql_contract::is_logical_relation(&name) {
                return Err(reject(format!(
                    "rule inputs cannot shadow logical relation '{name}' with a CTE"
                )));
            }
            check_rule_select(&cte.select)?;
        }
    }
    check_rule_one(&select.body.select)?;
    for compound in &select.body.compounds {
        check_rule_one(&compound.select)?;
    }
    for sorted in &select.order_by {
        check_expr_selects(&sorted.expr, &check_rule_select)?;
    }
    if let Some(limit) = &select.limit {
        check_expr_selects(&limit.expr, &check_rule_select)?;
        if let Some(offset) = &limit.offset {
            check_expr_selects(offset, &check_rule_select)?;
        }
    }
    Ok(())
}

fn check_rule_one(one: &OneSelect) -> crate::Result<()> {
    if let OneSelect::Values(rows) = one {
        for row in rows {
            for expr in row {
                check_expr_selects(expr, &check_rule_select)?;
            }
        }
        return Ok(());
    }
    let OneSelect::Select {
        columns,
        from,
        where_clause,
        group_by,
        window_clause,
        ..
    } = one
    else {
        return Ok(());
    };
    for column in columns {
        match column {
            ResultColumn::Expr(expr, _) => check_expr_selects(expr, &check_rule_select)?,
            ResultColumn::Star | ResultColumn::TableStar(_) => {
                return Err(reject(
                    "rule inputs need explicit output columns, never SELECT *",
                ));
            }
        }
    }
    if let Some(from) = from {
        check_rule_from(from)?;
    }
    if let Some(where_clause) = where_clause {
        check_expr_selects(where_clause, &check_rule_select)?;
    }
    if let Some(group_by) = group_by {
        for key in &group_by.exprs {
            check_expr_selects(key, &check_rule_select)?;
        }
        if let Some(having) = group_by.having.as_ref() {
            check_expr_selects(having, &check_rule_select)?;
        }
    }
    for definition in window_clause {
        check_window_selects(&definition.window, &check_rule_select)?;
    }
    Ok(())
}

fn check_rule_from(from: &FromClause) -> crate::Result<()> {
    check_rule_table(&from.select)?;
    for join in &from.joins {
        // NATURAL hides the join columns from the authorizer (parent
        // reproduced: only the outer side is reported), so it is rejected;
        // explicit JOIN ... ON reads both sides and stays supported.
        if let JoinOperator::TypedJoin(Some(kind)) = join.operator {
            if kind.contains(JoinType::NATURAL) {
                return Err(reject(
                    "rule inputs reject NATURAL joins: name the join columns with ON",
                ));
            }
        }
        if matches!(join.constraint, Some(JoinConstraint::Using(_))) {
            return Err(reject(
                "rule inputs reject USING: name the join columns with ON",
            ));
        }
        check_rule_table(&join.table)?;
        if let Some(JoinConstraint::On(expr)) = join.constraint.as_ref() {
            check_expr_selects(expr, &check_rule_select)?;
        }
    }
    Ok(())
}

fn check_rule_table(table: &SelectTable) -> crate::Result<()> {
    match table {
        SelectTable::Table(..) => Ok(()),
        SelectTable::TableCall(..) => Err(reject("rule inputs reject table functions")),
        SelectTable::Select(select, _) => check_rule_select(select),
        SelectTable::Sub(from, _) => check_rule_from(from),
    }
}

/// Run `check` on every SELECT nested in an expression. The match is
/// exhaustive over expression shapes holding children, so no nesting level
/// escapes the caller (LIMIT and GROUP BY both build on this).
pub fn check_expr_selects(
    expr: &Expr,
    check: &dyn Fn(&Select) -> crate::Result<()>,
) -> crate::Result<()> {
    match expr {
        Expr::Exists(select) | Expr::Subquery(select) => check(select),
        Expr::InSelect { lhs, rhs, .. } => {
            check_expr_selects(lhs, check)?;
            check(rhs)
        }
        Expr::Binary(left, _, right) => {
            check_expr_selects(left, check)?;
            check_expr_selects(right, check)
        }
        Expr::Unary(_, operand)
        | Expr::IsNull(operand)
        | Expr::NotNull(operand)
        | Expr::Collate(operand, _) => check_expr_selects(operand, check),
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => {
            if let Some(base) = base {
                check_expr_selects(base, check)?;
            }
            for (when, then) in when_then_pairs {
                check_expr_selects(when, check)?;
                check_expr_selects(then, check)?;
            }
            if let Some(else_expr) = else_expr {
                check_expr_selects(else_expr, check)?;
            }
            Ok(())
        }
        Expr::Cast { expr, .. } => check_expr_selects(expr, check),
        Expr::Like {
            lhs, rhs, escape, ..
        } => {
            check_expr_selects(lhs, check)?;
            check_expr_selects(rhs, check)?;
            if let Some(escape) = escape {
                check_expr_selects(escape, check)?;
            }
            Ok(())
        }
        Expr::Between {
            lhs, start, end, ..
        } => {
            check_expr_selects(lhs, check)?;
            check_expr_selects(start, check)?;
            check_expr_selects(end, check)
        }
        Expr::InList { lhs, rhs, .. } => {
            check_expr_selects(lhs, check)?;
            for value in rhs {
                check_expr_selects(value, check)?;
            }
            Ok(())
        }
        Expr::InTable { lhs, args, .. } => {
            check_expr_selects(lhs, check)?;
            for arg in args {
                check_expr_selects(arg, check)?;
            }
            Ok(())
        }
        Expr::FunctionCall {
            args,
            order_by,
            within_group,
            filter_over,
            ..
        } => {
            for arg in args {
                check_expr_selects(arg, check)?;
            }
            for sorted in order_by.iter().chain(within_group.iter()) {
                check_expr_selects(&sorted.expr, check)?;
            }
            check_tail_selects(filter_over, check)
        }
        Expr::FunctionCallStar { filter_over, .. } => check_tail_selects(filter_over, check),
        Expr::Parenthesized(values) => {
            for value in values {
                check_expr_selects(value, check)?;
            }
            Ok(())
        }
        Expr::FieldAccess { base, .. } => check_expr_selects(base, check),
        Expr::Array { elements } => {
            for element in elements {
                check_expr_selects(element, check)?;
            }
            Ok(())
        }
        Expr::Subscript { base, index } => {
            check_expr_selects(base, check)?;
            check_expr_selects(index, check)
        }
        Expr::SubqueryResult { lhs, .. } => {
            if let Some(lhs) = lhs {
                check_expr_selects(lhs, check)?;
            }
            Ok(())
        }
        Expr::Raise(_, operand) => {
            if let Some(operand) = operand {
                check_expr_selects(operand, check)?;
            }
            Ok(())
        }
        // Leaves and name-only positions: Register, DoublyQualified, Id,
        // Column, RowId, Literal, Name, Qualified, Variable, Default.
        _ => Ok(()),
    }
}

fn check_tail_selects(
    tail: &FunctionTail,
    check: &dyn Fn(&Select) -> crate::Result<()>,
) -> crate::Result<()> {
    if let Some(filter) = &tail.filter_clause {
        check_expr_selects(filter, check)?;
    }
    if let Some(Over::Window(window)) = &tail.over_clause {
        check_window_selects(window, check)?;
    }
    Ok(())
}

fn check_window_selects(
    window: &Window,
    check: &dyn Fn(&Select) -> crate::Result<()>,
) -> crate::Result<()> {
    for partition in &window.partition_by {
        check_expr_selects(partition, check)?;
    }
    for sorted in &window.order_by {
        check_expr_selects(&sorted.expr, check)?;
    }
    Ok(())
}

/// Portable group aggregates. The classifier rejects the rest first, so any
/// other call is walked as a scalar function (its arguments must group).
const AGGREGATES: &[&str] = &["sum", "count", "avg", "min", "max"];

fn lower(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Grouping context one enclosing query level exposes to correlated
/// subqueries: its group-key column names (lowercased), its FROM labels,
/// and what its FROM may own, so a name resolves the way SQLite binds
/// it — innermost scope first. Expression-position subqueries see every
/// enclosing frame; FROM subqueries and CTE bodies start fresh (SQLite
/// has no LATERAL, so they cannot be correlated).
#[derive(Clone, Default)]
struct OuterFrame {
    /// Whether this level groups (GROUP BY or aggregates). An ungrouped
    /// level constrains nothing: any of its columns may be correlated.
    grouped: bool,
    key_names: std::collections::HashSet<String>,
    labels: std::collections::HashSet<String>,
    shadow: ShadowSet,
}

/// Base column name of a plain column reference (`Id`/`Name`,
/// `Qualified`/`DoublyQualified`), lowercased for SQLite's
/// case-insensitive resolution. Complex expressions have none.
fn column_base_name(expr: &Expr) -> Option<String> {
    column_parts(expr).0
}

/// (base name, qualifier) of a plain column reference, lowercased.
/// Complex expressions yield no parts.
fn column_parts(expr: &Expr) -> (Option<String>, Option<String>) {
    match expr {
        Expr::Id(name) | Expr::Name(name) => (Some(lower(name.as_str())), None),
        Expr::Qualified(table, column) => {
            (Some(lower(column.as_str())), Some(lower(table.as_str())))
        }
        Expr::DoublyQualified(_, table, column) => {
            (Some(lower(column.as_str())), Some(lower(table.as_str())))
        }
        _ => (None, None),
    }
}

/// Qualifier resolution for one SELECT core, per FROM *occurrence* —
/// two aliases of the same table are different sources, so a column of one
/// is never grouped by the other's key. An unaliased occurrence keeps its
/// bare table name as a valid qualifier; once aliased, the base name is
/// hidden (SQLite: "no such column").
#[derive(Default)]
struct QualScope {
    /// Lowercased FROM label (alias, or table name when unaliased) →
    /// occurrence index.
    canon: HashMap<String, usize>,
    /// Lowercased base table name → occurrence count in this FROM clause.
    occurrences: HashMap<String, usize>,
    /// Occurrence index → lowercased base table name.
    bases: Vec<String>,
    /// Lowercased base names with at least one unaliased occurrence
    /// (bare-name qualification stays valid for these).
    bare_ok: HashSet<String>,
}

impl QualScope {
    /// True when `name` is a base table name hidden behind an alias on
    /// every occurrence — an invalid qualifier SQLite rejects.
    fn is_hidden_base(&self, name: &str) -> bool {
        self.occurrences.contains_key(name) && !self.bare_ok.contains(name)
    }

    /// Base table name behind a qualifier label, if it names a
    /// known occurrence.
    fn base_of(&self, qualifier: &str) -> Option<&str> {
        self.canon
            .get(qualifier)
            .and_then(|id| self.bases.get(*id))
            .map(String::as_str)
    }
}

/// Resolved column identity: same base name (case-insensitive) with
/// compatible qualifiers — both absent, both resolving to the same FROM
/// *occurrence*, or one side absent with the other's base table occurring
/// exactly once (an unqualified name beside a twice-occurring table is
/// ambiguous — SQLite errors there anyway). Unknown qualifiers stay
/// compatible (the relation gate owns table existence).
/// Replaces raw `Expr` equality, which never matched across qualification
/// spellings (`records.kind` vs `kind`, `r.kind` vs `records.kind`).
fn same_column(expr: &Expr, key: &Expr, scope: &QualScope) -> bool {
    let (base, qualifier) = column_parts(expr);
    let (key_base, key_qualifier) = column_parts(key);
    match (base, key_base) {
        (Some(base), Some(key_base)) if base == key_base => match (qualifier, key_qualifier) {
            (None, None) => true,
            (Some(left), Some(right)) => match (scope.canon.get(&left), scope.canon.get(&right)) {
                (Some(left), Some(right)) => left == right,
                // A qualifier hidden behind an alias never matches
                // (SQLite rejects it); other unknown qualifiers stay
                // compatible (the relation gate owns table existence).
                _ => !scope.is_hidden_base(&left) && !scope.is_hidden_base(&right),
            },
            (Some(label), None) | (None, Some(label)) => match scope.base_of(&label) {
                Some(table) => scope
                    .occurrences
                    .get(table)
                    .is_some_and(|count| *count == 1),
                None => true,
            },
        },
        _ => false,
    }
}

/// Visible CTE output columns by lowercased name: `None` when a CTE's
/// outputs are underivable. Accumulated down the query tree — subqueries
/// see enclosing CTEs.
type CteScope = HashMap<String, Option<HashSet<String>>>;

/// What the current level's FROM may own, for the correlated-reference
/// shadow check (SQLite binds names innermost): a name an inner source
/// may own must never be admitted as an outer group key.
#[derive(Clone, Default)]
struct ShadowSet {
    /// Definitely-known inner column names (lowercased).
    known: HashSet<String>,
    /// True when some inner source has underivable columns (unknown
    /// table, table function, `SELECT *` …): any name may be inner.
    unknown: bool,
}

impl ShadowSet {
    fn may_own(&self, name: &str) -> bool {
        self.unknown || self.known.contains(name)
    }

    fn for_from(from: &FromClause, ctes: &CteScope) -> Self {
        let mut shadow = ShadowSet::default();
        let tables = std::iter::once(from.select.as_ref())
            .chain(from.joins.iter().map(|join| join.table.as_ref()));
        for table in tables {
            match table_outputs(table, ctes) {
                Some(columns) => shadow.known.extend(columns),
                None => shadow.unknown = true,
            }
        }
        shadow
    }
}

/// Output columns a SELECT is known to produce, when derivable from the
/// AST: explicit aliases (any spelling), bare unaliased column references
/// (first compound leg names the output), and `*` / `t.*` expanded through
/// the FROM sources (logical relations, visible CTEs, derived tables).
/// VALUES and stars over an underivable source yield `None`.
fn select_outputs(select: &Select, ctes: &CteScope) -> Option<HashSet<String>> {
    // A star resolves against this SELECT's own WITH first: a local CTE may
    // shadow an enclosing CTE or a logical relation of the same name.
    let local;
    let ctes = match &select.with {
        Some(with) => {
            let mut scope = ctes.clone();
            for cte in &with.ctes {
                scope.insert(lower(cte.tbl_name.as_str()), cte_outputs(cte, &scope));
            }
            local = scope;
            &local
        }
        None => ctes,
    };
    match &select.body.select {
        OneSelect::Select { columns, from, .. } => {
            let mut outputs = HashSet::new();
            for column in columns {
                match column {
                    ResultColumn::Expr(_, Some(alias)) => {
                        outputs.insert(lower(alias.name().as_str()));
                    }
                    ResultColumn::Expr(expr, None) => {
                        // Unaliased complex expressions take the
                        // expression text as their name and cannot
                        // shadow a bare column reference.
                        if let (Some(base), _) = column_parts(expr) {
                            outputs.insert(base);
                        }
                    }
                    ResultColumn::Star => {
                        let from = from.as_ref()?;
                        let tables = std::iter::once(from.select.as_ref())
                            .chain(from.joins.iter().map(|join| join.table.as_ref()));
                        for table in tables {
                            outputs.extend(table_outputs(table, ctes)?);
                        }
                    }
                    ResultColumn::TableStar(label) => {
                        let from = from.as_ref()?;
                        let label = lower(label.as_str());
                        let table = std::iter::once(from.select.as_ref())
                            .chain(from.joins.iter().map(|join| join.table.as_ref()))
                            .find(|table| table_label(table).as_deref() == Some(label.as_str()))?;
                        outputs.extend(table_outputs(table, ctes)?);
                    }
                }
            }
            Some(outputs)
        }
        OneSelect::Values(_) => None,
    }
}

/// Known output columns of one inner FROM source, or `None` when
/// underivable. CTE names resolve through the visible scope, logical
/// relations through the shared contract, derived tables through their
/// SELECT list; anything else is unknown.
fn table_outputs(table: &SelectTable, ctes: &CteScope) -> Option<HashSet<String>> {
    match table {
        SelectTable::Table(name, _, _) => {
            let base = lower(name.name.as_str());
            match ctes.get(&base) {
                Some(outputs) => outputs.clone(),
                None => relation_columns(&base),
            }
        }
        SelectTable::TableCall(..) => None,
        SelectTable::Select(nested, _) => select_outputs(nested, ctes),
        SelectTable::Sub(from, _) => {
            let mut outputs = HashSet::new();
            let tables = std::iter::once(from.select.as_ref())
                .chain(from.joins.iter().map(|join| join.table.as_ref()));
            for table in tables {
                outputs.extend(table_outputs(table, ctes)?);
            }
            Some(outputs)
        }
    }
}

/// Output columns of one CTE, seen from `scope` (the CTEs before it plus
/// the enclosing ones). An explicit column list renames the outputs.
fn cte_outputs(cte: &CommonTableExpr, scope: &CteScope) -> Option<HashSet<String>> {
    if cte.columns.is_empty() {
        select_outputs(&cte.select, scope)
    } else {
        Some(
            cte.columns
                .iter()
                .map(|column| lower(column.col_name.as_str()))
                .collect(),
        )
    }
}

/// The label a FROM source is referenced by: its alias, or the table name
/// when unaliased. Unaliased derived tables have none.
fn table_label(table: &SelectTable) -> Option<String> {
    match table {
        SelectTable::Table(name, alias, _) | SelectTable::TableCall(name, _, alias) => {
            Some(match alias {
                Some(alias) => lower(alias.name().as_str()),
                None => lower(name.name.as_str()),
            })
        }
        SelectTable::Select(_, alias) | SelectTable::Sub(_, alias) => {
            alias.as_ref().map(|alias| lower(alias.name().as_str()))
        }
    }
}

/// Lowercased columns of a logical relation on any engine profile, or
/// `None` when the name is not a known logical relation.
fn relation_columns(name: &str) -> Option<HashSet<String>> {
    use super::sql_contract::{logical_columns, QuerySqlProfile};
    [
        QuerySqlProfile::SqliteLocal,
        QuerySqlProfile::PostgresServer,
        QuerySqlProfile::TursoLocal,
    ]
    .into_iter()
    .find_map(|profile| logical_columns(name, profile))
    .map(|columns| {
        columns
            .iter()
            .map(|column| column.to_ascii_lowercase())
            .collect()
    })
}

/// Reject bare GROUP BY columns at every nesting level. Bare target and
/// HAVING columns must be group keys or expressions over them (Postgres
/// parity); aggregate arguments, FILTER clauses and whole windowed calls
/// are exempt. With no GROUP BY, any group aggregate triggers the same
/// check with empty keys (F8). A qualifier naming an enclosing scope is
/// judged there (a grouped key admits, any other column fails); CTE and
/// unknown qualifiers defer to the engine/relation gate.
/// An unqualified column matching an enclosing level's group key is a
/// correlated outer reference and is admitted — but only when no inner
/// scope (innermost first) may own the name; a shadowed name is rejected
/// with a qualify-or-group repair.
pub fn check_group_columns(select: &Select) -> crate::Result<()> {
    check_group_select(select, &[], &HashMap::new())
}

impl OuterFrame {
    /// The frame one SELECT core exposes to correlated subqueries in
    /// expression positions: its group-key column names, its FROM labels,
    /// and what its FROM may own (for innermost-first name resolution).
    fn for_level(
        grouped: bool,
        keys: &[&Expr],
        from_tables: &HashSet<String>,
        shadow: &ShadowSet,
    ) -> Self {
        OuterFrame {
            grouped,
            key_names: keys
                .iter()
                .filter_map(|key| column_base_name(key))
                .collect(),
            labels: from_tables.clone(),
            shadow: shadow.clone(),
        }
    }
}

/// Grouping context of one SELECT core: resolved group keys, FROM labels
/// with occurrence-aware qualifier resolution, select-list aliases, and
/// whether the bare-column rule fires. `None` for VALUES (no columns to
/// check).
struct GroupCtx<'a> {
    keys: Vec<&'a Expr>,
    from_tables: HashSet<String>,
    scope: QualScope,
    aliases: Vec<(String, &'a Expr)>,
    triggered: bool,
    shadow: ShadowSet,
}

fn group_context<'a>(one: &'a OneSelect, ctes: &CteScope) -> Option<GroupCtx<'a>> {
    let OneSelect::Select {
        columns,
        from,
        group_by,
        ..
    } = one
    else {
        return None;
    };
    let mut from_tables = HashSet::new();
    // Occurrence-aware qualifier resolution: each FROM label (alias, or
    // table name when unaliased) maps to its own occurrence, so `r.kind`
    // and `records.kind` compare identical only for one occurrence.
    let mut scope = QualScope::default();
    if let Some(from) = from {
        collect_from_tables(&from.select, &mut from_tables, &mut scope);
        for join in &from.joins {
            collect_from_tables(&join.table, &mut from_tables, &mut scope);
        }
    }
    // Explicit select-list aliases (`AS w` and elided `w`; implicit names
    // excluded). GROUP BY / HAVING / ORDER BY references resolve through
    // these to the underlying expression — SQLite precedence (alias before
    // input column); shadowing an input column name is pathological in
    // agent SQL and the census cost is 0.
    let aliases: Vec<(String, &Expr)> = columns
        .iter()
        .filter_map(|column| match column {
            ResultColumn::Expr(expr, Some(alias)) if alias.is_explicit() => {
                Some((lower(alias.name().as_str()), expr.as_ref()))
            }
            _ => None,
        })
        .collect();
    let keys: Vec<&Expr> = group_by
        .as_ref()
        .map(|group| {
            group
                .exprs
                .iter()
                .map(|key| resolve_key(key.as_ref(), columns, &aliases))
                .collect()
        })
        .unwrap_or_default();
    let having_agg = group_by
        .as_ref()
        .and_then(|group| group.having.as_ref())
        .is_some_and(|having| expr_has_agg(having));
    let triggered = group_by.is_some()
        || columns.iter().any(|column| match column {
            ResultColumn::Expr(expr, _) => expr_has_agg(expr),
            _ => false,
        })
        || having_agg;
    // What this level's FROM may own: the shadow guard for correlated
    // references checked under this context.
    let shadow = from
        .as_ref()
        .map(|from| ShadowSet::for_from(from, ctes))
        .unwrap_or_default();
    Some(GroupCtx {
        keys,
        from_tables,
        scope,
        aliases,
        triggered,
        shadow,
    })
}

fn check_group_select(select: &Select, outer: &[OuterFrame], ctes: &CteScope) -> crate::Result<()> {
    // Visible CTEs accumulate down the tree (subqueries see enclosing
    // CTEs); an explicit column list renames the outputs.
    let mut scope_ctes = ctes.clone();
    if let Some(with) = &select.with {
        for cte in &with.ctes {
            scope_ctes.insert(lower(cte.tbl_name.as_str()), cte_outputs(cte, &scope_ctes));
            // CTE bodies cannot reference the enclosing query's columns.
            check_group_select(&cte.select, &[], &scope_ctes)?;
        }
    }
    check_group_one(&select.body.select, outer, &scope_ctes)?;
    for compound in &select.body.compounds {
        check_group_one(&compound.select, outer, &scope_ctes)?;
    }
    check_group_order(select, outer, &scope_ctes)?;
    Ok(())
}

/// Bare-column rule for ORDER BY under grouping: with GROUP BY (or an
/// aggregate) present, each ORDER BY term must be a group key, an
/// aggregate, a select-list alias or an ordinal — the same repair wording
/// as the select-list rule. Skipped without grouping (plain row ordering
/// is engine business) and for compounds (one ORDER BY names the compound
/// output, not one leg's keys). Nested selects inside terms are still
/// walked scope-aware.
fn check_group_order(select: &Select, outer: &[OuterFrame], ctes: &CteScope) -> crate::Result<()> {
    if select.order_by.is_empty() {
        return Ok(());
    }
    let Some(ctx) = group_context(&select.body.select, ctes) else {
        let sub = &|nested: &Select| check_group_select(nested, outer, ctes);
        for sorted in &select.order_by {
            check_expr_selects(&sorted.expr, sub)?;
        }
        return Ok(());
    };
    let mut extended: Vec<OuterFrame> = outer.to_vec();
    extended.push(OuterFrame::for_level(
        ctx.triggered,
        &ctx.keys,
        &ctx.from_tables,
        &ctx.shadow,
    ));
    let sub = &|nested: &Select| check_group_select(nested, &extended, ctes);
    // Per-leg keys do not govern a compound's shared ORDER BY.
    let check_terms = select.body.compounds.is_empty() && ctx.triggered;
    for sorted in &select.order_by {
        if check_terms {
            check_expr_grouped(
                &sorted.expr,
                &ctx.keys,
                &ctx.from_tables,
                &ctx.aliases,
                0,
                outer,
                &ctx.scope,
                &ctx.shadow,
            )?;
        }
        check_expr_selects(&sorted.expr, sub)?;
    }
    Ok(())
}

fn check_group_one(one: &OneSelect, outer: &[OuterFrame], ctes: &CteScope) -> crate::Result<()> {
    let OneSelect::Select {
        columns,
        from,
        where_clause,
        group_by,
        window_clause,
        ..
    } = one
    else {
        if let OneSelect::Values(rows) = one {
            let sub = &|nested: &Select| check_group_select(nested, outer, ctes);
            for row in rows {
                for expr in row {
                    check_expr_selects(expr, sub)?;
                }
            }
        }
        return Ok(());
    };
    // Same context the ORDER BY check (check_group_order) reuses.
    let Some(ctx) = group_context(one, ctes) else {
        return Ok(());
    };
    let GroupCtx {
        keys,
        from_tables,
        scope,
        aliases,
        triggered,
        shadow,
    } = &ctx;
    if *triggered {
        for column in columns {
            match column {
                ResultColumn::Expr(expr, _) => {
                    check_expr_grouped(expr, keys, from_tables, aliases, 0, outer, scope, shadow)?
                }
                ResultColumn::Star | ResultColumn::TableStar(_) => {
                    return Err(reject(
                        "SELECT * with GROUP BY or aggregates needs explicit output columns",
                    ));
                }
            }
        }
        if let Some(having) = group_by.as_ref().and_then(|group| group.having.as_ref()) {
            check_expr_grouped(having, keys, from_tables, aliases, 0, outer, scope, shadow)?;
        }
    }
    // Correlated references into a grouped enclosing level, from every
    // position of this level (aggregating or not).
    if outer.iter().any(|frame| frame.grouped) {
        let selected = columns.iter().filter_map(|column| match column {
            ResultColumn::Expr(expr, _) => Some(expr.as_ref()),
            _ => None,
        });
        let joined = from.iter().flat_map(|from| {
            from.joins
                .iter()
                .filter_map(|join| match join.constraint.as_ref() {
                    Some(JoinConstraint::On(expr)) => Some(expr.as_ref()),
                    _ => None,
                })
        });
        let grouping = group_by.iter().flat_map(|group| {
            group
                .exprs
                .iter()
                .map(|key| key.as_ref())
                .chain(group.having.iter().map(|having| having.as_ref()))
        });
        let positions = selected
            .chain(joined)
            .chain(where_clause.iter().map(|expr| expr.as_ref()))
            .chain(grouping);
        for expr in positions {
            check_outer_refs(expr, outer, from_tables, shadow)?;
        }
    }
    // Every subquery position is always walked, scope-aware: expression
    // positions see this level's frame on top of the enclosing ones, while
    // FROM positions start fresh (no LATERAL in SQLite) but keep the
    // visible CTEs.
    let mut extended: Vec<OuterFrame> = outer.to_vec();
    extended.push(OuterFrame::for_level(*triggered, keys, from_tables, shadow));
    let sub = &|nested: &Select| check_group_select(nested, &extended, ctes);
    for column in columns {
        if let ResultColumn::Expr(expr, _) = column {
            check_expr_selects(expr, sub)?;
        }
    }
    if let Some(from) = from {
        check_group_from(&from.select, ctes)?;
        for join in &from.joins {
            check_group_from(&join.table, ctes)?;
            if let Some(JoinConstraint::On(expr)) = join.constraint.as_ref() {
                check_expr_selects(expr, sub)?;
            }
        }
    }
    if let Some(where_clause) = where_clause {
        check_expr_selects(where_clause, sub)?;
    }
    if let Some(having) = group_by.as_ref().and_then(|group| group.having.as_ref()) {
        check_expr_selects(having, sub)?;
    }
    for definition in window_clause {
        check_window_selects(&definition.window, sub)?;
    }
    Ok(())
}

fn check_group_from(table: &SelectTable, ctes: &CteScope) -> crate::Result<()> {
    match table {
        // FROM subqueries start a fresh grouping scope (no LATERAL in
        // SQLite) but keep the visible CTEs.
        SelectTable::Select(nested, _) => check_group_select(nested, &[], ctes),
        SelectTable::Sub(from, _) => {
            check_group_from(&from.select, ctes)?;
            for join in &from.joins {
                check_group_from(&join.table, ctes)?;
            }
            Ok(())
        }
        SelectTable::Table(..) | SelectTable::TableCall(..) => Ok(()),
    }
}

/// Resolve a GROUP BY key through select-list aliases and ordinals to the
/// underlying expression. Chains (`b` -> `a` -> expr) and ordinal-to-alias
/// are followed with a bounded loop, so cyclic aliases terminate.
fn resolve_key<'a>(
    key: &'a Expr,
    columns: &'a [ResultColumn],
    aliases: &[(String, &'a Expr)],
) -> &'a Expr {
    let mut current = key;
    for _ in 0..aliases.len() + 2 {
        match current {
            Expr::Id(name) | Expr::Name(name) => {
                let label = lower(name.as_str());
                match aliases.iter().find(|(alias, _)| *alias == label) {
                    Some((_, target)) => current = target,
                    None => return current,
                }
            }
            Expr::Literal(Literal::Numeric(text)) => match text.parse::<usize>() {
                Ok(position) if position >= 1 => match columns.get(position - 1) {
                    Some(ResultColumn::Expr(expr, _)) => current = expr.as_ref(),
                    _ => return current,
                },
                _ => return current,
            },
            _ => return current,
        }
    }
    current
}

fn collect_from_tables(
    table: &SelectTable,
    from_tables: &mut HashSet<String>,
    scope: &mut QualScope,
) {
    // Labels only; nested subqueries are checked by check_group_from.
    // Each occurrence gets its own index; the bare table name registers
    // only for unaliased occurrences (an alias hides it in SQLite).
    match table {
        SelectTable::Table(name, alias, _) | SelectTable::TableCall(name, _, alias) => {
            let table_name = lower(name.name.as_str());
            let id = scope.bases.len();
            scope.bases.push(table_name.clone());
            *scope.occurrences.entry(table_name.clone()).or_insert(0) += 1;
            match alias {
                Some(alias) => {
                    let alias_name = lower(alias.name().as_str());
                    from_tables.insert(alias_name.clone());
                    scope.canon.insert(alias_name, id);
                }
                None => {
                    from_tables.insert(table_name.clone());
                    scope.canon.insert(table_name.clone(), id);
                    scope.bare_ok.insert(table_name);
                }
            }
        }
        SelectTable::Select(_, alias) | SelectTable::Sub(_, alias) => {
            if let Some(alias) = alias {
                let alias_name = lower(alias.name().as_str());
                from_tables.insert(alias_name.clone());
                // Derived tables are their own single occurrence.
                let id = scope.bases.len();
                scope.bases.push(alias_name.clone());
                *scope.occurrences.entry(alias_name.clone()).or_insert(0) += 1;
                scope.canon.insert(alias_name.clone(), id);
                scope.bare_ok.insert(alias_name);
            }
        }
    }
}

fn expr_has_agg(expr: &Expr) -> bool {
    match expr {
        Expr::FunctionCall {
            name,
            args,
            filter_over,
            ..
        } => {
            if filter_over.over_clause.is_some() {
                return false; // windowed: not a group aggregate (F8)
            }
            if AGGREGATES.contains(&name.as_str().to_ascii_lowercase().as_str()) {
                return true;
            }
            args.iter().any(|arg| expr_has_agg(arg))
        }
        Expr::FunctionCallStar { filter_over, .. } => filter_over.over_clause.is_none(),
        Expr::Binary(left, _, right) => expr_has_agg(left) || expr_has_agg(right),
        Expr::Unary(_, operand)
        | Expr::IsNull(operand)
        | Expr::NotNull(operand)
        | Expr::Collate(operand, _) => expr_has_agg(operand),
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => {
            base.as_ref().is_some_and(|base| expr_has_agg(base))
                || when_then_pairs
                    .iter()
                    .any(|(when, then)| expr_has_agg(when) || expr_has_agg(then))
                || else_expr.as_ref().is_some_and(|expr| expr_has_agg(expr))
        }
        Expr::Cast { expr, .. } => expr_has_agg(expr),
        Expr::Parenthesized(values) => values.iter().any(|value| expr_has_agg(value)),
        _ => false,
    }
}

/// Bare-column check under one expression. Group-key match (whole or,
/// by descent, expressions over grouped columns, as Postgres admits) and
/// correlated outer references pass; anything else must aggregate.
/// Subqueries are skipped here — the scope-aware walker covers them.
#[allow(clippy::too_many_arguments)]
fn check_expr_grouped(
    expr: &Expr,
    keys: &[&Expr],
    from_tables: &HashSet<String>,
    aliases: &[(String, &Expr)],
    depth: u8,
    outer: &[OuterFrame],
    scope: &QualScope,
    shadow: &ShadowSet,
) -> crate::Result<()> {
    if keys.contains(&expr) || keys.iter().any(|key| same_column(expr, key, scope)) {
        return Ok(());
    }
    let bare = |expr: &Expr| {
        Err(reject(format!(
            "column {} must appear in GROUP BY or inside an aggregate",
            display_column(expr)
        )))
    };
    let shadowed = |expr: &Expr| {
        Err(reject(format!(
            "column {} may resolve to the subquery's own FROM rather than the enclosing query; give the enclosing table an alias (FROM records AS o) and qualify the reference (o.kind), or add it to GROUP BY or an aggregate",
            display_column(expr)
        )))
    };
    match expr {
        Expr::Id(name) | Expr::Name(name) => {
            if depth > 8 {
                return bare(expr);
            }
            let label = lower(name.as_str());
            match aliases.iter().find(|(alias, _)| *alias == label) {
                Some((_, target)) => check_expr_grouped(
                    target,
                    keys,
                    from_tables,
                    aliases,
                    depth + 1,
                    outer,
                    scope,
                    shadow,
                ),
                None => {
                    // SQLite binds names innermost-first: inside a
                    // subquery, an inner source that may own the name
                    // defeats the correlation. (At the top level the own
                    // FROM trivially owns every selected column, so the
                    // guard only applies with enclosing frames.)
                    if !outer.is_empty() && shadow.may_own(&label) {
                        return shadowed(expr);
                    }
                    // Otherwise the name resolves to the nearest enclosing
                    // scope that may own it; admit only when that scope
                    // groups it.
                    match outer_name_ungrouped(&label, outer) {
                        Some(true) => return Err(outer_ungrouped(expr)),
                        Some(false) => return Ok(()),
                        None => {}
                    }
                    // No scope owns the name: legacy fail-open correlation
                    // when an enclosing level groups it or does not group
                    // at all (the engine errors if the name is truly absent
                    // everywhere).
                    if outer
                        .iter()
                        .any(|frame| !frame.grouped || frame.key_names.contains(&label))
                    {
                        Ok(())
                    } else {
                        bare(expr)
                    }
                }
            }
        }
        // A qualifier on a current-FROM label must group (by resolved
        // column identity); a base table name hidden behind an alias is
        // invalid (SQLite: "no such column") and rejected precisely; a
        // qualifier naming an enclosing frame's source is a correlated
        // outer reference, admitted only when that same scope groups the
        // column (inner aggregates never reach here — their arguments
        // are exempt); anything else — CTE or unknown — defers to the
        // engine/relation gate.
        Expr::Qualified(table, column) | Expr::DoublyQualified(_, table, column) => {
            let qualifier = lower(table.as_str());
            let base = lower(column.as_str());
            if (from_tables.contains(&qualifier)
                && !keys.iter().any(|key| same_column(expr, key, scope)))
                || scope.is_hidden_base(&qualifier)
            {
                bare(expr)
            } else if let Some(frame) = outer
                .iter()
                .rev()
                .find(|frame| frame.labels.contains(&qualifier))
            {
                if !frame.grouped || frame.key_names.contains(&base) {
                    Ok(())
                } else {
                    Err(outer_ungrouped(expr))
                }
            } else {
                Ok(())
            }
        }
        Expr::FunctionCall {
            name,
            args,
            order_by,
            within_group,
            filter_over,
            ..
        } => {
            if filter_over.over_clause.is_some() {
                return Ok(()); // windowed call: partition/order/args exempt
            }
            if AGGREGATES.contains(&name.as_str().to_ascii_lowercase().as_str()) {
                return Ok(()); // aggregate arguments exempt (F1)
            }
            for arg in args {
                check_expr_grouped(arg, keys, from_tables, aliases, depth, outer, scope, shadow)?;
            }
            for sorted in order_by.iter().chain(within_group.iter()) {
                check_expr_grouped(
                    &sorted.expr,
                    keys,
                    from_tables,
                    aliases,
                    depth,
                    outer,
                    scope,
                    shadow,
                )?;
            }
            Ok(())
        }
        Expr::FunctionCallStar { .. } => Ok(()),
        Expr::Binary(left, _, right) => {
            check_expr_grouped(
                left,
                keys,
                from_tables,
                aliases,
                depth,
                outer,
                scope,
                shadow,
            )?;
            check_expr_grouped(
                right,
                keys,
                from_tables,
                aliases,
                depth,
                outer,
                scope,
                shadow,
            )
        }
        Expr::Unary(_, operand)
        | Expr::IsNull(operand)
        | Expr::NotNull(operand)
        | Expr::Collate(operand, _) => check_expr_grouped(
            operand,
            keys,
            from_tables,
            aliases,
            depth,
            outer,
            scope,
            shadow,
        ),
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => {
            if let Some(base) = base {
                check_expr_grouped(
                    base,
                    keys,
                    from_tables,
                    aliases,
                    depth,
                    outer,
                    scope,
                    shadow,
                )?;
            }
            for (when, then) in when_then_pairs {
                check_expr_grouped(
                    when,
                    keys,
                    from_tables,
                    aliases,
                    depth,
                    outer,
                    scope,
                    shadow,
                )?;
                check_expr_grouped(
                    then,
                    keys,
                    from_tables,
                    aliases,
                    depth,
                    outer,
                    scope,
                    shadow,
                )?;
            }
            if let Some(else_expr) = else_expr {
                check_expr_grouped(
                    else_expr,
                    keys,
                    from_tables,
                    aliases,
                    depth,
                    outer,
                    scope,
                    shadow,
                )?;
            }
            Ok(())
        }
        Expr::Cast { expr, .. } => check_expr_grouped(
            expr,
            keys,
            from_tables,
            aliases,
            depth,
            outer,
            scope,
            shadow,
        ),
        Expr::Like {
            lhs, rhs, escape, ..
        } => {
            check_expr_grouped(lhs, keys, from_tables, aliases, depth, outer, scope, shadow)?;
            check_expr_grouped(rhs, keys, from_tables, aliases, depth, outer, scope, shadow)?;
            if let Some(escape) = escape {
                check_expr_grouped(
                    escape,
                    keys,
                    from_tables,
                    aliases,
                    depth,
                    outer,
                    scope,
                    shadow,
                )?;
            }
            Ok(())
        }
        Expr::Between {
            lhs, start, end, ..
        } => {
            check_expr_grouped(lhs, keys, from_tables, aliases, depth, outer, scope, shadow)?;
            check_expr_grouped(
                start,
                keys,
                from_tables,
                aliases,
                depth,
                outer,
                scope,
                shadow,
            )?;
            check_expr_grouped(end, keys, from_tables, aliases, depth, outer, scope, shadow)
        }
        Expr::InList { lhs, rhs, .. } => {
            check_expr_grouped(lhs, keys, from_tables, aliases, depth, outer, scope, shadow)?;
            for value in rhs {
                check_expr_grouped(
                    value,
                    keys,
                    from_tables,
                    aliases,
                    depth,
                    outer,
                    scope,
                    shadow,
                )?;
            }
            Ok(())
        }
        Expr::Parenthesized(values) => {
            for value in values {
                check_expr_grouped(
                    value,
                    keys,
                    from_tables,
                    aliases,
                    depth,
                    outer,
                    scope,
                    shadow,
                )?;
            }
            Ok(())
        }
        // The subquery side is walker-covered; the left operand is this
        // level's expression.
        Expr::InSelect { lhs, .. } | Expr::InTable { lhs, .. } => {
            check_expr_grouped(lhs, keys, from_tables, aliases, depth, outer, scope, shadow)
        }
        // Literals, params, stars, rowids, subqueries (walker-covered) and
        // anything else hold no bare columns at this level.
        _ => Ok(()),
    }
}

/// `qualifier.column` (or `column`) for repair text; other expressions
/// fall back to their debug form.
fn display_column(expr: &Expr) -> String {
    match column_parts(expr) {
        (Some(base), Some(qualifier)) => format!("{qualifier}.{base}"),
        (Some(base), None) => base,
        _ => format!("{expr:?}"),
    }
}

/// Repair for a correlated reference into a grouped enclosing query that
/// does not group that column (Postgres: "subquery uses ungrouped column
/// from outer query"; SQLite silently picks an arbitrary row).
fn outer_ungrouped(expr: &Expr) -> crate::Error {
    reject(format!(
        "column {} belongs to an enclosing query that groups by other columns; add it to that query's GROUP BY, or aggregate it in that query",
        display_column(expr)
    ))
}

/// Direct child expressions of `expr` at the same query level. Subquery
/// bodies are excluded: their own level is checked with this level's frame.
fn child_exprs(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::Binary(left, _, right) => vec![left.as_ref(), right.as_ref()],
        Expr::Unary(_, operand)
        | Expr::IsNull(operand)
        | Expr::NotNull(operand)
        | Expr::Collate(operand, _)
        | Expr::Cast { expr: operand, .. }
        | Expr::InSelect { lhs: operand, .. }
        | Expr::InTable { lhs: operand, .. } => vec![operand.as_ref()],
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => base
            .iter()
            .map(|base| base.as_ref())
            .chain(
                when_then_pairs
                    .iter()
                    .flat_map(|(when, then)| [when.as_ref(), then.as_ref()]),
            )
            .chain(else_expr.iter().map(|value| value.as_ref()))
            .collect(),
        Expr::FunctionCall {
            args,
            order_by,
            within_group,
            ..
        } => args
            .iter()
            .map(|arg| arg.as_ref())
            .chain(
                order_by
                    .iter()
                    .chain(within_group.iter())
                    .map(|sorted| sorted.expr.as_ref()),
            )
            .collect(),
        Expr::Like {
            lhs, rhs, escape, ..
        } => [lhs.as_ref(), rhs.as_ref()]
            .into_iter()
            .chain(escape.iter().map(|value| value.as_ref()))
            .collect(),
        Expr::Between {
            lhs, start, end, ..
        } => vec![lhs.as_ref(), start.as_ref(), end.as_ref()],
        Expr::InList { lhs, rhs, .. } => std::iter::once(lhs.as_ref())
            .chain(rhs.iter().map(|value| value.as_ref()))
            .collect(),
        Expr::Parenthesized(values) => values.iter().map(|value| value.as_ref()).collect(),
        _ => Vec::new(),
    }
}

/// Plain column references under `expr` at this query level.
fn column_refs<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Id(_) | Expr::Name(_) | Expr::Qualified(..) | Expr::DoublyQualified(..) => {
            out.push(expr)
        }
        _ => {
            for child in child_exprs(expr) {
                column_refs(child, out);
            }
        }
    }
}

/// True when a column reference binds to this level's own FROM (innermost
/// first, as SQLite resolves names). Unknown sources count as inner.
fn resolves_inner(column: &Expr, labels: &HashSet<String>, shadow: &ShadowSet) -> bool {
    match column_parts(column) {
        (Some(_), Some(qualifier)) => labels.contains(&qualifier),
        (Some(base), None) => shadow.may_own(&base),
        _ => true,
    }
}

/// One column reference: if it resolves to a grouped enclosing level, it
/// must be one of that level's group keys.
fn check_outer_ref(
    column: &Expr,
    outer: &[OuterFrame],
    labels: &HashSet<String>,
    shadow: &ShadowSet,
) -> crate::Result<()> {
    if resolves_inner(column, labels, shadow) {
        return Ok(());
    }
    let violates = match column_parts(column) {
        (Some(base), Some(qualifier)) => outer
            .iter()
            .rev()
            .find(|frame| frame.labels.contains(&qualifier))
            .is_some_and(|frame| frame.grouped && !frame.key_names.contains(&base)),
        (Some(base), None) => outer_name_ungrouped(&base, outer) == Some(true),
        _ => false,
    };
    if violates {
        Err(outer_ungrouped(column))
    } else {
        Ok(())
    }
}

/// Resolve an unqualified name outward through the enclosing frames
/// (innermost first, as SQLite binds) and report whether it violates
/// grouping: `Some(true)` it binds to (or may bind to) a grouped level that
/// does not group it, `Some(false)` it binds acceptably, `None` no frame may
/// own it. A frame whose FROM definitely owns the name decides. A frame
/// that only *may* own it (an underivable source such as `SELECT *`)
/// cannot end the search by admitting, because the name may bind further
/// out; a grouped one that does not group the name rejects,
/// conservatively.
fn outer_name_ungrouped(label: &str, outer: &[OuterFrame]) -> Option<bool> {
    let mut uncertain = false;
    for frame in outer.iter().rev() {
        let definite = frame.shadow.known.contains(label);
        if !definite && !frame.shadow.unknown {
            continue;
        }
        if frame.grouped && !frame.key_names.contains(label) {
            return Some(true);
        }
        if definite {
            return Some(false);
        }
        uncertain = true;
    }
    uncertain.then_some(false)
}

/// Correlated references from one subquery level into grouped enclosing
/// levels, at every position and whether or not this level aggregates:
/// each must be a group key of the level it binds to. An aggregate whose
/// arguments reference only enclosing columns belongs to the enclosing
/// level (SQL standard; SQLite and Postgres agree), so it is exempt; one
/// that mixes in this level's columns is evaluated here, so its enclosing
/// references are checked. Subqueries are skipped — their own level runs
/// the same check with this level's frame added.
fn check_outer_refs(
    expr: &Expr,
    outer: &[OuterFrame],
    labels: &HashSet<String>,
    shadow: &ShadowSet,
) -> crate::Result<()> {
    match expr {
        Expr::Id(_) | Expr::Name(_) | Expr::Qualified(..) | Expr::DoublyQualified(..) => {
            check_outer_ref(expr, outer, labels, shadow)
        }
        Expr::FunctionCall {
            name,
            args,
            filter_over,
            ..
        } if filter_over.over_clause.is_none()
            && AGGREGATES.contains(&lower(name.as_str()).as_str()) =>
        {
            let mut refs = Vec::new();
            for arg in args {
                column_refs(arg, &mut refs);
            }
            if refs
                .iter()
                .any(|column| resolves_inner(column, labels, shadow))
            {
                for column in refs {
                    check_outer_ref(column, outer, labels, shadow)?;
                }
            }
            Ok(())
        }
        _ => {
            for child in child_exprs(expr) {
                check_outer_refs(child, outer, labels, shadow)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limited(sql: &str) -> bool {
        check_limit_order(&parse_select(sql).expect("test SQL must parse")).is_err()
    }

    fn grouped(sql: &str) -> bool {
        check_group_columns(&parse_select(sql).expect("test SQL must parse")).is_err()
    }

    fn rule_rejected(sql: &str) -> bool {
        check_rule_statement(sql).is_err()
    }

    #[test]
    fn rule_inputs_admit_explicit_shapes_reject_hidden_reads() {
        // (sql, expect_reject): the conservative subset the authorizer proves.
        for (sql, rejected) in [
            ("SELECT id, name FROM records WHERE id = ?1", false),
            ("SELECT count(*) FROM records", false),
            (
                "SELECT 1 FROM links WHERE EXISTS (SELECT 1 FROM records)",
                false,
            ),
            (
                "SELECT e.id FROM content_events e JOIN records r ON r.id = e.record_id",
                false,
            ),
            (
                "WITH x AS (SELECT id FROM records) SELECT count(*) FROM x",
                false,
            ),
            ("SELECT 'SELECT *' AS literal FROM records", false),
            ("SELECT id FROM records -- SELECT *", false),
            ("SELECT * FROM records", true),
            ("SELECT r.* FROM records r", true),
            ("SELECT id FROM (SELECT * FROM records)", true),
            (
                "SELECT e.id FROM content_events e JOIN records r USING (id)",
                true,
            ),
            (
                "SELECT e.id FROM content_events e NATURAL JOIN records r",
                true,
            ),
            (
                "SELECT e.id FROM content_events e NATURAL LEFT JOIN records r",
                true,
            ),
            ("WITH records AS (SELECT 1) SELECT * FROM records", true),
            (
                "WITH ReCoRdS AS (SELECT 1) SELECT count(*) FROM ReCoRdS",
                true,
            ),
            ("SELECT id FROM records, pragma_table_info('records')", true),
            ("SELECT id FROM records LIMIT 1", false),
        ] {
            assert_eq!(rule_rejected(sql), rejected, "{sql}");
        }
    }

    #[test]
    fn group_bare_columns_need_keys_or_aggregates() {
        // (sql, expect_reject): F1 aggregate args, F6 elided aliases, F7
        // window scoping, F8 no-GROUP-BY aggregates, correlated outers.
        for (sql, rejected) in [
            ("SELECT kind, sum(x) FROM t GROUP BY kind", false),
            ("SELECT sum(amount), count(*) FROM t GROUP BY kind", false),
            ("SELECT kind FROM t GROUP BY kind HAVING sum(x) > 0", false),
            ("SELECT kind, other FROM t GROUP BY kind", true),
            ("SELECT kind FROM t GROUP BY kind HAVING other > 0", true),
            ("SELECT upper(kind), count(*) FROM t GROUP BY kind", false),
            ("SELECT upper(other), count(*) FROM t GROUP BY kind", true),
            ("SELECT kind k, count(*) FROM t GROUP BY kind", false),
            ("SELECT id, row_number() OVER (ORDER BY id) AS rn, kind FROM t GROUP BY id", true),
            ("SELECT kind, row_number() OVER (ORDER BY id) FROM t GROUP BY kind", false),
            ("SELECT kind, sum(x) FILTER (WHERE y > 0) FROM t GROUP BY kind", false),
            ("SELECT kind, sum(x) FROM t", true),
            ("SELECT kind FROM t", false),
            ("SELECT sum(x) FROM t", false),
            ("SELECT a + 1 FROM t GROUP BY a + 1", false),
            ("SELECT a + 1 FROM t GROUP BY a", false),
            ("SELECT *, count(*) FROM t GROUP BY kind", true),
            ("SELECT t.kind, sum(t.x) FROM t GROUP BY t.kind", false),
            // Correlated on an ungrouped outer column: Postgres rejects, SQLite
            // returns an arbitrary row (was wrongly pinned admitted).
            ("SELECT (SELECT sum(x) FROM u WHERE u.id = t.id) FROM t GROUP BY kind", true),
            ("SELECT kind FROM t GROUP BY kind HAVING count(*) > (SELECT count(*) FROM u WHERE u.id = t.id)", true),
            ("SELECT * FROM (SELECT other, sum(x) FROM u GROUP BY kind) s ORDER BY other", true),
            ("SELECT created_at_ms / 604800000 AS week, count(*) AS n FROM t GROUP BY week ORDER BY week", false),
            ("SELECT created_at_ms / 604800000 AS week, count(*) AS n FROM t GROUP BY 1 ORDER BY 1", false),
            ("SELECT kind, count(*) AS n FROM t GROUP BY kind ORDER BY n", false),
            ("SELECT kind k, count(*) FROM t GROUP BY k", false),
            ("SELECT kind, sum(x) AS s FROM t GROUP BY kind HAVING s > 0", false),
            ("SELECT kind, sum(x) AS s FROM t GROUP BY kind HAVING other > 0", true),
            ("SELECT a AS b, b AS c, count(*) FROM t GROUP BY c", false),
            ("SELECT a, b FROM t GROUP BY 5", true),
            // Correlated unqualified outer refs resolve outside, where
            // GROUP BY fixes their value (SQLite admits) — but only when
            // no inner scope may own the name (SQLite binds innermost).
            // `facet_values` has no `kind`; `u` is unknown (possibly
            // inner); `records` owns it (shadowed).
            ("SELECT (SELECT count(*) + kind FROM facet_values) FROM t GROUP BY kind", false),
            ("SELECT (SELECT max(value) + kind FROM facet_values) FROM t GROUP BY kind", false),
            ("SELECT kind, count(*) FROM t GROUP BY kind HAVING count(*) > (SELECT count(*) + kind FROM facet_values)", false),
            ("SELECT (SELECT count(*) + kind FROM u) FROM t GROUP BY kind", true),
            ("SELECT (SELECT count(*) + kind FROM records) FROM records GROUP BY kind", true),
            ("SELECT (SELECT count(*) + other FROM facet_values) FROM records GROUP BY kind", true),
            ("SELECT (SELECT count(*) + other FROM u) FROM t GROUP BY kind", true),
            ("SELECT kind, count(*) FROM t GROUP BY kind HAVING count(*) > (SELECT count(*) + other FROM u)", true),
            // Two levels: correlation through a non-owning middle admits;
            // a middle scope owning the name binds it there; that middle
            // level does not group, so the correlation is an ordinary row
            // value (Postgres raises no grouping error; with several middle rows it
            // only fails on scalar-subquery cardinality). Was wrongly pinned
            // rejected.
            ("SELECT (SELECT (SELECT count(*) + kind FROM facet_values) FROM facet_values) FROM records GROUP BY kind", false),
            ("SELECT (SELECT (SELECT count(*) + kind FROM facet_values) FROM records) FROM records GROUP BY kind", false),
            // Derived tables and CTEs: derivable outputs decide.
            ("SELECT (SELECT count(*) + kind FROM (SELECT value FROM facet_values) s) FROM records GROUP BY kind", false),
            ("SELECT (SELECT count(*) + kind FROM (SELECT kind FROM records) s) FROM records GROUP BY kind", true),
            // `*` expands through derivable sources: facet_values has no
            // `kind`, so it correlates to the grouped key; records owns it.
            ("SELECT (SELECT count(*) + kind FROM (SELECT * FROM facet_values) s) FROM records GROUP BY kind", false),
            ("SELECT (SELECT count(*) + kind FROM (SELECT * FROM records) s) FROM records GROUP BY kind", true),
            // A star over an underivable source may own anything: shadowed.
            ("SELECT (SELECT count(*) + kind FROM (SELECT * FROM unknown_table) s) FROM records GROUP BY kind", true),
            ("WITH c AS (SELECT value FROM facet_values) SELECT (SELECT count(*) + kind FROM c) FROM records GROUP BY kind", false),
            ("WITH c AS (SELECT kind FROM records) SELECT (SELECT count(*) + kind FROM c) FROM records GROUP BY kind", true),
            // Qualified outer refs: only an outer group key admits.
            ("SELECT kind, (SELECT count(*) + t.kind FROM facet_values) FROM records t GROUP BY kind", false),
            ("SELECT kind, (SELECT count(*) + t.name FROM facet_values) FROM records t GROUP BY kind", true),
            ("SELECT (SELECT (SELECT count(*) + t.kind FROM facet_values) FROM facet_values) FROM records t GROUP BY kind", false),
            // `m` is an ungrouped middle level: an ordinary correlation
            // (no Postgres grouping error; was wrongly pinned rejected).
            ("SELECT (SELECT (SELECT count(*) + m.kind FROM facet_values) FROM records m) FROM records t GROUP BY kind", false),
            // Qualification spelling never decides grouping: identity is
            // base name plus resolved source, case-insensitive.
            ("SELECT t.kind, count(*) FROM t GROUP BY kind", false),
            ("SELECT kind, count(*) FROM t GROUP BY t.kind", false),
            ("SELECT r.kind, count(*) FROM t r GROUP BY kind", false),
            // An alias hides the base table name (SQLite: "no such
            // column"), so the hidden qualifier is rejected; the alias
            // itself still resolves to its occurrence.
            ("SELECT t.kind, count(*) FROM t r GROUP BY r.kind", true),
            ("SELECT r.kind, count(*) FROM t r GROUP BY r.kind", false),
            ("SELECT KIND, count(*) FROM t GROUP BY kind", false),
            ("SELECT r.kind, count(*) FROM t r GROUP BY kind HAVING count(*) > 0", false),
            ("SELECT t.kind, count(*) FROM t, u GROUP BY u.kind", true),
            // Self-join: identity is per occurrence, so the other alias's
            // column is bare; an unqualified name beside a twice-occurring
            // table is ambiguous (SQLite errors there too).
            ("SELECT b.kind, count(*) FROM t a JOIN t b ON a.id = b.id GROUP BY a.kind", true),
            ("SELECT a.kind, count(*) FROM t a JOIN t b ON a.id = b.id GROUP BY b.kind", true),
            ("SELECT a.kind, count(*) FROM t a JOIN t b ON a.id = b.id GROUP BY a.kind ORDER BY b.kind", true),
            ("SELECT kind, count(*) FROM t a JOIN t b ON a.id = b.id GROUP BY a.kind", true),
            ("SELECT a.kind, count(*) FROM t a JOIN u b ON a.id = b.id GROUP BY kind", false),
            // ORDER BY under grouping: keys, aggregates, aliases and
            // ordinals admit; bare non-keys fail with the same repair.
            ("SELECT kind, count(*) FROM t GROUP BY kind ORDER BY kind", false),
            ("SELECT kind, count(*) FROM t GROUP BY kind ORDER BY count(*)", false),
            ("SELECT kind, count(*) AS n FROM t GROUP BY kind ORDER BY n DESC", false),
            ("SELECT kind, count(*) FROM t GROUP BY kind ORDER BY 1", false),
            ("SELECT r.kind, count(*) FROM t r GROUP BY kind ORDER BY r.kind", false),
            ("SELECT sum(x) FROM t ORDER BY sum(x)", false),
            ("SELECT kind, count(*) FROM t GROUP BY kind ORDER BY created_at_ms", true),
            ("SELECT kind FROM t GROUP BY kind ORDER BY created_at_ms", true),
            ("SELECT kind, count(*) AS n FROM t GROUP BY kind ORDER BY other", true),
            ("SELECT count(*) FROM t ORDER BY created_at_ms", true),
        ] {
            assert_eq!(grouped(sql), rejected, "{sql}");
        }
    }

    #[test]
    fn unparseable_statements_fail_open_and_count() {
        // Bare OFFSET is a syntax error on both engines, so the AST layer
        // admits it for the engine gate to refuse precisely — and counts it.
        assert!(parse_select("SELECT a FROM t OFFSET 5").is_err());
        let before = fail_open_count();
        check_statement("SELECT a FROM t OFFSET 5").expect("fail-open admit");
        assert_eq!(fail_open_count(), before + 1);
    }

    #[test]
    fn top_level_gate_sees_only_the_outermost_limit_and_order() {
        // E2 default ORDER BY: the rewrite gate fires exactly for a
        // top-level LIMIT with no top-level ORDER BY, and stays quiet
        // (fail-open false) for anything the AST cannot confirm.
        for sql in [
            "SELECT a FROM t LIMIT 5",
            "SELECT a FROM t LIMIT 5 OFFSET 2",
            "WITH c AS (SELECT a FROM t LIMIT 5) SELECT a FROM c LIMIT 3",
            "SELECT a FROM t UNION ALL SELECT a FROM u LIMIT 5",
            "SELECT * FROM (SELECT a FROM t LIMIT 5) s LIMIT 3",
        ] {
            assert!(top_level_unordered_limit(sql), "{sql}");
        }
        for sql in [
            "SELECT a FROM t",
            "SELECT a FROM t ORDER BY a",
            "SELECT a FROM t ORDER BY a LIMIT 5",
            "SELECT * FROM (SELECT a FROM t LIMIT 5) s ORDER BY a",
            "WITH c AS (SELECT a FROM t LIMIT 5) SELECT a FROM c ORDER BY a",
            "EXPLAIN QUERY PLAN SELECT a FROM t LIMIT 5",
            "SELECT a FROM t OFFSET 5",
            "SELECT a FROM t LIMIT 5; SELECT b FROM u",
        ] {
            assert!(!top_level_unordered_limit(sql), "{sql}");
        }
    }

    #[test]
    fn turso_parses_everything_sqlite_accepts() {
        // Differential: every classifier-admitted statement must survive
        // the turso parse (the AST layer only ever sees admitted text), and
        // no engine-accepted statement may fail it. Universe: the shared
        // conformance corpus plus the 75 distinct logged census statements.
        // (First run caught a real oracle gap: rusqlite `prepare` accepts
        // multi-statement tails, so the universe is classifier-admitted
        // text, matching what production feeds the AST layer.)
        use super::super::sql_contract::{classify_single_read_statement, QuerySqlProfile};
        let census: Vec<String> =
            serde_json::from_str(include_str!("sql_census_fixture.json")).unwrap();
        let corpus = super::super::sql_conformance::corpus();
        let mut admitted = 0;
        let mut engine_accepted = 0;
        let mut checked = 0;
        for sql in corpus
            .iter()
            .map(|case| case.sql)
            .chain(census.iter().map(String::as_str))
        {
            checked += 1;
            if classify_single_read_statement(QuerySqlProfile::SqliteLocal, sql).is_err() {
                continue;
            }
            admitted += 1;
            assert!(
                parse_select(sql).is_ok(),
                "turso rejects classifier-admitted: {sql}"
            );
            if super::super::sql::strict_prepare(sql).is_ok() {
                engine_accepted += 1;
            }
        }
        assert!(
            admitted > 0 && engine_accepted > 0,
            "differential ran on nothing"
        );
        println!("differential: {checked} statements, {admitted} admitted, {engine_accepted} engine-accepted");
    }

    #[test]
    fn limit_needs_order_by_at_every_level() {
        for sql in [
            "SELECT a FROM t ORDER BY a LIMIT 5",
            "SELECT a FROM t ORDER BY a LIMIT -1 OFFSET 5",
            "SELECT a FROM t",
            "SELECT * FROM (SELECT a FROM t ORDER BY a LIMIT 5) s ORDER BY a",
            "WITH c AS (SELECT a FROM t ORDER BY a LIMIT 5) SELECT a FROM c ORDER BY a",
            "SELECT a FROM t UNION ALL SELECT a FROM u ORDER BY a LIMIT 5",
            "SELECT (SELECT max(x) FROM u ORDER BY x LIMIT 1) FROM t ORDER BY a",
            "SELECT CASE WHEN (SELECT max(x) FROM u ORDER BY x LIMIT 1) > 0 THEN 1 ELSE 0 END FROM t ORDER BY a",
        ] {
            assert!(!limited(sql), "wrongly rejected {sql}");
        }
        for sql in [
            "SELECT a FROM t LIMIT 5",
            "SELECT a FROM t LIMIT -1 OFFSET 5",
            "SELECT * FROM (SELECT a FROM t LIMIT 5) s ORDER BY a",
            "WITH c AS (SELECT a FROM t LIMIT 5) SELECT a FROM c ORDER BY a",
            "SELECT a FROM t UNION ALL SELECT a FROM u LIMIT 5",
            "SELECT (SELECT a FROM u LIMIT 1) FROM t ORDER BY a",
            "SELECT CASE WHEN (SELECT max(x) FROM u LIMIT 1) > 0 THEN 1 ELSE 0 END FROM t ORDER BY a",
            "SELECT kind FROM t GROUP BY kind HAVING count(*) > (SELECT max(x) FROM u LIMIT 1)",
            "SELECT a FROM t ORDER BY (SELECT max(x) FROM u LIMIT 1) LIMIT 5",
        ] {
            assert!(limited(sql), "wrongly admitted {sql}");
        }
    }

    #[test]
    fn correlated_references_into_grouped_and_ungrouped_levels() {
        // (sql, expect_reject). Verdicts checked against Postgres 16 and
        // SQLite 3.45: Postgres rejects every `true` row with "subquery uses
        // ungrouped column from outer query"; SQLite admits them and returns
        // an arbitrary row.
        for (sql, rejected) in [
            // Ungrouped enclosing level: any correlation is fine.
            ("SELECT id, (SELECT count(*) + r.n FROM links) FROM records r", false),
            ("SELECT id, (SELECT count(*) + name FROM facet_values) FROM records", false),
            ("SELECT id, (SELECT count(*) FROM links l WHERE l.source_id = r.id) FROM records r", false),
            ("SELECT id FROM records r WHERE EXISTS (SELECT 1 FROM links l WHERE l.source_id = r.id)", false),
            // Grouped enclosing level, non-aggregating subquery.
            ("SELECT kind, (SELECT r2.name FROM records r2 WHERE r2.id = records.id) FROM records GROUP BY kind", true),
            ("SELECT kind, (SELECT r2.name FROM records r2 WHERE r2.kind = records.kind LIMIT 1) FROM records GROUP BY kind", false),
            ("SELECT kind FROM records GROUP BY kind HAVING EXISTS (SELECT 1 FROM links WHERE links.source_id = records.id)", true),
            // Aggregates over only enclosing columns belong to the enclosing level.
            ("SELECT kind, (SELECT max(records.name) FROM facet_values) FROM records GROUP BY kind", false),
            ("SELECT kind, (SELECT count(*) + max(records.name) FROM facet_values) FROM records GROUP BY kind", false),
            // Aggregates mixing inner and enclosing columns are evaluated inside.
            ("SELECT kind, (SELECT max(records.name || facet_values.value) FROM facet_values) FROM records GROUP BY kind", true),
            ("SELECT kind, (SELECT max(records.kind || facet_values.value) FROM facet_values) FROM records GROUP BY kind", false),
            // A middle level with an underivable source (`SELECT *`) may or may
            // not own the name: it cannot end the search by admitting, so the
            // grouped outer level that does own `name` still rejects (PG:
            // ungrouped column "records.name"; SQLite: row-order dependent).
            ("SELECT (SELECT (SELECT count(*) + name FROM facet_values) FROM (SELECT * FROM facet_values) s) FROM records GROUP BY kind", true),
            ("SELECT (SELECT (SELECT count(*) + name FROM facet_values) FROM (SELECT * FROM links) s) FROM records GROUP BY kind", true),
            ("SELECT (SELECT (SELECT count(*) + kind FROM facet_values) FROM (SELECT * FROM links) s) FROM records GROUP BY kind", false),
            ("SELECT id, (SELECT (SELECT count(*) + name FROM facet_values) FROM (SELECT * FROM links) s) FROM records", false),
            // ...but a `SELECT *` middle over a derivable source that does own
            // the name binds it there (review N-1: PG16 and SQLite both run
            // these; they were falsely rejected while `*` was underivable).
            ("SELECT kind, (SELECT (SELECT count(*) + length(name) FROM facet_values) FROM (SELECT * FROM records ORDER BY id LIMIT 1) r) FROM records GROUP BY kind", false),
            ("SELECT kind, (SELECT (SELECT count(*) FROM facet_values f WHERE f.value = name) FROM (SELECT * FROM records ORDER BY id LIMIT 1) r) FROM records GROUP BY kind", false),
            ("WITH c AS (SELECT * FROM records ORDER BY id LIMIT 1) SELECT kind, (SELECT (SELECT count(*) + length(name) FROM facet_values) FROM c) FROM records GROUP BY kind", false),
            ("SELECT kind, (SELECT (SELECT count(*) + length(name) FROM facet_values) FROM (SELECT r2.* FROM records r2 ORDER BY id LIMIT 1) r) FROM records GROUP BY kind", false),
            // A star resolves against its own SELECT's WITH first (review of
            // the N-1 fix): a local CTE shadowing `records` owns only `id`, so
            // `name` binds to the grouped outer level (PG16: ungrouped
            // "o.name"); a local CTE over records owns `name` (PG16 admits).
            ("SELECT (SELECT (SELECT count(*) + length(name) FROM facet_values) FROM (WITH records AS (SELECT id FROM links) SELECT * FROM records LIMIT 1) s) FROM records o GROUP BY kind", true),
            ("SELECT (SELECT (SELECT count(*) + length(name) FROM facet_values) FROM (WITH c AS (SELECT * FROM records) SELECT * FROM c ORDER BY id LIMIT 1) s) FROM records o GROUP BY kind", false),
            // Parenthesised and IN operands are checked like any expression.
            ("SELECT kind, (other) FROM t GROUP BY kind", true),
            ("SELECT kind, other IN (SELECT 1) FROM t GROUP BY kind", true),
        ] {
            assert_eq!(grouped(sql), rejected, "wrong verdict for {sql}");
        }
    }

    #[test]
    fn outer_repairs_point_at_the_enclosing_query() {
        let message = |sql: &str| {
            check_group_columns(&parse_select(sql).expect("test SQL must parse"))
                .expect_err("must reject")
                .to_string()
        };
        let ungrouped = message(
            "SELECT kind, (SELECT r2.name FROM records r2 WHERE r2.id = records.id) FROM records GROUP BY kind",
        );
        assert!(
            ungrouped.contains("records.id belongs to an enclosing query"),
            "{ungrouped}"
        );
        let shadowed =
            message("SELECT (SELECT count(*) + kind FROM records) FROM records GROUP BY kind");
        assert!(shadowed.contains("FROM records AS o"), "{shadowed}");
    }
}
