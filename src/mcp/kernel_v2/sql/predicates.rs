//! Conservative finite text constraints for physical relation occurrences.
use super::contract::QuerySqlParameter;
use std::collections::BTreeSet;
use turso_parser::ast::{Expr, Literal, Operator};

#[cfg(test)]
tokio::task_local! { static FULL_STAGING: (); }
#[cfg(test)]
pub(super) async fn with_full_staging<F: std::future::Future>(work: F) -> F::Output {
    FULL_STAGING.scope((), work).await
}
pub(super) fn full_staging() -> bool {
    #[cfg(test)]
    if FULL_STAGING.try_with(|_| ()).is_ok() {
        return true;
    }
    false
}

fn unparen(mut expr: &Expr) -> &Expr {
    while let Expr::Parenthesized(exprs) = expr {
        if exprs.len() != 1 {
            break;
        }
        expr = &exprs[0];
    }
    expr
}
fn is_column(expr: &Expr, qualifier: &str, column: &str) -> bool {
    match unparen(expr) {
        Expr::Id(name) => name.as_str().eq_ignore_ascii_case(column),
        Expr::Qualified(table, name) => {
            table.as_str().eq_ignore_ascii_case(qualifier)
                && name.as_str().eq_ignore_ascii_case(column)
        }
        _ => false,
    }
}
fn text(expr: &Expr, parameters: &[QuerySqlParameter]) -> Option<Option<String>> {
    match unparen(expr) {
        Expr::Literal(Literal::String(value)) => Some(Some(
            value
                .strip_prefix('\'')?
                .strip_suffix('\'')?
                .replace("''", "'"),
        )),
        Expr::Literal(Literal::Null) => Some(None),
        Expr::Variable(variable) if variable.numbered && variable.name.is_none() => {
            match parameters.get(variable.index.get() as usize - 1)? {
                QuerySqlParameter::Text { value } => Some(value.clone()),
                _ => None,
            }
        }
        _ => None,
    }
}
pub(super) fn bounds(
    expr: &Expr,
    qualifier: &str,
    column: &str,
    parameters: &[QuerySqlParameter],
) -> Option<BTreeSet<String>> {
    match unparen(expr) {
        Expr::Binary(a, Operator::And, b) => match (
            bounds(a, qualifier, column, parameters),
            bounds(b, qualifier, column, parameters),
        ) {
            (Some(a), Some(b)) => Some(a.intersection(&b).cloned().collect()),
            (Some(a), None) | (None, Some(a)) => Some(a),
            _ => None,
        },
        Expr::Binary(a, Operator::Or, b) => Some(
            bounds(a, qualifier, column, parameters)?
                .union(&bounds(b, qualifier, column, parameters)?)
                .cloned()
                .collect(),
        ),
        Expr::Binary(a, Operator::Equals, b) => {
            let value = if is_column(a, qualifier, column) {
                text(b, parameters)?
            } else if is_column(b, qualifier, column) {
                text(a, parameters)?
            } else {
                return None;
            };
            Some(value.into_iter().collect())
        }
        Expr::InList {
            lhs,
            not: false,
            rhs,
        } if is_column(lhs, qualifier, column) => {
            let mut values = BTreeSet::new();
            for value in rhs {
                values.extend(text(value, parameters)?);
            }
            Some(values)
        }
        _ => None,
    }
}

/// Union necessary value bounds across every physical scan. One unbounded
/// occurrence cancels the optimization, including scans nested in expressions.
/// ON constraints can bound the optional/right input of INNER/LEFT joins; a
/// RIGHT/FULL join preserves that input and therefore uses WHERE bounds only.
pub(super) fn relation_values(
    statement: &str,
    parameters: &[QuerySqlParameter],
    relation: &str,
    column: &str,
) -> Option<BTreeSet<String>> {
    collect(statement, parameters, relation, column)
}

fn collect(
    statement: &str,
    parameters: &[QuerySqlParameter],
    relation: &str,
    column: &str,
) -> Option<BTreeSet<String>> {
    use turso_parser::ast::{Cmd, Stmt};
    let mut parser = turso_parser::parser::Parser::new(statement.as_bytes());
    let Cmd::Stmt(Stmt::Select(select)) = parser.next()?.ok()? else {
        return None;
    };
    if parser.next().is_some() {
        return None;
    }
    let collector = Collector {
        parameters,
        relation,
        column,
        sets: std::cell::RefCell::new(Vec::new()),
    };
    collector.select(&select)?;
    let sets = collector.sets.into_inner();
    if sets.is_empty() {
        return None;
    }
    let values: BTreeSet<String> = sets.into_iter().flatten().collect();
    (values.len() <= 1000).then_some(values)
}

struct Collector<'a> {
    parameters: &'a [QuerySqlParameter],
    relation: &'a str,
    column: &'a str,
    sets: std::cell::RefCell<Vec<BTreeSet<String>>>,
}
impl Collector<'_> {
    fn bound(&self, expr: &Expr, alias: &str) -> Option<BTreeSet<String>> {
        bounds(expr, alias, self.column, self.parameters)
    }
    fn expr(&self, expr: &Expr) -> Option<()> {
        crate::query::turso_ast_rules::check_expr_selects(expr, &|select| {
            self.select(select)
                .ok_or_else(|| crate::Error::engine("unbounded relation occurrence"))
        })
        .ok()
    }
    fn select(&self, select: &turso_parser::ast::Select) -> Option<()> {
        if let Some(with) = &select.with {
            for cte in &with.ctes {
                if cte.tbl_name.as_str().eq_ignore_ascii_case(self.relation) {
                    return None;
                }
                self.select(&cte.select)?;
            }
        }
        self.one(&select.body.select)?;
        for compound in &select.body.compounds {
            self.one(&compound.select)?;
        }
        for term in &select.order_by {
            self.expr(&term.expr)?;
        }
        if let Some(limit) = &select.limit {
            self.expr(&limit.expr)?;
            if let Some(offset) = &limit.offset {
                self.expr(offset)?;
            }
        }
        Some(())
    }
    fn one(&self, one: &turso_parser::ast::OneSelect) -> Option<()> {
        use turso_parser::ast::{OneSelect, ResultColumn};
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
                for row in rows {
                    for expr in row {
                        self.expr(expr)?;
                    }
                }
            }
            return Some(());
        };
        if !window_clause.is_empty() {
            return None;
        }
        if let Some(from) = from {
            self.from(from, where_clause.as_deref())?;
        }
        for column in columns {
            if let ResultColumn::Expr(expr, _) = column {
                self.expr(expr)?;
            }
        }
        if let Some(expr) = where_clause {
            self.expr(expr)?;
        }
        if let Some(group) = group_by {
            for expr in &group.exprs {
                self.expr(expr)?;
            }
            if let Some(expr) = &group.having {
                self.expr(expr)?;
            }
        }
        Some(())
    }
    fn from(&self, from: &turso_parser::ast::FromClause, predicate: Option<&Expr>) -> Option<()> {
        use turso_parser::ast::{JoinConstraint, JoinOperator, JoinType};
        self.table(&from.select, predicate, None)?;
        for join in &from.joins {
            let preserved = matches!(join.operator,JoinOperator::TypedJoin(Some(kind)) if kind.contains(JoinType::RIGHT));
            let on = if preserved {
                None
            } else {
                match &join.constraint {
                    Some(JoinConstraint::On(expr)) => Some(expr.as_ref()),
                    _ => None,
                }
            };
            self.table(&join.table, predicate, on)?;
            if let Some(JoinConstraint::On(expr)) = &join.constraint {
                self.expr(expr)?;
            }
        }
        Some(())
    }
    fn table(
        &self,
        table: &turso_parser::ast::SelectTable,
        predicate: Option<&Expr>,
        on: Option<&Expr>,
    ) -> Option<()> {
        use turso_parser::ast::SelectTable;
        match table {
            SelectTable::Table(table, alias, _)
                if table.name.as_str().eq_ignore_ascii_case(self.relation) =>
            {
                if table.db_name.is_some() || table.alias.is_some() {
                    return None;
                }
                let alias = alias
                    .as_ref()
                    .map(|a| a.name().as_str())
                    .unwrap_or_else(|| table.name.as_str());
                let filter = predicate.and_then(|p| self.bound(p, alias));
                let join = on.and_then(|p| self.bound(p, alias));
                let bound = match (filter, join) {
                    (Some(a), Some(b)) => a.intersection(&b).cloned().collect(),
                    (Some(a), None) | (None, Some(a)) => a,
                    _ => return None,
                };
                self.sets.borrow_mut().push(bound);
                Some(())
            }
            SelectTable::Table(..) => Some(()),
            SelectTable::Select(select, _) => self.select(select),
            SelectTable::Sub(from, _) => self.from(from, None),
            SelectTable::TableCall(name, args, _) => {
                if name.name.as_str().eq_ignore_ascii_case(self.relation) {
                    return None;
                }
                for expr in args {
                    self.expr(expr)?;
                }
                Some(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn values(sql: &str) -> Option<BTreeSet<String>> {
        relation_values(sql, &[], "facet_values", "key")
    }
    #[test]
    fn all_occurrences_and_optional_join_inputs_must_be_bounded() {
        for (sql,expected) in [
            ("SELECT f.value FROM facet_values f WHERE f.key='a' OR f.key='b'",vec!["a","b"]),
            ("SELECT r.id FROM records r LEFT JOIN facet_values f ON f.record_id=r.id AND f.key='a'",vec!["a"]),
            ("SELECT r.id FROM records r FULL JOIN facet_values f ON f.key='b' WHERE f.key='a'",vec!["a"]),
            ("WITH x AS (SELECT value FROM facet_values WHERE key='a') SELECT value FROM facet_values WHERE key='b'",vec!["a","b"]),
            ("SELECT (SELECT value FROM facet_values WHERE key='a') FROM records",vec!["a"]),
        ] {assert_eq!(values(sql),Some(expected.into_iter().map(str::to_owned).collect()),"{sql}");}
        for sql in [
            "SELECT * FROM facet_values",
            "SELECT r.id FROM records r RIGHT JOIN facet_values f ON f.key='a'",
            "SELECT r.id FROM records r FULL JOIN facet_values f ON f.key='a'",
            "SELECT value,(SELECT count(*) FROM facet_values) FROM facet_values WHERE key='a'",
            "SELECT * FROM facet_values WHERE key='a' UNION ALL SELECT * FROM facet_values",
            "WITH facet_values AS (SELECT * FROM records) SELECT * FROM facet_values WHERE key='a'",
            "SELECT value FROM facet_values WHERE key='a' OR value='other'",
        ] {
            assert_eq!(values(sql), None, "{sql}");
        }
    }
}
