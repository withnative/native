//! Finite record scopes for rows whose visibility depends only on those IDs.
//! Caller SQL stays intact; global catalogue joins need no additional records.
use super::contract::QuerySqlParameter;
use std::collections::BTreeSet;
use turso_parser::ast::{Cmd, Expr, Literal, OneSelect, Operator, ResultColumn, SelectTable, Stmt};

#[cfg(test)]
tokio::task_local! { static FULL_STAGING: (); }
#[cfg(test)]
pub(crate) async fn with_full_staging<F: std::future::Future>(work: F) -> F::Output {
    FULL_STAGING.scope((), work).await
}
pub(super) fn full_staging() -> bool {
    #[cfg(test)]
    if FULL_STAGING.try_with(|_| ()).is_ok() {
        return true;
    }
    false
}

pub(super) fn ids(
    statement: &str,
    parameters: &[QuerySqlParameter],
    reads: &BTreeSet<(String, String)>,
) -> Option<Vec<String>> {
    if full_staging()
        || reads
            .iter()
            .any(|(r, c)| r == "records" && ["is_current", "successor_count"].contains(&c.as_str()))
    {
        // Currency cells depend on other visible records, not just this row.
        return None;
    }
    let mut parser = turso_parser::parser::Parser::new(statement.as_bytes());
    let Cmd::Stmt(Stmt::Select(select)) = parser.next()?.ok()? else {
        return None;
    };
    if parser.next().is_some() || select.with.is_some() || !select.body.compounds.is_empty() {
        return None;
    }
    let OneSelect::Select {
        columns,
        from: Some(from),
        where_clause: Some(predicate),
        group_by: None,
        window_clause,
        ..
    } = &select.body.select
    else {
        return None;
    };
    if !window_clause.is_empty() {
        return None;
    }
    let SelectTable::Table(table, alias, _) = from.select.as_ref() else {
        return None;
    };
    if table.db_name.is_some() || table.alias.is_some() {
        return None;
    }
    let relation = table.name.as_str().to_ascii_lowercase();
    let (column, allowed): (&str, &[&str]) = match relation.as_str() {
        "records" => ("id", &["records", "facet_values"]),
        "facet_values" => ("record_id", &["facet_values"]),
        "record_lifecycle_interpretations" => (
            "record_id",
            &[
                "record_lifecycle_interpretations",
                "vocabularies",
                "vocabulary_values",
            ],
        ),
        _ => return None,
    };
    if reads
        .iter()
        .any(|(relation, _)| !allowed.contains(&relation.as_str()))
    {
        return None;
    }
    let qualifier = alias
        .as_ref()
        .map(|a| a.name().as_str())
        .unwrap_or_else(|| table.name.as_str());
    // Only global vocabulary joins are independent of the finite record set.
    // Home self-joins can read the joined home's own logical placement. The
    // finite-ID path stages only one home level, so retain full staging for
    // every records self-join rather than exposing incomplete home-derived cells.
    for join in &from.joins {
        let SelectTable::Table(table, _, _) = join.table.as_ref() else {
            return None;
        };
        if table.db_name.is_some() || table.alias.is_some() {
            return None;
        }
        if relation != "record_lifecycle_interpretations"
            || !["vocabularies", "vocabulary_values"]
                .contains(&table.name.as_str().to_ascii_lowercase().as_str())
        {
            return None;
        }
        if let Some(turso_parser::ast::JoinConstraint::On(expr)) = &join.constraint {
            crate::query::turso_ast_rules::check_expr_selects(expr, &|_| {
                Err(crate::Error::engine("scope requires independent joins"))
            })
            .ok()?;
        }
    }
    // A facet subquery can only consume this outer record's values when its
    // own necessary predicate proves that correlation. Other subqueries may
    // need records outside the finite domain and retain full staging.
    let reject_select = |select: &turso_parser::ast::Select| {
        (relation == "records")
            .then(|| scoped_facets(select, qualifier))
            .flatten()
            .ok_or_else(|| crate::Error::engine("scope requires independent record rows"))
    };
    let check =
        |e: &Expr| crate::query::turso_ast_rules::check_expr_selects(e, &reject_select).ok();
    for column in columns {
        if let ResultColumn::Expr(expr, _) = column {
            check(expr)?;
        }
    }
    check(predicate)?;
    for term in &select.order_by {
        check(&term.expr)?;
    }
    if let Some(limit) = &select.limit {
        check(&limit.expr)?;
        if let Some(offset) = &limit.offset {
            check(offset)?;
        }
    }
    let ids = bounds(predicate, qualifier, column, parameters)?;
    (ids.len() <= 1000).then(|| ids.into_iter().collect())
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

fn scoped_facets(select: &turso_parser::ast::Select, outer: &str) -> Option<()> {
    if select.with.is_some() || !select.body.compounds.is_empty() {
        return None;
    }
    let OneSelect::Select {
        columns,
        from: Some(from),
        where_clause: Some(predicate),
        group_by: None,
        window_clause,
        ..
    } = &select.body.select
    else {
        return None;
    };
    if !from.joins.is_empty() || !window_clause.is_empty() {
        return None;
    }
    let SelectTable::Table(table, alias, _) = from.select.as_ref() else {
        return None;
    };
    if table.db_name.is_some()
        || table.alias.is_some()
        || !table.name.as_str().eq_ignore_ascii_case("facet_values")
    {
        return None;
    }
    let alias = alias
        .as_ref()
        .map(|a| a.name().as_str())
        .unwrap_or_else(|| table.name.as_str());
    if alias.eq_ignore_ascii_case(outer) {
        return None;
    }
    fn necessary(expr: &Expr, alias: &str, outer: &str) -> bool {
        use turso_parser::ast::Operator;
        match expr {
            Expr::Parenthesized(v) if v.len() == 1 => necessary(&v[0], alias, outer),
            Expr::Binary(a, Operator::And, b) => {
                necessary(a, alias, outer) || necessary(b, alias, outer)
            }
            Expr::Binary(a, Operator::Or, b) => {
                necessary(a, alias, outer) && necessary(b, alias, outer)
            }
            Expr::Binary(a, Operator::Equals, b) => {
                let local = |e: &Expr| match e {
                    Expr::Id(n) => n.as_str().eq_ignore_ascii_case("record_id"),
                    Expr::Qualified(t, n) => {
                        t.as_str().eq_ignore_ascii_case(alias)
                            && n.as_str().eq_ignore_ascii_case("record_id")
                    }
                    _ => false,
                };
                let foreign = |e: &Expr| matches!(e,Expr::Qualified(t,n) if t.as_str().eq_ignore_ascii_case(outer) && n.as_str().eq_ignore_ascii_case("id"));
                (local(a) && foreign(b)) || (local(b) && foreign(a))
            }
            _ => false,
        }
    }
    if !necessary(predicate, alias, outer) {
        return None;
    }
    let no_nested =
        |_: &turso_parser::ast::Select| Err(crate::Error::engine("facet scope requires one scan"));
    let check = |e: &Expr| crate::query::turso_ast_rules::check_expr_selects(e, &no_nested).ok();
    for column in columns {
        if let ResultColumn::Expr(expr, _) = column {
            check(expr)?;
        }
    }
    check(predicate)?;
    for term in &select.order_by {
        check(&term.expr)?;
    }
    if let Some(limit) = &select.limit {
        check(&limit.expr)?;
        if let Some(offset) = &limit.offset {
            check(offset)?;
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(sql: &str) -> Option<Vec<String>> {
        ids(
            sql,
            &[QuerySqlParameter::Text {
                value: Some("parameter".into()),
            }],
            &BTreeSet::from([("records".into(), "id".into())]),
        )
    }
    #[test]
    fn finite_predicates_accept_aliases_boolean_bounds_literals_and_nulls() {
        for (sql, expected) in [
            (
                "SELECT * FROM records r WHERE r.id=?1 AND deleted_at IS NULL",
                vec!["parameter"],
            ),
            (
                "SELECT id FROM records WHERE 'a'=id OR id IN ('b','a',NULL)",
                vec!["a", "b"],
            ),
            (
                "SELECT id FROM records WHERE id IN ('a','b') AND id IN ('b','c')",
                vec!["b"],
            ),
            ("SELECT id FROM records WHERE id=NULL", vec![]),
            (
                "SELECT \"x\".id FROM \"records\" AS \"x\" WHERE (\"x\".id)='a''b'",
                vec!["a'b"],
            ),
        ] {
            assert_eq!(
                plan(sql),
                Some(expected.into_iter().map(str::to_owned).collect()),
                "{sql}"
            );
        }
    }
    #[test]
    fn record_self_joins_keep_full_home_dependencies() {
        for sql in [
            "SELECT r.id,h.name FROM records r LEFT JOIN records h ON h.id=r.home_id WHERE r.id='a'",
            "SELECT r.id,h.name FROM records r FULL JOIN records h ON r.home_id=h.id WHERE r.id='a'",
            "SELECT r.id, h.id AS home, h.home_id AS grand FROM records r LEFT JOIN records h ON h.id = r.home_id WHERE r.id='private-child'",
        ] {
            assert_eq!(plan(sql), None, "{sql}");
        }
    }
    #[test]
    fn facet_and_lifecycle_rows_share_only_their_finite_record_scope() {
        let parameters = [QuerySqlParameter::Text {
            value: Some("parameter".into()),
        }];
        let facets = BTreeSet::from([("facet_values".into(), "record_id".into())]);
        assert_eq!(
            ids(
                "SELECT key,value FROM facet_values f WHERE f.record_id=?1",
                &parameters,
                &facets
            ),
            Some(vec!["parameter".into()])
        );
        let lifecycle = BTreeSet::from([
            (
                "record_lifecycle_interpretations".into(),
                "record_id".into(),
            ),
            ("vocabulary_values".into(), "value".into()),
        ]);
        assert_eq!(ids("SELECT v.value FROM record_lifecycle_interpretations i JOIN vocabulary_values v ON v.vocabulary_id=i.vocabulary_id WHERE i.record_id=?1",&parameters,&lifecycle),Some(vec!["parameter".into()]));
        assert_eq!(ids("SELECT i.record_id FROM record_lifecycle_interpretations i JOIN record_lifecycle_interpretations j ON j.status=i.status WHERE i.record_id=?1",&parameters,&lifecycle),None);
    }
    #[test]
    fn correlated_facets_share_only_the_outer_finite_record_domain() {
        let reads = BTreeSet::from([
            ("records".into(), "id".into()),
            ("facet_values".into(), "value".into()),
        ]);
        for sql in [
            "SELECT r.id,(SELECT value FROM facet_values WHERE record_id=r.id AND key='priority') FROM records r WHERE r.id='a'",
            "SELECT r.id FROM records r WHERE r.id='a' AND NOT EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived')",
            "SELECT r.id,(SELECT count(*) FROM facet_values f WHERE (f.record_id=r.id AND f.key='a') OR (f.record_id=r.id AND f.key='b')) FROM records r WHERE r.id='a'",
        ] {
            assert_eq!(ids(sql, &[], &reads), Some(vec!["a".into()]), "{sql}");
        }
        for sql in [
            "SELECT r.id,(SELECT count(*) FROM facet_values f WHERE f.record_id=r.id OR f.key='priority') FROM records r WHERE r.id='a'",
            "SELECT r.id,(SELECT count(*) FROM facet_values r WHERE r.key='priority') FROM records r WHERE r.id='a'",
            "SELECT r.id,(SELECT count(*) FROM facet_values f WHERE f.record_id=r.home_id) FROM records r WHERE r.id='a'",
            "SELECT r.id,(SELECT value FROM facet_values f WHERE f.record_id=r.id),(SELECT count(*) FROM facet_values) FROM records r WHERE r.id='a'",
            "SELECT r.id,(SELECT count(*) FROM facet_values f WHERE f.record_id=r.id AND EXISTS(SELECT 1 FROM facet_values)) FROM records r WHERE r.id='a'",
            "SELECT r.id,(WITH facet_values AS (SELECT * FROM records) SELECT count(*) FROM facet_values WHERE id=r.id) FROM records r WHERE r.id='a'",
        ] {
            assert_eq!(ids(sql, &[], &reads), None, "{sql}");
        }
    }

    #[test]
    fn uncertain_scopes_fall_back_to_full_visibility() {
        for sql in [
            "SELECT id FROM records WHERE id='a' OR kind='task'",
            "SELECT id FROM records WHERE id COLLATE NOCASE='a'",
            "SELECT id FROM records WHERE id=12",
            "SELECT id FROM records WHERE id IN ()",
            "SELECT id FROM records WHERE id=:named",
            "SELECT id FROM records WHERE id=?",
            "SELECT id FROM records WHERE id NOT IN ('a')",
            "SELECT id FROM records WHERE id IN ('a',12)",
            "SELECT r.id FROM records r JOIN records x ON x.id=r.id WHERE r.id='a'",
            "WITH x AS (SELECT id FROM records) SELECT id FROM x WHERE id='a'",
            "SELECT id,(SELECT count(*) FROM records) FROM records WHERE id='a'",
            "SELECT id FROM records WHERE id='a' ORDER BY (SELECT max(id) FROM records)",
            "SELECT id FROM records WHERE id='a' UNION ALL SELECT id FROM records",
        ] {
            assert_eq!(plan(sql), None, "{sql}");
        }
    }
}
