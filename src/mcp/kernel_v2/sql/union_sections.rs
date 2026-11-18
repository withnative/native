//! Omit only unobserved history populations behind closed UNION ALL selectors.
//! Original SQL, its complete validation and all non-history dependencies stay.
use super::{contract::QuerySqlParameter, guard};
use std::collections::BTreeSet;
use turso_parser::ast::{
    Cmd, CompoundOperator, Expr, Literal, OneSelect, Operator, ResultColumn, Select, SelectBody,
    SelectTable, Stmt,
};

const HISTORY: [&str; 3] = ["content_events", "actors", "runs"];

#[cfg(test)]
tokio::task_local! { static FULL_STAGING: (); }
#[cfg(test)]
pub(super) async fn with_full_staging<F: std::future::Future>(work: F) -> F::Output {
    FULL_STAGING.scope((), work).await
}

fn word(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn literal(expr: &Expr) -> Option<&str> {
    let Expr::Literal(Literal::String(value)) = expr else {
        return None;
    };
    value
        .strip_prefix('\'')?
        .strip_suffix('\'')
        .filter(|v| word(v))
}
fn guard(arm: &OneSelect) -> Option<(usize, &str)> {
    let OneSelect::Select {
        distinctness: None,
        columns,
        from: Some(from),
        where_clause: Some(predicate),
        group_by: None,
        window_clause,
    } = arm
    else {
        return None;
    };
    if !window_clause.is_empty()
        || !from.joins.is_empty()
        || !matches!(from.select.as_ref(), SelectTable::Select(_, _))
    {
        return None;
    }
    // In particular, an aggregate over a false WHERE can still return a row.
    if columns.iter().any(|column| !matches!(column, ResultColumn::Expr(expr, _) if matches!(expr.as_ref(), Expr::Id(_) | Expr::Literal(Literal::Null) | Expr::Literal(Literal::String(_))))) {
        return None;
    }
    let Expr::Binary(lhs, Operator::Equals, rhs) = predicate.as_ref() else {
        return None;
    };
    let Expr::Variable(variable) = lhs.as_ref() else {
        return None;
    };
    if !variable.numbered || variable.name.is_some() {
        return None;
    }
    Some((variable.index.get() as usize, literal(rhs)?))
}

/// Called only after full validation and installed-app admission, while the
/// standalone SQL read transaction is pinned. The observer prepares SQL against
/// its fixed logical schema only: it reads no workspace/source data, and its
/// result is neither cached nor reused across callers or snapshots.
pub(super) fn staging_reads(
    statement: &str,
    parameters: &[QuerySqlParameter],
    original: &BTreeSet<(String, String)>,
) -> Option<BTreeSet<(String, String)>> {
    #[cfg(test)]
    if FULL_STAGING.try_with(|_| ()).is_ok() {
        return None;
    }
    if !original
        .iter()
        .any(|(relation, _)| HISTORY.contains(&relation.as_str()))
    {
        return None;
    }
    let mut parser = turso_parser::parser::Parser::new(statement.as_bytes());
    let Cmd::Stmt(Stmt::Select(select)) = parser.next()?.ok()? else {
        return None;
    };
    if parser.next().is_some() {
        return None;
    }
    if select.with.is_some()
        || select.body.compounds.is_empty()
        || select.body.compounds.len() > 7
        || select
            .body
            .compounds
            .iter()
            .any(|c| c.operator != CompoundOperator::UnionAll)
    {
        return None;
    }
    let OneSelect::Select { columns, .. } = &select.body.select else {
        return None;
    };
    let names: BTreeSet<_> = columns
        .iter()
        .filter_map(|column| match column {
            ResultColumn::Expr(_, Some(alias)) => Some(alias.name().as_str()),
            ResultColumn::Expr(expr, None) => match expr.as_ref() {
                Expr::Id(name) => Some(name.as_str()),
                _ => None,
            },
            _ => None,
        })
        .collect();
    if select
        .order_by
        .iter()
        .any(|term| !matches!(term.expr.as_ref(), Expr::Id(name) if names.contains(name.as_str())))
    {
        return None;
    }
    if select.limit.as_ref().is_some_and(|limit| limit.offset.is_some() || !matches!(limit.expr.as_ref(), Expr::Literal(Literal::Numeric(n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))) { return None; }
    let mut index = None;
    let mut labels = BTreeSet::new();
    let mut selected = None;
    for arm in
        std::iter::once(&select.body.select).chain(select.body.compounds.iter().map(|c| &c.select))
    {
        let (parameter, label) = guard(arm)?;
        if index
            .replace(parameter)
            .is_some_and(|prior| prior != parameter)
            || !labels.insert(label)
        {
            return None;
        }
        let QuerySqlParameter::Text { value: Some(value) } =
            parameters.get(parameter.checked_sub(1)?)?
        else {
            return None;
        };
        if !word(value) {
            return None;
        }
        if value == label {
            selected = Some(arm);
        }
    }
    let selected = Select {
        with: None,
        body: SelectBody {
            select: selected?.clone(),
            compounds: vec![],
        },
        order_by: vec![],
        limit: None,
    };
    let observed = guard::public_reads_ad_hoc(&selected.to_string()).ok()?;
    if observed
        .iter()
        .any(|(relation, _)| HISTORY.contains(&relation.as_str()))
    {
        return None;
    }
    Some(
        original
            .iter()
            .filter(|(relation, _)| !HISTORY.contains(&relation.as_str()))
            .cloned()
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const SQL: &str = "SELECT id FROM (SELECT id FROM records) d WHERE ?1='details' UNION ALL SELECT id FROM (SELECT id FROM content_events) h WHERE ?1='history' ORDER BY id LIMIT 20";
    fn params(value: Option<&str>) -> Vec<QuerySqlParameter> {
        vec![QuerySqlParameter::Text {
            value: value.map(str::to_owned),
        }]
    }
    fn plan(sql: &str, parameters: &[QuerySqlParameter]) -> Option<BTreeSet<(String, String)>> {
        staging_reads(
            sql,
            parameters,
            &BTreeSet::from([
                ("records".into(), "id".into()),
                ("content_events".into(), "id".into()),
            ]),
        )
    }
    #[test]
    fn closed_selector_omits_only_unobserved_history() {
        assert_eq!(
            plan(SQL, &params(Some("details"))),
            Some(BTreeSet::from([("records".into(), "id".into())]))
        );
        assert!(plan(SQL, &params(Some("history"))).is_none());
    }
    #[test]
    fn unsupported_selectors_and_shapes_keep_full_staging() {
        for value in [None, Some("unknown"), Some("DETAILS"), Some("details ")] {
            assert!(plan(SQL, &params(value)).is_none());
        }
        assert!(plan(SQL, &[]).is_none());
        assert!(plan(
            SQL,
            &[QuerySqlParameter::Integer {
                value: Some("1".into())
            }]
        )
        .is_none());
        for sql in [
            SQL.replace("UNION ALL", "UNION"),
            SQL.replace("?1='details'", "?1 IN ('details')"),
            SQL.replace("?1='details'", "?1='details' OR 1"),
            SQL.replace("?1='details'", "lower(?1)='details'"),
            SQL.replace("?1='details'", "?1 COLLATE NOCASE='details'"),
            SQL.replace("?1='details'", "?1=CAST('details' AS TEXT)"),
            SQL.replace("?1='history'", "?1='details'"),
            SQL.replace("?1='history'", "?2='history'"),
            SQL.replace(
                "SELECT id FROM (SELECT id FROM records)",
                "SELECT count(*) AS id FROM (SELECT id FROM records)",
            ),
            format!("WITH x AS (SELECT 1) {SQL}"),
            SQL.replace("ORDER BY id", "ORDER BY (id||'')"),
            SQL.replace("LIMIT 20", "LIMIT ?1"),
            SQL.replace("'details'", "'det''ails'"),
            "malformed SQL".into(),
        ] {
            assert!(plan(&sql, &params(Some("details"))).is_none(), "{sql}");
        }
    }
}
