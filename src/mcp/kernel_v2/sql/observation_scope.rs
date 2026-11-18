//! A bounded event history may consume only that history's record facets.
//! Other observation consumers retain the complete original staging path.
use super::*;
use turso_parser::ast::{Cmd, Expr, OneSelect, Operator, ResultColumn, Select, SelectTable, Stmt};

tokio::task_local! { static IDS: String; }

pub(super) fn current() -> Option<String> {
    IDS.try_with(Clone::clone).ok()
}

pub(super) async fn scope<F: std::future::Future>(queries: &[PreparedRead], work: F) -> F::Output {
    match plan(queries) {
        Some(ids) => IDS.scope(ids, work).await,
        None => work.await,
    }
}

fn mentions(sql: &str) -> usize {
    sql.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|word| word.eq_ignore_ascii_case("facet_observations"))
        .count()
}

fn plan(queries: &[PreparedRead]) -> Option<String> {
    let mut ids = BTreeSet::new();
    let mut found = false;
    for query in queries {
        if !guard::public_reads_ad_hoc(&query.statement)
            .ok()?
            .iter()
            .any(|(r, _)| r == "facet_observations")
        {
            continue;
        }
        found = true;
        ids.extend(query_ids(&query.statement, &query.parameters)?);
        if ids.len() > 1000 {
            return None;
        }
    }
    if found {
        serde_json::to_string(&ids).ok()
    } else {
        None
    }
}

fn source(select: &Select) -> Option<(&str, &str)> {
    if select.with.is_some() || !select.body.compounds.is_empty() {
        return None;
    }
    let OneSelect::Select {
        from: Some(from),
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
    if table.db_name.is_some() || table.alias.is_some() {
        return None;
    }
    Some((
        table.name.as_str(),
        alias
            .as_ref()
            .map(|a| a.name().as_str())
            .unwrap_or(table.name.as_str()),
    ))
}

fn expressions(select: &Select, check: &dyn Fn(&Select) -> Result<()>) -> Option<()> {
    let OneSelect::Select {
        columns,
        where_clause,
        ..
    } = &select.body.select
    else {
        return None;
    };
    let visit = |e: &Expr| crate::query::turso_ast_rules::check_expr_selects(e, check).ok();
    for c in columns {
        if let ResultColumn::Expr(e, _) = c {
            visit(e)?;
        }
    }
    if let Some(e) = where_clause {
        visit(e)?;
    }
    for order in &select.order_by {
        visit(&order.expr)?;
    }
    if let Some(limit) = &select.limit {
        visit(&limit.expr)?;
        if let Some(e) = &limit.offset {
            visit(e)?;
        }
    }
    Some(())
}

fn correlated(e: &Expr, inner: &str, outer: &str) -> bool {
    let column = |e: &Expr, table: &str| matches!(e,Expr::Qualified(t,n) if t.as_str().eq_ignore_ascii_case(table) && n.as_str().eq_ignore_ascii_case("record_id"));
    match e {
        Expr::Parenthesized(v) if v.len() == 1 => correlated(&v[0], inner, outer),
        Expr::Binary(a, Operator::And, b) => {
            correlated(a, inner, outer) || correlated(b, inner, outer)
        }
        Expr::Binary(a, Operator::Or, b) => {
            correlated(a, inner, outer) && correlated(b, inner, outer)
        }
        Expr::Binary(a, Operator::Equals, b) => {
            (column(a, inner) && column(b, outer)) || (column(b, inner) && column(a, outer))
        }
        _ => false,
    }
}

fn query_ids(sql: &str, parameters: &[contract::QuerySqlParameter]) -> Option<BTreeSet<String>> {
    let mut parser = turso_parser::parser::Parser::new(sql.as_bytes());
    let Cmd::Stmt(Stmt::Select(select)) = parser.next()?.ok()? else {
        return None;
    };
    if parser.next().is_some() {
        return None;
    }
    let (table, outer) = source(&select)?;
    if !table.eq_ignore_ascii_case("content_events") {
        return None;
    }
    let OneSelect::Select {
        where_clause: Some(predicate),
        ..
    } = &select.body.select
    else {
        return None;
    };
    let ids = record_scope::bounds(predicate, outer, "record_id", parameters)?;
    let seen = std::cell::Cell::new(0);
    let check = |nested: &Select| {
        let text = nested.to_string();
        if mentions(&text) == 0 {
            return Ok(());
        }
        let verify = || {
            let (table, inner) = source(nested)?;
            if !table.eq_ignore_ascii_case("facet_observations")
                || inner.eq_ignore_ascii_case(outer)
            {
                return None;
            }
            let OneSelect::Select {
                where_clause: Some(p),
                ..
            } = &nested.body.select
            else {
                return None;
            };
            if !correlated(p, inner, outer) {
                return None;
            }
            expressions(nested, &|_| Err(Error::engine("nested observation scope")))?;
            // Also reject IN-table references, qualifiers or literals which
            // prevent this closed pass accounting for every observation scan.
            if mentions(&text) != 1 {
                return None;
            }
            Some(())
        };
        verify().ok_or_else(|| Error::engine("observations require full staging"))?;
        seen.set(seen.get() + 1);
        Ok(())
    };
    expressions(&select, &check)?;
    (seen.get() > 0 && seen.get() == mentions(sql)).then_some(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_observations_require_every_consumer_to_be_correlated() {
        let parameters = [contract::QuerySqlParameter::Text {
            value: Some("selected".into()),
        }];
        let good="SELECT e.local_seq,(SELECT o.value FROM facet_observations o WHERE o.record_id=e.record_id AND o.event_seq=e.local_seq ORDER BY o.id LIMIT 1) FROM content_events e WHERE e.record_id=?1 ORDER BY e.local_seq";
        assert_eq!(
            query_ids(good, &parameters),
            Some(BTreeSet::from(["selected".into()]))
        );
        for bad in [
            good.replace("o.record_id=e.record_id AND ", ""),
            good.replace("o.record_id=e.record_id AND", "o.record_id=e.record_id OR"),
            good.replace(
                "SELECT o.value",
                "SELECT (SELECT value FROM facet_observations LIMIT 1)",
            ),
            good.replace("WHERE e.record_id=?1", "WHERE e.actor=?1"),
            good.replace(
                "SELECT e.local_seq,",
                "SELECT e.local_seq,(SELECT count(*) FROM facet_observations),",
            ),
        ] {
            assert!(query_ids(&bad, &parameters).is_none(), "{bad}");
        }
        let (a, _) = prepare_read(
            "fixture",
            json!({"sql":good,"parameters":[{"type":"text","value":"selected"}]}),
            false,
        )
        .unwrap();
        let (b, _) = prepare_read(
            "fixture",
            json!({"sql":"SELECT count(*) FROM facet_observations"}),
            false,
        )
        .unwrap();
        assert!(
            plan(&[a, b]).is_none(),
            "an unbounded batch item keeps full observations"
        );
    }
}
