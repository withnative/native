//! Demand for correlated event counts. Candidate IDs narrow event work only;
//! every original record, endpoint and retained-header admission still runs.
use super::*;
use std::collections::BTreeMap;
use turso_parser::ast::{
    Cmd, Expr, Literal, OneSelect, Operator, ResultColumn, Select, SelectTable, Stmt,
};

tokio::task_local! { static CANDIDATE: String; }
#[cfg(test)]
tokio::task_local! { static FULL: (); }

#[cfg(test)]
pub(crate) async fn with_full_staging<F: std::future::Future>(work: F) -> F::Output {
    FULL.scope((), work).await
}

pub(super) async fn scope<F: std::future::Future>(statements: &[&str], work: F) -> F::Output {
    #[cfg(test)]
    if FULL.try_with(|_| ()).is_ok() {
        return work.await;
    }
    match statements {
        [statement] => match candidate(statement) {
            Some(sql) => CANDIDATE.scope(sql, work).await,
            None => work.await,
        },
        _ => work.await,
    }
}

/// Bindings may narrow event demand, never record visibility. Every event
/// reference must have a proven subject superset or the whole batch falls back.
pub(super) async fn bound_scope<F: std::future::Future>(
    queries: &[PreparedRead],
    work: F,
) -> F::Output {
    #[cfg(test)]
    if FULL.try_with(|_| ()).is_ok() {
        return work.await;
    }
    let mut subjects = Vec::new();
    for query in queries {
        if has_events(&query.statement) == Some(false) {
            continue;
        }
        let Some(mut demand) = bound_candidates(&query.statement, &query.parameters) else {
            return work.await;
        };
        subjects.append(&mut demand);
    }
    if subjects.is_empty() {
        let statements = queries
            .iter()
            .map(|q| q.statement.as_str())
            .collect::<Vec<_>>();
        return scope(&statements, work).await;
    }
    observation_scope::scope(queries, CANDIDATE.scope(subjects.join(" UNION "), work)).await
}

fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn id_query(ids: &BTreeSet<String>) -> String {
    format!(
        "SELECT value FROM json_each({})",
        literal(&serde_json::to_string(ids).expect("string ids"))
    )
}

fn bound_candidates(sql: &str, parameters: &[contract::QuerySqlParameter]) -> Option<Vec<String>> {
    let mut parser = turso_parser::parser::Parser::new(sql.as_bytes());
    let Cmd::Stmt(Stmt::Select(select)) = parser.next()?.ok()? else {
        return None;
    };
    if parser.next().is_some() {
        return None;
    }
    let demand = collect_bound(&select, parameters, &BTreeMap::new())?;
    // The shared expression walker visits SELECTs, but SQLite also permits
    // `x IN content_events` without a SELECT node. Require one recognized
    // FROM per occurrence. Qualifiers, aliases or literal text can overcount
    // and conservatively fall back; no reference may silently be omitted.
    let words = sql
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .collect::<Vec<_>>();
    if words.iter().any(|word| word.eq_ignore_ascii_case("actors")) {
        return None;
    }
    let references = words
        .iter()
        .filter(|word| word.eq_ignore_ascii_case("content_events"))
        .count();
    (references == demand.len()).then_some(demand)
}

fn collect_bound(
    select: &Select,
    parameters: &[contract::QuerySqlParameter],
    inherited: &BTreeMap<String, String>,
) -> Option<Vec<String>> {
    use turso_parser::ast::{JoinConstraint, JoinOperator, JoinType};
    if select.with.is_some() || !select.body.compounds.is_empty() {
        return None;
    }
    let OneSelect::Select {
        columns,
        from: Some(from),
        where_clause,
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
    let table = |source: &SelectTable| -> Option<(String, String)> {
        let SelectTable::Table(t, a, _) = source else {
            return None;
        };
        if t.db_name.is_some() || t.alias.is_some() {
            return None;
        }
        Some((
            t.name.as_str().to_ascii_lowercase(),
            a.as_ref()
                .map(|a| a.name().as_str())
                .unwrap_or(t.name.as_str())
                .to_ascii_lowercase(),
        ))
    };
    let (relation, alias) = table(&from.select)?;
    let mut correlations = inherited.clone();
    correlations.remove(&alias);
    for join in &from.joins {
        let (relation, alias) = table(&join.table)?;
        if relation == "content_events" || relation == "actors" {
            return None;
        }
        correlations.remove(&alias);
    }
    // A link endpoint lookup supplies a superset for correlated event reads
    // on the joined record. Keep all link endpoints, regardless of later
    // record predicates; final SQL and event admission remain unchanged.
    if relation == "links" && from.joins.len() == 1 {
        let join = &from.joins[0];
        let (joined, record_alias) = table(&join.table)?;
        let inner = matches!(join.operator, JoinOperator::TypedJoin(None))
            || matches!(join.operator, JoinOperator::TypedJoin(Some(t)) if t == JoinType::INNER);
        if joined == "records" && inner {
            if let (Some(predicate), Some(JoinConstraint::On(on))) =
                (where_clause, &join.constraint)
            {
                for (bound, endpoint) in [("target_id", "source_id"), ("source_id", "target_id")] {
                    let equality = matches!(on.as_ref(), Expr::Binary(a,Operator::Equals,b) if
                        (column(a,&record_alias,"id") && column(b,&alias,endpoint)) ||
                        (column(b,&record_alias,"id") && column(a,&alias,endpoint)));
                    if equality {
                        if let Some(ids) =
                            record_scope::bounds(predicate, &alias, bound, parameters)
                        {
                            correlations.insert(
                                record_alias.clone(),
                                format!(
                                    "SELECT {endpoint} FROM links WHERE {bound} IN ({})",
                                    id_query(&ids)
                                ),
                            );
                        }
                    }
                }
            }
        }
    }
    let mut result = Vec::new();
    if relation == "actors" {
        return None;
    }
    if relation == "content_events" {
        if !from.joins.is_empty() {
            return None;
        }
        let predicate = where_clause.as_ref()?;
        if let Some(ids) = record_scope::bounds(predicate, &alias, "record_id", parameters) {
            result.push(id_query(&ids));
        } else {
            fn correlation(
                e: &Expr,
                alias: &str,
                known: &BTreeMap<String, String>,
            ) -> Option<String> {
                match e {
                    Expr::Parenthesized(v) if v.len() == 1 => correlation(&v[0], alias, known),
                    Expr::Binary(a, Operator::And, b) => {
                        correlation(a, alias, known).or_else(|| correlation(b, alias, known))
                    }
                    Expr::Binary(a, Operator::Equals, b) => {
                        for (local, foreign) in [(a, b), (b, a)] {
                            if column(local, alias, "record_id") {
                                if let Expr::Qualified(t, n) = foreign.as_ref() {
                                    if n.as_str().eq_ignore_ascii_case("id") {
                                        return known
                                            .get(&t.as_str().to_ascii_lowercase())
                                            .cloned();
                                    }
                                }
                            }
                        }
                        None
                    }
                    _ => None,
                }
            }
            result.push(correlation(predicate, &alias, &correlations)?);
        }
    }
    let nested = std::cell::RefCell::new(Vec::new());
    let check = |s: &Select| {
        let found = collect_bound(s, parameters, &correlations)
            .ok_or_else(|| Error::engine("event demand needs full staging"))?;
        nested.borrow_mut().extend(found);
        Ok(())
    };
    let visit = |e: &Expr| crate::query::turso_ast_rules::check_expr_selects(e, &check).ok();
    for c in columns {
        if let ResultColumn::Expr(e, _) = c {
            visit(e)?;
        }
    }
    if let Some(e) = where_clause {
        visit(e)?;
    }
    for join in &from.joins {
        if let Some(JoinConstraint::On(e)) = &join.constraint {
            visit(e)?;
        }
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
    result.extend(nested.into_inner());
    Some(result)
}

fn has_events(sql: &str) -> Option<bool> {
    Some(
        guard::public_reads_ad_hoc(sql)
            .ok()?
            .iter()
            // actors is derived from the complete staged event relation.
            .any(|(r, _)| r == "content_events" || r == "actors"),
    )
}

fn column(expr: &Expr, table: &str, name: &str) -> bool {
    matches!(expr, Expr::Qualified(t, n) if t.as_str().eq_ignore_ascii_case(table) && n.as_str().eq_ignore_ascii_case(name))
}

fn correlated_count(select: &Select, outer: &str) -> bool {
    if select.with.is_some()
        || !select.body.compounds.is_empty()
        || select.limit.is_some()
        || !select.order_by.is_empty()
    {
        return false;
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
        return false;
    };
    if !from.joins.is_empty() || !window_clause.is_empty() {
        return false;
    }
    let SelectTable::Table(table, alias, _) = from.select.as_ref() else {
        return false;
    };
    if table.db_name.is_some()
        || table.alias.is_some()
        || !table.name.as_str().eq_ignore_ascii_case("content_events")
    {
        return false;
    }
    let inner = alias
        .as_ref()
        .map(|a| a.name().as_str())
        .unwrap_or(table.name.as_str());
    if inner.eq_ignore_ascii_case(outer) {
        return false;
    }
    let [ResultColumn::Expr(expr, _)] = columns.as_slice() else {
        return false;
    };
    let Expr::FunctionCallStar { name, filter_over } = expr.as_ref() else {
        return false;
    };
    if !name.as_str().eq_ignore_ascii_case("count")
        || filter_over.filter_clause.is_some()
        || filter_over.over_clause.is_some()
    {
        return false;
    }
    let Expr::Binary(a, Operator::Equals, b) = predicate.as_ref() else {
        return false;
    };
    // Keep the public event record_id on the left: an arbitrary CTE's id may
    // carry a different inherited collation or affinity.
    column(a, inner, "record_id") && column(b, outer, "id")
}

// The two evaluations must select the same subjects. Admit only direct
// column projections and deterministic predicates over identity-preserving
// record/link sources. Nested LIMITs require the source's unique id in ORDER
// BY; timestamp ties alone must never select different subjects between passes.
fn stable_expr(expr: &Expr, sources: &BTreeMap<String, bool>) -> bool {
    match expr {
        Expr::Id(_) | Expr::Qualified(_, _) | Expr::Variable(_) => true,
        Expr::Literal(literal) => matches!(
            literal,
            Literal::Numeric(_)
                | Literal::String(_)
                | Literal::Blob(_)
                | Literal::Null
                | Literal::True
                | Literal::False
        ),
        Expr::Binary(a, _, b) => stable_expr(a, sources) && stable_expr(b, sources),
        Expr::IsNull(e) | Expr::NotNull(e) | Expr::Unary(_, e) => stable_expr(e, sources),
        Expr::Parenthesized(es) => es.iter().all(|e| stable_expr(e, sources)),
        Expr::InList { lhs, rhs, .. } => {
            stable_expr(lhs, sources) && rhs.iter().all(|e| stable_expr(e, sources))
        }
        Expr::InSelect { lhs, rhs, .. } => stable_expr(lhs, sources) && stable_select(rhs, sources),
        _ => false,
    }
}

fn stable_select(select: &Select, inherited: &BTreeMap<String, bool>) -> bool {
    let mut sources = inherited.clone();
    if let Some(with) = &select.with {
        if with.recursive {
            return false;
        }
        for cte in &with.ctes {
            let name = cte.tbl_name.as_str().to_ascii_lowercase();
            // Only unrenamed direct projections preserve source identity.
            // Link IDs need not be unique across provider and ordinary rows;
            // only record lineage can establish a total nested LIMIT order.
            if sources.contains_key(&name)
                || !cte.columns.is_empty()
                || !cte.select.body.compounds.is_empty()
                || !stable_select(&cte.select, &sources)
            {
                return false;
            }
            let unique = simple_source(&cte.select.body.select, &sources);
            sources.insert(name, unique);
        }
    }
    for one in
        std::iter::once(&select.body.select).chain(select.body.compounds.iter().map(|c| &c.select))
    {
        let OneSelect::Select {
            columns,
            from: Some(from),
            where_clause,
            group_by: None,
            window_clause,
            ..
        } = one
        else {
            return false;
        };
        if !from.joins.is_empty() || !window_clause.is_empty() {
            return false;
        }
        let source_alias = match from.select.as_ref() {
            SelectTable::Table(table, alias, _) => Some(
                alias
                    .as_ref()
                    .map(|a| a.name().as_str())
                    .unwrap_or(table.name.as_str()),
            ),
            SelectTable::Select(_, alias) => alias.as_ref().map(|a| a.name().as_str()),
            _ => None,
        };
        let column_name = |e: &Expr| match e {
            Expr::Id(n) => Some(n.as_str().to_ascii_lowercase()),
            Expr::Qualified(t, n)
                if source_alias.is_some_and(|a| t.as_str().eq_ignore_ascii_case(a)) =>
            {
                Some(n.as_str().to_ascii_lowercase())
            }
            _ => None,
        };
        if !columns.iter().all(|c| matches!(c, ResultColumn::Expr(e, alias) if alias.as_ref().is_none_or(|a| !a.is_explicit()) && column_name(e).is_some()))
            || !columns.iter().any(|c| matches!(c, ResultColumn::Expr(e, alias) if alias.as_ref().is_none_or(|a| !a.is_explicit()) && column_name(e).as_deref()==Some("id")))
            || where_clause.as_ref().is_some_and(|e| !stable_expr(e, &sources))
        { return false; }
        match from.select.as_ref() {
            SelectTable::Table(table, _, _) if table.db_name.is_none() && table.alias.is_none() && sources.contains_key(&table.name.as_str().to_ascii_lowercase()) => {},
            SelectTable::Select(child, _) if select.limit.is_none() && stable_select(child, &sources)
                && columns.iter().all(|c| matches!(c, ResultColumn::Expr(e, alias) if alias.as_ref().is_none_or(|a| !a.is_explicit()) && column_name(e).as_deref()==Some("id"))) => {},
            _ => return false,
        }
        if select.limit.is_some() {
            if !simple_source(one, &sources) {
                return false;
            }
            let SelectTable::Table(table, alias, _) = from.select.as_ref() else {
                return false;
            };
            let alias = alias
                .as_ref()
                .map(|a| a.name().as_str())
                .unwrap_or(table.name.as_str());
            if !select.body.compounds.is_empty() || !select.order_by.iter().any(|c| column(&c.expr, alias, "id") || matches!(c.expr.as_ref(), Expr::Id(n) if n.as_str().eq_ignore_ascii_case("id"))) { return false; }
        }
    }
    select
        .order_by
        .iter()
        .all(|c| stable_expr(&c.expr, &sources))
        && select.limit.as_ref().is_none_or(|l| {
            matches!(l.expr.as_ref(), Expr::Literal(Literal::Numeric(_))) && l.offset.is_none()
        })
}

fn simple_source(one: &OneSelect, sources: &BTreeMap<String, bool>) -> bool {
    matches!(one, OneSelect::Select { from: Some(from), .. }
        if matches!(from.select.as_ref(), SelectTable::Table(table, _, _) if sources.get(&table.name.as_str().to_ascii_lowercase()) == Some(&true)))
}

/// Keep the outer FROM/WHERE and CTEs, but discard ordering/limit: candidates
/// must include every possible outer record, including those sorted by counts.
/// Every event reference must be one of the recognized projection subqueries.
fn candidate(sql: &str) -> Option<String> {
    let mut parser = turso_parser::parser::Parser::new(sql.as_bytes());
    let Cmd::Stmt(Stmt::Select(mut select)) = parser.next()?.ok()? else {
        return None;
    };
    if parser.next().is_some() || !select.body.compounds.is_empty() {
        return None;
    }
    if select.with.as_ref().is_some_and(|w| {
        w.recursive
            || w.ctes
                .iter()
                .any(|c| c.tbl_name.as_str().eq_ignore_ascii_case("content_events"))
    }) {
        return None;
    }
    let OneSelect::Select {
        columns,
        from: Some(from),
        group_by: None,
        window_clause,
        ..
    } = &mut select.body.select
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
    let outer = alias
        .as_ref()
        .map(|a| a.name().clone())
        .unwrap_or_else(|| table.name.clone());
    let mut found = false;
    for column in columns.iter_mut() {
        if let ResultColumn::Expr(expr, _) = column {
            if let Expr::Subquery(subquery) = expr.as_ref() {
                if correlated_count(subquery, outer.as_str()) {
                    **expr = Expr::Literal(Literal::Null);
                    found = true;
                }
            }
        }
    }
    if !found || has_events(&select.to_string())? {
        return None;
    }
    let OneSelect::Select { columns, .. } = &mut select.body.select else {
        unreachable!()
    };
    *columns = vec![ResultColumn::Expr(
        Box::new(Expr::Qualified(
            outer,
            turso_parser::ast::Name::exact("id".into()),
        )),
        None,
    )];
    select.order_by.clear();
    select.limit = None;
    if !stable_select(
        &select,
        &BTreeMap::from([("records".into(), true), ("links".into(), false)]),
    ) {
        return None;
    }
    let sql = select.to_string();
    // Candidate discovery runs before messaging, runs, catalogue and blob
    // relations are populated. Reading their temporary empty placeholders
    // would silently omit event subjects. Only inspect dependencies retained
    // in the candidate, since discarded result columns execute later.
    if guard::public_reads_ad_hoc(&sql)
        .ok()?
        .iter()
        .any(|(relation, _)| {
            !matches!(
                relation.as_str(),
                "records" | "links" | "facet_values" | "facet_observations" | "facet_times"
            )
        })
    {
        return None;
    }
    Some(sql)
}

pub(super) async fn stage(conn: &mut sqlx::SqliteConnection, actor: &str) -> Result<bool> {
    let Ok(sql) = CANDIDATE.try_with(Clone::clone) else {
        return Ok(false);
    };
    // Validate the generated read through the same public compiler. Parameter
    // and clock-dependent candidates retain full staging; this helper has no
    // independent binding or clock authority.
    let Ok((prepared, _)) = prepare_read(actor, json!({"sql":sql}), false) else {
        return Ok(false);
    };
    if prepared.time_dependent || !prepared.parameters.is_empty() {
        return Ok(false);
    }
    let started = std::time::Instant::now();
    let mut ids = BTreeSet::new();
    let scan = async {
        let mut rows = sqlx::query(&prepared.statement)
            .persistent(false)
            .fetch(&mut *conn);
        while let Some(row) = rows.try_next().await? {
            let Ok(id) = row.try_get::<Option<String>, _>(0) else {
                return Ok::<bool, sqlx::Error>(false);
            };
            if let Some(id) = id {
                ids.insert(id);
            }
            if ids.len() > 1000 {
                return Ok(false);
            }
        }
        Ok(true)
    }
    .await;
    match scan {
        Ok(true) => {}
        Ok(false) => return Ok(false),
        Err(error) => {
            // Removing result aliases can invalidate a legal WHERE alias;
            // discovering a superset can also encounter an expression error
            // outside the original LIMIT. Only semantic statement errors may
            // fall back, and only inside the original transaction. Interrupts
            // and storage errors retain their original failure and deadline.
            let semantic = error
                .as_database_error()
                .and_then(|e| e.code())
                .and_then(|code| code.parse::<i32>().ok())
                .is_some_and(|code| code & 0xff == libsqlite3_sys::SQLITE_ERROR);
            if !semantic {
                return Err(error.into());
            }
            let mut handle = conn.lock_handle().await?;
            // SAFETY: the exclusively locked handle is live.
            let active = unsafe {
                libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) == 0
            };
            if !active {
                return Err(error.into());
            }
            drop(handle);
            // Keep the original progress guard active while confirming that
            // this snapshot can still execute after the failed statement.
            sqlx::query("SELECT 1").execute(&mut *conn).await?;
            return Ok(false);
        }
    }
    tracing::debug!(target: "native_ce::read_staging", phase = "event_candidates", elapsed_us = started.elapsed().as_micros() as u64, subjects = ids.len());
    sqlx::query("CREATE TEMP TABLE _v2_event_subjects(id TEXT PRIMARY KEY)")
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO temp._v2_event_subjects SELECT value FROM json_each(?)")
        .bind(serde_json::to_string(&ids)?)
        .execute(&mut *conn)
        .await?;
    // Native positions and retained logical headers may have different record
    // carriers. Keep their union as a structural superset; the unchanged
    // position-bounded selectors still decide admission. Visibility already
    // covers the complete corpus, including endpoints and legacy subjects.
    sqlx::query("CREATE TEMP TABLE _v2_history_candidates(seq INTEGER PRIMARY KEY); INSERT INTO temp._v2_history_candidates SELECT e.seq FROM temp._v2_event_subjects s CROSS JOIN main.content_events e ON e.record_id=s.id UNION SELECT e.seq FROM temp._v2_event_subjects s CROSS JOIN main.kernel_legacy_sql_events e ON e.record_id=s.id").execute(conn).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_event_demand_covers_installed_prism_details_and_refuses_uncertain_shapes() {
        let needs: Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/kernel_v2_prism_reads.json"
        ))
        .unwrap();
        let parameters = [contract::QuerySqlParameter::Text {
            value: Some("selected' record".into()),
        }];
        for need in needs.as_array().unwrap() {
            if ["prism.history", "prism.comments", "prism.runs"]
                .contains(&need["key"].as_str().unwrap())
            {
                assert!(
                    !bound_candidates(need["sql"].as_str().unwrap(), &parameters)
                        .unwrap()
                        .is_empty(),
                    "{}",
                    need["key"]
                );
            }
        }
        for statement in [
            "SELECT local_seq FROM content_events ORDER BY local_seq",
            "SELECT local_seq FROM content_events WHERE record_id=?1 OR actor='other' ORDER BY local_seq",
            "SELECT e.local_seq,(SELECT count(*) FROM content_events) FROM content_events e WHERE e.record_id=?1 ORDER BY e.local_seq",
            "SELECT e.local_seq FROM content_events e WHERE e.record_id=?1 AND e.local_seq IN content_events ORDER BY e.local_seq",
            "SELECT e.local_seq FROM content_events e WHERE e.record_id=?1 AND e.actor IN actors ORDER BY e.local_seq",
            "WITH content_events AS (SELECT id FROM records) SELECT id FROM content_events WHERE id=?1",
            "SELECT e.local_seq FROM records r JOIN content_events e ON e.record_id=r.id WHERE r.id=?1",
            "SELECT c.id,(SELECT e.actor FROM content_events e WHERE e.record_id=c.id ORDER BY e.local_seq LIMIT 1) FROM links l RIGHT JOIN records c ON c.id=l.source_id WHERE l.target_id=?1 OR l.target_id IS NULL ORDER BY c.id",
            "SELECT c.id,(SELECT e.actor FROM content_events e WHERE e.record_id=c.id ORDER BY e.local_seq LIMIT 1) FROM links l JOIN records c ON c.id=l.source_id WHERE l.target_id=?1 OR l.relationship='other' ORDER BY c.id",
            "SELECT l.id,(SELECT e.actor FROM content_events e WHERE e.record_id=c.id ORDER BY e.local_seq LIMIT 1),(SELECT count(*) FROM actors) FROM links l JOIN records c ON c.id=l.source_id WHERE l.target_id=?1 ORDER BY l.id",
        ] { assert!(bound_candidates(statement,&parameters).is_none(),"{statement}"); }
    }

    #[tokio::test]
    async fn event_count_candidate_fallback_keeps_transaction_and_temp_schema() {
        use sqlx::Connection;
        let mut conn = sqlx::SqliteConnection::connect(":memory:").await.unwrap();
        sqlx::raw_sql("CREATE TABLE records(id TEXT PRIMARY KEY); BEGIN; INSERT INTO records WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1001) SELECT printf('%04d',x) FROM n;").execute(&mut conn).await.unwrap();
        for sql in [
            "SELECT id FROM records",                         // >1000 distinct subjects
            "SELECT id FROM records WHERE missing_alias='a'", // prepare-time semantic error
            "SELECT id FROM records WHERE json_extract('broken','$') IS NULL", // step-time semantic error
            "SELECT id FROM records WHERE id=?1", // no binding authority
            "SELECT id FROM records WHERE now_ms()>0", // no independent clock
        ] {
            assert!(!CANDIDATE
                .scope(sql.to_owned(), stage(&mut conn, "acct:test"))
                .await
                .unwrap());
            let absent: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM sqlite_temp_master WHERE name='_v2_event_subjects'",
            )
            .fetch_one(&mut conn)
            .await
            .unwrap();
            assert_eq!(absent, 0);
            let mut handle = conn.lock_handle().await.unwrap();
            assert_eq!(
                unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) },
                0
            );
        }
        // A real SQLite interruption during candidate scanning must propagate.
        {
            let mut handle = conn.lock_handle().await.unwrap();
            handle.set_progress_handler(1, || false);
        }
        assert!(CANDIDATE
            .scope(
                "SELECT id FROM records".to_owned(),
                stage(&mut conn, "acct:test")
            )
            .await
            .is_err());
    }

    #[test]
    fn event_count_candidates_exclude_relations_staged_later() {
        for relation in [
            "my_message_state",
            "messages_awaiting_reply",
            "message_reactions",
            "my_mentions",
            "agent_activity",
            "agent_activity_claims",
            "runs",
            "run_intents",
            "record_lifecycle_interpretations",
            "blobs",
            "actors",
            "viewer",
            "bindings",
            "comment_anchors",
        ] {
            let sql = format!("SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM records r WHERE r.id IN (SELECT id FROM {relation})");
            assert!(candidate(&sql).is_none(), "{relation}");
        }
    }

    #[test]
    fn event_count_candidates_must_be_correlated_and_cover_every_event_reference() {
        for sql in [
            "SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) AS events FROM records r WHERE r.id IN ('a','b') ORDER BY events DESC LIMIT 1",
            "WITH picked AS MATERIALIZED (SELECT id FROM records WHERE kind='task' ORDER BY id LIMIT 5) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM picked r",
        ] { assert!(candidate(sql).is_some(), "{sql}"); }
        for sql in [
            "SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM records r WHERE CURRENT_TIMESTAMP>'2000'",
            "WITH picked AS (SELECT id FROM links ORDER BY id LIMIT 5) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM picked r",
            "WITH picked AS (SELECT id FROM records ORDER BY id LIMIT 5 OFFSET 1) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM picked r",
            "WITH records AS (SELECT id FROM links) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM records r",
            "WITH picked AS (SELECT id FROM records UNION ALL SELECT id FROM records) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM picked r",
            "WITH picked(id) AS (SELECT id FROM records) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM picked r",
            "WITH picked AS (SELECT id FROM records ORDER BY created_at LIMIT 5) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM picked r",
            "WITH picked AS (SELECT id FROM records ORDER BY id LIMIT 5) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM picked r WHERE random()>0",
            "SELECT r.id,(SELECT count(*) FROM content_events) FROM records r",
            "SELECT r.id,(SELECT count(*) FROM content_events r WHERE r.record_id=r.id) FROM records r",
            "SELECT r.id,(SELECT count(*) FROM content_events e WHERE r.id=e.record_id) FROM records r",
            "SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id OR e.actor='other') FROM records r",
            "SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id),(SELECT max(local_seq) FROM content_events) FROM records r",
            "SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id),(SELECT count(*) FROM actors) FROM records r",
            "SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM records r WHERE EXISTS(SELECT 1 FROM content_events)",
            "WITH content_events AS (SELECT id AS record_id FROM records) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) FROM records r",
        ] { assert!(candidate(sql).is_none(), "{sql}"); }
    }
}
