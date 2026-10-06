//! Proposed registry-owned SQL total-order proof, using the shared authoritative
//! AST/catalog. No author uniqueness claims or observed rows are accepted.
#![allow(dead_code)] // Pure proposed seam; production admission belongs to parent.
use crate::{Error, Result};
use native_query_contract::{
    rule_contract::{PinnedRelation, RULE_ORDER_PROOF_VERSION},
    sql_contract::{QuerySqlProfile, LOGICAL_RELATIONS},
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use turso_parser::ast::{
    Expr, JoinOperator, JoinType, Literal, OneSelect, Operator, ResultColumn, Select, SelectTable,
};

fn reject(message: impl AsRef<str>) -> Error {
    super::sql_contract::categorized_error(super::sql_contract::QuerySqlErrorCategory::UnsafeStatement, format!("rule total order: {}; use audited base keys in ORDER BY (records: id; links: source_id,target_id,relationship), or aggregate to one row", message.as_ref()))
}
/// Host-issued proof. No Deserialize and private fields: request data cannot
/// masquerade as ordering evidence. Future receipts bind its canonical digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrderProof {
    version: u32,
    profile_id: String,
    profile_revision: u32,
    relations: Vec<PinnedRelation>,
    singleton: bool,
    ordered_keys: Vec<String>,
}
impl OrderProof {
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn singleton(&self) -> bool {
        self.singleton
    }
    pub fn ordered_keys(&self) -> &[String] {
        &self.ordered_keys
    }
}
struct Base {
    name: String,
    qualifier: String,
    columns: BTreeSet<String>,
    keys: &'static [&'static [&'static str]],
}

fn base(table: &SelectTable) -> Result<Base> {
    let SelectTable::Table(name, alias, indexed) = table else {
        return Err(reject(
            "CTEs, derived tables and table functions are unsupported; flatten the query",
        ));
    };
    if name.db_name.is_some() || indexed.is_some() {
        return Err(reject("schema qualifiers and index hints are unsupported"));
    }
    let name = name.name.as_str().to_ascii_lowercase();
    let relation = LOGICAL_RELATIONS
        .iter()
        .find(|r| r.name == name)
        .ok_or_else(|| reject("relation is not in the authoritative public catalog"))?;
    if relation.completeness != "complete" || !relation.profiles.contains(&"sqlite-local") {
        return Err(reject("relation is ineligible for SQLite rules"));
    }
    let keys = native_query_contract::rule_contract::rule_stable_unique_keys(
        relation.identity,
        relation.semantic_version,
        QuerySqlProfile::SqliteLocal.contract().id,
        QuerySqlProfile::SqliteLocal.contract().revision,
        RULE_ORDER_PROOF_VERSION,
    )
    .ok_or_else(|| {
        reject(format!(
            "no audited stable key for '{name}' in this proof version"
        ))
    })?;
    Ok(Base {
        qualifier: alias
            .as_ref()
            .map(|a| a.name().as_str().to_ascii_lowercase())
            .unwrap_or_else(|| name.clone()),
        name,
        columns: relation.columns.iter().map(|c| c.to_string()).collect(),
        keys,
    })
}
// SQLite preserves alias/ordinal precedence through singleton parentheses.
// Normalize before exactly ONE output resolution; alias targets are base SQL
// expressions, never recursively resolved through other output labels.
fn normalized(mut expr: &Expr) -> &Expr {
    while let Expr::Parenthesized(items) = expr {
        if items.len() != 1 {
            break;
        }
        expr = &items[0];
    }
    expr
}
fn parts(expr: &Expr) -> Option<(Option<String>, String)> {
    match expr {
        Expr::Id(n) | Expr::Name(n) => Some((None, n.as_str().to_ascii_lowercase())),
        Expr::Qualified(q, n) => Some((
            Some(q.as_str().to_ascii_lowercase()),
            n.as_str().to_ascii_lowercase(),
        )),
        Expr::Parenthesized(v) if v.len() == 1 => parts(&v[0]),
        _ => None,
    }
}
fn column(expr: &Expr, bases: &[Base]) -> Option<(usize, String)> {
    let (qualifier, name) = parts(expr)?;
    let candidates = bases
        .iter()
        .enumerate()
        .filter(|(_, b)| {
            b.columns.contains(&name) && qualifier.as_ref().is_none_or(|q| q == &b.qualifier)
        })
        .collect::<Vec<_>>();
    if candidates.len() == 1 {
        Some((candidates[0].0, name))
    } else {
        None
    }
}
fn fixed_value(expr: &Expr, bases: &[Base]) -> bool {
    match expr {
        Expr::Literal(_) | Expr::Variable(_) => true,
        // Explicit correlated reference, never a column of this SELECT. Names
        // are authorizer/prepare checked; alias shadowing cannot imply unique.
        Expr::Qualified(q, _) => !bases
            .iter()
            .any(|b| b.qualifier.eq_ignore_ascii_case(q.as_str())),
        Expr::Parenthesized(v) if v.len() == 1 => fixed_value(&v[0], bases),
        _ => false,
    }
}
fn fixed_columns(expr: &Expr, bases: &[Base], fixed: &mut BTreeSet<(usize, String)>) {
    match expr {
        Expr::Binary(a, Operator::And, b) => {
            fixed_columns(a, bases, fixed);
            fixed_columns(b, bases, fixed);
        }
        Expr::Binary(a, Operator::Equals, b) => {
            if fixed_value(b, bases) {
                if let Some(c) = column(a, bases) {
                    fixed.insert(c);
                }
            }
            if fixed_value(a, bases) {
                if let Some(c) = column(b, bases) {
                    fixed.insert(c);
                }
            }
        }
        Expr::Parenthesized(v) if v.len() == 1 => fixed_columns(&v[0], bases, fixed),
        _ => {}
    }
}
fn singleton_aggregate(expr: &Expr) -> bool {
    // Narrow honest first version. Arbitrary aggregate expressions/ordered
    // aggregates need a separate proof; especially floating SUM order.
    match expr {
        Expr::FunctionCallStar { name, filter_over } => {
            name.as_str().eq_ignore_ascii_case("count") && filter_over.over_clause.is_none()
        }
        Expr::FunctionCall {
            name,
            args,
            order_by,
            within_group,
            filter_over,
            ..
        } => {
            ["count", "min", "max"]
                .iter()
                .any(|n| name.as_str().eq_ignore_ascii_case(n))
                && args.len() == 1
                && order_by.is_empty()
                && within_group.is_empty()
                && filter_over.over_clause.is_none()
                && parts(&args[0]).is_some()
        }
        _ => false,
    }
}
/// Reject every window/ordered aggregate anywhere, even if an ORDER BY key
/// appears beside it. Unsupported output expressions never earn a singleton.
fn expression_shape(expr: &Expr) -> Result<()> {
    // Existing walker exhaustively handles subqueries in all expression
    // positions. Non-order-sensitive scalar functions remain engine gated.
    super::turso_ast_rules::check_expr_selects(expr, &|s| {
        let proof = prove_select(s)?;
        if !proof.singleton
            && !s
                .limit
                .as_ref()
                .is_some_and(|l| matches!(&*l.expr, Expr::Literal(Literal::Numeric(n)) if n == "1"))
        {
            return Err(reject("scalar subquery must prove a unique key or use a proved ORDER BY ... LIMIT 1 winner"));
        }
        Ok(())
    })?;
    // Walk non-subquery children using the shared AST walker callback is not
    // enough for window functions. A fail-closed function inspection follows.
    fn walk(e: &Expr) -> Result<()> {
        match e {
            Expr::FunctionCall {
                args,
                order_by,
                within_group,
                filter_over,
                ..
            } => {
                if filter_over.over_clause.is_some()
                    || !order_by.is_empty()
                    || !within_group.is_empty()
                {
                    return Err(reject("windows and ordered aggregates are unsupported"));
                }
                for a in args {
                    walk(a)?;
                }
                if let Some(f) = &filter_over.filter_clause {
                    walk(f)?;
                }
            }
            Expr::FunctionCallStar { filter_over, .. } => {
                if filter_over.over_clause.is_some() {
                    return Err(reject("windows are unsupported"));
                }
                if let Some(f) = &filter_over.filter_clause {
                    walk(f)?;
                }
            }
            Expr::Binary(a, _, b) => {
                walk(a)?;
                walk(b)?;
            }
            Expr::Unary(_, a)
            | Expr::IsNull(a)
            | Expr::NotNull(a)
            | Expr::Collate(a, _)
            | Expr::Cast { expr: a, .. } => walk(a)?,
            Expr::Parenthesized(v) => {
                for a in v {
                    walk(a)?;
                }
            }
            Expr::Between {
                lhs, start, end, ..
            } => {
                walk(lhs)?;
                walk(start)?;
                walk(end)?;
            }
            Expr::InList { lhs, rhs, .. } => {
                walk(lhs)?;
                for a in rhs {
                    walk(a)?;
                }
            }
            Expr::Like {
                lhs, rhs, escape, ..
            } => {
                walk(lhs)?;
                walk(rhs)?;
                if let Some(a) = escape {
                    walk(a)?;
                }
            }
            Expr::Case {
                base,
                when_then_pairs,
                else_expr,
            } => {
                if let Some(a) = base {
                    walk(a)?;
                }
                for (a, b) in when_then_pairs {
                    walk(a)?;
                    walk(b)?;
                }
                if let Some(a) = else_expr {
                    walk(a)?;
                }
            }
            Expr::InSelect { lhs, .. } => walk(lhs)?,
            Expr::Id(_)
            | Expr::Name(_)
            | Expr::Qualified(..)
            | Expr::Literal(_)
            | Expr::Variable(_)
            | Expr::Subquery(_)
            | Expr::Exists(_) => {}
            _ => return Err(reject(
                "unsupported expression shape; project scalar columns or audited scalar subqueries",
            )),
        }
        Ok(())
    }
    walk(expr)
}
fn prove_select(select: &Select) -> Result<OrderProof> {
    if select.with.is_some() || !select.body.compounds.is_empty() {
        return Err(reject(
            "CTEs and compound queries are unsupported; flatten or aggregate",
        ));
    }
    let OneSelect::Select {
        columns,
        from,
        where_clause,
        group_by,
        window_clause,
        distinctness,
    } = &select.body.select
    else {
        return Err(reject("VALUES is unsupported; use a scalar SELECT"));
    };
    if distinctness.is_some() || group_by.is_some() || !window_clause.is_empty() {
        return Err(reject(
            "DISTINCT, grouping and windows need a separate uniqueness proof",
        ));
    }
    let mut bases = Vec::new();
    if let Some(from) = from {
        bases.push(base(&from.select)?);
        for join in &from.joins {
            if let JoinOperator::TypedJoin(Some(kind)) = join.operator {
                if kind.intersects(
                    JoinType::LEFT | JoinType::RIGHT | JoinType::OUTER | JoinType::NATURAL,
                ) {
                    return Err(reject("outer/NATURAL joins need a separate NULL/multiplicity proof; use explicit inner JOIN ON"));
                }
            }
            bases.push(base(&join.table)?);
            if let Some(turso_parser::ast::JoinConstraint::On(expr)) = &join.constraint {
                expression_shape(expr)?;
            }
        }
    }
    let mut qualifiers = BTreeSet::new();
    if bases.iter().any(|b| !qualifiers.insert(&b.qualifier)) {
        return Err(reject("each table occurrence needs a distinct alias"));
    }
    let mut aliases = BTreeMap::<String, Vec<&Expr>>::new();
    for output in columns {
        let ResultColumn::Expr(expr, alias) = output else {
            return Err(reject("explicit output columns required"));
        };
        expression_shape(expr)?;
        let label = alias
            .as_ref()
            .map(|a| a.name().as_str().to_ascii_lowercase())
            .or_else(|| parts(expr).map(|(_, name)| name));
        if let Some(label) = label {
            aliases.entry(label).or_default().push(expr);
        }
    }
    if let Some(expr) = where_clause {
        expression_shape(expr)?;
    }
    for term in &select.order_by {
        expression_shape(&term.expr)?;
    }
    if let Some(limit) = &select.limit {
        expression_shape(&limit.expr)?;
        if let Some(offset) = &limit.offset {
            expression_shape(offset)?;
        }
    }
    let mut fixed = BTreeSet::new();
    if let Some(expr) = where_clause {
        fixed_columns(expr, &bases, &mut fixed);
    }
    let singleton = bases.is_empty()
        || columns
            .iter()
            .all(|c| matches!(c, ResultColumn::Expr(e,_) if singleton_aggregate(e)))
        || bases.iter().enumerate().all(|(i, b)| {
            b.keys
                .iter()
                .any(|key| key.iter().all(|k| fixed.contains(&(i, k.to_string()))))
        });
    if singleton {
        return Ok(OrderProof {
            version: RULE_ORDER_PROOF_VERSION,
            profile_id: QuerySqlProfile::SqliteLocal.contract().id.into(),
            profile_revision: QuerySqlProfile::SqliteLocal.contract().revision,
            relations: vec![],
            singleton: true,
            ordered_keys: vec![],
        });
    }
    let mut ordered = BTreeSet::new();
    for term in &select.order_by {
        let mut expr = normalized(&term.expr);
        // SQLite ORDER BY resolves output aliases before base columns. Resolve
        // exactly once: SELECT id AS x, name AS id ORDER BY id isn't the key.
        if let Expr::Id(name) | Expr::Name(name) = expr {
            if let Some(targets) = aliases.get(&name.as_str().to_ascii_lowercase()) {
                if targets.len() != 1 {
                    return Err(reject("ambiguous ORDER BY output alias"));
                }
                expr = targets[0];
            }
        } else if let Expr::Literal(Literal::Numeric(n)) = expr {
            let position = n
                .parse::<usize>()
                .map_err(|_| reject("invalid ORDER BY ordinal"))?;
            let Some(ResultColumn::Expr(target, _)) =
                position.checked_sub(1).and_then(|i| columns.get(i))
            else {
                return Err(reject("ORDER BY ordinal is outside output columns"));
            };
            expr = target;
        }
        // No transformed/collated key may establish uniqueness. Even explicit
        // NOCASE can collapse distinct binary ids; unrelated terms may use it.
        if let Some(key) = column(expr, &bases) {
            ordered.insert(key);
        }
    }
    let mut keys = Vec::new();
    for (i, b) in bases.iter().enumerate() {
        let key = b
            .keys
            .iter()
            .find(|key| key.iter().all(|k| ordered.contains(&(i, k.to_string()))))
            .ok_or_else(|| {
                reject(format!(
                    "ORDER BY lacks a unique tie-breaker for '{}' (alias '{}'); add {}.{}",
                    b.name,
                    b.qualifier,
                    b.qualifier,
                    b.keys[0].join(", ")
                ))
            })?;
        keys.extend(key.iter().map(|k| format!("{}.{}", b.qualifier, k)));
    }
    Ok(OrderProof {
        version: RULE_ORDER_PROOF_VERSION,
        profile_id: QuerySqlProfile::SqliteLocal.contract().id.into(),
        profile_revision: QuerySqlProfile::SqliteLocal.contract().revision,
        relations: vec![],
        singleton: false,
        ordered_keys: keys,
    })
}
/// Admission wrapper: strict SQLite/public-view prepare and authorizer-derived
/// eligibility first, then the stronger order proof. Returned evidence is
/// derived from actual SQL, never a caller-supplied AST or catalog.
pub fn prove_rule_input_order(sql: &str) -> Result<OrderProof> {
    let readset = super::sql::extract_rule_input_dependencies(sql)?;
    let select = super::turso_ast_rules::parse_rule_select(sql)?;
    let mut proof = prove_select(&select)?;
    proof.relations = readset.relations;
    Ok(proof)
}

/// New-contract SQL admission only, never historical replay. Integer-text
/// conversions must originate from the canonical facet value column; neither
/// REAL value_num nor a truncating CAST earns a canonical-money declaration.
pub fn validate_input_sql(input: &super::rule_install::RuleInputDecl) -> Result<OrderProof> {
    let proof = prove_rule_input_order(&input.sql)?;
    let Some(contract) = &input.contract else {
        return Ok(proof);
    };
    let labels = super::sql::validated_output_columns(&input.sql)?;
    super::rule_shape::validate_output_labels(input, &labels)?;
    let select = super::turso_ast_rules::parse_rule_select(&input.sql)?;
    let OneSelect::Select { columns, from, .. } = &select.body.select else {
        return Err(reject("scalar projections require SELECT"));
    };
    let mut bases = Vec::new();
    if let Some(from) = from {
        bases.push(base(&from.select)?);
        for join in &from.joins {
            bases.push(base(&join.table)?);
        }
    }
    fn facet_text(expr: &Expr, bases: &[Base]) -> bool {
        if let Some((i, name)) = column(expr, bases) {
            return bases[i].name == "facet_values" && name == "value";
        }
        if let Expr::Subquery(select) = expr {
            let OneSelect::Select {
                columns,
                from: Some(from),
                ..
            } = &select.body.select
            else {
                return false;
            };
            if !from.joins.is_empty() || columns.len() != 1 {
                return false;
            }
            let Ok(source) = base(&from.select) else {
                return false;
            };
            if let ResultColumn::Expr(expr, _) = &columns[0] {
                return facet_text(expr, &[source]);
            }
        }
        false
    }
    for field in contract
        .fields()
        .iter()
        .filter(|f| f.canonical_integer_text)
    {
        let position = labels
            .iter()
            .position(|label| label == &field.name)
            .ok_or_else(|| reject("canonical integer output label missing"))?;
        let Some(ResultColumn::Expr(expr, _)) = columns.get(position) else {
            return Err(reject("canonical integer output expression missing"));
        };
        if !facet_text(expr, &bases) {
            return Err(reject(format!("integer field '{}' must project facet_values.value directly or through a proved scalar subquery; do not CAST/truncate value_num", field.name)));
        }
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Use frozen storage DDL and the exact current caller-view SQL, not the
    // synthetic prepare catalog. Visibility membership is explicit test setup.
    fn caller_views() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TEMP TABLE _query_sql_visible_ids(id TEXT PRIMARY KEY);")
            .unwrap();
        for name in ["records", "links", "facet_values"] {
            let prefix = format!("CREATE TABLE {name} (");
            let ddl = crate::schema::ddl::DDL_STATEMENTS
                .iter()
                .find(|s| s.starts_with(&prefix))
                .unwrap();
            conn.execute_batch(ddl).unwrap();
            let source = include_str!("sql.rs");
            let start = source
                .find(&format!("CREATE TEMP VIEW IF NOT EXISTS {name} AS"))
                .unwrap();
            let end = source[start..].find(';').unwrap() + start + 1;
            conn.execute_batch(&source[start..end]).unwrap();
        }
        conn
    }
    #[test]
    fn parenthesized_aliases_cannot_forge_winner_keys() {
        for order in ["id", "(id)", "((id))", "(((id)))"] {
            for suffix in ["", " LIMIT 1"] {
                let sql = format!(
                    "SELECT r.id AS real_id,r.name AS id FROM records r ORDER BY {order}{suffix}"
                );
                assert!(prove_rule_input_order(&sql).is_err(), "{sql}");
                let nested = format!("SELECT r.id,(SELECT name AS id FROM records ORDER BY {order} LIMIT 1) AS chosen FROM records r ORDER BY r.id");
                assert!(prove_rule_input_order(&nested).is_err(), "{nested}");
            }
        }
        for sql in [
            "SELECT id AS x,name AS id FROM records ORDER BY ((x)) LIMIT 1",
            "SELECT id AS name FROM records ORDER BY ((name))",
            "SELECT name AS id,r.id AS real_id FROM records r ORDER BY ((r.id)) LIMIT 1",
            "SELECT name,id FROM records ORDER BY ((2)) LIMIT 1",
        ] {
            assert!(prove_rule_input_order(sql).is_ok(), "{sql}");
        }
        for sql in [
            "SELECT name AS x,id AS x FROM records ORDER BY ((x))",
            "SELECT a.id FROM records a JOIN records b ON a.home_id=b.id ORDER BY ((id))",
        ] {
            assert!(prove_rule_input_order(sql).is_err(), "{sql}");
        }
        // Actual SQLite output-alias precedence: a tied name changes LIMIT 1
        // with insertion order, while the qualified base key stays stable.
        for ids in [["b", "a"], ["a", "b"]] {
            let conn = caller_views();
            for id in ids {
                conn.execute(
                    "INSERT INTO main.records(id,type,name) VALUES(?1,'WorkItem','same')",
                    [id],
                )
                .unwrap();
                conn.execute("INSERT INTO temp._query_sql_visible_ids VALUES(?1)", [id])
                    .unwrap();
            }
            let bad = "SELECT r.id AS real_id,r.name AS id FROM records r ORDER BY ((id)) LIMIT 1";
            assert_eq!(
                conn.query_row(bad, [], |r| r.get::<_, String>(0)).unwrap(),
                ids[0]
            );
            let good =
                "SELECT r.id AS real_id,r.name AS id FROM records r ORDER BY ((r.id)) LIMIT 1";
            prove_rule_input_order(good).unwrap();
            assert_eq!(
                conn.query_row(good, [], |r| r.get::<_, String>(0)).unwrap(),
                "a"
            );
        }
    }
    #[test]
    fn caller_view_null_link_ids_require_nonnull_composites() {
        let conn = caller_views();
        conn.execute_batch("INSERT INTO main.records(id,type) VALUES('a','WorkItem'),('b','WorkItem');
            INSERT INTO temp._query_sql_visible_ids VALUES('a'),('b');
            INSERT INTO main.links(id,source_id,target_id,relationship) VALUES(NULL,'a','b','x'),(NULL,'a','b','y');
            INSERT INTO main.facet_values(id,record_id,key,value) VALUES(NULL,'a','x','1'),(NULL,'a','y','2');
            INSERT INTO main.records(id,type) VALUES(NULL,'WorkItem'),(NULL,'WorkItem');").unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM links WHERE id IS NULL", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM facet_values WHERE id IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM records WHERE id IS NULL", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        for sql in [
            "SELECT id FROM links ORDER BY id LIMIT 1",
            "SELECT id FROM facet_values ORDER BY id LIMIT 1",
        ] {
            assert!(prove_rule_input_order(sql).is_err(), "{sql}");
        }
        for sql in [
            "SELECT id FROM links ORDER BY source_id,target_id,relationship",
            "SELECT id FROM facet_values ORDER BY record_id,key",
        ] {
            prove_rule_input_order(sql).unwrap();
            assert_eq!(
                conn.prepare(sql)
                    .unwrap()
                    .query_map([], |_| Ok(()))
                    .unwrap()
                    .count(),
                2
            );
        }
    }
    #[test]
    fn key_evidence_pins_relation_profile_and_proof_versions() {
        use native_query_contract::rule_contract::rule_stable_unique_keys as keys;
        let identity = "native.query-sql.links";
        assert_eq!(
            keys(identity, 1, "sqlite-local", 1, RULE_ORDER_PROOF_VERSION),
            Some(&[&["source_id", "target_id", "relationship"][..]][..])
        );
        for (id, semantic, profile, revision, proof) in [
            (identity, 2, "sqlite-local", 1, RULE_ORDER_PROOF_VERSION),
            (identity, 1, "other", 1, RULE_ORDER_PROOF_VERSION),
            (identity, 1, "sqlite-local", 2, RULE_ORDER_PROOF_VERSION),
            (identity, 1, "sqlite-local", 1, 1),
            ("unreviewed", 1, "sqlite-local", 1, RULE_ORDER_PROOF_VERSION),
        ] {
            assert!(keys(id, semantic, profile, revision, proof).is_none());
        }
        let proof = prove_rule_input_order(
            "SELECT id FROM links ORDER BY source_id,target_id,relationship",
        )
        .unwrap();
        assert_eq!(proof.version(), RULE_ORDER_PROOF_VERSION);
        assert_eq!(proof.profile_id, "sqlite-local");
        assert_eq!(proof.profile_revision, 1);
        assert_eq!(proof.relations[0].identity, identity);
        assert_eq!(proof.relations[0].semantic_version, 1);
    }
    #[test]
    fn integer_money_projection_requires_original_facet_text() {
        use super::super::rule_shape::{RuleInputContract, ScalarField, ScalarType};
        let mut input = super::super::rule_install::RuleInputDecl {
            name: "money".into(), cardinality: super::super::rule_install::RuleCardinality::One,
            required_fields: vec!["amount".into()], parameters: vec![],
            sql: "SELECT (SELECT value FROM facet_values WHERE record_id=r.id AND key='amount') AS amount FROM records r WHERE r.id='deal'".into(),
            contract: Some(RuleInputContract::ScalarRowsV1 { fields: vec![ScalarField { name: "amount".into(), scalar_type: ScalarType::Int, nullable: true, canonical_integer_text: true }], required_when: None }),
        };
        assert!(validate_input_sql(&input).is_ok());
        for expression in [
            "value_num",
            "CAST(value_num AS INTEGER)",
            "CAST(CAST(value_num AS INTEGER) AS TEXT)",
        ] {
            input.sql = format!("SELECT (SELECT {expression} FROM facet_values WHERE record_id=r.id AND key='amount') AS amount FROM records r WHERE r.id='deal'");
            assert!(validate_input_sql(&input).is_err(), "{expression}");
        }
    }
    #[test]
    fn orders_ties_nulls_aliases_and_ordinals_by_audited_keys() {
        for sql in [
            "SELECT id, name FROM records ORDER BY name, id",
            "SELECT r.id AS rid, r.summary AS s FROM records r ORDER BY s DESC NULLS FIRST, rid",
            "SELECT name, id AS rid FROM records ORDER BY 1, 2",
            "SELECT id AS name FROM records ORDER BY name",
            "SELECT id FROM records WHERE id=?1",
            "SELECT count(*) AS n FROM records",
            "SELECT id FROM records ORDER BY id LIMIT 1 OFFSET 2",
        ] {
            assert!(
                prove_rule_input_order(sql).is_ok(),
                "{sql}: {:?}",
                prove_rule_input_order(sql)
            );
        }
        for sql in [
            "SELECT id, name FROM records ORDER BY name",
            "SELECT name, id AS name FROM records ORDER BY name",
            "SELECT id AS rid, name AS id FROM records ORDER BY id",
            "SELECT id FROM records ORDER BY id COLLATE NOCASE",
            "SELECT id FROM records ORDER BY lower(id)",
            "SELECT id FROM records ORDER BY id || ''",
            "SELECT id FROM records WHERE id=id",
            "SELECT id FROM records WHERE id=?1 OR id=?2",
            "SELECT id FROM records WHERE id COLLATE NOCASE=?1",
        ] {
            assert!(prove_rule_input_order(sql).is_err(), "{sql}");
        }
    }
    #[test]
    fn every_join_occurrence_needs_a_key() {
        assert!(prove_rule_input_order(
            "SELECT r.id FROM records r JOIN links l ON l.source_id=r.id ORDER BY r.id"
        )
        .is_err());
        assert!(prove_rule_input_order(
            "SELECT r.id FROM records r JOIN links l ON l.source_id=r.id ORDER BY r.id,l.id"
        )
        .is_err());
        assert!(prove_rule_input_order("SELECT r.id FROM records r JOIN links l ON l.source_id=r.id ORDER BY r.id,l.source_id,l.target_id,l.relationship").is_ok());
        assert!(prove_rule_input_order(
            "SELECT a.id FROM records a JOIN records b ON a.home_id=b.id ORDER BY a.id"
        )
        .is_err());
        assert!(prove_rule_input_order(
            "SELECT a.id FROM records a JOIN records b ON a.home_id=b.id ORDER BY a.id,b.id"
        )
        .is_ok());
    }
    #[test]
    fn full_deal_sql_proves_policy_and_refuses_approval_ties() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../crates/cel-subset/tests/corpus/policy/m1/full-deal.cel.json"
        ))
        .unwrap();
        for input in fixture["inputs"].as_array().unwrap() {
            let sql = input["sql"].as_str().unwrap();
            if input["name"] == "approvals" {
                assert!(prove_rule_input_order(sql).is_err());
                assert!(prove_rule_input_order(&format!(
                    "{sql}, l.source_id,l.target_id,l.relationship"
                ))
                .is_ok());
            } else {
                assert!(
                    prove_rule_input_order(sql).is_ok(),
                    "{sql}: {:?}",
                    prove_rule_input_order(sql)
                );
            }
        }
    }
    #[test]
    fn rewritten_deal_desk_joins_have_canonical_money_and_total_order() {
        use super::super::{
            rule_install::{RuleCardinality, RuleInputDecl},
            rule_shape::{RuleInputContract, ScalarField, ScalarType},
        };
        let sqls = include_str!("fixtures/rule_v1_deal_desk.sql")
            .split(';')
            .filter(|s| !s.trim().is_empty())
            .collect::<Vec<_>>();
        assert_eq!(sqls.len(), 3);
        for (sql, names) in sqls.into_iter().zip([
            vec!["id", "discount_bp"],
            vec![
                "id",
                "base_cap",
                "appr_cap",
                "effective_from_ms",
                "effective_to_ms",
            ],
            vec![
                "id",
                "source_id",
                "target_id",
                "relationship",
                "cap_bp",
                "expires_at_ms",
            ],
        ]) {
            let fields = names
                .into_iter()
                .map(|name| {
                    let integer =
                        !matches!(name, "id" | "source_id" | "target_id" | "relationship");
                    ScalarField {
                        name: name.into(),
                        nullable: false,
                        scalar_type: if integer {
                            ScalarType::Int
                        } else {
                            ScalarType::String
                        },
                        canonical_integer_text: integer,
                    }
                })
                .collect();
            let input = RuleInputDecl {
                name: "example".into(),
                sql: sql.into(),
                cardinality: RuleCardinality::Many,
                required_fields: vec![],
                parameters: vec![],
                contract: Some(RuleInputContract::ScalarRowsV1 {
                    fields,
                    required_when: None,
                }),
            };
            assert!(
                validate_input_sql(&input).is_ok(),
                "{sql}: {:?}",
                validate_input_sql(&input)
            );
        }
    }
    #[test]
    fn unsupported_shapes_and_unbounded_scalar_winners_refuse_actionably() {
        for sql in [
            "WITH x AS (SELECT id FROM records) SELECT id FROM x ORDER BY id",
            "SELECT id FROM records UNION ALL SELECT id FROM records ORDER BY id",
            "SELECT DISTINCT id FROM records ORDER BY id",
            "SELECT name,count(*) FROM records GROUP BY name ORDER BY name",
            "SELECT r.id FROM records r LEFT JOIN links l ON l.source_id=r.id ORDER BY r.id,l.id",
            "SELECT id,row_number() OVER (ORDER BY id) FROM records ORDER BY id",
            "SELECT r.id, (SELECT value FROM facet_values WHERE record_id=r.id) AS v FROM records r ORDER BY r.id",
            "SELECT id FROM (SELECT id FROM records) ORDER BY id",
        ] { assert!(prove_rule_input_order(sql).is_err(),"{sql}"); }
        let err = prove_rule_input_order("SELECT id FROM records ORDER BY name")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tie-breaker") && err.contains("ORDER BY"),
            "{err}"
        );
    }
    #[test]
    fn sqlite_rows_with_tied_null_sort_values_match_key_order() {
        // The proof does not inspect these rows; execute solely to verify the
        // shared AST alias/null resolution agrees with SQLite on a real tie.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE records(id TEXT PRIMARY KEY,name TEXT); INSERT INTO records VALUES('c',NULL),('b','same'),('a','same'),('d',NULL);").unwrap();
        let sql = "SELECT id AS rid,name AS label FROM records ORDER BY label NULLS FIRST,rid";
        prove_rule_input_order(sql).unwrap();
        let mut stmt = conn.prepare(sql).unwrap();
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["c", "d", "a", "b"]);
    }
}
