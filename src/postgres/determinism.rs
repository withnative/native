//! Postgres-only determinism normalisation (E1 M2 I3, AST design).
//!
//! SQLite/Turso already order NULLs first on ASC/default, last on DESC,
//! and yield NULL on division by zero, so only Postgres is rewritten, and
//! only via the pinned `pg_query` AST + deparse. Three idempotent rules:
//! bare `SortBy` gets NULLS FIRST (DESC: NULLS LAST; USING untouched),
//! `/`/`%` right operands become `NULLIF(rhs, 0)` in pg's own
//! `A_Expr{kind: Nullif, name: ["="]}` shape (a hand-built FuncCall
//! SIGABRTs deparse), and every case-sensitive LIKE spelling becomes its
//! ILIKE one (I4: LIKE is case-insensitive on every engine;
//! SQLite/Turso LIKE already folds ASCII case). That is `AEXPR_LIKE` to
//! pg's own `AEXPR_ILIKE` shape, plus a name-only rename for the shapes
//! pg itself spells as a direct operator: bare `~~`/`!~~` (including
//! `OPERATOR(~~)`), `LIKE`/`NOT LIKE` `ANY`/`ALL` over arrays
//! (`AexprOpAny`/`AexprOpAll`), and `ANY`/`ALL` subquery `SubLink`s.
//! `validate()` runs `walk_ast` first, which visits
//! every node and fails closed outside `SAFE_NODE_VARIANTS`, so the
//! mutator only recurses those variants' children.

use pg_query::protobuf::a_const::Val;
use pg_query::protobuf::node::Node as NodeVariant;
use pg_query::protobuf::{
    AConst, AExpr, AExprKind, Integer, Node, SelectStmt, SortByDir, SortByNulls,
    String as PgString, WindowDef,
};

use crate::query::sql_contract::{self, QuerySqlErrorCategory};

fn reject(detail: impl AsRef<str>) -> crate::Error {
    sql_contract::categorized_error(QuerySqlErrorCategory::Engine, detail)
}

/// Normalise determinism on an already-validated parse tree, in place.
/// Returns whether anything changed, so callers can keep the input text
/// byte-identical when there was nothing to normalise.
pub fn normalise(tree: &mut pg_query::protobuf::ParseResult) -> crate::Result<bool> {
    let mut changed = false;
    for raw in &mut tree.stmts {
        if let Some(root) = raw.stmt.as_mut() {
            mutate(root, &mut changed);
        }
    }
    Ok(changed)
}

/// Deparse a normalised tree back to SQL for execution.
pub fn deparse(tree: &pg_query::protobuf::ParseResult) -> crate::Result<String> {
    pg_query::deparse(tree).map_err(|error| reject(error.to_string()))
}

/// Variants with expression children the mutator recurses into.
#[cfg(test)]
pub const MUTATOR_HANDLED: &[&str] = &[
    "SortBy",
    "AExpr",
    "FuncCall",
    "WindowDef",
    "SelectStmt",
    "ResTarget",
    "TypeCast",
    "JoinExpr",
    "RangeSubselect",
    "WithClause",
    "CommonTableExpr",
    "BoolExpr",
    "NullTest",
    "BooleanTest",
    "CaseExpr",
    "CaseWhen",
    "CoalesceExpr",
    "MinMaxExpr",
    "SubLink",
    "RowExpr",
    "ArrayExpr",
    "AArrayExpr",
    "GroupingSet",
    "List",
];
/// Allowlist variants holding no expressions.
#[cfg(test)]
pub const MUTATOR_LEAF: &[&str] = &[
    "Alias",
    "RangeVar",
    "ColumnRef",
    "ParamRef",
    "AStar",
    "Integer",
    "Float",
    "Boolean",
    "String",
    "AConst",
    "CaseTestExpr",
    "TypeName",
];

fn nodes(children: &mut [Node], changed: &mut bool) {
    for child in children.iter_mut() {
        mutate(child, changed);
    }
}

fn maybe(child: &mut Option<Box<Node>>, changed: &mut bool) {
    if let Some(node) = child {
        mutate(node, changed);
    }
}

fn mutate(node: &mut Node, changed: &mut bool) {
    if let Some(inner) = node.node.as_mut() {
        mutate_variant(inner, changed);
    }
}

fn mutate_variant(inner: &mut NodeVariant, changed: &mut bool) {
    match inner {
        NodeVariant::SortBy(sort) => {
            if (sort.sortby_nulls == SortByNulls::SortbyNullsDefault as i32
                || sort.sortby_nulls == SortByNulls::Undefined as i32)
                && sort.use_op.is_empty()
                && sort.sortby_dir != SortByDir::SortbyUsing as i32
            {
                sort.sortby_nulls = if sort.sortby_dir == SortByDir::SortbyDesc as i32 {
                    SortByNulls::SortbyNullsLast as i32
                } else {
                    SortByNulls::SortbyNullsFirst as i32
                };
                *changed = true;
            }
            maybe(&mut sort.node, changed);
        }
        NodeVariant::AExpr(expr) => {
            if expr.kind == AExprKind::AexprOp as i32
                && matches!(op_name(expr).as_deref(), Some("/" | "%"))
            {
                if let Some(rhs) = expr.rexpr.take() {
                    expr.rexpr = Some(if is_nullif(&rhs) {
                        rhs
                    } else {
                        *changed = true;
                        nullif_wrap(rhs)
                    });
                }
            }
            // I4: LIKE is case-insensitive on every engine. SQLite/Turso
            // LIKE already folds ASCII case; Postgres LIKE does not, so
            // rewrite AEXPR_LIKE to pg's own AEXPR_ILIKE shape (kind plus
            // operator: `~~` to `~~*`, `!~~` to `!~~*`). Operands,
            // locations and any ESCAPE wrapper stay byte-identical, and
            // anything already ILIKE (or SIMILAR) is untouched.
            let binary =
                binary_operand(expr.lexpr.as_deref()) || binary_operand(expr.rexpr.as_deref());
            if binary {
                // bytea has `~~` but no `~~*`, and bytes have no case: a
                // binary LIKE stays as written (review R1).
            } else if expr.kind == AExprKind::AexprLike as i32 {
                if rename_like_operator(&mut expr.name) {
                    expr.kind = AExprKind::AexprIlike as i32;
                    *changed = true;
                }
            } else if expr.kind == AExprKind::AexprOp as i32
                || expr.kind == AExprKind::AexprOpAny as i32
                || expr.kind == AExprKind::AexprOpAll as i32
            {
                // F1/F2: bare `~~`/`!~~` (including `OPERATOR(~~)`, which
                // parses to the same single-element name) and LIKE ANY/ALL
                // over arrays spell the operator directly; pg itself uses
                // AexprOp(/Any/All) there, so only the name is renamed to
                // the ILIKE spelling and the kind stays put.
                if rename_like_operator(&mut expr.name) {
                    *changed = true;
                }
            }
            maybe(&mut expr.lexpr, changed);
            maybe(&mut expr.rexpr, changed);
        }
        NodeVariant::FuncCall(call) => {
            lower_regexp_call(call, changed);
            nodes(&mut call.args, changed);
            nodes(&mut call.agg_order, changed);
            maybe(&mut call.agg_filter, changed);
            if let Some(over) = call.over.as_mut() {
                mutate_windowdef(over, changed);
            }
        }
        NodeVariant::WindowDef(window) => mutate_windowdef(window, changed),
        NodeVariant::SelectStmt(select) => mutate_select(select, changed),
        NodeVariant::ResTarget(target) => maybe(&mut target.val, changed),
        NodeVariant::TypeCast(cast) => maybe(&mut cast.arg, changed),
        NodeVariant::JoinExpr(join) => {
            maybe(&mut join.larg, changed);
            maybe(&mut join.rarg, changed);
            maybe(&mut join.quals, changed);
        }
        NodeVariant::RangeSubselect(sub) => maybe(&mut sub.subquery, changed),
        NodeVariant::WithClause(with) => nodes(&mut with.ctes, changed),
        NodeVariant::CommonTableExpr(cte) => maybe(&mut cte.ctequery, changed),
        NodeVariant::BoolExpr(expr) => nodes(&mut expr.args, changed),
        NodeVariant::CaseExpr(case) => {
            maybe(&mut case.arg, changed);
            nodes(&mut case.args, changed);
            maybe(&mut case.defresult, changed);
        }
        NodeVariant::CoalesceExpr(expr) => nodes(&mut expr.args, changed),
        NodeVariant::MinMaxExpr(expr) => nodes(&mut expr.args, changed),
        NodeVariant::SubLink(link) => {
            // F2: `LIKE ANY (SELECT …)` spells the operator on the
            // sublink; rename it exactly like the direct operators.
            if !binary_operand(link.testexpr.as_deref())
                && rename_like_operator(&mut link.oper_name)
            {
                *changed = true;
            }
            maybe(&mut link.testexpr, changed);
            maybe(&mut link.subselect, changed);
        }
        NodeVariant::RowExpr(row) => nodes(&mut row.args, changed),
        NodeVariant::ArrayExpr(array) => nodes(&mut array.elements, changed),
        NodeVariant::AArrayExpr(array) => nodes(&mut array.elements, changed),
        NodeVariant::GroupingSet(set) => nodes(&mut set.content, changed),
        NodeVariant::List(list) => nodes(&mut list.items, changed),
        // Leaves and single-arg wrappers handled inline below; everything
        // else (Alias, RangeVar, ColumnRef, ParamRef, AStar, Integer, Float,
        // Boolean, String, AConst, CaseTestExpr, TypeName) holds no
        // expressions. Allowlist drift is caught by `mutator_covers_allowlist`.
        NodeVariant::NullTest(test) => maybe(&mut test.arg, changed),
        NodeVariant::BooleanTest(test) => maybe(&mut test.arg, changed),
        NodeVariant::CaseWhen(when) => {
            maybe(&mut when.expr, changed);
            maybe(&mut when.result, changed);
        }
        _ => {}
    }
}

fn mutate_select(select: &mut SelectStmt, changed: &mut bool) {
    // DISTINCT ON expressions divide and sort like any other: walk them.
    nodes(&mut select.distinct_clause, changed);
    nodes(&mut select.target_list, changed);
    nodes(&mut select.from_clause, changed);
    maybe(&mut select.where_clause, changed);
    nodes(&mut select.group_clause, changed);
    maybe(&mut select.having_clause, changed);
    nodes(&mut select.window_clause, changed);
    nodes(&mut select.values_lists, changed);
    nodes(&mut select.sort_clause, changed);
    maybe(&mut select.limit_offset, changed);
    maybe(&mut select.limit_count, changed);
    if let Some(with) = select.with_clause.as_mut() {
        nodes(&mut with.ctes, changed);
    }
    for side in [&mut select.larg, &mut select.rarg].into_iter().flatten() {
        mutate_select(side, changed);
    }
}

fn mutate_windowdef(window: &mut WindowDef, changed: &mut bool) {
    nodes(&mut window.partition_clause, changed);
    nodes(&mut window.order_clause, changed);
    maybe(&mut window.start_offset, changed);
    maybe(&mut window.end_offset, changed);
}

fn op_name(expr: &AExpr) -> Option<String> {
    if expr.name.len() != 1 {
        return None;
    }
    match &expr.name[0].node {
        Some(NodeVariant::String(name)) => Some(name.sval.clone()),
        _ => None,
    }
}

/// Rename a single-element LIKE operator to its ILIKE spelling (`~~` to
/// `~~*`, `!~~` to `!~~*`). Anything else — already-ILIKE, SIMILAR's
/// `~`/`!~`, other operators, and multi-element qualified
/// `OPERATOR(pg_catalog.~~)` names (which the validator rejects) — stays
/// untouched.
fn rename_like_operator(name: &mut [Node]) -> bool {
    if name.len() != 1 {
        return false;
    }
    if let Some(NodeVariant::String(string)) = name[0].node.as_mut() {
        let renamed = match string.sval.as_str() {
            "~~" => "~~*",
            "!~~" => "!~~*",
            _ => return false,
        };
        string.sval = renamed.to_string();
        return true;
    }
    false
}

/// E1 M3: lower portable `regexp(pattern, haystack)` to Postgres's
/// Oracle-compat `regexp_like(haystack, pattern)` (Postgres 16+): same
/// boolean result, same NULL on NULL input, statement error on invalid
/// patterns (matching SQLite; Turso yields NULL there — documented in the
/// classifier and pinned by engine-specific tests, not the shared corpus).
/// Only the bare two-argument form with no window or aggregation is
/// rewritten — the shape the validator admits. Qualified names, wrong
/// arity, and windowed/aggregated forms fail closed for Postgres to reject.
fn lower_regexp_call(call: &mut pg_query::protobuf::FuncCall, changed: &mut bool) {
    if call.funcname.len() != 1 || call.args.len() != 2 {
        return;
    }
    if call.over.is_some() || call.agg_star || call.agg_distinct {
        return;
    }
    let is_regexp = matches!(
        call.funcname.first().and_then(|node| node.node.as_ref()),
        Some(NodeVariant::String(name)) if name.sval.eq_ignore_ascii_case("regexp")
    );
    if !is_regexp {
        return;
    }
    if let Some(NodeVariant::String(name)) = call
        .funcname
        .first_mut()
        .and_then(|node| node.node.as_mut())
    {
        name.sval = "regexp_like".to_string();
    }
    call.args.swap(0, 1);
    *changed = true;
}

/// True when an operand is visibly binary, so LIKE on it must not become
/// ILIKE: Postgres has `bytea ~~ bytea` but no `~~*` for bytea, and bytes
/// have no case to fold. Types are unknown at parse time, so this
/// recognises what the SQL shows: a cast to `bytea`, or a reference to a
/// column named `bytes` (`blobs.bytes` is the only binary column in the
/// logical catalog). A text column aliased `bytes` therefore keeps
/// case-sensitive LIKE; that is contrived, and documented here.
fn binary_operand(node: Option<&Node>) -> bool {
    match node.and_then(|node| node.node.as_ref()) {
        Some(NodeVariant::TypeCast(cast)) => {
            cast.type_name.as_ref().is_some_and(|type_name| {
                type_name.names.iter().any(|name| {
                    matches!(name.node.as_ref(), Some(NodeVariant::String(s)) if s.sval == "bytea")
                })
            }) || binary_operand(cast.arg.as_deref())
        }
        Some(NodeVariant::ColumnRef(column)) => matches!(
            column.fields.last().and_then(|field| field.node.as_ref()),
            Some(NodeVariant::String(s)) if s.sval.eq_ignore_ascii_case("bytes")
        ),
        _ => false,
    }
}

fn is_nullif(node: &Node) -> bool {
    matches!(node.node.as_ref(),
        Some(NodeVariant::AExpr(expr)) if expr.kind == AExprKind::AexprNullif as i32)
}

/// `NULLIF(rhs, 0)` in Postgres's own A_Expr shape (see module docs).
fn nullif_wrap(rhs: Box<Node>) -> Box<Node> {
    let zero = Node {
        node: Some(NodeVariant::AConst(AConst {
            val: Some(Val::Ival(Integer { ival: 0 })),
            isnull: false,
            location: -1,
        })),
    };
    Box::new(Node {
        node: Some(NodeVariant::AExpr(Box::new(AExpr {
            kind: AExprKind::AexprNullif as i32,
            name: vec![Node {
                node: Some(NodeVariant::String(PgString {
                    sval: "=".to_string(),
                })),
            }],
            lexpr: Some(rhs),
            rexpr: Some(Box::new(zero)),
            location: -1,
        }))),
    })
}
