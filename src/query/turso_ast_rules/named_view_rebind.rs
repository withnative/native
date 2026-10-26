//! Structural rebinding of admitted definition relation tokens. Original implicit
//! table names become aliases so qualified columns and table stars keep meaning.
use super::*;
use std::collections::BTreeMap;
use turso_parser::ast::{As, FrameBound, Name, QualifiedName};

#[allow(dead_code)] // Called by the dormant PR 2b closure builder.
pub(crate) fn rebind_definition(
    sql: &str,
    bindings: &BTreeMap<String, String>,
) -> crate::Result<String> {
    validate_named_view_shape(sql)?;
    let mut ast = parse_select_inner(sql).map_err(|_| reject("view definition must parse"))?;
    select(&mut ast, bindings)?;
    Ok(ast.to_string())
}
#[allow(dead_code)] // Structural visitor used by the dormant rebinding entry point.
fn rename(name: &mut QualifiedName, map: &BTreeMap<String, String>) -> Option<Name> {
    let original = name.name.clone();
    if let Some(replacement) = map.get(&original.as_str().to_ascii_lowercase()) {
        name.name = Name::from_string(replacement);
        Some(original)
    } else {
        None
    }
}
#[allow(dead_code)] // Structural visitor used by the dormant rebinding entry point.
fn table(t: &mut SelectTable, map: &BTreeMap<String, String>) -> crate::Result<()> {
    match t {
        SelectTable::Table(name, alias, _) => {
            if let Some(original) = rename(name, map) {
                if alias.is_none() {
                    *alias = Some(As::As(original));
                }
            }
        }
        SelectTable::TableCall(_, args, _) => {
            for e in args {
                expr(e, map)?;
            }
        }
        SelectTable::Select(s, _) => select(s, map)?,
        SelectTable::Sub(f, _) => from(f, map)?,
    }
    Ok(())
}
#[allow(dead_code)] // Structural visitor used by the dormant rebinding entry point.
fn from(f: &mut FromClause, map: &BTreeMap<String, String>) -> crate::Result<()> {
    table(&mut f.select, map)?;
    for join in &mut f.joins {
        table(&mut join.table, map)?;
        if let Some(JoinConstraint::On(e)) = &mut join.constraint {
            expr(e, map)?;
        }
    }
    Ok(())
}
#[allow(dead_code)] // Structural visitor used by the dormant rebinding entry point.
fn select(s: &mut Select, map: &BTreeMap<String, String>) -> crate::Result<()> {
    if let Some(w) = &mut s.with {
        for c in &mut w.ctes {
            select(&mut c.select, map)?;
        }
    }
    for one in std::iter::once(&mut s.body.select)
        .chain(s.body.compounds.iter_mut().map(|c| &mut c.select))
    {
        match one {
            OneSelect::Values(rows) => {
                for row in rows {
                    for e in row {
                        expr(e, map)?;
                    }
                }
            }
            OneSelect::Select {
                columns,
                from: f,
                where_clause,
                group_by,
                window_clause,
                ..
            } => {
                for c in columns {
                    if let ResultColumn::Expr(e, _) = c {
                        expr(e, map)?;
                    }
                }
                if let Some(f) = f {
                    from(f, map)?;
                }
                if let Some(e) = where_clause {
                    expr(e, map)?;
                }
                if let Some(g) = group_by {
                    for e in &mut g.exprs {
                        expr(e, map)?;
                    }
                    if let Some(e) = &mut g.having {
                        expr(e, map)?;
                    }
                }
                for w in window_clause {
                    window(&mut w.window, map)?;
                }
            }
        }
    }
    for o in &mut s.order_by {
        expr(&mut o.expr, map)?;
    }
    if let Some(l) = &mut s.limit {
        expr(&mut l.expr, map)?;
        if let Some(e) = &mut l.offset {
            expr(e, map)?;
        }
    }
    Ok(())
}
#[allow(dead_code)] // Structural visitor used by the dormant rebinding entry point.
fn window(w: &mut Window, map: &BTreeMap<String, String>) -> crate::Result<()> {
    for e in &mut w.partition_by {
        expr(e, map)?;
    }
    for o in &mut w.order_by {
        expr(&mut o.expr, map)?;
    }
    if let Some(f) = &mut w.frame_clause {
        for b in std::iter::once(&mut f.start).chain(f.end.iter_mut()) {
            match b {
                FrameBound::Following(e) | FrameBound::Preceding(e) => expr(e, map)?,
                _ => {}
            }
        }
    }
    Ok(())
}
#[allow(dead_code)] // Structural visitor used by the dormant rebinding entry point.
fn tail(t: &mut FunctionTail, map: &BTreeMap<String, String>) -> crate::Result<()> {
    if let Some(e) = &mut t.filter_clause {
        expr(e, map)?;
    }
    if let Some(Over::Window(w)) = &mut t.over_clause {
        window(w, map)?;
    }
    Ok(())
}
#[allow(dead_code)] // Structural visitor used by the dormant rebinding entry point.
fn expr(e: &mut Expr, map: &BTreeMap<String, String>) -> crate::Result<()> {
    match e {
        Expr::Between {
            lhs, start, end, ..
        } => {
            expr(lhs, map)?;
            expr(start, map)?;
            expr(end, map)?;
        }
        Expr::Binary(a, _, b) => {
            expr(a, map)?;
            expr(b, map)?;
        }
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => {
            for e in base.iter_mut().chain(else_expr.iter_mut()) {
                expr(e, map)?;
            }
            for (a, b) in when_then_pairs {
                expr(a, map)?;
                expr(b, map)?;
            }
        }
        Expr::Cast { expr: e, .. }
        | Expr::Collate(e, _)
        | Expr::IsNull(e)
        | Expr::NotNull(e)
        | Expr::Unary(_, e)
        | Expr::FieldAccess { base: e, .. } => expr(e, map)?,
        Expr::Exists(s) | Expr::Subquery(s) => select(s, map)?,
        Expr::FunctionCall {
            args,
            order_by,
            within_group,
            filter_over,
            ..
        } => {
            for e in args {
                expr(e, map)?;
            }
            for o in order_by.iter_mut().chain(within_group.iter_mut()) {
                expr(&mut o.expr, map)?;
            }
            tail(filter_over, map)?;
        }
        Expr::FunctionCallStar { filter_over, .. } => tail(filter_over, map)?,
        Expr::InList { lhs, rhs, .. } => {
            expr(lhs, map)?;
            for e in rhs {
                expr(e, map)?;
            }
        }
        Expr::InSelect { lhs, rhs, .. } => {
            expr(lhs, map)?;
            select(rhs, map)?;
        }
        Expr::InTable { lhs, rhs, args, .. } => {
            expr(lhs, map)?;
            rename(rhs, map);
            for e in args {
                expr(e, map)?;
            }
        }
        Expr::Like {
            lhs, rhs, escape, ..
        } => {
            expr(lhs, map)?;
            expr(rhs, map)?;
            if let Some(e) = escape {
                expr(e, map)?;
            }
        }
        Expr::Parenthesized(args) | Expr::Array { elements: args } => {
            for e in args {
                expr(e, map)?;
            }
        }
        Expr::Raise(_, arg) => {
            if let Some(e) = arg {
                expr(e, map)?;
            }
        }
        Expr::Subscript { base, index } => {
            expr(base, map)?;
            expr(index, map)?;
        }
        // These cannot contain relation references or nested SELECTs. Keep this
        // exhaustive so a parser update cannot silently miss a new AST edge.
        Expr::Register(_)
        | Expr::DoublyQualified(..)
        | Expr::Id(_)
        | Expr::Column { .. }
        | Expr::RowId { .. }
        | Expr::Literal(_)
        | Expr::Name(_)
        | Expr::Qualified(..)
        | Expr::Variable(_)
        | Expr::Default => {}
        Expr::SubqueryResult { .. } => {
            return Err(reject("planner-only expression in view definition"))
        }
    }
    Ok(())
}
