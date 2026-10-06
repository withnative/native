use crate::common::ast::{operators, CallExpr, ComprehensionExpr, Expr, IdedExpr, LiteralValue};
use crate::parser::Expression;
pub(crate) enum AppendStep<'a> {
    Map(&'a IdedExpr),
    Filter {
        condition: &'a IdedExpr,
        element: &'a IdedExpr,
    },
}

pub(crate) fn append_step(comp: &ComprehensionExpr) -> Option<AppendStep<'_>> {
    match &comp.loop_step.expr {
        Expr::Call(call) if call.func_name == operators::ADD => {
            single_append(comp, call).map(AppendStep::Map)
        }
        Expr::Call(call) if call.func_name == operators::CONDITIONAL && call.args.len() == 3 => {
            let Expr::Call(add) = &call.args[1].expr else {
                return None;
            };
            if add.func_name != operators::ADD || !is_accu_ident(&call.args[2], &comp.accu_var) {
                return None;
            }
            single_append(comp, add).map(|element| AppendStep::Filter {
                condition: &call.args[0],
                element,
            })
        }
        _ => None,
    }
}

fn single_append<'a>(comp: &ComprehensionExpr, add: &'a CallExpr) -> Option<&'a IdedExpr> {
    if add.args.len() != 2 || !is_accu_ident(&add.args[0], &comp.accu_var) {
        return None;
    }
    let Expr::List(list) = &add.args[1].expr else {
        return None;
    };
    if list.elements.len() != 1 || !list.optional_indices.is_empty() {
        return None;
    }
    Some(&list.elements[0])
}

pub(crate) fn is_accu_ident(e: &IdedExpr, accu_var: &str) -> bool {
    matches!(&e.expr, Expr::Ident(name) if name == accu_var)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AbsorbingFold {
    All,
    Exists,
}

/// Detect the `all`/`exists` macro expansion shape: a boolean accu
/// init with a `LOGICAL_AND` / `LOGICAL_OR(@result, pred)` step.
/// Returns the predicate to fold directly. Hand-written
/// comprehensions of exactly this shape get the same (spec-correct)
/// treatment; anything else uses the generic fold.
pub(crate) fn absorbing_fold(
    comprehension: &ComprehensionExpr,
) -> Option<(AbsorbingFold, &Expression)> {
    if comprehension.accu_var != "@result" {
        return None;
    }
    let Expr::Literal(LiteralValue::Boolean(init)) = &comprehension.accu_init.expr else {
        return None;
    };
    let Expr::Call(step) = &comprehension.loop_step.expr else {
        return None;
    };
    if step.target.is_some() || step.args.len() != 2 {
        return None;
    }
    let Expr::Ident(accu) = &step.args[0].expr else {
        return None;
    };
    if accu != &comprehension.accu_var {
        return None;
    }
    match (step.func_name.as_str(), *init.inner()) {
        (operators::LOGICAL_AND, true) => Some((AbsorbingFold::All, &step.args[1])),
        (operators::LOGICAL_OR, false) => Some((AbsorbingFold::Exists, &step.args[1])),
        _ => None,
    }
}

pub(crate) enum Macro<'a> {
    Fold(AbsorbingFold, &'a IdedExpr),
    Append(AppendStep<'a>),
    ExistsOne(&'a IdedExpr),
}
/// Closed production forms. Runtime specialization above remains available for
/// private raw semantic tests; admission requires the complete parser expansion.
pub(crate) fn classify(c: &ComprehensionExpr) -> Option<Macro<'_>> {
    if c.accu_var != "@result" || c.iter_var2.is_some() {
        return None;
    }
    if let Some((kind, pred)) = absorbing_fold(c) {
        let Expr::Call(cond) = &c.loop_cond.expr else {
            return None;
        };
        if cond.target.is_none()
            && cond.func_name == operators::NOT_STRICTLY_FALSE
            && cond.args.len() == 1
            && match kind {
                AbsorbingFold::All => is_accu_ident(&cond.args[0], &c.accu_var),
                AbsorbingFold::Exists => {
                    matches!(&cond.args[0].expr, Expr::Call(not) if not.func_name==operators::LOGICAL_NOT && not.target.is_none() && not.args.len()==1 && is_accu_ident(&not.args[0],&c.accu_var))
                }
            }
            && is_accu_ident(&c.result, &c.accu_var)
        {
            return Some(Macro::Fold(kind, pred));
        }
        return None;
    }
    if !matches!(&c.loop_cond.expr, Expr::Literal(LiteralValue::Boolean(b)) if *b.inner()) {
        return None;
    }
    if let Some(step) = append_step(c) {
        if matches!(&c.accu_init.expr, Expr::List(l) if l.elements.is_empty() && l.optional_indices.is_empty())
            && is_accu_ident(&c.result, &c.accu_var)
        {
            return Some(Macro::Append(step));
        }
    }
    if !matches!(&c.accu_init.expr, Expr::Literal(LiteralValue::Int(n)) if *n.inner()==0) {
        return None;
    }
    let Expr::Call(step) = &c.loop_step.expr else {
        return None;
    };
    if step.target.is_some()
        || step.func_name != operators::CONDITIONAL
        || step.args.len() != 3
        || !is_accu_ident(&step.args[2], &c.accu_var)
    {
        return None;
    }
    let Expr::Call(add) = &step.args[1].expr else {
        return None;
    };
    if add.target.is_some()
        || add.func_name != operators::ADD
        || add.args.len() != 2
        || !is_accu_ident(&add.args[0], &c.accu_var)
        || !matches!(&add.args[1].expr, Expr::Literal(LiteralValue::Int(n)) if *n.inner()==1)
    {
        return None;
    }
    let Expr::Call(result) = &c.result.expr else {
        return None;
    };
    if result.target.is_some()
        || result.func_name != operators::EQUALS
        || result.args.len() != 2
        || !is_accu_ident(&result.args[0], &c.accu_var)
        || !matches!(&result.args[1].expr, Expr::Literal(LiteralValue::Int(n)) if *n.inner()==1)
    {
        return None;
    }
    Some(Macro::ExistsOne(&step.args[0]))
}

/// A closed macro cannot observe its temporary singleton range list. Resolve
/// its element directly and borrow it during the sole iteration. Every output
/// copy remains in the ordinary append/emission paths. Raw forms keep the list.
pub(crate) fn singleton_range(c: &ComprehensionExpr) -> Option<&IdedExpr> {
    classify(c)?;
    let Expr::List(list) = &c.iter_range.expr else {
        return None;
    };
    (list.elements.len() == 1 && list.optional_indices.is_empty()).then(|| &list.elements[0])
}
