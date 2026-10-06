//! Post-expansion L1. All structural measures use an iterative tree walk.
//! Values add <=one level at each literal/map wrapper; native inputs start <=3.
use crate::common::ast::{EntryExpr, Expr, IdedExpr};
use crate::comprehension;

pub(crate) const SOURCE_BYTES: usize = 8 * 1024;
pub(crate) const REAL_TOKENS: usize = 1024;
pub(crate) const AST_DEPTH: usize = 32;
pub(crate) const VALUE_DEPTH: usize = 3 + AST_DEPTH;
pub(crate) const COMPREHENSION_DEPTH: usize = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Measures {
    pub source_bytes: usize,
    /// Filled from the lexer L0 seam once integrated, never inferred from AST.
    pub real_tokens: Option<usize>,
    pub expanded_nodes: usize,
    pub ast_depth: usize,
    pub comprehensions: usize,
    pub comprehension_depth: usize,
    /// Conservative constructed value depth (input3 plus path wrappers).
    pub value_depth: usize,
}
#[derive(Clone, Debug)]
pub(crate) struct Refusal {
    pub expr_id: u64,
    pub cap: &'static str,
    pub measured: usize,
    pub limit: usize,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} exceeds {}", self.cap, self.measured, self.limit)
    }
}
pub(crate) fn measure(
    root: &IdedExpr,
    source_bytes: usize,
    real_tokens: Option<usize>,
) -> Result<Measures, Refusal> {
    let fail = |id, cap, got, limit| {
        Err(Refusal {
            expr_id: id,
            cap,
            measured: got,
            limit,
        })
    };
    if source_bytes > SOURCE_BYTES {
        return fail(root.id, "expression_bytes", source_bytes, SOURCE_BYTES);
    }
    if real_tokens.is_some_and(|t| t > REAL_TOKENS) {
        return fail(root.id, "real_tokens", real_tokens.unwrap(), REAL_TOKENS);
    }
    let mut m = Measures {
        source_bytes,
        real_tokens,
        value_depth: 3,
        ..Measures::default()
    };
    let mut stack = vec![(root, 1usize, 0usize, 0usize)];
    while let Some((e, depth, comp, value)) = stack.pop() {
        if depth > AST_DEPTH {
            return fail(e.id, "ast_depth", depth, AST_DEPTH);
        }
        m.expanded_nodes = m.expanded_nodes.saturating_add(1);
        m.ast_depth = m.ast_depth.max(depth);
        let mut next_comp = comp;
        let mut next_value = value;
        let mut children = Vec::new();
        match &e.expr {
            Expr::Ident(name) => {
                if name.len() > 128 {
                    return fail(e.id, "identifier_bytes", name.len(), 128);
                }
            }
            Expr::Call(c) => {
                if let Some(t) = &c.target {
                    children.push(t.as_ref());
                }
                children.extend(&c.args);
            }
            Expr::Select(s) => {
                children.push(s.operand.as_ref());
            }
            Expr::List(l) => {
                if !l.optional_indices.is_empty() {
                    return fail(e.id, "optional_list", 1, 0);
                }
                next_value += 1;
                children.extend(&l.elements);
            }
            Expr::Map(map) => {
                next_value += 1;
                for entry in &map.entries {
                    let EntryExpr::MapEntry(v) = &entry.expr else {
                        return fail(e.id, "struct_entry", 1, 0);
                    };
                    if v.optional {
                        return fail(e.id, "optional_map", 1, 0);
                    }
                    children.push(&v.key);
                    children.push(&v.value);
                }
            }
            Expr::Comprehension(c) => {
                // Read the same closed form which the estimator consumes.
                let body = match comprehension::classify(c) {
                    Some(comprehension::Macro::Fold(kind, pred)) => match kind {
                        comprehension::AbsorbingFold::All
                        | comprehension::AbsorbingFold::Exists => pred,
                    },
                    Some(comprehension::Macro::Append(comprehension::AppendStep::Map(body))) => {
                        body
                    }
                    Some(comprehension::Macro::Append(comprehension::AppendStep::Filter {
                        condition,
                        element,
                    })) => {
                        if condition.id == element.id {
                            return fail(e.id, "invalid_macro", 1, 0);
                        }
                        element
                    }
                    Some(comprehension::Macro::ExistsOne(pred)) => pred,
                    None => return fail(e.id, "raw_comprehension", 1, 0),
                };
                debug_assert_ne!(body.id, e.id);
                if c.iter_var.len() > 128 {
                    return fail(e.id, "identifier_bytes", c.iter_var.len(), 128);
                }
                next_comp += 1;
                m.comprehensions += 1;
                m.comprehension_depth = m.comprehension_depth.max(next_comp);
                if next_comp > COMPREHENSION_DEPTH {
                    return fail(e.id, "comprehension_depth", next_comp, COMPREHENSION_DEPTH);
                }
                // Independent sequential comprehensions in the range do not
                // count as nested bodies. Scope/depth still applies structurally.
                stack.push((&c.iter_range, depth + 1, comp, value));
                children.extend([&c.accu_init, &c.loop_cond, &c.loop_step, &c.result]);
            }
            Expr::Literal(_) => {}
            Expr::Struct(_) | Expr::Unspecified => return fail(e.id, "unsupported_ast", 1, 0),
        }
        m.value_depth = m.value_depth.max(3 + next_value);
        if m.value_depth > VALUE_DEPTH {
            return fail(e.id, "value_depth", m.value_depth, VALUE_DEPTH);
        }
        for child in children.into_iter().rev() {
            stack.push((child, depth + 1, next_comp, next_value));
        }
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use crate::{api, Declarations, InputDecl, InputKind, Policy};
    #[test]
    fn l1_measures_expanded_ast_separately_from_l0_frames() {
        let d = Declarations::empty();
        let p = api::measure(
            &format!("{}1{}", "(".repeat(33), ")".repeat(33)),
            &d,
            &Policy::P0_INTERIM,
        )
        .result
        .unwrap();
        assert_eq!(p.measures().ast_depth, 1);
        assert_eq!(p.measures().real_tokens, Some(67));
        let source = format!("{}1{}", "[".repeat(32), "]".repeat(32));
        let err = api::measure(&source, &d, &Policy::P0_INTERIM)
            .result
            .unwrap_err();
        assert!(err.to_string().contains("ast_depth"));
        assert_ne!(err.errors[0].expr_id, 0);
        assert!(err.errors[0].source_info.is_some());
    }
    #[test]
    fn l1_classifies_every_supported_macro_and_rejects_third_body_nesting() {
        let d = Declarations::new(
            [InputDecl {
                name: "rows".into(),
                kind: InputKind::Many,
            }],
            &Policy::P0_INTERIM,
        )
        .unwrap();
        for source in [
            "rows.all(r,true)",
            "rows.exists(r,true)",
            "rows.exists_one(r,true)",
            "rows.map(r,r)",
            "rows.filter(r,true)",
            "rows.map(r,true,r)",
            "rows.all(r, r.all(k,true))",
        ] {
            let p = api::measure(source, &d, &Policy::P0_INTERIM)
                .result
                .unwrap_or_else(|e| panic!("{source}: {e}"));
            assert!(p.measures().comprehensions > 0);
        }
        assert!(api::measure(
            "rows.all(r,r.all(k,[0].all(x,true)))",
            &d,
            &Policy::P0_INTERIM
        )
        .result
        .unwrap_err()
        .to_string()
        .contains("comprehension_depth"));
    }
}
