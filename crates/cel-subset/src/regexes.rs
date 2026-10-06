//! `matches` (U5, design §1.3/§2.3/§8 F4).
//!
//! - **Literal-only:** a `matches` pattern must be a string literal in
//!   the source; a non-literal is refused at [`crate::check`].
//! - **Size tiers:** `t(p)` is the smallest `RegexBuilder::size_limit`
//!   tier in the policy ladder at which the pattern compiles under the
//!   policy's `nest_limit`. A pattern over the byte cap, or that
//!   compiles under no tier, is refused at `check`.
//! - **Compile once per prepared program:** every distinct literal
//!   pattern is compiled during `check` and looked up at evaluation, so
//!   no evaluation recompiles.
//! - **Charge:** `1 + ⌈len(s) × t(p) / K_re⌉` wu before the search;
//!   `K_re` is `Policy::regex_k_re` (provisional; PR 1b measures).
//!
//! Every attempted compilation tier is precharged on check's separate native
//! load account. Search reuses the same pure row as the estimator.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use crate::common::ast::{EntryExpr, Expr, IdedExpr, LiteralValue};
use crate::{ExecutionError, Policy, Program};

/// A compiled literal pattern with its NFA size tier.
#[derive(Debug)]
pub(crate) struct PreparedRegex {
    pub(crate) regex: regex::Regex,
    /// `t(p)`: the tier's NFA size limit in bytes.
    pub(crate) weight: u64,
    /// `K_re` (policy): the reference NFA size for the search charge.
    pub(crate) k_re: u64,
}

thread_local! {
    static REGISTRY: RefCell<Option<Arc<HashMap<String, PreparedRegex>>>> =
        const { RefCell::new(None) };
}

/// Install the prepared regexes for the current thread; clears on drop.
pub(crate) struct Installed(Option<Arc<HashMap<String, PreparedRegex>>>);

impl Drop for Installed {
    fn drop(&mut self) {
        REGISTRY.with(|r| *r.borrow_mut() = self.0.take());
    }
}

pub(crate) fn install(map: Arc<HashMap<String, PreparedRegex>>) -> Installed {
    let prev = REGISTRY.with(|r| r.borrow_mut().replace(map));
    Installed(prev)
}

/// Run the prepared pattern against `receiver`, charging before the
/// search. Without an installed registry there is no tier to charge
/// and no size limit to enforce, so production code refuses (F6);
/// only in-crate tests (`Program::execute`, no registry) keep the
/// fresh-compile fallback.
pub(crate) fn is_match(pattern: &str, receiver: &str) -> Result<bool, ExecutionError> {
    REGISTRY.with(|r| {
        let map = r.borrow();
        if let Some(map) = map.as_ref() {
            let prepared = map.get(pattern).ok_or_else(|| {
                ExecutionError::function_error("matches", "pattern was not prepared")
            })?;
            crate::meter::charge_cost(crate::charges::regex_search(
                receiver.len() as u64,
                prepared.weight,
                prepared.k_re,
            ))?;
            return Ok(prepared.regex.is_match(receiver));
        }
        #[cfg(test)]
        {
            let re = regex::Regex::new(pattern)
                .map_err(|e| ExecutionError::function_error("matches", e.to_string()))?;
            Ok(re.is_match(receiver))
        }
        #[cfg(not(test))]
        {
            Err(ExecutionError::InternalError(
                "matches pattern registry not installed".to_string(),
            ))
        }
    })
}

/// Compile every distinct literal `matches` pattern in `program`,
/// refusing non-literal patterns and patterns over the tier cap.
pub(crate) fn prepare_program(
    program: &Program,
    policy: &Policy,
) -> Result<HashMap<String, PreparedRegex>, String> {
    let mut patterns = Vec::new();
    collect(program.expression(), &mut patterns)?;
    let mut map = HashMap::new();
    for pattern in patterns {
        if map.contains_key(&pattern) {
            continue;
        }
        let prepared = prepare(&pattern, policy)?;
        map.insert(pattern, prepared);
    }
    Ok(map)
}

fn prepare(pattern: &str, policy: &Policy) -> Result<PreparedRegex, String> {
    if pattern.len() > policy.regex_max_pattern_bytes() {
        return Err(format!(
            "matches pattern is {} bytes; the limit is {}",
            pattern.len(),
            policy.regex_max_pattern_bytes()
        ));
    }
    for &tier in policy.regex_size_tiers() {
        crate::meter::charge_cost(crate::charges::regex_compile(tier as u64))
            .map_err(|e| e.to_string())?;
        crate::meter::note_op_body();
        if let Ok(regex) = regex::RegexBuilder::new(pattern)
            .size_limit(tier)
            .nest_limit(policy.regex_nest_limit())
            .build()
        {
            return Ok(PreparedRegex {
                regex,
                weight: tier as u64,
                k_re: policy.regex_k_re(),
            });
        }
    }
    Err(format!(
        "matches pattern exceeds the top NFA size tier ({} bytes)",
        policy.regex_size_tiers().last().copied().unwrap_or(0)
    ))
}

/// Collect the pattern of every `matches` call, refusing non-literals.
fn collect(e: &IdedExpr, out: &mut Vec<String>) -> Result<(), String> {
    match &e.expr {
        Expr::Call(call) => {
            if call.func_name == "matches" {
                let pattern = match (&call.target, call.args.len()) {
                    (Some(_), 1) => call.args.first(),
                    (None, 2) => call.args.get(1),
                    _ => None,
                };
                match pattern.map(|p| &p.expr) {
                    Some(Expr::Literal(LiteralValue::String(s))) => out.push(s.inner().to_string()),
                    _ => return Err("matches pattern must be a string literal".to_string()),
                }
            }
            if let Some(t) = &call.target {
                collect(t, out)?;
            }
            for a in &call.args {
                collect(a, out)?;
            }
        }
        Expr::Select(s) => collect(&s.operand, out)?,
        Expr::List(l) => {
            for el in &l.elements {
                collect(el, out)?;
            }
        }
        Expr::Map(m) => {
            for entry in &m.entries {
                if let EntryExpr::MapEntry(me) = &entry.expr {
                    collect(&me.key, out)?;
                    collect(&me.value, out)?;
                }
            }
        }
        Expr::Struct(s) => {
            for entry in &s.entries {
                if let EntryExpr::StructField(f) = &entry.expr {
                    collect(&f.value, out)?;
                }
            }
        }
        Expr::Comprehension(c) => {
            collect(&c.iter_range, out)?;
            collect(&c.accu_init, out)?;
            collect(&c.loop_cond, out)?;
            collect(&c.loop_step, out)?;
            collect(&c.result, out)?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{check, evaluate, Bindings, Policy, Value};

    fn rows_with_string(n: usize, len: usize) -> Vec<Value> {
        (0..n)
            .map(|_| {
                let m: indexmap::IndexMap<String, String> = [("s", "a".repeat(len))]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect();
                m.into()
            })
            .collect()
    }

    /// The compile count equals the number of distinct literal
    /// patterns, and evaluation with prepared patterns never recompiles
    /// (including a 5k scan).
    #[test]
    fn compiles_once_per_distinct_literal_pattern() {
        let report = check(
            "['ab'.matches('a'), 'ab'.matches('b'), 'ab'.matches('a')]",
            &Policy::P0_INTERIM,
        );
        let prepared = report.result.expect("check");
        assert_eq!(prepared.regex_count(), 2, "two distinct literal patterns");

        let mut bindings = Bindings::new();
        bindings.set("rows", rows_with_string(5000, 4).into());
        let prepared = check("rows.all(r, r.s.matches('a'))", &Policy::P0_INTERIM)
            .result
            .expect("check");
        assert_eq!(prepared.regex_count(), 1, "one pattern compiles once");
        // A 5,000-row scan evaluates against the one prepared pattern.
        let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
        assert!(
            report.result.is_ok(),
            "5k scan should pass: work={}",
            report.cost.work
        );
        assert_eq!(prepared.regex_count(), 1, "evaluation must not recompile");
    }

    /// A pattern over the top tier is refused at `check`.
    #[test]
    fn pattern_over_top_tier_is_refused() {
        assert!(check("'x'.matches('a{100000}')", &Policy::P0_INTERIM)
            .result
            .is_err());
    }

    /// A non-literal pattern is refused at `check`, not at evaluation.
    #[test]
    fn non_literal_pattern_is_refused_at_check() {
        let report = check("r.s.matches(r.p)", &Policy::P0_INTERIM);
        let err = report.result.expect_err("must refuse non-literal");
        assert!(
            err.to_string().contains("string literal"),
            "message should name the literal requirement: {err}"
        );
    }

    /// The review's `matches` scan is charged and refused under P0.
    #[test]
    fn matches_scan_is_refused_under_p0() {
        use crate::ExecutionError;
        let mut bindings = Bindings::new();
        // 5,000 rows of 500-char strings: 1 + ⌈500×1024/64⌉ = 8,001 wu
        // each, far over P0's 2,000,000.
        bindings.set("rows", rows_with_string(5000, 500).into());
        let prepared = check("rows.all(r, r.s.matches('a'))", &Policy::P0_INTERIM)
            .result
            .expect("check");
        let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
        assert!(
            matches!(report.result, Err(ExecutionError::WorkBudgetExceeded(_))),
            "expected work_budget: {:?}",
            report.result.is_err()
        );
    }

    /// Exact wu for a small `matches`.
    #[test]
    fn exact_wu_for_small_matches() {
        let prepared = check("'ab'.matches('a')", &Policy::P0_INTERIM)
            .result
            .expect("check");
        let report = evaluate(&prepared, &Bindings::new(), &Policy::P0_INTERIM);
        assert!(report.result.is_ok());
        // 3 visits + 33 search wu + 2 result-emission wu = 38.
        assert_eq!(report.cost.work, 38);
    }
}
