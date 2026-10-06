//! Two meters (PR 1a increment 4, design §1.3 and §1.4).
//!
//! Replaces round 2's step and allocation budget.
//!
//! - **Work (wu):** charged **before** the operation runs
//!   (charge-before-work), so an operation that would exceed the
//!   budget is refused before it starts. Cumulative per evaluation.
//! - **Memory (mb):** a *scoped* high-water mark. Every construction
//!   raises the current level `L`; `H = max L` is sampled at every
//!   charge, and the refusal fires on `H`. `L` drops only at
//!   comprehension iteration ends and at comprehension exit (the
//!   caller supplies the new level via [`set_level`]).
//! - **Depth** is not a budget knob (design §1.3): exceeding the
//!   assertion is an engine defect, reported as
//!   [`ExecutionError::InternalLimit`], never a verdict.
//!
//! One budget per evaluation: [`install`] resets the counters, so a
//! native `evaluate` call is one budget for the whole rule. The
//! guest's per-execution behaviour is unchanged here (design §7.1,
//! PR 2). All state is thread-local, so the pool worker's counters
//! do not leak to callers.

use std::cell::{Cell, RefCell};

use crate::charges::Cost;
use crate::ExecutionError;

/// Maximum evaluator recursion depth. §1.3 says this is not a budget
/// knob but an assertion derived from the size policy (§2); the §2
/// derivation and the admitted shapes land in increment 5, so this
/// keeps the fork's round-2 value (the review found it unreachable
/// under the parse caps).
pub(crate) const MAX_EVAL_DEPTH: u32 = 512;

/// A bound on one evaluation: work units and retained bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub work: u64,
    pub memory: u64,
}

thread_local! {
    static WORK: Cell<u64> = const { Cell::new(0) };
    static LEVEL: Cell<u64> = const { Cell::new(0) };
    static HIGH: Cell<u64> = const { Cell::new(0) };
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    static LIMITS: RefCell<Option<Budget>> = const { RefCell::new(None) };
    /// Sticky budget refusal (F2): the first `WorkBudgetExceeded`,
    /// `MemoryBudgetExceeded` or `InternalLimit` latched here. Once
    /// set, every charge and `enter_node` re-fails with it, so no
    /// `||`, `&&`, `all`, `exists`, `exists_one` or ternary can
    /// absorb the refusal into a verdict.
    static TRIPPED: RefCell<Option<ExecutionError>> = const { RefCell::new(None) };
    #[cfg(test)]
    static BODY_RUNS: Cell<u64> = const { Cell::new(0) };
    #[cfg(test)]
    static OP_BODIES: Cell<u64> = const { Cell::new(0) };
}

fn limits() -> Option<Budget> {
    LIMITS.with(|l| *l.borrow())
}

/// Install `budget` for the current thread, resetting all counters,
/// and return the previous setting (for save/restore across nested
/// executions).
pub(crate) fn install(budget: Budget) -> Option<Budget> {
    reset_counters();
    LIMITS.replace(Some(budget))
}

/// Clear the current thread's budget, resetting counters, and return
/// the previous setting.
pub(crate) fn clear() -> Option<Budget> {
    reset_counters();
    LIMITS.replace(None)
}

fn reset_counters() {
    WORK.set(0);
    LEVEL.set(0);
    HIGH.set(0);
    DEPTH.set(0);
    TRIPPED.with(|t| *t.borrow_mut() = None);
}

/// The latched refusal, if any budget refusal has fired.
fn latched() -> Option<ExecutionError> {
    TRIPPED.with(|t| t.borrow().clone())
}

/// Latch `err` as the sticky refusal (first one wins) and return it.
/// Crate-visible so every budget refusal path (including
/// `charge_value`'s unmeasurable-value refusal) latches by
/// construction.
pub(crate) fn latch(err: ExecutionError) -> ExecutionError {
    TRIPPED.with(|t| {
        let mut slot = t.borrow_mut();
        if slot.is_none() {
            *slot = Some(err.clone());
        }
        slot.clone().unwrap_or(err)
    })
}

/// The latched refusal for `execute_budgeted` to enforce after the
/// run: a tripped evaluation yields the refusal whatever value was
/// computed.
pub(crate) fn tripped() -> Option<ExecutionError> {
    latched()
}

/// Totals for the current evaluation: cumulative work and the memory
/// high-water mark. `None` when no budget is installed.
pub(crate) fn totals() -> Option<Cost> {
    limits().map(|_| Cost::new(WORK.get(), HIGH.get()))
}

/// Charge `wu` work units before the operation runs. Refuses with
/// [`ExecutionError::WorkBudgetExceeded`] when the cumulative work
/// would exceed the budget.
pub(crate) fn charge_work(wu: u64) -> Result<(), ExecutionError> {
    let Some(limits) = limits() else {
        return Ok(());
    };
    if let Some(err) = latched() {
        return Err(err);
    }
    if wu == 0 {
        return Ok(());
    }
    let total = WORK.get().saturating_add(wu);
    WORK.set(total);
    if total > limits.work {
        return Err(latch(ExecutionError::WorkBudgetExceeded(format!(
            "work_budget: more than {} work units",
            limits.work
        ))));
    }
    Ok(())
}

/// Raise the current level by `bytes`, sample the high-water mark, and
/// refuse with [`ExecutionError::MemoryBudgetExceeded`] when `H`
/// exceeds the budget. No-op when no budget is installed.
pub(crate) fn charge_memory(bytes: u64) -> Result<(), ExecutionError> {
    let Some(limits) = limits() else {
        return Ok(());
    };
    if let Some(err) = latched() {
        return Err(err);
    }
    if bytes == 0 {
        return Ok(());
    }
    let level = LEVEL.get().saturating_add(bytes);
    LEVEL.set(level);
    if level > HIGH.get() {
        HIGH.set(level);
    }
    if level > limits.memory {
        return Err(latch(ExecutionError::MemoryBudgetExceeded(format!(
            "memory_budget: more than {} retained bytes",
            limits.memory
        ))));
    }
    Ok(())
}

/// Charge a table row's cost at an operation/construction site:
/// work first (charge-before-work, so a refused operation's body never
/// runs), then the memory level.
pub(crate) fn charge_cost(cost: Cost) -> Result<(), ExecutionError> {
    charge_work(cost.work)?;
    charge_memory(cost.memory)
}

/// Current memory level `L`.
pub(crate) fn level() -> u64 {
    LEVEL.get()
}

/// Lower (or raise) the current level `L` without sampling the
/// high-water mark. Used only at the two scoping points §1.3 names:
/// comprehension iteration ends and comprehension exit.
pub(crate) fn set_level(level: u64) {
    LEVEL.set(level);
}

/// The high-water mark `H` seen so far (`#[cfg(test)]`: only the
/// meter's own tests observe it; production reads it via `totals`).
#[cfg(test)]
pub(crate) fn high_water() -> u64 {
    HIGH.get()
}

/// Node-visit entry: charge the node-visit work (1 wu) and one depth
/// level. The returned guard decrements depth on drop, so every
/// `resolve_val` return path (including `?` and panics) balances.
pub(crate) fn enter_node() -> Result<DepthGuard, ExecutionError> {
    charge_cost(crate::charges::node_visit())?;
    if limits().is_none() {
        return Ok(DepthGuard { active: false });
    }
    let depth = DEPTH.get().saturating_add(1);
    DEPTH.set(depth);
    if depth > MAX_EVAL_DEPTH {
        return Err(latch(ExecutionError::InternalLimit(format!(
            "internal_limit: evaluation depth {depth} exceeds {MAX_EVAL_DEPTH}"
        ))));
    }
    Ok(DepthGuard { active: true })
}

pub(crate) struct DepthGuard {
    active: bool,
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        if self.active {
            DEPTH.set(DEPTH.get().saturating_sub(1));
        }
    }
}

/// `#[cfg(test)]` hook: record that a guarded operation body ran.
#[inline(always)]
pub(crate) fn note_body_ran() {
    #[cfg(test)]
    BODY_RUNS.set(BODY_RUNS.get().saturating_add(1));
}

/// `#[cfg(test)]` hook: record that a sized operation's body ran
/// (equality, containment, list concat). Lets a test prove that a
/// refused operation's charge fired before its body.
#[inline(always)]
pub(crate) fn note_op_body() {
    #[cfg(test)]
    OP_BODIES.set(OP_BODIES.get().saturating_add(1));
}

/// `#[cfg(test)]`: guarded bodies entered since the last reset.
#[cfg(test)]
pub(crate) fn body_runs() -> u64 {
    BODY_RUNS.get()
}

/// `#[cfg(test)]`: sized-operation bodies entered since the reset.
#[cfg(test)]
pub(crate) fn op_bodies() -> u64 {
    OP_BODIES.get()
}

/// `#[cfg(test)]`: reset both guarded-body counters.
#[cfg(test)]
pub(crate) fn reset_body_runs() {
    BODY_RUNS.set(0);
    OP_BODIES.set(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Context, Program, Value};

    /// Evaluate on this thread under an effectively unbounded budget
    /// and return the result with the cost it consumed.
    fn eval_cost(src: &str) -> (Result<Value, ExecutionError>, Cost) {
        eval_cost_with(src, Context::default())
    }

    fn eval_cost_with(src: &str, ctx: Context<'_>) -> (Result<Value, ExecutionError>, Cost) {
        let program = Program::compile(src).expect("compiles");
        program.execute_budgeted(
            &ctx,
            Budget {
                work: u64::MAX,
                memory: u64::MAX,
            },
        )
    }

    fn cost_of(src: &str) -> Cost {
        let (result, cost) = eval_cost(src);
        assert!(result.is_ok(), "eval failed: {result:?}");
        cost
    }

    #[test]
    fn exact_costs_for_wired_rows() {
        // node visit + U12 result emission of one node.
        assert_eq!(cost_of("1"), Cost::new(3, 16));
        // string literal: node visit + literal len bytes + U12 (1).
        assert_eq!(cost_of("'abc'"), Cost::new(3, 14));
        // 3 node visits + `s + t` work ⌈5/64⌉ = 1 + U12 (1) = 5 wu;
        // memory 3 + 2 + (3 + 2) = 10.
        assert_eq!(cost_of("'abc' + 'de'"), Cost::new(6, 39));
        // list literal: 4 node visits + U8 (3 elements + 3 nodes = 6)
        // + payload ⌈24/64⌉ = 1 + U12 (4) = 15 wu; memory 32×3 + 8×3
        // = 120 (round 3 charges cached element bytes, not just text).
        assert_eq!(cost_of("[1, 2, 3]"), Cost::new(17, 272));
        // map literal: 3 node visits + U8 (1 entry + 1 value node = 2)
        // + text ⌈1/64⌉ = 1 + U12 (2) = 8 wu; memory = key-literal
        // materialisation 1 (string-literal row) + U8 64 slot + 1 key
        // + 8 value = 74.
        assert_eq!(cost_of("{'a': 1}"), Cost::new(12, 172));
    }

    #[test]
    fn exact_work_for_remaining_u_rows() {
        // U14 ordering: 3 nodes + ⌈min(3,3)/64⌉ = 1 + U12 1 = 5 wu.
        assert_eq!(cost_of("'abc' < 'abd'").work, 6);
        // U2 in-list: 5 nodes + U8 4 + payload ⌈16/64⌉ = 1 + U2
        // (3 nodes + ⌈80/64⌉ = 5) + U12 1 = 16 wu.
        assert_eq!(cost_of("1 in [1, 2]").work, 17);
        // map-key: 5 nodes + U8 2 + text 1 + key 1 + U12 1 = 10 wu
        // (F4 remainder adds the key-text term).
        assert_eq!(cost_of("{'a': 1}['a']").work, 13);
        // U4 string contains: 3 nodes + ⌈(3+1)/64⌉ 1 + U12 1 = 5 wu.
        assert_eq!(cost_of("'abc'.contains('b')").work, 6);
        // U4 startsWith and endsWith.
        assert_eq!(cost_of("'abc'.startsWith('a')").work, 6);
        assert_eq!(cost_of("'abc'.endsWith('c')").work, 6);
    }

    /// F4: string-length-proportional work charges (⌈len/64⌉ terms).
    #[test]
    fn string_length_proportional_charges() {
        // Scalar string `==`: 3 nodes + ⌈min(3,3)/64⌉ = 1 + U12 1 = 5.
        assert_eq!(cost_of("'abc' == 'abd'").work, 6);
        // `size(string)`: 2 nodes + ⌈3/64⌉ = 1 + U12 1 = 4.
        assert_eq!(cost_of("size('abc')").work, 5);
        // `string(int)`: 2 nodes + ⌈8/64⌉ = 1 + U12 1 = 4.
        assert_eq!(cost_of("string(1)").work, 6);
        // `bytes(string)`: 2 nodes + ⌈2/64⌉ = 1 + U12 1 = 4.
        assert_eq!(cost_of("bytes('ab')").work, 6);
        // `in` over strings: 5 nodes + U8 4 + text ⌈6/64⌉ = 1 +
        // U2 (3 nodes + ⌈70/64⌉ = 6, minus the visit) + U12 1 = 16.
        assert_eq!(cost_of("'x' in ['abc', 'abd']").work, 17);
        // Select owning a 3-byte string copy: 6 nodes + U8 2 + text
        // ⌈4/64⌉ = 1 + key hash 1 + select ⌈3/64⌉ = 1 + `==`
        // ⌈1/64⌉ = 1 + U12 1 = 13 (F4b, F4 remainder).
        assert_eq!(cost_of("{'s': 'abc'}.s == 'x'").work, 18);
        // `int(string)`: 2 nodes + parse ⌈2/64⌉ = 1 + U12 1 = 4
        // (F4 remainder).
        assert_eq!(cost_of("int('12')").work, 5);
    }

    /// F4 remainder: the reviewer's parse and literal-text probes (4
    /// MiB strings over 1k rows) are refused by `work_budget` instead
    /// of running seconds of uncharged O(len) work per iteration.
    #[test]
    fn parse_and_literal_text_are_refused_by_work_budget() {
        use crate::{check, Bindings, ExecutionError, Policy, Value};
        let mut bindings = Bindings::new();
        bindings.set("big", Value::from("a".repeat(4 * 1024 * 1024)));
        bindings.set("digits", Value::from("9".repeat(4 * 1024 * 1024)));
        let xs: Vec<Value> = (0..1000).map(Value::Int).collect();
        bindings.set("xs", Value::from(xs));
        // `exists` with an always-false predicate runs every
        // iteration (`all` would stop at the first one, and a
        // successful `double` parse compares false).
        for src in [
            "xs.exists(i, int(digits) == 1)",
            "xs.exists(i, uint(digits) == 1u)",
            "xs.exists(i, double(digits) == 1.0)",
            "xs.exists(i, duration(big) == duration('1s'))",
            "xs.exists(i, timestamp(big) == timestamp('2024-01-01T00:00:00Z'))",
            "xs.all(i, [big].size() > 0)",
            "xs.all(i, {'k': big}.size() > 0)",
            "xs.all(i, {big: 1}.size() > 0)",
        ] {
            let prepared = check(src, &Policy::P0_INTERIM).result.expect("check");
            let mut context = Context::default();
            for (name, value) in &bindings.variables {
                context.add_variable_from_value(name, value.clone());
            }
            let _ = prepared; // Check remains part of the probe.
            let (result, _) = Program::compile(src).unwrap().execute_budgeted(
                &context,
                Budget {
                    work: Policy::P0_INTERIM.work_limit(),
                    memory: u64::MAX,
                },
            );
            assert!(
                matches!(result, Err(ExecutionError::WorkBudgetExceeded(_))),
                "{src}: expected work_budget, got {:?}",
                result
            );
        }
    }

    /// Round 3: strings nested inside a literal element are charged
    /// from the element's cached bytes. `[bigs]` copies ~4 MiB per
    /// iteration; over 1k `all` iterations (predicate always true)
    /// the literal charge refuses by `work_budget`.
    #[test]
    fn nested_text_in_literals_is_refused_by_work_budget() {
        use crate::{check, evaluate, Bindings, ExecutionError, Policy, Value};
        let bigs: Vec<Value> = (0..16)
            .map(|_| Value::from("a".repeat(256 * 1024)))
            .collect();
        let mut bindings = Bindings::new();
        bindings.set("bigs", Value::from(bigs));
        let xs: Vec<Value> = (0..1000).map(Value::Int).collect();
        bindings.set("xs", Value::from(xs));
        for src in [
            "xs.all(i, [bigs].size() > 0)",
            "xs.all(i, {'k': bigs}.size() > 0)",
        ] {
            let prepared = check(src, &Policy::P0_INTERIM).result.expect("check");
            let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
            assert!(
                matches!(report.result, Err(ExecutionError::WorkBudgetExceeded(_))),
                "{src}: expected work_budget, got {:?}",
                report.result
            );
        }
    }

    /// F4b: selecting a 4 MiB string field from a per-iteration map
    /// temporary copies 4 MiB each time (`exists` runs all 1k
    /// iterations since the predicate is always false); the
    /// owned-copy charge refuses by `work_budget`.
    #[test]
    fn big_string_select_copy_is_refused_by_work_budget() {
        use crate::{check, Bindings, ExecutionError, Policy, Value};
        let big = "a".repeat(4 * 1024 * 1024);
        let mut bindings = Bindings::new();
        bindings.set("big", Value::from(big));
        let xs: Vec<Value> = (0..1000).map(Value::Int).collect();
        bindings.set("xs", Value::from(xs));
        let src = "xs.exists(i, {'s': big}.s == 'a')";
        let prepared = check(src, &Policy::P0_INTERIM).result.expect("check");
        let mut context = Context::default();
        for (name, value) in &bindings.variables {
            context.add_variable_from_value(name, value.clone());
        }
        let _ = prepared; // Check remains part of the probe.
        let (result, _) = Program::compile(src).unwrap().execute_budgeted(
            &context,
            Budget {
                work: Policy::P0_INTERIM.work_limit(),
                memory: u64::MAX,
            },
        );
        assert!(
            matches!(result, Err(ExecutionError::WorkBudgetExceeded(_))),
            "{src}: expected work_budget, got {:?}",
            result
        );
    }

    /// F4: the review's string-payload probes (4 MiB strings over 1k
    /// rows) are refused by `work_budget` instead of running minutes
    /// of uncharged O(len) work per iteration.
    #[test]
    fn big_string_payloads_are_refused_by_work_budget() {
        use crate::{check, evaluate, Bindings, ExecutionError, Policy, Value};
        let big = "a".repeat(4 * 1024 * 1024);
        let mut bindings = Bindings::new();
        bindings.set("big", Value::from(big.clone()));
        bindings.set("big2", Value::from(big));
        let xs: Vec<Value> = (0..1000).map(Value::Int).collect();
        bindings.set("xs", Value::from(xs));
        for src in [
            "xs.all(i, big == big2)",
            "xs.all(i, big.size() > 0)",
            "xs.all(i, big in [big2])",
        ] {
            let prepared = check(src, &Policy::P0_INTERIM).result.expect("check");
            let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
            assert!(
                matches!(report.result, Err(ExecutionError::WorkBudgetExceeded(_))),
                "{src}: expected work_budget, got {:?}",
                report.result
            );
        }
    }

    #[test]
    fn high_water_persists_across_level_drops() {
        clear();
        install(Budget {
            work: u64::MAX,
            memory: 1_000,
        });
        charge_memory(400).unwrap();
        assert_eq!(level(), 400);
        assert_eq!(high_water(), 400);
        set_level(0); // an iteration-end drop
        assert_eq!(level(), 0);
        assert_eq!(high_water(), 400, "H persists across a level drop");
        charge_memory(300).unwrap();
        assert_eq!(level(), 300);
        assert_eq!(high_water(), 400, "H is still the earlier peak");
        clear();
    }

    #[test]
    fn refused_operation_body_never_ran() {
        let ctx = Context::default();
        let program = Program::compile("1 + 1").expect("compiles");

        // Work budget 0: the first node visit refuses charge-before-work.
        reset_body_runs();
        let (result, _) = program.execute_budgeted(
            &ctx,
            Budget {
                work: 0,
                memory: u64::MAX,
            },
        );
        assert!(matches!(result, Err(ExecutionError::WorkBudgetExceeded(_))));
        assert_eq!(body_runs(), 0, "a refused node's body must not run");

        // With headroom the same body runs.
        reset_body_runs();
        let (result, _) = program.execute_budgeted(
            &ctx,
            Budget {
                work: 100,
                memory: u64::MAX,
            },
        );
        assert!(result.is_ok());
        assert!(body_runs() > 0);

        // Sized operations charge before their bodies too: a budget that
        // admits the operands' node visits but not the operation charge
        // must refuse without entering the operation body.
        let mut vars = Context::default();
        vars.add_variable_from_value("a", vec![1i64, 2]);
        vars.add_variable_from_value("b", vec![3i64, 4]);
        vars.add_variable_from_value("x", 1i64);
        for (src, budget) in [
            ("a == b", 3u64),
            ("x in b", 3u64),
            ("a + b", 3u64),
            // F3: literals charge from the borrowed elements before
            // copying them: 3 wu admits the node visits but not the
            // literal charge, so the copies must not run.
            ("[a, b]", 3u64),
            ("{'k': a}", 3u64),
        ] {
            let op = Program::compile(src).expect("compiles");
            reset_body_runs();
            let (result, _) = op.execute_budgeted(
                &vars,
                Budget {
                    work: budget,
                    memory: u64::MAX,
                },
            );
            assert!(
                matches!(result, Err(ExecutionError::WorkBudgetExceeded(_))),
                "{src}: expected work_budget, got {result:?}"
            );
            assert_eq!(op_bodies(), 0, "{src}: refused operation body must not run");

            reset_body_runs();
            let (result, _) = op.execute_budgeted(
                &vars,
                Budget {
                    work: 1_000,
                    memory: u64::MAX,
                },
            );
            assert!(result.is_ok(), "{src}: {result:?}");
            assert!(op_bodies() > 0, "{src}: operation body should run");
        }
    }

    /// The review's CPU case: `xs.all(i, rows == rows)` over 100 × 5k
    /// rows. Deep equality of the two 5k-row lists is charged per
    /// iteration, so 100 iterations exceed W = 2,000,000 wu and the
    /// evaluation is refused by the work meter, with no deep-walk or
    /// fuel guard involved.
    #[test]
    fn review_cpu_case_refused_by_work_budget() {
        use crate::{check, evaluate, Bindings, Policy};
        fn heavy_rows(n: usize) -> Vec<Value> {
            (0..n)
                .map(|i| {
                    let m: indexmap::IndexMap<String, i64> =
                        [("a", i), ("b", i), ("c", i), ("d", i)]
                            .into_iter()
                            .map(|(k, v)| (k.to_string(), v as i64))
                            .collect();
                    m.into()
                })
                .collect()
        }
        let mut bindings = Bindings::new();
        bindings.set("rows", heavy_rows(5000).into());
        bindings.set("xs", vec![Value::Int(0); 100].into());
        let prepared = check("xs.all(i, rows == rows)", &Policy::P0_INTERIM)
            .result
            .expect("check");
        let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
        assert!(
            matches!(report.result, Err(ExecutionError::WorkBudgetExceeded(_))),
            "expected work_budget, got {:?}",
            report.result
        );
    }

    /// F2: a latched `memory_budget` refusal is sticky — no `||`,
    /// `&&`, `all`, `exists` (or ternary/`exists_one`) may absorb it
    /// into a verdict. From the review's probes: 3,000 4-field rows
    /// are ~0.97 MB, so `[rows x30]` peaks at ~29 MB over P0's 8 MiB.
    fn heavy_rows_binding(n: usize) -> crate::Bindings {
        use crate::{Bindings, Value};
        let rows: Vec<Value> = (0..n)
            .map(|i| {
                let m: indexmap::IndexMap<String, i64> = ["a", "b", "c", "d"]
                    .into_iter()
                    .map(|k| (k.to_string(), i as i64))
                    .collect();
                Value::from(m)
            })
            .collect();
        let mut bindings = Bindings::new();
        bindings.set("rows", Value::from(rows));
        bindings
    }

    fn rows_times_30() -> String {
        format!("[{}]", vec!["rows"; 30].join(", "))
    }

    #[test]
    fn memory_refusal_not_absorbed_by_or() {
        use crate::{check, evaluate, ExecutionError, Policy};
        let bindings = heavy_rows_binding(3000);
        let src = format!("{}.size() > 0 || true", rows_times_30());
        let prepared = check(&src, &Policy::P0_INTERIM).result.expect("check");
        let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
        assert!(
            matches!(report.result, Err(ExecutionError::MemoryBudgetExceeded(_))),
            "|| must not absorb memory_budget, got {:?}",
            report.result
        );
    }

    #[test]
    fn memory_refusal_not_absorbed_by_and() {
        use crate::{check, evaluate, ExecutionError, Policy};
        let bindings = heavy_rows_binding(3000);
        let src = format!("{}.size() < 0 && false", rows_times_30());
        let prepared = check(&src, &Policy::P0_INTERIM).result.expect("check");
        let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
        assert!(
            matches!(report.result, Err(ExecutionError::MemoryBudgetExceeded(_))),
            "&& must not absorb memory_budget, got {:?}",
            report.result
        );
    }

    #[test]
    fn memory_refusal_not_absorbed_by_all() {
        use crate::{check, evaluate, ExecutionError, Policy};
        let bindings = heavy_rows_binding(3000);
        let src = format!(
            "[0, 1].all(i, i == 1 ? false : {}.size() < 0)",
            rows_times_30()
        );
        let prepared = check(&src, &Policy::P0_INTERIM).result.expect("check");
        let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
        assert!(
            matches!(report.result, Err(ExecutionError::MemoryBudgetExceeded(_))),
            "all must not absorb memory_budget, got {:?}",
            report.result
        );
    }

    #[test]
    fn memory_refusal_not_absorbed_by_exists() {
        use crate::{check, evaluate, ExecutionError, Policy, Value};
        let mut bindings = heavy_rows_binding(3000);
        bindings.set("xs2", Value::from(vec![Value::Int(0), Value::Int(1)]));
        let src = format!(
            "xs2.exists(i, i == 0 ? {}.size() < 0 : true)",
            rows_times_30()
        );
        let prepared = check(&src, &Policy::P0_INTERIM).result.expect("check");
        let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
        assert!(
            matches!(report.result, Err(ExecutionError::MemoryBudgetExceeded(_))),
            "exists must not absorb memory_budget, got {:?}",
            report.result
        );
    }

    /// Round 3: `charge_value`'s unmeasurable-value refusal latches
    /// like every other budget refusal, so no absorption site can
    /// turn it into a verdict. A stub value past the measurable cap
    /// exercises the latch path directly (it is unreachable through
    /// the public API after F1 narrowed the generic comprehension to
    /// `exists_one` over ints).
    #[test]
    fn unmeasurable_value_refusal_latches() {
        use crate::common::types::{Type, INT_TYPE};
        use crate::common::value::Val;
        #[derive(Debug)]
        struct Huge;
        impl Val for Huge {
            fn get_type(&self) -> &Type {
                &INT_TYPE
            }
            fn cached_nodes(&self) -> u64 {
                3_000_000
            }
            fn clone_as_boxed(&self) -> Box<dyn Val> {
                Box::new(Huge)
            }
        }
        clear();
        install(Budget {
            work: u64::MAX,
            memory: u64::MAX,
        });
        let huge = Huge;
        let result = crate::objects::charge_value(&huge);
        assert!(
            matches!(result, Err(ExecutionError::MemoryBudgetExceeded(_))),
            "expected memory_budget, got {result:?}"
        );
        // Latched: even a zero-byte charge now fails.
        assert!(
            matches!(
                charge_memory(0),
                Err(ExecutionError::MemoryBudgetExceeded(_))
            ),
            "the refusal must be sticky"
        );
        clear();
    }

    /// `all`/`exists` short-circuit: the determining element returns
    /// before the iteration's `set_level`, so the fold must restore the
    /// level itself.
    #[test]
    fn absorbing_fold_short_circuit_restores_level() {
        clear();
        install(Budget {
            work: u64::MAX,
            memory: u64::MAX,
        });
        let ctx = rows_ctx(&["aaaa", "bbbb", "cccc"]);
        let program =
            Program::compile("rows.exists(r, (r + 'yyyyyyyy').size() > 0)").expect("compiles");
        let entry = level();
        let _ = Value::resolve_val(program.expression(), &ctx).expect("eval");
        let after = level();
        let h = high_water();
        clear();
        assert!(h > entry, "the concat temporary raised the level");
        assert_eq!(
            after,
            entry + 2 * crate::charges::node_visit().memory,
            "only comprehension and range node charges survive"
        );
    }

    /// Increment 7 (U10) recognises the in-place `@result + [e]` step,
    /// so `map` over 5,000 rows is linear again and passes under
    /// `P0_INTERIM` (it was refused by `work_budget` after increment 5
    /// wired U7's fresh-`l + r` charge for the accumulator).
    #[test]
    fn map_over_five_thousand_rows_passes_under_p0() {
        use crate::{check, evaluate, Bindings, Policy};
        let rows: Vec<String> = (0..5000).map(|i| format!("row{i}")).collect();
        let mut bindings = Bindings::new();
        bindings.set("rows", rows.into());
        let prepared = check("rows.map(r, r)", &Policy::P0_INTERIM)
            .result
            .expect("check");
        let report = evaluate(&prepared, &bindings, &Policy::P0_INTERIM);
        assert!(
            report.result.is_ok(),
            "expected pass: {}",
            report.result.is_err()
        );
    }

    // --- U10 linearity -------------------------------------------------

    fn work_of(src: &str, bindings: &crate::Bindings) -> u64 {
        use crate::{check, evaluate, Policy};
        let prepared = check(src, &Policy::P0_INTERIM).result.expect("check");
        let report = evaluate(&prepared, bindings, &Policy::P0_INTERIM);
        assert!(
            report.result.is_ok(),
            "{src} failed: {}",
            report.result.is_err()
        );
        report.cost.work
    }

    /// `xs.map(x, x*2)` and `rows.filter(r, r.ok)` at 1k/2k/4k/8k:
    /// the work increments must be identical (exactly linear).
    #[test]
    fn map_and_filter_work_is_exactly_linear() {
        use crate::{Bindings, Value};
        let sizes = [1000usize, 2000, 4000, 8000];

        let mut xs_work = Vec::new();
        for n in sizes {
            let xs: Vec<Value> = (0..n as i64).map(Value::Int).collect();
            let mut b = Bindings::new();
            b.set("xs", xs.into());
            xs_work.push(work_of("xs.map(x, x * 2)", &b));
        }
        let (w1, w2, w4, w8) = (xs_work[0], xs_work[1], xs_work[2], xs_work[3]);
        let per_1k = w2 - w1;
        assert_eq!(
            w4 - w2,
            2 * per_1k,
            "map work must be exactly linear: {xs_work:?}"
        );
        assert_eq!(
            w8 - w4,
            4 * per_1k,
            "map work must be exactly linear: {xs_work:?}"
        );

        let mut rows_work = Vec::new();
        for n in sizes {
            let rows: Vec<Value> = (0..n)
                .map(|i| {
                    let m: indexmap::IndexMap<String, bool> = [("ok", i % 2 == 0)]
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect();
                    m.into()
                })
                .collect();
            let mut b = Bindings::new();
            b.set("rows", rows.into());
            rows_work.push(work_of("rows.filter(r, r.ok)", &b));
        }
        let (r1, r2, r4, r8) = (rows_work[0], rows_work[1], rows_work[2], rows_work[3]);
        let per_1k = r2 - r1;
        assert_eq!(
            r4 - r2,
            2 * per_1k,
            "filter work must be exactly linear: {rows_work:?}"
        );
        assert_eq!(
            r8 - r4,
            4 * per_1k,
            "filter work must be exactly linear: {rows_work:?}"
        );
    }

    /// `@` is not an identifier character, so user text cannot observe
    /// or alias the macro accumulator.
    #[test]
    fn user_text_cannot_name_the_accumulator() {
        use crate::{check, Policy};
        for src in ["@result", "[1].map(@r, @r + 1)", "@result + [1]"] {
            assert!(
                check(src, &Policy::P0_INTERIM).result.is_err(),
                "{src} must not parse"
            );
        }
    }

    /// Wall-clock linearity (release): `#[ignore]` so it is not in the
    /// default run. Run with
    /// `cargo test --release -p cel-subset linearity_wall_time -- --ignored --nocapture`.
    /// Best of 3 runs per size (N2: a single sub-millisecond sample is
    /// noisy); the gate is 2x linear (32 for 16k/1k). The exact
    /// work-unit gate is `map_and_filter_work_is_exactly_linear`.
    #[test]
    #[ignore = "wall-clock check; run in release with --ignored"]
    fn linearity_wall_time() {
        use crate::{check, evaluate, Bindings, Policy, Value};
        use std::time::{Duration, Instant};
        let xs_1k: Vec<Value> = (0..1000).map(Value::Int).collect();
        let xs_16k: Vec<Value> = (0..16000).map(Value::Int).collect();
        let p1 = check("xs.map(x, x * 2)", &Policy::P0_INTERIM)
            .result
            .unwrap();
        let p16 = check("xs.map(x, x * 2)", &Policy::P0_INTERIM)
            .result
            .unwrap();
        let mut b1 = Bindings::new();
        b1.set("xs", xs_1k.into());
        let mut b16 = Bindings::new();
        b16.set("xs", xs_16k.into());
        fn best_of_3(prepared: &crate::Prepared, bindings: &crate::Bindings) -> Duration {
            (0..3)
                .map(|_| {
                    let t = Instant::now();
                    let _ = evaluate(prepared, bindings, &Policy::P0_INTERIM);
                    t.elapsed()
                })
                .min()
                .unwrap_or_default()
        }
        let d1 = best_of_3(&p1, &b1);
        let d16 = best_of_3(&p16, &b16);
        let ratio = d16.as_secs_f64() / d1.as_secs_f64().max(1e-9);
        eprintln!("map wall time t(1k)={d1:?} t(16k)={d16:?} ratio={ratio:.2}");
        assert!(ratio <= 32.0, "t(16k)/t(1k) = {ratio:.2} > 32");
    }

    // --- D1: deterministic map order -----------------------------------

    #[test]
    fn map_literal_iteration_follows_source_order() {
        use crate::{check, evaluate, Bindings, Policy, Value};
        let prepared = check("{'b': 1, 'a': 2}.map(k, k)", &Policy::P0_INTERIM)
            .result
            .expect("check");
        let report = evaluate(&prepared, &Bindings::new(), &Policy::P0_INTERIM);
        assert_eq!(
            report.result.unwrap(),
            Value::List(std::sync::Arc::new(vec![
                Value::String(std::sync::Arc::new("b".to_string())),
                Value::String(std::sync::Arc::new("a".to_string())),
            ]))
        );
    }

    #[test]
    fn map_equality_is_order_insensitive() {
        use crate::{check, evaluate, Bindings, Policy, Value};
        let prepared = check("{'a': 1, 'b': 2} == {'b': 2, 'a': 1}", &Policy::P0_INTERIM)
            .result
            .expect("check");
        let report = evaluate(&prepared, &Bindings::new(), &Policy::P0_INTERIM);
        assert_eq!(report.result.unwrap(), Value::Bool(true));
    }

    /// `exists` over a map short-circuits at the first determining key,
    /// which is the first inserted key — a deterministic stopping point.
    #[test]
    fn map_exists_stops_at_first_key() {
        use crate::{check, evaluate, Bindings, Policy};
        let prepared = |src: &str| check(src, &Policy::P0_INTERIM).result.expect("check");
        let early = evaluate(
            &prepared("{'a': 1, 'b': 2, 'c': 3}.exists(k, k == 'a')"),
            &Bindings::new(),
            &Policy::P0_INTERIM,
        );
        let late = evaluate(
            &prepared("{'a': 1, 'b': 2, 'c': 3}.exists(k, k == 'c')"),
            &Bindings::new(),
            &Policy::P0_INTERIM,
        );
        assert!(early.result.is_ok() && late.result.is_ok());
        assert!(
            early.cost.work < late.cost.work,
            "the first inserted key must be reached first ({} vs {})",
            early.cost.work,
            late.cost.work
        );
    }

    // --- review CPU/memory cases ---------------------------------------

    /// `.map(x, [x, x, x, x])` nested within the L0 frame cap until
    /// the accumulator exceeds 8 MiB is
    /// refused by `memory_budget`, never by a panic or stack overflow.
    #[test]
    fn nested_mapdoubling_refused_by_memory_budget() {
        use crate::ExecutionError;
        use crate::{check, evaluate, Bindings, Policy};
        let mut saw_ok = false;
        let mut saw_refusal = false;
        for n in 1..=11usize {
            let mut expr = "[0]".to_string();
            for _ in 0..n {
                expr = format!("{expr}.map(x, [x, x, x, x])");
            }
            let prepared = check(&expr, &Policy::P0_INTERIM)
                .result
                .unwrap_or_else(|e| panic!("n={n}: check refused: {e}"));
            match evaluate(&prepared, &Bindings::new(), &Policy::P0_INTERIM).result {
                Ok(_) => {
                    assert!(!saw_refusal, "n={n}: ok after a refusal");
                    saw_ok = true;
                }
                Err(ExecutionError::MemoryBudgetExceeded(_)) => saw_refusal = true,
                Err(e) => panic!("n={n}: expected memory_budget, got {e:?}"),
            }
        }
        assert!(
            saw_ok && saw_refusal,
            "expected a flip from ok to memory_budget within the L0 cap"
        );
    }

    /// Historical deep sweep: these sources now exceed the L0 frame cap.
    /// They must refuse before evaluation; run with `--ignored`.
    #[test]
    #[ignore = "full mapdoubling sweep to n=22; slow in debug"]
    fn nested_mapdoubling_full_sweep() {
        use crate::{check, Policy};
        for n in 19..=22usize {
            let mut expr = "[0]".to_string();
            for _ in 0..n {
                expr = format!("{expr}.map(x, [x, x])");
            }
            let report = check(&expr, &Policy::P0_INTERIM);
            assert!(report.result.is_err(), "n={n}: expected source refusal");
        }
    }

    // --- review F3 memory high-water shapes ---------------------------

    fn rows_ctx(rows: &[&str]) -> Context<'static> {
        let mut ctx = Context::default();
        ctx.add_variable_from_value("rows", rows.to_vec());
        ctx
    }

    /// Shape 1: per-iteration concatenation under `all`. `all` keeps no
    /// accumulator, so the level falls back at every iteration end and
    /// H is independent of the number of rows.
    #[test]
    fn high_water_independent_of_row_count_under_all() {
        let small = eval_cost_with(
            "rows.all(r, (r + 'y').size() > 0)",
            rows_ctx(&["aaaa", "bbbb", "cccc"]),
        )
        .1
        .memory;
        let large_rows: Vec<String> = (0..300).map(|i| format!("r{i:03}")).collect();
        let refs: Vec<&str> = large_rows.iter().map(|s| s.as_str()).collect();
        let large = eval_cost_with("rows.all(r, (r + 'y').size() > 0)", rows_ctx(&refs))
            .1
            .memory;
        assert_eq!(
            small, large,
            "all keeps no accumulator, so H must not grow with n"
        );
    }

    /// Shape 2: `map` keeps its list, so memory (and H) grows with the
    /// number of rows.
    #[test]
    fn high_water_grows_with_kept_list_under_map() {
        let small = eval_cost_with("rows.map(r, r)", rows_ctx(&["aaaa", "bbbb", "cccc"]))
            .1
            .memory;
        let large_rows: Vec<String> = (0..60).map(|i| format!("r{i:03}")).collect();
        let refs: Vec<&str> = large_rows.iter().map(|s| s.as_str()).collect();
        let large = eval_cost_with("rows.map(r, r)", rows_ctx(&refs)).1.memory;
        assert!(large > small, "kept accumulator must grow H with n");
    }

    /// Shape 3: `exists_one` with a large predicate temporary. The
    /// temporary is built and dropped inside every iteration, so H is
    /// the one-iteration peak and does not grow with the row count.
    #[test]
    fn high_water_bounded_under_exists_one_with_large_temporaries() {
        let src = "rows.exists_one(r, (r + 'yyyyyyyyyyyyyyyy').size() > 3)";
        let small = eval_cost_with(src, rows_ctx(&["aaaa", "bbbb", "cccc"]))
            .1
            .memory;
        let large_rows: Vec<String> = (0..300).map(|i| format!("r{i:03}")).collect();
        let refs: Vec<&str> = large_rows.iter().map(|s| s.as_str()).collect();
        let large = eval_cost_with(src, rows_ctx(&refs)).1.memory;
        assert_eq!(
            small, large,
            "exists_one's temporary is dropped each iteration, so H is the peak"
        );
    }

    /// Nested concatenation under `map`. The per-iteration
    /// intermediates are recorded even though the iteration ends with
    /// only the accumulator retained.
    #[test]
    fn high_water_records_in_iteration_peak_under_map() {
        let flat = eval_cost_with("rows.map(r, r + 'y')", rows_ctx(&["aaaa", "bbbb", "cccc"]))
            .1
            .memory;
        let nested = eval_cost_with(
            "rows.map(r, (r + 'y') + (r + 'z'))",
            rows_ctx(&["aaaa", "bbbb", "cccc"]),
        )
        .1
        .memory;
        assert!(
            nested > flat,
            "H must capture the second intermediate built inside each iteration"
        );
    }
}
