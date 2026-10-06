//! `cel-subset@1` allowlist (PR 1a, review F1, design §1.3).
//!
//! `check` refuses any function or macro call that is not on this
//! list, naming it. A built-in without a borrowed (`&dyn Val`)
//! implementation and a declared charge row is not in the subset
//! (§1.3) — notably `optional.*`, `.value()` and `.orValue()`, which
//! deep-copy aggregates with no charge — so it is refused at save
//! rather than evaluated.

use crate::common::ast::operators;
use crate::common::ast::{EntryExpr, Expr, IdedExpr};

/// Every `Call` func_name admitted by [`check_expression`]: the
/// §1.3 built-ins the subset uses, the macros, and the operators
/// (internal names). One place: both `check` and the registry test
/// below read this list.
pub(crate) const ALLOWLIST: &[&str] = &[
    // §1.3 built-ins: predicates, conversions, time.
    "min",
    "max",
    "size",
    "contains",
    "startsWith",
    "endsWith",
    "matches",
    "int",
    "uint",
    "double",
    "string",
    "bytes",
    "timestamp",
    "duration",
    "dyn",
    // §1.3 timestamp and duration accessors.
    "getFullYear",
    "getMonth",
    "getDayOfYear",
    "getDayOfMonth",
    "getDate",
    "getDayOfWeek",
    "getHours",
    "getMinutes",
    "getSeconds",
    "getMilliseconds",
    // Macros (expand at parse; listed so the subset is explicit).
    "has",
    "all",
    "exists",
    "exists_one",
    "map",
    "filter",
    // Operators (internal names).
    operators::CONDITIONAL,
    operators::LOGICAL_AND,
    operators::LOGICAL_OR,
    operators::LOGICAL_NOT,
    operators::SUBSTRACT,
    operators::ADD,
    operators::MULTIPLY,
    operators::DIVIDE,
    operators::MODULO,
    operators::EQUALS,
    operators::NOT_EQUALS,
    operators::GREATER_EQUALS,
    operators::LESS_EQUALS,
    operators::GREATER,
    operators::LESS,
    operators::NEGATE,
    operators::INDEX,
    operators::NOT_STRICTLY_FALSE,
    operators::IN,
];

/// Registered built-ins deliberately outside the subset: refused by
/// `check` (see [`check_expression`]). `optional.*` deep-copies
/// aggregates with no charge (review F1); `type` has no subset use.
/// Test-only: production `check` needs just the allowlist above.
/// `#[cfg(test)]` keeps `cargo check` warning-free.
#[cfg(test)]
pub(crate) const OUT_OF_SUBSET: &[&str] = &[
    "optional.none",
    "optional.of",
    "optional.ofNonZeroValue",
    "value",
    "hasValue",
    "or",
    "orValue",
    "type",
];

pub(crate) fn is_allowed(name: &str) -> bool {
    ALLOWLIST.contains(&name)
}

/// Refuse the first call whose function is not allowlisted, naming
/// it. A call through an identifier target (e.g. `optional.of(x)`)
/// is judged by both the bare and the qualified name, so member
/// calls on ordinary variables (`s.contains(t)`) still pass while
/// qualified built-ins outside the subset do not.
pub(crate) fn check_expression(expr: &IdedExpr) -> Result<(), String> {
    walk(expr)
}

fn walk(e: &IdedExpr) -> Result<(), String> {
    match &e.expr {
        Expr::Call(call) => {
            let qualified = match &call.target {
                Some(t) => match &t.expr {
                    Expr::Ident(prefix) => Some(format!("{prefix}.{}", call.func_name)),
                    _ => None,
                },
                None => None,
            };
            let admitted =
                is_allowed(&call.func_name) || qualified.as_ref().is_some_and(|q| is_allowed(q));
            if !admitted {
                let name = qualified.unwrap_or_else(|| call.func_name.clone());
                return Err(format!("function '{name}' is not in cel-subset@1"));
            }
            if let Some(t) = &call.target {
                walk(t)?;
            }
            for a in &call.args {
                walk(a)?;
            }
            Ok(())
        }
        Expr::Select(s) => walk(&s.operand),
        Expr::List(l) => l.elements.iter().try_for_each(walk),
        Expr::Map(m) => m.entries.iter().try_for_each(|entry| match &entry.expr {
            EntryExpr::MapEntry(me) => walk(&me.key).and_then(|_| walk(&me.value)),
            EntryExpr::StructField(f) => walk(&f.value),
        }),
        Expr::Struct(s) => s.entries.iter().try_for_each(|entry| match &entry.expr {
            EntryExpr::StructField(f) => walk(&f.value),
            EntryExpr::MapEntry(me) => walk(&me.key).and_then(|_| walk(&me.value)),
        }),
        Expr::Comprehension(c) => walk(&c.iter_range)
            .and_then(|_| walk(&c.accu_init))
            .and_then(|_| walk(&c.loop_cond))
            .and_then(|_| walk(&c.loop_step))
            .and_then(|_| walk(&c.result)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_builtins_are_refused_by_name() {
        use crate::{check, Policy};
        for (src, name) in [
            ("optional.of(1) == 1", "optional.of"),
            ("optional.none() == 1", "optional.none"),
            ("optional.ofNonZeroValue(0) == 1", "optional.ofNonZeroValue"),
            ("optional.of(1).value() == 1", "value"),
            ("optional.of(1).hasValue()", "hasValue"),
            ("optional.of(1).orValue(2) == 1", "orValue"),
            ("type(1) == int", "type"),
        ] {
            let report = check(src, &Policy::P0_INTERIM);
            let err = report.result.expect_err(&format!("{src} must be refused"));
            assert!(
                err.to_string().contains(name),
                "{src}: refusal must name '{name}': {err}"
            );
        }
    }

    /// Every registered stdlib built-in is either allowlisted or
    /// refused by `check`: a newly registered built-in without an
    /// allowlist entry fails this test.
    #[test]
    fn registry_reachable_only_if_allowlisted() {
        use crate::Env;
        let mut registered = Env::stdlib().function_names();
        registered.sort();
        let mut unexpected: Vec<&str> = Vec::new();
        for name in &registered {
            if !is_allowed(name) && !OUT_OF_SUBSET.contains(&name.as_str()) {
                unexpected.push(name);
            }
        }
        assert!(
            unexpected.is_empty(),
            "registered built-ins outside the allowlist: {unexpected:?}"
        );
        let mut missing: Vec<&&str> = Vec::new();
        for name in OUT_OF_SUBSET {
            if !registered.iter().any(|r| r == name) {
                missing.push(name);
            }
        }
        assert!(
            missing.is_empty(),
            "OUT_OF_SUBSET names no longer registered: {missing:?}"
        );
    }

    /// Reviewer F12: every allowlist entry must resolve at
    /// evaluation — no entry may pass `check` only to fail with
    /// `UndeclaredReference`. Each entry is exercised by a probe;
    /// the probe must evaluate (an `UndeclaredReference` fails the
    /// test even where the probe's value is not asserted exactly).
    #[test]
    fn every_allowlisted_entry_resolves_at_evaluation() {
        use crate::{check, evaluate, Bindings, ExecutionError, Policy};
        for (entry, src) in [
            ("size", "size([1, 2]) == 2"),
            ("contains", "[1, 2].contains(1)"),
            ("contains", "'abc'.contains('b')"),
            ("startsWith", "'abc'.startsWith('a')"),
            ("endsWith", "'abc'.endsWith('c')"),
            ("matches", "'ab'.matches('b')"),
            ("int", "int('12') == 12"),
            ("uint", "uint('12') == 12u"),
            ("double", "double('1.5') == 1.5"),
            ("string", "string(1) == '1'"),
            ("bytes", "bytes('ab') == b'ab'"),
            (
                "timestamp",
                "timestamp('2024-01-01T00:00:00Z').getFullYear() == 2024",
            ),
            ("duration", "duration('60s') == duration('60s')"),
            ("dyn", "dyn(1) == 1"),
            (
                "getFullYear",
                "timestamp('2024-01-01T00:00:00Z').getFullYear() == 2024",
            ),
            (
                "getMonth",
                "timestamp('2024-06-15T00:00:00Z').getMonth() == 5",
            ),
            (
                "getDayOfYear",
                "timestamp('2024-01-01T00:00:00Z').getDayOfYear() == 1",
            ),
            (
                "getDayOfMonth",
                "timestamp('2024-01-15T00:00:00Z').getDayOfMonth() == 15",
            ),
            (
                "getDate",
                "timestamp('2024-01-15T00:00:00Z').getDate() == 15",
            ),
            (
                "getDayOfWeek",
                "timestamp('2024-01-01T00:00:00Z').getDayOfWeek() == 1",
            ),
            (
                "getHours",
                "timestamp('2024-01-01T02:00:00Z').getHours() == 2",
            ),
            (
                "getMinutes",
                "timestamp('2024-01-01T00:05:00Z').getMinutes() == 5",
            ),
            ("getSeconds", "duration('60s').getSeconds() == 0"),
            (
                "getMilliseconds",
                "timestamp('2024-01-01T00:00:00.123Z').getMilliseconds() == 123",
            ),
            ("has", "has({'a': 1}.a)"),
            ("all", "[1].all(x, x > 0)"),
            ("exists", "[1].exists(x, x > 0)"),
            ("exists_one", "[1].exists_one(x, x > 0)"),
            ("map", "[1].map(x, x + 1) == [2]"),
            ("filter", "[1].filter(x, x > 0) == [1]"),
            (operators::CONDITIONAL, "true ? 1 : 2"),
            (operators::LOGICAL_AND, "true && true"),
            (operators::LOGICAL_OR, "false || true"),
            (operators::LOGICAL_NOT, "!false"),
            (operators::SUBSTRACT, "3 - 1 == 2"),
            (operators::ADD, "1 + 2 == 3"),
            (operators::MULTIPLY, "2 * 3 == 6"),
            (operators::DIVIDE, "6 / 2 == 3"),
            (operators::MODULO, "5 % 2 == 1"),
            (operators::EQUALS, "1 == 1"),
            (operators::NOT_EQUALS, "1 != 2"),
            (operators::GREATER_EQUALS, "2 >= 2"),
            (operators::LESS_EQUALS, "1 <= 2"),
            (operators::GREATER, "2 > 1"),
            (operators::LESS, "1 < 2"),
            (operators::NEGATE, "-1 < 0"),
            (operators::INDEX, "[7][0] == 7"),
            (operators::NOT_STRICTLY_FALSE, "[1].exists(x, x == 1)"),
            (operators::IN, "1 in [1, 2]"),
        ] {
            assert!(
                is_allowed(entry),
                "probe entry '{entry}' must be allowlisted"
            );
            let prepared = check(src, &Policy::P0_INTERIM)
                .result
                .unwrap_or_else(|e| panic!("{entry}: {src} must be admitted: {e}"));
            let report = evaluate(&prepared, &Bindings::new(), &Policy::P0_INTERIM);
            assert!(
                !matches!(report.result, Err(ExecutionError::UndeclaredReference(_))),
                "{entry}: {src} must resolve, got {:?}",
                report.result
            );
        }
    }

    #[test]
    fn subset_builtins_are_admitted() {
        use crate::{check, Policy};
        for src in [
            "size([1, 2]) == 2",
            "[1, 2].size() == 2",
            "'abc'.contains('b')",
            "'abc'.startsWith('a')",
            "'abc'.endsWith('c')",
            "'ab'.matches('b')",
            "int('1') == 1",
            "uint('1') == 1u",
            "double('1.5') == 1.5",
            "string(1) == '1'",
            "bytes('ab') == b'ab'",
            "dyn(1) == 1",
            "[1].all(x, x > 0)",
            "[1].exists(x, x > 0)",
            "[1].exists_one(x, x > 0)",
            "[1].map(x, x + 1) == [2]",
            "[1].filter(x, x > 0) == [1]",
            "has({'a': 1}.a)",
            "1 in [1, 2]",
            "timestamp('2024-01-01T00:00:00Z').getFullYear() > 2000",
            "duration('60s').getSeconds() == 0",
        ] {
            assert!(
                check(src, &Policy::P0_INTERIM).result.is_ok(),
                "{src} must be admitted"
            );
        }
    }
}
