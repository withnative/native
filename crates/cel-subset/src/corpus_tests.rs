//! Corpus runner (increment 10a): every case through the public
//! [`crate::check`]/[`crate::evaluate`] under `P0_INTERIM`.
//!
//! The corpus is the spike's 225-case set (`tests/corpus/*.json`), kept
//! as test data. Expected values use the tagged encoding documented in
//! `tests/corpus/README.md`; errors are compared by cel-spec category.

use std::sync::Arc;

use serde_json::Value as J;

use crate::objects::{Key, Map};
use crate::{check, evaluate, Bindings, ExecutionError, Policy, Value};

const CORPUS: &[(&str, &str)] = &[
    (
        "aggregates",
        include_str!("../tests/corpus/aggregates.json"),
    ),
    ("arith", include_str!("../tests/corpus/arith.json")),
    ("compare", include_str!("../tests/corpus/compare.json")),
    (
        "double_special",
        include_str!("../tests/corpus/double_special.json"),
    ),
    ("logic", include_str!("../tests/corpus/logic.json")),
    ("macros", include_str!("../tests/corpus/macros.json")),
    (
        "macros_rows",
        include_str!("../tests/corpus/macros_rows.json"),
    ),
    ("map_keys", include_str!("../tests/corpus/map_keys.json")),
    ("null", include_str!("../tests/corpus/null.json")),
    (
        "numeric_edges",
        include_str!("../tests/corpus/numeric_edges.json"),
    ),
    ("strings", include_str!("../tests/corpus/strings.json")),
    (
        "strings_astral",
        include_str!("../tests/corpus/strings_astral.json"),
    ),
    ("time", include_str!("../tests/corpus/time.json")),
];

fn tagged(v: &J) -> Value {
    let o = v
        .as_object()
        .unwrap_or_else(|| panic!("not a tagged object: {v}"));
    if let Some(J::String(s)) = o.get("int") {
        return Value::Int(s.parse().expect("int"));
    }
    if let Some(J::String(s)) = o.get("uint") {
        return Value::UInt(s.parse().expect("uint"));
    }
    if let Some(d) = o.get("double") {
        return Value::Float(match d {
            J::Number(n) => n.as_f64().expect("double"),
            J::String(s) => match s.as_str() {
                "NaN" => f64::NAN,
                "+Inf" | "Inf" | "Infinity" => f64::INFINITY,
                "-Inf" | "-Infinity" => f64::NEG_INFINITY,
                "-0" => -0.0,
                other => other.parse().expect("double"),
            },
            _ => panic!("bad double tag: {d}"),
        });
    }
    if let Some(J::String(s)) = o.get("string") {
        return Value::String(Arc::new(s.clone()));
    }
    if let Some(J::Bool(b)) = o.get("bool") {
        return Value::Bool(*b);
    }
    if o.contains_key("null") {
        return Value::Null;
    }
    if let Some(J::Array(a)) = o.get("list") {
        return Value::List(Arc::new(a.iter().map(tagged).collect()));
    }
    if let Some(J::Array(a)) = o.get("map") {
        let mut m = indexmap::IndexMap::new();
        for pair in a {
            let p = pair.as_array().expect("map pair");
            m.insert(tagged_key(&p[0]), tagged(&p[1]));
        }
        return Value::Map(Map { map: Arc::new(m) });
    }
    panic!("unknown tagged value: {v}");
}

fn tagged_key(v: &J) -> Key {
    match tagged(v) {
        Value::Int(i) => Key::from(i),
        Value::UInt(u) => Key::from(u),
        Value::String(s) => Key::from((*s).clone()),
        Value::Bool(b) => Key::from(b),
        other => panic!("unsupported map key: {other:?}"),
    }
}

/// Value equality with the corpus's special-double convention.
fn value_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) if x.is_nan() && y.is_nan() => true,
        _ => a == b,
    }
}

/// Map a typed evaluation error to the corpus's cel-spec category.
fn category(e: &ExecutionError) -> &'static str {
    use ExecutionError::*;
    match e {
        NoSuchKey(_) => "no_such_key",
        DivisionByZero(_) => "division_by_zero",
        RemainderByZero(_) => "modulus_by_zero",
        Overflow(..) | UnaryOverflow(..) => "overflow",
        IndexOutOfBounds(_) | UnexpectedType { .. } => "invalid_argument",
        UnsupportedKeyType(_) => "bad_key_type",
        FunctionError { message, .. }
            if {
                let m = message.to_lowercase();
                // No "out of range" arm: its only producer is the
                // timestamp conversion, which has no corpus case; a
                // range error must stay `invalid_argument` (F7).
                m.contains("overflow") || m.contains("too large")
            } =>
        {
            "overflow"
        }
        FunctionError { .. } => "invalid_argument",
        UndeclaredReference(_) => "parse_error",
        _ => "no_matching_overload",
    }
}

/// A `check` refusal's corpus category. Out-of-range int/uint literals
/// are a parse-time refusal here but the corpus (with the spike's
/// runner) classifies them `overflow`.
fn check_category(err: &crate::ParseErrors) -> &'static str {
    let text = err.to_string().to_lowercase();
    if text.contains("invalid int literal") || text.contains("invalid uint literal") {
        "overflow"
    } else {
        "parse_error"
    }
}

#[test]
fn corpus_matches_expectations() {
    let mut failures: Vec<String> = Vec::new();
    let mut count = 0usize;

    for (group, src) in CORPUS {
        let cases: Vec<J> = serde_json::from_str(src).expect("corpus json");
        for case in cases {
            let name = case["name"].as_str().expect("name");
            let expr = case["expr"].as_str().expect("expr");
            let expect = &case["expect"];
            if expect.get("probe").and_then(J::as_bool).unwrap_or(false) {
                continue;
            }
            count += 1;

            let mut bindings = Bindings::new();
            if let Some(J::Object(bind)) = case.get("bindings") {
                for (k, v) in bind {
                    bindings.set(k, tagged(v));
                }
            }

            let exp_err = expect.get("error");
            let any_err = matches!(exp_err, Some(J::Bool(true)))
                || matches!(exp_err, Some(J::String(s)) if s == "any");
            let exp_cat = exp_err.and_then(J::as_str);

            let prepared = match check(expr, &Policy::P0_INTERIM).result {
                Ok(p) => p,
                Err(e) => {
                    // F7: a worker panic surfaces from `check` as
                    // "cel-subset worker failed" — never a category.
                    if e.to_string().contains("cel-subset worker failed") {
                        failures.push(format!("{group}/{name}: check worker failed: {e}"));
                        continue;
                    }
                    let cat = check_category(&e);
                    if any_err || exp_cat == Some(cat) {
                        continue;
                    }
                    failures.push(format!("{group}/{name}: check {cat} != {exp_cat:?}: {e}"));
                    continue;
                }
            };

            match evaluate(&prepared, &bindings, &Policy::P0_INTERIM).result {
                Ok(actual) => {
                    if let Some(ev) = expect.get("value") {
                        let expected = tagged(ev);
                        if !value_eq(&actual, &expected) {
                            failures.push(format!(
                                "{group}/{name}: got {actual:?}, expected {expected:?}"
                            ));
                        }
                    } else {
                        failures.push(format!("{group}/{name}: expected error, got {actual:?}"));
                    }
                }
                Err(e) => {
                    // F7: budget refusals, the depth assertion and
                    // worker panics are never corpus categories — fail
                    // loudly rather than mapping them to
                    // `no_matching_overload`, which would silently
                    // satisfy cases expecting that category.
                    if matches!(
                        e,
                        ExecutionError::WorkBudgetExceeded(_)
                            | ExecutionError::MemoryBudgetExceeded(_)
                            | ExecutionError::InternalLimit(_)
                            | ExecutionError::InternalError(_)
                    ) {
                        failures.push(format!(
                            "{group}/{name}: budget/internal error, not a verdict ({e})"
                        ));
                    } else {
                        let cat = category(&e);
                        if any_err || exp_cat == Some(cat) {
                            // ok
                        } else if let Some(exp) = exp_cat {
                            failures.push(format!("{group}/{name}: {cat} != {exp} ({e})"));
                        } else {
                            failures.push(format!("{group}/{name}: unexpected {cat} ({e})"));
                        }
                    }
                }
            }
        }
    }

    // 227 cases minus the 5 `probe` cases, which are skipped above
    // (225 from the spike plus the 2 N1 map-key-precedence cases).
    assert_eq!(count, 222, "expected the full corpus");
    assert!(
        failures.is_empty(),
        "{} case(s) differ from the corpus:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
