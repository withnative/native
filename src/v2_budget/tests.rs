//! Functional proofs for the gated budget arithmetic provider.
//!
//! These tests exercise the public `evaluate` surface, not private helpers.
//! They prove arithmetic and precedence, dependency traversal with
//! recalculation, rectangular `SUM`, forward references, the blank-cell rule,
//! deterministic missing/cycle/division failures, and every admission cap.

use super::*;

fn sheet(pairs: &[(&str, &str)]) -> Evaluated {
    evaluate(pairs.iter().copied()).expect("sheet should evaluate")
}

fn refusal(pairs: &[(&str, &str)]) -> BudgetError {
    evaluate(pairs.iter().copied()).expect_err("sheet should be refused")
}

fn refusal_owned(pairs: Vec<(String, String)>) -> BudgetError {
    evaluate(pairs).expect_err("sheet should be refused")
}

#[test]
fn arithmetic_precedence_and_associativity() {
    assert_eq!(sheet(&[("A1", "2+3*4")]).get("A1"), Some(14.0));
    assert_eq!(sheet(&[("A1", "=(2+3)*4")]).get("A1"), Some(20.0));
    assert_eq!(sheet(&[("A1", "20/4/5")]).get("A1"), Some(1.0));
    assert_eq!(sheet(&[("A1", "10-2-3")]).get("A1"), Some(5.0));
    assert_eq!(sheet(&[("A1", "-3+1")]).get("A1"), Some(-2.0));
    assert_eq!(sheet(&[("A1", "+5")]).get("A1"), Some(5.0));
    assert_eq!(sheet(&[("A1", "5")]).get("A1"), Some(5.0));
    assert_eq!(sheet(&[("A1", "=1.5+0.25")]).get("A1"), Some(1.75));
    assert_eq!(sheet(&[("A1", "=2*-3")]).get("A1"), Some(-6.0));
}

#[test]
fn reference_chain_recalculates_on_edit() {
    let first = sheet(&[("A1", "2"), ("B1", "=A1*3"), ("C1", "=B1+A1")]);
    assert_eq!(first.get("B1"), Some(6.0));
    assert_eq!(first.get("C1"), Some(8.0));

    // The same formulas against an edited input recalculate the whole chain.
    // No state survives between calls.
    let edited = sheet(&[("A1", "5"), ("B1", "=A1*3"), ("C1", "=B1+A1")]);
    assert_eq!(edited.get("B1"), Some(15.0));
    assert_eq!(edited.get("C1"), Some(20.0));
}

#[test]
fn forward_reference_resolves_and_shared_dependency_is_computed() {
    let forward = sheet(&[("A1", "=B1+1"), ("B1", "=3")]);
    assert_eq!(forward.get("A1"), Some(4.0));
    assert_eq!(forward.get("B1"), Some(3.0));

    let diamond = sheet(&[("A1", "=B1+C1"), ("B1", "=D1"), ("C1", "=D1"), ("D1", "2")]);
    assert_eq!(diamond.get("A1"), Some(4.0));
}

#[test]
fn sum_rectangular_range() {
    let rectangular = sheet(&[
        ("A1", "1"),
        ("A2", "2"),
        ("B1", "3"),
        ("B2", "4"),
        ("C1", "=SUM(A1:B2)"),
    ]);
    assert_eq!(rectangular.get("C1"), Some(10.0));

    assert_eq!(
        sheet(&[("A1", "7"), ("B1", "=SUM(A1:A1)")]).get("B1"),
        Some(7.0)
    );
    assert_eq!(
        sheet(&[("A1", "1"), ("A2", "2"), ("A3", "4"), ("B1", "=SUM(A1:A3)")]).get("B1"),
        Some(7.0)
    );
}

#[test]
fn sum_reversed_range_normalises_to_bounding_box() {
    let ev = sheet(&[
        ("A1", "1"),
        ("A2", "2"),
        ("B1", "3"),
        ("B2", "4"),
        ("C1", "=SUM(B2:A1)"),
    ]);
    assert_eq!(ev.get("C1"), Some(10.0));
}

#[test]
fn sum_wide_rectangular_range_within_member_cap() {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for letter in ["A", "B"] {
        for row in 1..=99 {
            pairs.push((format!("{letter}{row}"), "1".to_string()));
        }
    }
    pairs.push(("C1".to_string(), "=SUM(A1:B99)".to_string()));
    let ev = evaluate(pairs).expect("198-member range is within the cap");
    assert_eq!(ev.get("C1"), Some(198.0));
}

#[test]
fn sum_range_over_member_cap_is_refused_at_admission() {
    assert_eq!(
        refusal(&[("A1", "=SUM(A1:Z99)")]),
        BudgetError::RangeTooLarge {
            address: "A1".into(),
            members: 2574,
            max: MAX_RANGE_MEMBERS,
        }
    );
}

#[test]
fn missing_reference_is_refused() {
    assert_eq!(
        refusal(&[("A1", "=B1")]),
        BudgetError::MissingReference {
            address: "A1".into(),
            referenced: "B1".into(),
        }
    );
    assert_eq!(
        refusal(&[("A1", "1"), ("B1", "=SUM(A1:A2)")]),
        BudgetError::MissingReference {
            address: "B1".into(),
            referenced: "A2".into(),
        }
    );
}

#[test]
fn a_zero_cell_is_present_and_not_missing() {
    let ev = sheet(&[("A1", "1"), ("A2", "=0"), ("B1", "=A1+A2")]);
    assert_eq!(ev.get("B1"), Some(1.0));
}

#[test]
fn cycle_is_detected_deterministically() {
    assert_eq!(
        refusal(&[("A1", "=B1"), ("B1", "=A1")]),
        BudgetError::Cycle {
            chain: vec!["A1".into(), "B1".into(), "A1".into()],
        }
    );
    assert_eq!(
        refusal(&[("A1", "=A1+1")]),
        BudgetError::Cycle {
            chain: vec!["A1".into(), "A1".into()],
        }
    );
}

#[test]
fn division_by_zero_is_refused() {
    assert_eq!(
        refusal(&[("A1", "=1/0")]),
        BudgetError::DivisionByZero {
            address: "A1".into(),
        }
    );
    assert_eq!(
        refusal(&[("A1", "=1/(2-2)")]),
        BudgetError::DivisionByZero {
            address: "A1".into(),
        }
    );
}

#[test]
fn grid_boundary_and_lowercase_addresses_are_accepted() {
    let ev = sheet(&[("A1", "1"), ("Z99", "2")]);
    assert_eq!(ev.get("a1"), Some(1.0));
    assert_eq!(ev.get("z99"), Some(2.0));
}

#[test]
fn invalid_input_addresses_are_refused() {
    for raw in ["AA1", "A100", "A0", "1A", "A", "A1234", "A 1", "Z99x"] {
        assert!(
            matches!(refusal(&[(raw, "1")]), BudgetError::InvalidAddress { .. }),
            "raw key {raw:?} should be invalid"
        );
    }
}

#[test]
fn duplicate_normalised_address_is_refused() {
    assert_eq!(
        refusal(&[("A1", "1"), ("a01", "2")]),
        BudgetError::DuplicateAddress {
            address: "A1".into(),
        }
    );
}

#[test]
fn formula_is_case_insensitive_and_ignores_whitespace() {
    let ev = sheet(&[("A1", "1"), ("A2", "2"), ("B1", "= sum( a1 : a2 )")]);
    assert_eq!(ev.get("B1"), Some(3.0));
}

#[test]
fn too_many_cells_is_refused() {
    let mut pairs: Vec<(String, String)> = Vec::new();
    'outer: for letter in ["A", "B", "C"] {
        for row in 1..=99 {
            pairs.push((format!("{letter}{row}"), "1".to_string()));
            if pairs.len() == 257 {
                break 'outer;
            }
        }
    }
    assert_eq!(pairs.len(), 257);
    assert!(matches!(
        refusal_owned(pairs),
        BudgetError::TooManyCells {
            count: 257,
            max: MAX_CELLS
        }
    ));
}

#[test]
fn overlong_formula_is_refused_at_the_exact_cap() {
    let at_cap = format!("=1{}", " ".repeat(MAX_FORMULA_BYTES - 2));
    assert_eq!(at_cap.len(), MAX_FORMULA_BYTES);
    assert_eq!(sheet(&[("A1", at_cap.as_str())]).get("A1"), Some(1.0));

    let over = format!("=1{}", " ".repeat(MAX_FORMULA_BYTES - 1));
    assert_eq!(over.len(), MAX_FORMULA_BYTES + 1);
    assert_eq!(
        refusal(&[("A1", over.as_str())]),
        BudgetError::FormulaTooLong {
            address: "A1".into(),
            bytes: MAX_FORMULA_BYTES + 1,
            max: MAX_FORMULA_BYTES,
        }
    );
}

#[test]
fn aggregate_expression_bytes_is_refused() {
    // 70 cells x 1000 bytes = 70000 bytes, over the 64 KiB aggregate cap,
    // while every cell stays under the per-expression cap.
    let mut pairs: Vec<(String, String)> = Vec::new();
    for row in 1..=70 {
        pairs.push((format!("A{row}"), format!("=1{}", " ".repeat(998))));
    }
    assert!(matches!(
        refusal_owned(pairs),
        BudgetError::ExpressionsTooLarge { .. }
    ));
}

#[test]
fn token_cap_is_refused() {
    let value = format!("=1{}", "+1".repeat(200));
    assert!(matches!(
        refusal(&[("A1", value.as_str())]),
        BudgetError::TooManyTokens { .. }
    ));
}

#[test]
fn parser_nesting_depth_is_capped() {
    let over = format!(
        "={}1{}",
        "(".repeat(MAX_NESTING_DEPTH + 1),
        ")".repeat(MAX_NESTING_DEPTH + 1)
    );
    assert_eq!(
        refusal(&[("A1", over.as_str())]),
        BudgetError::NestingTooDeep {
            address: "A1".into(),
            depth: MAX_NESTING_DEPTH + 1,
            max: MAX_NESTING_DEPTH,
        }
    );

    let at_cap = format!(
        "={}1{}",
        "(".repeat(MAX_NESTING_DEPTH),
        ")".repeat(MAX_NESTING_DEPTH)
    );
    assert_eq!(sheet(&[("A1", at_cap.as_str())]).get("A1"), Some(1.0));

    let deep_unary = format!("={}1", "-".repeat(MAX_NESTING_DEPTH + 1));
    assert!(matches!(
        refusal(&[("A1", deep_unary.as_str())]),
        BudgetError::NestingTooDeep { .. }
    ));
}

#[test]
fn dependency_depth_is_capped_with_a_working_boundary() {
    // A 32-cell chain is allowed...
    let mut allowed: Vec<(String, String)> = Vec::new();
    for row in 1..=31 {
        allowed.push((format!("A{row}"), format!("=A{}", row + 1)));
    }
    allowed.push(("A32".to_string(), "7".to_string()));
    let ev = evaluate(allowed).expect("a 32-deep chain is within the cap");
    assert_eq!(ev.get("A1"), Some(7.0));

    // ...and a 33-deep chain is refused.
    let mut refused: Vec<(String, String)> = Vec::new();
    for row in 1..=32 {
        refused.push((format!("A{row}"), format!("=A{}", row + 1)));
    }
    refused.push(("A33".to_string(), "7".to_string()));
    assert!(matches!(
        refusal_owned(refused),
        BudgetError::DependencyTooDeep {
            max: MAX_DEPENDENCY_DEPTH,
            ..
        }
    ));
}

#[test]
fn nonfinite_results_are_refused() {
    let huge: String = "9".repeat(200);
    assert!(huge.parse::<f64>().expect("finite").is_finite());
    assert_eq!(
        refusal(&[
            ("A1", huge.as_str()),
            ("A2", huge.as_str()),
            ("B1", "=A1*A2"),
        ]),
        BudgetError::NonFiniteResult {
            address: "B1".into(),
        }
    );

    let overflow_literal = "9".repeat(400);
    assert_eq!(
        refusal(&[("A1", overflow_literal.as_str())]),
        BudgetError::NonFiniteResult {
            address: "A1".into(),
        }
    );
}

#[test]
fn nonfinite_intermediate_is_refused_not_silently_zero() {
    // A1 * A2 overflows to inf. Without an intermediate check, 1 / inf would
    // quietly evaluate to 0; finite-only arithmetic refuses instead.
    let huge: String = "9".repeat(200);
    assert_eq!(
        refusal(&[
            ("A1", huge.as_str()),
            ("A2", huge.as_str()),
            ("B1", "=1/(A1*A2)"),
        ]),
        BudgetError::NonFiniteResult {
            address: "B1".into(),
        }
    );
}

#[test]
fn malformed_expressions_are_refused() {
    for body in [
        "=",
        "=1+",
        "=(1+2",
        "=1 2",
        "=SUM(A1)",
        "=SUM A1",
        "=1..2",
        "=@",
        "=SUM(A1:A2:B3)",
        "=1+*2",
        "=()",
    ] {
        let outcome = refusal(&[("A1", body)]);
        assert!(
            matches!(outcome, BudgetError::MalformedSyntax { .. }),
            "body {body:?} should be malformed syntax, got {outcome:?}"
        );
    }
}

#[test]
fn empty_or_blank_cell_values_are_refused() {
    assert_eq!(
        refusal(&[("A1", "")]),
        BudgetError::MalformedSyntax {
            address: "A1".into(),
            detail: "empty expression".into(),
        }
    );
    assert!(matches!(
        refusal(&[("A1", "   ")]),
        BudgetError::MalformedSyntax { .. }
    ));
}

#[test]
fn empty_sheet_is_accepted() {
    let ev = evaluate(std::iter::empty::<(&str, &str)>()).expect("empty sheet is valid");
    assert!(ev.values().is_empty());
}
