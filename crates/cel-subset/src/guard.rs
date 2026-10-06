//! Required-when native seam. Prefix order is engine-owned checked metadata;
//! later adapters translate registry dependency/name order into this seam.
use crate::{
    api, Bindings, Bound, Declarations, EvalCost, ExecutionError, InputDecl, InputKind,
    ParseErrors, Policy, Prepared,
};

#[derive(Debug)]
pub struct PreparedGuard {
    input: String,
    prefix: Declarations,
    expression: Prepared,
}
impl PreparedGuard {
    pub fn input(&self) -> &str {
        &self.input
    }
    pub fn declarations(&self) -> &Declarations {
        &self.prefix
    }
    pub fn bound(&self) -> Bound {
        self.expression.bound()
    }
    #[cfg(any(test, feature = "native-proof-tools"))]
    pub(crate) fn native_aux(&self) -> crate::symbolic_control::Counts {
        self.expression.native_aux()
    }
}
#[derive(Debug)]
pub struct GuardCheckReport {
    pub policy_id: &'static str,
    pub interim: bool,
    pub load_cost: EvalCost,
    pub result: Result<PreparedGuard, ParseErrors>,
}
#[derive(Debug)]
pub struct GuardReport {
    pub policy_id: &'static str,
    pub interim: bool,
    pub budget_scope: &'static str,
    pub cost: EvalCost,
    pub input_cost: EvalCost,
    pub result: Result<bool, ExecutionError>,
}

/// Check one guard against the strictly earlier input prefix plus declared
/// scalar arguments. The pending input and every future input are unavailable.
pub fn check_guard(
    source: &str,
    input: &str,
    declarations: &Declarations,
    policy: &Policy,
) -> GuardCheckReport {
    check_guard_native(source, input, declarations, policy, true)
}
pub(crate) fn check_guard_native(
    source: &str,
    input: &str,
    declarations: &Declarations,
    policy: &Policy,
    admit: bool,
) -> GuardCheckReport {
    let mut load_cost = EvalCost::default();
    let result = (|| {
        declarations
            .validate_policy(policy)
            .map_err(|e| api::check_error(e.to_string()))?;
        let Some(index) = declarations.order.iter().position(|name| name == input) else {
            return Err(api::check_error("guard input is not declared".into()));
        };
        if declarations.entries.get(input) != Some(&InputKind::One) {
            return Err(api::check_error(
                "required_when guards require a one input".into(),
            ));
        }
        let prefix = Declarations::new(
            declarations.order[..index]
                .iter()
                .map(|name| InputDecl {
                    name: name.clone(),
                    kind: declarations.entries[name].clone(),
                })
                .chain(
                    declarations
                        .entries
                        .iter()
                        .filter(|(_, kind)| matches!(kind, InputKind::Scalar { .. }))
                        .map(|(name, kind)| InputDecl {
                            name: name.clone(),
                            kind: kind.clone(),
                        }),
                ),
            policy,
        )
        .map_err(|e| api::check_error(e.to_string()))?;
        let checked = api::check_guard_expression(source, &prefix, policy, admit);
        load_cost = checked.load_cost;
        let expression = checked.result?;
        let bound = expression.bound();
        let budget = policy.guard_budget();
        if admit && (bound.work > budget.work || bound.memory > budget.memory) {
            return Err(api::check_error_at(
                &expression.program,
                expression.program.expression().id,
                format!(
                    "guard_cost: work {}/{} memory {}/{}; project the prefix in SQL",
                    bound.work, budget.work, bound.memory, budget.memory
                ),
            ));
        }
        Ok((
            PreparedGuard {
                input: input.into(),
                prefix,
                expression,
            },
            checked.load_cost,
        ))
    })();
    match result {
        Ok((g, load_cost)) => GuardCheckReport {
            policy_id: policy.id(),
            interim: policy.interim(),
            load_cost,
            result: Ok(g),
        },
        Err(e) => GuardCheckReport {
            policy_id: policy.id(),
            interim: policy.interim(),
            load_cost,
            result: Err(e),
        },
    }
}
/// Revalidate the current COMPLETE prefix snapshot before conversion/body;
/// guards always use a fresh guard account, never a rule's remaining counters.
pub fn guard(prepared: &PreparedGuard, bindings: &Bindings, policy: &Policy) -> GuardReport {
    let report = api::evaluate_account(
        &prepared.expression,
        bindings,
        policy,
        policy.guard_budget(),
        "per-guard-call",
    );
    GuardReport {
        policy_id: report.policy_id,
        interim: report.interim,
        budget_scope: report.budget_scope,
        cost: report.cost,
        input_cost: report.input_cost,
        result: report.result.and_then(|v| match v {
            crate::Value::Bool(b) => Ok(b),
            _ => Err(ExecutionError::NoSuchOverload),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScalarType, Value};
    fn declarations() -> Declarations {
        Declarations::new(
            [
                InputDecl {
                    name: "z_first".into(),
                    kind: InputKind::One,
                },
                InputDecl {
                    name: "a_pending".into(),
                    kind: InputKind::One,
                },
                InputDecl {
                    name: "b_future".into(),
                    kind: InputKind::One,
                },
                InputDecl {
                    name: "flag".into(),
                    kind: InputKind::Scalar {
                        kind: ScalarType::Bool,
                        nullable: false,
                    },
                },
            ],
            &Policy::P0_INTERIM,
        )
        .unwrap()
    }
    #[test]
    fn union_field_regex_guard_refuses_from_payload_bound_before_preparation() {
        let policy = Policy::P0_INTERIM;
        let d = Declarations::new(
            ["one", "pending"].map(|name| InputDecl {
                name: name.into(),
                kind: InputKind::One,
            }),
            &policy,
        )
        .unwrap();
        let source = "(true?one:0).body.matches('x')";
        let checked = check_guard(source, "pending", &d, &policy);
        let error = checked.result.unwrap_err();
        assert!(error.to_string().contains("work_cost"), "{error}");
        let measured = check_guard_native(source, "pending", &d, &policy, false)
            .result
            .unwrap();
        assert!(measured.bound().work > policy.work_limit());
        let mut prefix = Bindings::empty(measured.declarations(), &policy);
        prefix
            .insert(
                "one",
                &Value::from(indexmap::IndexMap::from([(
                    "body".to_string(),
                    Value::from("x".repeat(131_072)),
                )])),
            )
            .unwrap();
        // Private candidate execution reproduces the old runtime failure, while
        // public check above now refuses before issuing a PreparedGuard.
        let runtime = guard(&measured, &prefix, &policy);
        assert!(matches!(
            runtime.result,
            Err(ExecutionError::WorkBudgetExceeded(_))
        ));
    }
    #[test]
    fn guards_pin_declared_order_and_validate_each_complete_prefix() {
        let d = declarations();
        let prepared = check_guard(
            "flag && z_first != null",
            "a_pending",
            &d,
            &Policy::P0_INTERIM,
        )
        .result
        .unwrap();
        assert_eq!(
            prepared.declarations().order.as_ref(),
            &vec!["z_first".to_string()]
        );
        assert!(
            check_guard("a_pending==null", "a_pending", &d, &Policy::P0_INTERIM)
                .result
                .is_err()
        );
        assert!(
            check_guard("b_future==null", "a_pending", &d, &Policy::P0_INTERIM)
                .result
                .is_err()
        );
        let mut b = Bindings::empty(prepared.declarations(), &Policy::P0_INTERIM);
        b.insert("flag", &Value::Bool(true)).unwrap();
        let missing = guard(&prepared, &b, &Policy::P0_INTERIM);
        assert!(missing.result.is_err());
        assert_eq!(missing.cost, EvalCost::default());
        b.insert("z_first", &Value::Null).unwrap();
        for _ in 0..2 {
            let report = guard(&prepared, &b, &Policy::P0_INTERIM);
            assert!(!report.result.unwrap());
            assert_eq!(report.budget_scope, "per-guard-call");
            assert!(
                report.cost.work <= prepared.bound().work
                    && report.cost.memory <= prepared.bound().memory
            );
        }
        b.variables.insert("b_future".into(), Value::Null);
        let bad = guard(&prepared, &b, &Policy::P0_INTERIM);
        assert!(matches!(
            bad.result,
            Err(ExecutionError::InputRefused { .. })
        ));
        assert_eq!(bad.cost, EvalCost::default());
    }
    #[test]
    fn first_and_final_prefixes_and_typed_guard_errors() {
        let d = declarations();
        let first = check_guard("flag", "z_first", &d, &Policy::P0_INTERIM)
            .result
            .unwrap();
        assert_eq!(first.declarations().order.len(), 0);
        let last = check_guard(
            "flag && a_pending==null",
            "b_future",
            &d,
            &Policy::P0_INTERIM,
        )
        .result
        .unwrap();
        assert_eq!(last.declarations().order.len(), 2);
        let mut b = Bindings::empty(last.declarations(), &Policy::P0_INTERIM);
        for input in ["z_first", "a_pending"] {
            b.insert(input, &Value::Null).unwrap();
        }
        b.insert("flag", &Value::Bool(true)).unwrap();
        assert!(guard(&last, &b, &Policy::P0_INTERIM).result.unwrap());
        let wrong = check_guard("1", "b_future", &d, &Policy::P0_INTERIM)
            .result
            .unwrap();
        assert!(matches!(
            guard(&wrong, &b, &Policy::P0_INTERIM).result,
            Err(ExecutionError::NoSuchOverload)
        ));
    }
}
