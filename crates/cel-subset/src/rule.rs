//! Native rule seam; opaque registry examples and hosted adapter semantics stay
//! outside this module. Every when/result phase shares one runtime account.
use crate::{
    api, Bindings, Bound, Declarations, EvalCost, ExecutionError, ParseErrors, Policy, Prepared,
    PreparedGuard, Value,
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize)]
pub struct Clause {
    pub id: String,
    pub when: String,
    pub result: String,
}
#[derive(Clone, Debug)]
pub struct GuardSource {
    pub input: String,
    pub source: String,
}
#[derive(Debug)]
struct PreparedClause {
    id: String,
    when: Prepared,
    result: Prepared,
}
#[derive(Debug)]
pub struct PreparedRule {
    clauses: Vec<PreparedClause>,
    guards: Vec<PreparedGuard>,
    declarations: Declarations,
    policy_id: &'static str,
    bound: Bound,
    seal: std::sync::Arc<()>,
}
impl PreparedRule {
    pub fn bound(&self) -> Bound {
        self.bound
    }
    pub fn guards(&self) -> &[PreparedGuard] {
        &self.guards
    }
    pub fn clause_id(&self, index: usize) -> Option<&str> {
        self.clauses.get(index).map(|c| c.id.as_str())
    }
    #[cfg(any(test, feature = "native-proof-tools"))]
    pub(crate) fn native_aux_phases(&self) -> Vec<(String, crate::symbolic_control::Counts)> {
        let mut phases = Vec::new();
        for clause in &self.clauses {
            phases.push((format!("{}:When", clause.id), clause.when.native_aux()));
            phases.push((format!("{}:Result", clause.id), clause.result.native_aux()));
        }
        for guard in &self.guards {
            phases.push((format!("guard:{}", guard.input()), guard.native_aux()));
        }
        phases
    }
}
/// Complete immutable bindings minted only by this rule's ordered prefix builder.
/// The private seal prevents a different PreparedRule from accepting the token.
#[derive(Debug)]
pub struct CheckedRuleBindings {
    bindings: Bindings,
    seal: std::sync::Arc<()>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixProgress {
    Advanced,
    GuardPending,
}
/// Native admission state, independent of any host fetching or guest codec.
/// Pending empty inputs are never visible to their own guard or later inputs.
pub struct RulePrefix<'a> {
    rule: &'a PreparedRule,
    bindings: Bindings,
    policy: Policy,
    next: usize,
    pending: Option<Value>,
}
impl PreparedRule {
    pub fn argument_declarations(&self) -> Declarations {
        Declarations {
            entries: std::sync::Arc::new(
                self.declarations
                    .entries
                    .iter()
                    .filter(|(_, kind)| matches!(kind, crate::InputKind::Scalar { .. }))
                    .map(|(name, kind)| (name.clone(), kind.clone()))
                    .collect(),
            ),
            order: std::sync::Arc::new(Vec::new()),
        }
    }
    /// Start with a complete checked snapshot of scalar arguments only.
    pub fn start_prefix<'a>(
        &'a self,
        arguments: &Bindings,
        policy: &Policy,
    ) -> Result<RulePrefix<'a>, ExecutionError> {
        if self.policy_id != policy.id() || arguments.policy != *policy {
            return Err(ExecutionError::PolicyMismatch(
                "rule prefix policy mismatch".into(),
            ));
        }
        let declarations = self.argument_declarations();
        if arguments.declarations != declarations {
            return Err(crate::input::refused(
                "declarations",
                "arguments",
                1,
                0,
                "use this rule's argument declarations",
            ));
        }
        declarations.validate_policy(policy)?;
        crate::input::validate(&arguments.variables, &declarations, policy, true)?;
        Ok(RulePrefix {
            rule: self,
            bindings: Bindings {
                variables: arguments.variables.clone(),
                declarations: self.declarations.clone(),
                policy: *policy,
            },
            policy: *policy,
            next: 0,
            pending: None,
        })
    }
}
impl RulePrefix<'_> {
    pub fn next_input(&self) -> Option<&str> {
        self.rule
            .declarations
            .order
            .get(self.next)
            .map(String::as_str)
    }
    /// Transactional borrowed append: validation precedes visibility/progress.
    /// A pending empty input may be replaced with a valid nonempty value.
    pub fn append_next(
        &mut self,
        name: &str,
        value: &Value,
    ) -> Result<PrefixProgress, ExecutionError> {
        if self.next_input() != Some(name) {
            return Err(crate::input::refused(
                "prefix_order",
                name,
                1,
                0,
                "append only the next declared input",
            ));
        }
        let mut candidate = self.bindings.clone();
        candidate.insert(name, value)?;
        let empty = match value {
            Value::Null => true,
            Value::Map(map) => map.map.is_empty(),
            _ => false,
        };
        if empty && self.rule.guards.iter().any(|guard| guard.input() == name) {
            self.pending = Some(value.clone());
            return Ok(PrefixProgress::GuardPending);
        }
        self.bindings = candidate;
        self.pending = None;
        self.next += 1;
        Ok(PrefixProgress::Advanced)
    }
    /// Evaluate only the guard pinned to the current pending input. True means
    /// required and keeps the empty input pending; false commits and advances.
    pub fn resolve_guard(&mut self) -> Result<crate::GuardReport, ExecutionError> {
        let name = self.next_input().ok_or_else(|| {
            crate::input::refused(
                "guard_progress",
                "prefix",
                1,
                0,
                "append a guarded empty input first",
            )
        })?;
        if self.pending.is_none() {
            return Err(crate::input::refused(
                "guard_progress",
                name,
                1,
                0,
                "append a guarded empty input first",
            ));
        }
        let guard = self
            .rule
            .guards
            .iter()
            .find(|guard| guard.input() == name)
            .expect("pending input has pinned guard");
        let prefix = Bindings {
            variables: self.bindings.variables.clone(),
            declarations: guard.declarations().clone(),
            policy: self.policy,
        };
        let report = crate::guard(guard, &prefix, &self.policy);
        if matches!(report.result, Ok(false)) {
            let mut candidate = self.bindings.clone();
            candidate.insert(name, self.pending.as_ref().expect("pending"))?;
            self.bindings = candidate;
            self.pending = None;
            self.next += 1;
        }
        Ok(report)
    }
    pub fn finish(self) -> Result<CheckedRuleBindings, ExecutionError> {
        if self.pending.is_some() || self.next != self.rule.declarations.order.len() {
            return Err(crate::input::refused(
                "prefix_incomplete",
                "prefix",
                self.next as u64,
                self.rule.declarations.order.len() as u64,
                "resolve pending guards and append every input",
            ));
        }
        crate::input::validate(
            &self.bindings.variables,
            &self.rule.declarations,
            &self.policy,
            true,
        )?;
        Ok(CheckedRuleBindings {
            bindings: self.bindings,
            seal: self.rule.seal.clone(),
        })
    }
}

#[derive(Debug)]
pub struct RuleCheckReport {
    pub policy_id: &'static str,
    pub interim: bool,
    pub load_cost: EvalCost,
    pub result: Result<PreparedRule, RuleCheckError>,
}
#[derive(Debug)]
pub struct RuleCheckError {
    pub clause_id: Option<String>,
    pub phase: Option<ClausePhase>,
    pub errors: ParseErrors,
}
impl std::fmt::Display for RuleCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(id) = &self.clause_id {
            write!(f, "clause {id} {:?}: ", self.phase)?;
        }
        write!(f, "{}", self.errors)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClausePhase {
    When,
    Result,
}
#[derive(Debug)]
pub enum RuleDecision {
    Matched { clause_index: usize, value: Value },
    NoMatch,
}
#[derive(Debug)]
pub struct RuleError {
    pub clause_index: Option<usize>,
    pub phase: Option<ClausePhase>,
    pub error: ExecutionError,
}
#[derive(Debug)]
pub struct RuleEvalReport {
    pub policy_id: &'static str,
    pub interim: bool,
    pub budget_scope: &'static str,
    pub cost: EvalCost,
    pub input_cost: EvalCost,
    pub result: Result<RuleDecision, RuleError>,
}

/// Engine-owned compact JSON clause-array bytes, counted without constructing
/// an encoded buffer. Guards have their own source/load accounts.
fn rule_bytes(clauses: &[Clause]) -> Result<u64, ParseErrors> {
    struct Counter(u64);
    impl std::io::Write for Counter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(b.len() as u64);
            if self.0 > 64 * 1024 {
                Err(std::io::Error::other("rule_bytes exceeds 65536"))
            } else {
                Ok(b.len())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, clauses)
        .map_err(|_| api::check_error("rule_bytes exceeds 65536".into()))?;
    Ok(counter.0)
}
/// Parse and bound EVERY when/result phase. The resulting native bound composes
/// their peaks/exits in order; it never discounts later clauses by first match.
pub fn check_rule(
    clauses: &[Clause],
    declarations: &Declarations,
    guards: &[GuardSource],
    policy: &Policy,
) -> RuleCheckReport {
    check_rule_native(clauses, declarations, guards, policy, true)
}
/// Private measurement path, never a public-admitted proof denominator.
pub(crate) fn check_rule_native(
    clauses: &[Clause],
    declarations: &Declarations,
    guards: &[GuardSource],
    policy: &Policy,
    admit: bool,
) -> RuleCheckReport {
    let mut load_cost = EvalCost::default();
    let mut failure_context = None;
    let result = (|| {
        declarations
            .validate_policy(policy)
            .map_err(|e| api::check_error(e.to_string()))?;
        if clauses.len() > 32 {
            return Err(api::check_error("clauses exceeds 32".into()));
        }
        if guards.len() > declarations.order.len() {
            return Err(api::check_error("guard_count exceeds input_count".into()));
        }
        let mut ids = BTreeSet::new();
        for clause in clauses {
            if clause.id.is_empty() || clause.id.len() > 128 || !ids.insert(&clause.id) {
                return Err(api::check_error(
                    "clause ids must be unique and contain 1..128 bytes".into(),
                ));
            }
        }
        rule_bytes(clauses)?;
        let mut prepared = vec![];
        let mut bound = Bound::default();
        for clause in clauses {
            let mut phases = vec![];
            for (which, source) in [
                (ClausePhase::When, &clause.when),
                (ClausePhase::Result, &clause.result),
            ] {
                failure_context = Some((clause.id.clone(), which));
                let checked = api::check_native(source, declarations, policy, admit);
                load_cost.work = load_cost.work.saturating_add(checked.load_cost.work);
                load_cost.memory = load_cost.memory.saturating_add(checked.load_cost.memory);
                let phase = checked.result?;
                let b = phase.bound();
                bound.work = bound.work.saturating_add(b.work);
                bound.memory = bound.memory.max(bound.retained.saturating_add(b.memory));
                bound.retained = bound.retained.saturating_add(b.retained);
                bound.result_nodes = bound.result_nodes.max(b.result_nodes);
                bound.result_bytes = bound.result_bytes.max(b.result_bytes);
                bound.result_depth = bound.result_depth.max(b.result_depth);
                bound.resource_product |= b.resource_product;
                if admit {
                    crate::estimate::admit(bound, policy.to_budget()).map_err(|message| {
                        api::check_error_at(
                            &phase.program,
                            phase.program.expression().id,
                            format!("whole_rule_{message}"),
                        )
                    })?;
                }
                phases.push(phase);
                failure_context = None;
            }
            let result = phases.pop().expect("result phase");
            let when = phases.pop().expect("when phase");
            prepared.push(PreparedClause {
                id: clause.id.clone(),
                when,
                result,
            });
        }
        let mut seen = BTreeSet::new();
        let mut checked_guards = vec![];
        for g in guards {
            if !seen.insert(&g.input) {
                return Err(api::check_error("one required_when guard per input".into()));
            }
            let checked =
                crate::guard::check_guard_native(&g.source, &g.input, declarations, policy, admit);
            load_cost.work = load_cost.work.saturating_add(checked.load_cost.work);
            load_cost.memory = load_cost.memory.saturating_add(checked.load_cost.memory);
            checked_guards.push(checked.result?);
        }
        checked_guards.sort_by_key(|g| {
            declarations
                .order
                .iter()
                .position(|input| input == g.input())
                .expect("checked guard input")
        });
        let load_budget = policy.check_load_budget();
        if load_cost.work > load_budget.work || load_cost.memory > load_budget.memory {
            return Err(api::check_error(
                "whole_rule_load exceeds native compile account".into(),
            ));
        }
        if bound.work == u64::MAX || bound.memory == u64::MAX || bound.retained == u64::MAX {
            return Err(api::check_error(
                "symbolic_overflow in composed rule".into(),
            ));
        }
        Ok(PreparedRule {
            clauses: prepared,
            guards: checked_guards,
            declarations: declarations.clone(),
            policy_id: policy.id(),
            bound,
            seal: std::sync::Arc::new(()),
        })
    })();
    RuleCheckReport {
        policy_id: policy.id(),
        interim: policy.interim(),
        load_cost,
        result: result.map_err(|errors| {
            let (clause_id, phase) = match failure_context {
                Some((id, p)) => (Some(id), Some(p)),
                None => (None, None),
            };
            RuleCheckError {
                clause_id,
                phase,
                errors,
            }
        }),
    }
}
/// First-match native clause behavior. Semantic errors retain their typed phase
/// and yield no successful decision; they are distinct from budget/input refusal.
pub fn evaluate_rule(
    prepared: &PreparedRule,
    checked: &CheckedRuleBindings,
    policy: &Policy,
) -> RuleEvalReport {
    let bindings = &checked.bindings;
    let initial = (|| {
        if !std::sync::Arc::ptr_eq(&prepared.seal, &checked.seal) {
            return Err(crate::input::refused(
                "rule_association",
                "bindings",
                1,
                0,
                "complete the prefix for this prepared rule",
            ));
        }
        if prepared.policy_id != policy.id() {
            return Err(ExecutionError::PolicyMismatch(
                "rule policy mismatch".into(),
            ));
        }
        if bindings.declarations != prepared.declarations || bindings.policy != *policy {
            return Err(crate::input::refused(
                "declaration_identity",
                "bindings",
                1,
                0,
                "use the pinned complete rule snapshot",
            ));
        }
        crate::input::validate(&bindings.variables, &prepared.declarations, policy, true)?;
        Ok(())
    })();
    let wrap = |error| RuleError {
        clause_index: None,
        phase: None,
        error,
    };
    let (result, cost, input_cost) = match initial {
        Err(error) => (
            Err(wrap(error)),
            crate::charges::Cost::ZERO,
            crate::charges::Cost::ZERO,
        ),
        Ok(()) => api::run_on_pool(|| {
            let (context, input_cost) = api::context_for(bindings, policy);
            let context = match context {
                Ok(c) => c,
                Err(e) => return (Err(wrap(e)), crate::charges::Cost::ZERO, input_cost),
            };
            let (result, cost) = crate::load::account(policy.to_budget(), || {
                for (index, clause) in prepared.clauses.iter().enumerate() {
                    let phase = |p: &Prepared, which: ClausePhase| {
                        let _registry = crate::regexes::install(p.regexes.clone());
                        let result = Value::resolve(p.program.expression(), &context);
                        let result = if let Some(e) = crate::meter::tripped() {
                            Err(e)
                        } else {
                            result
                        };
                        result.map_err(|error| RuleError {
                            clause_index: Some(index),
                            phase: Some(which),
                            error,
                        })
                    };
                    let required = phase(&clause.when, ClausePhase::When)?;
                    match required {
                        Value::Bool(false) => continue,
                        Value::Bool(true) => {
                            return phase(&clause.result, ClausePhase::Result).map(|value| {
                                RuleDecision::Matched {
                                    clause_index: index,
                                    value,
                                }
                            })
                        }
                        _ => {
                            return Err(RuleError {
                                clause_index: Some(index),
                                phase: Some(ClausePhase::When),
                                error: ExecutionError::NoSuchOverload,
                            })
                        }
                    }
                }
                Ok(RuleDecision::NoMatch)
            });
            (result, cost, input_cost)
        })
        .unwrap_or_else(|msg| {
            (
                Err(wrap(ExecutionError::InternalError(msg))),
                crate::charges::Cost::ZERO,
                crate::charges::Cost::ZERO,
            )
        }),
    };
    RuleEvalReport {
        policy_id: policy.id(),
        interim: policy.interim(),
        budget_scope: "per-rule-call",
        cost: EvalCost {
            work: cost.work,
            memory: cost.memory,
        },
        input_cost: EvalCost {
            work: input_cost.work,
            memory: input_cost.memory,
        },
        result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prefix_rule(guard: &str) -> PreparedRule {
        let d = Declarations::new(
            [
                crate::InputDecl {
                    name: "z_first".into(),
                    kind: crate::InputKind::One,
                },
                crate::InputDecl {
                    name: "a_second".into(),
                    kind: crate::InputKind::One,
                },
                crate::InputDecl {
                    name: "later".into(),
                    kind: crate::InputKind::Many,
                },
                crate::InputDecl {
                    name: "flag".into(),
                    kind: crate::InputKind::Scalar {
                        kind: crate::ScalarType::Bool,
                        nullable: false,
                    },
                },
            ],
            &Policy::P0_INTERIM,
        )
        .unwrap();
        check_rule(
            &[Clause {
                id: "decision".into(),
                when: "true".into(),
                result: "null".into(),
            }],
            &d,
            &[
                GuardSource {
                    input: "a_second".into(),
                    source: "z_first != null".into(),
                },
                GuardSource {
                    input: "z_first".into(),
                    source: guard.into(),
                },
            ],
            &Policy::P0_INTERIM,
        )
        .result
        .unwrap()
    }
    fn prefix_args(p: &PreparedRule, flag: bool) -> Bindings {
        let mut b = Bindings::empty(&p.argument_declarations(), &Policy::P0_INTERIM);
        b.insert("flag", &Value::Bool(flag)).unwrap();
        b
    }
    #[test]
    fn checked_prefix_cannot_skip_guards_order_or_rule_association() {
        let p = prefix_rule("flag");
        assert_eq!(
            p.guards().iter().map(|g| g.input()).collect::<Vec<_>>(),
            ["z_first", "a_second"]
        );
        let args = prefix_args(&p, true);
        let mut prefix = p.start_prefix(&args, &Policy::P0_INTERIM).unwrap();
        assert!(prefix.resolve_guard().is_err());
        assert!(prefix.append_next("a_second", &Value::Null).is_err());
        assert_eq!(
            prefix.append_next("z_first", &Value::Null).unwrap(),
            PrefixProgress::GuardPending
        );
        assert!(prefix.resolve_guard().unwrap().result.unwrap());
        assert_eq!(prefix.next_input(), Some("z_first"));
        assert!(prefix
            .append_next("later", &Value::from(Vec::<Value>::new()))
            .is_err());
        let row = Value::from(indexmap::IndexMap::from([(
            "body".to_string(),
            Value::Int(1),
        )]));
        assert_eq!(
            prefix.append_next("z_first", &row).unwrap(),
            PrefixProgress::Advanced
        );
        assert_eq!(
            prefix
                .append_next(
                    "a_second",
                    &Value::from(indexmap::IndexMap::<String, Value>::new())
                )
                .unwrap(),
            PrefixProgress::GuardPending
        );
        assert!(prefix.resolve_guard().unwrap().result.unwrap());
        assert!(prefix
            .append_next("a_second", &Value::from(vec![row.clone()]))
            .is_err());
        assert_eq!(prefix.next_input(), Some("a_second"));
        prefix.append_next("a_second", &row).unwrap();
        prefix
            .append_next("later", &Value::from(Vec::<Value>::new()))
            .unwrap();
        let checked = prefix.finish().unwrap();
        assert!(evaluate_rule(&p, &checked, &Policy::P0_INTERIM)
            .result
            .is_ok());
        let foreign = prefix_rule("flag");
        let r = evaluate_rule(&foreign, &checked, &Policy::P0_INTERIM);
        assert!(matches!(
            r.result,
            Err(RuleError {
                error: ExecutionError::InputRefused { .. },
                ..
            })
        ));
        assert_eq!(r.cost, EvalCost::default());
        assert_eq!(r.input_cost, EvalCost::default());
        let mut unfinished = p.start_prefix(&args, &Policy::P0_INTERIM).unwrap();
        unfinished.append_next("z_first", &Value::Null).unwrap();
        assert!(unfinished.finish().is_err());
        let missing = Bindings::empty(&p.argument_declarations(), &Policy::P0_INTERIM);
        assert!(p.start_prefix(&missing, &Policy::P0_INTERIM).is_err());
        let foreign_args = Bindings::empty(&Declarations::empty(), &Policy::P0_INTERIM);
        assert!(p.start_prefix(&foreign_args, &Policy::P0_INTERIM).is_err());
    }
    #[test]
    fn prefix_false_guards_commit_empty_and_errors_do_not_advance() {
        let p = prefix_rule("flag");
        let args = prefix_args(&p, false);
        let mut prefix = p.start_prefix(&args, &Policy::P0_INTERIM).unwrap();
        for name in ["z_first", "a_second"] {
            assert_eq!(
                prefix.append_next(name, &Value::Null).unwrap(),
                PrefixProgress::GuardPending
            );
            let report = prefix.resolve_guard().unwrap();
            assert!(!report.result.unwrap());
            assert_eq!(report.budget_scope, "per-guard-call");
        }
        prefix
            .append_next("later", &Value::from(Vec::<Value>::new()))
            .unwrap();
        let checked = prefix.finish().unwrap();
        assert!(matches!(
            evaluate_rule(&p, &checked, &Policy::P0_INTERIM).result,
            Ok(RuleDecision::Matched {
                value: Value::Null,
                ..
            })
        ));
        let p = prefix_rule("1/0>0");
        let mut prefix = p
            .start_prefix(&prefix_args(&p, true), &Policy::P0_INTERIM)
            .unwrap();
        prefix.append_next("z_first", &Value::Null).unwrap();
        assert!(prefix.resolve_guard().unwrap().result.is_err());
        assert_eq!(prefix.next_input(), Some("z_first"));
        assert!(prefix.finish().is_err());
    }
    #[test]
    fn prefix_total_cap_failure_is_transactional_before_visibility() {
        let p = prefix_rule("flag");
        let args = prefix_args(&p, false);
        let mut prefix = p.start_prefix(&args, &Policy::P0_INTERIM).unwrap();
        let big = Value::from(indexmap::IndexMap::from([(
            "body".to_string(),
            Value::from("x".repeat(600_000)),
        )]));
        prefix.append_next("z_first", &big).unwrap();
        assert!(matches!(
            prefix.append_next("a_second", &big),
            Err(ExecutionError::InputRefused { .. })
        ));
        assert_eq!(prefix.next_input(), Some("a_second"));
        assert!(!prefix.bindings.variables.contains_key("a_second"));
        assert!(prefix.pending.is_none());
        prefix.append_next("a_second", &Value::Null).unwrap();
        assert!(prefix.resolve_guard().unwrap().result.unwrap());
        assert_eq!(prefix.next_input(), Some("a_second"));
    }
    #[test]
    fn composed_work_and_memory_refuse_at_the_crossing_clause_phase() {
        let d = Declarations::new(
            [crate::InputDecl {
                name: "text".into(),
                kind: crate::InputKind::Scalar {
                    kind: crate::ScalarType::String,
                    nullable: false,
                },
            }],
            &Policy::P0_INTERIM,
        )
        .unwrap();
        for (when, result, count, cap, phase) in [
            (
                vec!["text.contains(text)"; 30].join(" && "),
                "0".to_string(),
                3,
                "work_cost",
                ClausePhase::When,
            ),
            (
                "true".to_string(),
                "text+text".to_string(),
                3,
                "memory_cost",
                ClausePhase::Result,
            ),
        ] {
            for source in [&when, &result] {
                assert!(
                    api::check(source, &d, &Policy::P0_INTERIM).result.is_ok(),
                    "{source}"
                );
            }
            let clauses = (0..count)
                .map(|i| Clause {
                    id: format!("clause-{i}"),
                    when: when.clone(),
                    result: result.clone(),
                })
                .collect::<Vec<_>>();
            let report = check_rule(&clauses, &d, &[], &Policy::P0_INTERIM);
            let error = report.result.unwrap_err();
            assert!(error.errors.to_string().contains(cap), "{error}");
            assert!(error.clause_id.is_some());
            assert_eq!(error.phase, Some(phase));
            let measured = check_rule_native(&clauses, &d, &[], &Policy::P0_INTERIM, false)
                .result
                .unwrap();
            assert!(
                measured.bound().work > Policy::P0_INTERIM.work_limit()
                    || measured.bound().memory > Policy::P0_INTERIM.mem_limit_bytes()
            );
        }
    }
    #[test]
    fn production_expression_refuses_products_before_any_numeric_ceiling() {
        let d = Declarations::new(
            ["xs", "ys"].map(|name| crate::InputDecl {
                name: name.into(),
                kind: crate::InputKind::Many,
            }),
            &Policy::P0_INTERIM,
        )
        .unwrap();
        let source = "xs.all(x,ys.all(y,true))";
        let measured = api::measure(source, &d, &Policy::P0_INTERIM)
            .result
            .unwrap();
        assert!(measured.bound().resource_product);
        let public = api::check(source, &d, &Policy::P0_INTERIM)
            .result
            .unwrap_err();
        assert!(public.to_string().contains("cross_product"), "{public}");
        assert!(public.to_string().contains("SQL"));
        assert!(api::check("xs.all(x,true)", &d, &Policy::P0_INTERIM)
            .result
            .is_ok());
        let ordinary = api::check("xs.map(x,x)", &d, &Policy::P0_INTERIM)
            .result
            .unwrap_err();
        assert!(ordinary.to_string().contains("memory_cost"), "{ordinary}");
        assert!(!ordinary.to_string().contains("cross_product"));
    }
    #[test]
    fn whole_rule_composes_all_phases_without_first_match_discount() {
        let d = Declarations::empty();
        let clauses = vec![
            Clause {
                id: "first".into(),
                when: "true".into(),
                result: "1".into(),
            },
            Clause {
                id: "later".into(),
                when: "true".into(),
                result: "[1,2,3]".into(),
            },
        ];
        let p = check_rule(&clauses, &d, &[], &Policy::P0_INTERIM)
            .result
            .unwrap();
        let parts: Vec<_> = clauses
            .iter()
            .flat_map(|c| [&c.when, &c.result])
            .map(|s| {
                api::check(s, &d, &Policy::P0_INTERIM)
                    .result
                    .unwrap()
                    .bound()
            })
            .collect();
        assert_eq!(p.bound().work, parts.iter().map(|b| b.work).sum::<u64>());
        let b = Bindings::empty(&d, &Policy::P0_INTERIM);
        let checked = p
            .start_prefix(&b, &Policy::P0_INTERIM)
            .unwrap()
            .finish()
            .unwrap();
        let r = evaluate_rule(&p, &checked, &Policy::P0_INTERIM);
        assert!(matches!(
            r.result,
            Ok(RuleDecision::Matched {
                clause_index: 0,
                value: Value::Int(1)
            })
        ));
        assert!(r.cost.work < p.bound().work);
        assert!(r.cost.memory <= p.bound().memory);
        assert_eq!(r.budget_scope, "per-rule-call");
    }
    #[test]
    fn false_clause_prefixes_share_one_runtime_account() {
        let d = Declarations::empty();
        let b = Bindings::empty(&d, &Policy::P0_INTERIM);
        let clauses = vec![
            Clause {
                id: "a".into(),
                when: "[1,2,3].size()<0".into(),
                result: "0".into(),
            },
            Clause {
                id: "b".into(),
                when: "false".into(),
                result: "0".into(),
            },
            Clause {
                id: "c".into(),
                when: "true".into(),
                result: "[4,5]".into(),
            },
        ];
        let mut actual_work = 0;
        for source in clauses
            .iter()
            .map(|c| c.when.as_str())
            .chain(std::iter::once(clauses[2].result.as_str()))
        {
            let p = api::check(source, &d, &Policy::P0_INTERIM).result.unwrap();
            actual_work += crate::evaluate(&p, &b, &Policy::P0_INTERIM).cost.work;
        }
        let p = check_rule(&clauses, &d, &[], &Policy::P0_INTERIM)
            .result
            .unwrap();
        let checked = p
            .start_prefix(&b, &Policy::P0_INTERIM)
            .unwrap()
            .finish()
            .unwrap();
        let r = evaluate_rule(&p, &checked, &Policy::P0_INTERIM);
        assert!(matches!(
            r.result,
            Ok(RuleDecision::Matched {
                clause_index: 2,
                ..
            })
        ));
        assert_eq!(r.cost.work, actual_work);
        assert!(r.cost.memory <= p.bound().memory);
    }
    #[test]
    fn semantic_phase_errors_and_caps_are_typed_and_pre_body() {
        let d = Declarations::empty();
        let b = Bindings::empty(&d, &Policy::P0_INTERIM);
        for (when, result, expected) in [
            ("1", "1", ClausePhase::When),
            ("true", "min([])", ClausePhase::Result),
            ("1/0>0", "1", ClausePhase::When),
        ] {
            let clauses = [Clause {
                id: "bad".into(),
                when: when.into(),
                result: result.into(),
            }];
            let p = check_rule(&clauses, &d, &[], &Policy::P0_INTERIM)
                .result
                .unwrap();
            let checked = p
                .start_prefix(&b, &Policy::P0_INTERIM)
                .unwrap()
                .finish()
                .unwrap();
            let error = evaluate_rule(&p, &checked, &Policy::P0_INTERIM)
                .result
                .unwrap_err();
            assert_eq!(error.clause_index, Some(0));
            assert_eq!(error.phase, Some(expected));
        }
        let too_many: Vec<_> = (0..33)
            .map(|i| Clause {
                id: i.to_string(),
                when: "false".into(),
                result: "0".into(),
            })
            .collect();
        assert!(check_rule(&too_many, &d, &[], &Policy::P0_INTERIM)
            .result
            .is_err());
        let duplicate = [
            Clause {
                id: "same".into(),
                when: "true".into(),
                result: "0".into(),
            },
            Clause {
                id: "same".into(),
                when: "true".into(),
                result: "0".into(),
            },
        ];
        assert!(check_rule(&duplicate, &d, &[], &Policy::P0_INTERIM)
            .result
            .is_err());
    }
}
