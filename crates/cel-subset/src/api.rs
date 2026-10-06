//! Checked native engine surface (PR 1b, design §7.3).
//!
//! Expressions use [`check`] and [`evaluate`] with immutable declarations.
//! Whole rules and ordered input-prefix guards use the checked APIs reexported
//! at the crate root. Every evaluation revalidates current bindings before
//! conversion/body work. No raw `compile`/`execute` path is exported.
//! [`Policy::P1`] remains interim: native meter proof is available; hosted
//! validation evidence waits for PR 2's guest codec/session/backstop composition.
//!
//! Both entry points take a `&Policy`, and both run worker logic on
//! an internal thread with a stack of at least 8 MiB (see
//! [`run_on_pool`]): callers cannot supply their own stack.
//!
//! No unbudgeted entry point is exported (design §7.2 "Must test:
//! Public API"). These doctests fail to compile — and so pass —
//! exactly while that holds:
//!
//! <!-- native-doctest-id: cel-subset-policy-no-program-compile -->
//! ```compile_fail
//! # use cel::Policy;
//! // `Program` is crate-private: no unbudgeted compile path exists.
//! let _ = cel::Program::compile("1 + 1");
//! ```
//!
//! <!-- native-doctest-id: cel-subset-policy-no-context -->
//! ```compile_fail
//! # use cel::Policy;
//! // `Context` is crate-private: no unbudgeted execute path exists.
//! let _ = cel::Context::default();
//! ```

use std::collections::{BTreeMap, HashMap};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use crate::context::Context;
use crate::objects::Value;
use crate::regexes::{self, PreparedRegex};
use crate::{Declarations, ExecutionError, ParseError, ParseErrors, Policy, Program, STACK_8MIB};

/// A checked expression, ready for [`evaluate`]. Only [`check`] builds one.
///
/// Records the policy id it was checked under (review F5):
/// [`evaluate`] refuses a `Prepared` checked under a different
/// policy, since the compiled `matches` tiers and `K_re` are baked
/// from the check policy.
#[derive(Debug)]
pub struct Prepared {
    pub(crate) program: Program,
    /// Compiled `matches` patterns, keyed by the literal pattern.
    pub(crate) regexes: Arc<HashMap<String, PreparedRegex>>,
    policy_id: &'static str,
    declarations: Declarations,
    measures: crate::Measures,
    bound: crate::Bound,
    #[allow(dead_code)] // reported by private native tools; not runtime W/H
    native_aux: crate::symbolic_control::Counts,
    #[cfg(test)]
    legacy: bool,
}

impl Prepared {
    #[cfg(any(test, feature = "native-proof-tools"))]
    pub(crate) fn native_aux(&self) -> crate::symbolic_control::Counts {
        self.native_aux
    }
    pub fn bound(&self) -> crate::Bound {
        self.bound
    }
    pub fn measures(&self) -> crate::Measures {
        self.measures
    }
    /// `#[cfg(test)]`: the number of distinct literal `matches`
    /// patterns compiled for this program (the compile count).
    #[cfg(test)]
    pub(crate) fn regex_count(&self) -> usize {
        self.regexes.len()
    }
}

/// Owned variable bindings for [`evaluate`]: plain [`Value`] data.
///
/// Stored as data rather than a live context so bindings stay `Send
/// + Sync` and can cross into the evaluation worker thread; the
/// worker builds a fresh [`Context`] from them on every call.
#[derive(Clone, Debug)]
pub struct Bindings {
    pub(crate) variables: BTreeMap<String, Value>,
    pub(crate) declarations: Declarations,
    pub(crate) policy: Policy,
}
impl Bindings {
    pub fn empty(declarations: &Declarations, policy: &Policy) -> Self {
        Self {
            variables: BTreeMap::new(),
            declarations: declarations.clone(),
            policy: *policy,
        }
    }
    /// Validate before replacement; a failed insertion leaves the old snapshot intact.
    pub fn insert(&mut self, name: &str, value: &Value) -> Result<(), ExecutionError> {
        let kind = self.declarations.entries.get(name).ok_or_else(|| {
            crate::input::refused("undeclared", name, 1, 0, "declare this binding")
        })?;
        crate::input::validate_value(name, value, kind, &self.policy)?;
        let previous = self.variables.insert(name.into(), value.clone());
        if let Err(error) =
            crate::input::validate(&self.variables, &self.declarations, &self.policy, false)
        {
            if let Some(previous) = previous {
                self.variables.insert(name.into(), previous);
            } else {
                self.variables.remove(name);
            }
            return Err(error);
        }
        Ok(())
    }
    // Private semantic-corpus construction, compiled only into library unit tests.
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::empty(&Declarations::empty(), &Policy::P0_INTERIM)
    }
    #[cfg(test)]
    pub(crate) fn set(&mut self, name: &str, value: Value) -> &mut Self {
        self.variables.insert(name.into(), value);
        self
    }
}

/// Proven native L0 parser caps: 16 KiB, 2048 real tokens and weighted
/// grammar/visitor chain 96. The legacy max_parse_depth field names that
/// weighted L0 measure; exact expanded L1 AST depth is a separate limit32.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseCaps {
    pub max_source_bytes: usize,
    pub max_parse_tokens: usize,
    pub max_parse_depth: usize,
}

impl ParseCaps {
    /// The caps in force (single source of truth: the parser).
    pub fn current() -> Self {
        Self {
            max_source_bytes: crate::parser::MAX_SOURCE_BYTES,
            max_parse_tokens: crate::parser::MAX_PARSE_TOKENS,
            max_parse_depth: crate::parser::MAX_PARSE_DEPTH,
        }
    }
}

/// Outcome of [`check`]: the parse result plus the caps it ran
/// under. `interim` mirrors the policy: an interim policy makes no
/// save⇒eval claim, and PR 4's adapter must refuse evidence under
/// one (design §7.1).
#[derive(Debug)]
pub struct CheckReport {
    pub policy_id: &'static str,
    pub interim: bool,
    pub caps: ParseCaps,
    /// Separate source/regex compilation account.
    pub load_cost: EvalCost,
    pub result: Result<Prepared, ParseErrors>,
}

/// The cost one [`evaluate`] call consumed (design §7.2 item 7).
///
/// Covers evaluation only. Native input conversion and source/regex compilation
/// are separate reported accounts. H is the deterministic scoped charge level,
/// not measured allocator usage; guest allocation/fuel coupling remains PR 2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvalCost {
    /// Cumulative work units charged.
    pub work: u64,
    /// Memory high-water mark in bytes.
    pub memory: u64,
}

/// Outcome of [`evaluate`]: the value (or refusal), the cost it
/// consumed, plus the budget it ran under. `budget_scope` is
/// `"per-evaluate-call"` for an expression. Whole-rule evaluation composes all
/// when/result phases under one separate shared rule account; guards have
/// independent accounts. Guest session/backstop composition remains PR 2.
#[derive(Debug)]
pub struct EvalReport {
    pub policy_id: &'static str,
    pub interim: bool,
    pub budget_scope: &'static str,
    pub cost: EvalCost,
    /// Validated native input conversion; excluded from evaluation W/H.
    pub input_cost: EvalCost,
    pub result: Result<Value, ExecutionError>,
}

/// Parse `source` under `policy` on the internal pool.
///
/// <!-- native-doctest-id: cel-subset-check -->
/// ```
/// # use cel::{check, Declarations, Policy};
/// let report = check("size([1, 2]) == 2", &Declarations::empty(), &Policy::P1);
/// assert!(report.interim);
/// assert!(report.result.is_ok());
/// ```
pub fn check(source: &str, declarations: &Declarations, policy: &Policy) -> CheckReport {
    check_inner(
        source,
        declarations,
        policy,
        false,
        true,
        policy.to_budget(),
        false,
    )
}

#[cfg(test)]
pub(crate) fn legacy_check(source: &str, policy: &Policy) -> CheckReport {
    check_inner(
        source,
        &Declarations::empty(),
        policy,
        true,
        false,
        policy.to_budget(),
        false,
    )
}

/// Private calibration path still checks L0/L1, names, declarations and overload
/// surface, but returns candidate bounds without claiming production admission.
pub(crate) fn check_native(
    source: &str,
    declarations: &Declarations,
    policy: &Policy,
    admit: bool,
) -> CheckReport {
    check_inner(
        source,
        declarations,
        policy,
        false,
        admit,
        policy.to_budget(),
        false,
    )
}
pub(crate) fn check_guard_expression(
    source: &str,
    declarations: &Declarations,
    policy: &Policy,
    admit: bool,
) -> CheckReport {
    check_inner(
        source,
        declarations,
        policy,
        false,
        admit,
        policy.guard_budget(),
        false,
    )
}
#[cfg(test)]
pub(crate) fn measure(source: &str, declarations: &Declarations, policy: &Policy) -> CheckReport {
    check_native(source, declarations, policy, false)
}

#[cfg(test)]
pub(crate) fn check_current_thread(
    source: &str,
    declarations: &Declarations,
    policy: &Policy,
) -> CheckReport {
    check_inner(
        source,
        declarations,
        policy,
        false,
        true,
        policy.to_budget(),
        true,
    )
}
fn check_inner(
    source: &str,
    declarations: &Declarations,
    policy: &Policy,
    legacy: bool,
    admit: bool,
    admission_budget: crate::meter::Budget,
    on_current_thread: bool,
) -> CheckReport {
    let caps = ParseCaps::current();
    let worker = || {
        crate::load::account(policy.check_load_budget(), || {
            crate::meter::charge_cost(crate::charges::source_compile(source.len() as u64))
                .map_err(|e| check_error(e.to_string()))?;
            declarations
                .validate_policy(policy)
                .map_err(|e| check_error(e.to_string()))?;
            let program = Program::compile(source)?;
            // L0 protects parser frames; L1 measures the expanded expression.
            // Private upstream semantic helpers deliberately omit L1 admission.
            let measures = if legacy {
                crate::Measures::default()
            } else {
                let l0 = crate::parser::l0::check(source)?;
                crate::limits::measure(program.expression(), source.len(), Some(l0.real_tokens))
                    .map_err(|r| check_error_at(&program, r.expr_id, r.to_string()))?
            };
            // F1: refuse any function or macro outside cel-subset@1,
            // naming it, before compiling patterns.
            crate::subset::check_expression(program.expression())
                .map_err(|msg| check_error_at(&program, program.expression().id, msg))?;
            if !legacy {
                crate::input::check_names(program.expression(), declarations)
                    .map_err(check_error)?;
            }
            let regexes = regexes::prepare_program(&program, policy)
                .map_err(|msg| check_error_at(&program, program.expression().id, msg))?;
            let (bound, native_aux) = if legacy {
                (
                    crate::Bound::default(),
                    crate::symbolic_control::Counts::default(),
                )
            } else {
                crate::estimate::estimate(program.expression(), declarations, &regexes, policy)
                    .map_err(|r| check_error_at(&program, r.expr_id, r.to_string()))?
            };
            if admit {
                crate::estimate::admit(bound, admission_budget)
                    .map_err(|r| check_error_at(&program, program.expression().id, r))?;
            }
            Ok(Prepared {
                program,
                regexes: Arc::new(regexes),
                policy_id: policy.id(),
                declarations: declarations.clone(),
                measures,
                bound,
                native_aux,
                #[cfg(test)]
                legacy,
            })
        })
    };
    let (result, load_cost) = (if on_current_thread {
        Ok(worker())
    } else {
        run_on_pool(worker)
    })
    .unwrap_or_else(|msg| (Err(check_error(msg)), crate::charges::Cost::ZERO));
    CheckReport {
        policy_id: policy.id(),
        interim: policy.interim(),
        caps,
        load_cost: EvalCost {
            work: load_cost.work,
            memory: load_cost.memory,
        },
        result,
    }
}

/// Evaluate a [`check`]ed rule under `policy` on the internal pool.
///
/// <!-- native-doctest-id: cel-subset-evaluate -->
/// ```
/// # use cel::{check, evaluate, Bindings, Declarations, InputDecl, InputKind, ScalarType, Policy};
/// # use cel::Value;
/// let declarations = Declarations::new([InputDecl { name: "x".into(), kind: InputKind::Scalar { kind: ScalarType::Int, nullable: false } }], &Policy::P1).unwrap();
/// let prepared = check("x * 2", &declarations, &Policy::P1).result.unwrap();
/// let mut bindings = Bindings::empty(&declarations, &Policy::P1);
/// bindings.insert("x", &Value::Int(21)).unwrap();
/// let report = evaluate(&prepared, &bindings, &Policy::P1);
/// assert_eq!(report.budget_scope, "per-evaluate-call");
/// assert!(matches!(report.result, Ok(Value::Int(42))));
/// assert!(report.cost.work > 0);
/// ```
pub fn evaluate(prepared: &Prepared, bindings: &Bindings, policy: &Policy) -> EvalReport {
    evaluate_account(
        prepared,
        bindings,
        policy,
        policy.to_budget(),
        "per-evaluate-call",
    )
}
pub(crate) fn evaluate_account(
    prepared: &Prepared,
    bindings: &Bindings,
    policy: &Policy,
    budget: crate::meter::Budget,
    budget_scope: &'static str,
) -> EvalReport {
    evaluate_native(prepared, bindings, policy, budget, budget_scope, false)
}
#[cfg(test)]
pub(crate) fn evaluate_current_thread(
    prepared: &Prepared,
    bindings: &Bindings,
    policy: &Policy,
) -> EvalReport {
    evaluate_native(
        prepared,
        bindings,
        policy,
        policy.to_budget(),
        "native-stack-probe",
        true,
    )
}
fn evaluate_native(
    prepared: &Prepared,
    bindings: &Bindings,
    policy: &Policy,
    budget: crate::meter::Budget,
    budget_scope: &'static str,
    on_current_thread: bool,
) -> EvalReport {
    // F5: the `matches` tiers baked into `Prepared` come from the
    // check policy; evaluating under another policy would charge the
    // wrong tier, so refuse.
    if prepared.policy_id != policy.id() {
        return EvalReport {
            policy_id: policy.id(),
            interim: policy.interim(),
            budget_scope,
            cost: EvalCost::default(),
            input_cost: EvalCost::default(),
            result: Err(ExecutionError::PolicyMismatch(format!(
                "policy mismatch: prepared under {}, evaluated under {}",
                prepared.policy_id,
                policy.id(),
            ))),
        };
    }
    #[cfg(test)]
    let validate_inputs = !prepared.legacy;
    #[cfg(not(test))]
    let validate_inputs = true;
    if validate_inputs {
        let validation =
            if bindings.declarations != prepared.declarations || bindings.policy != *policy {
                Err(crate::input::refused(
                    "declaration_identity",
                    "bindings",
                    1,
                    0,
                    "build bindings for the pinned declarations and policy",
                ))
            } else {
                crate::input::validate(&bindings.variables, &prepared.declarations, policy, true)
                    .map(|_| ())
            };
        if let Err(error) = validation {
            return EvalReport {
                policy_id: policy.id(),
                interim: policy.interim(),
                budget_scope,
                cost: EvalCost::default(),
                input_cost: EvalCost::default(),
                result: Err(error),
            };
        }
    }
    let worker = || {
        let _regexes = regexes::install(prepared.regexes.clone());
        let (context, input_cost) = if validate_inputs {
            context_for(bindings, policy)
        } else {
            // Private corpus helper, deliberately outside the production contract.
            let mut context = Context::default();
            for (name, value) in &bindings.variables {
                context.add_variable_from_value(name, value.clone());
            }
            (Ok(context), crate::charges::Cost::ZERO)
        };
        let context = match context {
            Ok(c) => c,
            Err(e) => return (Err(e), crate::charges::Cost::ZERO, input_cost),
        };
        let (result, cost) = prepared.program.execute_budgeted(&context, budget);
        (result, cost, input_cost)
    };
    let (result, cost, input_cost) = (if on_current_thread {
        Ok(worker())
    } else {
        run_on_pool(worker)
    })
    .unwrap_or_else(|msg| {
        (
            Err(ExecutionError::InternalError(msg)),
            crate::charges::Cost::ZERO,
            crate::charges::Cost::ZERO,
        )
    });
    EvalReport {
        policy_id: policy.id(),
        interim: policy.interim(),
        budget_scope,
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

/// Caller validated the entire snapshot before entering this construction phase.
pub(crate) fn context_for(
    bindings: &Bindings,
    policy: &Policy,
) -> (
    Result<Context<'static>, ExecutionError>,
    crate::charges::Cost,
) {
    crate::load::account(policy.input_load_budget(), || {
        let (nodes, bytes) = bindings
            .variables
            .iter()
            .fold((0u64, 0u64), |(n, b), (name, v)| {
                let (vn, vb) = crate::load::metrics(v);
                (
                    n.saturating_add(vn.saturating_add(1)),
                    b.saturating_add(vb.saturating_add(name.len() as u64).saturating_add(64)),
                )
            });
        crate::meter::charge_cost(crate::charges::input_decode(nodes, bytes))?;
        crate::meter::note_op_body();
        let mut context = Context::default();
        for (name, value) in &bindings.variables {
            context.add_variable_as_val(name, crate::load::convert(value)?);
        }
        Ok(context)
    })
}

/// Run `f` on a dedicated thread with a stack of at least 8 MiB.
///
/// Choice of mechanism (per-call scoped thread, not a fixed pool):
/// spawning is microseconds against millisecond parse/eval work,
/// and a thread per call needs no shared pool state, lifecycle, or
/// shutdown. Revisit with a fixed pool only if profiling says the
/// spawn cost matters. `T: Send` is required: the outcome crosses
/// back to the caller. Unwinding worker panics become `Err`; `catch_unwind`
/// cannot recover process aborts such as stack overflow. Native 4/8 MiB probes
/// exercise the tested source/value/shape boundary fixtures on this closure.
pub(crate) fn run_on_pool<T, F>(f: F) -> Result<T, String>
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    // Only the isolated combined-stack test child, on its explicit worker,
    // may bypass dispatch. Public rule/guard phases then use that same stack
    // and the same panic mapping; ordinary callers still take the 8 MiB path.
    #[cfg(test)]
    if std::thread::current().name() == Some("cel-native-combined-stack")
        && matches!(
            std::env::var("CEL_NATIVE_COMBINED_STACK_BYTES")
                .ok()
                .and_then(|s| s.parse::<usize>().ok()),
            Some(4_194_304 | 8_388_608)
        )
    {
        return catch_unwind(AssertUnwindSafe(f))
            .map_err(|_| "cel-subset worker failed".to_string());
    }
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name("cel-subset-pool".into())
            .stack_size(STACK_8MIB)
            .spawn_scoped(scope, || {
                catch_unwind(AssertUnwindSafe(f))
                    .map_err(|_| "cel-subset worker failed".to_string())
            });
        match handle {
            // The closure already maps panics via `catch_unwind`, so a
            // join error here is unreachable in practice; keep it an
            // error rather than a panic out of caution.
            Ok(handle) => handle
                .join()
                .unwrap_or_else(|_| Err("cel-subset worker failed".to_string())),
            Err(e) => Err(format!("cel-subset worker failed to spawn: {e}")),
        }
    })
}

/// A check-time refusal (parse error, or an inadmissible `matches`
/// pattern) rendered as `ParseErrors`.
pub(crate) fn check_error_at(program: &Program, expr_id: u64, msg: String) -> ParseErrors {
    ParseErrors {
        errors: vec![ParseError {
            source: None,
            pos: program.source_info().pos_for(expr_id).unwrap_or_default(),
            msg,
            expr_id,
            source_info: Some(program.source_info().clone()),
        }],
    }
}
pub(crate) fn check_error(msg: String) -> ParseErrors {
    ParseErrors {
        errors: vec![ParseError {
            source: None,
            pos: (0, 0),
            msg,
            expr_id: 0,
            source_info: None,
        }],
    }
}

#[test]
fn pool_types_are_send_sync() {
    fn assert<T: Send + Sync>() {}
    // Everything the pool moves or shares across threads.
    assert::<Prepared>();
    assert::<Bindings>();
    assert::<Value>();
    assert::<ExecutionError>();
    assert::<ParseErrors>();
}
