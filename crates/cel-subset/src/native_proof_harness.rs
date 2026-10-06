//! Private native proof runner. Admission is always through the public API.
//! Candidate generation, policy calibration, adapter semantics and hosted proof
//! belong to callers. Exact expanded-AST strings establish syntactic distinctness
//! only; generator types, parser ids, positions and example ids are excluded.
use super::native_fixture_sets::{Expected, Fixture, Scenario, Source};
use super::native_rule_generator::GeneratedSet;
use crate::common::ast::{EntryExpr, Expr, IdedExpr, LiteralValue};
use crate::common::value::Val;
use crate::{
    api, Bindings, Bound, Declarations, EvalCost, ExecutionError, InputKind, Policy,
    PrefixProgress, PreparedGuard, PreparedRule, RuleDecision, Value,
};
use serde::Serialize;
use serde_json::{json, Value as Json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Serialize)]
pub(crate) struct ProofCounts {
    pub candidates: usize,
    pub canonicalized: usize,
    pub canonical_missing: usize,
    pub distinct_candidates: usize,
    pub duplicate_candidates: usize,
    pub admitted_candidates: usize,
    pub rejected_candidates: usize,
    pub admitted_distinct: usize,
    pub rejected_distinct: usize,
    pub exercised_distinct: usize,
    pub successful_distinct: usize,
    pub semantic_error_distinct: usize,
    pub value_executions: usize,
    pub semantic_error_executions: usize,
    pub input_refusals: usize,
    pub guard_value_executions: usize,
    pub guard_semantic_error_executions: usize,
    pub guard_failure_executions: usize,
    pub required_missing_events: usize,
    pub required_replacements: usize,
    pub no_token_required: usize,
    pub no_token_guard_error: usize,
    pub false_refusals: usize,
    pub failures: usize,
}
#[derive(Debug, Serialize)]
pub(crate) struct ProofReport {
    pub policy_id: &'static str,
    pub interim: bool,
    pub mode: &'static str,
    pub limits: Json,
    pub counts: ProofCounts,
    pub by_family: BTreeMap<String, Json>,
    pub generator: Option<Json>,
    pub cases: Vec<Json>,
    pub failures: Vec<Json>,
}

/// Mandatory fixture expectations apply here; CandidateDependent is excluded
/// from false refusals. Repeated definitions still execute all their scenarios.
pub(crate) fn fixture_batch(fixtures: &[Fixture], policy: &Policy) -> ProofReport {
    on_worker(|| batch(fixtures, policy, false))
}
/// Generated success labels are semantic candidates, not cost-admission promises.
/// Refused draws stay visible and never become grammar rejections or disappear.
pub(crate) fn generated_corpus(generated: &GeneratedSet, policy: &Policy) -> ProofReport {
    generated_report(generated, policy, false)
}
/// Same exhaustive execution/identity checks, with reproducible successful
/// binding/result payloads dropped after their audits. Failures stay complete.
pub(crate) fn generated_summary(generated: &GeneratedSet, policy: &Policy) -> ProofReport {
    generated_report(generated, policy, true)
}
fn generated_report(generated: &GeneratedSet, policy: &Policy, prune: bool) -> ProofReport {
    on_worker(|| {
        let fixtures = generated
            .rules
            .iter()
            .map(|r| r.fixture.clone())
            .collect::<Vec<_>>();
        let mut report = batch_inner(&fixtures, policy, true, prune);
        let c = &generated.counts;
        report.generator = Some(json!({
            "seed": generated.seed, "version": generated.version,
            "requested_successes": c.requested_successes, "generated_candidates": c.generated_candidates,
            "successful_candidates": c.successful_candidates, "semantic_error_candidates": c.semantic_error_candidates,
            "attempts": c.attempts, "retries": c.retries, "canonical_duplicates": c.canonical_duplicates,
            "structural_duplicates": c.structural_duplicates, "grammar_limit_rejections": c.grammar_limit_rejections,
            "exhausted_attempt_budget": c.exhausted_attempt_budget,
            "attempted_by_family": c.attempted_by_family, "generated_by_family": c.generated_by_family,
            "generated_by_output_type": c.generated_by_output_type, "features": c.features,
            "note": "Generator counters are provenance; actual public admissions are counts.admitted_distinct. No hidden resampling."
        }));
        for (case, rule) in report.cases.iter_mut().zip(&generated.rules) {
            case["generator"] = json!({"seed":generated.seed,"version":generated.version,"attempt": rule.attempt, "family": rule.metadata.family,
                "intentional_semantic_error": rule.metadata.intentional_semantic_error,
                "features": rule.metadata.features, "nodes": rule.metadata.nodes,
                "expanded_depth_bound": rule.metadata.expanded_depth_bound,
                "comprehension_body_depth": rule.metadata.comprehension_body_depth});
        }
        // Refresh witnesses after adding seed/attempt provenance.
        report.failures = report
            .cases
            .iter()
            .filter(|c| c["failures"].as_array().is_some_and(|f| !f.is_empty()))
            .cloned()
            .collect();
        report
    })
}
// Canonical recursion and diagnostic value conversion live on an explicit native
// worker. Public calls retain their own engine pool and scoped accounts.
fn on_worker<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("native-proof".into())
            .stack_size(crate::STACK_8MIB)
            .spawn_scoped(scope, f)
            .expect("native proof worker creation")
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}
fn cost(c: EvalCost) -> Json {
    json!({"work": c.work, "memory": c.memory})
}
fn bound(b: Bound) -> Json {
    json!({"work":b.work,"memory":b.memory,"retained":b.retained,"result_nodes":b.result_nodes,
        "result_bytes":b.result_bytes,"result_depth":b.result_depth,"resource_product":b.resource_product})
}
fn declarations(f: &Fixture) -> Json {
    json!(f
        .declarations
        .iter()
        .map(|d| json!({"name":d.name,"kind":format!("{:?}",d.kind)}))
        .collect::<Vec<_>>())
}
fn definition(f: &Fixture) -> Json {
    let source = match &f.source {
        Source::Expression(s) => json!({"expression":s}),
        Source::Clauses(cs) => {
            json!({"clauses":cs.iter().map(|c| json!({"id":c.id,"when":c.when,"result":c.result})).collect::<Vec<_>>()})
        }
    };
    json!({"source":source,"declarations":declarations(f),"guards":f.guards.iter().map(|g|
        json!({"input":g.pending_input_name,"source":g.source})).collect::<Vec<_>>(),
        "input_metadata":f.input_metadata})
}
/// Lossless tagged witness encoding, including float bits and ordered map keys.
/// Adapter JSON is stored separately and never executed or compared to raw CEL.
fn value(v: &Value) -> Json {
    match v {
        Value::List(xs) => json!(["List", xs.iter().map(value).collect::<Vec<_>>()]),
        Value::Map(m) => json!([
            "Map",
            m.map
                .iter()
                .map(|(k, v)| json!([format!("{k:?}"), value(v)]))
                .collect::<Vec<_>>()
        ]),
        Value::Int(v) => json!(["Int", v]),
        Value::UInt(v) => json!(["UInt", v]),
        Value::Float(v) => json!(["DoubleBits", format!("{:016x}", v.to_bits())]),
        Value::String(v) => json!(["String", v.as_str()]),
        Value::Bytes(v) => json!(["Bytes", v.as_slice()]),
        Value::Bool(v) => json!(["Bool", v]),
        Value::Null => json!(["Null"]),
        Value::Duration(v) => json!(["Duration", v.num_seconds(), v.subsec_nanos()]),
        Value::Timestamp(v) => json!(["Timestamp", v.to_rfc3339()]),
        _ => json!(["UnsupportedWitness", format!("{v:?}")]),
    }
}
fn bindings(s: &Scenario) -> Json {
    json!(s
        .bindings
        .iter()
        .map(|(n, v)| json!({"name":n,"value":value(v)}))
        .collect::<Vec<_>>())
}
fn error_kind(e: &ExecutionError) -> &'static str {
    match e {
        ExecutionError::WorkBudgetExceeded(_) => "WorkBudgetExceeded",
        ExecutionError::MemoryBudgetExceeded(_) => "MemoryBudgetExceeded",
        ExecutionError::InternalError(_) => "InternalError",
        ExecutionError::InternalLimit(_) => "InternalLimit",
        ExecutionError::PolicyMismatch(_) => "PolicyMismatch",
        ExecutionError::InputRefused { .. } => "InputRefused",
        ExecutionError::FunctionError { .. } => "FunctionError",
        ExecutionError::NoSuchOverload => "NoSuchOverload",
        ExecutionError::UnexpectedType { .. } => "UnexpectedType",
        ExecutionError::Overflow(..) => "Overflow",
        ExecutionError::UnaryOverflow(..) => "UnaryOverflow",
        ExecutionError::NoSuchKey(_) => "NoSuchKey",
        ExecutionError::UndeclaredReference(_) => "UndeclaredReference",
        ExecutionError::UnsupportedKeyType(_) => "UnsupportedKeyType",
        ExecutionError::UnsupportedIndex(..) => "UnsupportedIndex",
        ExecutionError::IndexOutOfBounds(_) => "IndexOutOfBounds",
        ExecutionError::DivisionByZero(_) => "DivisionByZero",
        ExecutionError::RemainderByZero(_) => "RemainderByZero",
        ExecutionError::InvalidArgumentCount { .. } => "InvalidArgumentCount",
        ExecutionError::UnsupportedTargetType { .. } => "UnsupportedTargetType",
        ExecutionError::NotSupportedAsMethod { .. } => "NotSupportedAsMethod",
        ExecutionError::MissingArgumentOrTarget => "MissingArgumentOrTarget",
        ExecutionError::ValuesNotComparable(..) => "ValuesNotComparable",
        ExecutionError::UnsupportedBinaryOperator(..) => "UnsupportedBinaryOperator",
        _ => "OtherSemanticError",
    }
}
fn error(e: &ExecutionError) -> Json {
    let mut detail = json!({"category":error_kind(e),"diagnostic":e.to_string()});
    if let ExecutionError::InputRefused {
        cap,
        path,
        measured,
        limit,
        message,
    } = e
    {
        detail["input_refusal"] =
            json!({"cap":cap,"path":path,"measured":measured,"limit":limit,"message":message});
    }
    detail
}
fn semantic(e: &ExecutionError) -> bool {
    !matches!(
        error_kind(e),
        "WorkBudgetExceeded"
            | "MemoryBudgetExceeded"
            | "InternalError"
            | "InternalLimit"
            | "PolicyMismatch"
            | "InputRefused"
    )
}
fn legitimate(e: Expected) -> bool {
    matches!(
        e,
        Expected::AdmitValue
            | Expected::AdmitSemanticError(_)
            | Expected::AdmitValueOrSemanticError
    )
}
fn compatible(e: Expected, outcome: Result<(), &ExecutionError>, guard: bool) -> bool {
    match (e, outcome) {
        (Expected::AdmitValue, Ok(()))
        | (Expected::AdmitValueOrSemanticError, Ok(()))
        | (Expected::CandidateDependent(_), Ok(())) => true,
        (Expected::AdmitSemanticError(want), Err(got)) => {
            semantic(got)
                && (want == error_kind(got)
                    || guard && want == "guard-result-kind" && error_kind(got) == "NoSuchOverload")
        }
        (Expected::AdmitValueOrSemanticError, Err(got))
        | (Expected::CandidateDependent(_), Err(got)) => semantic(got),
        _ => false,
    }
}
fn audit(
    b: Bound,
    c: EvalCost,
    input: EvalCost,
    result: Result<Option<&Value>, &ExecutionError>,
    scope: &str,
) -> (Json, Vec<String>) {
    let mut failures = vec![];
    if c.work > b.work {
        failures.push("work_underbound".into());
    }
    if c.memory > b.memory {
        failures.push("memory_underbound".into());
    }
    let mut output = Json::Null;
    if let Ok(Some(v)) = result {
        let mut depth = 0usize;
        let mut stack = vec![(v, 1usize)];
        while let Some((v, d)) = stack.pop() {
            depth = depth.max(d);
            match v {
                Value::List(xs) => stack.extend(xs.iter().map(|x| (x, d.saturating_add(1)))),
                Value::Map(m) => stack.extend(m.map.values().map(|x| (x, d.saturating_add(1)))),
                _ => {}
            }
        }
        match Box::<dyn Val>::try_from(v.clone()) {
            Ok(v) => {
                let nodes = v.cached_nodes();
                let bytes = v.cached_bytes();
                if nodes > b.result_nodes {
                    failures.push("output_nodes_underbound".into());
                }
                if bytes > b.result_bytes {
                    failures.push("output_bytes_underbound".into());
                }
                if depth > b.result_depth {
                    failures.push("output_depth_underbound".into());
                }
                output = json!({"cached_nodes":nodes,"cached_bytes":bytes,"depth":depth});
            }
            Err(e) => failures.push(format!("output_metric_conversion: {e}")),
        }
    }
    if let Err(e) = result {
        if !semantic(e) {
            failures.push(format!("execution_failure: {}", error_kind(e)));
        }
    }
    (
        json!({"bound":bound(b),"cost":cost(c),"input_cost":cost(input),"budget_scope":scope,
        "output":output,"error":result.err().map(error),"failures":failures}),
        failures,
    )
}

// Lexical scope matches execution: range/init are outside this binder, loop
// condition/step see iter+accu, result sees accu only. De Bruijn distances also
// distinguish shadowing of iterator, accumulator and caller free names.
fn ast(e: &IdedExpr, env: &mut Vec<String>) -> Json {
    let rec = |e: &IdedExpr, env: &mut Vec<String>| ast(e, env);
    let entry = |e: &crate::common::ast::IdedEntryExpr, env: &mut Vec<String>| match &e.expr {
        EntryExpr::MapEntry(m) => {
            json!(["entry", rec(&m.key, env), rec(&m.value, env), m.optional])
        }
        EntryExpr::StructField(s) => json!(["field", s.field, rec(&s.value, env), s.optional]),
    };
    match &e.expr {
        Expr::Unspecified => json!(["unspecified"]),
        Expr::Ident(n) => match env.iter().rev().position(|v| v == n) {
            Some(i) => json!(["bound", i]),
            None => json!(["free", n]),
        },
        Expr::Literal(v) => match v {
            LiteralValue::Boolean(v) => json!(["bool", v.inner()]),
            LiteralValue::Int(v) => json!(["int", v.inner()]),
            LiteralValue::UInt(v) => json!(["uint", v.inner()]),
            LiteralValue::Double(v) => {
                json!(["double_bits", format!("{:016x}", v.inner().to_bits())])
            }
            LiteralValue::String(v) => json!(["string", v.inner()]),
            LiteralValue::Bytes(v) => json!(["bytes", v.inner()]),
            LiteralValue::Null => json!(["null"]),
        },
        Expr::Call(c) => json!([
            "call",
            c.func_name,
            c.target.as_ref().map(|t| rec(t, env)),
            c.args.iter().map(|a| rec(a, env)).collect::<Vec<_>>()
        ]),
        Expr::Select(s) => json!(["select", rec(&s.operand, env), s.field, s.test]),
        Expr::List(l) => json!([
            "list",
            l.elements.iter().map(|e| rec(e, env)).collect::<Vec<_>>(),
            l.optional_indices
        ]),
        Expr::Map(m) => json!([
            "map",
            m.entries.iter().map(|e| entry(e, env)).collect::<Vec<_>>()
        ]),
        Expr::Struct(s) => json!([
            "struct",
            s.type_name,
            s.entries.iter().map(|e| entry(e, env)).collect::<Vec<_>>()
        ]),
        Expr::Comprehension(c) => {
            let range = rec(&c.iter_range, env);
            let init = rec(&c.accu_init, env);
            let start = env.len();
            env.push(c.accu_var.clone());
            env.push(c.iter_var.clone());
            if let Some(v) = &c.iter_var2 {
                env.push(v.clone());
            }
            let cond = rec(&c.loop_cond, env);
            let step = rec(&c.loop_step, env);
            env.truncate(start);
            env.push(c.accu_var.clone());
            let result = rec(&c.result, env);
            env.truncate(start);
            json!([
                "comprehension",
                c.iter_var2.is_some(),
                range,
                init,
                cond,
                step,
                result
            ])
        }
    }
}
fn measures(m: crate::Measures) -> Json {
    json!({"source_bytes":m.source_bytes,"real_tokens":m.real_tokens,"expanded_nodes":m.expanded_nodes,
        "ast_depth":m.ast_depth,"comprehensions":m.comprehensions,"comprehension_depth":m.comprehension_depth,"value_depth":m.value_depth})
}
fn expression_key(
    source: &str,
    d: Option<&Declarations>,
    p: &Policy,
) -> Result<(Json, Json), String> {
    // Prefer the admitted immutable AST. A refused parse is diagnostic identity
    // only, never admission or estimator evidence.
    if let Some(d) = d {
        let report = api::check(source, d, p);
        if let Ok(checked) = report.result {
            return Ok((
                ast(checked.program.expression(), &mut vec![]),
                json!({"origin":"public-prepared","measures":measures(checked.measures()),
                    "identity_check_load_cost":cost(report.load_cost)}),
            ));
        }
    }
    crate::Program::compile(source)
        .map(|program| {
            (
                ast(program.expression(), &mut vec![]),
                json!({"origin":"parsed-definition-only","source_bytes":source.len(),"measures":null,"identity_check_load_cost":null}),
            )
        })
        .map_err(|e| e.to_string())
}
fn canonical(
    f: &Fixture,
    d: Option<&Declarations>,
    p: &Policy,
) -> Result<(String, Vec<Json>), String> {
    let mut origins = vec![];
    let mut key = |s: &str, d: Option<&Declarations>| -> Result<Json, String> {
        let (ast, origin) = expression_key(s, d, p)?;
        origins.push(origin);
        Ok(ast)
    };
    let source = match &f.source {
        Source::Expression(s) => json!(["expression", key(s, d)?]),
        Source::Clauses(cs) => {
            let phases = cs
                .iter()
                .map(|c| Ok(json!([key(&c.when, d)?, key(&c.result, d)?])))
                .collect::<Result<Vec<Json>, String>>()?;
            json!(["clauses", phases])
        }
    };
    let mut guards = vec![];
    for decl in &f.declarations {
        for g in f
            .guards
            .iter()
            .filter(|g| g.pending_input_name == decl.name)
        {
            let checked = d.and_then(|d| {
                crate::check_guard(&g.source, &g.pending_input_name, d, p)
                    .result
                    .ok()
            });
            guards.push(json!([
                g.pending_input_name,
                key(&g.source, checked.as_ref().map(|g| g.declarations()))?
            ]));
        }
    }
    // Retain malformed unknown guard associations as well in rejection identity.
    for g in f.guards.iter().filter(|g| {
        !f.declarations
            .iter()
            .any(|d| d.name == g.pending_input_name)
    }) {
        guards.push(json!([g.pending_input_name, key(&g.source, None)?]));
    }
    Ok((
        json!(["native-expanded-ast-v1", declarations(f), source, guards]).to_string(),
        origins,
    ))
}

enum Admitted {
    Expression(crate::Prepared),
    Rule(PreparedRule),
}
impl Admitted {
    fn bound(&self) -> Bound {
        match self {
            Self::Expression(p) => p.bound(),
            Self::Rule(p) => p.bound(),
        }
    }
}
fn prepare(f: &Fixture, d: &Declarations, p: &Policy) -> (Result<Admitted, String>, Json) {
    if let Source::Expression(s) = &f.source {
        if f.guards.is_empty() {
            let checked = api::check(s, d, p);
            let diagnostic = checked.result.as_ref().err().map(ToString::to_string);
            let messages = checked
                .result
                .as_ref()
                .err()
                .map(|e| e.errors.iter().map(|e| e.msg.clone()).collect::<Vec<_>>());
            let load = cost(checked.load_cost);
            let native_aux = checked
                .result
                .as_ref()
                .ok()
                .map(|p| vec![("expression", p.native_aux())]);
            return (
                checked
                    .result
                    .map(Admitted::Expression)
                    .map_err(|e| e.to_string()),
                json!({"api":"api::check","load_cost":load,"diagnostic":diagnostic,"messages":messages,
                    "native_aux":native_aux}),
            );
        }
    }
    let clauses = match &f.source {
        Source::Expression(s) => vec![crate::Clause {
            id: "proof-envelope".into(),
            when: "true".into(),
            result: s.clone(),
        }],
        Source::Clauses(cs) => cs
            .iter()
            .map(|c| crate::Clause {
                id: c.id.clone(),
                when: c.when.clone(),
                result: c.result.clone(),
            })
            .collect(),
    };
    let guards = f
        .guards
        .iter()
        .map(|g| crate::GuardSource {
            input: g.pending_input_name.clone(),
            source: g.source.clone(),
        })
        .collect::<Vec<_>>();
    let checked = crate::check_rule(&clauses, d, &guards, p);
    let detail = json!({"api":"check_rule","load_cost":cost(checked.load_cost),
        "native_aux":checked.result.as_ref().ok().map(|p|p.native_aux_phases()),
        "diagnostic":checked.result.as_ref().err().map(ToString::to_string),
        "messages":checked.result.as_ref().err().map(|e|e.errors.errors.iter().map(|e|e.msg.clone()).collect::<Vec<_>>()),
        "crossing_phase":checked.result.as_ref().err().and_then(|e|e.phase).map(|p|format!("{p:?}")),
        "crossing_clause":checked.result.as_ref().err().and_then(|e|e.clause_id.as_ref())});
    (
        checked
            .result
            .map(Admitted::Rule)
            .map_err(|e| e.to_string()),
        detail,
    )
}
fn guard_audit(
    g: &PreparedGuard,
    report: &crate::GuardReport,
    phase: &str,
    p: &Policy,
) -> (Json, Vec<String>) {
    let v = report.result.as_ref().ok().map(|b| Value::Bool(*b));
    let result = match &report.result {
        Ok(_) => Ok(v.as_ref()),
        Err(e) => Err(e),
    };
    let (mut row, mut failures) = audit(
        g.bound(),
        report.cost,
        report.input_cost,
        result,
        report.budget_scope,
    );
    if g.bound().work > p.guard_work_limit() || g.bound().memory > p.guard_mem_limit_bytes() {
        failures.push("guard_bound_exceeds_guard_ceiling".into());
    }
    row["input"] = json!(g.input());
    row["native_aux"] = json!(g.native_aux());
    row["phase"] = json!(phase);
    row["required"] = json!(report.result.as_ref().ok());
    row["semantic_error"] = json!(report.result.as_ref().err().is_some_and(semantic));
    if matches!(report.result, Err(ExecutionError::InputRefused { .. })) {
        let zero = report.cost == EvalCost::default();
        row["pre_body_cost_zero"] = json!(zero);
        if !zero {
            failures.push("guard_snapshot_refusal_consumed_body_cost".into());
        }
    }
    row["failures"] = json!(failures);
    (row, failures)
}
fn supplied<'a>(s: &'a Scenario, name: &str) -> Option<&'a Value> {
    s.bindings.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}
fn fill(d: &Declarations, s: &Scenario, p: &Policy) -> Result<Bindings, ExecutionError> {
    let mut b = Bindings::empty(d, p);
    for (name, v) in &s.bindings {
        b.insert(name, v)?;
    }
    Ok(b)
}
struct ScenarioRun {
    row: Json,
    failures: Vec<String>,
    outcome: &'static str,
    false_refusal: bool,
}
fn input_refusal(
    f: &Fixture,
    s: &Scenario,
    e: ExecutionError,
    stage: &str,
    candidate: bool,
    mut row: Json,
    mut failures: Vec<String>,
) -> ScenarioRun {
    let false_refusal = !candidate && legitimate(s.expected);
    // Once admitted, legitimate generated scenarios must also validate. The
    // candidate exemption applies to cost admission, not runtime input setup.
    if legitimate(s.expected) {
        failures.push("legitimate_input_refused".into());
    }
    if !matches!(e, ExecutionError::InputRefused { .. }) {
        failures.push(format!("input_setup_failure: {}", error_kind(&e)));
    }
    match expected_refusal(f, s, RefusalEvidence::Input(&e, stage)) {
        Ok(check) => row["expected_refusal_check"] = check,
        Err(issue) => {
            row["expected_refusal_check"] = json!({"matched":false,"issue":issue});
            if !failures.contains(&issue) {
                failures.push(issue);
            }
        }
    }
    row["outcome"] = json!("input_refusal");
    row["refusal_stage"] = json!(stage);
    row["error"] = error(&e);
    ScenarioRun {
        row,
        failures,
        outcome: "input_refusal",
        false_refusal,
    }
}
fn scenario(
    f: &Fixture,
    s: &Scenario,
    prepared: &Admitted,
    d: &Declarations,
    p: &Policy,
    candidate: bool,
) -> ScenarioRun {
    let mut row = json!({"name":s.name,"expected_category":format!("{:?}",s.expected),
        "bindings":bindings(s),"notes":s.notes,"opaque_adapter_expected":s.adapter_expected,
        "adapter_interpretation":"none; raw native CEL outcomes are separate"});
    let b = prepared.bound();
    let mut failures = vec![];
    if let Expected::Refuse(reason) = s.expected {
        if !known_refusal(reason) {
            failures.push(format!("unsupported_expected_refusal_reason: {reason}"));
        }
    }
    let guard_expectation = f.family == "ordered-guard";
    let mut guards = vec![];
    let mut events = vec![];
    let mut replacement_values: BTreeMap<String, Value> = BTreeMap::new();
    let (result, c, input, scope, phase) = match prepared {
        Admitted::Expression(prepared) => {
            let inputs = match fill(d, s, p) {
                Ok(b) => b,
                Err(e) => {
                    return input_refusal(f, s, e, "bindings.insert", candidate, row, failures)
                }
            };
            let r = api::evaluate(prepared, &inputs, p);
            (
                r.result.map(Some),
                r.cost,
                r.input_cost,
                r.budget_scope,
                Json::Null,
            )
        }
        Admitted::Rule(prepared) => {
            let args_d = prepared.argument_declarations();
            let mut args = Bindings::empty(&args_d, p);
            // All scalar arguments, including explicit time, precede every row.
            for decl in f
                .declarations
                .iter()
                .filter(|d| matches!(d.kind, InputKind::Scalar { .. }))
            {
                if let Some(v) = supplied(s, &decl.name) {
                    if let Err(e) = args.insert(&decl.name, v) {
                        return input_refusal(
                            f,
                            s,
                            e,
                            "arguments.insert",
                            candidate,
                            row,
                            failures,
                        );
                    }
                }
            }
            // Reject unexpected fixture names through the actual binding API.
            for (name, v) in &s.bindings {
                if !f.declarations.iter().any(|d| d.name == *name) {
                    let mut validation = Bindings::empty(d, p);
                    if let Err(e) = validation.insert(name, v) {
                        return input_refusal(
                            f,
                            s,
                            e,
                            "undeclared_binding",
                            candidate,
                            row,
                            failures,
                        );
                    }
                }
            }
            let mut prefix = match prepared.start_prefix(&args, p) {
                Ok(prefix) => prefix,
                Err(e) => return input_refusal(f, s, e, "start_prefix", candidate, row, failures),
            };
            for decl in f
                .declarations
                .iter()
                .filter(|d| !matches!(d.kind, InputKind::Scalar { .. }))
            {
                let name = &decl.name;
                if let Some(g) = prepared.guards().iter().find(|g| g.input() == name) {
                    let mut checked = Bindings::empty(g.declarations(), p);
                    for declared in f
                        .declarations
                        .iter()
                        .filter(|d| g.declarations().entries.contains_key(&d.name))
                    {
                        if let Some(v) = replacement_values
                            .get(&declared.name)
                            .or_else(|| supplied(s, &declared.name))
                        {
                            if let Err(e) = checked.insert(&declared.name, v) {
                                row["guards"] = json!(guards);
                                row["prefix"] = json!(events);
                                return input_refusal(
                                    f,
                                    s,
                                    e,
                                    "guard_prefix.insert",
                                    candidate,
                                    row,
                                    failures,
                                );
                            }
                        }
                    }
                    // These ordinary public inserts must reject pending/future
                    // row names; they cannot alter the checked guard snapshot.
                    let unavailable = f
                        .declarations
                        .iter()
                        .filter(|d| {
                            !matches!(d.kind, InputKind::Scalar { .. })
                                && !g.declarations().entries.contains_key(&d.name)
                        })
                        .map(|d| {
                            let refused = checked.insert(&d.name, &Value::Null).is_err();
                            if !refused {
                                failures.push("guard_pending_or_future_visible".into());
                            }
                            json!({"input":d.name,"insertion_refused":refused})
                        })
                        .collect::<Vec<_>>();
                    let report = crate::guard(g, &checked, p);
                    let (mut detail, issues) = guard_audit(g, &report, "standalone", p);
                    failures.extend(issues);
                    detail["unavailable_inputs"] = json!(unavailable);
                    detail["prefix_declarations"] = json!(g.declarations().order.as_ref());
                    detail["arguments"] = json!(args_d.entries.keys().collect::<Vec<_>>());
                    guards.push(detail);
                    if guard_expectation
                        && !compatible(s.expected, report.result.as_ref().map(|_| ()), true)
                    {
                        failures.push("guard_expected_category_mismatch".into());
                    }
                    if let Err(e) = &report.result {
                        if semantic(e)
                            && !guard_expectation
                            && !matches!(
                                s.expected,
                                Expected::AdmitValueOrSemanticError
                                    | Expected::CandidateDependent(_)
                            )
                        {
                            failures.push("unexpected_guard_semantic_error".into());
                        }
                    }
                }
                let Some(v) = supplied(s, name) else {
                    row["guards"] = json!(guards);
                    row["prefix"] = json!(events);
                    let e = prefix
                        .finish()
                        .expect_err("missing declared row cannot mint a token");
                    return input_refusal(
                        f,
                        s,
                        e,
                        "finish_missing_scenario_input",
                        candidate,
                        row,
                        failures,
                    );
                };
                let progress = match prefix.append_next(name, v) {
                    Ok(progress) => progress,
                    Err(e) => {
                        row["guards"] = json!(guards);
                        row["prefix"] = json!(events);
                        return input_refusal(f, s, e, "append_next", candidate, row, failures);
                    }
                };
                events.push(json!({"input":name,"progress":format!("{progress:?}"),"next_input":prefix.next_input()}));
                if progress == PrefixProgress::GuardPending {
                    let g = prepared
                        .guards()
                        .iter()
                        .find(|g| g.input() == name)
                        .expect("public pending guard");
                    let report = match prefix.resolve_guard() {
                        Ok(r) => r,
                        Err(e) => {
                            failures.push(format!("resolve_guard_state_failure: {e}"));
                            row["guards"] = json!(guards);
                            row["prefix"] = json!(events);
                            return ScenarioRun {
                                row,
                                failures,
                                outcome: "guard_state_failure",
                                false_refusal: false,
                            };
                        }
                    };
                    let (detail, issues) = guard_audit(g, &report, "resolve_guard", p);
                    failures.extend(issues);
                    guards.push(detail);
                    match report.result {
                        Err(e) => {
                            if prefix.next_input() != Some(name.as_str()) {
                                failures.push("guard_error_advanced_prefix".into());
                            }
                            events.push(json!({"input":name,"state":"guard_error_pending","error":error(&e),"next_input":prefix.next_input()}));
                            if !guard_expectation && !compatible(s.expected, Err(&e), true) {
                                failures.push("guard_expected_category_mismatch".into());
                            }
                            let finish_refused = prefix.finish().is_err();
                            if !finish_refused {
                                failures.push("guard_error_minted_token".into());
                            }
                            row["guards"] = json!(guards);
                            row["prefix"] = json!(events);
                            row["finish_refused"] = json!(finish_refused);
                            row["outcome"] = json!("no_token_guard_error");
                            return ScenarioRun {
                                row,
                                failures,
                                outcome: "no_token_guard_error",
                                false_refusal: false,
                            };
                        }
                        Ok(false) => {
                            if prefix.next_input() == Some(name.as_str()) {
                                failures.push("false_guard_did_not_advance".into());
                            }
                            events.push(json!({"input":name,"state":"optional_empty_committed","next_input":prefix.next_input()}));
                        }
                        Ok(true) => {
                            if prefix.next_input() != Some(name.as_str()) {
                                failures.push("required_empty_advanced_prefix".into());
                            }
                            // Attempted advancement while required-empty stays
                            // pending must fail without exposing any later row.
                            let blocked = prefix
                                .append_next("__proof_unavailable", &Value::Null)
                                .is_err();
                            if !blocked {
                                failures.push("required_empty_skipped".into());
                            }
                            events.push(json!({"input":name,"state":"required_missing_pending","advance_refused":blocked,"next_input":prefix.next_input()}));
                            // A recorded native synthetic One is a separate raw
                            // execution input. Never substitute adapter results.
                            let replacement = Value::from(indexmap::IndexMap::from([(
                                "proof_present".to_string(),
                                Value::Bool(true),
                            )]));
                            match prefix.append_next(name, &replacement) {
                                Ok(PrefixProgress::Advanced) => {
                                    events.push(json!({"input":name,"state":"required_replacement","original":value(v),"replacement":value(&replacement),"next_input":prefix.next_input()}));
                                    replacement_values.insert(name.clone(), replacement);
                                }
                                other => {
                                    events.push(json!({"input":name,"state":"no_token_required","replacement_attempt":format!("{other:?}")}));
                                    let refused = prefix.finish().is_err();
                                    if !refused {
                                        failures.push("required_empty_minted_token".into());
                                    }
                                    row["guards"] = json!(guards);
                                    row["prefix"] = json!(events);
                                    row["finish_refused"] = json!(refused);
                                    row["outcome"] = json!("no_token_required");
                                    return ScenarioRun {
                                        row,
                                        failures,
                                        outcome: "no_token_required",
                                        false_refusal: false,
                                    };
                                }
                            }
                        }
                    }
                }
            }
            let checked = match prefix.finish() {
                Ok(b) => b,
                Err(e) => {
                    row["guards"] = json!(guards);
                    row["prefix"] = json!(events);
                    return input_refusal(f, s, e, "finish", candidate, row, failures);
                }
            };
            let r = crate::evaluate_rule(prepared, &checked, p);
            let phase = match &r.result {
                Err(e) => {
                    json!({"clause_index":e.clause_index,"phase":e.phase.map(|p|format!("{p:?}"))})
                }
                Ok(RuleDecision::Matched { clause_index, .. }) => {
                    json!({"clause_index":clause_index,"phase":"Result"})
                }
                _ => Json::Null,
            };
            let result = r
                .result
                .map(|r| match r {
                    RuleDecision::Matched { value, .. } => Some(value),
                    RuleDecision::NoMatch => None,
                })
                .map_err(|e| e.error);
            (result, r.cost, r.input_cost, r.budget_scope, phase)
        }
    };
    row["guards"] = json!(guards);
    row["prefix"] = json!(events);
    row["phase"] = phase;
    row["replacement_execution"] = json!(!replacement_values.is_empty());
    row["actual_bindings"] = json!(s
        .bindings
        .iter()
        .map(|(name, v)| json!({"name":name,
        "value":value(replacement_values.get(name).unwrap_or(v))}))
        .collect::<Vec<_>>());
    if let Err(e @ ExecutionError::InputRefused { .. }) = result {
        let pre_body_zero = c == EvalCost::default();
        if !pre_body_zero {
            failures.push("input_snapshot_refusal_consumed_body_cost".into());
        }
        row["pre_body_cost_zero"] = json!(pre_body_zero);
        row["execution"] =
            json!({"cost":cost(c),"input_cost":cost(input),"budget_scope":scope,"error":error(&e)});
        return input_refusal(
            f,
            s,
            e,
            "evaluate_input_validation",
            candidate,
            row,
            failures,
        );
    }
    let borrowed = result.as_ref().map(|v| v.as_ref());
    let (detail, issues) = audit(b, c, input, borrowed, scope);
    failures.extend(issues);
    // Ordered-guard fixture expectations refer to guard semantics; its envelope
    // is true. Other categories describe raw CEL, never original adapter JSON.
    if !guard_expectation && !compatible(s.expected, result.as_ref().map(|_| ()), false) {
        failures.push("body_expected_category_mismatch".into());
    }
    let outcome = match &result {
        Ok(_) => "value",
        Err(e) if semantic(e) => "semantic_error",
        Err(_) => "execution_failure",
    };
    row["execution"] = detail;
    row["outcome"] = json!(outcome);
    row["raw_result"] = match &result {
        Ok(Some(v)) => value(v),
        Ok(None) => json!(["NoMatch"]),
        Err(e) => error(e),
    };
    ScenarioRun {
        row,
        failures,
        outcome,
        false_refusal: false,
    }
}

/// Match structured messages/caps, never source snippets in formatted errors.
/// Expected input refusal cannot be certified by an earlier admission rejection.
enum RefusalEvidence<'a> {
    Admission(&'a Json),
    Input(&'a ExecutionError, &'a str),
}
fn known_refusal(reason: &str) -> bool {
    matches!(
        reason,
        "many-cross-product"
            | "many-product-or-repeated-many-traversal"
            | "total-serialized-input-bytes"
            | "guard-self-reference"
            | "guard-future-reference"
            | "external-scalar-kind-or-nonfinite"
    )
}
fn expected_refusal(
    f: &Fixture,
    s: &Scenario,
    evidence: RefusalEvidence<'_>,
) -> Result<Json, String> {
    let Expected::Refuse(reason) = s.expected else {
        return Ok(Json::Null);
    };
    if !known_refusal(reason) {
        return Err(format!("unsupported_expected_refusal_reason: {reason}"));
    }
    let matched = match evidence {
        RefusalEvidence::Admission(detail) => {
            let messages = detail["messages"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Json::as_str)
                .collect::<Vec<_>>();
            match reason {
                "many-cross-product" | "many-product-or-repeated-many-traversal" => {
                    messages.iter().any(|m| {
                        m.starts_with("cross_product:")
                            || m.starts_with("whole_rule_cross_product:")
                    })
                }
                "guard-self-reference" | "guard-future-reference" => {
                    detail["api"] == "check_rule"
                        && detail["crossing_phase"].is_null()
                        && f.guards.iter().any(|g| {
                            let rows = f
                                .declarations
                                .iter()
                                .filter(|d| !matches!(d.kind, InputKind::Scalar { .. }))
                                .collect::<Vec<_>>();
                            let Some(index) = rows.iter().position(|d| {
                                d.name == g.pending_input_name && d.kind == InputKind::One
                            }) else {
                                return false;
                            };
                            let forbidden = if reason == "guard-self-reference" {
                                &rows[index..=index]
                            } else {
                                &rows[index + 1..]
                            };
                            forbidden.iter().any(|d| {
                                messages.iter().any(|m| {
                                    *m == format!(
                                    "undeclared binding '{}'; declare its shape before checking",
                                    d.name
                                )
                                })
                            })
                        })
                }
                _ => false,
            }
        }
        RefusalEvidence::Input(e, stage) => {
            let ExecutionError::InputRefused { cap, path, .. } = e else {
                return Err(format!(
                    "expected_refusal_reason_mismatch: {reason}: non-input error"
                ));
            };
            let insertion_or_load = matches!(
                stage,
                "bindings.insert"
                    | "arguments.insert"
                    | "append_next"
                    | "guard_prefix.insert"
                    | "evaluate_input_validation"
            );
            match reason {
                "total-serialized-input-bytes" => {
                    insertion_or_load && cap == "total_bytes" && path == "bindings"
                }
                "external-scalar-kind-or-nonfinite" => {
                    let mut pending = s
                        .bindings
                        .iter()
                        .map(|(name, v)| (name.clone(), v))
                        .collect::<Vec<_>>();
                    let mut match_found = false;
                    while let Some((at, v)) = pending.pop() {
                        let truncated: String = at.chars().take(128).collect();
                        match v {
                            Value::UInt(_) => {
                                match_found |= cap == "scalar_shape" && *path == truncated
                            }
                            Value::Float(v) if !v.is_finite() => {
                                match_found |= cap == "safe_number" && *path == truncated
                            }
                            Value::Map(m) => {
                                for (key, v) in m.map.iter() {
                                    if let crate::objects::Key::String(key) = key {
                                        pending.push((
                                            format!(
                                                "{at}.{}",
                                                key.chars().take(64).collect::<String>()
                                            ),
                                            v,
                                        ));
                                    }
                                }
                            }
                            Value::List(xs) => pending.extend(
                                xs.iter()
                                    .enumerate()
                                    .map(|(i, v)| (format!("{at}[{i}]"), v)),
                            ),
                            _ => {}
                        }
                    }
                    insertion_or_load && match_found
                }
                _ => false,
            }
        }
    };
    if matched {
        Ok(json!({"required_reason":reason,"matched":true}))
    } else {
        Err(format!("expected_refusal_reason_mismatch: {reason}"))
    }
}

/// ParseError.msg is the structured message, excluding source/line rendering.
/// Only the exact engine admission codes below permit a generated rejection.
/// Identifiers/source text that happen to contain a code never classify it.
fn rejection(admission: &Json) -> (&'static str, &'static str, bool) {
    if admission["api"] == "Declarations::new" {
        return ("declarations", "input_contract", false);
    }
    let Some(messages) = admission["messages"].as_array().filter(|m| !m.is_empty()) else {
        return ("unknown", "missing_structured_messages", false);
    };
    let mut category = None;
    for message in messages {
        let code = message
            .as_str()
            .and_then(|m| m.split_once(':').map(|(c, _)| c));
        let next = match code {
            Some("cross_product" | "whole_rule_cross_product") => "cross_product",
            Some("work_cost" | "whole_rule_work_cost") => "work_cost",
            Some("memory_cost" | "whole_rule_memory_cost") => "memory_cost",
            _ => {
                return (
                    "parser_shape_names_or_internal",
                    "unpermitted_rejection",
                    false,
                )
            }
        };
        if category.is_some_and(|prior| prior != next) {
            return ("unknown", "inconsistent_rejection_codes", false);
        }
        category = Some(next);
    }
    let category = category.expect("nonempty messages");
    let stage = if category == "cross_product" {
        "resource_product"
    } else if admission["api"] == "check_rule" && admission["crossing_phase"].is_null() {
        "guard_admission"
    } else {
        "body_admission"
    };
    (stage, category, true)
}
fn batch(fixtures: &[Fixture], p: &Policy, candidate: bool) -> ProofReport {
    batch_inner(fixtures, p, candidate, false)
}
fn batch_inner(fixtures: &[Fixture], p: &Policy, candidate: bool, prune: bool) -> ProofReport {
    let mut report = ProofReport {
        policy_id: p.id(),
        interim: p.interim(),
        mode: if candidate {
            "generated-candidates"
        } else {
            "mandatory-fixtures"
        },
        limits: json!({"work":p.work_limit(),"memory":p.mem_limit_bytes(),"guard_work":p.guard_work_limit(),
            "guard_memory":p.guard_mem_limit_bytes(),"string_bytes":p.string_bytes_candidate(),"input_count":p.input_count_candidate()}),
        counts: ProofCounts::default(),
        by_family: BTreeMap::new(),
        generator: None,
        cases: vec![],
        failures: vec![],
    };
    let mut canonical_seen = BTreeMap::<String, usize>::new();
    let mut admitted = BTreeSet::new();
    let mut rejected = BTreeSet::new();
    let mut exercised = BTreeSet::new();
    let mut successful = BTreeSet::new();
    let mut semantic_errors = BTreeSet::new();
    let mut families = BTreeMap::<String, BTreeMap<String, usize>>::new();
    for (index, f) in fixtures.iter().enumerate() {
        report.counts.candidates += 1;
        let family = families.entry(f.family.into()).or_default();
        *family.entry("candidates".into()).or_default() += 1;
        for s in &f.scenarios {
            *family
                .entry(format!("expected:{:?}", s.expected))
                .or_default() += 1;
        }
        let d = Declarations::new(f.declarations.clone(), p);
        let key = canonical(f, d.as_ref().ok(), p);
        let mut case = json!({"index":index,"name":f.name,"family":f.family,"definition":definition(f),
            "canonical":null,"canonical_origins":[],"duplicate_of":null,"failures":[]});
        let mut canonical_string = None;
        match key {
            Ok((key, origins)) => {
                report.counts.canonicalized += 1;
                if let Some(prior) = canonical_seen.get(&key) {
                    report.counts.duplicate_candidates += 1;
                    case["duplicate_of"] = json!(prior);
                } else {
                    canonical_seen.insert(key.clone(), index);
                }
                case["canonical"] = json!(key);
                case["canonical_origins"] = json!(origins);
                canonical_string = Some(key);
            }
            Err(diagnostic) => {
                report.counts.canonical_missing += 1;
                case["canonical_diagnostic"] = json!(diagnostic);
            }
        }
        let (prepared, admission) = match &d {
            Ok(d) => prepare(f, d, p),
            Err(e) => (
                Err(e.to_string()),
                json!({"api":"Declarations::new","diagnostic":error(e),"load_cost":null}),
            ),
        };
        case["admission"] = admission;
        let mut issues = vec![];
        if candidate && canonical_string.is_none() {
            issues.push("generated_definition_missing_canonical".into());
        }
        match prepared {
            Err(diagnostic) => {
                let (stage, category, permitted) = rejection(&case["admission"]);
                if candidate && !permitted {
                    issues.push(format!("unpermitted_generated_rejection: {category}"));
                }
                report.counts.rejected_candidates += 1;
                *family.entry("rejected_candidates".into()).or_default() += 1;
                *family
                    .entry(format!("rejection_stage:{stage}"))
                    .or_default() += 1;
                *family
                    .entry(format!("rejection_reason:{category}"))
                    .or_default() += 1;
                if let Some(key) = &canonical_string {
                    rejected.insert(key.clone());
                }
                case["admitted"] = json!(false);
                case["refusal_stage"] = json!(stage);
                case["rejection_category"] = json!(category);
                case["candidate_rejection_permitted"] = json!(permitted);
                case["scenarios"] = json!(f.scenarios.iter().map(|s|{
                    let false_refusal = !candidate && legitimate(s.expected);
                    if false_refusal {report.counts.false_refusals+=1;issues.push(format!("legitimate_fixture_refused: {}",s.name));}
                    let refusal_check = match expected_refusal(f,s,RefusalEvidence::Admission(&case["admission"])) {
                        Ok(check)=>check,Err(issue)=>{issues.push(format!("{}: {issue}",s.name));json!({"matched":false,"issue":issue})}
                    };
                    json!({"name":s.name,"expected_category":format!("{:?}",s.expected),"bindings":bindings(s),"expected_refusal_check":refusal_check,
                        "opaque_adapter_expected":s.adapter_expected,"outcome":"admission_refused","diagnostic":diagnostic,
                        "false_refusal":false_refusal})
                }).collect::<Vec<_>>());
            }
            Ok(prepared) => {
                report.counts.admitted_candidates += 1;
                *family.entry("admitted_candidates".into()).or_default() += 1;
                case["admitted"] = json!(true);
                case["bound"] = bound(prepared.bound());
                if let Some(key) = &canonical_string {
                    admitted.insert(key.clone());
                } else {
                    issues.push("admitted_definition_missing_canonical".into());
                }
                let mut rows = vec![];
                for s in &f.scenarios {
                    let mut run = scenario(
                        f,
                        s,
                        &prepared,
                        d.as_ref().expect("admitted declarations"),
                        p,
                        candidate,
                    );
                    if run.false_refusal {
                        report.counts.false_refusals += 1;
                    }
                    match run.outcome {
                        "value" => {
                            report.counts.value_executions += 1;
                            if let Some(k) = &canonical_string {
                                exercised.insert(k.clone());
                                successful.insert(k.clone());
                            }
                        }
                        "semantic_error" => {
                            report.counts.semantic_error_executions += 1;
                            if let Some(k) = &canonical_string {
                                exercised.insert(k.clone());
                                semantic_errors.insert(k.clone());
                            }
                        }
                        "input_refusal" => report.counts.input_refusals += 1,
                        "no_token_required" => report.counts.no_token_required += 1,
                        "no_token_guard_error" => report.counts.no_token_guard_error += 1,
                        _ => {}
                    }
                    if let Some(category) = run.row["execution"]["error"]["category"].as_str() {
                        *family.entry(format!("body_error:{category}")).or_default() += 1;
                    }
                    for g in run.row["guards"].as_array().into_iter().flatten() {
                        if g["error"].is_null() {
                            report.counts.guard_value_executions += 1;
                            *family.entry("guard_value_executions".into()).or_default() += 1;
                        } else if g["semantic_error"] == true {
                            report.counts.guard_semantic_error_executions += 1;
                            *family
                                .entry(format!(
                                    "guard_error:{}",
                                    g["error"]["category"].as_str().unwrap_or("unknown")
                                ))
                                .or_default() += 1;
                        } else {
                            report.counts.guard_failure_executions += 1;
                        }
                    }
                    for event in run.row["prefix"].as_array().into_iter().flatten() {
                        if event["state"] == "required_missing_pending" {
                            report.counts.required_missing_events += 1;
                        }
                        if event["state"] == "required_replacement" {
                            report.counts.required_replacements += 1;
                        }
                    }
                    *family
                        .entry(format!("outcome:{}", run.outcome))
                        .or_default() += 1;
                    run.row["false_refusal"] = json!(run.false_refusal);
                    run.row["failures"] = json!(run.failures);
                    issues.extend(run.failures.iter().map(|e| format!("{}: {e}", s.name)));
                    rows.push(run.row);
                }
                case["scenarios"] = json!(rows);
            }
        }
        case["failures"] = json!(issues);
        if !issues.is_empty() {
            report.counts.failures += issues.len();
            *family.entry("failures".into()).or_default() += issues.len();
            // The full case is the reproducible witness; no source/input elision.
            report.failures.push(case.clone());
        } else if prune {
            for row in case["scenarios"].as_array_mut().into_iter().flatten() {
                if let Some(row) = row.as_object_mut() {
                    for key in ["bindings", "actual_bindings", "raw_result", "notes"] {
                        row.remove(key);
                    }
                }
            }
            case["retention"] = json!("successful payloads reproducible from generator version/seed/attempt; audits, sources and canonical identity retained");
        }
        report.cases.push(case);
    }
    report.counts.distinct_candidates = canonical_seen.len();
    report.counts.admitted_distinct = admitted.len();
    report.counts.rejected_distinct = rejected.len();
    report.counts.exercised_distinct = exercised.len();
    report.counts.successful_distinct = successful.len();
    report.counts.semantic_error_distinct = semantic_errors.len();
    report.by_family = families.into_iter().map(|(k, v)| (k, json!(v))).collect();
    report
}

#[cfg(test)]
mod tests {
    use super::super::native_fixture_sets::{Clause, GuardDescriptor};
    use super::*;
    fn simple(name: &str, source: &str, expected: Expected) -> Fixture {
        Fixture {
            name: name.into(),
            family: "proof-small",
            source: Source::Expression(source.into()),
            declarations: vec![],
            scenarios: vec![Scenario {
                name: "default".into(),
                bindings: vec![],
                expected,
                adapter_expected: None,
                notes: String::new(),
            }],
            guards: vec![],
            input_metadata: vec![],
        }
    }
    fn product(expected: Expected) -> Fixture {
        let mut f = simple("quadratic", "xs.all(x,ys.all(y,true))", expected);
        f.declarations = ["xs", "ys"]
            .map(|name| crate::InputDecl {
                name: name.into(),
                kind: InputKind::Many,
            })
            .to_vec();
        f.scenarios[0].bindings = ["xs", "ys"]
            .map(|n| (n.into(), Value::from(Vec::<Value>::new())))
            .to_vec();
        f
    }
    #[test]
    fn canonical_expanded_ast_alpha_ids_literals_and_scope() {
        on_worker(|| {
            let key = |s| {
                ast(
                    crate::Program::compile(s).unwrap().expression(),
                    &mut vec![],
                )
                .to_string()
            };
            assert_eq!(
                key("[1,2].map(x,x+1)"),
                key(" [1,2].map(renamed, renamed + 1) ")
            );
            assert_eq!(
                key("[1].map(x,[2].map(y,x+y))"),
                key("[1].map(a,[2].map(b,a+b))")
            );
            assert_ne!(
                key("[1].map(x,[2].map(y,x+y))"),
                key("[1].map(x,[2].map(x,x+x))")
            );
            assert_ne!(key("[1].map(x,x+1)"), key("[1].map(x,x+2)"));
            assert_ne!(key("n+1"), key("m+1"));
            assert_ne!(key("one.a"), key("one.b"));
            assert_ne!(key("[1,2]"), key("[2,1]"));
            assert_ne!(key("1"), key("1u"));
            let program = crate::Program::compile("[1].all(x,x>0)").unwrap();
            let mut expression = program.expression().clone();
            let expected = ast(&expression, &mut vec![]);
            expression.id = u64::MAX;
            assert_eq!(expected, ast(&expression, &mut vec![]));
            let mut a = simple("ignored-A", "1", Expected::AdmitValue);
            let mut b = a.clone();
            b.name = "ignored-B".into();
            assert_eq!(
                canonical(&a, None, &Policy::P0_INTERIM).unwrap().0,
                canonical(&b, None, &Policy::P0_INTERIM).unwrap().0
            );
            a.source = Source::Clauses(vec![Clause {
                id: "A".into(),
                when: "true".into(),
                result: "1".into(),
            }]);
            b.source = Source::Clauses(vec![Clause {
                id: "B".into(),
                when: "true".into(),
                result: "1".into(),
            }]);
            assert_eq!(
                canonical(&a, None, &Policy::P0_INTERIM).unwrap().0,
                canonical(&b, None, &Policy::P0_INTERIM).unwrap().0
            );
            b.source = Source::Clauses(vec![Clause {
                id: "B".into(),
                when: "false".into(),
                result: "1".into(),
            }]);
            assert_ne!(
                canonical(&a, None, &Policy::P0_INTERIM).unwrap().0,
                canonical(&b, None, &Policy::P0_INTERIM).unwrap().0
            );
        });
    }
    #[test]
    fn truthful_admission_dedup_and_error_prefix_audits() {
        let fixtures = vec![
            simple("value", "[1,2]", Expected::AdmitValue),
            simple("same", " [1, 2] ", Expected::AdmitValue),
            simple(
                "error",
                "min([])",
                Expected::AdmitSemanticError("FunctionError"),
            ),
            product(Expected::Refuse("many-cross-product")),
            simple("parse", "(", Expected::CandidateDependent("syntax-probe")),
        ];
        let r = fixture_batch(&fixtures, &Policy::P0_INTERIM);
        assert_eq!(r.counts.candidates, 5);
        assert_eq!(r.counts.admitted_candidates, 3);
        assert_eq!(r.counts.rejected_candidates, 2);
        assert_eq!(r.counts.duplicate_candidates, 1);
        assert_eq!(r.counts.canonical_missing, 1);
        assert_eq!(r.counts.distinct_candidates, 3);
        assert_eq!(r.counts.admitted_distinct, 2);
        assert_eq!(r.counts.exercised_distinct, 2);
        assert_eq!(r.counts.value_executions, 2);
        assert_eq!(r.counts.semantic_error_executions, 1);
        assert_eq!(r.counts.false_refusals, 0);
        assert_eq!(r.counts.failures, 0, "{:#?}", r.failures);
        for i in 0..3 {
            let e = &r.cases[i]["scenarios"][0]["execution"];
            assert!(e["cost"]["work"].as_u64().unwrap() > 0);
            assert!(e["failures"].as_array().unwrap().is_empty());
            assert!(e["input_cost"].is_object());
            assert!(r.cases[i]["admission"]["load_cost"].is_object());
        }
        assert_eq!(
            r.cases[0]["scenarios"][0]["execution"]["output"]["cached_nodes"],
            3
        );
        assert_eq!(
            r.cases[2]["scenarios"][0]["execution"]["error"]["category"],
            "FunctionError"
        );
        serde_json::to_string(&r).unwrap();
    }
    #[test]
    fn all_refusal_denominators_separate_fixture_and_generated_candidates() {
        let guard =
            json!({"api":"check_rule","crossing_phase":null,"messages":["work_cost: 9 exceeds 8"]});
        let clause = json!({"api":"check_rule","crossing_phase":"Result","messages":["work_cost: 9 exceeds 8"]});
        assert_eq!(rejection(&guard), ("guard_admission", "work_cost", true));
        assert_eq!(rejection(&clause), ("body_admission", "work_cost", true));
        assert!(!rejection(&json!({"messages":["undeclared input 'cross_product'"]})).2);
        let bad = vec![
            simple("malformed", "(", Expected::AdmitValue),
            simple("undeclared", "cross_product", Expected::AdmitValue),
        ];
        let refused = on_worker(|| batch(&bad, &Policy::P0_INTERIM, true));
        assert_eq!(refused.counts.canonical_missing, 1);
        assert_eq!(refused.failures.len(), 2);
        assert_eq!(refused.counts.rejected_candidates, 2);
        assert!(refused
            .cases
            .iter()
            .all(|c| c["candidate_rejection_permitted"] == false));
        let fixtures = vec![
            product(Expected::AdmitValue),
            product(Expected::CandidateDependent("sensitivity")),
        ];
        let required = fixture_batch(&fixtures, &Policy::P0_INTERIM);
        assert_eq!(required.counts.candidates, 2);
        assert_eq!(required.counts.rejected_candidates, 2);
        assert_eq!(required.counts.admitted_distinct, 0);
        assert_eq!(required.counts.exercised_distinct, 0);
        assert_eq!(required.counts.false_refusals, 1);
        assert_eq!(required.counts.duplicate_candidates, 1);
        let candidates = on_worker(|| batch(&fixtures, &Policy::P0_INTERIM, true));
        assert_eq!(candidates.counts.rejected_candidates, 2);
        assert_eq!(candidates.counts.false_refusals, 0);
        assert_eq!(candidates.counts.failures, 0);
        assert_eq!(candidates.counts.rejected_distinct, 1);
        assert_eq!(candidates.cases[0]["refusal_stage"], "resource_product");
    }
    #[test]
    fn clause_first_match_and_semantic_prefix_share_public_rule_account() {
        let mut f = simple(
            "clauses",
            "0",
            Expected::AdmitSemanticError("DivisionByZero"),
        );
        f.source = Source::Clauses(vec![
            Clause {
                id: "first".into(),
                when: "[1,2].size()<0".into(),
                result: "99".into(),
            },
            Clause {
                id: "second".into(),
                when: "true".into(),
                result: "1/0".into(),
            },
            Clause {
                id: "unreachable".into(),
                when: "true".into(),
                result: "9".into(),
            },
        ]);
        let report = fixture_batch(&[f.clone()], &Policy::P0_INTERIM);
        assert_eq!(report.counts.admitted_distinct, 1);
        assert_eq!(report.counts.semantic_error_executions, 1);
        assert_eq!(report.counts.failures, 0, "{:#?}", report.failures);
        let r = &report.cases[0]["scenarios"][0];
        assert_eq!(r["phase"]["clause_index"], 1);
        assert_eq!(r["phase"]["phase"], "Result");
        assert_eq!(r["execution"]["budget_scope"], "per-rule-call");
        f.scenarios[0].expected = Expected::AdmitValue;
        if let Source::Clauses(cs) = &mut f.source {
            cs[1].result = "{'x':[1,2]}".into();
        }
        let report = fixture_batch(&[f], &Policy::P0_INTERIM);
        assert_eq!(report.counts.value_executions, 1);
        assert_eq!(report.counts.failures, 0, "{:#?}", report.failures);
    }
    #[test]
    fn checked_guards_required_pending_replacement_and_unavailable_names() {
        let fixtures = super::super::native_fixture_sets::ordered_guards(0);
        let r = fixture_batch(&fixtures, &Policy::P0_INTERIM);
        assert_eq!(r.counts.candidates, 6);
        assert_eq!(r.counts.admitted_candidates, 4);
        assert_eq!(r.counts.rejected_candidates, 2);
        assert_eq!(r.counts.no_token_guard_error, 1);
        assert_eq!(r.counts.value_executions, 3);
        assert_eq!(r.counts.failures, 0, "{:#?}", r.failures);
        let first = &r.cases[0]["scenarios"][0];
        assert_eq!(first["replacement_execution"], true);
        let events = first["prefix"].as_array().unwrap();
        assert!(events
            .iter()
            .any(|e| e["state"] == "required_missing_pending" && e["advance_refused"] == true));
        assert!(events.iter().any(|e| e["state"] == "required_replacement"));
        assert_eq!(r.cases[2]["scenarios"][0]["replacement_execution"], false);
        assert_eq!(r.cases[3]["scenarios"][0]["finish_refused"], true);
        // Explicitly prove a true guard cannot issue a checked token before
        // replacement, using only public builder/guard operations.
        let f = &fixtures[0];
        let d = Declarations::new(f.declarations.clone(), &Policy::P0_INTERIM).unwrap();
        let (prepared, _) = prepare(f, &d, &Policy::P0_INTERIM);
        let Admitted::Rule(p) = prepared.unwrap() else {
            panic!("rule")
        };
        let mut args = Bindings::empty(&p.argument_declarations(), &Policy::P0_INTERIM);
        for (name, v) in &f.scenarios[0].bindings {
            if matches!(d.entries[name], InputKind::Scalar { .. }) {
                args.insert(name, v).unwrap();
            }
        }
        let mut prefix = p.start_prefix(&args, &Policy::P0_INTERIM).unwrap();
        assert_eq!(
            prefix.append_next("pending", &Value::Null).unwrap(),
            PrefixProgress::GuardPending
        );
        assert!(prefix.resolve_guard().unwrap().result.unwrap());
        assert_eq!(prefix.next_input(), Some("pending"));
        assert!(prefix.finish().is_err());
        let mut different = f.clone();
        different.guards.push(GuardDescriptor {
            pending_input_name: "future".into(),
            source: "false".into(),
        });
        assert_ne!(
            on_worker(|| canonical(f, Some(&d), &Policy::P0_INTERIM))
                .unwrap()
                .0,
            on_worker(|| canonical(&different, Some(&d), &Policy::P0_INTERIM))
                .unwrap()
                .0
        );
    }
    #[test]
    fn refusal_reasons_reject_earlier_mismatches_and_record_pre_body_zero() {
        let product_ok = product(Expected::Refuse("many-cross-product"));
        let mut wrong_declaration = product_ok.clone();
        wrong_declaration.declarations[0].name = "bad-name".into();
        let wrong_stage = product(Expected::Refuse("total-serialized-input-bytes"));
        let admitted = simple(
            "admitted-refusal",
            "1",
            Expected::Refuse("many-cross-product"),
        );
        let unknown = simple("unknown-label", "(", Expected::Refuse("unrecognized-label"));
        let mut wrong_input = simple(
            "wrong-cap",
            "1",
            Expected::Refuse("external-scalar-kind-or-nonfinite"),
        );
        wrong_input.scenarios[0].bindings = vec![("undeclared".into(), Value::UInt(1))];
        let mut external = simple(
            "external-nonfinite",
            "1",
            Expected::Refuse("external-scalar-kind-or-nonfinite"),
        );
        external.declarations = vec![crate::InputDecl {
            name: "one".into(),
            kind: InputKind::One,
        }];
        external.scenarios[0].bindings = vec![(
            "one".into(),
            Value::from(indexmap::IndexMap::from([(
                "n".to_string(),
                Value::Float(f64::NAN),
            )])),
        )];
        let mut missing = simple("missing-snapshot", "1", Expected::AdmitValue);
        missing.declarations = vec![crate::InputDecl {
            name: "n".into(),
            kind: InputKind::Scalar {
                kind: crate::ScalarType::Int,
                nullable: false,
            },
        }];
        // Admitted generated cases cannot hide an invalid snapshot behind a
        // different exercised scenario. Expected input refusals still succeed.
        let mut candidate_value = missing.clone();
        let mut valid = candidate_value.scenarios[0].clone();
        valid.name = "valid-snapshot".into();
        valid.bindings = vec![("n".into(), Value::Int(1))];
        candidate_value.scenarios.push(valid);
        let mut candidate_error = candidate_value.clone();
        candidate_error.name = "candidate-error-prefix".into();
        candidate_error.source = Source::Expression("min([])".into());
        for scenario in &mut candidate_error.scenarios {
            scenario.expected = Expected::AdmitSemanticError("FunctionError");
        }
        let candidates = on_worker(|| {
            batch(
                &[candidate_value, candidate_error, external.clone()],
                &Policy::P0_INTERIM,
                true,
            )
        });
        assert_eq!(candidates.counts.admitted_candidates, 3);
        assert_eq!(candidates.counts.rejected_candidates, 0);
        assert_eq!(candidates.counts.exercised_distinct, 2);
        assert_eq!(candidates.counts.value_executions, 1);
        assert_eq!(candidates.counts.semantic_error_executions, 1);
        assert_eq!(candidates.counts.input_refusals, 3);
        assert_eq!(candidates.counts.false_refusals, 0);
        assert_eq!(candidates.counts.failures, 2);
        assert_eq!(candidates.failures.len(), 2);
        for case in &candidates.failures {
            let invalid = &case["scenarios"][0];
            assert_eq!(invalid["outcome"], "input_refusal");
            assert_eq!(invalid["false_refusal"], false);
            assert_eq!(invalid["pre_body_cost_zero"], true);
            assert!(invalid["failures"]
                .to_string()
                .contains("legitimate_input_refused"));
            assert_eq!(case["scenarios"][1]["failures"], json!([]));
        }
        assert_eq!(candidates.cases[2]["failures"], json!([]));
        assert_eq!(
            candidates.cases[2]["scenarios"][0]["expected_refusal_check"]["matched"],
            true
        );
        let r = fixture_batch(
            &[
                product_ok,
                wrong_declaration,
                wrong_stage,
                admitted,
                unknown,
                wrong_input,
                external,
                missing,
            ],
            &Policy::P0_INTERIM,
        );
        assert!(r.cases[0]["failures"].as_array().unwrap().is_empty());
        for i in [1, 2, 3, 4, 5, 7] {
            assert!(
                !r.cases[i]["failures"].as_array().unwrap().is_empty(),
                "{i}: {}",
                r.cases[i]
            );
        }
        assert!(r.cases[1]["failures"]
            .to_string()
            .contains("expected_refusal_reason_mismatch"));
        assert!(r.cases[2]["failures"]
            .to_string()
            .contains("expected_refusal_reason_mismatch"));
        assert!(r.cases[3]["failures"]
            .to_string()
            .contains("body_expected_category_mismatch"));
        assert!(r.cases[4]["failures"]
            .to_string()
            .contains("unsupported_expected_refusal_reason"));
        assert!(r.cases[5]["failures"]
            .to_string()
            .contains("expected_refusal_reason_mismatch"));
        assert!(
            r.cases[6]["failures"].as_array().unwrap().is_empty(),
            "{}",
            r.cases[6]
        );
        assert_eq!(
            r.cases[6]["scenarios"][0]["error"]["input_refusal"]["cap"],
            "safe_number"
        );
        let snapshot = &r.cases[7]["scenarios"][0];
        assert_eq!(snapshot["pre_body_cost_zero"], true);
        assert_eq!(snapshot["execution"]["cost"]["work"], 0);
        assert_eq!(snapshot["execution"]["cost"]["memory"], 0);
        assert!(snapshot["execution"]["input_cost"].is_object());
        // Exact native total_bytes on the complete envelope is supported;
        // identical cap text at a row-local path must not satisfy whole-B.
        let total = Expected::Refuse("total-serialized-input-bytes");
        let f = simple("total-check", "1", total);
        let s = &f.scenarios[0];
        let whole = ExecutionError::InputRefused {
            cap: "total_bytes".into(),
            path: "bindings".into(),
            measured: 1_048_577,
            limit: 1_048_576,
            message: "whole envelope".into(),
        };
        assert!(expected_refusal(&f, s, RefusalEvidence::Input(&whole, "bindings.insert")).is_ok());
        let row = ExecutionError::InputRefused {
            cap: "total_bytes".into(),
            path: "one".into(),
            measured: 1_048_577,
            limit: 1_048_576,
            message: "row local".into(),
        };
        assert!(expected_refusal(&f, s, RefusalEvidence::Input(&row, "bindings.insert")).is_err());
        // Source snippets containing an expected reason cannot forge evidence.
        let fake = json!({"api":"api::check","messages":["memory_cost: 9 exceeds 8"],"diagnostic":"cross_product: source snippet"});
        let product = product(Expected::Refuse("many-cross-product"));
        assert!(expected_refusal(
            &product,
            &product.scenarios[0],
            RefusalEvidence::Admission(&fake)
        )
        .is_err());
    }

    #[test]
    fn generated_report_keeps_seed_attempts_and_public_rejections() {
        let generated = super::super::native_rule_generator::generate(
            super::super::native_rule_generator::DEFAULT_SEED,
            2,
        );
        let report = generated_corpus(&generated, &Policy::P0_INTERIM);
        assert_eq!(report.counts.candidates, generated.rules.len());
        assert_eq!(
            report.counts.admitted_candidates + report.counts.rejected_candidates,
            report.counts.candidates
        );
        assert_eq!(report.generator.as_ref().unwrap()["seed"], generated.seed);
        assert_eq!(
            report.generator.as_ref().unwrap()["attempts"],
            generated.counts.attempts
        );
        assert_eq!(report.counts.false_refusals, 0);
        assert_eq!(report.counts.failures, 0, "{:#?}", report.failures);
        assert!(report
            .cases
            .iter()
            .all(|c| c["generator"]["attempt"].is_number()));
    }

    #[test]
    fn seeded_public_p1_soundness_exercises_ten_thousand_distinct_definitions() {
        let generated = crate::native_rule_generator::generate(
            crate::native_rule_generator::DEFAULT_SEED,
            10_000,
        );
        let report = generated_summary(&generated, &Policy::P1);
        assert_eq!(report.counts.canonical_missing, 0, "{:#?}", report.failures);
        assert_eq!(
            report.counts.failures,
            0,
            "{}",
            serde_json::to_string_pretty(&report.failures).unwrap()
        );
        assert!(
            report.counts.admitted_distinct >= 10_000,
            "{:?}",
            report.counts
        );
        assert!(
            report.counts.exercised_distinct >= 10_000,
            "{:?}",
            report.counts
        );
        assert!(report
            .cases
            .iter()
            .filter(|c| c["admitted"] == false)
            .all(|c| c["candidate_rejection_permitted"] == true));
        println!(
            "PUBLIC_P1_SEEDED {:?} families={}",
            report.counts,
            report.by_family.len()
        );
    }
    #[test]
    fn compact_generated_audits_preserve_counts_costs_and_failure_witnesses() {
        let generated =
            crate::native_rule_generator::generate(crate::native_rule_generator::DEFAULT_SEED, 32);
        let full = generated_corpus(&generated, &Policy::P1);
        let compact = generated_summary(&generated, &Policy::P1);
        assert_eq!(
            serde_json::to_value(&full.counts).unwrap(),
            serde_json::to_value(&compact.counts).unwrap()
        );
        assert_eq!(full.by_family, compact.by_family);
        assert_eq!(full.failures, compact.failures);
        for (full, small) in full.cases.iter().zip(&compact.cases) {
            assert_eq!(full["canonical"], small["canonical"]);
            for (a, b) in full["scenarios"]
                .as_array()
                .unwrap()
                .iter()
                .zip(small["scenarios"].as_array().unwrap())
            {
                assert_eq!(a["execution"], b["execution"]);
                assert_eq!(a["guards"], b["guards"]);
                if small["failures"].as_array().unwrap().is_empty() {
                    assert!(b["bindings"].is_null());
                }
            }
        }
        let bad = vec![simple("malformed", "(", Expected::AdmitValue)];
        let full = on_worker(|| batch_inner(&bad, &Policy::P1, true, false));
        let compact = on_worker(|| batch_inner(&bad, &Policy::P1, true, true));
        assert_eq!(full.failures, compact.failures);
        assert!(!compact.failures[0]["scenarios"][0]["bindings"].is_null());
    }
}
