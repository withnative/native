//! Legacy semantic parser probes after the L0 migration. These deliberately
//! use private upstream bindings (including nested values outside the native
//! scalar-row contract). L1 and combined production value/eval stack evidence
//! are separate: parser success here is not production admission.

use std::sync::Arc;

use crate::objects::{Key, Map};
use crate::{check, evaluate, Bindings, Policy, Value};

const CASES: &[(&str, &str)] = &[
    // Admitted: deepest shapes the caps allow.
    ("paren32", "ok"),
    ("neg32", "ok"),
    ("minus32", "ok"),
    ("listnest32", "ok"),
    ("mapnest32", "ok"),
    ("callnest32", "ok"),
    ("select32", "ok"),
    ("index32", "ok"),
    ("plus32", "ok"),
    ("listlit100", "ok"),
    ("mixed160", "ok"),
    ("spaces", "ok"),
    ("comments", "ok"),
    // These former total-chain caps now pass L0; missing bindings still error.
    ("neg33", "ok"),
    ("paren33", "ok"),
    ("listnest33", "ok"),
    ("mapnest33", "ok"),
    ("callnest33", "ok"),
    ("select33", "evalerr"),
    ("index33", "evalerr"),
    ("plus33", "ok"),
    // L0 accepts 300 tokens / 5KiB; deeper grammar chains remain refused.
    ("tokens300", "ok"),
    ("bigstr5k", "ok"),
    ("plus499", "refused"),
    ("select499", "refused"),
    ("index330", "refused"),
    ("paren95", "refused"),
    ("bracket95", "refused"),
    ("ws_spaced", "refused"),
    ("ws_bare", "refused"),
];

fn map_of(key: &str, value: Value) -> Value {
    let mut m = indexmap::IndexMap::new();
    m.insert(Key::from(key.to_string()), value);
    Value::Map(Map { map: Arc::new(m) })
}

fn build(kind: &str) -> (String, Vec<(String, Value)>) {
    match kind {
        "paren32" => (format!("{}1{}", "(".repeat(32), ")".repeat(32)), vec![]),
        "neg32" => (format!("{}true", "!".repeat(32)), vec![]),
        "minus32" => (format!("{}1", "-".repeat(32)), vec![]),
        "listnest32" => (format!("{}1{}", "[".repeat(32), "]".repeat(32)), vec![]),
        "mapnest32" => (
            format!("{}1{}", "{'a': ".repeat(32), "}".repeat(32)),
            vec![],
        ),
        "callnest32" => (
            format!("{}1{}", "string(".repeat(32), ")".repeat(32)),
            vec![],
        ),
        "select32" => {
            let mut v = Value::Int(1);
            for _ in 0..32 {
                v = map_of("f", v);
            }
            (format!("a{}", ".f".repeat(32)), vec![("a".to_string(), v)])
        }
        "index32" => {
            let mut v = Value::Int(7);
            for _ in 0..32 {
                v = Value::List(Arc::new(vec![v]));
            }
            (format!("a{}", "[0]".repeat(32)), vec![("a".to_string(), v)])
        }
        "plus32" => ((0..33).map(|_| "1").collect::<Vec<_>>().join("+"), vec![]),
        "listlit100" => (
            format!(
                "[{}]",
                (0..100)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            vec![],
        ),
        "mixed160" => {
            let mut bindings = Vec::new();
            for k in 0..16 {
                for prefix in ["x", "y"] {
                    let field = if prefix == "x" { "f" } else { "g" };
                    bindings.push((format!("{prefix}{k}"), map_of(field, Value::Int(k))));
                }
            }
            let groups: Vec<String> = (0..16).map(|k| format!("(x{k}.f + y{k}.g)")).collect();
            (groups.join("+"), bindings)
        }
        "spaces" => (format!("1{}+{}1", " ".repeat(300), " ".repeat(300)), vec![]),
        "comments" => (format!("1 // {}\n+ 1", "c".repeat(300)), vec![]),
        "neg33" => (format!("{}true", "!".repeat(33)), vec![]),
        "paren33" => (format!("{}1{}", "(".repeat(33), ")".repeat(33)), vec![]),
        "listnest33" => (format!("{}1{}", "[".repeat(33), "]".repeat(33)), vec![]),
        "mapnest33" => (
            format!("{}1{}", "{'a': ".repeat(33), "}".repeat(33)),
            vec![],
        ),
        "callnest33" => (
            format!("{}1{}", "string(".repeat(33), ")".repeat(33)),
            vec![],
        ),
        "select33" => (format!("a{}", ".f".repeat(33)), vec![]),
        "index33" => (format!("a{}", "[0]".repeat(33)), vec![]),
        "plus33" => ((0..34).map(|_| "1").collect::<Vec<_>>().join("+"), vec![]),
        "tokens300" => (
            format!(
                "[{}]",
                (0..150)
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            vec![],
        ),
        "bigstr5k" => (format!("'{}'", "x".repeat(5000)), vec![]),
        "plus499" => ((0..499).map(|_| "1").collect::<Vec<_>>().join("+"), vec![]),
        "select499" => (format!("a{}", ".f".repeat(499)), vec![]),
        "index330" => (format!("a{}", "[0]".repeat(330)), vec![]),
        "paren95" => (format!("{}1{}", "(".repeat(95), ")".repeat(95)), vec![]),
        "bracket95" => (format!("{}1{}", "[".repeat(95), "]".repeat(95)), vec![]),
        "ws_spaced" => (
            (0..300).map(|_| "1").collect::<Vec<_>>().join(" + "),
            vec![],
        ),
        "ws_bare" => ((0..300).map(|_| "1").collect::<Vec<_>>().join("+"), vec![]),
        other => panic!("unknown kind {other}"),
    }
}

fn outcome(kind: &str) -> &'static str {
    let (expr, vars) = build(kind);
    let mut bindings = Bindings::new();
    for (k, v) in vars {
        bindings.set(&k, v);
    }
    let prepared = match check(&expr, &Policy::P0_INTERIM).result {
        Ok(p) => p,
        Err(_) => return "refused",
    };
    match evaluate(&prepared, &bindings, &Policy::P0_INTERIM).result {
        Ok(_) => "ok",
        Err(_) => "evalerr",
    }
}

fn run_all() {
    let mut failures = Vec::new();
    for (kind, allowed) in CASES {
        let got = outcome(kind);
        if got != *allowed {
            failures.push(format!("{kind}: {got} (expected {allowed})"));
        }
    }
    assert!(
        failures.is_empty(),
        "{}/{} parse-proof cases failed:\n{}",
        failures.len(),
        CASES.len(),
        failures.join("\n")
    );
}

#[test]
fn parse_proof_debug() {
    run_all();
}

#[test]
#[ignore = "stack proof in release; run with --release --ignored"]
fn parse_proof_release() {
    if std::env::var_os("CEL_NATIVE_COMBINED_STACK_BYTES").is_none() {
        run_all();
    }
    combined_headroom("parse_proof_tests::parse_proof_release", true);
}

// Child processes isolate stack-overflow aborts. The test-only dispatcher seam
// recognizes ONLY this named worker plus the child marker; all public calls and
// their returned ASTs/regexes/summaries/values are created and dropped here.
fn combined_headroom(selector: &str, ignored: bool) {
    const ENV: &str = "CEL_NATIVE_COMBINED_STACK_BYTES";
    if let Ok(stack) = std::env::var(ENV) {
        let stack: usize = stack.parse().unwrap();
        assert!([4 * 1024 * 1024, 8 * 1024 * 1024].contains(&stack));
        // The marker alone must not redirect an ordinary caller.
        assert_ne!(
            crate::api::run_on_pool(|| std::thread::current().id()).unwrap(),
            std::thread::current().id()
        );
        std::thread::Builder::new()
            .name("cel-native-combined-stack".into())
            .stack_size(stack)
            .spawn(move || {
                assert_eq!(
                    crate::api::run_on_pool(|| std::thread::current().id()).unwrap(),
                    std::thread::current().id()
                );
                let policy = Policy::P1;
                println!("COMBINED start stack={stack} debug={} policy={} caps={:?} L1=8192/1024/AST32/body2/Value35 W={} H={} guardW={} guardH={}",
                    cfg!(debug_assertions), policy.id(), crate::ParseCaps::current(),
                    policy.work_limit(), policy.mem_limit_bytes(),
                    policy.guard_work_limit(), policy.guard_mem_limit_bytes());
                combined_expressions(&policy);
                combined_rules_and_guards(&policy);
                combined_shape_frontier(&policy);
                combined_auxiliary_helpers();
                assert!(crate::symbolic_control::refusal().is_none());
                assert!(crate::meter::tripped().is_none());
                println!("COMBINED complete stack={stack} debug={} (all drops on worker)", cfg!(debug_assertions));
            })
            .unwrap()
            .join()
            .unwrap();
        return;
    }
    for stack in [4 * 1024 * 1024, 8 * 1024 * 1024] {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", selector, "--nocapture", "--test-threads=1"]);
        if ignored {
            child.arg("--ignored");
        }
        let output = child.env(ENV, stack.to_string()).output().unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "native combined stack {stack} failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
#[test]
fn native_combined_stack_debug() {
    combined_headroom("parse_proof_tests::native_combined_stack_debug", false);
}

fn nested_list(n: usize, item: &str) -> String {
    format!("{}{item}{}", "[".repeat(n), "]".repeat(n))
}

fn value_depth(v: &Value) -> usize {
    match v {
        Value::List(l) => 1 + l.iter().map(value_depth).max().unwrap_or(0),
        Value::Map(m) => 1 + m.map.values().map(value_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn audit_cost(cost: crate::EvalCost, bound: crate::Bound) {
    assert!(
        cost.work <= bound.work && cost.memory <= bound.memory,
        "cost {cost:?} exceeds {bound:?}"
    );
}

fn audit_value(v: &Value, bound: crate::Bound) -> (u64, u64, usize) {
    let (nodes, bytes) = crate::load::metrics(v);
    let depth = value_depth(v);
    assert!(
        nodes <= bound.result_nodes && bytes <= bound.result_bytes && depth <= bound.result_depth,
        "output {nodes}/{bytes}/{depth} exceeds {bound:?}"
    );
    (nodes, bytes, depth)
}

// Public gate and public evaluator; direct expression seam remains a comparison
// with the pre-existing meaningful AST32/Value35 proof, never an admission bypass.
fn probe_expression(
    label: &str,
    source: &str,
    d: &crate::Declarations,
    b: &Bindings,
    policy: &Policy,
) -> (crate::Prepared, crate::EvalReport) {
    let p = crate::api::check(source, d, policy)
        .result
        .unwrap_or_else(|e| panic!("{label} {source}: {e}"));
    let direct = crate::api::check_current_thread(source, d, policy)
        .result
        .unwrap();
    assert_eq!(p.bound(), direct.bound());
    assert_eq!(p.measures(), direct.measures());
    drop(direct);
    let r = crate::api::evaluate(&p, b, policy);
    audit_cost(r.cost, p.bound());
    let output = r.result.as_ref().ok().map(|v| audit_value(v, p.bound()));
    println!("EXPR {label} source={source:?} measures={:?} bound={:?} aux={:?} cost={:?} output={output:?} result={:?}",
        p.measures(), p.bound(), p.native_aux(), r.cost, r.result.as_ref().err());
    (p, r)
}

fn combined_declarations(policy: &Policy) -> crate::Declarations {
    use crate::{InputDecl, InputKind, ScalarType};
    crate::Declarations::new(
        [
            InputDecl {
                name: "one".into(),
                kind: InputKind::One,
            },
            InputDecl {
                name: "pending".into(),
                kind: InputKind::One,
            },
            InputDecl {
                name: "future".into(),
                kind: InputKind::One,
            },
            InputDecl {
                name: "flag".into(),
                kind: InputKind::Scalar {
                    kind: ScalarType::Bool,
                    nullable: false,
                },
            },
            InputDecl {
                name: "other".into(),
                kind: InputKind::Scalar {
                    kind: ScalarType::Int,
                    nullable: false,
                },
            },
        ],
        policy,
    )
    .unwrap()
}

fn combined_bindings(d: &crate::Declarations, policy: &Policy) -> Bindings {
    let mut b = Bindings::empty(d, policy);
    for name in ["one", "pending", "future"] {
        b.insert(name, &map_of("n", Value::Int(0))).unwrap();
    }
    b.insert("flag", &Value::Bool(true)).unwrap();
    b.insert("other", &Value::Int(0)).unwrap();
    b
}

fn combined_expressions(policy: &Policy) {
    let d = crate::Declarations::empty();
    let b = Bindings::empty(&d, policy);
    let range = nested_list(30, "0");
    let ceiling = format!("{range}.map(r,[[[[r]]]])");
    let sources = [
        ("ast32-value35", ceiling),
        ("literal32", nested_list(31, "null")),
        (
            "calls32",
            format!("{}1{}", "int(".repeat(31), ")".repeat(31)),
        ),
        (
            "equal-value35",
            format!("{range}.map(r,[[[[[r]]]]] == [[[[[r]]]]])"),
        ),
        (
            "unequal-value35",
            format!("{range}.map(r,[[[[[r]]]]] != [[[[[r]]]]])"),
        ),
    ];
    for (label, source) in sources {
        let (p, r) = probe_expression(label, &source, &d, &b, policy);
        assert!(r.result.is_ok());
        if label == "ast32-value35" {
            assert_eq!(p.measures().ast_depth, 32);
            assert_eq!(p.bound().result_depth, 35);
            assert_eq!(value_depth(r.result.as_ref().unwrap()), 35);
        }
        let direct = crate::api::evaluate_current_thread(&p, &b, policy);
        assert_eq!(direct.result, r.result);
        assert_eq!(direct.cost, r.cost);
        drop(direct);
        drop(r);
        drop(p);
    }
    let d = combined_declarations(policy);
    let b = combined_bindings(&d, policy);
    let value35 = format!("{range}.map(r,[one].map(q,[[[r]]]))");
    let cases = [
        ("body2-value35", value35, 35, None),
        (
            "body2-owned-append",
            format!("{range}.map(r,([r]+[r]).map(q,[[q]]))"),
            34,
            None,
        ),
        (
            "body2-all-absorbs",
            format!("{range}.map(r,[0,1].all(q,q==0 ? 1/0==0 : false))"),
            2,
            Some(Value::from(vec![Value::Bool(false)])),
        ),
        (
            "body2-exists-absorbs",
            format!("{range}.map(r,[0,1].exists(q,q==0 ? 1/0==0 : true))"),
            2,
            Some(Value::from(vec![Value::Bool(true)])),
        ),
        (
            "body2-filter",
            format!("{range}.map(r,[one,one].filter(q,q.n==0))"),
            4,
            None,
        ),
    ];
    for (label, source, expected_depth, expected) in cases {
        let (p, r) = probe_expression(label, &source, &d, &b, policy);
        assert_eq!(p.measures().ast_depth, 32);
        assert_eq!(p.measures().comprehension_depth, 2);
        let v = r.result.as_ref().unwrap();
        assert_eq!(value_depth(v), expected_depth);
        if let Some(expected) = expected {
            assert_eq!(v, &expected);
        }
        drop(r);
        drop(p);
    }
    // Temporary range, borrowed child bindings, retained first append, then an
    // error on the second iteration: cleanup must release all of them.
    for (label, source) in [
        (
            "body2-append-error",
            format!("{range}.map(r,[0,1].map(q,q==0 ? [[[r]]] : [][0]))"),
        ),
        (
            "body2-all-error",
            format!("{range}.map(r,[0].all(q,[][q]==0))"),
        ),
    ] {
        let (p, r) = probe_expression(label, &source, &d, &b, policy);
        assert_eq!(p.measures().ast_depth, 32);
        assert_eq!(p.measures().comprehension_depth, 2);
        assert!(matches!(
            &r.result,
            Err(crate::ExecutionError::IndexOutOfBounds(_))
        ));
        drop(r);
        drop(p);
        assert!(crate::meter::tripped().is_none());
        assert!(crate::symbolic_control::refusal().is_none());
    }
}

// Independently measure a public rule/guard source without accessing private
// PreparedRule/PreparedGuard fields. This check has the same structural gates.
fn probe_phase(label: &str, source: &str, d: &crate::Declarations, policy: &Policy) {
    let p = crate::api::check(source, d, policy).result.unwrap();
    println!(
        "PHASE {label} source={source:?} measures={:?} bound={:?} aux={:?} regexes={}",
        p.measures(),
        p.bound(),
        p.native_aux(),
        p.regex_count()
    );
    assert_eq!(p.measures().ast_depth, 32);
    assert_eq!(p.measures().comprehension_depth, 2);
    drop(p);
}

// An empty outer registry must be restored after a phase's temporary compiled
// registry. A leaked registry (or an erroneous clear to the test fallback) would
// make this known pattern succeed rather than return the typed FunctionError.
fn assert_phase_cleanup() {
    assert!(matches!(
        crate::regexes::is_match("x", "x"),
        Err(crate::ExecutionError::FunctionError { .. })
    ));
    assert!(crate::meter::tripped().is_none());
    assert!(crate::meter::totals().is_none());
    assert!(crate::symbolic_control::refusal().is_none());
}

fn combined_rules_and_guards(policy: &Policy) {
    use crate::{Clause, ClausePhase, ExecutionError, GuardSource, PrefixProgress, RuleDecision};
    let _outer_registry = crate::regexes::install(Arc::new(std::collections::HashMap::new()));
    let d = combined_declarations(policy);
    let range = nested_list(30, "0");
    let deep = format!("{range}.map(r,[one].map(q,[[[r]]]))");
    // Guard keeps maximum AST32 on its range and body2; prior One, both scalar
    // arguments and a compiled literal regex participate in actual execution.
    let guard_source =
        format!("{range}.all(r,[one].all(q,flag && other==0 && q.n==0 && 'x'.matches('x')))");
    let guard = crate::check_guard(&guard_source, "pending", &d, policy)
        .result
        .unwrap();
    assert_eq!(
        guard.declarations().order.as_ref(),
        &vec!["one".to_string()]
    );
    assert_eq!(guard.declarations().entries.len(), 3);
    probe_phase(
        "guard-required",
        &guard_source,
        guard.declarations(),
        policy,
    );
    probe_phase("rule-value35", &deep, &d, policy);
    let mut gb = Bindings::empty(guard.declarations(), policy);
    gb.insert("one", &map_of("n", Value::Int(0))).unwrap();
    gb.insert("flag", &Value::Bool(true)).unwrap();
    let missing = crate::guard(&guard, &gb, policy);
    assert!(matches!(
        missing.result,
        Err(ExecutionError::InputRefused { ref cap, ref path, .. }) if cap == "missing" && path == "other"
    ));
    assert_eq!(missing.cost, crate::EvalCost::default());
    drop(missing);
    gb.insert("other", &Value::Int(0)).unwrap();
    let success = crate::guard(&guard, &gb, policy);
    assert_eq!(success.result, Ok(true));
    audit_cost(success.cost, guard.bound());
    println!(
        "GUARD source={guard_source:?} bound={:?} cost={:?} required=true",
        guard.bound(),
        success.cost
    );
    drop(success);
    assert_phase_cleanup();
    for illegal in ["pending==null", "future==null"] {
        let refused = crate::check_guard(illegal, "pending", &d, policy)
            .result
            .unwrap_err();
        assert!(refused
            .errors
            .iter()
            .any(|e| e.msg.starts_with("undeclared binding")));
        println!(
            "GUARD refusal source={illegal:?} error={:?}",
            refused.errors[0].msg
        );
        drop(refused);
    }
    drop(gb);
    drop(guard);

    // Later preparation failure releases earlier phases and regex tables here.
    let bad_clauses = [
        Clause {
            id: "retained".into(),
            when: "'x'.matches('x')".into(),
            result: deep.clone(),
        },
        Clause {
            id: "bad".into(),
            when: "true".into(),
            result: nested_list(32, "0"),
        },
    ];
    let rejected = crate::check_rule(&bad_clauses, &d, &[], policy)
        .result
        .unwrap_err();
    assert_eq!(rejected.clause_id.as_deref(), Some("bad"));
    assert_eq!(rejected.phase, Some(ClausePhase::Result));
    assert_eq!(rejected.errors.errors[0].msg, "ast_depth: 33 exceeds 32");
    println!(
        "RULE partial-prepare clauses={bad_clauses:?} refusal={:?}",
        rejected.errors.errors[0].msg
    );
    drop(rejected);
    let good_clause = [Clause {
        id: "body".into(),
        when: "true".into(),
        result: deep.clone(),
    }];
    let bad_guards = [
        GuardSource {
            input: "pending".into(),
            source: guard_source.clone(),
        },
        GuardSource {
            input: "future".into(),
            source: "future==null".into(),
        },
    ];
    let rejected = crate::check_rule(&good_clause, &d, &bad_guards, policy)
        .result
        .unwrap_err();
    assert_eq!(rejected.phase, None);
    assert!(rejected.errors.errors[0]
        .msg
        .starts_with("undeclared binding 'future'"));
    println!(
        "RULE partial-guard-prepare refusal={:?}",
        rejected.errors.errors[0].msg
    );
    drop(rejected);
    assert_phase_cleanup();

    let clauses = [
        Clause {
            id: "skip".into(),
            when: "false".into(),
            result: "[][0]".into(),
        },
        Clause {
            id: "match".into(),
            when: "true".into(),
            result: deep.clone(),
        },
        Clause {
            id: "unreached".into(),
            when: "[][0]".into(),
            result: "[][0]".into(),
        },
    ];
    let guards = [GuardSource {
        input: "pending".into(),
        source: guard_source.clone(),
    }];
    let rule = crate::check_rule(&clauses, &d, &guards, policy)
        .result
        .unwrap();
    let mut args = Bindings::empty(&rule.argument_declarations(), policy);
    args.insert("flag", &Value::Bool(true)).unwrap();
    args.insert("other", &Value::Int(0)).unwrap();
    let mut prefix = rule.start_prefix(&args, policy).unwrap();
    assert_eq!(
        prefix
            .append_next("one", &map_of("n", Value::Int(0)))
            .unwrap(),
        PrefixProgress::Advanced
    );
    let wrong_order = prefix.append_next("future", &Value::Null).unwrap_err();
    assert!(
        matches!(wrong_order, ExecutionError::InputRefused { ref cap, .. } if cap == "prefix_order")
    );
    assert_eq!(
        prefix.append_next("pending", &Value::Null).unwrap(),
        PrefixProgress::GuardPending
    );
    for _ in 0..2 {
        let required = prefix.resolve_guard().unwrap();
        assert_eq!(required.result, Ok(true));
        audit_cost(required.cost, rule.guards()[0].bound());
        drop(required);
        assert_eq!(prefix.next_input(), Some("pending"));
    }
    assert!(
        matches!(prefix.finish(), Err(ExecutionError::InputRefused { ref cap, .. }) if cap == "prefix_incomplete")
    );
    // Restart a complete sealed prefix and replace the required pending null.
    let mut prefix = rule.start_prefix(&args, policy).unwrap();
    prefix
        .append_next("one", &map_of("n", Value::Int(0)))
        .unwrap();
    prefix.append_next("pending", &Value::Null).unwrap();
    assert!(prefix.resolve_guard().unwrap().result.unwrap());
    assert_eq!(
        prefix
            .append_next("pending", &map_of("n", Value::Int(1)))
            .unwrap(),
        PrefixProgress::Advanced
    );
    prefix.append_next("future", &Value::Null).unwrap();
    let token = prefix.finish().unwrap();
    let report = crate::evaluate_rule(&rule, &token, policy);
    audit_cost(report.cost, rule.bound());
    match &report.result {
        Ok(RuleDecision::Matched {
            clause_index: 1,
            value,
        }) => {
            assert_eq!(value_depth(value), 35);
            let output = audit_value(value, rule.bound());
            println!(
                "RULE first-match result_source={deep:?} bound={:?} cost={:?} output={output:?}",
                rule.bound(),
                report.cost
            );
        }
        other => panic!("first-match: {other:?}"),
    }
    drop(report);
    assert_phase_cleanup();
    // Tokens cannot be reused for another PreparedRule.
    let other_rule = crate::check_rule(&clauses, &d, &guards, policy)
        .result
        .unwrap();
    let wrong_token = crate::evaluate_rule(&other_rule, &token, policy);
    assert!(
        matches!(wrong_token.result, Err(crate::RuleError { error: ExecutionError::InputRefused { ref cap, .. }, .. }) if cap == "rule_association")
    );
    assert_eq!(wrong_token.cost, crate::EvalCost::default());
    drop(wrong_token);
    drop(other_rule);
    drop(token);
    drop(rule);

    let error_source = format!("{range}.map(r,[0,1].map(q,q==0 ? [[[r]]] : [][0]))");
    // Both rule phases get a typed semantic error, with compiled regex state
    // retained in the failing phase and a prior successful phase in the rule.
    for phase in [ClausePhase::When, ClausePhase::Result] {
        let error = format!("'x'.matches('x') ? {error_source} : []");
        let clauses = [
            Clause {
                id: "skip".into(),
                when: "false".into(),
                result: deep.clone(),
            },
            Clause {
                id: "error".into(),
                when: if phase == ClausePhase::When {
                    error.clone()
                } else {
                    "true".into()
                },
                result: if phase == ClausePhase::Result {
                    error
                } else {
                    deep.clone()
                },
            },
        ];
        // Wrapping the deep range in a conditional adds one AST edge: use29 to
        // keep the actual public AST gate at32, never relax the cap.
        let clauses: Vec<_> = clauses
            .into_iter()
            .map(|mut c| {
                c.when = c.when.replace(&range, &nested_list(29, "0"));
                c.result = c.result.replace(&range, &nested_list(29, "0"));
                c
            })
            .collect();
        let failing_source = if phase == ClausePhase::When {
            &clauses[1].when
        } else {
            &clauses[1].result
        };
        probe_phase(&format!("rule-error-{phase:?}"), failing_source, &d, policy);
        let rule = crate::check_rule(&clauses, &d, &[], policy).result.unwrap();
        let mut prefix = rule.start_prefix(&args, policy).unwrap();
        for name in ["one", "pending", "future"] {
            prefix
                .append_next(name, &map_of("n", Value::Int(0)))
                .unwrap();
        }
        let token = prefix.finish().unwrap();
        let report = crate::evaluate_rule(&rule, &token, policy);
        audit_cost(report.cost, rule.bound());
        let error = report.result.as_ref().unwrap_err();
        assert_eq!(error.clause_index, Some(1));
        assert_eq!(error.phase, Some(phase));
        assert!(matches!(error.error, ExecutionError::IndexOutOfBounds(_)));
        println!(
            "RULE error phase={phase:?} clauses={clauses:?} bound={:?} cost={:?} error={error:?}",
            rule.bound(),
            report.cost
        );
        drop(report);
        drop(token);
        drop(rule);
        assert_phase_cleanup();
    }
    // Pending guard error retains progress; a valid replacement can complete.
    // False required_when commits the empty input and advances.
    for (label, source, expected_error) in [
        ("false", guard_source.replace("flag &&", "!flag &&"), false),
        (
            "error",
            format!("{range}.all(r,[one].all(q,q.missing==0 && 'x'.matches('x')))"),
            true,
        ),
    ] {
        let guards = [GuardSource {
            input: "pending".into(),
            source: source.clone(),
        }];
        let clauses = [Clause {
            id: "body".into(),
            when: "true".into(),
            result: deep.clone(),
        }];
        let rule = crate::check_rule(&clauses, &d, &guards, policy)
            .result
            .unwrap();
        let mut prefix = rule.start_prefix(&args, policy).unwrap();
        prefix
            .append_next("one", &map_of("n", Value::Int(0)))
            .unwrap();
        prefix.append_next("pending", &Value::Null).unwrap();
        probe_phase(
            &format!("guard-{label}"),
            &source,
            rule.guards()[0].declarations(),
            policy,
        );
        let report = prefix.resolve_guard().unwrap();
        audit_cost(report.cost, rule.guards()[0].bound());
        if expected_error {
            assert!(matches!(&report.result, Err(ExecutionError::NoSuchKey(_))));
            assert_eq!(prefix.next_input(), Some("pending"));
            prefix
                .append_next("pending", &map_of("n", Value::Int(1)))
                .unwrap();
        } else {
            assert_eq!(report.result, Ok(false));
            assert_eq!(prefix.next_input(), Some("future"));
        }
        println!(
            "GUARD {label} source={source:?} bound={:?} cost={:?} result={:?}",
            rule.guards()[0].bound(),
            report.cost,
            report.result
        );
        drop(report);
        assert_phase_cleanup();
        prefix.append_next("future", &Value::Null).unwrap();
        let token = prefix.finish().unwrap();
        let report = crate::evaluate_rule(&rule, &token, policy);
        audit_cost(report.cost, rule.bound());
        let Ok(RuleDecision::Matched { value, .. }) = &report.result else {
            panic!("{:?}", report.result)
        };
        audit_value(value, rule.bound());
        drop(report);
        drop(token);
        drop(rule);
    }
}

fn combined_shape_frontier(policy: &Policy) {
    let d = combined_declarations(policy);
    let mut b = combined_bindings(&d, policy);
    let kinds = [
        "0",
        "true",
        "'x'",
        "b'x'",
        "null",
        "duration('0s')",
        "{'n':0}",
        "[0]",
    ];
    for width in [1, 4, 17] {
        let left = format!("[{}]", kinds.repeat(width).join(","));
        let right = format!(
            "[{}]",
            kinds
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>()
                .repeat(width)
                .join(",")
        );
        // Conditional joins recursively rebind two independent list shapes;
        // heterogeneous leaves exercise finite-kind Union clone/rebind/join.
        let source = format!(
            "(flag ? {} : {}).map(r,[one].map(q,r))",
            nested_list(27, &left),
            nested_list(27, &right)
        );
        for flag in [true, false] {
            b.insert("flag", &Value::Bool(flag)).unwrap();
            let (p, r) = probe_expression(
                &format!("shape-width{width}-flag{flag}"),
                &source,
                &d,
                &b,
                policy,
            );
            assert_eq!(p.measures().ast_depth, 32);
            assert_eq!(p.measures().comprehension_depth, 2);
            assert!(r.result.is_ok());
            drop(r);
            drop(p);
        }
    }
    let make_source = |width, body: &str| {
        let left = format!("[{}]", kinds.repeat(width).join(","));
        let right = format!(
            "[{}]",
            kinds
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>()
                .repeat(width)
                .join(",")
        );
        format!(
            "(flag ? {} : {}).map(r,{body})",
            nested_list(27, &left),
            nested_list(27, &right)
        )
    };
    let source = make_source(18, "[one].map(q,r)");
    let refused = crate::api::check(&source, &d, policy).result.unwrap_err();
    assert_eq!(refused.errors[0].msg, "real_tokens: 1031 exceeds 1024");
    println!(
        "FRONTIER token refusal source={source:?} error={:?}",
        refused.errors[0].msg
    );
    drop(refused);
    let source = make_source(17, "[r,r,r].map(q,q)");
    let refused = crate::api::check(&source, &d, policy).result.unwrap_err();
    println!(
        "FRONTIER auxiliary refusal source={source:?} error={:?}",
        refused.errors[0].msg
    );
    assert!(refused.errors[0]
        .msg
        .starts_with("symbolic_shapes: 16385 exceeds 16384;"));
    drop(refused);
    assert!(crate::symbolic_control::refusal().is_none());
    // Structural-only inspection of this REFUSED source, never admission.
    let l0 = crate::parser::l0::check(&source).unwrap();
    let program = crate::Program::compile(&source).unwrap();
    let measures =
        crate::limits::measure(program.expression(), source.len(), Some(l0.real_tokens)).unwrap();
    assert_eq!(measures.ast_depth, 32);
    assert_eq!(measures.comprehension_depth, 2);
    println!("FRONTIER auxiliary structural-only measures={measures:?} (no Prepared issued)");
    drop(program);
    let p = crate::api::check("true", &d, policy).result.unwrap();
    let r = crate::api::evaluate(&p, &b, policy);
    assert_eq!(r.result, Ok(Value::Bool(true)));
    audit_cost(r.cost, p.bound());
    drop(r);
    drop(p);
}

fn combined_auxiliary_helpers() {
    use crate::quantity::Sym;
    use crate::symbolic_control::{self as control, account_limits, Counts, Resource};
    // Helper evidence only: public checking installs its OWN account, so this
    // deliberately does not pretend to override a public admission limit.
    let limits = Counts {
        nodes: 64,
        visits: 10_000,
        cells: 10_000,
        shapes: 100,
    };
    let (_, counts, refusal) = account_limits(limits, || {
        let mut graph = Sym::input(1, None);
        for scope in 0..100 {
            graph = Sym::parameter(scope, Sym::c(1), graph);
        }
        assert!(graph.value().is_err());
        assert!(!control::spend(Resource::Cells, 1));
        drop(graph);
    });
    assert_eq!(counts.nodes, 64);
    let refused = refusal.unwrap();
    assert_eq!(refused.cap, "symbolic_nodes");
    assert_eq!(refused.limit, 64);
    assert_eq!(refused.measured, 65);
    println!("HELPER construction counts={counts:?} refusal={refused:?}");
    assert!(control::refusal().is_none());

    let mut graph = Sym::input(1, None);
    for _ in 0..96 {
        graph = graph.add(&Sym::c(1));
    }
    // Enough cells/visits to finish some leaf entries, then refuse with a
    // partial postorder/interval map still live; it must return Err and drop.
    for (label, limits) in [
        (
            "visits",
            Counts {
                nodes: 10_000,
                visits: 120,
                cells: 10_000,
                shapes: 100,
            },
        ),
        (
            "cells",
            Counts {
                nodes: 10_000,
                visits: 10_000,
                cells: 700,
                shapes: 100,
            },
        ),
    ] {
        let (_, counts, refusal) = account_limits(limits, || {
            assert!(graph.value().is_err());
            let rebound = graph.rebind(1, 2);
            assert!(rebound.value().is_err());
            let maximum = graph.maximum(1);
            assert!(maximum.value().is_err());
            let summed = graph.sum(1, &Sym::c(2));
            assert!(summed.value().is_err());
            assert!(graph.cross_product());
            drop(summed);
            drop(maximum);
            drop(rebound);
        });
        let refused = refusal.unwrap();
        assert_eq!(
            refused.cap,
            if label == "visits" {
                "symbolic_visits"
            } else {
                "symbolic_cells"
            }
        );
        println!("HELPER partial-{label} counts={counts:?} refusal={refused:?}");
        assert!(control::refusal().is_none());
        assert_eq!(graph.value().unwrap(), 97);
    }
    drop(graph);
    // Preserve separate 20k hidden-total shared/last-owner teardown evidence.
    let mut total = Sym::input(1, None);
    for scope in 0..20_000 {
        total = Sym::parameter(scope, Sym::c(1), total);
    }
    let shared = total.clone();
    assert_eq!(total.value().unwrap(), 1);
    drop(total);
    drop(shared);
    println!("HELPER hidden-total20k shared/last-owner drop complete (uncontrolled helper graph)");
}
