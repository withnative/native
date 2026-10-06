//! Private fixture data for native measurement and false-refusal harnesses.
//!
//! No policy, admission, evaluation or binding bypass lives here. The caller must
//! construct checked declarations/bindings and execute through its normal API.
//! Expected categories describe the intended corpus role, not measured results.
//! JSON B is the complete compact binding envelope; cached metrics are separate.
use crate::{InputDecl, InputKind, ScalarType, Value};
use indexmap::IndexMap;
use serde_json::Value as Json;

pub(crate) const M1_REF: &str = "53c887685";
const B: usize = 1_048_576;
const MANY: usize = 5_000;

#[derive(Clone, Debug)]
pub(crate) struct Clause {
    pub id: String,
    pub when: String,
    pub result: String,
}
#[derive(Clone, Debug)]
pub(crate) enum Source {
    Expression(String),
    Clauses(Vec<Clause>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expected {
    AdmitValue,
    AdmitSemanticError(&'static str),
    /// Error prefixes are legitimate executions, including adapter-only unknowns.
    AdmitValueOrSemanticError,
    Refuse(&'static str),
    /// Deliberate sensitivity probe; never count this as a legitimate false refusal.
    CandidateDependent(&'static str),
}
#[derive(Clone, Debug)]
pub(crate) struct GuardDescriptor {
    pub pending_input_name: String,
    pub source: String,
}
#[derive(Clone, Debug)]
pub(crate) struct Scenario {
    pub name: String,
    /// Declaration order; M1 preserves input order then argument order.
    pub bindings: Vec<(String, Value)>,
    pub expected: Expected,
    /// Original adapter expectation, intentionally opaque to raw CEL execution.
    pub adapter_expected: Option<Json>,
    pub notes: String,
}
#[derive(Clone, Debug)]
pub(crate) struct Fixture {
    pub name: String,
    pub family: &'static str,
    pub source: Source,
    /// Declared from metadata/domain, never inferred from scenarios.
    pub declarations: Vec<InputDecl>,
    pub scenarios: Vec<Scenario>,
    /// Ordered by pending input's position in declarations.
    pub guards: Vec<GuardDescriptor>,
    /// Original SQL/required/required_when/unknown descriptors, no registry schema.
    pub input_metadata: Vec<Json>,
}

fn decl(name: &str, kind: InputKind) -> InputDecl {
    InputDecl {
        name: name.into(),
        kind,
    }
}
fn scalar(name: &str, kind: ScalarType) -> InputDecl {
    decl(
        name,
        InputKind::Scalar {
            kind,
            nullable: false,
        },
    )
}
fn row(entries: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::from(entries.into_iter().collect::<IndexMap<String, Value>>())
}
fn json_value(value: &Json) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(v) => Value::Bool(*v),
        Json::Number(v) => v
            .as_i64()
            .map(Value::Int)
            .unwrap_or_else(|| Value::Float(v.as_f64().expect("finite M1 number"))),
        Json::String(v) => Value::from(v.clone()),
        Json::Array(v) => Value::from(v.iter().map(json_value).collect::<Vec<_>>()),
        Json::Object(v) => row(v.iter().map(|(k, v)| (k.clone(), json_value(v)))),
    }
}
fn scenario(bindings: Vec<(String, Value)>, expected: Expected) -> Scenario {
    Scenario {
        name: "default".into(),
        bindings,
        expected,
        adapter_expected: None,
        notes: String::new(),
    }
}
fn expression(
    name: impl Into<String>,
    family: &'static str,
    source: impl Into<String>,
    declarations: Vec<InputDecl>,
    bindings: Vec<(String, Value)>,
    expected: Expected,
) -> Fixture {
    Fixture {
        name: name.into(),
        family,
        source: Source::Expression(source.into()),
        declarations,
        scenarios: vec![scenario(bindings, expected)],
        guards: vec![],
        input_metadata: vec![],
    }
}
fn base_rows(count: usize) -> Value {
    Value::from(
        (0..count)
            .map(|i| {
                row([
                    ("id".into(), Value::from(format!("r{i}"))),
                    ("n".into(), Value::Int(i as i64)),
                    ("ok".into(), Value::Bool(true)),
                ])
            })
            .collect::<Vec<_>>(),
    )
}
fn many_decls(names: &[&str]) -> Vec<InputDecl> {
    names
        .iter()
        .map(|name| decl(name, InputKind::Many))
        .collect()
}

/// Five byte-pinned groups and exactly seventeen original examples.
pub(crate) fn m1_groups() -> Vec<Fixture> {
    [
        ("bands", include_str!("../tests/corpus/policy/m1/bands.cel.json")),
        ("capacity", include_str!("../tests/corpus/policy/m1/capacity.cel.json")),
        ("eu", include_str!("../tests/corpus/policy/m1/eu.cel.json")),
        ("full-deal", include_str!("../tests/corpus/policy/m1/full-deal.cel.json")),
        ("sheet", include_str!("../tests/corpus/policy/m1/sheet.cel.json")),
    ].into_iter().map(|(name, raw)| {
        let doc: Json = serde_json::from_str(raw).expect("pinned M1 JSON");
        let metadata = doc["inputs"].as_array().expect("inputs").clone();
        let mut declarations = metadata.iter().map(|input| decl(input["name"].as_str().unwrap(),
            match input["cardinality"].as_str().unwrap() {
                "one" => InputKind::One, "many" => InputKind::Many, _ => unreachable!("pinned cardinality"),
            })).collect::<Vec<_>>();
        for arg in doc["args"].as_array().unwrap() {
            let arg = arg.as_str().unwrap();
            declarations.push(scalar(arg, if arg == "now_ms" { ScalarType::Int } else { ScalarType::String }));
        }
        let clauses = doc["clauses"].as_array().unwrap().iter().map(|c| Clause {
            id: c["id"].as_str().unwrap().into(), when: c["when"].as_str().unwrap().into(),
            result: c["result"].as_str().unwrap().into(),
        }).collect();
        let guards = metadata.iter().filter_map(|input| input["required_when"].as_str().map(|source|
            GuardDescriptor { pending_input_name: input["name"].as_str().unwrap().into(), source: source.into() })).collect();
        let scenarios = doc["examples"].as_array().unwrap().iter().map(|ex| {
            let bindings = declarations.iter().map(|d| {
                let value = ex["inputs"].get(&d.name).or_else(|| ex["args"].get(&d.name)).expect("original binding");
                (d.name.clone(), json_value(value))
            }).collect();
            Scenario { name: ex["name"].as_str().unwrap().into(), bindings,
                expected: if ex["expect"]["decision"] == "unknown" { Expected::AdmitValueOrSemanticError } else { Expected::AdmitValue },
                adapter_expected: Some(ex["expect"].clone()),
                notes: format!("Original {M1_REF}; adapter required/unknown handling is outside raw CEL. Evaluate guards against the preceding prefix."),
            }
        }).collect();
        Fixture { name: name.into(), family: "m1-original", source: Source::Clauses(clauses),
            declarations, scenarios, guards, input_metadata: metadata }
    }).collect()
}

/// One additional measurement scenario per original group. Many rows are
/// constructed from the SQL/domain labels, independently of example values.
/// Original seventeen examples remain exclusively in `m1_groups`.
pub(crate) fn m1_max_many() -> Vec<Fixture> {
    m1_groups().into_iter().map(|mut f| {
        f.family = "m1-max-many";
        f.name.push_str("-max-many");
        let mut scenario = f.scenarios.remove(0);
        scenario.name = "max-many-domain-rows".into();
        scenario.adapter_expected = None;
        scenario.expected = Expected::AdmitValue;
        scenario.notes = "5000 rows for each Many; scalar SQL/domain labels; original input order and declarations retained. Groups without Many retain the first original binding.".into();
        for declaration in &f.declarations {
            if declaration.kind != InputKind::Many { continue; }
            let rows = (0..MANY).map(|i| {
                let mut fields = vec![("id".into(), Value::from(format!("m{i}")))];
                match declaration.name.as_str() {
                    "tickets" => {},
                    "approvals" => fields.extend([
                        ("cap_bp".into(), Value::Int(2200)),
                        ("expires_at_ms".into(), Value::Int(1_700_000_005_000)),
                    ]),
                    "lines" => fields.push(("amount_minor".into(), Value::Int(1))),
                    _ => unreachable!("pinned M1 SQL domain"),
                }
                row(fields)
            }).collect::<Vec<_>>();
            let binding = scenario.bindings.iter_mut().find(|(name,_)| name == &declaration.name).unwrap();
            binding.1 = Value::from(rows);
        }
        f.scenarios = vec![scenario]; f
    }).collect()
}

/// Realistic, small scalar rows, maximum native many cardinality and total JSON < B.
pub(crate) fn canonical_many() -> Vec<Fixture> {
    let rows = base_rows(MANY);
    let one = row([("id".into(), Value::from("one"))]);
    [
        ("size-global", "size(rows)"),
        ("size-receiver", "rows.size()"),
        ("all", "rows.all(r,r.n >= 0)"),
        ("exists", "rows.exists(r,r.n == 4999)"),
        ("exists-one", "rows.exists_one(r,r.n == 4999)"),
        ("filter", "rows.filter(r,r.n >= 0)"),
        ("map", "rows.map(r,r.id)"),
        ("three-arg-map", "rows.map(r,r.n >= 0,r.id)"),
        ("filter-map", "rows.filter(r,r.n >= 0).map(r,r.id)"),
        ("used-list", "[one.id]+rows.map(r,r.id)"),
        (
            "contains",
            "rows.contains({'id':'r4999','n':4999,'ok':true})",
        ),
        ("membership", "{'id':'r4999','n':4999,'ok':true} in rows"),
        ("min-global", "min(rows.map(r,r.n))"),
        ("max-global", "max(rows.map(r,r.n))"),
        ("min-receiver", "rows.map(r,r.n).min()"),
        ("max-receiver", "rows.map(r,r.n).max()"),
    ]
    .into_iter()
    .map(|(name, source)| {
        expression(
            name,
            "canonical-many",
            source,
            vec![decl("rows", InputKind::Many), decl("one", InputKind::One)],
            vec![("rows".into(), rows.clone()), ("one".into(), one.clone())],
            Expected::AdmitValue,
        )
    })
    .collect()
}

/// 34/40/60/80 distinct field references; only TWO One declarations each.
pub(crate) fn wide_conditions() -> Vec<Fixture> {
    [17,20,30,40].into_iter().map(|n| {
        let source = (0..n).map(|i| format!("left.f{i} >= right.f{i}")).collect::<Vec<_>>().join(" && ");
        let left = row((0..n).map(|i| (format!("f{i}"),Value::Int(2))));
        let right = row((0..n).map(|i| (format!("f{i}"),Value::Int(1))));
        let mut f = expression(format!("wide-{n}"),"wide",source,
            vec![decl("left",InputKind::One),decl("right",InputKind::One)],
            vec![("left".into(),left),("right".into(),right)],Expected::AdmitValue);
        let Source::Expression(when) = f.source else { unreachable!() };
        f.source = Source::Clauses(vec![Clause { id: "allow".into(), when,
            result: "{'decision':'allow','reason':{'code':'within-policy','details':['capacity','region','term']},'used':['left','right']}".into() }]);
        f
    }).collect()
}

pub(crate) fn loop_controls() -> Vec<Fixture> {
    let rows = base_rows(MANY);
    [
        ("depth-zero", "size(rows)"),
        ("depth-one", "rows.map(r,r.n)"),
        ("depth-two-literal", "rows.map(r,[0,1].exists(i,i == 0))"),
        ("depth-two-one-row", "rows.map(r,[one].all(q,q.n >= 0))"),
        ("sequential", "rows.map(r,r.n).filter(n,n >= 0).map(n,n+1)"),
        ("shadowing", "rows.map(r,[1].map(r,r+1))"),
        ("caller-name-shadowing", "rows.map(one,one.n)"),
    ]
    .into_iter()
    .map(|(name, source)| {
        expression(
            name,
            "loop-control",
            source,
            vec![decl("rows", InputKind::Many), decl("one", InputKind::One)],
            vec![
                ("rows".into(), rows.clone()),
                ("one".into(), row([("n".into(), Value::Int(1))])),
            ],
            Expected::AdmitValue,
        )
    })
    .collect()
}

/// Exact total-B counterexample to multiplying the largest row by every item.
pub(crate) fn heterogeneous_rows() -> Vec<Fixture> {
    let build = |fields| {
        let large = row((0..fields).map(|i| (format!("k{i}"), Value::Int(0))));
        let mut rows = vec![row([]); MANY];
        rows[0] = large;
        Value::from(rows)
    };
    [("heterogeneous-exact",10_000),("cached-over-one-mib",15_000)].into_iter().map(|(name, fields)| {
        let mut f = expression(name,"heterogeneous", "rows.map(r,size(r))",many_decls(&["rows"]),
            vec![("rows".into(),build(fields))],Expected::AdmitValue);
        f.scenarios[0].notes = if fields == 10_000 {
            "Complete compact JSON 113899 bytes; rows value nodes 15001, metric 928890 bytes; prior owned-copy item-bind row 32014 WU; current reference-bind row 5000 WU (binding-name copies separate). Envelope is not an extra value node.".into()
        } else { "15000 fields in one row +4999 empty rows: cached metric >1MiB; complete compact JSON <B. No per-input cached-byte cap.".into() };
        f
    }).collect()
}

/// Repeated passes/copies deliberately remain distinct from one amortized scan.
pub(crate) fn copy_and_error_prefixes() -> Vec<Fixture> {
    let rows = base_rows(MANY);
    let one = row([(
        "body".into(),
        Value::from("a bounded body for repeated copies"),
    )]);
    [
        ("row-twice", "rows.map(r,[r,r])", Expected::AdmitValue),
        (
            "same-field-many-times",
            "rows.map(r,one.body)",
            Expected::AdmitValue,
        ),
        (
            "iteration-text-concat",
            "rows.map(r,string(r.n)+one.body)",
            Expected::AdmitValue,
        ),
        ("output-text", "one.body", Expected::AdmitValue),
        ("output-bytes", "bytes(one.body)", Expected::AdmitValue),
        (
            "output-aggregate",
            "{'body':one.body,'rows':rows}",
            Expected::AdmitValue,
        ),
        (
            "negative-uint-prefix",
            "rows.all(r,uint(-1)>0u)",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "bad-numeric-parse",
            "rows.exists(r,int('not-a-number')>0)",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "fractional-index",
            "rows[0.5]",
            Expected::AdmitSemanticError("UnexpectedType"),
        ),
        (
            "wrong-kind-index",
            "rows[true]",
            Expected::AdmitSemanticError("UnexpectedType"),
        ),
        (
            "first-item-owned-steal",
            "rows.map(r,0)[0]",
            Expected::AdmitValue,
        ),
        (
            "first-item-owned-uint",
            "rows.map(r,0)[0u]",
            Expected::AdmitValue,
        ),
        (
            "first-item-owned-double",
            "rows.map(r,0)[0.0]",
            Expected::AdmitValue,
        ),
        (
            "invalid-key-membership",
            "[1] in {'x':1}",
            Expected::AdmitSemanticError("UnsupportedKeyType"),
        ),
        (
            "invalid-key-index",
            "{'x':1}[[1]]",
            Expected::AdmitSemanticError("UnsupportedKeyType"),
        ),
        (
            "invalid-key-mapliteral",
            "{[1]:0}",
            Expected::AdmitSemanticError("UnsupportedKeyType"),
        ),
    ]
    .into_iter()
    .map(|(name, source, expected)| {
        expression(
            name,
            "copy-error-prefix",
            source,
            vec![decl("rows", InputKind::Many), decl("one", InputKind::One)],
            vec![("rows".into(), rows.clone()), ("one".into(), one.clone())],
            expected,
        )
    })
    .collect()
}

/// Cap-valid bindings; static refusal expected even if concrete data short-circuits.
pub(crate) fn cross_product_refusals() -> Vec<Fixture> {
    let xs = base_rows(MANY);
    let ys = base_rows(MANY);
    let mut fixtures: Vec<_> = [
        ("different-many", "xs.all(x,ys.exists(y,y.n == x.n))"),
        ("same-many", "xs.all(x,xs.exists(y,y.n == x.n))"),
        (
            "outer-filter",
            "xs.filter(x,x.ok).map(x,ys.exists(y,y.n == x.n))",
        ),
        (
            "materialized-inner-map",
            "xs.map(x,ys.map(y,y.n).contains(x.n))",
        ),
        (
            "materialized-inner-filter",
            "xs.map(x,ys.filter(y,y.ok).contains(x))",
        ),
        ("inner-contains", "xs.map(x,ys.contains(x))"),
        ("inner-membership", "xs.map(x,x in ys)"),
        ("inner-equality", "xs.map(x,ys == xs)"),
        ("whole-list-copy", "xs.map(x,ys)"),
        (
            "hidden-filter-map",
            "xs.map(x,ys.filter(y,y.n == x.n).map(y,y.id))",
        ),
    ]
    .into_iter()
    .map(|(name, source)| {
        expression(
            name,
            "cross-product-refusal",
            source,
            many_decls(&["xs", "ys"]),
            vec![("xs".into(), xs.clone()), ("ys".into(), ys.clone())],
            Expected::Refuse("many-product-or-repeated-many-traversal"),
        )
    })
    .collect();
    fixtures.push(expression(
        "linear-size-control",
        "cross-product-control",
        "xs.map(x,size(ys))",
        many_decls(&["xs", "ys"]),
        vec![("xs".into(), xs), ("ys".into(), ys)],
        Expected::AdmitValue,
    ));
    fixtures
}

/// S is a candidate input-text length, not a Policy override. Huge text uses one row.
/// Reserve envelope space near B and label the realized byte length explicitly.
pub(crate) fn text_boundaries(candidate_s: usize) -> Vec<Fixture> {
    let actual = candidate_s.min(B - 128);
    let body = "x".repeat(actual);
    let one = row([("body".into(), Value::from(body))]);
    let mut fixtures: Vec<_> = [
        ("text-output", "one.body", Expected::AdmitValue),
        ("text-bytes-output", "bytes(one.body)", Expected::AdmitValue),
        ("text-size", "size(one.body)", Expected::AdmitValue),
        ("text-copy-twice", "[one.body,one.body]", Expected::CandidateDependent("text-copy-multiplicity")),
        ("text-concat", "one.body+one.body", Expected::CandidateDependent("text-copy-multiplicity")),
    ].into_iter().map(|(name, source, expected)| {
        let mut f = expression(format!("{name}-{actual}"),"text-boundary",source,
            vec![decl("one",InputKind::One)],vec![("one".into(),one.clone())],expected);
        f.scenarios[0].notes = format!("Requested S={candidate_s}; actual body bytes={actual}; one row; reserved 128 bytes of total B for envelope. At S>B-128 this is a total-B control, not an exact S boundary."); f
    }).collect();
    // Two individually legal shallow inputs whose COMBINED envelope exceeds B.
    // Split text into scalar fields <=candidate S, so the refusal isolates total B.
    if candidate_s > 0 {
        let make = || {
            let target = B / 2 + 64;
            let mut bytes = 2; // braces; ordinary unescaped ASCII labels/text
            let mut entries = Vec::new();
            while bytes < target {
                let name = format!("p{}", entries.len());
                let len = candidate_s.min(target - bytes);
                bytes += name.len() + len + 5 + usize::from(!entries.is_empty());
                entries.push((name, Value::from("x".repeat(len))));
            }
            row(entries)
        };
        let mut f = expression(
            "combined-input-total-over-b",
            "input-refusal",
            "true",
            vec![decl("left", InputKind::One), decl("right", InputKind::One)],
            vec![("left".into(), make()), ("right".into(), make())],
            Expected::Refuse("total-serialized-input-bytes"),
        );
        f.scenarios[0].notes = "Each input alone fits B, each string <=candidate S; complete combined binding object >B. For tiny S, key/envelope overhead is included, not discarded.".into();
        fixtures.push(f);
    }
    // Two-entry maps exercise left-key hashing; one-entry fast path is insufficient.
    let key_len = candidate_s.clamp(1, B - 128);
    let long = row([
        ("x".repeat(key_len), Value::Int(0)),
        ("y".into(), Value::Int(0)),
    ]);
    for (name, source) in [
        ("long-left-key", "one == {'x':0,'y':0}"),
        ("nested-long-left-key", "[one] == [{'x':0,'y':0}]"),
    ] {
        let mut f = expression(
            format!("{name}-{key_len}"),
            "map-key-equality",
            source,
            vec![decl("one", InputKind::One)],
            vec![("one".into(), long.clone())],
            Expected::AdmitValue,
        );
        f.scenarios[0].notes = format!("Two entries; long LEFT key bytes={key_len}; key length is not scalar string S. Whole binding <B.");
        fixtures.push(f);
    }
    // Bounded binding, short source: parse a long duration without over-source input.
    let len = candidate_s.min(B - 128);
    let text = if len >= 2 {
        format!("{}s", "0".repeat(len - 1))
    } else {
        "0".repeat(len)
    };
    fixtures.push(expression(
        format!("bound-duration-{len}"),
        "temporal-boundary",
        "duration(text)",
        vec![scalar("text", ScalarType::String)],
        vec![("text".into(), Value::from(text))],
        if len >= 1 {
            Expected::AdmitValue
        } else {
            Expected::AdmitSemanticError("FunctionError")
        },
    ));
    if len > 0 {
        fixtures.push(expression(
            format!("bound-duration-invalid-{len}"),
            "temporal-boundary",
            "duration(text)",
            vec![scalar("text", ScalarType::String)],
            vec![(
                "text".into(),
                Value::from(format!("{}x", "0".repeat(len - 1))),
            )],
            Expected::AdmitSemanticError("FunctionError"),
        ));
    }
    fixtures
}

/// Ordered full binding snapshots. Harness must expose only the preceding prefix
/// to a guard, omitting the pending null One and every subsequent input.
/// Scenario.expected describes the GUARD outcome, not the trivial envelope source.
pub(crate) fn ordered_guards(candidate_input_count: usize) -> Vec<Fixture> {
    let mut fixtures = vec![];
    let first = row([("ok".into(), Value::Bool(true))]);
    for (name, source, expected) in [
        ("first-one", "enabled && now_ms > 0", Expected::AdmitValue),
        (
            "after-first-one",
            "first.ok && enabled",
            Expected::AdmitValue,
        ),
        ("guard-false", "!enabled", Expected::AdmitValue),
        (
            "guard-nonbool",
            "1",
            Expected::AdmitSemanticError("guard-result-kind"),
        ),
        (
            "guard-self",
            "pending.ok",
            Expected::Refuse("guard-self-reference"),
        ),
        (
            "guard-future",
            "future.ok",
            Expected::Refuse("guard-future-reference"),
        ),
    ] {
        let before_first = name == "first-one";
        let mut declarations = vec![
            scalar("enabled", ScalarType::Bool),
            scalar("now_ms", ScalarType::Int),
        ];
        if !before_first {
            declarations.push(decl("first", InputKind::One));
        }
        declarations.extend([
            decl("pending", InputKind::One),
            decl("future", InputKind::One),
        ]);
        let mut bindings = vec![
            ("enabled".into(), Value::Bool(true)),
            ("now_ms".into(), Value::Int(1)),
        ];
        if !before_first {
            bindings.push(("first".into(), first.clone()));
        }
        bindings.extend([
            ("pending".into(), Value::Null),
            ("future".into(), first.clone()),
        ]);
        let mut f = expression(
            name,
            "ordered-guard",
            "true",
            declarations,
            bindings,
            expected,
        );
        f.guards.push(GuardDescriptor {
            pending_input_name: "pending".into(),
            source: source.into(),
        });
        fixtures.push(f);
    }
    if candidate_input_count >= 2 {
        let prefix = candidate_input_count - 1;
        // Empty rows minimize envelope size while retaining maximal many length
        // for ordinary candidate Imax. For larger Imax label actual row count.
        // Exact empty-envelope accounting: 31 bytes for enabled/pending/root,
        // and name.len()+6 for each comma, quoted name, colon and empty list.
        // Replacing [] with R empty rows adds 3*R-1 bytes when R>0.
        let empty_envelope = (0..prefix).fold(31usize, |bytes, i| {
            bytes.saturating_add(format!("prefix{i}").len() + 6)
        });
        let rows_per = MANY.min(B.saturating_sub(empty_envelope) / prefix / 3);
        let rows = Value::from(vec![row([]); rows_per]);
        let mut declarations = vec![scalar("enabled", ScalarType::Bool)];
        let mut bindings = vec![("enabled".into(), Value::Bool(true))];
        for i in 0..prefix {
            let name = format!("prefix{i}");
            declarations.push(decl(&name, InputKind::Many));
            bindings.push((name, rows.clone()));
        }
        declarations.push(decl("pending", InputKind::One));
        bindings.push(("pending".into(), Value::Null));
        let source = (0..prefix)
            .map(|i| format!("prefix{i}.all(r,size(r) == 0)"))
            .collect::<Vec<_>>()
            .join(" && ");
        let mut f = expression(
            format!("many-prefix-{prefix}-{rows_per}"),
            "ordered-guard",
            "true",
            declarations,
            bindings,
            Expected::AdmitValue,
        );
        f.guards.push(GuardDescriptor {
            pending_input_name: "pending".into(),
            source: format!("enabled && {source}"),
        });
        if empty_envelope > B {
            f.scenarios[0].expected = Expected::Refuse("total-serialized-input-bytes");
        }
        f.scenarios[0].notes = format!("Candidate Imax={candidate_input_count}; {prefix} preceding Many inputs, {rows_per} rows each, pending null One. If rows_per<5000 this is total-B constrained, not maximal cardinality.");
        fixtures.push(f);
    }
    fixtures
}

/// Compact exact overload and semantic-prefix probes; internal special numbers
/// are expressions, never nonfinite or UInt external production bindings.
pub(crate) fn callable_shapes() -> Vec<Fixture> {
    let mut fixtures = vec![];
    for (name, source, expected) in [
        ("min-int", "min([2,1,1])", Expected::AdmitValue),
        ("max-int", "[2,1,1].max()", Expected::AdmitValue),
        ("min-uint", "[2u,1u].min()", Expected::AdmitValue),
        ("max-uint", "max([2u,1u])", Expected::AdmitValue),
        ("min-double", "min([2.0,1.0])", Expected::AdmitValue),
        ("max-double", "[2.0,1.0].max()", Expected::AdmitValue),
        (
            "min-empty",
            "min([])",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "max-empty",
            "[].max()",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "min-mixed",
            "min([1,1.0])",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "mixed-before-nan",
            "min([double('NaN'),1])",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "mixed-after-nan",
            "max([1,double('NaN')])",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "homogeneous-nan",
            "min([1.0,double('NaN')])",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "first-tie-negative-zero",
            "min([-0.0,0.0])",
            Expected::AdmitValue,
        ),
        (
            "first-tie-positive-zero",
            "[0.0,-0.0].max()",
            Expected::AdmitValue,
        ),
        (
            "internal-infinities",
            "[double('-inf'),0.0,double('inf')].max()",
            Expected::AdmitValue,
        ),
        (
            "min-global-arity-zero",
            "min()",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "max-global-arity-two",
            "max([1],[2])",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "min-receiver-arity-one",
            "[1].min(2)",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "max-wrong-receiver",
            "1.max()",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "min-wrong-kind",
            "min(['a'])",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "invalid-map-contains",
            "{'x':1}.contains([1])",
            Expected::AdmitSemanticError("NoSuchOverload"),
        ),
        (
            "uint-overflow-int",
            "uint(-1)",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "uint-overflow-double",
            "uint(-1.0)",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "int-overflow-uint",
            "int(18446744073709551615u)",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "int-overflow-infinity",
            "int(double('inf'))",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "duration-overflow-add",
            "duration('9223372036854775807ms')+duration('1ms')",
            Expected::AdmitSemanticError("Overflow"),
        ),
        (
            "duration-overflow-subtract",
            "duration('-9223372036854775807ms')-duration('1ms')",
            Expected::AdmitSemanticError("Overflow"),
        ),
        (
            "duration-trailing-junk",
            "duration('1s!')",
            Expected::AdmitSemanticError("FunctionError"),
        ),
        (
            "duration-exact-exponent",
            "duration('1e-9s')",
            Expected::AdmitValue,
        ),
        (
            "timestamp-upper-add",
            "timestamp('9999-12-31T23:59:59Z')+duration('1s')",
            Expected::AdmitSemanticError("Overflow"),
        ),
        (
            "timestamp-lower-sub",
            "timestamp('0001-01-01T00:00:00Z')-duration('1s')",
            Expected::AdmitSemanticError("Overflow"),
        ),
        (
            "timestamp-upper-valid",
            "timestamp('9999-12-31T23:59:59Z')+duration('0s')",
            Expected::AdmitValue,
        ),
        (
            "timestamp-bad-parse",
            "timestamp('not-a-time')",
            Expected::AdmitSemanticError("FunctionError"),
        ),
    ] {
        fixtures.push(expression(
            name,
            "callable-semantic",
            source,
            vec![],
            vec![],
            expected,
        ));
    }
    for (name, source) in [
        ("min-int-receiver", "[2,1].min()"),
        ("max-int-global", "max([2,1])"),
        ("min-uint-global", "min([2u,1u])"),
        ("max-uint-receiver", "[2u,1u].max()"),
        ("min-double-receiver", "[2.0,1.0].min()"),
        ("max-double-global", "max([2.0,1.0])"),
        ("duration-max-valid", "duration('9223372036854775807ms')"),
        ("duration-min-valid", "duration('-9223372036854775807ms')"),
    ] {
        fixtures.push(expression(
            name,
            "callable-semantic",
            source,
            vec![],
            vec![],
            Expected::AdmitValue,
        ));
    }
    // Shape coverage selected by registered logical operand count, not names alone.
    for (name, source) in [
        ("size-list-global", "size([1])"),
        ("size-list-receiver", "[1].size()"),
        ("size-map-global", "size({'x':1})"),
        ("size-text-receiver", "'abc'.size()"),
        ("size-bytes-global", "size(b'abc')"),
        ("size-map-receiver", "{'x':1}.size()"),
        ("size-text-global", "size('abc')"),
        ("size-bytes-receiver", "b'abc'.size()"),
        ("contains-text", "'abc'.contains('b')"),
        ("prefix", "'abc'.startsWith('a')"),
        ("suffix", "'abc'.endsWith('c')"),
        ("regex-global", "matches('abc','a.*')"),
        ("regex-receiver", "'abc'.matches('a.*')"),
        ("cast-int-string", "int('12')"),
        ("cast-int-identity", "int(12)"),
        ("cast-uint-identity", "uint(12u)"),
        ("cast-double-identity", "double(12.0)"),
        ("string-identity", "string('abc')"),
        ("cast-int-uint", "int(12u)"),
        ("cast-int-double", "int(12.0)"),
        ("cast-uint-string", "uint('12')"),
        ("cast-uint-int", "uint(12)"),
        ("cast-uint-double", "uint(12.0)"),
        ("cast-double-string", "double('12')"),
        ("cast-double-int", "double(12)"),
        ("cast-double-uint", "double(12u)"),
        ("string-int", "string(12)"),
        ("string-uint", "string(12u)"),
        ("string-double", "string(12.5)"),
        ("string-bytes", "string(b'abc')"),
        (
            "string-duration",
            "string(duration('-9223372036854775807ms'))",
        ),
        (
            "string-timestamp",
            "string(timestamp('2000-01-01T00:00:00Z'))",
        ),
        ("bytes-text", "bytes('abc')"),
        ("bytes-identity", "bytes(b'abc')"),
        ("duration-identity", "duration(duration('1s'))"),
        (
            "timestamp-identity",
            "timestamp(timestamp('2000-01-01T00:00:00Z'))",
        ),
        ("dyn-aggregate", "dyn([1,{'x':2}])"),
    ] {
        fixtures.push(expression(
            name,
            "callable-shape",
            source,
            vec![],
            vec![],
            Expected::AdmitValue,
        ));
    }
    for (name, source) in [
        ("string-bool", "string(true)"),
        ("size-arity", "size()"),
        ("size-kind", "size(1)"),
        ("cast-arity", "int()"),
        ("cast-receiver", "'1'.int()"),
        ("cast-kind", "int([])"),
        ("temporal-arity", "duration('1s','2s')"),
        ("temporal-kind", "timestamp(1)"),
        ("text-kind", "'abc'.contains(1)"),
        ("temporal-receiver", "'1s'.duration()"),
        ("timestamp-arity", "timestamp()"),
        ("global-contains", "contains('abc','a')"),
        ("text-arity", "'abc'.startsWith()"),
        ("text-wrong-receiver", "[1].endsWith('a')"),
    ] {
        fixtures.push(expression(
            name,
            "callable-shape",
            source,
            vec![],
            vec![],
            Expected::AdmitSemanticError("NoSuchOverload"),
        ));
    }
    for (name, value) in [
        ("external-uint", Value::UInt(1)),
        ("external-nan", Value::Float(f64::NAN)),
        ("external-infinity", Value::Float(f64::INFINITY)),
    ] {
        fixtures.push(expression(
            name,
            "input-refusal",
            "one.n",
            vec![decl("one", InputKind::One)],
            vec![("one".into(), row([("n".into(), value)]))],
            Expected::Refuse("external-scalar-kind-or-nonfinite"),
        ));
    }
    fixtures
}
