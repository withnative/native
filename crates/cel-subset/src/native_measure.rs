//! Private reproducible native calibration. Measurement-only Prepared objects
//! never populate the public-admitted soundness denominator.
use crate::native_fixture_sets::{self as data, Expected, Fixture, Source};
use crate::{api, Bound, Declarations, Policy};
use serde_json::{json, Value as Json};
use std::collections::BTreeMap;

fn maximum(all: &mut BTreeMap<String, Json>, key: String, n: Option<u64>, witness: &Json) {
    if let Some(n) = n {
        if all
            .get(&key)
            .and_then(|v| v["value"].as_u64())
            .is_none_or(|old| n > old)
        {
            all.insert(key, json!({"value":n,"witness":witness}));
        }
    }
}

/// Keep complete failure witnesses; successful definitions remain reproducible
/// from the pinned fixture/generator version instead of duplicating their inputs.
fn compact(report: crate::native_proof_harness::ProofReport) -> Json {
    let mut canonical_digest = 0xcbf29ce484222325u64;
    let mut extrema = [0u64; 3];
    let mut actual = BTreeMap::new();
    let mut originals = Vec::new();
    for case in &report.cases {
        if let Some(identity) = case["canonical"].as_str() {
            for byte in identity.bytes().chain(std::iter::once(0)) {
                canonical_digest ^= byte as u64;
                canonical_digest = canonical_digest.wrapping_mul(0x100000001b3);
            }
        }
        for (index, key) in ["work", "memory", "result_bytes"].iter().enumerate() {
            extrema[index] = extrema[index].max(case["bound"][key].as_u64().unwrap_or(0));
        }
        for phase in case["admission"]["native_aux"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let witness = json!({"fixture":case["name"],"definition":case["definition"],"generator":case["generator"],"phase":phase[0]});
            for metric in ["nodes", "visits", "cells", "shapes"] {
                maximum(
                    &mut actual,
                    format!("native_aux.{metric}"),
                    phase[1][metric].as_u64(),
                    &witness,
                );
            }
        }
        for scenario in case["scenarios"].as_array().into_iter().flatten() {
            if case["family"] == "m1-original" {
                originals.push(json!({"group":case["name"],"example":scenario["name"],
                    "opaque_adapter_expected":scenario["opaque_adapter_expected"],"raw_outcome":scenario["outcome"],
                    "raw_phase":scenario["phase"],"replacement_execution":scenario["replacement_execution"],
                    "guard_observations":scenario["guards"].as_array().map(|guards|guards.iter().map(|g|json!({"input":g["input"],"required":g["required"],"error":g["error"]})).collect::<Vec<_>>()),
                    "note":"Original expected decision/required/unknown gating is opaque adapter evidence. Raw clauses and prefix outcomes are reported independently."}));
            }
            let witness = json!({"fixture":case["name"],"index":case["index"],"family":case["family"],
                "definition":case["definition"],"generator":case["generator"],"scenario":scenario["name"],
                "outcome":scenario["outcome"],"error_category":scenario["execution"]["error"]["category"],
                "replacement_execution":scenario["replacement_execution"]});
            let execution = &scenario["execution"];
            let partition = if execution["error"].is_null() {
                "success"
            } else {
                if scenario["outcome"] == "semantic_error" {
                    "semantic_error_prefix"
                } else {
                    "failure_or_refusal"
                }
            };
            for phase in ["cost", "input_cost"] {
                for metric in ["work", "memory"] {
                    maximum(
                        &mut actual,
                        format!("body.{partition}.{phase}.{metric}"),
                        execution[phase][metric].as_u64(),
                        &witness,
                    );
                }
            }
            for metric in ["cached_nodes", "cached_bytes", "depth"] {
                maximum(
                    &mut actual,
                    format!("body.{partition}.output.{metric}"),
                    execution["output"][metric].as_u64(),
                    &witness,
                );
            }
            for guard in scenario["guards"].as_array().into_iter().flatten() {
                let mut witness = witness.clone();
                witness["guard_input"] = guard["input"].clone();
                witness["guard_phase"] = guard["phase"].clone();
                witness["guard_error_category"] = guard["error"]["category"].clone();
                let partition = if guard["error"].is_null() {
                    "success"
                } else {
                    if guard["semantic_error"] == true {
                        "semantic_error_prefix"
                    } else {
                        "failure_or_refusal"
                    }
                };
                for phase in ["cost", "input_cost", "bound"] {
                    for metric in ["work", "memory"] {
                        maximum(
                            &mut actual,
                            format!("guard.{partition}.{phase}.{metric}"),
                            guard[phase][metric].as_u64(),
                            &witness,
                        );
                    }
                }
            }
        }
    }
    json!({"policy_id":report.policy_id,"interim":report.interim,"mode":report.mode,
        "limits":report.limits,"counts":report.counts,"by_family":report.by_family,
        "generator":report.generator,"ordered_canonical_fnv1a64":format!("{canonical_digest:016x}"),
        "m1_original_examples":originals,
        "admitted_bound_maxima":{"work":extrema[0],"memory":extrema[1],"result_bytes":extrema[2]},
        "actual_extrema":actual,
        "auxiliary_limits":crate::symbolic_control::limits(),
        "auxiliary_storage":auxiliary_storage(),
        "failures":report.failures,
        "note":"Counts use exact expanded-AST identity; this digest is reproducibility evidence, not the distinctness test. Full failure witnesses retained."})
}

pub(crate) fn run(mode: &str, candidate: usize, count: usize) -> Result<Json, String> {
    let started = std::time::Instant::now();
    let command = |exe, args: &[&str]| {
        std::process::Command::new(exe)
            .args(args)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    let head_start = command("git", &["rev-parse", "HEAD"]);
    let tree_start = command("git", &["status", "--porcelain"]);
    let binary_sha = std::env::current_exe()
        .ok()
        .and_then(|path| {
            std::process::Command::new("sha256sum")
                .arg(path)
                .output()
                .ok()
        })
        .filter(|out| out.status.success())
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .next()
                .map(str::to_owned)
        });
    let chosen = if candidate == usize::MAX {
        Policy::P1
    } else {
        *Policy::MEASUREMENT_CANDIDATES
            .get(candidate)
            .ok_or("unknown candidate")?
    };
    let p = &chosen;
    let fixtures = fixtures(p);
    let mut report = match mode {
        "calibrate" => Ok::<Json, String>(calibration(p, &fixtures)),
        "regex" => Ok(crate::native_regex_measure::measure(p)),
        "fixtures" => Ok(compact(crate::native_proof_harness::fixture_batch(
            &fixtures, p,
        ))),
        "generated" => {
            let generated = crate::native_rule_generator::generate(
                crate::native_rule_generator::DEFAULT_SEED,
                count,
            );
            Ok(compact(crate::native_proof_harness::generated_summary(
                &generated, p,
            )))
        }
        _ => Err("mode must be calibrate, fixtures, generated or regex".into()),
    }?;
    report["execution"] = json!({"elapsed_seconds":started.elapsed().as_secs_f64(),
        "command":{"mode":mode,"candidate":candidate,"requested_successes":count},
        "execution_head_start":head_start,"working_tree_start":tree_start,"binary_sha256":binary_sha,
        "execution_head_end":command("git", &["rev-parse","HEAD"]),"working_tree_end":command("git", &["status","--porcelain"]),
        "rustc":command("rustc", &["-Vv"]),"debug_assertions":cfg!(debug_assertions),
        "arch":std::env::consts::ARCH,"os":std::env::consts::OS,
        "available_parallelism":std::thread::available_parallelism().ok().map(|n|n.get()),
        "cpu":std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|s|s.lines().find(|l|l.starts_with("model name")).map(str::to_owned)),
        "memory":std::fs::read_to_string("/proc/meminfo").ok().and_then(|s|s.lines().find(|l|l.starts_with("MemTotal:")).map(str::to_owned)),
        "scope":"Native wall time includes source check, input validation, proof diagnostics and runtime; not guest fuel or allocator high-water."});
    Ok(report)
}

pub(crate) fn fixtures(policy: &Policy) -> Vec<Fixture> {
    let mut all = Vec::new();
    for mut set in [
        data::m1_groups(),
        data::m1_max_many(),
        data::canonical_many(),
        data::wide_conditions(),
        data::loop_controls(),
        data::heterogeneous_rows(),
        data::copy_and_error_prefixes(),
        data::cross_product_refusals(),
        data::text_boundaries(policy.string_bytes_candidate()),
        data::ordered_guards(policy.input_count_candidate()),
        data::callable_shapes(),
        payload_cases(policy),
    ] {
        all.append(&mut set);
    }
    all
}
fn legitimate(f: &Fixture) -> bool {
    f.scenarios.iter().any(|s| {
        matches!(
            s.expected,
            Expected::AdmitValue
                | Expected::AdmitSemanticError(_)
                | Expected::AdmitValueOrSemanticError
        )
    })
}
fn bound(b: Bound) -> Json {
    json!({"work":b.work,"memory":b.memory,"retained":b.retained,
    "result_nodes":b.result_nodes,"result_bytes":b.result_bytes,"result_depth":b.result_depth,"resource_product":b.resource_product})
}
pub(crate) fn calibration(policy: &Policy, fixtures: &[Fixture]) -> Json {
    let mut cases = Vec::new();
    let mut largest_work = (0u64, String::new());
    let mut largest_memory = (0u64, String::new());
    let mut guard_work = (0u64, String::new());
    let mut guard_memory = (0u64, String::new());
    let update = |best: &mut (u64, String), n, name: &str| {
        if n > best.0 {
            *best = (n, name.into());
        }
    };
    for f in fixtures {
        let required = legitimate(f);
        let mut case =
            json!({"name":f.name,"family":f.family,"legitimate":required,"measurement_only":true});
        let d = match Declarations::new(f.declarations.clone(), policy) {
            Ok(d) => d,
            Err(e) => {
                case["refusal"] = json!(e.to_string());
                cases.push(case);
                continue;
            }
        };
        let guards = f
            .guards
            .iter()
            .map(|g| crate::GuardSource {
                input: g.pending_input_name.clone(),
                source: g.source.clone(),
            })
            .collect::<Vec<_>>();
        let measured = match &f.source {
            Source::Expression(source) if guards.is_empty() => {
                let r = api::check_native(source, &d, policy, false);
                case["load"] = json!({"work":r.load_cost.work,"memory":r.load_cost.memory});
                r.result
                    .map(|p| {
                        case["native_aux"] = json!([("expression", p.native_aux())]);
                        p.bound()
                    })
                    .map_err(|e| e.to_string())
            }
            source => {
                let clauses = match source {
                    Source::Expression(source) => vec![crate::Clause {
                        id: "measurement-envelope".into(),
                        when: "true".into(),
                        result: source.clone(),
                    }],
                    Source::Clauses(clauses) => clauses
                        .iter()
                        .map(|c| crate::Clause {
                            id: c.id.clone(),
                            when: c.when.clone(),
                            result: c.result.clone(),
                        })
                        .collect(),
                };
                let r = crate::rule::check_rule_native(&clauses, &d, &guards, policy, false);
                case["load"] = json!({"work":r.load_cost.work,"memory":r.load_cost.memory});
                r.result
                    .map(|p| {
                        case["native_aux"] = json!(p.native_aux_phases());
                        p.bound()
                    })
                    .map_err(|e| e.to_string())
            }
        };
        match measured {
            Ok(b) => {
                case["bound"] = bound(b);
                if required && !b.resource_product {
                    update(&mut largest_work, b.work, &f.name);
                    update(&mut largest_memory, b.memory, &f.name);
                }
                case["public_gate_would_refuse"] =
                    json!(crate::estimate::admit(b, policy.to_budget()).err());
            }
            Err(e) => case["refusal"] = json!(e),
        }
        let mut guard_cases = Vec::new();
        for g in &f.guards {
            let report = crate::guard::check_guard_native(
                &g.source,
                &g.pending_input_name,
                &d,
                policy,
                false,
            );
            match report.result {
                Ok(p) => {
                    let b = p.bound();
                    if required && !b.resource_product {
                        update(&mut guard_work, b.work, &f.name);
                        update(&mut guard_memory, b.memory, &f.name);
                    }
                    guard_cases.push(json!({"input":g.pending_input_name,"source":g.source,"bound":bound(b),"native_aux":p.native_aux(),
                        "public_gate_would_refuse":crate::estimate::admit(b,policy.guard_budget()).err(),
                        "load":{"work":report.load_cost.work,"memory":report.load_cost.memory}}));
                }
                Err(e) => guard_cases.push(
                    json!({"input":g.pending_input_name,"source":g.source,"refusal":e.to_string()}),
                ),
            }
        }
        case["guards"] = json!(guard_cases);
        cases.push(case);
    }
    let mut auxiliary = BTreeMap::new();
    for case in &cases {
        for phase in case["native_aux"].as_array().into_iter().flatten() {
            let witness = json!({"fixture":case["name"],"phase":phase[0]});
            for metric in ["nodes", "visits", "cells", "shapes"] {
                maximum(
                    &mut auxiliary,
                    metric.into(),
                    phase[1][metric].as_u64(),
                    &witness,
                );
            }
        }
        for guard in case["guards"].as_array().into_iter().flatten() {
            let witness =
                json!({"fixture":case["name"],"guard":guard["input"],"source":guard["source"]});
            for metric in ["nodes", "visits", "cells", "shapes"] {
                maximum(
                    &mut auxiliary,
                    metric.into(),
                    guard["native_aux"][metric].as_u64(),
                    &witness,
                );
            }
        }
    }
    let measurement_refusals = cases
        .iter()
        .filter(|case| {
            case["legitimate"] == true
                && (case["bound"].is_null()
                    || case["guards"]
                        .as_array()
                        .is_some_and(|guards| guards.iter().any(|g| g["bound"].is_null())))
        })
        .cloned()
        .collect::<Vec<_>>();
    json!({"policy":policy.id(),"measurement_only":true,"limits":limits(policy),"cases":cases,
        "all_legitimate_measured":measurement_refusals.is_empty(),"measurement_refusals":measurement_refusals,
        "measured_auxiliary_maxima":auxiliary,"auxiliary_storage":auxiliary_storage(),
        "largest_legitimate_estimated":{"rule_work":largest_work,"rule_memory":largest_memory,"guard_work":guard_work,"guard_memory":guard_memory},
        "required_twofold":{"rule_work":largest_work.0.saturating_mul(2),"rule_memory":largest_memory.0.saturating_mul(2),"guard_work":guard_work.0.saturating_mul(2),"guard_memory":guard_memory.0.saturating_mul(2)}})
}
pub(crate) fn limits(p: &Policy) -> Json {
    json!({"S":p.string_bytes_candidate(),"Imax":p.input_count_candidate(),"B":crate::input::TOTAL_INPUT_BYTES,
        "rows":crate::input::ROWS_PER_INPUT,"rule_work":p.work_limit(),"rule_memory":p.mem_limit_bytes(),
        "guard_work":p.guard_work_limit(),"guard_memory":p.guard_mem_limit_bytes(),
        "regex_tiers":p.regex_size_tiers(),"regex_nest":p.regex_nest_limit(),"regex_K":p.regex_k_re(),"regex_pattern":p.regex_max_pattern_bytes()})
}
fn auxiliary_storage() -> Json {
    let limits = crate::symbolic_control::limits();
    let (node, edge) = crate::quantity::native_layout();
    let (shape, kind) = crate::estimate::native_layout();
    json!({"ceilings":limits,"node_inline_bytes":node,"arc_edge_bytes":edge,"shape_inline_bytes":shape,"kind_inline_bytes":kind,
        "node_inline_payload_max":limits.nodes.saturating_mul(node as u64),
        "last_owner_drop_edge_payload_max":limits.nodes.saturating_mul(2).saturating_mul(edge as u64),
        "shape_inline_payload_model":limits.shapes.saturating_mul(shape as u64),
        "source_bytes":crate::limits::SOURCE_BYTES,"real_tokens":crate::limits::REAL_TOKENS,
        "ast_depth":crate::limits::AST_DEPTH,"value_depth":crate::limits::VALUE_DEPTH,"body_depth":crate::limits::COMPREHENSION_DEPTH,
        "scope":"Inline payload models exclude allocator headers/capacity/alignment. Cells cumulatively bound traversal/memo/coefficient records with bounded Rust record sizes; Shapes also count clone/rebind/join operations and bound nested union slots. These are finite native auxiliary-control storage implications, not an allocator census or runtime H charge. Visits bound traversal work. Last-owner queues have at most2edges per constructed node; source/declaration/value validation imposes separate finite bounds."})
}
fn payload_cases(policy: &Policy) -> Vec<Fixture> {
    use crate::{InputDecl, InputKind, Value};
    let row = |value: Value| Value::from(indexmap::IndexMap::from([("body".to_string(), value)]));
    let rows = Value::from(vec![
        row(Value::from(
            "x".repeat(197.min(policy.string_bytes_candidate()))
        ));
        5000
    ]);
    let mut out = Vec::new();
    for source in [
        "rows.map(r,r.body)",
        "rows+rows",
        "rows == rows",
        "rows.map(r,string(r.body))",
        "rows.map(r,bytes(r.body))",
        "rows.map(r,string(bytes(r.body)))",
        "rows.map(r,r.body.matches('x'))",
        "rows.all(r,r.body.matches('x'))",
    ] {
        out.push(Fixture { name:format!("total-B-text-{source}"), family:"total-B-text", source:Source::Expression(source.into()),
            declarations:vec![InputDecl { name:"rows".into(),kind:InputKind::Many }],
            scenarios:vec![data::Scenario { name:"5000-text-rows".into(),bindings:vec![("rows".into(),rows.clone())],
                expected:Expected::AdmitValue,adapter_expected:None,notes:"5000 rows, each197 ASCII bytes; complete binding below1MiB. ScalarS does not create5000 independentB allowances.".into() }],
            guards:vec![],input_metadata:vec![] });
    }
    for mut f in data::heterogeneous_rows() {
        for source in [
            "rows.map(r,r)",
            "rows.map(r,[r,r])",
            "rows.map(r,[r,r,r])",
            "rows.filter(r,true)",
        ] {
            f.name = format!("{}-{source}", f.name.split('-').next().unwrap());
            f.source = Source::Expression(source.into());
            out.push(f.clone());
        }
    }
    let mut guard = out
        .iter()
        .find(|f| matches!(&f.source,Source::Expression(s) if s=="rows.map(r,r.body.matches('x'))"))
        .unwrap()
        .clone();
    guard.name = "total-B-regex-guard".into();
    guard.family = "ordered-guard";
    guard.source = Source::Expression("true".into());
    guard.declarations.push(InputDecl {
        name: "pending".into(),
        kind: InputKind::One,
    });
    guard.scenarios[0]
        .bindings
        .push(("pending".into(), Value::Null));
    guard.guards.push(data::GuardDescriptor {
        pending_input_name: "pending".into(),
        source: "rows.all(r,r.body.matches('x'))".into(),
    });
    out.push(guard);
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calibration_records_estimated_extrema_without_claiming_admission() {
        let policy = Policy::MEASUREMENT_CANDIDATES[1];
        let f = fixtures(&policy);
        let report = calibration(&policy, &f);
        if let Ok(path) = std::env::var("CEL_NATIVE_CALIBRATION_OUTPUT") {
            std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        }
        assert_eq!(report["measurement_only"], true);
        assert!(
            report["largest_legitimate_estimated"]["rule_work"][0]
                .as_u64()
                .unwrap()
                > 0
        );
        let actual = compact(crate::native_proof_harness::fixture_batch(
            &data::ordered_guards(0),
            &policy,
        ));
        assert!(
            actual["actual_extrema"]["body.success.cost.work"]["value"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(
            actual["actual_extrema"]["guard.success.cost.work"]["value"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(
            actual["actual_extrema"]["guard.semantic_error_prefix.cost.work"]["value"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(actual["counts"]["failures"], 0);
    }
}
