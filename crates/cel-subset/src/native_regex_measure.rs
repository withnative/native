//! Native regex candidate measurements; compilation timing is library-only,
//! while search cost/output checks use the ordinary public engine API.
use crate::{api, Bindings, Declarations, InputDecl, InputKind, Policy, Value};
use serde_json::{json, Value as Json};

pub(crate) fn measure(p: &Policy) -> Json {
    let mut patterns = Vec::new();
    for count in [1, 4, 16, 64, 128, 256, 512, 1024, 2048, 1_000_000] {
        patterns.push(("counted-repetition", format!("a{{{count}}}")));
    }
    for count in [2, 4, 8, 16, 32] {
        patterns.push((
            "wide-alternation",
            format!(
                "({})",
                (0..count)
                    .map(|i| format!("a{i}"))
                    .collect::<Vec<_>>()
                    .join("|")
            ),
        ));
    }
    for depth in [
        p.regex_nest_limit().saturating_sub(1),
        p.regex_nest_limit(),
        p.regex_nest_limit() + 1,
    ] {
        patterns.push((
            "nest-boundary",
            format!(
                "{}a{}",
                "(".repeat(depth as usize),
                ")".repeat(depth as usize)
            ),
        ));
    }
    for pattern in [
        "a",
        "[a-zA-Z0-9_]+",
        "(a|aa)*b",
        "(a+)+$",
        "(?:a?){32}b",
        "^(?:a{1,8}|b{1,8})+$",
        "(ab|cd){128}",
    ] {
        patterns.push(("search-adversary", pattern.into()));
    }
    let d = Declarations::new(
        [InputDecl {
            name: "one".into(),
            kind: InputKind::One,
        }],
        p,
    )
    .expect("fixed regex declaration");
    let mut cases = Vec::new();
    for (family, pattern) in patterns {
        let mut tiers = Vec::new();
        for &tier in p.regex_size_tiers() {
            let started = std::time::Instant::now();
            let compiled = regex::RegexBuilder::new(&pattern)
                .size_limit(tier)
                .nest_limit(p.regex_nest_limit())
                .build();
            tiers.push(json!({"tier":tier,"compiled":compiled.is_ok(),"elapsed_ns":started.elapsed().as_nanos(),
                "native_compile_row":{"work":crate::charges::regex_compile(tier as u64).work,"memory":crate::charges::regex_compile(tier as u64).memory}}));
        }
        let source = format!("one.body.matches(r'{pattern}')");
        let started = std::time::Instant::now();
        let checked = api::check(&source, &d, p);
        let elapsed = started.elapsed().as_nanos();
        let mut case = json!({"family":family,"pattern":pattern,"pattern_bytes":pattern.len(),"tiers":tiers,
            "source":source,"public_check_elapsed_ns":elapsed,"public_load":{"work":checked.load_cost.work,"memory":checked.load_cost.memory}});
        match checked.result {
            Err(e) => {
                case["public_refusal"] = json!(e.errors.iter().map(|e| &e.msg).collect::<Vec<_>>())
            }
            Ok(prepared) => {
                case["bound"] =
                    json!({"work":prepared.bound().work,"memory":prepared.bound().memory});
                let mut searches = Vec::new();
                for suffix in ["", "b", "!"] {
                    let body = format!(
                        "{}{suffix}",
                        "a".repeat(p.string_bytes_candidate() - suffix.len())
                    );
                    let row = Value::from(indexmap::IndexMap::from([(
                        "body".to_string(),
                        Value::from(body),
                    )]));
                    let mut bindings = Bindings::empty(&d, p);
                    bindings.insert("one", &row).expect("legal regex input");
                    let started = std::time::Instant::now();
                    let evaluated = api::evaluate(&prepared, &bindings, p);
                    let ns = started.elapsed().as_nanos();
                    let sound = evaluated.cost.work <= prepared.bound().work
                        && evaluated.cost.memory <= prepared.bound().memory;
                    searches.push(json!({"body_bytes":p.string_bytes_candidate(),"suffix":suffix,"elapsed_ns":ns,
                        "result":format!("{:?}",evaluated.result),"work":evaluated.cost.work,"memory":evaluated.cost.memory,"within_bound":sound,"ok_bool":matches!(&evaluated.result, Ok(Value::Bool(_)))}));
                }
                case["searches"] = json!(searches);
            }
        }
        cases.push(case);
    }
    json!({"policy":p.id(),"limits":crate::native_measure::limits(p),"cases":cases,
        "scope":"Native compile timings invoke the same RegexBuilder parameters directly; public check includes parsing/preparation/estimation. Public search timings include validation/conversion/emission. K is a conservative native charge scale, not guest fuel evidence."})
}

#[cfg(test)]
mod tests {
    #[test]
    fn public_p1_regex_stack_headroom_on_explicit_four_and_eight_mib() {
        const MARKER: &str = "CEL_NATIVE_REGEX_STACK";
        if let Ok(stack) = std::env::var(MARKER) {
            let stack: usize = stack.parse().unwrap();
            assert!([4 * 1024 * 1024, 8 * 1024 * 1024].contains(&stack));
            std::thread::Builder::new()
                .name("cel-native-combined-stack".into())
                .stack_size(stack)
                .spawn(move || {
                    assert_eq!(
                        crate::api::run_on_pool(|| std::thread::current().id()).unwrap(),
                        std::thread::current().id()
                    );
                    let report = super::measure(&crate::Policy::P1);
                    assert_eq!(report["cases"].as_array().unwrap().len(), 25);
                    for search in report["cases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .flat_map(|c| c["searches"].as_array().into_iter().flatten())
                    {
                        assert_eq!(search["within_bound"], true);
                        assert_eq!(search["ok_bool"], true, "admitted regex search: {search}");
                    }
                    drop(report);
                    println!(
                        "P1_REGEX_STACK_PASS stack={stack} debug={} cases=25",
                        cfg!(debug_assertions)
                    );
                })
                .unwrap()
                .join()
                .unwrap();
            return;
        }
        for stack in [4 * 1024 * 1024, 8 * 1024 * 1024] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","native_regex_measure::tests::public_p1_regex_stack_headroom_on_explicit_four_and_eight_mib","--nocapture"])
                .env(MARKER,stack.to_string()).env("CEL_NATIVE_COMBINED_STACK_BYTES",stack.to_string()).output().unwrap();
            assert!(
                output.status.success(),
                "stack={stack} {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
    #[test]
    fn adversarial_tiers_and_searches_use_pinned_public_candidates() {
        let report = super::measure(&crate::Policy::MEASUREMENT_CANDIDATES[3]);
        let cases = report["cases"].as_array().unwrap();
        assert!(cases.iter().any(|c| !c["public_refusal"].is_null()));
        assert!(cases.iter().any(|c| c["searches"].is_array()));
        for search in cases
            .iter()
            .flat_map(|c| c["searches"].as_array().into_iter().flatten())
        {
            assert_eq!(search["within_bound"], true);
            assert_eq!(search["ok_bool"], true, "admitted regex search: {search}");
        }
    }
}
