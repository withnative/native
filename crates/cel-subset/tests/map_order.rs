//! D1: CEL map iteration order is insertion order and is stable across
//! processes with different native hash seeds.
//!
//! The parent re-execs this test binary twice as a child; each process
//! gets a fresh `RandomState` seed, so a hash-ordered map would differ.

use std::process::Command;

fn keys_of(report: cel::EvalReport) -> String {
    use cel::Value;
    match report.result {
        Ok(Value::List(items)) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => s.to_string(),
                _ => "?".to_string(),
            })
            .collect::<Vec<_>>()
            .join(","),
        other => format!("ERR:{other:?}"),
    }
}

fn child_order() -> String {
    use cel::{check, evaluate, Bindings, Declarations, InputDecl, InputKind, Policy, Value};
    let prepared = check(
        "{'b': 1, 'a': 2, 'c': 3}.map(k, k)",
        &Declarations::empty(),
        &Policy::P1,
    )
    .result
    .expect("check");
    let report = evaluate(
        &prepared,
        &Bindings::empty(&Declarations::empty(), &Policy::P1),
        &Policy::P1,
    );
    let literal = keys_of(report);
    // F12: a bound map comes from an insertion-ordered IndexMap (the
    // public HashMap conversion is gone), so its order is stable too.
    let declarations = Declarations::new(
        [InputDecl {
            name: "m".into(),
            kind: InputKind::One,
        }],
        &Policy::P1,
    )
    .unwrap();
    let prepared = check("m.map(k, k)", &declarations, &Policy::P1)
        .result
        .expect("check");
    let mut bindings = Bindings::empty(&declarations, &Policy::P1);
    bindings
        .insert(
            "m",
            &Value::from(indexmap::IndexMap::from([
                ("b".to_string(), Value::Int(1)),
                ("a".to_string(), Value::Int(2)),
                ("c".to_string(), Value::Int(3)),
            ])),
        )
        .unwrap();
    let report = evaluate(&prepared, &bindings, &Policy::P1);
    format!("{literal}|{}", keys_of(report))
}

fn order_line(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("ORDER="))
        .unwrap_or("")
        .to_string()
}

#[test]
fn map_order_is_stable_across_processes() {
    if std::env::var("CEL_MAP_ORDER_CHILD").is_ok() {
        println!("ORDER={}", child_order());
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let run = || {
        let out = Command::new(&exe)
            .args([
                "map_order_is_stable_across_processes",
                "--exact",
                "--nocapture",
            ])
            .env("CEL_MAP_ORDER_CHILD", "1")
            .output()
            .expect("spawn child test binary");
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    let first = order_line(&run());
    let second = order_line(&run());
    assert_eq!(first, "b,a,c|b,a,c", "insertion order expected");
    assert_eq!(
        first, second,
        "map order must be identical across processes"
    );
}
