// Parse benches, rewritten for the locked-down public API (PR 1a):
// throughput of `check` under `P1` per category. Verdicts
// are covered by unit tests and the rule corpus, not asserted here:
// several cases were calibrated to a custom parser (optional
// syntax, depth 512) that no longer exists publicly, and `check`
// enforces the product caps instead.
use cel::{check, Declarations, Policy};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

struct BenchTestInfo {
    input: String,
}

struct BenchCategory {
    name: &'static str,
    cases: Vec<BenchTestInfo>,
}

fn bench_categories() -> Vec<BenchCategory> {
    vec![
        // Simple: common, representative CEL expressions covering basic syntax, operators, calls, and literals
        BenchCategory {
            name: "Simple",
            cases: vec![
                BenchTestInfo {
                    input: "x * 2 + y / 3".to_string(),
                },
                BenchTestInfo {
                    input: "foo.bar.baz(1, 2, \"abc\")".to_string(),
                },
                BenchTestInfo {
                    input: "a > 5 && b < 10 || c == \"xyz\"".to_string(),
                },
                BenchTestInfo {
                    input: "x ? y : z".to_string(),
                },
                BenchTestInfo {
                    input: "{\"foo\": 1, \"bar\": [2, 3]}".to_string(),
                },
                BenchTestInfo {
                    input: "a[b]".to_string(),
                },
                BenchTestInfo {
                    input: "a.b.c".to_string(),
                },
                BenchTestInfo {
                    input: "a.`b-c`".to_string(),
                },
                BenchTestInfo {
                    input: "\"\\a\\b\\f\\n\\r\\t\\v'\\\"\\\\ Legal escapes \\u2764\"".to_string(),
                },
            ],
        },
        // Complex: expressions with deep chaining, nesting, precedence, and complex structures
        BenchCategory {
            name: "Complex",
            cases: vec![
                BenchTestInfo {
                    input: "a".to_string() + &" + a".repeat(49),
                },
                BenchTestInfo {
                    input: "a".to_string() + &" || a".repeat(49),
                },
                BenchTestInfo {
                    input: "a".to_string() + &".f".repeat(49),
                },
                BenchTestInfo {
                    input: "(".repeat(20) + "a" + &")".repeat(20),
                },
                BenchTestInfo {
                    input: "SomeMessage{foo: 5, bar: \"xyz\"}".to_string(),
                },
                BenchTestInfo {
                    input: "1 + 2 * 3 - 1 / 2 == 6 % 1".to_string(),
                },
                BenchTestInfo {
                    input: "[] + [1, 2, 3] + [4]".to_string(),
                },
            ],
        },
        // Macros: standard and receiver comprehension macros, optional syntax traversal
        BenchCategory {
            name: "Macros",
            cases: vec![
                BenchTestInfo {
                    input: "has(m.f)".to_string(),
                },
                BenchTestInfo {
                    input: "[1, 2, 3].all(x, x > 0)".to_string(),
                },
                BenchTestInfo {
                    input: "m.map(v, v * 2)".to_string(),
                },
                BenchTestInfo {
                    input: "m.filter(v, v > 0)".to_string(),
                },
                BenchTestInfo {
                    input: "m.exists_one(v, v == 1)".to_string(),
                },
                BenchTestInfo {
                    input: "x.filter(y, y.exists(z, has(z.a)))".to_string(),
                },
                BenchTestInfo {
                    input: "a.?b[?0] && a[?c]".to_string(),
                },
            ],
        },
        // Errors: representative syntax errors, invalid tokens, keywords, and unclosed delimiters
        BenchCategory {
            name: "Errors",
            cases: vec![
                BenchTestInfo {
                    input: "x * 2 + y /".to_string(),
                },
                BenchTestInfo {
                    input: "foo.bar.baz(1, 2, \"abc\"".to_string(),
                },
                BenchTestInfo {
                    input: "a > 5 && && b < 10".to_string(),
                },
                BenchTestInfo {
                    input: "{\"foo\": 1, \"bar\": [2, 3".to_string(),
                },
                BenchTestInfo {
                    input: "1 + $".to_string(),
                },
                BenchTestInfo {
                    input: "break".to_string(),
                },
                BenchTestInfo {
                    input: "\"\\xFh\"".to_string(),
                },
                BenchTestInfo {
                    input: "a".to_string() + &" + a".repeat(49) + " +",
                },
                BenchTestInfo {
                    input: "(".repeat(20) + "a",
                },
                BenchTestInfo {
                    input: "f(*".to_string() + &", *".repeat(9) + ")",
                },
            ],
        },
    ]
}

pub fn benchmark_by_category(c: &mut Criterion) {
    let categories = bench_categories();

    let mut group = c.benchmark_group("by_category/check");
    for cat in &categories {
        group.bench_function(BenchmarkId::from_parameter(cat.name), |b| {
            b.iter(|| {
                for tc in &cat.cases {
                    let _ = black_box(check(
                        black_box(&tc.input),
                        &Declarations::empty(),
                        &Policy::P1,
                    ));
                }
            });
        });
    }
    group.finish();
}

pub fn benchmark_by_category_comparison(c: &mut Criterion) {
    let categories = bench_categories();

    for cat in &categories {
        let mut group = c.benchmark_group(cat.name);

        group.bench_function("check", |b| {
            b.iter(|| {
                for tc in &cat.cases {
                    let _ = black_box(check(
                        black_box(&tc.input),
                        &Declarations::empty(),
                        &Policy::P1,
                    ));
                }
            });
        });

        group.finish();
    }
}

criterion_group!(
    benches,
    benchmark_by_category,
    benchmark_by_category_comparison
);
criterion_main!(benches);
