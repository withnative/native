// Runtime benches, rewritten for the locked-down public API (PR 1a):
// everything runs through `check` + `evaluate` under `P1`.
// The old custom-`VariableResolver` case is gone with the resolver
// surface; `banana` is bound as plain data instead.
use cel::{
    check, evaluate, Bindings, Declarations, InputDecl, InputKind, Policy, ScalarType, Value,
};
use criterion::{black_box, criterion_group, BenchmarkId, Criterion};

const EXPRESSIONS: [(&str, &str); 34] = [
    ("ternary_1", "(false || true) ? 1 : 2"),
    ("ternary_2", "(true ? false : true) ? 1 : 2"),
    ("or_1", "false || true"),
    ("and_1", "true && false"),
    ("and_2", "true && (false ? 2 : 3) > 2"),
    ("number", "1"),
    ("construct_list", "[1,2,3]"),
    ("construct_list_1", "[1]"),
    ("construct_list_2", "[a, 2]"),
    ("add_list", "[1,2,3] + [4, 5, 6]"),
    ("list_element", "[1,2,3][1]"),
    ("construct_dict", "{1: 2, '3': '4'}"),
    ("add_string", "'abc' + 'def'"),
    ("mapexpr", "{1 + a: 3}"),
    ("size_list", "[1].size()"),
    ("size_list_1", "size([1])"),
    ("size_str", "'a'.size()"),
    ("size_str_2", "size('a')"),
    ("size_map", "{1:2}.size()"),
    ("size_map_2", "size({1:2})"),
    ("member", "foo.bar"),
    ("map has", "has(foo.bar)"),
    ("map macro", "[1, 2, 3].map(x, x * 2)"),
    ("filter macro", "[1, 2, 3].filter(x, x > 2)"),
    ("all macro", "[1, 2, 3].all(x, x > 0)"),
    ("all map macro", "{0: 0, 1:1, 2:2}.all(x, x >= 0)"),
    ("max", "max([1, 2, 3])"),
    ("max negative", "max([-1, 0, 1])"),
    ("max float", "max([-1.0, 0.0, 1.0])"),
    ("duration", "duration('1s')"),
    ("timestamp", "timestamp('2023-05-28T00:00:00Z')"), // ("complex", "Account{user_id: 123}.user_id == 123"),
    ("variable resolver", "banana"),
    ("variable hashmap", "apple"),
    ("stress", "true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true && true"),
];

fn bench_declarations() -> Declarations {
    Declarations::new(
        [
            InputDecl {
                name: "foo".into(),
                kind: InputKind::One,
            },
            InputDecl {
                name: "apple".into(),
                kind: InputKind::Scalar {
                    kind: ScalarType::Bool,
                    nullable: false,
                },
            },
            InputDecl {
                name: "banana".into(),
                kind: InputKind::Scalar {
                    kind: ScalarType::Bool,
                    nullable: false,
                },
            },
            InputDecl {
                name: "a".into(),
                kind: InputKind::Scalar {
                    kind: ScalarType::Int,
                    nullable: false,
                },
            },
        ],
        &Policy::P1,
    )
    .unwrap()
}
fn bench_bindings(declarations: &Declarations) -> Bindings {
    let mut bindings = Bindings::empty(declarations, &Policy::P1);
    bindings
        .insert(
            "foo",
            &indexmap::IndexMap::from([("bar".to_string(), Value::Int(1))]).into(),
        )
        .unwrap();
    bindings.insert("apple", &Value::Bool(true)).unwrap();
    bindings.insert("banana", &Value::Bool(false)).unwrap();
    bindings.insert("a", &Value::Int(1)).unwrap();
    bindings
}

pub fn criterion_benchmark(c: &mut Criterion) {
    // https://gist.github.com/rhnvrm/db4567fcd87b2cb8e997999e1366d406
    let mut execution_group = c.benchmark_group("execute");
    let declarations = bench_declarations();
    for (name, expr) in black_box(&EXPRESSIONS) {
        let prepared = check(expr, &declarations, &Policy::P1)
            .result
            .expect("check failed");
        let bindings = bench_bindings(&declarations);
        execution_group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| evaluate(&prepared, &bindings, &Policy::P1))
        });
    }
}

pub fn criterion_benchmark_parsing(c: &mut Criterion) {
    let mut parsing_group = c.benchmark_group("parse");
    let declarations = bench_declarations();
    for (name, expr) in black_box(&EXPRESSIONS) {
        parsing_group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| check(expr, &declarations, &Policy::P1))
        });
    }
}

pub fn map_macro_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("map list");
    let sizes = [1, 10, 100, 1000, 5000];
    let declarations = Declarations::new(
        [InputDecl {
            name: "rows".into(),
            kind: InputKind::Many,
        }],
        &Policy::P1,
    )
    .unwrap();
    let prepared = check("rows.map(r, r.n * 2)", &declarations, &Policy::P1)
        .result
        .expect("check failed");
    for size in sizes {
        group.bench_function(format!("map_{size}").as_str(), |b| {
            let rows: Vec<Value> = (0..size)
                .map(|n| indexmap::IndexMap::from([("n".to_string(), Value::Int(n))]).into())
                .collect();
            let mut bindings = Bindings::empty(&declarations, &Policy::P1);
            bindings.insert("rows", &rows.into()).unwrap();
            b.iter(|| evaluate(&prepared, &bindings, &Policy::P1))
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark, criterion_benchmark_parsing, map_macro_benchmark
}

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// This is the following macro expanded:
/// criterion_main!(benches);
/// But expanded manually so that we can keep the dhat profiler in scope until after benchmarks run
fn main() {
    #[cfg(feature = "dhat-heap")]
    let profiler = dhat::Profiler::new_heap();

    benches();
    // If adding new criterion groups, do so here.

    // Dropping the dhat profiler prints information to stderr: https://docs.rs/dhat/latest/dhat/
    // Doing so before the below ensures profiler doesn't measure Criterion's summary code.
    // It still may measure other bits of Criterion during the benchmark, of course..
    #[cfg(feature = "dhat-heap")]
    drop(profiler);

    Criterion::default().configure_from_args().final_summary();
}
