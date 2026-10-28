//! Private WAT injection uses the same validator, worker, Store and decoder.
//! No test hooks are imports or externally available runtime capabilities.
use super::*;
use crate::runtime::{Compiled, Runtime};
use crate::runtime::{Failure, Gate, Hooks, Phase, Stop, FUEL};
use native_package_cel_wire::{
    Binding as DeclarationBinding, Declaration, Kind, Request as WireRequest,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const PARITY:&str="all fields of reduced protocol report: status, policy/interim, scalar value/error; excludes checked API caps/load cost/budget scope/cost/input cost";
#[derive(Clone)]
struct Binding {
    name: String,
    kind: Kind,
    value: Value,
}
#[derive(Clone)]
struct Request {
    expression: String,
    bindings: Vec<Binding>,
}
fn wire(r: Request) -> WireRequest {
    let source = serde_json::to_string(
        &r.bindings
            .iter()
            .map(|b| (b.name.clone(), b.value.clone()))
            .collect::<serde_json::Map<_, _>>(),
    )
    .unwrap();
    WireRequest::Evaluate {
        declaration: Declaration {
            language: native_package_cel_wire::LANGUAGE.into(),
            profile: native_package_cel_wire::PROFILE.into(),
            expression: r.expression,
            bindings: r
                .bindings
                .into_iter()
                .map(|b| DeclarationBinding {
                    name: b.name,
                    kind: b.kind,
                })
                .collect(),
        },
        source,
    }
}
fn run(r: Request) -> native_package_cel_wire::Report {
    native_package_cel_guest::run(wire(r))
}

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

fn request() -> Request {
    Request {
        expression: "1 + 1".into(),
        bindings: vec![],
    }
}
fn good_wire() -> Value {
    serde_json::to_value(run(request())).unwrap()
}
fn wat_bytes(text: &str) -> Vec<u8> {
    wat::parse_str(text).expect("literal WAT fixture")
}
fn module(output: &[u8], body: Option<&str>, extra: &str, ptr: i32, len: usize) -> Vec<u8> {
    let data = output
        .iter()
        .map(|b| format!("\\{b:02x}"))
        .collect::<String>();
    let packed = ((len as u64) << 32) | (ptr as u32 as u64);
    let body = body
        .map(str::to_owned)
        .unwrap_or_else(|| format!("i64.const {}", packed as i64));
    wat_bytes(&format!(
        r#"(module (memory (export "memory") 1) {extra}
      (data (i32.const 1024) "{data}")
      (func (export "guest_abi_version") (result i32) i32.const 2)
      (func (export "guest_allocate") (param i32) (result i32) i32.const 16)
      (func (export "guest_evaluate") (param i32 i32) (result i64) {body}))"#
    ))
}
fn wait_flag(flag: &AtomicBool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !flag.load(Ordering::Acquire) {
        assert!(Instant::now() < end, "shutdown flag timeout");
        std::thread::yield_now();
    }
}
fn recover(rt: &Runtime, rows: &mut Vec<Value>, after: &str) {
    let t = rt.submit(&wire(request())).expect("recovery admission");
    let probe = t.probe();
    let o = t.wait().expect("recovery reply");
    probe.wait_released();
    assert!(
        o.failure.is_none(),
        "STOP recovery failure after {after}: {o:?}"
    );
    assert_eq!(o.report.as_ref().unwrap().value, json!(2));
    rows.push(json!({"after":after,"fresh_CEL_recovery":o}));
}
fn failure_case(
    rt: &Runtime,
    rows: &mut Vec<Value>,
    name: &str,
    bytes: &[u8],
    expected: Stop,
    fuel: u64,
) {
    let m = rt.test_module(bytes).unwrap();
    let t = rt
        .test_submit(
            m,
            codec::encode(&wire(request())).unwrap(),
            fuel,
            Duration::from_secs(5),
            Hooks::default(),
        )
        .unwrap();
    let probe = t.probe();
    let o = t.wait().unwrap();
    probe.wait_released();
    assert_eq!(o.failure.map(|f| f.stop), Some(expected), "{name}: {o:?}");
    assert!(o.report.is_none());
    rows.push(json!({"case":name,"outcome":o}));
    recover(rt, rows, name);
}
fn rejected_module(rt: &Runtime, rows: &mut Vec<Value>, name: &str, bytes: &[u8]) {
    let error = rt.test_module(bytes).err().expect("bad module accepted");
    assert_eq!(error.phase, Phase::Module);
    rows.push(
        json!({"case":name,"failure":error,"module_sha256":format!("{:x}",Sha256::digest(bytes))}),
    );
    recover(rt, rows, name);
}

#[test]
fn integrated_guest_backstops_async_cancellation_and_recovery() {
    let mut objects = Vec::new();
    // Exercise each claimed object encoding without claiming cross-platform execution.
    for os in ["linux", "macos", "windows"] {
        for arch in ["x86_64", "aarch64"] {
            let config = embedding::target(os, arch, "little").unwrap();
            let bytes =
                embedding::encode(GUEST, config).unwrap_or_else(|e| panic!("{os}/{arch}: {e}"));
            embedding::verify(&bytes, GUEST, config).unwrap();
            objects.push(json!({"os":os,"arch":arch,"endian":"little","object_sha256":format!("{:x}",Sha256::digest(&bytes)),"object_bytes":bytes.len(),"module_bytes":GUEST.len(),"symbol":embedding::SYMBOL,"alignment":embedding::ALIGN,"length_hash_negatives_refused":true}));
            assert!(embedding::verify(&bytes, &GUEST[..GUEST.len() - 1], config).is_err());
            let mut wrong = GUEST.to_vec();
            wrong[0] ^= 1;
            assert!(embedding::verify(&bytes, &wrong, config).is_err());
        }
    }
    assert!(embedding::target("freebsd", "x86_64", "little").is_err());
    assert!(embedding::target("linux", "riscv64", "little").is_err());
    assert!(embedding::target("linux", "aarch64", "big").is_err());
    verify_embedded(GUEST, GUEST_LENGTH, GUEST_MODULE_SHA256).unwrap();
    assert!(verify_embedded(GUEST, GUEST_LENGTH + 1, GUEST_MODULE_SHA256).is_err());
    assert!(verify_embedded(GUEST, GUEST_LENGTH, &"0".repeat(64)).is_err());
    for (abi, source, manifest, lock) in [
        (
            "wrong",
            GUEST_SOURCE_SHA256,
            BUILD_MANIFEST_SHA256,
            env!("GUEST_ROOT_LOCK_SHA256"),
        ),
        (
            env!("GUEST_ABI"),
            &"0".repeat(64),
            BUILD_MANIFEST_SHA256,
            env!("GUEST_ROOT_LOCK_SHA256"),
        ),
        (
            env!("GUEST_ABI"),
            GUEST_SOURCE_SHA256,
            &"0".repeat(64),
            env!("GUEST_ROOT_LOCK_SHA256"),
        ),
        (
            env!("GUEST_ABI"),
            GUEST_SOURCE_SHA256,
            BUILD_MANIFEST_SHA256,
            &"0".repeat(64),
        ),
    ] {
        assert!(!verify_identity(
            abi,
            GUEST_MODULE_SHA256,
            source,
            manifest,
            lock,
            GUEST_LENGTH
        ));
    }
    // Compile the trusted module ONCE, outside all per-job deadlines.
    let compiled = Compiled::new(GUEST).expect("STOP actual guest stack/contract audit");
    let mut rt = Runtime::new(compiled.clone()).unwrap();
    assert_eq!(rt.live_threads(), 3);
    let mut rows = Vec::new();
    recover(&rt, &mut rows, "initial");

    // Module contract failures never reach instantiation.
    let base = r#"(module (memory (export "memory") 1)
      (func (export "guest_abi_version") (result i32) i32.const 2)
      (func (export "guest_allocate") (param i32) (result i32) i32.const 16)
      (func (export "guest_evaluate") (param i32 i32) (result i64) i64.const 0))"#;
    for (name, text) in [
        (
            "import",
            base.replacen("(module", "(module (import \"env\" \"x\" (func))", 1),
        ),
        (
            "extra-export",
            base.replace(
                "(memory",
                "(global (export \"unsafe\") i32 (i32.const 0)) (memory",
            ),
        ),
        (
            "wrong-function-type",
            base.replace("(param i32) (result i32)", "(param i64) (result i32)"),
        ),
        (
            "memory64",
            base.replace("(export \"memory\") 1", "(export \"memory\") i64 1"),
        ),
        (
            "shared-memory",
            base.replace("(export \"memory\") 1", "(export \"memory\") 1 1 shared"),
        ),
        (
            "initial-memory-over-limit",
            base.replace("(export \"memory\") 1", "(export \"memory\") 1025"),
        ),
    ] {
        rejected_module(&rt, &mut rows, name, &wat_bytes(&text));
    }
    // Typed ABI value and allocation-pointer checks occur before evaluation/decoding.
    let wrong_version =
        wat_bytes(&base.replace("(result i32) i32.const 2)", "(result i32) i32.const 3)"));
    failure_case(
        &rt,
        &mut rows,
        "wrong-ABI-version",
        &wrong_version,
        Stop::Contract,
        FUEL,
    );
    let bad_allocation = wat_bytes(&base.replace("i32.const 16)", "i32.const -1)"));
    failure_case(
        &rt,
        &mut rows,
        "bad-allocation-pointer",
        &bad_allocation,
        Stop::Pointer,
        FUEL,
    );
    for (name, bad) in [
        (
            "input-expression-cap",
            Request {
                expression: "x".repeat(1025),
                bindings: vec![],
            },
        ),
        (
            "input-serialized-byte-cap",
            Request {
                expression: "n0".into(),
                bindings: (0..16)
                    .map(|i| Binding {
                        name: format!("n{i}"),
                        kind: Kind::String,
                        value: json!("\u{0}".repeat(1024)),
                    })
                    .collect(),
            },
        ),
    ] {
        let error = rt.submit(&wire(bad)).err().expect("input cap accepted");
        assert_eq!(error, Failure::new(Phase::Encode, Stop::Input));
        rows.push(json!({"case":name,"failure":error}));
        recover(&rt, &mut rows, name);
    }
    let loop_module = wat_bytes(include_str!("../tests/fixtures/loop.wat"));
    failure_case(
        &rt,
        &mut rows,
        "fuel-evaluate",
        &loop_module,
        Stop::Fuel,
        1000,
    );
    let start = module(
        b"",
        Some("i64.const 0"),
        "(func $start (loop $x (br $x))) (start $start)",
        1024,
        1,
    );
    failure_case(&rt, &mut rows, "fuel-start", &start, Stop::Fuel, 1000);
    let recursive = module(
        b"",
        Some("call $recur drop i64.const 0"),
        "(func $recur (result i32) call $recur i32.const 1 i32.add)",
        1024,
        1,
    );
    failure_case(
        &rt,
        &mut rows,
        "call-stack",
        &recursive,
        Stop::CallStack,
        FUEL,
    );
    failure_case(
        &rt,
        &mut rows,
        "linear-stack-underflow",
        &wat_bytes(include_str!("../tests/fixtures/linear-stack.wat")),
        Stop::MemoryBounds,
        FUEL,
    );
    let memory = module(
        b"",
        Some("i32.const 1025 memory.grow drop i64.const 0"),
        "",
        1024,
        1,
    );
    failure_case(
        &rt,
        &mut rows,
        "memory-growth",
        &memory,
        Stop::MemoryLimit,
        FUEL,
    );
    let table = module(
        b"",
        Some("ref.null func i32.const 1 table.grow drop i64.const 0"),
        "(table 1 funcref)",
        1024,
        1,
    );
    failure_case(
        &rt,
        &mut rows,
        "table-growth",
        &table,
        Stop::TableLimit,
        FUEL,
    );
    // Epoch-only deadline: fuel is intentionally huge in this test, not disabled.
    let t = rt
        .test_submit(
            rt.test_module(&loop_module).unwrap(),
            codec::encode(&wire(request())).unwrap(),
            u64::MAX,
            Duration::from_millis(runtime::DEADLINE_MS),
            Hooks::default(),
        )
        .unwrap();
    let p = t.probe();
    let o = t.wait().unwrap();
    p.wait_released();
    assert_eq!(o.failure.map(|f| f.stop), Some(Stop::Deadline));
    assert!(o.fuel_used < u64::MAX);
    rows.push(json!({"case":"epoch-only-deadline","outcome":o}));
    recover(&rt, &mut rows, "epoch-only-deadline");
    // The same epoch callback also interrupts guest start code before exports exist.
    let t = rt
        .test_submit(
            rt.test_module(&start).unwrap(),
            codec::encode(&wire(request())).unwrap(),
            u64::MAX,
            Duration::from_millis(runtime::DEADLINE_MS),
            Hooks::default(),
        )
        .unwrap();
    let p = t.probe();
    let o = t.wait().unwrap();
    p.wait_released();
    assert_eq!(
        o.failure,
        Some(Failure::new(Phase::Instantiate, Stop::Deadline))
    );
    assert!(o.fuel_used < u64::MAX);
    rows.push(json!({"case":"epoch-only-start-deadline","outcome":o}));
    recover(&rt, &mut rows, "epoch-only-start-deadline");
    // A completed, queued result must still be discarded if its handle is cancelled.
    let t = rt.submit(&wire(request())).unwrap();
    t.probe().wait_released(); // reply published and actual Store destroyed
    t.cancel();
    let o = t.wait().unwrap();
    assert_eq!(
        o.failure,
        Some(Failure::new(Phase::Deliver, Stop::Cancelled))
    );
    assert!(o.report.is_none());
    rows.push(json!({"case":"cancel-before-delivery","outcome":o}));
    recover(&rt, &mut rows, "cancel-before-delivery");
    // Cancellation after an actual epoch callback in the evaluation phase.
    let gate = Gate::new();
    let t = rt
        .test_submit(
            rt.test_module(&loop_module).unwrap(),
            codec::encode(&wire(request())).unwrap(),
            u64::MAX,
            Duration::from_secs(5),
            Hooks {
                epoch: Some(gate.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    let p = t.probe();
    gate.entered();
    recover(&rt, &mut rows, "independent-job-while-loop-paused");
    t.cancel();
    gate.release();
    let o = t.wait().unwrap();
    p.wait_released();
    gate.assert_no_timeout();
    assert_eq!(
        o.failure,
        Some(Failure::new(Phase::Evaluate, Stop::Cancelled))
    );
    rows.push(json!({"case":"epoch-cancel","outcome":o}));
    recover(&rt, &mut rows, "epoch-cancel");
    // Real Store exists and decode completed, but the permit must remain owned.
    let g1 = Gate::new();
    let g2 = Gate::new();
    let dropped1 = Arc::new(AtomicBool::new(false));
    let dropped2 = Arc::new(AtomicBool::new(false));
    let bytes = codec::encode(&wire(request())).unwrap();
    let t1 = rt
        .test_submit(
            rt.trusted_test_module(),
            bytes.clone(),
            FUEL,
            Duration::from_secs(5),
            Hooks {
                before_drop: Some(g1.clone()),
                dropped: Some(dropped1.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    let t2 = rt
        .test_submit(
            rt.trusted_test_module(),
            bytes.clone(),
            FUEL,
            Duration::from_secs(5),
            Hooks {
                before_drop: Some(g2.clone()),
                dropped: Some(dropped2.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    let p1 = t1.probe();
    let p2 = t2.probe();
    g1.entered();
    g2.entered();
    assert!(p1.busy() && p2.busy());
    assert!(!dropped1.load(Ordering::Acquire));
    assert_eq!(
        rt.submit(&wire(request())).err(),
        Some(Failure::new(Phase::Admission, Stop::Busy))
    );
    // Abort the actual async reply future, not only the synchronous handle.
    let async_runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let task = async_runtime.spawn(async move { t1.wait_async().await });
    async_runtime.block_on(async {
        tokio::task::yield_now().await;
    });
    task.abort();
    assert!(async_runtime.block_on(task).unwrap_err().is_cancelled());
    assert!(p1.busy());
    assert!(!dropped1.load(Ordering::Acquire));
    assert_eq!(
        rt.submit(&wire(request())).err(),
        Some(Failure::new(Phase::Admission, Stop::Busy))
    );
    g1.release();
    p1.wait_released();
    assert!(dropped1.load(Ordering::Acquire));
    recover(&rt, &mut rows, "Busy-after-two-admissions");
    recover(&rt, &mut rows, "Busy-and-dropped-handle-after-Store-drop");
    g2.release();
    let o = t2.wait().unwrap();
    p2.wait_released();
    g1.assert_no_timeout();
    g2.assert_no_timeout();
    assert!(dropped2.load(Ordering::Acquire));
    assert!(o.failure.is_none());
    rows.push(json!({"case":"two-slots-drop-cancel-lifetime","permit_released_after_Store_drop":true,"no_pending_queue":true}));
    // Pointer and codec failures, followed by actual fresh checked CEL each time.
    for (name, ptr, len, expected) in [
        ("zero-length", 1024, 0, Stop::Length),
        ("oversize-output", 1024, 8193, Stop::Length),
        ("invalid-pointer", -2, 8, Stop::Pointer),
    ] {
        failure_case(
            &rt,
            &mut rows,
            name,
            &module(b"", None, "", ptr, len),
            expected,
            FUEL,
        );
    }
    failure_case(
        &rt,
        &mut rows,
        "invalid-UTF8",
        &module(&[255], None, "", 1024, 1),
        Stop::Utf8,
        FUEL,
    );
    failure_case(
        &rt,
        &mut rows,
        "invalid-JSON",
        &module(b"{", None, "", 1024, 1),
        Stop::Json,
        FUEL,
    );
    let mut bad_reports = Vec::new();
    for key in ["eval_policy", "eval_interim", "error_stage", "error"] {
        let mut v = good_wire();
        v.as_object_mut().unwrap().remove(key);
        bad_reports.push((
            format!("missing-{key}"),
            serde_json::to_vec(&v).unwrap(),
            Stop::Json,
        ));
    }
    let mut unknown = good_wire();
    unknown["unknown"] = json!({"nested":[1]});
    bad_reports.push((
        "unknown-field".into(),
        serde_json::to_vec(&unknown).unwrap(),
        Stop::Json,
    ));
    let valid = serde_json::to_string(&good_wire()).unwrap();
    let duplicate = valid.replacen('{', "{\"abi\":\"native.cel-scalar-guest/2\",", 1);
    bad_reports.push(("duplicate-field".into(), duplicate.into_bytes(), Stop::Json));
    for (name, key, value, expected) in [
        (
            "nested-result",
            "value",
            json!({"x":[1]}),
            Stop::ReportScalar,
        ),
        (
            "long-result",
            "value",
            json!("x".repeat(1025)),
            Stop::ReportScalar,
        ),
        (
            "unsafe-number",
            "value",
            json!(9007199254740992_i64),
            Stop::ReportScalar,
        ),
        (
            "false-interim",
            "check_interim",
            json!(false),
            Stop::ReportMetadata,
        ),
        (
            "bad-policy",
            "check_policy",
            json!("cel-subset@1/p0"),
            Stop::ReportMetadata,
        ),
    ] {
        let mut v = good_wire();
        v[key] = value;
        bad_reports.push((name.into(), serde_json::to_vec(&v).unwrap(), expected));
    }
    for (name, data, expected) in bad_reports {
        failure_case(
            &rt,
            &mut rows,
            &name,
            &module(&data, None, "", 1024, data.len()),
            expected,
            FUEL,
        );
    }
    // Small reduced-report parity expansion, not checked-API accounting parity.
    for (name, r, stage) in [
        (
            "double-result",
            Request {
                expression: "1.5 + 1.0".into(),
                bindings: vec![],
            },
            None,
        ),
        (
            "string-result",
            Request {
                expression: "'a' + 'b'".into(),
                bindings: vec![],
            },
            None,
        ),
        (
            "null-result",
            Request {
                expression: "null".into(),
                bindings: vec![],
            },
            None,
        ),
        (
            "regex",
            Request {
                expression: "'ab'.matches('b')".into(),
                bindings: vec![],
            },
            None,
        ),
        (
            "timestamp",
            Request {
                expression: "timestamp('2024-01-01T00:00:00Z').getFullYear() == 2024".into(),
                bindings: vec![],
            },
            None,
        ),
        (
            "wrong-scalar-type",
            Request {
                expression: "n+1".into(),
                bindings: vec![Binding {
                    name: "n".into(),
                    kind: Kind::Int,
                    value: json!(true),
                }],
            },
            Some("bindings"),
        ),
        (
            "duplicate-binding",
            Request {
                expression: "n+1".into(),
                bindings: vec![
                    Binding {
                        name: "n".into(),
                        kind: Kind::Int,
                        value: json!(1)
                    };
                    2
                ],
            },
            Some("request"),
        ),
        (
            "unsafe-result",
            Request {
                expression: "n+1".into(),
                bindings: vec![Binding {
                    name: "n".into(),
                    kind: Kind::Int,
                    value: json!(9007199254740991_i64),
                }],
            },
            Some("result"),
        ),
    ] {
        let native = run(r.clone());
        let t = rt
            .test_submit(
                rt.trusted_test_module(),
                serde_json::to_vec(&wire(r.clone())).unwrap(),
                FUEL,
                Duration::from_millis(runtime::DEADLINE_MS),
                Hooks::default(),
            )
            .unwrap();
        let p = t.probe();
        let o = t.wait().unwrap();
        p.wait_released();
        assert!(
            o.failure.is_none(),
            "STOP unexplained valid/checked case trap {name}: {o:?}"
        );
        let guest = o.report.as_ref().unwrap();
        assert_eq!(guest, &native);
        assert_eq!(guest.error_stage.as_deref(), stage);
        rows.push(json!({"case":name,"parity":PARITY,"outcome":o}));
        recover(&rt, &mut rows, name);
    }
    // Shutdown joins workers while their epoch ticker is demonstrably alive.
    let a = Gate::new();
    let b = Gate::new();
    let t1 = rt
        .test_submit(
            rt.test_module(&loop_module).unwrap(),
            codec::encode(&wire(request())).unwrap(),
            u64::MAX,
            Duration::from_secs(5),
            Hooks {
                epoch: Some(a.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    let t2 = rt
        .test_submit(
            rt.test_module(&loop_module).unwrap(),
            codec::encode(&wire(request())).unwrap(),
            u64::MAX,
            Duration::from_secs(5),
            Hooks {
                epoch: Some(b.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    a.entered();
    b.entered();
    let (flag, live) = rt.flags();
    std::thread::scope(|scope| {
        let join = scope.spawn(|| rt.shutdown());
        wait_flag(&flag);
        assert_eq!(live.load(Ordering::Acquire), 3);
        a.release();
        b.release();
        join.join().unwrap().unwrap();
    });
    for t in [t1, t2] {
        let o = t.wait().unwrap();
        assert_eq!(o.failure.map(|f| f.stop), Some(Stop::Shutdown));
        rows.push(json!({"case":"shutdown-active-epoch","outcome":o}));
    }
    a.assert_no_timeout();
    b.assert_no_timeout();
    assert_eq!(rt.live_threads(), 0);
    assert_eq!(
        rt.submit(&wire(request())).err(),
        Some(Failure::new(Phase::Admission, Stop::Closed))
    );
    let mut replacement = Runtime::new(compiled).unwrap();
    recover(&replacement, &mut rows, "shutdown-then-new-runtime");
    replacement.shutdown().unwrap();
    assert_eq!(replacement.live_threads(), 0);
    assert!(rows.len() <= 128);
    let mut bounded = codec::BoundedBytes::new(256 * 1024);
    serde_json::to_writer_pretty(&mut bounded,&json!({"stage":3,"embedding":{"objects":objects,"linked_module_sha256":GUEST_MODULE_SHA256,"linked_length":GUEST_LENGTH,"startup_pins_verified":true,"negative_pins_refused":true},"parity":PARITY,"rows":rows,"owned_threads_after_shutdown":0,"guest_stack_audit":replacement.compiled.audit,"limits":"targeted backstops only; host compilation outside guest bounds; no production qualification or full checked-API accounting parity"})).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/package-cel-guest-stage3/host-boundary-receipt.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, &bounded.bytes).unwrap();
}
