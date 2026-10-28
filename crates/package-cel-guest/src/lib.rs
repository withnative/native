//! Checked CEL runs only in this guest (or explicit native parity tests).
use cel::{Bindings, Declarations, InputDecl, InputKind, Policy, ScalarType};
use native_package_cel_wire::*;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::BTreeMap;
fn failure(mut report: Report, stage: &str, message: impl std::fmt::Display) -> Report {
    report.error_stage = Some(stage.into());
    report.error = Some(message.to_string().chars().take(512).collect());
    report
}
pub fn run(request: Request) -> Report {
    let declaration = request.declaration();
    let mode = request.mode();
    let policy = Policy::P1;
    let mut report = Report {
        abi: ABI.into(),
        mode,
        check_policy: policy.id().into(),
        check_interim: policy.interim(),
        check_ok: false,
        eval_policy: None,
        eval_interim: None,
        value: Value::Null,
        error_stage: None,
        error: None,
    };
    if let Err(e) = declaration.shape() {
        return failure(report, "request", e);
    }
    if let Request::Evaluate { source, .. } = &request {
        if source.len() > MAX_SOURCE {
            return failure(report, "source", "source JSON exceeds 16384 bytes");
        }
    }
    let declarations = match Declarations::new(
        declaration.bindings.iter().map(|b| InputDecl {
            name: b.name.clone(),
            kind: InputKind::Scalar {
                kind: scalar_type(b.kind),
                nullable: false,
            },
        }),
        &policy,
    ) {
        Ok(d) => d,
        Err(e) => return failure(report, "declarations", e),
    };
    let checked = cel::check(&declaration.expression, &declarations, &policy);
    report.check_policy = checked.policy_id.into();
    report.check_interim = checked.interim;
    let prepared = match checked.result {
        Ok(p) => p,
        Err(e) => return failure(report, "check", format!("{e:?}")),
    };
    let m = prepared.measures();
    if m.comprehensions != 0 || m.ast_depth > 16 || m.expanded_nodes > 128 {
        return failure(report, "profile", "development parsed-measure cap");
    }
    report.check_ok = true;
    let source = match &request {
        Request::Check { .. } => return report,
        Request::Evaluate { source, .. } => source,
    };
    let values = match bind_values(declaration, source) {
        Ok(v) => v,
        Err(e) => return failure(report, "bindings", e),
    };
    let mut bindings = Bindings::empty(&declarations, &policy);
    for (name, value) in values {
        if let Err(e) = bindings.insert(&name, &value) {
            return failure(report, "bindings", e);
        }
    }
    let evaluated = cel::evaluate(&prepared, &bindings, &policy);
    report.eval_policy = Some(evaluated.policy_id.into());
    report.eval_interim = Some(evaluated.interim);
    match evaluated.result {
        Ok(v) => match json_scalar(v) {
            Some(v) => report.value = v,
            None => return failure(report, "result", "expected bounded JSON scalar"),
        },
        Err(e) => return failure(report, "evaluate", e),
    }
    report
}
fn scalar(kind: Kind, value: &Value) -> Option<cel::Value> {
    Some(match kind {
        Kind::Int => cel::Value::Int(value.as_i64().filter(|v| (-SAFE..=SAFE).contains(v))?),
        Kind::Double => {
            let f = value
                .as_f64()
                .filter(|v| v.is_finite() && v.abs() <= SAFE as f64)?;
            cel::Value::Float(f)
        }
        Kind::Bool => cel::Value::Bool(value.as_bool()?),
        Kind::String => {
            let s = value.as_str().filter(|s| s.len() <= 1024)?;
            cel::Value::String(s.to_owned().into())
        }
    })
}
fn json_scalar(value: cel::Value) -> Option<Value> {
    match value {
        cel::Value::Int(v) if (-SAFE..=SAFE).contains(&v) => Some(v.into()),
        cel::Value::UInt(v) if v <= SAFE as u64 => Some(v.into()),
        cel::Value::Float(v) if v.is_finite() && v.abs() <= SAFE as f64 => {
            Some(serde_json::json!(v))
        }
        cel::Value::Bool(v) => Some(v.into()),
        cel::Value::String(v) if v.len() <= 1024 => Some(v.as_str().into()),
        cel::Value::Null => Some(Value::Null),
        _ => None,
    }
}

fn scalar_type(kind: Kind) -> ScalarType {
    match kind {
        Kind::Int => ScalarType::Int,
        Kind::Double => ScalarType::Double,
        Kind::Bool => ScalarType::Bool,
        Kind::String => ScalarType::String,
    }
}
struct Closed(BTreeMap<String, Value>);
impl<'de> Deserialize<'de> for Closed {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Closed;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("closed scalar object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Closed, M::Error> {
                let mut values = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.len() >= 16 || key.len() > 64 || values.contains_key(&key) {
                        return Err(serde::de::Error::custom(
                            "too many/duplicate/oversized binding names",
                        ));
                    }
                    let value: Value = map.next_value()?;
                    if value.is_array() || value.is_object() {
                        return Err(serde::de::Error::custom("binding must be scalar"));
                    }
                    values.insert(key, value);
                }
                Ok(Closed(values))
            }
        }
        d.deserialize_map(Visitor)
    }
}
fn bind_values(d: &Declaration, source: &str) -> Result<Vec<(String, cel::Value)>, &'static str> {
    let Closed(values) = serde_json::from_str(source).map_err(|_| "invalid closed scalar JSON")?;
    if values.len() != d.bindings.len() {
        return Err("source must exactly match declared names/types");
    }
    d.bindings
        .iter()
        .map(|b| {
            let value = values.get(&b.name).ok_or("missing binding")?;
            Ok((
                b.name.clone(),
                scalar(b.kind, value).ok_or("wrong scalar type/range/length")?,
            ))
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
mod abi {
    use super::*;
    // One allocation and evaluation per instance, always discarded by the host.
    static mut INPUT: Option<&'static mut [u8]> = None;

    #[no_mangle]
    pub extern "C" fn guest_abi_version() -> u32 {
        ABI_VERSION
    }

    #[no_mangle]
    pub extern "C" fn guest_allocate(len: u32) -> u32 {
        assert!(len > 0 && len as usize <= MAX_REQUEST);
        // This guest is single-threaded and has no imported callbacks/reentrancy.
        unsafe {
            assert!((*std::ptr::addr_of!(INPUT)).is_none());
            let bytes = Box::leak(vec![0; len as usize].into_boxed_slice());
            let ptr = bytes.as_mut_ptr() as u32;
            *std::ptr::addr_of_mut!(INPUT) = Some(bytes);
            ptr
        }
    }

    #[no_mangle]
    pub extern "C" fn guest_evaluate(ptr: u32, len: u32) -> u64 {
        // Consume the actual allocation, rather than trusting an arbitrary span.
        let input = unsafe {
            (*std::ptr::addr_of_mut!(INPUT))
                .take()
                .expect("allocate first")
        };
        assert_eq!(ptr, input.as_ptr() as u32);
        assert_eq!(len as usize, input.len());
        let request: Request = serde_json::from_slice(input).expect("closed request codec");
        let response = serde_json::to_vec(&run(request)).expect("bounded scalar report");
        assert!(response.len() <= MAX_RESPONSE);
        let response = Box::leak(response.into_boxed_slice());
        ((response.len() as u64) << 32) | response.as_ptr() as u32 as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn declaration(expression: &str) -> Declaration {
        Declaration {
            language: LANGUAGE.into(),
            profile: PROFILE.into(),
            expression: expression.into(),
            bindings: vec![Binding {
                name: "n".into(),
                kind: Kind::Int,
            }],
        }
    }
    fn evaluate(d: Declaration, source: &str) -> Report {
        run(Request::Evaluate {
            declaration: d,
            source: source.into(),
        })
    }
    #[test]
    fn check_only_has_no_invented_values_or_evaluation() {
        let d = declaration("1 / n");
        let check = run(Request::Check {
            declaration: d.clone(),
        });
        assert!(check.check_ok && check.error.is_none());
        assert_eq!(check.mode, Mode::Check);
        assert!(
            check.eval_policy.is_none() && check.eval_interim.is_none() && check.value.is_null()
        );
        assert_eq!(
            evaluate(d.clone(), r#"{"n":0}"#).error_stage.as_deref(),
            Some("evaluate")
        );
        assert_eq!(evaluate(d, r#"{"n":1}"#).value, serde_json::json!(1));
    }
    #[test]
    fn raw_source_rejects_duplicates_unknowns_missing_nested_and_unsafe_values() {
        for source in [
            "{",
            "[]",
            "null",
            r#"{"n":1,"n":2}"#,
            r#"{"n":1,"extra":0}"#,
            r#"{}"#,
            r#"{"n":null}"#,
            r#"{"n":[]}"#,
            r#"{"n":true}"#,
            r#"{"n":9007199254740992}"#,
            r#"{"n":1e999}"#,
        ] {
            let bad = evaluate(declaration("n+1"), source);
            assert_eq!(bad.error_stage.as_deref(), Some("bindings"), "{source}");
            let good = evaluate(declaration("n+1"), r#"{"n":1}"#);
            assert!(good.error.is_none());
            assert_eq!(good.value, serde_json::json!(2));
        }
    }
    #[test]
    fn all_development_admission_restrictions_are_checked_inside_guest() {
        let base = declaration("n+1");
        let mut cases = Vec::new();
        for expression in ["n +", "host.read()", "[1].all(x,x>0)"] {
            let mut d = base.clone();
            d.expression = expression.into();
            cases.push(d);
        }
        let mut d = base.clone();
        d.expression = format!("{}n{}", "-(".repeat(17), ")".repeat(17));
        cases.push(d);
        d = base.clone();
        d.language = "unknown".into();
        cases.push(d);
        d = base.clone();
        d.profile = "unknown".into();
        cases.push(d);
        d = base.clone();
        d.expression = " ".repeat(1025);
        cases.push(d);
        d = base.clone();
        d.bindings = vec![d.bindings[0].clone(); 2];
        cases.push(d);
        d = base.clone();
        d.bindings = (0..17)
            .map(|i| Binding {
                name: format!("n{i}"),
                kind: Kind::Int,
            })
            .collect();
        cases.push(d);
        for declaration in cases {
            let report = run(Request::Check { declaration });
            assert!(!report.check_ok && report.error.is_some());
            assert!(report.eval_policy.is_none());
        }
        let report = evaluate(base, &" ".repeat(MAX_SOURCE + 1));
        assert_eq!(report.error_stage.as_deref(), Some("source"));
        assert!(!report.check_ok);
    }
}
