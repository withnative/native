//! Native scalar-row contract. Serialized bytes and allocation metrics are distinct.
use crate::objects::{Key, Value};
use crate::{ExecutionError, Policy};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;

pub const TOTAL_INPUT_BYTES: u64 = 1024 * 1024;
pub const ROWS_PER_INPUT: usize = 5000;
pub const SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarType {
    Int,
    Double,
    Bool,
    String,
    Any,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputKind {
    One,
    Many,
    Scalar { kind: ScalarType, nullable: bool },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputDecl {
    pub name: String,
    pub kind: InputKind,
}

/// Immutable after construction; policy supplies caps, never observed example values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declarations {
    pub(crate) entries: Arc<BTreeMap<String, InputKind>>,
    pub(crate) order: Arc<Vec<String>>,
}
impl Declarations {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn new(
        entries: impl IntoIterator<Item = InputDecl>,
        policy: &Policy,
    ) -> Result<Self, ExecutionError> {
        let mut result = BTreeMap::new();
        let mut order = Vec::new();
        let mut scalar_count = 0;
        for entry in entries {
            if matches!(entry.kind, InputKind::Scalar { .. }) {
                scalar_count += 1;
                if scalar_count > 1024 {
                    return Err(refused(
                        "argument_count",
                        "declarations",
                        scalar_count,
                        1024,
                        "declare only referenced arguments",
                    ));
                }
            }
            let name = &entry.name;
            if name.is_empty()
                || name.len() > 128
                || !name.bytes().enumerate().all(|(i, c)| {
                    c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                })
            {
                return Err(refused(
                    "identifier",
                    name,
                    name.len() as u64,
                    128,
                    "use a CEL identifier of at most 128 bytes",
                ));
            }
            if !matches!(entry.kind, InputKind::Scalar { .. }) {
                order.push(entry.name.clone());
            }
            if result.insert(entry.name.clone(), entry.kind).is_some() {
                return Err(refused(
                    "duplicate",
                    name,
                    2,
                    1,
                    "declare each binding once",
                ));
            }
            if order.len() > policy.input_count_candidate() {
                return Err(refused(
                    "input_count",
                    name,
                    order.len() as u64,
                    policy.input_count_candidate() as u64,
                    "combine inputs in SQL",
                ));
            }
        }
        let declarations = Self {
            entries: Arc::new(result),
            order: Arc::new(order),
        };
        declarations.validate_policy(policy)?;
        Ok(declarations)
    }
    pub(crate) fn validate_policy(&self, policy: &Policy) -> Result<(), ExecutionError> {
        if self.order.len() > policy.input_count_candidate() {
            return Err(refused(
                "input_count",
                "declarations",
                self.order.len() as u64,
                policy.input_count_candidate() as u64,
                "combine inputs in SQL",
            ));
        }
        // Revalidate every metadata invariant under the checking policy. The
        // ordered seam must contain exactly the non-scalar declarations once.
        let mut seen = std::collections::BTreeSet::new();
        for name in self.order.iter() {
            if !seen.insert(name)
                || !matches!(
                    self.entries.get(name),
                    Some(InputKind::One | InputKind::Many)
                )
            {
                return Err(refused(
                    "declaration_order",
                    "declarations",
                    1,
                    0,
                    "use checked ordered declarations",
                ));
            }
        }
        let mut scalars = 0;
        for (name, kind) in self.entries.iter() {
            if name.is_empty()
                || name.len() > 128
                || !name.bytes().enumerate().all(|(i, c)| {
                    c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                })
            {
                return Err(refused(
                    "identifier",
                    name,
                    name.len() as u64,
                    128,
                    "use a CEL identifier of at most 128 bytes",
                ));
            }
            if matches!(kind, InputKind::Scalar { .. }) {
                scalars += 1;
            } else if !seen.contains(name) {
                return Err(refused(
                    "declaration_order",
                    name,
                    1,
                    0,
                    "use checked ordered declarations",
                ));
            }
        }
        if scalars > 1024 {
            return Err(refused(
                "argument_count",
                "declarations",
                scalars as u64,
                1024,
                "declare only referenced arguments",
            ));
        }
        Ok(())
    }
}

pub(crate) fn refused(cap: &str, path: &str, got: u64, limit: u64, next: &str) -> ExecutionError {
    ExecutionError::InputRefused {
        cap: cap.into(),
        path: path.chars().take(128).collect(),
        measured: got,
        limit,
        message: next.into(),
    }
}
fn scalar(
    value: &Value,
    path: &str,
    kind: ScalarType,
    nullable: bool,
    policy: &Policy,
) -> Result<(), ExecutionError> {
    let accepted = match value {
        Value::Null => nullable,
        Value::Int(n) => {
            if !(-SAFE_INTEGER..=SAFE_INTEGER).contains(n) {
                return Err(refused(
                    "safe_number",
                    path,
                    n.unsigned_abs(),
                    SAFE_INTEGER as u64,
                    "use a string for large numbers",
                ));
            }
            matches!(kind, ScalarType::Int | ScalarType::Any)
        }
        Value::Float(n) => {
            if !n.is_finite() || n.abs() > SAFE_INTEGER as f64 {
                return Err(refused(
                    "safe_number",
                    path,
                    u64::MAX,
                    SAFE_INTEGER as u64,
                    "use a finite interoperable number",
                ));
            }
            matches!(kind, ScalarType::Double | ScalarType::Any)
        }
        Value::Bool(_) => matches!(kind, ScalarType::Bool | ScalarType::Any),
        Value::String(s) => {
            if s.len() > policy.string_bytes_candidate() {
                return Err(refused(
                    "string_bytes",
                    path,
                    s.len() as u64,
                    policy.string_bytes_candidate() as u64,
                    "shorten the text in SQL",
                ));
            }
            matches!(kind, ScalarType::String | ScalarType::Any)
        }
        _ => false,
    };
    if accepted {
        Ok(())
    } else {
        Err(refused(
            "scalar_shape",
            path,
            1,
            0,
            "supply a declared scalar; row fields cannot contain collections or bytes",
        ))
    }
}
fn row(value: &Value, path: &str, policy: &Policy) -> Result<(), ExecutionError> {
    let Value::Map(map) = value else {
        return Err(refused(
            "row_shape",
            path,
            1,
            0,
            "supply a row of scalar columns",
        ));
    };
    // Every compact JSON entry needs at least a quoted key, colon and scalar.
    if map.map.len() as u64 > TOTAL_INPUT_BYTES / 5 {
        return Err(refused(
            "total_bytes",
            path,
            TOTAL_INPUT_BYTES + 1,
            TOTAL_INPUT_BYTES,
            "narrow the input query",
        ));
    }
    for (key, value) in map.map.iter() {
        let Key::String(key) = key else {
            return Err(refused("column_key", path, 1, 0, "use text column names"));
        };
        // Bound diagnostic allocation before formatting paths with hostile keys.
        if key.len() as u64 > TOTAL_INPUT_BYTES {
            return Err(refused(
                "key_bytes",
                path,
                key.len() as u64,
                TOTAL_INPUT_BYTES,
                "shorten the column name",
            ));
        }
        let short: String = key.chars().take(64).collect();
        scalar(
            value,
            &format!("{path}.{short}"),
            ScalarType::Any,
            true,
            policy,
        )?;
    }
    Ok(())
}
pub(crate) fn validate_value(
    name: &str,
    value: &Value,
    kind: &InputKind,
    policy: &Policy,
) -> Result<(), ExecutionError> {
    match kind {
        InputKind::Scalar { kind, nullable } => scalar(value, name, *kind, *nullable, policy),
        InputKind::One => {
            if matches!(value, Value::Null) {
                Ok(())
            } else {
                row(value, name, policy)
            }
        }
        InputKind::Many => {
            let Value::List(rows) = value else {
                return Err(refused(
                    "many_shape",
                    name,
                    1,
                    0,
                    "supply a list of scalar rows",
                ));
            };
            if rows.len() > ROWS_PER_INPUT {
                return Err(refused(
                    "rows",
                    name,
                    rows.len() as u64,
                    ROWS_PER_INPUT as u64,
                    "narrow the input query",
                ));
            }
            let mut minimal_bytes = 2u64;
            for (i, value) in rows.iter().enumerate() {
                if let Value::Map(map) = value {
                    let entries = map.map.len() as u64;
                    // Exact structural lower bound: {} plus E minimal "":0
                    // entries and E-1 commas; list separators after row zero.
                    minimal_bytes = minimal_bytes.saturating_add(
                        2 + 5 * entries - u64::from(entries > 0) + u64::from(i > 0),
                    );
                    if minimal_bytes > TOTAL_INPUT_BYTES {
                        return Err(refused(
                            "total_bytes",
                            name,
                            minimal_bytes,
                            TOTAL_INPUT_BYTES,
                            "narrow the input query",
                        ));
                    }
                }
                row(value, &format!("{name}[{i}]"), policy)?;
            }
            Ok(())
        }
    }
}

/// Borrowed shallow serializer: validation has already excluded arbitrary depth/kinds.
struct ScalarJson<'a>(&'a Value);
impl Serialize for ScalarJson<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Null => s.serialize_unit(),
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Int(i) => s.serialize_i64(*i),
            Value::Float(f) => s.serialize_f64(*f),
            Value::String(t) => s.serialize_str(t),
            Value::List(l) => {
                let mut seq = s.serialize_seq(Some(l.len()))?;
                for v in l.iter() {
                    seq.serialize_element(&ScalarJson(v))?;
                }
                seq.end()
            }
            Value::Map(m) => {
                let mut map = s.serialize_map(Some(m.map.len()))?;
                for (k, v) in m.map.iter() {
                    let Key::String(k) = k else {
                        return Err(serde::ser::Error::custom("non-string key"));
                    };
                    map.serialize_entry(k.as_str(), &ScalarJson(v))?;
                }
                map.end()
            }
            _ => Err(serde::ser::Error::custom("not a scalar-row binding")),
        }
    }
}
struct ObjectJson<'a>(&'a BTreeMap<String, Value>);
impl Serialize for ObjectJson<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0 {
            map.serialize_entry(k, &ScalarJson(v))?;
        }
        map.end()
    }
}
struct Counter {
    bytes: u64,
}
impl Write for Counter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .saturating_add(buf.len() as u64)
            .min(TOTAL_INPUT_BYTES + 1);
        if self.bytes > TOTAL_INPUT_BYTES {
            return Err(io::Error::other("serialized input byte cap"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn serialized_bytes(values: &BTreeMap<String, Value>) -> Result<u64, ExecutionError> {
    let mut counter = Counter { bytes: 0 };
    if serde_json::to_writer(&mut counter, &ObjectJson(values)).is_err() {
        return Err(refused(
            "total_bytes",
            "bindings",
            counter.bytes,
            TOTAL_INPUT_BYTES,
            "narrow the total input queries",
        ));
    }
    Ok(counter.bytes)
}
pub(crate) fn validate(
    values: &BTreeMap<String, Value>,
    decls: &Declarations,
    policy: &Policy,
    complete: bool,
) -> Result<u64, ExecutionError> {
    for (name, value) in values {
        let Some(kind) = decls.entries.get(name) else {
            return Err(refused(
                "undeclared",
                name,
                1,
                0,
                "declare this binding before admission",
            ));
        };
        validate_value(name, value, kind, policy)?;
    }
    if complete {
        for name in decls.entries.keys() {
            if !values.contains_key(name) {
                return Err(refused(
                    "missing",
                    name,
                    0,
                    1,
                    "supply every declared binding",
                ));
            }
        }
    }
    serialized_bytes(values)
}

/// Iterative lexical free-name check; macro variables shadow declared names.
pub(crate) fn check_names(
    root: &crate::common::ast::IdedExpr,
    decls: &Declarations,
) -> Result<(), String> {
    use crate::common::ast::{EntryExpr, Expr};
    let mut pending = vec![(root, Vec::<String>::new())];
    while let Some((node, scope)) = pending.pop() {
        let mut push = |child, scope: Vec<String>| pending.push((child, scope));
        match &node.expr {
            Expr::Ident(name) => {
                if !scope.contains(name) && !decls.entries.contains_key(name) {
                    return Err(format!(
                        "undeclared binding '{name}'; declare its shape before checking"
                    ));
                }
            }
            Expr::Call(c) => {
                if let Some(t) = &c.target {
                    push(t, scope.clone());
                }
                for a in &c.args {
                    push(a, scope.clone());
                }
            }
            Expr::Select(s) => push(&s.operand, scope),
            Expr::List(l) => {
                for e in &l.elements {
                    push(e, scope.clone());
                }
            }
            Expr::Map(m) => {
                for e in &m.entries {
                    match &e.expr {
                        EntryExpr::MapEntry(m) => {
                            push(&m.key, scope.clone());
                            push(&m.value, scope.clone());
                        }
                        EntryExpr::StructField(f) => push(&f.value, scope.clone()),
                    }
                }
            }
            Expr::Comprehension(c) => {
                push(&c.iter_range, scope.clone());
                push(&c.accu_init, scope.clone());
                let mut inner = scope;
                inner.push(c.iter_var.clone());
                inner.push(c.accu_var.clone());
                push(&c.loop_cond, inner.clone());
                push(&c.loop_step, inner.clone());
                push(&c.result, inner);
            }
            Expr::Struct(_) | Expr::Unspecified => {
                return Err("AST form is not in cel-subset@1".into())
            }
            Expr::Literal(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{check, evaluate},
        Bindings,
    };
    fn decls() -> Declarations {
        Declarations::new(
            [InputDecl {
                name: "rows".into(),
                kind: InputKind::Many,
            }],
            &Policy::P0_INTERIM,
        )
        .unwrap()
    }
    fn row(v: Value) -> Value {
        let mut m = indexmap::IndexMap::new();
        m.insert(Key::from("body"), v);
        Value::Map(crate::objects::Map { map: Arc::new(m) })
    }
    #[test]
    fn declared_snapshot_revalidated_before_conversion() {
        let d = decls();
        let p = check("size(rows)", &d, &Policy::P0_INTERIM).result.unwrap();
        let mut b = Bindings::empty(&d, &Policy::P0_INTERIM);
        b.insert("rows", &Value::List(Arc::new(vec![row(Value::Int(1))])))
            .unwrap();
        assert!(evaluate(&p, &b, &Policy::P0_INTERIM).result.is_ok());
        b.variables.insert(
            "rows".into(),
            Value::List(Arc::new(vec![row(Value::Bytes(Arc::new(vec![])))])),
        );
        assert!(matches!(
            evaluate(&p, &b, &Policy::P0_INTERIM).result,
            Err(ExecutionError::InputRefused { .. })
        ));
    }
    #[test]
    fn failed_replace_keeps_previous_snapshot() {
        let d = decls();
        let mut b = Bindings::empty(&d, &Policy::P0_INTERIM);
        b.insert("rows", &Value::List(Arc::new(vec![]))).unwrap();
        assert!(b.insert("rows", &Value::Int(1)).is_err());
        assert!(matches!(b.variables["rows"], Value::List(_)));
    }
    #[test]
    fn json_bytes_include_escapes_and_keys() {
        let mut values = BTreeMap::new();
        values.insert("x".into(), row(Value::from("\"\n💡")));
        let bytes = serialized_bytes(&values).unwrap();
        assert_eq!(
            bytes,
            serde_json::to_vec(&serde_json::json!({"x":{"body":"\"\n💡"}}))
                .unwrap()
                .len() as u64
        );
    }
    #[test]
    fn unsupported_shapes_and_numbers_refuse() {
        let p = &Policy::P0_INTERIM;
        for v in [
            Value::Float(f64::NAN),
            Value::Float(f64::INFINITY),
            Value::Int(SAFE_INTEGER + 1),
            Value::UInt(1),
            Value::List(Arc::new(vec![])),
            Value::Bytes(Arc::new(vec![])),
        ] {
            assert!(scalar(&v, "x", ScalarType::Any, true, p).is_err());
        }
    }
    #[test]
    fn missing_and_extra_names_refuse() {
        let d = decls();
        assert!(validate(&BTreeMap::new(), &d, &Policy::P0_INTERIM, true).is_err());
        assert!(check("unknown", &d, &Policy::P0_INTERIM).result.is_err());
    }
}
