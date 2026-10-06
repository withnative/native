//! Bounded value descriptions for error payloads (step 7.0).
//!
//! Error variants that name operands must never deep-copy them: an
//! error can be raised once per iteration and absorbed (`all`/`exists`,
//! review E4), so an O(size) payload would be an uncharged
//! per-iteration copy and would break "the budget is the whole
//! deterministic policy". [`ValueDesc`] renders a bounded,
//! allocation-light description — a scalar's value, or an aggregate's
//! type and size — and building it charges 1 wu.

use std::fmt::{Debug, Display, Formatter, Write};
use std::sync::Arc;

use crate::common::types::{
    CelBool, CelBytes, CelDouble, CelInt, CelList, CelMap, CelString, CelUInt, Kind,
};
use crate::common::value::Val;
use crate::objects::Value;

/// Longest description kept (bytes).
const MAX: usize = 64;

/// A bounded description of a value for error payloads.
#[derive(Clone, PartialEq, Eq)]
pub struct ValueDesc(Option<Arc<str>>);

impl ValueDesc {
    /// The description for an absent or unknown operand.
    pub fn null() -> Self {
        ValueDesc(None)
    }

    /// A bounded description of `v`, charging 1 wu (best effort: an
    /// error is already being raised, so a refusal here does not
    /// change the outcome).
    pub fn of(v: &dyn Val) -> Self {
        if crate::meter::charge_cost(crate::charges::diagnostic()).is_err() {
            return Self::null();
        }
        crate::meter::note_op_body();
        bounded(describe(v))
    }
}

/// Cap a description at [`MAX`] bytes.
fn bounded(mut s: String) -> ValueDesc {
    if s.len() > MAX {
        s.truncate(MAX);
    }
    ValueDesc(Some(Arc::from(s.as_str())))
}

macro_rules! desc_scalar {
    ($t:ty, $tag:literal) => {
        impl From<$t> for ValueDesc {
            fn from(v: $t) -> Self {
                if crate::meter::charge_cost(crate::charges::diagnostic()).is_err() {
                    return Self::null();
                }
                crate::meter::note_op_body();
                bounded(format!("{}({})", $tag, v))
            }
        }
    };
}

desc_scalar!(i32, "int");
desc_scalar!(i64, "int");
desc_scalar!(u64, "uint");
desc_scalar!(f64, "double");
desc_scalar!(bool, "bool");

impl From<&str> for ValueDesc {
    fn from(v: &str) -> Self {
        bounded(format!("string(len {})", v.len()))
    }
}

impl From<String> for ValueDesc {
    fn from(v: String) -> Self {
        bounded(format!("string(len {})", v.len()))
    }
}

impl From<chrono::DateTime<chrono::FixedOffset>> for ValueDesc {
    fn from(v: chrono::DateTime<chrono::FixedOffset>) -> Self {
        bounded(format!("timestamp({})", v.to_rfc3339()))
    }
}

impl From<chrono::Duration> for ValueDesc {
    fn from(v: chrono::Duration) -> Self {
        bounded(format!("duration({v:?})"))
    }
}

impl From<Value> for ValueDesc {
    fn from(v: Value) -> Self {
        ValueDesc::from(&v)
    }
}

impl From<&Value> for ValueDesc {
    fn from(v: &Value) -> Self {
        if crate::meter::charge_cost(crate::charges::diagnostic()).is_err() {
            return Self::null();
        }
        crate::meter::note_op_body();
        bounded(describe_value(v))
    }
}

/// Render an owned `Value` without deep-copying it.
fn describe_value(v: &Value) -> String {
    match v {
        Value::List(l) => format!("list(len {})", l.len()),
        Value::Map(m) => format!("map(len {})", m.map.len()),
        Value::Function(_, _) => "function".to_string(),
        Value::Int(i) => format!("int({i})"),
        Value::UInt(u) => format!("uint({u})"),
        Value::Float(f) => format!("double({f})"),
        Value::String(s) => format!("string(len {})", s.len()),
        Value::Bytes(b) => format!("bytes(len {})", b.len()),
        Value::Bool(b) => format!("bool({b})"),
        Value::Duration(_) => "duration".to_string(),
        Value::Timestamp(_) => "timestamp".to_string(),
        Value::Opaque(_) => "opaque".to_string(),
        #[cfg(feature = "structs")]
        Value::Struct(_) => "struct".to_string(),
        Value::Null => "null".to_string(),
    }
}

impl Display for ValueDesc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_deref().unwrap_or("null"))
    }
}

impl Debug for ValueDesc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_deref().unwrap_or("null"))
    }
}

/// Render a value without walking it: scalars print their value, and
/// aggregates print their type and size.
fn describe(v: &dyn Val) -> String {
    let mut s = String::new();
    let _ = match v.get_type().kind() {
        Kind::Boolean => v
            .downcast_ref::<CelBool>()
            .map(|b| write!(s, "bool({})", b.inner()))
            .unwrap_or_else(|| write!(s, "bool")),
        Kind::Int => v
            .downcast_ref::<CelInt>()
            .map(|i| write!(s, "int({})", i.inner()))
            .unwrap_or_else(|| write!(s, "int")),
        Kind::UInt => v
            .downcast_ref::<CelUInt>()
            .map(|u| write!(s, "uint({})", u.inner()))
            .unwrap_or_else(|| write!(s, "uint")),
        Kind::Double => v
            .downcast_ref::<CelDouble>()
            .map(|d| write!(s, "double({})", d.inner()))
            .unwrap_or_else(|| write!(s, "double")),
        Kind::String => v
            .downcast_ref::<CelString>()
            .map(|t| write!(s, "string(len {})", t.inner().len()))
            .unwrap_or_else(|| write!(s, "string")),
        Kind::Bytes => v
            .downcast_ref::<CelBytes>()
            .map(|b| write!(s, "bytes(len {})", b.inner().len()))
            .unwrap_or_else(|| write!(s, "bytes")),
        Kind::List => v
            .downcast_ref::<CelList>()
            .map(|l| write!(s, "list(len {})", l.len()))
            .unwrap_or_else(|| write!(s, "list")),
        Kind::Map => v
            .downcast_ref::<CelMap>()
            .map(|m| write!(s, "map(len {})", m.len()))
            .unwrap_or_else(|| write!(s, "map")),
        Kind::NullType => write!(s, "null"),
        Kind::Duration => write!(s, "duration"),
        Kind::Timestamp => write!(s, "timestamp"),
        other => write!(s, "{other:?}"),
    };
    s
}
