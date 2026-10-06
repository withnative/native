//! Separate native load accounts. Guest decode and allocator proof remain PR 2.
use crate::common::types::{
    CelBool, CelDouble, CelInt, CelList, CelMap, CelMapKey, CelNull, CelString,
};
use crate::common::value::Val;
use crate::objects::{Key, Value};
use crate::{charges, meter, ExecutionError};

/// A phase on the pool worker; evaluation starts with fresh counters afterwards.
pub(crate) fn account<T>(budget: meter::Budget, body: impl FnOnce() -> T) -> (T, charges::Cost) {
    struct Restore(Option<meter::Budget>);
    impl Drop for Restore {
        fn drop(&mut self) {
            meter::clear();
            if let Some(b) = self.0 {
                meter::install(b);
            }
        }
    }
    let _restore = Restore(meter::install(budget));
    let result = body();
    let cost = meter::totals().unwrap_or(charges::Cost::ZERO);
    (result, cost)
}

/// Caller has validated the scalar-row snapshot (max recursive depth three).
/// Counts cached metrics, not compact JSON bytes. Keys contribute payload and
/// scalar construction; Context names are separately charged by the caller.
pub(crate) fn metrics(v: &Value) -> (u64, u64) {
    match v {
        Value::String(s) => (1, s.len() as u64),
        Value::List(rows) => rows.iter().fold((1, 0), |(n, b), r| {
            let (rn, rb) = metrics(r);
            (n + rn, b + charges::LIST_ELEM_BYTES + rb)
        }),
        Value::Map(row) => row.map.iter().fold((1, 0), |(n, b), (k, v)| {
            let kb = match k {
                Key::String(k) => k.len() as u64,
                _ => 8,
            };
            let (vn, vb) = metrics(v);
            (n + vn, b + charges::MAP_ENTRY_BYTES + kb + vb)
        }),
        _ => (1, 8),
    }
}

/// Borrow the validated shallow Value, constructing only the final native
/// representation. No intermediate clone of the input list/map is made.
pub(crate) fn convert(v: &Value) -> Result<Box<dyn Val>, ExecutionError> {
    Ok(match v {
        Value::Null => Box::new(CelNull),
        Value::Bool(x) => Box::new(CelBool::from(*x)),
        Value::Int(x) => Box::new(CelInt::from(*x)),
        Value::Float(x) => Box::new(CelDouble::from(*x)),
        Value::String(s) => Box::new(CelString::from(s.as_str())),
        Value::List(rows) => Box::new(CelList::from(
            rows.iter().map(convert).collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Map(row) => {
            let mut out = indexmap::IndexMap::with_capacity(row.map.len());
            for (key, value) in row.map.iter() {
                let Key::String(key) = key else {
                    return Err(ExecutionError::NoSuchOverload);
                };
                out.insert(
                    CelMapKey::String(CelString::from(key.as_str())),
                    convert(value)?,
                );
            }
            Box::new(CelMap::from(out))
        }
        _ => return Err(ExecutionError::NoSuchOverload),
    })
}
