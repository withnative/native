use crate::runtime::{Failure, Phase, Stop};
use native_package_cel_wire::{Report, Request, ABI, MAX_REQUEST};

use serde_json::Value;
use std::io::Write;

pub(crate) struct BoundedBytes {
    pub bytes: Vec<u8>,
    cap: usize,
}
impl BoundedBytes {
    pub fn new(cap: usize) -> Self {
        Self {
            bytes: Vec::new(),
            cap,
        }
    }
}
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > self.cap)
        {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode(request: &Request) -> Result<Vec<u8>, Failure> {
    // Native shape/byte transport checks only. Raw source is interpreted in the guest.
    // These are transport/byte restrictions, not CEL parsing or checking.
    if request.declaration().shape().is_err() {
        return Err(Failure::new(Phase::Encode, Stop::Input));
    }
    let mut out = BoundedBytes::new(MAX_REQUEST);
    serde_json::to_writer(&mut out, request)
        .map_err(|_| Failure::new(Phase::Encode, Stop::Input))?;
    Ok(out.bytes)
}
pub(crate) fn span(
    ptr: u32,
    len: usize,
    size: usize,
    cap: usize,
) -> Result<std::ops::Range<usize>, Failure> {
    if len == 0 || len > cap {
        return Err(Failure::new(Phase::Decode, Stop::Length));
    }
    let start = ptr as usize;
    let end = start
        .checked_add(len)
        .filter(|end| *end <= size)
        .ok_or(Failure::new(Phase::Decode, Stop::Pointer))?;
    Ok(start..end)
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Report, Failure> {
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::new(Phase::Decode, Stop::Utf8))?;
    let r: Report =
        serde_json::from_str(text).map_err(|_| Failure::new(Phase::Decode, Stop::Json))?;
    let safe = 9_007_199_254_740_991_f64;
    let scalar = match &r.value {
        Value::Null | Value::Bool(_) => true,
        Value::Number(n) => n.as_f64().is_some_and(|f| f.is_finite() && f.abs() <= safe),
        Value::String(s) => s.len() <= 1024,
        _ => false,
    };
    if !scalar {
        return Err(Failure::new(Phase::Decode, Stop::ReportScalar));
    }
    let stages = [
        "request",
        "source",
        "declarations",
        "check",
        "profile",
        "bindings",
        "evaluate",
        "result",
    ];
    let coherent = match r.error_stage.as_deref() {
        None => {
            r.check_ok
                && match r.mode {
                    native_package_cel_wire::Mode::Check => {
                        r.eval_policy.is_none() && r.value.is_null()
                    }
                    native_package_cel_wire::Mode::Evaluate => r.eval_policy.is_some(),
                }
        }
        Some("request" | "source" | "declarations" | "check" | "profile") => {
            !r.check_ok && r.eval_policy.is_none()
        }
        Some("bindings") => r.check_ok && r.eval_policy.is_none(),
        Some("evaluate" | "result") => r.check_ok && r.eval_policy.is_some(),
        _ => false,
    };
    if !coherent
        || (r.mode == native_package_cel_wire::Mode::Check
            && matches!(
                r.error_stage.as_deref(),
                Some("source" | "bindings" | "evaluate" | "result")
            ))
        || r.abi != ABI
        || r.check_policy != "cel-subset@1/p1"
        || !r.check_interim
        || r.eval_policy
            .as_deref()
            .is_some_and(|p| p != "cel-subset@1/p1")
        || r.eval_interim.is_some_and(|v| !v)
        || r.eval_policy.is_some() != r.eval_interim.is_some()
        || r.error.is_some() != r.error_stage.is_some()
        || r.error_stage
            .as_deref()
            .is_some_and(|s| !stages.contains(&s))
        || r.error.as_ref().is_some_and(|s| s.chars().count() > 512)
        || (r.error.is_some() && !r.value.is_null())
        || (r.mode == native_package_cel_wire::Mode::Check
            && (r.eval_policy.is_some() || !r.value.is_null()))
    {
        return Err(Failure::new(Phase::Decode, Stop::ReportMetadata));
    }
    Ok(r)
}
