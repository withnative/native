//! Claims /1 owns its decoder, fold and codec independently of future versions.
use super::claims_v1 as v1;
use crate::error::{Error, Result};
use crate::kernel::{
    claims_port::Outcome,
    provider_catalogue::{Decoded, Entry, FoldInput, Folded, ProjectionFacts, StoredState},
};
use serde_json::Value;
pub(crate) const SOURCE_SHA: &str =
    "f553cc709f794242b6b48732ec1683220b79aeb6d2f5e1f3cdef95e270a43fb9";
pub(crate) const V1: Entry = Entry {
    pins: v1::pins,
    package: v1::package,
    source: include_str!("claims_v1.rs"),
    source_sha256: SOURCE_SHA,
    validate_recorded: crate::kernel::claims_port::validate_recorded,
    admit: crate::kernel::claims_port::admit_recorded,
    decode,
    fold,
    state_codec: view,
};
fn decode(payload: &Value) -> Result<Decoded> {
    let o: Outcome = serde_json::from_value(payload.clone())?;
    let r = &o.request;
    Ok(Decoded {
        facts: ProjectionFacts {
            pins: r.pins.clone(),
            stream_id: r.aggregate_id.clone(),
            aggregate_id: r.aggregate_id.clone(),
            provider_key: v1::PROVIDER_KEY.into(),
            subjects: vec![r.target.record_id.clone()],
            principal: r.principal_id.clone(),
            operation: r.command.operation().into(),
            operation_key: r.operation_key.clone(),
            receipt_id: o.receipt_id.clone(),
            receipt_request: serde_json::to_value(r)?,
        },
        domain: serde_json::to_value(o)?,
    })
}
fn fold(i: &FoldInput<'_>, current: Option<&StoredState>) -> Result<Folded> {
    let o: Outcome = serde_json::from_value(i.decoded.domain.clone())?;
    let previous: Option<v1::State> = current
        .map(|s| s.view().and_then(|v| Ok(serde_json::from_value(v)?)))
        .transpose()?;
    let state = v1::fold(
        &o.request.command,
        &o.request.target.record_id,
        previous.as_ref(),
        &v1::HostStamp {
            principal: i.principal,
            run_id: &o.request.run.run_id,
            receipt_id: &o.receipt_id,
            timestamp: i.timestamp,
            seq: i.event_seq,
            head: o.request.expected_head,
        },
    )?
    .ok_or_else(|| Error::engine("no-op claims must not append"))?;
    Ok(Folded {
        state: serde_json::to_value(state)?,
        attribution: Value::Null,
    })
}
fn view(s: &StoredState) -> Result<Value> {
    Ok(serde_json::to_value(serde_json::from_value::<v1::State>(
        s.state.clone(),
    )?)?)
}
