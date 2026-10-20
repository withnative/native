//! Version-specific codecs/adapters. All dispatch lives in the catalogue table.
//! Golden vectors lock these adapters as well as each retained semantic fold.
use super::{relates_to_v1 as v1, relates_to_v2 as v2, relates_to_v3 as v3};
use crate::{
    error::{Error, Result},
    kernel::provider_catalogue::{Decoded, Entry, FoldInput, Folded, ProjectionFacts, StoredState},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
pub(crate) const V3_SOURCE_SHA: &str =
    "20b395c2b26762ddfb86a603cfd0be8fbe04951254baa600bca022312eb922d1";
pub(crate) const V1: Entry = Entry {
    pins: v1::pins,
    package: v1::package,
    source: include_str!("relates_to_v1.rs"),
    source_sha256: "2958fe1ea0d8ee573141de2a87778bb9ea3db6ab381b27ae5fc4249e86a02bc9",
    validate_recorded: crate::kernel::relates_to_port::validate_recorded,
    admit: crate::kernel::relates_to_port::admit_recorded,
    decode: decode_v1,
    fold: fold_v1,
    state_codec: view_v1,
};
pub(crate) const V2: Entry = Entry {
    pins: v2::pins,
    package: v2::package,
    source: include_str!("relates_to_v2.rs"),
    source_sha256: "09989e90e55b8a65987e043cc520e529226b34aae5e6c4b29f693e672a1d95c2",
    validate_recorded: crate::kernel::relates_to_port::validate_recorded,
    admit: crate::kernel::relates_to_port::admit_recorded,
    decode: decode_v2,
    fold: fold_v2,
    state_codec: view_v2,
};
pub(crate) const V3: Entry = Entry {
    pins: v3::pins,
    package: v3::package,
    source: include_str!("relates_to_v3.rs"),
    source_sha256: V3_SOURCE_SHA,
    validate_recorded: crate::kernel::relates_to_port::validate_recorded,
    admit: crate::kernel::relates_to_port::admit_recorded,
    decode: decode_v3,
    fold: fold_v3,
    state_codec: view_v3,
};
/// Relation-only compatibility data; never parsed by shared host infrastructure.
#[derive(Serialize, Deserialize)]
pub(crate) struct RelationDecoded {
    pub request: Value,
    pub command: Value,
    pub assertion_id: String,
    pub recorded_state: Option<Value>,
    pub legacy: bool,
}
pub(crate) fn relation_decoded(decoded: &Decoded) -> Result<RelationDecoded> {
    Ok(serde_json::from_value(decoded.domain.clone())?)
}
pub(crate) fn host_request(domain: &RelationDecoded) -> Result<crate::kernel::ProviderRequest> {
    let mut request: crate::kernel::ProviderRequest =
        serde_json::from_value(domain.request.clone())?;
    if domain.legacy {
        request.request_digest = crate::kernel::relates_to_port::request_checksum(&request)?;
    }
    Ok(request)
}
fn decoded(domain: RelationDecoded) -> Result<Decoded> {
    let request = host_request(&domain)?;
    let (left, right) = v1::pair(&request.anchor.record_id, &request.counterpart.record_id)?;
    let facts = ProjectionFacts {
        pins: request.pins.clone(),
        stream_id: if domain.legacy {
            request.anchor.record_id.clone()
        } else {
            request.aggregate_id.clone()
        },
        aggregate_id: request.aggregate_id.clone(),
        provider_key: v1::RELATIONSHIP.into(),
        subjects: vec![left.into(), right.into()],
        principal: request.principal_id.clone(),
        operation: v1::RELATIONSHIP.into(),
        operation_key: request.operation_key.clone(),
        receipt_id: domain.assertion_id.clone(),
        receipt_request: serde_json::to_value(request)?,
    };
    Ok(Decoded {
        facts,
        domain: serde_json::to_value(domain)?,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    request: Value,
    assertion_id: String,
}
fn decode_v1(payload: &Value) -> Result<Decoded> {
    let mut request = payload.clone();
    let object = request
        .as_object_mut()
        .ok_or_else(|| Error::engine("invalid retained provider request"))?;
    let state = object
        .remove("outcome")
        .ok_or_else(|| Error::engine("missing retained provider outcome"))?;
    let id = object
        .remove("assertion_id")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(|| Error::engine("missing retained assertion ID"))?;
    let command: v1::Command = serde_json::from_value(request["command"].clone())?;
    let original_command = serde_json::to_value(command)?;
    if let Some(sources) = request
        .pointer_mut("/command/Assert/sources")
        .and_then(Value::as_array_mut)
    {
        for source in sources {
            let object = source
                .as_object_mut()
                .ok_or_else(|| Error::engine("invalid retained provenance"))?;
            if let Some(value) = object.remove("author") {
                object.insert("claimed_author".into(), value);
            }
            if let Some(value) = object.remove("timestamp") {
                object.insert("claimed_timestamp".into(), value);
            }
        }
    }
    request["request_digest"] = json!("");
    request["policy_head"] = json!(0);
    decoded(RelationDecoded {
        request,
        command: original_command,
        assertion_id: id,
        recorded_state: Some(state),
        legacy: true,
    })
}
fn decode_v2(payload: &Value) -> Result<Decoded> {
    let e: Envelope = serde_json::from_value(payload.clone())?;
    let c: v2::Command = serde_json::from_value(e.request["command"].clone())?;
    decoded(RelationDecoded {
        request: e.request,
        command: serde_json::to_value(c)?,
        assertion_id: e.assertion_id,
        recorded_state: None,
        legacy: false,
    })
}
fn decode_v3(payload: &Value) -> Result<Decoded> {
    let e: Envelope = serde_json::from_value(payload.clone())?;
    let c: v3::Command = serde_json::from_value(e.request["command"].clone())?;
    decoded(RelationDecoded {
        request: e.request,
        command: serde_json::to_value(c)?,
        assertion_id: e.assertion_id,
        recorded_state: None,
        legacy: false,
    })
}
fn current_view(current: Option<&StoredState>) -> Result<Option<Value>> {
    current.map(StoredState::view).transpose()
}
fn fold_v1(i: &FoldInput<'_>, current: Option<&StoredState>) -> Result<Folded> {
    let domain = relation_decoded(i.decoded)?;
    let previous = current_view(current)?;
    // Translate only relation fields required by /1; do not visit the /3 type.
    let old = previous
        .clone()
        .map(|mut value| -> Result<v1::State> {
            for assertion in value["assertions"]
                .as_array_mut()
                .ok_or_else(|| Error::engine("invalid retained state"))?
            {
                let object = assertion
                    .as_object_mut()
                    .ok_or_else(|| Error::engine("invalid retained assertion"))?;
                for key in [
                    "asserted_by",
                    "asserted_at",
                    "asserted_seq",
                    "retracted_by",
                    "retracted_at",
                    "retracted_seq",
                ] {
                    object.remove(key);
                }
                for source in object
                    .get_mut("sources")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| Error::engine("invalid retained sources"))?
                {
                    let object = source
                        .as_object_mut()
                        .ok_or_else(|| Error::engine("invalid retained source"))?;
                    let author = object.remove("claimed_author").unwrap_or(Value::Null);
                    let timestamp = object
                        .remove("claimed_timestamp")
                        .filter(|v| !v.is_null())
                        .unwrap_or_else(|| json!(""));
                    object.insert("author".into(), author);
                    object.insert("timestamp".into(), timestamp);
                }
            }
            Ok(serde_json::from_value(value)?)
        })
        .transpose()?;
    let command: v1::Command = serde_json::from_value(domain.command.clone())?;
    let folded = v1::prepare(
        &command,
        &i.decoded.facts.subjects[0],
        &i.decoded.facts.subjects[1],
        &domain.assertion_id,
        old.as_ref(),
    )?;
    let state = serde_json::to_value(folded)?;
    if domain.recorded_state.as_ref() != Some(&state) {
        return Err(Error::engine("retained provider outcome mismatch"));
    }
    let mut attribution = serde_json::Map::new();
    for a in state["assertions"]
        .as_array()
        .ok_or_else(|| Error::engine("invalid retained state"))?
    {
        let id = a["id"]
            .as_str()
            .ok_or_else(|| Error::engine("invalid retained assertion"))?;
        let prior = previous
            .as_ref()
            .and_then(|s| s["assertions"].as_array())
            .and_then(|items| items.iter().find(|a| a["id"].as_str() == Some(id)));
        let mut stamp = match prior {
            Some(a) => {
                json!({"asserted_by":a["asserted_by"],"asserted_at":a["asserted_at"],"asserted_seq":a["asserted_seq"],"retracted_by":a["retracted_by"],"retracted_at":a["retracted_at"],"retracted_seq":a["retracted_seq"]})
            }
            None => {
                json!({"asserted_by":i.principal,"asserted_at":i.timestamp,"asserted_seq":i.event_seq,"retracted_by":null,"retracted_at":null,"retracted_seq":null})
            }
        };
        if a["retracted"] == true && prior.is_none_or(|a| a["retracted"] != true) {
            stamp["retracted_by"] = json!(i.principal);
            stamp["retracted_at"] = json!(i.timestamp);
            stamp["retracted_seq"] = json!(i.event_seq);
        }
        attribution.insert(id.into(), stamp);
    }
    Ok(Folded {
        state,
        attribution: Value::Object(attribution),
    })
}
// /1's retained read representation. Kept independent of later semantic types.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1View {
    left: String,
    right: String,
    assertions: Vec<V1ViewAssertion>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1ViewAssertion {
    id: String,
    sources: Vec<V1ViewSource>,
    retracted: bool,
    asserted_by: Option<String>,
    asserted_at: String,
    asserted_seq: i64,
    retracted_by: Option<String>,
    retracted_at: Option<String>,
    retracted_seq: Option<i64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1ViewSource {
    source_id: String,
    from: String,
    to: String,
    claimed_author: Option<String>,
    claimed_timestamp: Option<String>,
    note: Option<String>,
}
fn view_v1(s: &StoredState) -> Result<Value> {
    let old: v1::State = serde_json::from_value(s.state.clone())?;
    let mut value = serde_json::to_value(old)?;
    for a in value["assertions"]
        .as_array_mut()
        .ok_or_else(|| Error::engine("invalid retained state"))?
    {
        let id = a["id"]
            .as_str()
            .ok_or_else(|| Error::engine("invalid retained assertion"))?;
        let stamp = s
            .attribution
            .get(id)
            .and_then(Value::as_object)
            .ok_or_else(|| Error::engine("missing retained host attribution"))?
            .clone();
        a.as_object_mut()
            .ok_or_else(|| Error::engine("invalid retained assertion"))?
            .extend(stamp);
        for source in a["sources"]
            .as_array_mut()
            .ok_or_else(|| Error::engine("invalid retained sources"))?
        {
            let obj = source
                .as_object_mut()
                .ok_or_else(|| Error::engine("invalid retained source"))?;
            if let Some(v) = obj.remove("author") {
                obj.insert("claimed_author".into(), v);
            }
            if let Some(v) = obj.remove("timestamp") {
                obj.insert("claimed_timestamp".into(), v);
            }
        }
    }
    Ok(serde_json::to_value(serde_json::from_value::<V1View>(
        value,
    )?)?)
}
fn fold_v2(i: &FoldInput<'_>, current: Option<&StoredState>) -> Result<Folded> {
    let domain = relation_decoded(i.decoded)?;
    let current: Option<v2::State> = current_view(current)?
        .map(serde_json::from_value)
        .transpose()?;
    let c: v2::Command = serde_json::from_value(domain.command.clone())?;
    let state = v2::fold(
        &c,
        &i.decoded.facts.subjects[0],
        &i.decoded.facts.subjects[1],
        &domain.assertion_id,
        current.as_ref(),
        &v2::HostStamp {
            principal: i.principal.into(),
            timestamp: i.timestamp.into(),
            event_seq: i.event_seq,
        },
    )?;
    Ok(Folded {
        state: serde_json::to_value(state)?,
        attribution: Value::Null,
    })
}
fn view_v2(s: &StoredState) -> Result<Value> {
    Ok(serde_json::to_value(serde_json::from_value::<v2::State>(
        s.state.clone(),
    )?)?)
}
fn fold_v3(i: &FoldInput<'_>, current: Option<&StoredState>) -> Result<Folded> {
    let domain = relation_decoded(i.decoded)?;
    let current: Option<v3::State> = current_view(current)?
        .map(serde_json::from_value)
        .transpose()?;
    let c: v3::Command = serde_json::from_value(domain.command.clone())?;
    let state = v3::fold(
        &c,
        &i.decoded.facts.subjects[0],
        &i.decoded.facts.subjects[1],
        &domain.assertion_id,
        current.as_ref(),
        &v3::HostStamp {
            principal: i.principal.into(),
            timestamp: i.timestamp.into(),
            event_seq: i.event_seq,
        },
    )?;
    Ok(Folded {
        state: serde_json::to_value(state)?,
        attribution: Value::Null,
    })
}
fn view_v3(s: &StoredState) -> Result<Value> {
    Ok(serde_json::to_value(serde_json::from_value::<v3::State>(
        s.state.clone(),
    )?)?)
}
