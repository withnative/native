//! Conditional `render_artifact` revalidation. Content-free: port names only.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

#[derive(Clone, Debug)]
pub(crate) struct RevalidateRequest {
    pub artifact_id: String,
    pub snapshot_event_id: String,
    pub snapshot_event_seq: i64,
    pub authorization_revision: i64,
    pub cache_key: String,
    pub caller_sha256: String,
    pub meta_sha256: String,
    pub ports: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RevalidateMiss {
    Malformed,
    Artifact,
    Head,
    Authorization,
    CacheKey,
    Caller,
    Meta,
    RelationPort,
}

impl RevalidateMiss {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Artifact => "artifact",
            Self::Head => "head",
            Self::Authorization => "authorization",
            Self::CacheKey => "cache_key",
            Self::Caller => "caller",
            Self::Meta => "meta",
            Self::RelationPort => "relation_port",
        }
    }
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, RevalidateMiss> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(RevalidateMiss::Malformed)
        .map(str::to_owned)
}

pub(crate) fn parse_revalidate(value: &Value) -> Result<RevalidateRequest, RevalidateMiss> {
    let object = value.as_object().ok_or(RevalidateMiss::Malformed)?;
    let artifact_id = required_string(object, "artifact_id")?;
    let snapshot_event_id = required_string(object, "snapshot_event_id")?;
    let snapshot_event_seq = object
        .get("snapshot_event_seq")
        .and_then(Value::as_i64)
        .ok_or(RevalidateMiss::Malformed)?;
    let authorization_revision = object
        .get("authorization_revision")
        .and_then(Value::as_i64)
        .ok_or(RevalidateMiss::Malformed)?;
    let cache_key = required_string(object, "cache_key")?;
    let caller_sha256 = required_string(object, "caller_sha256")?;
    let meta_sha256 = required_string(object, "meta_sha256")?;
    let ports_object = object
        .get("ports")
        .and_then(Value::as_object)
        .ok_or(RevalidateMiss::Malformed)?;
    let mut ports = BTreeMap::new();
    for (name, port) in ports_object {
        if name.is_empty() || !port.is_object() {
            return Err(RevalidateMiss::Malformed);
        }
        ports.insert(name.clone(), port.clone());
    }
    Ok(RevalidateRequest {
        artifact_id,
        snapshot_event_id,
        snapshot_event_seq,
        authorization_revision,
        cache_key,
        caller_sha256,
        meta_sha256,
        ports,
    })
}

pub(crate) fn port_rows_sha256(port: &Value) -> Option<&str> {
    port.get("rows_sha256").and_then(Value::as_str)
}

pub(crate) fn port_schema_sha256(port: &Value) -> Option<&str> {
    port.get("schema_sha256").and_then(Value::as_str)
}

/// Live identity the client token is compared against. Same fields as
/// `plan.provenance.revalidation`.
pub(crate) struct LiveRevalidateIdentity<'a> {
    pub artifact_id: &'a str,
    pub snapshot_event_id: &'a str,
    pub snapshot_event_seq: i64,
    pub authorization_revision: i64,
    pub cache_key: &'a str,
    pub caller_sha256: &'a str,
    pub meta_sha256: &'a str,
}

pub(crate) fn evaluate(
    request: &RevalidateRequest,
    live: &LiveRevalidateIdentity<'_>,
    expected_ports: &BTreeSet<String>,
) -> Result<(), RevalidateMiss> {
    if request.artifact_id != live.artifact_id {
        return Err(RevalidateMiss::Artifact);
    }
    if request.snapshot_event_id != live.snapshot_event_id
        || request.snapshot_event_seq != live.snapshot_event_seq
    {
        return Err(RevalidateMiss::Head);
    }
    if request.authorization_revision != live.authorization_revision {
        return Err(RevalidateMiss::Authorization);
    }
    if request.cache_key != live.cache_key {
        return Err(RevalidateMiss::CacheKey);
    }
    if request.caller_sha256 != live.caller_sha256 {
        return Err(RevalidateMiss::Caller);
    }
    if request.meta_sha256 != live.meta_sha256 {
        return Err(RevalidateMiss::Meta);
    }
    let got: BTreeSet<String> = request.ports.keys().cloned().collect();
    if got != *expected_ports {
        return Err(RevalidateMiss::Malformed);
    }
    Ok(())
}

pub(crate) fn relation_hashes_match(
    envelope: &Value,
    client_port: &Value,
) -> Result<(), RevalidateMiss> {
    let rows = envelope
        .pointer("/relation/rows_sha256")
        .and_then(Value::as_str)
        .ok_or(RevalidateMiss::Malformed)?;
    let schema = envelope
        .pointer("/relation/schema_sha256")
        .and_then(Value::as_str)
        .ok_or(RevalidateMiss::Malformed)?;
    let client_rows = port_rows_sha256(client_port).ok_or(RevalidateMiss::Malformed)?;
    let client_schema = port_schema_sha256(client_port).ok_or(RevalidateMiss::Malformed)?;
    if rows != client_rows || schema != client_schema {
        return Err(RevalidateMiss::RelationPort);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_request() -> RevalidateRequest {
        parse_revalidate(&json!({
            "artifact_id": "artifact-a",
            "snapshot_event_id": "event-1",
            "snapshot_event_seq": 1,
            "authorization_revision": 1,
            "cache_key": "cache",
            "caller_sha256": "caller",
            "meta_sha256": "meta",
            "ports": { "items": { "sha256": "abc" } },
            "future_field": "ignored",
        }))
        .expect("extra keys are ignored")
    }

    #[test]
    fn extra_keys_are_not_malformed() {
        let request = valid_request();
        assert_eq!(request.artifact_id, "artifact-a");
        let expected = BTreeSet::from(["items".to_owned()]);
        evaluate(
            &request,
            &LiveRevalidateIdentity {
                artifact_id: "artifact-a",
                snapshot_event_id: "event-1",
                snapshot_event_seq: 1,
                authorization_revision: 1,
                cache_key: "cache",
                caller_sha256: "caller",
                meta_sha256: "meta",
            },
            &expected,
        )
        .expect("known fields still match");
    }

    #[test]
    fn artifact_mismatch_is_artifact_not_malformed() {
        let request = valid_request();
        let expected = BTreeSet::from(["items".to_owned()]);
        assert_eq!(
            evaluate(
                &request,
                &LiveRevalidateIdentity {
                    artifact_id: "artifact-b",
                    snapshot_event_id: "event-1",
                    snapshot_event_seq: 1,
                    authorization_revision: 1,
                    cache_key: "cache",
                    caller_sha256: "caller",
                    meta_sha256: "meta",
                },
                &expected,
            ),
            Err(RevalidateMiss::Artifact)
        );
    }
}
