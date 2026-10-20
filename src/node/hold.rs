//! Which writes the node may take over while hosted cannot take them, and
//! what it says to the caller when it does (slice 2B).
//!
//! The node holds a write only when all of these are true: the operation is
//! on [`HOLDABLE`], it is keyed (so sending it again later is safe), and hosted
//! either answered `DEPLOYMENT_READ_ONLY` or was confirmed unreachable. The
//! caller then gets `accepted_pending` with everything needed to refer to the
//! write while it waits: its key, and for a create the record's ID.
//!
//! # Node-chosen record IDs
//!
//! A create without an `id` gets one from the node, *before the first send*.
//! Doing it any later would change the arguments, and the engine refuses the
//! same key with changed arguments. The ID is derived from the call's key and
//! content, so a repeat of the call (same key) rebuilds the same arguments
//! with nothing stored, even after the journal entry has been pruned. It is a
//! UUIDv4-shaped value; the key is random unless the caller chose it, and the
//! node serves one workspace, so there is nothing for it to collide with.
use super::journal::{Entry, HoldReason};
use super::*;
use sha2::{Digest, Sha256};

/// The writes the node may hold: creates, links, text attachments, and
/// appends to a record's body. `update_record` qualifies only when its sole
/// change is `body_append` (see [`is_holdable`]). Each must accept
/// `idempotency_key` in its contract; a test checks that against the engine's
/// own contracts. Everything else keeps slice 2A's behaviour.
pub(super) const HOLDABLE: [(&str, &str); 5] = [
    ("records_write", "create_record"),
    ("records_write", "create_many"),
    ("records_write", "manage_links.add"),
    ("records_write", "attach_text"),
    ("records_write", "update_record"),
];

/// What the node worked out about a held write from its arguments.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Plan {
    pub(super) title: Option<String>,
    /// The record a create makes, or the one an append, link or attachment
    /// targets.
    pub(super) record_id: Option<String>,
    /// Every record a `create_many` makes.
    pub(super) record_ids: Vec<String>,
}

pub(super) fn creates(operation: &str) -> bool {
    matches!(operation, "create_record" | "create_many")
}

/// Whether this call's operation and shape are eligible to be held. The gate
/// must also establish matching cached hosted/local contracts and validate the
/// original and prepared call when it decides to hold. Online admission stays
/// with hosted.
pub(super) fn is_holdable(executor: &str, operation: &str, arguments: &Value) -> bool {
    if !HOLDABLE.contains(&(executor, operation)) {
        return false;
    }
    let Some(arguments) = arguments.as_object() else {
        return false;
    };
    if operation != "update_record" {
        return true;
    }
    // Only an append to one record. A guard (`if_body_digest` and friends)
    // would be judged against a record that has moved on by the time it is
    // sent, and every other field is an edit, not an addition.
    const APPEND_ONLY: [&str; 7] = [
        "id",
        "record_id",
        "reason",
        "sources",
        "body_append",
        "idempotency_key",
        "response_mode",
    ];
    arguments
        .keys()
        .all(|key| APPEND_ONLY.contains(&key.as_str()))
        && arguments
            .get("body_append")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty())
        && ["id", "record_id"]
            .iter()
            .any(|field| arguments.get(*field).is_some_and(Value::is_string))
}

/// SHA-256 of the arguments with every object's keys sorted, so the same
/// call hashes the same however the caller ordered its fields. `response_mode`
/// is left out, as the engine leaves it out of its own digest
/// (`provenance.rs`): it changes how the answer is shown, not what is asked, so
/// a repeat that only changes it is still the same call.
pub(super) fn intent_digest(arguments: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                Value::Object(
                    keys.into_iter()
                        .map(|k| (k.clone(), sorted(&map[k])))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    let mut asked = arguments.clone();
    if let Some(object) = asked.as_object_mut() {
        object.remove("response_mode");
    }
    hex::encode(Sha256::digest(sorted(&asked).to_string().as_bytes()))
}

fn derived_id(key: &str, intent: &str, index: usize) -> String {
    let mut hash = Sha256::new();
    hash.update(b"native-node/record-id/v1\0");
    hash.update(key.as_bytes());
    hash.update([0]);
    hash.update(intent.as_bytes());
    hash.update([0]);
    hash.update((index as u64).to_be_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.finalize()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Give a create the IDs the caller left out, and read the title and record
/// from the arguments. `intent` is [`intent_digest`] of the arguments as the
/// caller sent them, key included, taken before this runs.
pub(super) fn prepare(operation: &str, arguments: &mut Value, key: &str, intent: &str) -> Plan {
    let Some(object) = arguments.as_object_mut() else {
        return Plan::default();
    };
    match operation {
        "create_record" => {
            let id = match text(object.get("id")) {
                Some(id) => id,
                None => {
                    let id = derived_id(key, intent, 0);
                    object.insert("id".into(), json!(id));
                    id
                }
            };
            Plan {
                title: text(object.get("name")),
                record_id: Some(id),
                record_ids: Vec::new(),
            }
        }
        "create_many" => {
            let mut ids = Vec::new();
            let mut first_name = None;
            let mut count = 0usize;
            if let Some(records) = object.get_mut("records").and_then(Value::as_array_mut) {
                count = records.len();
                for (index, record) in records.iter_mut().enumerate() {
                    let Some(record) = record.as_object_mut() else {
                        continue;
                    };
                    let id = match text(record.get("id")) {
                        Some(id) => id,
                        None => {
                            let id = derived_id(key, intent, index);
                            record.insert("id".into(), json!(id));
                            id
                        }
                    };
                    ids.push(id);
                    if first_name.is_none() {
                        first_name = text(record.get("name"));
                    }
                }
            }
            let title = first_name.map(|name| match count {
                0 | 1 => name,
                n => format!("{name} (+{} more)", n - 1),
            });
            Plan {
                title,
                record_id: None,
                record_ids: ids,
            }
        }
        "attach_text" => Plan {
            title: text(object.get("name")).or_else(|| text(object.get("filename"))),
            record_id: text(object.get("record_id"))
                .or_else(|| text(object.get("id")))
                .or_else(|| {
                    object
                        .get("ids")
                        .and_then(Value::as_array)
                        .and_then(|ids| ids.first())
                        .and_then(|id| text(Some(id)))
                }),
            record_ids: Vec::new(),
        },
        "update_record" => Plan {
            title: None,
            record_id: text(object.get("id")).or_else(|| text(object.get("record_id"))),
            record_ids: Vec::new(),
        },
        "manage_links.add" => Plan {
            title: None,
            record_id: text(object.get("source_id")),
            record_ids: Vec::new(),
        },
        _ => Plan::default(),
    }
}

/// The record IDs a write refers to, read only from the fields that hold
/// references. Free text (bodies, titles, reasons) never counts: a note that
/// happens to contain an ID is not a dependency on that record.
pub(super) fn references(operation: &str, arguments: &Value) -> Vec<String> {
    fn push(into: &mut Vec<String>, value: Option<&Value>) {
        if let Some(id) = text(value) {
            into.push(id);
        }
    }
    fn link_targets(into: &mut Vec<String>, record: &Value) {
        push(into, record.get("home_id"));
        for link in record
            .get("links")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            push(into, link.get("target_id"));
        }
    }
    let mut found = Vec::new();
    match operation {
        "update_record" => {
            push(&mut found, arguments.get("id"));
            push(&mut found, arguments.get("record_id"));
        }
        "manage_links.add" => {
            push(&mut found, arguments.get("source_id"));
            push(&mut found, arguments.get("target_id"));
        }
        "attach_text" => {
            push(&mut found, arguments.get("id"));
            push(&mut found, arguments.get("record_id"));
            for id in arguments
                .get("ids")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                push(&mut found, Some(id));
            }
        }
        "create_record" => link_targets(&mut found, arguments),
        "create_many" => {
            for record in arguments
                .get("records")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                link_targets(&mut found, record);
            }
        }
        _ => {}
    }
    found
}

/// Whether hosted's reply is the `DEPLOYMENT_READ_ONLY` refusal, in any of the
/// shapes it arrives in: an `isError` tool result, a framed error, or an HTTP
/// error body the node framed with the original under `upstream_body`.
pub(super) fn is_deployment_read_only(reply: &str) -> bool {
    const CODE: &str = "DEPLOYMENT_READ_ONLY";
    let Ok(reply) = serde_json::from_str::<Value>(reply) else {
        return false;
    };
    let is = |pointer: &str| reply.pointer(pointer).and_then(Value::as_str) == Some(CODE);
    // An engine refusal says `applied: false`; anything else is not this one.
    let applied_false = |pointer: &str| {
        reply
            .pointer(pointer)
            .is_none_or(|applied| applied == &Value::Bool(false))
    };
    (is("/result/structuredContent/error_code")
        && applied_false("/result/structuredContent/applied"))
        || (is("/error/data/error_code") && applied_false("/error/data/applied"))
        || (is("/error/data/code") && applied_false("/error/data/applied"))
        || (is("/error/data/upstream_body/error_code")
            && applied_false("/error/data/upstream_body/applied"))
        || (is("/error/data/upstream_body/error/code")
            && applied_false("/error/data/upstream_body/applied"))
        || (is("/error/data/upstream_body/code")
            && applied_false("/error/data/upstream_body/applied"))
}

/// The one reply for a write the node holds: the first time, and again for
/// every repeat of the call while it is still waiting.
pub(super) fn pending_reply(
    id: Option<&Value>,
    entry: &Entry,
    position: usize,
    modern: bool,
) -> Option<String> {
    let reason = entry.hold_reason.unwrap_or(HoldReason::Other);
    let key = entry.idempotency_key.as_deref().unwrap_or_default();
    let why = match reason {
        HoldReason::DeploymentReadOnly => "hosted is read-only for a deployment",
        HoldReason::HostedUnreachable => "hosted is unreachable",
        HoldReason::Other => "hosted cannot take writes",
    };
    let mut info = json!({
        "outcome": "accepted_pending",
        "idempotency_key": key,
        "key_origin": entry.key_origin,
        "reason": reason.as_str(),
        "may_already_be_applied": entry.maybe_applied,
        "queue_position": position,
        "journal_entry": entry.id,
        "accepted_at": entry.received_at,
        "how_to_check": format!(
            "Repeat this exact call with idempotency_key={key}. It returns 'pending' while the write waits, then the original receipt or the refusal."
        ),
        "attribution_note": "A held write commits under the run's intent at the time it is sent, so its attribution can differ slightly from the intent at the time of this call.",
    });
    let object = info.as_object_mut().expect("object");
    if creates(&entry.operation) {
        if let Some(record) = &entry.record_id {
            object.insert("record_id".into(), json!(record));
        }
        if !entry.record_ids.is_empty() {
            object.insert("record_ids".into(), json!(entry.record_ids));
        }
    } else if let Some(record) = &entry.record_id {
        object.insert("target_record_id".into(), json!(record));
    }
    let mut lines = vec![format!(
        "Accepted, not yet applied: {why}, so the node is holding this write and will send it when hosted can take it (position {position} in the queue)."
    )];
    if entry.maybe_applied {
        lines.push("It may already have been applied: an earlier attempt was in flight when hosted stopped answering. Sending it again with its key settles that either way.".into());
    }
    if let Some(record) = &entry.record_id {
        if creates(&entry.operation) {
            lines.push(format!("Record ID: {record}"));
        }
    }
    for record in &entry.record_ids {
        lines.push(format!("Record ID: {record}"));
    }
    lines.push(format!(
        "To check: repeat the same call with idempotency_key={key}. It returns 'pending' while the write waits, then the original receipt or the refusal."
    ));
    lines.push("It commits under the run's intent at the time it is sent, which can differ slightly from the intent now.".into());
    super::tool_reply(
        id,
        json!({
            "content":[{"type":"text","text":lines.join("\n")}],
            "structuredContent":info,
            "isError":false,
        }),
        modern,
    )
}

/// A repeat of a held call whose content differs from the held write.
pub(super) fn conflict_reply(id: Option<&Value>, entry: &Entry) -> Option<String> {
    frame_error(
        id,
        "This idempotency_key already holds a different write, still waiting to be sent; this call was not sent",
        json!({
            "outcome": "not_sent",
            "reason": "idempotency_conflict",
            "idempotency_key": entry.idempotency_key,
            "journal_entry": entry.id,
        }),
    )
}

#[cfg(test)]
mod tests;
