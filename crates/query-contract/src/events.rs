//! Payload-free content-log invalidation contract.

use serde::Serialize;

/// Public invalidation envelope. Stored payload, actor and run annotations are
/// intentionally not representable here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ContentInvalidation {
    pub local_seq: i64,
    pub id: String,
    pub record_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_invalidation_serializes_with_the_pinned_field_set() {
        let value = serde_json::to_value(ContentInvalidation {
            local_seq: 7,
            id: "evt-1".into(),
            record_id: "rec-1".into(),
            event_type: "record.updated".into(),
            created_at: "2026-08-12T00:00:00Z".into(),
        })
        .unwrap();
        let object = value.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["created_at", "id", "local_seq", "record_id", "type"]);
        assert_eq!(object["type"], "record.updated");
    }
}
