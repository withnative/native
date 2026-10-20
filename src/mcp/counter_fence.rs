//! The one definition of "counter-bearing" for responses that must not carry
//! workspace-wide counters to a non-owner (design 08b4c21 §4 S1).
//!
//! Non-owners may learn the *timing* of activity they cannot see, but not its
//! count, identity or content. A counter is any field whose value is a
//! position in, or a head of, the workspace-wide log. This module names those
//! fields once, so the three places that care cannot drift apart:
//!
//! - the member-copy scrub (`member_serving::scrub_member_response`), which
//!   removes them at the envelope's known positions;
//! - the member-copy fence test's verdict walker, which asserts none remain;
//! - the deny-by-default non-owner guard (`tests/tools/counter_guard.rs`),
//!   which walks every tool response for a non-owner.
//!
//! The predicates here are for *metadata positions*. Authored body, name,
//! summary and facet text ships verbatim, so a caller must only walk values it
//! knows hold no authored strings (the guard's fixture authors none that match)
//! or apply [`remove_counter_keys`] to a known metadata object.

use serde_json::{Map, Value};

/// Exact key names that always carry a counter.
pub const COUNTER_KEYS: &[&str] = &[
    "act",
    "acts",
    "head_act",
    "frontier",
    "causal_frontier",
    "seq",
    "heads",
    "event_heads",
    "content_head",
    // The raw authorization counter, which `get_workspace_snapshot` returns to
    // members today and S8 replaces with a random `epoch_id`.
    "authorization_epoch",
];

/// Key suffixes that mark a counter (`as_of_seq`, `local_seq`, `event_seq`,
/// `content_head_seq`, `previous_seq`, ...).
pub const COUNTER_KEY_SUFFIXES: &[&str] = &["_seq"];

/// Key prefixes that mark a counter (`authorization_revision`,
/// `authorization_revision_epoch`).
pub const COUNTER_KEY_PREFIXES: &[&str] = &["authorization_revision"];

/// Whether `key` (with its `value`) is a counter-bearing field.
///
/// `acts` is the one value-sensitive key: the verdict envelope serialises an
/// absent act list as `null`, which carries no counter.
pub fn is_counter_key(key: &str, value: &Value) -> bool {
    if key == "acts" {
        return !value.is_null();
    }
    COUNTER_KEYS.contains(&key)
        || COUNTER_KEY_SUFFIXES
            .iter()
            .any(|suffix| key.ends_with(suffix))
        || COUNTER_KEY_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

/// Whether a string value is a counter-shaped token: `rec:<n>`, `obs:<n>`,
/// `canvas:<n>` (a version or position by number), or a `schema-state-v1:`
/// revision, which embeds the meta and content heads.
pub fn is_counter_value(text: &str) -> bool {
    if text.starts_with("schema-state-v1:") {
        return true;
    }
    ["rec:", "obs:", "canvas:"].iter().any(|prefix| {
        text.strip_prefix(prefix)
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Remove every counter-bearing key from one metadata object (not recursive).
pub fn remove_counter_keys(object: &mut Map<String, Value>) {
    object.retain(|key, value| !is_counter_key(key, value));
}

/// Withhold the engine's `act` / `acts` receipt metadata from one outward tool
/// result (design 08b4c21 §4 S2a). The caller must be a non-owner
/// ([`Caller::counter_footing`](super::registry::Caller::counter_footing)); an
/// owner's result is never passed here.
///
/// This is the single outward decision for act counters, applied by the
/// `ToolRegistry` once per call after the handler, request lifecycle and every
/// late registry decoration have composed the result. Handlers and the
/// internal composition helpers (`echo_act`, `create_many`'s act collection,
/// `committed_creation`'s hoist) keep the act until then.
///
/// It names the engine's receipt metadata positions and nothing else:
///
/// - the top-level `act` / `acts` of any tool result (every `echo_act` site,
///   the direct act inserts, keyed replays and `create_many`'s compact
///   `acts[]`);
/// - `create_many` verbose `results[].record`, the per-item create receipt the
///   tool wraps;
/// - `invoke_artifact_interaction` `refresh.record`, the create receipt a
///   committed creation nests.
///
/// It never searches by key: a caller-authored `body`, `name`, facet value or
/// `metadata` object that happens to contain `act` or `acts` is not at one of
/// these positions and is returned unchanged.
pub(crate) fn withhold_receipt_acts(tool: &str, structured: &mut Value) {
    let Some(object) = structured.as_object_mut() else {
        return;
    };
    object.remove("act");
    object.remove("acts");
    match tool {
        "create_many" => {
            if let Some(results) = object.get_mut("results").and_then(Value::as_array_mut) {
                for item in results {
                    if let Some(record) = item.get_mut("record").and_then(Value::as_object_mut) {
                        record.remove("act");
                    }
                }
            }
        }
        "invoke_artifact_interaction" => {
            if let Some(record) = object
                .get_mut("refresh")
                .and_then(|refresh| refresh.get_mut("record"))
                .and_then(Value::as_object_mut)
            {
                record.remove("act");
            }
        }
        _ => {}
    }
}

/// Whether the decimal `head` appears in `text` as a whole token, for error text
/// that must not name the workspace head.
///
/// A token boundary is any non-ASCII-alphanumeric byte. Treating letters as
/// continuations too is what stops an isolated decimal inside a hex UUID, such
/// as the `27` in `a27b`, from reading as the workspace head.
pub fn text_names_head(text: &str, head: i64) -> bool {
    let needle = head.to_string();
    let bytes = text.as_bytes();
    text.match_indices(&needle).any(|(start, _)| {
        let end = start + needle.len();
        let before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        before && after
    })
}

/// Why a position in a response is a counter hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterHitKind {
    /// A banned key.
    Key,
    /// A counter-shaped string value under a non-banned key.
    Value,
}

/// One counter found in a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterHit {
    /// Normalised JSON path: `$` is the response, `.key` descends an object and
    /// `[]` any array element, so two rows of one array share a path.
    pub path: String,
    pub kind: CounterHitKind,
}

/// Every counter in `value`, one hit per banned key and per counter-shaped
/// string, in document order. A banned key's subtree is not descended into: it
/// is removed as a whole, so what it contains is not a separate leak.
pub fn find_counters(value: &Value) -> Vec<CounterHit> {
    let mut hits = Vec::new();
    walk(value, "$", &mut hits);
    hits
}

fn walk(value: &Value, path: &str, hits: &mut Vec<CounterHit>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if is_counter_key(key, child) {
                    hits.push(CounterHit {
                        path: child_path,
                        kind: CounterHitKind::Key,
                    });
                } else {
                    walk(child, &child_path, hits);
                }
            }
        }
        Value::Array(items) => {
            let child_path = format!("{path}[]");
            for child in items {
                walk(child, &child_path, hits);
            }
        }
        Value::String(text) if is_counter_value(text) => hits.push(CounterHit {
            path: path.to_string(),
            kind: CounterHitKind::Value,
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_cover_the_design_list() {
        for key in [
            "act",
            "head_act",
            "frontier",
            "causal_frontier",
            "seq",
            "as_of_seq",
            "local_seq",
            "high_water_local_seq",
            "authorization_revision",
            "authorization_revision_epoch",
            "authorization_epoch",
            "heads",
            "event_heads",
            "content_head",
        ] {
            assert!(is_counter_key(key, &json!(7)), "{key}");
        }
        assert!(is_counter_key("acts", &json!([1])));
        assert!(!is_counter_key("acts", &Value::Null));
        for key in ["id", "sequence", "act_kind", "head", "content"] {
            assert!(!is_counter_key(key, &json!(7)), "{key}");
        }
    }

    #[test]
    fn values_cover_the_design_list() {
        for text in [
            "rec:1",
            "obs:42",
            "canvas:7",
            "schema-state-v1:meta:3:content:9",
        ] {
            assert!(is_counter_value(text), "{text}");
        }
        for text in [
            "rec:",
            "rec:1a",
            "rev:abc",
            "recx:1",
            "canvas:",
            "schema-state-v2:x",
        ] {
            assert!(!is_counter_value(text), "{text}");
        }
    }

    #[test]
    fn head_matches_whole_numbers_only() {
        assert!(text_names_head("current head is 42", 42));
        assert!(text_names_head("seq 42.", 42));
        assert!(!text_names_head("id 1420", 42));
        assert!(!text_names_head("id 142", 42));
        // A decimal head embedded in a hex UUID is not a whole token: the
        // `27` here sits between the letters `a` and `b`.
        assert!(!text_names_head("record 3c9d-a27b does not exist", 27));
        assert!(!text_names_head("event a27b-4c1e", 27));
        assert!(!text_names_head("id b42c", 42));
    }

    #[test]
    fn find_counters_normalises_paths_and_skips_banned_subtrees() {
        let value = json!({
            "records": [
                { "id": "a", "version": "rec:5" },
                { "id": "b", "version": "rec:6" }
            ],
            "as_of": { "content_seq": 9, "timestamp": "t" },
            "acts": [{ "act": 3 }],
            "advisory_basis": { "event_heads": { "meta": 7, "content": 9 } },
            "causal": null
        });
        let hits = find_counters(&value);
        let described: Vec<_> = hits.iter().map(|h| (h.path.as_str(), h.kind)).collect();
        assert_eq!(
            described,
            vec![
                ("$.records[].version", CounterHitKind::Value),
                ("$.records[].version", CounterHitKind::Value),
                ("$.as_of.content_seq", CounterHitKind::Key),
                ("$.acts", CounterHitKind::Key),
                ("$.advisory_basis.event_heads", CounterHitKind::Key),
            ]
        );
    }

    #[test]
    fn receipt_acts_are_withheld_only_at_the_named_positions() {
        let authored = json!({ "act": 1, "acts": [2], "seq": 3, "frontier": ["f"] });
        let mut receipt = json!({
            "id": "r",
            "act": 9,
            "acts": [{ "index": 0, "act": 9 }],
            "body": authored.clone(),
            "metadata": { "act": 5 },
            "results": [{ "record": { "act": 4, "name": "acts", "body": authored.clone() } }],
            "refresh": { "record": { "act": 6, "metadata": { "act": 8 } } },
        });
        // A neutral tool: only the top level.
        withhold_receipt_acts("update_record", &mut receipt);
        assert_eq!(
            receipt,
            json!({
                "id": "r",
                "body": authored.clone(),
                "metadata": { "act": 5 },
                "results": [{ "record": { "act": 4, "name": "acts", "body": authored.clone() } }],
                "refresh": { "record": { "act": 6, "metadata": { "act": 8 } } },
            })
        );
        // create_many: results[].record.
        withhold_receipt_acts("create_many", &mut receipt);
        assert_eq!(
            receipt["results"],
            json!([{ "record": { "name": "acts", "body": authored.clone() } }])
        );
        assert_eq!(receipt["refresh"]["record"]["act"], 6);
        // invoke_artifact_interaction: refresh.record only; authored nested
        // metadata is untouched.
        withhold_receipt_acts("invoke_artifact_interaction", &mut receipt);
        assert_eq!(
            receipt["refresh"],
            json!({ "record": { "metadata": { "act": 8 } } })
        );
        assert_eq!(receipt["metadata"], json!({ "act": 5 }));
    }

    #[test]
    fn receipt_acts_withholding_ignores_non_object_results() {
        let mut value = json!([{ "act": 1 }]);
        withhold_receipt_acts("create_many", &mut value);
        assert_eq!(value, json!([{ "act": 1 }]));
    }

    #[test]
    fn remove_counter_keys_is_shallow() {
        let mut value = json!({ "a": 1, "local_seq": 2, "event_heads": { "meta": 7, "content": 9 }, "nested": { "seq": 3, "event_heads": { "meta": 4 } } });
        remove_counter_keys(value.as_object_mut().unwrap());
        assert_eq!(
            value,
            json!({ "a": 1, "nested": { "seq": 3, "event_heads": { "meta": 4 } } })
        );
    }
}
