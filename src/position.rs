//! Event-id positions (design 08b4c21 §3, "Event-id rules").
//!
//! A position in the content log can be named by the id of the content event
//! at that position. Content event ids are unique (`content_events.id`), so
//! the server resolves an id to its internal sequence through that index. The
//! caller never handles the number, and cannot pick one: locally minted ids
//! are random UUIDv4, and for a non-owner any id that is not v4-shaped is
//! refused exactly like an unknown id (replicated Message events keep the
//! peer's id, which may be any UUID version).
//!
//! `origin` names the empty prefix, so an empty log still has a position.
//!
//! Every refusal here is the same value: unknown, pruned and non-v4 ids must
//! not be distinguishable, and the text carries no number.

use sqlx::SqliteConnection;

use crate::error::Result;
use crate::mcp::registry::CounterFooting;
use crate::query::error::contract_violation;

/// The position before the first event: the only position an empty log has.
pub const ORIGIN: &str = "origin";

/// The one refusal for a position that cannot be resolved. It carries no
/// number and does not say which of the reasons applied.
pub const UNKNOWN_POSITION_MESSAGE: &str =
    "unknown position: the event id does not name a position that can be read";

pub fn unknown_position() -> crate::Error {
    contract_violation(UNKNOWN_POSITION_MESSAGE)
}

/// Whether `error` is the uniform unknown-position refusal. Callers that turn
/// that refusal into a precondition failure use this to let every other error
/// (a busy or timed-out store, say) propagate instead of being relabelled.
pub fn is_unknown_position(error: &crate::Error) -> bool {
    matches!(error, crate::Error::Engine(message) if message == UNKNOWN_POSITION_MESSAGE)
}

/// Lowercase, hyphenated, version nibble `4`, variant nibble `8`/`9`/`a`/`b`.
pub fn is_v4_shaped(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => *byte == b'-',
        14 => *byte == b'4',
        19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
        _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
    })
}

/// Resolve a position token to its internal content sequence.
///
/// `origin` is sequence 0. For a non-owner, an id that is not v4-shaped is
/// refused before the index is consulted, so it behaves exactly like an id
/// that does not exist.
pub async fn resolve(
    conn: &mut SqliteConnection,
    footing: CounterFooting,
    token: &str,
) -> Result<i64> {
    if token == ORIGIN {
        return Ok(0);
    }
    if !footing.is_owner() && !is_v4_shaped(token) {
        return Err(unknown_position());
    }
    sqlx::query_scalar::<_, i64>("SELECT seq FROM content_events WHERE id = ?")
        .bind(token)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(unknown_position)
}

/// Message for a snapshot that cannot be continued by event id. Numberless,
/// like every other refusal in this module.
pub const NO_CONTINUATION_MESSAGE: &str =
    "this page cannot be continued by event id: its final event has no stable position id; retry the query";

/// The position token naming the prefix of the content log up to `seq`: the id
/// of the greatest event at or below `seq`, or `origin` when there is none.
///
/// At a genuine gap in the sequence (no row at `seq`) the greatest earlier
/// event names the same prefix, because no row lies between it and `seq`.
///
/// For a non-owner the token must resolve again on the next page, and
/// [`resolve`] refuses ids that are not v4-shaped (replicated Message events
/// keep the peer's id). Handing out such an id would make the continuation
/// fail on the following request, and substituting an earlier v4 id would name
/// a smaller prefix and silently drop the final rows from the snapshot. So the
/// honest answer is a refusal at the point the token is needed.
pub async fn token_for_seq(
    conn: &mut SqliteConnection,
    footing: CounterFooting,
    seq: i64,
) -> Result<String> {
    if seq <= 0 {
        return Ok(ORIGIN.to_owned());
    }
    let id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE seq <= ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(seq)
    .fetch_optional(&mut *conn)
    .await?;
    match id {
        None => Ok(ORIGIN.to_owned()),
        Some(id) if footing.is_owner() || is_v4_shaped(&id) => Ok(id),
        Some(_) => Err(crate::Error::engine(NO_CONTINUATION_MESSAGE)),
    }
}

/// The `as_of` a continuation should carry for this caller: the numeric form
/// for an owner, the event-id form for everyone else.
pub async fn continuation_as_of(
    conn: &mut SqliteConnection,
    footing: CounterFooting,
    seq: i64,
) -> Result<serde_json::Value> {
    if footing.is_owner() {
        Ok(serde_json::json!({ "content_seq": seq }))
    } else {
        Ok(serde_json::json!({ "event_id": token_for_seq(conn, footing, seq).await? }))
    }
}

/// Parse a facet version precondition token, accepting the event-id forms
/// (`rev:<event id>`, `obsv:<event id>`) beside `rec:N` and `obs:N`. An event
/// id resolves to the sequence it stands for, so the caller compares exactly
/// as it would for the numeric token. `None` means the token has no valid
/// shape; an id that does not resolve is the uniform position refusal.
pub async fn parse_facet_version(
    conn: &mut SqliteConnection,
    footing: CounterFooting,
    token: &str,
) -> Result<Option<native_artifact_runtime::artifact_intents::FacetVersion>> {
    use native_artifact_runtime::artifact_intents::{EventFacetVersion, FacetVersion};
    if let Some(version) = FacetVersion::parse(token) {
        return Ok(Some(version));
    }
    Ok(match EventFacetVersion::parse(token) {
        Some(EventFacetVersion::Record { event_id }) => Some(FacetVersion::Record {
            event_seq: resolve(conn, footing, event_id).await?,
        }),
        Some(EventFacetVersion::Observation { event_id }) => Some(FacetVersion::Observation {
            event_seq: resolve(conn, footing, event_id).await?,
        }),
        None => None,
    })
}

/// The tools whose arguments carry an `if_content_seq` precondition and so
/// accept `if_previous_event_id` beside it.
const EVENT_ID_PRECONDITION_TOOLS: &[&str] = &[
    "correct_record_type",
    "delete_record",
    "manage_citations",
    "manage_record_policy",
];

/// Rewrite `if_previous_event_id` into the `if_content_seq` the handlers
/// already understand. `if_content_seq` is the record's latest event seq
/// (`previous_seq`), so the event id a write receipt returned as
/// `previous_event_id` names exactly that value. Runs at argument admission,
/// before the handler deserializes its arguments.
///
/// Only the argument positions that really carry `if_content_seq` are
/// rewritten: the top level, and the `items` of `manage_record_policy`
/// (`set_many`). Anything deeper is caller content and is left untouched, so a
/// record body that happens to contain the key is never altered or refused.
///
/// `origin` is refused here although `rev:origin` and `obsv:origin` are
/// accepted as facet tokens: a record's previous event is never the empty
/// prefix, and `null` already says "no precondition" (a new record's receipt
/// carries `previous_event_id: null`).
pub async fn admit_event_id_preconditions(
    engine: &crate::mcp::registry::EngineHandle,
    caller: &crate::mcp::registry::Caller,
    tool: &str,
    mut arguments: serde_json::Value,
) -> Result<serde_json::Value> {
    if !EVENT_ID_PRECONDITION_TOOLS.contains(&tool) || !contains_precondition(tool, &arguments) {
        return Ok(arguments);
    }
    let Some(db) = engine.sqlite() else {
        // The Postgres and Turso twins do not accept the event-id form yet;
        // their argument parsers refuse the unknown field.
        return Ok(arguments);
    };
    let mut conn = db.write_pool().acquire().await?;
    rewrite_preconditions(&mut conn, caller.counter_footing(), tool, &mut arguments).await?;
    Ok(arguments)
}

/// The `items` of `manage_record_policy` (`set_many`) carry their own
/// precondition beside the top-level one.
fn has_item_preconditions(tool: &str) -> bool {
    tool == "manage_record_policy"
}

fn contains_precondition(tool: &str, arguments: &serde_json::Value) -> bool {
    let holds = |value: &serde_json::Value| {
        value
            .as_object()
            .is_some_and(|map| map.contains_key("if_previous_event_id"))
    };
    holds(arguments)
        || (has_item_preconditions(tool)
            && arguments
                .get("items")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|items| items.iter().any(holds)))
}

async fn rewrite_preconditions(
    conn: &mut SqliteConnection,
    footing: CounterFooting,
    tool: &str,
    arguments: &mut serde_json::Value,
) -> Result<()> {
    let Some(top) = arguments.as_object_mut() else {
        return Ok(());
    };
    if has_item_preconditions(tool) {
        if let Some(serde_json::Value::Array(items)) = top.get_mut("items") {
            for item in items
                .iter_mut()
                .filter_map(serde_json::Value::as_object_mut)
            {
                rewrite_one(conn, footing, item).await?;
            }
        }
    }
    rewrite_one(conn, footing, top).await
}

async fn rewrite_one(
    conn: &mut SqliteConnection,
    footing: CounterFooting,
    map: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let Some(supplied) = map.remove("if_previous_event_id") else {
        return Ok(());
    };
    if map.contains_key("if_content_seq") {
        return Err(crate::Error::engine(
            "supply either if_content_seq or if_previous_event_id, not both",
        ));
    }
    match supplied {
        serde_json::Value::Null => {}
        serde_json::Value::String(id) if id != ORIGIN => {
            let seq = resolve(conn, footing, &id).await?;
            map.insert("if_content_seq".into(), seq.into());
        }
        _ => return Err(unknown_position()),
    }
    Ok(())
}

/// [`echo_previous_event_ids`] on a pooled connection.
pub async fn echo_previous_event_ids_in(
    db: &crate::db::Db,
    value: &mut serde_json::Value,
) -> Result<()> {
    let mut conn = db.write_pool().acquire().await?;
    echo_previous_event_ids(&mut conn, value).await
}

/// Add `previous_event_id` beside every integer `previous_seq` in a write
/// receipt (nested receipts included). A null `previous_seq` (a new record)
/// gets a null `previous_event_id`. Existing `previous_event_id` fields are
/// left alone.
pub async fn echo_previous_event_ids(
    conn: &mut SqliteConnection,
    value: &mut serde_json::Value,
) -> Result<()> {
    let mut wanted = Vec::new();
    collect_previous_seqs(value, &mut wanted);
    if wanted.is_empty() {
        return Ok(());
    }
    let mut ids = std::collections::BTreeMap::new();
    for seq in wanted {
        if let std::collections::btree_map::Entry::Vacant(slot) = ids.entry(seq) {
            let id: Option<String> =
                sqlx::query_scalar("SELECT id FROM content_events WHERE seq = ?")
                    .bind(seq)
                    .fetch_optional(&mut *conn)
                    .await?;
            slot.insert(id);
        }
    }
    attach_previous_event_ids(value, &ids);
    Ok(())
}

fn collect_previous_seqs(value: &serde_json::Value, out: &mut Vec<i64>) {
    match value {
        serde_json::Value::Object(map) => {
            if !map.contains_key("previous_event_id") {
                if let Some(seq) = map.get("previous_seq").and_then(serde_json::Value::as_i64) {
                    out.push(seq);
                }
            }
            map.values()
                .for_each(|child| collect_previous_seqs(child, out));
        }
        serde_json::Value::Array(items) => {
            items
                .iter()
                .for_each(|child| collect_previous_seqs(child, out));
        }
        _ => {}
    }
}

fn attach_previous_event_ids(
    value: &mut serde_json::Value,
    ids: &std::collections::BTreeMap<i64, Option<String>>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if !map.contains_key("previous_event_id") {
                match map.get("previous_seq") {
                    Some(serde_json::Value::Null) => {
                        map.insert("previous_event_id".into(), serde_json::Value::Null);
                    }
                    Some(seq) => {
                        if let Some(seq) = seq.as_i64() {
                            map.insert(
                                "previous_event_id".into(),
                                ids.get(&seq).cloned().flatten().into(),
                            );
                        }
                    }
                    None => {}
                }
            }
            map.values_mut()
                .for_each(|child| attach_previous_event_ids(child, ids));
        }
        serde_json::Value::Array(items) => {
            items
                .iter_mut()
                .for_each(|child| attach_previous_event_ids(child, ids));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_shape_is_lowercase_hyphenated_with_version_and_variant() {
        assert!(is_v4_shaped("3f2b8c1e-5d4a-4b6c-9e7f-0a1b2c3d4e5f"));
        assert!(is_v4_shaped("3f2b8c1e-5d4a-4b6c-8e7f-0a1b2c3d4e5f"));
        assert!(is_v4_shaped("3f2b8c1e-5d4a-4b6c-ae7f-0a1b2c3d4e5f"));
        assert!(is_v4_shaped("3f2b8c1e-5d4a-4b6c-be7f-0a1b2c3d4e5f"));
        // Uppercase, wrong version, wrong variant, no hyphens, wrong length.
        assert!(!is_v4_shaped("3F2B8C1E-5D4A-4B6C-9E7F-0A1B2C3D4E5F"));
        assert!(!is_v4_shaped("3f2b8c1e-5d4a-1b6c-9e7f-0a1b2c3d4e5f"));
        assert!(!is_v4_shaped("3f2b8c1e-5d4a-7b6c-9e7f-0a1b2c3d4e5f"));
        assert!(!is_v4_shaped("3f2b8c1e-5d4a-4b6c-ce7f-0a1b2c3d4e5f"));
        assert!(!is_v4_shaped("3f2b8c1e5d4a4b6c9e7f0a1b2c3d4e5f"));
        assert!(!is_v4_shaped("3f2b8c1e-5d4a-4b6c-9e7f-0a1b2c3d4e5"));
        assert!(!is_v4_shaped("origin"));
        assert!(!is_v4_shaped(""));
        assert!(!is_v4_shaped("3f2b8c1e-5d4a-4b6c-9e7f-0a1b2c3d4e5g"));
    }

    #[test]
    fn refusal_carries_no_number() {
        assert!(!UNKNOWN_POSITION_MESSAGE.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn the_numberless_continuation_message_carries_no_number() {
        assert!(!NO_CONTINUATION_MESSAGE.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn only_the_unknown_position_refusal_is_classified_as_one() {
        assert!(is_unknown_position(&unknown_position()));
        assert!(!is_unknown_position(&crate::Error::engine(
            "database is busy"
        )));
    }

    #[test]
    fn preconditions_are_found_at_the_top_level_and_policy_items_only() {
        let key = "if_previous_event_id";
        let nested = serde_json::json!({
            "items": [{ "nested": { key: "caller content" } }],
            "body": { key: "caller content" },
        });
        assert!(!contains_precondition("manage_record_policy", &nested));
        assert!(contains_precondition(
            "delete_record",
            &serde_json::json!({ key: "x" })
        ));
        let item = serde_json::json!({ "items": [{ key: "x" }] });
        assert!(contains_precondition("manage_record_policy", &item));
        // `items` is caller content for any other tool.
        assert!(!contains_precondition("delete_record", &item));
    }

    #[tokio::test]
    async fn rewriting_leaves_caller_json_untouched() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        let key = "if_previous_event_id";
        let mut arguments = serde_json::json!({
            "items": [{ "record_id": "r", key: null, "payload": { key: "caller content" } }],
            "payload": { key: ["caller content"] },
        });
        let before = arguments.clone();
        rewrite_preconditions(
            &mut conn,
            CounterFooting::NonOwner,
            "manage_record_policy",
            &mut arguments,
        )
        .await
        .unwrap();
        // The null precondition is removed (it means "none"); the nested
        // caller content survives byte for byte, and no `if_content_seq`
        // appears anywhere.
        assert_eq!(arguments["payload"], before["payload"]);
        assert_eq!(
            arguments["items"][0]["payload"],
            before["items"][0]["payload"]
        );
        assert!(arguments["items"][0].get(key).is_none());
        assert!(arguments["items"][0].get("if_content_seq").is_none());
    }
}
