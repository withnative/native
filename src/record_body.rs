//! One historical `records.body` without replaying the workspace.
//!
//! Resolving a body-anchored annotation used to load every content event up to
//! the anchor's `source_event_seq`, replay the whole prefix through the
//! projector in a scratch database, and read one body back out. Cost was
//! proportional to the whole workspace log, paid serially once per anchored
//! comment.
//!
//! The projector derives `records.body` from the event payload in exactly four
//! places, and no other projection touches the column:
//!
//! - `record.created` inserts the row; the body is the payload's `body` value
//!   (`apply_record_created`), `NULL` when the key is absent;
//! - `record.updated` overwrites the body only when its payload object carries
//!   a `body` key, including an explicit null (`apply_record_updated` via
//!   `RecordFieldUpdate::Body`);
//! - `receipt.committed.v1` synthesizes a `record.updated` carrying
//!   `{"body": <payload.body>}` (`project_receipt_committed_aggregate`), so the
//!   payload's top-level `body` always wins;
//! - `unit.revision.recorded.v1` overwrites the body with
//!   `payload.content.content` (`project_unit_revision_recorded`).
//!
//! Values pass through the same coercion the projector applies: payload
//! values bind through `push_json_arg` into a `TEXT` column, so null stays
//! `NULL`, strings store verbatim, booleans and numbers render as decimal
//! text under `TEXT` affinity, and arrays or objects are serialized to JSON
//! text before binding (see `coerce_body`).
//!
//! `record.deleted`, `record.type_corrected.v1`, facet, link, and every other
//! event family leave the column alone (a soft delete only stamps
//! `deleted_at`, which is why a deleted record still resolves its anchored
//! bytes). So the body at seq N is the last body written by one of the four
//! event types above for that record at or before N — one indexed query on
//! `content_events`, folded in Rust with the same null/empty semantics the
//! projector applies.
//!
//! Return contract mirrors the replay it replaces: `Ok(None)` when no
//! `record.created` exists for the record at or before the seq (the replay has
//! no row to read), otherwise `Ok(Some(bytes))` with a SQL `NULL` body
//! reading as empty, exactly as `SELECT body` followed by
//! `unwrap_or_default` does.

pub(crate) mod budgeted;
pub(crate) mod context;
pub(crate) mod live_artifact;
pub(crate) mod pinned;

use serde_json::Value;
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use crate::error::{Error, Result};

/// Content event types whose projection writes `records.body`.
const BODY_WRITING_TYPES: &str =
    "'record.created','record.updated','receipt.committed.v1','unit.revision.recorded.v1'";

/// SQL twin of [`payload_carries_body`]: the predicate selecting events whose
/// projection writes `records.body` with a payload value. The two must move
/// together — a new body-writing event type belongs in both, alongside
/// [`BODY_WRITING_TYPES`]. `json_type(...) IS NOT NULL` distinguishes an
/// absent key from an explicit JSON `null`, so a `record.updated` that clears
/// the body still counts as a writer here.
pub(crate) const BODY_CARRYING_EVENT_SQL: &str = "(type IN ('record.created','record.updated','receipt.committed.v1') AND json_type(payload,'$.body') IS NOT NULL) OR (type = 'unit.revision.recorded.v1' AND json_type(payload,'$.content.content') IS NOT NULL)";

/// Legacy contribution/history selection. This deliberately differs from
/// payload-bearing projection provenance: a bodyless create counts, while
/// raw receipt and unit events do not. Public history converts receipts to
/// updates before applying this policy. Do not widen it as a refactor.
pub const BODY_PRODUCING_EVENT_SQL: &str = "(type = 'record.created' \
     OR (type = 'record.updated' AND json_type(payload, '$.body') IS NOT NULL))";

/// A caller's revision-selection contract, separate from body reconstruction.
#[derive(Clone, Copy)]
pub(crate) enum BodyRevisionSelection {
    PayloadCarrying,
    LegacyContribution,
}

impl BodyRevisionSelection {
    pub(crate) fn sql(self) -> &'static str {
        match self {
            Self::PayloadCarrying => BODY_CARRYING_EVENT_SQL,
            Self::LegacyContribution => BODY_PRODUCING_EVENT_SQL,
        }
    }

    pub(crate) fn matches(self, event_type: &str, payload: &Value) -> bool {
        match self {
            Self::PayloadCarrying => payload_carries_body(event_type, payload),
            Self::LegacyContribution => {
                event_type == "record.created"
                    || (event_type == "record.updated"
                        && event_body_value(event_type, payload).is_some())
            }
        }
    }
}

/// The payload value at a legacy body writer's path, without coercion or
/// admission. `Some(Null)` is a carried clear; `None` is an absent value.
/// Callers validating exact source text must retain their own type checks.
pub(crate) fn event_body_value<'a>(event_type: &str, payload: &'a Value) -> Option<&'a Value> {
    match event_type {
        "record.created" | "record.updated" | "receipt.committed.v1" => payload.get("body"),
        "unit.revision.recorded.v1" => payload.get("content")?.get("content"),
        _ => None,
    }
}

/// Identity of a selected revision; selection never loads the body payload.
pub(crate) struct BodyRevision {
    pub(crate) event_id: String,
    pub(crate) seq: i64,
}

/// Latest legacy contribution facts, without transporting payload bytes.
/// A bodyless create counts; raw receipts and units do not. Callers retain
/// creation lookup, nullable fact decoding and attestation resolution order.
pub(crate) async fn latest_revision_facts_on<'e, E>(
    executor: E,
    record_id: &str,
) -> std::result::Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(&format!(
        "SELECT id, type, run_key, actor FROM content_events
          WHERE record_id = ? AND {}
          ORDER BY seq DESC LIMIT 1",
        BodyRevisionSelection::LegacyContribution.sql()
    ))
    .bind(record_id)
    .fetch_optional(executor)
    .await
}

/// Materialized body and its latest payload-carrying event in one statement.
/// The joined row keeps body bytes and event id/seq atomic. Missing records
/// return None; a record without a carrier retains its body and null identity.
/// No transaction, authorization, JSON normalization or body cap is added.
pub(crate) async fn stored_body_with_revision_on<'e, E>(
    executor: E,
    record_id: &str,
) -> std::result::Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(&format!(
        "SELECT r.body AS body, e.id AS body_event_id, e.seq AS body_event_seq
           FROM records r
           LEFT JOIN content_events e
             ON e.record_id = r.id
            AND e.seq = (SELECT MAX(seq) FROM content_events
                          WHERE record_id = r.id AND ({}))
          WHERE r.id = ?",
        BodyRevisionSelection::PayloadCarrying.sql()
    ))
    .bind(record_id)
    .fetch_optional(executor)
    .await
}

/// Latest revision for one record, optionally at an inclusive sequence horizon.
/// A delete/restore or metadata-only update does not advance this identity.
/// Body bytes are resolved separately by the historical fold below.
pub(crate) async fn latest_body_revision_on(
    conn: &mut SqliteConnection,
    record_id: &str,
    through: Option<i64>,
    selection: BodyRevisionSelection,
) -> Result<Option<BodyRevision>> {
    let row = sqlx::query(&format!(
        "SELECT id,seq FROM content_events
          WHERE record_id=? AND seq<=? AND ({}) ORDER BY seq DESC LIMIT 1",
        selection.sql()
    ))
    .bind(record_id)
    .bind(through.unwrap_or(i64::MAX))
    .fetch_optional(conn)
    .await?;
    row.map(|row| {
        Ok(BodyRevision {
            event_id: row.try_get("id")?,
            seq: row.try_get("seq")?,
        })
    })
    .transpose()
}

/// Whether a body-writing event's payload actually carries a body value, so
/// its projection overwrites `records.body`.
///
/// This is the Rust twin of [`BODY_CARRYING_EVENT_SQL`], used by the
/// revision-3 interchange upgrade to reconstruct the provenance of an
/// imported current body. Both mirror the projector: a `record.updated` or
/// `receipt.committed.v1` writes the body only when the payload object has a
/// `body` key (any JSON type, including `null`), and a
/// `unit.revision.recorded.v1` writes `content.content`.
pub(crate) fn payload_carries_body(event_type: &str, payload: &Value) -> bool {
    event_body_value(event_type, payload).is_some()
}

/// Coerce an event-payload `body` value the way the projector stores it.
///
/// The projector binds payload values through `push_json_arg` into a `TEXT`
/// column: null stays `NULL`; strings store verbatim; booleans bind as 0/1
/// and other numbers bind by affinity, both of which `TEXT` affinity renders
/// as decimal text; arrays and objects are serialized to JSON text in Rust
/// before binding. `None` is SQL `NULL`.
///
/// The live body-mention fold must scan this same text, not just string
/// bodies: an array or object body is stored as its JSON rendering, and the
/// migration backfill scans the stored column, so scanning anything else
/// would make live folding and replay disagree.
pub(crate) fn coerce_body(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(body) => Some(body.clone()),
        Value::Bool(flag) => Some(if *flag { "1".into() } else { "0".into() }),
        Value::Number(number) => Some(number_text(number)),
        other => Some(other.to_string()),
    }
}

/// Render a JSON number the way `TEXT` affinity renders the bound value.
///
/// This mirrors `push_json_arg` exactly: integers that fit `i64` bind as
/// integers (decimal text under `TEXT` affinity); anything else binds as
/// `f64`, which `TEXT` affinity renders with SQLite's `%.15g`.
fn number_text(number: &serde_json::Number) -> String {
    if let Some(integer) = number.as_i64() {
        return integer.to_string();
    }
    sqlite_g15(number.as_f64().unwrap_or(f64::NAN))
}

/// Format a finite `f64` like SQLite's `%.15g`: fifteen significant digits,
/// fixed notation for decimal exponents in `[-4, 15)`, exponential otherwise,
/// trailing zeros stripped but the point keeping one digit (`1.0e+300`,
/// `100000.0`, `150000000000000.0`), so a whole float never reads back as an
/// integer. Non-finite inputs cannot arrive through JSON payloads; they map
/// the way SQLite renders them for completeness.
fn sqlite_g15(value: f64) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0".into()
        } else {
            "0".into()
        };
    }
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value.is_sign_positive() {
            "Inf".into()
        } else {
            "-Inf".into()
        };
    }
    // Fifteen significant digits, correctly rounded, plus the decimal
    // exponent of the rounded value. Branching on the rounded exponent —
    // rather than `log10` of the binary value — keeps values at the top of
    // the exponent-14 decade (e.g. `999999999999999.0`) in fixed notation
    // with their point, exactly like SQLite.
    let text = format!("{value:.14e}");
    let (mantissa, exponent) = text.split_once('e').expect("exponential formats");
    let exponent: i32 = exponent.parse().expect("decimal exponent");
    let (sign, mantissa) = mantissa
        .strip_prefix('-')
        .map_or(("", mantissa), |rest| ("-", rest));
    let digits: String = mantissa
        .bytes()
        .filter(|byte| *byte != b'.')
        .map(char::from)
        .collect();
    debug_assert_eq!(digits.len(), 15);
    if (-4..15).contains(&exponent) {
        let (int, frac) = if exponent >= 0 {
            let split = (exponent + 1) as usize;
            (digits[..split].to_owned(), digits[split..].to_owned())
        } else {
            (
                "0".to_owned(),
                format!("{}{digits}", "0".repeat((-exponent - 1) as usize)),
            )
        };
        let frac = strip_frac_zeros(frac);
        if frac.is_empty() {
            format!("{sign}{int}.0")
        } else {
            format!("{sign}{int}.{frac}")
        }
    } else {
        // Only the exponent spelling needs normalizing to SQLite's `e±XX`
        // (at least two digits); the mantissa digits are already rounded.
        let (lead, rest) = digits.split_at(1);
        let rest = strip_frac_zeros(rest.to_owned());
        let mantissa = if rest.is_empty() {
            format!("{lead}.0")
        } else {
            format!("{lead}.{rest}")
        };
        let designator = if exponent < 0 { "-" } else { "+" };
        format!("{sign}{mantissa}e{designator}{:02}", exponent.abs())
    }
}

/// Strip redundant fraction digits. The caller restores the point with one
/// digit when nothing remains, so this never has to handle the point itself.
fn strip_frac_zeros(mut frac: String) -> String {
    while frac.ends_with('0') {
        frac.pop();
    }
    frac
}

/// Extract the body the projector would write for one body-writing event.
///
/// Returns `None` when the event carries no body update (an update without a
/// `body` key, or a malformed unit payload the projector itself would reject).
/// Otherwise returns the new body, with `None` standing for SQL `NULL` — a
/// missing key on create, or an explicit null — which the projector stores as
/// `NULL` and every reader coerces to empty.
pub(crate) fn projected_body(event_type: &str, payload: &Value) -> Option<Option<String>> {
    match event_type {
        "record.created" => Some(coerce_body(
            event_body_value(event_type, payload).unwrap_or(&Value::Null),
        )),
        "record.updated" | "receipt.committed.v1" => {
            event_body_value(event_type, payload).map(coerce_body)
        }
        "unit.revision.recorded.v1" => event_body_value(event_type, payload)
            .and_then(Value::as_str)
            .map(|content| Some(content.to_owned())),
        _ => None,
    }
}

/// Fold the body-writing events for one record up to and including `seq`.
///
/// This is the shared core: the pool and transaction wrappers below only
/// supply the connection.
pub(crate) async fn body_at_seq_on(
    conn: &mut SqliteConnection,
    record_id: &str,
    seq: i64,
) -> Result<Option<Vec<u8>>> {
    let rows = sqlx::query(&format!(
        "SELECT id, type, payload FROM content_events
          WHERE record_id = ? AND seq <= ? AND type IN ({BODY_WRITING_TYPES})
          ORDER BY seq",
    ))
    .bind(record_id)
    .bind(seq)
    .fetch_all(&mut *conn)
    .await?;
    // Only `record.created` inserts the row; every other body writer asserts
    // the record is live first. Without a create at or before the seq the
    // replay has no row, so the fold has no body either.
    let mut exists = false;
    let mut body: Option<String> = None;
    for row in rows {
        let event_type: String = row.try_get("type")?;
        let raw: Option<String> = row.try_get("payload")?;
        let Some(raw) = raw else {
            let id: String = row.try_get("id")?;
            return Err(Error::engine(format!("event {id} has no payload")));
        };
        let payload: Value = serde_json::from_str(&raw)?;
        if event_type == "record.created" {
            exists = true;
        }
        if let Some(next) = projected_body(&event_type, &payload) {
            body = next;
        }
    }
    if !exists {
        return Ok(None);
    }
    Ok(Some(body.unwrap_or_default().into_bytes()))
}

/// Historical body from a pool (read-only suffices: one indexed select).
pub async fn body_at_seq_in_pool(
    pool: &sqlx::SqlitePool,
    record_id: &str,
    seq: i64,
) -> Result<Option<Vec<u8>>> {
    let mut conn = pool.acquire().await?;
    body_at_seq_on(&mut conn, record_id, seq).await
}

/// Historical body inside a caller's write transaction.
pub(crate) async fn body_at_seq_in(
    tx: &mut Transaction<'_, Sqlite>,
    record_id: &str,
    seq: i64,
) -> Result<Option<Vec<u8>>> {
    body_at_seq_on(tx, record_id, seq).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Read-contract fixtures only: this table does not admit events through
    // the store. Full projector equivalence lives in anchored_body_fold.
    async fn log() -> SqliteConnection {
        use sqlx::Connection;
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        sqlx::query("CREATE TABLE content_events(seq INTEGER PRIMARY KEY,id TEXT,record_id TEXT,type TEXT,payload TEXT)")
            .execute(&mut conn).await.unwrap();
        conn
    }

    async fn insert(conn: &mut SqliteConnection, seq: i64, event_type: &str, payload: Value) {
        sqlx::query("INSERT INTO content_events VALUES(?,?,'record',?,?)")
            .bind(seq)
            .bind(format!("event-{seq}"))
            .bind(event_type)
            .bind(payload.to_string())
            .execute(conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revision_policies_preserve_sql_and_payload_semantics() {
        let mut conn = log().await;
        // Carrying, legacy contribution, projected body: these are distinct
        // contracts. A malformed unit value may carry a payload without
        // yielding a body; an absent create still projects SQL NULL.
        let cases = [
            ("record.created", json!({}), false, true, Some(None)),
            (
                "record.created",
                json!({"body":null}),
                true,
                true,
                Some(None),
            ),
            (
                "record.updated",
                json!({"name":"metadata"}),
                false,
                false,
                None,
            ),
            (
                "record.updated",
                json!({"body":null}),
                true,
                true,
                Some(None),
            ),
            (
                "record.updated",
                json!({"body":""}),
                true,
                true,
                Some(Some(String::new())),
            ),
            (
                "record.updated",
                json!({"body":true}),
                true,
                true,
                Some(Some("1".into())),
            ),
            (
                "record.updated",
                json!({"body":{"a":1}}),
                true,
                true,
                Some(Some("{\"a\":1}".into())),
            ),
            (
                "receipt.committed.v1",
                json!({"body":"receipt"}),
                true,
                false,
                Some(Some("receipt".into())),
            ),
            ("receipt.committed.v1", json!({}), false, false, None),
            (
                "unit.revision.recorded.v1",
                json!({"content":{"content":"unit"}}),
                true,
                false,
                Some(Some("unit".into())),
            ),
            (
                "unit.revision.recorded.v1",
                json!({"content":{"content":null}}),
                true,
                false,
                None,
            ),
            (
                "unit.revision.recorded.v1",
                json!({"content":{}}),
                false,
                false,
                None,
            ),
            (
                "record.deleted",
                json!({"body":"ignored"}),
                false,
                false,
                None,
            ),
            (
                "record.restored",
                json!({"body":"ignored"}),
                false,
                false,
                None,
            ),
            (
                "record.body_appended",
                json!({"body":"ignored","text":"tail"}),
                false,
                false,
                None,
            ),
        ];
        for (index, (event_type, payload, carrying, contribution, projected)) in
            cases.into_iter().enumerate()
        {
            let seq = index as i64 + 1;
            insert(&mut conn, seq, event_type, payload.clone()).await;
            assert_eq!(
                projected_body(event_type, &payload),
                projected,
                "{event_type}: {payload}"
            );
            for (policy, expected) in [
                (BodyRevisionSelection::PayloadCarrying, carrying),
                (BodyRevisionSelection::LegacyContribution, contribution),
            ] {
                let sql = format!("SELECT ({}) FROM content_events WHERE seq=?", policy.sql());
                let selected: bool = sqlx::query_scalar(&sql)
                    .bind(seq)
                    .fetch_one(&mut conn)
                    .await
                    .unwrap();
                assert_eq!(selected, expected, "SQL {event_type}: {payload}");
                assert_eq!(
                    policy.matches(event_type, &payload),
                    expected,
                    "Rust {event_type}: {payload}"
                );
            }
        }
    }

    #[tokio::test]
    async fn revision_identity_and_historical_bytes_preserve_order_and_clears() {
        let mut conn = log().await;
        let events = [
            ("record.created", json!({})),
            ("record.updated", json!({"body":"same"})),
            ("record.updated", json!({"name":"metadata"})),
            ("record.updated", json!({"body":null})),
            ("record.updated", json!({"body":""})),
            ("record.updated", json!({"body":"same"})),
            ("record.deleted", json!({})),
            ("record.restored", json!({})),
            ("receipt.committed.v1", json!({"body":"receipt"})),
            (
                "unit.revision.recorded.v1",
                json!({"content":{"content":"unit"}}),
            ),
        ];
        for (index, (event_type, payload)) in events.into_iter().enumerate() {
            insert(&mut conn, index as i64 + 1, event_type, payload).await;
        }
        for (through, carrying_seq, contribution_seq, bytes) in [
            (0, None, None, None),
            (1, None, Some(1), Some("")),
            (3, Some(2), Some(2), Some("same")),
            (4, Some(4), Some(4), Some("")),
            (5, Some(5), Some(5), Some("")),
            (8, Some(6), Some(6), Some("same")),
            (9, Some(9), Some(6), Some("receipt")),
            (10, Some(10), Some(6), Some("unit")),
        ] {
            for (policy, expected) in [
                (BodyRevisionSelection::PayloadCarrying, carrying_seq),
                (BodyRevisionSelection::LegacyContribution, contribution_seq),
            ] {
                let revision = latest_body_revision_on(&mut conn, "record", Some(through), policy)
                    .await
                    .unwrap();
                assert_eq!(revision.as_ref().map(|revision| revision.seq), expected);
                assert_eq!(
                    revision.map(|revision| revision.event_id),
                    expected.map(|seq| format!("event-{seq}"))
                );
            }
            assert_eq!(
                body_at_seq_on(&mut conn, "record", through).await.unwrap(),
                bytes.map(|text| text.as_bytes().to_vec())
            );
        }
        let latest = latest_body_revision_on(
            &mut conn,
            "record",
            None,
            BodyRevisionSelection::PayloadCarrying,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(latest.seq, 10);
        assert!(latest_body_revision_on(
            &mut conn,
            "missing",
            None,
            BodyRevisionSelection::PayloadCarrying
        )
        .await
        .unwrap()
        .is_none());
        assert_eq!(
            body_at_seq_on(&mut conn, "missing", 10).await.unwrap(),
            None
        );
    }
}
