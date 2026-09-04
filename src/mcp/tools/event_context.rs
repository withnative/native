//! `get_event_context` — what one exact moment in a run looked like.
//!
//! # The question this answers
//!
//! A comment byline deep-links to the event that produced the utterance being
//! read. Opening that link should let a reader see the exact comment-producing
//! event, what the run said it was trying to do at that moment, the writes
//! around it, the exact change made, and the records the run most immediately
//! opened beforehand.
//!
//! `get_run_activity` cannot answer this. It returns visibility-filtered
//! AGGREGATE counts for a whole run and deliberately omits raw arguments and
//! query text; it has no notion of "before this event". Reconstructing a moment
//! by subtracting aggregates would be both wrong and slower than asking the
//! question directly, so this is a focused server-side projection that resolves
//! the event once and returns one authorization-consistent envelope.
//!
//! # What "consulted" does and does not mean
//!
//! The consulted list is **evidence, not proof**. `opened` means the run
//! explicitly requested that record — a stronger signal than `surfaced`, which
//! only means a record appeared in some bounded result. Neither establishes
//! that the agent read, understood, relied on, or agreed with anything. The
//! panel therefore says "Opened before this event", not "Sources" and not
//! "Used".
//!
//! Two failure modes are called out explicitly rather than papered over:
//!
//! - The read log is **disposable operational evidence**, not canonical
//!   history. If it is absent or a query fails, the answer is `unavailable` —
//!   never an empty list, which a reader would correctly interpret as "this run
//!   opened nothing".
//! - Visibility filtering and the eight-record bound both TRUNCATE. That is
//!   reported as `partial`, so an incomplete list is never mistaken for a
//!   complete one.
//!
//! A deep-link grants no read authority. Every returned record passes the
//! viewer's ordinary visibility check, and redaction behaves exactly as it does
//! on the ordinary history surface.

use serde_json::{json, Value};
use sqlx::Row;

use super::history::{event_is_visible, event_to_value, redact_event, ActorDisclosure};
use super::{can_record, parse_args, require_record};
use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::EventRow;
use crate::mcp::interactions::ToolKind;
use crate::mcp::registry::{Caller, ToolRegistry};

const TOOL: &str = "get_event_context";
/// The bound on the consulted list. Eight is a legibility budget, not a claim
/// that the run opened at most eight things — which is exactly why the response
/// reports `partial` when it truncates.
pub const MAX_CONSULTED: usize = 8;
/// How many events either side of the selected one to return as context.
pub const NEIGHBOUR_WINDOW: i64 = 6;

pub const LIMIT_OPENED_NOT_COMPREHENSION: &str =
    "opened_does_not_establish_comprehension_or_reliance";
pub const LIMIT_CONSULTED_BOUNDED: &str = "consulted_context_is_bounded";
pub const LIMIT_CONSULTED_FILTERED: &str = "consulted_context_may_be_visibility_filtered";
pub const LIMIT_READ_LOG_BEST_EFFORT: &str = "read_log_is_best_effort_not_canonical_history";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GetEventContextArgs {
    /// The IMMUTABLE event id. Sequence orders and displays; it does not
    /// address, because a database-local counter is not a durable address.
    event_id: String,
}

/// Consulted-evidence completeness. `Unavailable` and an empty `Available` are
/// different answers and must never collapse into each other.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EvidenceStatus {
    Available,
    Partial,
    Unavailable,
}

impl EvidenceStatus {
    fn as_str(self) -> &'static str {
        match self {
            EvidenceStatus::Available => "available",
            EvidenceStatus::Partial => "partial",
            EvidenceStatus::Unavailable => "unavailable",
        }
    }
}

pub fn register_event_context_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::GetEventContext,
        "One moment in a run, addressed by immutable event id: the selected event, the intent in force at that event rather than the run's latest intent, the exact before/after body delta that event itself produced (correct even after later edits), neighbouring events in the same run, and up to eight records the same run most recently OPENED beforehand. Opened means the run explicitly requested the record; it establishes no comprehension, reliance or agreement. Records that were only surfaced in results are reported as a separate weaker count, never as consulted. Evidence status is explicit: an empty available list means no qualifying opens were logged in the bounded scope, while an absent or failed read log reports unavailable. Raw tool arguments and query text are never returned, and the link grants no read authority beyond the viewer's ordinary visibility.",
        json!({
            "type": "object",
            "properties": {
                "event_id": {
                    "type": "string",
                    "description": "Immutable content event id. Database-local sequence is for ordering and display, not addressing."
                }
            },
            "required": ["event_id"],
            "additionalProperties": false
        }),
        get_event_context,
    )
}

async fn get_event_context(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: GetEventContextArgs = parse_args(TOOL, arguments)?;
    let row = sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor, run_key, parent_key, intent, created_at,
                causal_envelope_version, causal_status,
                (SELECT json_group_array(parent_event_id)
                   FROM content_event_causal_frontier
                  WHERE event_id = content_events.id) AS causal_frontier
           FROM content_events WHERE id = ?",
    )
    .bind(&args.event_id)
    .fetch_optional(db.write_pool())
    .await?
    .ok_or_else(|| Error::engine(format!("{TOOL}: event {} does not exist", args.event_id)))?;
    let mut selected = event_row(&row)?;

    // Authorize the event's subject FIRST. A missing event and an unauthorized
    // one produce the same refusal above and below, so this is not an oracle.
    require_record(&db, &caller, TOOL, &selected.record_id, Capability::View).await?;
    if !event_is_visible(&db, &caller, &selected).await? {
        return Err(Error::engine(format!(
            "{TOOL}: event {} does not exist",
            args.event_id
        )));
    }

    let event_created_at = selected.created_at.clone();
    let event_run_key = selected.run_key.clone();
    let event_record_id = selected.record_id.clone();
    let event_seq = selected.local_seq;

    let delta = body_delta(&db, &event_record_id, &selected).await?;

    let mut disclosure = ActorDisclosure::default();
    redact_event(&db, &caller, &mut disclosure, &mut selected).await?;
    // The event-local intent is the one stamped on THIS event, not the run's
    // latest. A run that has since re-declared its aim must not have that later
    // aim retro-attached to an earlier write.
    let event_intent = selected.intent.clone();

    let neighbours =
        neighbouring_events(&db, &caller, &mut disclosure, &selected, event_seq).await?;

    let consulted = match event_run_key.as_deref() {
        Some(run_key) => {
            consulted_context(&db, &caller, run_key, &event_created_at, &event_record_id).await
        }
        // No run key means no bounded scope to scan. That is an absence of
        // evidence, reported as such.
        None => Ok(ConsultedEvidence::unavailable()),
    }
    .unwrap_or_else(|_| ConsultedEvidence::unavailable());

    let actor_names = if selected.actor.is_some() {
        crate::mcp::tools::history::resolve_actor_names(&db, std::slice::from_ref(&selected)).await
    } else {
        std::collections::HashMap::new()
    };

    Ok(json!({
        "event": event_to_value(&selected, &actor_names),
        "run": event_run_key.as_ref().map(|run_key| json!({
            "run_key": run_key,
            "agent_key": crate::runkey::agent_key_of(run_key),
            // The same disclaimer the contribution projection carries: a run
            // key groups calls, it does not identify a persistent agent.
            "assurance": "correlation_only",
        })),
        "intent_at_event": event_intent,
        "delta": delta,
        "neighbouring_events": neighbours,
        "consulted": {
            "label": "Opened before this event",
            "status": consulted.status.as_str(),
            "records": consulted.records,
            // Deliberately a bare count, not a list. Surfacing is weaker
            // evidence and keeping it collapsed stops it reading as consulting.
            "other_records_surfaced": consulted.surfaced_only,
            "limit": MAX_CONSULTED,
        },
        "interpretation_limits": [
            LIMIT_OPENED_NOT_COMPREHENSION,
            LIMIT_CONSULTED_BOUNDED,
            LIMIT_CONSULTED_FILTERED,
            LIMIT_READ_LOG_BEST_EFFORT,
        ],
    }))
}

fn event_row(row: &sqlx::sqlite::SqliteRow) -> Result<EventRow> {
    crate::query::events::event_from_row(row)
}

/// The exact change THIS event made.
///
/// `render_record_version_diff` compares a historical point with the record's
/// CURRENT revision, which answers a different question: after two later edits
/// it reports the accumulated difference rather than the one this event
/// produced. Both bodies are therefore folded from the event log — the state
/// just before this event, and the state this event left behind — so the delta
/// stays exact no matter how much happened afterwards.
async fn body_delta(db: &Db, record_id: &str, event: &EventRow) -> Result<Value> {
    if !is_body_producing(event) {
        return Ok(json!({
            "kind": "not_a_body_revision",
            "event_type": event.event_type,
        }));
    }
    let mut tx = db.write_pool().begin().await?;
    let after = crate::attribution::body_at_event_in(&mut tx, record_id, &event.id).await?;
    let previous: Option<String> = sqlx::query_scalar(&format!(
        "SELECT id FROM content_events
          WHERE record_id = ? AND seq < ? AND {}
          ORDER BY seq DESC LIMIT 1",
        crate::contribution::BODY_PRODUCING_EVENT_SQL
    ))
    .bind(record_id)
    .bind(event.local_seq)
    .fetch_optional(&mut *tx)
    .await?;
    let before = match previous.as_deref() {
        Some(previous) => {
            crate::attribution::body_at_event_in(&mut tx, record_id, previous).await?
        }
        None => None,
    };
    tx.rollback().await?;
    Ok(json!({
        "kind": "body_revision",
        "record_id": record_id,
        "before_event_id": previous,
        "before": before.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        "after": after.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        "is_creation": previous.is_none(),
    }))
}

fn is_body_producing(event: &EventRow) -> bool {
    if event.event_type == "record.created" {
        return true;
    }
    if event.event_type != "record.updated" {
        return false;
    }
    event
        .payload
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .is_some_and(|payload| payload.get("body").is_some())
}

async fn neighbouring_events(
    db: &Db,
    caller: &Caller,
    disclosure: &mut ActorDisclosure,
    selected: &EventRow,
    event_seq: i64,
) -> Result<Vec<Value>> {
    // Scoped to the exact run. A neighbour from a different run is not what
    // "this run was in the middle of" means.
    let Some(run_key) = selected.run_key.as_deref() else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor, run_key, parent_key, intent, created_at,
                causal_envelope_version, causal_status,
                (SELECT json_group_array(parent_event_id)
                   FROM content_event_causal_frontier
                  WHERE event_id = content_events.id) AS causal_frontier
           FROM content_events
          WHERE run_key = ? AND id <> ?
            AND seq BETWEEN ? AND ?
          ORDER BY seq",
    )
    .bind(run_key)
    .bind(&selected.id)
    .bind(event_seq - NEIGHBOUR_WINDOW)
    .bind(event_seq + NEIGHBOUR_WINDOW)
    .fetch_all(db.write_pool())
    .await?;
    let mut events = Vec::new();
    for row in rows.iter() {
        let mut event = event_row(row)?;
        if !can_record(db, caller, &event.record_id, Capability::View).await? {
            continue;
        }
        if !event_is_visible(db, caller, &event).await? {
            continue;
        }
        redact_event(db, caller, disclosure, &mut event).await?;
        events.push(event);
    }
    let names = crate::mcp::tools::history::resolve_actor_names(db, &events).await;
    Ok(events
        .iter()
        .map(|event| event_to_value(event, &names))
        .collect())
}

struct ConsultedEvidence {
    status: EvidenceStatus,
    records: Vec<Value>,
    surfaced_only: i64,
}

impl ConsultedEvidence {
    fn unavailable() -> Self {
        ConsultedEvidence {
            status: EvidenceStatus::Unavailable,
            // Empty because there is nothing to show, NOT because nothing was
            // opened. The status is what distinguishes those.
            records: Vec::new(),
            surfaced_only: 0,
        }
    }
}

/// The bounded consulted-record scan.
///
/// Scope, narrowest first:
/// 1. the same exact run — a sibling run's reads are not this run's context;
/// 2. successful calls only — a failed read consulted nothing;
/// 3. calls that ENDED at or before the selected event was created (read-log
///    and content sequences are independent counters, so this compares
///    timestamps and never sequences across tiers);
/// 4. the active intent episode, when a preceding `set_intent` boundary exists.
async fn consulted_context(
    db: &Db,
    caller: &Caller,
    run_key: &str,
    event_created_at: &str,
    event_record_id: &str,
) -> Result<ConsultedEvidence> {
    // Absence of the disposable read log is not "nothing was opened".
    let log_present: Option<i64> = sqlx::query_scalar("SELECT 1 FROM read_log_calls LIMIT 1")
        .fetch_optional(db.write_pool())
        .await?;
    if log_present.is_none() {
        return Ok(ConsultedEvidence::unavailable());
    }

    let episode_start_seq: Option<i64> = sqlx::query_scalar(
        "SELECT seq FROM read_log_calls
          WHERE run_key = ? AND tool = 'set_intent' AND outcome = 'ok'
            AND intent IS NOT NULL AND ended_at <= ?
          ORDER BY ended_at DESC, seq DESC LIMIT 1",
    )
    .bind(run_key)
    .bind(event_created_at)
    .fetch_optional(db.write_pool())
    .await?;

    let rows = sqlx::query(
        "SELECT touch.record_id AS record_id,
                touch.interaction AS interaction,
                MAX(call.ended_at) AS last_at
           FROM read_log_calls call
           JOIN read_log_touches touch ON touch.call_seq = call.seq
          WHERE call.run_key = ?
            AND call.outcome = 'ok'
            AND call.ended_at <= ?
            AND (?3 IS NULL OR call.seq > ?3)
          GROUP BY touch.record_id, touch.interaction
          ORDER BY last_at DESC, touch.record_id",
    )
    .bind(run_key)
    .bind(event_created_at)
    .bind(episode_start_seq)
    .fetch_all(db.write_pool())
    .await?;

    // De-duplicate per record, keeping the LATEST open time. A record opened
    // three times is one consulted record, not three.
    let mut opened: Vec<(String, String)> = Vec::new();
    let mut surfaced_only_ids: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for row in rows.iter() {
        let record_id: String = row.try_get("record_id")?;
        let interaction: String = row.try_get("interaction")?;
        let last_at: String = row.try_get("last_at")?;
        match interaction.as_str() {
            "opened" => {
                if !opened.iter().any(|(id, _)| id == &record_id) {
                    opened.push((record_id, last_at));
                }
            }
            "surfaced" => {
                surfaced_only_ids.insert(record_id);
            }
            // A mutation is the run's own writing, not something it consulted.
            _ => {}
        }
    }
    // A record that was opened is not merely surfaced, whatever else the log
    // also recorded about it.
    surfaced_only_ids.retain(|id| !opened.iter().any(|(opened_id, _)| opened_id == id));

    let total_opened = opened.len();
    let mut records = Vec::new();
    let mut filtered_any = false;
    for (record_id, last_at) in opened {
        if records.len() >= MAX_CONSULTED {
            break;
        }
        // The deep-link grants no additional read authority. A hidden record is
        // omitted WITHOUT disclosing that it existed.
        if !can_record(db, caller, &record_id, Capability::View).await? {
            filtered_any = true;
            continue;
        }
        let display = sqlx::query("SELECT name, type, kind FROM records WHERE id = ?")
            .bind(&record_id)
            .fetch_optional(db.write_pool())
            .await?;
        let (name, record_type, kind) = match display {
            Some(row) => (
                row.try_get::<Option<String>, _>("name")?,
                row.try_get::<Option<String>, _>("type")?,
                row.try_get::<Option<String>, _>("kind")?,
            ),
            None => (None, None, None),
        };
        records.push(json!({
            "record_id": record_id,
            "name": name,
            "type": record_type,
            "kind": kind,
            "last_opened_at": last_at,
            "interaction": "opened",
            // Labelled rather than silently removed: "the run opened the very
            // record it then wrote to" is itself informative.
            "is_event_target": record_id == event_record_id,
        }));
    }

    let mut surfaced_only = 0;
    for record_id in surfaced_only_ids {
        if can_record(db, caller, &record_id, Capability::View).await? {
            surfaced_only += 1;
        } else {
            filtered_any = true;
        }
    }

    let status = if filtered_any || total_opened > MAX_CONSULTED {
        EvidenceStatus::Partial
    } else {
        EvidenceStatus::Available
    };
    Ok(ConsultedEvidence {
        status,
        records,
        surfaced_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(event_type: &str, payload: Option<&str>) -> EventRow {
        EventRow {
            local_seq: 1,
            id: "e1".into(),
            record_id: "r1".into(),
            event_type: event_type.into(),
            payload: payload.map(str::to_owned),
            actor: None,
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: "2026-08-19T00:00:00.000Z".into(),
            causal_envelope: crate::events::CausalEnvelopeV1::complete(
                crate::events::CausalFrontierV1::empty(),
            ),
        }
    }

    #[test]
    fn creation_always_produces_a_body_revision() {
        assert!(is_body_producing(&event("record.created", Some("{}"))));
    }

    #[test]
    fn an_update_without_a_body_key_is_not_a_body_revision() {
        assert!(!is_body_producing(&event(
            "record.updated",
            Some(r#"{"name":"renamed"}"#)
        )));
        assert!(is_body_producing(&event(
            "record.updated",
            Some(r#"{"body":"new"}"#)
        )));
    }

    #[test]
    fn a_link_event_is_not_a_body_revision() {
        assert!(!is_body_producing(&event("link.added", Some("{}"))));
    }

    #[test]
    fn unavailable_is_not_an_empty_available_list() {
        let evidence = ConsultedEvidence::unavailable();
        assert_eq!(evidence.status.as_str(), "unavailable");
        assert!(evidence.records.is_empty());
        assert_ne!(
            EvidenceStatus::Available.as_str(),
            EvidenceStatus::Unavailable.as_str(),
            "an absent read log must never render as 'no records opened'"
        );
    }
}
