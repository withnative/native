//! `get_event_context` — what one exact moment in a run looked like.
//!
//! # The question this answers
//!
//! A comment byline deep-links to the event that produced the utterance being
//! read. Opening that link should let a reader see the exact comment-producing
//! event, what the run said it was trying to do at that moment, the writes
//! around it, the exact change made, and any retained evidence of records the
//! run opened beforehand.
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
//! Selective capture makes the consulted list partial whenever old opens
//! survive. Ordinary new reads create no row, so an empty list is unavailable
//! evidence, never proof that the run opened nothing. Two additional limits
//! are called out explicitly:
//!
//! - The read log is **disposable operational evidence**, not canonical
//!   history. If it is absent or a query fails, the answer is `unavailable` —
//!   never an empty list, which a reader would correctly interpret as "this run
//!   opened nothing".
//! - Visibility filtering and the eight-record bound can further truncate a
//!   partial list; neither grants inference about unretained opens.
//!
//! A deep-link grants no read authority. Every returned record passes the
//! viewer's ordinary visibility check, and redaction behaves exactly as it does
//! on the ordinary history surface.
//!
//! # What "basis" does and does not mean
//!
//! Beside the observed `consulted` evidence sits the run's own `basis`
//! declaration, read from the selected event's `native.source-basis.v1`
//! envelope: `declared` with sources, `declared_none` with an empty list, and
//! `not_declared` with an empty list. The three never collapse into each other.
//! A declaration is an authored claim of use, never verified use — hence the
//! `basis_is_declared_not_verified` interpretation limit, and hence the label
//! honestly saying "Sources" where the consulted panel must not. The
//! opened-does-not-establish-comprehension limit describes observed opens only
//! and is not applied to declarations.

use serde_json::{json, Value};
use sqlx::Row;

use super::history::{event_is_visible, event_to_value, redact_event, ActorDisclosure};
use super::lifecycle::SOURCE_BASIS_FORMAT;
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
/// A declared source basis is an authored claim of use, never verified use.
/// This limit travels with the `basis` block only; the opened/comprehension
/// limit above describes observed opens and is not applied to declarations.
pub const LIMIT_BASIS_DECLARED_NOT_VERIFIED: &str = "basis_is_declared_not_verified";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GetEventContextArgs {
    /// The IMMUTABLE event id. Sequence orders and displays; it does not
    /// address, because a database-local counter is not a durable address.
    event_id: String,
}

/// Consulted-evidence completeness. Selective capture means retained opens
/// can only establish partial evidence; none means unavailable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EvidenceStatus {
    Partial,
    Unavailable,
}

impl EvidenceStatus {
    fn as_str(self) -> &'static str {
        match self {
            EvidenceStatus::Partial => "partial",
            EvidenceStatus::Unavailable => "unavailable",
        }
    }
}

pub fn register_event_context_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::GetEventContext,
        "One moment in a run, addressed by immutable event id: the selected event, the intent in force at that event rather than the run's latest intent, the exact before/after body delta that event itself produced (correct even after later edits), neighbouring events in the same run, and any retained records the run opened beforehand. Read capture is now selective: consulted evidence is partial when retained opens exist and unavailable when none survive; an empty list never proves that nothing was opened. A sibling basis block reports the run's own declared source basis from the selected event's native.source-basis.v1 envelope as declared, declared_none or not_declared; a declaration is an authored claim, never verified use. Raw tool arguments and query text are never returned, and the link grants no read authority beyond the viewer's ordinary visibility.",
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
                causal_envelope_version, causal_status, act,
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
    let event_record_id = selected.record_id.clone();
    let event_seq = selected.local_seq;

    let delta = body_delta(&db, &event_record_id, &selected).await?;

    // The basis is read from the CANONICAL payload, before redaction nulls
    // `_id` keys the viewer may not see. Visibility is enforced per source
    // below instead, so a hidden source is omitted whole — reason included —
    // rather than leaked field by field through the redacted echo.
    let canonical_payload = selected.payload.clone();

    let mut disclosure = ActorDisclosure::default();
    redact_event(&db, &caller, &mut disclosure, &mut selected).await?;
    // The generic redaction nulls `_id` keys the viewer may not see but keeps
    // the surrounding prose — right for bodies, wrong for a structured basis
    // entry, where a surviving `reason`/`role` beside a nulled id still
    // discloses that a hidden source was cited and why. Entries no viewer may
    // show are removed whole from the echo below; the sibling `basis` block
    // above already reports their absence as `partial`.
    scrub_hidden_basis_entries(&db, &caller, &mut selected).await?;
    // The run block, the consulted scope and the neighbour scope must all
    // observe the REDACTED run key: for a caller outside the holder's
    // account the claim run is withheld exactly as on ordinary history,
    // so capture it only after redaction above.
    let event_run_key = selected.run_key.clone();
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

    let basis = basis_context(&db, &caller, &event_record_id, canonical_payload.as_deref()).await;

    let actor_names = if selected.actor.is_some() {
        crate::mcp::tools::history::resolve_actor_names(&db, std::slice::from_ref(&selected)).await
    } else {
        std::collections::HashMap::new()
    };

    // Run-level, read once for this request, and only for the run the redacted
    // event still names. The client software named itself at run start; it is
    // not an attestation, and it is not a per-event fact.
    let reported_client = match event_run_key.as_deref() {
        Some(run_key) => crate::control::read_agent_run_reported_identity(&db, run_key)
            .await?
            .and_then(crate::contribution::reported_client_facts),
        None => None,
    };

    let run = event_run_key.as_ref().map(|run_key| {
        let mut run = json!({
            "run_key": run_key,
            "agent_key": crate::runkey::agent_key_of(run_key),
            // The same disclaimer the contribution projection carries: a run
            // key groups calls, it does not identify a persistent agent.
            "assurance": "correlation_only",
        });
        if let Some(client) = &reported_client {
            run.as_object_mut()
                .expect("run correlation is an object")
                .insert("reported_mcp_client".into(), json!(client));
        }
        run
    });

    Ok(json!({
        "event": event_to_value(&selected, &actor_names),
        "run": run,
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
        "basis": {
            "label": "Sources",
            "status": basis.status,
            "completeness": basis.completeness,
            "sources": basis.sources,
        },
        "interpretation_limits": [
            LIMIT_OPENED_NOT_COMPREHENSION,
            LIMIT_CONSULTED_BOUNDED,
            LIMIT_CONSULTED_FILTERED,
            LIMIT_READ_LOG_BEST_EFFORT,
            LIMIT_BASIS_DECLARED_NOT_VERIFIED,
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
                causal_envelope_version, causal_status, act,
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
        // Neighbour payloads echo on the same response as the selected one,
        // so the same whole-entry basis scrub applies: generic redaction
        // alone would keep a hidden declared source's reason and role beside
        // its nulled id.
        scrub_hidden_basis_entries(db, caller, &mut event).await?;
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

    let episode_boundary: Option<(i64, String)> = sqlx::query_as(
        "SELECT seq, ended_at FROM read_log_calls
          WHERE run_key = ? AND tool = 'set_intent' AND outcome = 'ok'
            AND intent IS NOT NULL AND ended_at <= ?
          ORDER BY ended_at DESC, seq DESC LIMIT 1",
    )
    .bind(run_key)
    .bind(event_created_at)
    .fetch_optional(db.write_pool())
    .await?;
    // Response-time ordering, not insertion ordering: the synchronous
    // declaration path can sequence a `set_intent` row ahead of an earlier-
    // ended ordinary read whose queued capture lands later. Filtering by
    // `seq > boundary_seq` alone would then admit that pre-intent read as
    // episode evidence. Instead require the read to have begun at or after
    // the declaration ended; `seq <> boundary_seq` is identity exclusion of
    // the boundary row itself (which carries no touches), never a temporal
    // tie-break. Same-millisecond ties are a bounded ambiguity this
    // deliberately preserves: timestamps cannot establish chronology within
    // one millisecond across the direct and queued paths, so a read stamped
    // in the boundary millisecond is treated as episode evidence.
    let (episode_start_seq, episode_start_ended_at): (Option<i64>, Option<String>) =
        match &episode_boundary {
            Some((seq, ended_at)) => (Some(*seq), Some(ended_at.clone())),
            None => (None, None),
        };

    let rows = sqlx::query(
        "SELECT dictionary.record_id AS record_id,
                touch.interaction AS interaction,
                MAX(call.ended_at) AS last_at
           FROM read_log_calls call
           JOIN read_log_touches touch ON touch.call_seq = call.seq
           JOIN read_log_record_ids dictionary ON dictionary.record_ref = touch.record_ref
          WHERE call.run_key = ?
            AND call.outcome = 'ok'
            AND call.ended_at <= ?
            AND (?3 IS NULL OR (call.started_at >= ?3 AND call.seq <> ?4))
          GROUP BY dictionary.record_id, touch.interaction
          ORDER BY last_at DESC, dictionary.record_id",
    )
    .bind(run_key)
    .bind(event_created_at)
    .bind(episode_start_ended_at)
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

    let mut records = Vec::new();
    for (record_id, last_at) in opened {
        if records.len() >= MAX_CONSULTED {
            break;
        }
        // The deep-link grants no additional read authority. A hidden record is
        // omitted WITHOUT disclosing that it existed.
        if !can_record(db, caller, &record_id, Capability::View).await? {
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
        }
    }

    // Capture no longer retains ordinary reads. A legacy retained open is
    // useful evidence, but can never prove this list complete across the
    // policy transition. With none, report unavailable rather than silently
    // claiming that the run opened nothing.
    let status = if records.is_empty() && surfaced_only == 0 {
        EvidenceStatus::Unavailable
    } else {
        EvidenceStatus::Partial
    };
    Ok(ConsultedEvidence {
        status,
        records,
        surfaced_only,
    })
}

/// The run's own declared source basis, read from the selected event's
/// canonical payload envelope — never from the read log.
///
/// Three states, never collapsed: `declared` (a declaration exists; its
/// enumerable visible sources may still be empty when the stored list is
/// hidden or unreadable), `declared_none` (a stored empty array: the writer
/// said this rested on no Native record), and `not_declared` (no recognized
/// envelope at all). An
/// unrecognized envelope — an unknown format, a non-object, or no `basis` key
/// — reads as `not_declared` rather than being misread: only the v1 envelope
/// this binary writes is interpreted, so a newer format is never parsed as
/// v1. A recognized v1 envelope whose `sources` is missing or not an array is
/// a declaration this server cannot enumerate; it reads as `declared` with
/// `partial` completeness and no source lines, never as `not_declared`, which
/// would falsely report that nothing was declared.
struct BasisEvidence {
    status: &'static str,
    completeness: &'static str,
    sources: Vec<Value>,
}

impl BasisEvidence {
    fn not_declared() -> Self {
        BasisEvidence {
            status: "not_declared",
            // Empty because nothing was declared, not because something was
            // withheld. The status is what distinguishes those.
            completeness: "complete",
            sources: Vec::new(),
        }
    }
}

async fn basis_context(
    db: &Db,
    caller: &Caller,
    event_record_id: &str,
    canonical_payload: Option<&str>,
) -> BasisEvidence {
    let Some(raw) = canonical_payload else {
        return BasisEvidence::not_declared();
    };
    let Ok(payload) = serde_json::from_str::<Value>(raw) else {
        return BasisEvidence::not_declared();
    };
    let Some(envelope) = payload.get("basis") else {
        return BasisEvidence::not_declared();
    };
    // Forward compatibility gate: the envelope is only interpreted when it
    // names the format this binary writes. Anything else — a future version,
    // a mistyped key, a non-object — is left unread, never coerced.
    let is_v1 = envelope.as_object().is_some_and(|object| {
        object.get("format").and_then(Value::as_str) == Some(SOURCE_BASIS_FORMAT)
    });
    if !is_v1 {
        return BasisEvidence::not_declared();
    }
    // Recognized v1, so a declaration exists even if its source list cannot
    // be enumerated: report it as declared-but-partial, never not_declared.
    let Some(declared) = envelope.get("sources").and_then(Value::as_array) else {
        return BasisEvidence {
            status: "declared",
            completeness: "partial",
            sources: Vec::new(),
        };
    };
    if declared.is_empty() {
        return BasisEvidence {
            status: "declared_none",
            completeness: "complete",
            sources: Vec::new(),
        };
    }
    let mut sources = Vec::with_capacity(declared.len());
    let mut partial = false;
    for entry in declared {
        // An entry without a usable record id names nothing showable. It is
        // skipped without disclosure, exactly like a hidden source: the list
        // reports `partial` rather than pretending to be whole.
        let Some(record_id) = entry.get("record_id").and_then(Value::as_str) else {
            partial = true;
            continue;
        };
        // Fail closed: a visibility check that errors hides, and the list
        // reports `partial` rather than passing something unseen.
        if !can_record(db, caller, record_id, Capability::View)
            .await
            .unwrap_or(false)
        {
            partial = true;
            continue;
        }
        let display = sqlx::query("SELECT name, type, kind FROM records WHERE id = ?")
            .bind(record_id)
            .fetch_optional(db.write_pool())
            .await;
        let Ok(display) = display else {
            partial = true;
            continue;
        };
        let (name, record_type, kind) = match display {
            Some(row) => (
                row.try_get::<Option<String>, _>("name").ok().flatten(),
                row.try_get::<Option<String>, _>("type").ok().flatten(),
                row.try_get::<Option<String>, _>("kind").ok().flatten(),
            ),
            None => (None, None, None),
        };
        let field = |key: &str| {
            entry
                .get(key)
                .and_then(Value::as_str)
                .map_or(Value::Null, |value| json!(value))
        };
        sources.push(json!({
            "record_id": record_id,
            "name": name,
            "type": record_type,
            "kind": kind,
            "revision_event_id": field("revision_event_id"),
            "revision_supplied_by": field("revision_supplied_by"),
            "role": field("role"),
            "reason": field("reason"),
            // Labelled rather than silently removed: "the run read the very
            // record it then wrote to" is itself informative.
            "is_event_target": record_id == event_record_id,
        }));
    }
    BasisEvidence {
        status: "declared",
        completeness: if partial { "partial" } else { "complete" },
        sources,
    }
}

/// Remove hidden declared-source entries whole from a redacted payload echo.
///
/// Generic redaction is field-shaped: it nulls `_id` keys the viewer may not
/// see while keeping the surrounding prose. Applied to a structured basis
/// entry that leaves the `reason`/`role` of a hidden source beside its nulled
/// id — a disclosure the sibling `basis` block was built to prevent. Any
/// entry whose `record_id` is not a viewer-visible string is therefore
/// dropped entire, visible entries preserved byte-for-byte. The envelope
/// version is deliberately not gated: this removes unshowable entries from
/// whatever envelope carries them without interpreting version-specific
/// fields. Applied to the selected event AND every neighbouring event, since
/// both echo their payloads on the same response.
async fn scrub_hidden_basis_entries(db: &Db, caller: &Caller, event: &mut EventRow) -> Result<()> {
    let Some(raw) = event.payload.as_deref() else {
        return Ok(());
    };
    let Ok(payload) = serde_json::from_str::<Value>(raw) else {
        return Ok(());
    };
    let Some(entries) = payload
        .get("basis")
        .and_then(|envelope| envelope.get("sources"))
        .and_then(Value::as_array)
    else {
        return Ok(());
    };
    let mut kept = Vec::with_capacity(entries.len());
    for entry in entries {
        // Fail closed, as in `basis_context`: a visibility check that errors
        // hides, and the sibling block already reports `partial`.
        let visible = match entry.get("record_id").and_then(Value::as_str) {
            Some(record_id) => can_record(db, caller, record_id, Capability::View)
                .await
                .unwrap_or(false),
            None => false,
        };
        if visible {
            kept.push(entry.clone());
        }
    }
    if kept.len() != entries.len() {
        let mut redacted = payload;
        redacted["basis"]["sources"] = Value::Array(kept);
        event.payload = Some(serde_json::to_string(&redacted)?);
    }
    Ok(())
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
            act: None,
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
    fn unavailable_is_not_a_partial_list() {
        let evidence = ConsultedEvidence::unavailable();
        assert_eq!(evidence.status.as_str(), "unavailable");
        assert!(evidence.records.is_empty());
        assert_ne!(
            EvidenceStatus::Partial.as_str(),
            EvidenceStatus::Unavailable.as_str(),
            "an absent read log must never render as 'no records opened'"
        );
    }

    /// A pre-intent read whose queued capture lands after the synchronous
    /// declaration must not become episode evidence: insertion order (`seq`)
    /// no longer reflects response order across the direct and queued paths,
    /// so the boundary compares response-time `ended_at` first. Insert the
    /// declaration first (smaller `seq`, later `ended_at`), then the earlier-
    /// ended read (larger `seq`), and require the read to be excluded.
    #[tokio::test]
    async fn delayed_pre_intent_capture_is_not_episode_evidence() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let run_key = "scout-chair-a748b2";
        let record_id = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "consulted"}),
        )
        .await
        .unwrap();
        // Declaration responds (and inserts) second in time but first in seq.
        sqlx::query(
            "INSERT INTO read_log_calls
              (id, tool, run_key, outcome, intent, started_at, ended_at)
             VALUES ('decl-1', 'set_intent', ?, 'ok', 'episode two',
                     '2026-09-16T00:00:00.000Z', '2026-09-16T00:00:02.000Z')",
        )
        .bind(run_key)
        .execute(db.write_pool())
        .await
        .unwrap();
        // Ordinary read responds first but its queued capture inserts later.
        sqlx::query(
            "INSERT INTO read_log_calls
              (id, tool, run_key, outcome, started_at, ended_at)
             VALUES ('read-1', 'get_record', ?, 'ok',
                     '2026-09-16T00:00:00.000Z', '2026-09-16T00:00:01.000Z')",
        )
        .bind(run_key)
        .execute(db.write_pool())
        .await
        .unwrap();
        let read_seq: i64 =
            sqlx::query_scalar("SELECT seq FROM read_log_calls WHERE id = 'read-1'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let declaration_seq: i64 =
            sqlx::query_scalar("SELECT seq FROM read_log_calls WHERE id = 'decl-1'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert!(
            read_seq > declaration_seq,
            "fixture must invert seq vs response order: read_seq={read_seq} decl_seq={declaration_seq}"
        );
        sqlx::query("INSERT OR IGNORE INTO read_log_record_ids (record_id) VALUES (?)")
            .bind(&record_id)
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO read_log_touches (call_seq, record_ref, interaction, result_rank)
             VALUES (?, (SELECT record_ref FROM read_log_record_ids WHERE record_id = ?), 'opened', NULL)",
        )
        .bind(read_seq)
        .bind(&record_id)
        .execute(db.write_pool())
        .await
        .unwrap();

        let evidence = consulted_context(
            &db,
            &Caller::local(),
            run_key,
            "2026-09-16T00:00:03.000Z",
            &record_id,
        )
        .await
        .unwrap();
        assert!(
            evidence.records.is_empty(),
            "pre-intent read leaked into the episode: {:?}",
            evidence.records
        );
        db.close().await;
    }

    /// Same-millisecond ties are a bounded ambiguity this preserves: a read
    /// stamped in the boundary millisecond is treated as episode evidence,
    /// because timestamps cannot establish chronology within one millisecond
    /// across the direct and queued paths. This pins that choice so a future
    /// change to conservative exclusion fails loudly here instead of
    /// silently narrowing episode evidence.
    #[tokio::test]
    async fn boundary_millisecond_read_counts_as_episode_evidence() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let run_key = "scout-chair-a748b2";
        let record_id = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "consulted"}),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO read_log_calls
              (id, tool, run_key, outcome, intent, started_at, ended_at)
             VALUES ('decl-1', 'set_intent', ?, 'ok', 'episode two',
                     '2026-09-16T00:00:00.000Z', '2026-09-16T00:00:02.000Z')",
        )
        .bind(run_key)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO read_log_calls
              (id, tool, run_key, outcome, started_at, ended_at)
             VALUES ('read-1', 'get_record', ?, 'ok',
                     '2026-09-16T00:00:02.000Z', '2026-09-16T00:00:02.000Z')",
        )
        .bind(run_key)
        .execute(db.write_pool())
        .await
        .unwrap();
        let read_seq: i64 =
            sqlx::query_scalar("SELECT seq FROM read_log_calls WHERE id = 'read-1'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        sqlx::query("INSERT OR IGNORE INTO read_log_record_ids (record_id) VALUES (?)")
            .bind(&record_id)
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO read_log_touches (call_seq, record_ref, interaction, result_rank)
             VALUES (?, (SELECT record_ref FROM read_log_record_ids WHERE record_id = ?), 'opened', NULL)",
        )
        .bind(read_seq)
        .bind(&record_id)
        .execute(db.write_pool())
        .await
        .unwrap();

        let evidence = consulted_context(
            &db,
            &Caller::local(),
            run_key,
            "2026-09-16T00:00:03.000Z",
            &record_id,
        )
        .await
        .unwrap();
        assert_eq!(
            evidence.records.len(),
            1,
            "boundary-millisecond read should count as episode evidence: {:?}",
            evidence.records
        );
        assert_eq!(evidence.records[0]["record_id"], record_id);
        db.close().await;
    }
}
