//! `set_intent` and its bounded, structural tier-1 briefing.

use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::Result;
use crate::query::lifecycle::{LifecycleInterpretation, LifecycleInterpreter};
use crate::query::lineage;

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{can_record, parse_args};

const DECLARATION_LIMIT: usize = 10;
const TOUCHED_LIMIT: usize = 20;
const NON_TERMINAL_LIMIT: usize = 20;
const UNCLASSIFIED_LIFECYCLE_LIMIT: usize = 20;
const CLAIM_LIMIT: usize = 20;
const CLAIM_CANDIDATE_LIMIT: usize = 100;

// The briefing version describes the compatible response family. New bounded
// sections are additive within v1; bump it only when an existing field's
// meaning or shape changes.
const BRIEFING_VERSION: u8 = 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetIntentArgs {
    intent: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseRunArgs {}

fn bounded(items: Vec<Value>, total_count: usize, limit: usize) -> Value {
    json!({
        "items": items.into_iter().take(limit).collect::<Vec<_>>(),
        "total_count": total_count,
        "truncated": total_count > limit,
    })
}

fn empty_working_under() -> Value {
    json!({
        "items": [],
        "total_count": 0,
        "truncated": false,
        "end": null,
    })
}

fn unavailable_briefing(reason: &'static str) -> Value {
    json!({
        "availability": {
            "status": "unavailable",
            "reason": reason,
        },
        "this_run": { "declarations": bounded(Vec::new(), 0, DECLARATION_LIMIT) },
        "resume": null,
        "working_under": empty_working_under(),
        "open_claims": bounded(Vec::new(), 0, CLAIM_LIMIT),
    })
}

/// The deliberately bounded declaration response used by storage adapters
/// that have qualified durable run context but not the wider activity/briefing
/// family yet.
///
/// Persisting the declaration belongs to the governed request wrapper: it can
/// only happen after this handler succeeds, and it is keyed by the wrapper's
/// validated full run key rather than by untrusted handler arguments. The
/// empty briefing keeps this route honest while `set_intent` itself remains
/// unproved on those adapters.
#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) fn declare_without_activity_briefing(arguments: Value) -> Result<Value> {
    let args: SetIntentArgs = parse_args("set_intent", arguments)?;
    Ok(json!({
        "accepted_intent": args.intent,
        "briefing_version": BRIEFING_VERSION,
        "briefing": unavailable_briefing("backend_not_qualified"),
    }))
}

async fn read_log_available(db: &Db) -> bool {
    sqlx::query("SELECT 1 FROM read_log_calls LIMIT 1")
        .fetch_optional(db.write_pool())
        .await
        .is_ok()
}

fn record_summary(row: &sqlx::sqlite::SqliteRow) -> Result<Value> {
    Ok(json!({
        "id": row.try_get::<String, _>("id")?,
        "name": row.try_get::<String, _>("name")?,
        "type": row.try_get::<String, _>("type")?,
        "lifecycle": row.try_get::<Option<String>, _>("lifecycle")?,
        "interactions": {
            "surfaced": row.try_get::<i64, _>("surfaced")?,
            "opened": row.try_get::<i64, _>("opened")?,
            "mutated": row.try_get::<i64, _>("mutated")?,
        },
        "last_touched_at": row.try_get::<String, _>("last_touched_at")?,
    }))
}

async fn touched_between(
    db: &Db,
    caller: &Caller,
    run_key: &str,
    after_seq: i64,
    before_seq: Option<i64>,
    limit: usize,
) -> Result<Value> {
    let rows = sqlx::query(
        "SELECT r.id, r.name, r.type, r.lifecycle,
                SUM(CASE WHEN t.interaction = 'surfaced' THEN 1 ELSE 0 END) AS surfaced,
                SUM(CASE WHEN t.interaction = 'opened' THEN 1 ELSE 0 END) AS opened,
                SUM(CASE WHEN t.interaction = 'mutated' THEN 1 ELSE 0 END) AS mutated,
                MAX(c.ended_at) AS last_touched_at
           FROM read_log_calls c
           JOIN read_log_touches t ON t.call_seq = c.seq
           JOIN records r ON r.id = t.record_id
          WHERE c.run_key = ? AND c.seq > ? AND (? IS NULL OR c.seq < ?)
          GROUP BY r.id, r.name, r.type, r.lifecycle
          ORDER BY last_touched_at DESC, r.id",
    )
    .bind(run_key)
    .bind(after_seq)
    .bind(before_seq)
    .bind(before_seq)
    .fetch_all(db.write_pool())
    .await?;
    let mut visible_rows = Vec::new();
    for row in &rows {
        let id: String = row.try_get("id")?;
        if can_record(db, caller, &id, Capability::View).await? {
            visible_rows.push(row);
        }
    }
    let total = visible_rows.len();
    let items = visible_rows
        .into_iter()
        .take(limit)
        .map(record_summary)
        .collect::<Result<Vec<_>>>()?;
    Ok(bounded(items, total, limit))
}

async fn declarations(
    db: &Db,
    caller: &Caller,
    run_key: &str,
    pending: Option<(&str, &str)>,
) -> Result<Value> {
    let rows = sqlx::query(
        "SELECT seq, intent, started_at
           FROM read_log_calls
          WHERE run_key = ? AND tool = 'set_intent' AND outcome = 'ok'
            AND intent IS NOT NULL
          ORDER BY seq",
    )
    .bind(run_key)
    .fetch_all(db.write_pool())
    .await?;
    let total = rows.len() + usize::from(pending.is_some());
    let keep_from = total.saturating_sub(DECLARATION_LIMIT);
    let mut items = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if index < keep_from {
            continue;
        }
        let seq: i64 = row.try_get("seq")?;
        let before = rows
            .get(index + 1)
            .map(|next| next.try_get::<i64, _>("seq"))
            .transpose()?;
        items.push(json!({
            "intent": row.try_get::<String, _>("intent")?,
            "declared_at": row.try_get::<String, _>("started_at")?,
            "touched_records": touched_between(db, caller, run_key, seq, before, TOUCHED_LIMIT).await?,
        }));
    }
    if let Some((intent, declared_at)) = pending {
        items.push(json!({
            "intent": intent,
            "declared_at": declared_at,
            "touched_records": bounded(Vec::new(), 0, TOUCHED_LIMIT),
        }));
    }
    Ok(json!({
        "items": items,
        "total_count": total,
        "truncated": total > DECLARATION_LIMIT,
    }))
}

fn record_summary_with_reason(
    row: &sqlx::sqlite::SqliteRow,
    reason: &'static str,
) -> Result<Value> {
    let mut summary = record_summary(row)?;
    summary
        .as_object_mut()
        .expect("record_summary always returns an object")
        .insert("reason".into(), Value::String(reason.into()));
    Ok(summary)
}

async fn lifecycle_lists(db: &Db, caller: &Caller, run_key: &str) -> Result<(Value, Value)> {
    let rows = sqlx::query(
        "SELECT r.id, r.name, r.type, r.kind, r.home_id, r.lifecycle,
                SUM(CASE WHEN t.interaction = 'surfaced' THEN 1 ELSE 0 END) AS surfaced,
                SUM(CASE WHEN t.interaction = 'opened' THEN 1 ELSE 0 END) AS opened,
                SUM(CASE WHEN t.interaction = 'mutated' THEN 1 ELSE 0 END) AS mutated,
                MAX(c.ended_at) AS last_touched_at
           FROM read_log_calls c
           JOIN read_log_touches t ON t.call_seq = c.seq
           JOIN records r ON r.id = t.record_id
          WHERE c.run_key = ?
            AND r.deleted_at IS NULL
            AND r.lifecycle IS NOT NULL
            AND NOT EXISTS (
                SELECT 1 FROM facet_values f
                 WHERE f.record_id = r.id AND f.key = 'archived'
            )
          GROUP BY r.id, r.name, r.type, r.kind, r.home_id, r.lifecycle
          ORDER BY last_touched_at DESC, r.id",
    )
    .bind(run_key)
    .fetch_all(db.write_pool())
    .await?;

    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let lifecycle_interpreter = LifecycleInterpreter::load(db, principal).await?;
    let mut non_terminal = Vec::new();
    let mut unclassified = Vec::new();
    for row in &rows {
        let id: String = row.try_get("id")?;
        if !can_record(db, caller, &id, Capability::View).await? {
            continue;
        }
        let record_type: String = row.try_get("type")?;
        let kind: Option<String> = row.try_get("kind")?;
        let home_id: Option<String> = row.try_get("home_id")?;
        let lifecycle: String = row.try_get("lifecycle")?;
        match lifecycle_interpreter.interpret(
            &record_type,
            kind.as_deref(),
            home_id.as_deref(),
            Some(&lifecycle),
        ) {
            LifecycleInterpretation::Governed(governed) => {
                if governed.terminality == "open" {
                    non_terminal.push(record_summary(row)?);
                }
            }
            LifecycleInterpretation::Unclassified(unclassified_value) => {
                unclassified.push(record_summary_with_reason(row, unclassified_value.reason)?);
            }
            LifecycleInterpretation::Absent(_) => {}
        }
    }
    let non_terminal_total = non_terminal.len();
    let unclassified_total = unclassified.len();
    Ok((
        bounded(non_terminal, non_terminal_total, NON_TERMINAL_LIMIT),
        bounded(
            unclassified,
            unclassified_total,
            UNCLASSIFIED_LIFECYCLE_LIMIT,
        ),
    ))
}

async fn resume(db: &Db, caller: &Caller) -> Result<Value> {
    let Some(run_key) = caller.run_key() else {
        return Ok(Value::Null);
    };
    let agent_key = crate::runkey::agent_key_of(run_key);
    let row = sqlx::query(
        "SELECT run_key, MIN(started_at) AS started_at, MAX(ended_at) AS ended_at
           FROM read_log_calls
          WHERE actor = ? AND run_key <> ? AND run_key LIKE ?
          GROUP BY run_key
          ORDER BY ended_at DESC, run_key
          LIMIT 1",
    )
    .bind(caller.credential())
    .bind(run_key)
    .bind(format!("{agent_key}-%"))
    .fetch_optional(db.write_pool())
    .await?;
    let Some(row) = row else {
        return Ok(Value::Null);
    };
    let prior_key: String = row.try_get("run_key")?;
    let started_at: String = row.try_get("started_at")?;
    let ended_at: String = row.try_get("ended_at")?;
    let duration_ms = chrono::DateTime::parse_from_rfc3339(&ended_at)
        .ok()
        .zip(chrono::DateTime::parse_from_rfc3339(&started_at).ok())
        .map(|(end, start)| (end - start).num_milliseconds());
    let (left_non_terminal, unclassified_lifecycle) =
        lifecycle_lists(db, caller, &prior_key).await?;
    Ok(json!({
        "run_key": prior_key,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": duration_ms,
        "declarations": declarations(db, caller, &prior_key, None).await?,
        "touched_records": touched_between(db, caller, &prior_key, -1, None, TOUCHED_LIMIT).await?,
        "left_non_terminal": left_non_terminal,
        "unclassified_lifecycle": unclassified_lifecycle,
    }))
}

async fn working_under(db: &Db, run_key: &str, pending_intent: &str) -> Result<Value> {
    let lineage = lineage::lineage_walk(db, run_key).await?;
    let mut items = Vec::with_capacity(lineage.path.len());
    for key in &lineage.path {
        let intent = if key == run_key {
            Some(pending_intent.to_string())
        } else {
            crate::runkey::intent_at(db, Some(key)).await
        };
        items.push(json!({ "run_key": key, "intent": intent }));
    }
    Ok(json!({
        "items": items,
        "total_count": lineage.path.len(),
        "truncated": lineage.truncated,
        "end": lineage.end,
    }))
}

async fn open_claims(db: &Db, caller: &Caller) -> Result<Value> {
    let caller_agent_key = caller.run_key().and_then(|run_key| {
        matches!(
            crate::runkey::validate_full(Some(run_key)),
            crate::runkey::KeyOutcome::Valid(_)
        )
        .then(|| crate::runkey::agent_key_of(run_key))
    });
    // Account is the leading index column. Fetch one lookahead row so the
    // response can say that this finite candidate window, not only its 20-item
    // output page, truncated the briefing.
    let rows = sqlx::query(
        "SELECT id, name, type, claimed_at, claimed_run_key FROM records
          WHERE claimed_by_account = ? AND deleted_at IS NULL
          ORDER BY claimed_at DESC, id
          LIMIT ?",
    )
    .bind(caller.credential())
    .bind((CLAIM_CANDIDATE_LIMIT + 1) as i64)
    .fetch_all(db.write_pool())
    .await?;
    let candidate_truncated = rows.len() > CLAIM_CANDIDATE_LIMIT;
    let mut items = Vec::new();
    for row in rows.iter().take(CLAIM_CANDIDATE_LIMIT) {
        let claimant_key: Option<String> = row.try_get("claimed_run_key")?;
        if let Some(agent_key) = caller_agent_key {
            let Some(valid_claimant_key) = claimant_key.as_deref().filter(|key| {
                matches!(
                    crate::runkey::validate_full(Some(key)),
                    crate::runkey::KeyOutcome::Valid(_)
                )
            }) else {
                continue;
            };
            if crate::runkey::agent_key_of(valid_claimant_key) != agent_key {
                continue;
            }
        }
        let id: String = row.try_get("id")?;
        if !can_record(db, caller, &id, Capability::View).await? {
            continue;
        }
        items.push(json!({
            "id": id,
            "name": row.try_get::<String, _>("name")?,
            "type": row.try_get::<String, _>("type")?,
            "claimed_at": row.try_get::<String, _>("claimed_at")?,
            "run_key": claimant_key,
        }));
    }
    let total = items.len();
    Ok(json!({
        "items": items.into_iter().take(CLAIM_LIMIT).collect::<Vec<_>>(),
        "total_count": total,
        "truncated": candidate_truncated || total > CLAIM_LIMIT,
    }))
}

async fn briefing_from_log(db: &Db, caller: &Caller, intent: &str) -> Result<Value> {
    let Some(run_key) = caller.run_key() else {
        return Ok(unavailable_briefing("run_context_unavailable"));
    };
    let declared_at = crate::mcp::interactions::timestamp();
    Ok(json!({
        "availability": {
            "status": "available",
            "reason": null,
        },
        "this_run": {
            "declarations": declarations(db, caller, run_key, Some((intent, &declared_at))).await?,
        },
        "resume": resume(db, caller).await?,
        "working_under": working_under(db, run_key, intent).await?,
        "open_claims": open_claims(db, caller).await?,
    }))
}

async fn briefing(db: &Db, caller: &Caller, intent: &str) -> Value {
    if !read_log_available(db).await {
        return unavailable_briefing("read_log_unavailable");
    }
    briefing_from_log(db, caller, intent)
        .await
        .unwrap_or_else(|_| unavailable_briefing("briefing_failed"))
}

async fn set_intent(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: SetIntentArgs = parse_args("set_intent", arguments)?;
    Ok(json!({
        "accepted_intent": args.intent,
        "briefing_version": BRIEFING_VERSION,
        "briefing": briefing(&db, &caller, &args.intent).await,
    }))
}

async fn close_run(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let _: CloseRunArgs = parse_args("close_run", arguments)?;
    let run_key = caller.run_key().ok_or_else(|| {
        crate::error::Error::engine("close_run requires a validated full run key")
    })?;
    let lifecycle = crate::control::close_agent_run(&db, run_key, caller.credential()).await?;
    Ok(json!({
        "activity_id": lifecycle.activity_id,
        "started_at": lifecycle.started_at,
        "ended_at": lifecycle.ended_at,
        "changed": lifecycle.changed,
    }))
}

pub fn register_intent_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::SetIntent,
        "Declare this run's current intent and receive a bounded structural briefing. \
         Finish the durable activity explicitly with close_run.",
        json!({
            "type": "object",
            "properties": {
                "intent": {
                    "type": "string",
                    "description": "Free prose describing what this run is trying to accomplish."
                }
            },
            "required": ["intent"],
            "additionalProperties": false
        }),
        set_intent,
    )?;
    registry.register(
        ToolKind::CloseRun,
        "Explicitly close this run's durable activity lifecycle. Repeating the call is safe.",
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        close_run,
    )
}
