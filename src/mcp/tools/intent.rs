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
use super::lifecycle::SOURCE_BASIS_FORMAT;
use super::work::work_overlap_for_record;
use super::{can_record, parse_args};

const DECLARATION_LIMIT: usize = 10;
const TOUCHED_LIMIT: usize = 20;
const NON_TERMINAL_LIMIT: usize = 20;
const UNCLASSIFIED_LIFECYCLE_LIMIT: usize = 20;
const CLAIM_LIMIT: usize = 20;
const CLAIM_CANDIDATE_LIMIT: usize = 100;
/// Anchors named in `overlapping_claims.items`: open claims first, then
/// retained action touches and declared sources, deduplicated.
const OVERLAP_ANCHOR_CAP: usize = 10;

// The briefing version describes the compatible response family. New bounded
// sections are additive within a version; bump it when an existing field's
// meaning or shape changes. v2 changed the meaning of a declaration's
// `touched_records`: it now folds DECLARED sources from content events rather
// than touched records from the read log, and its item shape changed to match
// (declaring `reason`/`role`/revision bearing, no `interactions` count). The
// key and bounded `{items,total_count,truncated}` wrapper are unchanged, and
// `resume.touched_records` remains a run-level list of retained touches. Its
// observational tier is partial once capture filtering begins.
const BRIEFING_VERSION: u8 = 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetIntentArgs {
    intent: String,
    /// Optional self-declared model name: the model's own claim about which
    /// model is running this turn. Free prose, stored exactly as given —
    /// never normalised against a model list — and fixed for the run.
    #[serde(default)]
    model: Option<String>,
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
        "overlapping_claims": json!({
            "items": [],
            "total_count": 0,
            "truncated": false,
        }),
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
        "declared_model": {
            "declared": args.model,
            "recorded": Value::Null,
            "refused": false,
            "note": "This backend does not stamp run identity, so a declared model is carried but nothing is recorded. Declare `model` on the first set_intent call of runs admitted by the qualified backend instead. A declaration is the model's own unverified claim, fixed per run, and grants no capability.",
        },
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
           JOIN read_log_record_ids d ON d.record_ref = t.record_ref
           JOIN records r ON r.id = d.record_id
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

/// The declared source basis folded per intent episode, from canonical
/// content-event envelopes — never from the disposable read log.
///
/// Each episode keeps the `touched_records` key and its bounded
/// `{items, total_count, truncated}` shape, but the items are the records
/// this run's writes in that episode DECLARED they rested on
/// (`native.source-basis.v1` on the write event — `record.created`, the
/// body-bearing `record.updated`, or the first facet event of an update call,
/// exactly the placement the `reason` key follows), not the records the run
/// merely touched. An item carries the declaring detail
/// the old touch summary has room for — the declared `reason`, `role` and
/// revision bearing — and `last_touched_at` is the last declaring write in
/// the episode. There is no `interactions` count: touches were not consulted,
/// and a zeroed count would claim a measurement that never happened.
///
/// Scope is temporal, mirroring `consulted_context`'s cross-tier rule:
/// `read_log_calls.seq` and `content_events.seq` are unrelated counters, so
/// episodes are windows over `created_at` between one declaration's
/// `ended_at` and the next — never sequence comparisons across tiers, and
/// never grouping by intent text, which cannot tell two episodes apart when
/// the same aim is declared twice.
///
/// The window is HALF-OPEN: the lower edge (`after_ended_at`, this
/// declaration's `ended_at`) is inclusive, the upper edge (`before_ended_at`,
/// the next declaration's `ended_at`) is exclusive. A write stamped exactly
/// at the next declaration's response time therefore belongs only to the new
/// episode, never to both, so adjacent windows cannot double-count it.
async fn declared_sources_between(
    db: &Db,
    caller: &Caller,
    run_key: &str,
    after_ended_at: &str,
    before_ended_at: Option<&str>,
    limit: usize,
) -> Result<Value> {
    let rows = sqlx::query(
        "SELECT id, payload, created_at FROM content_events
          WHERE run_key = ? AND created_at >= ? AND (?3 IS NULL OR created_at < ?3)
          ORDER BY created_at DESC, id DESC",
    )
    .bind(run_key)
    .bind(after_ended_at)
    .bind(before_ended_at)
    .bind(before_ended_at)
    .fetch_all(db.write_pool())
    .await?;
    // De-duplicate per record, keeping the LATEST declaring write. A record
    // cited three times in one episode is one declared source, not three.
    let mut latest: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for row in rows.iter() {
        let created_at: String = row.try_get("created_at")?;
        let payload_raw: Option<String> = row.try_get("payload")?;
        let Some(payload_raw) = payload_raw.as_deref() else {
            continue;
        };
        let Ok(payload) = serde_json::from_str::<Value>(payload_raw) else {
            continue;
        };
        let Some(envelope) = payload.get("basis") else {
            continue;
        };
        let is_v1 = envelope.as_object().is_some_and(|object| {
            object.get("format").and_then(Value::as_str) == Some(SOURCE_BASIS_FORMAT)
        });
        if !is_v1 {
            continue;
        }
        let Some(declared) = envelope.get("sources").and_then(Value::as_array) else {
            continue;
        };
        for entry in declared {
            let Some(record_id) = entry.get("record_id").and_then(Value::as_str) else {
                continue;
            };
            if latest.contains_key(record_id) {
                continue;
            }
            let field = |key: &str| {
                entry
                    .get(key)
                    .and_then(Value::as_str)
                    .map_or(Value::Null, |value| json!(value))
            };
            latest.insert(
                record_id.to_string(),
                json!({
                    "record_id": record_id,
                    "last_touched_at": created_at,
                    "reason": field("reason"),
                    "role": field("role"),
                    "revision_event_id": field("revision_event_id"),
                    "revision_supplied_by": field("revision_supplied_by"),
                }),
            );
        }
    }
    let mut items = Vec::new();
    for (record_id, mut item) in latest {
        // The deep-link rule applies here too: a hidden source is omitted
        // WITHOUT disclosing that it existed — not even in `total_count`.
        if !can_record(db, caller, &record_id, Capability::View).await? {
            continue;
        }
        let display: Option<(String, String, Option<String>)> =
            sqlx::query_as("SELECT name, type, lifecycle FROM records WHERE id = ?")
                .bind(&record_id)
                .fetch_optional(db.write_pool())
                .await?;
        let Some((name, record_type, lifecycle)) = display else {
            continue;
        };
        item.as_object_mut()
            .expect("declared item is an object")
            .insert("id".into(), Value::String(record_id));
        item.as_object_mut()
            .expect("declared item is an object")
            .insert("name".into(), Value::String(name));
        item.as_object_mut()
            .expect("declared item is an object")
            .insert("type".into(), Value::String(record_type));
        item.as_object_mut()
            .expect("declared item is an object")
            .insert(
                "lifecycle".into(),
                lifecycle.map_or(Value::Null, Value::String),
            );
        // `record_id` was the fold key; `id` is the shape's key. Both name
        // the same record, and the shape keeps exactly one.
        item.as_object_mut()
            .expect("declared item is an object")
            .shift_remove("record_id");
        items.push(item);
    }
    // Rows arrived most-recent-first and `BTreeMap` iteration is by record
    // id, so restore recency order explicitly: the episode's latest declared
    // source reads first, as touches did.
    items.sort_by(|left, right| {
        right
            .get("last_touched_at")
            .and_then(Value::as_str)
            .cmp(&left.get("last_touched_at").and_then(Value::as_str))
            .then_with(|| {
                left.get("id")
                    .and_then(Value::as_str)
                    .cmp(&right.get("id").and_then(Value::as_str))
            })
    });
    let total = items.len();
    Ok(bounded(items, total, limit))
}

async fn declarations(
    db: &Db,
    caller: &Caller,
    run_key: &str,
    pending: Option<(&str, &str)>,
) -> Result<Value> {
    let rows = sqlx::query(
        "SELECT seq, intent, started_at, ended_at
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
        // The episode this declaration opens runs from its response time to
        // the next declaration's response time. `ended_at` carries the
        // boundary; `started_at` is only the fallback a missing stamp would
        // need, since an unbounded lower edge would misattribute the whole
        // run's earlier writes into this episode.
        let started_at: String = row.try_get("started_at")?;
        let ended_at: Option<String> = row.try_get("ended_at")?;
        let lower = ended_at.as_deref().unwrap_or(&started_at);
        let before: Option<String> = rows
            .get(index + 1)
            .map(|next| {
                next.try_get::<Option<String>, _>("ended_at")
                    .map(|ended| ended.or_else(|| next.try_get::<String, _>("started_at").ok()))
            })
            .transpose()?
            .flatten();
        items.push(json!({
            "intent": row.try_get::<String, _>("intent")?,
            "declared_at": started_at,
            "touched_records": declared_sources_between(db, caller, run_key, lower, before.as_deref(), TOUCHED_LIMIT).await?,
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
           JOIN read_log_record_ids d ON d.record_ref = t.record_ref
           JOIN records r ON r.id = d.record_id
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
        "touched_records_completeness": "retained_rows_only",
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

/// Neighbouring claims around the records this briefing already names:
/// the caller's open claims first, then retained action touches and declared
/// sources, deduplicated, in that order. Each anchor with a non-empty window
/// is named with its window; unlike the claim-time notice the anchor ITSELF
/// is folded in as a `same_record` item when another holder claims it, so a
/// run that walked straight into someone else's claim sees it here.
///
/// The cap bounds only the emitted items: every anchor's window is computed
/// so `total_count` stays the exact number of anchors with a non-empty
/// overlap and `truncated` means precisely that more anchors than the cap had
/// overlap. Always present, even when empty — an additive section inside
/// briefing v1, so no version bump.
async fn overlapping_claims(db: &Db, caller: &Caller, open: &Value) -> Result<Value> {
    let mut anchors: Vec<String> = open
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if let Some(run_key) = caller.run_key() {
        // Capture omits pure reads. Preserve anchors from retained action
        // touches, including undeclared mutations, and add the sources this
        // run's writes declared across its episodes.
        let retained = touched_between(db, caller, run_key, -1, None, TOUCHED_LIMIT).await?;
        let declared =
            declared_sources_between(db, caller, run_key, "", None, TOUCHED_LIMIT).await?;
        for section in [&retained, &declared] {
            for item in section
                .get("items")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(id) = item.get("id").and_then(Value::as_str) {
                    if !anchors.iter().any(|anchor| anchor == id) {
                        anchors.push(id.to_string());
                    }
                }
            }
        }
    }
    let mut items = Vec::new();
    let mut total_count = 0usize;
    for anchor in &anchors {
        let Some(window) = work_overlap_for_record(db, caller, anchor, true).await? else {
            continue;
        };
        total_count += 1;
        if items.len() < OVERLAP_ANCHOR_CAP {
            items.push(json!({ "record_id": anchor, "overlap": window }));
        }
    }
    Ok(json!({
        "items": items,
        "total_count": total_count,
        "truncated": total_count > OVERLAP_ANCHOR_CAP,
    }))
}

async fn briefing_from_log(db: &Db, caller: &Caller, intent: &str) -> Result<Value> {
    let Some(run_key) = caller.run_key() else {
        return Ok(unavailable_briefing("run_context_unavailable"));
    };
    let declared_at = crate::mcp::interactions::timestamp();
    let open = open_claims(db, caller).await?;
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
        "open_claims": open,
        "overlapping_claims": overlapping_claims(db, caller, &open).await?,
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
    let declared_model = declared_model(&db, &caller, args.model).await;
    Ok(json!({
        "accepted_intent": args.intent,
        "briefing_version": BRIEFING_VERSION,
        "briefing": briefing(&db, &caller, &args.intent).await,
        "declared_model": declared_model,
    }))
}

/// Honesty paragraph shared by every declared-model response note. It names
/// the real beneficiary, states both limits (per-run fixity and no better
/// source coming), and claims no benefit that is not true: the value grants
/// no capability and does not affect routing, permission, gating or rendering
/// priority.
const DECLARED_MODEL_ABOUT: &str = "Declare once, on the first set_intent of the run: the first declaration wins and a later differing one is refused, while repeating the recorded value is harmless. The value is the model's own unverified claim about itself, fixed per run — a mid-run model switch leaves it naming the earlier model — and no launcher-independent source will correct it. It grants no capability and does not affect routing, permission, gating or rendering priority; it exists so a future reader attributing this run's work to a model, person or agent, has the claim on record.";

fn declared_model_note(sentence: String) -> String {
    format!("{sentence} {DECLARED_MODEL_ABOUT}")
}

/// Confirmation of what this response actually records for the run's
/// self-declared model: what this call declared, what the run has recorded,
/// and whether this call's declaration was refused.
///
/// A refusal is response-level, never a failed call: the intent declaration
/// still lands and the briefing is still returned, because an unverified
/// value must never decide whether the declaration itself succeeds. What the
/// refusal costs the claim is exactly what it says — the recorded model is
/// unchanged — and the response is where the caller is told.
///
/// This handler runs before the governed wrapper persists the declaration, so
/// the confirmation is computed optimistically — and it is exact on every
/// path where the response survives: on an existing run persistence never
/// touches the model, so the pre-read stored value is the post-call one; on
/// a new run admission stamps exactly the clamped declaration. A read failure
/// degrades to the same optimism: anything that breaks the read breaks
/// persistence too, and a failed call carries no confirmation.
async fn declared_model(db: &Db, caller: &Caller, declared: Option<String>) -> Value {
    let Some(run_key) = caller.run_key() else {
        return json!({
            "declared": declared,
            "recorded": Value::Null,
            "refused": false,
            "note": declared_model_note(
                "No run context on this call, so nothing is recorded.".into(),
            ),
        });
    };
    let clamped = crate::control::ReportedRunIdentity {
        model: declared.clone(),
        ..Default::default()
    }
    .clamped()
    .model;
    let stored: Option<Option<String>> =
        crate::control::read_agent_run_reported_identity(db, run_key)
            .await
            .ok()
            .flatten()
            .map(|identity| identity.model);
    match stored {
        Some(recorded) => {
            let (sentence, refused) = match &recorded {
                Some(recorded) => {
                    let repeated = declared.as_deref() == Some(recorded.as_str());
                    let refused = declared.is_some() && !repeated;
                    let mut sentence = format!(
                        "This run already records declared model '{recorded}'."
                    );
                    if refused {
                        sentence.push_str(&format!(
                            " The declaration of '{}' is refused and the recorded model is unchanged. This call's intent is still recorded and its briefing still returned.",
                            declared.as_deref().unwrap_or_default()
                        ));
                    } else if declared.is_some() {
                        sentence.push_str(
                            " The repeated declaration matches, so this call succeeds unchanged.",
                        );
                    }
                    (sentence, refused)
                }
                None => match declared {
                    Some(_) => (
                        "This run records no declared model: none was declared on the call that admitted it, and a later declaration cannot be recorded. The declaration is refused; this call's intent is still recorded normally. Declare 'model' on the first set_intent call of the run."
                            .into(),
                        true,
                    ),
                    None => (
                        "This run records no declared model: none was declared on the call that admitted it, and a later declaration cannot be recorded."
                            .into(),
                        false,
                    ),
                },
            };
            json!({
                "declared": declared,
                "recorded": recorded,
                "refused": refused,
                "note": declared_model_note(sentence),
            })
        }
        None => {
            let sentence = match clamped.clone() {
                Some(model) => format!("Recorded '{model}' as this run's declared model."),
                None => "No model was declared on this call, so this run records none; a later call cannot add one."
                    .into(),
            };
            json!({
                "declared": declared,
                "recorded": clamped,
                "note": declared_model_note(sentence),
                "refused": false,
            })
        }
    }
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
         Optionally self-declare the running model with `model`: a free-form name recorded once, at run admission, \
         so a future reader attributing this work has the claim on record. \
         The first declaration wins — a later differing one is refused, while repeating the recorded value is harmless. \
         A self-declaration is the model's own unverified claim, fixed per run, and grants nothing. \
         Finish the durable activity explicitly with close_run.",
        json!({
            "type": "object",
            "properties": {
                "intent": {
                    "type": "string",
                    "description": "Free prose describing what this run is trying to accomplish."
                },
                "model": {
                    "type": "string",
                    "description": "Optional self-declared model name for this run (for example the model running this turn). Stored exactly as given up to 256 bytes — never normalised against a list — and fixed for the run: the first declaration wins and a later differing one is refused. Unverified and per-run: it says which model claimed the run at admission, grants no capability, and does not affect routing, permission, gating or rendering priority."
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
