//! MCP App launcher tools. Handlers compose authoritative reads and return
//! typed bootstrap payloads; the embedded TypeScript shells never replay
//! history or simulate suggestion writes.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::EventRow;

use super::super::apps::{RECORD_VERSION_DIFF_URI, SUGGESTION_REVIEW_URI};
use super::super::registry::{AppMetadata, Caller, ToolRegistry};
use super::super::ToolKind;
use super::{can_record, history::record_version_at, parse_args, require_record};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordVersionDiffArgs {
    record_id: String,
    before_seq: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuggestionReviewArgs {
    record_id: String,
}

async fn render_record_version_diff(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: RecordVersionDiffArgs = parse_args("render_record_version_diff", arguments)?;
    require_record(
        &db,
        &caller,
        "render_record_version_diff",
        &args.record_id,
        Capability::View,
    )
    .await?;
    if args.before_seq < 1 {
        return Err(Error::engine(
            "render_record_version_diff before_seq must be positive",
        ));
    }
    let current_seq: Option<i64> =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
            .bind(&args.record_id)
            .fetch_one(db.write_pool())
            .await?;
    let Some(current_seq) = current_seq else {
        return Err(Error::engine(format!(
            "record {} does not exist",
            args.record_id
        )));
    };
    if args.before_seq > current_seq {
        return Err(Error::engine(format!(
            "render_record_version_diff before_seq {} is after the record's current revision {}",
            args.before_seq, current_seq
        )));
    }
    let before = record_version_at(&db, &caller, &args.record_id, args.before_seq).await?;
    let after = record_version_at(&db, &caller, &args.record_id, current_seq).await?;
    let rows = sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor, run_key, parent_key, intent, created_at
           FROM content_events
          WHERE record_id = ? AND seq > ? AND seq <= ?
          ORDER BY seq",
    )
    .bind(&args.record_id)
    .bind(args.before_seq)
    .bind(current_seq)
    .fetch_all(db.write_pool())
    .await?;
    let mut events = Vec::with_capacity(rows.len());
    let mut actor_disclosure = super::history::ActorDisclosure::default();
    for row in rows {
        let mut event = EventRow {
            local_seq: row.try_get("seq")?,
            id: row.try_get("id")?,
            record_id: row.try_get("record_id")?,
            event_type: row.try_get("type")?,
            payload: row.try_get("payload")?,
            actor: row.try_get("actor")?,
            run_key: row.try_get("run_key")?,
            parent_key: row.try_get("parent_key")?,
            intent: row.try_get("intent")?,
            created_at: row.try_get("created_at")?,
            causal_envelope: crate::events::CausalEnvelopeV1::default(),
        };
        if !super::history::event_is_visible(&db, &caller, &event).await? {
            continue;
        }
        super::history::redact_event(&db, &caller, &mut actor_disclosure, &mut event).await?;
        events.push(event);
    }
    let actor_names = super::history::resolve_actor_names(&db, &events).await;
    let events = events
        .iter()
        .map(|event| super::history::event_to_value(event, &actor_names))
        .collect::<Vec<_>>();
    Ok(json!({
        "view": "record_version_diff",
        "record_id": args.record_id,
        "before": before,
        "after": after,
        "events": events,
    }))
}

async fn render_suggestion_review(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: SuggestionReviewArgs = parse_args("render_suggestion_review", arguments)?;
    require_record(
        &db,
        &caller,
        "render_suggestion_review",
        &args.record_id,
        Capability::View,
    )
    .await?;
    let row = sqlx::query(
        "SELECT id, name, type, body, last_activity_at, deleted_at
           FROM records WHERE id = ?",
    )
    .bind(&args.record_id)
    .fetch_optional(db.write_pool())
    .await?;
    let Some(row) = row else {
        return Err(Error::engine(format!(
            "record {} does not exist",
            args.record_id
        )));
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "record {} is deleted",
            args.record_id
        )));
    }
    let body: Option<String> = row.try_get("body")?;
    let current_seq: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
            .bind(&args.record_id)
            .fetch_one(db.write_pool())
            .await?;
    let body_digest = body
        .as_deref()
        .map(|value| hex::encode(Sha256::digest(value.as_bytes())));
    let body_is_null = body_digest.is_none();
    let suggestion = crate::query::suggestion_predicate("r");
    let suggestion_candidates_sql = format!(
        "SELECT DISTINCT r.id FROM records r
          JOIN links bearer ON bearer.source_id = r.id AND bearer.relationship = 'part_of'
          WHERE bearer.target_id = ? AND {suggestion}
            AND r.deleted_at IS NULL AND r.lifecycle = 'open'
          ORDER BY r.id"
    );
    let suggestion_candidates: Vec<String> = sqlx::query_scalar(&suggestion_candidates_sql)
        .bind(&args.record_id)
        .fetch_all(db.write_pool())
        .await?;
    let mut suggestion_count = 0i64;
    for suggestion_id in suggestion_candidates {
        if can_record(&db, &caller, &suggestion_id, Capability::View).await? {
            suggestion_count += 1;
        }
    }
    Ok(json!({
        "view": "suggestion_review",
        "target": {
            "id": row.try_get::<String, _>("id")?,
            "name": row.try_get::<String, _>("name")?,
            "type": row.try_get::<String, _>("type")?,
            "body": body,
            "current_seq": current_seq,
            "body_digest": body_digest,
            "body_is_null": body_is_null,
            "last_activity_at": row.try_get::<Option<String>, _>("last_activity_at")?,
        },
        "suggestion_count": suggestion_count,
    }))
}

pub fn register_history_app_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_app(
        ToolKind::RenderRecordVersionDiff,
        "Open a read-only App comparing one historical record revision with its current state. The prose fallback identifies both revisions for hosts without MCP Apps.",
        json!({
            "type": "object",
            "properties": {
                "record_id": { "type": "string" },
                "before_seq": { "type": "integer", "minimum": 1 }
            },
            "required": ["record_id", "before_seq"],
            "additionalProperties": false
        }),
        AppMetadata::model_and_app(RECORD_VERSION_DIFF_URI),
        render_record_version_diff,
    )
}

pub fn register_suggestion_app_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_app(
        ToolKind::RenderSuggestionReview,
        "Open an App for reviewing the open body suggestions under one target. The App stages locally, dry-runs the ordered selection, and commits once.",
        json!({
            "type": "object",
            "properties": { "record_id": { "type": "string" } },
            "required": ["record_id"],
            "additionalProperties": false
        }),
        AppMetadata::model_and_app(SUGGESTION_REVIEW_URI),
        render_suggestion_review,
    )
}
