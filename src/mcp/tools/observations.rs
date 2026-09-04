//! Observation-only authoring and bounded valid-time series reads for open
//! facets. Current assertions remain owned by `create_record` / `update_record`.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::query::cascade;
use crate::store::{append_in, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::lifecycle::{
    assert_facet_value_predicates_in, assert_open_facet_key, parse_facet_entry,
};
use super::{
    parse_args, previous_record_seq_in, require_nonblank_reason, require_record, require_record_in,
    PREVIOUS_SEQ_DESCRIPTION, REASON_DESCRIPTION,
};

const DEFAULT_LIMIT: i64 = 200;
const MAX_LIMIT: i64 = 1_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageFacetObservationsArgs {
    Set {
        record_id: String,
        key: String,
        value: Value,
        vocab_ref: Option<String>,
        as_of: String,
        reason: String,
    },
    Unset {
        record_id: String,
        key: String,
        as_of: String,
        reason: String,
    },
    List {
        record_id: String,
        key: String,
        from_as_of: Option<String>,
        to_as_of: Option<String>,
        after_as_of: Option<String>,
        limit: Option<i64>,
    },
}

fn normalize_timestamp(tool: &str, field: &str, value: &str) -> Result<String> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| {
        Error::engine(format!(
            "{tool}: '{field}' must be an RFC3339 timestamp (for example 2026-08-01T09:30:00Z)"
        ))
    })?;
    Ok(parsed
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}

async fn record_shape_context_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> Result<(String, Option<String>)> {
    let row = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "manage_facet_observations: record {record_id} does not exist"
            ))
        })?;
    Ok((row.try_get("type")?, row.try_get("kind")?))
}

async fn write_observation(
    db: Db,
    caller: Caller,
    record_id: String,
    key: String,
    value: Option<(Value, Option<String>)>,
    as_of: String,
    reason: String,
) -> Result<Value> {
    const TOOL: &str = "manage_facet_observations";
    require_nonblank_reason(TOOL, &reason)?;
    let as_of = normalize_timestamp(TOOL, "as_of", &as_of)?;
    assert_open_facet_key(TOOL, &key)?;

    let mut facet = match value {
        Some((value, vocab_ref)) => {
            let entry = match vocab_ref {
                Some(vocab_ref) => json!({ "value": value, "vocab_ref": vocab_ref }),
                None => value,
            };
            Some(
                parse_facet_entry(TOOL, &key, &entry, false)?
                    .expect("observation set never parses as unset"),
            )
        }
        None => None,
    };

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    require_record_in(&mut tx, &caller, TOOL, &record_id, Capability::Edit).await?;
    let previous_seq = previous_record_seq_in(&mut tx, &record_id).await?;
    let (record_type, kind) = record_shape_context_in(&mut tx, &record_id).await?;
    if let Some(facet) = facet.as_mut() {
        let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
        assert_facet_value_predicates_in(
            &mut tx,
            &schema_rows,
            TOOL,
            &record_type,
            kind.as_deref(),
            None,
            std::slice::from_mut(facet),
        )
        .await?;
    }

    let (event_type, mut payload, status) = match facet {
        Some(facet) => {
            let mut payload = json!({
                "key": key,
                "value": facet.stored_value(),
                "as_of": as_of,
                "observation_only": true,
            });
            if let Some(vocab_ref) = facet.vocab_ref {
                payload["vocab_ref"] = json!(vocab_ref);
            }
            ("facet.set", payload, "set")
        }
        None => (
            "facet.unset",
            json!({
                "key": key,
                "as_of": as_of,
                "observation_only": true,
            }),
            "unset",
        ),
    };
    payload["reason"] = json!(reason);
    let event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: record_id.clone(),
            event_type: event_type.into(),
            payload,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(crate::domain_transaction::observation_write_response(
        status,
        &record_id,
        &key,
        &as_of,
        event.local_seq,
        previous_seq,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn list_observations(
    db: &Db,
    caller: &Caller,
    record_id: String,
    key: String,
    from_as_of: Option<String>,
    to_as_of: Option<String>,
    after_as_of: Option<String>,
    limit: Option<i64>,
) -> Result<Value> {
    const TOOL: &str = "manage_facet_observations";
    if key.is_empty() {
        return Err(Error::engine(format!("{TOOL}: 'key' must not be empty")));
    }
    let from_as_of = from_as_of
        .map(|value| normalize_timestamp(TOOL, "from_as_of", &value))
        .transpose()?;
    let to_as_of = to_as_of
        .map(|value| normalize_timestamp(TOOL, "to_as_of", &value))
        .transpose()?;
    // A keyset cursor is an opaque storage key, not a newly authored valid
    // time. Legacy databases may contain pre-surface values such as a
    // date-only `2026-07-01`; returning that exact key and accepting it back
    // unchanged is what makes every emitted cursor round-trippable.
    if matches!((&from_as_of, &to_as_of), (Some(from), Some(to)) if from > to) {
        return Err(Error::engine(format!(
            "{TOOL}: 'from_as_of' must be earlier than or equal to 'to_as_of'"
        )));
    }
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Error::engine(format!(
            "{TOOL}: 'limit' must be between 1 and {MAX_LIMIT}"
        )));
    }
    require_record(db, caller, TOOL, &record_id, Capability::View).await?;

    let rows = sqlx::query(
        "SELECT value, op, vocab_ref, as_of, observed_at, event_seq
           FROM facet_observations
          WHERE record_id = ? AND key = ?
            AND (? IS NULL OR as_of >= ?)
            AND (? IS NULL OR as_of <= ?)
            AND (? IS NULL OR as_of > ?)
          ORDER BY as_of ASC
          LIMIT ?",
    )
    .bind(&record_id)
    .bind(&key)
    .bind(&from_as_of)
    .bind(&from_as_of)
    .bind(&to_as_of)
    .bind(&to_as_of)
    .bind(&after_as_of)
    .bind(&after_as_of)
    .bind(limit + 1)
    .fetch_all(db.write_pool())
    .await?;
    let has_more = rows.len() > limit as usize;
    let items: Vec<Value> = rows
        .iter()
        .take(limit as usize)
        .map(|row| {
            Ok(json!({
                "value": row.try_get::<Option<String>, _>("value")?,
                "op": row.try_get::<String, _>("op")?,
                "vocab_ref": row.try_get::<Option<String>, _>("vocab_ref")?,
                "as_of": row.try_get::<String, _>("as_of")?,
                "observed_at": row.try_get::<String, _>("observed_at")?,
                "event_seq": row.try_get::<i64, _>("event_seq")?,
            }))
        })
        .collect::<Result<_>>()?;
    let next_after_as_of = if has_more {
        items
            .last()
            .and_then(|item| item.get("as_of"))
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Ok(json!({
        "record_id": record_id,
        "key": key,
        "observations": items,
        "next_after_as_of": next_after_as_of,
    }))
}

async fn manage_facet_observations(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    match parse_args("manage_facet_observations", arguments)? {
        ManageFacetObservationsArgs::Set {
            record_id,
            key,
            value,
            vocab_ref,
            as_of,
            reason,
        } => {
            write_observation(
                db,
                caller,
                record_id,
                key,
                Some((value, vocab_ref)),
                as_of,
                reason,
            )
            .await
        }
        ManageFacetObservationsArgs::Unset {
            record_id,
            key,
            as_of,
            reason,
        } => write_observation(db, caller, record_id, key, None, as_of, reason).await,
        ManageFacetObservationsArgs::List {
            record_id,
            key,
            from_as_of,
            to_as_of,
            after_as_of,
            limit,
        } => {
            list_observations(
                &db,
                &caller,
                record_id,
                key,
                from_as_of,
                to_as_of,
                after_as_of,
                limit,
            )
            .await
        }
    }
}

pub fn register_observation_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageFacetObservations,
        &format!(
            "Set or unset one valid-time open-facet observation without changing the record's current facet value, or list one bounded series oldest-first. Writes require RFC3339 as_of and normalize it to UTC milliseconds. List bounds are inclusive; after_as_of is an exclusive keyset cursor; limit defaults to {DEFAULT_LIMIT} and is capped at {MAX_LIMIT}. Numeric values are returned as stored strings. {PREVIOUS_SEQ_DESCRIPTION}"
        ),
        json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "set" },
                        "record_id": { "type": "string" },
                        "key": { "type": "string", "minLength": 1, "description": "One open facet key; spine and engine-reserved facets are rejected." },
                        "value": { "type": ["string", "number"], "description": "Preserve JSON numbers for facets declared type:number." },
                        "vocab_ref": { "type": "string", "description": "Optional vocabulary reference, checked against the governing shape." },
                        "as_of": { "type": "string", "description": "Required RFC3339 valid-time timestamp." },
                        "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
                    },
                    "required": ["action", "record_id", "key", "value", "as_of", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "unset" },
                        "record_id": { "type": "string" },
                        "key": { "type": "string", "minLength": 1, "description": "One open facet key; spine and engine-reserved facets are rejected." },
                        "as_of": { "type": "string", "description": "Required RFC3339 valid-time timestamp." },
                        "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION }
                    },
                    "required": ["action", "record_id", "key", "as_of", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "list" },
                        "record_id": { "type": "string" },
                        "key": { "type": "string", "minLength": 1, "description": "One projected facet-series key." },
                        "from_as_of": { "type": "string", "description": "Optional inclusive RFC3339 lower bound." },
                        "to_as_of": { "type": "string", "description": "Optional inclusive RFC3339 upper bound." },
                        "after_as_of": { "type": "string", "description": "Optional opaque exclusive keyset cursor returned as next_after_as_of; pass it back unchanged." },
                        "limit": { "type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": DEFAULT_LIMIT }
                    },
                    "required": ["action", "record_id", "key"],
                    "additionalProperties": false
                }
            ]
        }),
        manage_facet_observations,
    )?;
    Ok(())
}
