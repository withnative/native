//! Tool 27 — resolve body suggestions.
//!
//! Suggestions are ordinary `Annotation/kind:suggestion` records whose target
//! is an explicit outgoing `part_of` link. Filing home is independent.
//! module owns only resolution: it validates the authored shape and executes
//! target + lifecycle writes under one caller-owned `BEGIN IMMEDIATE`
//! transaction through `store::append_in`.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::generated::kinds::CoreKind;
use crate::store::{append_in, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, require_nonblank_reason, require_record_in, REASON_DESCRIPTION};

const TOOL: &str = "resolve_suggestions";
const MAX_BATCH: usize = 100;
const OLD_FACET: &str = "anchor.old";
const DIGEST_FACET: &str = "anchor.base_digest";
const PRECONDITION_FACET: &str = "proposal.precondition";

async fn validate_lifecycle_destination_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    destination: &str,
) -> Result<()> {
    let schema_rows = crate::query::cascade::schema_config_rows_in(tx).await?;
    let mut write = [super::lifecycle::FacetWrite {
        key: "lifecycle".into(),
        value: Value::String(destination.into()),
        vocab_ref: None,
    }];
    super::lifecycle::assert_facet_value_predicates_in(
        tx,
        &schema_rows,
        TOOL,
        "Annotation",
        Some("suggestion"),
        None,
        &mut write,
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveSuggestionsArgs {
    action: String,
    suggestion_ids: Vec<String>,
    reason: String,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Debug)]
struct Suggestion {
    id: String,
    target_id: String,
    lifecycle: Option<String>,
    replacement: Option<String>,
}

#[derive(Debug)]
enum Precondition {
    None { old: Option<String> },
    Span { old: String },
    Digest { expected: String },
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn authoring_error(id: &str, message: impl AsRef<str>) -> Error {
    Error::engine(format!(
        "{TOOL}: suggestion {id} has an invalid authored shape: {}",
        message.as_ref()
    ))
}

async fn read_suggestions_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    ids: &[String],
) -> Result<Vec<Suggestion>> {
    let mut suggestions = Vec::with_capacity(ids.len());
    for id in ids {
        let row = sqlx::query(
            "SELECT id, type, kind, lifecycle, body, deleted_at
               FROM records WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(row) = row else {
            return Err(Error::engine(format!(
                "{TOOL}: suggestion {id} does not exist"
            )));
        };
        if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
            return Err(authoring_error(id, "record is deleted (tombstoned)"));
        }
        let record_type: String = row.try_get("type")?;
        let kind: Option<String> = row.try_get("kind")?;
        let governed = match kind.as_deref() {
            Some(kind) => crate::meta::kind::resolve_on(&mut *tx, &record_type, kind).await?,
            None => {
                return Err(authoring_error(
                    id,
                    "expected live Annotation/kind:suggestion",
                ))
            }
        };
        if !CoreKind::AnnotationSuggestion.matches(&governed) {
            return Err(authoring_error(
                id,
                "expected live Annotation/kind:suggestion",
            ));
        }
        let targets: Vec<String> = sqlx::query_scalar(
            "SELECT target_id FROM links
              WHERE source_id = ? AND relationship = 'part_of'
              ORDER BY target_id",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await?;
        if targets.len() != 1 {
            return Err(authoring_error(
                id,
                format!(
                    "expected exactly one outgoing part_of target; found {}",
                    targets.len()
                ),
            ));
        }
        suggestions.push(Suggestion {
            id: id.clone(),
            target_id: targets[0].clone(),
            lifecycle: row.try_get("lifecycle")?,
            replacement: row.try_get("body")?,
        });
    }
    Ok(suggestions)
}

async fn read_preconditions_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    suggestions: &[Suggestion],
) -> Result<Vec<Precondition>> {
    let mut out = Vec::with_capacity(suggestions.len());
    for suggestion in suggestions {
        if suggestion.replacement.is_none() {
            return Err(authoring_error(&suggestion.id, "body is required"));
        }
        let rows = sqlx::query(
            "SELECT key, value FROM facet_values
              WHERE record_id = ? AND key IN (?, ?, ?)",
        )
        .bind(&suggestion.id)
        .bind(OLD_FACET)
        .bind(DIGEST_FACET)
        .bind(PRECONDITION_FACET)
        .fetch_all(&mut **tx)
        .await?;
        let mut facets = HashMap::new();
        for row in rows {
            facets.insert(
                row.try_get::<String, _>("key")?,
                row.try_get::<Option<String>, _>("value")?,
            );
        }
        let declared = facets
            .get(PRECONDITION_FACET)
            .and_then(Option::as_deref)
            .ok_or_else(|| {
                authoring_error(
                    &suggestion.id,
                    format!("missing required facet '{PRECONDITION_FACET}'"),
                )
            })?;
        let precondition = match declared {
            "none" => {
                let old = facets.get(OLD_FACET).and_then(Option::as_deref);
                if old == Some("") {
                    return Err(authoring_error(
                        &suggestion.id,
                        format!("facet '{OLD_FACET}' must not be empty when present"),
                    ));
                }
                Precondition::None {
                    old: old.map(String::from),
                }
            }
            "span" => {
                let old = facets
                    .get(OLD_FACET)
                    .and_then(Option::as_deref)
                    .filter(|old| !old.is_empty())
                    .ok_or_else(|| {
                        authoring_error(
                            &suggestion.id,
                            format!("span requires non-empty facet '{OLD_FACET}'"),
                        )
                    })?;
                Precondition::Span { old: old.into() }
            }
            "digest" => {
                let expected = facets
                    .get(DIGEST_FACET)
                    .and_then(Option::as_deref)
                    .ok_or_else(|| {
                        authoring_error(
                            &suggestion.id,
                            format!("digest requires facet '{DIGEST_FACET}'"),
                        )
                    })?;
                if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(authoring_error(
                        &suggestion.id,
                        format!("facet '{DIGEST_FACET}' must be a SHA-256 hex digest"),
                    ));
                }
                Precondition::Digest {
                    expected: expected.to_ascii_lowercase(),
                }
            }
            "field_equals" | "seq" => {
                return Err(authoring_error(
                    &suggestion.id,
                    format!("precondition '{declared}' is unsupported for body suggestions in v1"),
                ))
            }
            other => {
                return Err(authoring_error(
                    &suggestion.id,
                    format!(
                        "facet '{PRECONDITION_FACET}' must be none, span, or digest; got '{other}'"
                    ),
                ))
            }
        };
        out.push(precondition);
    }
    Ok(out)
}

fn lifecycle_conflict(suggestions: &[Suggestion], target_id: &str) -> Option<Value> {
    let causes: Vec<Value> = suggestions
        .iter()
        .filter(|suggestion| suggestion.lifecycle.as_deref() != Some("open"))
        .map(|suggestion| {
            json!({
                "suggestion_id": suggestion.id,
                "code": "lifecycle_not_open",
                "current_lifecycle": suggestion.lifecycle,
            })
        })
        .collect();
    (!causes.is_empty()).then(|| {
        let ids: Vec<&str> = causes
            .iter()
            .filter_map(|cause| cause.get("suggestion_id").and_then(Value::as_str))
            .collect();
        json!({
            "status": "conflict",
            "target_id": target_id,
            "suggestion_ids": ids,
            "causes": causes,
        })
    })
}

async fn mark_stale_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    causes: &[Value],
) -> Result<()> {
    validate_lifecycle_destination_in(tx, "stale").await?;
    for cause in causes {
        let id = cause
            .get("suggestion_id")
            .and_then(Value::as_str)
            .expect("stale causes always carry suggestion_id");
        let code = cause
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("precondition_failed");
        let payload = json!({
            "lifecycle": "stale",
            "summary": format!("Stale: {code}"),
        });
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: id.into(),
                event_type: "record.updated".into(),
                payload,
                actor: Some(caller.actor().into()),
            },
        )
        .await?;
    }
    Ok(())
}

fn stale_causes(
    suggestions: &[Suggestion],
    preconditions: &[Precondition],
    target_body: Option<&str>,
) -> Vec<Value> {
    let current = target_body.unwrap_or_default();
    let mut stale = Vec::new();
    for (suggestion, precondition) in suggestions.iter().zip(preconditions.iter()) {
        match precondition {
            Precondition::None { old: None } => {}
            Precondition::None { old: Some(old) } | Precondition::Span { old } => {
                let count = current.matches(old).count();
                if count != 1 {
                    stale.push(json!({
                        "suggestion_id": suggestion.id,
                        "code": if count == 0 { "span_missing" } else { "span_ambiguous" },
                        "match_count": count,
                    }));
                }
            }
            Precondition::Digest { expected } => match target_body {
                None => stale.push(json!({
                    "suggestion_id": suggestion.id,
                    "code": "target_body_null",
                })),
                Some(_) => {
                    let actual = sha256_hex(current);
                    if &actual != expected {
                        stale.push(json!({
                            "suggestion_id": suggestion.id,
                            "code": "digest_mismatch",
                            "expected": expected,
                            "actual": actual,
                        }));
                    }
                }
            },
        }
    }
    stale
}

fn simulate(
    suggestions: &[Suggestion],
    preconditions: &[Precondition],
    current: &str,
    target_id: &str,
    ids: &[String],
    dry_run: bool,
) -> std::result::Result<String, Value> {
    let mut prospective = current.to_string();
    for (suggestion, precondition) in suggestions.iter().zip(preconditions.iter()) {
        let replacement = suggestion
            .replacement
            .as_deref()
            .expect("authored shape validated replacement body");
        match precondition {
            Precondition::None { old: None } | Precondition::Digest { .. } => {
                prospective = replacement.to_string();
            }
            Precondition::None { old: Some(old) } | Precondition::Span { old } => {
                let count = prospective.matches(old).count();
                if count != 1 {
                    return Err(json!({
                        "status": if dry_run { "would_conflict" } else { "conflict" },
                        "target_id": target_id,
                        "suggestion_ids": ids,
                        "causes": [{
                            "suggestion_id": suggestion.id,
                            "code": "batch_overlap",
                            "match_count": count,
                        }],
                    }));
                }
                prospective = prospective.replacen(old, replacement, 1);
            }
        }
    }
    Ok(prospective)
}

async fn accept(
    db: Db,
    caller: Caller,
    ids: Vec<String>,
    reason: String,
    dry_run: bool,
) -> Result<Value> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut authorized_targets = Vec::with_capacity(ids.len());
    for id in &ids {
        let target: Option<String> = sqlx::query_scalar(
            "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of' LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let target =
            target.ok_or_else(|| Error::engine(format!("{TOOL}: suggestion does not exist")))?;
        if require_record_in(&mut tx, &caller, TOOL, &target, Capability::Edit)
            .await
            .is_err()
        {
            return Err(Error::engine(format!("{TOOL}: suggestion does not exist")));
        }
        authorized_targets.push(target);
    }
    if authorized_targets.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(Error::engine(format!(
            "{TOOL}: all accepted suggestions must share one part_of target"
        )));
    }
    let suggestions = read_suggestions_in(&mut tx, &ids).await?;
    let target_id = suggestions[0].target_id.clone();
    if suggestions
        .iter()
        .any(|suggestion| suggestion.target_id != target_id)
    {
        return Err(Error::engine(format!(
            "{TOOL}: all accepted suggestions must share one part_of target"
        )));
    }
    if let Some(mut conflict) = lifecycle_conflict(&suggestions, &target_id) {
        if dry_run {
            conflict["status"] = json!("would_conflict");
        }
        return Ok(conflict);
    }
    let preconditions = read_preconditions_in(&mut tx, &suggestions).await?;
    if suggestions.len() > 1
        && preconditions.iter().any(|precondition| {
            matches!(
                precondition,
                Precondition::Digest { .. } | Precondition::None { old: None }
            )
        })
    {
        return Err(Error::engine(format!(
            "{TOOL}: digest and whole-body none suggestions must be accepted alone"
        )));
    }

    let target = sqlx::query("SELECT body, deleted_at FROM records WHERE id = ?")
        .bind(&target_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(target) = target else {
        let causes: Vec<Value> = ids
            .iter()
            .map(|id| json!({ "suggestion_id": id, "code": "target_missing" }))
            .collect();
        if !dry_run {
            mark_stale_in(&db, &mut tx, &caller, &causes).await?;
            db.commit_content(tx).await?;
        }
        return Ok(
            json!({ "status": if dry_run { "would_stale" } else { "stale" }, "target_id": target_id, "suggestion_ids": ids, "causes": causes }),
        );
    };
    if target.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        let causes: Vec<Value> = ids
            .iter()
            .map(|id| json!({ "suggestion_id": id, "code": "target_deleted" }))
            .collect();
        if !dry_run {
            mark_stale_in(&db, &mut tx, &caller, &causes).await?;
            db.commit_content(tx).await?;
        }
        return Ok(
            json!({ "status": if dry_run { "would_stale" } else { "stale" }, "target_id": target_id, "suggestion_ids": ids, "causes": causes }),
        );
    }

    let target_body: Option<String> = target.try_get("body")?;
    let current = target_body.clone().unwrap_or_default();
    let stale = stale_causes(&suggestions, &preconditions, target_body.as_deref());
    if !stale.is_empty() {
        if !dry_run {
            mark_stale_in(&db, &mut tx, &caller, &stale).await?;
            db.commit_content(tx).await?;
        }
        let stale_ids: Vec<&str> = stale
            .iter()
            .filter_map(|cause| cause.get("suggestion_id").and_then(Value::as_str))
            .collect();
        return Ok(json!({
            "status": if dry_run { "would_stale" } else { "stale" },
            "target_id": target_id,
            "suggestion_ids": stale_ids,
            "causes": stale,
        }));
    }

    // Every world-state precondition passed against the same current target.
    // Only now simulate the selected operations in request order. A later span
    // that is invalidated by an earlier selected edit is a batch collision,
    // not evidence that the world moved; return a no-write conflict and leave
    // every selected suggestion open.
    let prospective = match simulate(
        &suggestions,
        &preconditions,
        &current,
        &target_id,
        &ids,
        dry_run,
    ) {
        Ok(prospective) => prospective,
        Err(conflict) => return Ok(conflict),
    };
    if dry_run {
        return Ok(json!({
            "status": "would_accept",
            "target_id": target_id,
            "suggestion_ids": ids,
            "prospective_body": prospective,
        }));
    }

    validate_lifecycle_destination_in(&mut tx, "accepted").await?;

    append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: target_id.clone(),
            event_type: "record.updated".into(),
            payload: json!({ "body": prospective, "reason": reason }),
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    for suggestion in &suggestions {
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: suggestion.id.clone(),
                event_type: "record.updated".into(),
                payload: json!({ "lifecycle": "accepted" }),
                actor: Some(caller.actor().into()),
            },
        )
        .await?;
    }
    db.commit_content(tx).await?;
    Ok(json!({
        "status": "accepted",
        "target_id": target_id,
        "suggestion_ids": ids,
    }))
}

async fn reject(db: Db, caller: Caller, id: String, reason: String) -> Result<Value> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let target: Option<String> = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of' LIMIT 1",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    let target =
        target.ok_or_else(|| Error::engine(format!("{TOOL}: suggestion does not exist")))?;
    if require_record_in(&mut tx, &caller, TOOL, &target, Capability::Edit)
        .await
        .is_err()
    {
        return Err(Error::engine(format!("{TOOL}: suggestion does not exist")));
    }
    let suggestions = read_suggestions_in(&mut tx, std::slice::from_ref(&id)).await?;
    let suggestion = &suggestions[0];
    if let Some(conflict) = lifecycle_conflict(&suggestions, &suggestion.target_id) {
        return Ok(conflict);
    }
    read_preconditions_in(&mut tx, &suggestions).await?;
    validate_lifecycle_destination_in(&mut tx, "rejected").await?;
    append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "record.updated".into(),
            payload: json!({
                "lifecycle": "rejected",
                "summary": format!("Rejected: {}", reason.trim()),
                "reason": reason,
            }),
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(json!({
        "status": "rejected",
        "target_id": suggestion.target_id,
        "suggestion_ids": [id],
    }))
}

async fn resolve_suggestions(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ResolveSuggestionsArgs = parse_args(TOOL, arguments)?;
    require_nonblank_reason(TOOL, &args.reason)?;
    if args.suggestion_ids.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'suggestion_ids' must not be empty"
        )));
    }
    if args.suggestion_ids.len() > MAX_BATCH {
        return Err(Error::engine(format!(
            "{TOOL}: at most {MAX_BATCH} suggestion_ids per call"
        )));
    }
    let unique: HashSet<&str> = args.suggestion_ids.iter().map(String::as_str).collect();
    if unique.len() != args.suggestion_ids.len() {
        return Err(Error::engine(format!(
            "{TOOL}: 'suggestion_ids' must not contain duplicates"
        )));
    }
    match args.action.as_str() {
        "accept" => accept(db, caller, args.suggestion_ids, args.reason, args.dry_run).await,
        "reject" if args.dry_run => Err(Error::engine(format!(
            "{TOOL}: dry_run is only valid with action accept"
        ))),
        "reject" if args.suggestion_ids.len() == 1 => {
            reject(db, caller, args.suggestion_ids[0].clone(), args.reason).await
        }
        "reject" => Err(Error::engine(format!(
            "{TOOL}: reject takes exactly one suggestion id"
        ))),
        _ => Err(Error::engine(format!(
            "{TOOL}: 'action' must be accept or reject"
        ))),
    }
}

pub fn register_suggestion_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ResolveSuggestions,
        "Accept an ordered non-empty batch of body suggestions sharing one target, or reject exactly one. Author suggestions with ordinary create_record: use type Annotation, kind suggestion, exactly one outgoing part_of link to the target (`links: [{ target_id: <target>, relationship: \"part_of\" }]`), lifecycle open, body set to the replacement text, and facets containing proposal.precondition plus, as applicable, anchor.old for an exact span or anchor.base_digest for a digest. The declared proposal.precondition facet (none, span, or digest for body suggestions; field_equals and seq are reserved family values) is enforced inside the same write transaction as the target and suggestion lifecycle events. Staleness and lifecycle conflicts are structured successful outcomes; malformed authored shapes are errors.",
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["accept", "reject"] },
                "suggestion_ids": {
                    "type": "array",
                    "items": { "type": "string" },
                    "minItems": 1,
                    "maxItems": MAX_BATCH,
                    "description": "Accept preserves this request order. Reject requires exactly one id."
                },
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION },
                "dry_run": { "type": "boolean", "default": false, "description": "For accept only: run identical preconditions and ordered simulation, returning the prospective body without writing." }
            },
            "required": ["action", "suggestion_ids", "reason"],
            "additionalProperties": false
        }),
        resolve_suggestions,
    )
}
