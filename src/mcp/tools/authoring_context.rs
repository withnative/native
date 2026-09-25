//! `get_reuse_context` — bounded reuse context for one ordinary Document.
//!
//! Read-only authoring aid: current body + exact revision, declared source
//! basis from the latest Receipt, open concerns with bounded replies, compact
//! treatment history, inherited Receipt uncertainty, and a versioned drafting
//! instruction. Structured data out, no prose synthesis, no semantic-equivalence
//! inference.

use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, principal, require_record_in};

pub const TOOL: &str = "get_reuse_context";
const DEFAULT_LIMIT: i64 = 10;
const MAX_LIMIT: i64 = 50;
const MAX_REPLIES_PER_ROOT: i64 = 10;
const MAX_OFFSET: i64 = 10_000;

/// Versioned drafting instruction for evidence scope and recorded treatment.
pub const DRAFTING_INSTRUCTION_VERSION: &str = "native.authoring-scope-preservation.v2";
/// Scope-preserving prose plus explicit interpretation of resolved concerns.
pub const DRAFTING_INSTRUCTION: &str = "Write the reusable draft so it can be reused without the basis note. Preserve material scope qualifiers in that text: information not supplied or not found in the reviewed material does not establish that an event has not happened or a decision is pending. State recorded operational facts as facts, with their attribution when material. Keep unknown evidence coverage distinct from an explicitly recorded pending state; do not hide that distinction solely in the basis note. Read lifecycle and chronology as part of the supplied evidence. A resolved comment body describes its original concern; its resolution_summary is supplied evidence of the later recorded outcome for that root. Preserve that outcome in the reusable draft, with attribution when material, instead of repeating the original concern as still open or treating the resolution as missing evidence. Use supplied revision and update times to distinguish earlier statements from later treatment. Keep separate concerns separate: resolving one root does not resolve another or establish unrelated approval. If supplied records conflict, state the bounded conflict rather than silently discarding a recorded resolution.";

const LIMIT_NOT_EXHAUSTIVE: &str = "reuse_context_is_bounded_not_exhaustive";
const LIMIT_NO_SEMANTIC_EQUIVALENCE: &str = "no_semantic_equivalence_inferred";
const LIMIT_UNKNOWN_VS_PENDING: &str = "unknown_coverage_distinct_from_recorded_pending";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetReuseContextArgs {
    record_id: String,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    sources_offset: Option<i64>,
    #[serde(default)]
    roots_offset: Option<i64>,
    #[serde(default)]
    uncertainty_offset: Option<i64>,
}

/// Register the bounded authoring read surface.
pub fn register_reuse_context_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::GetReuseContext,
        "Bounded reuse context for one ordinary Document: current body with exact revision, declared source basis from the latest Receipt (current vs historical), direct open concerns with bounded replies, compact resolved treatment history, inherited Receipt uncertainty, and a versioned drafting instruction. Bounded and visibility-filtered; never claims all organisational evidence is complete.",
        json!({
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "description": "One ordinary Document record id; echoed top-level for telemetry."
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 10,
                    "description": "Independent bound on each window: basis sources, open concerns, resolved treatment entries, and inherited uncertainty. Replies per root are separately bounded at 10."
                },
                "sources_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_OFFSET,
                    "default": 0,
                    "description": "Offset into the receipt basis window; the response carries a callable get_reuse_context expansion for the next page."
                },
                "roots_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_OFFSET,
                    "default": 0,
                    "description": "Offset into each concern/treatment window, applied independently so treatment history never crowds out open concerns."
                },
                "uncertainty_offset": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_OFFSET,
                    "default": 0,
                    "description": "Offset into visible inherited uncertainty; continuation calls read live state."
                }
            },
            "required": ["record_id"],
            "additionalProperties": false
        }),
        get_context,
    )
}

fn bound_limit(requested: Option<i64>) -> Result<i64> {
    let limit = requested.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Error::engine(format!(
            "{TOOL}: limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    Ok(limit)
}

fn bound_offset(requested: Option<i64>) -> Result<i64> {
    let value = requested.unwrap_or(0);
    if !(0..=MAX_OFFSET).contains(&value) {
        return Err(Error::engine(format!(
            "{TOOL}: offsets must be between 0 and {MAX_OFFSET}"
        )));
    }
    Ok(value)
}

/// Latest body-bearing revision for a record on this snapshot, via the
/// canonical kernel fold — no duplicate scope logic here.
async fn body_revision_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> Result<Option<(String, i64, String)>> {
    let current = crate::freshness::current_body_revision_on(tx, record_id).await?;
    Ok(current.map(|(reference, _)| {
        (
            reference.revision_event_id,
            reference.revision_seq,
            reference.sha256,
        )
    }))
}

/// Latest event touching a record (body or resolution metadata).
async fn latest_event_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?)
}

/// Whether a kind token carries the governed comment identity, aliases
/// included — the transaction mirror of the canonical read-path check.
async fn is_comment_kind_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_type: &str,
    kind: Option<&str>,
) -> Result<bool> {
    let Some(kind) = kind else { return Ok(false) };
    let resolution = crate::meta::kind::resolve_on(tx, record_type, kind).await?;
    Ok(crate::generated::kinds::CoreKind::AnnotationComment.matches(&resolution))
}

/// Canonical lifecycle predicate as a SQL scalar: resolves `comment-lifecycle`
/// aliases, treats legacy null as informational. Unknown tokens yield NULL and
/// match neither window — malformed, never a concern.
const CANONICAL_LIFECYCLE_SQL: &str = "COALESCE((SELECT canonical.value FROM vocabularies v JOIN vocabulary_values stored ON stored.vocabulary_id = v.id JOIN vocabulary_values canonical ON canonical.id = COALESCE(stored.alias_of, stored.id) AND canonical.vocabulary_id = v.id WHERE v.name = 'comment-lifecycle' AND stored.value = r.lifecycle AND canonical.status = 'active' AND canonical.alias_of IS NULL), CASE WHEN r.lifecycle IS NULL THEN 'informational' END)";

/// Boolean gap probe for root-shaped rows whose lifecycle resolves to no
/// governed state. They match neither window; the flag keeps either window
/// from claiming completeness over them without exposing rows or counts.
async fn root_gaps_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    tokens: &[String],
    bearer_id: &str,
) -> Result<bool> {
    if tokens.is_empty() {
        return Ok(false);
    }
    let placeholders = std::iter::repeat_n("?", tokens.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM records r
          WHERE r.deleted_at IS NULL AND r.type = 'Annotation'
            AND r.kind IN ({placeholders})
            AND TRIM(COALESCE(r.body, '')) <> ''
            AND (SELECT COUNT(*) FROM links p
                  WHERE p.source_id = r.id AND p.relationship = 'part_of') = 1
            AND EXISTS (SELECT 1 FROM links d
                         WHERE d.source_id = r.id AND d.relationship = 'part_of'
                           AND d.target_id = ?)
            AND r.lifecycle IS NOT NULL
            AND {CANONICAL_LIFECYCLE_SQL} IS NULL)"
    );
    let mut query = sqlx::query_scalar::<_, bool>(&sql);
    for token in tokens {
        query = query.bind(token);
    }
    Ok(query.bind(bearer_id).fetch_one(&mut **tx).await?)
}

/// One window's honesty state: withheld (hidden rows), truncated (more rows),
/// degraded (malformed rows dropped), else complete. Gaps never compose into
/// a completeness claim.
fn window_state(withheld: bool, gaps: bool, truncated: bool) -> &'static str {
    if withheld {
        "withheld"
    } else if truncated {
        "truncated"
    } else if gaps {
        "degraded"
    } else {
        "complete"
    }
}
async fn root_window_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    tokens: &[String],
    bearer_id: &str,
    canonical_lifecycle: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<sqlx::sqlite::SqliteRow>> {
    let placeholders = std::iter::repeat_n("?", tokens.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.body, r.lifecycle, r.summary,
                r.created_at, r.updated_at
           FROM records r
          WHERE r.deleted_at IS NULL AND r.type = 'Annotation'
            AND r.kind IN ({placeholders})
            AND TRIM(COALESCE(r.body, '')) <> ''
            AND (SELECT COUNT(*) FROM links p
                  WHERE p.source_id = r.id AND p.relationship = 'part_of') = 1
            AND EXISTS (SELECT 1 FROM links d
                         WHERE d.source_id = r.id AND d.relationship = 'part_of'
                           AND d.target_id = ?)
            AND {CANONICAL_LIFECYCLE_SQL} = ?
          ORDER BY r.created_at DESC, r.id DESC LIMIT ? OFFSET ?"
    );
    let mut query = sqlx::query(&sql);
    for token in tokens {
        query = query.bind(token);
    }
    Ok(query
        .bind(bearer_id)
        .bind(canonical_lifecycle)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&mut **tx)
        .await?)
}

/// Root anchor rule: an anchored root must target its bearer's body; a
/// targetless root is unanchored but still a valid concern.
async fn root_anchor_ok_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    comment_id: &str,
    bearer_id: &str,
) -> Result<bool> {
    let target = sqlx::query(
        "SELECT target_record_id, source_slot FROM annotation_targets WHERE annotation_id = ?",
    )
    .bind(comment_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(match target {
        None => true,
        Some(target) => {
            target.try_get::<String, _>("target_record_id")? == bearer_id
                && target.try_get::<String, _>("source_slot")? == "body"
        }
    })
}

/// Canonical reply shape: governed comment, exactly one part_of onto the root,
/// null lifecycle/summary, nonblank body, targetless, and itself rootless
/// (no reply-to-reply).
async fn reply_ok_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    tokens: &[String],
    reply_id: &str,
    root_id: &str,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<bool> {
    if row.try_get::<Option<String>, _>("lifecycle")?.is_some()
        || row.try_get::<Option<String>, _>("summary")?.is_some()
    {
        return Ok(false);
    }
    if row
        .try_get::<Option<String>, _>("body")?
        .is_none_or(|body| body.trim().is_empty())
    {
        return Ok(false);
    }
    if !is_comment_kind_in(tx, "Annotation", row.try_get("kind")?).await? {
        return Ok(false);
    }
    let bearers: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(reply_id)
    .fetch_all(&mut **tx)
    .await?;
    if bearers != [root_id.to_string()] {
        return Ok(false);
    }
    let targeted: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM annotation_targets WHERE annotation_id = ?)",
    )
    .bind(reply_id)
    .fetch_one(&mut **tx)
    .await?;
    if targeted {
        return Ok(false);
    }
    let placeholders = std::iter::repeat_n("?", tokens.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM records r
          WHERE r.deleted_at IS NULL AND r.type = 'Annotation' AND r.kind IN ({placeholders})
            AND EXISTS (SELECT 1 FROM links d WHERE d.source_id = r.id
                        AND d.relationship = 'part_of' AND d.target_id = ?))"
    );
    let mut query = sqlx::query_scalar::<_, bool>(&sql);
    for token in tokens {
        query = query.bind(token);
    }
    let nested: bool = query.bind(reply_id).fetch_one(&mut **tx).await?;
    Ok(!nested)
}

pub(super) async fn get_context(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: GetReuseContextArgs = parse_args(TOOL, arguments)?;
    let limit = bound_limit(args.limit)?;
    let sources_offset = bound_offset(args.sources_offset)?;
    let roots_offset = bound_offset(args.roots_offset)?;
    let uncertainty_offset = bound_offset(args.uncertainty_offset)?;
    let record_id = args.record_id.clone();

    // Single caller-owned snapshot for record, basis and concerns. The
    // inherited-uncertainty projection below is a deliberate second read.
    let mut tx = db.write_pool().begin().await?;
    require_record_in(&mut tx, &caller, TOOL, &record_id, Capability::View).await?;
    if !crate::query::read::ordinary_record_read_eligible_live_in(&mut tx, &record_id).await? {
        return Err(Error::engine(format!(
            "{TOOL}: record {record_id} does not exist"
        )));
    }
    let row = sqlx::query(
        "SELECT id, type, kind, name, body FROM records WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(&record_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{TOOL}: record {record_id} does not exist")))?;
    let name: Option<String> = row.try_get("name")?;
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    if record_type != "Document" {
        return Err(Error::engine(format!(
            "{TOOL}: record {record_id} is not an ordinary Document"
        )));
    }
    let body: Option<String> = row.try_get("body")?;
    let current_revision = body_revision_in(&mut tx, &record_id).await?;
    let (current_event_id, current_seq, current_sha) = match current_revision {
        Some(revision) => (Some(revision.0), Some(revision.1), Some(revision.2)),
        None => (None, None, None),
    };

    // Latest Receipt scoped to this consumer: exact declared source basis.
    let receipt = sqlx::query(
        "SELECT receipt_id, output_revision_event_id, output_revision,
                withheld_context, receipt_event_seq
           FROM receipts WHERE consumer_record_id = ?
           ORDER BY receipt_event_seq DESC LIMIT 1",
    )
    .bind(&record_id)
    .fetch_optional(&mut *tx)
    .await?;
    let mut basis_sources = Vec::new();
    let mut basis_withheld = false;
    let mut basis_truncated = false;
    let mut basis_unit_entries = false;
    let (basis_status, receipt_id, output_event_id, output_seq) = match receipt.as_ref() {
        None => ("none".to_string(), None, None, None),
        Some(receipt) => {
            let rid: String = receipt.try_get("receipt_id")?;
            let output_event: String = receipt.try_get("output_revision_event_id")?;
            let output_rev: String = receipt.try_get("output_revision")?;
            let output_rev: crate::freshness::RevisionRef = serde_json::from_str(&output_rev)?;
            if receipt.try_get::<i64, _>("withheld_context")? != 0 {
                basis_withheld = true;
            }
            let status = match current_event_id.as_deref() {
                Some(current) if current == output_event => "current",
                _ => "historical",
            }
            .to_string();
            // Bounded window: limit+1 detects truncation without a count query
            // (a count would disclose hidden rows).
            let rows = sqlx::query(
                "SELECT source_record_id, source_revision_event_id, source_revision, reason
                   FROM receipt_provenance WHERE receipt_id = ?
                   ORDER BY ordinal LIMIT ? OFFSET ?",
            )
            .bind(&rid)
            .bind(limit + 1)
            .bind(sources_offset)
            .fetch_all(&mut *tx)
            .await?;
            if (rows.len() as i64) > limit {
                basis_truncated = true;
            }
            for row in rows.iter().take(limit as usize) {
                let column_id: String = row.try_get("source_record_id")?;
                let column_event: String = row.try_get("source_revision_event_id")?;
                let source_rev: String = row.try_get("source_revision")?;
                let reason: String = row.try_get("reason")?;
                let parsed: crate::freshness::RevisionRef = serde_json::from_str(&source_rev)
                    .map_err(|_| Error::engine(format!("{TOOL}: receipt basis is unavailable")))?;
                // The parsed revision is authoritative; the mirror columns must
                // agree with it. Anything else reads as unavailable, never data.
                if parsed.subject_id != column_id || parsed.revision_event_id != column_event {
                    basis_withheld = true;
                    continue;
                }
                // Public contract carries record bodies only. Unit-scoped inputs
                // are not emittable here; their presence is a flag, never
                // identities, and the window is not claimed complete for them.
                if !matches!(
                    parsed.subject_kind,
                    crate::freshness::RevisionSubjectKind::Artefact
                ) {
                    basis_unit_entries = true;
                    continue;
                }
                let visible = crate::authorization::effective_capability_on(
                    &mut tx,
                    principal(&caller),
                    &parsed.subject_id,
                )
                .await
                .is_ok_and(|capability| capability.allows(Capability::View));
                if !visible {
                    basis_withheld = true;
                    continue;
                }
                // The true declared role lives on the matching dependency row,
                // authored at save time — never a hardcoded label here.
                let role: Option<String> = sqlx::query_scalar(
                    "SELECT semantic_role FROM dependencies
                      WHERE receipt_id = ? AND source_revision_event_id = ?
                      ORDER BY dependency_id LIMIT 1",
                )
                .bind(&rid)
                .bind(&parsed.revision_event_id)
                .fetch_optional(&mut *tx)
                .await?;
                basis_sources.push(json!({
                    "record_id": parsed.subject_id,
                    "revision_event_id": parsed.revision_event_id,
                    "role": role,
                    "reason": reason,
                }));
            }
            (
                status,
                Some(rid),
                Some(output_event),
                Some(output_rev.revision_seq),
            )
        }
    };
    // No receipt means no declared basis — stated outright, never "complete".
    // Unit-scoped entries keep the window from claiming completeness silently.
    let basis_completeness = if receipt.is_none() {
        "no_declared_basis"
    } else if basis_withheld || basis_unit_entries {
        "withheld"
    } else if basis_truncated {
        "truncated"
    } else {
        "complete"
    };

    // Independent bounded windows: open concerns and resolved treatment are
    // fetched and paged separately (shared roots_offset, applied to each) so
    // treatment history never crowds out open concerns. Informational roots —
    // including the legacy null spelling — appear in neither window.
    let tokens = crate::meta::kind::active_identity_tokens_on(
        &mut tx,
        "Annotation",
        crate::generated::kinds::CoreKind::AnnotationComment.value_id(),
    )
    .await?;
    let mut concerns = Vec::new();
    let mut treatment = Vec::new();
    let (mut concerns_truncated, mut treatment_truncated) = (false, false);
    let (mut concerns_withheld, mut treatment_withheld) = (false, false);
    let (mut concerns_gaps, mut treatment_gaps) = (false, false);
    for (canonical, is_treatment) in [("open", false), ("resolved", true)] {
        let rows = if tokens.is_empty() {
            Vec::new()
        } else {
            root_window_in(&mut tx, &tokens, &record_id, canonical, limit, roots_offset).await?
        };
        let truncated = (rows.len() as i64) > limit;
        if is_treatment {
            treatment_truncated = truncated;
        } else {
            concerns_truncated = truncated;
        }
        for row in rows.iter().take(limit as usize) {
            let comment_id: String = row.try_get("id")?;
            let visible = crate::authorization::effective_capability_on(
                &mut tx,
                principal(&caller),
                &comment_id,
            )
            .await
            .is_ok_and(|capability| capability.allows(Capability::View));
            if !visible {
                if is_treatment {
                    treatment_withheld = true;
                } else {
                    concerns_withheld = true;
                }
                continue;
            }
            // Canonical field shape on the resolved lifecycle: open roots carry no
            // summary; resolved roots carry a nonblank one. Anything else is
            // malformed — dropped with a gap flag, never a concern claim.
            let summary: Option<String> = row.try_get("summary")?;
            let shape_ok = match canonical {
                "open" => summary.is_none(),
                _ => summary
                    .as_deref()
                    .is_some_and(|text| !text.trim().is_empty()),
            };
            if !shape_ok || !root_anchor_ok_in(&mut tx, &comment_id, &record_id).await? {
                if is_treatment {
                    treatment_gaps = true;
                } else {
                    concerns_gaps = true;
                }
                continue;
            }
            let body_rev = body_revision_in(&mut tx, &comment_id).await?;
            let meta_event = latest_event_in(&mut tx, &comment_id).await?;
            // Bounded direct replies (oldest first) in canonical shape; the batch
            // target projection below covers roots only — replies inherit it.
            let reply_rows = sqlx::query(
                "SELECT r.id, r.type, r.kind, r.body, r.lifecycle, r.summary, r.created_at
               FROM records r
              WHERE r.deleted_at IS NULL AND r.type = 'Annotation'
                AND TRIM(COALESCE(r.body, '')) <> ''
                AND EXISTS (SELECT 1 FROM links d
                             WHERE d.source_id = r.id AND d.relationship = 'part_of'
                               AND d.target_id = ?)
              ORDER BY r.created_at ASC, r.id ASC LIMIT ?",
            )
            .bind(&comment_id)
            .bind(MAX_REPLIES_PER_ROOT + 1)
            .fetch_all(&mut *tx)
            .await?;
            let mut replies = Vec::new();
            let replies_truncated = (reply_rows.len() as i64) > MAX_REPLIES_PER_ROOT;
            let mut replies_withheld = false;
            let mut replies_gaps = false;
            for reply in reply_rows.iter().take(MAX_REPLIES_PER_ROOT as usize) {
                let reply_id: String = reply.try_get("id")?;
                let reply_visible = crate::authorization::effective_capability_on(
                    &mut tx,
                    principal(&caller),
                    &reply_id,
                )
                .await
                .is_ok_and(|capability| capability.allows(Capability::View));
                if !reply_visible {
                    replies_withheld = true;
                    continue;
                }
                if !reply_ok_in(&mut tx, &tokens, &reply_id, &comment_id, reply).await? {
                    replies_gaps = true;
                    continue;
                }
                let reply_rev = body_revision_in(&mut tx, &reply_id).await?;
                let reply_body: Option<String> = reply.try_get("body")?;
                replies.push(json!({
                    "comment_id": reply_id,
                    "body": reply_body,
                    "body_revision_event_id": reply_rev.map(|revision| revision.0),
                    "created_at": reply.try_get::<String, _>("created_at")?,
                }));
            }
            let lifecycle: Option<String> = row.try_get("lifecycle")?;
            let entry = json!({
                "comment_id": comment_id,
                "name": row.try_get::<Option<String>, _>("name")?,
                "body": row.try_get::<Option<String>, _>("body")?,
                "lifecycle": lifecycle,
                "resolution_summary": summary,
                "body_revision_event_id": body_rev.as_ref().map(|revision| revision.0.clone()),
                "body_revision_seq": body_rev.as_ref().map(|revision| revision.1),
                "body_sha256": body_rev.as_ref().map(|revision| revision.2.clone()),
                // Resolution metadata revision: equals the body event unless a
                // summary/lifecycle-only change moved it afterwards.
                "metadata_revision_event_id": meta_event,
                "created_at": row.try_get::<String, _>("created_at")?,
                "updated_at": row.try_get::<String, _>("updated_at")?,
                "replies": replies,
                "replies_truncated": replies_truncated,
                "replies_withheld": replies_withheld,
                "replies_integrity_gaps": replies_gaps,
            });
            if is_treatment {
                treatment.push((entry, replies_truncated));
            } else {
                concerns.push((entry, replies_truncated));
            }
        }
    }
    // Roots whose lifecycle resolves to no governed state are malformed: they
    // match neither window, so name the gap with a boolean, never rows.
    let roots_gaps = root_gaps_in(&mut tx, &tokens, &record_id).await?;
    concerns_gaps = concerns_gaps || roots_gaps;
    treatment_gaps = treatment_gaps || roots_gaps;
    // Canonical passage anchors in one batch read over this same snapshot.
    let anchor_ids: Vec<String> = concerns
        .iter()
        .map(|(entry, _)| entry["comment_id"].as_str().unwrap().to_string())
        .chain(
            treatment
                .iter()
                .map(|(entry, _)| entry["comment_id"].as_str().unwrap().to_string()),
        )
        .collect();
    let anchors = crate::citations::read_target_views_live_in(&mut tx, &anchor_ids).await?;
    let attach = |entries: Vec<(Value, bool)>| {
        entries
            .into_iter()
            .map(|(mut entry, root_truncated)| {
                let id = entry["comment_id"].as_str().unwrap().to_owned();
                entry["target"] = anchors
                    .get(&id)
                    .cloned()
                    .flatten()
                    .map(|view| serde_json::to_value(&view).unwrap())
                    .into();
                if root_truncated {
                    entry["expand_replies_via"] = json!({
                        "tool": "get_record",
                        "args": {
                            "ids": [&id],
                            "include_comments": true,
                            "comments_limit": MAX_REPLIES_PER_ROOT,
                            "comments_offset": MAX_REPLIES_PER_ROOT,
                        },
                    });
                }
                entry
            })
            .collect::<Vec<_>>()
    };
    let concerns = attach(concerns);
    let treatment = attach(treatment);
    tx.rollback().await?;
    let concerns_completeness = window_state(concerns_withheld, concerns_gaps, concerns_truncated);
    let treatment_completeness =
        window_state(treatment_withheld, treatment_gaps, treatment_truncated);

    // Inherited Receipt uncertainty: authorization-aware, separate snapshot.
    // explain_freshness filters hidden sources internally; project friendlies,
    // bounded like every other window. A receipt behind later edits labels
    // its uncertainty historical — it assessed an older output, not current
    // coverage.
    let mut inherited = Vec::new();
    let mut uncertainty_withheld = false;
    let mut uncertainty_truncated = false;
    let mut uncertainty_status = "none";
    if let Some(receipt_id) = receipt_id.clone() {
        let parsed = crate::freshness::ReceiptId::new(receipt_id.clone());
        match parsed {
            Ok(receipt_ref) => {
                match crate::freshness::explain_freshness(&db, principal(&caller), receipt_ref)
                    .await
                {
                    Ok(explanation) => {
                        uncertainty_status = basis_status.as_str();
                        for lineage in explanation
                            .unresolved_uncertainty
                            .iter()
                            .skip(uncertainty_offset as usize)
                            .take(limit as usize)
                        {
                            inherited.push(json!({
                                "dependency_id": lineage.dependency_id.as_str(),
                                "affected_conclusion": lineage.affected_conclusion.key,
                                "affected_conclusion_description":
                                    lineage.affected_conclusion.description,
                                "verdict": lineage.verdict.as_str(),
                                "evidence": lineage.evidence,
                                "assessment_task_scope": lineage.assessment_task_scope,
                            }));
                        }
                        if (explanation.unresolved_uncertainty.len() as i64)
                            > uncertainty_offset + limit
                        {
                            uncertainty_truncated = true;
                        }
                        if matches!(
                            explanation.provenance_completeness,
                            crate::freshness::ProvenanceCompleteness::Withheld
                        ) {
                            uncertainty_withheld = true;
                        }
                    }
                    // Denied or missing reads as unavailable, never an oracle.
                    Err(_) => uncertainty_status = "unavailable",
                }
            }
            Err(_) => uncertainty_status = "unavailable",
        }
    }

    // Continuations stay inside the offset bound: a next page past MAX_OFFSET
    // is omitted rather than emitted as an instantly-failing call.
    let next_sources_offset = sources_offset.saturating_add(limit);
    let basis_expand = if basis_truncated && next_sources_offset <= MAX_OFFSET {
        receipt_id.clone().map(|rid| {
            json!({
                "tool": "get_reuse_context",
                "args": {
                    "record_id": record_id.clone(),
                    "limit": limit,
                    "sources_offset": next_sources_offset,
                },
                "previous_receipt_id": rid,
                "note": "Continuation reads live state; compare receipt_id before combining basis pages.",
            })
        })
    } else {
        None
    };
    let next_roots_offset = roots_offset.saturating_add(limit);
    let roots_expand = |window_truncated: bool| {
        (window_truncated && next_roots_offset <= MAX_OFFSET).then(|| {
            json!({
                "tool": "get_reuse_context",
                "args": {
                    "record_id": record_id.clone(),
                    "limit": limit,
                    "roots_offset": next_roots_offset,
                },
            })
        })
    };
    let concerns_expand = roots_expand(concerns_truncated);
    let treatment_expand = roots_expand(treatment_truncated);
    let next_uncertainty_offset = uncertainty_offset + limit;
    let uncertainty_expand = (uncertainty_truncated && next_uncertainty_offset <= MAX_OFFSET).then(|| json!({
        "tool": "get_reuse_context",
        "args": {"record_id": record_id, "limit": limit, "uncertainty_offset": next_uncertainty_offset},
        "previous_receipt_id": receipt_id,
    }));

    Ok(json!({
        "record_id": record_id.clone(),
        "record": {
            "id": record_id.clone(),
            "type": record_type,
            "kind": kind,
            "name": name,
            "body": body,
            // Exact local revision. Basis `sources[]` below are the
            // declared-use references. General Receipts may have no semantic
            // role; do not invent one. This object also carries seq/digest.
            "revision": {
                "record_id": record_id,
                "revision_event_id": current_event_id,
                "revision_seq": current_seq,
                "sha256": current_sha,
            },
        },
        "basis": {
            "status": basis_status,
            "receipt_id": receipt_id,
            "output_revision_event_id": output_event_id,
            "output_revision_seq": output_seq,
            "sources": basis_sources,
            "completeness": basis_completeness,
            "withheld": basis_withheld,
            "unit_entries_present": basis_unit_entries,
            "truncated": basis_truncated,
            "expand_sources_via": basis_expand,
        },
        "concerns": {
            "entries": concerns,
            "completeness": concerns_completeness,
            "withheld": concerns_withheld,
            "integrity_gaps": concerns_gaps,
            "truncated": concerns_truncated,
            "expand_via": concerns_expand,
        },
        "treatment": {
            "entries": treatment,
            "completeness": treatment_completeness,
            "withheld": treatment_withheld,
            "integrity_gaps": treatment_gaps,
            "truncated": treatment_truncated,
            "expand_via": treatment_expand,
        },
        "uncertainty": {
            "status": uncertainty_status,
            "inherited": inherited,
            "withheld": uncertainty_withheld,
            "truncated": uncertainty_truncated,
            "expand_via": uncertainty_expand,
        },
        "drafting_instruction": {
            "version": DRAFTING_INSTRUCTION_VERSION,
            "instruction": DRAFTING_INSTRUCTION,
        },
        "interpretation_limits": [
            LIMIT_NOT_EXHAUSTIVE,
            LIMIT_NO_SEMANTIC_EQUIVALENCE,
            LIMIT_UNKNOWN_VS_PENDING,
        ],
        "read_boundaries": "record, basis and concern windows share one caller-owned snapshot transaction; inherited Receipt uncertainty comes from explain_freshness on its own snapshot",
        "pagination_boundary": "Continuations read live state, not a pinned snapshot. Basis and uncertainty pages must share a receipt_id; comment windows may change between calls.",
    }))
}
