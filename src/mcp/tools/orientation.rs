//! Tools 1–4 — orientation & structure (docs/tool-surface.md §Orientation).
//!
//! `bootstrap` gives a caller a bounded first-contact orientation: build-owned
//! posture, principal and workspace footing, standing context, a point-in-time
//! world preview, intent/session boundaries, callable next steps, and legacy
//! compatibility projections. `describe_schema` gets the easy Rust
//! version of its contract: the DDL is a frozen in-crate constant, so the
//! static half is a compile-time fact, with PRAGMA answering only the live
//! half (`user_version`).
//!
//! `get_dashboard`'s attention buckets are deterministic reads over spine
//! columns and links, no model: `active`/`stale` split by `last_activity_at`
//! against a caller-set staleness floor, and lifecycle now governs ENTRY to
//! that split rather than merely gating on non-nullness — a record whose
//! lifecycle interprets as terminal is finished, so it leaves the attention
//! view instead of ageing to the head of the neglect list. A record whose
//! lifecycle cannot be interpreted is NOT excluded: an ungoverned kind is a
//! governance gap, not a claim that the work is done, and dropping it would
//! hide real open work. It stays in the split and is additionally named in
//! the `unclassified_lifecycle` census with the reason. `blocked` is
//! link-derived — an incoming `blocks` edge or an outgoing `depends_on` edge
//! whose OTHER endpoint is live and unarchived (tombstoning or archiving a
//! blocker releases what it blocked) — and does not consult lifecycle at all.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::{self, Capability};
use crate::db::{apply_schema, open_database, Db};
use crate::error::{Error, Result};
use crate::query::lens::{self, ReadLens};
use crate::query::lifecycle::{LifecycleInterpretation, LifecycleInterpreter};
use crate::query::{cascade, pipeline, tree};
use crate::schema::{
    CONTROL_PROJECTION_TABLES, DDL_STATEMENTS, DERIVATION_PROJECTION_TABLES, FROZEN_DDL_SHA256,
    META_PROJECTION_TABLES, PROJECTION_TABLES, REQUIRED_TABLES, SPINE_TYPES,
};
use crate::{
    CURRENT_ENGINE_SCHEMA_VERSION, ENGINE_NAME, ENGINE_VERSION, GIT_SHA,
    SUPPORTED_ENGINE_SCHEMA_BASELINE,
};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{can_record, parse_args, require_record, visible_ids};

/// Default depth for `get_structure` walks.
const DEFAULT_STRUCTURE_DEPTH: i64 = 3;
/// Default staleness floor for `get_dashboard`, in days.
const DEFAULT_STALE_AFTER_DAYS: i64 = 14;
/// Ceiling on the staleness floor — bounds the value long before
/// `chrono::Duration::days` (which PANICS on overflow) or the timestamp
/// subtraction could see anything unrepresentable.
const MAX_STALE_AFTER_DAYS: i64 = 36_500;
/// Default and maximum per-bucket sizes for `get_dashboard`.
const DEFAULT_DASHBOARD_LIMIT: usize = 20;
const MAX_DASHBOARD_LIMIT: usize = 100;

/// Bootstrap's bounds are compositional: authored instructions do not compete
/// with the guaranteed orientation, and caller-visible previews cannot expand
/// with the size of the database. The transport ceiling is derived from every
/// valid component rather than serving as the design input for the prose.
pub const MAX_BOOTSTRAP_ORIENTATION_BYTES: usize = 8 * 1024;
pub const MAX_BOOTSTRAP_FOOTING_BYTES: usize = 8 * 1024;
pub const MAX_BOOTSTRAP_CURRENT_WORLD_BYTES: usize = 8 * 1024;
pub const MAX_BOOTSTRAP_INTENTFUL_SESSIONS_BYTES: usize = 2 * 1024;
pub const MAX_BOOTSTRAP_NEXT_STEPS_BYTES: usize = 8 * 1024;
pub const MAX_BOOTSTRAP_SESSION_BYTES: usize = 1024;
pub const MAX_BOOTSTRAP_COMPATIBILITY_BYTES: usize = 16 * 1024;
pub const MAX_BOOTSTRAP_CONTRACT_BYTES: usize = 4 * 1024;
pub const MAX_BOOTSTRAP_DIAGNOSTICS_BYTES: usize = 8 * 1024;
// The complete standby status can contain distinct serving and accepted
// generation provenance plus live refresh evidence. Every variable collection
// inside that projection is independently bounded; reserve enough for its
// maximally populated valid shape rather than making degraded Bootstrap fail.
pub const MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES: usize = 8 * 1024;
/// JSON structure surrounding the bounded top-level values. This covers the
/// object braces, separators, and serialized field names, including the
/// `tool_exposure` projection added by the registry after this handler.
pub const MAX_BOOTSTRAP_JSON_ENVELOPE_BYTES: usize = 4 * 1024;
/// Fixed JSON fields around caller-authored instruction bodies and their
/// separately bounded metadata, plus the temporary compatibility copy of the
/// build-owned orientation entry.
pub const MAX_BOOTSTRAP_INSTRUCTION_CONTEXT_OVERHEAD_BYTES: usize = 16 * 1024;
pub const MAX_BOOTSTRAP_INSTRUCTION_CONTEXT_BYTES: usize =
    crate::instructions::MAX_RESOLVED_INSTRUCTION_BYTES
        + crate::instructions::MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES
        + MAX_BOOTSTRAP_ORIENTATION_BYTES
        + MAX_BOOTSTRAP_INSTRUCTION_CONTEXT_OVERHEAD_BYTES;
pub const MAX_BOOTSTRAP_TOTAL_BYTES: usize = MAX_BOOTSTRAP_ORIENTATION_BYTES
    + MAX_BOOTSTRAP_FOOTING_BYTES
    + MAX_BOOTSTRAP_CURRENT_WORLD_BYTES
    + MAX_BOOTSTRAP_INTENTFUL_SESSIONS_BYTES
    + MAX_BOOTSTRAP_NEXT_STEPS_BYTES
    + MAX_BOOTSTRAP_SESSION_BYTES
    + MAX_BOOTSTRAP_COMPATIBILITY_BYTES
    + MAX_BOOTSTRAP_CONTRACT_BYTES
    + MAX_BOOTSTRAP_DIAGNOSTICS_BYTES
    + MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES
    + MAX_BOOTSTRAP_JSON_ENVELOPE_BYTES
    + MAX_BOOTSTRAP_INSTRUCTION_CONTEXT_BYTES;

/// Compatibility name retained for callers/tests that tracked the previous
/// monolithic fixed-envelope constant. Its meaning is now the sum of all
/// caller-independent and bounded caller-relative non-instruction components.
pub const MAX_BOOTSTRAP_FIXED_ENVELOPE_BYTES: usize = MAX_BOOTSTRAP_ORIENTATION_BYTES
    + MAX_BOOTSTRAP_FOOTING_BYTES
    + MAX_BOOTSTRAP_CURRENT_WORLD_BYTES
    + MAX_BOOTSTRAP_INTENTFUL_SESSIONS_BYTES
    + MAX_BOOTSTRAP_NEXT_STEPS_BYTES
    + MAX_BOOTSTRAP_SESSION_BYTES
    + MAX_BOOTSTRAP_COMPATIBILITY_BYTES
    + MAX_BOOTSTRAP_CONTRACT_BYTES
    + MAX_BOOTSTRAP_DIAGNOSTICS_BYTES
    + MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES
    + MAX_BOOTSTRAP_JSON_ENVELOPE_BYTES;

const BOOTSTRAP_CONTRACT_VERSION: &str = "native.bootstrap.v3";
/// Build-owned tool references emitted structurally by Bootstrap's
/// `next_steps`. QuickStart's continuation-closure regression consumes this
/// seam directly instead of inferring dependencies from rendered guidance.
pub(crate) const ACTIONABLE_NEXT_STEP_TOOLS: [&str; 4] =
    ["set_intent", "get_record", "get_dashboard", "get_structure"];
const RECENT_ACTIVITY_LIMIT: usize = 3;
const OPEN_WORK_LIMIT: usize = 2;
const WORKSPACE_VISIBILITY_SCAN_LIMIT: usize = 2_048;
const REGISTERED_HUMAN_SCAN_LIMIT: usize = 512;
const CURRENT_WORLD_SCAN_LIMIT: usize = 64;
const MAX_PREVIEW_ID_BYTES: usize = 256;
const MAX_PREVIEW_NAME_CHARS: usize = 160;
const MAX_PREVIEW_FACET_CHARS: usize = 64;
/// At most five world items are projected, so this leaves ample fixed-envelope
/// headroom inside `MAX_BOOTSTRAP_CURRENT_WORLD_BYTES` while rejecting an
/// author-controlled lifecycle interpretation that cannot be represented
/// faithfully. Semantic identities are never truncated.
const MAX_PREVIEW_ITEM_BYTES: usize = 1024;
const BOOTSTRAP_TOP_LEVEL_KEYS: &[&str] = &[
    "contract",
    "orientation",
    "principal",
    "workspace",
    "standing_context",
    "current_world",
    "intentful_sessions",
    "next_steps",
    "session",
    "diagnostics",
    "engine",
    "run",
    "roots",
    "instructions",
    "pending_obligations",
    "tool_exposure",
];

// ---------------------------------------------------------------------------
// Tool 1 — bootstrap
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapArgs {}

async fn user_version(db: &Db) -> Result<i64> {
    let row = sqlx::query("PRAGMA user_version")
        .fetch_one(db.write_pool())
        .await?;
    Ok(row.get(0))
}

fn serialized_bytes(value: &Value) -> Result<usize> {
    Ok(serde_json::to_vec(value)?.len())
}

fn enforce_component(label: &str, value: &Value, limit: usize) -> Result<usize> {
    let bytes = serialized_bytes(value)?;
    if bytes > limit {
        return Err(Error::engine(format!(
            "bootstrap {label} component is {bytes} bytes; limit is {limit} bytes"
        )));
    }
    Ok(bytes)
}

fn bootstrap_json_envelope_bytes() -> Result<usize> {
    // The serialized size contributed by the surrounding object is invariant
    // with respect to its values. `null` contributes four bytes per value, so
    // subtracting those leaves the exact braces, keys, colons, and commas.
    let placeholder = Value::Object(
        BOOTSTRAP_TOP_LEVEL_KEYS
            .iter()
            .map(|key| ((*key).to_string(), Value::Null))
            .collect(),
    );
    Ok(serialized_bytes(&placeholder)? - (BOOTSTRAP_TOP_LEVEL_KEYS.len() * 4))
}

fn bounded_text(value: &str, max_chars: usize) -> (String, bool) {
    if value.chars().count() <= max_chars {
        return (value.to_string(), false);
    }
    let kept = value.chars().take(max_chars).collect::<String>();
    (format!("{kept}…"), true)
}

async fn bounded_visible_record_count(db: &Db, caller: &Caller) -> Result<(usize, bool)> {
    let not_hidden = crate::query::not_hidden_predicate("r");
    if super::is_legacy_local(caller) {
        let sql =
            format!("SELECT COUNT(*) FROM records r WHERE r.deleted_at IS NULL AND {not_hidden}");
        let count: i64 = sqlx::query_scalar(&sql).fetch_one(db.pool()).await?;
        return Ok((count.max(0) as usize, false));
    }
    let sql = format!(
        "SELECT r.id FROM records r WHERE r.deleted_at IS NULL AND {not_hidden} ORDER BY r.id LIMIT ?"
    );
    let mut ids: Vec<String> = sqlx::query_scalar(&sql)
        .bind((WORKSPACE_VISIBILITY_SCAN_LIMIT + 1) as i64)
        .fetch_all(db.pool())
        .await?;
    let truncated = ids.len() > WORKSPACE_VISIBILITY_SCAN_LIMIT;
    ids.truncate(WORKSPACE_VISIBILITY_SCAN_LIMIT);
    let visible = visible_ids(db, caller, ids).await?;
    Ok((visible.len(), truncated))
}

async fn principal_footing(db: &Db, caller: &Caller, observed_at: &str) -> Result<Value> {
    let row = sqlx::query(
        "SELECT r.id, r.name,
                (SELECT e.identifier FROM bindings e
                  WHERE e.record_id=r.id AND e.system='email' AND e.is_canonical=1
                  ORDER BY e.identifier LIMIT 1) AS email
           FROM bindings a
           JOIN records r ON r.id=a.record_id
          WHERE a.system='account' AND a.identifier=? AND a.is_canonical=1
            AND r.deleted_at IS NULL
          LIMIT 1",
    )
    .bind(caller.credential())
    .fetch_optional(db.pool())
    .await?;

    let mut person_record_id = None;
    let mut display_name = None;
    let mut display_name_truncated = false;
    let mut email = None;
    let mut email_truncated = false;
    if let Some(row) = row {
        let id: String = row.try_get("id")?;
        if can_record(db, caller, &id, Capability::View).await? {
            person_record_id = Some(id);
            let raw_name: String = row.try_get("name")?;
            if !raw_name.trim().is_empty() {
                let (bounded, truncated) = bounded_text(&raw_name, MAX_PREVIEW_NAME_CHARS);
                display_name = Some(bounded);
                display_name_truncated = truncated;
            }
            let raw_email: Option<String> = row.try_get("email")?;
            if let Some(raw_email) = raw_email.filter(|value| !value.trim().is_empty()) {
                let (bounded, truncated) = bounded_text(&raw_email, MAX_PREVIEW_NAME_CHARS);
                email = Some(bounded);
                email_truncated = truncated;
            }
        }
    }

    let identity_basis = if person_record_id.is_some() {
        "verified portable account binding"
    } else {
        "authenticated credential; no visible portable person binding"
    };
    let mut private_tx = db.pool().begin().await?;
    let private_context_row = sqlx::query(
        "SELECT mc.root_record_id,mc.person_record_id,r.name,r.deleted_at
           FROM member_contexts mc JOIN records r ON r.id=mc.root_record_id
          WHERE mc.account_id=?",
    )
    .bind(caller.credential())
    .fetch_optional(&mut *private_tx)
    .await?;
    let private_context = if let Some(row) = private_context_row {
        let root_record_id: String = row.try_get("root_record_id")?;
        let context_person_record_id: String = row.try_get("person_record_id")?;
        let deleted: Option<String> = row.try_get("deleted_at")?;
        let capability = authorization::effective_capability_on(
            &mut private_tx,
            crate::authorization::Principal::bound(caller.credential(), true),
            &root_record_id,
        )
        .await
        .ok();
        if deleted.is_none()
            && capability.is_some_and(|capability| capability.allows(Capability::Manage))
        {
            let policy_rows = sqlx::query(
                "SELECT subject_kind,subject_id,effect,capability FROM policy_entries
                  WHERE policy_anchor_id=? ORDER BY subject_kind,subject_id LIMIT 2",
            )
            .bind(&root_record_id)
            .fetch_all(&mut *private_tx)
            .await?;
            let account_only_private = policy_rows.len() == 1
                && policy_rows[0].try_get::<String, _>("subject_kind")? == "account"
                && policy_rows[0].try_get::<String, _>("subject_id")? == caller.credential()
                && policy_rows[0].try_get::<String, _>("effect")? == "allow"
                && policy_rows[0].try_get::<String, _>("capability")? == "manage";
            let existing_starting_contexts: Vec<(String, i64)> = if account_only_private {
                sqlx::query_as(
                    "SELECT r.id,
                            CASE WHEN r.owner_id=? AND r.policy_anchor_id=? THEN 1 ELSE 0 END contract_valid
                       FROM records r
                      WHERE r.home_id=? AND r.type='Document' AND r.kind='note'
                        AND r.name='Starting context' AND r.deleted_at IS NULL
                      ORDER BY r.id LIMIT 2",
                )
                .bind(&context_person_record_id)
                .bind(&root_record_id)
                .bind(&root_record_id)
                .fetch_all(&mut *private_tx)
                .await?
            } else {
                vec![]
            };
            let raw_name: String = row.try_get("name")?;
            let (name, name_truncated) = bounded_text(&raw_name, MAX_PREVIEW_NAME_CHARS);
            let starting_context_contract = if account_only_private
                && existing_starting_contexts.len() <= 1
                && existing_starting_contexts
                    .first()
                    .is_none_or(|(id, contract_valid)| {
                        id.len() <= MAX_PREVIEW_ID_BYTES && *contract_valid != 0
                    }) {
                let existing_note_id = existing_starting_contexts.first().map(|(id, _)| id);
                json!({
                    "available": true,
                    "record_shape": { "type": "Document", "kind": "note", "name": "Starting context" },
                    "placement": "create directly under root_record_id",
                    "preview_before_write": true,
                    "explicit_consent_before_write": true,
                    "allowed_content": ["current aim", "useful learned context", "work or decision made", "next step", "material uncertainty and source attribution"],
                    "body_template": "# Starting context\n\n## Current aim\n<nonempty member-stated content>\n\n## Useful learned context\n<nonempty member-stated content>\n\n## Work or decision made\n<nonempty member-stated content>\n\n## Next step\n<nonempty member-stated content>\n\n## Material uncertainty and source attribution\n<nonempty uncertainty and attribution>",
                    "controls": ["inspect", "edit", "delete", "export with the portable database"],
                    "boundaries": ["do not infer personal, organisational, or external-system facts", "do not create shared records or extracted entities through this private flow"],
                    "existing_note_id": existing_note_id,
                    "write_path": if existing_starting_contexts.is_empty() { "create after consented preview" } else { "inspect and update the sole existing note after consented preview" }
                })
            } else {
                json!({
                    "available": false,
                    "blocker": if account_only_private { "My agent context contains conflicting Starting context records. Inspect and resolve duplicates, ownership, policy boundaries, or a same-run prewritten note before previewing or writing." } else { "My agent context has a custom policy. Do not preview or write Starting context until the caller-only private boundary is restored." }
                })
            };
            Some(json!({
            "root_record_id": root_record_id,
            "name": name,
            "name_truncated": name_truncated,
            "visibility": if account_only_private { "account_only_private" } else { "custom_policy" },
            "visibility_guidance": if account_only_private { "The current root policy grants only this authenticated account Manage." } else { "The current root policy is customized; inspect it before describing the context as private." },
            "starting_context_contract": starting_context_contract,
            }))
        } else {
            None
        }
    } else {
        None
    };
    private_tx.rollback().await?;
    Ok(json!({
        "person_record_id": person_record_id,
        "display_name": display_name,
        "display_name_truncated": display_name_truncated,
        "email": email,
        "email_truncated": email_truncated,
        "identity_basis": identity_basis,
        "principal_distinction": "The authenticated human principal is distinct from the agent or client acting for them.",
        "local_timezone": null,
        "local_datetime": null,
        "local_time_status": "unknown: no verified principal timezone is available in native-ce",
        "utc_datetime": observed_at,
        "private_context": private_context,
    }))
}

async fn workspace_footing(
    db: &Db,
    root: &sqlx::sqlite::SqliteRow,
    caller: &Caller,
) -> Result<Value> {
    let raw_name: String = root.try_get("name")?;
    let (name, name_truncated) = bounded_text(&raw_name, MAX_PREVIEW_NAME_CHARS);
    let (records_visible, record_count_truncated) =
        bounded_visible_record_count(db, caller).await?;
    let mut human_candidates: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT r.id
           FROM records r
           JOIN bindings a ON a.record_id=r.id
          WHERE r.deleted_at IS NULL AND r.type='Entity' AND r.kind='person'
            AND a.system='account' AND a.is_canonical=1
          ORDER BY r.id LIMIT ?",
    )
    .bind((REGISTERED_HUMAN_SCAN_LIMIT + 1) as i64)
    .fetch_all(db.pool())
    .await?;
    let human_count_truncated = human_candidates.len() > REGISTERED_HUMAN_SCAN_LIMIT;
    human_candidates.truncate(REGISTERED_HUMAN_SCAN_LIMIT);
    let registered_humans_visible = if super::is_legacy_local(caller) {
        human_candidates.len()
    } else {
        visible_ids(db, caller, human_candidates).await?.len()
    };

    Ok(json!({
        "scope": "one connected Native database and one primary workspace",
        "primary_workspace": {
            "id": crate::schema::ROOT_RECORD_ID,
            "name": name,
            "name_truncated": name_truncated,
        },
        "records_visible": records_visible,
        "record_count_truncated": record_count_truncated,
        "record_count_qualification": if record_count_truncated {
            "lower bound from an operationally bounded visibility scan; live, non-hidden records visible to this caller"
        } else {
            "live, non-hidden records visible to this caller"
        },
        "registered_humans_visible": registered_humans_visible,
        "human_count_truncated": human_count_truncated,
        "human_count_qualification": if human_count_truncated {
            "lower bound from an operationally bounded visibility scan; not proof of an exhaustive roster"
        } else {
            "registered human identity records visible to this caller; not proof of an exhaustive roster"
        },
        "known_limitations": ["personal-home and multi-workspace orientation are outside the current native-ce bootstrap horizon"],
    }))
}

fn world_item(
    row: &sqlx::sqlite::SqliteRow,
    lifecycle_interpretation: &crate::query::lifecycle::LifecycleInterpretation,
) -> Result<Option<Value>> {
    let id: String = row.try_get("id")?;
    if id.len() > MAX_PREVIEW_ID_BYTES {
        return Ok(None);
    }
    let raw_name: String = row.try_get("name")?;
    let (name, name_truncated) = bounded_text(&raw_name, MAX_PREVIEW_NAME_CHARS);
    let kind: Option<String> = row.try_get("kind")?;
    let (kind, kind_truncated) = kind
        .map(|value| bounded_text(&value, MAX_PREVIEW_FACET_CHARS))
        .map_or((None, false), |(value, truncated)| (Some(value), truncated));
    let item = json!({
        "id": id,
        "name": name,
        "name_truncated": name_truncated,
        "type": row.try_get::<String, _>("type")?,
        "kind": kind,
        "kind_truncated": kind_truncated,
        "lifecycle_interpretation": lifecycle_interpretation,
        "last_activity_at": row.try_get::<String, _>("observed_activity_at")?,
    });
    if serialized_bytes(&item)? > MAX_PREVIEW_ITEM_BYTES {
        return Ok(None);
    }
    Ok(Some(item))
}

async fn current_world_preview(db: &Db, caller: &Caller, observed_at: &str) -> Result<Value> {
    let not_hidden = crate::query::not_hidden_predicate("r");
    let sql = format!(
        "SELECT r.id,r.type,r.kind,r.name,r.home_id,r.lifecycle,
                COALESCE(r.last_activity_at,r.updated_at,r.created_at) AS observed_activity_at
           FROM records r
          WHERE r.deleted_at IS NULL AND {not_hidden}
            AND r.id NOT IN (?,?)
            AND r.id NOT LIKE 'native:%'
            AND NOT EXISTS (SELECT 1 FROM facet_values av
                             WHERE av.record_id=r.id AND av.key='archived')
            AND NOT EXISTS (SELECT 1 FROM instruction_bindings ib
                             WHERE ib.source_record_id=r.id)
            AND NOT EXISTS (SELECT 1 FROM onboarding_programme_sources ops
                             WHERE ops.source_record_id=r.id)
            AND NOT EXISTS (SELECT 1 FROM member_contexts mc
                             WHERE mc.person_record_id=r.id OR mc.root_record_id=r.id)
          ORDER BY observed_activity_at DESC,r.id LIMIT ?"
    );
    let rows = sqlx::query(&sql)
        .bind(crate::schema::ROOT_RECORD_ID)
        .bind(crate::schema::UNFILED_RECORD_ID)
        .bind((CURRENT_WORLD_SCAN_LIMIT + 1) as i64)
        .fetch_all(db.pool())
        .await?;
    let scan_truncated = rows.len() > CURRENT_WORLD_SCAN_LIMIT;
    let rows = rows
        .into_iter()
        .take(CURRENT_WORLD_SCAN_LIMIT)
        .collect::<Vec<_>>();
    let candidate_ids = rows
        .iter()
        .map(|row| row.try_get::<String, _>("id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let visible = if super::is_legacy_local(caller) {
        candidate_ids.into_iter().collect::<HashSet<_>>()
    } else {
        visible_ids(db, caller, candidate_ids).await?
    };
    let lifecycle_interpreter =
        crate::query::lifecycle::LifecycleInterpreter::load(db, Some(super::principal(caller)))
            .await?;

    let mut recent = Vec::new();
    let mut open_work = Vec::new();
    let mut recent_total = 0usize;
    let mut open_work_total = 0usize;
    let mut omitted_unrepresentable = 0usize;
    for row in &rows {
        let id: String = row.try_get("id")?;
        if !visible.contains(&id) {
            continue;
        }
        recent_total += 1;
        let record_type: String = row.try_get("type")?;
        let kind: Option<String> = row.try_get("kind")?;
        let home_id: Option<String> = row.try_get("home_id")?;
        let lifecycle: Option<String> = row.try_get("lifecycle")?;
        let interpretation = lifecycle_interpreter.interpret(
            &record_type,
            kind.as_deref(),
            home_id.as_deref(),
            lifecycle.as_deref(),
        );
        let item = world_item(row, &interpretation)?;
        if item.is_none() {
            omitted_unrepresentable += 1;
        }
        if recent.len() < RECENT_ACTIVITY_LIMIT {
            if let Some(item) = item.clone() {
                recent.push(item);
            }
        }
        let is_open_work = record_type == "WorkItem"
            && matches!(
                &interpretation,
                crate::query::lifecycle::LifecycleInterpretation::Governed(value)
                    if value.terminality == "open"
            );
        if is_open_work {
            open_work_total += 1;
            if open_work.len() < OPEN_WORK_LIMIT {
                if let Some(item) = item {
                    open_work.push(item);
                }
            }
        }
    }

    Ok(json!({
        "observed_at": observed_at,
        "freshness": "point-in-time caller-visible preview; activity may have changed since this observation",
        "scope": "bounded preview, not a complete dashboard or claim of omniscience",
        "scan_limit": CURRENT_WORLD_SCAN_LIMIT,
        "scan_truncated": scan_truncated,
        "recent_activity": {
            "items": recent,
            "total_count": recent_total,
            "limit": RECENT_ACTIVITY_LIMIT,
            "truncated": scan_truncated || recent_total > RECENT_ACTIVITY_LIMIT,
        },
        "open_work": {
            "items": open_work,
            "total_count": open_work_total,
            "limit": OPEN_WORK_LIMIT,
            "truncated": scan_truncated || open_work_total > OPEN_WORK_LIMIT,
        },
        "resumability": {
            "assessed": false,
            "reason": "Bootstrap does not infer same-agent resumability from lifecycle alone; set_intent owns the purpose-relative resume briefing.",
        },
        "omitted_unrepresentable_count": omitted_unrepresentable,
    }))
}

fn next_steps(intent_declared: bool, world: &Value, run_key: &str) -> Value {
    let [set_intent_tool, get_record_tool, get_dashboard_tool, get_structure_tool] =
        ACTIONABLE_NEXT_STEP_TOOLS;
    let mut items = Vec::new();
    if !intent_declared {
        items.push(json!({
            "tool": set_intent_tool,
            "label": "Declare the current intent",
            "why": "Establish purposeful continuity and receive the separate bounded purpose-relative briefing.",
            "arguments": {
                "intent": "<infer the current aim from the user's request>",
                "run_key": run_key,
            },
            "replace_placeholders": ["intent"],
        }));
    }
    if let Some(id) = world
        .pointer("/recent_activity/items/0/id")
        .and_then(Value::as_str)
    {
        items.push(json!({
            "tool": get_record_tool,
            "label": "Inspect recent activity",
            "why": "Understand the most recently active visible record and decide whether it is relevant to the user's request.",
            "arguments": { "ids": [id], "run_key": run_key },
        }));
    }
    items.push(json!({
        "tool": get_dashboard_tool,
        "label": "Check broader attention",
        "why": "Inspect active, stale, and blocked work when it matters to the user's request.",
        "arguments": { "run_key": run_key },
    }));
    items.push(json!({
        "tool": get_structure_tool,
        "label": "Browse the durable structure",
        "why": "Use placement and wider context when the task depends on where work lives.",
        "arguments": {
            "root_id": crate::schema::ROOT_RECORD_ID,
            "run_key": run_key,
        },
    }));
    json!({
        "items": items,
        "guidance": "Context-sensitive affordances, not a mandatory checklist.",
    })
}

async fn bootstrap(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let _args: BootstrapArgs = parse_args("bootstrap", arguments)?;
    resolve_session_footing(&db, &caller, "bootstrap").await
}

/// Resolve Bootstrap's canonical read-only session footing.
pub(crate) async fn resolve_session_footing(db: &Db, caller: &Caller, tool: &str) -> Result<Value> {
    // Bootstrap is the sole first-call issuer. QuickStart is a static launcher
    // and deliberately never enters this resolver. The universal `new` /
    // `new:<agent_key>` sentinels remain the same fail-open minting path when a
    // caller starts elsewhere.
    //
    // Minting is not reserving. Nothing is written, and the key becomes real
    // only by being used. A caller who already HAS a key gets it echoed back
    // rather than a new one, so a mid-run bootstrap does not invite an agent to
    // rotate its own key and fragment its run.
    let run_key = match caller.run_key() {
        Some(existing) => existing.to_string(),
        None => crate::runkey::suggest(db).await?,
    };

    let not_hidden_r = crate::query::not_hidden_predicate("r");
    let not_hidden_c = crate::query::not_hidden_predicate("c");
    let roots_sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.persistence
          FROM records r
          WHERE r.home_id IS NULL AND r.deleted_at IS NULL
            AND {not_hidden_r}
            AND NOT EXISTS (SELECT 1 FROM facet_values av
                             WHERE av.record_id = r.id AND av.key = 'archived')
          ORDER BY r.name, r.id"
    );
    let root_rows = sqlx::query(&roots_sql).fetch_all(db.write_pool()).await?;
    if root_rows.len() != 1
        || root_rows[0].try_get::<String, _>("id")? != crate::schema::ROOT_RECORD_ID
    {
        return Err(Error::engine(format!(
            "{tool}: canonical-root invariant violated: expected exactly one live visible parentless record '{}', found {}",
            crate::schema::ROOT_RECORD_ID,
            root_rows.len()
        )));
    }
    let root = &root_rows[0];
    let root_id: String = root.try_get("id")?;
    if !can_record(db, caller, &root_id, Capability::View).await? {
        return Err(Error::auth(format!(
            "{tool}: canonical root is not visible to this caller"
        )));
    }
    let child_ids_sql = format!(
        "SELECT c.id FROM records c
          WHERE c.home_id=? AND c.deleted_at IS NULL
            AND {not_hidden_c}
            AND NOT EXISTS (SELECT 1 FROM facet_values av
                             WHERE av.record_id=c.id AND av.key='archived')"
    );
    let child_ids: Vec<String> = sqlx::query_scalar(&child_ids_sql)
        .bind(&root_id)
        .fetch_all(db.write_pool())
        .await?;
    let mut visible_children = 0i64;
    for child in child_ids {
        if can_record(db, caller, &child, Capability::View).await? {
            visible_children += 1;
        }
    }
    let observed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut principal = principal_footing(db, caller, &observed_at).await?;
    let workspace = workspace_footing(db, root, caller).await?;
    let current_world = current_world_preview(db, caller, &observed_at).await?;
    let intent_declared = caller.intent().is_some();
    let next_steps = next_steps(intent_declared, &current_world, &run_key);
    let orientation = json!({
        "template_key": crate::instructions::ENGINE_ORIENTATION_TEMPLATE_KEY,
        "template_version": crate::instructions::ENGINE_ORIENTATION_TEMPLATE_VERSION,
        "content": crate::instructions::ENGINE_ORIENTATION,
        "ownership": "build-owned and guaranteed independently of portable instruction resolution",
    });
    let portable_resolution = crate::instructions::resolve_for_account(
        db.write_pool(),
        caller.credential(),
        Some(&run_key),
    )
    .await?;
    let portable_status = portable_resolution.instructions.status.clone();
    let portable_entry_count = portable_resolution.instructions.entries.len();
    let pending_obligation_count = portable_resolution.pending_obligations.len();
    let native_first_run_obligation = (portable_status == "ready")
        .then(|| {
            portable_resolution
                .pending_obligations
                .iter()
                .find(|obligation| {
                    matches!(
                        obligation.programme_id.as_str(),
                        "native:onboarding-owner-first-run" | "native:onboarding-member-joined"
                    )
                })
        })
        .flatten();
    let passive_mode = native_first_run_obligation.and_then(|obligation| {
        match obligation.progress_phase.as_deref() {
            Some("deferred") => Some((
                "deferred_wait",
                "wait_for_explicit_resume",
                "A resume-after date is reminder eligibility only and does not authorize prompting or writing.",
            )),
            Some("artifact_written") | Some("value_delivered")
                if obligation.progress_artifact_id.is_some() => Some((
                "already_written",
                "none",
                "The Starting context is already recorded; do not preview or write it again.",
            )),
            _ => None,
        }
    });
    let account_only_private = principal
        .pointer("/private_context/visibility")
        .and_then(Value::as_str)
        == Some("account_only_private");
    if native_first_run_obligation.is_none() || passive_mode.is_some() {
        if let Some(contract) = principal.pointer_mut("/private_context/starting_context_contract")
        {
            let (mode, onboarding_action, guidance) = passive_mode.unwrap_or(if account_only_private {
                ("ordinary_private_context", "none", "No first-run onboarding action is pending.")
            } else {
                ("ordinary_context", "none", "No first-run onboarding action is pending; inspect the custom policy before making any privacy claim.")
            });
            *contract = json!({
                "available": false,
                "mode": mode,
                "onboarding_action": onboarding_action,
                "guidance": guidance,
                "controls": ["inspect", "edit", "delete", "export with the portable database"]
            });
        }
    }
    // Keep the former engine instruction entry for one migration window. New
    // clients consume `orientation`; invalid portable state still leaves this
    // legacy stack empty and non-authoritative.
    let instruction_resolution =
        crate::instructions::prepend_engine_instruction(portable_resolution);
    let standing_context = json!({
        "portable_instructions": {
            "status": portable_status,
            "entry_count": portable_entry_count,
            "exact_entries_path": "/instructions/entries",
            "diagnostics_path": "/instructions/diagnostics",
        },
        "pending_onboarding_obligations": {
            "count": pending_obligation_count,
            "exact_items_path": "/pending_obligations",
        },
        "note": "Permissions and product boundaries still apply when no additional instruction body is present.",
        "product_boundaries": [
            "Native does not passively learn from or observe activity outside durable recorded state and calls made through currently available tools.",
            "Do not claim unverified training, egress, encryption, security, compliance, confidentiality, residency, or data-sovereignty properties.",
            "Do not run unprompted bulk surveys or imports, or offer connectors that are not currently available."
        ],
    });
    let intentful_sessions = json!({
        "intent_declared_for_run": intent_declared,
        "declaration_tool": "set_intent",
        "briefing_location": "the separate set_intent response",
        "why": "Native uses agent-declared intent to return a purpose-relative briefing, connect work into an inspectable run, surface resumable work and open claims, and leave a more intelligible hand-off.",
        "guidance": "Infer a clear intent from the user's request rather than asking them to repeat it. Update the declaration when the underlying aim materially changes.",
        "boundaries": [
            {
                "kind": "bootstrap",
                "statement": "Bootstrap does not accept or resolve intent.",
            },
            {
                "kind": "declaration",
                "statement": "set_intent is a separate call that declares intent and returns the purpose-relative briefing.",
            },
            {
                "kind": "history",
                "statement": "Changing intent begins a new declaration window while preserving earlier run history.",
            },
        ],
    });
    let run = json!({
        "run_key": run_key,
        "how": "Required: pass this exact run_key on every call, reads included, and reuse it throughout the run. Reuse groups writes and reads for inspection and recovery; it does not provide run-scoped rollback.",
    });
    let session = json!({
        "run_key": run["run_key"],
        "reuse_required": true,
        "guidance": "Reuse this exact key as run_key on subsequent calls, reads included. It groups this session's reads and writes for continuity, inspection, and recovery.",
        "whole_run_rollback": false,
    });
    let engine = json!({
        "name": ENGINE_NAME,
        "version": ENGINE_VERSION,
        "schema_version": CURRENT_ENGINE_SCHEMA_VERSION,
        "user_version": user_version(db).await?,
    });
    let roots = json!({
        "items": [{
            "id": root_id,
            "type": root.try_get::<String, _>("type")?,
            "kind": root.try_get::<Option<String>, _>("kind")?,
            "name": root.try_get::<String, _>("name")?,
            "persistence": root.try_get::<String, _>("persistence")?,
            "child_count": visible_children,
        }],
        "total": 1,
        "continuation": {
            "tool": "get_structure",
            "arguments": { "root_id": crate::schema::ROOT_RECORD_ID },
        },
    });

    let orientation_bytes =
        enforce_component("orientation", &orientation, MAX_BOOTSTRAP_ORIENTATION_BYTES)?;
    let footing = json!({ "principal": &principal, "workspace": &workspace, "standing_context": &standing_context });
    let footing_bytes = enforce_component("footing", &footing, MAX_BOOTSTRAP_FOOTING_BYTES)?;
    let current_world_bytes = enforce_component(
        "current-world",
        &current_world,
        MAX_BOOTSTRAP_CURRENT_WORLD_BYTES,
    )?;
    let intentful_sessions_bytes = enforce_component(
        "intentful-sessions",
        &intentful_sessions,
        MAX_BOOTSTRAP_INTENTFUL_SESSIONS_BYTES,
    )?;
    let next_steps_bytes =
        enforce_component("next-steps", &next_steps, MAX_BOOTSTRAP_NEXT_STEPS_BYTES)?;
    let session_bytes = enforce_component("session", &session, MAX_BOOTSTRAP_SESSION_BYTES)?;
    let compatibility = json!({ "engine": &engine, "run": &run, "roots": &roots });
    let compatibility_bytes = enforce_component(
        "compatibility",
        &compatibility,
        MAX_BOOTSTRAP_COMPATIBILITY_BYTES,
    )?;
    let instruction_context = json!({
        "instructions": &instruction_resolution.instructions,
        "pending_obligations": &instruction_resolution.pending_obligations,
    });
    let instruction_context_bytes = enforce_component(
        "instruction-context",
        &instruction_context,
        MAX_BOOTSTRAP_INSTRUCTION_CONTEXT_BYTES,
    )?;
    let json_envelope_bytes = bootstrap_json_envelope_bytes()?;
    if json_envelope_bytes > MAX_BOOTSTRAP_JSON_ENVELOPE_BYTES {
        return Err(Error::engine(format!(
            "bootstrap JSON envelope is {json_envelope_bytes} bytes; limit is {MAX_BOOTSTRAP_JSON_ENVELOPE_BYTES} bytes"
        )));
    }
    let contract = json!({
        "version": BOOTSTRAP_CONTRACT_VERSION,
        "intent_agnostic": true,
        "compatibility_projections": ["run", "roots", "instructions", "pending_obligations", "engine"],
        "bounds_bytes": {
            "orientation": MAX_BOOTSTRAP_ORIENTATION_BYTES,
            "footing": MAX_BOOTSTRAP_FOOTING_BYTES,
            "current_world": MAX_BOOTSTRAP_CURRENT_WORLD_BYTES,
            "intentful_sessions": MAX_BOOTSTRAP_INTENTFUL_SESSIONS_BYTES,
            "next_steps": MAX_BOOTSTRAP_NEXT_STEPS_BYTES,
            "session": MAX_BOOTSTRAP_SESSION_BYTES,
            "compatibility": MAX_BOOTSTRAP_COMPATIBILITY_BYTES,
            "contract": MAX_BOOTSTRAP_CONTRACT_BYTES,
            "diagnostics": MAX_BOOTSTRAP_DIAGNOSTICS_BYTES,
            "tool_exposure": MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES,
            "json_envelope": MAX_BOOTSTRAP_JSON_ENVELOPE_BYTES,
            "instruction_context": MAX_BOOTSTRAP_INSTRUCTION_CONTEXT_BYTES,
            "portable_instruction_bodies": crate::instructions::MAX_RESOLVED_INSTRUCTION_BYTES,
            "portable_context_metadata": crate::instructions::MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES,
            "instruction_context_overhead": MAX_BOOTSTRAP_INSTRUCTION_CONTEXT_OVERHEAD_BYTES,
            "total": MAX_BOOTSTRAP_TOTAL_BYTES,
        },
    });
    let contract_bytes = enforce_component("contract", &contract, MAX_BOOTSTRAP_CONTRACT_BYTES)?;
    let diagnostics = json!({
        "engine": &engine,
        "component_bytes": {
            "contract": contract_bytes,
            "orientation": orientation_bytes,
            "footing": footing_bytes,
            "current_world": current_world_bytes,
            "intentful_sessions": intentful_sessions_bytes,
            "next_steps": next_steps_bytes,
            "session": session_bytes,
            "compatibility": compatibility_bytes,
            "instruction_context": instruction_context_bytes,
            "json_envelope": json_envelope_bytes,
        },
        "instruction_provenance": "Retained under instructions.entries[].source; intentionally omitted from default text.",
    });
    enforce_component("diagnostics", &diagnostics, MAX_BOOTSTRAP_DIAGNOSTICS_BYTES)?;

    let payload = json!({
        "contract": contract,
        "orientation": orientation,
        "principal": principal,
        "workspace": workspace,
        "standing_context": standing_context,
        "current_world": current_world,
        "intentful_sessions": intentful_sessions,
        "next_steps": next_steps,
        "session": session,
        "diagnostics": diagnostics,
        // Compatibility projections retained for existing structured clients.
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            "schema_version": CURRENT_ENGINE_SCHEMA_VERSION,
            "user_version": user_version(db).await?,
        },
        "run": run,
        "roots": roots,
        "instructions": instruction_resolution.instructions,
        "pending_obligations": instruction_resolution.pending_obligations,
    });
    let total_bytes = serialized_bytes(&payload)?;
    if total_bytes > MAX_BOOTSTRAP_TOTAL_BYTES {
        return Err(Error::engine(format!(
            "bootstrap payload is {total_bytes} bytes; compositional transport limit is {MAX_BOOTSTRAP_TOTAL_BYTES} bytes"
        )));
    }
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Tool 2 — get_structure
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetStructureArgs {
    root_id: String,
    max_depth: Option<i64>,
    include_archived: Option<bool>,
    max_children_per_node: Option<i64>,
    #[serde(default)]
    exclude_types: Vec<String>,
}

async fn get_structure(db: Db, caller: Caller, mut arguments: Value) -> Result<Value> {
    const TOOL: &str = "get_structure";
    let as_of = lens::take_as_of(TOOL, &mut arguments)?;
    let args: GetStructureArgs = parse_args(TOOL, arguments)?;
    require_record(&db, &caller, TOOL, &args.root_id, Capability::View).await?;
    let Some(selector) = as_of else {
        return get_structure_from_lens(&ReadLens::live(&db), &caller, args).await;
    };
    let resolved = lens::resolve_as_of(&db, selector).await?;
    let scratch = open_database(":memory:").await?;
    let result = async {
        apply_schema(&scratch).await?;
        lens::replay_projection(&db, &scratch, resolved.resolved_content_seq).await?;
        let read_lens = ReadLens::historical(&scratch, &db, &resolved);
        let mut output = get_structure_from_lens(&read_lens, &caller, args).await?;
        lens::echo_temporal(&mut output, &resolved);
        Ok(output)
    }
    .await;
    scratch.close().await;
    result
}

async fn get_structure_from_lens(
    lens: &ReadLens<'_>,
    caller: &Caller,
    args: GetStructureArgs,
) -> Result<Value> {
    const TOOL: &str = "get_structure";
    let db = lens.projection().snapshot_pool();
    let row = sqlx::query("SELECT deleted_at FROM records WHERE id = ?")
        .bind(&args.root_id)
        .fetch_optional(db)
        .await?;
    let Some(row) = row else {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.root_id
        )));
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: record {} is deleted (tombstoned)",
            args.root_id
        )));
    }
    let requested_children = args
        .max_children_per_node
        .unwrap_or(tree::DEFAULT_MAX_CHILDREN_PER_NODE);
    if !(0..=tree::MAX_CHILDREN_PER_NODE).contains(&requested_children) {
        return Err(Error::engine(format!(
            "{TOOL}: max_children_per_node must be between 0 and {}",
            tree::MAX_CHILDREN_PER_NODE
        )));
    }
    for excluded in &args.exclude_types {
        if !SPINE_TYPES.contains(&excluded.as_str()) {
            return Err(Error::engine(format!(
                "{TOOL}: exclude_types entry '{excluded}' is not a spine type (closed set: {})",
                SPINE_TYPES.join(", ")
            )));
        }
    }
    let opts = tree::TreeOptions {
        max_depth: args.max_depth.unwrap_or(DEFAULT_STRUCTURE_DEPTH),
        include_archived: args.include_archived.unwrap_or(false),
        max_children_per_node: requested_children,
        exclude_types: args.exclude_types.clone(),
    };
    let max_depth = opts.max_depth;
    let max_children_per_node = opts.max_children_per_node;
    let nodes = if super::is_legacy_local(caller) {
        tree::descendants_from(lens.projection(), &args.root_id, opts).await?
    } else {
        tree::descendants_with_lens_as(lens, &args.root_id, opts, super::principal(caller)).await?
    };
    // Both bounds are echoed back: a caller comparing a node's `child_count`
    // against the siblings it received needs to know which cap produced the
    // gap, and defaults it never passed are exactly the ones it does not know.
    Ok(json!({
        "root_id": args.root_id,
        "max_depth": max_depth,
        "max_children_per_node": max_children_per_node,
        "nodes": nodes,
    }))
}

// ---------------------------------------------------------------------------
// Tool 3 — get_dashboard
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetDashboardArgs {
    scope: Option<String>,
    stale_after_days: Option<i64>,
    limit: Option<usize>,
}

/// A dashboard row: the record fields a triage view needs, no enrichment.
fn dashboard_entry(
    row: &sqlx::sqlite::SqliteRow,
    lifecycle_interpreter: &crate::query::lifecycle::LifecycleInterpreter,
) -> Result<Value> {
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    let home_id: Option<String> = row.try_get("home_id")?;
    let lifecycle: Option<String> = row.try_get("lifecycle")?;
    let lifecycle_interpretation = lifecycle_interpreter.interpret(
        &record_type,
        kind.as_deref(),
        home_id.as_deref(),
        lifecycle.as_deref(),
    );
    Ok(json!({
        "id": row.try_get::<String, _>("id")?,
        "type": record_type,
        "kind": kind,
        "name": row.try_get::<String, _>("name")?,
        "lifecycle_interpretation": lifecycle_interpretation,
        "maturity": row.try_get::<Option<String>, _>("maturity")?,
        "last_activity_at": row.try_get::<Option<String>, _>("last_activity_at")?,
    }))
}

/// A census row: the same dashboard shape plus WHY the lifecycle could not be
/// interpreted. Without the reason a reader cannot tell an ungoverned kind
/// from a token its vocabulary has retired.
fn dashboard_entry_with_reason(
    row: &sqlx::sqlite::SqliteRow,
    lifecycle_interpreter: &crate::query::lifecycle::LifecycleInterpreter,
    reason: &'static str,
) -> Result<Value> {
    let mut entry = dashboard_entry(row, lifecycle_interpreter)?;
    entry
        .as_object_mut()
        .expect("dashboard_entry always returns an object")
        .insert("reason".into(), Value::String(reason.into()));
    Ok(entry)
}

/// The governance-gap census that rides alongside the attention buckets.
///
/// This is NOT a fourth bucket and deliberately does not have a bucket's
/// shape: the records it names are ALSO in `active` or `stale`, and a caller
/// that treated it as a destination would double-count them. It answers one
/// question — which of the records I am being shown carry a lifecycle the
/// engine could not interpret, and why.
const UNCLASSIFIED_LIFECYCLE_NOTE: &str =
    "Diagnostic census, not a bucket: these records are ALSO reported in \
     `active` or `stale`, bucketed on `last_activity_at` alone, because an \
     uninterpretable lifecycle is a governance gap rather than evidence that \
     the work is finished. Each entry names why interpretation failed.";

async fn get_dashboard(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "get_dashboard";
    let args: GetDashboardArgs = parse_args(TOOL, arguments)?;
    let stale_after_days = args.stale_after_days.unwrap_or(DEFAULT_STALE_AFTER_DAYS);
    if !(1..=MAX_STALE_AFTER_DAYS).contains(&stale_after_days) {
        return Err(Error::engine(format!(
            "{TOOL}: 'stale_after_days' must be between 1 and {MAX_STALE_AFTER_DAYS}"
        )));
    }
    let limit = args.limit.unwrap_or(DEFAULT_DASHBOARD_LIMIT);
    if limit == 0 || limit > MAX_DASHBOARD_LIMIT {
        return Err(Error::engine(format!(
            "{TOOL}: 'limit' must be between 1 and {MAX_DASHBOARD_LIMIT}"
        )));
    }
    let scope_set: Option<HashSet<String>> = match &args.scope {
        Some(root) => {
            require_record(&db, &caller, TOOL, root, Capability::View).await?;
            let ids = tree::subtree_ids(&db, root).await?;
            if ids.is_empty() {
                return Err(Error::engine(format!(
                    "{TOOL}: scope record {root} does not exist"
                )));
            }
            Some(ids.into_iter().collect())
        }
        None => None,
    };
    let in_scope = |id: &str| scope_set.as_ref().is_none_or(|s| s.contains(id));
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(stale_after_days))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    // Everything that carries a lifecycle, most recent activity first; the
    // active/stale split is one pass against the cutoff. Bounded by the file
    // (one connected database), so no SQL-side limit before scope filtering.
    //
    // `lifecycle IS NOT NULL` is only the candidate gate. What the token MEANS
    // is not this query's to decide: a `completed` task and an `open` one are
    // indistinguishable in SQL, and hard-coding the finished tokens here would
    // both miss every kind-specific vocabulary and rot the moment one changed.
    // The interpretation happens once per row below, through the governed
    // seam, so a new terminal token needs a vocabulary edit and nothing here.
    let not_hidden_r = crate::query::not_hidden_predicate("r");
    let attention_sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.home_id, r.lifecycle, r.maturity,
                r.last_activity_at
          FROM records r
          WHERE r.deleted_at IS NULL AND r.lifecycle IS NOT NULL
            AND {not_hidden_r}
            AND NOT EXISTS (SELECT 1 FROM facet_values av
                             WHERE av.record_id = r.id AND av.key = 'archived')
          ORDER BY r.last_activity_at DESC, r.id"
    );
    let attention = sqlx::query(&attention_sql)
        .fetch_all(db.write_pool())
        .await?;
    // One interpreter for the whole pass: it amortizes the schema-cascade and
    // vocabulary reads that would otherwise repeat per row.
    let principal = (!super::is_legacy_local(&caller)).then(|| super::principal(&caller));
    let lifecycle_interpreter = LifecycleInterpreter::load(&db, principal).await?;
    let mut active = Vec::new();
    let mut stale = Vec::new();
    let mut unclassified_lifecycle = Vec::new();
    let mut active_total = 0usize;
    let mut unclassified_lifecycle_total = 0usize;
    for row in &attention {
        let id: String = row.try_get("id")?;
        if !in_scope(&id) {
            continue;
        }
        if !can_record(&db, &caller, &id, Capability::View).await? {
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
            // Finished work is not attention. It leaves both buckets rather
            // than ageing into `stale`, where oldest-first would otherwise
            // put a long-closed record at the head of the neglect list. This
            // is the only exclusion, and it is the only one with evidence
            // behind it: the vocabulary SAYS the record is done.
            LifecycleInterpretation::Governed(governed) if governed.terminality != "open" => {
                continue;
            }
            LifecycleInterpretation::Governed(_) => {}
            // An uninterpretable lifecycle is a fact about the GOVERNANCE, not
            // about the work. Most kinds bind no lifecycle vocabulary at all,
            // so excluding these would drop genuinely open records — an epic,
            // a design note — out of the only view that surfaces them, to
            // punish a gap the records did not create. They stay in the
            // attention split, bucketed on `last_activity_at` alone exactly as
            // before, and are ALSO named in the census below so the gap is
            // impossible to miss.
            LifecycleInterpretation::Unclassified(unclassified) => {
                unclassified_lifecycle_total += 1;
                if unclassified_lifecycle.len() < limit {
                    unclassified_lifecycle.push(dashboard_entry_with_reason(
                        row,
                        &lifecycle_interpreter,
                        unclassified.reason,
                    )?);
                }
            }
            LifecycleInterpretation::Absent(_) => {}
        }
        let last_activity: Option<String> = row.try_get("last_activity_at")?;
        let is_active = last_activity.as_deref().is_some_and(|ts| ts >= &*cutoff);
        if is_active {
            active_total += 1;
            if active.len() < limit {
                active.push(dashboard_entry(row, &lifecycle_interpreter)?);
            }
        } else {
            // Collect ALL stale rows before truncating: the scan runs
            // newest-first, and the stale bucket must keep its OLDEST rows —
            // truncating here would drop exactly the most neglected records.
            stale.push(dashboard_entry(row, &lifecycle_interpreter)?);
        }
    }
    // Stale reads oldest-first — the longest-neglected record leads.
    stale.reverse();
    let stale_total = stale.len();
    stale.truncate(limit);

    // Blocked: an incoming `blocks` edge, or an outgoing `depends_on` edge,
    // whose other endpoint is live and unarchived. Tombstoning or archiving
    // the blocker releases the block.
    let live_other = |col: &str| {
        let not_hidden_o = crate::query::not_hidden_predicate("o");
        format!(
            "EXISTS (SELECT 1 FROM records o
                      WHERE o.id = {col} AND o.deleted_at IS NULL
                        AND {not_hidden_o}
                        AND NOT EXISTS (SELECT 1 FROM facet_values av
                                         WHERE av.record_id = o.id AND av.key = 'archived'))"
        )
    };
    let blocked_sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.home_id, r.lifecycle, r.maturity, r.last_activity_at,
                (SELECT json_group_array(json_object(
                     'id', l.source_id, 'relationship', 'blocks'))
                   FROM links l WHERE l.target_id = r.id AND l.relationship = 'blocks'
                     AND {blocks_live}) AS blocked_by,
                (SELECT json_group_array(json_object(
                     'id', l.target_id, 'relationship', 'depends_on'))
                   FROM links l WHERE l.source_id = r.id AND l.relationship = 'depends_on'
                     AND {depends_live}) AS waiting_on
          FROM records r
          WHERE r.deleted_at IS NULL
            AND {not_hidden_r}
            AND NOT EXISTS (SELECT 1 FROM facet_values av
                             WHERE av.record_id = r.id AND av.key = 'archived')
            AND (EXISTS (SELECT 1 FROM links l
                          WHERE l.target_id = r.id AND l.relationship = 'blocks'
                            AND {blocks_live})
                 OR EXISTS (SELECT 1 FROM links l
                             WHERE l.source_id = r.id AND l.relationship = 'depends_on'
                               AND {depends_live}))
          ORDER BY r.last_activity_at DESC, r.id",
        blocks_live = live_other("l.source_id"),
        depends_live = live_other("l.target_id"),
    );
    let mut blocked = Vec::new();
    let mut blocked_total = 0usize;
    for row in &sqlx::query(&blocked_sql).fetch_all(db.write_pool()).await? {
        let id: String = row.try_get("id")?;
        if !in_scope(&id) {
            continue;
        }
        if !can_record(&db, &caller, &id, Capability::View).await? {
            continue;
        }
        let mut entry = dashboard_entry(row, &lifecycle_interpreter)?;
        let object = entry.as_object_mut().expect("dashboard entry object");
        let parse = |raw: Option<String>| -> Value {
            raw.and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| json!([]))
        };
        object.insert("blocked_by".into(), parse(row.try_get("blocked_by")?));
        object.insert("waiting_on".into(), parse(row.try_get("waiting_on")?));
        for key in ["blocked_by", "waiting_on"] {
            if let Some(items) = object.get_mut(key).and_then(Value::as_array_mut) {
                let visible = visible_ids(
                    &db,
                    &caller,
                    items
                        .iter()
                        .filter_map(|item| item.get("id").and_then(Value::as_str).map(String::from))
                        .collect(),
                )
                .await?;
                items.retain(|item| {
                    item.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| visible.contains(id))
                });
            }
        }
        let has_visible_block = ["blocked_by", "waiting_on"].into_iter().any(|key| {
            object
                .get(key)
                .and_then(Value::as_array)
                .is_some_and(|items| !items.is_empty())
        });
        if !has_visible_block {
            continue;
        }
        blocked_total += 1;
        if blocked.len() < limit {
            blocked.push(entry);
        }
    }

    // Lifecycle census over the scope, via the pipeline engine.
    let census_steps = [pipeline::Step::filter(pipeline::Filter {
        ancestor_id: args.scope.clone(),
        ..pipeline::Filter::default()
    })];
    let (census, _) = if super::is_legacy_local(&caller) {
        pipeline::run_with_diagnostics(
            &db,
            &census_steps,
            Some(pipeline::CountAxis::Lifecycle),
            &pipeline::PipelineOptions::default(),
        )
        .await?
    } else {
        pipeline::run_with_diagnostics_as(
            &db,
            super::principal(&caller),
            &census_steps,
            Some(pipeline::CountAxis::Lifecycle),
            &pipeline::PipelineOptions::default(),
        )
        .await?
    };

    Ok(json!({
        "scope": args.scope,
        "stale_after_days": stale_after_days,
        "stale_cutoff": cutoff,
        "limit": limit,
        "active": active,
        "active_total": active_total,
        "stale": stale,
        "stale_total": stale_total,
        "blocked": blocked,
        "blocked_total": blocked_total,
        "unclassified_lifecycle": {
            "note": UNCLASSIFIED_LIFECYCLE_NOTE,
            "items": unclassified_lifecycle,
            "total_count": unclassified_lifecycle_total,
            "truncated": unclassified_lifecycle_total > limit,
        },
        "lifecycle_census": census,
    }))
}

// ---------------------------------------------------------------------------
// Tool 4 — describe_schema
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescribeSchemaArgs {
    include_ddl: Option<bool>,
}

/// The authority classification of one table — the orientation `query_sql`
/// callers need before trusting a read.
fn table_role(table: &str) -> &'static str {
    if matches!(
        table,
        "content_events" | "meta_events" | "policy_events" | "control_events" | "derivation_events"
    ) {
        "authoritative"
    } else if table == "content_event_sources" {
        "authoritative source provenance (immutable companion to content_events)"
    } else if PROJECTION_TABLES.contains(&table) {
        "projection (rebuildable from content_events; never write directly)"
    } else if META_PROJECTION_TABLES.contains(&table) {
        "projection (rebuildable from meta_events; never write directly)"
    } else if table == "blobs" {
        "substrate (byte tier, direct-write by design)"
    } else if table == "bindings" {
        "substrate (durable external-identity mappings, direct-write by design)"
    } else if table == "binding_systems" {
        "substrate (engine-governed identity-system registry)"
    } else if table == "binding_audit" {
        "substrate (append-only binding lifecycle audit)"
    } else if table == "external_observations" {
        "substrate (append-only qualified external observations)"
    } else if matches!(table, "database_identity" | "database_identity_audit") {
        "substrate (protected portable database identity and append-only lifecycle audit)"
    } else if matches!(table, "record_policies" | "policy_entries") {
        "projection (rebuildable from policy_events; never write directly)"
    } else if CONTROL_PROJECTION_TABLES.contains(&table) {
        "projection (rebuildable from control_events; never write directly)"
    } else if DERIVATION_PROJECTION_TABLES.contains(&table) {
        "projection (rebuildable from derivation_events; never write directly)"
    } else if table == "derivation_requests" {
        "substrate (durable operational derivation coordination, direct-write with fenced leases)"
    } else if table == "authorization_revision" {
        "substrate (monotonic authorization cache-invalidation fence)"
    } else if table.starts_with("records_fts") || table.starts_with("records_name_idx") {
        "derived index (FTS5 over records)"
    } else if table.starts_with("read_log_") {
        // Worth saying out loud in the orientation surface rather than only in
        // `ddl.rs`: this tier is DISPOSABLE by promise. A caller reading these
        // rows should know they may not be there, and a caller tempted to build
        // on them should know the build enforces that they can vanish.
        "substrate (read log — direct-write, raw, and disposable: droppable at \
         any time, and every tool must behave identically without it)"
    } else {
        // `jobs` alone, now that bindings and portable policies have explicit
        // durable substrate roles and the meta tier is event-sourced (ba9f97e).
        "substrate (transient operational state, direct-write by design)"
    }
}

async fn describe_schema(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: DescribeSchemaArgs = parse_args("describe_schema", arguments)?;
    let mut tables = Vec::new();
    for table in REQUIRED_TABLES {
        let owner_only = matches!(
            table,
            "record_policies"
                | "policy_entries"
                | "policy_events"
                | "control_events"
                | "member_contexts"
                | "instruction_bindings"
                | "onboarding_programmes"
                | "onboarding_programme_sources"
                | "member_obligations"
                | "seeded_instruction_sources"
                | "control_event_applications"
                | "derivation_events"
                | "derivation_series"
                | "derivation_revisions"
                | "derivation_revision_inputs"
                | "derivation_attempts"
                | "derivation_target_bindings"
                | "derivation_target_publications"
                | "derivation_selected_publications"
                | "derivation_target_heads"
                | "derivation_event_applications"
                | "derivation_requests"
                | "derivation_artifact_role_assignments"
                | "derivation_artifact_role_retirements"
                | "derivation_artifact_role_heads"
                | "derivation_revision_confirmations"
                | "derivation_confirmation_retractions"
                | "derivation_confirmation_heads"
                | "bindings"
                | "binding_systems"
                | "binding_audit"
                | "external_observations"
                | "database_identity"
                | "database_identity_audit"
                | "authorization_revision"
                | "meta_events"
                | "jobs"
                | "read_log_calls"
                | "read_log_touches"
                | "embeddings"
        ) || table.starts_with("records_fts")
            || table.starts_with("records_name_idx");
        if owner_only && !caller.is_host_owner() {
            continue;
        }
        // `table_info` hides generated columns. `table_xinfo` returns the same
        // fields for ordinary columns and also exposes VIRTUAL projections such
        // as `facet_values.value_num`.
        let columns = sqlx::query(&format!("PRAGMA table_xinfo({table})"))
            .fetch_all(db.write_pool())
            .await?
            .iter()
            .map(|row| {
                let name = row.try_get::<String, _>("name")?;
                let semantics = crate::schema::discovery::column_semantics(table, &name);
                let mut column = json!({
                    "name": name,
                    "type": row.try_get::<String, _>("type")?,
                    "notnull": row.try_get::<i64, _>("notnull")? != 0,
                    "pk": row.try_get::<i64, _>("pk")? != 0,
                });
                if let Some(metadata) = semantics {
                    column
                        .as_object_mut()
                        .expect("column metadata is an object")
                        .extend(
                            metadata
                                .as_object()
                                .expect("column semantics are an object")
                                .clone(),
                        );
                }
                Ok(column)
            })
            .collect::<Result<Vec<_>>>()?;
        tables.push(json!({
            "name": table,
            "role": table_role(table),
            "columns": columns,
        }));
    }
    let all_schema_rows = cascade::schema_config_rows(&db, None).await?;
    let mut visible_schema_rows = Vec::with_capacity(all_schema_rows.len());
    for row in all_schema_rows {
        let visible = match row.applies_to_collection_id.as_deref() {
            Some(collection) => can_record(&db, &caller, collection, Capability::View).await?,
            None => true,
        };
        if visible {
            visible_schema_rows.push(row);
        }
    }
    let mut resolved = cascade::resolve_from_rows(&visible_schema_rows);
    let mut connection = db.write_pool().acquire().await?;
    cascade::inject_kind_projection_on(&mut connection, &mut resolved.resolved).await?;
    let mut kind_registry = serde_json::Map::new();
    for record_type in SPINE_TYPES {
        kind_registry.insert(
            record_type.into(),
            serde_json::to_value(crate::meta::kind::list_active(&db, record_type).await?)?,
        );
    }
    let mut out = json!({
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
            // The source revision this binary was built from (task 142e0d2).
            // Distinct from `ddl_fingerprint`, which pins the frozen schema:
            // that answers "which contract?", this answers "which build?".
            "git_sha": GIT_SHA,
            "schema_version": CURRENT_ENGINE_SCHEMA_VERSION,
            "supported_schema_baseline": SUPPORTED_ENGINE_SCHEMA_BASELINE,
            "user_version": user_version(&db).await?,
            "ddl_fingerprint": FROZEN_DDL_SHA256,
        },
        "model": "event-authoritative: `content_events` plus its identity-preserving \
                  `content_event_sources` provenance are authoritative for the content \
                  projections (`records`, `links`, `facet_values`, `facet_observations`, \
                  `annotation_targets`, `message_audience_state`, `message_audiences`, \
                  `message_conversations`, `module_releases`, `module_release_imports`, \
                  `recipe_releases`, `recipe_release_input_classes`, \
                  `artifact_source_attestations`, `artifact_inputs`, `artifact_module_grants`); \
                  `meta_events` is authoritative for the meta projections (`vocabularies`, \
                  `vocabulary_values`, `schema_config`); `policy_events` is authoritative for \
                  portable policy; `control_events` is authoritative for portable member, \
                  instruction, and onboarding control state; `derivation_events` is authoritative \
                  for stable derivation series, immutable revisions, exact input manifests and \
                  failed attempts; projections are rebuilt by replay and must never be written directly",
        "tables": tables,
        "resolved_schema_config": resolved.resolved,
        "kind_registry": kind_registry,
    });
    if args.include_ddl.unwrap_or(false) {
        if !caller.is_host_owner() {
            return Err(Error::auth(
                "describe_schema: database owner host role required for physical DDL",
            ));
        }
        out.as_object_mut()
            .expect("describe_schema payload")
            .insert("ddl_statements".into(), json!(&DDL_STATEMENTS[..]));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register tools 1–4.
pub fn register_orientation_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::Bootstrap,
        "Predictably bounded first-contact orientation for the connected Native database: \
         build-owned shared-world posture, verified principal/workspace footing, standing \
         context, a freshness-labelled current-world preview, exact callable continuations, \
         and the required reusable run key. Intent is deliberately declared separately with \
         set_intent.",
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        bootstrap,
    )?;
    registry.register(
        ToolKind::GetStructure,
        "Bounded containment tree from a root, live or pinned by optional as_of. \
         Reports per-node child counts; skips archived subtrees unless asked.",
        json!({
            "type": "object",
            "properties": {
                "root_id": { "type": "string", "description": "Record to walk from." },
                "max_depth": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Levels below the root to descend (default 3)."
                },
                "include_archived": { "type": "boolean", "description": "Walk into archived subtrees (default false)." },
                "max_children_per_node": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": tree::MAX_CHILDREN_PER_NODE,
                    "description": "Siblings emitted per node (default 200). Capped-out \
                                    children are not walked into either; compare a node's \
                                    child_count to see what was cut."
                },
                "exclude_types": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Spine types to prune before counts and cap."
                },
                "as_of": lens::as_of_input_schema()
            },
            "required": ["root_id"],
            "additionalProperties": false
        }),
        get_structure,
    )?;
    registry.register(
        ToolKind::GetDashboard,
        "Attention view: active and stale records (split by last_activity_at \
         against a staleness floor; records whose lifecycle is terminal in \
         its governing vocabulary are finished and appear in neither), \
         link-derived blocked records, a lifecycle census, and an \
         unclassified_lifecycle diagnostic naming which of the returned \
         records carry an uninterpretable lifecycle and why — optionally \
         scoped to a subtree.",
        json!({
            "type": "object",
            "properties": {
                "scope": { "type": "string", "description": "Restrict to the subtree rooted at this record." },
                "stale_after_days": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_STALE_AFTER_DAYS,
                    "description": "Days without activity before a record counts as stale (default 14)."
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_DASHBOARD_LIMIT,
                    "description": "Max records per bucket (default 20)."
                }
            },
            "additionalProperties": false
        }),
        get_dashboard,
    )?;
    registry.register(
        ToolKind::DescribeSchema,
        "The physical schema: every table with its columns and its authority \
         role (authoritative log / projection / substrate / meta tier) — \
         orientation before reading the database directly. Set include_ddl for \
         the frozen statements.",
        json!({
            "type": "object",
            "properties": {
                "include_ddl": { "type": "boolean", "description": "Include the frozen DDL statement list (default false)." }
            },
            "additionalProperties": false
        }),
        describe_schema,
    )?;
    Ok(())
}
