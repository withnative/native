//! Shared caller-relative instruction resolution and hard-size guards.

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

use crate::authorization::{self, Capability, Principal};
use crate::error::{Error, Result};
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, LogicalType,
    NormalizedRow, NormalizedValue, StatementKind, StatementTemplate,
};

pub const MAX_RESOLVED_INSTRUCTION_BYTES: usize = 32 * 1024;
/// Caller-relative control metadata has its own bound: the authored-body limit
/// does not stop thousands of empty sources or obligations from bloating a
/// bootstrap response. Count ceilings make resolution work bounded too; the
/// serialized ceiling catches individually oversized titles, ids, and reasons.
pub const MAX_BOOTSTRAP_INSTRUCTION_ENTRIES: usize = 128;
pub const MAX_BOOTSTRAP_PENDING_OBLIGATIONS: usize = 64;
pub const MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES: usize = 64 * 1024;
pub const ENGINE_ORIENTATION_TEMPLATE_KEY: &str = "engine-orientation";
pub const ENGINE_ORIENTATION_TEMPLATE_VERSION: i64 = 8;
pub const ENGINE_ORIENTATION: &str = include_str!("mcp/posture-capsule.md");
pub const DURABLE_ORIENTATION_GUIDANCE: &str = "Bootstrap is read-only. Repeating or ending a session does not complete, decline, reopen, or otherwise consume an onboarding obligation; it remains pending until an explicit member action changes it.";
pub const NEUTRAL_PRECEDENCE_GUIDANCE: &str = "Consider all active instructions together. Their scopes describe where they came from, not an automatic priority. If they materially conflict, exercise judgement and ask the user when necessary.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeedProvenance {
    pub template_key: String,
    pub template_version: i64,
    pub last_applied_digest: String,
    pub last_applied_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InstructionSource {
    Engine {
        engine_name: &'static str,
        engine_version: &'static str,
        template_key: &'static str,
        template_version: i64,
        body_digest: String,
    },
    Record {
        record_id: String,
        title: String,
        body_digest: String,
        updated_at: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedInstructionEntry {
    pub entry_id: String,
    pub scope: String,
    pub kind: String,
    pub position: i64,
    pub source: InstructionSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    pub binding_id: Option<String>,
    pub scope_kind: Option<String>,
    pub scope_id: Option<String>,
    pub programme_id: Option<String>,
    pub generation: Option<i64>,
    pub trigger_key: Option<String>,
    pub programme_position: Option<i64>,
    pub source_role: Option<String>,
    pub source_position: Option<i64>,
    pub seed: Option<SeedProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingObligation {
    pub programme_id: String,
    pub trigger_key: String,
    pub generation: i64,
    pub programme_enabled: bool,
    pub programme_position: i64,
    pub created_at: String,
    pub updated_at: String,
    pub updated_by: Option<String>,
    pub updated_run_key: Option<String>,
    pub reason: Option<String>,
    pub progress_state: String,
    pub progress_phase: Option<String>,
    pub selected_route_id: Option<String>,
    pub progress_updated_at: Option<String>,
    pub progress_run_relation: String,
    pub resume_after: Option<String>,
    pub progress_artifact_id: Option<String>,
    pub progress_artifact_status: String,
    pub instruction_entry_ids: Vec<String>,
    pub completion_criteria_entry_ids: Vec<String>,
    pub allowed_resolutions: [&'static str; 2],
    pub defer_for_run_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolutionDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_record_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedInstructionStack {
    pub status: String,
    pub resolved_bytes: usize,
    pub limit_bytes: usize,
    pub entries: Vec<ResolvedInstructionEntry>,
    pub diagnostics: Vec<ResolutionDiagnostic>,
    pub guidance: &'static str,
    pub delivery: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootstrapInstructionResolution {
    pub instructions: ResolvedInstructionStack,
    pub pending_obligations: Vec<PendingObligation>,
}

/// Add the legacy build-owned instruction alias after portable resolution.
/// Bootstrap's first-class `orientation` field is independently guaranteed;
/// this entry remains for one compatibility window. Invalid portable state
/// deliberately keeps an empty legacy stack so a partial stack cannot look
/// authoritative merely because the compatibility alias is valid.
pub fn prepend_engine_instruction(
    mut resolution: BootstrapInstructionResolution,
) -> BootstrapInstructionResolution {
    if resolution.instructions.status != "ready" {
        return resolution;
    }
    let body_digest = hex::encode(Sha256::digest(ENGINE_ORIENTATION.as_bytes()));
    resolution.instructions.entries.insert(
        0,
        ResolvedInstructionEntry {
            entry_id: format!("instruction-entry:engine:{}", &body_digest[..32]),
            scope: "engine".into(),
            kind: "fixed".into(),
            position: 0,
            source: InstructionSource::Engine {
                engine_name: crate::ENGINE_NAME,
                engine_version: crate::ENGINE_VERSION,
                template_key: ENGINE_ORIENTATION_TEMPLATE_KEY,
                template_version: ENGINE_ORIENTATION_TEMPLATE_VERSION,
                body_digest,
            },
            content: Some(ENGINE_ORIENTATION.into()),
            binding_id: None,
            scope_kind: None,
            scope_id: None,
            programme_id: None,
            generation: None,
            trigger_key: None,
            programme_position: None,
            source_role: None,
            source_position: None,
            seed: None,
        },
    );
    resolution
}

fn invalid_resolution(
    pending_obligations: Vec<PendingObligation>,
    resolved_bytes: usize,
    code: &str,
    message: &str,
    source_record_id: Option<String>,
) -> BootstrapInstructionResolution {
    BootstrapInstructionResolution {
        instructions: ResolvedInstructionStack {
            status: "invalid".into(),
            resolved_bytes,
            limit_bytes: MAX_RESOLVED_INSTRUCTION_BYTES,
            entries: vec![],
            diagnostics: vec![ResolutionDiagnostic {
                code: code.into(),
                message: message.into(),
                source_record_id,
            }],
            guidance: NEUTRAL_PRECEDENCE_GUIDANCE,
            delivery: DURABLE_ORIENTATION_GUIDANCE,
        },
        pending_obligations,
    }
}

fn metadata_bytes(
    entries: &[ResolvedInstructionEntry],
    pending_obligations: &[PendingObligation],
) -> Result<usize> {
    let mut entries = serde_json::to_value(entries)?;
    for entry in entries.as_array_mut().into_iter().flatten() {
        if let Some(entry) = entry.as_object_mut() {
            entry.remove("content");
        }
    }
    Ok(serde_json::to_vec(&serde_json::json!({
        "entries": entries,
        "pending_obligations": pending_obligations,
    }))?
    .len())
}

fn metadata_overflow(
    pending_obligations: Vec<PendingObligation>,
    resolved_bytes: usize,
    code: &str,
    message: &str,
) -> Result<BootstrapInstructionResolution> {
    let keep_obligations =
        metadata_bytes(&[], &pending_obligations)? <= MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES;
    Ok(invalid_resolution(
        if keep_obligations {
            pending_obligations
        } else {
            vec![]
        },
        resolved_bytes,
        code,
        message,
        None,
    ))
}

/// Resolve the authenticated caller's complete instruction context from one
/// SQLite read snapshot. Logical corruption is returned as an invalid,
/// non-authoritative stack with no partial sources; database failures remain
/// ordinary errors.
pub async fn resolve_for_account(
    pool: &SqlitePool,
    account_id: &str,
    current_run_key: Option<&str>,
) -> Result<BootstrapInstructionResolution> {
    let mut tx = pool.begin().await?;
    let result = resolve_for_account_in(&mut tx, account_id, current_run_key).await;
    tx.rollback().await?;
    result
}

async fn resolve_for_account_in(
    tx: &mut Transaction<'_, Sqlite>,
    account_id: &str,
    current_run_key: Option<&str>,
) -> Result<BootstrapInstructionResolution> {
    let obligation_rows = sqlx::query(
        "SELECT o.programme_id,p.trigger_key,o.generation,p.enabled,p.position,
                o.created_at,o.updated_at,o.updated_by,o.updated_run_key,o.reason,
                progress.phase progress_phase,progress.selected_route_id,
                progress.updated_at progress_updated_at,
                progress.updated_run_key progress_updated_run_key,
                progress.resume_after,progress.artifact_id progress_artifact_id,
                artifact.deleted_at progress_artifact_deleted_at,
                artifact.type progress_artifact_type,artifact.kind progress_artifact_kind,
                artifact.name progress_artifact_name,artifact.home_id progress_artifact_home_id,
                artifact.owner_id progress_artifact_owner_id,
                artifact.policy_anchor_id progress_artifact_policy_anchor_id,
                mc.root_record_id progress_root_id,mc.person_record_id progress_person_id,
                progress_root.deleted_at progress_root_deleted_at,
                (SELECT COUNT(*) FROM (SELECT 1 FROM policy_entries pe
                  WHERE pe.policy_anchor_id=mc.root_record_id LIMIT 2)) progress_root_policy_count,
                EXISTS(SELECT 1 FROM policy_entries pe
                  WHERE pe.policy_anchor_id=mc.root_record_id
                    AND pe.subject_kind='account' AND pe.subject_id=o.account_id
                    AND pe.effect='allow' AND pe.capability='manage') progress_root_private_manage,
                (SELECT COUNT(*) FROM (SELECT 1 FROM records sibling
                  WHERE sibling.home_id=mc.root_record_id AND sibling.type='Document'
                    AND sibling.kind='note' AND sibling.name='Starting context'
                    AND sibling.deleted_at IS NULL LIMIT 2)) progress_starting_context_count
           FROM member_obligations o
           JOIN onboarding_programmes p ON p.id=o.programme_id
           LEFT JOIN member_obligation_progress progress
             ON progress.account_id=o.account_id AND progress.programme_id=o.programme_id
            AND progress.generation=o.generation
           LEFT JOIN records artifact ON artifact.id=progress.artifact_id
           LEFT JOIN member_contexts mc ON mc.account_id=o.account_id
           LEFT JOIN records progress_root ON progress_root.id=mc.root_record_id
          WHERE o.account_id=? AND o.state='pending' AND p.enabled=1
          ORDER BY p.position,p.id,o.generation
          LIMIT ?",
    )
    .bind(account_id)
    .bind((MAX_BOOTSTRAP_PENDING_OBLIGATIONS + 1) as i64)
    .fetch_all(&mut **tx)
    .await?;
    if obligation_rows.len() > MAX_BOOTSTRAP_PENDING_OBLIGATIONS {
        return metadata_overflow(
            vec![],
            0,
            "pending_obligation_count_exceeded",
            "The caller has too many pending onboarding obligations for the bounded bootstrap contract. Complete, decline, or consolidate obligations before relying on this stack.",
        );
    }
    let mut pending_obligations = obligation_rows
        .into_iter()
        .map(|row| {
            let progress_phase: Option<String> = row.try_get("progress_phase")?;
            let progress_artifact_id: Option<String> = row.try_get("progress_artifact_id")?;
            let progress_artifact_deleted_at: Option<String> =
                row.try_get("progress_artifact_deleted_at")?;
            let artifact_available_private = progress_artifact_id.is_some()
                && progress_artifact_deleted_at.is_none()
                && row
                    .try_get::<Option<String>, _>("progress_root_deleted_at")?
                    .is_none()
                && row
                    .try_get::<Option<String>, _>("progress_artifact_type")?
                    .as_deref()
                    == Some("Document")
                && row
                    .try_get::<Option<String>, _>("progress_artifact_kind")?
                    .as_deref()
                    == Some("note")
                && row
                    .try_get::<Option<String>, _>("progress_artifact_name")?
                    .as_deref()
                    == Some("Starting context")
                && row.try_get::<Option<String>, _>("progress_artifact_home_id")?
                    == row.try_get::<Option<String>, _>("progress_root_id")?
                && row.try_get::<Option<String>, _>("progress_artifact_owner_id")?
                    == row.try_get::<Option<String>, _>("progress_person_id")?
                && row.try_get::<Option<String>, _>("progress_artifact_policy_anchor_id")?
                    == row.try_get::<Option<String>, _>("progress_root_id")?
                && row.try_get::<i64, _>("progress_root_policy_count")? == 1
                && row.try_get::<i64, _>("progress_root_private_manage")? != 0
                && row.try_get::<i64, _>("progress_starting_context_count")? == 1;
            let progress_updated_run_key: Option<String> =
                row.try_get("progress_updated_run_key")?;
            Ok(PendingObligation {
                programme_id: row.try_get("programme_id")?,
                trigger_key: row.try_get("trigger_key")?,
                generation: row.try_get("generation")?,
                programme_enabled: row.try_get::<i64, _>("enabled")? != 0,
                programme_position: row.try_get("position")?,
                created_at: row.try_get("created_at")?,
                updated_at: row.try_get("updated_at")?,
                updated_by: row.try_get("updated_by")?,
                updated_run_key: row.try_get("updated_run_key")?,
                reason: row.try_get("reason")?,
                progress_state: match progress_phase.as_deref() {
                    None => "new",
                    Some("deferred") => "deferred",
                    Some(_) => "in_progress",
                }
                .into(),
                progress_phase: progress_phase.clone(),
                selected_route_id: row.try_get("selected_route_id")?,
                progress_updated_at: row.try_get("progress_updated_at")?,
                progress_run_relation: match (
                    progress_phase.as_ref(),
                    progress_updated_run_key.as_deref(),
                    current_run_key,
                ) {
                    (None, _, _) => "none",
                    (Some(_), Some(progress), Some(current)) if progress == current => {
                        "current_run"
                    }
                    (Some(_), Some(_), Some(_)) => "returning",
                    (Some(_), _, _) => "portable_unknown",
                }
                .into(),
                resume_after: row.try_get("resume_after")?,
                progress_artifact_status: match (
                    progress_artifact_id.as_ref(),
                    progress_artifact_deleted_at.as_ref(),
                ) {
                    (None, _) => "none",
                    (Some(_), None) if artifact_available_private => "available_private",
                    (Some(_), None) => "moved_or_policy_changed",
                    (Some(_), Some(_)) => "deleted",
                }
                .into(),
                progress_artifact_id,
                instruction_entry_ids: vec![],
                completion_criteria_entry_ids: vec![],
                allowed_resolutions: ["completed", "declined"],
                defer_for_run_supported: true,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if metadata_bytes(&[], &pending_obligations)? > MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES {
        return metadata_overflow(
            vec![],
            0,
            "instruction_metadata_budget_exceeded",
            "Pending onboarding metadata exceeds the bounded bootstrap metadata budget. Shorten or consolidate the active control state before relying on this stack.",
        );
    }
    let generation_mismatch: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM member_obligations o
           JOIN onboarding_programmes p ON p.id=o.programme_id AND p.enabled=1
          WHERE o.account_id=? AND o.state='pending' AND o.generation<>p.generation)",
    )
    .bind(account_id)
    .fetch_one(&mut **tx)
    .await?;
    if generation_mismatch {
        return Ok(invalid_resolution(
            pending_obligations,
            0,
            "pending_obligation_generation_mismatch",
            "A pending onboarding obligation does not match its programme's current generation. Rebase or repair the obligation before relying on this stack.",
            None,
        ));
    }

    let rows = sqlx::query(
        "SELECT c.layer,c.source_record_id,c.binding_id,c.scope_kind,c.scope_id,
                c.binding_position,c.programme_id,c.programme_generation,c.programme_position,
                c.source_role,c.source_position,c.trigger_key,r.type record_type,r.name source_title,
                r.body,r.updated_at source_updated_at,r.deleted_at,typeof(r.body) body_type,
                seed.template_key,seed.template_version,seed.last_applied_digest,seed.last_applied_at
           FROM (
             SELECT 0 layer,b.source_record_id,b.id binding_id,b.scope_kind,b.scope_id,
                    b.position binding_position,NULL programme_id,NULL programme_generation,
                    NULL programme_position,NULL source_role,NULL source_position,NULL trigger_key
               FROM instruction_bindings b
              WHERE b.scope_kind='database' AND b.scope_id='native:database' AND b.enabled=1
             UNION ALL
             SELECT 1,s.source_record_id,NULL,NULL,NULL,NULL,p.id,o.generation,p.position,
                    s.source_role,s.position,p.trigger_key
               FROM member_obligations o
               JOIN onboarding_programmes p ON p.id=o.programme_id AND p.enabled=1
               JOIN onboarding_programme_sources s ON s.programme_id=p.id
              WHERE o.account_id=? AND o.state='pending'
             UNION ALL
             SELECT 2,b.source_record_id,b.id,b.scope_kind,b.scope_id,b.position,
                    NULL,NULL,NULL,NULL,NULL,NULL
               FROM instruction_bindings b
              WHERE b.scope_kind='account' AND b.scope_id=? AND b.enabled=1
           ) c
           LEFT JOIN records r ON r.id=c.source_record_id
           LEFT JOIN seeded_instruction_sources seed ON seed.source_record_id=c.source_record_id
          ORDER BY c.layer,
                   CASE WHEN c.layer=1 THEN c.programme_position ELSE c.binding_position END,
                   c.programme_id,c.source_position,c.source_record_id
          LIMIT ?",
    )
    .bind(account_id)
    .bind(account_id)
    .bind((MAX_BOOTSTRAP_INSTRUCTION_ENTRIES + 1) as i64)
    .fetch_all(&mut **tx)
    .await?;
    if rows.len() > MAX_BOOTSTRAP_INSTRUCTION_ENTRIES {
        return metadata_overflow(
            pending_obligations,
            0,
            "instruction_entry_count_exceeded",
            "The caller has too many active instruction sources for the bounded bootstrap contract. Consolidate or disable sources before relying on this stack.",
        );
    }

    let mut entries = Vec::with_capacity(rows.len());
    let mut resolved_bytes = 0usize;
    for row in rows {
        let source_record_id: String = row.try_get("source_record_id")?;
        let record_type: Option<String> = row.try_get("record_type")?;
        let deleted_at: Option<String> = row.try_get("deleted_at")?;
        if record_type.as_deref() != Some("Document") || deleted_at.is_some() {
            return Ok(invalid_resolution(
                pending_obligations,
                resolved_bytes,
                "instruction_source_invalid",
                "An active instruction source is missing, deleted, or not a Document. Repair or remove the control reference before relying on this stack.",
                None,
            ));
        }
        let readable = authorization::effective_capability_on(
            tx,
            Principal::bound(account_id, true),
            &source_record_id,
        )
        .await
        .map(|capability| capability.allows(Capability::View))
        .unwrap_or(false);
        if !readable {
            return Ok(invalid_resolution(
                pending_obligations,
                resolved_bytes,
                "instruction_source_unreadable",
                "An active instruction source is not readable by this caller. Ask the database owner to grant view access or remove the active control reference; no partial instruction stack is authoritative.",
                None,
            ));
        }
        let body_type: Option<String> = row.try_get("body_type")?;
        if !matches!(body_type.as_deref(), Some("text" | "null")) {
            return Ok(invalid_resolution(
                pending_obligations,
                resolved_bytes,
                "instruction_source_corrupt",
                "An active instruction source has an invalid body representation. No partial instruction stack is authoritative.",
                Some(source_record_id),
            ));
        }
        let body: Option<String> = row.try_get("body")?;
        let body = body.unwrap_or_default();
        let body_bytes = body.len();
        resolved_bytes = resolved_bytes
            .checked_add(body_bytes)
            .ok_or_else(|| Error::engine("resolved instruction byte count overflow"))?;
        let seed = match row.try_get::<Option<String>, _>("template_key")? {
            Some(template_key) => Some(SeedProvenance {
                template_key,
                template_version: row.try_get("template_version")?,
                last_applied_digest: row.try_get("last_applied_digest")?,
                last_applied_at: row.try_get("last_applied_at")?,
            }),
            None => None,
        };
        let layer: i64 = row.try_get("layer")?;
        let scope = match layer {
            0 => "workspace",
            1 => "onboarding",
            2 => "member",
            _ => "invalid",
        };
        let binding_id: Option<String> = row.try_get("binding_id")?;
        let programme_id: Option<String> = row.try_get("programme_id")?;
        let generation: Option<i64> = row.try_get("programme_generation")?;
        let source_role: Option<String> = row.try_get("source_role")?;
        let binding_position: Option<i64> = row.try_get("binding_position")?;
        let source_position: Option<i64> = row.try_get("source_position")?;
        if source_role.as_deref() == Some("completion_criteria") && body.is_empty() {
            return Ok(invalid_resolution(
                pending_obligations,
                resolved_bytes,
                "completion_criteria_empty",
                "An active onboarding completion-criteria source is empty. Add explicit criteria or remove the source before completing this obligation.",
                None,
            ));
        }
        if body.is_empty() {
            continue;
        }
        let identity = format!(
            "{scope}\0{}\0{}\0{}\0{source_record_id}",
            binding_id.as_deref().unwrap_or(""),
            programme_id.as_deref().unwrap_or(""),
            generation
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        let entry_id = format!(
            "instruction-entry:{}",
            &hex::encode(Sha256::digest(identity.as_bytes()))[..32]
        );
        if let (Some(programme_id), Some(generation)) = (&programme_id, generation) {
            if let Some(obligation) = pending_obligations.iter_mut().find(|obligation| {
                obligation.programme_id == *programme_id && obligation.generation == generation
            }) {
                if source_role.as_deref() == Some("completion_criteria") {
                    obligation
                        .completion_criteria_entry_ids
                        .push(entry_id.clone());
                } else {
                    obligation.instruction_entry_ids.push(entry_id.clone());
                }
            }
        }
        entries.push(ResolvedInstructionEntry {
            entry_id,
            scope: scope.into(),
            kind: if layer == 1 {
                "programme_source"
            } else {
                "standing"
            }
            .into(),
            position: if layer == 1 {
                source_position.unwrap_or_default()
            } else {
                binding_position.unwrap_or_default()
            },
            source: InstructionSource::Record {
                record_id: source_record_id,
                title: row.try_get("source_title")?,
                body_digest: hex::encode(Sha256::digest(body.as_bytes())),
                updated_at: row.try_get("source_updated_at")?,
            },
            content: Some(body),
            binding_id,
            scope_kind: row.try_get("scope_kind")?,
            scope_id: row.try_get("scope_id")?,
            programme_id,
            generation,
            trigger_key: row.try_get("trigger_key")?,
            programme_position: row.try_get("programme_position")?,
            source_role,
            source_position,
            seed,
        });
    }
    if resolved_bytes > MAX_RESOLVED_INSTRUCTION_BYTES {
        return Ok(invalid_resolution(
            pending_obligations,
            resolved_bytes,
            "instruction_budget_exceeded",
            "The resolved instruction stack exceeds the 32 KiB UTF-8 budget. No partial instruction stack is authoritative.",
            None,
        ));
    }
    if metadata_bytes(&entries, &pending_obligations)? > MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES {
        return metadata_overflow(
            pending_obligations,
            resolved_bytes,
            "instruction_metadata_budget_exceeded",
            "Resolved instruction and obligation metadata exceeds the bounded bootstrap metadata budget. Shorten or consolidate active sources before relying on this stack.",
        );
    }
    Ok(BootstrapInstructionResolution {
        instructions: ResolvedInstructionStack {
            status: "ready".into(),
            resolved_bytes,
            limit_bytes: MAX_RESOLVED_INSTRUCTION_BYTES,
            entries,
            diagnostics: vec![],
            guidance: NEUTRAL_PRECEDENCE_GUIDANCE,
            delivery: DURABLE_ORIENTATION_GUIDANCE,
        },
        pending_obligations,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstructionContributor {
    pub scope: String,
    pub source_record_id: String,
    pub title: String,
    pub body_bytes: usize,
    pub binding_id: Option<String>,
    pub programme_id: Option<String>,
    pub generation: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StackMeasure {
    pub account_id: Option<String>,
    pub resolved_bytes: usize,
    pub limit_bytes: usize,
    pub contributors: Vec<InstructionContributor>,
}

pub async fn measure_stack_in(
    tx: &mut Transaction<'_, Sqlite>,
    account_id: Option<&str>,
) -> Result<StackMeasure> {
    let rows = sqlx::query(
        "SELECT scope,source_record_id,title,body_bytes,deleted_at,binding_id,programme_id,generation,source_role FROM (
           SELECT 'workspace' scope,b.source_record_id,r.name title,length(CAST(COALESCE(r.body,'') AS BLOB)) body_bytes,r.deleted_at,
                  b.id binding_id,NULL programme_id,NULL generation,NULL source_role,0 layer,b.position outer_pos,0 inner_pos
             FROM instruction_bindings b LEFT JOIN records r ON r.id=b.source_record_id
            WHERE b.scope_kind='database' AND b.scope_id='native:database' AND b.enabled=1
           UNION ALL
           SELECT 'onboarding',s.source_record_id,r.name,length(CAST(COALESCE(r.body,'') AS BLOB)),r.deleted_at,NULL,p.id,o.generation,s.source_role,1,p.position,s.position
             FROM member_obligations o JOIN onboarding_programmes p ON p.id=o.programme_id AND p.enabled=1
             JOIN onboarding_programme_sources s ON s.programme_id=p.id
             LEFT JOIN records r ON r.id=s.source_record_id
            WHERE ? IS NOT NULL AND o.account_id=? AND o.state='pending'
           UNION ALL
           SELECT 'member',b.source_record_id,r.name,length(CAST(COALESCE(r.body,'') AS BLOB)),r.deleted_at,b.id,NULL,NULL,NULL,2,b.position,0
             FROM instruction_bindings b LEFT JOIN records r ON r.id=b.source_record_id
            WHERE ? IS NOT NULL AND b.scope_kind='account' AND b.scope_id=? AND b.enabled=1
         ) ORDER BY layer,outer_pos,inner_pos,source_record_id",
    )
    .bind(account_id)
    .bind(account_id)
    .bind(account_id)
    .bind(account_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut resolved_bytes = 0usize;
    let mut contributors = Vec::with_capacity(rows.len());
    for row in rows {
        let source_record_id: String = row.try_get("source_record_id")?;
        let title: Option<String> = row.try_get("title")?;
        let deleted_at: Option<String> = row.try_get("deleted_at")?;
        let Some(title) = title else {
            return Err(Error::engine(format!(
                "instruction stack contains dangling active source {source_record_id}; remove or retarget its binding/programme source"
            )));
        };
        if deleted_at.is_some() {
            return Err(Error::engine(format!(
                "instruction stack contains deleted active source {source_record_id}; disable/remove its binding or programme source"
            )));
        }
        let principal_id = account_id.unwrap_or("native:prospective-member");
        let capability = authorization::effective_capability_on(
            tx,
            Principal::bound(principal_id, true),
            &source_record_id,
        )
        .await
        .map_err(|_| {
            Error::engine(format!(
                "instruction source {source_record_id} cannot be authorized; repair its policy or remove it"
            ))
        })?;
        if !capability.allows(Capability::View) {
            return Err(Error::engine(format!(
                "instruction source {source_record_id} is unreadable by account {principal_id}; grant view access or remove it"
            )));
        }
        let raw: i64 = row.try_get::<Option<i64>, _>("body_bytes")?.unwrap_or(0);
        let body_bytes = usize::try_from(raw)
            .map_err(|_| Error::engine("instruction body byte count overflow"))?;
        if row.try_get::<Option<String>, _>("source_role")?.as_deref()
            == Some("completion_criteria")
            && body_bytes == 0
        {
            return Err(Error::engine(
                "instruction stack contains an empty active completion-criteria source; add explicit criteria or remove it",
            ));
        }
        resolved_bytes = resolved_bytes
            .checked_add(body_bytes)
            .ok_or_else(|| Error::engine("resolved instruction byte count overflow"))?;
        contributors.push(InstructionContributor {
            scope: row.try_get("scope")?,
            source_record_id,
            title,
            body_bytes,
            binding_id: row.try_get("binding_id")?,
            programme_id: row.try_get("programme_id")?,
            generation: row.try_get("generation")?,
        });
    }
    Ok(StackMeasure {
        account_id: account_id.map(str::to_owned),
        resolved_bytes,
        limit_bytes: MAX_RESOLVED_INSTRUCTION_BYTES,
        contributors,
    })
}

async fn measure_future_trigger_stack_in(
    tx: &mut Transaction<'_, Sqlite>,
    trigger_key: &str,
) -> Result<StackMeasure> {
    let mut measure = measure_stack_in(tx, None).await?;
    measure.account_id = Some(format!("<future:{trigger_key}>"));
    let rows = sqlx::query(
        "SELECT s.source_record_id,s.source_role,r.name,r.body,r.deleted_at,s.position,p.id programme_id,p.position programme_position
           FROM onboarding_programmes p
           JOIN onboarding_programme_sources s ON s.programme_id=p.id
           LEFT JOIN records r ON r.id=s.source_record_id
          WHERE p.trigger_key=? ORDER BY p.position,p.id,s.position,s.source_record_id",
    )
    .bind(trigger_key)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        let programme_id: String = row.try_get("programme_id")?;
        let source_record_id: String = row.try_get("source_record_id")?;
        let title: Option<String> = row.try_get("name")?;
        if title.is_none() || row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
            return Err(Error::engine(format!(
                "future onboarding programme {programme_id} contains dangling/deleted source {source_record_id}"
            )));
        }
        let capability = authorization::effective_capability_on(
            tx,
            Principal::bound("native:prospective-member", true),
            &source_record_id,
        )
        .await
        .map_err(|_| {
            Error::engine(format!(
                "future onboarding source {source_record_id} cannot be authorized"
            ))
        })?;
        if !capability.allows(Capability::View) {
            return Err(Error::engine(format!(
                "future onboarding source {source_record_id} is unreadable by joined members"
            )));
        }
        let body: Option<String> = row.try_get("body")?;
        let body_bytes = body.as_deref().unwrap_or("").len();
        if row.try_get::<String, _>("source_role")? == "completion_criteria" && body_bytes == 0 {
            return Err(Error::engine(format!(
                "future onboarding programme {programme_id} has an empty completion-criteria source"
            )));
        }
        measure.resolved_bytes = measure
            .resolved_bytes
            .checked_add(body_bytes)
            .ok_or_else(|| Error::engine("resolved instruction byte count overflow"))?;
        measure.contributors.push(InstructionContributor {
            scope: "onboarding".into(),
            source_record_id,
            title: title.expect("checked above"),
            body_bytes,
            binding_id: None,
            programme_id: Some(programme_id),
            generation: None,
        });
    }
    Ok(measure)
}

fn assert_measure_within_budget(tool: &str, measure: StackMeasure) -> Result<StackMeasure> {
    if measure.resolved_bytes <= measure.limit_bytes {
        Ok(measure)
    } else {
        Err(Error::engine(format!(
            "{tool}: instruction_budget_exceeded for {}: {} bytes exceeds {} bytes; shorten or remove a contributing source",
            measure.account_id.as_deref().unwrap_or("<future-member>"),
            measure.resolved_bytes,
            measure.limit_bytes
        )))
    }
}

pub async fn validate_account_stack_in(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    account_id: Option<&str>,
) -> Result<StackMeasure> {
    let measure = measure_stack_in(tx, account_id).await?;
    if measure.resolved_bytes <= measure.limit_bytes {
        return Ok(measure);
    }
    let contributors = measure
        .contributors
        .iter()
        .filter(|entry| entry.body_bytes > 0)
        .map(|entry| {
            format!(
                "{}:{}={} bytes",
                entry.scope, entry.source_record_id, entry.body_bytes
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    Err(Error::engine(format!(
        "{tool}: instruction_budget_exceeded for account {}: {} bytes exceeds {} bytes; contributors: [{contributors}]. Shorten a source or disable/remove its binding before retrying",
        measure.account_id.as_deref().unwrap_or("<future-member>"),
        measure.resolved_bytes,
        measure.limit_bytes
    )))
}

pub async fn validate_all_known_stacks_in(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
) -> Result<Vec<StackMeasure>> {
    let accounts: Vec<String> = sqlx::query_scalar(
        "SELECT account_id FROM member_contexts
         UNION SELECT scope_id FROM instruction_bindings WHERE scope_kind='account'
         UNION SELECT account_id FROM member_obligations ORDER BY 1",
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut measures = vec![validate_account_stack_in(tx, tool, None).await?];
    for account in accounts {
        measures.push(validate_account_stack_in(tx, tool, Some(&account)).await?);
    }
    for trigger_key in ["on_owner_first_run", "on_member_joined"] {
        let measure = measure_future_trigger_stack_in(tx, trigger_key).await?;
        measures.push(assert_measure_within_budget(tool, measure)?);
    }
    Ok(measures)
}

pub async fn source_is_active_in(
    tx: &mut Transaction<'_, Sqlite>,
    source_record_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM instruction_bindings WHERE source_record_id=? AND enabled=1
           UNION ALL SELECT 1 FROM onboarding_programme_sources s
             JOIN onboarding_programmes p ON p.id=s.programme_id
            WHERE s.source_record_id=? AND p.enabled=1)",
    )
    .bind(source_record_id)
    .bind(source_record_id)
    .fetch_one(&mut **tx)
    .await?)
}

pub async fn assert_source_deletable_in(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    source_record_id: &str,
) -> Result<()> {
    let mut executor = BorrowedSqliteStatementExecutor::new(tx);
    assert_source_deletable_with(&mut executor, tool, source_record_id).await
}

fn instruction_statement(
    tool: &str,
    relation: &'static str,
    fragments: &'static [&'static str],
) -> Result<StatementTemplate> {
    StatementTemplate::new(StatementKind::Select, relation, fragments)
        .map_err(|error| Error::engine(format!("{tool}: {}", error.stable_message())))
}

async fn instruction_rows<E: DomainStatementExecutor>(
    executor: &mut E,
    tool: &str,
    statement: &StatementTemplate,
    bindings: &[BindValue],
    columns: &[ColumnSpec],
) -> Result<Vec<NormalizedRow>> {
    executor
        .fetch_all(statement, bindings, columns)
        .await
        .map_err(|error| Error::engine(format!("{tool}: {}", error.stable_message())))
}

fn instruction_text(row: &NormalizedRow, column: &str, tool: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "{tool}: active instruction reference column '{column}' is invalid"
        ))),
    }
}

/// Return the canonical, deterministically ordered labels for every enabled
/// instruction binding or onboarding programme which names this record.
/// Reads stay split by physical relation so the same reviewed statements run
/// on SQLite, Postgres and Turso without embedding one backend's join syntax.
pub(crate) async fn active_source_references_with<E: DomainStatementExecutor>(
    executor: &mut E,
    tool: &str,
    source_record_id: &str,
) -> Result<Vec<String>> {
    let binding_query = instruction_statement(
        tool,
        "instruction_bindings",
        &[
            "SELECT id, scope_kind FROM {{relation}} WHERE source_record_id = ",
            " AND enabled = TRUE ORDER BY id",
        ],
    )?;
    let source_query = instruction_statement(
        tool,
        "onboarding_programme_sources",
        &[
            "SELECT programme_id, source_role FROM {{relation}} WHERE source_record_id = ",
            " ORDER BY programme_id",
        ],
    )?;
    let programme_query = instruction_statement(
        tool,
        "onboarding_programmes",
        &["SELECT id FROM {{relation}} WHERE enabled = TRUE ORDER BY id"],
    )?;
    let bindings = instruction_rows(
        executor,
        tool,
        &binding_query,
        &[BindValue::Text(source_record_id.into())],
        &[
            ColumnSpec::required("id", LogicalType::Text),
            ColumnSpec::required("scope_kind", LogicalType::Text),
        ],
    )
    .await?;
    let sources = instruction_rows(
        executor,
        tool,
        &source_query,
        &[BindValue::Text(source_record_id.into())],
        &[
            ColumnSpec::required("programme_id", LogicalType::Text),
            ColumnSpec::required("source_role", LogicalType::Text),
        ],
    )
    .await?;
    let enabled_programmes = instruction_rows(
        executor,
        tool,
        &programme_query,
        &[],
        &[ColumnSpec::required("id", LogicalType::Text)],
    )
    .await?
    .into_iter()
    .map(|row| instruction_text(&row, "id", tool))
    .collect::<Result<std::collections::BTreeSet<_>>>()?;

    let mut references = bindings
        .iter()
        .map(|row| {
            Ok(format!(
                "binding {} ({})",
                instruction_text(row, "id", tool)?,
                instruction_text(row, "scope_kind", tool)?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    for source in sources {
        let programme_id = instruction_text(&source, "programme_id", tool)?;
        if enabled_programmes.contains(&programme_id) {
            references.push(format!(
                "programme {programme_id} ({})",
                instruction_text(&source, "source_role", tool)?
            ));
        }
    }
    Ok(references)
}

/// Refuse deletion with the one canonical active-source error used by every
/// storage adapter and by the SQLite reference handler itself.
pub(crate) async fn assert_source_deletable_with<E: DomainStatementExecutor>(
    executor: &mut E,
    tool: &str,
    source_record_id: &str,
) -> Result<()> {
    let references = active_source_references_with(executor, tool, source_record_id).await?;
    if references.is_empty() {
        return Ok(());
    }
    Err(Error::engine(format!(
        "{tool}: record {source_record_id} is an active instruction source referenced by {}; disable or remove those bindings/programme sources before deleting it",
        references.join(", ")
    )))
}
