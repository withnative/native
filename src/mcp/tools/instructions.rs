//! Portable standing-instruction and onboarding control commands.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::{self, Capability, Principal};
use crate::control::{
    append_control_event_in, member_obligation_aggregate_id, programme_source_aggregate_id,
    ControlEventPayload, EmptyPayload, InstructionBindingReorderedPayload,
    InstructionBindingStatePayload, InstructionBindingTogglePayload,
    MemberObligationProgressedPayload, MemberObligationRebasedPayload,
    MemberObligationReopenedPayload, MemberObligationResolvedPayload, MemberObligationStatePayload,
    NewControlEvent, OnboardingProgrammeSourcePayload, OnboardingProgrammeSourceRemovedPayload,
    OnboardingProgrammeStatePayload, ProgrammeGenerationPublishedPayload,
    SeededInstructionSourceAppliedPayload,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::instructions::{self, StackMeasure};
use crate::store::{append_in, now_iso, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, require_nonblank_reason, REASON_DESCRIPTION};

const DATABASE_SCOPE_ID: &str = "native:database";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InstructionScope {
    Workspace,
    Member,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageInstructionsArgs {
    List {
        scope: Option<InstructionScope>,
    },
    CreateBinding {
        scope: InstructionScope,
        source_record_id: String,
        position: i64,
        enabled: Option<bool>,
        binding_id: Option<String>,
        idempotency_key: String,
        reason: String,
    },
    RetargetBinding {
        binding_id: String,
        source_record_id: String,
        idempotency_key: String,
        reason: String,
    },
    ReorderBinding {
        binding_id: String,
        position: i64,
        idempotency_key: String,
        reason: String,
    },
    EnableBinding {
        binding_id: String,
        idempotency_key: String,
        reason: String,
    },
    DisableBinding {
        binding_id: String,
        idempotency_key: String,
        reason: String,
    },
    RemoveBinding {
        binding_id: String,
        idempotency_key: String,
        reason: String,
    },
    CompareSeededDefault {
        source_record_id: String,
    },
    ApplySeededDefault {
        source_record_id: String,
        expected_body_digest: String,
        idempotency_key: String,
        reason: String,
    },
    ResetSeededDefault {
        source_record_id: String,
        expected_body_digest: String,
        confirm: bool,
        idempotency_key: String,
        reason: String,
    },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
enum AudienceKind {
    All,
    Terminal,
    Pending,
    Accounts,
}

impl AudienceKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Terminal => "terminal",
            Self::Pending => "pending",
            Self::Accounts => "accounts",
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct AudienceSelector {
    kind: AudienceKind,
    #[serde(default)]
    account_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageOnboardingArgs {
    ListProgrammes,
    CreateProgramme {
        programme_id: Option<String>,
        trigger_key: String,
        position: i64,
        enabled: Option<bool>,
        idempotency_key: String,
        reason: String,
    },
    ConfigureProgramme {
        programme_id: String,
        trigger_key: Option<String>,
        position: Option<i64>,
        enabled: Option<bool>,
        idempotency_key: String,
        reason: String,
    },
    AddSource {
        programme_id: String,
        source_record_id: String,
        source_role: String,
        position: i64,
        idempotency_key: String,
        reason: String,
    },
    ChangeSource {
        programme_id: String,
        source_record_id: String,
        source_role: String,
        position: i64,
        idempotency_key: String,
        reason: String,
    },
    ReorderSource {
        programme_id: String,
        source_record_id: String,
        position: i64,
        idempotency_key: String,
        reason: String,
    },
    RemoveSource {
        programme_id: String,
        source_record_id: String,
        idempotency_key: String,
        reason: String,
    },
    PreviewGeneration {
        programme_id: String,
        audience: AudienceSelector,
    },
    PublishGeneration {
        programme_id: String,
        audience: AudienceSelector,
        expected_generation: i64,
        expected_audience_digest: String,
        idempotency_key: String,
        reason: String,
    },
    RecordProgress {
        programme_id: String,
        generation: i64,
        phase: String,
        evidence: Value,
        resume_after: Option<String>,
        artifact_id: Option<String>,
        explicit_member_intent: Option<bool>,
        idempotency_key: String,
        reason: String,
    },
    ResolveObligation {
        programme_id: String,
        generation: i64,
        resolution: String,
        evidence: Value,
        explicit_member_intent: Option<bool>,
        idempotency_key: String,
        reason: String,
    },
    ReopenObligation {
        programme_id: String,
        generation: i64,
        evidence: Value,
        explicit_member_intent: bool,
        idempotency_key: String,
        reason: String,
    },
}

fn require_progress_evidence(tool: &str, evidence: &Value) -> Result<()> {
    if !evidence.is_object() {
        return Err(Error::engine(format!(
            "{tool}: progress evidence must be an object"
        )));
    }
    if serde_json::to_vec(evidence)?.len() > crate::control::MAX_OBLIGATION_PROGRESS_EVIDENCE_BYTES
    {
        return Err(Error::engine(format!(
            "{tool}: progress evidence exceeds {} bytes",
            crate::control::MAX_OBLIGATION_PROGRESS_EVIDENCE_BYTES
        )));
    }
    Ok(())
}

fn require_sha256(tool: &str, label: &str, value: Option<&str>) -> Result<String> {
    let value = value.ok_or_else(|| Error::engine(format!("{tool}: {label} is required")))?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::engine(format!(
            "{tool}: {label} must be a 64-character SHA-256 digest"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_starting_context_body(tool: &str, body: &str) -> Result<()> {
    const HEADINGS: [&str; 6] = [
        "# Starting context",
        "## Current aim",
        "## Useful learned context",
        "## Work or decision made",
        "## Next step",
        "## Material uncertainty and source attribution",
    ];
    if body.len() > 8 * 1024 {
        return Err(Error::engine(format!(
            "{tool}: Starting context body exceeds 8192 bytes"
        )));
    }
    let lines = body.lines().collect::<Vec<_>>();
    if lines.first().copied() != Some(HEADINGS[0]) {
        return Err(Error::engine(format!(
            "{tool}: Starting context title must be the first line"
        )));
    }
    let heading_indices = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| line.starts_with('#').then_some(index))
        .collect::<Vec<_>>();
    let heading_lines = heading_indices
        .iter()
        .map(|index| lines[*index])
        .collect::<Vec<_>>();
    if heading_lines != HEADINGS {
        return Err(Error::engine(format!(
            "{tool}: Starting context must contain exactly the required bounded sections in order"
        )));
    }
    if lines[1..heading_indices[1]]
        .iter()
        .any(|line| !line.trim().is_empty())
    {
        return Err(Error::engine(format!(
            "{tool}: Starting context may not contain prose outside the five required sections"
        )));
    }
    for (index, heading) in HEADINGS.iter().enumerate().skip(1) {
        let start = heading_indices[index] + 1;
        let end = heading_indices
            .get(index + 1)
            .copied()
            .unwrap_or(lines.len());
        if lines[start..end].iter().all(|line| line.trim().is_empty()) {
            return Err(Error::engine(format!(
                "{tool}: Starting context section '{heading}' must not be empty"
            )));
        }
    }
    Ok(())
}

async fn starting_context_is_current_private(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    artifact_id: &str,
) -> Result<bool> {
    let context = sqlx::query(
        "SELECT c.person_record_id,c.root_record_id
           FROM member_contexts c
           JOIN records root ON root.id=c.root_record_id AND root.deleted_at IS NULL
          WHERE c.account_id=?",
    )
    .bind(caller.credential())
    .fetch_optional(&mut **tx)
    .await?;
    let Some(context) = context else {
        return Ok(false);
    };
    let person_record_id: String = context.try_get("person_record_id")?;
    let root_record_id: String = context.try_get("root_record_id")?;
    let policy_rows = sqlx::query(
        "SELECT subject_kind,subject_id,effect,capability FROM policy_entries
          WHERE policy_anchor_id=? ORDER BY subject_kind,subject_id LIMIT 2",
    )
    .bind(&root_record_id)
    .fetch_all(&mut **tx)
    .await?;
    if policy_rows.len() != 1
        || policy_rows[0].try_get::<String, _>("subject_kind")? != "account"
        || policy_rows[0].try_get::<String, _>("subject_id")? != caller.credential()
        || policy_rows[0].try_get::<String, _>("effect")? != "allow"
        || policy_rows[0].try_get::<String, _>("capability")? != "manage"
    {
        return Ok(false);
    }
    let live: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM records
          WHERE home_id=? AND type='Document' AND kind='note'
            AND name='Starting context' AND deleted_at IS NULL
          ORDER BY id LIMIT 2",
    )
    .bind(&root_record_id)
    .fetch_all(&mut **tx)
    .await?;
    if live.as_slice() != [artifact_id] {
        return Ok(false);
    }
    let capability = authorization::effective_capability_on(
        tx,
        Principal::bound(caller.credential(), true),
        artifact_id,
    )
    .await;
    if !capability.is_ok_and(|capability| capability.allows(Capability::Manage)) {
        return Ok(false);
    }
    let exact: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records
          WHERE id=? AND deleted_at IS NULL AND type='Document' AND kind='note'
            AND name='Starting context' AND home_id=? AND owner_id=? AND policy_anchor_id=?)",
    )
    .bind(artifact_id)
    .bind(&root_record_id)
    .bind(&person_record_id)
    .bind(&root_record_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(exact)
}

fn require_owner(caller: &Caller, tool: &str) -> Result<()> {
    if caller.is_host_owner() {
        Ok(())
    } else {
        Err(Error::auth(format!(
            "{tool}: database owner host role required"
        )))
    }
}

fn require_position(tool: &str, position: i64) -> Result<()> {
    if position >= 0 {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "{tool}: position must be zero or greater"
        )))
    }
}

fn require_idempotency(tool: &str, key: &str) -> Result<()> {
    if key.trim().is_empty() {
        Err(Error::engine(format!(
            "{tool}: idempotency_key must not be blank"
        )))
    } else {
        Ok(())
    }
}

fn require_trigger(tool: &str, trigger: &str) -> Result<()> {
    if matches!(trigger, "on_owner_first_run" | "on_member_joined") {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "{tool}: trigger_key must be on_owner_first_run or on_member_joined"
        )))
    }
}

fn require_source_role(tool: &str, role: &str) -> Result<()> {
    if matches!(role, "guidance" | "completion_criteria") {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "{tool}: source_role must be guidance or completion_criteria"
        )))
    }
}

async fn prior_event(
    tx: &mut Transaction<'_, Sqlite>,
    key: &str,
) -> Result<Option<(String, String, String, String, Value)>> {
    let row = sqlx::query(
        "SELECT type,aggregate_id,actor,reason,payload FROM control_events WHERE idempotency_key=?",
    )
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok((
            row.try_get("type")?,
            row.try_get("aggregate_id")?,
            row.try_get("actor")?,
            row.try_get("reason")?,
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?,
        ))
    })
    .transpose()
}

async fn event_time(tx: &mut Transaction<'_, Sqlite>, key: &str, field: &str) -> Result<String> {
    Ok(prior_event(tx, key)
        .await?
        .and_then(|(_, _, _, _, payload)| payload.get(field)?.as_str().map(str::to_owned))
        .unwrap_or_else(now_iso))
}

async fn append_authored(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    key: String,
    aggregate_id: String,
    reason: String,
    payload: ControlEventPayload,
) -> Result<()> {
    append_control_event_in(
        tx,
        NewControlEvent::authored(
            key,
            aggregate_id,
            caller.actor(),
            caller.run_key().map(str::to_owned),
            reason,
            payload,
        )?,
    )
    .await?;
    Ok(())
}

async fn reappend_published_child(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    key: String,
    reason: &str,
) -> Result<()> {
    let (kind, aggregate, actor, prior_reason, payload) = prior_event(tx, &key)
        .await?
        .ok_or_else(|| Error::engine("published generation is missing a canonical child event"))?;
    if actor != caller.actor() || prior_reason != reason {
        return Err(Error::engine(
            "published generation child event does not match its canonical intent",
        ));
    }
    let payload = match kind.as_str() {
        "member_obligation.rebased" => {
            ControlEventPayload::MemberObligationRebased(serde_json::from_value(payload)?)
        }
        "member_obligation.activated" => {
            ControlEventPayload::MemberObligationActivated(serde_json::from_value(payload)?)
        }
        _ => {
            return Err(Error::engine(
                "published generation child event has an unexpected type",
            ))
        }
    };
    append_authored(tx, caller, key, aggregate, prior_reason, payload).await
}

async fn require_document_source(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    tool: &str,
    source: &str,
    workspace_wide: bool,
) -> Result<()> {
    let record_type: Option<String> =
        sqlx::query_scalar("SELECT type FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(source)
            .fetch_optional(&mut **tx)
            .await?;
    if record_type.as_deref() != Some("Document") {
        return Err(Error::engine(format!(
            "{tool}: source_record_id must name a live Document"
        )));
    }
    let principal = if workspace_wide {
        Principal::bound("native:prospective-member", true)
    } else {
        Principal::bound(caller.credential(), true)
    };
    let capability = authorization::effective_capability_on(tx, principal, source).await?;
    if !capability.allows(Capability::View) {
        return Err(Error::engine(format!(
            "{tool}: source {source} is not readable by every affected member"
        )));
    }
    Ok(())
}

async fn binding_for_actor(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    tool: &str,
    binding_id: &str,
) -> Result<InstructionBindingStatePayload> {
    let row = sqlx::query(
        "SELECT id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at
           FROM instruction_bindings WHERE id=?",
    )
    .bind(binding_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{tool}: binding {binding_id} does not exist")))?;
    let scope_kind: String = row.try_get("scope_kind")?;
    let scope_id: String = row.try_get("scope_id")?;
    if scope_kind == "database" {
        require_owner(caller, tool)?;
    } else if scope_id != caller.credential() {
        return Err(Error::auth(format!(
            "{tool}: matching member account required"
        )));
    }
    Ok(InstructionBindingStatePayload {
        id: row.try_get("id")?,
        scope_kind,
        scope_id,
        source_record_id: row.try_get("source_record_id")?,
        position: row.try_get("position")?,
        enabled: row.try_get::<i64, _>("enabled")? != 0,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn require_seed_authority_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    tool: &str,
    source_record_id: &str,
) -> Result<()> {
    let scopes: Vec<(String, String)> = sqlx::query_as(
        "SELECT scope_kind,scope_id FROM instruction_bindings WHERE source_record_id=?
         UNION SELECT 'database','native:database' FROM onboarding_programme_sources WHERE source_record_id=?",
    )
    .bind(source_record_id)
    .bind(source_record_id)
    .fetch_all(&mut **tx)
    .await?;
    if scopes.iter().any(|(kind, _)| kind == "database") {
        require_owner(caller, tool)
    } else if scopes
        .iter()
        .any(|(kind, id)| kind == "account" && id == caller.credential())
    {
        Ok(())
    } else {
        Err(Error::auth(format!(
            "{tool}: matching instruction source authority required"
        )))
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_or_reset_seeded_default(
    db: &Db,
    caller: &Caller,
    tool: &str,
    source_record_id: String,
    expected_body_digest: String,
    idempotency_key: String,
    reason: String,
    reset: bool,
    confirm: bool,
) -> Result<Value> {
    require_nonblank_reason(tool, &reason)?;
    require_idempotency(tool, &idempotency_key)?;
    if reset && !confirm {
        return Err(Error::engine(format!(
            "{tool}: reset_seeded_default requires confirm: true"
        )));
    }
    let operation = if reset {
        "reset_seeded_default"
    } else {
        "apply_seeded_default"
    };
    let expected_body_digest = expected_body_digest.to_ascii_lowercase();
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    require_seed_authority_in(&mut tx, caller, tool, &source_record_id).await?;
    if let Some((kind, aggregate, actor, prior_reason, raw_payload)) =
        prior_event(&mut tx, &idempotency_key).await?
    {
        let payload: SeededInstructionSourceAppliedPayload = serde_json::from_value(raw_payload)?;
        if kind != "seeded_instruction_source.applied"
            || aggregate != source_record_id
            || actor != caller.actor()
            || prior_reason != reason
            || payload.source_record_id != source_record_id
            || payload.operation.as_deref() != Some(operation)
            || payload.expected_body_digest.as_deref() != Some(expected_body_digest.as_str())
        {
            return Err(Error::engine(format!(
                "{tool}: idempotency_key was reused for different intent"
            )));
        }
        append_authored(
            &mut tx,
            caller,
            idempotency_key,
            source_record_id.clone(),
            reason,
            ControlEventPayload::SeededInstructionSourceApplied(payload.clone()),
        )
        .await?;
        let stacks = instructions::validate_all_known_stacks_in(&mut tx, tool).await?;
        tx.commit().await?;
        let template = crate::instruction_templates::instruction_template(&payload.template_key);
        return Ok(json!({
            "source_record_id": source_record_id,
            "template_key": payload.template_key,
            "template_version": payload.template_version,
            "source_title": template.map(|template| template.name),
            "body_digest": payload.last_applied_digest,
            "changed": false,
            "body_changed": false,
            "provenance_changed": false,
            "idempotent_retry": true,
            "stacks": stacks,
        }));
    }
    let row = sqlx::query(
        "SELECT s.template_key,s.template_version,s.last_applied_digest,r.body
           FROM seeded_instruction_sources s JOIN records r ON r.id=s.source_record_id
          WHERE s.source_record_id=? AND r.deleted_at IS NULL",
    )
    .bind(&source_record_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        Error::engine(format!(
            "{tool}: source {source_record_id} is not a seeded instruction source"
        ))
    })?;
    let template_key: String = row.try_get("template_key")?;
    let applied_version: i64 = row.try_get("template_version")?;
    let last_applied_digest: String = row.try_get("last_applied_digest")?;
    let current_body: Option<String> = row.try_get("body")?;
    let current_body = current_body.unwrap_or_default();
    let current_digest = crate::instruction_templates::instruction_body_digest(&current_body);
    if expected_body_digest != current_digest {
        return Err(Error::engine(format!(
            "{tool}: body digest conflict — the source changed since compare"
        )));
    }
    let template = crate::instruction_templates::instruction_template(&template_key)
        .ok_or_else(|| Error::engine(format!("{tool}: unknown shipped template {template_key}")))?;
    let shipped_digest = crate::instruction_templates::instruction_body_digest(template.body);
    if !reset && current_digest != last_applied_digest && current_digest != shipped_digest {
        return Err(Error::engine(format!(
            "{tool}: source is customized; compare it and use reset_seeded_default with explicit confirmation to replace it"
        )));
    }
    if template.version < applied_version {
        return Err(Error::engine(format!(
            "{tool}: stored template version is newer than this engine"
        )));
    }
    let body_changed = current_digest != shipped_digest;
    if body_changed {
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: source_record_id.clone(),
                event_type: "record.updated".into(),
                payload: json!({ "body": template.body, "reason": reason }),
                actor: Some(caller.actor().into()),
            },
        )
        .await?;
    }
    let provenance_changed = template.version > applied_version;
    let applied_at = event_time(&mut tx, &idempotency_key, "last_applied_at").await?;
    append_authored(
        &mut tx,
        caller,
        idempotency_key,
        source_record_id.clone(),
        reason,
        ControlEventPayload::SeededInstructionSourceApplied(
            SeededInstructionSourceAppliedPayload {
                source_record_id: source_record_id.clone(),
                template_key: template.key.into(),
                template_version: template.version,
                last_applied_digest: shipped_digest.clone(),
                last_applied_at: applied_at,
                operation: Some(operation.into()),
                expected_body_digest: Some(expected_body_digest),
            },
        ),
    )
    .await?;
    let stacks = instructions::validate_all_known_stacks_in(&mut tx, tool).await?;
    if body_changed {
        db.commit_content(tx).await?;
    } else {
        tx.commit().await?;
    }
    Ok(json!({
        "source_record_id": source_record_id,
        "template_key": template_key,
        "template_version": template.version,
        "source_title": template.name,
        "body_digest": shipped_digest,
        "changed": body_changed || provenance_changed,
        "body_changed": body_changed,
        "provenance_changed": provenance_changed,
        "stacks": stacks,
    }))
}

async fn manage_instructions(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "manage_instructions";
    let args: ManageInstructionsArgs = parse_args(TOOL, arguments)?;
    match args {
        ManageInstructionsArgs::List { scope } => {
            let include_workspace = !matches!(scope, Some(InstructionScope::Member));
            let include_member = !matches!(scope, Some(InstructionScope::Workspace));
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let rows = sqlx::query(
                "SELECT b.id,b.scope_kind,b.scope_id,b.source_record_id,b.position,b.enabled,
                        r.name,r.updated_at,s.template_key,s.template_version,s.last_applied_digest
                   FROM instruction_bindings b
                   JOIN records r ON r.id=b.source_record_id
                   LEFT JOIN seeded_instruction_sources s ON s.source_record_id=r.id
                  WHERE (b.scope_kind='database' AND ?) OR
                        (b.scope_kind='account' AND b.scope_id=? AND ?)
                  ORDER BY CASE b.scope_kind WHEN 'database' THEN 0 ELSE 1 END,b.position,b.id",
            )
            .bind(include_workspace)
            .bind(caller.credential())
            .bind(include_member)
            .fetch_all(&mut *tx)
            .await?;
            let mut bindings = Vec::with_capacity(rows.len());
            for row in rows {
                let source_record_id: String = row.try_get("source_record_id")?;
                let readable = authorization::effective_capability_on(
                    &mut tx,
                    Principal::bound(caller.credential(), true),
                    &source_record_id,
                )
                .await
                .map(|capability| capability.allows(Capability::View))
                .unwrap_or(false);
                if !readable {
                    return Err(Error::auth(format!(
                        "{TOOL}: an instruction source is not readable"
                    )));
                }
                bindings.push(json!({
                    "id": row.try_get::<String,_>("id")?,
                    "scope": if row.try_get::<String,_>("scope_kind")? == "database" { "workspace" } else { "member" },
                    "source_record_id": source_record_id,
                    "position": row.try_get::<i64,_>("position")?,
                    "enabled": row.try_get::<i64,_>("enabled")? != 0,
                    "source_title": row.try_get::<String,_>("name")?,
                    "source_updated_at": row.try_get::<String,_>("updated_at")?,
                    "seed": {
                        "template_key": row.try_get::<Option<String>,_>("template_key")?,
                        "template_version": row.try_get::<Option<i64>,_>("template_version")?,
                        "last_applied_digest": row.try_get::<Option<String>,_>("last_applied_digest")?,
                    }
                }));
            }
            tx.rollback().await?;
            Ok(
                json!({ "bindings": bindings, "limit_bytes": instructions::MAX_RESOLVED_INSTRUCTION_BYTES }),
            )
        }
        ManageInstructionsArgs::CreateBinding {
            scope,
            source_record_id,
            position,
            enabled,
            binding_id,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            require_position(TOOL, position)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let prior = prior_event(&mut tx, &idempotency_key).await?;
            let id = binding_id
                .or_else(|| prior.as_ref().map(|(_, id, _, _, _)| id.clone()))
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let (scope_kind, scope_id, workspace_wide) = match scope {
                InstructionScope::Workspace => {
                    require_owner(&caller, TOOL)?;
                    ("database", DATABASE_SCOPE_ID.to_string(), true)
                }
                InstructionScope::Member => ("account", caller.credential().to_string(), false),
            };
            require_document_source(&mut tx, &caller, TOOL, &source_record_id, workspace_wide)
                .await?;
            let timestamp = event_time(&mut tx, &idempotency_key, "created_at").await?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                id.clone(),
                reason,
                ControlEventPayload::InstructionBindingCreated(InstructionBindingStatePayload {
                    id: id.clone(),
                    scope_kind: scope_kind.into(),
                    scope_id,
                    source_record_id: source_record_id.clone(),
                    position,
                    enabled: enabled.unwrap_or(true),
                    created_by: caller.actor().into(),
                    created_at: timestamp.clone(),
                    updated_at: timestamp,
                }),
            )
            .await?;
            let measures = instructions::validate_all_known_stacks_in(&mut tx, TOOL).await?;
            tx.commit().await?;
            Ok(
                json!({ "binding_id": id, "source_record_id": source_record_id, "changed": true, "stacks": measures }),
            )
        }
        ManageInstructionsArgs::RetargetBinding {
            binding_id,
            source_record_id,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut state = binding_for_actor(&mut tx, &caller, TOOL, &binding_id).await?;
            require_document_source(
                &mut tx,
                &caller,
                TOOL,
                &source_record_id,
                state.scope_kind == "database",
            )
            .await?;
            state.source_record_id = source_record_id.clone();
            state.updated_at = event_time(&mut tx, &idempotency_key, "updated_at").await?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                binding_id.clone(),
                reason,
                ControlEventPayload::InstructionBindingChanged(state),
            )
            .await?;
            let measures = instructions::validate_all_known_stacks_in(&mut tx, TOOL).await?;
            tx.commit().await?;
            Ok(
                json!({ "binding_id": binding_id, "source_record_id": source_record_id, "changed": true, "stacks": measures }),
            )
        }
        ManageInstructionsArgs::ReorderBinding {
            binding_id,
            position,
            idempotency_key,
            reason,
        } => {
            require_position(TOOL, position)?;
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            binding_for_actor(&mut tx, &caller, TOOL, &binding_id).await?;
            let updated_at = event_time(&mut tx, &idempotency_key, "updated_at").await?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                binding_id.clone(),
                reason,
                ControlEventPayload::InstructionBindingReordered(
                    InstructionBindingReorderedPayload {
                        position,
                        updated_at,
                    },
                ),
            )
            .await?;
            tx.commit().await?;
            Ok(json!({ "binding_id": binding_id, "position": position, "changed": true }))
        }
        action @ (ManageInstructionsArgs::EnableBinding { .. }
        | ManageInstructionsArgs::DisableBinding { .. }) => {
            let enable = matches!(&action, ManageInstructionsArgs::EnableBinding { .. });
            let (binding_id, idempotency_key, reason) = match action {
                ManageInstructionsArgs::EnableBinding {
                    binding_id,
                    idempotency_key,
                    reason,
                }
                | ManageInstructionsArgs::DisableBinding {
                    binding_id,
                    idempotency_key,
                    reason,
                } => (binding_id, idempotency_key, reason),
                _ => unreachable!(),
            };
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            binding_for_actor(&mut tx, &caller, TOOL, &binding_id).await?;
            let updated_at = event_time(&mut tx, &idempotency_key, "updated_at").await?;
            let payload = InstructionBindingTogglePayload { updated_at };
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                binding_id.clone(),
                reason,
                if enable {
                    ControlEventPayload::InstructionBindingEnabled(payload)
                } else {
                    ControlEventPayload::InstructionBindingDisabled(payload)
                },
            )
            .await?;
            let measures = if enable {
                Some(instructions::validate_all_known_stacks_in(&mut tx, TOOL).await?)
            } else {
                None
            };
            tx.commit().await?;
            Ok(
                json!({ "binding_id": binding_id, "enabled": enable, "changed": true, "stacks": measures }),
            )
        }
        ManageInstructionsArgs::RemoveBinding {
            binding_id,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            if let Some((kind, aggregate, actor, prior_reason, payload)) =
                prior_event(&mut tx, &idempotency_key).await?
            {
                if kind != "instruction_binding.removed"
                    || aggregate != binding_id
                    || actor != caller.actor()
                    || prior_reason != reason
                    || payload != json!({})
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: idempotency_key was reused for different intent"
                    )));
                }
                append_authored(
                    &mut tx,
                    &caller,
                    idempotency_key,
                    binding_id.clone(),
                    reason,
                    ControlEventPayload::InstructionBindingRemoved(EmptyPayload::default()),
                )
                .await?;
                tx.commit().await?;
                return Ok(
                    json!({ "binding_id": binding_id, "removed": true, "changed": false, "idempotent_retry": true }),
                );
            }
            binding_for_actor(&mut tx, &caller, TOOL, &binding_id).await?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                binding_id.clone(),
                reason,
                ControlEventPayload::InstructionBindingRemoved(EmptyPayload::default()),
            )
            .await?;
            tx.commit().await?;
            Ok(json!({ "binding_id": binding_id, "removed": true, "changed": true }))
        }
        ManageInstructionsArgs::CompareSeededDefault { source_record_id } => {
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            require_seed_authority_in(&mut tx, &caller, TOOL, &source_record_id).await?;
            let readable = authorization::effective_capability_on(
                &mut tx,
                Principal::bound(caller.credential(), true),
                &source_record_id,
            )
            .await
            .map(|capability| capability.allows(Capability::View))
            .unwrap_or(false);
            if !readable {
                return Err(Error::auth(format!(
                    "{TOOL}: seeded instruction source is not readable"
                )));
            }
            let row = sqlx::query(
                "SELECT s.template_key,s.template_version,s.last_applied_digest,s.last_applied_at,
                        r.body FROM seeded_instruction_sources s JOIN records r ON r.id=s.source_record_id
                  WHERE s.source_record_id=? AND r.deleted_at IS NULL",
            )
            .bind(&source_record_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| Error::engine(format!("{TOOL}: source {source_record_id} is not a seeded instruction source")))?;
            let body: Option<String> = row.try_get("body")?;
            let current_digest = hex::encode(Sha256::digest(body.unwrap_or_default().as_bytes()));
            let template_key: String = row.try_get("template_key")?;
            let shipped = crate::instruction_templates::instruction_template(&template_key);
            let result = json!({
                "source_record_id": source_record_id,
                "template_key": template_key,
                "template_version": row.try_get::<i64,_>("template_version")?,
                "last_applied_digest": row.try_get::<String,_>("last_applied_digest")?,
                "last_applied_at": row.try_get::<String,_>("last_applied_at")?,
                "current_digest": current_digest,
                "shipped_template_available": shipped.is_some(),
                "shipped_version": shipped.map(|template| template.version),
                "shipped_digest": shipped.map(|template| crate::instruction_templates::instruction_body_digest(template.body)),
                "shipped_body": shipped.map(|template| template.body),
            });
            tx.rollback().await?;
            Ok(result)
        }
        ManageInstructionsArgs::ApplySeededDefault {
            source_record_id,
            expected_body_digest,
            idempotency_key,
            reason,
        } => {
            apply_or_reset_seeded_default(
                &db,
                &caller,
                TOOL,
                source_record_id,
                expected_body_digest,
                idempotency_key,
                reason,
                false,
                false,
            )
            .await
        }
        ManageInstructionsArgs::ResetSeededDefault {
            source_record_id,
            expected_body_digest,
            confirm,
            idempotency_key,
            reason,
        } => {
            apply_or_reset_seeded_default(
                &db,
                &caller,
                TOOL,
                source_record_id,
                expected_body_digest,
                idempotency_key,
                reason,
                true,
                confirm,
            )
            .await
        }
    }
}

#[derive(Debug, Clone)]
struct ProgrammeState {
    id: String,
    trigger_key: String,
    generation: i64,
    position: i64,
    enabled: bool,
    created_by: String,
    legacy_baseline_before: Option<String>,
    created_at: String,
    updated_at: String,
}

async fn programme_state(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    id: &str,
) -> Result<ProgrammeState> {
    let row = sqlx::query(
        "SELECT id,trigger_key,generation,position,enabled,created_by,legacy_baseline_before,created_at,updated_at
           FROM onboarding_programmes WHERE id=?",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("{tool}: programme {id} does not exist")))?;
    Ok(ProgrammeState {
        id: row.try_get("id")?,
        trigger_key: row.try_get("trigger_key")?,
        generation: row.try_get("generation")?,
        position: row.try_get("position")?,
        enabled: row.try_get::<i64, _>("enabled")? != 0,
        created_by: row.try_get("created_by")?,
        legacy_baseline_before: row.try_get("legacy_baseline_before")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

impl From<ProgrammeState> for OnboardingProgrammeStatePayload {
    fn from(value: ProgrammeState) -> Self {
        Self {
            id: value.id,
            trigger_key: value.trigger_key,
            generation: value.generation,
            position: value.position,
            enabled: value.enabled,
            created_by: value.created_by,
            legacy_baseline_before: value.legacy_baseline_before,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug)]
struct AudiencePreview {
    programme_id: String,
    generation: i64,
    next_generation: i64,
    account_ids: Vec<String>,
    pending_to_rebase: Vec<String>,
    terminal_or_absent_to_activate: Vec<String>,
    audience_digest: String,
}

async fn preview_audience_in(
    tx: &mut Transaction<'_, Sqlite>,
    tool: &str,
    programme_id: &str,
    selector: &AudienceSelector,
) -> Result<AudiencePreview> {
    let programme = programme_state(tx, tool, programme_id).await?;
    let mut account_ids: Vec<String> = match selector.kind {
        AudienceKind::All => sqlx::query_scalar("SELECT account_id FROM member_contexts ORDER BY account_id")
            .fetch_all(&mut **tx).await?,
        AudienceKind::Pending => sqlx::query_scalar(
            "SELECT account_id FROM member_obligations WHERE programme_id=? AND state='pending' ORDER BY account_id")
            .bind(programme_id).fetch_all(&mut **tx).await?,
        AudienceKind::Terminal => sqlx::query_scalar(
            "SELECT DISTINCT o.account_id FROM member_obligations o
              WHERE o.programme_id=? AND o.state IN ('completed','declined')
                AND NOT EXISTS (SELECT 1 FROM member_obligations p WHERE p.account_id=o.account_id AND p.programme_id=o.programme_id AND p.state='pending')
              ORDER BY o.account_id")
            .bind(programme_id).fetch_all(&mut **tx).await?,
        AudienceKind::Accounts => selector.account_ids.clone(),
    };
    account_ids.sort();
    account_ids.dedup();
    if matches!(selector.kind, AudienceKind::Accounts) {
        for account in &account_ids {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM member_contexts WHERE account_id=?)",
            )
            .bind(account)
            .fetch_one(&mut **tx)
            .await?;
            if !exists {
                return Err(Error::engine(format!(
                    "{tool}: audience account {account} is not a portable database member"
                )));
            }
        }
    } else if !selector.account_ids.is_empty() {
        return Err(Error::engine(format!(
            "{tool}: account_ids is only valid for audience kind accounts"
        )));
    }
    let next_generation = programme
        .generation
        .checked_add(1)
        .ok_or_else(|| Error::engine(format!("{tool}: programme generation is exhausted")))?;
    let mut pending_to_rebase = Vec::new();
    let mut terminal_or_absent_to_activate = Vec::new();
    for account in &account_ids {
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM member_obligations WHERE account_id=? AND programme_id=? AND state='pending')")
            .bind(account).bind(programme_id).fetch_one(&mut **tx).await?;
        if pending {
            pending_to_rebase.push(account.clone());
        } else {
            terminal_or_absent_to_activate.push(account.clone());
        }
    }
    let digest_payload = serde_json::to_vec(&json!({
        "programme_id": programme_id,
        "generation": programme.generation,
        "next_generation": next_generation,
        "account_ids": account_ids,
        "pending_to_rebase": pending_to_rebase,
        "terminal_or_absent_to_activate": terminal_or_absent_to_activate,
    }))?;
    let audience_digest = hex::encode(Sha256::digest(digest_payload));
    Ok(AudiencePreview {
        programme_id: programme_id.into(),
        generation: programme.generation,
        next_generation,
        account_ids,
        pending_to_rebase,
        terminal_or_absent_to_activate,
        audience_digest,
    })
}

fn preview_json(preview: &AudiencePreview) -> Value {
    json!({
        "programme_id": preview.programme_id,
        "generation": preview.generation,
        "next_generation": preview.next_generation,
        "account_ids": preview.account_ids,
        "pending_to_rebase": preview.pending_to_rebase,
        "terminal_or_absent_to_activate": preview.terminal_or_absent_to_activate,
        "audience_digest": preview.audience_digest,
    })
}

async fn manage_onboarding(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "manage_onboarding";
    let args: ManageOnboardingArgs = parse_args(TOOL, arguments)?;
    match args {
        ManageOnboardingArgs::ListProgrammes => {
            require_owner(&caller, TOOL)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let rows = sqlx::query(
                "SELECT p.id,p.trigger_key,p.generation,p.position,p.enabled,p.legacy_baseline_before,
                        (SELECT COUNT(*) FROM member_obligations o WHERE o.programme_id=p.id AND o.state='pending') pending_count
                   FROM onboarding_programmes p ORDER BY p.position,p.id")
                .fetch_all(&mut *tx).await?;
            let mut programmes = Vec::with_capacity(rows.len());
            for row in rows {
                let programme_id: String = row.try_get("id")?;
                let source_rows = sqlx::query(
                    "SELECT s.source_record_id,s.source_role,s.position,r.name source_title,
                            r.updated_at source_updated_at,r.deleted_at,
                            seed.template_key,seed.template_version,seed.last_applied_digest,seed.last_applied_at
                       FROM onboarding_programme_sources s
                       LEFT JOIN records r ON r.id=s.source_record_id
                       LEFT JOIN seeded_instruction_sources seed ON seed.source_record_id=s.source_record_id
                      WHERE s.programme_id=? ORDER BY s.position,s.source_record_id",
                )
                .bind(&programme_id)
                .fetch_all(&mut *tx)
                .await?;
                let mut sources = Vec::with_capacity(source_rows.len());
                for source in source_rows {
                    let source_record_id: String = source.try_get("source_record_id")?;
                    if source
                        .try_get::<Option<String>, _>("source_title")?
                        .is_none()
                        || source.try_get::<Option<String>, _>("deleted_at")?.is_some()
                    {
                        return Err(Error::engine(format!(
                            "{TOOL}: a programme instruction source is invalid"
                        )));
                    }
                    let readable = authorization::effective_capability_on(
                        &mut tx,
                        Principal::bound(caller.credential(), true),
                        &source_record_id,
                    )
                    .await
                    .map(|capability| capability.allows(Capability::View))
                    .unwrap_or(false);
                    if !readable {
                        return Err(Error::auth(format!(
                            "{TOOL}: a programme instruction source is not readable"
                        )));
                    }
                    sources.push(json!({
                        "source_record_id": source_record_id,
                        "source_title": source.try_get::<String,_>("source_title")?,
                        "source_role": source.try_get::<String,_>("source_role")?,
                        "position": source.try_get::<i64,_>("position")?,
                        "source_updated_at": source.try_get::<String,_>("source_updated_at")?,
                        "seed": {
                            "template_key": source.try_get::<Option<String>,_>("template_key")?,
                            "template_version": source.try_get::<Option<i64>,_>("template_version")?,
                            "last_applied_digest": source.try_get::<Option<String>,_>("last_applied_digest")?,
                            "last_applied_at": source.try_get::<Option<String>,_>("last_applied_at")?,
                        }
                    }));
                }
                programmes.push(json!({
                    "id": programme_id,
                    "trigger_key": row.try_get::<String,_>("trigger_key")?,
                    "generation": row.try_get::<i64,_>("generation")?,
                    "position": row.try_get::<i64,_>("position")?,
                    "enabled": row.try_get::<i64,_>("enabled")? != 0,
                    "legacy_baseline_before": row.try_get::<Option<String>,_>("legacy_baseline_before")?,
                    "pending_count": row.try_get::<i64,_>("pending_count")?,
                    "sources": sources,
                }));
            }
            tx.rollback().await?;
            Ok(json!({ "programmes": programmes }))
        }
        ManageOnboardingArgs::PreviewGeneration {
            programme_id,
            audience,
        } => {
            require_owner(&caller, TOOL)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let preview = preview_audience_in(&mut tx, TOOL, &programme_id, &audience).await?;
            tx.rollback().await?;
            Ok(preview_json(&preview))
        }
        ManageOnboardingArgs::CreateProgramme {
            programme_id,
            trigger_key,
            position,
            enabled,
            idempotency_key,
            reason,
        } => {
            require_owner(&caller, TOOL)?;
            require_trigger(TOOL, &trigger_key)?;
            require_position(TOOL, position)?;
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let prior = prior_event(&mut tx, &idempotency_key).await?;
            let id = programme_id
                .or_else(|| prior.as_ref().map(|(_, id, _, _, _)| id.clone()))
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let created_at = event_time(&mut tx, &idempotency_key, "created_at").await?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                id.clone(),
                reason,
                ControlEventPayload::OnboardingProgrammeCreated(OnboardingProgrammeStatePayload {
                    id: id.clone(),
                    trigger_key,
                    generation: 1,
                    position,
                    enabled: enabled.unwrap_or(true),
                    created_by: caller.actor().into(),
                    legacy_baseline_before: None,
                    created_at: created_at.clone(),
                    updated_at: created_at,
                }),
            )
            .await?;
            tx.commit().await?;
            Ok(json!({ "programme_id": id, "generation": 1, "changed": true }))
        }
        ManageOnboardingArgs::ConfigureProgramme {
            programme_id,
            trigger_key,
            position,
            enabled,
            idempotency_key,
            reason,
        } => {
            require_owner(&caller, TOOL)?;
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            if let Some(trigger) = &trigger_key {
                require_trigger(TOOL, trigger)?;
            }
            if let Some(position) = position {
                require_position(TOOL, position)?;
            }
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut state = programme_state(&mut tx, TOOL, &programme_id).await?;
            if let Some(trigger) = trigger_key {
                state.trigger_key = trigger;
            }
            if let Some(position) = position {
                state.position = position;
            }
            if let Some(enabled) = enabled {
                state.enabled = enabled;
            }
            state.updated_at = event_time(&mut tx, &idempotency_key, "updated_at").await?;
            let enabling = state.enabled;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                programme_id.clone(),
                reason,
                ControlEventPayload::OnboardingProgrammeChanged(state.into()),
            )
            .await?;
            let measures = if enabling {
                Some(instructions::validate_all_known_stacks_in(&mut tx, TOOL).await?)
            } else {
                None
            };
            tx.commit().await?;
            Ok(json!({ "programme_id": programme_id, "changed": true, "stacks": measures }))
        }
        action @ (ManageOnboardingArgs::AddSource { .. }
        | ManageOnboardingArgs::ChangeSource { .. }) => {
            let adding = matches!(&action, ManageOnboardingArgs::AddSource { .. });
            let (programme_id, source_record_id, source_role, position, idempotency_key, reason) =
                match action {
                    ManageOnboardingArgs::AddSource {
                        programme_id,
                        source_record_id,
                        source_role,
                        position,
                        idempotency_key,
                        reason,
                    }
                    | ManageOnboardingArgs::ChangeSource {
                        programme_id,
                        source_record_id,
                        source_role,
                        position,
                        idempotency_key,
                        reason,
                    } => (
                        programme_id,
                        source_record_id,
                        source_role,
                        position,
                        idempotency_key,
                        reason,
                    ),
                    _ => unreachable!(),
                };
            require_owner(&caller, TOOL)?;
            require_source_role(TOOL, &source_role)?;
            require_position(TOOL, position)?;
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            programme_state(&mut tx, TOOL, &programme_id).await?;
            require_document_source(&mut tx, &caller, TOOL, &source_record_id, true).await?;
            let payload = OnboardingProgrammeSourcePayload {
                programme_id: programme_id.clone(),
                source_record_id: source_record_id.clone(),
                source_role,
                position,
            };
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                programme_source_aggregate_id(&programme_id, &source_record_id),
                reason,
                if adding {
                    ControlEventPayload::OnboardingProgrammeSourceAdded(payload)
                } else {
                    ControlEventPayload::OnboardingProgrammeSourceChanged(payload)
                },
            )
            .await?;
            let measures = instructions::validate_all_known_stacks_in(&mut tx, TOOL).await?;
            tx.commit().await?;
            Ok(
                json!({ "programme_id": programme_id, "source_record_id": source_record_id, "changed": true, "stacks": measures }),
            )
        }
        ManageOnboardingArgs::ReorderSource {
            programme_id,
            source_record_id,
            position,
            idempotency_key,
            reason,
        } => {
            require_owner(&caller, TOOL)?;
            require_position(TOOL, position)?;
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let role: String = sqlx::query_scalar("SELECT source_role FROM onboarding_programme_sources WHERE programme_id=? AND source_record_id=?")
                .bind(&programme_id).bind(&source_record_id).fetch_optional(&mut *tx).await?
                .ok_or_else(|| Error::engine(format!("{TOOL}: programme source does not exist")))?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                programme_source_aggregate_id(&programme_id, &source_record_id),
                reason,
                ControlEventPayload::OnboardingProgrammeSourceReordered(
                    OnboardingProgrammeSourcePayload {
                        programme_id: programme_id.clone(),
                        source_record_id: source_record_id.clone(),
                        source_role: role,
                        position,
                    },
                ),
            )
            .await?;
            tx.commit().await?;
            Ok(
                json!({ "programme_id": programme_id, "source_record_id": source_record_id, "position": position, "changed": true }),
            )
        }
        ManageOnboardingArgs::RemoveSource {
            programme_id,
            source_record_id,
            idempotency_key,
            reason,
        } => {
            require_owner(&caller, TOOL)?;
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let aggregate_id = programme_source_aggregate_id(&programme_id, &source_record_id);
            if let Some((kind, aggregate, actor, prior_reason, payload)) =
                prior_event(&mut tx, &idempotency_key).await?
            {
                let expected_payload = json!({
                    "programme_id": programme_id,
                    "source_record_id": source_record_id,
                });
                if kind != "onboarding_programme_source.removed"
                    || aggregate != aggregate_id
                    || actor != caller.actor()
                    || prior_reason != reason
                    || payload != expected_payload
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: idempotency_key was reused for different intent"
                    )));
                }
                append_authored(
                    &mut tx,
                    &caller,
                    idempotency_key,
                    aggregate_id,
                    reason,
                    ControlEventPayload::OnboardingProgrammeSourceRemoved(
                        OnboardingProgrammeSourceRemovedPayload {
                            programme_id: programme_id.clone(),
                            source_record_id: source_record_id.clone(),
                        },
                    ),
                )
                .await?;
                tx.commit().await?;
                return Ok(
                    json!({ "programme_id": programme_id, "source_record_id": source_record_id, "removed": true, "changed": false, "idempotent_retry": true }),
                );
            }
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM onboarding_programme_sources WHERE programme_id=? AND source_record_id=?)")
                .bind(&programme_id).bind(&source_record_id).fetch_one(&mut *tx).await?;
            if !exists {
                return Err(Error::engine(format!(
                    "{TOOL}: programme source does not exist"
                )));
            }
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                aggregate_id,
                reason,
                ControlEventPayload::OnboardingProgrammeSourceRemoved(
                    OnboardingProgrammeSourceRemovedPayload {
                        programme_id: programme_id.clone(),
                        source_record_id: source_record_id.clone(),
                    },
                ),
            )
            .await?;
            tx.commit().await?;
            Ok(
                json!({ "programme_id": programme_id, "source_record_id": source_record_id, "removed": true, "changed": true }),
            )
        }
        ManageOnboardingArgs::PublishGeneration {
            programme_id,
            audience,
            expected_generation,
            expected_audience_digest,
            idempotency_key,
            reason,
        } => {
            require_owner(&caller, TOOL)?;
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut requested_account_ids = audience.account_ids.clone();
            requested_account_ids.sort();
            requested_account_ids.dedup();
            if let Some((kind, aggregate, actor, existing_reason, raw_payload)) =
                prior_event(&mut tx, &idempotency_key).await?
            {
                let payload: ProgrammeGenerationPublishedPayload =
                    serde_json::from_value(raw_payload)?;
                if kind != "onboarding_programme.generation_published"
                    || aggregate != programme_id
                    || actor != caller.actor()
                    || existing_reason != reason
                    || payload.previous_generation != expected_generation
                    || payload.audience_digest.as_deref() != Some(expected_audience_digest.as_str())
                    || payload.audience_kind.as_deref() != Some(audience.kind.as_str())
                    || payload.requested_account_ids != requested_account_ids
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: idempotency_key was reused for different intent"
                    )));
                }
                let account_ids = payload.audience_account_ids.clone();
                append_authored(
                    &mut tx,
                    &caller,
                    idempotency_key.clone(),
                    programme_id.clone(),
                    reason.clone(),
                    ControlEventPayload::ProgrammeGenerationPublished(payload.clone()),
                )
                .await?;
                for account in &account_ids {
                    reappend_published_child(
                        &mut tx,
                        &caller,
                        format!("{idempotency_key}/obligation/{account}"),
                        &reason,
                    )
                    .await?;
                }
                tx.commit().await?;
                return Ok(
                    json!({ "programme_id": programme_id, "generation": payload.generation, "account_ids": account_ids, "changed": false, "idempotent_retry": true }),
                );
            }
            let preview = preview_audience_in(&mut tx, TOOL, &programme_id, &audience).await?;
            if preview.generation != expected_generation
                || preview.audience_digest != expected_audience_digest
            {
                return Err(Error::engine(format!(
                    "{TOOL}: audience preview changed; preview again before publishing"
                )));
            }
            if preview.account_ids.is_empty() {
                return Err(Error::engine(format!(
                    "{TOOL}: generation audience must not be empty"
                )));
            }
            let now = now_iso();
            append_authored(
                &mut tx,
                &caller,
                idempotency_key.clone(),
                programme_id.clone(),
                reason.clone(),
                ControlEventPayload::ProgrammeGenerationPublished(
                    ProgrammeGenerationPublishedPayload {
                        previous_generation: preview.generation,
                        generation: preview.next_generation,
                        updated_at: now.clone(),
                        audience_account_ids: preview.account_ids.clone(),
                        audience_digest: Some(preview.audience_digest.clone()),
                        audience_kind: Some(audience.kind.as_str().into()),
                        requested_account_ids,
                    },
                ),
            )
            .await?;
            for account in &preview.pending_to_rebase {
                let old_generation: i64 = sqlx::query_scalar("SELECT generation FROM member_obligations WHERE account_id=? AND programme_id=? AND state='pending'")
                    .bind(account).bind(&programme_id).fetch_one(&mut *tx).await?;
                append_authored(
                    &mut tx,
                    &caller,
                    format!("{idempotency_key}/obligation/{account}"),
                    member_obligation_aggregate_id(account, &programme_id, preview.next_generation),
                    reason.clone(),
                    ControlEventPayload::MemberObligationRebased(MemberObligationRebasedPayload {
                        account_id: account.clone(),
                        programme_id: programme_id.clone(),
                        previous_generation: old_generation,
                        generation: preview.next_generation,
                        created_at: now.clone(),
                        updated_at: now.clone(),
                    }),
                )
                .await?;
            }
            for account in &preview.terminal_or_absent_to_activate {
                append_authored(
                    &mut tx,
                    &caller,
                    format!("{idempotency_key}/obligation/{account}"),
                    member_obligation_aggregate_id(account, &programme_id, preview.next_generation),
                    reason.clone(),
                    ControlEventPayload::MemberObligationActivated(MemberObligationStatePayload {
                        account_id: account.clone(),
                        programme_id: programme_id.clone(),
                        generation: preview.next_generation,
                        state: "pending".into(),
                        created_at: now.clone(),
                        updated_at: now.clone(),
                    }),
                )
                .await?;
            }
            let measures = instructions::validate_all_known_stacks_in(&mut tx, TOOL).await?;
            tx.commit().await?;
            let mut result = preview_json(&preview);
            result["changed"] = json!(true);
            result["stacks"] = json!(measures);
            Ok(result)
        }
        ManageOnboardingArgs::RecordProgress {
            programme_id,
            generation,
            phase,
            mut evidence,
            resume_after,
            artifact_id,
            explicit_member_intent,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            require_progress_evidence(TOOL, &evidence)?;
            if caller.run_key().is_none() {
                return Err(Error::engine(format!(
                    "{TOOL}: record_progress requires Bootstrap's exact run_key"
                )));
            }
            if !matches!(
                phase.as_str(),
                "anchor_established"
                    | "route_selected"
                    | "artifact_previewed"
                    | "artifact_written"
                    | "value_delivered"
                    | "deferred"
            ) {
                return Err(Error::engine(format!(
                    "{TOOL}: phase must be anchor_established, route_selected, artifact_previewed, artifact_written, value_delivered, or deferred"
                )));
            }
            match phase.as_str() {
                "deferred" => {
                    if evidence != json!({"basis":"explicit_member_request"}) {
                        return Err(Error::engine(format!(
                            "{TOOL}: deferred evidence must be exactly {{\"basis\":\"explicit_member_request\"}}"
                        )));
                    }
                    if explicit_member_intent != Some(true) {
                        return Err(Error::engine(format!(
                            "{TOOL}: deferral requires explicit member intent"
                        )));
                    }
                    if let Some(value) = &resume_after {
                        chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
                            Error::engine(format!("{TOOL}: resume_after must be RFC3339"))
                        })?;
                    }
                    if artifact_id.is_some() {
                        return Err(Error::engine(format!(
                            "{TOOL}: deferred progress cannot introduce an artifact"
                        )));
                    }
                }
                "artifact_written" => {
                    if evidence != json!({}) {
                        return Err(Error::engine(format!(
                            "{TOOL}: artifact_written evidence must be an empty object; artifact identity is recorded separately"
                        )));
                    }
                    if explicit_member_intent != Some(true) {
                        return Err(Error::engine(format!(
                            "{TOOL}: artifact_written requires explicit member consent"
                        )));
                    }
                    if resume_after.is_some() || artifact_id.as_deref().is_none_or(str::is_empty) {
                        return Err(Error::engine(format!(
                            "{TOOL}: artifact_written requires artifact_id and cannot set resume_after"
                        )));
                    }
                }
                "artifact_previewed" => {
                    if explicit_member_intent != Some(true) {
                        return Err(Error::engine(format!(
                            "{TOOL}: artifact_previewed requires explicit member consent before the content write"
                        )));
                    }
                    if resume_after.is_some() || artifact_id.is_some() {
                        return Err(Error::engine(format!(
                            "{TOOL}: artifact_previewed cannot set resume_after or artifact_id"
                        )));
                    }
                    if evidence.as_object().is_none_or(|object| {
                        object.len() != 1 || !object.contains_key("content_digest")
                    }) {
                        return Err(Error::engine(format!(
                            "{TOOL}: artifact_previewed evidence may contain only content_digest; preview text is forbidden in immutable control history"
                        )));
                    }
                    let digest = require_sha256(
                        TOOL,
                        "evidence.content_digest",
                        evidence.get("content_digest").and_then(Value::as_str),
                    )?;
                    let object = evidence
                        .as_object_mut()
                        .expect("progress evidence was validated as an object");
                    object.insert("content_digest".into(), json!(digest));
                    object.insert("explicit_member_consent".into(), json!(true));
                }
                "route_selected" => {
                    let route_id = evidence
                        .as_object()
                        .filter(|object| object.len() == 1)
                        .and_then(|object| object.get("route_id"))
                        .and_then(Value::as_str);
                    if route_id
                        .is_none_or(|route| !crate::control::valid_quickstart_route_id(route))
                    {
                        return Err(Error::engine(format!(
                            "{TOOL}: route_selected evidence must be exactly {{\"route_id\":\"practical_workflow|comparative_evaluation|conceptual_explanation\"}}"
                        )));
                    }
                    if resume_after.is_some() || artifact_id.is_some() {
                        return Err(Error::engine(format!(
                            "{TOOL}: route_selected cannot set resume_after or artifact_id"
                        )));
                    }
                }
                "value_delivered" => {
                    if evidence != json!({"basis":"user_confirmed"}) {
                        return Err(Error::engine(format!(
                            "{TOOL}: value_delivered evidence must be exactly {{\"basis\":\"user_confirmed\"}}"
                        )));
                    }
                    if resume_after.is_some() || artifact_id.is_some() {
                        return Err(Error::engine(format!(
                            "{TOOL}: value_delivered cannot set resume_after or artifact_id"
                        )));
                    }
                }
                "anchor_established" => {
                    if evidence != json!({"basis":"user_stated"})
                        && evidence != json!({"basis":"user_confirmed"})
                        && evidence
                            != json!({"basis":"user_confirmed","checkpoint":"reset_invalid_artifact"})
                    {
                        return Err(Error::engine(format!(
                            "{TOOL}: anchor_established evidence basis must be user_stated or user_confirmed"
                        )));
                    }
                    if resume_after.is_some() || artifact_id.is_some() {
                        return Err(Error::engine(format!(
                            "{TOOL}: anchor_established cannot set resume_after or artifact_id"
                        )));
                    }
                }
                _ => unreachable!("progress phase was validated above"),
            }
            require_progress_evidence(TOOL, &evidence)?;

            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let aggregate_id =
                member_obligation_aggregate_id(caller.credential(), &programme_id, generation);
            if let Some((kind, aggregate, actor, prior_reason, raw_payload)) =
                prior_event(&mut tx, &idempotency_key).await?
            {
                let payload: MemberObligationProgressedPayload =
                    serde_json::from_value(raw_payload)?;
                let evidence_matches = if phase == "artifact_previewed" {
                    payload.evidence.as_object().is_some_and(|object| {
                        object.len() == 4
                            && object.get("content_digest") == evidence.get("content_digest")
                            && object.get("explicit_member_consent") == Some(&json!(true))
                            && object
                                .get("content_event_floor_seq")
                                .and_then(Value::as_i64)
                                .is_some_and(|seq| seq >= 0)
                            && object.get("existing_artifact_id").is_some_and(|value| {
                                value.is_null()
                                    || value.as_str().is_some_and(|id| !id.trim().is_empty())
                            })
                    })
                } else if phase == "anchor_established"
                    && evidence == json!({"basis":"user_confirmed"})
                    && payload.evidence
                        == json!({"basis":"user_confirmed","checkpoint":"artifact_written"})
                {
                    true
                } else {
                    payload.evidence == evidence
                };
                if kind != "member_obligation.progressed"
                    || aggregate != aggregate_id
                    || actor != caller.actor()
                    || prior_reason != reason
                    || payload.account_id != caller.credential()
                    || payload.programme_id != programme_id
                    || payload.generation != generation
                    || payload.phase != phase
                    || !evidence_matches
                    || payload.resume_after != resume_after
                    || payload.artifact_id != artifact_id
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: idempotency_key was reused for different intent"
                    )));
                }
                append_authored(
                    &mut tx,
                    &caller,
                    idempotency_key,
                    aggregate_id,
                    reason,
                    ControlEventPayload::MemberObligationProgressed(payload),
                )
                .await?;
                let current = sqlx::query(
                    "SELECT o.state,p.phase,p.artifact_id,p.resume_after,p.selected_route_id
                       FROM member_obligations o
                       LEFT JOIN member_obligation_progress p
                         ON p.account_id=o.account_id AND p.programme_id=o.programme_id
                        AND p.generation=o.generation
                      WHERE o.account_id=? AND o.programme_id=? AND o.generation=?",
                )
                .bind(caller.credential())
                .bind(&programme_id)
                .bind(generation)
                .fetch_one(&mut *tx)
                .await?;
                let current_state: String = current.try_get("state")?;
                let current_phase: Option<String> = current.try_get("phase")?;
                let current_artifact: Option<String> = current.try_get("artifact_id")?;
                let current_resume_after: Option<String> = current.try_get("resume_after")?;
                let selected_route_id: Option<String> = current.try_get("selected_route_id")?;
                tx.commit().await?;
                return Ok(json!({
                    "programme_id": programme_id,
                    "generation": generation,
                    "state": current_state,
                    "progress_state": match current_phase.as_deref() { None => "new", Some("deferred") => "deferred", Some(_) => "in_progress" },
                    "phase": current_phase,
                    "artifact_id": current_artifact,
                    "selected_route_id": selected_route_id,
                    "resume_after": current_resume_after,
                    "changed": false,
                    "idempotent_retry": true,
                }));
            }
            if phase == "artifact_previewed" {
                let content_event_floor_seq: i64 =
                    sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
                        .fetch_one(&mut *tx)
                        .await?;
                let context = sqlx::query(
                    "SELECT c.person_record_id,c.root_record_id
                       FROM member_contexts c
                       JOIN records root ON root.id=c.root_record_id AND root.deleted_at IS NULL
                      WHERE c.account_id=?",
                )
                .bind(caller.credential())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| Error::engine(format!("{TOOL}: member context is unavailable")))?;
                let person_record_id: String = context.try_get("person_record_id")?;
                let root_record_id: String = context.try_get("root_record_id")?;
                let policy_rows = sqlx::query(
                    "SELECT subject_kind,subject_id,effect,capability FROM policy_entries
                      WHERE policy_anchor_id=? ORDER BY subject_kind,subject_id LIMIT 2",
                )
                .bind(&root_record_id)
                .fetch_all(&mut *tx)
                .await?;
                let private_boundary = policy_rows.len() == 1
                    && policy_rows[0].try_get::<String, _>("subject_kind")? == "account"
                    && policy_rows[0].try_get::<String, _>("subject_id")? == caller.credential()
                    && policy_rows[0].try_get::<String, _>("effect")? == "allow"
                    && policy_rows[0].try_get::<String, _>("capability")? == "manage";
                if !private_boundary {
                    return Err(Error::auth(format!(
                        "{TOOL}: My agent context must retain its exact caller-only policy before preview consent can be recorded"
                    )));
                }
                let existing: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
                    "SELECT id,owner_id,policy_anchor_id FROM records
                      WHERE home_id=? AND type='Document' AND kind='note'
                        AND name='Starting context' AND deleted_at IS NULL
                      ORDER BY id LIMIT 2",
                )
                .bind(&root_record_id)
                .fetch_all(&mut *tx)
                .await?;
                if existing.len() > 1
                    || existing.first().is_some_and(|(_, owner, anchor)| {
                        owner.as_deref() != Some(person_record_id.as_str())
                            || anchor.as_deref() != Some(root_record_id.as_str())
                    })
                {
                    return Err(Error::auth(format!(
                        "{TOOL}: resolve conflicting Starting context ownership, policy, or duplicates before previewing"
                    )));
                }
                if let Some((existing_id, _, _)) = existing.first() {
                    let previously_written: Option<String> = sqlx::query_scalar(
                        "SELECT json_extract(payload,'$.artifact_id') FROM control_events
                          WHERE aggregate_kind='member_obligation' AND aggregate_id=?
                            AND type='member_obligation.progressed'
                            AND json_extract(payload,'$.phase')='artifact_written'
                          ORDER BY seq DESC LIMIT 1",
                    )
                    .bind(&aggregate_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    let created_run_key: Option<String> = sqlx::query_scalar(
                        "SELECT run_key FROM content_events
                          WHERE record_id=? AND type='record.created'",
                    )
                    .bind(existing_id)
                    .fetch_one(&mut *tx)
                    .await?;
                    if previously_written.as_deref() != Some(existing_id.as_str())
                        && created_run_key.as_deref() == caller.run_key()
                    {
                        return Err(Error::auth(format!(
                            "{TOOL}: a Starting context created in this run before the exact preview cannot be retroactively consented"
                        )));
                    }
                }
                evidence
                    .as_object_mut()
                    .expect("validated progress evidence")
                    .insert(
                        "content_event_floor_seq".into(),
                        json!(content_event_floor_seq),
                    );
                evidence
                    .as_object_mut()
                    .expect("validated progress evidence")
                    .insert(
                        "existing_artifact_id".into(),
                        existing.first().map_or(Value::Null, |(id, _, _)| json!(id)),
                    );
            }
            let pending: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM member_obligations
                  WHERE account_id=? AND programme_id=? AND generation=? AND state='pending')",
            )
            .bind(caller.credential())
            .bind(&programme_id)
            .bind(generation)
            .fetch_one(&mut *tx)
            .await?;
            if !pending {
                return Err(Error::auth(format!(
                    "{TOOL}: matching pending member obligation required"
                )));
            }
            let previous = sqlx::query(
                "SELECT phase,artifact_id,selected_route_id FROM member_obligation_progress
                  WHERE account_id=? AND programme_id=? AND generation=?",
            )
            .bind(caller.credential())
            .bind(&programme_id)
            .bind(generation)
            .fetch_optional(&mut *tx)
            .await?;
            let previous_phase = previous
                .as_ref()
                .map(|row| row.try_get::<String, _>("phase"))
                .transpose()?;
            let previous_artifact = previous
                .as_ref()
                .map(|row| row.try_get::<Option<String>, _>("artifact_id"))
                .transpose()?
                .flatten();
            let previous_route = previous
                .as_ref()
                .map(|row| row.try_get::<Option<String>, _>("selected_route_id"))
                .transpose()?
                .flatten();
            if evidence.get("checkpoint").and_then(Value::as_str) == Some("reset_invalid_artifact")
                && !(previous_phase.as_deref() == Some("deferred") && previous_artifact.is_some())
            {
                return Err(Error::engine(format!(
                    "{TOOL}: reset_invalid_artifact requires a deferred retained artifact checkpoint"
                )));
            }
            if !crate::control::valid_obligation_progress_transition(
                previous_phase.as_deref(),
                &phase,
            ) {
                return Err(Error::engine(format!(
                    "{TOOL}: invalid progress transition {} -> {phase}",
                    previous_phase.as_deref().unwrap_or("new")
                )));
            }
            if phase == "value_delivered" && previous_route.is_none() {
                return Err(Error::engine(format!(
                    "{TOOL}: value_delivered requires route_selected progress first"
                )));
            }
            if previous_phase.as_deref() == Some("deferred")
                && phase != "deferred"
                && explicit_member_intent != Some(true)
            {
                return Err(Error::engine(format!(
                    "{TOOL}: resuming deferred onboarding requires explicit member intent"
                )));
            }
            if previous_phase.as_deref() == Some("deferred") && phase == "anchor_established" {
                if evidence.get("basis") != Some(&json!("user_confirmed")) {
                    return Err(Error::engine(format!(
                        "{TOOL}: resuming deferred onboarding requires explicit member intent"
                    )));
                }
                if let Some(previous_artifact) = previous_artifact.as_deref() {
                    if evidence.get("checkpoint").and_then(Value::as_str)
                        == Some("reset_invalid_artifact")
                    {
                        // Explicit recovery: the member chose to discard a stale checkpoint.
                    } else if starting_context_is_current_private(
                        &mut tx,
                        &caller,
                        previous_artifact,
                    )
                    .await?
                    {
                        evidence
                            .as_object_mut()
                            .expect("validated anchor evidence")
                            .insert("checkpoint".into(), json!("artifact_written"));
                    } else {
                        return Err(Error::auth(format!(
                            "{TOOL}: the deferred Starting context checkpoint is no longer a live sole private note; retry with evidence {{\"basis\":\"user_confirmed\",\"checkpoint\":\"reset_invalid_artifact\"}} only after the member explicitly chooses a fresh artifact flow"
                        )));
                    }
                } else if evidence.get("checkpoint").is_some() {
                    return Err(Error::engine(format!(
                        "{TOOL}: reset_invalid_artifact is valid only when deferred progress retains an artifact"
                    )));
                }
            }

            if phase == "artifact_written" {
                let artifact_id = artifact_id.as_deref().expect("validated above");
                let prior = sqlx::query(
                    "SELECT phase,evidence,updated_at,updated_run_key FROM member_obligation_progress
                      WHERE account_id=? AND programme_id=? AND generation=?",
                )
                .bind(caller.credential())
                .bind(&programme_id)
                .bind(generation)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| {
                    Error::engine(format!(
                        "{TOOL}: Starting context must be previewed before it is recorded as written"
                    ))
                })?;
                if prior.try_get::<String, _>("phase")? != "artifact_previewed" {
                    return Err(Error::engine(format!(
                        "{TOOL}: Starting context must be the currently previewed artifact"
                    )));
                }
                let preview_evidence: Value =
                    serde_json::from_str(&prior.try_get::<String, _>("evidence")?)?;
                if preview_evidence
                    .get("explicit_member_consent")
                    .and_then(Value::as_bool)
                    != Some(true)
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: Starting context preview does not carry explicit pre-write consent"
                    )));
                }
                let preview_digest = require_sha256(
                    TOOL,
                    "preview evidence content_digest",
                    preview_evidence
                        .get("content_digest")
                        .and_then(Value::as_str),
                )?;
                let preview_content_floor_seq = preview_evidence
                    .get("content_event_floor_seq")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| {
                        Error::engine(format!(
                            "{TOOL}: Starting context preview lacks a content-event watermark"
                        ))
                    })?;
                let preview_existing_artifact_id = preview_evidence
                    .get("existing_artifact_id")
                    .and_then(Value::as_str);
                let context = sqlx::query(
                    "SELECT c.person_record_id,c.root_record_id
                       FROM member_contexts c
                       JOIN records root ON root.id=c.root_record_id AND root.deleted_at IS NULL
                      WHERE c.account_id=?",
                )
                .bind(caller.credential())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| Error::engine(format!("{TOOL}: member context is unavailable")))?;
                let person_record_id: String = context.try_get("person_record_id")?;
                let root_record_id: String = context.try_get("root_record_id")?;
                let policy_rows = sqlx::query(
                    "SELECT subject_kind,subject_id,effect,capability FROM policy_entries
                      WHERE policy_anchor_id=? ORDER BY subject_kind,subject_id LIMIT 2",
                )
                .bind(&root_record_id)
                .fetch_all(&mut *tx)
                .await?;
                let private_boundary = policy_rows.len() == 1
                    && policy_rows[0].try_get::<String, _>("subject_kind")? == "account"
                    && policy_rows[0].try_get::<String, _>("subject_id")? == caller.credential()
                    && policy_rows[0].try_get::<String, _>("effect")? == "allow"
                    && policy_rows[0].try_get::<String, _>("capability")? == "manage";
                if !private_boundary {
                    return Err(Error::auth(format!(
                        "{TOOL}: My agent context must retain its exact caller-only policy before a Starting context can be recorded as private"
                    )));
                }
                let live_starting_contexts: Vec<String> = sqlx::query_scalar(
                    "SELECT id FROM records
                      WHERE home_id=? AND type='Document' AND kind='note'
                        AND name='Starting context' AND deleted_at IS NULL
                      ORDER BY id LIMIT 2",
                )
                .bind(&root_record_id)
                .fetch_all(&mut *tx)
                .await?;
                if live_starting_contexts.len() != 1
                    || live_starting_contexts.first().map(String::as_str) != Some(artifact_id)
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: artifact_id must be the sole live Starting context note directly under My agent context"
                    )));
                }
                let capability = authorization::effective_capability_on(
                    &mut tx,
                    Principal::bound(caller.credential(), true),
                    artifact_id,
                )
                .await
                .map_err(|_| {
                    Error::auth(format!(
                        "{TOOL}: artifact_id must be a caller-managed private Starting context"
                    ))
                })?;
                if !capability.allows(Capability::Manage) {
                    return Err(Error::auth(format!(
                        "{TOOL}: artifact_id must be a caller-managed private Starting context"
                    )));
                }
                let artifact = sqlx::query(
                    "SELECT type,kind,name,body,home_id,owner_id,policy_anchor_id,deleted_at FROM records WHERE id=?",
                )
                .bind(artifact_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| Error::engine(format!("{TOOL}: artifact_id does not exist")))?;
                let body: String =
                    artifact
                        .try_get::<Option<String>, _>("body")?
                        .ok_or_else(|| {
                            Error::engine(format!("{TOOL}: Starting context body is required"))
                        })?;
                validate_starting_context_body(TOOL, &body)?;
                let exact_contract = artifact.try_get::<String, _>("type")? == "Document"
                    && artifact.try_get::<Option<String>, _>("kind")?.as_deref() == Some("note")
                    && artifact.try_get::<String, _>("name")? == "Starting context"
                    && artifact.try_get::<Option<String>, _>("home_id")?.as_deref()
                        == Some(root_record_id.as_str())
                    && artifact
                        .try_get::<Option<String>, _>("owner_id")?
                        .as_deref()
                        == Some(person_record_id.as_str())
                    && artifact
                        .try_get::<Option<String>, _>("policy_anchor_id")?
                        .as_deref()
                        == Some(root_record_id.as_str())
                    && artifact
                        .try_get::<Option<String>, _>("deleted_at")?
                        .is_none();
                if !exact_contract {
                    return Err(Error::auth(format!(
                        "{TOOL}: artifact_id must be the caller-owned live Starting context Document/note directly under My agent context"
                    )));
                }
                let actual_digest = hex::encode(Sha256::digest(body.as_bytes()));
                if actual_digest != preview_digest {
                    return Err(Error::engine(format!(
                        "{TOOL}: Starting context content differs from the preview"
                    )));
                }
                let authored_body = sqlx::query(
                    "SELECT seq,actor,run_key,payload FROM content_events
                      WHERE record_id=? AND type IN ('record.created','record.updated')
                        AND json_type(payload,'$.body') IS NOT NULL
                      ORDER BY seq DESC LIMIT 1",
                )
                .bind(artifact_id)
                .fetch_one(&mut *tx)
                .await?;
                let created_seq: i64 = sqlx::query_scalar(
                    "SELECT seq FROM content_events WHERE record_id=? AND type='record.created'",
                )
                .bind(artifact_id)
                .fetch_one(&mut *tx)
                .await?;
                let preview_run_key: Option<String> = prior.try_get("updated_run_key")?;
                let body_actor: Option<String> = authored_body.try_get("actor")?;
                let body_run_key: Option<String> = authored_body.try_get("run_key")?;
                let body_event_seq: i64 = authored_body.try_get("seq")?;
                let body_payload: Value =
                    serde_json::from_str(&authored_body.try_get::<String, _>("payload")?)?;
                let event_body = body_payload.get("body").and_then(Value::as_str);
                let artifact_origin_invalid = match preview_existing_artifact_id {
                    Some(existing) => existing != artifact_id,
                    None => created_seq <= preview_content_floor_seq,
                };
                if body_actor.as_deref() != Some(caller.actor())
                    || body_event_seq <= preview_content_floor_seq
                    || artifact_origin_invalid
                    || preview_run_key.as_deref() != caller.run_key()
                    || body_run_key.as_deref() != caller.run_key()
                    || event_body != Some(body.as_str())
                {
                    return Err(Error::auth(format!(
                        "{TOOL}: the current Starting context body must be written by this caller after the consented preview in the same run"
                    )));
                }
            }

            let updated_at = event_time(&mut tx, &idempotency_key, "updated_at").await?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                aggregate_id,
                reason,
                ControlEventPayload::MemberObligationProgressed(
                    MemberObligationProgressedPayload {
                        account_id: caller.credential().into(),
                        programme_id: programme_id.clone(),
                        generation,
                        phase: phase.clone(),
                        updated_at,
                        evidence,
                        resume_after: resume_after.clone(),
                        artifact_id: artifact_id.clone(),
                    },
                ),
            )
            .await?;
            let current = sqlx::query(
                "SELECT phase,artifact_id,resume_after,selected_route_id FROM member_obligation_progress
                  WHERE account_id=? AND programme_id=? AND generation=?",
            )
            .bind(caller.credential())
            .bind(&programme_id)
            .bind(generation)
            .fetch_one(&mut *tx)
            .await?;
            let current_phase: String = current.try_get("phase")?;
            let current_artifact_id: Option<String> = current.try_get("artifact_id")?;
            let current_resume_after: Option<String> = current.try_get("resume_after")?;
            let selected_route_id: Option<String> = current.try_get("selected_route_id")?;
            tx.commit().await?;
            Ok(json!({
                "programme_id": programme_id,
                "generation": generation,
                "state": "pending",
                "progress_state": if current_phase == "deferred" { "deferred" } else { "in_progress" },
                "phase": current_phase,
                "artifact_id": current_artifact_id,
                "selected_route_id": selected_route_id,
                "resume_after": current_resume_after,
                "changed": true,
            }))
        }
        ManageOnboardingArgs::ResolveObligation {
            programme_id,
            generation,
            resolution,
            evidence,
            explicit_member_intent,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            if !matches!(resolution.as_str(), "completed" | "declined") {
                return Err(Error::engine(format!(
                    "{TOOL}: resolution must be completed or declined"
                )));
            }
            if evidence.is_null() {
                return Err(Error::engine(format!("{TOOL}: evidence is required")));
            }
            if resolution == "declined" && explicit_member_intent != Some(true) {
                return Err(Error::engine(format!(
                    "{TOOL}: decline requires explicit member intent"
                )));
            }
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let aggregate_id =
                member_obligation_aggregate_id(caller.credential(), &programme_id, generation);
            if let Some((kind, aggregate, actor, prior_reason, raw_payload)) =
                prior_event(&mut tx, &idempotency_key).await?
            {
                let payload: MemberObligationResolvedPayload = serde_json::from_value(raw_payload)?;
                if kind != "member_obligation.resolved"
                    || aggregate != aggregate_id
                    || actor != caller.actor()
                    || prior_reason != reason
                    || payload.account_id != caller.credential()
                    || payload.programme_id != programme_id
                    || payload.generation != generation
                    || payload.state != resolution
                    || payload.evidence != evidence
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: idempotency_key was reused for different intent"
                    )));
                }
                append_authored(
                    &mut tx,
                    &caller,
                    idempotency_key,
                    aggregate_id,
                    reason,
                    ControlEventPayload::MemberObligationResolved(payload),
                )
                .await?;
                tx.commit().await?;
                return Ok(
                    json!({ "programme_id": programme_id, "generation": generation, "state": resolution, "changed": false, "idempotent_retry": true }),
                );
            }
            let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM member_obligations WHERE account_id=? AND programme_id=? AND generation=? AND state='pending')")
                .bind(caller.credential()).bind(&programme_id).bind(generation).fetch_one(&mut *tx).await?;
            if !pending {
                return Err(Error::auth(format!(
                    "{TOOL}: matching pending member obligation required"
                )));
            }
            if resolution == "completed" {
                let criteria: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM onboarding_programme_sources WHERE programme_id=? AND source_role='completion_criteria')")
                    .bind(&programme_id).fetch_one(&mut *tx).await?;
                if !criteria {
                    return Err(Error::engine(format!(
                        "{TOOL}: completion requires declared completion criteria"
                    )));
                }
                instructions::validate_account_stack_in(&mut tx, TOOL, Some(caller.credential()))
                    .await?;
            }
            let updated_at = event_time(&mut tx, &idempotency_key, "updated_at").await?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                aggregate_id,
                reason,
                ControlEventPayload::MemberObligationResolved(MemberObligationResolvedPayload {
                    account_id: caller.credential().into(),
                    programme_id: programme_id.clone(),
                    generation,
                    state: resolution.clone(),
                    updated_at,
                    evidence,
                }),
            )
            .await?;
            tx.commit().await?;
            Ok(
                json!({ "programme_id": programme_id, "generation": generation, "state": resolution, "changed": true }),
            )
        }
        ManageOnboardingArgs::ReopenObligation {
            programme_id,
            generation,
            evidence,
            explicit_member_intent,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason(TOOL, &reason)?;
            require_idempotency(TOOL, &idempotency_key)?;
            if !explicit_member_intent || evidence.is_null() {
                return Err(Error::engine(format!(
                    "{TOOL}: reopening requires explicit member intent and evidence"
                )));
            }
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let aggregate_id =
                member_obligation_aggregate_id(caller.credential(), &programme_id, generation);
            if let Some((kind, aggregate, actor, prior_reason, raw_payload)) =
                prior_event(&mut tx, &idempotency_key).await?
            {
                let payload: MemberObligationReopenedPayload = serde_json::from_value(raw_payload)?;
                if kind != "member_obligation.reopened"
                    || aggregate != aggregate_id
                    || actor != caller.actor()
                    || prior_reason != reason
                    || payload.account_id != caller.credential()
                    || payload.programme_id != programme_id
                    || payload.generation != generation
                    || payload.evidence != evidence
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: idempotency_key was reused for different intent"
                    )));
                }
                append_authored(
                    &mut tx,
                    &caller,
                    idempotency_key,
                    aggregate_id,
                    reason,
                    ControlEventPayload::MemberObligationReopened(payload),
                )
                .await?;
                let measure = instructions::validate_account_stack_in(
                    &mut tx,
                    TOOL,
                    Some(caller.credential()),
                )
                .await?;
                tx.commit().await?;
                return Ok(
                    json!({ "programme_id": programme_id, "generation": generation, "state": "pending", "changed": false, "idempotent_retry": true, "stack": measure }),
                );
            }
            let previous_state: String = sqlx::query_scalar("SELECT state FROM member_obligations WHERE account_id=? AND programme_id=? AND generation=? AND state IN ('completed','declined')")
                .bind(caller.credential()).bind(&programme_id).bind(generation).fetch_optional(&mut *tx).await?
                .ok_or_else(|| Error::auth(format!("{TOOL}: matching terminal member obligation required")))?;
            let updated_at = event_time(&mut tx, &idempotency_key, "updated_at").await?;
            append_authored(
                &mut tx,
                &caller,
                idempotency_key,
                aggregate_id,
                reason,
                ControlEventPayload::MemberObligationReopened(MemberObligationReopenedPayload {
                    account_id: caller.credential().into(),
                    programme_id: programme_id.clone(),
                    generation,
                    previous_state,
                    updated_at,
                    evidence,
                }),
            )
            .await?;
            let measure: StackMeasure =
                instructions::validate_account_stack_in(&mut tx, TOOL, Some(caller.credential()))
                    .await?;
            tx.commit().await?;
            Ok(
                json!({ "programme_id": programme_id, "generation": generation, "state": "pending", "changed": true, "stack": measure }),
            )
        }
    }
}

pub fn register_instruction_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageInstructions,
        "Read and configure portable workspace/member standing instruction bindings, and inspect or safely update seeded defaults. Member scope is always the authenticated caller; workspace scope is database-owner-only.",
        json!({
            "type":"object",
            "properties":{
                "action":{"type":"string","enum":["list","create_binding","retarget_binding","reorder_binding","enable_binding","disable_binding","remove_binding","compare_seeded_default","apply_seeded_default","reset_seeded_default"]},
                "scope":{"type":"string","enum":["workspace","member"]}, "source_record_id":{"type":"string"}, "binding_id":{"type":"string"},
                "position":{"type":"integer","minimum":0}, "enabled":{"type":"boolean"}, "idempotency_key":{"type":"string","minLength":1},
                "expected_body_digest":{"type":"string","pattern":"^[0-9a-fA-F]{64}$"}, "confirm":{"type":"boolean"},
                "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
            }, "required":["action"], "additionalProperties":false
        }), manage_instructions)?;
    registry.register(
        ToolKind::ManageOnboarding,
        "Configure portable onboarding programmes and sources; preview/publish generations; record bounded non-terminal progress; or explicitly resolve/reopen only the authenticated member's own obligation. route_selected stores one stable QuickStart route ID and value_delivered requires user-confirmed value. artifact_previewed is the pre-write consent gate: caller evidence contains only the exact draft's SHA-256, while the server adds consent proof plus bounded content-event and existing-note snapshot metadata; preview text is forbidden in immutable evidence. artifact_written validates that the current caller authored that exact Document/note under an unchanged caller-only My agent context policy after the preview in the same run. Bootstrap delivery itself never changes state.",
        json!({
            "type":"object",
            "properties":{
                "action":{"type":"string","enum":["list_programmes","create_programme","configure_programme","add_source","change_source","reorder_source","remove_source","preview_generation","publish_generation","record_progress","resolve_obligation","reopen_obligation"]},
                "programme_id":{"type":"string"}, "trigger_key":{"type":"string","enum":["on_owner_first_run","on_member_joined"]},
                "position":{"type":"integer","minimum":0}, "enabled":{"type":"boolean"}, "source_record_id":{"type":"string"},
                "source_role":{"type":"string","enum":["guidance","completion_criteria"]},
                "audience":{"type":"object","properties":{"kind":{"type":"string","enum":["all","terminal","pending","accounts"]},"account_ids":{"type":"array","items":{"type":"string"}}},"required":["kind"],"additionalProperties":false},
                "expected_generation":{"type":"integer","minimum":1}, "expected_audience_digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
                "generation":{"type":"integer","minimum":1}, "resolution":{"type":"string","enum":["completed","declined"]},
                "phase":{"type":"string","enum":["anchor_established","route_selected","artifact_previewed","artifact_written","value_delivered","deferred"]},
                "resume_after":{"type":"string","format":"date-time"}, "artifact_id":{"type":"string"},
                "evidence":{"type":"object","maxProperties":2,"description":"Caller-supplied audit metadata. anchor_established: {basis:user_stated|user_confirmed}; route_selected: exactly {route_id:practical_workflow|comparative_evaluation|conceptual_explanation}; only explicit recovery from a deferred invalid artifact may add checkpoint:reset_invalid_artifact (the server adds checkpoint:artifact_written when safely restoring a valid checkpoint). artifact_previewed: exactly {content_digest:<sha256>} (the server adds consent and bounded causality/snapshot fields; preview/body/context text is forbidden); artifact_written: {}; value_delivered: exactly {basis:user_confirmed}; deferred: exactly {basis:explicit_member_request}."}, "explicit_member_intent":{"type":"boolean"}, "idempotency_key":{"type":"string","minLength":1},
                "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
            }, "required":["action"], "additionalProperties":false
        }), manage_onboarding)?;
    Ok(())
}
