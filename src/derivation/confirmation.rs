//! Relational artifact roles and explicit shipping confirmation.
//!
//! Recognition is never inferred from a record title, kind, recipe, or timing.
//! An ordinary `Document kind:note` becomes a change-summary artifact only by
//! an active role assignment. Execution/publication remains separate from the
//! explicit, authorized confirmation recorded here.

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use crate::authorization::{Capability, Principal};
use crate::db::{begin_write, Db};
use crate::error::{Error, Result};

use super::bindings::{validate_target, DerivationTarget};
use super::events::{DerivationEventPayload, DerivationEventRow, NewDerivationEvent};
use super::persistence::append_derivation_event_in;

pub const CHANGE_SUMMARY_ROLE: &str = "change_summary";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRoleAssigned {
    pub assignment_id: String,
    pub target: DerivationTarget,
    pub role: String,
    /// Exact prior role-head fence. `None` is valid only when this target/role
    /// has never had an assignment; re-assignment after retirement must name
    /// the retirement event so a stale observer cannot cross an ABA cycle.
    pub expected_role_head_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRoleRetired {
    pub retirement_id: String,
    pub assignment_id: String,
    pub target: DerivationTarget,
    pub role: String,
    pub expected_assignment_event_id: String,
    pub expected_confirmation_head_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionConfirmed {
    pub confirmation_id: String,
    pub assignment_id: String,
    pub target: DerivationTarget,
    pub role: String,
    pub series_id: String,
    pub revision_id: String,
    pub publication_id: String,
    pub binding_id: String,
    pub expected_generation: i64,
    pub expected_target_version: i64,
    pub expected_input_manifest_sha256: String,
    pub expected_output_sha256: String,
    pub expected_confirmation_head_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationRetracted {
    pub retraction_id: String,
    pub confirmation_id: String,
    pub assignment_id: String,
    pub target: DerivationTarget,
    pub expected_confirmation_head_event_id: String,
}

fn nonblank(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::engine(format!("derivation {label} cannot be empty")))
    } else {
        Ok(())
    }
}

fn sha256(label: &str, value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "derivation {label} must be lowercase sha256"
        )))
    }
}

fn require_actor(principal: Principal<'_>, actor: &str) -> Result<()> {
    if principal.account_id == Some(actor) {
        Ok(())
    } else {
        Err(Error::engine(
            "derivation actor must match the authorized account principal",
        ))
    }
}

async fn require_note(conn: &mut SqliteConnection, target: &DerivationTarget) -> Result<()> {
    validate_target(target)?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records
          WHERE id=? AND type='Document' AND kind='note' AND deleted_at IS NULL)",
    )
    .bind(&target.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if live {
        Ok(())
    } else {
        Err(Error::engine(
            "derivation artifact role requires a live Document kind:note carrier",
        ))
    }
}

pub(super) async fn project_role_assigned(
    conn: &mut SqliteConnection,
    event: &DerivationEventRow,
    value: ArtifactRoleAssigned,
) -> Result<()> {
    nonblank("artifact role", &value.role)?;
    nonblank("role assignment id", &value.assignment_id)?;
    if value.assignment_id != event.aggregate_id {
        return Err(Error::engine(
            "derivation role assignment payload id does not match aggregate",
        ));
    }
    let head: Option<(Option<String>, String)> = sqlx::query_as(
        "SELECT active_assignment_id,head_event_id FROM derivation_artifact_role_heads
          WHERE target_kind=? AND target_record_id=? AND target_slot=? AND role=?",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(&value.role)
    .fetch_optional(&mut *conn)
    .await?;
    if head
        .as_ref()
        .and_then(|(active, _)| active.as_ref())
        .is_some()
    {
        return Err(Error::engine("derivation artifact role is already active"));
    }
    let actual_head_event_id = head.map(|(_, event_id)| event_id);
    if actual_head_event_id != value.expected_role_head_event_id {
        return Err(Error::engine(
            "derivation artifact role assignment lost its role-head CAS",
        ));
    }
    sqlx::query(
        "INSERT INTO derivation_artifact_role_assignments
         (assignment_id,target_kind,target_record_id,target_slot,role,
          assigned_event_id,assigned_event_seq,assigned_at)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(&value.assignment_id)
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(&value.role)
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO derivation_artifact_role_heads
         (target_kind,target_record_id,target_slot,role,active_assignment_id,head_event_id,head_event_seq)
         VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(target_kind,target_record_id,target_slot,role) DO UPDATE SET
           active_assignment_id=excluded.active_assignment_id,
           head_event_id=excluded.head_event_id,head_event_seq=excluded.head_event_seq",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(&value.role)
    .bind(&value.assignment_id)
    .bind(&event.id)
    .bind(event.seq)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) async fn project_role_retired(
    conn: &mut SqliteConnection,
    event: &DerivationEventRow,
    value: ArtifactRoleRetired,
) -> Result<()> {
    for (label, item) in [
        ("role retirement id", value.retirement_id.as_str()),
        ("role assignment id", value.assignment_id.as_str()),
        ("artifact role", value.role.as_str()),
        (
            "expected assignment event",
            value.expected_assignment_event_id.as_str(),
        ),
    ] {
        nonblank(label, item)?;
    }
    if value.assignment_id != event.aggregate_id {
        return Err(Error::engine(
            "derivation role retirement aggregate does not match assignment",
        ));
    }
    let head: Option<(Option<String>, String)> = sqlx::query_as(
        "SELECT active_assignment_id,head_event_id FROM derivation_artifact_role_heads
          WHERE target_kind=? AND target_record_id=? AND target_slot=? AND role=?",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(&value.role)
    .fetch_optional(&mut *conn)
    .await?;
    if head
        != Some((
            Some(value.assignment_id.clone()),
            value.expected_assignment_event_id.clone(),
        ))
    {
        return Err(Error::engine(
            "derivation role retirement lost its assignment CAS",
        ));
    }
    let confirmation_head: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT confirmation_id,head_event_id FROM derivation_confirmation_heads WHERE assignment_id=?",
    )
    .bind(&value.assignment_id)
    .fetch_optional(&mut *conn)
    .await?;
    let actual_head_event = confirmation_head
        .as_ref()
        .and_then(|(_, head_event_id)| head_event_id.clone());
    if actual_head_event != value.expected_confirmation_head_event_id {
        return Err(Error::engine(
            "derivation role retirement lost its confirmation-head CAS",
        ));
    }
    if confirmation_head
        .as_ref()
        .and_then(|(confirmation_id, _)| confirmation_id.as_ref())
        .is_some()
    {
        return Err(Error::engine(
            "active confirmation blocks derivation artifact role retirement",
        ));
    }
    sqlx::query(
        "INSERT INTO derivation_artifact_role_retirements
         (retirement_id,assignment_id,retired_event_id,retired_event_seq,retired_at)
         VALUES(?,?,?,?,?)",
    )
    .bind(&value.retirement_id)
    .bind(&value.assignment_id)
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE derivation_artifact_role_heads
            SET active_assignment_id=NULL,head_event_id=?,head_event_seq=?
          WHERE target_kind=? AND target_record_id=? AND target_slot=? AND role=?",
    )
    .bind(&event.id)
    .bind(event.seq)
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(&value.role)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) async fn project_revision_confirmed(
    conn: &mut SqliteConnection,
    event: &DerivationEventRow,
    value: RevisionConfirmed,
) -> Result<()> {
    for (label, item) in [
        ("confirmation id", value.confirmation_id.as_str()),
        ("role assignment id", value.assignment_id.as_str()),
        ("artifact role", value.role.as_str()),
        ("series id", value.series_id.as_str()),
        ("revision id", value.revision_id.as_str()),
        ("publication id", value.publication_id.as_str()),
        ("binding id", value.binding_id.as_str()),
    ] {
        nonblank(label, item)?;
    }
    sha256(
        "input manifest digest",
        &value.expected_input_manifest_sha256,
    )?;
    sha256("output digest", &value.expected_output_sha256)?;
    if value.confirmation_id != event.aggregate_id {
        return Err(Error::engine(
            "derivation confirmation payload id does not match aggregate",
        ));
    }
    let role_head: Option<Option<String>> = sqlx::query_scalar(
        "SELECT active_assignment_id FROM derivation_artifact_role_heads
          WHERE target_kind=? AND target_record_id=? AND target_slot=? AND role=?",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(&value.role)
    .fetch_optional(&mut *conn)
    .await?;
    if role_head.flatten().as_deref() != Some(value.assignment_id.as_str()) {
        return Err(Error::engine(
            "derivation confirmation role assignment is not active",
        ));
    }
    let head_event: Option<Option<String>> = sqlx::query_scalar(
        "SELECT head_event_id FROM derivation_confirmation_heads WHERE assignment_id=?",
    )
    .bind(&value.assignment_id)
    .fetch_optional(&mut *conn)
    .await?;
    if head_event.flatten() != value.expected_confirmation_head_event_id {
        return Err(Error::engine(
            "derivation confirmation lost its confirmation-head CAS",
        ));
    }
    let publication: Option<(String, i64, i64, String, String, String, String)> = sqlx::query_as(
        "SELECT b.series_id,p.generation,p.target_version,p.revision_id,p.binding_id,
                p.output_sha256,r.input_manifest_sha256
           FROM derivation_target_publications p
           JOIN derivation_target_bindings b ON b.binding_id=p.binding_id
           JOIN derivation_revisions r ON r.id=p.revision_id
          WHERE p.publication_id=? AND b.target_kind=? AND b.target_record_id=? AND b.target_slot=?",
    )
    .bind(&value.publication_id)
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .fetch_optional(&mut *conn)
    .await?;
    if publication
        != Some((
            value.series_id.clone(),
            value.expected_generation,
            value.expected_target_version,
            value.revision_id.clone(),
            value.binding_id.clone(),
            value.expected_output_sha256.clone(),
            value.expected_input_manifest_sha256.clone(),
        ))
    {
        return Err(Error::engine(
            "derivation confirmation lost its series/revision/publication/binding/input/output CAS",
        ));
    }
    let target_head: Option<(i64, i64, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT generation,target_version,active_binding_id,selected_publication_id
           FROM derivation_target_heads
          WHERE target_kind=? AND target_record_id=? AND target_slot=?",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .fetch_optional(&mut *conn)
    .await?;
    if target_head
        != Some((
            value.expected_generation,
            value.expected_target_version,
            Some(value.binding_id.clone()),
            Some(value.publication_id.clone()),
        ))
    {
        return Err(Error::engine(
            "derivation confirmation lost its target-head CAS",
        ));
    }
    sqlx::query(
        "INSERT INTO derivation_revision_confirmations
         (confirmation_id,assignment_id,series_id,revision_id,publication_id,binding_id,
          generation,target_version,input_manifest_sha256,output_sha256,
          predecessor_head_event_id,confirmed_event_id,confirmed_event_seq,confirmed_at,confirmed_by)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&value.confirmation_id)
    .bind(&value.assignment_id)
    .bind(&value.series_id)
    .bind(&value.revision_id)
    .bind(&value.publication_id)
    .bind(&value.binding_id)
    .bind(value.expected_generation)
    .bind(value.expected_target_version)
    .bind(&value.expected_input_manifest_sha256)
    .bind(&value.expected_output_sha256)
    .bind(&value.expected_confirmation_head_event_id)
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .bind(&event.actor)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO derivation_confirmation_heads
         (assignment_id,confirmation_id,head_event_id,head_event_seq)
         VALUES(?,?,?,?)
         ON CONFLICT(assignment_id) DO UPDATE SET
           confirmation_id=excluded.confirmation_id,head_event_id=excluded.head_event_id,
           head_event_seq=excluded.head_event_seq",
    )
    .bind(&value.assignment_id)
    .bind(&value.confirmation_id)
    .bind(&event.id)
    .bind(event.seq)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) async fn project_confirmation_retracted(
    conn: &mut SqliteConnection,
    event: &DerivationEventRow,
    value: ConfirmationRetracted,
) -> Result<()> {
    for (label, item) in [
        ("retraction id", value.retraction_id.as_str()),
        ("confirmation id", value.confirmation_id.as_str()),
        ("role assignment id", value.assignment_id.as_str()),
        (
            "expected confirmation head event",
            value.expected_confirmation_head_event_id.as_str(),
        ),
    ] {
        nonblank(label, item)?;
    }
    if value.confirmation_id != event.aggregate_id {
        return Err(Error::engine(
            "derivation retraction aggregate does not match confirmation",
        ));
    }
    let target_matches: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM derivation_artifact_role_assignments a
             WHERE a.assignment_id=? AND a.target_kind=? AND a.target_record_id=? AND a.target_slot=?)",
    )
    .bind(&value.assignment_id)
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .fetch_one(&mut *conn)
    .await?;
    if !target_matches {
        return Err(Error::engine(
            "derivation retraction target does not match role",
        ));
    }
    let head: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT confirmation_id,head_event_id FROM derivation_confirmation_heads
          WHERE assignment_id=?",
    )
    .bind(&value.assignment_id)
    .fetch_optional(&mut *conn)
    .await?;
    if head
        != Some((
            Some(value.confirmation_id.clone()),
            Some(value.expected_confirmation_head_event_id.clone()),
        ))
    {
        return Err(Error::engine(
            "derivation retraction lost its confirmation-head CAS",
        ));
    }
    let predecessor_head_event_id: Option<String> = sqlx::query_scalar(
        "SELECT predecessor_head_event_id FROM derivation_revision_confirmations
          WHERE confirmation_id=? AND assignment_id=?",
    )
    .bind(&value.confirmation_id)
    .bind(&value.assignment_id)
    .fetch_one(&mut *conn)
    .await?;
    let restored_confirmation_id: Option<String> =
        if let Some(predecessor) = predecessor_head_event_id.as_deref() {
            sqlx::query_scalar(
                "SELECT confirmation_id FROM derivation_revision_confirmations
                  WHERE assignment_id=? AND confirmed_event_id=?",
            )
            .bind(&value.assignment_id)
            .bind(predecessor)
            .fetch_optional(&mut *conn)
            .await?
        } else {
            None
        };
    sqlx::query(
        "INSERT INTO derivation_confirmation_retractions
         (retraction_id,confirmation_id,retracted_event_id,retracted_event_seq,retracted_at,retracted_by)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(&value.retraction_id)
    .bind(&value.confirmation_id)
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .bind(&event.actor)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE derivation_confirmation_heads
            SET confirmation_id=?,head_event_id=?,head_event_seq=?
          WHERE assignment_id=?",
    )
    .bind(restored_confirmation_id)
    .bind(&event.id)
    .bind(event.seq)
    .bind(&value.assignment_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn append_authorized(
    db: &Db,
    principal: Principal<'_>,
    idempotency_key: String,
    actor: String,
    run_key: Option<String>,
    reason: String,
    target: &DerivationTarget,
    capability: Capability,
    payload: DerivationEventPayload,
) -> Result<DerivationEventRow> {
    let mut tx = begin_write(db.write_pool()).await?;
    let event = append_authorized_in(
        &mut tx,
        principal,
        idempotency_key,
        actor,
        run_key,
        reason,
        target,
        capability,
        payload,
    )
    .await?;
    tx.commit().await?;
    Ok(event)
}

#[allow(clippy::too_many_arguments)]
async fn append_authorized_in(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    idempotency_key: String,
    actor: String,
    run_key: Option<String>,
    reason: String,
    target: &DerivationTarget,
    capability: Capability,
    payload: DerivationEventPayload,
) -> Result<DerivationEventRow> {
    require_actor(principal, &actor)?;
    crate::authorization::require_capability_on(tx, principal, &target.record_id, capability)
        .await?;
    // Content-tier carrier shape is a command precondition, checked under the
    // same writer lock as authorization and append. The derivation projector
    // remains a pure fold of the derivation log and can replay without
    // fabricating content records.
    require_note(tx, target).await?;
    let event = append_derivation_event_in(
        tx,
        NewDerivationEvent::authored(idempotency_key, actor, run_key, reason, payload)?,
    )
    .await?;
    Ok(event)
}

pub(crate) async fn confirm_revision_in(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    idempotency_key: String,
    actor: String,
    run_key: Option<String>,
    reason: String,
    confirmation: RevisionConfirmed,
) -> Result<DerivationEventRow> {
    let target = confirmation.target.clone();
    append_authorized_in(
        tx,
        principal,
        idempotency_key,
        actor,
        run_key,
        reason,
        &target,
        Capability::Edit,
        DerivationEventPayload::RevisionConfirmed(confirmation),
    )
    .await
}

pub(crate) async fn retract_confirmation_in(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    idempotency_key: String,
    actor: String,
    run_key: Option<String>,
    reason: String,
    retraction: ConfirmationRetracted,
) -> Result<DerivationEventRow> {
    let target = retraction.target.clone();
    append_authorized_in(
        tx,
        principal,
        idempotency_key,
        actor,
        run_key,
        reason,
        &target,
        Capability::Edit,
        DerivationEventPayload::ConfirmationRetracted(retraction),
    )
    .await
}

pub async fn assign_artifact_role(
    db: &Db,
    principal: Principal<'_>,
    idempotency_key: impl Into<String>,
    actor: impl Into<String>,
    run_key: Option<String>,
    reason: impl Into<String>,
    assignment: ArtifactRoleAssigned,
) -> Result<DerivationEventRow> {
    let target = assignment.target.clone();
    append_authorized(
        db,
        principal,
        idempotency_key.into(),
        actor.into(),
        run_key,
        reason.into(),
        &target,
        Capability::Manage,
        DerivationEventPayload::ArtifactRoleAssigned(assignment),
    )
    .await
}

pub async fn retire_artifact_role(
    db: &Db,
    principal: Principal<'_>,
    idempotency_key: impl Into<String>,
    actor: impl Into<String>,
    run_key: Option<String>,
    reason: impl Into<String>,
    retirement: ArtifactRoleRetired,
) -> Result<DerivationEventRow> {
    let target = retirement.target.clone();
    append_authorized(
        db,
        principal,
        idempotency_key.into(),
        actor.into(),
        run_key,
        reason.into(),
        &target,
        Capability::Manage,
        DerivationEventPayload::ArtifactRoleRetired(retirement),
    )
    .await
}

pub async fn confirm_revision(
    db: &Db,
    principal: Principal<'_>,
    idempotency_key: impl Into<String>,
    actor: impl Into<String>,
    run_key: Option<String>,
    reason: impl Into<String>,
    confirmation: RevisionConfirmed,
) -> Result<DerivationEventRow> {
    let target = confirmation.target.clone();
    append_authorized(
        db,
        principal,
        idempotency_key.into(),
        actor.into(),
        run_key,
        reason.into(),
        &target,
        Capability::Edit,
        DerivationEventPayload::RevisionConfirmed(confirmation),
    )
    .await
}

pub async fn retract_confirmation(
    db: &Db,
    principal: Principal<'_>,
    idempotency_key: impl Into<String>,
    actor: impl Into<String>,
    run_key: Option<String>,
    reason: impl Into<String>,
    retraction: ConfirmationRetracted,
) -> Result<DerivationEventRow> {
    let target = retraction.target.clone();
    append_authorized(
        db,
        principal,
        idempotency_key.into(),
        actor.into(),
        run_key,
        reason.into(),
        &target,
        Capability::Edit,
        DerivationEventPayload::ConfirmationRetracted(retraction),
    )
    .await
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRunInspection {
    pub ordinal: i64,
    pub input_role: String,
    pub input_kind: String,
    pub portable_id: Option<String>,
    pub sha256: Option<String>,
    pub run_key: Option<String>,
    pub redacted: bool,
}

pub const MAX_CONFIRMED_ARTIFACT_PAGE_LIMIT: usize = 100;
pub const MAX_SOURCE_RUN_PAGE_LIMIT: usize = 100;
const MAX_APPLICABILITY_SCAN: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputContractSelector {
    pub id: String,
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedArtifactCursor {
    /// Opaque continuation token. Its encoding is an engine detail and never
    /// contains artifact, assignment, or confirmation identifiers.
    pub token: String,
}

fn confirmed_artifact_cursor(head_event_seq: i64) -> ConfirmedArtifactCursor {
    ConfirmedArtifactCursor {
        token: format!("native-confirmed-v1.{head_event_seq:016x}"),
    }
}

fn confirmed_artifact_cursor_seq(cursor: &ConfirmedArtifactCursor) -> Result<i64> {
    let value = cursor
        .token
        .strip_prefix("native-confirmed-v1.")
        .filter(|value| value.len() == 16)
        .and_then(|value| i64::from_str_radix(value, 16).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| Error::engine("derivation confirmed artifact cursor is invalid"))?;
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRunCursor {
    pub ordinal: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevisionRecognitionBasis {
    pub series_id: String,
    pub revision_id: String,
    pub definition_sha256: String,
    pub canonical_request: super::events::CanonicalDerivationRequest,
    pub recipe_revision: super::events::RecipeRevisionRef,
    pub effective_source_boundary: super::events::EffectiveSourceBoundary,
    pub completion_metadata: serde_json::Value,
}

/// Trusted engine seam for request-relative applicability plus the complete-
/// audience availability proof. This is deliberately not caller-authored
/// data. The f0 integration adapter should build both requested and revision
/// bases with `revision_applicability_basis`, call `compute_applicability`, and
/// return true only for `Current` with a successful audience revalidation.
pub trait RevisionApplicabilityGate {
    fn is_current_and_audience_available<'a>(
        &'a self,
        snapshot: &'a mut Transaction<'static, Sqlite>,
        basis: &'a RevisionRecognitionBasis,
    ) -> BoxFuture<'a, Result<bool>>;
}

/// Resolve the workflow's requested basis *now* inside the confirmation
/// query's read snapshot. Returning the historical request basis is not a
/// freshness proof: workflows must resolve their current source boundary,
/// scope membership, target head, definition and audience basis here.
pub trait CurrentRevisionBasisResolver {
    fn current_basis<'a>(
        &'a self,
        snapshot: &'a mut Transaction<'static, Sqlite>,
        revision: &'a RevisionRecognitionBasis,
    ) -> BoxFuture<'a, Result<Option<super::DerivationApplicabilityBasis>>>;
}

/// Native request-relative gate. The host supplies live membership answers;
/// applicability and the complete-audience proof then execute inside the
/// confirmation reader's existing database snapshot.
pub struct RequestRevisionApplicabilityGate<F, R> {
    live_membership: F,
    current_basis: R,
}

impl<F, R> RequestRevisionApplicabilityGate<F, R> {
    pub fn new(live_membership: F, current_basis: R) -> Self {
        Self {
            live_membership,
            current_basis,
        }
    }
}

impl<F, R> RevisionApplicabilityGate for RequestRevisionApplicabilityGate<F, R>
where
    F: Fn(&str) -> Option<bool> + Send + Sync,
    R: CurrentRevisionBasisResolver + Sync,
{
    fn is_current_and_audience_available<'a>(
        &'a self,
        snapshot: &'a mut Transaction<'static, Sqlite>,
        basis: &'a RevisionRecognitionBasis,
    ) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            let Some(request_key) = basis
                .completion_metadata
                .get("request_key_sha256")
                .and_then(serde_json::Value::as_str)
            else {
                return Ok(false);
            };
            let request_id: Option<String> = sqlx::query_scalar(
                "SELECT id FROM derivation_requests
                  WHERE result_revision_id=? AND request_key_sha256=?",
            )
            .bind(&basis.revision_id)
            .bind(request_key)
            .fetch_optional(&mut **snapshot)
            .await?;
            let Some(request_id) = request_id else {
                return Ok(false);
            };
            let Some(request) = super::requests::inspect_request_in(snapshot, &request_id).await?
            else {
                return Ok(false);
            };
            if request.state != super::DerivationRequestState::Succeeded
                || request.result_revision_id.as_deref() != Some(basis.revision_id.as_str())
            {
                return Ok(false);
            }
            let Some(requested) = self.current_basis.current_basis(snapshot, basis).await? else {
                return Ok(false);
            };
            let revision = super::revision_applicability_basis(
                &basis.series_id,
                &basis.definition_sha256,
                basis.canonical_request.clone(),
                basis.recipe_revision.clone(),
                basis.effective_source_boundary.clone(),
                &basis.completion_metadata,
            )?;
            let audience_available = super::requests::revision_audience_is_available_in(
                snapshot,
                &request_id,
                &basis.revision_id,
                &self.live_membership,
            )
            .await?;
            Ok(matches!(
                super::compute_applicability(&requested, &revision, audience_available),
                super::DerivationApplicability::Current
            ))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedArtifactInspection {
    pub assignment_id: String,
    pub target_record_id: String,
    pub role: String,
    pub confirmation_id: String,
    pub series_id: String,
    pub revision_id: String,
    pub publication_id: String,
    pub confirmed_event_id: String,
    pub confirmed_by: String,
    pub confirmed_body: String,
    pub draft_available: bool,
    pub source_runs: Vec<SourceRunInspection>,
    pub next_source_cursor: Option<SourceRunCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedArtifactPage {
    pub items: Vec<ConfirmedArtifactInspection>,
    pub next_cursor: Option<ConfirmedArtifactCursor>,
}

fn bounded_limit(label: &str, limit: usize, maximum: usize) -> Result<i64> {
    if limit == 0 || limit > maximum {
        Err(Error::engine(format!(
            "derivation {label} must be between 1 and {maximum}"
        )))
    } else {
        Ok(limit as i64)
    }
}

fn recognition_basis(row: &sqlx::sqlite::SqliteRow) -> Result<RevisionRecognitionBasis> {
    Ok(RevisionRecognitionBasis {
        series_id: row.try_get("series_id")?,
        revision_id: row.try_get("revision_id")?,
        definition_sha256: row.try_get("definition_sha256")?,
        canonical_request: serde_json::from_str(&row.try_get::<String, _>("canonical_request")?)?,
        recipe_revision: serde_json::from_str(&row.try_get::<String, _>("recipe_revision")?)?,
        effective_source_boundary: serde_json::from_str(
            &row.try_get::<String, _>("effective_source_boundary")?,
        )?,
        completion_metadata: serde_json::from_str(
            &row.try_get::<String, _>("completion_metadata")?,
        )?,
    })
}

async fn source_visibility(
    snapshot: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    principal: Principal<'_>,
    input_kind: &str,
    portable_id: &str,
) -> Result<(bool, Option<String>)> {
    let candidates: Vec<(String, Option<String>)> = match input_kind {
        "content_event" | "record_body" => {
            sqlx::query_as("SELECT record_id,run_key FROM content_events WHERE id=?")
                .bind(portable_id)
                .fetch_optional(&mut **snapshot)
                .await?
                .into_iter()
                .collect()
        }
        "blob" => {
            sqlx::query_as(
                "SELECT r.id,NULL
               FROM facet_values f
               JOIN records r ON r.id=f.record_id AND r.deleted_at IS NULL
              WHERE f.key='blob_ref' AND f.value=?
              ORDER BY r.id",
            )
            .bind(portable_id)
            .fetch_all(&mut **snapshot)
            .await?
        }
        // There is no authoritative versioned-input ownership relation in the
        // current schema. Caller-authored metadata is never an authority seam.
        _ => Vec::new(),
    };
    for (record_id, run_key) in candidates {
        match crate::authorization::effective_capability_on(snapshot, principal, &record_id).await {
            Ok(capability) if capability.allows(Capability::View) => {
                return Ok((true, run_key));
            }
            Ok(_) | Err(Error::Engine(_)) | Err(Error::Auth(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok((false, None))
}

async fn source_page(
    snapshot: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    principal: Principal<'_>,
    revision_id: &str,
    after: Option<&SourceRunCursor>,
    limit: usize,
) -> Result<(Vec<SourceRunInspection>, Option<SourceRunCursor>)> {
    let limit = bounded_limit("source page limit", limit, MAX_SOURCE_RUN_PAGE_LIMIT)?;
    let after = after.map_or(-1, |cursor| cursor.ordinal);
    if after < -1 {
        return Err(Error::engine(
            "derivation source cursor ordinal cannot be below -1",
        ));
    }
    let source_rows = sqlx::query(
        "SELECT ordinal,input_role,input_kind,portable_id,sha256
           FROM derivation_revision_inputs
          WHERE revision_id=? AND ordinal>?
          ORDER BY ordinal LIMIT ?",
    )
    .bind(revision_id)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(&mut **snapshot)
    .await?;
    let has_more = source_rows.len() > limit as usize;
    let mut source_runs = Vec::with_capacity(source_rows.len().min(limit as usize));
    for source in source_rows.into_iter().take(limit as usize) {
        let ordinal: i64 = source.try_get("ordinal")?;
        let input_role: String = source.try_get("input_role")?;
        let input_kind: String = source.try_get("input_kind")?;
        let portable_id: String = source.try_get("portable_id")?;
        let sha256: String = source.try_get("sha256")?;
        let (visible, run_key) =
            source_visibility(snapshot, principal, &input_kind, &portable_id).await?;
        source_runs.push(SourceRunInspection {
            ordinal,
            input_role,
            input_kind,
            portable_id: visible.then_some(portable_id),
            sha256: visible.then_some(sha256),
            run_key: visible.then_some(run_key).flatten(),
            redacted: !visible,
        });
    }
    let next = has_more.then(|| SourceRunCursor {
        ordinal: source_runs.last().expect("non-empty bounded page").ordinal,
    });
    Ok((source_runs, next))
}

#[allow(clippy::too_many_arguments)]
async fn inspect_assignment_in(
    snapshot: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    principal: Principal<'_>,
    assignment_id: &str,
    role: &str,
    output_contract: &OutputContractSelector,
    source_after: Option<&SourceRunCursor>,
    source_limit: usize,
    applicability: &impl RevisionApplicabilityGate,
) -> Result<Option<ConfirmedArtifactInspection>> {
    let row = sqlx::query(
        "SELECT a.target_record_id,a.role,h.confirmation_id,c.series_id,c.revision_id,
                c.publication_id,p.output_event_id,c.confirmed_event_id,c.confirmed_by,
                th.selected_publication_id,r.definition_sha256,r.canonical_request,
                r.recipe_revision,r.effective_source_boundary,r.completion_metadata
           FROM derivation_artifact_role_assignments a
           JOIN derivation_artifact_role_heads rh
             ON rh.active_assignment_id=a.assignment_id
           JOIN derivation_confirmation_heads h ON h.assignment_id=a.assignment_id
           JOIN derivation_revision_confirmations c ON c.confirmation_id=h.confirmation_id
           JOIN derivation_revisions r ON r.id=c.revision_id AND r.series_id=c.series_id
           JOIN derivation_target_publications p ON p.publication_id=c.publication_id
           JOIN recipe_releases rr
             ON rr.program_id=json_extract(r.recipe_revision,'$.definition_id')
            AND rr.publication_event_id=json_extract(r.recipe_revision,'$.publication_id')
            AND rr.descriptor_sha256=json_extract(r.recipe_revision,'$.sha256')
           JOIN derivation_target_heads th
             ON th.target_kind=a.target_kind AND th.target_record_id=a.target_record_id
            AND th.target_slot=a.target_slot
            AND th.active_binding_id=c.binding_id
           JOIN records carrier ON carrier.id=a.target_record_id
            AND carrier.type='Document' AND carrier.kind='note' AND carrier.deleted_at IS NULL
          WHERE a.assignment_id=? AND a.role=?
            AND json_extract(rr.descriptor,'$.definition.output_contract.id')=?
            AND CAST(json_extract(rr.descriptor,'$.definition.output_contract.version') AS INTEGER)=?",
    )
    .bind(assignment_id)
    .bind(role)
    .bind(&output_contract.id)
    .bind(i64::from(output_contract.version))
    .fetch_optional(&mut **snapshot)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let target_record_id: String = row.try_get("target_record_id")?;
    if !crate::authorization::effective_capability_on(snapshot, principal, &target_record_id)
        .await?
        .allows(Capability::View)
    {
        return Ok(None);
    }
    let basis = recognition_basis(&row)?;
    if !applicability
        .is_current_and_audience_available(snapshot, &basis)
        .await?
    {
        return Ok(None);
    }
    let revision_id = basis.revision_id;
    let confirmed_body: Option<String> =
        sqlx::query_scalar("SELECT json_extract(payload,'$.body') FROM content_events WHERE id=?")
            .bind(row.try_get::<String, _>("output_event_id")?)
            .fetch_optional(&mut **snapshot)
            .await?;
    let Some(confirmed_body) = confirmed_body else {
        return Ok(None);
    };
    let (source_runs, next_source_cursor) = source_page(
        snapshot,
        principal,
        &revision_id,
        source_after,
        source_limit,
    )
    .await?;
    let confirmation_id: String = row.try_get("confirmation_id")?;
    let publication_id: String = row.try_get("publication_id")?;
    let selected: Option<String> = row.try_get("selected_publication_id")?;
    Ok(Some(ConfirmedArtifactInspection {
        assignment_id: assignment_id.to_string(),
        target_record_id,
        role: row.try_get("role")?,
        confirmation_id,
        series_id: row.try_get("series_id")?,
        revision_id,
        draft_available: selected.as_deref() != Some(publication_id.as_str()),
        publication_id,
        confirmed_event_id: row.try_get("confirmed_event_id")?,
        confirmed_by: row.try_get("confirmed_by")?,
        confirmed_body,
        source_runs,
        next_source_cursor,
    }))
}

#[allow(clippy::too_many_arguments)]
pub async fn inspect_confirmed_artifact<G: RevisionApplicabilityGate>(
    db: &Db,
    principal: Principal<'_>,
    assignment_id: &str,
    role: &str,
    output_contract: &OutputContractSelector,
    source_after: Option<&SourceRunCursor>,
    source_limit: usize,
    applicability: &G,
) -> Result<Option<ConfirmedArtifactInspection>> {
    nonblank("artifact role", role)?;
    nonblank("output contract", &output_contract.id)?;
    let mut snapshot = db.pool().begin().await?;
    let result = inspect_assignment_in(
        &mut snapshot,
        principal,
        assignment_id,
        role,
        output_contract,
        source_after,
        source_limit,
        applicability,
    )
    .await?;
    snapshot.rollback().await?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub async fn query_confirmed_artifacts<G: RevisionApplicabilityGate>(
    db: &Db,
    principal: Principal<'_>,
    role: &str,
    output_contract: &OutputContractSelector,
    after: Option<&ConfirmedArtifactCursor>,
    limit: usize,
    source_limit: usize,
    applicability: &G,
) -> Result<ConfirmedArtifactPage> {
    nonblank("artifact role", role)?;
    nonblank("output contract", &output_contract.id)?;
    let limit = bounded_limit(
        "confirmed artifact page limit",
        limit,
        MAX_CONFIRMED_ARTIFACT_PAGE_LIMIT,
    )?;
    bounded_limit("source page limit", source_limit, MAX_SOURCE_RUN_PAGE_LIMIT)?;
    let Some(account_id) = principal.account_id else {
        return Ok(ConfirmedArtifactPage {
            items: Vec::new(),
            next_cursor: None,
        });
    };
    if let Some(cursor) = after {
        confirmed_artifact_cursor_seq(cursor)?;
    }
    let mut snapshot = db.pool().begin().await?;
    let mut scan_after = after.cloned();
    let mut scanned = 0_usize;
    let mut results = Vec::with_capacity(limit as usize);
    let mut continuation = None;
    const SCAN_CHUNK: usize = 100;
    loop {
        let remaining = MAX_APPLICABILITY_SCAN - scanned;
        if remaining == 0 {
            break;
        }
        let chunk = remaining.min(SCAN_CHUNK);
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT a.assignment_id,ch.head_event_seq,ch.confirmation_id
           FROM derivation_artifact_role_heads rh INDEXED BY idx_derivation_artifact_role_heads_active_role
           JOIN derivation_artifact_role_assignments a ON a.assignment_id=rh.active_assignment_id
           JOIN derivation_confirmation_heads ch ON ch.assignment_id=a.assignment_id
           JOIN derivation_revision_confirmations c ON c.confirmation_id=ch.confirmation_id
           JOIN derivation_revisions r ON r.id=c.revision_id AND r.series_id=c.series_id
           JOIN recipe_releases rr
             ON rr.program_id=json_extract(r.recipe_revision,'$.definition_id')
            AND rr.publication_event_id=json_extract(r.recipe_revision,'$.publication_id')
            AND rr.descriptor_sha256=json_extract(r.recipe_revision,'$.sha256')
           JOIN derivation_target_heads th
             ON th.target_kind=a.target_kind AND th.target_record_id=a.target_record_id
            AND th.target_slot=a.target_slot AND th.active_binding_id=c.binding_id
           JOIN records carrier ON carrier.id=a.target_record_id
            AND carrier.type='Document' AND carrier.kind='note' AND carrier.deleted_at IS NULL
          WHERE rh.role=",
    );
        query.push_bind(role);
        query.push(" AND ch.confirmation_id IS NOT NULL AND json_extract(rr.descriptor,'$.definition.output_contract.id')=");
        query.push_bind(&output_contract.id);
        query.push(
            " AND CAST(json_extract(rr.descriptor,'$.definition.output_contract.version') AS INTEGER)=",
        );
        query.push_bind(i64::from(output_contract.version));
        query.push(" AND carrier.policy_anchor_id IS NOT NULL AND EXISTS(SELECT 1 FROM record_policies rp WHERE rp.record_id=carrier.policy_anchor_id) AND (");
        query.push("EXISTS(SELECT 1 FROM bindings own JOIN records owner ON owner.id=carrier.owner_id WHERE own.record_id=owner.id AND own.system='account' AND own.identifier=");
        query.push_bind(account_id);
        query.push(" AND own.is_canonical=1) OR EXISTS(SELECT 1 FROM policy_entries pe WHERE pe.policy_anchor_id=carrier.policy_anchor_id AND pe.effect='allow' AND pe.capability IN ('view','edit','manage') AND pe.subject_kind='account' AND pe.subject_id=");
        query.push_bind(account_id);
        query.push(")");
        if principal.is_member {
            query.push(" OR EXISTS(SELECT 1 FROM policy_entries pe WHERE pe.policy_anchor_id=carrier.policy_anchor_id AND pe.effect='allow' AND pe.capability IN ('view','edit','manage') AND pe.subject_kind='members' AND pe.subject_id='native:members')");
        }
        query.push(")");
        if let Some(cursor) = &scan_after {
            let cursor_sequence = confirmed_artifact_cursor_seq(cursor)?;
            query.push(" AND (ch.head_event_seq<");
            query.push_bind(cursor_sequence);
            query.push(")");
        }
        query.push(" ORDER BY ch.head_event_seq DESC LIMIT ");
        query.push_bind(chunk as i64);
        let candidates = query.build().fetch_all(&mut *snapshot).await?;
        let fetched = candidates.len();
        if fetched == 0 {
            continuation = None;
            break;
        }
        for candidate in candidates {
            let assignment_id: String = candidate.try_get("assignment_id")?;
            let candidate_cursor = confirmed_artifact_cursor(candidate.try_get("head_event_seq")?);
            continuation = Some(candidate_cursor.clone());
            scanned += 1;
            if let Some(result) = inspect_assignment_in(
                &mut snapshot,
                principal,
                &assignment_id,
                role,
                output_contract,
                None,
                source_limit,
                applicability,
            )
            .await?
            {
                results.push(result);
                if results.len() == limit as usize {
                    break;
                }
            }
        }
        if results.len() == limit as usize {
            break;
        }
        if fetched < chunk {
            continuation = None;
            break;
        }
        scan_after = continuation.clone();
        if scanned >= MAX_APPLICABILITY_SCAN {
            break;
        }
    }
    let next_cursor = continuation;
    snapshot.rollback().await?;
    Ok(ConfirmedArtifactPage {
        items: results,
        next_cursor,
    })
}
