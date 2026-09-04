//! Generic target ownership and selected-publication state for derivations.
//!
//! A target descriptor says exactly which mutable slot is engine-owned.  V1
//! supports only an ordinary record's `body`; metadata, facets and links remain
//! authored through their existing paths.  Binding generations and optimistic
//! target versions fence stale workers without making bindings graph records.

use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use crate::authorization::{Capability, Principal};
use crate::db::{begin_write, Db};
use crate::error::{Error, Result};

use super::events::{
    DerivationEventPayload, DerivationEventRow, DerivationOutputRef, DerivationRevisionCompleted,
    NewDerivationEvent,
};
use super::persistence::{append_derivation_event_in, read_by_key};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationTarget {
    pub target_kind: String,
    pub record_id: String,
    pub slot: String,
}

impl DerivationTarget {
    pub fn record_body(record_id: impl Into<String>) -> Self {
        Self {
            target_kind: "record".into(),
            record_id: record_id.into(),
            slot: "body".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationTargetBound {
    pub binding_id: String,
    pub series_id: String,
    pub target: DerivationTarget,
    pub expected_target_version: i64,
    pub generation: i64,
    pub expected_body_event_id: Option<String>,
    pub expected_body_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationTargetDetached {
    pub binding_id: String,
    pub target: DerivationTarget,
    pub expected_generation: i64,
    pub expected_target_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationTargetPublished {
    pub publication_id: String,
    pub binding_id: String,
    pub series_id: String,
    pub revision_id: String,
    pub target: DerivationTarget,
    pub expected_generation: i64,
    pub expected_target_version: i64,
    pub output_ref: DerivationOutputRef,
}

fn nonblank(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::engine(format!(
            "derivation target {label} cannot be empty"
        )));
    }
    Ok(())
}

pub(super) fn validate_target(target: &DerivationTarget) -> Result<()> {
    if target.target_kind != "record" || target.slot != "body" {
        return Err(Error::engine(
            "derivation target must be the explicit record/body slot",
        ));
    }
    nonblank("record id", &target.record_id)
}

async fn head(
    conn: &mut SqliteConnection,
    target: &DerivationTarget,
) -> Result<Option<(i64, i64, Option<String>)>> {
    sqlx::query(
        "SELECT generation,target_version,active_binding_id
           FROM derivation_target_heads
          WHERE target_kind=? AND target_record_id=? AND target_slot=?",
    )
    .bind(&target.target_kind)
    .bind(&target.record_id)
    .bind(&target.slot)
    .fetch_optional(&mut *conn)
    .await?
    .map(|row| {
        Ok((
            row.try_get("generation")?,
            row.try_get("target_version")?,
            row.try_get("active_binding_id")?,
        ))
    })
    .transpose()
}

pub(super) async fn project_target_bound(
    conn: &mut SqliteConnection,
    event: &DerivationEventRow,
    value: DerivationTargetBound,
) -> Result<()> {
    validate_target(&value.target)?;
    for (label, item) in [
        ("binding id", value.binding_id.as_str()),
        ("series id", value.series_id.as_str()),
    ] {
        nonblank(label, item)?;
    }
    match (
        value.expected_body_event_id.as_deref(),
        value.expected_body_sha256.as_deref(),
    ) {
        (None, None) => {}
        (Some(event_id), Some(sha256)) => {
            nonblank("expected body event id", event_id)?;
            if sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(Error::engine(
                    "derivation expected body digest must be lowercase sha256",
                ));
            }
        }
        _ => {
            return Err(Error::engine(
                "derivation body CAS requires both event id and digest, or neither",
            ));
        }
    }
    if value.binding_id != event.aggregate_id {
        return Err(Error::engine(
            "derivation binding payload id does not match aggregate",
        ));
    }
    let series_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM derivation_series WHERE id=?)")
            .bind(&value.series_id)
            .fetch_one(&mut *conn)
            .await?;
    if !series_exists {
        return Err(Error::engine("derivation binding series does not exist"));
    }
    let prior = head(conn, &value.target).await?;
    let (prior_generation, prior_version, active) = prior.unwrap_or((0, 0, None));
    if active.is_some()
        || value.expected_target_version != prior_version
        || value.generation != prior_generation + 1
    {
        return Err(Error::engine(
            "derivation target bind lost its generation/version race",
        ));
    }
    sqlx::query(
        "INSERT INTO derivation_target_bindings
         (binding_id,series_id,target_kind,target_record_id,target_slot,generation,
          bound_event_id,bound_event_seq,bound_at)
         VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(&value.binding_id)
    .bind(&value.series_id)
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(value.generation)
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO derivation_target_heads
         (target_kind,target_record_id,target_slot,generation,target_version,active_binding_id)
         VALUES(?,?,?,?,?,?)
         ON CONFLICT(target_kind,target_record_id,target_slot) DO UPDATE SET
           generation=excluded.generation,target_version=excluded.target_version,
           active_binding_id=excluded.active_binding_id,selected_publication_id=NULL",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(value.generation)
    .bind(prior_version + 1)
    .bind(&value.binding_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) async fn project_target_detached(
    conn: &mut SqliteConnection,
    event: &DerivationEventRow,
    value: DerivationTargetDetached,
) -> Result<()> {
    validate_target(&value.target)?;
    if value.binding_id != event.aggregate_id {
        return Err(Error::engine(
            "derivation detach payload id does not match aggregate",
        ));
    }
    let current = head(conn, &value.target).await?;
    if current
        != Some((
            value.expected_generation,
            value.expected_target_version,
            Some(value.binding_id.clone()),
        ))
    {
        return Err(Error::engine(
            "derivation target detach lost its generation/version race",
        ));
    }
    let active_role: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1
              FROM derivation_artifact_role_assignments a
              JOIN derivation_artifact_role_heads rh ON rh.active_assignment_id=a.assignment_id
             WHERE a.target_kind=? AND a.target_record_id=? AND a.target_slot=?
            )",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .fetch_one(&mut *conn)
    .await?;
    if active_role {
        return Err(Error::engine(
            "active artifact role blocks derivation target detach; retire it first",
        ));
    }
    let changed = sqlx::query(
        "UPDATE derivation_target_bindings
            SET detached_event_id=?,detached_event_seq=?,detached_at=?
          WHERE binding_id=? AND generation=? AND detached_event_id IS NULL",
    )
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .bind(&value.binding_id)
    .bind(value.expected_generation)
    .execute(&mut *conn)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(Error::engine("derivation target binding is not active"));
    }
    sqlx::query(
        "UPDATE derivation_target_heads
            SET target_version=target_version+1,active_binding_id=NULL,selected_publication_id=NULL
          WHERE target_kind=? AND target_record_id=? AND target_slot=?",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "DELETE FROM derivation_selected_publications
          WHERE target_kind=? AND target_record_id=? AND target_slot=?",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(super) async fn project_target_published(
    conn: &mut SqliteConnection,
    event: &DerivationEventRow,
    value: DerivationTargetPublished,
) -> Result<()> {
    validate_target(&value.target)?;
    if value.publication_id != event.aggregate_id {
        return Err(Error::engine(
            "derivation publication payload id does not match aggregate",
        ));
    }
    let current = head(conn, &value.target).await?;
    if current
        != Some((
            value.expected_generation,
            value.expected_target_version,
            Some(value.binding_id.clone()),
        ))
    {
        return Err(Error::engine(
            "derivation publication lost its generation/version race",
        ));
    }
    let binding_series: Option<String> = sqlx::query_scalar(
        "SELECT series_id FROM derivation_target_bindings
          WHERE binding_id=? AND generation=? AND detached_event_id IS NULL",
    )
    .bind(&value.binding_id)
    .bind(value.expected_generation)
    .fetch_optional(&mut *conn)
    .await?;
    if binding_series.as_deref() != Some(&value.series_id) {
        return Err(Error::engine(
            "derivation publication does not match the active binding series",
        ));
    }
    let revision: Option<String> = sqlx::query_scalar(
        "SELECT output_ref FROM derivation_revisions WHERE id=? AND series_id=?",
    )
    .bind(&value.revision_id)
    .bind(&value.series_id)
    .fetch_optional(&mut *conn)
    .await?;
    let revision_output: DerivationOutputRef = revision
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .ok_or_else(|| Error::engine("derivation publication revision does not exist"))?;
    if revision_output != value.output_ref {
        return Err(Error::engine(
            "derivation publication output does not match its immutable revision",
        ));
    }
    sqlx::query(
        "INSERT INTO derivation_target_publications
         (publication_id,binding_id,generation,target_version,revision_id,output_event_id,
          output_sha256,published_event_id,published_event_seq,published_at)
         VALUES(?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&value.publication_id)
    .bind(&value.binding_id)
    .bind(value.expected_generation)
    .bind(value.expected_target_version + 1)
    .bind(&value.revision_id)
    .bind(&value.output_ref.event_id)
    .bind(&value.output_ref.sha256)
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO derivation_selected_publications
         (target_kind,target_record_id,target_slot,publication_id,binding_id,generation,
          target_version,revision_id,output_event_id,output_sha256,selected_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(target_kind,target_record_id,target_slot) DO UPDATE SET
           publication_id=excluded.publication_id,binding_id=excluded.binding_id,
           generation=excluded.generation,target_version=excluded.target_version,
           revision_id=excluded.revision_id,output_event_id=excluded.output_event_id,
           output_sha256=excluded.output_sha256,selected_at=excluded.selected_at",
    )
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .bind(&value.publication_id)
    .bind(&value.binding_id)
    .bind(value.expected_generation)
    .bind(value.expected_target_version + 1)
    .bind(&value.revision_id)
    .bind(&value.output_ref.event_id)
    .bind(&value.output_ref.sha256)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE derivation_target_heads
            SET target_version=target_version+1,selected_publication_id=?
          WHERE target_kind=? AND target_record_id=? AND target_slot=?",
    )
    .bind(&value.publication_id)
    .bind(&value.target.target_kind)
    .bind(&value.target.record_id)
    .bind(&value.target.slot)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn require_live_target(conn: &mut SqliteConnection, target: &DerivationTarget) -> Result<()> {
    validate_target(target)?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND type='Document' AND deleted_at IS NULL)",
    )
    .bind(&target.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if !live {
        return Err(Error::engine(
            "derivation record/body target must be a live Document",
        ));
    }
    Ok(())
}

async fn require_bodyless_cas(
    conn: &mut SqliteConnection,
    target: &DerivationTarget,
    expected_event_id: Option<&str>,
    expected_sha256: Option<&str>,
) -> Result<()> {
    if expected_event_id.is_some() != expected_sha256.is_some() {
        return Err(Error::engine(
            "derivation body CAS requires both event id and digest, or neither",
        ));
    }
    let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&target.record_id)
        .fetch_one(&mut *conn)
        .await?;
    if body.is_some() {
        return Err(Error::engine(
            "derivation target must have no canonical body before binding",
        ));
    }
    let current: Option<(String, Option<String>)> = sqlx::query(
        "SELECT id,payload FROM content_events
          WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&target.record_id)
    .fetch_optional(&mut *conn)
    .await?
    .map(|row| Ok::<_, sqlx::Error>((row.try_get("id")?, row.try_get("payload")?)))
    .transpose()?;
    let actual = current
        .map(|(event_id, payload)| {
            let payload: serde_json::Value = payload
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?
                .unwrap_or(serde_json::Value::Null);
            Ok::<_, Error>((event_id, super::events::digest_json(&payload)))
        })
        .transpose()?;
    if actual.as_ref().map(|(id, _)| id.as_str()) != expected_event_id
        || actual.as_ref().map(|(_, sha)| sha.as_str()) != expected_sha256
    {
        return Err(Error::engine(
            "derivation target body changed since binding preflight",
        ));
    }
    Ok(())
}

fn require_actor(principal: Principal<'_>, actor: &str) -> Result<()> {
    if principal.account_id != Some(actor) {
        return Err(Error::engine(
            "derivation actor must match the authorized account principal",
        ));
    }
    Ok(())
}

pub async fn bind_target(
    db: &Db,
    principal: Principal<'_>,
    idempotency_key: impl Into<String>,
    actor: impl Into<String>,
    run_key: Option<String>,
    reason: impl Into<String>,
    binding: DerivationTargetBound,
) -> Result<DerivationEventRow> {
    let idempotency_key = idempotency_key.into();
    let actor = actor.into();
    require_actor(principal, &actor)?;
    let command = NewDerivationEvent::authored(
        idempotency_key.clone(),
        actor,
        run_key,
        reason,
        DerivationEventPayload::TargetBound(binding.clone()),
    )?;
    let mut tx = begin_write(db.write_pool()).await?;
    if super::persistence::read_by_key(&mut tx, &idempotency_key)
        .await?
        .is_some()
    {
        let event = append_derivation_event_in(&mut tx, command).await?;
        tx.commit().await?;
        return Ok(event);
    }
    require_live_target(&mut tx, &binding.target).await?;
    crate::authorization::require_capability_on(
        &mut tx,
        principal,
        &binding.target.record_id,
        Capability::Edit,
    )
    .await?;
    require_bodyless_cas(
        &mut tx,
        &binding.target,
        binding.expected_body_event_id.as_deref(),
        binding.expected_body_sha256.as_deref(),
    )
    .await?;
    let event = append_derivation_event_in(&mut tx, command).await?;
    tx.commit().await?;
    Ok(event)
}

pub async fn detach_target(
    db: &Db,
    principal: Principal<'_>,
    idempotency_key: impl Into<String>,
    actor: impl Into<String>,
    run_key: Option<String>,
    reason: impl Into<String>,
    detach: DerivationTargetDetached,
) -> Result<DerivationEventRow> {
    let idempotency_key = idempotency_key.into();
    let actor = actor.into();
    require_actor(principal, &actor)?;
    let command = NewDerivationEvent::authored(
        idempotency_key.clone(),
        actor,
        run_key,
        reason,
        DerivationEventPayload::TargetDetached(detach.clone()),
    )?;
    let mut tx = begin_write(db.write_pool()).await?;
    if super::persistence::read_by_key(&mut tx, &idempotency_key)
        .await?
        .is_some()
    {
        let event = append_derivation_event_in(&mut tx, command).await?;
        tx.commit().await?;
        return Ok(event);
    }
    crate::authorization::require_capability_on(
        &mut tx,
        principal,
        &detach.target.record_id,
        Capability::Edit,
    )
    .await?;
    let event = append_derivation_event_in(&mut tx, command).await?;
    tx.commit().await?;
    Ok(event)
}

#[derive(Debug, Clone)]
pub struct PublishRecordBodyRevision {
    pub publication_idempotency_key: String,
    pub revision_idempotency_key: String,
    pub actor: String,
    pub run_key: Option<String>,
    pub reason: String,
    pub publication_id: String,
    pub binding_id: String,
    pub target: DerivationTarget,
    pub expected_generation: i64,
    pub expected_target_version: i64,
    pub body: String,
    pub revision: DerivationRevisionCompleted,
}

#[derive(Debug, Clone)]
pub struct PublishedRecordBodyRevision {
    pub content_event: crate::events::EventRow,
    pub revision_event: DerivationEventRow,
    pub publication_event: DerivationEventRow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicationFailurePoint {
    None,
    AfterContentEvent,
    AfterRevisionEvent,
    AfterPublicationEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicationAuthority {
    Generic,
    ControlledRequest,
}

pub async fn publish_record_body_revision(
    db: &Db,
    principal: Principal<'_>,
    input: PublishRecordBodyRevision,
) -> Result<PublishedRecordBodyRevision> {
    publish_record_body_revision_impl(db, principal, input, PublicationFailurePoint::None).await
}

#[cfg(test)]
pub(super) async fn publish_record_body_revision_with_failure(
    db: &Db,
    principal: Principal<'_>,
    input: PublishRecordBodyRevision,
    failure_point: PublicationFailurePoint,
) -> Result<PublishedRecordBodyRevision> {
    publish_record_body_revision_impl(db, principal, input, failure_point).await
}

async fn publish_record_body_revision_impl(
    db: &Db,
    principal: Principal<'_>,
    input: PublishRecordBodyRevision,
    failure_point: PublicationFailurePoint,
) -> Result<PublishedRecordBodyRevision> {
    let mut tx = begin_write(db.write_pool()).await?;
    let published = publish_record_body_revision_in(
        db,
        &mut tx,
        principal,
        input,
        failure_point,
        PublicationAuthority::Generic,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(published)
}

pub(super) async fn publish_record_body_revision_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    principal: Principal<'_>,
    mut input: PublishRecordBodyRevision,
    failure_point: PublicationFailurePoint,
    authority: PublicationAuthority,
) -> Result<PublishedRecordBodyRevision> {
    validate_target(&input.target)?;
    if input.revision.series_id.trim().is_empty() {
        return Err(Error::engine(
            "derivation publication series cannot be empty",
        ));
    }
    require_actor(principal, &input.actor)?;
    let controlled_series: bool = sqlx::query_scalar(
        "SELECT COALESCE(json_type(definition,'$.audience_sha256')='text',0)
           FROM derivation_series WHERE id=?",
    )
    .bind(&input.revision.series_id)
    .fetch_one(&mut **tx)
    .await?;
    if controlled_series && authority != PublicationAuthority::ControlledRequest {
        return Err(Error::engine(
            "controlled derivation publication requires durable request completion",
        ));
    }
    let output_payload = serde_json::json!({"body": input.body});
    let output_sha256 = super::events::digest_json(&output_payload);
    if let Some(publication_event) = read_by_key(tx, &input.publication_idempotency_key).await? {
        let publication: DerivationTargetPublished =
            serde_json::from_str(&publication_event.payload)?;
        let revision_event = read_by_key(tx, &input.revision_idempotency_key)
            .await?
            .ok_or_else(|| Error::engine("derivation publication is missing its revision event"))?;
        let stored_revision: DerivationRevisionCompleted =
            serde_json::from_str(&revision_event.payload)?;
        let mut expected_revision = input.revision.clone();
        expected_revision.output_ref = publication.output_ref.clone();
        let same = publication_event.event_type == "derivation.target.published"
            && publication_event.actor == input.actor
            && (authority == PublicationAuthority::Generic
                || publication_event.run_key == input.run_key)
            && publication_event.reason == input.reason
            && publication.publication_id == input.publication_id
            && publication.binding_id == input.binding_id
            && publication.series_id == input.revision.series_id
            && publication.revision_id == input.revision.id
            && publication.target == input.target
            && publication.expected_generation == input.expected_generation
            && publication.expected_target_version == input.expected_target_version
            && publication.output_ref.sha256 == output_sha256
            && revision_event.event_type == "derivation.revision.completed"
            && revision_event.aggregate_id == input.revision.id
            && revision_event.actor == input.actor
            && (authority == PublicationAuthority::Generic
                || revision_event.run_key == input.run_key)
            && revision_event.reason == input.reason
            && stored_revision == expected_revision;
        if !same {
            return Err(Error::engine(format!(
                "derivation event idempotency key '{}' was reused for different intent",
                input.publication_idempotency_key
            )));
        }
        let row = sqlx::query(
            "SELECT seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at
               FROM content_events WHERE id=?",
        )
        .bind(&publication.output_ref.event_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine("derivation publication output event is missing"))?;
        let content_event = crate::events::EventRow {
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
        let stored_output: serde_json::Value = content_event
            .payload
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
            .ok_or_else(|| Error::engine("derivation publication output payload is missing"))?;
        if content_event.record_id != input.target.record_id
            || content_event.event_type != "record.updated"
            || content_event.actor.as_deref() != Some(input.actor.as_str())
            || (authority == PublicationAuthority::ControlledRequest
                && content_event.run_key != input.run_key)
            || stored_output != output_payload
            || super::events::digest_json(&stored_output) != publication.output_ref.sha256
        {
            return Err(Error::engine(
                "derivation publication output event no longer matches its durable response",
            ));
        }
        return Ok(PublishedRecordBodyRevision {
            content_event,
            revision_event,
            publication_event,
        });
    }

    require_live_target(tx, &input.target).await?;
    crate::authorization::require_capability_on(
        tx,
        principal,
        &input.target.record_id,
        Capability::Edit,
    )
    .await?;

    // BEGIN IMMEDIATE serializes the preflight with publication. The ordinary
    // content append remains the single projection path; its sealed authority
    // token permits only this binding generation to touch the owned body.
    let output_event_id = uuid::Uuid::new_v4().to_string();
    let content_event = crate::store::with_event_annotations(
        crate::store::EventAnnotations {
            run_key: input.run_key.clone(),
            parent_key: None,
            intent: Some("derivation publication".into()),
        },
        crate::store::append_derived_body_with_event_id_in(
            db,
            tx,
            output_event_id.clone(),
            input.binding_id.clone(),
            input.expected_generation,
            input.expected_target_version,
            crate::store::AppendSpec {
                record_id: input.target.record_id.clone(),
                event_type: "record.updated".into(),
                payload: output_payload,
                actor: Some(input.actor.clone()),
            },
        ),
    )
    .await?;
    if failure_point == PublicationFailurePoint::AfterContentEvent {
        return Err(Error::engine(
            "injected derivation failure after content event",
        ));
    }

    input.revision.output_ref = DerivationOutputRef {
        output_kind: "content_event".into(),
        event_id: output_event_id,
        sha256: output_sha256,
    };
    let revision_event = append_derivation_event_in(
        tx,
        NewDerivationEvent::authored(
            input.revision_idempotency_key,
            input.actor.clone(),
            input.run_key.clone(),
            input.reason.clone(),
            DerivationEventPayload::RevisionCompleted(input.revision.clone()),
        )?,
    )
    .await?;
    if failure_point == PublicationFailurePoint::AfterRevisionEvent {
        return Err(Error::engine(
            "injected derivation failure after revision event",
        ));
    }
    let publication_event = append_derivation_event_in(
        tx,
        NewDerivationEvent::authored(
            input.publication_idempotency_key,
            input.actor,
            input.run_key,
            input.reason,
            DerivationEventPayload::TargetPublished(DerivationTargetPublished {
                publication_id: input.publication_id,
                binding_id: input.binding_id,
                series_id: input.revision.series_id.clone(),
                revision_id: input.revision.id.clone(),
                target: input.target,
                expected_generation: input.expected_generation,
                expected_target_version: input.expected_target_version,
                output_ref: input.revision.output_ref,
            }),
        )?,
    )
    .await?;
    if failure_point == PublicationFailurePoint::AfterPublicationEvent {
        return Err(Error::engine(
            "injected derivation failure after publication event",
        ));
    }
    Ok(PublishedRecordBodyRevision {
        content_event,
        revision_event,
        publication_event,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationTargetHead {
    pub generation: i64,
    pub target_version: i64,
    pub active_binding_id: Option<String>,
    pub selected_publication_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationBindingInspection {
    pub binding_id: String,
    pub series_id: String,
    pub generation: i64,
    pub bound_event_id: String,
    pub detached_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationPublicationInspection {
    pub publication_id: String,
    pub binding_id: String,
    pub generation: i64,
    pub target_version: i64,
    pub revision_id: String,
    pub output_event_id: String,
    pub output_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationTargetInspection {
    pub target: DerivationTarget,
    pub head: Option<DerivationTargetHead>,
    pub bindings: Vec<DerivationBindingInspection>,
    pub publications: Vec<DerivationPublicationInspection>,
}

/// Read the current owner/selection and retained binding/publication history
/// for an explicit derived slot. This is the product-neutral observability
/// surface used by higher-level tools rather than title or kind heuristics.
pub async fn inspect_target(
    db: &Db,
    principal: Principal<'_>,
    target: DerivationTarget,
) -> Result<DerivationTargetInspection> {
    validate_target(&target)?;
    let mut snapshot = db.pool().begin().await?;
    crate::authorization::require_capability_on(
        &mut snapshot,
        principal,
        &target.record_id,
        Capability::View,
    )
    .await?;
    let head = sqlx::query(
        "SELECT generation,target_version,active_binding_id,selected_publication_id
           FROM derivation_target_heads
          WHERE target_kind=? AND target_record_id=? AND target_slot=?",
    )
    .bind(&target.target_kind)
    .bind(&target.record_id)
    .bind(&target.slot)
    .fetch_optional(&mut *snapshot)
    .await?
    .map(|row| {
        Ok::<_, sqlx::Error>(DerivationTargetHead {
            generation: row.try_get("generation")?,
            target_version: row.try_get("target_version")?,
            active_binding_id: row.try_get("active_binding_id")?,
            selected_publication_id: row.try_get("selected_publication_id")?,
        })
    })
    .transpose()?;
    let bindings = sqlx::query(
        "SELECT binding_id,series_id,generation,bound_event_id,detached_event_id
           FROM derivation_target_bindings
          WHERE target_kind=? AND target_record_id=? AND target_slot=?
          ORDER BY generation",
    )
    .bind(&target.target_kind)
    .bind(&target.record_id)
    .bind(&target.slot)
    .fetch_all(&mut *snapshot)
    .await?
    .into_iter()
    .map(|row| {
        Ok::<_, sqlx::Error>(DerivationBindingInspection {
            binding_id: row.try_get("binding_id")?,
            series_id: row.try_get("series_id")?,
            generation: row.try_get("generation")?,
            bound_event_id: row.try_get("bound_event_id")?,
            detached_event_id: row.try_get("detached_event_id")?,
        })
    })
    .collect::<std::result::Result<Vec<_>, _>>()?;
    let publications = sqlx::query(
        "SELECT p.publication_id,p.binding_id,p.generation,p.target_version,p.revision_id,
                p.output_event_id,p.output_sha256
           FROM derivation_target_publications p
           JOIN derivation_target_bindings b ON b.binding_id=p.binding_id
          WHERE b.target_kind=? AND b.target_record_id=? AND b.target_slot=?
          ORDER BY p.published_event_seq",
    )
    .bind(&target.target_kind)
    .bind(&target.record_id)
    .bind(&target.slot)
    .fetch_all(&mut *snapshot)
    .await?
    .into_iter()
    .map(|row| {
        Ok::<_, sqlx::Error>(DerivationPublicationInspection {
            publication_id: row.try_get("publication_id")?,
            binding_id: row.try_get("binding_id")?,
            generation: row.try_get("generation")?,
            target_version: row.try_get("target_version")?,
            revision_id: row.try_get("revision_id")?,
            output_event_id: row.try_get("output_event_id")?,
            output_sha256: row.try_get("output_sha256")?,
        })
    })
    .collect::<std::result::Result<Vec<_>, _>>()?;
    let inspection = DerivationTargetInspection {
        target,
        head,
        bindings,
        publications,
    };
    snapshot.rollback().await?;
    Ok(inspection)
}
