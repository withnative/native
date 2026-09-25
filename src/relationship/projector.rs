use std::collections::BTreeSet;

use serde_json::json;
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use crate::interchange::{Cell, Section, REVISION, SECTION_FORMAT};
use crate::{Error, Result};

use super::reducer::{AssertionHead, ReductionFacts, RelationshipProposition};
use super::{RelationshipEventPayload, RelationshipEventSpec, StreamKind};

pub(super) async fn validate_transition_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
) -> Result<()> {
    match &spec.payload {
        RelationshipEventPayload::RelationshipCreated(created) => {
            if spec.expected_stream_version != 0 {
                return Err(Error::conflict(
                    "relationship.created.v1 requires an empty relationship stream",
                ));
            }
            let conflict: Option<String> = sqlx::query_scalar(
                "SELECT relationship_id FROM relationships
                 WHERE relationship_origin_db_id=?1 AND type_definition_id=?2
                   AND canonical_proposition_key=?3 AND status='active'",
            )
            .bind(&spec.relationship.relationship_origin_db_id)
            .bind(&created.type_definition_id)
            .bind(&created.canonical_proposition_key)
            .fetch_optional(&mut **tx)
            .await?;
            if conflict.is_some() {
                return Err(Error::conflict(
                    "an active relationship already represents this proposition",
                ));
            }
        }
        RelationshipEventPayload::RelationshipSuperseded(payload) => {
            if payload.successor == spec.relationship {
                return Err(Error::engine("relationship cannot supersede itself"));
            }
            require_relationship_state(tx, spec, "active").await?;
        }
        RelationshipEventPayload::RelationshipRetired(_) => {
            require_relationship_state(tx, spec, "active").await?;
        }
        RelationshipEventPayload::AssertionCreated(created) => {
            if spec.expected_stream_version != 0 {
                return Err(Error::conflict(
                    "assertion.created.v1 requires an empty assertion stream",
                ));
            }
            let relationship = sqlx::query(
                "SELECT relationship_revision,type_definition_id,
                        created_event_issuer_origin_db_id,created_event_id
                 FROM relationships
                 WHERE relationship_origin_db_id=?1 AND relationship_id=?2",
            )
            .bind(&spec.relationship.relationship_origin_db_id)
            .bind(&spec.relationship.relationship_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| Error::engine("assertion references an unknown relationship"))?;
            let revision: i64 = relationship.try_get("relationship_revision")?;
            let definition: String = relationship.try_get("type_definition_id")?;
            let created_issuer: String =
                relationship.try_get("created_event_issuer_origin_db_id")?;
            let created_id: String = relationship.try_get("created_event_id")?;
            if revision != i64::try_from(created.relationship.relationship_revision).unwrap_or(-1)
                || definition != created.origin_admission.relationship_type_definition()
                || created_issuer != created.relationship_created_event.issuer_origin_db_id
                || created_id != created.relationship_created_event.event_id
            {
                return Err(Error::engine(
                    "assertion changed the immutable relationship revision or creation pin",
                ));
            }
            let anchor_exists: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM relationship_endpoints
                 WHERE relationship_origin_db_id=?1 AND relationship_id=?2
                   AND role=?3 AND portable_ref=?4",
            )
            .bind(&spec.relationship.relationship_origin_db_id)
            .bind(&spec.relationship.relationship_id)
            .bind(&created.origin_admission.authority_anchor().endpoint_role)
            .bind(&created.origin_admission.authority_anchor().endpoint_ref)
            .fetch_one(&mut **tx)
            .await?;
            if anchor_exists != 1 {
                return Err(Error::engine(
                    "origin admission authority anchor is not a relationship endpoint",
                ));
            }
            for parent in &created.causal_parents {
                if parent.assertion_issuer_origin_db_id == spec.issuer_origin_db_id
                    && parent.assertion_id == spec.stream_id
                {
                    return Err(Error::engine("assertion cannot causally parent itself"));
                }
                // Missing parents are valid unresolved federation state. If
                // the pinned event is already present, however, its immutable
                // assertion and relationship identities must agree exactly.
                let known = sqlx::query(
                    "SELECT stream_kind,stream_id,stream_version,
                            relationship_origin_db_id,relationship_id
                     FROM relationship_events
                     WHERE issuer_origin_db_id=?1 AND id=?2",
                )
                .bind(&parent.head_event_issuer_origin_db_id)
                .bind(&parent.head_event_id)
                .fetch_optional(&mut **tx)
                .await?;
                if known.is_some_and(|row| {
                    row.try_get::<String, _>("stream_kind").ok().as_deref() != Some("assertion")
                        || row.try_get::<String, _>("stream_id").ok().as_deref()
                            != Some(parent.assertion_id.as_str())
                        || row.try_get::<i64, _>("stream_version").ok()
                            != i64::try_from(parent.head_stream_version).ok()
                        || row
                            .try_get::<String, _>("relationship_origin_db_id")
                            .ok()
                            .as_deref()
                            != Some(spec.relationship.relationship_origin_db_id.as_str())
                        || row.try_get::<String, _>("relationship_id").ok().as_deref()
                            != Some(spec.relationship.relationship_id.as_str())
                }) {
                    return Err(Error::engine(
                        "causal assertion parent pin conflicts with known event identity",
                    ));
                }
            }
        }
        RelationshipEventPayload::AssertionEvidenceAdded(_) => {
            require_assertion_state(tx, spec, &["active"]).await?;
        }
        RelationshipEventPayload::AssertionRetracted(_) => {
            require_assertion_state(tx, spec, &["active"]).await?;
        }
        RelationshipEventPayload::AssertionInvalidated(_) => {
            require_assertion_state(tx, spec, &["active"]).await?;
        }
        RelationshipEventPayload::AssertionRestored(_) => {
            require_assertion_state(tx, spec, &["invalidated"]).await?;
        }
    }
    Ok(())
}

async fn require_relationship_state(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
    expected: &str,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT status,stream_version FROM relationships
         WHERE relationship_origin_db_id=?1 AND relationship_id=?2",
    )
    .bind(&spec.relationship.relationship_origin_db_id)
    .bind(&spec.relationship.relationship_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine("relationship stream has no creation event"))?;
    let state: String = row.try_get("status")?;
    let projected_version: i64 = row.try_get("stream_version")?;
    if state != expected || projected_version != spec.expected_stream_version {
        return Err(Error::conflict(format!(
            "illegal relationship transition from state '{state}'"
        )));
    }
    Ok(())
}

async fn require_assertion_state(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
    expected: &[&str],
) -> Result<()> {
    let row = sqlx::query(
        "SELECT relationship_origin_db_id,relationship_id,relationship_revision,state,stream_version
         FROM relationship_assertion_heads
         WHERE issuer_origin_db_id=?1 AND assertion_id=?2",
    )
    .bind(&spec.issuer_origin_db_id)
    .bind(&spec.stream_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine("assertion stream has no creation event"))?;
    let origin: String = row.try_get("relationship_origin_db_id")?;
    let relationship_id: String = row.try_get("relationship_id")?;
    let revision: i64 = row.try_get("relationship_revision")?;
    let state: String = row.try_get("state")?;
    let projected_version: i64 = row.try_get("stream_version")?;
    if origin != spec.relationship.relationship_origin_db_id
        || relationship_id != spec.relationship.relationship_id
        || revision != i64::try_from(spec.relationship.relationship_revision).unwrap_or(-1)
    {
        return Err(Error::conflict(
            "assertion event changed its immutable relationship coordinate",
        ));
    }
    if !expected.contains(&state.as_str()) || projected_version != spec.expected_stream_version {
        return Err(Error::conflict(format!(
            "illegal assertion transition from state '{state}'"
        )));
    }
    Ok(())
}

pub(super) async fn apply_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
    stream_version: i64,
) -> Result<()> {
    match &spec.payload {
        RelationshipEventPayload::RelationshipCreated(created) => {
            let qualifiers = String::from_utf8(crate::derivation::canonical_json(
                &serde_json::Value::Object(created.identity_qualifiers.clone()),
            ))
            .expect("canonical JSON is UTF-8");
            sqlx::query(
                "INSERT INTO relationships
                 (relationship_origin_db_id,relationship_id,relationship_revision,
                  relationship_type,type_definition_id,canonical_proposition_key,
                  endpoint_semantics,identity_qualifiers,reducer_id,reducer_version,
                  stream_version,status,successor_origin_db_id,successor_relationship_id,
                  created_event_issuer_origin_db_id,created_event_id,
                  last_event_issuer_origin_db_id,last_event_id,occurred_at)
                 VALUES(?1,?2,1,?3,?4,?5,?6,?7,?8,?9,?10,'active',NULL,NULL,
                        ?11,?12,?11,?12,?13)",
            )
            .bind(&spec.relationship.relationship_origin_db_id)
            .bind(&spec.relationship.relationship_id)
            .bind(&created.relationship_type)
            .bind(&created.type_definition_id)
            .bind(&created.canonical_proposition_key)
            .bind(match created.endpoint_semantics {
                super::EndpointSemantics::Directed => "directed",
                super::EndpointSemantics::Symmetric => "symmetric",
            })
            .bind(qualifiers)
            .bind(&created.reducer_id)
            .bind(i64::try_from(created.reducer_version).unwrap_or(i64::MAX))
            .bind(stream_version)
            .bind(&spec.issuer_origin_db_id)
            .bind(&spec.event_id)
            .bind(&spec.occurred_at)
            .execute(&mut **tx)
            .await?;
            for (ordinal, endpoint) in created.endpoints.iter().enumerate() {
                sqlx::query(
                    "INSERT INTO relationship_endpoints
                     (relationship_origin_db_id,relationship_id,ordinal,role,portable_ref,
                      record_type,record_kind,record_id)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                )
                .bind(&spec.relationship.relationship_origin_db_id)
                .bind(&spec.relationship.relationship_id)
                .bind(i64::try_from(ordinal).unwrap_or(i64::MAX))
                .bind(&endpoint.role)
                .bind(&endpoint.portable_ref)
                .bind(endpoint.record_type.as_deref())
                .bind(endpoint.record_kind.as_deref())
                .bind(endpoint.record_id.as_deref())
                .execute(&mut **tx)
                .await?;
            }
            if let Some(legacy) = &created.legacy_link {
                let source_facts = String::from_utf8(crate::derivation::canonical_json(
                    &serde_json::to_value(&legacy.source_facts)?,
                ))
                .expect("canonical JSON is UTF-8");
                sqlx::query(
                    "INSERT INTO relationship_legacy_links
                     (relationship_origin_db_id,relationship_id,relationship_token,note,
                      created_at,source_facts) VALUES(?1,?2,?3,?4,?5,?6)",
                )
                .bind(&spec.relationship.relationship_origin_db_id)
                .bind(&spec.relationship.relationship_id)
                .bind(&legacy.relationship_token)
                .bind(legacy.note.as_deref())
                .bind(&legacy.created_at)
                .bind(source_facts)
                .execute(&mut **tx)
                .await?;
            }
        }
        RelationshipEventPayload::RelationshipSuperseded(payload) => {
            update_relationship_head(
                tx,
                spec,
                stream_version,
                "superseded",
                Some(&payload.successor),
            )
            .await?;
        }
        RelationshipEventPayload::RelationshipRetired(_) => {
            update_relationship_head(tx, spec, stream_version, "retired", None).await?;
        }
        RelationshipEventPayload::AssertionCreated(created) => {
            let origin_admission = String::from_utf8(crate::derivation::canonical_json(
                &serde_json::to_value(&created.origin_admission)?,
            ))
            .expect("canonical JSON is UTF-8");
            let causal_parents = String::from_utf8(crate::derivation::canonical_json(
                &serde_json::to_value(&created.causal_parents)?,
            ))
            .expect("canonical JSON is UTF-8");
            sqlx::query(
                "INSERT INTO relationship_assertion_heads
                 (issuer_origin_db_id,assertion_id,relationship_origin_db_id,relationship_id,
                  relationship_revision,relationship_created_event_issuer_origin_db_id,
                  relationship_created_event_id,stream_version,stance,semantic_claimant,
                  on_behalf_of,rationale,valid_from,valid_until,causal_parents,origin_admission,
                  authoring_action_attestation_id,state,created_event_issuer_origin_db_id,
                  created_event_id,last_event_issuer_origin_db_id,last_event_id,occurred_at)
                 VALUES(?1,?2,?3,?4,1,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                        'active',?1,?17,?1,?17,?18)",
            )
            .bind(&spec.issuer_origin_db_id)
            .bind(&spec.stream_id)
            .bind(&spec.relationship.relationship_origin_db_id)
            .bind(&spec.relationship.relationship_id)
            .bind(&created.relationship_created_event.issuer_origin_db_id)
            .bind(&created.relationship_created_event.event_id)
            .bind(stream_version)
            .bind(&created.stance)
            .bind(&created.semantic_claimant)
            .bind(created.on_behalf_of.as_deref())
            .bind(created.rationale.as_deref())
            .bind(created.valid_from.as_deref())
            .bind(created.valid_until.as_deref())
            .bind(causal_parents)
            .bind(origin_admission)
            .bind(&created.authoring_action_attestation_id)
            .bind(&spec.event_id)
            .bind(&spec.occurred_at)
            .execute(&mut **tx)
            .await?;
            let evidence_digest = crate::provenance::digest_json(&json!({
                "schema_version": 1,
                "origin_admission": created.origin_admission,
                "receiver_verification": "unresolved",
                "local_policy_version": 1,
            }));
            sqlx::query(
                "INSERT INTO relationship_local_admissions
                 (issuer_origin_db_id,assertion_id,local_admission_state,
                  local_admission_class,type_definition_id,local_policy_version,
                  local_reason,local_evidence_digest,recomputed_at)
                 VALUES(?1,?2,'unresolved',NULL,?3,1,
                        'origin admission is not receiver-local verified authority',?4,?5)",
            )
            .bind(&spec.issuer_origin_db_id)
            .bind(&spec.stream_id)
            .bind(created.origin_admission.relationship_type_definition())
            .bind(evidence_digest)
            .bind(&spec.occurred_at)
            .execute(&mut **tx)
            .await?;
        }
        RelationshipEventPayload::AssertionEvidenceAdded(_) => {
            update_assertion_head(tx, spec, stream_version, None).await?;
        }
        RelationshipEventPayload::AssertionRetracted(_) => {
            update_assertion_head(tx, spec, stream_version, Some("retracted")).await?;
        }
        RelationshipEventPayload::AssertionInvalidated(_) => {
            update_assertion_head(tx, spec, stream_version, Some("invalidated")).await?;
        }
        RelationshipEventPayload::AssertionRestored(_) => {
            update_assertion_head(tx, spec, stream_version, Some("active")).await?;
        }
    }
    project_endpoint_activity_in(tx, spec).await?;
    recompute_relationship_in(
        tx,
        &spec.relationship.relationship_origin_db_id,
        &spec.relationship.relationship_id,
    )
    .await?;
    Ok(())
}

/// Project an immutable foreign event using only receiver-resolved endpoint
/// bindings. Origin-local `record_id` values remain in the canonical event but
/// never become destination references merely because their text collides.
pub(super) async fn apply_federated_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
    stream_version: i64,
) -> Result<()> {
    let mut projected = spec.clone();
    if let RelationshipEventPayload::RelationshipCreated(created) = &mut projected.payload {
        for endpoint in &mut created.endpoints {
            endpoint.record_id = resolve_receiver_endpoint_in(tx, endpoint).await?;
        }
    }
    apply_event_in(tx, &projected, stream_version).await
}

async fn resolve_receiver_endpoint_in(
    tx: &mut Transaction<'_, Sqlite>,
    endpoint: &super::RelationshipEndpoint,
) -> Result<Option<String>> {
    let (origin, origin_record_id) = crate::identity::decode_native_record(&endpoint.portable_ref)?;
    let local_origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    let candidate: Option<String> = if origin == local_origin {
        sqlx::query_scalar("SELECT id FROM records WHERE id=?1")
            .bind(&origin_record_id)
            .fetch_optional(&mut **tx)
            .await?
    } else {
        sqlx::query_scalar(
            "SELECT record_id FROM bindings
              WHERE system='native-record' AND identifier=?1",
        )
        .bind(&endpoint.portable_ref)
        .fetch_optional(&mut **tx)
        .await?
    };
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let shape: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT type,kind FROM records WHERE id=?1")
            .bind(&candidate)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((record_type, record_kind)) = shape else {
        return Ok(None);
    };
    if endpoint
        .record_type
        .as_deref()
        .is_some_and(|expected| expected != record_type)
        || endpoint
            .record_kind
            .as_deref()
            .is_some_and(|expected| Some(expected) != record_kind.as_deref())
    {
        return Ok(None);
    }
    Ok(Some(candidate))
}

async fn project_endpoint_activity_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO relationship_endpoint_activity
         (relationship_origin_db_id,relationship_id,event_issuer_origin_db_id,event_id,
          endpoint_ordinal,endpoint_role,portable_ref,record_id,event_type,occurred_at)
         SELECT relationship_origin_db_id,relationship_id,?1,?2,ordinal,role,
                portable_ref,record_id,?3,?4
           FROM relationship_endpoints
          WHERE relationship_origin_db_id=?5 AND relationship_id=?6",
    )
    .bind(&spec.issuer_origin_db_id)
    .bind(&spec.event_id)
    .bind(spec.payload.event_type())
    .bind(&spec.occurred_at)
    .bind(&spec.relationship.relationship_origin_db_id)
    .bind(&spec.relationship.relationship_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn project_receiver_local_admissions_for_outputs_in(
    tx: &mut Transaction<'_, Sqlite>,
    outputs: &[crate::provenance::ActionOutput],
) -> Result<()> {
    let local_origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    for output in outputs {
        if output.domain != crate::provenance::OutputDomain::Relationship {
            continue;
        }
        refresh_receiver_local_admission_for_event_in(tx, &local_origin, &output.event_id).await?;
    }
    Ok(())
}

pub(crate) async fn refresh_receiver_local_admissions_for_attestation_in(
    tx: &mut Transaction<'_, Sqlite>,
    attestation_id: &str,
) -> Result<()> {
    let events = sqlx::query_as::<_, (String, String)>(
        "SELECT issuer_origin_db_id,id FROM relationship_events
          WHERE type='assertion.created.v1'
            AND json_extract(payload,'$.authoring_action_attestation_id')=?1
          ORDER BY issuer_origin_db_id,id",
    )
    .bind(attestation_id)
    .fetch_all(&mut **tx)
    .await?;
    for (issuer_origin_db_id, event_id) in events {
        refresh_receiver_local_admission_for_event_in(tx, &issuer_origin_db_id, &event_id).await?;
    }
    Ok(())
}

async fn refresh_receiver_local_admission_for_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    issuer_origin_db_id: &str,
    event_id: &str,
) -> Result<()> {
    let Some(row) = sqlx::query(
        "SELECT issuer_origin_db_id,stream_id,relationship_origin_db_id,relationship_id,type,payload
           FROM relationship_events WHERE issuer_origin_db_id=?1 AND id=?2",
    )
    .bind(issuer_origin_db_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(());
    };
    let event_type: String = row.try_get("type")?;
    if event_type != "assertion.created.v1" {
        return Ok(());
    }
    let issuer: String = row.try_get("issuer_origin_db_id")?;
    let assertion_id: String = row.try_get("stream_id")?;
    let payload = super::parse_event_payload(
        &event_type,
        serde_json::from_str(&row.try_get::<String, _>("payload")?)?,
    )?;
    let RelationshipEventPayload::AssertionCreated(created) = payload else {
        return Ok(());
    };
    let verified = crate::provenance::verify_receiver_local_assertion_admission_in(
        tx,
        &issuer,
        event_id,
        &created.origin_admission,
    )
    .await?;
    set_receiver_local_admission_in(
        tx,
        &issuer,
        &assertion_id,
        &created.relationship,
        &created.origin_admission,
        verified,
    )
    .await
}

async fn set_receiver_local_admission_in(
    tx: &mut Transaction<'_, Sqlite>,
    assertion_issuer_origin_db_id: &str,
    assertion_id: &str,
    relationship: &super::RelationshipCoordinate,
    origin_admission: &super::OriginAdmissionV1,
    verified: bool,
) -> Result<()> {
    let recomputed_at: String = sqlx::query_scalar(
        "SELECT occurred_at FROM relationship_assertion_heads
          WHERE issuer_origin_db_id=?1 AND assertion_id=?2",
    )
    .bind(assertion_issuer_origin_db_id)
    .bind(assertion_id)
    .fetch_one(&mut **tx)
    .await?;
    let state = if verified { "admitted" } else { "unresolved" };
    let class = verified.then(|| origin_admission.admission_class());
    let reason = if verified {
        "receiver verified local issuance, current validity, and v2 output membership"
    } else {
        "origin admission is not receiver-local verified authority"
    };
    let evidence_digest = crate::provenance::digest_json(&json!({
        "schema_version": 1,
        "origin_admission": origin_admission,
        "receiver_verification": state,
        "local_policy_version": 1,
    }));
    sqlx::query(
        "INSERT INTO relationship_local_admissions
         (issuer_origin_db_id,assertion_id,local_admission_state,local_admission_class,
          type_definition_id,local_policy_version,local_reason,local_evidence_digest,recomputed_at)
         VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8)
         ON CONFLICT(issuer_origin_db_id,assertion_id) DO UPDATE SET
           local_admission_state=excluded.local_admission_state,
           local_admission_class=excluded.local_admission_class,
           type_definition_id=excluded.type_definition_id,
           local_policy_version=excluded.local_policy_version,
           local_reason=excluded.local_reason,
           local_evidence_digest=excluded.local_evidence_digest,
           recomputed_at=excluded.recomputed_at",
    )
    .bind(assertion_issuer_origin_db_id)
    .bind(assertion_id)
    .bind(state)
    .bind(class)
    .bind(origin_admission.relationship_type_definition())
    .bind(reason)
    .bind(evidence_digest)
    .bind(recomputed_at)
    .execute(&mut **tx)
    .await?;
    recompute_relationship_in(
        tx,
        &relationship.relationship_origin_db_id,
        &relationship.relationship_id,
    )
    .await
}

pub(super) async fn recompute_relationship_in(
    tx: &mut Transaction<'_, Sqlite>,
    relationship_origin_db_id: &str,
    relationship_id: &str,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT status,relationship_type,type_definition_id,reducer_id,reducer_version,occurred_at
           FROM relationships WHERE relationship_origin_db_id=?1 AND relationship_id=?2",
    )
    .bind(relationship_origin_db_id)
    .bind(relationship_id)
    .fetch_one(&mut **tx)
    .await?;
    let status: String = row.try_get("status")?;
    let relationship_type: String = row.try_get("relationship_type")?;
    let type_definition_id: String = row.try_get("type_definition_id")?;
    let reducer_id: String = row.try_get("reducer_id")?;
    let reducer_version_i64: i64 = row.try_get("reducer_version")?;
    let reducer_version = u64::try_from(reducer_version_i64)
        .map_err(|_| Error::engine("invalid relationship reducer version"))?;
    let relationship_occurred_at: String = row.try_get("occurred_at")?;
    let mut recomputed_at = relationship_occurred_at.clone();
    let rows = sqlx::query(
        "SELECT a.issuer_origin_db_id,a.assertion_id,a.stream_version,a.stance,a.state,
                a.causal_parents,a.last_event_issuer_origin_db_id,a.last_event_id,a.occurred_at,
                COALESCE(l.local_admission_state,'unresolved') AS local_admission_state,
                l.local_admission_class,COALESCE(l.local_policy_version,1) AS local_policy_version,
                l.local_evidence_digest
           FROM relationship_assertion_heads a
           LEFT JOIN relationship_local_admissions l
             ON l.issuer_origin_db_id=a.issuer_origin_db_id AND l.assertion_id=a.assertion_id
          WHERE a.relationship_origin_db_id=?1 AND a.relationship_id=?2
          ORDER BY a.issuer_origin_db_id,a.assertion_id",
    )
    .bind(relationship_origin_db_id)
    .bind(relationship_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut heads = Vec::with_capacity(rows.len());
    for row in rows {
        let occurred_at: String = row.try_get("occurred_at")?;
        if occurred_at > recomputed_at {
            recomputed_at = occurred_at;
        }
        let causal_parents: Vec<super::CausalAssertionParent> =
            serde_json::from_str(&row.try_get::<String, _>("causal_parents")?)?;
        let causal_parents_resolved = causal_parents_resolved_in(
            tx,
            relationship_origin_db_id,
            relationship_id,
            &causal_parents,
        )
        .await?;
        heads.push(AssertionHead {
            issuer_origin_db_id: row.try_get("issuer_origin_db_id")?,
            assertion_id: row.try_get("assertion_id")?,
            stream_version: u64::try_from(row.try_get::<i64, _>("stream_version")?)
                .map_err(|_| Error::engine("invalid assertion stream version"))?,
            stance: row.try_get("stance")?,
            state: row.try_get("state")?,
            causal_parents,
            causal_parents_resolved,
            last_event_issuer_origin_db_id: row.try_get("last_event_issuer_origin_db_id")?,
            last_event_id: row.try_get("last_event_id")?,
            local_admission_state: row.try_get("local_admission_state")?,
            local_admission_class: row.try_get("local_admission_class")?,
            local_policy_version: u64::try_from(row.try_get::<i64, _>("local_policy_version")?)
                .map_err(|_| Error::engine("invalid local relationship policy version"))?,
            local_evidence_digest: row.try_get("local_evidence_digest")?,
        });
    }
    let assertion_set_digest = crate::provenance::digest_json(&serde_json::to_value(&heads)?);
    let watermark = heads
        .iter()
        .map(|head| {
            json!({
                "assertion_issuer_origin_db_id": head.issuer_origin_db_id,
                "assertion_id": head.assertion_id,
                "stream_version": head.stream_version,
                "head_event_issuer_origin_db_id": head.last_event_issuer_origin_db_id,
                "head_event_id": head.last_event_id,
            })
        })
        .collect::<Vec<_>>();
    let knowledge_watermark =
        String::from_utf8(crate::derivation::canonical_json(&json!(watermark)))
            .expect("canonical JSON is UTF-8");
    super::reducer::validate_reducer(&reducer_id, reducer_version)?;
    let endpoints_resolved = if status == "active" {
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM relationship_endpoints
              WHERE relationship_origin_db_id=?1 AND relationship_id=?2 AND record_id IS NULL)",
        )
        .bind(relationship_origin_db_id)
        .bind(relationship_id)
        .fetch_one(&mut **tx)
        .await?
    } else {
        true
    };
    let outcome = super::reducer::reduce_effective_relationship(ReductionFacts {
        reducer_id: &reducer_id,
        reducer_version,
        relationship_active: status == "active",
        endpoints_resolved,
        proposition: RelationshipProposition {
            relationship_type: &relationship_type,
            type_definition_id: &type_definition_id,
        },
        heads: &heads,
    })?;
    let admission_counts = String::from_utf8(crate::derivation::canonical_json(
        &serde_json::to_value(&outcome.admission_counts)?,
    ))
    .expect("canonical JSON is UTF-8");
    sqlx::query(
        "INSERT INTO effective_relationships
         (relationship_origin_db_id,relationship_id,effective_state,epistemic_state,
          support_count,contest_count,admission_counts,reducer_id,reducer_version,
          assertion_set_digest,knowledge_watermark,recomputed_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
         ON CONFLICT(relationship_origin_db_id,relationship_id) DO UPDATE SET
           effective_state=excluded.effective_state,
           epistemic_state=excluded.epistemic_state,
           support_count=excluded.support_count,
           contest_count=excluded.contest_count,
           admission_counts=excluded.admission_counts,
           reducer_id=excluded.reducer_id,reducer_version=excluded.reducer_version,
           assertion_set_digest=excluded.assertion_set_digest,
           knowledge_watermark=excluded.knowledge_watermark,
           recomputed_at=excluded.recomputed_at",
    )
    .bind(relationship_origin_db_id)
    .bind(relationship_id)
    .bind(outcome.effective_state)
    .bind(outcome.epistemic_state)
    .bind(i64::try_from(outcome.support_count).unwrap_or(i64::MAX))
    .bind(i64::try_from(outcome.contest_count).unwrap_or(i64::MAX))
    .bind(admission_counts)
    .bind(&reducer_id)
    .bind(reducer_version_i64)
    .bind(assertion_set_digest)
    .bind(knowledge_watermark)
    .bind(&recomputed_at)
    .execute(&mut **tx)
    .await?;
    project_compatibility_link_in(
        tx,
        relationship_origin_db_id,
        relationship_id,
        outcome.effective_state,
        &relationship_occurred_at,
    )
    .await
}

pub(super) async fn causal_parents_resolved_in(
    tx: &mut Transaction<'_, Sqlite>,
    relationship_origin_db_id: &str,
    relationship_id: &str,
    parents: &[super::CausalAssertionParent],
) -> Result<bool> {
    for parent in parents {
        let resolved: bool = sqlx::query_scalar(
            "SELECT EXISTS(
               SELECT 1 FROM relationship_events
                WHERE issuer_origin_db_id=?1 AND id=?2
                  AND stream_kind='assertion' AND stream_id=?3 AND stream_version=?4
                  AND relationship_origin_db_id=?5 AND relationship_id=?6)",
        )
        .bind(&parent.head_event_issuer_origin_db_id)
        .bind(&parent.head_event_id)
        .bind(&parent.assertion_id)
        .bind(i64::try_from(parent.head_stream_version).unwrap_or(i64::MAX))
        .bind(relationship_origin_db_id)
        .bind(relationship_id)
        .fetch_one(&mut **tx)
        .await?;
        if !resolved {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn project_compatibility_link_in(
    tx: &mut Transaction<'_, Sqlite>,
    relationship_origin_db_id: &str,
    relationship_id: &str,
    effective_state: &str,
    recomputed_at: &str,
) -> Result<()> {
    let link_id = format!("rel:{relationship_origin_db_id}:{relationship_id}");
    sqlx::query("DELETE FROM links WHERE id=?1")
        .bind(&link_id)
        .execute(&mut **tx)
        .await?;
    if effective_state != "active" {
        return Ok(());
    }
    let relationship: (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT r.relationship_type,r.endpoint_semantics,l.relationship_token,l.note,l.created_at
           FROM relationships r LEFT JOIN relationship_legacy_links l
             ON l.relationship_origin_db_id=r.relationship_origin_db_id
            AND l.relationship_id=r.relationship_id
          WHERE r.relationship_origin_db_id=?1 AND r.relationship_id=?2",
    )
    .bind(relationship_origin_db_id)
    .bind(relationship_id)
    .fetch_one(&mut **tx)
    .await?;
    let endpoints = sqlx::query(
        "SELECT role,portable_ref,record_id FROM relationship_endpoints
          WHERE relationship_origin_db_id=?1 AND relationship_id=?2
          ORDER BY ordinal",
    )
    .bind(relationship_origin_db_id)
    .bind(relationship_id)
    .fetch_all(&mut **tx)
    .await?;
    if endpoints.len() != 2
        || endpoints.iter().any(|endpoint| {
            endpoint
                .try_get::<Option<String>, _>("record_id")
                .ok()
                .flatten()
                .is_none()
        })
    {
        return Ok(());
    }
    let mut resolved = endpoints
        .iter()
        .map(|endpoint| {
            Ok((
                endpoint.try_get::<String, _>("role")?,
                endpoint.try_get::<String, _>("portable_ref")?,
                endpoint.try_get::<String, _>("record_id")?,
            ))
        })
        .collect::<std::result::Result<Vec<_>, sqlx::Error>>()?;
    if resolved.iter().all(|endpoint| endpoint.0 == "participant") {
        resolved.sort_by(|left, right| left.1.cmp(&right.1));
    } else {
        resolved.sort_by_key(|endpoint| match endpoint.0.as_str() {
            "subject" => 0,
            "object" => 1,
            _ => 2,
        });
    }
    let source_id = &resolved[0].2;
    let target_id = &resolved[1].2;
    let relationship_type = relationship.2.unwrap_or(relationship.0);
    let symmetric = relationship.1 == "symmetric";
    let occupied: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM links
          WHERE id<>?5 AND relationship=?3 AND
                ((source_id=?1 AND target_id=?2)
                 OR (?4 AND source_id=?2 AND target_id=?1)))",
    )
    .bind(source_id)
    .bind(target_id)
    .bind(&relationship_type)
    .bind(symmetric)
    .bind(&link_id)
    .fetch_one(&mut **tx)
    .await?;
    if occupied {
        // A content-owned legacy row retains this compatibility coordinate
        // until the explicit link cutover migration transfers ownership.
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO links(id,source_id,target_id,relationship,note,created_at)
         VALUES(?1,?2,?3,?4,?5,?6)",
    )
    .bind(link_id)
    .bind(source_id)
    .bind(target_id)
    .bind(relationship_type)
    .bind(relationship.3.as_deref())
    .bind(relationship.4.as_deref().unwrap_or(recomputed_at))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct ReceiverAdmissionDecision {
    pub assertion_event_issuer_origin_db_id: String,
    pub assertion_created_event_id: String,
    pub verified: bool,
}

/// One authoritative relationship-log row prepared for replay. `act` is not
/// part of the relationship event's origin fingerprint, but it is canonical
/// workspace commit grouping and must survive a local rebuild exactly,
/// including legacy rows whose grouping is unknown (`NULL`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RelationshipReplayEvent {
    pub(crate) event: RelationshipEventSpec,
    pub(crate) act: Option<i64>,
}

impl std::ops::Deref for RelationshipReplayEvent {
    type Target = RelationshipEventSpec;

    fn deref(&self) -> &Self::Target {
        &self.event
    }
}

pub(crate) async fn read_all_relationship_events(
    conn: &mut SqliteConnection,
) -> Result<Vec<RelationshipReplayEvent>> {
    let rows = sqlx::query(
        "SELECT id,stream_id,stream_version,relationship_origin_db_id,relationship_id,
                type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at,act
           FROM relationship_events ORDER BY seq",
    )
    .fetch_all(conn)
    .await?;
    rows.iter().map(relationship_event_spec_from_row).collect()
}

/// Read the relationship log prefix at or before `max_seq`, in commit order.
/// Idempotent receipt reconstruction replays exactly this prefix into a
/// scratch projection so the rebuilt receipt reflects the attested command,
/// not later stream writes. Prefix-closure is what makes the replay's stream
/// CAS succeed: versions are assigned in commit order, so every replayed
/// event's predecessors are in the prefix too.
pub(crate) async fn read_relationship_event_prefix(
    conn: &mut SqliteConnection,
    max_seq: i64,
) -> Result<Vec<RelationshipReplayEvent>> {
    let rows = sqlx::query(
        "SELECT id,stream_id,stream_version,relationship_origin_db_id,relationship_id,
                type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at,act
           FROM relationship_events WHERE seq <= ? ORDER BY seq",
    )
    .bind(max_seq)
    .fetch_all(conn)
    .await?;
    rows.iter().map(relationship_event_spec_from_row).collect()
}

/// The relationship-only act-range reader: exactly the rows whose `act` falls
/// in the half-open interval `(from_exclusive_act, to_inclusive_act]`, in `seq`
/// order, decoded by the same [`relationship_event_spec_from_row`] the full
/// reader uses. Legacy rows whose act is `NULL` never satisfy the strict
/// `act > ?` predicate and are excluded.
#[allow(dead_code)] // R3 wires the bounded fold; the reader lands ahead of its caller.
pub(crate) async fn relationship_events_in_act_range(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Vec<RelationshipReplayEvent>> {
    let rows = sqlx::query(
        "SELECT id,stream_id,stream_version,relationship_origin_db_id,relationship_id,
                type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at,act
           FROM relationship_events WHERE act > ? AND act <= ? ORDER BY seq",
    )
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
    .fetch_all(conn)
    .await?;
    rows.iter().map(relationship_event_spec_from_row).collect()
}

fn relationship_event_spec_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<RelationshipReplayEvent> {
    let event_type: String = row.try_get("type")?;
    let stream_version: i64 = row.try_get("stream_version")?;
    let event = RelationshipEventSpec {
        event_id: row.try_get("id")?,
        stream_id: row.try_get("stream_id")?,
        expected_stream_version: stream_version - 1,
        relationship: super::RelationshipCoordinate {
            relationship_origin_db_id: row.try_get("relationship_origin_db_id")?,
            relationship_id: row.try_get("relationship_id")?,
            relationship_revision: 1,
        },
        payload: super::parse_event_payload(
            &event_type,
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?,
        )?,
        actor: row.try_get("actor")?,
        issuer_origin_db_id: row.try_get("issuer_origin_db_id")?,
        occurred_at: row.try_get("occurred_at")?,
        ingested_at: row.try_get("ingested_at")?,
    };
    Ok(RelationshipReplayEvent {
        event,
        act: row.try_get("act")?,
    })
}

/// The canonical interchange table name of the co-located relationship /
/// assertion authority log.
const RELATIONSHIP_EVENTS_SECTION: &str = "relationship_events";

/// The exact canonical interchange columns of the carried `relationship_events`
/// act section, in the live-schema order the authority act-range reader emits.
///
/// Names *and* declared types are pinned together, so no cell is ever read by
/// position before the column list has been proven: a tampered section cannot
/// relabel one column as another, and a schema drift cannot silently reorder a
/// value into the wrong envelope field.
const RELATIONSHIP_EVENTS_SECTION_COLUMNS: [(&str, &str); 14] = [
    ("seq", "INTEGER"),
    ("id", "TEXT"),
    ("stream_kind", "TEXT"),
    ("stream_id", "TEXT"),
    ("stream_version", "INTEGER"),
    ("relationship_origin_db_id", "TEXT"),
    ("relationship_id", "TEXT"),
    ("type", "TEXT"),
    ("payload", "TEXT"),
    ("actor", "TEXT"),
    ("issuer_origin_db_id", "TEXT"),
    ("occurred_at", "TEXT"),
    ("ingested_at", "TEXT"),
    ("act", "INTEGER"),
];

const RELATIONSHIP_EVENTS_SECTION_PRIMARY_KEY: [&str; 1] = ["seq"];

/// The canonical table name of the receiver-local federation-evidence
/// companion carried alongside the relationship act section.
const RELATIONSHIP_FEDERATION_EVENTS_SECTION: &str = "relationship_federation_events";

const RELATIONSHIP_FEDERATION_EVENTS_SECTION_COLUMNS: [(&str, &str); 9] = [
    ("issuer_origin_db_id", "TEXT"),
    ("event_id", "TEXT"),
    ("fingerprint", "TEXT"),
    ("source_batch_origin_db_id", "TEXT"),
    ("envelope_id", "TEXT"),
    ("authenticated_peer_principal", "TEXT"),
    ("origin_trust_state", "TEXT"),
    ("origin_evidence_state", "TEXT"),
    ("received_at", "TEXT"),
];

const RELATIONSHIP_FEDERATION_EVENTS_SECTION_PRIMARY_KEY: [&str; 2] =
    ["issuer_origin_db_id", "event_id"];

/// Fail-closed pin of one carried section's identity and shape before any
/// positional cell is read: exact table name, current canonical format and
/// revision, the exact ordered column list (name and declared type), and the
/// exact ordered declared primary key.
///
/// Row width, cell storage-class validity, primary-key reachability and
/// strictly increasing primary-key order (which also rejects duplicate primary
/// keys) are delegated to the shared canonical
/// [`crate::interchange::validate_section_shape`] helper, so this decode path
/// reuses the one canonical cell validator rather than a second permissive
/// codec.
fn pin_relationship_section(
    section: &Section,
    table: &str,
    columns: &[(&str, &str)],
    primary_key: &[&str],
) -> Result<()> {
    if section.name != table {
        return Err(Error::engine(format!(
            "carried relationship section is '{}', not '{table}'",
            section.name
        )));
    }
    if section.format != SECTION_FORMAT || section.revision != REVISION {
        return Err(Error::engine(format!(
            "carried '{table}' section is not current canonical interchange"
        )));
    }
    if section.columns.len() != columns.len()
        || section
            .columns
            .iter()
            .zip(columns.iter())
            .any(|(column, (name, declared_type))| {
                column.name != *name || column.declared_type != *declared_type
            })
    {
        return Err(Error::engine(format!(
            "carried '{table}' section columns do not match the canonical shape"
        )));
    }
    if section.primary_key.len() != primary_key.len()
        || section
            .primary_key
            .iter()
            .zip(primary_key.iter())
            .any(|(actual, expected)| actual != expected)
    {
        return Err(Error::engine(format!(
            "carried '{table}' section primary key does not match the canonical shape"
        )));
    }
    crate::interchange::validate_section_shape(section)
        .map_err(|error| Error::engine(format!("carried '{table}' section is malformed: {error}")))
}

fn column_index(section: &Section, column: &str) -> Result<usize> {
    section
        .columns
        .iter()
        .position(|candidate| candidate.name == column)
        .ok_or_else(|| {
            Error::engine(format!(
                "carried '{}' section has no {column} column",
                section.name
            ))
        })
}

fn text_cell(section: &Section, row: &[Cell], column: &str) -> Result<String> {
    match row.get(column_index(section, column)?) {
        Some(Cell::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "carried '{}' cell '{column}' is not text",
            section.name
        ))),
    }
}

fn integer_cell(section: &Section, row: &[Cell], column: &str) -> Result<i64> {
    match row.get(column_index(section, column)?) {
        Some(Cell::Integer(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "carried '{}' cell '{column}' is not an integer",
            section.name
        ))),
    }
}

fn optional_integer_cell(section: &Section, row: &[Cell], column: &str) -> Result<Option<i64>> {
    match row.get(column_index(section, column)?) {
        Some(Cell::Integer(value)) => Ok(Some(*value)),
        Some(Cell::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "carried '{}' cell '{column}' is not an integer or null",
            section.name
        ))),
    }
}

/// Decode the carried `relationship_events` act section into the exact typed
/// replay inputs the preserved-act replay seam consumes, in section primary-key
/// (`seq`) order.
///
/// This is the wire-boundary twin of [`relationship_event_spec_from_row`]: it
/// produces the same [`RelationshipEventSpec`] fields and the same
/// [`RelationshipReplayEvent::act`] (`Option<i64>`) as the live bounded reader,
/// but from a validated carried section rather than a SQLite row. The section
/// is pinned by name, format, revision, ordered columns and primary key before
/// any cell is read, and every cell is decoded by its pinned column name. A
/// `NULL` `act` is preserved exactly as `None`: a live `(F1, F2]` authority cut
/// cannot carry one (its act predicate is strict and its rows are act-stamped),
/// but a directly constructed current-revision section may, and replay's
/// legacy grouping-unknown semantics require it round-trips.
pub(crate) fn relationship_replay_events_from_section(
    section: &Section,
) -> Result<Vec<RelationshipReplayEvent>> {
    pin_relationship_section(
        section,
        RELATIONSHIP_EVENTS_SECTION,
        &RELATIONSHIP_EVENTS_SECTION_COLUMNS,
        &RELATIONSHIP_EVENTS_SECTION_PRIMARY_KEY,
    )?;
    section
        .rows
        .iter()
        .map(|row| relationship_replay_event_from_cells(section, row))
        .collect()
}

fn relationship_replay_event_from_cells(
    section: &Section,
    row: &[Cell],
) -> Result<RelationshipReplayEvent> {
    let event_type = text_cell(section, row, "type")?;
    let expected_stream_version = integer_cell(section, row, "stream_version")?
        .checked_sub(1)
        .ok_or_else(|| Error::engine("carried 'relationship_events' stream_version underflows"))?;
    let event = RelationshipEventSpec {
        event_id: text_cell(section, row, "id")?,
        stream_id: text_cell(section, row, "stream_id")?,
        expected_stream_version,
        relationship: super::RelationshipCoordinate {
            relationship_origin_db_id: text_cell(section, row, "relationship_origin_db_id")?,
            relationship_id: text_cell(section, row, "relationship_id")?,
            relationship_revision: 1,
        },
        payload: super::parse_event_payload(
            &event_type,
            serde_json::from_str(&text_cell(section, row, "payload")?)?,
        )?,
        actor: text_cell(section, row, "actor")?,
        issuer_origin_db_id: text_cell(section, row, "issuer_origin_db_id")?,
        occurred_at: text_cell(section, row, "occurred_at")?,
        ingested_at: text_cell(section, row, "ingested_at")?,
    };
    Ok(RelationshipReplayEvent {
        event,
        act: optional_integer_cell(section, row, "act")?,
    })
}

/// Decode the carried `relationship_federation_events` companion section into
/// the exact `(issuer_origin_db_id, event_id)` identity set
/// [`replay_relationship_events`] routes through the receiver-resolved
/// federated path.
///
/// The section is pinned by name, format, revision, ordered columns and
/// primary key before any cell is read. Both identity cells must be `TEXT`, and
/// every identity must be unique and must name a carried relationship event:
/// the companion closure is only reachable through the act section, so a
/// federation row that names no carried event is a fabricated row, not a
/// legitimate federated identity, and is refused.
pub(crate) fn relationship_federation_identities_from_section(
    section: &Section,
    carried_events: &[RelationshipReplayEvent],
) -> Result<BTreeSet<(String, String)>> {
    pin_relationship_section(
        section,
        RELATIONSHIP_FEDERATION_EVENTS_SECTION,
        &RELATIONSHIP_FEDERATION_EVENTS_SECTION_COLUMNS,
        &RELATIONSHIP_FEDERATION_EVENTS_SECTION_PRIMARY_KEY,
    )?;
    let carried = carried_events
        .iter()
        .map(|event| (event.issuer_origin_db_id.as_str(), event.event_id.as_str()))
        .collect::<BTreeSet<_>>();
    let mut identities = BTreeSet::new();
    for row in &section.rows {
        let issuer_origin_db_id = text_cell(section, row, "issuer_origin_db_id")?;
        let event_id = text_cell(section, row, "event_id")?;
        if !carried.contains(&(issuer_origin_db_id.as_str(), event_id.as_str())) {
            return Err(Error::engine(
                "carried relationship_federation_events row does not name a carried relationship event",
            ));
        }
        if !identities.insert((issuer_origin_db_id, event_id)) {
            return Err(Error::engine(
                "carried relationship_federation_events repeats a federation identity",
            ));
        }
    }
    Ok(identities)
}

/// Fold authoritative rows into an empty relationship projection while
/// preserving their workspace acts verbatim. This path deliberately does
/// not advance `act_state`; durable restore callers own that singleton,
/// while conformance and receipt reconstruction use disposable scratch DBs.
pub(crate) async fn replay_relationship_events(
    tx: &mut Transaction<'_, Sqlite>,
    events: &[RelationshipReplayEvent],
    federated_events: &std::collections::BTreeSet<(String, String)>,
) -> Result<()> {
    for event in events {
        if federated_events.contains(&(event.issuer_origin_db_id.clone(), event.event_id.clone())) {
            super::persistence::replay_federated_relationship_event_in(tx, &event.event, event.act)
                .await?;
        } else {
            super::persistence::replay_relationship_event_in(tx, &event.event, event.act).await?;
        }
    }
    Ok(())
}

/// Re-derive receiver-local admission state for exactly the freshly replayed
/// relationship events, in the order they were replayed.
///
/// This is the bounded counterpart of
/// [`initialize_receiver_local_state_after_import_in`]: it never scans the
/// whole relationship log and never recomputes an unrelated relationship. It
/// reuses the same per-event admission seam the live validity and output paths
/// call, so a newly replayed assertion's `relationship_local_admissions` row is
/// upgraded from the placeholder `unresolved` state that `apply_event_in`
/// inserted exactly as the live writer leaves it before the admission refresh.
/// A non-assertion event is a no-op inside the per-event seam.
pub(crate) async fn initialize_receiver_local_state_for_replayed_events_in(
    tx: &mut Transaction<'_, Sqlite>,
    events: &[RelationshipReplayEvent],
) -> Result<()> {
    for event in events {
        refresh_receiver_local_admission_for_event_in(
            tx,
            &event.issuer_origin_db_id,
            &event.event_id,
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn rebuild_receiver_local_state_in(
    tx: &mut Transaction<'_, Sqlite>,
    decisions: &[ReceiverAdmissionDecision],
) -> Result<()> {
    for decision in decisions {
        let row = sqlx::query(
            "SELECT issuer_origin_db_id,stream_id,type,payload
               FROM relationship_events WHERE issuer_origin_db_id=?1 AND id=?2",
        )
        .bind(&decision.assertion_event_issuer_origin_db_id)
        .bind(&decision.assertion_created_event_id)
        .fetch_one(&mut **tx)
        .await?;
        let event_type: String = row.try_get("type")?;
        let payload = super::parse_event_payload(
            &event_type,
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?,
        )?;
        let RelationshipEventPayload::AssertionCreated(created) = payload else {
            return Err(Error::engine(
                "receiver-local rebuild decision does not name assertion creation",
            ));
        };
        set_receiver_local_admission_in(
            tx,
            &row.try_get::<String, _>("issuer_origin_db_id")?,
            &row.try_get::<String, _>("stream_id")?,
            &created.relationship,
            &created.origin_admission,
            decision.verified,
        )
        .await?;
    }
    Ok(())
}

/// Re-derive receiver-local state after canonical portable import. Neither
/// local admission rows nor local attestation-authority anchors are portable,
/// so this can preserve origin evidence while only producing unresolved local
/// decisions unless the receiving database independently has trusted proof.
pub(crate) async fn initialize_receiver_local_state_after_import_in(
    tx: &mut Transaction<'_, Sqlite>,
) -> Result<()> {
    let assertion_events = sqlx::query_as::<_, (String, String)>(
        "SELECT issuer_origin_db_id,id FROM relationship_events
          WHERE type='assertion.created.v1'
          ORDER BY issuer_origin_db_id,id",
    )
    .fetch_all(&mut **tx)
    .await?;
    for (issuer_origin_db_id, event_id) in assertion_events {
        refresh_receiver_local_admission_for_event_in(tx, &issuer_origin_db_id, &event_id).await?;
    }
    let relationships = sqlx::query_as::<_, (String, String)>(
        "SELECT relationship_origin_db_id,relationship_id FROM relationships
          ORDER BY relationship_origin_db_id,relationship_id",
    )
    .fetch_all(&mut **tx)
    .await?;
    for (origin, relationship_id) in relationships {
        recompute_relationship_in(tx, &origin, &relationship_id).await?;
    }
    Ok(())
}

async fn update_relationship_head(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
    stream_version: i64,
    state: &str,
    successor: Option<&super::RelationshipCoordinate>,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE relationships SET stream_version=?1,status=?2,
         successor_origin_db_id=?3,successor_relationship_id=?4,
         last_event_issuer_origin_db_id=?5,last_event_id=?6,occurred_at=?7
         WHERE relationship_origin_db_id=?8 AND relationship_id=?9
           AND stream_version=?10 AND status='active'",
    )
    .bind(stream_version)
    .bind(state)
    .bind(successor.map(|value| value.relationship_origin_db_id.as_str()))
    .bind(successor.map(|value| value.relationship_id.as_str()))
    .bind(&spec.issuer_origin_db_id)
    .bind(&spec.event_id)
    .bind(&spec.occurred_at)
    .bind(&spec.relationship.relationship_origin_db_id)
    .bind(&spec.relationship.relationship_id)
    .bind(spec.expected_stream_version)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(Error::conflict(
            "relationship projection compare-and-set failed",
        ));
    }
    Ok(())
}

async fn update_assertion_head(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
    stream_version: i64,
    state: Option<&str>,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE relationship_assertion_heads
         SET stream_version=?1,state=COALESCE(?2,state),
             last_event_issuer_origin_db_id=?3,last_event_id=?4,occurred_at=?5
         WHERE issuer_origin_db_id=?6 AND assertion_id=?7 AND stream_version=?8",
    )
    .bind(stream_version)
    .bind(state)
    .bind(&spec.issuer_origin_db_id)
    .bind(&spec.event_id)
    .bind(&spec.occurred_at)
    .bind(&spec.issuer_origin_db_id)
    .bind(&spec.stream_id)
    .bind(spec.expected_stream_version)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(Error::conflict(
            "assertion projection compare-and-set failed",
        ));
    }
    Ok(())
}

pub(super) async fn projection_matches_retry_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
) -> Result<bool> {
    let expected_version = spec.stream_version()?;
    let matches = match spec.payload.stream_kind() {
        StreamKind::Relationship => {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM relationships
             WHERE relationship_origin_db_id=?1 AND relationship_id=?2
               AND stream_version>=?3",
            )
            .bind(&spec.relationship.relationship_origin_db_id)
            .bind(&spec.relationship.relationship_id)
            .bind(expected_version)
            .fetch_one(&mut **tx)
            .await?
                == 1
        }
        StreamKind::Assertion => {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM relationship_assertion_heads
             WHERE issuer_origin_db_id=?1 AND assertion_id=?2 AND stream_version>=?3
               AND relationship_origin_db_id=?4 AND relationship_id=?5
               AND relationship_revision=?6",
            )
            .bind(&spec.issuer_origin_db_id)
            .bind(&spec.stream_id)
            .bind(expected_version)
            .bind(&spec.relationship.relationship_origin_db_id)
            .bind(&spec.relationship.relationship_id)
            .bind(i64::try_from(spec.relationship.relationship_revision).unwrap_or(-1))
            .fetch_one(&mut **tx)
            .await?
                == 1
        }
    };
    Ok(matches)
}
