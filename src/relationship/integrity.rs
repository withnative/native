use std::collections::BTreeMap;

use sqlx::Row;

use crate::Result;

use super::{
    parse_event_payload, RelationshipCoordinate, RelationshipEventPayload, RelationshipEventSpec,
};

/// Read-only ledger/projection integrity scan. Phase 4 adds full rebuild/diff;
/// this kernel-level check focuses on invariants that must already hold before
/// a projector can safely replay the log.
pub(crate) async fn relationship_state_violations(db: &crate::Db) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    let ledger: (i64, i64, i64) = sqlx::query_as(
        "SELECT COALESCE(MIN(seq),0),COALESCE(MAX(seq),0),COUNT(*) FROM relationship_events",
    )
    .fetch_one(db.pool())
    .await?;
    if ledger.2 > 0 && (ledger.0 != 1 || ledger.1 != ledger.2) {
        violations.push("relationship ledger seq is not contiguous from 1".into());
    }
    let streams = sqlx::query(
        "SELECT issuer_origin_db_id,stream_kind,stream_id,
                MIN(stream_version) AS minimum,MAX(stream_version) AS maximum,COUNT(*) AS count
         FROM relationship_events GROUP BY issuer_origin_db_id,stream_kind,stream_id",
    )
    .fetch_all(db.pool())
    .await?;
    for row in streams {
        let minimum: i64 = row.try_get("minimum")?;
        let maximum: i64 = row.try_get("maximum")?;
        let count: i64 = row.try_get("count")?;
        if minimum != 1 || maximum != count {
            violations.push(format!(
                "non-contiguous relationship stream {}:{}:{}",
                row.try_get::<String, _>("issuer_origin_db_id")?,
                row.try_get::<String, _>("stream_kind")?,
                row.try_get::<String, _>("stream_id")?
            ));
        }
    }

    let rows = sqlx::query(
        "SELECT id,stream_kind,stream_id,stream_version,relationship_origin_db_id,
                relationship_id,type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at
         FROM relationship_events
         ORDER BY issuer_origin_db_id,stream_kind,stream_id,stream_version",
    )
    .fetch_all(db.pool())
    .await?;
    let mut states: BTreeMap<(String, String, String), &'static str> = BTreeMap::new();
    for row in rows {
        let issuer: String = row.try_get("issuer_origin_db_id")?;
        let stream_kind: String = row.try_get("stream_kind")?;
        let stream_id: String = row.try_get("stream_id")?;
        let stream_version: i64 = row.try_get("stream_version")?;
        let event_type: String = row.try_get("type")?;
        let payload_text: String = row.try_get("payload")?;
        let event_id: String = row.try_get("id")?;
        let key = (issuer.clone(), stream_kind.clone(), stream_id.clone());
        let parsed = serde_json::from_str(&payload_text)
            .map_err(crate::Error::from)
            .and_then(|value| parse_event_payload(&event_type, value));
        let Ok(payload) = parsed else {
            violations.push(format!(
                "invalid closed relationship payload {issuer}:{}",
                event_id
            ));
            continue;
        };
        let canonical_payload =
            String::from_utf8(crate::derivation::canonical_json(&payload.value()?))
                .expect("canonical JSON is UTF-8");
        if payload_text != canonical_payload {
            violations.push(format!(
                "relationship event payload is not canonical JCS {issuer}:{}",
                event_id
            ));
        }
        if payload.stream_kind().as_str() != stream_kind {
            violations.push(format!(
                "relationship event type/stream mismatch {issuer}:{}",
                event_id
            ));
            continue;
        }
        let spec = RelationshipEventSpec {
            event_id: event_id.clone(),
            stream_id: stream_id.clone(),
            expected_stream_version: stream_version - 1,
            relationship: RelationshipCoordinate {
                relationship_origin_db_id: row.try_get("relationship_origin_db_id")?,
                relationship_id: row.try_get("relationship_id")?,
                relationship_revision: 1,
            },
            payload: payload.clone(),
            actor: row.try_get("actor")?,
            issuer_origin_db_id: issuer.clone(),
            occurred_at: row.try_get("occurred_at")?,
            ingested_at: row.try_get("ingested_at")?,
        };
        if let Err(error) = spec.validate() {
            violations.push(format!(
                "invalid relationship event envelope {issuer}:{event_id}: {error}"
            ));
            continue;
        }
        let before = states.get(&key).copied();
        let after = match (&payload, before) {
            (RelationshipEventPayload::RelationshipCreated(_), None) => Some("active"),
            (RelationshipEventPayload::RelationshipSuperseded(_), Some("active")) => {
                Some("superseded")
            }
            (RelationshipEventPayload::RelationshipRetired(_), Some("active")) => Some("retired"),
            (RelationshipEventPayload::AssertionCreated(_), None) => Some("active"),
            (RelationshipEventPayload::AssertionEvidenceAdded(_), Some("active")) => Some("active"),
            (RelationshipEventPayload::AssertionRetracted(_), Some("active")) => Some("retracted"),
            (RelationshipEventPayload::AssertionInvalidated(_), Some("active")) => {
                Some("invalidated")
            }
            (RelationshipEventPayload::AssertionRestored(_), Some("invalidated")) => Some("active"),
            _ => None,
        };
        if let Some(after) = after {
            states.insert(key, after);
        } else {
            violations.push(format!(
                "illegal relationship aggregate transition {issuer}:{}",
                event_id
            ));
        }
    }

    let projection_mismatches: i64 = sqlx::query_scalar(
        "SELECT
           (SELECT COUNT(*) FROM relationships r
             WHERE NOT EXISTS (
               SELECT 1 FROM relationship_events e
                WHERE e.issuer_origin_db_id=r.last_event_issuer_origin_db_id
                  AND e.id=r.last_event_id AND e.stream_kind='relationship'
                  AND e.relationship_origin_db_id=r.relationship_origin_db_id
                  AND e.relationship_id=r.relationship_id
                  AND e.stream_version=r.stream_version))
         + (SELECT COUNT(*) FROM relationship_assertion_heads a
             WHERE NOT EXISTS (
               SELECT 1 FROM relationship_events e
                WHERE e.issuer_origin_db_id=a.last_event_issuer_origin_db_id
                  AND e.id=a.last_event_id AND e.stream_kind='assertion'
                  AND e.stream_id=a.assertion_id
                  AND e.relationship_origin_db_id=a.relationship_origin_db_id
                  AND e.relationship_id=a.relationship_id
                  AND e.stream_version=a.stream_version))",
    )
    .fetch_one(db.pool())
    .await?;
    if projection_mismatches != 0 {
        violations.push(format!(
            "{projection_mismatches} relationship projection head(s) do not match their streams"
        ));
    }
    let relationship_heads = sqlx::query(
        "SELECT relationship_origin_db_id,relationship_id,status,stream_version,
                created_event_issuer_origin_db_id,created_event_id
         FROM relationships",
    )
    .fetch_all(db.pool())
    .await?;
    for row in relationship_heads {
        let origin: String = row.try_get("relationship_origin_db_id")?;
        let id: String = row.try_get("relationship_id")?;
        let status: String = row.try_get("status")?;
        let version: i64 = row.try_get("stream_version")?;
        if states
            .get(&(origin.clone(), "relationship".into(), id.clone()))
            .copied()
            != Some(status.as_str())
        {
            violations.push(format!(
                "relationship projection state differs from stream {origin}:{id}"
            ));
        }
        let created_matches: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM relationship_events
             WHERE issuer_origin_db_id=?1 AND id=?2 AND stream_kind='relationship'
               AND stream_id=?3 AND stream_version=1 AND type='relationship.created.v1'",
        )
        .bind(row.try_get::<String, _>("created_event_issuer_origin_db_id")?)
        .bind(row.try_get::<String, _>("created_event_id")?)
        .bind(&id)
        .fetch_one(db.pool())
        .await?;
        if created_matches != 1 || version < 1 {
            violations.push(format!(
                "relationship projection creation identity differs from stream {origin}:{id}"
            ));
        }
    }
    let assertion_heads = sqlx::query(
        "SELECT issuer_origin_db_id,assertion_id,relationship_origin_db_id,relationship_id,
                relationship_revision,state,stream_version,causal_parents,
                created_event_issuer_origin_db_id,created_event_id
         FROM relationship_assertion_heads",
    )
    .fetch_all(db.pool())
    .await?;
    for row in assertion_heads {
        let issuer: String = row.try_get("issuer_origin_db_id")?;
        let id: String = row.try_get("assertion_id")?;
        let state: String = row.try_get("state")?;
        if states
            .get(&(issuer.clone(), "assertion".into(), id.clone()))
            .copied()
            != Some(state.as_str())
        {
            violations.push(format!(
                "assertion projection state differs from stream {issuer}:{id}"
            ));
        }
        let created_payload: Option<String> = sqlx::query_scalar(
            "SELECT payload FROM relationship_events
             WHERE issuer_origin_db_id=?1 AND id=?2 AND stream_kind='assertion'
               AND stream_id=?3 AND stream_version=1 AND type='assertion.created.v1'
               AND relationship_origin_db_id=?4 AND relationship_id=?5",
        )
        .bind(row.try_get::<String, _>("created_event_issuer_origin_db_id")?)
        .bind(row.try_get::<String, _>("created_event_id")?)
        .bind(&id)
        .bind(row.try_get::<String, _>("relationship_origin_db_id")?)
        .bind(row.try_get::<String, _>("relationship_id")?)
        .fetch_optional(db.pool())
        .await?;
        let created_matches = created_payload
            .and_then(|text| serde_json::from_str(&text).ok())
            .and_then(|value| parse_event_payload("assertion.created.v1", value).ok())
            .and_then(|payload| match payload {
                RelationshipEventPayload::AssertionCreated(created) => Some(created),
                _ => None,
            })
            .is_some_and(|created| {
                let causal = String::from_utf8(crate::derivation::canonical_json(
                    &serde_json::to_value(created.causal_parents).expect("parents serialize"),
                ))
                .expect("canonical JSON is UTF-8");
                created.relationship.relationship_revision
                    == u64::try_from(row.try_get::<i64, _>("relationship_revision").unwrap_or(-1))
                        .unwrap_or(0)
                    && causal
                        == row
                            .try_get::<String, _>("causal_parents")
                            .unwrap_or_default()
            });
        if !created_matches || row.try_get::<i64, _>("stream_version")? < 1 {
            violations.push(format!(
                "assertion projection creation identity differs from stream {issuer}:{id}"
            ));
        }
    }

    let missing_local: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM relationship_assertion_heads a
          WHERE NOT EXISTS (SELECT 1 FROM relationship_local_admissions l
           WHERE l.issuer_origin_db_id=a.issuer_origin_db_id AND l.assertion_id=a.assertion_id)",
    )
    .fetch_one(db.pool())
    .await?;
    if missing_local != 0 {
        violations.push(format!(
            "{missing_local} assertion head(s) have no receiver-local admission projection"
        ));
    }
    let missing_effective: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM relationships r
          WHERE NOT EXISTS (SELECT 1 FROM effective_relationships e
           WHERE e.relationship_origin_db_id=r.relationship_origin_db_id
             AND e.relationship_id=r.relationship_id)",
    )
    .fetch_one(db.pool())
    .await?;
    if missing_effective != 0 {
        violations.push(format!(
            "{missing_effective} relationship(s) have no effective projection"
        ));
    }
    let activity_mismatch: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM relationship_events e
          WHERE (SELECT COUNT(*) FROM relationship_endpoint_activity a
                  WHERE a.event_issuer_origin_db_id=e.issuer_origin_db_id AND a.event_id=e.id)
             != (SELECT COUNT(*) FROM relationship_endpoints p
                  WHERE p.relationship_origin_db_id=e.relationship_origin_db_id
                    AND p.relationship_id=e.relationship_id)",
    )
    .fetch_one(db.pool())
    .await?;
    if activity_mismatch != 0 {
        violations.push(format!(
            "{activity_mismatch} relationship event(s) have incomplete endpoint activity"
        ));
    }
    let orphan_compatibility_links: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links l WHERE l.id LIKE 'rel:%'
          AND NOT EXISTS (
            SELECT 1 FROM relationships r JOIN effective_relationships e
              ON e.relationship_origin_db_id=r.relationship_origin_db_id
             AND e.relationship_id=r.relationship_id
             WHERE l.id='rel:' || r.relationship_origin_db_id || ':' || r.relationship_id
               AND e.effective_state='active')",
    )
    .fetch_one(db.pool())
    .await?;
    if orphan_compatibility_links != 0 {
        violations.push(format!(
            "{orphan_compatibility_links} rel: compatibility link(s) have no active effective relationship"
        ));
    }

    let mut admission_snapshot = db.pool().begin().await?;
    let admissions = sqlx::query(
        "SELECT a.issuer_origin_db_id,a.created_event_id,a.origin_admission,
                l.local_admission_state
           FROM relationship_assertion_heads a
           JOIN relationship_local_admissions l
             ON l.issuer_origin_db_id=a.issuer_origin_db_id AND l.assertion_id=a.assertion_id",
    )
    .fetch_all(&mut *admission_snapshot)
    .await?;
    for row in admissions {
        let issuer: String = row.try_get("issuer_origin_db_id")?;
        let event_id: String = row.try_get("created_event_id")?;
        let origin_admission: super::OriginAdmissionV1 =
            serde_json::from_str(&row.try_get::<String, _>("origin_admission")?)?;
        let verified = crate::provenance::verify_receiver_local_assertion_admission_in(
            &mut admission_snapshot,
            &issuer,
            &event_id,
            &origin_admission,
        )
        .await?;
        let projected: String = row.try_get("local_admission_state")?;
        if verified != (projected == "admitted") {
            violations.push(format!(
                "receiver-local admission differs from current evidence {issuer}:{event_id}"
            ));
        }
    }
    admission_snapshot.rollback().await?;

    let mut effective_snapshot = db.pool().begin().await?;
    let effective_rows = sqlx::query(
        "SELECT r.relationship_origin_db_id,r.relationship_id,r.status,r.relationship_type,
                r.type_definition_id,r.reducer_id,
                r.reducer_version,r.occurred_at,e.effective_state,e.epistemic_state,
                e.support_count,e.contest_count,e.admission_counts,e.assertion_set_digest,
                e.knowledge_watermark,e.recomputed_at
           FROM relationships r JOIN effective_relationships e
             ON e.relationship_origin_db_id=r.relationship_origin_db_id
            AND e.relationship_id=r.relationship_id",
    )
    .fetch_all(&mut *effective_snapshot)
    .await?;
    for effective in effective_rows {
        let origin: String = effective.try_get("relationship_origin_db_id")?;
        let relationship_id: String = effective.try_get("relationship_id")?;
        let head_rows = sqlx::query(
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
        .bind(&origin)
        .bind(&relationship_id)
        .fetch_all(&mut *effective_snapshot)
        .await?;
        let mut recomputed_at: String = effective.try_get("occurred_at")?;
        let mut heads = Vec::with_capacity(head_rows.len());
        for head in head_rows {
            let occurred_at: String = head.try_get("occurred_at")?;
            recomputed_at = recomputed_at.max(occurred_at);
            let causal_parents: Vec<super::CausalAssertionParent> =
                serde_json::from_str(&head.try_get::<String, _>("causal_parents")?)?;
            let causal_parents_resolved = super::projector::causal_parents_resolved_in(
                &mut effective_snapshot,
                &origin,
                &relationship_id,
                &causal_parents,
            )
            .await?;
            heads.push(super::reducer::AssertionHead {
                issuer_origin_db_id: head.try_get("issuer_origin_db_id")?,
                assertion_id: head.try_get("assertion_id")?,
                stream_version: u64::try_from(head.try_get::<i64, _>("stream_version")?)
                    .unwrap_or(0),
                stance: head.try_get("stance")?,
                state: head.try_get("state")?,
                causal_parents,
                causal_parents_resolved,
                last_event_issuer_origin_db_id: head.try_get("last_event_issuer_origin_db_id")?,
                last_event_id: head.try_get("last_event_id")?,
                local_admission_state: head.try_get("local_admission_state")?,
                local_admission_class: head.try_get("local_admission_class")?,
                local_policy_version: u64::try_from(
                    head.try_get::<i64, _>("local_policy_version")?,
                )
                .unwrap_or(0),
                local_evidence_digest: head.try_get("local_evidence_digest")?,
            });
        }
        let digest = crate::provenance::digest_json(&serde_json::to_value(&heads)?);
        let watermark = heads
            .iter()
            .map(|head| {
                serde_json::json!({
                    "assertion_issuer_origin_db_id": head.issuer_origin_db_id,
                    "assertion_id": head.assertion_id,
                    "stream_version": head.stream_version,
                    "head_event_issuer_origin_db_id": head.last_event_issuer_origin_db_id,
                    "head_event_id": head.last_event_id,
                })
            })
            .collect::<Vec<_>>();
        let watermark = String::from_utf8(crate::derivation::canonical_json(&serde_json::json!(
            watermark
        )))
        .expect("canonical JSON is UTF-8");
        let reducer_id: String = effective.try_get("reducer_id")?;
        let reducer_version: i64 = effective.try_get("reducer_version")?;
        let relationship_type: String = effective.try_get("relationship_type")?;
        let type_definition_id: String = effective.try_get("type_definition_id")?;
        let relationship_active = effective.try_get::<String, _>("status")? == "active";
        let reducer_version = u64::try_from(reducer_version).unwrap_or(0);
        super::reducer::validate_reducer(&reducer_id, reducer_version)?;
        let endpoints_resolved = if relationship_active {
            sqlx::query_scalar::<_, i64>(
                "SELECT EXISTS(
                    SELECT 1 FROM relationship_endpoints
                     WHERE relationship_origin_db_id=?
                       AND relationship_id=?
                       AND record_id IS NULL
                 )",
            )
            .bind(&origin)
            .bind(&relationship_id)
            .fetch_one(&mut *effective_snapshot)
            .await?
                == 0
        } else {
            true
        };
        let outcome =
            super::reducer::reduce_effective_relationship(super::reducer::ReductionFacts {
                reducer_id: &reducer_id,
                reducer_version,
                relationship_active,
                endpoints_resolved,
                proposition: super::reducer::RelationshipProposition {
                    relationship_type: &relationship_type,
                    type_definition_id: &type_definition_id,
                },
                heads: &heads,
            })?;
        let counts = String::from_utf8(crate::derivation::canonical_json(&serde_json::to_value(
            &outcome.admission_counts,
        )?))
        .expect("canonical JSON is UTF-8");
        if effective.try_get::<String, _>("assertion_set_digest")? != digest
            || effective.try_get::<String, _>("knowledge_watermark")? != watermark
            || effective.try_get::<String, _>("recomputed_at")? != recomputed_at
            || effective.try_get::<String, _>("effective_state")? != outcome.effective_state
            || effective.try_get::<String, _>("epistemic_state")? != outcome.epistemic_state
            || effective.try_get::<i64, _>("support_count")?
                != i64::try_from(outcome.support_count).unwrap_or(i64::MAX)
            || effective.try_get::<i64, _>("contest_count")?
                != i64::try_from(outcome.contest_count).unwrap_or(i64::MAX)
            || effective.try_get::<String, _>("admission_counts")? != counts
        {
            violations.push(format!(
                "effective relationship projection is not reproducible {origin}:{relationship_id}"
            ));
        }
    }
    effective_snapshot.rollback().await?;

    for (name, expected) in [
        (
            "relationship_events_no_update",
            "CREATE TRIGGER relationship_events_no_update BEFORE UPDATE ON relationship_events
             BEGIN SELECT RAISE(ABORT, 'relationship_events is append-only'); END",
        ),
        (
            "relationship_events_no_delete",
            "CREATE TRIGGER relationship_events_no_delete BEFORE DELETE ON relationship_events
             BEGIN SELECT RAISE(ABORT, 'relationship_events is append-only'); END",
        ),
    ] {
        let sql: Option<String> =
            sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1")
                .bind(name)
                .fetch_optional(db.pool())
                .await?;
        let normalized = |sql: &str| sql.split_whitespace().collect::<Vec<_>>().join(" ");
        if sql.is_none_or(|sql| normalized(&sql) != normalized(expected)) {
            violations.push(format!(
                "relationship append-only trigger {name} is missing or changed"
            ));
        }
    }
    Ok(violations)
}
