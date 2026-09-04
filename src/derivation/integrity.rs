use sqlx::{Row, SqliteConnection};

use crate::db::Db;
use crate::error::Result;

use super::persistence::read_all_derivation_events;
use super::projector::validate_event;

async fn cross_log_violations(db: &Db) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT h.target_record_id,h.active_binding_id,h.selected_publication_id,
                r.id AS carrier_id,r.type AS carrier_type,r.deleted_at AS carrier_deleted_at,
                r.body,s.output_event_id,s.output_sha256,
                e.record_id AS output_record_id,e.type AS output_type,e.payload AS output_payload,
                (SELECT latest.id FROM content_events latest
                  WHERE latest.record_id=h.target_record_id
                    AND json_type(latest.payload,'$.body') IS NOT NULL
                  ORDER BY latest.seq DESC LIMIT 1) AS latest_body_event_id
           FROM derivation_target_heads h
           LEFT JOIN records r ON r.id=h.target_record_id
           LEFT JOIN derivation_selected_publications s
             ON s.publication_id=h.selected_publication_id
           LEFT JOIN content_events e ON e.id=s.output_event_id
          WHERE h.active_binding_id IS NOT NULL",
    )
    .fetch_all(db.pool())
    .await?;
    let mut violations = Vec::new();
    for row in rows {
        let target: String = row.try_get("target_record_id")?;
        let carrier_id: Option<String> = row.try_get("carrier_id")?;
        let carrier_type: Option<String> = row.try_get("carrier_type")?;
        let carrier_deleted_at: Option<String> = row.try_get("carrier_deleted_at")?;
        if carrier_id.is_none()
            || carrier_type.as_deref() != Some("Document")
            || carrier_deleted_at.is_some()
        {
            violations.push(format!(
                "active derivation target {target} is not a live Document carrier"
            ));
            continue;
        }
        let selected: Option<String> = row.try_get("selected_publication_id")?;
        let body: Option<String> = row.try_get("body")?;
        let Some(selected) = selected else {
            if body.is_some() {
                violations.push(format!(
                    "active derivation target {target} has a visible body without a selected publication"
                ));
            }
            continue;
        };
        let output_event_id: Option<String> = row.try_get("output_event_id")?;
        let output_sha256: Option<String> = row.try_get("output_sha256")?;
        let output_record_id: Option<String> = row.try_get("output_record_id")?;
        let output_type: Option<String> = row.try_get("output_type")?;
        let output_payload: Option<String> = row.try_get("output_payload")?;
        let latest_body_event_id: Option<String> = row.try_get("latest_body_event_id")?;
        let Some(payload) = output_payload else {
            violations.push(format!(
                "selected derivation publication {selected} has no output content event"
            ));
            continue;
        };
        let payload: serde_json::Value = match serde_json::from_str(&payload) {
            Ok(payload) => payload,
            Err(error) => {
                violations.push(format!(
                    "selected derivation publication {selected} has malformed output payload: {error}"
                ));
                continue;
            }
        };
        if output_record_id.as_deref() != Some(target.as_str())
            || output_type.as_deref() != Some("record.updated")
        {
            violations.push(format!(
                "selected derivation publication {selected} output is not a body update for {target}"
            ));
        }
        let actual_output_sha256 = super::events::digest_json(&payload);
        if output_sha256.as_deref() != Some(actual_output_sha256.as_str()) {
            violations.push(format!(
                "selected derivation publication {selected} output digest is invalid"
            ));
        }
        let Some(payload_body) = payload.get("body").and_then(serde_json::Value::as_str) else {
            violations.push(format!(
                "selected derivation publication {selected} output has no string body"
            ));
            continue;
        };
        if Some(payload_body) != body.as_deref() {
            violations.push(format!(
                "selected derivation publication {selected} does not match the visible body"
            ));
        }
        if latest_body_event_id != output_event_id {
            violations.push(format!(
                "selected derivation publication {selected} is not the latest body event"
            ));
        }
    }
    let role_rows = sqlx::query(
        "SELECT a.assignment_id,a.target_record_id,r.type,r.kind,r.deleted_at,
                ch.confirmation_id,c.publication_id,c.output_sha256,
                p.output_event_id,e.record_id AS output_record_id,e.payload AS output_payload
           FROM derivation_artifact_role_assignments a
           JOIN derivation_artifact_role_heads rh ON rh.active_assignment_id=a.assignment_id
           LEFT JOIN records r ON r.id=a.target_record_id
           LEFT JOIN derivation_confirmation_heads ch ON ch.assignment_id=a.assignment_id
           LEFT JOIN derivation_revision_confirmations c ON c.confirmation_id=ch.confirmation_id
           LEFT JOIN derivation_target_publications p ON p.publication_id=c.publication_id
           LEFT JOIN content_events e ON e.id=p.output_event_id",
    )
    .fetch_all(db.pool())
    .await?;
    for row in role_rows {
        let assignment_id: String = row.try_get("assignment_id")?;
        let target: String = row.try_get("target_record_id")?;
        let record_type: Option<String> = row.try_get("type")?;
        let kind: Option<String> = row.try_get("kind")?;
        let deleted_at: Option<String> = row.try_get("deleted_at")?;
        if record_type.as_deref() != Some("Document")
            || kind.as_deref() != Some("note")
            || deleted_at.is_some()
        {
            violations.push(format!(
                "active derivation artifact role {assignment_id} is not carried by a live Document kind:note"
            ));
        }
        let Some(confirmation_id) = row.try_get::<Option<String>, _>("confirmation_id")? else {
            continue;
        };
        let publication_id: Option<String> = row.try_get("publication_id")?;
        let output_sha256: Option<String> = row.try_get("output_sha256")?;
        let output_event_id: Option<String> = row.try_get("output_event_id")?;
        let output_record_id: Option<String> = row.try_get("output_record_id")?;
        let output_payload: Option<String> = row.try_get("output_payload")?;
        let Some(payload) = output_payload else {
            violations.push(format!(
                "active derivation confirmation {confirmation_id} has no output content event"
            ));
            continue;
        };
        let payload: serde_json::Value = match serde_json::from_str(&payload) {
            Ok(payload) => payload,
            Err(error) => {
                violations.push(format!(
                    "active derivation confirmation {confirmation_id} output is malformed: {error}"
                ));
                continue;
            }
        };
        if publication_id.is_none()
            || output_event_id.is_none()
            || output_record_id.as_deref() != Some(target.as_str())
            || output_sha256.as_deref() != Some(super::events::digest_json(&payload).as_str())
        {
            violations.push(format!(
                "active derivation confirmation {confirmation_id} output provenance is invalid"
            ));
        }
    }
    Ok(violations)
}

async fn log_violations_on(conn: &mut SqliteConnection) -> Result<Vec<String>> {
    let events = read_all_derivation_events(conn).await?;
    let mut violations = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let expected_seq = index as i64 + 1;
        if event.seq != expected_seq {
            violations.push(format!(
                "derivation event sequence is not contiguous: expected {expected_seq}, found {}",
                event.seq
            ));
        }
        if let Err(error) = validate_event(event) {
            violations.push(format!(
                "derivation event {} is malformed: {error}",
                event.id
            ));
        }
    }
    let applications = sqlx::query(
        "SELECT event_id,event_seq FROM derivation_event_applications ORDER BY event_seq",
    )
    .fetch_all(&mut *conn)
    .await?;
    if applications.len() != events.len() {
        violations.push(format!(
            "derivation event application count differs from log: {} applications for {} events",
            applications.len(),
            events.len()
        ));
    }
    for (index, row) in applications.iter().enumerate() {
        let Some(event) = events.get(index) else {
            break;
        };
        let event_id: String = row.try_get("event_id")?;
        let event_seq: i64 = row.try_get("event_seq")?;
        if event_id != event.id || event_seq != event.seq {
            violations.push(format!(
                "derivation event application at position {} does not match canonical event {}",
                index + 1,
                event.id
            ));
        }
    }
    Ok(violations)
}

/// Refuse ordinary serving when the authoritative derivation log cannot
/// account exactly for its projections. External source bytes are deliberately
/// not consulted: replay validates retained provenance without re-execution.
pub async fn state_violations(db: &Db) -> Result<Vec<String>> {
    let mut snapshot = db.pool().begin().await?;
    let mut violations = log_violations_on(&mut snapshot).await?;
    snapshot.rollback().await?;
    if violations.is_empty() {
        match crate::conformance::rebuild_and_diff_derivation(db).await {
            Ok(diff) => {
                for table in diff
                    .tables
                    .into_iter()
                    .filter(|table| table.live != table.rebuilt || !table.mismatches.is_empty())
                {
                    violations.push(format!(
                        "derivation projection drift in {} (live {}, rebuilt {}): {}",
                        table.table,
                        table.live,
                        table.rebuilt,
                        table
                            .mismatches
                            .into_iter()
                            .take(3)
                            .collect::<Vec<_>>()
                            .join("; ")
                    ));
                }
            }
            Err(error) => violations.push(format!(
                "derivation event log could not be replayed: {error}"
            )),
        }
    }
    if violations.is_empty() {
        violations.extend(cross_log_violations(db).await?);
    }
    Ok(violations)
}
