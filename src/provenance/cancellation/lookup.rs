//! Governed LOCAL evidence only: no projection rebuild, settlement or source write.
use super::*;
use crate::mcp::registry::HeldLocalOutcome;
use crate::provenance::cancellation_request::stop::ObservationBinding;
use sqlx::Connection;
fn hidden() -> Error {
    Error::auth("held_stop_evidence_unavailable")
}

/// The caller retains admission and BEGIN IMMEDIATE and has made no writes.
/// Its reserved lock freezes committed content throughout this private read.
/// SQLite 3.46 FTS5 integrity checks can use stale connection-local segment
/// caches after another connection merges segments. A new reader avoids that
/// cache without changing either integrity predicate. It must honor live WAL.
async fn fresh_integrity(db: &Db, tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM main.database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(db.path())
        .create_if_missing(false)
        .read_only(true)
        .immutable(false)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let mut reader = sqlx::SqliteConnection::connect_with(&options).await?;
    let observation: Result<()> = async {
        sqlx::query("PRAGMA query_only=ON")
            .execute(&mut reader)
            .await?;
        let mut snapshot = reader.begin_with("BEGIN DEFERRED").await?;
        let checks: Result<()> = async {
            if sqlx::query_scalar::<_, String>(
                "SELECT origin_db_id FROM main.database_identity WHERE singleton=1",
            )
            .fetch_one(&mut *snapshot)
            .await?
                != origin
                || sqlx::query_scalar::<_, i64>("PRAGMA user_version")
                    .fetch_one(&mut *snapshot)
                    .await?
                    != 94
                || sqlx::query_scalar::<_, String>("PRAGMA quick_check(1)")
                    .fetch_one(&mut *snapshot)
                    .await?
                    != "ok"
                || sqlx::query("PRAGMA foreign_key_check")
                    .fetch_optional(&mut *snapshot)
                    .await?
                    .is_some()
            {
                return Err(hidden());
            }
            Ok(())
        }
        .await;
        let rollback = snapshot.rollback().await;
        checks?;
        rollback?;
        Ok(())
    }
    .await;
    let close = reader.close().await;
    observation?;
    close?;
    Ok(())
}

/// Private DATA candidate; only registry-owned rollback paths publish wrappers.
pub(crate) struct LocalEvidenceData {
    pub(crate) binding: ObservationBinding,
    pub(crate) outcome: HeldLocalOutcome,
    pub(crate) issued_at: i64,
    pub(crate) deadline: i64,
}
/// DATA candidate; only the registry can publish its opaque wrapper after rollback.
pub(crate) async fn lookup(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    bytes: &[u8],
) -> Result<Option<LocalEvidenceData>> {
    let data = author_stop::verified_data(bytes)?;
    author_stop::check_database(db, tx, &data.claims).await?;
    crate::storage_profile::enforce_command_cancellation_on(&mut *tx).await?;
    if !crate::db::validate_engine_shape_on(&mut *tx, 94).await? {
        return Err(hidden());
    }
    fresh_integrity(db, tx).await?;
    if !crate::control::state_violations_on(&mut *tx)
        .await?
        .is_empty()
        || !super::super::state_violations_on(&mut *tx)
            .await?
            .is_empty()
    {
        return Err(hidden());
    }
    let e = &data.evidence;
    let cancelled = sqlx::query("SELECT c.*,e.id AS canonical_event FROM provenance_local_command_cancellations c LEFT JOIN control_events e ON e.id=c.event_id WHERE c.principal=? AND c.operation=? AND c.command_identity_digest=?")
        .bind(&e.principal).bind(&e.operation).bind(&e.command_identity_digest).fetch_optional(&mut **tx).await?;
    let saved = sqlx::query("SELECT l.issuer_origin_database_id AS local_origin,l.principal AS local_principal,l.operation AS local_operation,l.command_identity_digest AS local_command,a.* FROM provenance_local_attestation_authority l LEFT JOIN provenance_action_attestations a ON a.id=l.attestation_id WHERE l.principal=? AND l.operation=? AND l.command_identity_digest=?")
        .bind(&e.principal).bind(&e.operation).bind(&e.command_identity_digest).fetch_optional(&mut **tx).await?;
    if cancelled.is_some() && saved.is_some() {
        return Err(hidden());
    }
    let outcome = if let Some(row) = cancelled {
        let id: String = row.try_get("event_id")?;
        if row
            .try_get::<Option<String>, _>("canonical_event")?
            .as_deref()
            != Some(&id)
            || row.try_get::<String, _>("origin_db_id")? != e.origin_db_id
            || row.try_get::<String, _>("principal")? != e.principal
            || row.try_get::<String, _>("operation")? != e.operation
            || row.try_get::<String, _>("command_identity_digest")? != e.command_identity_digest
            || row.try_get::<String, _>("action_digest")? != e.action_digest
            || row.try_get::<Option<String>, _>("intent_digest")? != e.intent_digest
            || row.try_get::<String, _>("app_context_digest")? != e.app_context_digest
        {
            return Err(hidden());
        }
        let events = crate::control::read_all_control_events(&mut *tx).await?;
        let event = events.iter().find(|v| v.id == id).ok_or_else(hidden)?;
        crate::control::validate_stored_control_event(event)?;
        let payload: CancellationEvidence = serde_json::from_str(&event.payload)?;
        if &payload != e
            || event.event_type != "held_command.cancelled.v1"
            || event.actor != e.principal
            || event.aggregate_kind != "held_command"
            || event.aggregate_id != e.identity_digest()
            || event.idempotency_key != format!("held-command-cancel:{}", e.identity_digest())
            || sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM control_event_applications WHERE event_id=? AND event_seq=?",
            )
            .bind(&id)
            .bind(event.seq)
            .fetch_one(&mut **tx)
            .await?
                != 1
        {
            return Err(hidden());
        }
        if id.is_empty() || id.len() > 256 {
            return Err(hidden());
        }
        Some(HeldLocalOutcome::Cancelled { event_id: id })
    } else if let Some(row) = saved {
        let id: Option<String> = row.try_get("id")?;
        let id = id.ok_or_else(hidden)?;
        if row.try_get::<String, _>("local_origin")? != e.origin_db_id
            || row.try_get::<String, _>("issuer_origin_database_id")? != e.origin_db_id
            || row.try_get::<String, _>("issuer")? != ISSUER
            || row.try_get::<String, _>("local_principal")? != e.principal
            || row.try_get::<String, _>("principal")? != e.principal
            || row.try_get::<String, _>("local_operation")? != e.operation
            || row.try_get::<String, _>("operation")? != e.operation
            || row
                .try_get::<Option<String>, _>("local_command")?
                .as_deref()
                != Some(&e.command_identity_digest)
            || row
                .try_get::<Option<String>, _>("command_identity_digest")?
                .as_deref()
                != Some(&e.command_identity_digest)
            || row.try_get::<String, _>("action_digest")? != e.action_digest
            || row.try_get::<Option<String>, _>("intent_digest")? != e.intent_digest
        {
            return Err(hidden());
        }
        let context = CommandAppContext::host_app(&data.entry.call.app.claim()?)?;
        require_command_app_in(tx, &id, &context).await?;
        let text: String = row.try_get("action_commitment")?;
        let value: Value = serde_json::from_str(&text)?;
        if crate::canonical_json::canonical_json(&value) != text.as_bytes()
            || !commitment_is_exact(&value, &e.operation, &e.action_digest)
        {
            return Err(hidden());
        }
        let validity = sqlx::query("SELECT ordinal,status FROM provenance_attestation_validity_events WHERE attestation_id=? ORDER BY ordinal")
            .bind(&id).fetch_all(&mut **tx).await?;
        for (n, v) in validity.iter().enumerate() {
            if v.try_get::<i64, _>("ordinal")? != n as i64
                || !matches!(
                    v.try_get::<String, _>("status")?.as_str(),
                    "restored" | "invalidated"
                )
            {
                return Err(hidden());
            }
        }
        if validity.last().is_some_and(|v| {
            v.try_get::<String, _>("status").ok().as_deref() == Some("invalidated")
        }) {
            return Err(hidden());
        }
        let members = sqlx::query("SELECT ordinal,output_domain,output_event_id FROM provenance_action_outputs WHERE action_attestation_id=? ORDER BY ordinal")
            .bind(&id).fetch_all(&mut **tx).await?;
        let mut outputs = Vec::new();
        // Reuse existing pure decoders, never project into the source or open a pool.
        let content = if members
            .iter()
            .any(|v| v.try_get::<String, _>("output_domain").ok().as_deref() == Some("content"))
        {
            crate::conformance::read_all_events(&mut *tx).await?
        } else {
            Vec::new()
        };
        let relationship = if members.iter().any(|v| {
            v.try_get::<String, _>("output_domain").ok().as_deref() == Some("relationship")
        }) {
            // Guard the existing reader's stream_version - 1 conversion before decoding.
            if sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM relationship_events WHERE typeof(stream_version)!='integer' OR stream_version<=0)").fetch_one(&mut **tx).await? { return Err(hidden()); }
            crate::relationship::read_all_relationship_events(&mut *tx).await?
        } else {
            Vec::new()
        };
        for (n, member) in members.iter().enumerate() {
            if member.try_get::<i64, _>("ordinal")? != n as i64 {
                return Err(hidden());
            }
            let event_id: String = member.try_get("output_event_id")?;
            let output = match member.try_get::<String, _>("output_domain")?.as_str() {
                "content" => {
                    let event = content
                        .iter()
                        .find(|v| v.id == event_id)
                        .ok_or_else(hidden)?;
                    event.causal_envelope.validate_for_event(&event.id)?;
                    crate::domain_transaction::ProjectorIntent::from_event(event)?;
                    ActionOutput::content(event_id)
                }
                "relationship" => {
                    let event = relationship
                        .iter()
                        .find(|v| v.event_id == event_id)
                        .ok_or_else(hidden)?;
                    event.event.validate()?;
                    if event.issuer_origin_db_id != e.origin_db_id {
                        return Err(hidden());
                    }
                    ActionOutput::relationship(event_id)
                }
                _ => return Err(hidden()),
            };
            outputs.push(output);
        }
        let version: i64 = row.try_get("schema_version")?;
        let digest: String = row.try_get("output_event_set_digest")?;
        if (outputs.is_empty()
            && !is_empty_keyed_anchor_shape(
                version,
                &e.operation,
                ISSUER,
                Some(&e.command_identity_digest),
                &digest,
            ))
            || !attested_output_digest_is_exact(version, &outputs, &digest)
        {
            return Err(hidden());
        }
        if id.is_empty() || id.len() > 256 {
            return Err(hidden());
        }
        Some(HeldLocalOutcome::Saved { attestation_id: id })
    } else {
        None
    };
    #[cfg(test)]
    test_control::checkpoint().await;
    author_stop::fresh(&data.claims)?;
    Ok(outcome.map(|outcome| LocalEvidenceData {
        binding: data.binding,
        outcome,
        issued_at: data.claims.issued_at,
        deadline: data.claims.deadline,
    }))
}

#[cfg(test)]
mod integrity_tests;

#[cfg(test)]
mod fts_read_state_tests;

#[cfg(test)]
pub(super) mod test_control {
    use std::sync::Arc;
    use tokio::sync::Notify;
    #[derive(Default)]
    pub struct Pause {
        pub entered: Notify,
        pub release: Notify,
    }
    tokio::task_local! { pub static AFTER_READ: Arc<Pause>; }
    pub async fn checkpoint() {
        if let Ok(p) = AFTER_READ.try_with(Arc::clone) {
            p.entered.notify_one();
            p.release.notified().await;
        }
    }
}
