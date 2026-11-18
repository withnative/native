//! Internal SQLite-only keyed cancellation fence. No tool/HTTP/queue caller.
//!
//! The caller must own ordinary mutation admission and a BEGIN IMMEDIATE
//! transaction. This module NEVER opens a writer or bypasses maintenance,
//! writer-pause, lifecycle, or strict-portability admission. A staged decision
//! is not a cancellation receipt: it becomes durable only when that SAME
//! transaction commits. Later custody orchestration owns that acknowledgement.
use super::*;
use crate::control::{append_control_event_in, ControlEventPayload, NewControlEvent};

const CANCELLED: &str = "held_command_cancelled";
const MISMATCH: &str = "held_command_identity_mismatch";

/// Portable evidence only. Import/rebuild must never derive local authority
/// from this payload. Its receiver-local anchor is issued only by cancel_in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationEvidence {
    pub origin_db_id: String,
    pub principal: String,
    pub operation: String,
    pub command_identity_digest: String,
    pub action_digest: String,
    pub intent_digest: Option<String>,
    pub app_context_digest: String,
}
impl CancellationEvidence {
    pub(crate) fn validate(&self) -> Result<()> {
        if !crate::identity::is_database_id(&self.origin_db_id)
            || self.principal.trim().is_empty()
            || !matches!(self.operation.as_str(), "create_record" | "update_record")
            || !is_sha256_hex(&self.command_identity_digest)
            || !is_sha256_hex(&self.action_digest)
            || !is_sha256_hex(&self.app_context_digest)
            || self
                .intent_digest
                .as_deref()
                .is_some_and(|v| !is_sha256_hex(v))
        {
            return Err(Error::engine(MISMATCH));
        }
        Ok(())
    }
    pub(crate) fn identity_digest(&self) -> String {
        digest_json(&serde_json::to_value(self).expect("cancellation evidence"))
    }
}

/// Not deserializable; a portable event is never a verified original command.
#[allow(dead_code)] // Deliberately dark until custody verification is implemented.
pub(crate) struct VerifiedHeldCommand(CancellationEvidence);
impl VerifiedHeldCommand {
    /// Test-only fixture construction, not authentication. Production seal
    /// construction is confined to the private author_stop verifier after its
    /// separately enrolled purpose and original-command checks. No public or
    /// unchecked constructor exists; Rust unsafe would not prove authority.
    #[cfg(test)]
    pub(crate) fn for_test_command(
        origin_db_id: &str,
        principal: &str,
        operation: &str,
        prepared: &Value,
        intent: Option<&str>,
        app: Option<&crate::mcp::app_attribution::AppAttribution>,
    ) -> Result<Self> {
        let object = prepared
            .as_object()
            .ok_or_else(|| Error::engine(MISMATCH))?;
        let common = [
            "reason",
            "run_key",
            "parent_key",
            "idempotency_key",
            "response_mode",
            "sources",
        ];
        let fields: &[&str] = match operation {
            "create_record"
                if matches!(
                    (prepared["type"].as_str(), prepared["kind"].as_str()),
                    (Some("Document"), Some("note")) | (Some("WorkItem"), Some("task"))
                ) =>
            {
                &[
                    "id", "type", "kind", "name", "body", "home_id", "summary", "confirm",
                ]
            }
            "update_record"
                if prepared["body_append"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty()) =>
            {
                &["id", "record_id", "body_append"]
            }
            _ => return Err(Error::engine("held_command_cancellation_unsupported")),
        };
        if object
            .keys()
            .any(|k| !common.contains(&k.as_str()) && !fields.contains(&k.as_str()))
            || object.get("sources").is_some_and(|v| v != &json!([]))
        {
            return Err(Error::engine("held_command_cancellation_unsupported"));
        }
        let evidence = CancellationEvidence {
            origin_db_id: origin_db_id.into(),
            principal: principal.into(),
            operation: operation.into(),
            command_identity_digest: command_identity_digest(prepared)
                .ok_or_else(|| Error::engine(MISMATCH))?,
            action_digest: action_digest(operation, prepared),
            intent_digest: intent.map(|v| digest_json(&json!(v))),
            app_context_digest: app_digest(app),
        };
        evidence.validate()?;
        Ok(Self(evidence))
    }
}

#[derive(Debug, PartialEq, Eq)]
#[must_use = "a staged cancellation is not durable until the caller commits its transaction"]
#[allow(dead_code)]
pub(crate) enum StagedCancellation {
    Cancelled { event_id: String },
    AlreadySaved { attestation_id: String },
}

pub(super) fn app_digest(app: Option<&crate::mcp::app_attribution::AppAttribution>) -> String {
    digest_json(&match app {
        Some(app) => {
            json!({"assertion":"host", "package":app.package, "version":app.version, "install_event_id":app.install_event_id})
        }
        None => json!({"assertion":"none"}),
    })
}

async fn anchored_in(
    tx: &mut Transaction<'_, Sqlite>,
    principal: &str,
    operation: &str,
    command: &str,
) -> Result<Option<(String, CancellationEvidence)>> {
    let row = sqlx::query("SELECT c.event_id,e.payload FROM provenance_local_command_cancellations c JOIN control_events e ON e.id=c.event_id WHERE c.principal=? AND c.operation=? AND c.command_identity_digest=?")
        .bind(principal).bind(operation).bind(command).fetch_optional(&mut **tx).await?;
    row.map(|r| {
        Ok((
            r.try_get("event_id")?,
            serde_json::from_str(&r.try_get::<String, _>("payload")?)?,
        ))
    })
    .transpose()
}

/// Called inside keyed lookup AND attestation issuance. Even a delayed direct
/// same-key request is fenced; changed input/app/intent cannot evade the key.
pub(super) async fn guard_in(
    tx: &mut Transaction<'_, Sqlite>,
    principal: &str,
    operation: &str,
    command: Option<&str>,
    action: &str,
    intent: Option<&str>,
    app: &str,
) -> Result<()> {
    if !matches!(operation, "create_record" | "update_record") {
        return Ok(());
    }
    let Some(command) = command else {
        return Ok(());
    };
    #[cfg(test)]
    tests::checkpoint().await?;
    if let Some((_, evidence)) = anchored_in(tx, principal, operation, command).await? {
        evidence.validate()?;
        let origin: String =
            sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
                .fetch_one(&mut **tx)
                .await?;
        if evidence.origin_db_id != origin {
            return Err(Error::engine(MISMATCH));
        }
        if evidence.action_digest != action
            || evidence.intent_digest.as_deref() != intent
            || evidence.app_context_digest != app
        {
            return Err(Error::engine(MISMATCH));
        }
        return Err(Error::engine(CANCELLED));
    }
    Ok(())
}

/// SQLite transaction only, crate-private, no automatic dispatch or admission.
/// Never return this staged result to a person before the owner commits.
#[allow(dead_code)]
pub(crate) async fn cancel_in(
    tx: &mut Transaction<'_, Sqlite>,
    verified: &VerifiedHeldCommand,
) -> Result<StagedCancellation> {
    crate::storage_profile::enforce_command_cancellation_on(tx).await?;
    let evidence = &verified.0;
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    if origin != evidence.origin_db_id {
        return Err(Error::engine(MISMATCH));
    }
    if let Some((event_id, existing)) = anchored_in(
        tx,
        &evidence.principal,
        &evidence.operation,
        &evidence.command_identity_digest,
    )
    .await?
    {
        if &existing != evidence {
            return Err(Error::engine(MISMATCH));
        }
        return Ok(StagedCancellation::Cancelled { event_id });
    }
    // DO NOT use a negative lookup outside this writer transaction as proof.
    let row = sqlx::query("SELECT a.id,a.action_digest,a.intent_digest FROM provenance_action_attestations a JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id WHERE l.principal=? AND l.operation=? AND l.command_identity_digest=?")
        .bind(&evidence.principal).bind(&evidence.operation).bind(&evidence.command_identity_digest).fetch_optional(&mut **tx).await?;
    if let Some(row) = row {
        let id: String = row.try_get("id")?;
        let app = sqlx::query("SELECT package,version,install_event_id FROM provenance_action_app_attributions WHERE action_attestation_id=?")
            .bind(&id).fetch_optional(&mut **tx).await?.map(|r| crate::mcp::app_attribution::AppAttribution::new(r.get::<String,_>("package"),r.get::<String,_>("version"),r.get::<String,_>("install_event_id"))).transpose()?;
        if row.try_get::<String, _>("action_digest")? != evidence.action_digest
            || row.try_get::<Option<String>, _>("intent_digest")? != evidence.intent_digest
            || app_digest(app.as_ref()) != evidence.app_context_digest
        {
            return Err(Error::engine(MISMATCH));
        }
        return Ok(StagedCancellation::AlreadySaved { attestation_id: id });
    }
    let mut act = crate::act::ActAllocation::new();
    let event = append_control_event_in(
        tx,
        NewControlEvent::authored(
            format!("held-command-cancel:{}", evidence.identity_digest()),
            evidence.identity_digest(),
            &evidence.principal,
            None,
            "Cancelled an unaccepted held command.",
            ControlEventPayload::HeldCommandCancelled(evidence.clone()),
        )?,
        &mut act,
    )
    .await?;
    sqlx::query("INSERT INTO provenance_local_command_cancellations(event_id,origin_db_id,principal,operation,command_identity_digest,action_digest,intent_digest,app_context_digest) VALUES(?,?,?,?,?,?,?,?)")
        .bind(&event.id).bind(&evidence.origin_db_id).bind(&evidence.principal).bind(&evidence.operation)
        .bind(&evidence.command_identity_digest).bind(&evidence.action_digest).bind(&evidence.intent_digest).bind(&evidence.app_context_digest)
        .execute(&mut **tx).await?;
    Ok(StagedCancellation::Cancelled { event_id: event.id })
}

pub(super) async fn state_violations_on(conn: &mut sqlx::SqliteConnection) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT c.*,e.type,e.payload, EXISTS(SELECT 1 FROM database_identity_audit d WHERE d.new_origin_db_id=c.origin_db_id) AS origin_known FROM provenance_local_command_cancellations c LEFT JOIN control_events e ON e.id=c.event_id").fetch_all(&mut *conn).await?;
    let mut violations = Vec::new();
    for row in rows {
        let valid = (|| -> Result<bool> {
            let e: CancellationEvidence =
                serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
            e.validate()?;
            Ok(
                row.try_get::<String, _>("type")? == "held_command.cancelled.v1"
                    && row.try_get::<bool, _>("origin_known")?
                    && row.try_get::<String, _>("origin_db_id")? == e.origin_db_id
                    && row.try_get::<String, _>("principal")? == e.principal
                    && row.try_get::<String, _>("operation")? == e.operation
                    && row.try_get::<String, _>("command_identity_digest")?
                        == e.command_identity_digest
                    && row.try_get::<String, _>("action_digest")? == e.action_digest
                    && row.try_get::<Option<String>, _>("intent_digest")? == e.intent_digest
                    && row.try_get::<String, _>("app_context_digest")? == e.app_context_digest,
            )
        })()
        .unwrap_or(false);
        if !valid {
            violations.push(format!(
                "cancellation {} local authority is inconsistent",
                row.get::<String, _>("event_id")
            ));
        }
    }
    let conflicts: Vec<String> = sqlx::query_scalar("SELECT c.event_id FROM provenance_local_command_cancellations c JOIN provenance_local_attestation_authority a ON a.principal=c.principal AND a.operation=c.operation AND a.command_identity_digest=c.command_identity_digest")
        .fetch_all(&mut *conn).await?;
    for id in conflicts {
        violations.push(format!(
            "cancellation {id} conflicts with a locally committed command"
        ));
    }
    Ok(violations)
}

#[cfg(test)]
mod tests;

#[cfg(feature = "mcp-executor-prototype")]
mod author_stop;
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) use author_stop::{fingerprint, initialize, preflight, stage};

#[cfg(feature = "mcp-executor-prototype")]
mod lookup;
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) use lookup::{lookup, LocalEvidenceData};
