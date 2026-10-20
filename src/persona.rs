//! Persona identity has one immutable human owner. Speaker metadata grants nothing.
use crate::{Error, Result};
use serde_json::{json, Value};
use sqlx::{Row, SqliteConnection};

/// Historical content migrations may precede the additive persona projection.
/// Only that specific missing table is equivalent to an empty projection.
pub(crate) async fn registered(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    match sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM personas WHERE persona_id=?)")
        .bind(id)
        .fetch_one(conn)
        .await
    {
        Ok(value) => Ok(value),
        Err(sqlx::Error::Database(error)) if error.message() == "no such table: personas" => {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn require_unregistered(
    conn: &mut SqliteConnection,
    id: &str,
    operation: &str,
) -> Result<()> {
    if registered(conn, id).await? {
        return Err(Error::engine(format!(
            "{operation}: registered persona identity is owner-locked; retire it instead"
        )));
    }
    Ok(())
}

/// Shared storage-free claim parser; explicit null and extra fields refuse.
pub(crate) fn claim_persona_id(claim: Option<&Value>) -> Result<Option<&str>> {
    let Some(claim) = claim else {
        return Ok(None);
    };
    let not_found = || Error::engine("manage_messages.send: speaker not found");
    let object = claim.as_object().ok_or_else(not_found)?;
    if object.len() != 1 {
        return Err(not_found());
    }
    let Some(id) = object.get("persona_id").and_then(Value::as_str) else {
        return Err(not_found());
    };
    Ok(Some(id))
}

/// Validate a claim after ordinary permission checks. Every invalid claim has
/// the same not-found refusal; identity existence is never disclosed. Claims
/// grant no authority and assurance is engine-selected.
pub(crate) async fn resolve_claim(
    conn: &mut SqliteConnection,
    claim: Option<&Value>,
    owner_person_id: &str,
    owner_principal: &str,
) -> Result<Option<crate::events::MessageSpeakerDeclaredPayload>> {
    let Some(id) = claim_persona_id(claim)? else {
        return Ok(None);
    };
    let not_found = || Error::engine("manage_messages.send: speaker not found");
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM personas p JOIN records r ON r.id=p.persona_id
          WHERE p.persona_id=? AND p.owner_person_id=? AND p.owner_principal=?
            AND p.state='active' AND r.deleted_at IS NULL AND r.type='Entity' AND r.kind='persona')")
        .bind(id).bind(owner_person_id).bind(owner_principal).fetch_one(conn).await?;
    if !valid {
        return Err(not_found());
    }
    Ok(Some(crate::events::MessageSpeakerDeclaredPayload {
        kind: "persona".into(),
        persona_id: id.into(),
        owner_principal: owner_principal.into(),
        assurance: "client_asserted".into(),
    }))
}

/// Message visibility already admitted by the caller. Disclose the speaker's
/// name as part of that utterance without granting access to the private profile.
pub(crate) async fn message_speaker(
    conn: &mut SqliteConnection,
    message_id: &str,
) -> Result<Option<Value>> {
    let row = sqlx::query(
        "SELECT s.persona_id,s.speaker_kind,s.assurance,r.name FROM message_speakers s
        LEFT JOIN records r ON r.id=s.persona_id WHERE s.message_id=?",
    )
    .bind(message_id)
    .fetch_optional(conn)
    .await?;
    row.map(|r| {
        Ok(json!({"kind":r.try_get::<String,_>("speaker_kind")?,
        "id":r.try_get::<Option<String>,_>("persona_id")?,
        "display_name":r.try_get::<Option<String>,_>("name")?,
        "assurance":r.try_get::<String,_>("assurance")?}))
    })
    .transpose()
}
