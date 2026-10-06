//! Gated v2 definition-adoption seam (E1, test-only).
//!
//! Increment 3 carries the pure request-key validator (needed by the gated
//! fold); the transaction-scoped append/read seam lands in Increment 4.

use sqlx::{Sqlite, SqliteConnection, Transaction};

use crate::error::{Error, Result};
use crate::meta::definition_artifact::{validate_family_version, RevisionIdentity};
use crate::meta::events::DefinitionAdoptionSetV1Payload;
use crate::meta::log::{append_meta_in, MetaAppendSpec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdoptionChoice {
    pub selected: Option<RevisionIdentity>,
    pub event_seq: i64,
}

pub(crate) fn validate_request_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 128 || key.trim() != key || key.chars().any(char::is_control) {
        return Err(Error::engine("definition adoption request_key must be 1..128 non-control bytes without surrounding whitespace"));
    }
    Ok(())
}

/// Append an explicit selection or disable tombstone. The projector verifies
/// selected revisions against the installed projection in this transaction.
/// Every call appends, including a repeated choice; adoption idempotency is a
/// later caller policy, not a property of this primitive.
pub(crate) async fn append_definition_adoption_in(
    tx: &mut Transaction<'static, Sqlite>,
    family: &str,
    selected: Option<&RevisionIdentity>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<AdoptionChoice> {
    append_definition_adoption_keyed_in(tx, family, selected, None, None, act_alloc).await
}

pub(crate) async fn append_definition_adoption_keyed_in(
    tx: &mut Transaction<'static, Sqlite>,
    family: &str,
    selected: Option<&RevisionIdentity>,
    request_key: Option<&str>,
    actor: Option<&str>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<AdoptionChoice> {
    validate_family_version(family, 0)?;
    if let Some(key) = request_key {
        validate_request_key(key)?;
    }
    if selected.is_some_and(|s| s.family != family) {
        return Err(Error::engine(
            "definition adoption selected family mismatch",
        ));
    }
    let payload = DefinitionAdoptionSetV1Payload {
        family: family.to_string(),
        selected: selected.cloned(),
        request_key: request_key.map(str::to_owned),
    };
    let event = append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            format!("definition-adoption:{family}"),
            "definition_adoption.set.v1",
            serde_json::to_value(payload)?,
        )
        .with_actor(actor),
        act_alloc,
    )
    .await?;
    let choice = read_definition_adoption_on(&mut *tx, family)
        .await?
        .ok_or_else(|| Error::engine("definition adoption projection missing after append"))?;
    if choice.event_seq != event.seq || choice.selected.as_ref() != selected {
        return Err(Error::engine(
            "definition adoption projection disagrees with appended event",
        ));
    }
    Ok(choice)
}

/// Verify projection columns, the referenced event, and any selected artifact.
pub(crate) async fn read_definition_adoption_on(
    conn: &mut SqliteConnection,
    family: &str,
) -> Result<Option<AdoptionChoice>> {
    validate_family_version(family, 0)?;
    let row: Option<(Option<i64>, Option<String>, i64)> = sqlx::query_as(
        "SELECT selected_version, selected_digest, event_seq FROM definition_adoptions WHERE family = ?",
    )
    .bind(family)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((version, digest, event_seq)) = row else {
        return Ok(None);
    };
    let latest_seq: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(seq) FROM meta_events WHERE subject_id = ? AND type = 'definition_adoption.set.v1'",
    )
    .bind(format!("definition-adoption:{family}"))
    .fetch_one(&mut *conn)
    .await?;
    if latest_seq != Some(event_seq) {
        return Err(Error::engine(
            "adoption projection is not at the latest family event",
        ));
    }
    let selected = match (version, digest) {
        (None, None) => None,
        (Some(version), Some(digest)) => Some(RevisionIdentity {
            family: family.to_string(),
            version: u32::try_from(version)
                .map_err(|_| Error::engine("invalid adoption projection version"))?,
            digest,
        }),
        _ => return Err(Error::engine("incomplete adoption projection identity")),
    };
    let event: Option<(String, String, String)> =
        sqlx::query_as("SELECT subject_id, type, payload FROM meta_events WHERE seq = ?")
            .bind(event_seq)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((subject, event_type, payload)) = event else {
        return Err(Error::engine(
            "adoption projection references missing event",
        ));
    };
    let raw: serde_json::Value = serde_json::from_str(&payload)?;
    if raw.get("selected").is_none() {
        return Err(Error::engine(
            "adoption event omits explicit selected choice",
        ));
    }
    let event_payload: DefinitionAdoptionSetV1Payload = serde_json::from_value(raw)?;
    if subject != format!("definition-adoption:{family}")
        || event_type != "definition_adoption.set.v1"
        || event_payload.family != family
        || event_payload.selected != selected
    {
        return Err(Error::engine(
            "adoption projection disagrees with referenced event",
        ));
    }
    if let Some(selected) = &selected {
        if crate::definition_registry::read_definition_artifact_on(
            conn,
            family,
            selected.version,
            &selected.digest,
        )
        .await?
        .is_none()
        {
            return Err(Error::engine(
                "adoption projection selects missing definition artifact",
            ));
        }
    }
    Ok(Some(AdoptionChoice {
        selected,
        event_seq,
    }))
}
