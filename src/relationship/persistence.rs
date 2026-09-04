use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::{Error, Result};

use super::{
    AppendedRelationshipEvent, AssertionCreatedV1, CreateRelationshipWithAssertion,
    CreatedRelationshipWithAssertion, RelationshipCreatedV1, RelationshipEventCoordinate,
    RelationshipEventPayload, RelationshipEventSpec, StreamKind,
};

const APPEND_SAVEPOINT: &str = "native_relationship_append";
const CREATE_SAVEPOINT: &str = "native_relationship_create";

#[cfg(test)]
tokio::task_local! {
    static FORCE_ATOMIC_ASSERTION_WRITE_FAILURE: ();
}

pub(crate) async fn append_relationship_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
) -> Result<AppendedRelationshipEvent> {
    sqlx::query(&format!("SAVEPOINT {APPEND_SAVEPOINT}"))
        .execute(&mut **tx)
        .await?;
    match append_relationship_event_core_in(tx, spec, true, false).await {
        Ok(event) => {
            sqlx::query(&format!("RELEASE {APPEND_SAVEPOINT}"))
                .execute(&mut **tx)
                .await?;
            Ok(event)
        }
        Err(error) => {
            rollback_savepoint(tx, APPEND_SAVEPOINT).await?;
            Err(error)
        }
    }
}

async fn append_relationship_event_core_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
    capture_provenance: bool,
    federated_projection: bool,
) -> Result<AppendedRelationshipEvent> {
    spec.validate()?;
    if spec.payload.stream_kind() == StreamKind::Relationship
        && spec.issuer_origin_db_id != spec.relationship.relationship_origin_db_id
    {
        return Err(Error::engine(
            "relationship stream issuer must equal relationship origin",
        ));
    }
    let fingerprint = spec.fingerprint()?;

    // Event identity is the durable idempotency coordinate. Check it before
    // stream CAS so an exact retry remains a no-op after later stream writes.
    if let Some(existing) = existing_event_in(tx, &spec.issuer_origin_db_id, &spec.event_id).await?
    {
        if existing.fingerprint != fingerprint {
            return Err(Error::conflict(
                "relationship event identity collision with a different canonical fingerprint",
            ));
        }
        if !super::projector::projection_matches_retry_in(tx, spec).await? {
            return Err(Error::engine(
                "exact relationship event retry found a missing or divergent projection",
            ));
        }
        return Ok(AppendedRelationshipEvent {
            seq: existing.seq,
            stream_version: existing.stream_version,
            exact_retry: true,
            fingerprint,
        });
    }

    let current_version: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(stream_version),0) FROM relationship_events
         WHERE issuer_origin_db_id=?1 AND stream_kind=?2 AND stream_id=?3",
    )
    .bind(&spec.issuer_origin_db_id)
    .bind(spec.payload.stream_kind().as_str())
    .bind(&spec.stream_id)
    .fetch_one(&mut **tx)
    .await?;
    if current_version != spec.expected_stream_version {
        return Err(Error::conflict(format!(
            "relationship stream compare-and-set failed: expected {}, found {current_version}",
            spec.expected_stream_version
        )));
    }

    super::projector::validate_transition_in(tx, spec).await?;
    let stream_version = spec.stream_version()?;
    let payload = String::from_utf8(crate::derivation::canonical_json(&spec.payload.value()?))
        .expect("canonical JSON is UTF-8");
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO relationship_events
         (id,stream_kind,stream_id,stream_version,relationship_origin_db_id,
          relationship_id,type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
         RETURNING seq",
    )
    .bind(&spec.event_id)
    .bind(spec.payload.stream_kind().as_str())
    .bind(&spec.stream_id)
    .bind(stream_version)
    .bind(&spec.relationship.relationship_origin_db_id)
    .bind(&spec.relationship.relationship_id)
    .bind(spec.payload.event_type())
    .bind(payload)
    .bind(&spec.actor)
    .bind(&spec.issuer_origin_db_id)
    .bind(&spec.occurred_at)
    .bind(&spec.ingested_at)
    .fetch_one(&mut **tx)
    .await?;
    if federated_projection {
        super::projector::apply_federated_event_in(tx, spec, stream_version).await?;
    } else {
        super::projector::apply_event_in(tx, spec, stream_version).await?;
    }
    if capture_provenance {
        crate::provenance::note_appended_output(
            crate::provenance::OutputDomain::Relationship,
            &spec.event_id,
        );
    }
    Ok(AppendedRelationshipEvent {
        seq,
        stream_version,
        exact_retry: false,
        fingerprint,
    })
}

pub(crate) async fn create_relationship_with_assertion_in(
    tx: &mut Transaction<'_, Sqlite>,
    command: &CreateRelationshipWithAssertion,
) -> Result<CreatedRelationshipWithAssertion> {
    validate_atomic_command(command)?;
    sqlx::query(&format!("SAVEPOINT {CREATE_SAVEPOINT}"))
        .execute(&mut **tx)
        .await?;
    let result = async {
        let relationship =
            append_relationship_event_core_in(tx, &command.relationship_event, true, false).await?;
        #[cfg(test)]
        if FORCE_ATOMIC_ASSERTION_WRITE_FAILURE
            .try_with(|_| ())
            .is_ok()
        {
            return Err(Error::engine("forced atomic assertion write failure"));
        }
        let assertion =
            append_relationship_event_core_in(tx, &command.assertion_event, true, false).await?;
        if relationship.exact_retry != assertion.exact_retry {
            return Err(Error::engine(
                "atomic relationship creation found only one previously committed origin event",
            ));
        }
        Ok(CreatedRelationshipWithAssertion {
            relationship,
            assertion,
        })
    }
    .await;
    match result {
        Ok(created) => {
            sqlx::query(&format!("RELEASE {CREATE_SAVEPOINT}"))
                .execute(&mut **tx)
                .await?;
            Ok(created)
        }
        Err(error) => {
            rollback_savepoint(tx, CREATE_SAVEPOINT).await?;
            Err(error)
        }
    }
}

pub(super) async fn replay_relationship_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
) -> Result<AppendedRelationshipEvent> {
    append_relationship_event_core_in(tx, spec, false, false).await
}

/// Sealed preserved-origin append. The raw event stays byte-semantically
/// faithful to the issuer, while the projector resolves endpoint record ids
/// independently on the receiver.
pub(super) async fn append_federated_relationship_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: &RelationshipEventSpec,
) -> Result<AppendedRelationshipEvent> {
    append_relationship_event_core_in(tx, spec, false, true).await
}

#[cfg(test)]
pub(super) async fn with_forced_atomic_assertion_write_failure<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    FORCE_ATOMIC_ASSERTION_WRITE_FAILURE.scope((), future).await
}

pub(crate) async fn create_relationship_with_assertion(
    db: &crate::Db,
    command: &CreateRelationshipWithAssertion,
) -> Result<CreatedRelationshipWithAssertion> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    match create_relationship_with_assertion_in(&mut tx, command).await {
        Ok(created) => {
            db.commit_content(tx).await?;
            Ok(created)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

/// Preallocate both aggregate and event identities once. Retriers must retain
/// and resubmit the returned command; no ID is minted in the append/CAS loop.
pub(crate) fn prepare_relationship_with_assertion(
    issuer_origin_db_id: &str,
    actor: &str,
    occurred_at: &str,
    ingested_at: &str,
    relationship_created: RelationshipCreatedV1,
    mut assertion_created: AssertionCreatedV1,
) -> Result<CreateRelationshipWithAssertion> {
    if !crate::identity::is_database_id(issuer_origin_db_id) {
        return Err(Error::engine(
            "invalid relationship issuer database identity",
        ));
    }
    let relationship_id = Uuid::new_v4().to_string();
    let assertion_id = Uuid::new_v4().to_string();
    let relationship_event_id = Uuid::new_v4().to_string();
    let assertion_event_id = Uuid::new_v4().to_string();
    let coordinate = super::RelationshipCoordinate {
        relationship_origin_db_id: issuer_origin_db_id.into(),
        relationship_id: relationship_id.clone(),
        relationship_revision: 1,
    };
    assertion_created.relationship = coordinate.clone();
    assertion_created.relationship_created_event = RelationshipEventCoordinate {
        issuer_origin_db_id: issuer_origin_db_id.into(),
        event_id: relationship_event_id.clone(),
    };
    let command = CreateRelationshipWithAssertion {
        relationship_event: RelationshipEventSpec {
            event_id: relationship_event_id,
            stream_id: relationship_id,
            expected_stream_version: 0,
            relationship: coordinate.clone(),
            payload: RelationshipEventPayload::RelationshipCreated(relationship_created),
            actor: actor.into(),
            issuer_origin_db_id: issuer_origin_db_id.into(),
            occurred_at: occurred_at.into(),
            ingested_at: ingested_at.into(),
        },
        assertion_event: RelationshipEventSpec {
            event_id: assertion_event_id,
            stream_id: assertion_id,
            expected_stream_version: 0,
            relationship: coordinate,
            payload: RelationshipEventPayload::AssertionCreated(assertion_created),
            actor: actor.into(),
            issuer_origin_db_id: issuer_origin_db_id.into(),
            occurred_at: occurred_at.into(),
            ingested_at: ingested_at.into(),
        },
    };
    validate_atomic_command(&command)?;
    Ok(command)
}

fn validate_atomic_command(command: &CreateRelationshipWithAssertion) -> Result<()> {
    command.relationship_event.validate()?;
    command.assertion_event.validate()?;
    if !matches!(
        command.relationship_event.payload,
        RelationshipEventPayload::RelationshipCreated(_)
    ) || !matches!(
        command.assertion_event.payload,
        RelationshipEventPayload::AssertionCreated(_)
    ) || command.relationship_event.relationship != command.assertion_event.relationship
        || command.relationship_event.expected_stream_version != 0
        || command.assertion_event.expected_stream_version != 0
    {
        return Err(Error::engine(
            "atomic relationship creation requires one relationship-created and one assertion-created genesis",
        ));
    }
    if let RelationshipEventPayload::AssertionCreated(created) = &command.assertion_event.payload {
        if created.relationship_created_event.issuer_origin_db_id
            != command.relationship_event.issuer_origin_db_id
            || created.relationship_created_event.event_id != command.relationship_event.event_id
        {
            return Err(Error::engine(
                "initial assertion must pin the exact relationship-created event",
            ));
        }
    }
    Ok(())
}

async fn rollback_savepoint(tx: &mut Transaction<'_, Sqlite>, savepoint: &str) -> Result<()> {
    sqlx::query(&format!("ROLLBACK TO {savepoint}"))
        .execute(&mut **tx)
        .await?;
    sqlx::query(&format!("RELEASE {savepoint}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

struct ExistingEvent {
    seq: i64,
    stream_version: i64,
    fingerprint: String,
}

async fn existing_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    issuer_origin_db_id: &str,
    event_id: &str,
) -> Result<Option<ExistingEvent>> {
    let Some(row) = sqlx::query(
        "SELECT seq,id,stream_kind,stream_id,stream_version,relationship_origin_db_id,
                relationship_id,type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at
         FROM relationship_events WHERE issuer_origin_db_id=?1 AND id=?2",
    )
    .bind(issuer_origin_db_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let stream_version: i64 = row.try_get("stream_version")?;
    let event_type: String = row.try_get("type")?;
    let payload_json: String = row.try_get("payload")?;
    let payload = super::parse_event_payload(&event_type, serde_json::from_str(&payload_json)?)?;
    let stored = RelationshipEventSpec {
        event_id: row.try_get("id")?,
        stream_id: row.try_get("stream_id")?,
        expected_stream_version: stream_version - 1,
        relationship: super::RelationshipCoordinate {
            relationship_origin_db_id: row.try_get("relationship_origin_db_id")?,
            relationship_id: row.try_get("relationship_id")?,
            relationship_revision: 1,
        },
        payload,
        actor: row.try_get("actor")?,
        issuer_origin_db_id: row.try_get("issuer_origin_db_id")?,
        occurred_at: row.try_get("occurred_at")?,
        ingested_at: row.try_get("ingested_at")?,
    };
    let stored_kind: String = row.try_get("stream_kind")?;
    if stored_kind != stored.payload.stream_kind().as_str() {
        return Err(Error::engine(
            "stored relationship event stream-kind mismatch",
        ));
    }
    Ok(Some(ExistingEvent {
        seq: row.try_get("seq")?,
        stream_version,
        fingerprint: stored.fingerprint()?,
    }))
}
