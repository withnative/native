//! Closed `native.relationship.v1` interchange and receiver quarantine.
//!
//! Preserved relationship identities can only enter through this sealed child
//! of the relationship append kernel. The outer context is intentionally
//! opaque: a transport verifier may construct it after authenticating a peer,
//! while ordinary relationship callers cannot turn JSON into receiver trust.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;

use super::{RelationshipCoordinate, RelationshipEventPayload, RelationshipEventSpec, StreamKind};

const CONTENT_VERSION: &str = "native.relationship.v1";
const MAX_CONTENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_UNITS: usize = 256;
const MAX_EVENTS: usize = 2048;
const MAX_ATTESTATIONS: usize = 2048;
const MAX_OUTPUTS: usize = 8192;
const MAX_JSON_DEPTH: usize = 24;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_TOKEN_BYTES: usize = 4096;
const SUPPORTED_CAPABILITIES: [&str; 2] = ["origin_action_attestations", "relationship_streams"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelationshipFederationBackend {
    Sqlite,
    TursoLocal,
    Postgres,
}

impl RelationshipFederationBackend {
    pub(crate) fn require_qualified(self) -> Result<()> {
        match self {
            Self::Sqlite => Ok(()),
            Self::TursoLocal | Self::Postgres => Err(Error::engine(
                "native.relationship.v1 is not qualified for this storage backend",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum UnitKindV1 {
    RelationshipStream,
    AssertionStream,
}

impl UnitKindV1 {
    fn stream_kind(self) -> StreamKind {
        match self {
            Self::RelationshipStream => StreamKind::Relationship,
            Self::AssertionStream => StreamKind::Assertion,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::RelationshipStream => "relationship_stream",
            Self::AssertionStream => "assertion_stream",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationshipExportStream {
    pub(crate) assertion: bool,
    pub(crate) issuer_origin_db_id: String,
    pub(crate) stream_id: String,
}

impl RelationshipExportStream {
    fn unit_kind(&self) -> UnitKindV1 {
        if self.assertion {
            UnitKindV1::AssertionStream
        } else {
            UnitKindV1::RelationshipStream
        }
    }
}

/// Authenticated transport facts. Fields and constructors remain private so a
/// caller cannot assert direct-origin trust by supplying JSON.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedRelationshipEnvelopeContext {
    envelope_id: String,
    envelope_digest: [u8; 32],
    authenticated_peer_principal: String,
    cryptographically_bound_origin_db_id: Option<String>,
    received_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RelationshipFederationIngestResult {
    pub(crate) applied: usize,
    pub(crate) duplicates: usize,
    pub(crate) quarantined: usize,
    pub(crate) drained: usize,
    pub(crate) direct_origin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationshipBatchV1 {
    content_version: String,
    origin_db_id: String,
    snapshot: ApplicationSnapshotV1,
    units: Vec<RelationshipStreamUnitV1>,
    #[serde(default)]
    attestations: Vec<ActionAttestationV1>,
    #[serde(default)]
    required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationSnapshotV1 {
    source_database_id: String,
    high_water_seq: i64,
    cursor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationshipStreamUnitV1 {
    unit_kind: UnitKindV1,
    issuer_origin_db_id: String,
    stream_id: String,
    events: Vec<RelationshipEventV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationshipEventV1 {
    event_id: String,
    stream_version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor: Option<RelationshipEventCoordinateV1>,
    relationship: RelationshipCoordinate,
    event_type: String,
    payload: Value,
    actor: String,
    occurred_at: String,
    fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationshipEventCoordinateV1 {
    issuer_origin_db_id: String,
    event_id: String,
    stream_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionAttestationV1 {
    issuer_origin_db_id: String,
    id: String,
    schema_version: i64,
    principal: String,
    executor_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executor_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegation_ref: Option<String>,
    operation: String,
    action_commitment: Value,
    action_digest: String,
    output_event_set_digest: String,
    issuer: String,
    issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command_identity_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent_digest: Option<String>,
    outputs: Vec<ActionOutputV1>,
    fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionOutputV1 {
    ordinal: i64,
    domain: String,
    event_origin_db_id: String,
    event_id: String,
}

#[derive(Debug)]
struct PreparedEvent {
    unit_kind: UnitKindV1,
    wire: RelationshipEventV1,
    spec: RelationshipEventSpec,
    canonical_event: String,
}

#[derive(Debug)]
struct PreparedBatch {
    wire: RelationshipBatchV1,
    events: Vec<PreparedEvent>,
    direct_origin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingClass {
    New,
    Applied,
    Quarantined,
    Repeated,
}

/// Export explicitly named streams under one database snapshot. This cursor is
/// an application frontier over relationship event `seq`; it is unrelated to
/// relay mailbox leases and cannot acknowledge transport delivery.
pub(crate) async fn export_native_relationships(
    db: &Db,
    caller: &Caller,
    streams: &[RelationshipExportStream],
) -> Result<Vec<u8>> {
    RelationshipFederationBackend::Sqlite.require_qualified()?;
    if streams.is_empty() || streams.len() > MAX_UNITS {
        return Err(Error::engine(
            "relationship export requires 1..=256 named streams",
        ));
    }
    let mut normalized = streams.to_vec();
    normalized.sort_by(|left, right| {
        (left.unit_kind(), &left.issuer_origin_db_id, &left.stream_id).cmp(&(
            right.unit_kind(),
            &right.issuer_origin_db_id,
            &right.stream_id,
        ))
    });
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::engine(
            "relationship export stream names must be unique",
        ));
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let source_database_id: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut *tx)
            .await?;
    let high_water_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM relationship_events")
            .fetch_one(&mut *tx)
            .await?;
    authorize_export_in(&mut tx, caller, &normalized, high_water_seq).await?;

    let stream_cursor_value = normalized
        .iter()
        .map(|stream| {
            json!({
                "unit_kind": stream.unit_kind().as_str(),
                "issuer_origin_db_id": stream.issuer_origin_db_id,
                "stream_id": stream.stream_id,
            })
        })
        .collect::<Vec<_>>();
    let cursor = crate::derivation::digest_json(&json!({
        "content_version": CONTENT_VERSION,
        "source_database_id": source_database_id,
        "high_water_seq": high_water_seq,
        "streams": stream_cursor_value,
    }));

    let mut units = Vec::with_capacity(normalized.len());
    let mut required_attestations = BTreeSet::new();
    for stream in &normalized {
        let rows = sqlx::query(
            "SELECT id,stream_version,relationship_origin_db_id,relationship_id,type,payload,
                    actor,occurred_at
               FROM relationship_events
              WHERE issuer_origin_db_id=?1 AND stream_kind=?2 AND stream_id=?3 AND seq<=?4
              ORDER BY stream_version",
        )
        .bind(&stream.issuer_origin_db_id)
        .bind(stream.unit_kind().stream_kind().as_str())
        .bind(&stream.stream_id)
        .bind(high_water_seq)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            return Err(export_unavailable());
        }
        let mut events = Vec::with_capacity(rows.len());
        let mut predecessor = None;
        for row in rows {
            let event_type: String = row.try_get("type")?;
            let payload_value: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
            let payload = super::parse_event_payload(&event_type, payload_value.clone())?;
            if let RelationshipEventPayload::AssertionCreated(created) = &payload {
                required_attestations.insert((
                    stream.issuer_origin_db_id.clone(),
                    created.authoring_action_attestation_id.clone(),
                ));
            }
            let stream_version: i64 = row.try_get("stream_version")?;
            let event_id: String = row.try_get("id")?;
            let spec = RelationshipEventSpec {
                event_id: event_id.clone(),
                stream_id: stream.stream_id.clone(),
                expected_stream_version: stream_version - 1,
                relationship: RelationshipCoordinate {
                    relationship_origin_db_id: row.try_get("relationship_origin_db_id")?,
                    relationship_id: row.try_get("relationship_id")?,
                    relationship_revision: 1,
                },
                payload,
                actor: row.try_get("actor")?,
                issuer_origin_db_id: stream.issuer_origin_db_id.clone(),
                occurred_at: row.try_get("occurred_at")?,
                // Excluded from the origin fingerprint and wire contract.
                ingested_at: crate::store::now_iso(),
            };
            let fingerprint = spec.fingerprint()?;
            events.push(RelationshipEventV1 {
                event_id: event_id.clone(),
                stream_version,
                predecessor: predecessor.clone(),
                relationship: spec.relationship,
                event_type,
                payload: payload_value,
                actor: spec.actor,
                occurred_at: spec.occurred_at,
                fingerprint,
            });
            predecessor = Some(RelationshipEventCoordinateV1 {
                issuer_origin_db_id: stream.issuer_origin_db_id.clone(),
                event_id,
                stream_version,
            });
        }
        units.push(RelationshipStreamUnitV1 {
            unit_kind: stream.unit_kind(),
            issuer_origin_db_id: stream.issuer_origin_db_id.clone(),
            stream_id: stream.stream_id.clone(),
            events,
        });
    }
    let mut attestations = Vec::new();
    for (origin, id) in required_attestations {
        if let Some(attestation) = export_attestation_in(&mut tx, &origin, &id).await? {
            attestations.push(attestation);
        }
    }
    tx.rollback().await?;
    let batch = RelationshipBatchV1 {
        content_version: CONTENT_VERSION.into(),
        origin_db_id: source_database_id.clone(),
        snapshot: ApplicationSnapshotV1 {
            source_database_id,
            high_water_seq,
            cursor,
        },
        units,
        attestations,
        required_capabilities: SUPPORTED_CAPABILITIES
            .iter()
            .map(|value| (*value).into())
            .collect(),
    };
    Ok(crate::derivation::canonical_json(&serde_json::to_value(
        batch,
    )?))
}

async fn authorize_export_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    streams: &[RelationshipExportStream],
    high_water_seq: i64,
) -> Result<()> {
    for stream in streams {
        let relationship: Option<(String, String)> = if stream.assertion {
            sqlx::query_as(
                "SELECT relationship_origin_db_id,relationship_id
                   FROM relationship_events
                  WHERE issuer_origin_db_id=?1 AND stream_kind='assertion' AND stream_id=?2
                    AND seq<=?3 ORDER BY stream_version LIMIT 1",
            )
            .bind(&stream.issuer_origin_db_id)
            .bind(&stream.stream_id)
            .bind(high_water_seq)
            .fetch_optional(&mut **tx)
            .await?
        } else {
            sqlx::query_as(
                "SELECT relationship_origin_db_id,relationship_id
                   FROM relationship_events
                  WHERE issuer_origin_db_id=?1 AND stream_kind='relationship' AND stream_id=?2
                    AND seq<=?3 ORDER BY stream_version LIMIT 1",
            )
            .bind(&stream.issuer_origin_db_id)
            .bind(&stream.stream_id)
            .bind(high_water_seq)
            .fetch_optional(&mut **tx)
            .await?
        };
        let Some((relationship_origin, relationship_id)) = relationship else {
            return Err(export_unavailable());
        };
        let endpoints = sqlx::query_scalar::<_, Option<String>>(
            "SELECT record_id FROM relationship_endpoints
              WHERE relationship_origin_db_id=?1 AND relationship_id=?2 ORDER BY ordinal",
        )
        .bind(relationship_origin)
        .bind(relationship_id)
        .fetch_all(&mut **tx)
        .await?;
        if endpoints.is_empty() {
            return Err(export_unavailable());
        }
        for record_id in endpoints {
            let Some(record_id) = record_id else {
                return Err(export_unavailable());
            };
            if !crate::mcp::tools::can_record_in(tx, caller, &record_id, Capability::View).await? {
                return Err(export_unavailable());
            }
        }
    }
    Ok(())
}

fn export_unavailable() -> Error {
    Error::engine("relationship export unavailable")
}

async fn export_attestation_in(
    tx: &mut Transaction<'static, Sqlite>,
    origin: &str,
    id: &str,
) -> Result<Option<ActionAttestationV1>> {
    let local = sqlx::query(
        "SELECT id,schema_version,principal,executor_kind,executor_ref,delegation_ref,
                operation,action_commitment,action_digest,output_event_set_digest,issuer,
                issuer_origin_database_id,issued_at,command_identity_digest,intent_digest
           FROM provenance_action_attestations
          WHERE issuer_origin_database_id=?1 AND id=?2",
    )
    .bind(origin)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = local {
        let output_rows = sqlx::query(
            "SELECT ordinal,output_domain,output_event_id
               FROM provenance_action_outputs WHERE action_attestation_id=?1 ORDER BY ordinal",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await?;
        let outputs = output_rows
            .into_iter()
            .map(|output| {
                Ok(ActionOutputV1 {
                    ordinal: output.try_get("ordinal")?,
                    domain: output.try_get("output_domain")?,
                    event_origin_db_id: origin.into(),
                    event_id: output.try_get("output_event_id")?,
                })
            })
            .collect::<std::result::Result<Vec<_>, sqlx::Error>>()?;
        let mut attestation = ActionAttestationV1 {
            issuer_origin_db_id: row.try_get("issuer_origin_database_id")?,
            id: row.try_get("id")?,
            schema_version: row.try_get("schema_version")?,
            principal: row.try_get("principal")?,
            executor_kind: row.try_get("executor_kind")?,
            executor_ref: row.try_get("executor_ref")?,
            delegation_ref: row.try_get("delegation_ref")?,
            operation: row.try_get("operation")?,
            action_commitment: serde_json::from_str(
                &row.try_get::<String, _>("action_commitment")?,
            )?,
            action_digest: row.try_get("action_digest")?,
            output_event_set_digest: row.try_get("output_event_set_digest")?,
            issuer: row.try_get("issuer")?,
            issued_at: row.try_get("issued_at")?,
            command_identity_digest: row.try_get("command_identity_digest")?,
            intent_digest: row.try_get("intent_digest")?,
            outputs,
            fingerprint: String::new(),
        };
        attestation.fingerprint = attestation_fingerprint(&attestation)?;
        return Ok(Some(attestation));
    }

    let foreign = sqlx::query(
        "SELECT canonical_attestation FROM relationship_foreign_action_attestations
          WHERE issuer_origin_db_id=?1 AND attestation_id=?2",
    )
    .bind(origin)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    foreign
        .map(|row| {
            serde_json::from_str::<ActionAttestationV1>(
                &row.try_get::<String, _>("canonical_attestation")?,
            )
            .map_err(Error::from)
        })
        .transpose()
}

/// Import one authenticated batch atomically. Structurally valid events whose
/// stream predecessor or relationship proposition is absent are retained in
/// the durable quarantine and retried after every successful append.
pub(crate) async fn ingest_verified_native_relationships(
    db: &Db,
    context: VerifiedRelationshipEnvelopeContext,
    decrypted_content: &[u8],
) -> Result<RelationshipFederationIngestResult> {
    RelationshipFederationBackend::Sqlite.require_qualified()?;
    let prepared = preflight(&context, decrypted_content)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut classes = classify_all_in(&mut tx, &prepared.events).await?;
    persist_foreign_attestations_in(&mut tx, &prepared.wire.attestations).await?;

    let mut applied = 0usize;
    let mut duplicates = 0usize;
    let mut quarantined = 0usize;
    let mut order = (0..prepared.events.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| {
        let event = &prepared.events[*index];
        (
            event.unit_kind,
            event.spec.issuer_origin_db_id.clone(),
            event.spec.stream_id.clone(),
            event.wire.stream_version,
        )
    });
    for index in order {
        match classes[index] {
            ExistingClass::Applied | ExistingClass::Quarantined | ExistingClass::Repeated => {
                duplicates += 1;
            }
            ExistingClass::New => {
                let event = &prepared.events[index];
                let evidence = origin_evidence_state_in(&mut tx, event).await?;
                match dependency_state_in(&mut tx, event).await? {
                    DependencyState::Ready => {
                        append_imported_event_in(
                            &mut tx,
                            &context,
                            &prepared.wire.origin_db_id,
                            event,
                            prepared.direct_origin,
                            evidence,
                        )
                        .await?;
                        applied += 1;
                    }
                    DependencyState::Missing(reason) => {
                        quarantine_event_in(
                            &mut tx,
                            &context,
                            &prepared.wire.origin_db_id,
                            event,
                            prepared.direct_origin,
                            evidence,
                            reason,
                        )
                        .await?;
                        quarantined += 1;
                    }
                }
                classes[index] = ExistingClass::Applied;
            }
        }
    }
    let drained = drain_quarantine_in(&mut tx).await?;
    db.commit_content(tx).await?;
    Ok(RelationshipFederationIngestResult {
        applied,
        duplicates,
        quarantined,
        drained,
        direct_origin: prepared.direct_origin,
    })
}

fn preflight(context: &VerifiedRelationshipEnvelopeContext, bytes: &[u8]) -> Result<PreparedBatch> {
    if context.envelope_id.trim().is_empty()
        || context.authenticated_peer_principal.trim().is_empty()
        || validate_timestamp(&context.received_at).is_err()
        || bytes.is_empty()
        || bytes.len() > MAX_CONTENT_BYTES
        || <[u8; 32]>::from(Sha256::digest(bytes)) != context.envelope_digest
    {
        return Err(Error::engine("invalid verified relationship envelope"));
    }
    let value: Value = serde_json::from_slice(bytes)?;
    validate_json_value(&value, 1)?;
    let wire: RelationshipBatchV1 = serde_json::from_value(value)?;
    if wire.content_version != CONTENT_VERSION
        || !crate::identity::is_database_id(&wire.origin_db_id)
        || wire.snapshot.source_database_id != wire.origin_db_id
        || wire.snapshot.high_water_seq < 0
        || wire.units.is_empty()
        || wire.units.len() > MAX_UNITS
        || wire.attestations.len() > MAX_ATTESTATIONS
    {
        return Err(Error::engine("invalid native.relationship.v1 batch"));
    }
    validate_capabilities(&wire.required_capabilities)?;
    let mut unit_keys = BTreeSet::new();
    let mut stream_cursor = Vec::with_capacity(wire.units.len());
    let mut events = Vec::new();
    let mut event_identities = HashMap::<(String, String), String>::new();
    let mut last_unit_key = None;
    for unit in &wire.units {
        if !crate::identity::is_database_id(&unit.issuer_origin_db_id)
            || unit.events.is_empty()
            || !unit_keys.insert((
                unit.unit_kind,
                unit.issuer_origin_db_id.clone(),
                unit.stream_id.clone(),
            ))
        {
            return Err(Error::engine("invalid relationship stream unit"));
        }
        let unit_key = (
            unit.unit_kind,
            unit.issuer_origin_db_id.clone(),
            unit.stream_id.clone(),
        );
        if last_unit_key.as_ref().is_some_and(|last| last >= &unit_key) {
            return Err(Error::engine(
                "relationship stream units are not canonically ordered",
            ));
        }
        last_unit_key = Some(unit_key);
        stream_cursor.push(json!({
            "unit_kind":unit.unit_kind.as_str(),
            "issuer_origin_db_id":unit.issuer_origin_db_id,
            "stream_id":unit.stream_id,
        }));
        let mut previous: Option<RelationshipEventCoordinateV1> = None;
        for event in &unit.events {
            if event.stream_version <= 0 || event.stream_version > MAX_SAFE_INTEGER {
                return Err(Error::engine("invalid relationship event stream version"));
            }
            let expected_predecessor = if event.stream_version == 1 {
                None
            } else {
                event.predecessor.as_ref()
            };
            if event.stream_version == 1 && event.predecessor.is_some()
                || event.stream_version > 1 && expected_predecessor.is_none()
                || expected_predecessor.is_some_and(|predecessor| {
                    predecessor.issuer_origin_db_id != unit.issuer_origin_db_id
                        || predecessor.stream_version != event.stream_version - 1
                        || !is_canonical_uuid_v4(&predecessor.event_id)
                })
                || previous.as_ref().is_some_and(|prior| {
                    expected_predecessor != Some(prior)
                        || event.stream_version != prior.stream_version + 1
                })
            {
                return Err(Error::engine(
                    "invalid relationship event predecessor chain",
                ));
            }
            let payload = super::parse_event_payload(&event.event_type, event.payload.clone())?;
            if payload.stream_kind() != unit.unit_kind.stream_kind() {
                return Err(Error::engine(
                    "relationship unit kind does not match its event",
                ));
            }
            let spec = RelationshipEventSpec {
                event_id: event.event_id.clone(),
                stream_id: unit.stream_id.clone(),
                expected_stream_version: event.stream_version - 1,
                relationship: event.relationship.clone(),
                payload,
                actor: event.actor.clone(),
                issuer_origin_db_id: unit.issuer_origin_db_id.clone(),
                occurred_at: event.occurred_at.clone(),
                ingested_at: context.received_at.clone(),
            };
            let fingerprint = spec.fingerprint()?;
            if fingerprint != event.fingerprint || !is_digest(&event.fingerprint) {
                return Err(Error::engine("relationship event fingerprint mismatch"));
            }
            let identity = (unit.issuer_origin_db_id.clone(), event.event_id.clone());
            if event_identities
                .insert(identity, fingerprint.clone())
                .is_some_and(|existing| existing != fingerprint)
            {
                return Err(Error::conflict(
                    "relationship event identity collision in batch",
                ));
            }
            let canonical_event = String::from_utf8(crate::derivation::canonical_json(
                &serde_json::to_value(event)?,
            ))
            .expect("canonical JSON is UTF-8");
            events.push(PreparedEvent {
                unit_kind: unit.unit_kind,
                wire: event.clone(),
                spec,
                canonical_event,
            });
            previous = Some(RelationshipEventCoordinateV1 {
                issuer_origin_db_id: unit.issuer_origin_db_id.clone(),
                event_id: event.event_id.clone(),
                stream_version: event.stream_version,
            });
        }
    }
    if events.len() > MAX_EVENTS {
        return Err(Error::engine("relationship event limit exceeded"));
    }
    let expected_cursor = crate::derivation::digest_json(&json!({
        "content_version":CONTENT_VERSION,
        "source_database_id":wire.snapshot.source_database_id,
        "high_water_seq":wire.snapshot.high_water_seq,
        "streams":stream_cursor,
    }));
    if wire.snapshot.cursor != expected_cursor {
        return Err(Error::engine(
            "relationship application snapshot cursor mismatch",
        ));
    }
    let mut attestation_keys = BTreeSet::new();
    let mut output_count = 0usize;
    for attestation in &wire.attestations {
        validate_attestation(attestation)?;
        output_count += attestation.outputs.len();
        if output_count > MAX_OUTPUTS
            || !attestation_keys.insert((
                attestation.issuer_origin_db_id.clone(),
                attestation.id.clone(),
            ))
        {
            return Err(Error::engine("invalid relationship attestation set"));
        }
    }
    let direct_origin = context
        .cryptographically_bound_origin_db_id
        .as_deref()
        .is_some_and(|bound| {
            bound == wire.origin_db_id
                && events
                    .iter()
                    .all(|event| event.spec.issuer_origin_db_id == bound)
                && wire
                    .attestations
                    .iter()
                    .all(|attestation| attestation.issuer_origin_db_id == bound)
        });
    Ok(PreparedBatch {
        wire,
        events,
        direct_origin,
    })
}

fn validate_capabilities(values: &[String]) -> Result<()> {
    let canonical = values.iter().collect::<BTreeSet<_>>();
    if canonical.len() != values.len()
        || values.windows(2).any(|pair| pair[0] >= pair[1])
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > MAX_TOKEN_BYTES
                || !SUPPORTED_CAPABILITIES.contains(&value.as_str())
        })
    {
        return Err(Error::engine(
            "unsupported or non-canonical relationship capability set",
        ));
    }
    Ok(())
}

fn validate_json_value(value: &Value, depth: usize) -> Result<()> {
    if depth > MAX_JSON_DEPTH {
        return Err(Error::engine("relationship JSON depth limit exceeded"));
    }
    match value {
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .ok_or_else(|| Error::engine("relationship JSON numbers must be integers"))?;
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&integer) {
                return Err(Error::engine(
                    "relationship JSON integer is not interoperably safe",
                ));
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_json_value(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_json_value(value, depth + 1)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| Error::engine("relationship timestamp is not RFC3339"))?;
    if parsed
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
        != value
    {
        return Err(Error::engine(
            "relationship timestamp is not canonical UTC millisecond form",
        ));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_uuid_v4(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
        parsed.get_version_num() == 4 && parsed.hyphenated().to_string() == value
    })
}

fn attestation_commitment(attestation: &ActionAttestationV1) -> Value {
    json!({
        "issuer_origin_db_id":attestation.issuer_origin_db_id,
        "id":attestation.id,
        "schema_version":attestation.schema_version,
        "principal":attestation.principal,
        "executor_kind":attestation.executor_kind,
        "executor_ref":attestation.executor_ref,
        "delegation_ref":attestation.delegation_ref,
        "operation":attestation.operation,
        "action_commitment":attestation.action_commitment,
        "action_digest":attestation.action_digest,
        "output_event_set_digest":attestation.output_event_set_digest,
        "issuer":attestation.issuer,
        "issued_at":attestation.issued_at,
        "command_identity_digest":attestation.command_identity_digest,
        "intent_digest":attestation.intent_digest,
        "outputs":attestation.outputs,
    })
}

fn attestation_fingerprint(attestation: &ActionAttestationV1) -> Result<String> {
    Ok(crate::derivation::digest_json(&attestation_commitment(
        attestation,
    )))
}

fn output_digest(attestation: &ActionAttestationV1) -> String {
    match attestation.schema_version {
        1 => crate::provenance::digest_json(&json!(attestation
            .outputs
            .iter()
            .map(|output| &output.event_id)
            .collect::<Vec<_>>())),
        2 => crate::provenance::digest_json(&json!(attestation
            .outputs
            .iter()
            .map(|output| json!({"domain":output.domain,"event_id":output.event_id}))
            .collect::<Vec<_>>())),
        _ => String::new(),
    }
}

fn validate_attestation(attestation: &ActionAttestationV1) -> Result<()> {
    if !crate::identity::is_database_id(&attestation.issuer_origin_db_id)
        || attestation.id.trim().is_empty()
        || !matches!(attestation.schema_version, 1 | 2)
        || attestation.principal.trim().is_empty()
        || !matches!(
            attestation.executor_kind.as_str(),
            "human" | "agent" | "delegated_service" | "authenticated_principal" | "local"
        )
        || attestation.operation.trim().is_empty()
        || attestation.issuer.trim().is_empty()
        || !is_digest(&attestation.action_digest)
        || !is_digest(&attestation.output_event_set_digest)
        || validate_timestamp(&attestation.issued_at).is_err()
        || attestation.outputs.is_empty()
        || attestation.fingerprint != attestation_fingerprint(attestation)?
    {
        return Err(Error::engine("invalid foreign action attestation"));
    }
    for (ordinal, output) in attestation.outputs.iter().enumerate() {
        if output.ordinal != i64::try_from(ordinal).unwrap_or(i64::MAX)
            || !matches!(output.domain.as_str(), "content" | "relationship")
            || !crate::identity::is_database_id(&output.event_origin_db_id)
            || output.event_id.trim().is_empty()
            || (attestation.schema_version == 1 && output.domain != "content")
        {
            return Err(Error::engine("invalid foreign action output"));
        }
    }
    if output_digest(attestation) != attestation.output_event_set_digest {
        return Err(Error::engine("foreign action output digest mismatch"));
    }
    Ok(())
}

async fn classify_all_in(
    tx: &mut Transaction<'static, Sqlite>,
    events: &[PreparedEvent],
) -> Result<Vec<ExistingClass>> {
    let mut first = HashMap::<(String, String), usize>::new();
    let mut classes = vec![ExistingClass::New; events.len()];
    for (index, event) in events.iter().enumerate() {
        let identity = (
            event.spec.issuer_origin_db_id.clone(),
            event.spec.event_id.clone(),
        );
        if let Some(prior) = first.insert(identity, index) {
            if events[prior].wire.fingerprint != event.wire.fingerprint {
                return Err(Error::conflict(
                    "relationship event identity collision in batch",
                ));
            }
            classes[index] = ExistingClass::Repeated;
            continue;
        }
        if let Some(stored) =
            stored_event_fingerprint_in(tx, &event.spec.issuer_origin_db_id, &event.spec.event_id)
                .await?
        {
            if stored != event.wire.fingerprint {
                return Err(Error::conflict(
                    "relationship event identity collision with applied event",
                ));
            }
            classes[index] = ExistingClass::Applied;
            continue;
        }
        let quarantined: Option<String> = sqlx::query_scalar(
            "SELECT fingerprint FROM relationship_federation_quarantine
              WHERE issuer_origin_db_id=?1 AND event_id=?2",
        )
        .bind(&event.spec.issuer_origin_db_id)
        .bind(&event.spec.event_id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(stored) = quarantined {
            if stored != event.wire.fingerprint {
                return Err(Error::conflict(
                    "relationship event identity collision with quarantined event",
                ));
            }
            classes[index] = ExistingClass::Quarantined;
            continue;
        }
        let coordinate_collision: Option<(String, String)> = sqlx::query_as(
            "SELECT issuer_origin_db_id,id FROM relationship_events
              WHERE issuer_origin_db_id=?1 AND stream_kind=?2 AND stream_id=?3
                AND stream_version=?4
              UNION ALL
             SELECT issuer_origin_db_id,event_id FROM relationship_federation_quarantine
              WHERE issuer_origin_db_id=?1 AND unit_kind=?5 AND stream_id=?3
                AND stream_version=?4 LIMIT 1",
        )
        .bind(&event.spec.issuer_origin_db_id)
        .bind(event.spec.payload.stream_kind().as_str())
        .bind(&event.spec.stream_id)
        .bind(event.wire.stream_version)
        .bind(event.unit_kind.as_str())
        .fetch_optional(&mut **tx)
        .await?;
        if coordinate_collision.is_some() {
            return Err(Error::conflict(
                "relationship stream version is already occupied by another event",
            ));
        }
    }
    Ok(classes)
}

async fn stored_event_fingerprint_in(
    tx: &mut Transaction<'static, Sqlite>,
    origin: &str,
    event_id: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT id,stream_id,stream_version,relationship_origin_db_id,relationship_id,
                type,payload,actor,issuer_origin_db_id,occurred_at
           FROM relationship_events WHERE issuer_origin_db_id=?1 AND id=?2",
    )
    .bind(origin)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let event_type: String = row.try_get("type")?;
        let stream_version: i64 = row.try_get("stream_version")?;
        let spec = RelationshipEventSpec {
            event_id: row.try_get("id")?,
            stream_id: row.try_get("stream_id")?,
            expected_stream_version: stream_version - 1,
            relationship: RelationshipCoordinate {
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
            ingested_at: crate::store::now_iso(),
        };
        spec.fingerprint()
    })
    .transpose()
}

async fn persist_foreign_attestations_in(
    tx: &mut Transaction<'static, Sqlite>,
    attestations: &[ActionAttestationV1],
) -> Result<()> {
    for attestation in attestations {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT fingerprint FROM relationship_foreign_action_attestations
              WHERE issuer_origin_db_id=?1 AND attestation_id=?2",
        )
        .bind(&attestation.issuer_origin_db_id)
        .bind(&attestation.id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(existing) = existing {
            if existing != attestation.fingerprint {
                return Err(Error::conflict(
                    "foreign action attestation identity collision",
                ));
            }
            continue;
        }
        let canonical = String::from_utf8(crate::derivation::canonical_json(
            &serde_json::to_value(attestation)?,
        ))
        .expect("canonical JSON is UTF-8");
        sqlx::query(
            "INSERT INTO relationship_foreign_action_attestations
             (issuer_origin_db_id,attestation_id,schema_version,principal,operation,
              action_digest,output_event_set_digest,issued_at,canonical_attestation,fingerprint)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        )
        .bind(&attestation.issuer_origin_db_id)
        .bind(&attestation.id)
        .bind(attestation.schema_version)
        .bind(&attestation.principal)
        .bind(&attestation.operation)
        .bind(&attestation.action_digest)
        .bind(&attestation.output_event_set_digest)
        .bind(&attestation.issued_at)
        .bind(canonical)
        .bind(&attestation.fingerprint)
        .execute(&mut **tx)
        .await?;
        for output in &attestation.outputs {
            sqlx::query(
                "INSERT INTO relationship_foreign_action_outputs
                 (issuer_origin_db_id,attestation_id,ordinal,output_domain,
                  output_event_origin_db_id,output_event_id)
                 VALUES(?1,?2,?3,?4,?5,?6)",
            )
            .bind(&attestation.issuer_origin_db_id)
            .bind(&attestation.id)
            .bind(output.ordinal)
            .bind(&output.domain)
            .bind(&output.event_origin_db_id)
            .bind(&output.event_id)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn origin_evidence_state_in(
    tx: &mut Transaction<'static, Sqlite>,
    event: &PreparedEvent,
) -> Result<&'static str> {
    let RelationshipEventPayload::AssertionCreated(created) = &event.spec.payload else {
        return Ok("not_applicable");
    };
    let row = sqlx::query(
        "SELECT schema_version,output_event_set_digest,canonical_attestation
           FROM relationship_foreign_action_attestations
          WHERE issuer_origin_db_id=?1 AND attestation_id=?2",
    )
    .bind(&event.spec.issuer_origin_db_id)
    .bind(&created.authoring_action_attestation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok("missing") };
    if row.try_get::<i64, _>("schema_version")? != 2 {
        return Ok("legacy");
    }
    let canonical: ActionAttestationV1 =
        serde_json::from_str(&row.try_get::<String, _>("canonical_attestation")?)?;
    if output_digest(&canonical) != row.try_get::<String, _>("output_event_set_digest")? {
        return Err(Error::engine(
            "stored foreign action attestation output digest diverged",
        ));
    }
    let member = canonical.outputs.iter().any(|output| {
        output.domain == "relationship"
            && output.event_origin_db_id == event.spec.issuer_origin_db_id
            && output.event_id == event.spec.event_id
    });
    Ok(if member { "verified" } else { "missing_output" })
}

enum DependencyState {
    Ready,
    Missing(&'static str),
}

async fn dependency_state_in(
    tx: &mut Transaction<'static, Sqlite>,
    event: &PreparedEvent,
) -> Result<DependencyState> {
    let current: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(stream_version),0) FROM relationship_events
          WHERE issuer_origin_db_id=?1 AND stream_kind=?2 AND stream_id=?3",
    )
    .bind(&event.spec.issuer_origin_db_id)
    .bind(event.spec.payload.stream_kind().as_str())
    .bind(&event.spec.stream_id)
    .fetch_one(&mut **tx)
    .await?;
    if current < event.spec.expected_stream_version {
        return Ok(DependencyState::Missing("missing_predecessor"));
    }
    if current > event.spec.expected_stream_version {
        return Err(Error::conflict(
            "relationship stream advanced past incoming predecessor",
        ));
    }
    if let Some(predecessor) = &event.wire.predecessor {
        let known: Option<String> = sqlx::query_scalar(
            "SELECT id FROM relationship_events
              WHERE issuer_origin_db_id=?1 AND stream_kind=?2 AND stream_id=?3
                AND stream_version=?4",
        )
        .bind(&predecessor.issuer_origin_db_id)
        .bind(event.spec.payload.stream_kind().as_str())
        .bind(&event.spec.stream_id)
        .bind(predecessor.stream_version)
        .fetch_optional(&mut **tx)
        .await?;
        match known {
            None => return Ok(DependencyState::Missing("missing_predecessor")),
            Some(id) if id != predecessor.event_id => {
                return Err(Error::conflict(
                    "relationship predecessor pin conflicts with applied stream",
                ))
            }
            Some(_) => {}
        }
    }
    if event.unit_kind == UnitKindV1::AssertionStream {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM relationships
              WHERE relationship_origin_db_id=?1 AND relationship_id=?2)",
        )
        .bind(&event.spec.relationship.relationship_origin_db_id)
        .bind(&event.spec.relationship.relationship_id)
        .fetch_one(&mut **tx)
        .await?;
        if !exists {
            return Ok(DependencyState::Missing("missing_relationship"));
        }
    }
    Ok(DependencyState::Ready)
}

async fn append_imported_event_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &VerifiedRelationshipEnvelopeContext,
    source_batch_origin_db_id: &str,
    event: &PreparedEvent,
    direct_origin: bool,
    evidence_state: &str,
) -> Result<()> {
    super::persistence::append_federated_relationship_event_in(tx, &event.spec).await?;
    sqlx::query(
        "INSERT INTO relationship_federation_events
         (issuer_origin_db_id,event_id,fingerprint,source_batch_origin_db_id,envelope_id,
          authenticated_peer_principal,origin_trust_state,origin_evidence_state,received_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(issuer_origin_db_id,event_id) DO UPDATE SET
           origin_evidence_state=CASE
             WHEN relationship_federation_events.origin_evidence_state='verified' THEN 'verified'
             ELSE excluded.origin_evidence_state END",
    )
    .bind(&event.spec.issuer_origin_db_id)
    .bind(&event.spec.event_id)
    .bind(&event.wire.fingerprint)
    .bind(source_batch_origin_db_id)
    .bind(&context.envelope_id)
    .bind(&context.authenticated_peer_principal)
    .bind(if direct_origin {
        "direct_origin"
    } else {
        "relayed"
    })
    .bind(evidence_state)
    .bind(&context.received_at)
    .execute(&mut **tx)
    .await?;
    if direct_origin
        && evidence_state == "verified"
        && matches!(
            event.spec.payload,
            RelationshipEventPayload::AssertionCreated(_)
        )
    {
        mark_direct_origin_unadmitted_in(tx, event).await?;
    }
    Ok(())
}

async fn mark_direct_origin_unadmitted_in(
    tx: &mut Transaction<'static, Sqlite>,
    event: &PreparedEvent,
) -> Result<()> {
    let RelationshipEventPayload::AssertionCreated(created) = &event.spec.payload else {
        return Ok(());
    };
    let digest = crate::provenance::digest_json(&json!({
        "schema_version":1,
        "origin_admission":created.origin_admission,
        "receiver_verification":"direct_origin_evidence_only",
        "local_policy_version":1,
    }));
    sqlx::query(
        "UPDATE relationship_local_admissions
            SET local_admission_state='unadmitted',local_admission_class=NULL,
                local_reason='direct-origin evidence is verified but is not receiver-local issuance authority',
                local_evidence_digest=?1,recomputed_at=?2
          WHERE issuer_origin_db_id=?3 AND assertion_id=?4",
    )
    .bind(digest)
    .bind(&event.spec.occurred_at)
    .bind(&event.spec.issuer_origin_db_id)
    .bind(&event.spec.stream_id)
    .execute(&mut **tx)
    .await?;
    super::projector::recompute_relationship_in(
        tx,
        &event.spec.relationship.relationship_origin_db_id,
        &event.spec.relationship.relationship_id,
    )
    .await
}

async fn quarantine_event_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &VerifiedRelationshipEnvelopeContext,
    source_batch_origin_db_id: &str,
    event: &PreparedEvent,
    direct_origin: bool,
    evidence_state: &str,
    reason: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO relationship_federation_quarantine
         (issuer_origin_db_id,event_id,unit_kind,stream_id,stream_version,
          relationship_origin_db_id,relationship_id,fingerprint,canonical_event,reason,
          source_batch_origin_db_id,envelope_id,authenticated_peer_principal,
          origin_trust_state,origin_evidence_state,received_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
    )
    .bind(&event.spec.issuer_origin_db_id)
    .bind(&event.spec.event_id)
    .bind(event.unit_kind.as_str())
    .bind(&event.spec.stream_id)
    .bind(event.wire.stream_version)
    .bind(&event.spec.relationship.relationship_origin_db_id)
    .bind(&event.spec.relationship.relationship_id)
    .bind(&event.wire.fingerprint)
    .bind(&event.canonical_event)
    .bind(reason)
    .bind(source_batch_origin_db_id)
    .bind(&context.envelope_id)
    .bind(&context.authenticated_peer_principal)
    .bind(if direct_origin {
        "direct_origin"
    } else {
        "relayed"
    })
    .bind(evidence_state)
    .bind(&context.received_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn drain_quarantine_in(tx: &mut Transaction<'static, Sqlite>) -> Result<usize> {
    let mut drained = 0usize;
    loop {
        let rows = sqlx::query(
            "SELECT issuer_origin_db_id,event_id,unit_kind,stream_id,stream_version,
                    fingerprint,canonical_event,source_batch_origin_db_id,envelope_id,
                    authenticated_peer_principal,origin_trust_state,received_at
               FROM relationship_federation_quarantine
              ORDER BY CASE unit_kind WHEN 'relationship_stream' THEN 0 ELSE 1 END,
                       issuer_origin_db_id,stream_id,stream_version,event_id",
        )
        .fetch_all(&mut **tx)
        .await?;
        let mut progressed = false;
        for row in rows {
            let unit_kind = match row.try_get::<String, _>("unit_kind")?.as_str() {
                "relationship_stream" => UnitKindV1::RelationshipStream,
                "assertion_stream" => UnitKindV1::AssertionStream,
                _ => {
                    return Err(Error::engine(
                        "stored relationship quarantine unit kind is invalid",
                    ))
                }
            };
            let wire: RelationshipEventV1 =
                serde_json::from_str(&row.try_get::<String, _>("canonical_event")?)?;
            let event_type = wire.event_type.clone();
            let spec = RelationshipEventSpec {
                event_id: wire.event_id.clone(),
                stream_id: row.try_get("stream_id")?,
                expected_stream_version: wire.stream_version - 1,
                relationship: wire.relationship.clone(),
                payload: super::parse_event_payload(&event_type, wire.payload.clone())?,
                actor: wire.actor.clone(),
                issuer_origin_db_id: row.try_get("issuer_origin_db_id")?,
                occurred_at: wire.occurred_at.clone(),
                ingested_at: row.try_get("received_at")?,
            };
            let event = PreparedEvent {
                unit_kind,
                canonical_event: row.try_get("canonical_event")?,
                wire,
                spec,
            };
            if !matches!(
                dependency_state_in(tx, &event).await?,
                DependencyState::Ready
            ) {
                continue;
            }
            let stored_fingerprint: String = row.try_get("fingerprint")?;
            if stored_fingerprint != event.spec.fingerprint()? {
                return Err(Error::engine(
                    "stored quarantined relationship event fingerprint diverged",
                ));
            }
            let evidence_state = origin_evidence_state_in(tx, &event).await?;
            let direct_origin = row.try_get::<String, _>("origin_trust_state")? == "direct_origin";
            let context = VerifiedRelationshipEnvelopeContext {
                envelope_id: row.try_get("envelope_id")?,
                envelope_digest: [0; 32],
                authenticated_peer_principal: row.try_get("authenticated_peer_principal")?,
                cryptographically_bound_origin_db_id: direct_origin
                    .then(|| event.spec.issuer_origin_db_id.clone()),
                received_at: event.spec.ingested_at.clone(),
            };
            sqlx::query(
                "DELETE FROM relationship_federation_quarantine
                  WHERE issuer_origin_db_id=?1 AND event_id=?2",
            )
            .bind(&event.spec.issuer_origin_db_id)
            .bind(&event.spec.event_id)
            .execute(&mut **tx)
            .await?;
            append_imported_event_in(
                tx,
                &context,
                &row.try_get::<String, _>("source_batch_origin_db_id")?,
                &event,
                direct_origin,
                evidence_state,
            )
            .await?;
            drained += 1;
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
    Ok(drained)
}

#[cfg(test)]
impl VerifiedRelationshipEnvelopeContext {
    fn fixture(
        envelope_id: &str,
        bytes: &[u8],
        peer: &str,
        bound_origin: Option<&str>,
        received_at: &str,
    ) -> Self {
        Self {
            envelope_id: envelope_id.into(),
            envelope_digest: Sha256::digest(bytes).into(),
            authenticated_peer_principal: peer.into(),
            cryptographically_bound_origin_db_id: bound_origin.map(str::to_owned),
            received_at: received_at.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relationship::{
        AssertionCreatedV1, EndpointSemantics, OriginAdmissionV1, PropositionEndpoint,
        RelationshipCreatedV1, RelationshipEndpoint, RelationshipEventCoordinate,
        RelationshipRetiredV1,
    };

    const ORIGIN: &str = "ndb_11111111111111111111111111111111";
    const RECEIVED: &str = "2026-08-12T20:00:00.000Z";
    const RELATIONSHIP_ID: &str = "10000000-0000-4000-8000-000000000001";
    const CREATED_ID: &str = "20000000-0000-4000-8000-000000000001";
    const RETIRED_ID: &str = "20000000-0000-4000-8000-000000000002";
    const ASSERTION_ID: &str = "30000000-0000-4000-8000-000000000001";
    const ASSERTION_EVENT_ID: &str = "40000000-0000-4000-8000-000000000001";

    fn created_spec() -> RelationshipEventSpec {
        let definition = crate::relationship::core_relationship_type_manifest()
            .unwrap()
            .relationship_types
            .into_iter()
            .find(|definition| definition.id == "relates_to.v1")
            .unwrap();
        let endpoints = vec![
            PropositionEndpoint {
                role: "participant".into(),
                portable_ref: crate::identity::encode_native_record(ORIGIN, "remote:left").unwrap(),
            },
            PropositionEndpoint {
                role: "participant".into(),
                portable_ref: crate::identity::encode_native_record(ORIGIN, "remote:right")
                    .unwrap(),
            },
        ];
        let proposition = definition
            .canonical_proposition_key(&endpoints, &std::collections::BTreeMap::new())
            .unwrap();
        RelationshipEventSpec {
            event_id: CREATED_ID.into(),
            stream_id: RELATIONSHIP_ID.into(),
            expected_stream_version: 0,
            relationship: RelationshipCoordinate {
                relationship_origin_db_id: ORIGIN.into(),
                relationship_id: RELATIONSHIP_ID.into(),
                relationship_revision: 1,
            },
            payload: RelationshipEventPayload::RelationshipCreated(RelationshipCreatedV1 {
                schema_version: 1,
                relationship_revision: 1,
                relationship_type: "relates_to".into(),
                type_definition_id: "relates_to.v1".into(),
                endpoint_semantics: EndpointSemantics::Symmetric,
                endpoints: endpoints
                    .into_iter()
                    .map(|endpoint| {
                        let (_, record_id) =
                            crate::identity::decode_native_record(&endpoint.portable_ref).unwrap();
                        RelationshipEndpoint {
                            role: endpoint.role,
                            portable_ref: endpoint.portable_ref,
                            record_type: Some("Document".into()),
                            record_kind: Some("note".into()),
                            // Origin-local record ids must not be trusted by the receiver.
                            record_id: Some(record_id),
                        }
                    })
                    .collect(),
                identity_qualifiers: serde_json::Map::new(),
                canonical_proposition_key: proposition,
                reducer_id: "default".into(),
                reducer_version: 1,
                legacy_link: None,
            }),
            actor: "acct_remote".into(),
            issuer_origin_db_id: ORIGIN.into(),
            occurred_at: "2026-08-12T19:00:00.000Z".into(),
            ingested_at: RECEIVED.into(),
        }
    }

    fn retired_spec() -> RelationshipEventSpec {
        let mut spec = created_spec();
        spec.event_id = RETIRED_ID.into();
        spec.expected_stream_version = 1;
        spec.occurred_at = "2026-08-12T19:01:00.000Z".into();
        spec.payload = RelationshipEventPayload::RelationshipRetired(RelationshipRetiredV1 {
            schema_version: 1,
            reason: "origin retired proposition".into(),
        });
        spec
    }

    fn assertion_spec() -> RelationshipEventSpec {
        let relationship = RelationshipCoordinate {
            relationship_origin_db_id: ORIGIN.into(),
            relationship_id: RELATIONSHIP_ID.into(),
            relationship_revision: 1,
        };
        let endpoint_ref = crate::identity::encode_native_record(ORIGIN, "remote:left").unwrap();
        RelationshipEventSpec {
            event_id: ASSERTION_EVENT_ID.into(),
            stream_id: ASSERTION_ID.into(),
            expected_stream_version: 0,
            relationship: relationship.clone(),
            payload: RelationshipEventPayload::AssertionCreated(AssertionCreatedV1 {
                schema_version: 1,
                relationship,
                relationship_created_event: RelationshipEventCoordinate {
                    issuer_origin_db_id: ORIGIN.into(),
                    event_id: CREATED_ID.into(),
                },
                stance: "support".into(),
                semantic_claimant: "native-principal:remote".into(),
                on_behalf_of: None,
                rationale: Some("origin assertion".into()),
                valid_from: None,
                valid_until: None,
                causal_parents: Vec::new(),
                origin_admission: OriginAdmissionV1::test_fixture(
                    "relates_to.v1",
                    "anchor_authorised_support",
                    "participant",
                    &endpoint_ref,
                    "edit_either_anchor_view_both.v1",
                    &"a".repeat(64),
                    "origin-attestation-missing",
                ),
                authoring_action_attestation_id: "origin-attestation-missing".into(),
            }),
            actor: "acct_remote".into(),
            issuer_origin_db_id: ORIGIN.into(),
            occurred_at: "2026-08-12T19:00:30.000Z".into(),
            ingested_at: RECEIVED.into(),
        }
    }

    fn event(
        spec: RelationshipEventSpec,
        predecessor: Option<&RelationshipEventSpec>,
    ) -> RelationshipEventV1 {
        RelationshipEventV1 {
            event_id: spec.event_id.clone(),
            stream_version: spec.stream_version().unwrap(),
            predecessor: predecessor.map(|prior| RelationshipEventCoordinateV1 {
                issuer_origin_db_id: prior.issuer_origin_db_id.clone(),
                event_id: prior.event_id.clone(),
                stream_version: prior.stream_version().unwrap(),
            }),
            relationship: spec.relationship.clone(),
            event_type: spec.payload.event_type().into(),
            payload: spec.payload.value().unwrap(),
            actor: spec.actor.clone(),
            occurred_at: spec.occurred_at.clone(),
            fingerprint: spec.fingerprint().unwrap(),
        }
    }

    fn batch_bytes(events: Vec<RelationshipEventV1>) -> Vec<u8> {
        unit_batch_bytes("relationship_stream", RELATIONSHIP_ID, events)
    }

    fn unit_batch_bytes(
        unit_kind: &str,
        stream_id: &str,
        events: Vec<RelationshipEventV1>,
    ) -> Vec<u8> {
        let streams = vec![json!({
            "unit_kind":unit_kind,
            "issuer_origin_db_id":ORIGIN,
            "stream_id":stream_id,
        })];
        let cursor = crate::derivation::digest_json(&json!({
            "content_version":CONTENT_VERSION,
            "source_database_id":ORIGIN,
            "high_water_seq":2,
            "streams":streams,
        }));
        crate::derivation::canonical_json(&json!({
            "content_version":CONTENT_VERSION,
            "origin_db_id":ORIGIN,
            "snapshot":{"source_database_id":ORIGIN,"high_water_seq":2,"cursor":cursor},
            "units":[{
                "unit_kind":unit_kind,
                "issuer_origin_db_id":ORIGIN,
                "stream_id":stream_id,
                "events":events,
            }],
            "attestations":[],
            "required_capabilities":["origin_action_attestations","relationship_streams"],
        }))
    }

    async fn local_created_spec(db: &Db) -> RelationshipEventSpec {
        let origin: String =
            sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        for id in ["local:left", "local:right"] {
            sqlx::query(
                "INSERT INTO records(id,type,kind,policy_anchor_id)
                 VALUES(?1,'Document','note','native:root')",
            )
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        let mut spec = created_spec();
        spec.issuer_origin_db_id = origin.clone();
        spec.relationship.relationship_origin_db_id = origin.clone();
        let RelationshipEventPayload::RelationshipCreated(created) = &mut spec.payload else {
            unreachable!()
        };
        for (endpoint, record_id) in created
            .endpoints
            .iter_mut()
            .zip(["local:left", "local:right"])
        {
            endpoint.portable_ref =
                crate::identity::encode_native_record(&origin, record_id).unwrap();
            endpoint.record_id = Some(record_id.into());
        }
        let definition = crate::relationship::core_relationship_type_manifest()
            .unwrap()
            .relationship_types
            .into_iter()
            .find(|definition| definition.id == "relates_to.v1")
            .unwrap();
        created.canonical_proposition_key = definition
            .canonical_proposition_key(
                &created
                    .endpoints
                    .iter()
                    .map(RelationshipEndpoint::proposition_endpoint)
                    .collect::<Vec<_>>(),
                &std::collections::BTreeMap::new(),
            )
            .unwrap();
        spec
    }

    fn context(id: &str, bytes: &[u8], direct: bool) -> VerifiedRelationshipEnvelopeContext {
        VerifiedRelationshipEnvelopeContext::fixture(
            id,
            bytes,
            "principal:authenticated-peer",
            direct.then_some(ORIGIN),
            RECEIVED,
        )
    }

    fn attestation_for(event_id: &str) -> ActionAttestationV1 {
        let action_commitment = json!({"operation":"manage_relationships","fixture":true});
        let outputs = vec![ActionOutputV1 {
            ordinal: 0,
            domain: "relationship".into(),
            event_origin_db_id: ORIGIN.into(),
            event_id: event_id.into(),
        }];
        let mut attestation = ActionAttestationV1 {
            issuer_origin_db_id: ORIGIN.into(),
            id: "origin-attestation-missing".into(),
            schema_version: 2,
            principal: "native-principal:remote".into(),
            executor_kind: "authenticated_principal".into(),
            executor_ref: Some("native-principal:remote".into()),
            delegation_ref: None,
            operation: "manage_relationships".into(),
            action_digest: crate::provenance::digest_json(&action_commitment),
            action_commitment,
            output_event_set_digest: crate::provenance::digest_json(&json!([{
                "domain":"relationship",
                "event_id":event_id,
            }])),
            issuer: "native".into(),
            issued_at: "2026-08-12T19:00:30.000Z".into(),
            command_identity_digest: None,
            intent_digest: None,
            outputs,
            fingerprint: String::new(),
        };
        attestation.fingerprint = attestation_fingerprint(&attestation).unwrap();
        attestation
    }

    #[tokio::test]
    async fn predecessor_arrival_durably_drains_quarantine_and_redelivery_is_noop() {
        let db = crate::create_database(":memory:").await.unwrap();
        let created = created_spec();
        let retired = retired_spec();
        let later = batch_bytes(vec![event(retired.clone(), Some(&created))]);
        let first =
            ingest_verified_native_relationships(&db, context("env-later", &later, true), &later)
                .await
                .unwrap();
        assert_eq!((first.applied, first.quarantined, first.drained), (0, 1, 0));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relationship_federation_quarantine")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );

        let genesis = batch_bytes(vec![event(created, None)]);
        let second = ingest_verified_native_relationships(
            &db,
            context("env-genesis", &genesis, true),
            &genesis,
        )
        .await
        .unwrap();
        assert_eq!(
            (second.applied, second.quarantined, second.drained),
            (1, 0, 1)
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relationship_federation_quarantine")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            0
        );
        let state: String = sqlx::query_scalar(
            "SELECT status FROM relationships WHERE relationship_origin_db_id=?1 AND relationship_id=?2",
        )
        .bind(ORIGIN).bind(RELATIONSHIP_ID).fetch_one(db.write_pool()).await.unwrap();
        assert_eq!(state, "retired");

        let replay = ingest_verified_native_relationships(
            &db,
            context("env-replay", &genesis, false),
            &genesis,
        )
        .await
        .unwrap();
        assert_eq!((replay.applied, replay.duplicates), (0, 1));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relationship_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn relayed_origin_stays_unresolved_and_origin_record_ids_are_not_adopted() {
        let db = crate::create_database(":memory:").await.unwrap();
        let bytes = batch_bytes(vec![event(created_spec(), None)]);
        let result =
            ingest_verified_native_relationships(&db, context("env-relay", &bytes, false), &bytes)
                .await
                .unwrap();
        assert!(!result.direct_origin);
        let trust: String = sqlx::query_scalar(
            "SELECT origin_trust_state FROM relationship_federation_events WHERE event_id=?1",
        )
        .bind(CREATED_ID)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(trust, "relayed");
        let resolved: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM relationship_endpoints WHERE relationship_origin_db_id=?1 AND relationship_id=?2 AND record_id IS NOT NULL",
        )
        .bind(ORIGIN).bind(RELATIONSHIP_ID).fetch_one(db.write_pool()).await.unwrap();
        assert_eq!(resolved, 0);
        let effective: (String, String) = sqlx::query_as(
            "SELECT effective_state,epistemic_state FROM effective_relationships WHERE relationship_origin_db_id=?1 AND relationship_id=?2",
        )
        .bind(ORIGIN).bind(RELATIONSHIP_ID).fetch_one(db.write_pool()).await.unwrap();
        assert_eq!(effective, ("unresolved".into(), "incomplete".into()));
    }

    #[tokio::test]
    async fn same_origin_event_identity_with_a_different_fingerprint_fails_atomically() {
        let db = crate::create_database(":memory:").await.unwrap();
        let original = batch_bytes(vec![event(created_spec(), None)]);
        ingest_verified_native_relationships(
            &db,
            context("env-original", &original, true),
            &original,
        )
        .await
        .unwrap();
        let mut changed = created_spec();
        changed.actor = "acct_different".into();
        let collision = batch_bytes(vec![event(changed, None)]);
        let error = ingest_verified_native_relationships(
            &db,
            context("env-collision", &collision, true),
            &collision,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("identity collision"));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relationship_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn absent_relationship_assertion_drains_unadmitted_and_converges_by_arrival_order() {
        let assertion_bytes = unit_batch_bytes(
            "assertion_stream",
            ASSERTION_ID,
            vec![event(assertion_spec(), None)],
        );
        let relationship_bytes = batch_bytes(vec![event(created_spec(), None)]);

        let assertion_first = crate::create_database(":memory:").await.unwrap();
        let result = ingest_verified_native_relationships(
            &assertion_first,
            context("env-assertion-first", &assertion_bytes, false),
            &assertion_bytes,
        )
        .await
        .unwrap();
        assert_eq!((result.applied, result.quarantined), (0, 1));
        let result = ingest_verified_native_relationships(
            &assertion_first,
            context("env-relationship-second", &relationship_bytes, false),
            &relationship_bytes,
        )
        .await
        .unwrap();
        assert_eq!((result.applied, result.drained), (1, 1));

        let relationship_first = crate::create_database(":memory:").await.unwrap();
        ingest_verified_native_relationships(
            &relationship_first,
            context("env-relationship-first", &relationship_bytes, false),
            &relationship_bytes,
        )
        .await
        .unwrap();
        ingest_verified_native_relationships(
            &relationship_first,
            context("env-assertion-second", &assertion_bytes, false),
            &assertion_bytes,
        )
        .await
        .unwrap();

        let mut admission_counts = Vec::new();
        for db in [&assertion_first, &relationship_first] {
            let admission: (String, String) = sqlx::query_as(
                "SELECT local_admission_state,local_reason
                   FROM relationship_local_admissions
                  WHERE issuer_origin_db_id=?1 AND assertion_id=?2",
            )
            .bind(ORIGIN)
            .bind(ASSERTION_ID)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
            assert_eq!(admission.0, "unresolved");
            assert!(!admission.1.trim().is_empty());
            let effective: (String, String, String) = sqlx::query_as(
                "SELECT effective_state,epistemic_state,admission_counts
                   FROM effective_relationships
                  WHERE relationship_origin_db_id=?1 AND relationship_id=?2",
            )
            .bind(ORIGIN)
            .bind(RELATIONSHIP_ID)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
            assert_eq!(effective.0, "unresolved");
            assert_eq!(effective.1, "incomplete");
            admission_counts.push(effective.2);
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM provenance_local_attestation_authority",
                )
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
                0
            );
        }
        assert_eq!(admission_counts[0], admission_counts[1]);
    }

    #[tokio::test]
    async fn canonical_interchange_preserves_quarantine_and_foreign_evidence_without_local_trust() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("federation-source.db");
        let source = crate::create_database(source_path.to_str().unwrap())
            .await
            .unwrap();
        let mut assertion_batch: Value = serde_json::from_slice(&unit_batch_bytes(
            "assertion_stream",
            ASSERTION_ID,
            vec![event(assertion_spec(), None)],
        ))
        .unwrap();
        assertion_batch["attestations"] =
            serde_json::to_value([attestation_for(ASSERTION_EVENT_ID)]).unwrap();
        let assertion_bytes = crate::derivation::canonical_json(&assertion_batch);
        let first = ingest_verified_native_relationships(
            &source,
            context("env-quarantine", &assertion_bytes, false),
            &assertion_bytes,
        )
        .await
        .unwrap();
        assert_eq!((first.applied, first.quarantined), (0, 1));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM relationship_foreign_action_attestations",
            )
            .fetch_one(source.write_pool())
            .await
            .unwrap(),
            1
        );

        let interchange = crate::interchange::export_canonical_interchange(&source)
            .await
            .unwrap();
        let destination = temp.path().join("federation-restored.db");
        let restored = crate::interchange::import_canonical_interchange(&interchange, &destination)
            .await
            .unwrap();
        for table in [
            "relationship_federation_quarantine",
            "relationship_foreign_action_attestations",
            "relationship_foreign_action_outputs",
        ] {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                    .fetch_one(restored.write_pool())
                    .await
                    .unwrap(),
                1,
                "canonical restore lost durable federation state in {table}"
            );
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM provenance_local_attestation_authority",
            )
            .fetch_one(restored.write_pool())
            .await
            .unwrap(),
            0,
            "restoring foreign evidence must not mint receiver-local authority"
        );

        let relationship_bytes = batch_bytes(vec![event(created_spec(), None)]);
        let drained = ingest_verified_native_relationships(
            &restored,
            context("env-relationship", &relationship_bytes, false),
            &relationship_bytes,
        )
        .await
        .unwrap();
        assert_eq!((drained.applied, drained.drained), (1, 1));
        let restored_assertion: (String, String) = sqlx::query_as(
            "SELECT l.local_admission_state,f.origin_evidence_state
               FROM relationship_local_admissions l
               JOIN relationship_federation_events f
                 ON f.issuer_origin_db_id=l.issuer_origin_db_id
                AND f.event_id=?1
              WHERE l.issuer_origin_db_id=?2 AND l.assertion_id=?3",
        )
        .bind(ASSERTION_EVENT_ID)
        .bind(ORIGIN)
        .bind(ASSERTION_ID)
        .fetch_one(restored.write_pool())
        .await
        .unwrap();
        assert_eq!(restored_assertion, ("unresolved".into(), "verified".into()));
    }

    #[tokio::test]
    async fn canonical_export_import_preserves_origin_fingerprint_and_snapshot_cursor() {
        let source = crate::create_database(":memory:").await.unwrap();
        let spec = local_created_spec(&source).await;
        let source_origin = spec.issuer_origin_db_id.clone();
        let expected_fingerprint = spec.fingerprint().unwrap();
        let mut source_tx = crate::db::begin_write(source.write_pool()).await.unwrap();
        super::super::persistence::append_relationship_event_in(&mut source_tx, &spec)
            .await
            .unwrap();
        source.commit_content(source_tx).await.unwrap();

        let bytes = export_native_relationships(
            &source,
            &Caller::local(),
            &[RelationshipExportStream {
                assertion: false,
                issuer_origin_db_id: source_origin.clone(),
                stream_id: RELATIONSHIP_ID.into(),
            }],
        )
        .await
        .unwrap();
        assert_eq!(
            bytes,
            crate::derivation::canonical_json(&serde_json::from_slice::<Value>(&bytes).unwrap())
        );

        let target = crate::create_database(":memory:").await.unwrap();
        let context = VerifiedRelationshipEnvelopeContext::fixture(
            "env-roundtrip",
            &bytes,
            "principal:source-peer",
            Some(&source_origin),
            RECEIVED,
        );
        let result = ingest_verified_native_relationships(&target, context, &bytes)
            .await
            .unwrap();
        assert_eq!((result.applied, result.quarantined), (1, 0));
        let mut target_tx = crate::db::begin_write(target.write_pool()).await.unwrap();
        let imported = stored_event_fingerprint_in(&mut target_tx, &source_origin, CREATED_ID)
            .await
            .unwrap()
            .unwrap();
        target_tx.rollback().await.unwrap();
        assert_eq!(imported, expected_fingerprint);
        let parsed: RelationshipBatchV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.snapshot.high_water_seq, 1);
        assert_eq!(parsed.snapshot.source_database_id, source_origin);
    }

    #[test]
    fn secondary_backends_are_explicitly_fail_closed() {
        RelationshipFederationBackend::Sqlite
            .require_qualified()
            .unwrap();
        assert!(RelationshipFederationBackend::TursoLocal
            .require_qualified()
            .is_err());
        assert!(RelationshipFederationBackend::Postgres
            .require_qualified()
            .is_err());
    }
}
