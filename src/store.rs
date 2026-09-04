//! The CONTENT write API. Every mutation is **append-event-then-project**,
//! atomically: we open a write transaction, append the event to the
//! authoritative `content_events` log, fold it into the projections via the
//! projector, and commit. There are no ad-hoc UPDATEs of the projection tables
//! anywhere outside the projector.
//!
//! The meta tier's equivalent is `crate::meta::log` over `meta_events` (ba9f97e)
//! — same discipline, separate log, separate fold.

use serde_json::{json, Map, Value};
use sqlx::Row;
use std::future::Future;
use uuid::Uuid;

use crate::db::Db;
use crate::embed::{embed, text_change_for};
use crate::error::{Error, Result};
use crate::events::{
    CausalAdmission, CausalEnvelopeV1, CausalFrontierV1, CausalStatus, EventRow, FacetSetPayload,
    LinkAddedPayload, LinkRemovedPayload,
};
use crate::meta::resolve_vocab_ref;
#[cfg(test)]
use crate::projector::project;
use crate::schema::ARCHIVED_FACET_KEY;

// The preserved-id compiler is a private child of the append kernel so it can
// reach `PreparedEvent` without exposing that authority to sibling modules.
#[path = "replication.rs"]
#[allow(dead_code)]
mod replication;
#[path = "replication_v1.rs"]
#[allow(dead_code)]
mod replication_v1;

// Sealed crate-level seam for a future authenticated transport. The context
// remains opaque: only a verifier implemented under `replication_v1` can mint
// preserved-id authority.
#[allow(unused_imports)]
pub(crate) use replication_v1::{
    export_native_messages, ingest_verified_native_message, IngestResult, IngestStatus,
    VerifiedEnvelopeContext,
};

/// Current UTC time in the DDL's timestamp shape, e.g. `2026-07-22T10:30:00.123Z`.
pub(crate) fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// One event to append: the envelope fields plus a JSON payload.
pub struct AppendSpec {
    pub record_id: String,
    pub event_type: String,
    pub payload: Value,
    pub actor: Option<String>,
}

/// Caller-stamped annotations applied to every content event appended during
/// one registry dispatch. Keeping this at the append choke point covers every
/// content-writing tool without duplicating fields across every `AppendSpec`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EventAnnotations {
    pub run_key: Option<String>,
    pub parent_key: Option<String>,
    pub intent: Option<String>,
}

/// Authenticated source facts retained for identity-preserving Native Message
/// creation. Kept private to this module and its sealed replication child.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeEventSource {
    origin_database_id: String,
    source_seq: i64,
    source_record_id: String,
    source_principal: String,
    fingerprint: [u8; 32],
}

#[derive(Debug)]
struct PreparedEvent {
    event: EventRow,
    payload: Value,
    native_source: Option<NativeEventSource>,
    governed_causal_envelope: Option<CausalEnvelopeV1>,
}

struct SqliteContentPorts<'transaction> {
    transaction: &'transaction mut sqlx::Transaction<'static, sqlx::Sqlite>,
    native_source: Option<NativeEventSource>,
}

impl crate::domain_transaction::EventCursorPort for SqliteContentPorts<'_> {
    fn append_event<'a>(
        &'a mut self,
        event: &'a mut EventRow,
        causal_admission: &'a CausalAdmission,
        control: &'a crate::portable_sql::ExecutionControl,
    ) -> futures::future::BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let causal_envelope = match causal_admission {
                CausalAdmission::LocalComputed => {
                    let heads: Vec<String> = sqlx::query_scalar(
                        "SELECT event.id
                           FROM content_events event
                          WHERE NOT EXISTS (
                                SELECT 1
                                  FROM content_event_causal_frontier frontier
                                 WHERE frontier.parent_event_id = event.id
                          )
                          ORDER BY event.id",
                    )
                    .fetch_all(&mut **self.transaction)
                    .await?;
                    if heads.is_empty() {
                        let event_count: i64 =
                            sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
                                .fetch_one(&mut **self.transaction)
                                .await?;
                        if event_count != 0 {
                            return Err(Error::engine(
                                "content event causal state has no heads for a nonempty log",
                            ));
                        }
                    }
                    CausalEnvelopeV1::complete(CausalFrontierV1::new(heads)?)
                }
                CausalAdmission::GovernedImport(envelope) => {
                    if envelope.status() == CausalStatus::LegacyUnknown {
                        return Err(Error::engine(
                            "governed imports cannot claim legacy_unknown causality",
                        ));
                    }
                    let source = self.native_source.as_ref().ok_or_else(|| {
                        Error::engine("governed causal import requires retained source provenance")
                    })?;
                    if envelope.status() == CausalStatus::Complete
                        && envelope.frontier().is_empty()
                        && source.source_seq != 1
                    {
                        return Err(Error::engine(
                            "a complete empty causal frontier is valid only for source genesis",
                        ));
                    }
                    envelope.clone()
                }
            };
            causal_envelope.validate_for_event(&event.id)?;
            for parent_event_id in causal_envelope.frontier().as_slice() {
                let closes_cycle: bool = sqlx::query_scalar(
                    "WITH RECURSIVE ancestors(event_id) AS (
                         SELECT ?
                         UNION
                         SELECT frontier.parent_event_id
                           FROM content_event_causal_frontier frontier
                           JOIN ancestors ON frontier.event_id = ancestors.event_id
                     )
                     SELECT EXISTS(SELECT 1 FROM ancestors WHERE event_id = ?)",
                )
                .bind(parent_event_id)
                .bind(&event.id)
                .fetch_one(&mut **self.transaction)
                .await?;
                if closes_cycle {
                    return Err(Error::engine("causal frontier would create a cycle"));
                }
            }
            event.causal_envelope = causal_envelope;
            let inserted = control
                .run_domain(crate::portable_sql::ExecutionPhase::Statement, async {
                    Ok(sqlx::query(
                        "INSERT INTO content_events
                            (id, record_id, type, payload, actor, run_key, parent_key, intent,
                             created_at, causal_envelope_version, causal_status)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                         RETURNING seq",
                    )
                    .bind(&event.id)
                    .bind(&event.record_id)
                    .bind(&event.event_type)
                    .bind(&event.payload)
                    .bind(&event.actor)
                    .bind(&event.run_key)
                    .bind(&event.parent_key)
                    .bind(&event.intent)
                    .bind(&event.created_at)
                    .bind(event.causal_envelope.version().as_i64())
                    .bind(event.causal_envelope.status().as_str())
                    .fetch_one(&mut **self.transaction)
                    .await)
                })
                .await
                .map_err(|error| {
                    crate::domain_transaction::stable_storage_error("append event", &error)
                })??;
            let seq = inserted.try_get::<i64, _>("seq")?;
            for parent_event_id in event.causal_envelope.frontier().as_slice() {
                sqlx::query(
                    "INSERT INTO content_event_causal_frontier(event_id,parent_event_id)
                     VALUES (?,?)",
                )
                .bind(&event.id)
                .bind(parent_event_id)
                .execute(&mut **self.transaction)
                .await?;
            }
            if let Some(source) = &self.native_source {
                sqlx::query(
                    "INSERT INTO content_event_sources
                        (event_id, origin_database_id, source_seq, source_record_id,
                         source_principal, source_fingerprint)
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(&event.id)
                .bind(&source.origin_database_id)
                .bind(source.source_seq)
                .bind(&source.source_record_id)
                .bind(&source.source_principal)
                .bind(hex::encode(source.fingerprint))
                .execute(&mut **self.transaction)
                .await?;
            }
            Ok(seq)
        })
    }
}

impl crate::domain_transaction::ProjectorPort for SqliteContentPorts<'_> {
    fn apply_projector<'a>(
        &'a mut self,
        intent: &'a crate::domain_transaction::ProjectorIntent,
        event: &'a EventRow,
        control: &'a crate::portable_sql::ExecutionControl,
    ) -> futures::future::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            control
                .run_domain(crate::portable_sql::ExecutionPhase::Statement, async {
                    Ok(crate::projector::project_intent(self.transaction, event, intent).await)
                })
                .await
                .map_err(|error| {
                    crate::domain_transaction::stable_storage_error("apply projector", &error)
                })?
        })
    }
}

tokio::task_local! {
    static EVENT_ANNOTATIONS: EventAnnotations;
    static DERIVED_BODY_AUTHORITY: DerivedBodyAuthority;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivedBodyAuthority {
    record_id: String,
    binding_id: String,
    generation: i64,
    target_version: i64,
}

/// Scope all content appends performed by `future` to one caller's validated
/// context. Task-local scope is call-local under concurrent async dispatch;
/// direct engine API calls outside the registry retain nullable annotations.
pub(crate) async fn with_event_annotations<F>(annotations: EventAnnotations, future: F) -> F::Output
where
    F: Future,
{
    EVENT_ANNOTATIONS.scope(annotations, future).await
}

pub(crate) fn current_event_annotations() -> EventAnnotations {
    EVENT_ANNOTATIONS.try_with(Clone::clone).unwrap_or_default()
}

/// Append one event and project it INSIDE an already-open write transaction.
/// This is the caller-controlled transaction scope both `append_batch` and the
/// conditional lifecycle write compose over (tool-surface finding 5): the guard,
/// the insert and the projection all run on the caller's transaction, and the
/// caller decides when to commit.
///
/// `db` is here for the `embed()` seam alone (`crate::embed`) — it carries the
/// installed embedder, if any. Do NOT take a second connection off `db.write_pool()`
/// in this scope: `tx` holds the database's write lock, and a nested writer
/// would deadlock against it until `busy_timeout` expires.
pub(crate) async fn append_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    spec: AppendSpec,
) -> Result<EventRow> {
    if spec.event_type == "record.type_corrected.v1" {
        return Err(Error::engine(
            "record.type_corrected.v1 is correction-operation-owned and cannot be appended through the generic content seam",
        ));
    }
    append_with_event_id_in(db, tx, Uuid::new_v4().to_string(), spec).await
}

/// Governed-only append capability for the prepared record-type correction
/// operation. The caller must have revalidated its bound plan in this same
/// transaction before entering this seam.
pub(crate) async fn append_record_type_correction_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    spec: AppendSpec,
) -> Result<EventRow> {
    if spec.event_type != "record.type_corrected.v1" {
        return Err(Error::engine(
            "append_record_type_correction_in accepts only record.type_corrected.v1",
        ));
    }
    append_with_event_id_in(db, tx, Uuid::new_v4().to_string(), spec).await
}

async fn append_engine_seed_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    spec: AppendSpec,
) -> Result<EventRow> {
    let prepared = prepare_sealed_local_event(Uuid::new_v4().to_string(), spec)?;
    append_prepared_engine_seed_in(db, tx, prepared).await
}

/// Sealed instruction-provisioning append. The shared domain kernel permits
/// only the fixed engine-owned instruction ids in the reserved namespace; an
/// event actor cannot acquire this capability.
pub(crate) async fn append_engine_provisioned_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    spec: AppendSpec,
) -> Result<EventRow> {
    let prepared = prepare_sealed_local_event(Uuid::new_v4().to_string(), spec)?;
    append_prepared_admitted(db, tx, prepared, PreparedAdmission::EngineProvisioning).await
}

/// Append the change-summary carrier's `record.created`. This is the ONLY
/// caller of the temporary derived-record-id exemption (see
/// `crate::domain_transaction::engine_derived_change_summary_carrier`): the
/// carrier id is a SHA-256 digest because it doubles as the workflow's reuse
/// lookup key. Nothing else may use this seam, and it must go away with the
/// exemption once reuse is keyed on a stored idempotency key instead.
pub(crate) async fn append_engine_derived_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    spec: AppendSpec,
) -> Result<EventRow> {
    let prepared = prepare_sealed_local_event(Uuid::new_v4().to_string(), spec)?;
    append_prepared_admitted(db, tx, prepared, PreparedAdmission::EngineDerived).await
}

/// Narrow publication seam for protocols whose portable event UUID must exist
/// before their content hash is computed. It preserves the ordinary append /
/// projector kernel and accepts only a canonical lowercase random UUID.
pub(crate) async fn append_with_event_id_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    event_id: String,
    spec: AppendSpec,
) -> Result<EventRow> {
    let uuid = Uuid::parse_str(&event_id)
        .map_err(|_| Error::engine("preallocated content event id must be a canonical UUIDv4"))?;
    if uuid.get_version() != Some(uuid::Version::Random)
        || uuid.hyphenated().to_string() != event_id
    {
        return Err(Error::engine(
            "preallocated content event id must be a canonical lowercase UUIDv4",
        ));
    }
    let prepared = prepare_sealed_local_event(event_id, spec)?;
    append_prepared_in(db, tx, prepared).await
}

/// Sealed body-publication seam for the derivation substrate. The ordinary
/// content event/projector remains authoritative; this capability only proves
/// that the caller holds the current binding generation and target version.
pub(crate) async fn append_derived_body_with_event_id_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    event_id: String,
    binding_id: String,
    generation: i64,
    target_version: i64,
    spec: AppendSpec,
) -> Result<EventRow> {
    if spec.event_type != "record.updated" || spec.payload.get("body").is_none() {
        return Err(Error::engine(
            "derived body publication must be one record.updated carrying body",
        ));
    }
    let authority = DerivedBodyAuthority {
        record_id: spec.record_id.clone(),
        binding_id,
        generation,
        target_version,
    };
    DERIVED_BODY_AUTHORITY
        .scope(authority, append_with_event_id_in(db, tx, event_id, spec))
        .await
}

/// Migration-only content append on the migration runner's existing
/// connection. Migration steps already own one `BEGIN IMMEDIATE` transaction;
/// opening a `Db` here would take a second connection and deadlock. Fixed
/// migration records do not use the embedding seam, but they still enter the
/// canonical content log and synchronous projector exactly once.
#[cfg(test)]
pub(crate) async fn append_migration_on(
    conn: &mut sqlx::SqliteConnection,
    event_id: impl Into<String>,
    spec: AppendSpec,
    created_at: &str,
) -> Result<EventRow> {
    let payload = normalize_payload(&spec.record_id, &spec.event_type, spec.payload);
    let mut event = EventRow {
        local_seq: -1,
        id: event_id.into(),
        record_id: spec.record_id,
        event_type: spec.event_type,
        payload: Some(serde_json::to_string(&payload)?),
        actor: spec.actor,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: created_at.into(),
        causal_envelope: CausalEnvelopeV1::legacy_unknown(),
    };
    event.local_seq = sqlx::query_scalar(
        "INSERT INTO content_events
            (id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,
             causal_envelope_version,causal_status)
         VALUES(?,?,?,?,?,NULL,NULL,NULL,?,1,'legacy_unknown') RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.record_id)
    .bind(&event.event_type)
    .bind(&event.payload)
    .bind(&event.actor)
    .bind(&event.created_at)
    .fetch_one(&mut *conn)
    .await?;
    project(&mut *conn, &event).await?;
    Ok(event)
}

fn normalize_payload(record_id: &str, event_type: &str, payload: Value) -> Value {
    crate::domain_transaction::normalize_event_payload(record_id, event_type, payload)
}

/// Private sealed-local preparation shared by the engine-seed, provisioning,
/// derived, and preallocated-id append seams. It owns only the mechanical
/// construction — payload normalization, annotation capture, timestamp, default
/// causal envelope, and `PreparedEvent` wrapping — with no source provenance
/// and no governed envelope. Event-type validation and admission routing stay
/// in the capability wrappers, so each wrapper name remains the greppable
/// capability check. Not for the verified-message compiler, which must retain
/// its own source facts and envelope.
fn prepare_sealed_local_event(event_id: String, spec: AppendSpec) -> Result<PreparedEvent> {
    let payload = normalize_payload(&spec.record_id, &spec.event_type, spec.payload);
    let annotations = current_event_annotations();
    let event = EventRow {
        local_seq: -1, // filled in after insert
        id: event_id,
        record_id: spec.record_id,
        event_type: spec.event_type,
        payload: Some(serde_json::to_string(&payload)?),
        actor: spec.actor,
        run_key: annotations.run_key,
        parent_key: annotations.parent_key,
        intent: annotations.intent,
        created_at: now_iso(),
        causal_envelope: CausalEnvelopeV1::default(),
    };
    Ok(PreparedEvent {
        event,
        payload,
        native_source: None,
        governed_causal_envelope: None,
    })
}

/// The one append/project kernel shared by locally minted events and the sealed
/// verified Native Message compiler. Callers must prepare identity and metadata
/// before entry.
async fn append_prepared_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    prepared: PreparedEvent,
) -> Result<EventRow> {
    append_prepared_admitted(db, tx, prepared, PreparedAdmission::Ordinary).await
}

async fn append_prepared_engine_seed_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    prepared: PreparedEvent,
) -> Result<EventRow> {
    append_prepared_admitted(db, tx, prepared, PreparedAdmission::EngineSeed).await
}

#[derive(Clone, Copy)]
enum PreparedAdmission {
    Ordinary,
    EngineSeed,
    EngineProvisioning,
    EngineDerived,
}

async fn append_prepared_admitted(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    mut prepared: PreparedEvent,
    admission: PreparedAdmission,
) -> Result<EventRow> {
    if prepared.event.event_type == "record.deleted" {
        let active_binding: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM derivation_target_heads
                  WHERE target_kind='record' AND target_record_id=? AND target_slot='body'
                    AND active_binding_id IS NOT NULL
             )",
        )
        .bind(&prepared.event.record_id)
        .fetch_one(&mut **tx)
        .await?;
        if active_binding {
            return Err(Error::engine(
                "record cannot be deleted while its derived body binding is active; detach it first",
            ));
        }
        let active_artifact_role: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1
                   FROM derivation_artifact_role_assignments a
                   JOIN derivation_artifact_role_heads h
                     ON h.active_assignment_id=a.assignment_id
                  WHERE a.target_kind='record' AND a.target_record_id=?
                    AND a.target_slot='body'
             )",
        )
        .bind(&prepared.event.record_id)
        .fetch_one(&mut **tx)
        .await?;
        if active_artifact_role {
            return Err(Error::engine(
                "record cannot be deleted while its derivation artifact role is active; retire it first",
            ));
        }
    }
    if matches!(
        prepared.event.event_type.as_str(),
        "record.updated" | "receipt.committed.v1"
    ) && prepared.payload.get("body").is_some()
    {
        let head = sqlx::query(
            "SELECT generation,target_version,active_binding_id
               FROM derivation_target_heads
              WHERE target_kind='record' AND target_record_id=? AND target_slot='body'",
        )
        .bind(&prepared.event.record_id)
        .fetch_optional(&mut **tx)
        .await?;
        let authority = DERIVED_BODY_AUTHORITY.try_with(Clone::clone).ok();
        match (head, authority) {
            (None, None) => {}
            (Some(row), authority) => {
                let generation: i64 = row.try_get("generation")?;
                let target_version: i64 = row.try_get("target_version")?;
                let active_binding_id: Option<String> = row.try_get("active_binding_id")?;
                match (active_binding_id.as_deref(), authority) {
                    (None, None) => {}
                    (Some(_), None) => {
                        return Err(Error::engine(
                            "derived record body is engine-managed while its binding is active",
                        ));
                    }
                    (Some(active), Some(authority))
                        if authority.record_id == prepared.event.record_id
                            && active == authority.binding_id
                            && generation == authority.generation
                            && target_version == authority.target_version => {}
                    _ => {
                        return Err(Error::engine(
                            "derived record body binding generation/version is stale",
                        ));
                    }
                }
            }
            (None, Some(_)) => {
                return Err(Error::engine(
                    "derived record body binding generation/version is stale",
                ));
            }
        }
    }
    // Referential integrity for vocab_ref, app-layer (task e035091 guard 4):
    // the frozen DDL has no FK on facet_values.vocab_ref, so a dangling ref
    // would be silently storable. Enforced HERE — on every live facet.set,
    // inside the same write transaction as the append, so it (a) covers raw
    // `append()` callers, not just set_facet, and (b) serializes against the
    // guarded vocabulary deletes (crate::meta::vocabulary), closing the
    // check/delete race. NOT in the projector, and that still holds now the meta
    // tier IS event-sourced (ba9f97e) — the reason simply changed. It used to be
    // "the system tier is direct-write and outside the log"; it is now that the
    // two logs replay SEPARATELY, so the content rebuild folds content_events
    // into a fresh database whose vocabularies table is empty by construction. A
    // projector-side check would fail every rebuild either way, and keeping the
    // content projector free of any meta read is what makes content replay pure.
    if prepared.event.event_type == "facet.set" {
        if let Some(vocab_ref) = prepared.payload.get("vocab_ref").and_then(Value::as_str) {
            let found = sqlx::query("SELECT 1 FROM vocabularies WHERE id = ?")
                .bind(resolve_vocab_ref(vocab_ref))
                .fetch_optional(&mut **tx)
                .await?;
            if found.is_none() {
                return Err(Error::engine(format!(
                    "vocab_ref '{vocab_ref}' does not resolve to a vocabulary — create the vocabulary first"
                )));
            }
        }
    }
    // `native.message.v1` carries authenticated origin replay position but no
    // causal facts. Preserve that absence honestly as an explicitly incomplete
    // governed import. A later causal-capable wire revision can supply its exact
    // verified envelope through this same closed admission without exposing it
    // on `AppendSpec`.
    let causal_admission = if let Some(envelope) = prepared.governed_causal_envelope.clone() {
        if prepared.native_source.is_none() {
            return Err(Error::engine(
                "governed causal admission requires authenticated native source facts",
            ));
        }
        CausalAdmission::GovernedImport(envelope)
    } else if prepared.native_source.is_some() {
        CausalAdmission::GovernedImport(CausalEnvelopeV1::import_incomplete(
            CausalFrontierV1::empty(),
        ))
    } else {
        CausalAdmission::LocalComputed
    };
    let mut ports = SqliteContentPorts {
        transaction: tx,
        native_source: prepared.native_source.clone(),
    };
    let control = crate::portable_sql::ExecutionControl::default();
    match admission {
        PreparedAdmission::Ordinary => {
            if matches!(causal_admission, CausalAdmission::GovernedImport(_)) {
                crate::domain_transaction::append_and_project_governed_import(
                    &mut ports,
                    &mut prepared.event,
                    &causal_admission,
                    &control,
                )
                .await?;
            } else {
                crate::domain_transaction::append_and_project(
                    &mut ports,
                    &mut prepared.event,
                    &control,
                )
                .await?;
            }
        }
        PreparedAdmission::EngineSeed => {
            if !matches!(causal_admission, CausalAdmission::LocalComputed) {
                return Err(Error::engine(
                    "engine seed append cannot carry imported causality",
                ));
            }
            crate::domain_transaction::append_and_project_engine_seed(
                &mut ports,
                &mut prepared.event,
                &control,
            )
            .await?;
        }
        PreparedAdmission::EngineProvisioning => {
            if !matches!(causal_admission, CausalAdmission::LocalComputed) {
                return Err(Error::engine(
                    "engine provisioning append cannot carry imported causality",
                ));
            }
            crate::domain_transaction::append_and_project_engine_provisioned(
                &mut ports,
                &mut prepared.event,
                &control,
            )
            .await?;
        }
        PreparedAdmission::EngineDerived => {
            if !matches!(causal_admission, CausalAdmission::LocalComputed) {
                return Err(Error::engine(
                    "engine derived append cannot carry imported causality",
                ));
            }
            crate::domain_transaction::append_and_project_engine_derived(
                &mut ports,
                &mut prepared.event,
                &control,
            )
            .await?;
        }
    }
    // A definition is identified by the canonical glossary term it defines.
    // Enforce the single CURRENT agreed definition at the shared append seam,
    // after projection exposes the resulting state but before the transaction
    // can commit. Keeping this out of the projector preserves pure replay: the
    // content rebuild intentionally has an empty meta tier.
    assert_one_current_definition_per_term(tx, &prepared.event.record_id).await?;
    // The embed() seam (decision 3bc7fd0), AFTER the fold so the projected
    // name/body are visible, and on the caller's transaction so anything an
    // implementation writes commits with the mutation that caused it. No-op at
    // v1 — see crate::embed for what fires it and what may go inside.
    if let Some(change) = text_change_for(&prepared.event, &prepared.payload) {
        embed(tx, db.embedder(), change).await?;
    }
    crate::provenance::note_appended_event(&prepared.event.id);
    Ok(prepared.event)
}

/// Enforce at most one live, unarchived, decided `Document:definition` for one
/// canonical glossary term. Drafts and superseded definitions do not occupy the
/// slot. Alias resolution is one hop, matching vocabulary lifecycle semantics.
///
/// Calling this after every projected event is deliberate: kind/maturity
/// updates, term changes, archive restore, and low-level append callers all
/// reach this path. Events which leave the target outside the current set are a
/// cheap no-op query and, importantly, free the slot on archive/delete.
async fn assert_one_current_definition_per_term(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> Result<()> {
    let identity = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(identity) = identity else {
        return Ok(());
    };
    let record_type: String = identity.try_get("type")?;
    let kind: Option<String> = identity.try_get("kind")?;
    let Some(kind) = kind else {
        return Ok(());
    };
    let resolution = crate::meta::kind::resolve_on(&mut *tx, &record_type, &kind).await?;
    if !crate::generated::kinds::CoreKind::DocumentDefinition.matches(&resolution) {
        return Ok(());
    }
    let current = sqlx::query(
        "SELECT f.value AS stored_term, COALESCE(canonical.value, f.value) AS canonical_term
           FROM records r
           JOIN facet_values f ON f.record_id = r.id
           LEFT JOIN vocabulary_values term
             ON term.vocabulary_id = 'voc:glossary' AND term.value = f.value
           LEFT JOIN vocabulary_values canonical ON canonical.id = term.alias_of
          WHERE r.id = ?
            AND r.maturity = 'decided'
            AND r.deleted_at IS NULL
            AND f.key = 'term'
            AND f.vocab_ref IN ('voc:glossary', 'rec:voc:glossary')
            AND NOT EXISTS (
                SELECT 1 FROM facet_values a
                 WHERE a.record_id = r.id AND a.key = 'archived'
            )",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(current) = current else {
        return Ok(());
    };
    let stored_term: String = current.try_get("stored_term")?;
    let canonical_term: String = current.try_get("canonical_term")?;

    let candidates = sqlx::query(
        "SELECT r.id, r.type, r.kind
           FROM records r
           JOIN facet_values f ON f.record_id = r.id
           LEFT JOIN vocabulary_values term
             ON term.vocabulary_id = 'voc:glossary' AND term.value = f.value
           LEFT JOIN vocabulary_values canonical ON canonical.id = term.alias_of
          WHERE r.id <> ?
            AND r.type = 'Document'
            AND r.maturity = 'decided'
            AND r.deleted_at IS NULL
            AND f.key = 'term'
            AND f.vocab_ref IN ('voc:glossary', 'rec:voc:glossary')
            AND COALESCE(canonical.value, f.value) = ?
            AND NOT EXISTS (
                SELECT 1 FROM facet_values a
                 WHERE a.record_id = r.id AND a.key = 'archived'
            )
          ORDER BY r.id",
    )
    .bind(record_id)
    .bind(&canonical_term)
    .fetch_all(&mut **tx)
    .await?;
    let mut conflict = None;
    for candidate in candidates {
        let candidate_type: String = candidate.try_get("type")?;
        let candidate_kind: Option<String> = candidate.try_get("kind")?;
        let Some(candidate_kind) = candidate_kind else {
            continue;
        };
        let candidate_resolution =
            crate::meta::kind::resolve_on(&mut *tx, &candidate_type, &candidate_kind).await?;
        if crate::generated::kinds::CoreKind::DocumentDefinition.matches(&candidate_resolution) {
            conflict = Some(candidate.try_get::<String, _>("id")?);
            break;
        }
    }
    if let Some(existing_id) = conflict {
        return Err(Error::engine(format!(
            "current agreed definition conflict for glossary term '{canonical_term}' (stored as '{stored_term}'): existing definition record {existing_id} already occupies the term"
        )));
    }
    Ok(())
}

/// Append one event and project it, in a single write transaction. Returns the
/// stored event row (including its assigned `seq`).
pub async fn append(db: &Db, spec: AppendSpec) -> Result<EventRow> {
    reject_public_runtime_event(&spec)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    reject_public_governed_attribution_in(&mut tx, &spec).await?;
    let event = append_in(db, &mut tx, spec).await?;
    db.commit_content(tx).await?;
    Ok(event)
}

/// Append SEVERAL events and project each, atomically — one write transaction
/// for the whole batch (open call a54f708, resolved: batch append exists).
/// All-or-nothing: any guard or projection failure rolls the entire batch back,
/// so a multi-event tool call (`create_record` with facets and links) can no
/// longer leave a visible partial write. Events get consecutive `seq` values in
/// spec order.
pub async fn append_batch(db: &Db, specs: Vec<AppendSpec>) -> Result<Vec<EventRow>> {
    if specs.is_empty() {
        return Err(Error::engine("append_batch requires at least one event"));
    }
    for spec in &specs {
        reject_public_runtime_event(spec)?;
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut events = Vec::with_capacity(specs.len());
    for spec in specs {
        reject_public_governed_attribution_in(&mut tx, &spec).await?;
        events.push(append_in(db, &mut tx, spec).await?);
    }
    db.commit_content(tx).await?;
    Ok(events)
}

/// Genesis-only append capability for the two canonical filing records.
pub(crate) async fn append_engine_seed_batch(
    db: &Db,
    specs: Vec<AppendSpec>,
) -> Result<Vec<EventRow>> {
    if specs.is_empty() {
        return Err(Error::engine(
            "append_engine_seed_batch requires at least one event",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut events = Vec::with_capacity(specs.len());
    for spec in specs {
        events.push(append_engine_seed_in(db, &mut tx, spec).await?);
    }
    db.commit_content(tx).await?;
    Ok(events)
}

async fn reject_public_governed_attribution_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    spec: &AppendSpec,
) -> Result<()> {
    if !matches!(
        spec.event_type.as_str(),
        "record.created" | "record.updated"
    ) {
        return Ok(());
    }
    let Some(kind) = spec.payload.get("kind").and_then(serde_json::Value::as_str) else {
        return Ok(());
    };
    let record_type = if spec.event_type == "record.created" {
        spec.payload
            .get("type")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    } else {
        sqlx::query_scalar::<_, String>("SELECT type FROM records WHERE id=?")
            .bind(&spec.record_id)
            .fetch_optional(&mut **tx)
            .await?
    };
    let Some(record_type) = record_type else {
        return Ok(());
    };
    let resolution = crate::meta::kind::resolve_on(&mut *tx, &record_type, kind).await?;
    if !resolution.quarantined
        && resolution.canonical_value_id.as_deref() == Some("vv:voc:kind:Annotation:attribution")
    {
        return Err(Error::engine(
            "governed Annotation kind:attribution must be created through the atomic attribution aggregate",
        ));
    }
    Ok(())
}

fn reject_public_runtime_event(spec: &AppendSpec) -> Result<()> {
    if spec.event_type == "record.type_corrected.v1" {
        return Err(Error::engine(
            "record.type_corrected.v1 is correction-operation-owned and cannot be appended through the public event seam",
        ));
    }
    if spec.event_type == "receipt.committed.v1" {
        return Err(Error::engine(
            "receipt.committed.v1 is runtime-owned and cannot be appended through the public event seam",
        ));
    }
    if spec.event_type.starts_with("attribution.") {
        return Err(Error::engine(
            "attribution lifecycle events are aggregate-owned and cannot be appended through the public event seam",
        ));
    }
    if matches!(
        spec.event_type.as_str(),
        "record.created" | "record.updated"
    ) && ["claimed_by_account", "claimed_run_key", "claimed_at"]
        .iter()
        .any(|key| spec.payload.get(key).is_some())
    {
        return Err(Error::engine(
            "record claim projection is start_work-owned and cannot be appended through the public event seam",
        ));
    }
    if matches!(
        spec.event_type.as_str(),
        "record.created" | "record.updated"
    ) && spec.payload.get("kind").and_then(serde_json::Value::as_str) == Some("attribution")
        && (spec.event_type == "record.updated"
            || spec.payload.get("type").and_then(serde_json::Value::as_str) == Some("Annotation"))
    {
        return Err(Error::engine(
            "governed Annotation kind:attribution must be created through the atomic attribution aggregate",
        ));
    }
    Ok(())
}

/// Outcome of a generic conditional lifecycle write.
#[derive(Debug)]
// `EventRow` deliberately carries the complete causal envelope. Boxing this
// long-standing public result would add an allocation and break its API solely
// to optimize the much smaller conflict case.
#[allow(clippy::large_enum_variant)]
pub enum LifecycleCas {
    Applied(EventRow),
    Conflict { current: Option<String> },
}

/// Conditionally update a record when its current lifecycle equals `expected`.
/// This generic API remains for non-claim callers; work coordination no longer
/// uses lifecycle or an event-sequence precondition.
pub async fn update_record_when_lifecycle(
    db: &Db,
    id: &str,
    expected: Option<&str>,
    fields: Value,
) -> Result<LifecycleCas> {
    let spec = AppendSpec {
        record_id: id.into(),
        event_type: "record.updated".into(),
        payload: fields,
        actor: None,
    };
    reject_public_runtime_event(&spec)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let row = sqlx::query("SELECT lifecycle, deleted_at FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        return Err(Error::engine(format!(
            "cannot apply record.updated: record {id} does not exist"
        )));
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Err(Error::engine(format!(
            "cannot apply record.updated: record {id} is deleted (tombstoned)"
        )));
    }
    let current: Option<String> = row.try_get("lifecycle")?;
    if current.as_deref() != expected {
        return Ok(LifecycleCas::Conflict { current });
    }
    let event = append_in(db, &mut tx, spec).await?;
    db.commit_content(tx).await?;
    Ok(LifecycleCas::Applied(event))
}

// ---- Convenience mutations (all delegate to append) ----

/// Create a record. `fields` is a JSON object of `records` columns (must carry
/// `type`); an optional `id` field overrides the generated UUID.
pub async fn create_record(db: &Db, fields: Value) -> Result<String> {
    create_record_as(db, fields, None).await
}

pub async fn create_record_as(db: &Db, fields: Value, actor: Option<&str>) -> Result<String> {
    let mut fields = match fields {
        Value::Object(map) => map,
        other => {
            return Err(Error::engine(format!(
                "record fields must be a JSON object, got {other}"
            )))
        }
    };
    if let Some(Value::String(kind)) = fields.get("kind") {
        crate::freshness::reject_reserved_semantic_unit_kind(kind, "create_record")?;
    }
    let requested_id = match fields.remove("id") {
        Some(Value::String(id)) => Some(id),
        Some(other) => {
            return Err(Error::engine(format!(
                "record id must be a string, got {other}"
            )));
        }
        None => None,
    };
    let id = crate::domain_transaction::record_id_for_create(requested_id)?;
    append(
        db,
        AppendSpec {
            record_id: id.clone(),
            event_type: "record.created".into(),
            payload: Value::Object(fields),
            actor: actor.map(String::from),
        },
    )
    .await?;
    Ok(id)
}

/// Test-only historical fixture installation for engine-owned records. This
/// deliberately enters below live admission, matching import/replay semantics,
/// while still writing an authoritative event and folding it through the real
/// projector.
#[cfg(test)]
pub(crate) async fn install_historical_record_fixture(
    db: &Db,
    record_id: &str,
    fields: Value,
    actor: &str,
) -> Result<String> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let created_at = now_iso();
    append_migration_on(
        &mut tx,
        Uuid::new_v4().to_string(),
        AppendSpec {
            record_id: record_id.into(),
            event_type: "record.created".into(),
            payload: fields,
            actor: Some(actor.into()),
        },
        &created_at,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(record_id.into())
}

pub async fn update_record(db: &Db, id: &str, fields: Value) -> Result<()> {
    if let Some(Value::String(kind)) = fields.as_object().and_then(|fields| fields.get("kind")) {
        crate::freshness::reject_reserved_semantic_unit_kind(kind, "update_record")?;
    }
    append(
        db,
        AppendSpec {
            record_id: id.into(),
            event_type: "record.updated".into(),
            payload: fields,
            actor: None,
        },
    )
    .await?;
    Ok(())
}

pub async fn delete_record(db: &Db, id: &str) -> Result<()> {
    delete_record_as(db, id, None).await
}

pub async fn delete_record_as(db: &Db, id: &str, actor: Option<&str>) -> Result<()> {
    append(
        db,
        AppendSpec {
            record_id: id.into(),
            event_type: "record.deleted".into(),
            payload: Value::Object(Map::new()),
            actor: actor.map(String::from),
        },
    )
    .await?;
    Ok(())
}

pub async fn set_facet(db: &Db, record_id: &str, facet: FacetSetPayload) -> Result<()> {
    // vocab_ref integrity is enforced in append(), inside the write transaction.
    append(
        db,
        AppendSpec {
            record_id: record_id.into(),
            event_type: "facet.set".into(),
            payload: serde_json::to_value(&facet)?,
            actor: None,
        },
    )
    .await?;
    Ok(())
}

pub async fn unset_facet(db: &Db, record_id: &str, key: &str) -> Result<()> {
    append(
        db,
        AppendSpec {
            record_id: record_id.into(),
            event_type: "facet.unset".into(),
            payload: json!({ "key": key }),
            actor: None,
        },
    )
    .await?;
    Ok(())
}

/// Archive a record: sets the engine-reserved `archived` facet to 'true'
/// (tool-surface tool 9). Archived records drop out of default queries but stay
/// mutable; `lifecycle` is untouched, so archive/restore round-trips preserve it.
pub async fn archive_record(db: &Db, id: &str) -> Result<()> {
    set_facet(
        db,
        id,
        FacetSetPayload {
            key: ARCHIVED_FACET_KEY.into(),
            value: Some("true".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
}

/// Restore an archived record by UNSETTING the `archived` facet — absence of the
/// facet IS the restored state ('archived=false' is unrepresentable; the
/// projector rejects it).
pub async fn restore_record(db: &Db, id: &str) -> Result<()> {
    unset_facet(db, id, ARCHIVED_FACET_KEY).await
}

pub async fn add_link(db: &Db, link: LinkAddedPayload) -> Result<()> {
    add_link_as(db, link, None).await
}

pub async fn add_link_as(db: &Db, link: LinkAddedPayload, actor: Option<&str>) -> Result<()> {
    append(
        db,
        AppendSpec {
            record_id: link.source_id.clone(),
            event_type: "link.added".into(),
            payload: serde_json::to_value(&link)?,
            actor: actor.map(String::from),
        },
    )
    .await?;
    Ok(())
}

pub async fn remove_link(db: &Db, link: LinkRemovedPayload) -> Result<()> {
    remove_link_as(db, link, None).await
}

pub async fn remove_link_as(db: &Db, link: LinkRemovedPayload, actor: Option<&str>) -> Result<()> {
    append(
        db,
        AppendSpec {
            record_id: link.source_id.clone(),
            event_type: "link.removed".into(),
            payload: serde_json::to_value(&link)?,
            actor: actor.map(String::from),
        },
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod causal_admission_tests {
    use sqlx::Row;

    use super::*;
    use crate::domain_transaction::EventCursorPort;

    fn source(source_seq: i64) -> NativeEventSource {
        NativeEventSource {
            origin_database_id: "ndb_test_source".into(),
            source_seq,
            source_record_id: Uuid::new_v4().to_string(),
            source_principal: "native:principal:test-source".into(),
            fingerprint: [7; 32],
        }
    }

    fn imported_event(id: String) -> EventRow {
        EventRow {
            local_seq: -1,
            id,
            record_id: Uuid::new_v4().to_string(),
            event_type: "record.created".into(),
            payload: Some("{}".into()),
            actor: Some("account:test-source".into()),
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: "2026-09-01T00:00:00.000Z".into(),
            causal_envelope: CausalEnvelopeV1::default(),
        }
    }

    #[tokio::test]
    async fn fresh_content_genesis_is_complete_empty_and_second_event_consumes_it() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let rows =
            sqlx::query("SELECT seq,id,causal_status FROM content_events ORDER BY seq LIMIT 2")
                .fetch_all(db.write_pool())
                .await
                .unwrap();
        assert_eq!(rows.len(), 2);

        let first_id: String = rows[0].try_get("id").unwrap();
        assert_eq!(rows[0].try_get::<i64, _>("seq").unwrap(), 1);
        assert_eq!(
            rows[0].try_get::<String, _>("causal_status").unwrap(),
            "complete"
        );
        let first_frontier: Vec<String> = sqlx::query_scalar(
            "SELECT parent_event_id FROM content_event_causal_frontier WHERE event_id=?",
        )
        .bind(&first_id)
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert!(first_frontier.is_empty());

        let second_id: String = rows[1].try_get("id").unwrap();
        assert_eq!(
            rows[1].try_get::<String, _>("causal_status").unwrap(),
            "complete"
        );
        let second_frontier: Vec<String> = sqlx::query_scalar(
            "SELECT parent_event_id FROM content_event_causal_frontier WHERE event_id=? ORDER BY parent_event_id",
        )
        .bind(second_id)
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(second_frontier, [first_id]);
    }

    #[tokio::test]
    async fn governed_import_rejects_complete_empty_frontier_after_source_genesis() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let rejected_id = Uuid::new_v4().to_string();
        let mut event = imported_event(rejected_id.clone());
        let mut ports = SqliteContentPorts {
            transaction: &mut tx,
            native_source: Some(source(2)),
        };
        let error = ports
            .append_event(
                &mut event,
                &CausalAdmission::GovernedImport(CausalEnvelopeV1::complete(
                    CausalFrontierV1::empty(),
                )),
                &crate::portable_sql::ExecutionControl::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "a complete empty causal frontier is valid only for source genesis"
        );
        drop(ports);
        let stored: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE id=?)")
                .bind(rejected_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert!(!stored);
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn governed_import_rejects_an_edge_that_closes_a_cycle() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let first_id = Uuid::new_v4().to_string();
        let second_id = Uuid::new_v4().to_string();
        let control = crate::portable_sql::ExecutionControl::default();

        let mut first = imported_event(first_id.clone());
        {
            let mut ports = SqliteContentPorts {
                transaction: &mut tx,
                native_source: Some(source(7)),
            };
            ports
                .append_event(
                    &mut first,
                    &CausalAdmission::GovernedImport(CausalEnvelopeV1::complete(
                        CausalFrontierV1::new([second_id.clone()]).unwrap(),
                    )),
                    &control,
                )
                .await
                .unwrap();
        }

        let mut second = imported_event(second_id.clone());
        let mut ports = SqliteContentPorts {
            transaction: &mut tx,
            native_source: Some(source(8)),
        };
        let error = ports
            .append_event(
                &mut second,
                &CausalAdmission::GovernedImport(CausalEnvelopeV1::complete(
                    CausalFrontierV1::new([first_id]).unwrap(),
                )),
                &control,
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "causal frontier would create a cycle");
        drop(ports);
        let stored: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE id=?)")
                .bind(second_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert!(!stored);
        tx.rollback().await.unwrap();
    }
}

#[cfg(test)]
mod sealed_append_seam_tests {
    use serde_json::json;

    use super::*;

    fn created_spec(record_id: &str) -> AppendSpec {
        AppendSpec {
            record_id: record_id.into(),
            event_type: "record.created".into(),
            payload: json!({
                "type": "Document",
                "kind": "note",
                "persistence": "enduring",
            }),
            actor: Some("test:sealed-seam".into()),
        }
    }

    fn updated_spec(record_id: &str) -> AppendSpec {
        AppendSpec {
            record_id: record_id.into(),
            event_type: "record.updated".into(),
            payload: json!({ "name": "sealed seam probe" }),
            actor: Some("test:sealed-seam".into()),
        }
    }

    #[tokio::test]
    async fn engine_seed_wrapper_uses_seed_admission() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // An ordinary UUID is valid for the public seam but not for genesis.
        let ordinary_id = Uuid::new_v4().to_string();
        let error = append_engine_seed_in(&db, &mut tx, created_spec(&ordinary_id))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "engine seed record id must be native:root or native:unfiled"
        );
        // The seed seam admits only record.created, even for its own ids.
        let error =
            append_engine_seed_in(&db, &mut tx, updated_spec(crate::schema::ROOT_RECORD_ID))
                .await
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "engine seed admission accepts only record.created events"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn engine_provisioning_wrapper_uses_provisioning_admission() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // Reserved ids outside the fixed catalog are rejected with the
        // provisioning-specific allowlist error, not the generic reservation.
        let error = append_engine_provisioned_in(&db, &mut tx, created_spec("native:kernel-squat"))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "engine provisioning record id is not in the fixed allowlist"
        );
        // The provisioning seam admits only record.created, even for an
        // allowlisted id.
        let allowlisted = crate::schema::INSTRUCTIONS_FOLDER_ID;
        let error = append_engine_provisioned_in(&db, &mut tx, updated_spec(allowlisted))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "engine provisioning admission accepts only record.created events"
        );
        // An allowlisted record.created reaches the provisioning admission.
        let event = append_engine_provisioned_in(&db, &mut tx, created_spec(allowlisted))
            .await
            .unwrap();
        assert_eq!(event.record_id, allowlisted);
        assert_eq!(event.event_type, "record.created");
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn engine_derived_wrapper_uses_derived_admission() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // Engine-owned ids are not valid carrier ids: the derived seam reports
        // the UUID shape error, distinguishing it from the seed seam.
        let error =
            append_engine_derived_in(&db, &mut tx, created_spec(crate::schema::ROOT_RECORD_ID))
                .await
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "record id must be a canonical lowercase UUID of version 4 or 7"
        );
        // The derived seam admits only record.created, even for a carrier id.
        let carrier = format!("change-summary:carrier:{}", "a".repeat(64));
        let error = append_engine_derived_in(&db, &mut tx, updated_spec(&carrier))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "engine derived admission accepts only record.created events"
        );
        // A carrier record.created reaches the derived admission.
        let event = append_engine_derived_in(&db, &mut tx, created_spec(&carrier))
            .await
            .unwrap();
        assert_eq!(event.record_id, carrier);
        assert_eq!(event.event_type, "record.created");
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn preallocated_wrapper_uses_ordinary_admission() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // Engine-owned ids stay reserved on the ordinary preallocated seam,
        // distinguishing it from the seed seam which owns them.
        let error = append_with_event_id_in(
            &db,
            &mut tx,
            Uuid::new_v4().to_string(),
            created_spec(crate::schema::ROOT_RECORD_ID),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "record id prefix 'native:' is reserved for engine-owned records"
        );
        // Non-UUID event ids are rejected before any preparation runs.
        let error = append_with_event_id_in(
            &db,
            &mut tx,
            "not-a-uuid".into(),
            created_spec(&Uuid::new_v4().to_string()),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "preallocated content event id must be a canonical UUIDv4"
        );
        // An ordinary UUID reaches ordinary admission and keeps its
        // preallocated event id.
        let record_id = Uuid::new_v4().to_string();
        let event_id = Uuid::new_v4().to_string();
        let event =
            append_with_event_id_in(&db, &mut tx, event_id.clone(), created_spec(&record_id))
                .await
                .unwrap();
        assert_eq!(event.id, event_id);
        assert_eq!(event.record_id, record_id);
        assert_eq!(event.event_type, "record.created");
        tx.rollback().await.unwrap();
    }
}
