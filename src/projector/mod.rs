//! The app-layer projector — the event -> projection fold (Fork A).
//!
//! `project()` applies ONE event to the projection tables (`records`, `links`,
//! `facet_values`, `facet_observations`). It is the ONLY writer of those tables:
//! every business write is append-event-then-project (see `crate::store`), and
//! replay (`crate::conformance`) folds the same events through this same function
//! into a fresh database.
//!
//! This module folds the CONTENT log (`content_events`) and reads NOTHING from
//! the system/meta tier — no meta table is named anywhere in its fold. That
//! purity is what makes content replay correct by construction and lets
//! `rebuild_and_diff` stay on its four projection tables, so it is worth
//! keeping deliberately rather than by accident.
//!
//! The meta tier has its own log and its own projector (`self::meta`, decision
//! ba9f97e) for that reason among others: `project()` below ends in `unknown
//! event type`, so a meta event reaching it would break `replay()` — and with it
//! historical `as_of` reads and the content rebuild — on the very first row.
//!
//! Contract: DETERMINISTIC, EXACTLY-ONCE, IN-ORDER replay. Each event is applied
//! exactly once, in seq order, into a fresh (empty) set of projections. The
//! projector reads every timestamp from the event (`event.created_at`), never from
//! a SQL `DEFAULT` / `now()`, and derived-row ids (facet_values, links) are
//! deterministic functions of their natural key — so two replays of the same log
//! produce byte-identical projection rows.
//!
//! It is NOT idempotent: re-applying an already-applied event is unsupported
//! (`record.created` raises a primary-key violation; `link.removed` raises because
//! the link is already gone). Some paths happen to be upserts (`facet.set`,
//! `link.added`), but callers must not rely on that — the rebuild-and-diff harness
//! replays each event exactly once from an empty database.
//!
//! Functions take `&mut SqliteConnection`, so the projector works identically on
//! the live write path (inside the same transaction that appends the event) and
//! on the replay path — the Rust analogue of the TS `Executor` seam.

pub mod meta;

mod artifact;
mod attribution;
mod freshness;
mod intervention;
mod messaging;

use artifact::{
    project_artifact_input_bound, project_artifact_input_carried, project_artifact_input_unbound,
    project_artifact_module_grant_carried, project_artifact_module_grant_set,
    project_artifact_module_grant_unset, project_artifact_source_attested,
    project_module_release_published, project_module_release_status,
};
use attribution::{
    project_attribution_asserted, project_attribution_evidence_added,
    project_attribution_retracted, project_attribution_target_bound,
};
use freshness::{
    project_occurrence_bound, project_receipt_committed_aggregate,
    project_receipt_dependency_audited, project_reconciliation_recorded, project_unit_created,
    project_unit_revision_recorded, project_unit_superseded,
};
use intervention::{
    project_intervention_cancelled, project_intervention_execution_resumed,
    project_intervention_raised,
};
use messaging::{
    project_message_audience_declared, project_message_audience_legacy_unknown,
    project_message_delivery_authorized, project_message_origin_declared, project_message_reaction,
    project_message_send_evaluated, project_message_shared,
};

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use sqlx::sqlite::SqliteArguments;
use sqlx::{Arguments, Row, SqliteConnection};

use crate::db::Db;
use crate::domain_transaction::{
    ContentSemanticStatePort, ProjectionPlan, ProjectorIntent, RecordFieldUpdate,
    RecordSemanticState, SpineFacet,
};
use crate::error::{Error, Result};
use crate::events::{
    AnnotationTargetSetPayload, ArtifactInputBoundPayload, ArtifactInputCarriedPayload,
    ArtifactInputUnboundPayload, ArtifactModuleGrantCarriedPayload, ArtifactModuleGrantPayload,
    ArtifactSourceAttestedPayload, AttributionAssertedPayload, AttributionEvidenceAddedPayload,
    AttributionRetractedPayload, AttributionTargetBoundPayload, EventRow,
    InterventionCancelledPayload, InterventionExecutionResumedPayload, InterventionRaisedPayload,
    MessageAudienceDeclaredPayload, MessageDeliveryAuthorizedPayload, MessageOriginDeclaredPayload,
    MessageSendEvaluatedPayload, MessageSharedPayload, ModuleReleasePublishedPayload,
    ModuleReleaseStatusPayload, OccurrenceBoundPayload, ReceiptCommittedPayload,
    ReceiptDependencyAuditedPayload, ReconciliationRecordedPayload, SemanticCommandFinalization,
    UnitCreatedPayload, UnitRevisionRecordedPayload, UnitSupersededPayload,
};
use crate::freshness::{
    intent_sha256, receipt_assembly_sha256, DisclosureDecision, ExecutionDisposition,
    MaterialityOutcome, ReceiptAssemblySeal, RevisionSourceSlot, RevisionSubjectKind,
    RECEIPT_FORMAT, RUNTIME_CONTRACT_VERSION, SEMANTIC_CONTRACT_VERSION, UNIT_REVISION_FORMAT,
};
use crate::schema::ARCHIVED_FACET_KEY;

fn parse_payload_value(event: &EventRow) -> Result<Value> {
    let Some(payload) = event.payload.as_deref() else {
        return Err(Error::engine(format!(
            "event {} ({}) has no payload",
            event.id, event.event_type
        )));
    };
    Ok(serde_json::from_str(payload)?)
}

fn parse_payload<T: serde::de::DeserializeOwned>(event: &EventRow) -> Result<T> {
    let value = parse_payload_value(event)?;
    Ok(serde_json::from_value(value)?)
}

fn payload_object(event: &EventRow) -> Result<Map<String, Value>> {
    match parse_payload_value(event)? {
        Value::Object(map) => Ok(map),
        other => Err(Error::engine(format!(
            "event {} ({}) payload is not an object: {other}",
            event.id, event.event_type
        ))),
    }
}

/// Bind a JSON payload value as a SQLite argument. Payload fields are TEXT (or
/// null) in practice; non-string scalars pass through with their natural
/// affinity, as they did through the libSQL client.
fn push_json_arg(args: &mut SqliteArguments<'_>, value: &Value) -> Result<()> {
    let result = match value {
        Value::Null => args.add(None::<String>),
        Value::String(s) => args.add(s.clone()),
        Value::Bool(b) => args.add(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                args.add(i)
            } else {
                args.add(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        other => args.add(other.to_string()),
    };
    result.map_err(|e| Error::engine(format!("cannot bind payload value: {e}")))
}

/// Guard mutations so they only touch a LIVE record — one that exists and is not
/// soft-deleted. Two failure modes this closes, both of which would otherwise
/// commit an authoritative event against invalid state:
///   1. missing record — the event would silently no-op (a phantom event);
///   2. tombstoned record — a soft-deleted record is FROZEN and accepts no further
///      mutations (decision ef32e44).
///
/// Erroring here rolls back the append transaction.
async fn assert_record_live(conn: &mut SqliteConnection, id: &str, event_type: &str) -> Result<()> {
    let row = sqlx::query("SELECT deleted_at FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(row) = row else {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: record {id} does not exist"
        )));
    };
    let deleted_at: Option<String> = row.try_get("deleted_at")?;
    if deleted_at.is_some() {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: record {id} is deleted (tombstoned)"
        )));
    }
    Ok(())
}

struct SqliteSemanticState<'a> {
    conn: &'a mut SqliteConnection,
}

impl ContentSemanticStatePort for SqliteSemanticState<'_> {
    fn record_state<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Option<RecordSemanticState>>> {
        Box::pin(async move {
            let current = sqlx::query(
                "SELECT r.type, r.kind, r.persistence, r.deleted_at, r.policy_anchor_id,
                        EXISTS(SELECT 1 FROM facet_values f
                               WHERE f.record_id=r.id AND f.key=?) AS archived,
                        EXISTS(SELECT 1 FROM annotation_targets t
                               WHERE t.annotation_id=r.id) AS targeted,
                        EXISTS(SELECT 1 FROM attribution_targets a
                               WHERE a.annotation_id=r.id) AS attributed,
                        EXISTS(SELECT 1 FROM semantic_units u
                               WHERE u.unit_id=r.id) AS semantic_unit,
                        (SELECT status FROM message_audience_state m
                         WHERE m.message_id=r.id) AS message_status
                   FROM records r WHERE r.id=?",
            )
            .bind(ARCHIVED_FACET_KEY)
            .bind(record_id)
            .fetch_optional(&mut *self.conn)
            .await;
            match current {
                Ok(row) => {
                    return row
                        .map(|row| {
                            Ok(RecordSemanticState {
                                record_type: row.try_get("type")?,
                                kind: row.try_get("kind")?,
                                persistence: row.try_get("persistence")?,
                                deleted: row.try_get::<Option<String>, _>("deleted_at")?.is_some(),
                                policy_anchor_id: row.try_get("policy_anchor_id")?,
                                archived: row.try_get::<i64, _>("archived")? != 0,
                                targeted: row.try_get::<i64, _>("targeted")? != 0,
                                attributed: row.try_get::<i64, _>("attributed")? != 0,
                                semantic_unit: row.try_get::<i64, _>("semantic_unit")? != 0,
                                message_status: row.try_get("message_status")?,
                            })
                        })
                        .transpose();
                }
                Err(error) if is_missing_projection_table(&error) => {}
                Err(error) => return Err(error.into()),
            }

            // Historical migrations replay canonical events before all later
            // projection families exist. Their absence has the same meaning as
            // an empty later projection; use only the enduring base tables and
            // probe optional state with fail-closed, fixed statements.
            let row = sqlx::query(
                "SELECT r.type, r.kind, r.persistence, r.deleted_at, r.policy_anchor_id,
                        EXISTS(SELECT 1 FROM facet_values f
                               WHERE f.record_id=r.id AND f.key=?) AS archived
                   FROM records r WHERE r.id=?",
            )
            .bind(ARCHIVED_FACET_KEY)
            .bind(record_id)
            .fetch_optional(&mut *self.conn)
            .await?;
            let Some(row) = row else {
                return Ok(None);
            };
            let targeted = optional_projection_exists(
                &mut *self.conn,
                "SELECT EXISTS(SELECT 1 FROM annotation_targets WHERE annotation_id=?)",
                record_id,
            )
            .await?;
            let attributed = optional_projection_exists(
                &mut *self.conn,
                "SELECT EXISTS(SELECT 1 FROM attribution_targets WHERE annotation_id=?)",
                record_id,
            )
            .await?;
            let semantic_unit = optional_projection_exists(
                &mut *self.conn,
                "SELECT EXISTS(SELECT 1 FROM semantic_units WHERE unit_id=?)",
                record_id,
            )
            .await?;
            let message_status = match sqlx::query_scalar(
                "SELECT status FROM message_audience_state WHERE message_id=?",
            )
            .bind(record_id)
            .fetch_optional(&mut *self.conn)
            .await
            {
                Ok(status) => status,
                Err(error) if is_missing_projection_table(&error) => None,
                Err(error) => return Err(error.into()),
            };
            Ok(Some(RecordSemanticState {
                record_type: row.try_get("type")?,
                kind: row.try_get("kind")?,
                persistence: row.try_get("persistence")?,
                deleted: row.try_get::<Option<String>, _>("deleted_at")?.is_some(),
                policy_anchor_id: row.try_get("policy_anchor_id")?,
                archived: row.try_get::<i64, _>("archived")? != 0,
                targeted,
                attributed,
                semantic_unit,
                message_status,
            }))
        })
    }

    fn home_would_cycle<'a>(
        &'a mut self,
        record_id: &'a str,
        home_id: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            Ok(sqlx::query(
                "WITH RECURSIVE up(id, path) AS (
                    SELECT ?, ',' || ? || ','
                    UNION ALL
                    SELECT r.home_id, u.path || r.home_id || ','
                      FROM records r JOIN up u ON r.id = u.id
                     WHERE r.home_id IS NOT NULL
                       AND instr(u.path, ',' || r.home_id || ',') = 0
                ) SELECT 1 FROM up WHERE id = ? LIMIT 1",
            )
            .bind(home_id)
            .bind(home_id)
            .bind(record_id)
            .fetch_optional(&mut *self.conn)
            .await?
            .is_some())
        })
    }

    fn first_live_child<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            Ok(sqlx::query_scalar(
                "SELECT id FROM records WHERE home_id = ? AND deleted_at IS NULL LIMIT 1",
            )
            .bind(record_id)
            .fetch_optional(&mut *self.conn)
            .await?)
        })
    }

    fn link_identity<'a>(
        &'a mut self,
        source_id: &'a str,
        target_id: &'a str,
        relationship: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            Ok(sqlx::query_scalar(
                "SELECT id FROM links
                  WHERE source_id=? AND target_id=? AND relationship=?",
            )
            .bind(source_id)
            .bind(target_id)
            .bind(relationship)
            .fetch_optional(&mut *self.conn)
            .await?)
        })
    }
}

fn is_missing_projection_table(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database) if is_optional_projection_table_missing(database.message()))
}

fn is_optional_projection_table_missing(message: &str) -> bool {
    matches!(
        message.strip_prefix("no such table: "),
        Some(
            "annotation_targets"
                | "attribution_targets"
                | "semantic_units"
                | "message_audience_state"
        )
    )
}

async fn optional_projection_exists(
    conn: &mut SqliteConnection,
    sql: &'static str,
    record_id: &str,
) -> Result<bool> {
    match sqlx::query_scalar(sql)
        .bind(record_id)
        .fetch_one(conn)
        .await
    {
        Ok(exists) => Ok(exists),
        Err(error) if is_missing_projection_table(&error) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Bump a record's activity timestamp. Used so every mutation event advances it.
async fn touch(conn: &mut SqliteConnection, id: &str, ts: &str) -> Result<()> {
    let updated_at = next_record_updated_at(conn, id, ts).await?;
    sqlx::query("UPDATE records SET updated_at = ?, last_activity_at = ? WHERE id = ?")
        .bind(updated_at)
        .bind(ts)
        .bind(id)
        .execute(conn)
        .await?;
    Ok(())
}

/// Produce a replay-stable, strictly advancing record-wide write token.
///
/// Content event timestamps intentionally retain millisecond precision. Two
/// sequential events can therefore share a wall-clock value, and imported
/// events can move backwards. `updated_at` is also the optimistic concurrency
/// token, so it must advance for every projected mutation even in those cases.
async fn next_record_updated_at(
    conn: &mut SqliteConnection,
    id: &str,
    candidate: &str,
) -> Result<String> {
    let current: String = sqlx::query_scalar("SELECT updated_at FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
    let current = chrono::DateTime::parse_from_rfc3339(&current)
        .map_err(|_| Error::engine(format!("record {id} has invalid updated_at")))?
        .with_timezone(&chrono::Utc);
    let candidate = chrono::DateTime::parse_from_rfc3339(candidate)
        .map_err(|_| Error::engine("content event created_at must be RFC3339"))?
        .with_timezone(&chrono::Utc);
    let next = if candidate <= current {
        current + chrono::Duration::milliseconds(1)
    } else {
        candidate
    };
    Ok(next.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

/// Fold one event into the projection tables.
pub async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let intent = ProjectorIntent::from_event(event)?;
    project_intent(conn, event, &intent).await
}

/// Apply an intent already parsed by the append boundary. Replay calls
/// [`project`] and therefore performs the same parse exactly once.
pub(crate) async fn project_intent(
    conn: &mut SqliteConnection,
    event: &EventRow,
    intent: &ProjectorIntent,
) -> Result<()> {
    if !matches!(intent, ProjectorIntent::Extended { .. }) {
        return project_canonical_intent(conn, event, intent).await;
    }
    match intent.event_type() {
        "annotation.target.set" => project_annotation_target_set(conn, event).await,
        "annotation.target.removed" => project_annotation_target_removed(conn, event).await,
        "attribution.target.bound.v1" => project_attribution_target_bound(conn, event).await,
        "attribution.asserted.v1" => project_attribution_asserted(conn, event).await,
        "attribution.evidence.added.v1" => project_attribution_evidence_added(conn, event).await,
        "attribution.retracted.v1" => project_attribution_retracted(conn, event).await,
        crate::canvas::CANVAS_BATCH_EVENT_TYPE => {
            crate::canvas::project_batch_committed(conn, event).await
        }
        "message.audience.declared" => project_message_audience_declared(conn, event).await,
        "message.audience.legacy_unknown" => {
            project_message_audience_legacy_unknown(conn, event).await
        }
        "message.origin.declared.v1" => project_message_origin_declared(conn, event).await,
        "message.shared" => project_message_shared(conn, event).await,
        "message.send_evaluated.v1" => project_message_send_evaluated(conn, event).await,
        "message.delivery.authorized.v1" => project_message_delivery_authorized(conn, event).await,
        // Reactions are event-derived annotations. V1 deliberately has no
        // mutable reaction projection: grouped current state is a bounded fold
        // over these record-local events, so replay has nothing else to write.
        // The no-op is still a semantic projector boundary: imported/replayed
        // bytes must satisfy the same exact payload contract as live writes.
        "message.reaction.added.v1" | "message.reaction.removed.v1" => {
            project_message_reaction(conn, event).await
        }
        "intervention.raised.v1" => project_intervention_raised(conn, event).await,
        "intervention.cancelled.v1" => project_intervention_cancelled(conn, event).await,
        "intervention.execution_resumed.v1" => {
            project_intervention_execution_resumed(conn, event).await
        }
        "module.release_published" => project_module_release_published(conn, event).await,
        "module.release_deprecated" => {
            project_module_release_status(conn, event, "deprecated").await
        }
        "module.release_withdrawn" => project_module_release_status(conn, event, "withdrawn").await,
        "recipe.release_published" => {
            crate::recipe::project_recipe_release_published(conn, event).await
        }
        "recipe.release_deprecated" => {
            crate::recipe::project_recipe_release_status(conn, event, "deprecated").await
        }
        "recipe.release_withdrawn" => {
            crate::recipe::project_recipe_release_status(conn, event, "withdrawn").await
        }
        "artifact.source_attested" => project_artifact_source_attested(conn, event).await,
        "artifact.input_bound" => project_artifact_input_bound(conn, event).await,
        "artifact.input_carried" => project_artifact_input_carried(conn, event).await,
        "artifact.input_unbound" => project_artifact_input_unbound(conn, event).await,
        "artifact.module_grant_set" => project_artifact_module_grant_set(conn, event).await,
        "artifact.module_grant_carried" => project_artifact_module_grant_carried(conn, event).await,
        "artifact.module_grant_unset" => project_artifact_module_grant_unset(conn, event).await,
        "unit.created.v1" => project_unit_created(conn, event).await,
        "unit.revision.recorded.v1" => project_unit_revision_recorded(conn, event).await,
        "occurrence.bound.v1" => project_occurrence_bound(conn, event).await,
        "receipt.committed.v1" => project_receipt_committed_aggregate(conn, event).await,
        "reconciliation.recorded.v1" => project_reconciliation_recorded(conn, event).await,
        "unit.superseded.v1" => project_unit_superseded(conn, event).await,
        "receipt.dependency_audited.v1" => project_receipt_dependency_audited(conn, event).await,
        other => Err(Error::engine(format!("unknown event type: {other}"))),
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn project_annotation_target_set(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: AnnotationTargetSetPayload = parse_payload(event)?;
    assert_target_annotation(
        conn,
        &event.record_id,
        &event.event_type,
        Some((&p.target_record_id, &p.source_slot)),
    )
    .await?;
    assert_record_live(conn, &p.target_record_id, &event.event_type).await?;
    sqlx::query(
        "INSERT INTO annotation_targets
           (annotation_id, target_record_id, source_slot, source_event_seq, blob_id,
            source_sha256, selectors, purpose, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(annotation_id) DO UPDATE SET
           target_record_id = excluded.target_record_id,
           source_slot = excluded.source_slot,
           source_event_seq = excluded.source_event_seq,
           blob_id = excluded.blob_id,
           source_sha256 = excluded.source_sha256,
           selectors = excluded.selectors,
           purpose = excluded.purpose,
           updated_at = excluded.updated_at",
    )
    .bind(&event.record_id)
    .bind(&p.target_record_id)
    .bind(&p.source_slot)
    .bind(p.source_event_seq)
    .bind(&p.blob_id)
    .bind(&p.source_sha256)
    .bind(serde_json::to_string(&p.selectors)?)
    .bind(&p.purpose)
    .bind(&event.created_at)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

async fn assert_target_annotation(
    conn: &mut SqliteConnection,
    record_id: &str,
    event_type: &str,
    target: Option<(&str, &str)>,
) -> Result<()> {
    assert_record_live(conn, record_id, event_type).await?;
    let row = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_one(&mut *conn)
        .await?;
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    if record_type != "Annotation" || !matches!(kind.as_deref(), Some("citation" | "comment")) {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: record {record_id} is not a target-bearing Annotation"
        )));
    }
    if kind.as_deref() == Some("comment") {
        let bearer: Option<String> = sqlx::query_scalar(
            "SELECT CASE WHEN COUNT(*) = 1 THEN MIN(target_id) END
               FROM links WHERE source_id = ? AND relationship = 'part_of'",
        )
        .bind(record_id)
        .fetch_one(&mut *conn)
        .await?;
        let Some(bearer) = bearer else {
            return Err(Error::engine(format!(
                "cannot apply {event_type}: anchored comment {record_id} requires exactly one part_of bearer"
            )));
        };
        // Governed aliases are canonicalized before the content event is
        // appended. The content projector deliberately remains meta-tier
        // independent, so its direct/replay invariant consumes that canonical
        // token; the integration contract covers both stored projection and
        // record.created payload canonicalization.
        let bearer_is_comment: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM records
                  WHERE id = ? AND deleted_at IS NULL
                    AND type = 'Annotation' AND kind = 'comment'
             )",
        )
        .bind(&bearer)
        .fetch_one(&mut *conn)
        .await?;
        if target.is_some() && bearer_is_comment {
            return Err(Error::engine(format!(
                "cannot apply {event_type}: comment replies must be targetless; quoted context belongs to the root"
            )));
        }
        if let Some((target_record_id, source_slot)) = target {
            if target_record_id != bearer || source_slot != "body" {
                return Err(Error::engine(format!(
                    "cannot apply {event_type}: anchored comment {record_id} must target its part_of bearer's body"
                )));
            }
        }
    }
    Ok(())
}

async fn project_annotation_target_removed(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_target_annotation(conn, &event.record_id, &event.event_type, None).await?;
    let removed = sqlx::query("DELETE FROM annotation_targets WHERE annotation_id = ?")
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    if removed.rows_affected() != 1 {
        return Err(Error::engine(format!(
            "cannot apply {}: Annotation {} has no target",
            event.event_type, event.record_id
        )));
    }
    touch(conn, &event.record_id, &event.created_at).await
}

/// Replay a whole log (ordered by seq) into a fresh database.
pub async fn replay(conn: &mut SqliteConnection, events: &[EventRow]) -> Result<()> {
    for event in events {
        project(conn, event).await.map_err(|error| {
            Error::engine(format!(
                "replay event {} (seq {}, type {}) failed: {error}",
                event.id, event.local_seq, event.event_type
            ))
        })?;
    }
    Ok(())
}

/// Replay content events after installing the direct-write blob identities that
/// `annotation.target.set` rows FK-reference. Most replay consumers need only
/// cheap inert identities: conformance compares projections, and body history
/// must not copy unrelated finance attachments merely because their citation
/// events occur earlier in the log. A historical citation read can narrowly
/// hydrate blobs referenced by that one Annotation so its retained evidence is
/// available. Missing direct rows remain inert external placeholders, allowing
/// set -> remove history to replay while evidence correctly reports unavailable.
pub async fn replay_with_blob_seeds(
    live: &Db,
    conn: &mut SqliteConnection,
    events: &[EventRow],
    hydrate_annotation_id: Option<&str>,
) -> Result<()> {
    replay_with_blob_source(Some(live.write_pool()), conn, events, hydrate_annotation_id).await
}

pub(crate) async fn replay_with_blob_placeholders(
    conn: &mut SqliteConnection,
    events: &[EventRow],
) -> Result<()> {
    replay_with_blob_source(None, conn, events, None).await
}

async fn replay_with_blob_source(
    live_pool: Option<&sqlx::SqlitePool>,
    conn: &mut SqliteConnection,
    events: &[EventRow],
    hydrate_annotation_id: Option<&str>,
) -> Result<()> {
    let mut blob_ids = BTreeMap::<String, bool>::new();
    for event in events {
        if event.event_type != "annotation.target.set" {
            continue;
        }
        // Seed discovery is deliberately permissive. The projector below is
        // the authority for payload validation and error ordering (for example,
        // a bearerless citation is rejected before its malformed target body).
        let blob_id = event
            .payload
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|payload| payload.get("blob_id")?.as_str().map(str::to_owned));
        if let Some(blob_id) = blob_id {
            let hydrate = hydrate_annotation_id == Some(event.record_id.as_str());
            blob_ids
                .entry(blob_id)
                .and_modify(|needed| *needed |= hydrate)
                .or_insert(hydrate);
        }
    }

    for (blob_id, hydrate) in blob_ids {
        sqlx::query(
            "INSERT INTO blobs (id, storage_tier, external_ref, created_at)
             VALUES (?, 'external', 'replay-placeholder', '1970-01-01T00:00:00.000Z')",
        )
        .bind(&blob_id)
        .execute(&mut *conn)
        .await?;

        if !hydrate {
            continue;
        }
        let live_pool = live_pool.expect("hydrated replay requires a live blob source");
        let retained = sqlx::query(
            "SELECT bytes, mime, size_bytes, sha256, original_filename,
                    storage_tier, external_ref, created_at
               FROM blobs WHERE id = ?",
        )
        .bind(&blob_id)
        .fetch_optional(live_pool)
        .await?;
        let Some(retained) = retained else { continue };
        sqlx::query(
            "UPDATE blobs
                SET bytes = ?, mime = ?, size_bytes = ?, sha256 = ?,
                    original_filename = ?, storage_tier = ?, external_ref = ?, created_at = ?
              WHERE id = ?",
        )
        .bind(retained.try_get::<Option<Vec<u8>>, _>("bytes")?)
        .bind(retained.try_get::<Option<String>, _>("mime")?)
        .bind(retained.try_get::<Option<i64>, _>("size_bytes")?)
        .bind(retained.try_get::<Option<String>, _>("sha256")?)
        .bind(retained.try_get::<Option<String>, _>("original_filename")?)
        .bind(retained.try_get::<String, _>("storage_tier")?)
        .bind(retained.try_get::<Option<String>, _>("external_ref")?)
        .bind(retained.try_get::<String, _>("created_at")?)
        .bind(&blob_id)
        .execute(&mut *conn)
        .await?;
    }

    for event in events {
        sqlx::query(
            "INSERT INTO content_events
                (seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,
                 causal_envelope_version,causal_status)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(event.local_seq)
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
        .execute(&mut *conn)
        .await?;
        for parent_event_id in event.causal_envelope.frontier().as_slice() {
            sqlx::query(
                "INSERT INTO content_event_causal_frontier(event_id,parent_event_id)
                 VALUES (?,?)",
            )
            .bind(&event.id)
            .bind(parent_event_id)
            .execute(&mut *conn)
            .await?;
        }
        project(conn, event).await?;
    }
    let last_legacy_local_seq: i64 = events
        .iter()
        .filter(|event| {
            event.causal_envelope.status() == crate::events::CausalStatus::LegacyUnknown
        })
        .map(|event| event.local_seq)
        .max()
        .unwrap_or(0);
    sqlx::query(
        "UPDATE content_event_causal_cutover
            SET last_legacy_local_seq=?,
                from_engine_schema=CASE WHEN ? > 0 THEN 45 ELSE NULL END
          WHERE singleton=1",
    )
    .bind(last_legacy_local_seq)
    .bind(last_legacy_local_seq)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn project_canonical_intent(
    conn: &mut SqliteConnection,
    event: &EventRow,
    intent: &ProjectorIntent,
) -> Result<()> {
    let plan = {
        let mut state = SqliteSemanticState { conn };
        crate::domain_transaction::plan_projection(&mut state, event, intent).await?
    };
    apply_projection_plan(conn, event, plan).await
}

async fn apply_projection_plan(
    conn: &mut SqliteConnection,
    event: &EventRow,
    plan: ProjectionPlan,
) -> Result<()> {
    match plan {
        ProjectionPlan::RecordCreated {
            fields,
            kind,
            policy_anchor_id,
            message_mentions,
        } => {
            apply_record_created(
                conn,
                event,
                fields,
                &kind,
                &policy_anchor_id,
                message_mentions,
            )
            .await
        }
        ProjectionPlan::RecordUpdated {
            fields,
            refresh_policy_anchor,
        } => apply_record_updated(conn, event, &fields, refresh_policy_anchor).await,
        ProjectionPlan::RecordTypeCorrected { record_type, kind } => {
            apply_record_type_corrected(conn, event, &record_type, &kind).await
        }
        ProjectionPlan::RecordDeleted => apply_record_deleted(conn, event).await,
        ProjectionPlan::FacetSet { payload, spine } => {
            apply_facet_set(conn, event, payload, spine).await
        }
        ProjectionPlan::FacetUnset { payload, spine } => {
            apply_facet_unset(conn, event, payload, spine).await
        }
        ProjectionPlan::LinkAdded {
            payload,
            link_id,
            relationship_owned,
        } => apply_link_added(conn, event, payload, link_id, relationship_owned).await,
        ProjectionPlan::LinkRemoved {
            payload,
            relationship_owned,
        } => apply_link_removed(conn, event, payload, relationship_owned).await,
    }
}

async fn apply_record_type_corrected(
    conn: &mut SqliteConnection,
    event: &EventRow,
    record_type: &str,
    kind: &str,
) -> Result<()> {
    let updated_at = next_record_updated_at(conn, &event.record_id, &event.created_at).await?;
    sqlx::query("UPDATE records SET type=?, kind=?, updated_at=?, last_activity_at=? WHERE id=?")
        .bind(record_type)
        .bind(kind)
        .bind(updated_at)
        .bind(&event.created_at)
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn apply_record_created(
    conn: &mut SqliteConnection,
    event: &EventRow,
    fields: Map<String, Value>,
    kind: &str,
    policy_anchor_id: &str,
    message_mentions: Option<Vec<crate::domain_transaction::MessageMention>>,
) -> Result<()> {
    let ts = event.created_at.as_str();
    let mut args = SqliteArguments::default();
    push_json_arg(&mut args, &Value::String(event.record_id.clone()))?;
    push_json_arg(&mut args, fields.get("type").unwrap_or(&Value::Null))?;
    push_json_arg(&mut args, &Value::String(kind.to_string()))?;
    push_json_arg(
        &mut args,
        &match fields.get("name") {
            Some(Value::Null) | None => Value::String(String::new()),
            Some(v) => v.clone(),
        },
    )?;
    push_json_arg(&mut args, fields.get("body").unwrap_or(&Value::Null))?;
    push_json_arg(&mut args, fields.get("home_id").unwrap_or(&Value::Null))?;
    push_json_arg(&mut args, fields.get("lifecycle").unwrap_or(&Value::Null))?;
    push_json_arg(&mut args, fields.get("owner_id").unwrap_or(&Value::Null))?;
    push_json_arg(&mut args, &Value::String(policy_anchor_id.to_string()))?;
    push_json_arg(
        &mut args,
        &match fields.get("persistence") {
            None => Value::String("enduring".into()),
            Some(v) => v.clone(),
        },
    )?;
    push_json_arg(&mut args, fields.get("maturity").unwrap_or(&Value::Null))?;
    push_json_arg(&mut args, fields.get("summary").unwrap_or(&Value::Null))?;
    for _ in 0..3 {
        push_json_arg(&mut args, &Value::String(ts.into()))?;
    }
    sqlx::query_with(
        "INSERT INTO records
            (id, type, kind, name, body, home_id,
             lifecycle, owner_id, policy_anchor_id, persistence, maturity, summary,
             last_activity_at, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        args,
    )
    .execute(&mut *conn)
    .await?;
    if let Some(mentions) = message_mentions {
        sqlx::query(
            "INSERT INTO message_audience_state
                (message_id,status,declaration_event_seq,updated_at)
             VALUES (?,'pending_local',NULL,?)",
        )
        .bind(&event.record_id)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "INSERT INTO message_origin_state
                (message_id,status,origin_type,collection_id,direct_set_digest,
                 participant_count,declaration_event_seq,updated_at)
             VALUES (?,'legacy_unknown',NULL,NULL,NULL,NULL,NULL,?)",
        )
        .bind(&event.record_id)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
        for mention in mentions {
            sqlx::query(
                "INSERT INTO message_mentions
                   (message_id,mention_id,target_kind,target_binding,target_record_id,span_start,
                    span_end,authored_label,source_event_seq,effective)
                 VALUES (?,?,?,?,?,?,?,?,?,1)",
            )
            .bind(&event.record_id)
            .bind(mention.mention_id)
            .bind(mention.target_kind)
            .bind(mention.target_binding)
            .bind(mention.target_record_id)
            .bind(mention.span_start)
            .bind(mention.span_end)
            .bind(mention.authored_label)
            .bind(event.local_seq)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

async fn project_record_updated(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let intent = ProjectorIntent::from_event(event)?;
    project_canonical_intent(conn, event, &intent).await
}

async fn apply_record_updated(
    conn: &mut SqliteConnection,
    event: &EventRow,
    fields: &[RecordFieldUpdate],
    refresh_policy_anchor: bool,
) -> Result<()> {
    let updated_at = next_record_updated_at(conn, &event.record_id, &event.created_at).await?;
    // Name only the columns this event actually carries. The previous form
    // wrote every column as `CASE WHEN ? THEN ? ELSE col END`, which is
    // value-preserving but not statement-preserving: SQLite's
    // `AFTER UPDATE OF ...` triggers fire on the columns a statement NAMES, so
    // a body edit that mentioned `owner_id` and `kind` advanced the
    // database-wide authorization epoch and blanked every open artifact in
    // every connected client. Each column comes from `RecordFieldUpdate::write`
    // as a `&'static` literal, so the assembled SQL contains no
    // caller-controlled text.
    // Assembled from `&'static` assignment literals, so this allocates one
    // String and formats nothing. Different field subsets produce different
    // statement texts and therefore different prepared-statement cache
    // entries; the set of subsets a real workload uses is small, and paying a
    // cache miss beats telling every subscriber to re-read.
    let mut sql = String::with_capacity(96);
    sql.push_str("UPDATE records SET ");
    let mut args = SqliteArguments::default();
    for field in fields {
        let write = field.write();
        sql.push_str(write.assignment);
        sql.push_str(", ");
        push_json_arg(&mut args, write.value)?;
    }
    sql.push_str("updated_at=?, last_activity_at=? WHERE id=?");
    push_json_arg(&mut args, &Value::String(updated_at))?;
    push_json_arg(&mut args, &Value::String(event.created_at.clone()))?;
    push_json_arg(&mut args, &Value::String(event.record_id.clone()))?;
    sqlx::query_with(&sql, args).execute(&mut *conn).await?;
    if refresh_policy_anchor {
        crate::authorization::refresh_policy_anchor_subtree(conn, &event.record_id).await?;
    }
    Ok(())
}

async fn apply_record_deleted(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let updated_at = next_record_updated_at(conn, &event.record_id, &event.created_at).await?;
    sqlx::query(
        "UPDATE records SET deleted_at = ?, updated_at = ?, last_activity_at = ? WHERE id = ?",
    )
    .bind(&event.created_at)
    .bind(updated_at)
    .bind(&event.created_at)
    .bind(&event.record_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE message_mentions SET effective=0 WHERE message_id=?")
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn apply_facet_set(
    conn: &mut SqliteConnection,
    event: &EventRow,
    payload: crate::events::FacetSetPayload,
    spine: Option<SpineFacet>,
) -> Result<()> {
    if let Some(spine) = spine {
        let updated_at = next_record_updated_at(conn, &event.record_id, &event.created_at).await?;
        let sql = match spine {
            SpineFacet::Lifecycle => {
                "UPDATE records SET lifecycle=?, updated_at=?, last_activity_at=? WHERE id=?"
            }
            SpineFacet::Owner => {
                "UPDATE records SET owner_id=?, updated_at=?, last_activity_at=? WHERE id=?"
            }
            SpineFacet::Persistence => {
                "UPDATE records SET persistence=?, updated_at=?, last_activity_at=? WHERE id=?"
            }
            SpineFacet::Maturity => {
                "UPDATE records SET maturity=?, updated_at=?, last_activity_at=? WHERE id=?"
            }
        };
        sqlx::query(sql)
            .bind(&payload.value)
            .bind(updated_at)
            .bind(&event.created_at)
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        return Ok(());
    }
    if !payload.observation_only {
        sqlx::query(
            "INSERT INTO facet_values (id, record_id, key, value, vocab_ref, created_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (record_id, key)
             DO UPDATE SET value=excluded.value, vocab_ref=excluded.vocab_ref",
        )
        .bind(format!("fv:{}:{}", event.record_id, payload.key))
        .bind(&event.record_id)
        .bind(&payload.key)
        .bind(&payload.value)
        .bind(&payload.vocab_ref)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    }
    let as_of = payload.as_of.as_deref().unwrap_or(&event.created_at);
    sqlx::query(
        "INSERT INTO facet_observations
            (id, record_id, key, value, op, vocab_ref, as_of, observed_at, event_seq)
          VALUES (?, ?, ?, ?, 'set', ?, ?, ?, ?)
          ON CONFLICT (record_id, key, as_of)
          DO UPDATE SET value = excluded.value,
                        op = excluded.op,
                        vocab_ref = excluded.vocab_ref,
                        observed_at = excluded.observed_at,
                        event_seq = excluded.event_seq",
    )
    .bind(format!("fo:{}:{}:{as_of}", event.record_id, payload.key))
    .bind(&event.record_id)
    .bind(&payload.key)
    .bind(&payload.value)
    .bind(&payload.vocab_ref)
    .bind(as_of)
    .bind(&event.created_at)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

async fn apply_facet_unset(
    conn: &mut SqliteConnection,
    event: &EventRow,
    payload: crate::events::FacetUnsetPayload,
    spine: Option<SpineFacet>,
) -> Result<()> {
    if let Some(spine) = spine {
        let updated_at = next_record_updated_at(conn, &event.record_id, &event.created_at).await?;
        let sql = match spine {
            SpineFacet::Lifecycle => {
                "UPDATE records SET lifecycle=NULL, updated_at=?, last_activity_at=? WHERE id=?"
            }
            SpineFacet::Owner => {
                "UPDATE records SET owner_id=NULL, updated_at=?, last_activity_at=? WHERE id=?"
            }
            SpineFacet::Persistence => unreachable!("shared planner rejects persistence unset"),
            SpineFacet::Maturity => {
                "UPDATE records SET maturity=NULL, updated_at=?, last_activity_at=? WHERE id=?"
            }
        };
        sqlx::query(sql)
            .bind(updated_at)
            .bind(&event.created_at)
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        return Ok(());
    }
    if !payload.observation_only {
        sqlx::query("DELETE FROM facet_values WHERE record_id = ? AND key = ?")
            .bind(&event.record_id)
            .bind(&payload.key)
            .execute(&mut *conn)
            .await?;
    }
    let as_of = payload.as_of.as_deref().unwrap_or(&event.created_at);
    sqlx::query(
        "INSERT INTO facet_observations
            (id, record_id, key, value, op, vocab_ref, as_of, observed_at, event_seq)
          VALUES (?, ?, ?, NULL, 'unset', NULL, ?, ?, ?)
          ON CONFLICT (record_id, key, as_of)
          DO UPDATE SET value = excluded.value,
                        op = excluded.op,
                        vocab_ref = excluded.vocab_ref,
                        observed_at = excluded.observed_at,
                        event_seq = excluded.event_seq",
    )
    .bind(format!("fo:{}:{}:{as_of}", event.record_id, payload.key))
    .bind(&event.record_id)
    .bind(&payload.key)
    .bind(as_of)
    .bind(&event.created_at)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

async fn apply_link_added(
    conn: &mut SqliteConnection,
    event: &EventRow,
    payload: crate::events::LinkAddedPayload,
    link_id: String,
    relationship_owned: bool,
) -> Result<()> {
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *conn)
        .await?;
    if version >= 35 && relationship_owned {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO links (id, source_id, target_id, relationship, note, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT (source_id, target_id, relationship)
          DO UPDATE SET note = excluded.note",
    )
    .bind(&link_id)
    .bind(&payload.source_id)
    .bind(&payload.target_id)
    .bind(&payload.relationship)
    .bind(&payload.note)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    if payload.relationship == "participates_in" {
        sqlx::query(
            "INSERT INTO message_conversations
                (message_id,conversation_id,event_seq,classified_at)
             VALUES (?,?,?,?)
             ON CONFLICT(message_id,conversation_id) DO UPDATE SET
               event_seq=excluded.event_seq, classified_at=excluded.classified_at",
        )
        .bind(&payload.source_id)
        .bind(&payload.target_id)
        .bind(event.local_seq)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    }
    touch(conn, &payload.source_id, &event.created_at).await
}

async fn apply_link_removed(
    conn: &mut SqliteConnection,
    event: &EventRow,
    payload: crate::events::LinkRemovedPayload,
    relationship_owned: bool,
) -> Result<()> {
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *conn)
        .await?;
    if version >= 35 && relationship_owned {
        return Ok(());
    }
    let res =
        sqlx::query("DELETE FROM links WHERE source_id = ? AND target_id = ? AND relationship = ?")
            .bind(&payload.source_id)
            .bind(&payload.target_id)
            .bind(&payload.relationship)
            .execute(&mut *conn)
            .await?;
    if res.rows_affected() == 0 {
        return Err(Error::engine(format!(
            "cannot remove link: no '{}' link from {} to {}",
            payload.relationship, payload.source_id, payload.target_id
        )));
    }
    if payload.relationship == "participates_in" {
        sqlx::query(
            "DELETE FROM message_conversations WHERE message_id = ? AND conversation_id = ?",
        )
        .bind(&payload.source_id)
        .bind(&payload.target_id)
        .execute(&mut *conn)
        .await?;
    }
    touch(conn, &payload.source_id, &event.created_at).await
}

async fn assert_portable_person(
    conn: &mut SqliteConnection,
    record_id: &str,
    event_type: &str,
) -> Result<()> {
    let identity = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(identity) = identity else {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: audience identity {record_id} does not exist"
        )));
    };
    if identity.try_get::<String, _>("type")? != "Entity"
        || identity.try_get::<Option<String>, _>("kind")?.as_deref() != Some("person")
        || identity
            .try_get::<Option<String>, _>("deleted_at")?
            .is_some()
    {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: audience identity {record_id} must be a live Entity kind:person"
        )));
    }
    Ok(())
}

fn declared_principal(value: &str, event_type: &str) -> Result<String> {
    let normalized = crate::identity::normalize_identifier("native-principal", value)?;
    if normalized != value {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: native-principal is not canonical"
        )));
    }
    Ok(normalized)
}

async fn assert_message_event(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let record_type: String = sqlx::query_scalar("SELECT type FROM records WHERE id=?")
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
    if record_type != "Message" {
        return Err(Error::engine(format!(
            "{} may target only a Message",
            event.event_type
        )));
    }
    Ok(())
}

fn require_digest(value: &str, label: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "{label} must be a sha256 hex digest"
        )))
    }
}

async fn earlier_payload<T: serde::de::DeserializeOwned>(
    conn: &mut SqliteConnection,
    event: &EventRow,
    event_type: &str,
) -> Result<(String, T)> {
    let row = sqlx::query(
        "SELECT id,payload FROM content_events
          WHERE record_id=? AND type=? AND seq<? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&event.record_id)
    .bind(event_type)
    .bind(event.local_seq)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| {
        Error::engine(format!(
            "{} requires an earlier {event_type} on the same Message",
            event.event_type
        ))
    })?;
    let id: String = row.try_get("id")?;
    let payload = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
    Ok((id, payload))
}

async fn assert_single_terminal(
    conn: &mut SqliteConnection,
    event: &EventRow,
    intervention_id: &str,
) -> Result<()> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE record_id=? AND seq<=?
            AND type IN ('intervention.cancelled.v1','intervention.execution_resumed.v1')
            AND json_extract(payload,'$.intervention_id')=?",
    )
    .bind(&event.record_id)
    .bind(event.local_seq)
    .bind(intervention_id)
    .fetch_one(&mut *conn)
    .await?;
    if count != 1 {
        return Err(Error::engine(
            "an intervention may have exactly one terminal event",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod historical_projection_table_tests {
    use super::is_optional_projection_table_missing;

    #[test]
    fn fallback_is_limited_to_named_later_projection_tables() {
        for table in [
            "annotation_targets",
            "semantic_units",
            "message_audience_state",
        ] {
            assert!(is_optional_projection_table_missing(&format!(
                "no such table: {table}"
            )));
        }
        for message in [
            "no such table: records",
            "no such table: semantic_unit",
            "no such table: main.semantic_units",
            "database is locked",
        ] {
            assert!(!is_optional_projection_table_missing(message));
        }
    }
}
