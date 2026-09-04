//! Internal Receipt-driven context freshness runtime.
//!
//! The values in `domain` are backend-neutral. This module is the SQLite event
//! adapter and intentionally has no MCP/public-tool registration.

use std::collections::{BTreeSet, VecDeque};

use serde::Serialize;
use sqlx::{Row, SqliteConnection};
use uuid::Uuid;

use crate::authorization::{require_capability_on, Capability, Principal};
use crate::db::{begin_write, Db};
use crate::error::{Error, Result};
use crate::events::{
    ReceiptCommittedPayload, ReceiptDependencyAuditedPayload, ReconciliationRecordedPayload,
    SemanticCommandFinalization, UnitSupersededPayload,
};
use crate::store::{append_in, append_with_event_id_in, AppendSpec};

use super::domain::*;
use super::kernel::{
    authorization_revision_on, body_revision_from_event_on, current_body_revision_on,
    load_occurrence_on, resolve_occurrence_view_on, unit_bearer_on, verify_revision_ref_on,
};

const MAX_SUPERSESSION_TRAVERSAL: usize = 256;

struct CandidateResolution {
    candidates: Vec<RevisionRef>,
    withheld: bool,
}

struct DerivedContext<T> {
    values: Vec<T>,
    withheld: bool,
}

fn require_actor(actor: &str) -> Result<()> {
    if actor.trim().is_empty() {
        Err(Error::engine("freshness runtime actor must not be blank"))
    } else {
        Ok(())
    }
}

fn event_spec<T: Serialize>(
    record_id: &str,
    event_type: &str,
    payload: &T,
    actor: &str,
) -> Result<AppendSpec> {
    Ok(AppendSpec {
        record_id: record_id.into(),
        event_type: event_type.into(),
        payload: serde_json::to_value(payload)?,
        actor: Some(actor.into()),
    })
}

fn command(
    operation: &str,
    scope_record_id: &str,
    key: &IdempotencyKey,
    intent_sha256: String,
    authorization_revision_observed: i64,
) -> SemanticCommandFinalization {
    SemanticCommandFinalization {
        operation: operation.into(),
        scope_record_id: scope_record_id.into(),
        idempotency_key: key.as_str().into(),
        intent_sha256,
        authorization_revision_observed,
    }
}

async fn authorize_source_on(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Principal<'_>,
    reference: &RevisionRef,
) -> Result<()> {
    require_capability_on(tx, principal, &reference.subject_id, Capability::View).await?;
    if reference.subject_kind == RevisionSubjectKind::Unit {
        let bearer = unit_bearer_on(tx, &reference.subject_id).await?;
        require_capability_on(tx, principal, &bearer, Capability::View).await?;
    }
    Ok(())
}

async fn authorize_uncertainty_lineage_on(
    conn: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Principal<'_>,
    lineage: &UncertaintyLineage,
) -> Result<()> {
    authorize_source_on(conn, principal, &lineage.consumer_revision).await?;
    authorize_source_on(conn, principal, &lineage.pinned_source_revision).await?;
    authorize_source_on(conn, principal, &lineage.selected_source_revision).await?;
    if let Some(receipt_id) = lineage.inherited_from_receipt_id.as_ref() {
        let prior_consumer: String =
            sqlx::query_scalar("SELECT consumer_record_id FROM receipts WHERE receipt_id=?")
                .bind(receipt_id.as_str())
                .fetch_optional(&mut **conn)
                .await?
                .ok_or_else(|| Error::engine("uncertainty lineage Receipt is unavailable"))?;
        require_capability_on(conn, principal, &prior_consumer, Capability::View).await?;
    }
    Ok(())
}

/// Re-authorize every exact reference carried by a committed Receipt before an
/// embedding returns an idempotent result from that Receipt's event payload.
/// This preserves the runtime rule that authorization is checked before a
/// command's prior result becomes observable.
#[cfg(feature = "experimental-agent-intents")]
pub(super) async fn reauthorize_receipt_payload_on(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Principal<'_>,
    payload: &ReceiptCommittedPayload,
) -> Result<()> {
    for reference in payload
        .selected_sources
        .iter()
        .chain(payload.provenance.iter().map(|item| &item.source_revision))
        .chain(
            payload
                .dependencies
                .iter()
                .map(|item| &item.source_revision),
        )
        .chain(
            payload
                .assessments
                .iter()
                .map(|item| &item.compared_source_revision),
        )
        .chain(payload.comparisons.iter().flat_map(|item| {
            [
                &item.pinned_source_revision,
                &item.candidate_source_revision,
            ]
        }))
        .chain(payload.reconciliations.iter().flat_map(|item| {
            [
                &item.consumer_revision,
                &item.pinned_source_revision,
                &item.assessed_source_revision,
            ]
        }))
    {
        authorize_source_on(tx, principal, reference).await?;
        verify_revision_ref_on(tx, reference).await?;
    }
    for lineage in &payload.unresolved_uncertainty {
        authorize_uncertainty_lineage_on(tx, principal, lineage).await?;
        for reference in [
            &lineage.consumer_revision,
            &lineage.pinned_source_revision,
            &lineage.selected_source_revision,
        ] {
            verify_revision_ref_on(tx, reference).await?;
        }
    }
    Ok(())
}

async fn unit_heads_at_on(
    conn: &mut SqliteConnection,
    unit_id: &str,
    high_water: i64,
) -> Result<Vec<RevisionRef>> {
    let rows = sqlx::query(
        "SELECT r.revision_event_id,r.revision_seq,r.content_sha256
           FROM unit_revisions r
          WHERE r.unit_id=? AND r.revision_seq <= ?
            AND NOT EXISTS (
                SELECT 1 FROM unit_revisions child
                 WHERE child.unit_id=r.unit_id
                   AND child.based_on_revision_event_id=r.revision_event_id
                   AND child.revision_seq <= ?)
          ORDER BY r.revision_event_id",
    )
    .bind(unit_id)
    .bind(high_water)
    .bind(high_water)
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(RevisionRef {
                subject_kind: RevisionSubjectKind::Unit,
                subject_id: unit_id.into(),
                revision_event_id: row.try_get("revision_event_id")?,
                revision_seq: row.try_get("revision_seq")?,
                source_slot: RevisionSourceSlot::UnitContent,
                sha256: row.try_get("content_sha256")?,
            })
        })
        .collect()
}

async fn body_head_at_on(
    conn: &mut SqliteConnection,
    record_id: &str,
    high_water: i64,
) -> Result<RevisionRef> {
    let event_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events
          WHERE record_id=? AND seq <= ? AND type IN ('record.created','record.updated','receipt.committed.v1')
            AND json_type(payload,'$.body') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(record_id)
    .bind(high_water)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("context source has no body revision at the high-water"))?;
    body_revision_from_event_on(conn, record_id, &event_id).await
}

async fn resolve_unit_sources_on(
    conn: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Principal<'_>,
    unit_id: &str,
    high_water: i64,
) -> Result<CandidateResolution> {
    let mut queue = VecDeque::from([unit_id.to_owned()]);
    let mut seen = BTreeSet::new();
    let mut terminals = Vec::new();
    let mut withheld = false;
    while let Some(current) = queue.pop_front() {
        if !seen.insert(current.clone()) {
            continue;
        }
        if seen.len() > MAX_SUPERSESSION_TRAVERSAL {
            return Err(Error::engine("Unit supersession traversal limit exceeded"));
        }
        let next: Vec<String> = sqlx::query_scalar(
            "SELECT successor_revision FROM unit_supersessions
              WHERE predecessor_unit_id=? AND supersession_event_seq <= ?
              ORDER BY successor_unit_id,successor_revision_event_id",
        )
        .bind(&current)
        .bind(high_water)
        .fetch_all(&mut **conn)
        .await?;
        let mut visible_successors = Vec::new();
        for raw in next {
            let successor: RevisionRef = serde_json::from_str(&raw)?;
            if authorize_source_on(conn, principal, &successor)
                .await
                .is_ok()
            {
                visible_successors.push(successor.subject_id);
            } else {
                withheld = true;
            }
        }
        if visible_successors.is_empty() {
            terminals.extend(unit_heads_at_on(conn, &current, high_water).await?);
        } else {
            queue.extend(visible_successors);
        }
    }
    terminals.sort_by(|left, right| {
        (&left.subject_id, &left.revision_event_id)
            .cmp(&(&right.subject_id, &right.revision_event_id))
    });
    terminals.dedup();
    Ok(CandidateResolution {
        candidates: terminals,
        withheld,
    })
}

async fn derive_sources_on(
    conn: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Principal<'_>,
    requested_source_record_ids: &[String],
    high_water: i64,
) -> Result<DerivedContext<RevisionRef>> {
    let mut sources = Vec::new();
    let mut withheld = false;
    for record_id in requested_source_record_ids {
        require_capability_on(conn, principal, record_id, Capability::View).await?;
        let is_unit: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM semantic_units WHERE unit_id=? AND creation_event_seq <= ?)",
        )
        .bind(record_id)
        .bind(high_water)
        .fetch_one(&mut **conn)
        .await?;
        if is_unit {
            let bearer = unit_bearer_on(conn, record_id).await?;
            require_capability_on(conn, principal, &bearer, Capability::View).await?;
            let resolved = resolve_unit_sources_on(conn, principal, record_id, high_water).await?;
            if resolved.candidates.is_empty() {
                return Err(Error::engine("Unit has no revision at the high-water"));
            }
            withheld |= resolved.withheld;
            sources.extend(resolved.candidates);
        } else {
            sources.push(body_head_at_on(conn, record_id, high_water).await?);
        }
    }
    sources.sort_by(|left, right| {
        (&left.subject_id, &left.revision_event_id)
            .cmp(&(&right.subject_id, &right.revision_event_id))
    });
    sources.dedup();
    Ok(DerivedContext {
        values: sources,
        withheld,
    })
}

/// Assemble exact context through one temporal and authorization lens. Reading
/// context never declares a semantic dependency and appends no event.
pub async fn assemble_context(
    db: &Db,
    principal: Principal<'_>,
    request: ContextRequest,
    consumer_record_id: Option<&str>,
    source_record_ids: Vec<String>,
) -> Result<ContextAssembly> {
    assemble_context_with_pause(
        db,
        principal,
        request,
        consumer_record_id,
        source_record_ids,
        |_| async { Ok(()) },
    )
    .await
}

/// Test seam for deterministically coordinating a source change immediately
/// after the assembly snapshot captures its temporal and authorization
/// boundary. Production callers use [`assemble_context`].
#[doc(hidden)]
pub async fn assemble_context_with_pause<F, Fut>(
    db: &Db,
    principal: Principal<'_>,
    mut request: ContextRequest,
    consumer_record_id: Option<&str>,
    mut source_record_ids: Vec<String>,
    pause_after_high_water: F,
) -> Result<ContextAssembly>
where
    F: FnOnce(HistoryHighWater) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    request.risk_inputs.sort();
    request.risk_inputs.dedup();
    request.validate()?;
    source_record_ids.sort();
    if source_record_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::engine("context sources must be distinct"));
    }
    let mut snapshot = db.pool().begin().await?;
    // The first read establishes the SQLite snapshot and the content boundary.
    let content_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *snapshot)
        .await?;
    let auth_epoch = authorization_revision_on(&mut snapshot).await?;
    let high_water = HistoryHighWater {
        content_seq,
        authorization_revision_observed: auth_epoch,
        semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
    };
    pause_after_high_water(high_water.clone()).await?;
    if let Some(consumer_record_id) = consumer_record_id {
        require_capability_on(
            &mut snapshot,
            principal,
            consumer_record_id,
            Capability::View,
        )
        .await?;
    }
    let derived_sources =
        derive_sources_on(&mut snapshot, principal, &source_record_ids, content_seq).await?;

    let derived_comparisons = if let Some(consumer_record_id) = consumer_record_id {
        let consumer_revision =
            body_head_at_on(&mut snapshot, consumer_record_id, content_seq).await?;
        derive_comparisons_on(
            &mut snapshot,
            principal,
            consumer_record_id,
            &consumer_revision.revision_event_id,
            content_seq,
        )
        .await?
    } else {
        DerivedContext {
            values: Vec::new(),
            withheld: false,
        }
    };

    let derived_uncertainty = derive_inherited_uncertainty_on(
        &mut snapshot,
        principal,
        consumer_record_id,
        &derived_sources.values,
        content_seq,
    )
    .await?;
    let transitive_withheld = inherits_withheld_context_on(
        &mut snapshot,
        consumer_record_id,
        &derived_sources.values,
        content_seq,
    )
    .await?;
    snapshot.rollback().await?;
    Ok(ContextAssembly {
        request,
        high_water,
        requested_source_record_ids: source_record_ids,
        sources: derived_sources.values,
        comparisons: derived_comparisons.values,
        inherited_uncertainty: derived_uncertainty.values,
        withheld_context: derived_sources.withheld
            || derived_comparisons.withheld
            || derived_uncertainty.withheld
            || transitive_withheld,
    })
}

fn normalize_package(input: &mut CommitDurableOutputInput) -> Result<()> {
    input.assembly.request.risk_inputs.sort();
    input.assembly.request.risk_inputs.dedup();
    input.policy.hard_stop_categories.sort();
    input.policy.hard_stop_categories.dedup();
    input.assembly.requested_source_record_ids.sort();
    input.assembly.requested_source_record_ids.dedup();
    input.assembly.sources.sort_by(|left, right| {
        (&left.subject_id, &left.revision_event_id)
            .cmp(&(&right.subject_id, &right.revision_event_id))
    });
    input.assembly.sources.dedup();
    input.assembly.request.validate()?;
    input.assembly.high_water.validate()?;
    input.policy.validate()?;
    input.expected_consumer_revision.validate()?;
    input.idempotency_key.validate()?;
    if input.consumer_record_id.trim().is_empty()
        || input.output_body.trim().is_empty()
        || input.expected_consumer_revision.subject_id != input.consumer_record_id
        || input.expected_consumer_revision.subject_kind != RevisionSubjectKind::Artefact
        || input.expected_consumer_revision.source_slot != RevisionSourceSlot::RecordBody
        || input.expected_consumer_revision.revision_seq > input.assembly.high_water.content_seq
        || input
            .assembly
            .requested_source_record_ids
            .iter()
            .any(|record_id| record_id.trim().is_empty())
    {
        return Err(Error::engine("invalid durable output package"));
    }
    input.assembly.comparisons.sort_by(|left, right| {
        (&left.dependency_id, &left.candidate_source_revision)
            .cmp(&(&right.dependency_id, &right.candidate_source_revision))
    });
    for comparison in &input.assembly.comparisons {
        comparison.dependency_id.validate()?;
        comparison.receipt_id.validate()?;
        comparison.pinned_source_revision.validate()?;
        comparison.candidate_source_revision.validate()?;
    }
    input.provenance.sort_by(|left, right| {
        (
            &left.source_revision.subject_id,
            &left.source_revision.revision_event_id,
            &left.reason,
        )
            .cmp(&(
                &right.source_revision.subject_id,
                &right.source_revision.revision_event_id,
                &right.reason,
            ))
    });
    for provenance in &input.provenance {
        provenance.source_revision.validate()?;
        if provenance.reason.trim().is_empty() {
            return Err(Error::engine("provenance reason must not be blank"));
        }
    }
    input
        .dependencies
        .sort_by(|left, right| left.dependency_id.cmp(&right.dependency_id));
    for dependency in &input.dependencies {
        dependency.validate()?;
    }
    if input.dependencies.len() > input.policy.dependency_budget as usize {
        return Err(Error::engine(
            "declared dependencies exceed the Receipt policy budget",
        ));
    }
    input
        .assessments
        .sort_by(|left, right| left.assessment_id.cmp(&right.assessment_id));
    for assessment in &input.assessments {
        assessment.assessment_id.validate()?;
        assessment.dependency_id.validate()?;
        assessment.compared_source_revision.validate()?;
        validate_assessment_materiality(assessment)?;
        if assessment.category.trim().is_empty() || assessment.rationale.trim().is_empty() {
            return Err(Error::engine("assessment rationale must not be blank"));
        }
    }
    let comparison_keys: BTreeSet<_> = input
        .assembly
        .comparisons
        .iter()
        .map(|comparison| {
            (
                comparison.dependency_id.clone(),
                comparison.candidate_source_revision.clone(),
            )
        })
        .collect();
    let assessment_keys: BTreeSet<_> = input
        .assessments
        .iter()
        .map(|assessment| {
            (
                assessment.dependency_id.clone(),
                assessment.compared_source_revision.clone(),
            )
        })
        .collect();
    if comparison_keys != assessment_keys || assessment_keys.len() != input.assessments.len() {
        return Err(Error::engine(
            "every sealed comparison requires exactly one task-relative assessment",
        ));
    }
    input
        .reconciliations
        .sort_by(|left, right| left.reconciliation_id.cmp(&right.reconciliation_id));
    for reconciliation in &input.reconciliations {
        reconciliation.reconciliation_id.validate()?;
        reconciliation.dependency_id.validate()?;
        reconciliation.consumer_revision.validate()?;
        reconciliation.pinned_source_revision.validate()?;
        reconciliation.assessed_source_revision.validate()?;
        if reconciliation.task_scope.trim().is_empty()
            || reconciliation.affected_conclusion.key.trim().is_empty()
            || reconciliation
                .affected_conclusion
                .description
                .trim()
                .is_empty()
            || reconciliation.rationale.trim().is_empty()
        {
            return Err(Error::engine("invalid package reconciliation evidence"));
        }
    }
    input
        .unresolved_uncertainty
        .extend(input.assembly.inherited_uncertainty.clone());
    input
        .unresolved_uncertainty
        .sort_by(|left, right| left.uncertainty_id.cmp(&right.uncertainty_id));
    input
        .unresolved_uncertainty
        .dedup_by(|left, right| left == right);
    if input.unresolved_uncertainty.iter().any(|lineage| {
        lineage.assessment_task_scope.trim().is_empty()
            || lineage.evidence.trim().is_empty()
            || lineage.detail.trim().is_empty()
    }) {
        return Err(Error::engine(
            "uncertainty lineage evidence and detail must not be blank",
        ));
    }
    if input
        .unresolved_uncertainty
        .windows(2)
        .any(|pair| pair[0].uncertainty_id == pair[1].uncertainty_id)
    {
        return Err(Error::engine(
            "uncertainty ids cannot describe conflicting lineage",
        ));
    }
    for assessment in &input.assessments {
        if matches!(assessment.outcome, MaterialityOutcome::MateriallyUncertain)
            || (assessment.outcome == MaterialityOutcome::UnableToAssess
                && assessment.could_materially_change)
        {
            let has_lineage = input.unresolved_uncertainty.iter().any(|lineage| {
                lineage.dependency_id == assessment.dependency_id
                    && lineage.selected_source_revision == assessment.compared_source_revision
                    && lineage.verdict == assessment.outcome
            });
            if !has_lineage {
                return Err(Error::engine(
                    "uncertainty cannot be omitted: material uncertainty requires explicit lineage",
                ));
            }
        }
    }
    Ok(())
}

async fn prior_runtime_command_on(
    conn: &mut SqliteConnection,
    scope: &str,
    key: &IdempotencyKey,
    operation: &str,
    intent: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT operation,intent_sha256,result_event_id FROM freshness_runtime_command_results
          WHERE scope_record_id=? AND idempotency_key=?",
    )
    .bind(scope)
    .bind(key.as_str())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else { return Ok(None) };
    if row.try_get::<String, _>("operation")? != operation
        || row.try_get::<String, _>("intent_sha256")? != intent
    {
        return Err(Error::engine(
            "idempotency key was already used for a different runtime command",
        ));
    }
    Ok(Some(row.try_get("result_event_id")?))
}

async fn load_commit_result_on(
    conn: &mut SqliteConnection,
    receipt_event_id: &str,
) -> Result<CommitDurableOutputResult> {
    let row = sqlx::query(
        "SELECT receipt_id,output_revision,execution,disclosure,history_high_water
           FROM receipts WHERE receipt_event_id=?",
    )
    .bind(receipt_event_id)
    .fetch_one(&mut *conn)
    .await?;
    let receipt_id = ReceiptId::new(row.try_get::<String, _>("receipt_id")?)?;
    let dependency_ids = sqlx::query_scalar::<_, String>(
        "SELECT dependency_id FROM dependencies WHERE receipt_id=? ORDER BY dependency_id",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(DependencyId::new)
    .collect::<Result<Vec<_>>>()?;
    Ok(CommitDurableOutputResult {
        receipt_id,
        output_revision: serde_json::from_str(&row.try_get::<String, _>("output_revision")?)?,
        dependency_ids,
        execution: match row.try_get::<String, _>("execution")?.as_str() {
            "continued" => ExecutionDisposition::Continued,
            "stopped" => ExecutionDisposition::Stopped,
            _ => return Err(Error::engine("invalid projected Receipt execution")),
        },
        disclosure: match row.try_get::<String, _>("disclosure")?.as_str() {
            "silent" => DisclosureDecision::Silent,
            "explain_on_inspection" => DisclosureDecision::ExplainOnInspection,
            "surface_now" => DisclosureDecision::SurfaceNow,
            _ => return Err(Error::engine("invalid projected Receipt disclosure")),
        },
        high_water: serde_json::from_str(&row.try_get::<String, _>("history_high_water")?)?,
    })
}

pub async fn commit_durable_output(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    input: CommitDurableOutputInput,
) -> Result<CommitDurableOutputResult> {
    commit_durable_output_with_failure(db, principal, actor, input, None).await
}

/// Test seam for proving that every intermediate event/projection rolls back.
#[doc(hidden)]
pub async fn commit_durable_output_with_failure(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    mut input: CommitDurableOutputInput,
    failure: Option<CommitFailurePoint>,
) -> Result<CommitDurableOutputResult> {
    require_actor(actor)?;
    normalize_package(&mut input)?;
    let intent = intent_sha256(&input)?;
    let mut tx = begin_write(db.write_pool()).await?;
    // Authorization precedes idempotency occupancy lookup.
    require_capability_on(
        &mut tx,
        principal,
        &input.consumer_record_id,
        Capability::Edit,
    )
    .await?;
    for reference in input
        .assembly
        .sources
        .iter()
        .chain(input.provenance.iter().map(|item| &item.source_revision))
        .chain(input.dependencies.iter().map(|item| &item.source_revision))
        .chain(
            input
                .assessments
                .iter()
                .map(|item| &item.compared_source_revision),
        )
        .chain(input.assembly.comparisons.iter().flat_map(|item| {
            [
                &item.pinned_source_revision,
                &item.candidate_source_revision,
            ]
        }))
        .chain(input.reconciliations.iter().flat_map(|item| {
            [
                &item.consumer_revision,
                &item.pinned_source_revision,
                &item.assessed_source_revision,
            ]
        }))
    {
        authorize_source_on(&mut tx, principal, reference).await?;
        verify_revision_ref_on(&mut tx, reference).await?;
        if reference.revision_seq > input.assembly.high_water.content_seq {
            return Err(Error::engine(
                "package reference lies beyond its assembly high-water",
            ));
        }
    }
    for uncertainty in &input.unresolved_uncertainty {
        for reference in [
            &uncertainty.consumer_revision,
            &uncertainty.pinned_source_revision,
            &uncertainty.selected_source_revision,
        ] {
            authorize_source_on(&mut tx, principal, reference).await?;
            verify_revision_ref_on(&mut tx, reference).await?;
        }
    }
    if let Some(result_event_id) = prior_runtime_command_on(
        &mut tx,
        &input.consumer_record_id,
        &input.idempotency_key,
        "commit_durable_output",
        &intent,
    )
    .await?
    {
        return load_commit_result_on(&mut tx, &result_event_id).await;
    }
    let current = current_body_revision_on(&mut tx, &input.consumer_record_id)
        .await?
        .map(|(reference, _)| reference)
        .ok_or_else(|| Error::engine("output consumer has no current body revision"))?;
    if current != input.expected_consumer_revision {
        return Err(Error::engine(
            "output consumer changed since its expected revision",
        ));
    }
    let rederived_sources = derive_sources_on(
        &mut tx,
        principal,
        &input.assembly.requested_source_record_ids,
        input.assembly.high_water.content_seq,
    )
    .await?;
    if rederived_sources.values != input.assembly.sources {
        return Err(Error::engine(
            "sealed context sources are incomplete or do not match the assembly high-water",
        ));
    }
    let rederived_comparisons = derive_comparisons_on(
        &mut tx,
        principal,
        &input.consumer_record_id,
        &input.expected_consumer_revision.revision_event_id,
        input.assembly.high_water.content_seq,
    )
    .await?;
    if rederived_comparisons.values != input.assembly.comparisons {
        return Err(Error::engine(
            "sealed context comparisons are incomplete or stale",
        ));
    }
    let rederived_uncertainty = derive_inherited_uncertainty_on(
        &mut tx,
        principal,
        Some(&input.consumer_record_id),
        &input.assembly.sources,
        input.assembly.high_water.content_seq,
    )
    .await?;
    if rederived_uncertainty.values != input.assembly.inherited_uncertainty {
        return Err(Error::engine(
            "sealed inherited uncertainty is incomplete or stale",
        ));
    }
    let transitive_withheld = inherits_withheld_context_on(
        &mut tx,
        Some(&input.consumer_record_id),
        &input.assembly.sources,
        input.assembly.high_water.content_seq,
    )
    .await?;
    if input.assembly.withheld_context
        != (rederived_sources.withheld
            || rederived_comparisons.withheld
            || rederived_uncertainty.withheld
            || transitive_withheld)
    {
        return Err(Error::engine(
            "sealed authorization-redacted context state is stale",
        ));
    }
    for lineage in &input.unresolved_uncertainty {
        if input
            .assembly
            .inherited_uncertainty
            .iter()
            .any(|inherited| inherited == lineage)
        {
            continue;
        }
        let comparison = input
            .assembly
            .comparisons
            .iter()
            .find(|comparison| {
                comparison.dependency_id == lineage.dependency_id
                    && comparison.pinned_source_revision == lineage.pinned_source_revision
                    && comparison.candidate_source_revision == lineage.selected_source_revision
            })
            .ok_or_else(|| {
                Error::engine("uncertainty lineage does not bind an exact sealed comparison")
            })?;
        let assessment_matches = input.assessments.iter().any(|assessment| {
            assessment.dependency_id == lineage.dependency_id
                && assessment.compared_source_revision == lineage.selected_source_revision
                && assessment.outcome == lineage.verdict
                && (assessment.outcome == MaterialityOutcome::MateriallyUncertain
                    || (assessment.outcome == MaterialityOutcome::UnableToAssess
                        && assessment.could_materially_change))
        });
        let debt = sqlx::query(
            "SELECT d.consumer_revision,d.source_revision,d.affected_conclusion
               FROM dependencies d JOIN receipts r ON r.receipt_id=d.receipt_id
              WHERE d.dependency_id=? AND d.receipt_id=?",
        )
        .bind(lineage.dependency_id.as_str())
        .bind(comparison.receipt_id.as_str())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine("uncertainty lineage dependency debt is unavailable"))?;
        if !assessment_matches
            || lineage.inherited_from_receipt_id.as_ref() != Some(&comparison.receipt_id)
            || lineage.consumer_revision != input.expected_consumer_revision
            || serde_json::from_str::<RevisionRef>(
                &debt.try_get::<String, _>("consumer_revision")?,
            )? != lineage.consumer_revision
            || serde_json::from_str::<RevisionRef>(&debt.try_get::<String, _>("source_revision")?)?
                != lineage.pinned_source_revision
            || serde_json::from_str::<AffectedConclusion>(
                &debt.try_get::<String, _>("affected_conclusion")?,
            )? != lineage.affected_conclusion
            || lineage.assessment_task_scope != input.assembly.request.task_scope
        {
            return Err(Error::engine(
                "uncertainty lineage does not bind the exact dependency debt tuple",
            ));
        }
    }
    let assembly_sources: BTreeSet<_> = input
        .assembly
        .sources
        .iter()
        .map(|reference| reference.revision_event_id.as_str())
        .collect();
    for reference in input.provenance.iter().map(|item| &item.source_revision) {
        if !assembly_sources.contains(reference.revision_event_id.as_str()) {
            return Err(Error::engine(
                "provenance must come from the sealed assembly",
            ));
        }
    }
    for dependency in &input.dependencies {
        let compared_old = input
            .assembly
            .comparisons
            .iter()
            .any(|comparison| comparison.pinned_source_revision == dependency.source_revision);
        if !assembly_sources.contains(dependency.source_revision.revision_event_id.as_str())
            && !compared_old
        {
            return Err(Error::engine(
                "dependency must come from the sealed assembly or exact compared debt",
            ));
        }
    }
    let dependency_ids: BTreeSet<_> = input
        .dependencies
        .iter()
        .map(|item| item.dependency_id.as_str())
        .collect();
    let compared_dependency_ids: BTreeSet<_> = input
        .assembly
        .comparisons
        .iter()
        .map(|item| item.dependency_id.as_str())
        .collect();
    if input.assessments.iter().any(|item| {
        !dependency_ids.contains(item.dependency_id.as_str())
            && !compared_dependency_ids.contains(item.dependency_id.as_str())
    }) {
        return Err(Error::engine(
            "assessment references an undeclared package dependency",
        ));
    }
    for reconciliation in &input.reconciliations {
        if reconciliation.consumer_revision != input.expected_consumer_revision
            || reconciliation.task_scope != input.assembly.request.task_scope
            || !input.assembly.comparisons.iter().any(|comparison| {
                comparison.dependency_id == reconciliation.dependency_id
                    && comparison.pinned_source_revision == reconciliation.pinned_source_revision
                    && comparison.candidate_source_revision
                        == reconciliation.assessed_source_revision
            })
            || !input.assessments.iter().any(|assessment| {
                assessment.dependency_id == reconciliation.dependency_id
                    && assessment.compared_source_revision
                        == reconciliation.assessed_source_revision
                    && assessment.outcome == reconciliation.outcome
            })
        {
            return Err(Error::engine(
                "package reconciliation must bind the expected consumer and an exact sealed comparison and assessment",
            ));
        }
        let debt = sqlx::query(
            "SELECT d.consumer_revision,d.source_revision,d.affected_conclusion
               FROM dependencies d JOIN receipts r ON r.receipt_id=d.receipt_id
              WHERE d.dependency_id=?",
        )
        .bind(reconciliation.dependency_id.as_str())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine("package reconciliation dependency is unavailable"))?;
        if serde_json::from_str::<RevisionRef>(&debt.try_get::<String, _>("consumer_revision")?)?
            != reconciliation.consumer_revision
            || serde_json::from_str::<RevisionRef>(&debt.try_get::<String, _>("source_revision")?)?
                != reconciliation.pinned_source_revision
            || serde_json::from_str::<AffectedConclusion>(
                &debt.try_get::<String, _>("affected_conclusion")?,
            )? != reconciliation.affected_conclusion
        {
            return Err(Error::engine(
                "package reconciliation does not cover the exact dependency debt",
            ));
        }
    }

    let receipt_id = ReceiptId::new(Uuid::new_v4().to_string())?;
    let receipt_event_id = Uuid::new_v4().to_string();
    if matches!(
        failure,
        Some(
            CommitFailurePoint::AfterOutput
                | CommitFailurePoint::AfterDependency(_)
                | CommitFailurePoint::AfterAssessment(_)
                | CommitFailurePoint::AfterReconciliation(_)
                | CommitFailurePoint::AfterDependencies
                | CommitFailurePoint::BeforeReceipt
        )
    ) {
        return Err(Error::engine(
            "injected durable output failure before aggregate Receipt",
        ));
    }
    let (execution, disclosure) = receipt_decisions(
        &input.policy,
        &input.assessments,
        input.assembly.withheld_context,
    );
    let assembly_sha256 = receipt_assembly_sha256(&ReceiptAssemblySeal {
        request: &input.assembly.request,
        policy: &input.policy,
        requested_source_record_ids: &input.assembly.requested_source_record_ids,
        selected_sources: &input.assembly.sources,
        provenance: &input.provenance,
        comparisons: &input.assembly.comparisons,
        dependencies: &input.dependencies,
        assessments: &input.assessments,
        reconciliations: &input.reconciliations,
        lineage: &input.unresolved_uncertainty,
        withheld_context: input.assembly.withheld_context,
        high_water: &input.assembly.high_water,
    })?;
    let auth_revision = authorization_revision_on(&mut tx).await?;
    let dependency_budget_used = input.dependencies.len() as u32;
    let receipt_event = append_with_event_id_in(
        db,
        &mut tx,
        receipt_event_id,
        event_spec(
            &input.consumer_record_id,
            "receipt.committed.v1",
            &ReceiptCommittedPayload {
                format: RECEIPT_FORMAT.into(),
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                runtime_contract_version: RUNTIME_CONTRACT_VERSION.into(),
                receipt_id: receipt_id.clone(),
                expected_consumer_revision: input.expected_consumer_revision,
                body: input.output_body,
                context_request: input.assembly.request,
                resolution_policy: input.policy,
                requested_source_record_ids: input.assembly.requested_source_record_ids,
                selected_sources: input.assembly.sources,
                history_high_water: input.assembly.high_water,
                assembly_sha256,
                provenance: input.provenance,
                comparisons: input.assembly.comparisons,
                dependencies: input.dependencies,
                assessments: input.assessments,
                reconciliations: input.reconciliations,
                unresolved_uncertainty: input.unresolved_uncertainty,
                withheld_context: input.assembly.withheld_context,
                dependency_declaration_outcome: "declared".into(),
                dependency_budget_used,
                execution,
                disclosure,
                command: command(
                    "commit_durable_output",
                    &input.consumer_record_id,
                    &input.idempotency_key,
                    intent,
                    auth_revision,
                ),
            },
            actor,
        )?,
    )
    .await?;
    if failure == Some(CommitFailurePoint::BeforeCommit) {
        return Err(Error::engine(
            "injected durable output failure before commit",
        ));
    }
    tx.commit().await?;
    let mut conn = db.pool().acquire().await?;
    load_commit_result_on(&mut conn, &receipt_event.id).await
}

async fn current_candidates_for_dependency_on(
    conn: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Principal<'_>,
    pinned: &RevisionRef,
    high_water: i64,
) -> Result<CandidateResolution> {
    if pinned.subject_kind == RevisionSubjectKind::Artefact {
        let current = body_head_at_on(conn, &pinned.subject_id, high_water).await?;
        let withheld: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM receipts
              WHERE output_revision_event_id=? AND receipt_event_seq <= ?
                AND withheld_context=1)",
        )
        .bind(&current.revision_event_id)
        .bind(high_water)
        .fetch_one(&mut **conn)
        .await?;
        return Ok(CandidateResolution {
            candidates: (current != *pinned)
                .then_some(current)
                .into_iter()
                .collect(),
            withheld,
        });
    }
    let mut resolution =
        resolve_unit_sources_on(conn, principal, &pinned.subject_id, high_water).await?;
    resolution
        .candidates
        .retain(|reference| reference != pinned);
    Ok(CandidateResolution {
        candidates: resolution.candidates,
        withheld: resolution.withheld,
    })
}

async fn derive_comparisons_on(
    conn: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Principal<'_>,
    consumer_record_id: &str,
    consumer_revision_event_id: &str,
    high_water: i64,
) -> Result<DerivedContext<ImpactCandidate>> {
    let rows = sqlx::query(
        "SELECT d.dependency_id,d.receipt_id,d.source_revision,d.affected_conclusion,
                r.context_request
           FROM dependencies d JOIN receipts r ON r.receipt_id=d.receipt_id
          WHERE d.consumer_record_id=? AND d.consumer_revision_event_id=?
          ORDER BY d.dependency_id",
    )
    .bind(consumer_record_id)
    .bind(consumer_revision_event_id)
    .fetch_all(&mut **conn)
    .await?;
    let mut comparisons = Vec::new();
    let mut withheld = false;
    for row in rows {
        let pinned: RevisionRef =
            serde_json::from_str(&row.try_get::<String, _>("source_revision")?)?;
        if authorize_source_on(conn, principal, &pinned).await.is_err() {
            withheld = true;
            continue;
        }
        let dependency_id = DependencyId::new(row.try_get::<String, _>("dependency_id")?)?;
        let debt_scope =
            serde_json::from_str::<ContextRequest>(&row.try_get::<String, _>("context_request")?)?
                .task_scope;
        let affected_conclusion: String = row.try_get("affected_conclusion")?;
        let resolution =
            current_candidates_for_dependency_on(conn, principal, &pinned, high_water).await?;
        withheld |= resolution.withheld;
        for candidate in resolution.candidates {
            let reconciled: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM reconciliations
                  WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                    AND reconciliation_event_seq <= ?3 AND task_scope=?4
                    AND affected_conclusion=?5
                    AND outcome IN ('immaterial','remains_valid'))
                   AND NOT EXISTS(SELECT 1 FROM reconciliations
                  WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                    AND reconciliation_event_seq <= ?3 AND task_scope=?4
                    AND affected_conclusion=?5
                    AND outcome NOT IN ('immaterial','remains_valid'))",
            )
            .bind(dependency_id.as_str())
            .bind(&candidate.revision_event_id)
            .bind(high_water)
            .bind(&debt_scope)
            .bind(&affected_conclusion)
            .fetch_one(&mut **conn)
            .await?;
            if !reconciled {
                comparisons.push(ImpactCandidate {
                    dependency_id: dependency_id.clone(),
                    receipt_id: ReceiptId::new(row.try_get::<String, _>("receipt_id")?)?,
                    pinned_source_revision: pinned.clone(),
                    candidate_source_revision: candidate,
                });
            }
        }
    }
    comparisons.sort_by(|left, right| {
        (
            left.dependency_id.as_str(),
            &left.candidate_source_revision.revision_event_id,
        )
            .cmp(&(
                right.dependency_id.as_str(),
                &right.candidate_source_revision.revision_event_id,
            ))
    });
    Ok(DerivedContext {
        values: comparisons,
        withheld,
    })
}

async fn derive_inherited_uncertainty_on(
    conn: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Principal<'_>,
    consumer_record_id: Option<&str>,
    sources: &[RevisionRef],
    high_water: i64,
) -> Result<DerivedContext<UncertaintyLineage>> {
    let selected_events: BTreeSet<_> = sources
        .iter()
        .map(|reference| reference.revision_event_id.as_str())
        .collect();
    let rows = sqlx::query(
        "SELECT u.lineage,r.consumer_record_id,r.output_revision_event_id
           FROM receipt_uncertainty_lineage u
           JOIN receipts r ON r.receipt_id=u.receipt_id
          WHERE r.receipt_event_seq <= ?
          ORDER BY u.uncertainty_id",
    )
    .bind(high_water)
    .fetch_all(&mut **conn)
    .await?;
    let mut inherited = Vec::new();
    let mut withheld = false;
    for row in rows {
        let lineage: UncertaintyLineage =
            serde_json::from_str(&row.try_get::<String, _>("lineage")?)?;
        let lineage_consumer: String = row.try_get("consumer_record_id")?;
        let lineage_output_event_id: String = row.try_get("output_revision_event_id")?;
        let same_current_consumer = if consumer_record_id == Some(lineage_consumer.as_str()) {
            body_head_at_on(conn, &lineage_consumer, high_water)
                .await
                .is_ok_and(|reference| reference.revision_event_id == lineage_output_event_id)
        } else {
            false
        };
        if !selected_events.contains(lineage_output_event_id.as_str()) && !same_current_consumer {
            continue;
        }
        if authorize_uncertainty_lineage_on(conn, principal, &lineage)
            .await
            .is_err()
        {
            withheld = true;
            continue;
        }
        let reconciled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM reconciliations
              WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                AND task_scope=?3 AND affected_conclusion=?4
                AND reconciliation_event_seq <= ?5
                AND outcome IN ('immaterial','remains_valid'))
               AND NOT EXISTS(SELECT 1 FROM reconciliations
              WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                AND task_scope=?3 AND affected_conclusion=?4
                AND reconciliation_event_seq <= ?5
                AND outcome NOT IN ('immaterial','remains_valid'))",
        )
        .bind(lineage.dependency_id.as_str())
        .bind(&lineage.selected_source_revision.revision_event_id)
        .bind(&lineage.assessment_task_scope)
        .bind(serde_json::to_string(&lineage.affected_conclusion)?)
        .bind(high_water)
        .fetch_one(&mut **conn)
        .await?;
        if !reconciled {
            inherited.push(lineage);
        }
    }
    inherited.sort_by(|left, right| left.uncertainty_id.cmp(&right.uncertainty_id));
    Ok(DerivedContext {
        values: inherited,
        withheld,
    })
}

async fn inherits_withheld_context_on(
    conn: &mut SqliteConnection,
    consumer_record_id: Option<&str>,
    sources: &[RevisionRef],
    high_water: i64,
) -> Result<bool> {
    for source in sources {
        let withheld: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM receipts
              WHERE output_revision_event_id=? AND receipt_event_seq <= ?
                AND withheld_context=1)",
        )
        .bind(&source.revision_event_id)
        .bind(high_water)
        .fetch_one(&mut *conn)
        .await?;
        if withheld {
            return Ok(true);
        }
    }
    if let Some(consumer_record_id) = consumer_record_id {
        let head = body_head_at_on(conn, consumer_record_id, high_water).await?;
        let withheld: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM receipts
              WHERE output_revision_event_id=? AND receipt_event_seq <= ?
                AND withheld_context=1)",
        )
        .bind(&head.revision_event_id)
        .bind(high_water)
        .fetch_one(&mut *conn)
        .await?;
        if withheld {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Task-neutral exact mismatches. Materiality is deliberately absent.
pub async fn list_impact_candidates(
    db: &Db,
    principal: Principal<'_>,
    consumer_record_id: &str,
) -> Result<ImpactCandidateSet> {
    let mut snapshot = db.pool().begin().await?;
    require_capability_on(
        &mut snapshot,
        principal,
        consumer_record_id,
        Capability::View,
    )
    .await
    .map_err(|error| {
        semantic_runtime_read_error(principal, "freshness target unavailable", error)
    })?;
    let high_water: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *snapshot)
        .await?;
    let Some((consumer_revision, _)) =
        current_body_revision_on(&mut snapshot, consumer_record_id).await?
    else {
        snapshot.rollback().await?;
        return Ok(ImpactCandidateSet {
            candidates: Vec::new(),
            withheld_context: false,
        });
    };
    let mut withheld: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM receipts
          WHERE output_revision_event_id=? AND withheld_context=1)",
    )
    .bind(&consumer_revision.revision_event_id)
    .fetch_one(&mut *snapshot)
    .await?;
    let rows = sqlx::query(
        "SELECT d.dependency_id,d.receipt_id,d.source_revision,d.affected_conclusion,
                r.context_request
           FROM dependencies d JOIN receipts r ON r.receipt_id=d.receipt_id
          WHERE d.consumer_record_id=? AND d.consumer_revision_event_id=?
          ORDER BY d.dependency_id",
    )
    .bind(consumer_record_id)
    .bind(&consumer_revision.revision_event_id)
    .fetch_all(&mut *snapshot)
    .await?;
    let mut impacts = Vec::new();
    for row in rows {
        let pinned: RevisionRef =
            serde_json::from_str(&row.try_get::<String, _>("source_revision")?)?;
        if authorize_source_on(&mut snapshot, principal, &pinned)
            .await
            .is_err()
        {
            withheld = true;
            continue;
        }
        let dependency_id = DependencyId::new(row.try_get::<String, _>("dependency_id")?)?;
        let debt_scope =
            serde_json::from_str::<ContextRequest>(&row.try_get::<String, _>("context_request")?)?
                .task_scope;
        let affected_conclusion: String = row.try_get("affected_conclusion")?;
        let resolution =
            current_candidates_for_dependency_on(&mut snapshot, principal, &pinned, high_water)
                .await?;
        withheld |= resolution.withheld;
        for candidate in resolution.candidates {
            if authorize_source_on(&mut snapshot, principal, &candidate)
                .await
                .is_err()
            {
                withheld = true;
                continue;
            }
            let reconciled: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM reconciliations
                  WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                    AND task_scope=?3 AND affected_conclusion=?4
                    AND outcome IN ('immaterial','remains_valid'))
                   AND NOT EXISTS(SELECT 1 FROM reconciliations
                  WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                    AND task_scope=?3 AND affected_conclusion=?4
                    AND outcome NOT IN ('immaterial','remains_valid'))",
            )
            .bind(dependency_id.as_str())
            .bind(&candidate.revision_event_id)
            .bind(&debt_scope)
            .bind(&affected_conclusion)
            .fetch_one(&mut *snapshot)
            .await?;
            if !reconciled {
                impacts.push(ImpactCandidate {
                    dependency_id: dependency_id.clone(),
                    receipt_id: ReceiptId::new(row.try_get::<String, _>("receipt_id")?)?,
                    pinned_source_revision: pinned.clone(),
                    candidate_source_revision: candidate,
                });
            }
        }
    }
    snapshot.rollback().await?;
    Ok(ImpactCandidateSet {
        candidates: impacts,
        withheld_context: withheld,
    })
}

pub async fn reconcile_dependency(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    input: ReconcileDependencyInput,
) -> Result<()> {
    require_actor(actor)?;
    input.reconciliation_id.validate()?;
    input.dependency_id.validate()?;
    input.assessed_source_revision.validate()?;
    input.idempotency_key.validate()?;
    if input.rationale.trim().is_empty() || input.task_scope.trim().is_empty() {
        return Err(Error::engine(
            "reconciliation rationale and task scope must not be blank",
        ));
    }
    let intent = intent_sha256(&input)?;
    let mut tx = begin_write(db.write_pool()).await?;
    let row = sqlx::query(
        "SELECT d.consumer_record_id,d.consumer_revision,d.source_revision,d.affected_conclusion
           FROM dependencies d
          WHERE d.dependency_id=?",
    )
    .bind(input.dependency_id.as_str())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::engine("reconciliation target unavailable"))?;
    let consumer: String = row.try_get("consumer_record_id")?;
    require_capability_on(&mut tx, principal, &consumer, Capability::Edit)
        .await
        .map_err(|_| Error::engine("reconciliation target unavailable"))?;
    let pinned: RevisionRef = serde_json::from_str(&row.try_get::<String, _>("source_revision")?)?;
    let consumer_revision: RevisionRef =
        serde_json::from_str(&row.try_get::<String, _>("consumer_revision")?)?;
    let affected_conclusion: AffectedConclusion =
        serde_json::from_str(&row.try_get::<String, _>("affected_conclusion")?)?;
    authorize_source_on(&mut tx, principal, &pinned)
        .await
        .map_err(|_| Error::engine("reconciliation target unavailable"))?;
    authorize_source_on(&mut tx, principal, &input.assessed_source_revision)
        .await
        .map_err(|_| Error::engine("reconciliation target unavailable"))?;
    verify_revision_ref_on(&mut tx, &input.assessed_source_revision)
        .await
        .map_err(|_| Error::engine("reconciliation target unavailable"))?;
    if prior_runtime_command_on(
        &mut tx,
        &consumer,
        &input.idempotency_key,
        "reconcile_dependency",
        &intent,
    )
    .await?
    .is_some()
    {
        return Ok(());
    }
    let high_water: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let candidates = current_candidates_for_dependency_on(&mut tx, principal, &pinned, high_water)
        .await?
        .candidates;
    if !candidates.contains(&input.assessed_source_revision) {
        return Err(Error::engine(
            "reconciliation must name an exact current impact candidate",
        ));
    }
    let assessed_in_scope: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM dependency_assessments
          WHERE dependency_id=? AND compared_source_revision_event_id=? AND task_scope=?)",
    )
    .bind(input.dependency_id.as_str())
    .bind(&input.assessed_source_revision.revision_event_id)
    .bind(&input.task_scope)
    .fetch_one(&mut *tx)
    .await?;
    if !assessed_in_scope {
        return Err(Error::engine(
            "reconciliation must name a task scope with an exact prior assessment",
        ));
    }
    let auth_revision = authorization_revision_on(&mut tx).await?;
    append_in(
        db,
        &mut tx,
        event_spec(
            &consumer,
            "reconciliation.recorded.v1",
            &ReconciliationRecordedPayload {
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                runtime_contract_version: RUNTIME_CONTRACT_VERSION.into(),
                finalizing_receipt_id: None,
                reconciliation_id: input.reconciliation_id,
                dependency_id: input.dependency_id,
                consumer_revision,
                pinned_source_revision: pinned,
                assessed_source_revision: input.assessed_source_revision,
                task_scope: input.task_scope,
                affected_conclusion,
                outcome: input.outcome,
                rationale: input.rationale,
                command: Some(command(
                    "reconcile_dependency",
                    &consumer,
                    &input.idempotency_key,
                    intent,
                    auth_revision,
                )),
            },
            actor,
        )?,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn supersede_unit(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    mut input: SupersedeUnitInput,
) -> Result<()> {
    require_actor(actor)?;
    input.predecessor_unit_id.validate()?;
    input.idempotency_key.validate()?;
    if input.successors.is_empty() || input.rationale.trim().is_empty() {
        return Err(Error::engine(
            "supersession requires successors and rationale",
        ));
    }
    input.successors.sort_by(|left, right| {
        (&left.subject_id, &left.revision_event_id)
            .cmp(&(&right.subject_id, &right.revision_event_id))
    });
    let intent = intent_sha256(&input)?;
    let mut tx = begin_write(db.write_pool()).await?;
    require_capability_on(
        &mut tx,
        principal,
        input.predecessor_unit_id.as_str(),
        Capability::Edit,
    )
    .await?;
    let bearer = unit_bearer_on(&mut tx, input.predecessor_unit_id.as_str()).await?;
    require_capability_on(&mut tx, principal, &bearer, Capability::View).await?;
    for successor in &input.successors {
        authorize_source_on(&mut tx, principal, successor).await?;
        verify_revision_ref_on(&mut tx, successor).await?;
    }
    if prior_runtime_command_on(
        &mut tx,
        input.predecessor_unit_id.as_str(),
        &input.idempotency_key,
        "supersede_unit",
        &intent,
    )
    .await?
    .is_some()
    {
        return Ok(());
    }
    let auth_revision = authorization_revision_on(&mut tx).await?;
    append_in(
        db,
        &mut tx,
        event_spec(
            input.predecessor_unit_id.as_str(),
            "unit.superseded.v1",
            &UnitSupersededPayload {
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                runtime_contract_version: RUNTIME_CONTRACT_VERSION.into(),
                successors: input.successors,
                rationale: input.rationale,
                command: command(
                    "supersede_unit",
                    input.predecessor_unit_id.as_str(),
                    &input.idempotency_key,
                    intent,
                    auth_revision,
                ),
            },
            actor,
        )?,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn audit_dependency(
    db: &Db,
    principal: Principal<'_>,
    actor: &str,
    input: AuditDependencyInput,
) -> Result<()> {
    require_actor(actor)?;
    input.receipt_id.validate()?;
    input.idempotency_key.validate()?;
    if input.rationale.trim().is_empty() {
        return Err(Error::engine(
            "dependency audit rationale must not be blank",
        ));
    }
    let audits_declared = matches!(
        input.outcome,
        DependencyAuditOutcome::Confirmed | DependencyAuditOutcome::Overdeclared
    );
    match (
        audits_declared,
        input.declared_dependency_id.as_ref(),
        input.observed_dependency.as_ref(),
    ) {
        (true, Some(dependency_id), None) => dependency_id.validate()?,
        (false, None, Some(observed)) => observed.validate()?,
        _ => {
            return Err(Error::engine(
                "audit must name either one declared dependency or one omitted observed dependency",
            ));
        }
    }
    let intent = intent_sha256(&input)?;
    let mut tx = begin_write(db.write_pool()).await?;
    let consumer: String =
        sqlx::query_scalar("SELECT consumer_record_id FROM receipts WHERE receipt_id=?")
            .bind(input.receipt_id.as_str())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| Error::engine("dependency audit target unavailable"))?;
    require_capability_on(&mut tx, principal, &consumer, Capability::Edit)
        .await
        .map_err(|_| Error::engine("dependency audit target unavailable"))?;
    if let Some(dependency_id) = input.declared_dependency_id.as_ref() {
        let source: String = sqlx::query_scalar(
            "SELECT source_revision FROM dependencies WHERE dependency_id=? AND receipt_id=?",
        )
        .bind(dependency_id.as_str())
        .bind(input.receipt_id.as_str())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine("dependency audit target unavailable"))?;
        authorize_source_on(&mut tx, principal, &serde_json::from_str(&source)?)
            .await
            .map_err(|_| Error::engine("dependency audit target unavailable"))?;
    }
    if let Some(observed) = input.observed_dependency.as_ref() {
        let already_declared: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM dependencies
              WHERE receipt_id=?1 AND (
                    dependency_id=?2 OR (
                      source_revision=?3 AND semantic_role=?4
                      AND affected_conclusion=?5 AND reconsideration_trigger=?6)))",
        )
        .bind(input.receipt_id.as_str())
        .bind(observed.dependency_id.as_str())
        .bind(serde_json::to_string(&observed.source_revision)?)
        .bind(&observed.semantic_role)
        .bind(serde_json::to_string(&observed.affected_conclusion)?)
        .bind(&observed.reconsideration_trigger)
        .fetch_one(&mut *tx)
        .await?;
        if already_declared {
            return Err(Error::engine(
                "observed dependency was already declared by the Receipt",
            ));
        }
        authorize_source_on(&mut tx, principal, &observed.source_revision)
            .await
            .map_err(|_| Error::engine("dependency audit target unavailable"))?;
        verify_revision_ref_on(&mut tx, &observed.source_revision)
            .await
            .map_err(|_| Error::engine("dependency audit target unavailable"))?;
    }
    if prior_runtime_command_on(
        &mut tx,
        &consumer,
        &input.idempotency_key,
        "audit_dependency",
        &intent,
    )
    .await?
    .is_some()
    {
        return Ok(());
    }
    let auth_revision = authorization_revision_on(&mut tx).await?;
    append_in(
        db,
        &mut tx,
        event_spec(
            &consumer,
            "receipt.dependency_audited.v1",
            &ReceiptDependencyAuditedPayload {
                semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
                runtime_contract_version: RUNTIME_CONTRACT_VERSION.into(),
                receipt_id: input.receipt_id,
                declared_dependency_id: input.declared_dependency_id,
                observed_dependency: input.observed_dependency,
                outcome: input.outcome.as_str().into(),
                rationale: input.rationale,
                command: command(
                    "audit_dependency",
                    &consumer,
                    &input.idempotency_key,
                    intent,
                    auth_revision,
                ),
            },
            actor,
        )?,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn resolve_current_units(
    db: &Db,
    principal: Principal<'_>,
    unit_id: UnitId,
    high_water: HistoryHighWater,
) -> Result<CurrentUnitResolution> {
    unit_id.validate()?;
    high_water.validate()?;
    let mut snapshot = db.pool().begin().await?;
    let snapshot_head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *snapshot)
        .await?;
    if high_water.content_seq > snapshot_head {
        return Err(Error::engine(
            "Unit resolution high-water is beyond the snapshot head",
        ));
    }
    // Content is historical at the supplied boundary; authorization is
    // deliberately evaluated against the current policy projection.
    require_capability_on(&mut snapshot, principal, unit_id.as_str(), Capability::View)
        .await
        .map_err(|error| semantic_runtime_read_error(principal, "Unit unavailable", error))?;
    let bearer = unit_bearer_on(&mut snapshot, unit_id.as_str())
        .await
        .map_err(|error| semantic_runtime_read_error(principal, "Unit unavailable", error))?;
    require_capability_on(&mut snapshot, principal, &bearer, Capability::View)
        .await
        .map_err(|error| semantic_runtime_read_error(principal, "Unit unavailable", error))?;
    let mut queue = VecDeque::from([unit_id.as_str().to_owned()]);
    let mut seen = BTreeSet::new();
    let mut terminals = Vec::new();
    let mut withheld = false;
    while let Some(current) = queue.pop_front() {
        if !seen.insert(current.clone()) {
            continue;
        }
        if seen.len() > MAX_SUPERSESSION_TRAVERSAL {
            return Err(Error::engine("Unit supersession traversal limit exceeded"));
        }
        let rows = sqlx::query(
            "SELECT successor_revision FROM unit_supersessions
              WHERE predecessor_unit_id=? AND supersession_event_seq <= ?
              ORDER BY successor_unit_id,successor_revision_event_id",
        )
        .bind(&current)
        .bind(high_water.content_seq)
        .fetch_all(&mut *snapshot)
        .await?;
        let mut authorized = Vec::new();
        for row in rows {
            let successor: RevisionRef =
                serde_json::from_str(&row.try_get::<String, _>("successor_revision")?)?;
            if authorize_source_on(&mut snapshot, principal, &successor)
                .await
                .is_ok()
            {
                authorized.push(successor);
            } else {
                withheld = true;
            }
        }
        if authorized.is_empty() {
            terminals
                .extend(unit_heads_at_on(&mut snapshot, &current, high_water.content_seq).await?);
        } else {
            for successor in authorized {
                queue.push_back(successor.subject_id);
            }
        }
    }
    terminals.sort_by(|left, right| {
        (&left.subject_id, &left.revision_event_id)
            .cmp(&(&right.subject_id, &right.revision_event_id))
    });
    terminals.dedup();
    snapshot.rollback().await?;
    Ok(CurrentUnitResolution {
        requested_unit_id: unit_id,
        ambiguous: terminals.len() > 1,
        terminal_successors: terminals,
        withheld_context: withheld,
    })
}

fn semantic_runtime_read_error(principal: Principal<'_>, public: &str, error: Error) -> Error {
    if principal.is_trusted_local() {
        error
    } else {
        Error::engine(public)
    }
}

fn materiality_outcome(value: &str) -> Result<MaterialityOutcome> {
    match value {
        "immaterial" => Ok(MaterialityOutcome::Immaterial),
        "remains_valid" => Ok(MaterialityOutcome::RemainsValid),
        "material" => Ok(MaterialityOutcome::Material),
        "materially_uncertain" => Ok(MaterialityOutcome::MateriallyUncertain),
        "contradicted" => Ok(MaterialityOutcome::Contradicted),
        "unable_to_assess" => Ok(MaterialityOutcome::UnableToAssess),
        _ => Err(Error::engine("invalid materiality outcome")),
    }
}

fn dependency_audit_outcome(value: &str) -> Result<DependencyAuditOutcome> {
    match value {
        "confirmed" => Ok(DependencyAuditOutcome::Confirmed),
        "missing" => Ok(DependencyAuditOutcome::Missing),
        "overdeclared" => Ok(DependencyAuditOutcome::Overdeclared),
        "underdeclared" => Ok(DependencyAuditOutcome::Underdeclared),
        _ => Err(Error::engine("invalid dependency audit outcome")),
    }
}

pub async fn explain_freshness(
    db: &Db,
    principal: Principal<'_>,
    receipt_id: ReceiptId,
) -> Result<FreshnessExplanation> {
    receipt_id.validate()?;
    let mut snapshot = db.pool().begin().await?;
    let row = sqlx::query(
        "SELECT consumer_record_id,output_revision,context_request,resolution_policy,
                selected_sources,history_high_water,execution,disclosure,withheld_context
           FROM receipts WHERE receipt_id=?",
    )
    .bind(receipt_id.as_str())
    .fetch_optional(&mut *snapshot)
    .await?
    .ok_or_else(|| Error::engine("Receipt unavailable"))?;
    let consumer: String = row.try_get("consumer_record_id")?;
    require_capability_on(&mut snapshot, principal, &consumer, Capability::View)
        .await
        .map_err(|_| Error::engine("Receipt unavailable"))?;
    let output_revision: RevisionRef =
        serde_json::from_str(&row.try_get::<String, _>("output_revision")?)?;
    let context_request: ContextRequest =
        serde_json::from_str(&row.try_get::<String, _>("context_request")?)?;
    let resolution_policy: ResolutionPolicy =
        serde_json::from_str(&row.try_get::<String, _>("resolution_policy")?)?;
    let selected_sources: Vec<RevisionRef> =
        serde_json::from_str(&row.try_get::<String, _>("selected_sources")?)?;
    let history_high_water: HistoryHighWater =
        serde_json::from_str(&row.try_get::<String, _>("history_high_water")?)?;
    let mut withheld = row.try_get::<bool, _>("withheld_context")?;
    let mut visible_provenance = Vec::new();
    for source in sqlx::query(
        "SELECT source_revision,reason FROM receipt_provenance WHERE receipt_id=? ORDER BY ordinal",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *snapshot)
    .await?
    {
        let reference: RevisionRef =
            serde_json::from_str(&source.try_get::<String, _>("source_revision")?)?;
        if authorize_source_on(&mut snapshot, principal, &reference)
            .await
            .is_ok()
        {
            visible_provenance.push(ProvenanceUse {
                source_revision: reference,
                reason: source.try_get("reason")?,
            });
        } else {
            withheld = true;
        }
    }
    let mut visible_dependencies = Vec::new();
    for dependency in sqlx::query(
        "SELECT dependency_id,source_revision,semantic_role,affected_conclusion,rationale,
                reconsideration_trigger,confidence FROM dependencies WHERE receipt_id=? ORDER BY dependency_id",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *snapshot)
    .await?
    {
        let reference: RevisionRef = serde_json::from_str(&dependency.try_get::<String, _>("source_revision")?)?;
        if authorize_source_on(&mut snapshot, principal, &reference).await.is_ok() {
            let dependency_id = DependencyId::new(dependency.try_get::<String, _>("dependency_id")?)?;
            visible_dependencies.push(DependencyInput {
                dependency_id,
                source_revision: reference,
                semantic_role: dependency.try_get("semantic_role")?,
                affected_conclusion: serde_json::from_str(&dependency.try_get::<String, _>("affected_conclusion")?)?,
                rationale: dependency.try_get("rationale")?,
                reconsideration_trigger: dependency.try_get("reconsideration_trigger")?,
                confidence: dependency.try_get("confidence")?,
            });
        } else {
            withheld = true;
        }
    }

    let mut visible_comparisons = Vec::new();
    for comparison in sqlx::query(
        "SELECT c.receipt_id AS observed_in_receipt_id,
                d.receipt_id AS dependency_receipt_id,c.dependency_id,
                d.consumer_revision,c.pinned_source_revision,c.selected_source_revision,
                d.affected_conclusion,r.context_request,r.history_high_water,r.receipt_event_id
           FROM receipt_comparisons c
           JOIN dependencies d ON d.dependency_id=c.dependency_id
           JOIN receipts r ON r.receipt_id=c.receipt_id
          WHERE c.receipt_id=?1 OR d.receipt_id=?1
          ORDER BY r.receipt_event_seq,c.ordinal,c.dependency_id",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *snapshot)
    .await?
    {
        let consumer_revision: RevisionRef =
            serde_json::from_str(&comparison.try_get::<String, _>("consumer_revision")?)?;
        let pinned_source_revision: RevisionRef =
            serde_json::from_str(&comparison.try_get::<String, _>("pinned_source_revision")?)?;
        let selected_source_revision: RevisionRef =
            serde_json::from_str(&comparison.try_get::<String, _>("selected_source_revision")?)?;
        let mut authorized = true;
        for reference in [
            &consumer_revision,
            &pinned_source_revision,
            &selected_source_revision,
        ] {
            if authorize_source_on(&mut snapshot, principal, reference)
                .await
                .is_err()
            {
                authorized = false;
            }
        }
        if !authorized {
            withheld = true;
            continue;
        }
        let observed_request: ContextRequest =
            serde_json::from_str(&comparison.try_get::<String, _>("context_request")?)?;
        visible_comparisons.push(ComparisonEvidence {
            observed_in_receipt_id: ReceiptId::new(
                comparison.try_get::<String, _>("observed_in_receipt_id")?,
            )?,
            dependency_receipt_id: ReceiptId::new(
                comparison.try_get::<String, _>("dependency_receipt_id")?,
            )?,
            dependency_id: DependencyId::new(comparison.try_get::<String, _>("dependency_id")?)?,
            consumer_revision,
            mismatch: pinned_source_revision != selected_source_revision,
            pinned_source_revision,
            selected_source_revision,
            task_scope: observed_request.task_scope,
            affected_conclusion: serde_json::from_str(
                &comparison.try_get::<String, _>("affected_conclusion")?,
            )?,
            history_high_water: serde_json::from_str(
                &comparison.try_get::<String, _>("history_high_water")?,
            )?,
            evidence_event_id: comparison.try_get("receipt_event_id")?,
        });
    }

    let mut visible_assessments = Vec::new();
    for assessment in sqlx::query(
        "SELECT a.receipt_id AS observed_in_receipt_id,
                d.receipt_id AS dependency_receipt_id,
                a.assessment_id,a.assessment_event_id,a.dependency_id,
                a.compared_source_revision,a.task_scope,a.category,a.outcome,
                a.could_materially_change,a.rationale,a.actor,
                d.consumer_revision,d.source_revision,d.affected_conclusion,
                r.history_high_water
           FROM dependency_assessments a
           JOIN dependencies d ON d.dependency_id=a.dependency_id
           JOIN receipts r ON r.receipt_id=a.receipt_id
          WHERE a.receipt_id=?1 OR d.receipt_id=?1
          ORDER BY a.assessment_event_seq,a.assessment_id",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *snapshot)
    .await?
    {
        let consumer_revision: RevisionRef =
            serde_json::from_str(&assessment.try_get::<String, _>("consumer_revision")?)?;
        let pinned_source: RevisionRef =
            serde_json::from_str(&assessment.try_get::<String, _>("source_revision")?)?;
        let compared_source_revision: RevisionRef =
            serde_json::from_str(&assessment.try_get::<String, _>("compared_source_revision")?)?;
        if authorize_source_on(&mut snapshot, principal, &consumer_revision)
            .await
            .is_err()
            || authorize_source_on(&mut snapshot, principal, &pinned_source)
                .await
                .is_err()
            || authorize_source_on(&mut snapshot, principal, &compared_source_revision)
                .await
                .is_err()
        {
            withheld = true;
            continue;
        }
        visible_assessments.push(AssessmentEvidence {
            observed_in_receipt_id: ReceiptId::new(
                assessment.try_get::<String, _>("observed_in_receipt_id")?,
            )?,
            dependency_receipt_id: ReceiptId::new(
                assessment.try_get::<String, _>("dependency_receipt_id")?,
            )?,
            assessment_id: AssessmentId::new(assessment.try_get::<String, _>("assessment_id")?)?,
            dependency_id: DependencyId::new(assessment.try_get::<String, _>("dependency_id")?)?,
            consumer_revision,
            pinned_source_revision: pinned_source,
            compared_source_revision,
            task_scope: assessment.try_get("task_scope")?,
            affected_conclusion: serde_json::from_str(
                &assessment.try_get::<String, _>("affected_conclusion")?,
            )?,
            history_high_water: serde_json::from_str(
                &assessment.try_get::<String, _>("history_high_water")?,
            )?,
            category: assessment.try_get("category")?,
            outcome: materiality_outcome(&assessment.try_get::<String, _>("outcome")?)?,
            could_materially_change: assessment.try_get("could_materially_change")?,
            rationale: assessment.try_get("rationale")?,
            evaluator: assessment.try_get("actor")?,
            evidence_event_id: assessment.try_get("assessment_event_id")?,
        });
    }

    let mut visible_reconciliations = Vec::new();
    for reconciliation in sqlx::query(
        "SELECT rc.reconciliation_id,rc.reconciliation_event_id,
                rc.resolving_receipt_id,rc.dependency_id,rc.assessed_source_revision,
                rc.task_scope,rc.affected_conclusion,rc.outcome,rc.rationale,rc.actor,
                d.consumer_revision,d.source_revision,
                rr.output_revision AS resolving_output_revision
           FROM reconciliations rc
           JOIN dependencies d ON d.dependency_id=rc.dependency_id
           LEFT JOIN receipts rr ON rr.receipt_id=rc.resolving_receipt_id
          WHERE d.receipt_id=?1 OR rc.resolving_receipt_id=?1
             OR EXISTS(
                SELECT 1 FROM receipt_comparisons c
                 WHERE c.receipt_id=?1 AND c.dependency_id=rc.dependency_id)
             OR EXISTS(
                SELECT 1 FROM dependency_assessments a
                 WHERE a.receipt_id=?1 AND a.dependency_id=rc.dependency_id)
          ORDER BY rc.reconciliation_event_seq,rc.reconciliation_id",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *snapshot)
    .await?
    {
        let consumer_revision: RevisionRef =
            serde_json::from_str(&reconciliation.try_get::<String, _>("consumer_revision")?)?;
        let pinned_source_revision: RevisionRef =
            serde_json::from_str(&reconciliation.try_get::<String, _>("source_revision")?)?;
        let assessed_source_revision: RevisionRef = serde_json::from_str(
            &reconciliation.try_get::<String, _>("assessed_source_revision")?,
        )?;
        let resolving_output_revision = reconciliation
            .try_get::<Option<String>, _>("resolving_output_revision")?
            .map(|value| serde_json::from_str::<RevisionRef>(&value))
            .transpose()?;
        let mut authorized = true;
        for reference in [
            &consumer_revision,
            &pinned_source_revision,
            &assessed_source_revision,
        ] {
            if authorize_source_on(&mut snapshot, principal, reference)
                .await
                .is_err()
            {
                authorized = false;
            }
        }
        if let Some(reference) = resolving_output_revision.as_ref() {
            if authorize_source_on(&mut snapshot, principal, reference)
                .await
                .is_err()
            {
                authorized = false;
            }
        }
        if !authorized {
            withheld = true;
            continue;
        }
        visible_reconciliations.push(ReconciliationEvidenceView {
            reconciliation_id: ReconciliationId::new(
                reconciliation.try_get::<String, _>("reconciliation_id")?,
            )?,
            dependency_id: DependencyId::new(
                reconciliation.try_get::<String, _>("dependency_id")?,
            )?,
            consumer_revision,
            pinned_source_revision,
            assessed_source_revision,
            task_scope: reconciliation.try_get("task_scope")?,
            affected_conclusion: serde_json::from_str(
                &reconciliation.try_get::<String, _>("affected_conclusion")?,
            )?,
            outcome: materiality_outcome(&reconciliation.try_get::<String, _>("outcome")?)?,
            rationale: reconciliation.try_get("rationale")?,
            actor: reconciliation.try_get("actor")?,
            evidence_event_id: reconciliation.try_get("reconciliation_event_id")?,
            resolving_receipt_id: reconciliation
                .try_get::<Option<String>, _>("resolving_receipt_id")?
                .map(ReceiptId::new)
                .transpose()?,
            resolving_output_revision,
        });
    }

    let mut visible_dependency_audits = Vec::new();
    for audit in sqlx::query(
        "SELECT audit_event_id,audit_event_seq,receipt_id,declared_dependency_id,
                observed_dependency,outcome,rationale,actor
           FROM dependency_audits WHERE receipt_id=?
          ORDER BY audit_event_seq,audit_event_id",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *snapshot)
    .await?
    {
        let declared_dependency_id = audit
            .try_get::<Option<String>, _>("declared_dependency_id")?
            .map(DependencyId::new)
            .transpose()?;
        let observed_dependency = audit
            .try_get::<Option<String>, _>("observed_dependency")?
            .map(|value| serde_json::from_str::<DependencyInput>(&value))
            .transpose()?;
        let mut authorized = true;
        if let Some(dependency_id) = declared_dependency_id.as_ref() {
            let source: RevisionRef = serde_json::from_str(
                &sqlx::query_scalar::<_, String>(
                    "SELECT source_revision FROM dependencies
                      WHERE receipt_id=? AND dependency_id=?",
                )
                .bind(receipt_id.as_str())
                .bind(dependency_id.as_str())
                .fetch_one(&mut *snapshot)
                .await?,
            )?;
            if authorize_source_on(&mut snapshot, principal, &source)
                .await
                .is_err()
            {
                authorized = false;
            }
        }
        if let Some(dependency) = observed_dependency.as_ref() {
            if authorize_source_on(&mut snapshot, principal, &dependency.source_revision)
                .await
                .is_err()
            {
                authorized = false;
            }
        }
        if !authorized {
            withheld = true;
            continue;
        }
        visible_dependency_audits.push(DependencyAuditEvidence {
            audit_event_id: audit.try_get("audit_event_id")?,
            audit_event_seq: audit.try_get("audit_event_seq")?,
            receipt_id: ReceiptId::new(audit.try_get::<String, _>("receipt_id")?)?,
            declared_dependency_id,
            observed_dependency,
            outcome: dependency_audit_outcome(&audit.try_get::<String, _>("outcome")?)?,
            rationale: audit.try_get("rationale")?,
            actor: audit.try_get("actor")?,
        });
    }

    let mut occurrence_ids = BTreeSet::new();
    for selected_source in &selected_sources {
        if authorize_source_on(&mut snapshot, principal, selected_source)
            .await
            .is_err()
        {
            withheld = true;
            continue;
        }
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT occurrence_id FROM occurrences
              WHERE unit_revision_event_id=? OR artefact_revision_event_id=?
              ORDER BY binding_event_seq,occurrence_id",
        )
        .bind(&selected_source.revision_event_id)
        .bind(&selected_source.revision_event_id)
        .fetch_all(&mut *snapshot)
        .await?;
        occurrence_ids.extend(ids);
    }
    let mut visible_occurrence_evidence = Vec::new();
    for occurrence_id in occurrence_ids {
        let occurrence = load_occurrence_on(&mut snapshot, &occurrence_id).await?;
        if authorize_source_on(&mut snapshot, principal, &occurrence.unit_revision)
            .await
            .is_err()
            || authorize_source_on(&mut snapshot, principal, &occurrence.artefact_revision)
                .await
                .is_err()
        {
            withheld = true;
            continue;
        }
        let resolution = resolve_occurrence_view_on(&mut snapshot, occurrence.clone()).await?;
        visible_occurrence_evidence.push(OccurrenceEvidence {
            occurrence,
            resolution,
        });
    }

    let current_high_water: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
            .fetch_one(&mut *snapshot)
            .await?;
    let mut unresolved_uncertainty = Vec::new();
    for row in sqlx::query(
        "SELECT lineage FROM receipt_uncertainty_lineage WHERE receipt_id=? ORDER BY ordinal",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *snapshot)
    .await?
    {
        let lineage: UncertaintyLineage =
            serde_json::from_str(&row.try_get::<String, _>("lineage")?)?;
        if authorize_uncertainty_lineage_on(&mut snapshot, principal, &lineage)
            .await
            .is_ok()
        {
            let reconciled: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM reconciliations
                  WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                    AND task_scope=?3 AND affected_conclusion=?4
                    AND reconciliation_event_seq <= ?5
                    AND outcome IN ('immaterial','remains_valid'))
                   AND NOT EXISTS(SELECT 1 FROM reconciliations
                  WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                    AND task_scope=?3 AND affected_conclusion=?4
                    AND reconciliation_event_seq <= ?5
                    AND outcome NOT IN ('immaterial','remains_valid'))",
            )
            .bind(lineage.dependency_id.as_str())
            .bind(&lineage.selected_source_revision.revision_event_id)
            .bind(&lineage.assessment_task_scope)
            .bind(serde_json::to_string(&lineage.affected_conclusion)?)
            .bind(current_high_water)
            .fetch_one(&mut *snapshot)
            .await?;
            if !reconciled {
                unresolved_uncertainty.push(lineage);
            }
        } else {
            withheld = true;
        }
    }
    let mut visible_impacts = Vec::new();
    for dependency in sqlx::query(
        "SELECT d.dependency_id,d.source_revision,d.affected_conclusion,r.context_request
           FROM dependencies d JOIN receipts r ON r.receipt_id=d.receipt_id
          WHERE d.receipt_id=? ORDER BY d.dependency_id",
    )
    .bind(receipt_id.as_str())
    .fetch_all(&mut *snapshot)
    .await?
    {
        let dependency_id = DependencyId::new(dependency.try_get::<String, _>("dependency_id")?)?;
        let pinned: RevisionRef =
            serde_json::from_str(&dependency.try_get::<String, _>("source_revision")?)?;
        let debt_scope = serde_json::from_str::<ContextRequest>(
            &dependency.try_get::<String, _>("context_request")?,
        )?
        .task_scope;
        let affected_conclusion: String = dependency.try_get("affected_conclusion")?;
        if authorize_source_on(&mut snapshot, principal, &pinned)
            .await
            .is_err()
        {
            withheld = true;
            continue;
        }
        let resolution = current_candidates_for_dependency_on(
            &mut snapshot,
            principal,
            &pinned,
            current_high_water,
        )
        .await?;
        withheld |= resolution.withheld;
        for candidate in resolution.candidates {
            let reconciled: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM reconciliations
                  WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                    AND task_scope=?3 AND affected_conclusion=?4
                    AND outcome IN ('immaterial','remains_valid'))
                   AND NOT EXISTS(SELECT 1 FROM reconciliations
                  WHERE dependency_id=?1 AND assessed_source_revision_event_id=?2
                    AND task_scope=?3 AND affected_conclusion=?4
                    AND outcome NOT IN ('immaterial','remains_valid'))",
            )
            .bind(dependency_id.as_str())
            .bind(&candidate.revision_event_id)
            .bind(&debt_scope)
            .bind(&affected_conclusion)
            .fetch_one(&mut *snapshot)
            .await?;
            if !reconciled {
                visible_impacts.push(ImpactCandidate {
                    dependency_id: dependency_id.clone(),
                    receipt_id: receipt_id.clone(),
                    pinned_source_revision: pinned.clone(),
                    candidate_source_revision: candidate,
                });
            }
        }
    }
    snapshot.rollback().await?;
    Ok(FreshnessExplanation {
        receipt_id,
        output_revision,
        history_high_water,
        context_request,
        resolution_policy,
        execution: match row.try_get::<String, _>("execution")?.as_str() {
            "continued" => ExecutionDisposition::Continued,
            "stopped" => ExecutionDisposition::Stopped,
            _ => return Err(Error::engine("invalid Receipt execution")),
        },
        disclosure: match row.try_get::<String, _>("disclosure")?.as_str() {
            "silent" => DisclosureDecision::Silent,
            "explain_on_inspection" => DisclosureDecision::ExplainOnInspection,
            "surface_now" => DisclosureDecision::SurfaceNow,
            _ => return Err(Error::engine("invalid Receipt disclosure")),
        },
        visible_provenance,
        visible_dependencies,
        visible_comparisons,
        visible_assessments,
        visible_reconciliations,
        visible_dependency_audits,
        visible_occurrence_evidence,
        visible_impacts,
        unresolved_uncertainty,
        provenance_completeness: if withheld {
            ProvenanceCompleteness::Withheld
        } else {
            ProvenanceCompleteness::Complete
        },
    })
}
