use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability, Principal};
use native_ce::conformance::rebuild_and_diff;
use native_ce::freshness::*;
use native_ce::query::pipeline::{self, Filter, PipelineOptions, PipelineOutput, Step};
use native_ce::store::{archive_record, create_record, delete_record, update_record};
use native_ce::{Db, Error, Result};
use serde_json::json;
use sqlx::Row;
use std::sync::Arc;
use tokio::sync::{Barrier, Mutex};

use super::{scenarios, AuditEvidence, FreshnessHarness, SemanticInventory};

const ACTOR: &str = "test:freshness-contract";
const ACCOUNT: &str = "acct:freshness-contract";

pub struct SqliteFreshnessHarness;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcurrentHighWaterTrace {
    pub captured: HistoryHighWater,
    pub source_revision_committed_during_pause: RevisionRef,
    pub selected_revisions: Vec<RevisionRef>,
    pub sealed_comparisons: Vec<ImpactCandidate>,
    pub receipt_revision_seq: i64,
    pub immediate_impacts: Vec<ImpactCandidate>,
    pub control_selected_revisions: Vec<RevisionRef>,
    pub control_comparisons: Vec<ImpactCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccupancyDifferential {
    pub hidden_unit_error: String,
    pub absent_unit_error: String,
    pub hidden_occurrence_error: String,
    pub absent_occurrence_error: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtomicFootprint {
    pub content_events: i64,
    pub receipts: i64,
    pub dependencies: i64,
    pub assessments: i64,
    pub reconciliations: i64,
    pub provenance: i64,
    pub comparisons: i64,
    pub uncertainty: i64,
    pub runtime_commands: i64,
    pub consumer_body: String,
}

#[derive(Clone, Debug)]
pub struct AtomicFailureEvidence {
    pub stage: &'static str,
    pub error: String,
    pub before: AtomicFootprint,
    pub after_failure: AtomicFootprint,
    pub committed: CommitDurableOutputResult,
    pub identical_retry: CommitDurableOutputResult,
    pub after_changed_intent: AtomicFootprint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityLifecycleEvidence {
    pub archived_unit_readable: bool,
    pub archived_occurrence_state: OccurrenceResolutionState,
    pub deleted_unit_error: String,
    pub deleted_occurrence_error: String,
    pub deleted_explanation_completeness: ProvenanceCompleteness,
    pub deleted_visible_dependency_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingRepresentationEvidence {
    pub expected_original_artefact_revision: RevisionRef,
    pub resolution: OccurrenceResolution,
    pub sibling_resolution: OccurrenceResolution,
    pub unit_still_readable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayTableEvidence {
    pub table: String,
    pub live: usize,
    pub rebuilt: usize,
    pub mismatches: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationEvidence {
    pub rejected_error: String,
    pub content_events_before: i64,
    pub content_events_after_rejection: i64,
    pub occupied_keys_after_rejection: i64,
    pub restored_receipt: ReceiptId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecondaryOccurrenceAccessEvidence {
    pub secondary_artefact_accessible: bool,
    pub unit_error: String,
    pub occurrence_error: String,
    pub secondary_history_occurrence_events: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupersessionEvidence {
    pub single_terminal: Vec<RevisionRef>,
    pub plural_terminals: Vec<RevisionRef>,
    pub plural_ambiguous: bool,
    pub filtered_terminals: Vec<RevisionRef>,
    pub filtered_ambiguous: bool,
    pub filtered_withheld: bool,
    pub historical_dependency: RevisionRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationLeakageEvidence {
    pub one_hidden_shape: String,
    pub two_hidden_shape: String,
    pub secret_strings_absent: bool,
    pub impact_candidates_visible: usize,
    pub impact_withheld: bool,
}

impl SqliteFreshnessHarness {
    pub fn new() -> Self {
        Self
    }

    fn principal() -> native_ce::authorization::Principal<'static> {
        native_ce::authorization::Principal::bound(ACCOUNT, true)
    }
}

impl FreshnessHarness for SqliteFreshnessHarness {
    type Database = Db;

    async fn fresh_database(&self) -> Result<Self::Database> {
        native_ce::create_database(":memory:").await
    }

    async fn close(&self, _database: &Self::Database) {}

    async fn create_artefact(
        &self,
        database: &Self::Database,
        id: &str,
        name: &str,
        body: &str,
    ) -> Result<RevisionRef> {
        create_record(
            database,
            json!({"id":id,"type":"Document","kind":"note","name":name,"body":body}),
        )
        .await?;
        current_record_body_revision(database, id).await
    }

    async fn artefact_body(&self, database: &Self::Database, id: &str) -> Result<String> {
        sqlx::query_scalar("SELECT body FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(database.pool())
            .await?
            .ok_or_else(|| Error::engine("proof artefact is unavailable"))
    }

    async fn artefact_name(&self, database: &Self::Database, id: &str) -> Result<String> {
        sqlx::query_scalar("SELECT name FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(database.pool())
            .await?
            .ok_or_else(|| Error::engine("proof artefact is unavailable"))
    }

    async fn rename_artefact(&self, database: &Self::Database, id: &str, name: &str) -> Result<()> {
        update_record(database, id, json!({"name":name})).await
    }

    async fn update_artefact(
        &self,
        database: &Self::Database,
        id: &str,
        expected: &RevisionRef,
        body: &str,
    ) -> Result<RevisionRef> {
        if current_record_body_revision(database, id).await? != *expected {
            return Err(Error::engine("proof artefact expected revision conflict"));
        }
        update_record(database, id, json!({"body":body})).await?;
        current_record_body_revision(database, id).await
    }

    async fn promote_idea(
        &self,
        database: &Self::Database,
        input: PromoteIdeaInput,
    ) -> Result<PromoteIdeaResult> {
        native_ce::freshness::promote_idea(database, Self::principal(), ACTOR, input).await
    }

    async fn bind_occurrence(
        &self,
        database: &Self::Database,
        input: BindOccurrenceInput,
    ) -> Result<BindOccurrenceResult> {
        native_ce::freshness::bind_occurrence(database, Self::principal(), ACTOR, input).await
    }

    async fn revise_unit(
        &self,
        database: &Self::Database,
        input: ReviseUnitInput,
    ) -> Result<ReviseUnitResult> {
        native_ce::freshness::revise_unit(database, Self::principal(), ACTOR, input).await
    }

    async fn read_unit(&self, database: &Self::Database, unit_id: &UnitId) -> Result<UnitView> {
        native_ce::freshness::read_unit(database, Self::principal(), unit_id).await
    }

    async fn read_unit_revision(
        &self,
        database: &Self::Database,
        reference: &RevisionRef,
    ) -> Result<UnitRevisionView> {
        native_ce::freshness::read_unit_revision(database, Self::principal(), reference).await
    }

    async fn list_occurrences(
        &self,
        database: &Self::Database,
        unit_id: &UnitId,
    ) -> Result<Vec<OccurrenceView>> {
        native_ce::freshness::list_occurrences(database, Self::principal(), unit_id).await
    }

    async fn resolve_occurrence(
        &self,
        database: &Self::Database,
        occurrence_id: &OccurrenceId,
    ) -> Result<OccurrenceResolution> {
        native_ce::freshness::resolve_occurrence(database, Self::principal(), occurrence_id).await
    }

    async fn is_subordinate_in_ordinary_listing(
        &self,
        database: &Self::Database,
        unit_id: &UnitId,
    ) -> Result<bool> {
        let output = pipeline::run(
            database,
            &[Step::filter(Filter {
                ids: vec![unit_id.as_str().into()],
                ..Filter::default()
            })],
            None,
            &PipelineOptions::default(),
        )
        .await?;
        Ok(
            matches!(output, PipelineOutput::Records { total: 0, records, .. } if records.is_empty()),
        )
    }

    async fn assemble_context(
        &self,
        database: &Self::Database,
        request: ContextRequest,
        consumer_record_id: Option<&str>,
        source_record_ids: Vec<String>,
    ) -> Result<ContextAssembly> {
        native_ce::freshness::assemble_context(
            database,
            Self::principal(),
            request,
            consumer_record_id,
            source_record_ids,
        )
        .await
    }

    async fn commit_output(
        &self,
        database: &Self::Database,
        input: CommitDurableOutputInput,
    ) -> Result<CommitDurableOutputResult> {
        native_ce::freshness::commit_durable_output(database, Self::principal(), ACTOR, input).await
    }

    async fn impact_candidates(
        &self,
        database: &Self::Database,
        consumer_record_id: &str,
    ) -> Result<ImpactCandidateSet> {
        native_ce::freshness::list_impact_candidates(
            database,
            Self::principal(),
            consumer_record_id,
        )
        .await
    }

    async fn explain(
        &self,
        database: &Self::Database,
        receipt_id: ReceiptId,
    ) -> Result<FreshnessExplanation> {
        native_ce::freshness::explain_freshness(database, Self::principal(), receipt_id).await
    }

    async fn reconcile(
        &self,
        database: &Self::Database,
        input: ReconcileDependencyInput,
    ) -> Result<()> {
        native_ce::freshness::reconcile_dependency(database, Self::principal(), ACTOR, input).await
    }

    async fn audit(
        &self,
        database: &Self::Database,
        input: AuditDependencyInput,
    ) -> Result<AuditEvidence> {
        let key = input.idempotency_key.as_str().to_owned();
        native_ce::freshness::audit_dependency(database, Self::principal(), ACTOR, input).await?;
        let row = sqlx::query(
            "SELECT a.outcome,a.declared_dependency_id,a.observed_dependency
               FROM dependency_audits a
               JOIN freshness_runtime_command_results c ON c.result_event_id=a.audit_event_id
              WHERE c.idempotency_key=? AND c.operation='audit_dependency'",
        )
        .bind(key)
        .fetch_one(database.pool())
        .await?;
        let outcome = match row.try_get::<String, _>("outcome")?.as_str() {
            "confirmed" => DependencyAuditOutcome::Confirmed,
            "missing" => DependencyAuditOutcome::Missing,
            "overdeclared" => DependencyAuditOutcome::Overdeclared,
            "underdeclared" => DependencyAuditOutcome::Underdeclared,
            _ => return Err(Error::engine("invalid dependency audit outcome")),
        };
        Ok(AuditEvidence {
            outcome,
            has_declared_dependency: row
                .try_get::<Option<String>, _>("declared_dependency_id")?
                .is_some(),
            has_observed_dependency: row
                .try_get::<Option<String>, _>("observed_dependency")?
                .is_some(),
        })
    }

    async fn semantic_inventory(&self, database: &Self::Database) -> Result<SemanticInventory> {
        Ok(SemanticInventory {
            units: sqlx::query_scalar("SELECT COUNT(*) FROM semantic_units")
                .fetch_one(database.pool())
                .await?,
            occurrences: sqlx::query_scalar("SELECT COUNT(*) FROM occurrences")
                .fetch_one(database.pool())
                .await?,
            receipts: sqlx::query_scalar("SELECT COUNT(*) FROM receipts")
                .fetch_one(database.pool())
                .await?,
        })
    }

    async fn receipt_dependency_budget(
        &self,
        database: &Self::Database,
        receipt_id: &ReceiptId,
    ) -> Result<(u32, u32)> {
        let row = sqlx::query(
            "SELECT json_extract(e.payload,'$.dependency_budget_used') AS used,
                    json_extract(e.payload,'$.resolution_policy.dependency_budget') AS budget
               FROM receipts r JOIN content_events e ON e.id=r.receipt_event_id
              WHERE r.receipt_id=?",
        )
        .bind(receipt_id.as_str())
        .fetch_one(database.pool())
        .await?;
        Ok((
            row.try_get::<i64, _>("used")? as u32,
            row.try_get::<i64, _>("budget")? as u32,
        ))
    }

    async fn assert_replay_equivalent(&self, database: &Self::Database) -> Result<()> {
        let diff = rebuild_and_diff(database).await?;
        if diff.equal {
            Ok(())
        } else {
            Err(Error::engine(format!(
                "freshness replay differs: {:?}",
                diff.tables
            )))
        }
    }
}

async fn proof_document(database: &Db, id: &str, body: &str) -> Result<RevisionRef> {
    create_record(
        database,
        json!({"id":id,"type":"Document","kind":"note","name":id,"body":body}),
    )
    .await?;
    current_record_body_revision(database, id).await
}

/// `prefix` still names the semantic ids (Unit-internal occurrence id and the
/// idempotency key), which are not record ids and stay readable. `ordinal`
/// pins the two ids that ARE record ids — the artefact source and the promoted
/// Unit — to distinct, deterministic UUIDs.
async fn proof_unit(
    database: &Db,
    prefix: &str,
    ordinal: u8,
) -> Result<(String, PromoteIdeaResult)> {
    let source_id = format!("f9e50000-0000-4000-8000-0000000001{ordinal:02x}");
    let unit_id = format!("f9e50000-0000-4000-8000-0000000002{ordinal:02x}");
    let sentence = "Audience: technical founders.";
    let source_revision = proof_document(database, &source_id, sentence).await?;
    let promoted = native_ce::freshness::promote_idea(
        database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: sentence.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("Primary audience: technical founders.")?,
            expression_role: ExpressionRole::Canonical,
            label: Some("Audience".into()),
            requested_unit_id: Some(UnitId::new(unit_id)?),
            requested_occurrence_id: Some(OccurrenceId::new(format!("{prefix}:occurrence"))?),
            idempotency_key: IdempotencyKey::new(format!("{prefix}:promote"))?,
        },
    )
    .await?;
    Ok((source_id, promoted))
}

fn proof_request(scope: &str) -> ContextRequest {
    ContextRequest {
        intent: "Exercise an adversarial freshness proof".into(),
        task_scope: scope.into(),
        risk_inputs: vec!["audience accuracy".into()],
    }
}

fn proof_dependency(id: &str, source_revision: RevisionRef) -> DependencyInput {
    DependencyInput {
        dependency_id: DependencyId::new(id).unwrap(),
        source_revision,
        semantic_role: "audience premise".into(),
        affected_conclusion: AffectedConclusion {
            key: "hero.audience".into(),
            description: "Audience named by the hero".into(),
        },
        rationale: "The output names the selected audience".into(),
        reconsideration_trigger: "The audience changes".into(),
        confidence: Some(0.9),
    }
}

fn one_dependency_policy() -> ResolutionPolicy {
    let mut policy = ResolutionPolicy::agent_speed_default();
    policy.dependency_budget = 1;
    policy
}

pub async fn concurrent_high_water_trace() -> Result<ConcurrentHighWaterTrace> {
    let database = native_ce::create_database(":memory:").await?;
    let (_source_id, promoted) = proof_unit(&database, "concurrency", 5).await?;
    let consumer_id = "f9e50000-0000-4000-8000-000000000303";
    let consumer_initial = proof_document(&database, consumer_id, "Initial.").await?;
    let initial_assembly = native_ce::freshness::assemble_context(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("slow homepage"),
        Some(consumer_id),
        vec![promoted.unit_id.as_str().into()],
    )
    .await?;
    let first = native_ce::freshness::commit_durable_output(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer_id.into(),
            expected_consumer_revision: consumer_initial,
            output_body: "Built for technical founders.".into(),
            provenance: vec![ProvenanceUse {
                source_revision: promoted.first_revision.clone(),
                reason: "Audience input".into(),
            }],
            dependencies: vec![proof_dependency(
                "concurrency:first-dependency",
                promoted.first_revision.clone(),
            )],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            policy: one_dependency_policy(),
            idempotency_key: IdempotencyKey::new("concurrency:first-output")?,
            assembly: initial_assembly,
        },
    )
    .await?;

    let gate = Arc::new(Barrier::new(2));
    let captured = Arc::new(Mutex::new(None));
    let writer_database = database.clone();
    let writer_gate = gate.clone();
    let writer_unit = promoted.unit_id.clone();
    let writer_u1 = promoted.first_revision.clone();
    let writer = tokio::spawn(async move {
        writer_gate.wait().await;
        let revised = native_ce::freshness::revise_unit(
            &writer_database,
            SqliteFreshnessHarness::principal(),
            ACTOR,
            ReviseUnitInput {
                unit_id: writer_unit,
                expected_current: writer_u1,
                content: UnitContent::text("Primary audience: nontechnical operators.")?,
                rationale: "Source changed while assembly was paused".into(),
                idempotency_key: IdempotencyKey::new("concurrency:revise-u2")?,
            },
        )
        .await;
        writer_gate.wait().await;
        revised
    });
    let pause_gate = gate.clone();
    let pause_capture = captured.clone();
    let selected = native_ce::freshness::assemble_context_with_pause(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("slow homepage"),
        Some(consumer_id),
        vec![promoted.unit_id.as_str().into()],
        move |high_water| {
            let pause_gate = pause_gate.clone();
            let pause_capture = pause_capture.clone();
            async move {
                *pause_capture.lock().await = Some(high_water);
                pause_gate.wait().await;
                pause_gate.wait().await;
                Ok(())
            }
        },
    )
    .await?;
    let revised = writer
        .await
        .map_err(|error| Error::engine(format!("concurrency writer failed: {error}")))??;
    let captured = captured
        .lock()
        .await
        .clone()
        .ok_or_else(|| Error::engine("concurrency high-water was not captured"))?;
    if captured.content_seq >= revised.new_revision.revision_seq
        || selected.sources != vec![promoted.first_revision.clone()]
        || !selected.comparisons.is_empty()
    {
        return Err(Error::engine(
            "concurrent assembly crossed its captured boundary",
        ));
    }

    let slow = native_ce::freshness::commit_durable_output(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer_id.into(),
            expected_consumer_revision: first.output_revision,
            output_body: "Slow output still based on technical founders.".into(),
            provenance: vec![ProvenanceUse {
                source_revision: promoted.first_revision.clone(),
                reason: "Selected before the concurrent revision".into(),
            }],
            dependencies: vec![proof_dependency(
                "concurrency:slow-dependency",
                promoted.first_revision.clone(),
            )],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            policy: one_dependency_policy(),
            idempotency_key: IdempotencyKey::new("concurrency:slow-output")?,
            assembly: selected.clone(),
        },
    )
    .await?;
    let immediate = native_ce::freshness::list_impact_candidates(
        &database,
        SqliteFreshnessHarness::principal(),
        consumer_id,
    )
    .await?;
    let control = native_ce::freshness::assemble_context(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("slow homepage"),
        Some(consumer_id),
        vec![promoted.unit_id.as_str().into()],
    )
    .await?;
    Ok(ConcurrentHighWaterTrace {
        captured,
        source_revision_committed_during_pause: revised.new_revision,
        selected_revisions: selected.sources,
        sealed_comparisons: selected.comparisons,
        receipt_revision_seq: slow.output_revision.revision_seq,
        immediate_impacts: immediate.candidates,
        control_selected_revisions: control.sources,
        control_comparisons: control.comparisons,
    })
}

pub async fn occupancy_differential() -> Result<OccupancyDifferential> {
    const BETA: &str = "acct:freshness-hidden-reader";
    let database = native_ce::create_database(":memory:").await?;
    let (source_id, promoted) = proof_unit(&database, "occupancy", 8).await?;
    for record_id in [source_id.as_str(), promoted.unit_id.as_str()] {
        replace_explicit_policy(
            &database,
            ACTOR,
            record_id,
            vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
        )
        .await?;
    }
    let beta = Principal::bound(BETA, true);
    let hidden_unit_error = native_ce::freshness::read_unit(&database, beta, &promoted.unit_id)
        .await
        .unwrap_err()
        .to_string();
    let absent_unit_error = native_ce::freshness::read_unit(
        &database,
        beta,
        &UnitId::new("f9e50000-0000-4000-8000-0000000004ff")?,
    )
    .await
    .unwrap_err()
    .to_string();
    let hidden_occurrence_error =
        native_ce::freshness::resolve_occurrence(&database, beta, &promoted.occurrence_id)
            .await
            .unwrap_err()
            .to_string();
    let absent_occurrence_error = native_ce::freshness::resolve_occurrence(
        &database,
        beta,
        &OccurrenceId::new("occupancy:absent-occurrence")?,
    )
    .await
    .unwrap_err()
    .to_string();
    Ok(OccupancyDifferential {
        hidden_unit_error,
        absent_unit_error,
        hidden_occurrence_error,
        absent_occurrence_error,
    })
}

async fn atomic_footprint(database: &Db, consumer_id: &str) -> Result<AtomicFootprint> {
    Ok(AtomicFootprint {
        content_events: sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(database.pool())
            .await?,
        receipts: sqlx::query_scalar("SELECT COUNT(*) FROM receipts")
            .fetch_one(database.pool())
            .await?,
        dependencies: sqlx::query_scalar("SELECT COUNT(*) FROM dependencies")
            .fetch_one(database.pool())
            .await?,
        assessments: sqlx::query_scalar("SELECT COUNT(*) FROM dependency_assessments")
            .fetch_one(database.pool())
            .await?,
        reconciliations: sqlx::query_scalar("SELECT COUNT(*) FROM reconciliations")
            .fetch_one(database.pool())
            .await?,
        provenance: sqlx::query_scalar("SELECT COUNT(*) FROM receipt_provenance")
            .fetch_one(database.pool())
            .await?,
        comparisons: sqlx::query_scalar("SELECT COUNT(*) FROM receipt_comparisons")
            .fetch_one(database.pool())
            .await?,
        uncertainty: sqlx::query_scalar("SELECT COUNT(*) FROM receipt_uncertainty_lineage")
            .fetch_one(database.pool())
            .await?,
        runtime_commands: sqlx::query_scalar(
            "SELECT COUNT(*) FROM freshness_runtime_command_results",
        )
        .fetch_one(database.pool())
        .await?,
        consumer_body: sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(consumer_id)
            .fetch_one(database.pool())
            .await?,
    })
}

async fn rich_atomic_input(database: &Db) -> Result<(String, CommitDurableOutputInput)> {
    let (_source_id, promoted) = proof_unit(database, "atomic", 1).await?;
    let consumer_id = "f9e50000-0000-4000-8000-000000000301".to_owned();
    let initial = proof_document(database, &consumer_id, "Initial atomic body.").await?;
    let first_assembly = native_ce::freshness::assemble_context(
        database,
        SqliteFreshnessHarness::principal(),
        proof_request("atomic package"),
        Some(&consumer_id),
        vec![promoted.unit_id.as_str().into()],
    )
    .await?;
    let first = native_ce::freshness::commit_durable_output(
        database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer_id.clone(),
            expected_consumer_revision: initial,
            output_body: "Initial output for technical founders.".into(),
            assembly: first_assembly,
            policy: one_dependency_policy(),
            provenance: vec![ProvenanceUse {
                source_revision: promoted.first_revision.clone(),
                reason: "Initial audience evidence".into(),
            }],
            dependencies: vec![proof_dependency(
                "atomic:dc1",
                promoted.first_revision.clone(),
            )],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new("atomic:first")?,
        },
    )
    .await?;
    let u2 = native_ce::freshness::revise_unit(
        database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision,
            content: UnitContent::text("Primary audience: nontechnical operators.")?,
            rationale: "Create a rich comparison package".into(),
            idempotency_key: IdempotencyKey::new("atomic:revise-u2")?,
        },
    )
    .await?;
    let assembly = native_ce::freshness::assemble_context(
        database,
        SqliteFreshnessHarness::principal(),
        proof_request("atomic package"),
        Some(&consumer_id),
        vec![promoted.unit_id.as_str().into()],
    )
    .await?;
    let comparison = assembly.comparisons[0].clone();
    let lineage = UncertaintyLineage {
        uncertainty_id: UncertaintyId::new("atomic:uncertainty")?,
        dependency_id: comparison.dependency_id.clone(),
        inherited_from_receipt_id: Some(comparison.receipt_id.clone()),
        consumer_revision: first.output_revision.clone(),
        pinned_source_revision: comparison.pinned_source_revision.clone(),
        selected_source_revision: u2.new_revision.clone(),
        affected_conclusion: proof_dependency("shape", u2.new_revision.clone()).affected_conclusion,
        assessment_task_scope: "atomic package".into(),
        verdict: MaterialityOutcome::MateriallyUncertain,
        evidence: "Exact change remains uncertain".into(),
        detail: "Exercise aggregate uncertainty projection".into(),
    };
    Ok((
        consumer_id.clone(),
        CommitDurableOutputInput {
            consumer_record_id: consumer_id,
            expected_consumer_revision: first.output_revision.clone(),
            output_body: "Atomic provisional output.".into(),
            provenance: vec![ProvenanceUse {
                source_revision: u2.new_revision.clone(),
                reason: "Current audience evidence".into(),
            }],
            dependencies: vec![proof_dependency("atomic:dc2", u2.new_revision.clone())],
            assessments: vec![AssessmentInput {
                assessment_id: AssessmentId::new("atomic:assessment")?,
                dependency_id: comparison.dependency_id.clone(),
                compared_source_revision: u2.new_revision.clone(),
                category: "positioning".into(),
                outcome: MaterialityOutcome::MateriallyUncertain,
                could_materially_change: true,
                rationale: "The change may alter the output".into(),
            }],
            reconciliations: vec![ReconciliationEvidence {
                reconciliation_id: ReconciliationId::new("atomic:reconciliation")?,
                dependency_id: comparison.dependency_id,
                consumer_revision: first.output_revision,
                pinned_source_revision: comparison.pinned_source_revision,
                assessed_source_revision: u2.new_revision,
                task_scope: "atomic package".into(),
                affected_conclusion: lineage.affected_conclusion.clone(),
                outcome: MaterialityOutcome::MateriallyUncertain,
                rationale: "Record the unresolved exact assessment".into(),
            }],
            unresolved_uncertainty: vec![lineage],
            policy: one_dependency_policy(),
            idempotency_key: IdempotencyKey::new("atomic:rich-package")?,
            assembly,
        },
    ))
}

fn fail_trigger(stage: &str) -> Option<&'static str> {
    match stage {
        "event_append" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON content_events
             WHEN NEW.type='receipt.committed.v1'
             BEGIN SELECT RAISE(ABORT,'proof event append failure'); END",
        ),
        "receipt_row" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON receipts
             BEGIN SELECT RAISE(ABORT,'proof receipt failure'); END",
        ),
        "dependency_row" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON dependencies
             BEGIN SELECT RAISE(ABORT,'proof dependency failure'); END",
        ),
        "assessment_row" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON dependency_assessments
             BEGIN SELECT RAISE(ABORT,'proof assessment failure'); END",
        ),
        "reconciliation_row" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON reconciliations
             WHEN NEW.reconciliation_id='atomic:reconciliation'
             BEGIN SELECT RAISE(ABORT,'proof reconciliation failure'); END",
        ),
        "provenance_row" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON receipt_provenance
             WHEN NEW.receipt_id NOT IN (SELECT receipt_id FROM dependency_audits)
             BEGIN SELECT RAISE(ABORT,'proof provenance failure'); END",
        ),
        "comparison_row" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON receipt_comparisons
             BEGIN SELECT RAISE(ABORT,'proof comparison failure'); END",
        ),
        "uncertainty_row" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON receipt_uncertainty_lineage
             BEGIN SELECT RAISE(ABORT,'proof uncertainty failure'); END",
        ),
        "command_result" => Some(
            "CREATE TRIGGER proof_fail BEFORE INSERT ON freshness_runtime_command_results
             WHEN NEW.idempotency_key='atomic:rich-package'
             BEGIN SELECT RAISE(ABORT,'proof command failure'); END",
        ),
        "output_body_projection" => Some(
            "CREATE TRIGGER proof_fail BEFORE UPDATE OF body ON records
             WHEN NEW.id='f9e50000-0000-4000-8000-000000000301' AND NEW.body='Atomic provisional output.'
             BEGIN SELECT RAISE(ABORT,'proof output failure'); END",
        ),
        "final_commit" => None,
        _ => None,
    }
}

pub async fn atomic_failure_matrix() -> Result<Vec<AtomicFailureEvidence>> {
    let stages = [
        "event_append",
        "receipt_row",
        "dependency_row",
        "assessment_row",
        "reconciliation_row",
        "provenance_row",
        "comparison_row",
        "uncertainty_row",
        "command_result",
        "output_body_projection",
        "final_commit",
    ];
    let mut evidence = Vec::new();
    for stage in stages {
        let database = native_ce::create_database(":memory:").await?;
        let (consumer_id, input) = rich_atomic_input(&database).await?;
        let fixture_pool = crate::common::fixture_write_pool(&database).await;
        let before = atomic_footprint(&database, &consumer_id).await?;
        if let Some(trigger) = fail_trigger(stage) {
            sqlx::query(trigger).execute(&fixture_pool).await?;
        }
        let failure = if stage == "final_commit" {
            Some(CommitFailurePoint::BeforeCommit)
        } else {
            None
        };
        let error = native_ce::freshness::commit_durable_output_with_failure(
            &database,
            SqliteFreshnessHarness::principal(),
            ACTOR,
            input.clone(),
            failure,
        )
        .await
        .unwrap_err()
        .to_string();
        let after_failure = atomic_footprint(&database, &consumer_id).await?;
        if after_failure != before {
            return Err(Error::engine(format!(
                "atomic footprint changed after {stage}: before={before:?} after={after_failure:?}"
            )));
        }
        if fail_trigger(stage).is_some() {
            sqlx::query("DROP TRIGGER proof_fail")
                .execute(&fixture_pool)
                .await?;
        }
        let committed = native_ce::freshness::commit_durable_output(
            &database,
            SqliteFreshnessHarness::principal(),
            ACTOR,
            input.clone(),
        )
        .await?;
        let identical_retry = native_ce::freshness::commit_durable_output(
            &database,
            SqliteFreshnessHarness::principal(),
            ACTOR,
            input.clone(),
        )
        .await?;
        let after_success = atomic_footprint(&database, &consumer_id).await?;
        let mut changed = input;
        changed.output_body = "Changed intent under the occupied key.".into();
        let changed_error = native_ce::freshness::commit_durable_output(
            &database,
            SqliteFreshnessHarness::principal(),
            ACTOR,
            changed,
        )
        .await
        .unwrap_err()
        .to_string();
        if !changed_error.contains("idempotency") {
            return Err(Error::engine(format!(
                "changed-intent retry did not conflict after {stage}: {changed_error}"
            )));
        }
        let after_changed_intent = atomic_footprint(&database, &consumer_id).await?;
        if after_changed_intent != after_success || identical_retry != committed {
            return Err(Error::engine(format!(
                "retry semantics changed after {stage}"
            )));
        }
        evidence.push(AtomicFailureEvidence {
            stage,
            error,
            before,
            after_failure,
            committed,
            identical_retry,
            after_changed_intent,
        });
    }
    Ok(evidence)
}

pub async fn authority_lifecycle_evidence() -> Result<AuthorityLifecycleEvidence> {
    let database = native_ce::create_database(":memory:").await?;
    let (source_id, promoted) = proof_unit(&database, "authority-life", 2).await?;
    let consumer_id = "f9e50000-0000-4000-8000-000000000302";
    let consumer_initial = proof_document(&database, consumer_id, "Initial.").await?;
    let assembly = native_ce::freshness::assemble_context(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("authority lifecycle"),
        Some(consumer_id),
        vec![promoted.unit_id.as_str().into()],
    )
    .await?;
    let receipt = native_ce::freshness::commit_durable_output(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer_id.into(),
            expected_consumer_revision: consumer_initial,
            output_body: "Output bound to a live authority bearer.".into(),
            provenance: vec![ProvenanceUse {
                source_revision: promoted.first_revision.clone(),
                reason: "Authority lifecycle premise".into(),
            }],
            dependencies: vec![proof_dependency(
                "authority-life:dependency",
                promoted.first_revision.clone(),
            )],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            policy: one_dependency_policy(),
            idempotency_key: IdempotencyKey::new("authority-life:receipt")?,
            assembly,
        },
    )
    .await?;
    archive_record(&database, &source_id).await?;
    let archived_unit_readable = native_ce::freshness::read_unit(
        &database,
        SqliteFreshnessHarness::principal(),
        &promoted.unit_id,
    )
    .await
    .is_ok();
    let archived_occurrence_state = native_ce::freshness::resolve_occurrence(
        &database,
        SqliteFreshnessHarness::principal(),
        &promoted.occurrence_id,
    )
    .await?
    .state;
    delete_record(&database, &source_id).await?;
    let deleted_unit_error = native_ce::freshness::read_unit(
        &database,
        SqliteFreshnessHarness::principal(),
        &promoted.unit_id,
    )
    .await
    .unwrap_err()
    .to_string();
    let deleted_occurrence_error = native_ce::freshness::resolve_occurrence(
        &database,
        SqliteFreshnessHarness::principal(),
        &promoted.occurrence_id,
    )
    .await
    .unwrap_err()
    .to_string();
    let explanation = native_ce::freshness::explain_freshness(
        &database,
        SqliteFreshnessHarness::principal(),
        receipt.receipt_id,
    )
    .await?;
    Ok(AuthorityLifecycleEvidence {
        archived_unit_readable,
        archived_occurrence_state,
        deleted_unit_error,
        deleted_occurrence_error,
        deleted_explanation_completeness: explanation.provenance_completeness,
        deleted_visible_dependency_count: explanation.visible_dependencies.len(),
    })
}

pub async fn missing_representation_evidence() -> Result<MissingRepresentationEvidence> {
    let database = native_ce::create_database(":memory:").await?;
    let (_source_id, promoted) = proof_unit(&database, "missing-bytes", 7).await?;
    let sibling_id = "f9e50000-0000-4000-8000-000000000306";
    let sibling_text = "A second expression of the technical-founder premise.";
    let sibling_revision = proof_document(&database, sibling_id, sibling_text).await?;
    let sibling = native_ce::freshness::bind_occurrence(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision.clone(),
            artefact_revision: sibling_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: sibling_text.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Paraphrase,
            requested_occurrence_id: Some(OccurrenceId::new("missing-bytes:sibling-occurrence")?),
            idempotency_key: IdempotencyKey::new("missing-bytes:bind-sibling")?,
        },
    )
    .await?;
    let occurrence = native_ce::freshness::list_occurrences(
        &database,
        SqliteFreshnessHarness::principal(),
        &promoted.unit_id,
    )
    .await?
    .into_iter()
    .find(|candidate| candidate.occurrence_id == promoted.occurrence_id)
    .ok_or_else(|| Error::engine("primary Occurrence disappeared"))?;
    let fixture_pool = crate::common::fixture_write_pool(&database).await;
    let expected_original_artefact_revision = occurrence.artefact_revision.clone();
    sqlx::query(
        "UPDATE content_events
            SET payload=json_set(payload,'$.body','historical representation unavailable')
          WHERE id=?",
    )
    .bind(&occurrence.artefact_revision.revision_event_id)
    .execute(&fixture_pool)
    .await?;
    let resolution = native_ce::freshness::resolve_occurrence(
        &database,
        SqliteFreshnessHarness::principal(),
        &promoted.occurrence_id,
    )
    .await?;
    let sibling_resolution = native_ce::freshness::resolve_occurrence(
        &database,
        SqliteFreshnessHarness::principal(),
        &sibling.occurrence.occurrence_id,
    )
    .await?;
    let unit_still_readable = native_ce::freshness::read_unit_revision(
        &database,
        SqliteFreshnessHarness::principal(),
        &promoted.first_revision,
    )
    .await
    .is_ok();
    Ok(MissingRepresentationEvidence {
        expected_original_artefact_revision,
        resolution,
        sibling_resolution,
        unit_still_readable,
    })
}

pub async fn full_freshness_replay_evidence() -> Result<Vec<ReplayTableEvidence>> {
    let harness = SqliteFreshnessHarness::new();
    let database = harness.fresh_database().await?;
    let evidence = scenarios::twelve_step(&harness, &database).await?;
    let (_successor_source, successor) = proof_unit(&database, "replay-successor", 9).await?;
    native_ce::freshness::supersede_unit(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        SupersedeUnitInput {
            predecessor_unit_id: evidence.unit_id,
            successors: vec![successor.first_revision],
            rationale: "Populate the replay supersession projection".into(),
            idempotency_key: IdempotencyKey::new("replay:supersede")?,
        },
    )
    .await?;
    let fixture_pool = crate::common::fixture_write_pool(&database).await;
    sqlx::query("DELETE FROM read_log_calls")
        .execute(&fixture_pool)
        .await?;
    let diff = rebuild_and_diff(&database).await?;
    let freshness_tables = [
        "semantic_units",
        "unit_revisions",
        "unit_heads",
        "occurrences",
        "freshness_command_results",
        "freshness_runtime_command_results",
        "dependencies",
        "dependency_assessments",
        "receipts",
        "receipt_provenance",
        "receipt_comparisons",
        "receipt_uncertainty_lineage",
        "reconciliations",
        "unit_supersessions",
        "dependency_audits",
    ];
    let tables = diff
        .tables
        .into_iter()
        .filter(|table| freshness_tables.contains(&table.table.as_str()))
        .map(|table| ReplayTableEvidence {
            table: table.table,
            live: table.live,
            rebuilt: table.rebuilt,
            mismatches: table.mismatches,
        })
        .collect::<Vec<_>>();
    if !diff.equal
        || tables.len() != freshness_tables.len()
        || tables.iter().any(|table| {
            table.live == 0 || table.live != table.rebuilt || !table.mismatches.is_empty()
        })
    {
        return Err(Error::engine(format!(
            "freshness replay proof failed: {tables:?}"
        )));
    }
    Ok(tables)
}

pub async fn revocation_between_assembly_and_commit() -> Result<RevocationEvidence> {
    let database = native_ce::create_database(":memory:").await?;
    let (source_id, promoted) = proof_unit(&database, "revocation", 10).await?;
    let consumer_id = "f9e50000-0000-4000-8000-000000000307";
    let consumer_initial = proof_document(&database, consumer_id, "Initial.").await?;
    let assembly = native_ce::freshness::assemble_context(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("revocation proof"),
        Some(consumer_id),
        vec![promoted.unit_id.as_str().into()],
    )
    .await?;
    let input = CommitDurableOutputInput {
        consumer_record_id: consumer_id.into(),
        expected_consumer_revision: consumer_initial,
        output_body: "Output requiring current source authorization.".into(),
        provenance: vec![ProvenanceUse {
            source_revision: promoted.first_revision.clone(),
            reason: "Authorized at assembly".into(),
        }],
        dependencies: vec![proof_dependency(
            "revocation:dependency",
            promoted.first_revision,
        )],
        assessments: vec![],
        reconciliations: vec![],
        unresolved_uncertainty: vec![],
        policy: one_dependency_policy(),
        idempotency_key: IdempotencyKey::new("revocation:commit")?,
        assembly,
    };
    replace_explicit_policy(
        &database,
        ACTOR,
        &source_id,
        vec![AllowEntry::account("acct:not-alpha", Capability::Manage)],
    )
    .await?;
    let content_events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(database.pool())
        .await?;
    let rejected_error = native_ce::freshness::commit_durable_output(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        input.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    let content_events_after_rejection: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(database.pool())
            .await?;
    let occupied_keys_after_rejection: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM freshness_runtime_command_results
          WHERE idempotency_key='revocation:commit'",
    )
    .fetch_one(database.pool())
    .await?;
    replace_explicit_policy(
        &database,
        ACTOR,
        &source_id,
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await?;
    let mut restored_input = input;
    restored_input.assembly = native_ce::freshness::assemble_context(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("revocation proof"),
        Some(consumer_id),
        vec![promoted.unit_id.as_str().into()],
    )
    .await?;
    let restored = native_ce::freshness::commit_durable_output(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        restored_input,
    )
    .await?;
    Ok(RevocationEvidence {
        rejected_error,
        content_events_before,
        content_events_after_rejection,
        occupied_keys_after_rejection,
        restored_receipt: restored.receipt_id,
    })
}

pub async fn secondary_occurrence_without_authority() -> Result<SecondaryOccurrenceAccessEvidence> {
    const BETA: &str = "acct:secondary-occurrence";
    let database = native_ce::create_database(":memory:").await?;
    let (source_id, promoted) = proof_unit(&database, "secondary-access", 11).await?;
    let secondary_id = "f9e50000-0000-4000-8000-000000000308";
    let secondary_text = "Technical founders are the initial audience.";
    let secondary_revision = proof_document(&database, secondary_id, secondary_text).await?;
    let bound = native_ce::freshness::bind_occurrence(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision,
            artefact_revision: secondary_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: secondary_text.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            expression_role: ExpressionRole::Paraphrase,
            requested_occurrence_id: Some(OccurrenceId::new("secondary-access:occurrence-b")?),
            idempotency_key: IdempotencyKey::new("secondary-access:bind")?,
        },
    )
    .await?;
    replace_explicit_policy(
        &database,
        ACTOR,
        &source_id,
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await?;
    replace_explicit_policy(
        &database,
        ACTOR,
        promoted.unit_id.as_str(),
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(BETA, Capability::Edit),
        ],
    )
    .await?;
    replace_explicit_policy(
        &database,
        ACTOR,
        secondary_id,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(BETA, Capability::Edit),
        ],
    )
    .await?;
    let beta = Principal::bound(BETA, true);
    let secondary_artefact_accessible =
        native_ce::authorization::effective_capability(&database, beta, secondary_id)
            .await?
            .allows(Capability::View);
    let unit_error = native_ce::freshness::read_unit(&database, beta, &promoted.unit_id)
        .await
        .unwrap_err()
        .to_string();
    let occurrence_error =
        native_ce::freshness::resolve_occurrence(&database, beta, &bound.occurrence.occurrence_id)
            .await
            .unwrap_err()
            .to_string();
    let secondary_history_occurrence_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE record_id=? AND type='occurrence.bound.v1'",
    )
    .bind(secondary_id)
    .fetch_one(database.pool())
    .await?;
    Ok(SecondaryOccurrenceAccessEvidence {
        secondary_artefact_accessible,
        unit_error,
        occurrence_error,
        secondary_history_occurrence_events,
    })
}

pub async fn plural_supersession_evidence() -> Result<SupersessionEvidence> {
    const BETA: &str = "acct:supersession-filter";
    let database = native_ce::create_database(":memory:").await?;
    let (predecessor_source, predecessor) =
        proof_unit(&database, "supersession-predecessor", 14).await?;
    let (successor_a_source, successor_a) = proof_unit(&database, "supersession-a", 12).await?;
    let (successor_b_source, successor_b) = proof_unit(&database, "supersession-b", 13).await?;
    let consumer_id = "f9e50000-0000-4000-8000-000000000309";
    let initial = proof_document(&database, consumer_id, "Initial.").await?;
    let assembly = native_ce::freshness::assemble_context(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("supersession history"),
        Some(consumer_id),
        vec![predecessor.unit_id.as_str().into()],
    )
    .await?;
    let receipt = native_ce::freshness::commit_durable_output(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer_id.into(),
            expected_consumer_revision: initial,
            output_body: "Historical output using the predecessor.".into(),
            provenance: vec![ProvenanceUse {
                source_revision: predecessor.first_revision.clone(),
                reason: "Historical predecessor".into(),
            }],
            dependencies: vec![proof_dependency(
                "supersession:historical-dependency",
                predecessor.first_revision.clone(),
            )],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            policy: one_dependency_policy(),
            idempotency_key: IdempotencyKey::new("supersession:historical-receipt")?,
            assembly,
        },
    )
    .await?;
    native_ce::freshness::supersede_unit(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        SupersedeUnitInput {
            predecessor_unit_id: predecessor.unit_id.clone(),
            successors: vec![successor_a.first_revision.clone()],
            rationale: "First successor".into(),
            idempotency_key: IdempotencyKey::new("supersession:first")?,
        },
    )
    .await?;
    let single = native_ce::freshness::resolve_current_units(
        &database,
        SqliteFreshnessHarness::principal(),
        predecessor.unit_id.clone(),
        current_history_high_water(&database).await?,
    )
    .await?;
    native_ce::freshness::supersede_unit(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        SupersedeUnitInput {
            predecessor_unit_id: predecessor.unit_id.clone(),
            successors: vec![successor_b.first_revision.clone()],
            rationale: "Second sibling successor".into(),
            idempotency_key: IdempotencyKey::new("supersession:second")?,
        },
    )
    .await?;
    let plural = native_ce::freshness::resolve_current_units(
        &database,
        SqliteFreshnessHarness::principal(),
        predecessor.unit_id.clone(),
        current_history_high_water(&database).await?,
    )
    .await?;
    for (record_id, capability) in [
        (predecessor_source.as_str(), Capability::View),
        (predecessor.unit_id.as_str(), Capability::View),
        (successor_a_source.as_str(), Capability::View),
        (successor_a.unit_id.as_str(), Capability::View),
    ] {
        replace_explicit_policy(
            &database,
            ACTOR,
            record_id,
            vec![
                AllowEntry::account(ACCOUNT, Capability::Manage),
                AllowEntry::account(BETA, capability),
            ],
        )
        .await?;
    }
    for record_id in [successor_b_source.as_str(), successor_b.unit_id.as_str()] {
        replace_explicit_policy(
            &database,
            ACTOR,
            record_id,
            vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
        )
        .await?;
    }
    let filtered = native_ce::freshness::resolve_current_units(
        &database,
        Principal::bound(BETA, true),
        predecessor.unit_id,
        current_history_high_water(&database).await?,
    )
    .await?;
    let historical_dependency = native_ce::freshness::explain_freshness(
        &database,
        SqliteFreshnessHarness::principal(),
        receipt.receipt_id,
    )
    .await?
    .visible_dependencies[0]
        .source_revision
        .clone();
    Ok(SupersessionEvidence {
        single_terminal: single.terminal_successors,
        plural_terminals: plural.terminal_successors,
        plural_ambiguous: plural.ambiguous,
        filtered_terminals: filtered.terminal_successors,
        filtered_ambiguous: filtered.ambiguous,
        filtered_withheld: filtered.withheld_context,
        historical_dependency,
    })
}

pub async fn authorization_leakage_matrix() -> Result<AuthorizationLeakageEvidence> {
    const BETA: &str = "acct:leakage-matrix";
    let database = native_ce::create_database(":memory:").await?;
    let (source_one, unit_one) = proof_unit(&database, "classified-one", 3).await?;
    let (source_two, unit_two) = proof_unit(&database, "classified-two", 4).await?;
    let one_consumer = "f9e50000-0000-4000-8000-000000000304";
    let two_consumer = "f9e50000-0000-4000-8000-000000000305";
    let one_initial = proof_document(&database, one_consumer, "Visible one-source output.").await?;
    let two_initial = proof_document(&database, two_consumer, "Visible two-source output.").await?;

    let one_assembly = native_ce::freshness::assemble_context(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("redacted comparison"),
        Some(one_consumer),
        vec![unit_one.unit_id.as_str().into()],
    )
    .await?;
    let two_assembly = native_ce::freshness::assemble_context(
        &database,
        SqliteFreshnessHarness::principal(),
        proof_request("redacted comparison"),
        Some(two_consumer),
        vec![
            unit_one.unit_id.as_str().into(),
            unit_two.unit_id.as_str().into(),
        ],
    )
    .await?;
    assert_eq!(one_assembly.request, two_assembly.request);
    assert_eq!(one_assembly.high_water, two_assembly.high_water);
    let mut shared_policy = ResolutionPolicy::agent_speed_default();
    shared_policy.dependency_budget = 2;
    let mut one_dependency =
        proof_dependency("leakage:one-dependency", unit_one.first_revision.clone());
    one_dependency.rationale = "classified-one rationale".into();
    let one_receipt = native_ce::freshness::commit_durable_output(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: one_consumer.into(),
            expected_consumer_revision: one_initial,
            output_body: "Visible output with redacted provenance.".into(),
            provenance: vec![ProvenanceUse {
                source_revision: unit_one.first_revision.clone(),
                reason: "classified-one provenance".into(),
            }],
            dependencies: vec![one_dependency],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            policy: shared_policy.clone(),
            idempotency_key: IdempotencyKey::new("leakage:one-receipt")?,
            assembly: one_assembly,
        },
    )
    .await?;

    let mut two_dependency_one =
        proof_dependency("leakage:two-dependency-a", unit_one.first_revision.clone());
    two_dependency_one.rationale = "classified-one rationale".into();
    let mut two_dependency_two =
        proof_dependency("leakage:two-dependency-b", unit_two.first_revision.clone());
    two_dependency_two.rationale = "classified-two rationale with different grouping".into();
    let two_receipt = native_ce::freshness::commit_durable_output(
        &database,
        SqliteFreshnessHarness::principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: two_consumer.into(),
            expected_consumer_revision: two_initial,
            output_body: "Visible output with redacted provenance.".into(),
            provenance: vec![
                ProvenanceUse {
                    source_revision: unit_one.first_revision.clone(),
                    reason: "classified-one provenance".into(),
                },
                ProvenanceUse {
                    source_revision: unit_two.first_revision.clone(),
                    reason: "classified-two provenance".into(),
                },
            ],
            dependencies: vec![two_dependency_one, two_dependency_two],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            policy: shared_policy,
            idempotency_key: IdempotencyKey::new("leakage:two-receipt")?,
            assembly: two_assembly,
        },
    )
    .await?;

    for consumer in [one_consumer, two_consumer] {
        replace_explicit_policy(
            &database,
            ACTOR,
            consumer,
            vec![
                AllowEntry::account(ACCOUNT, Capability::Manage),
                AllowEntry::account(BETA, Capability::View),
            ],
        )
        .await?;
    }
    for hidden in [
        source_one.as_str(),
        unit_one.unit_id.as_str(),
        source_two.as_str(),
        unit_two.unit_id.as_str(),
    ] {
        replace_explicit_policy(
            &database,
            ACTOR,
            hidden,
            vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
        )
        .await?;
    }
    let beta = Principal::bound(BETA, true);
    let one =
        native_ce::freshness::explain_freshness(&database, beta, one_receipt.receipt_id).await?;
    let two =
        native_ce::freshness::explain_freshness(&database, beta, two_receipt.receipt_id).await?;
    let redacted_shape = |explanation: &FreshnessExplanation| -> Result<String> {
        let mut value = serde_json::to_value(explanation)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| Error::engine("freshness explanation must serialize as an object"))?;
        // These are authorized consumer/output identities and differ because
        // the matrix uses two distinct consumer records. Every other field,
        // including request, policy, high-water, decisions, and every visible
        // evidence collection, must be byte-for-byte shape-equivalent.
        object.insert("receipt_id".into(), json!("<consumer-receipt-id>"));
        object.insert(
            "output_revision".into(),
            json!("<consumer-output-revision>"),
        );
        Ok(serde_json::to_string(&value)?)
    };
    let one_hidden_shape = redacted_shape(&one)?;
    let two_hidden_shape = redacted_shape(&two)?;
    let encoded = format!(
        "{} {}",
        serde_json::to_string(&one)?,
        serde_json::to_string(&two)?
    );
    let secret_strings_absent = [
        "classified-one",
        "classified-two",
        "different grouping",
        "technical founders",
    ]
    .iter()
    .all(|secret| !encoded.contains(secret));
    let impacts =
        native_ce::freshness::list_impact_candidates(&database, beta, two_consumer).await?;
    Ok(AuthorizationLeakageEvidence {
        one_hidden_shape,
        two_hidden_shape,
        secret_strings_absent,
        impact_candidates_visible: impacts.candidates.len(),
        impact_withheld: impacts.withheld_context,
    })
}

pub async fn generic_unit_body_mutation_error() -> Result<String> {
    let database = native_ce::create_database(":memory:").await?;
    let (_source, promoted) = proof_unit(&database, "generic-unit-mutation", 6).await?;
    Ok(update_record(
        &database,
        promoted.unit_id.as_str(),
        json!({"body":"This must not become authoritative Unit content."}),
    )
    .await
    .unwrap_err()
    .to_string())
}
