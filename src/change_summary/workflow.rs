//! First-party change-summary composition over generic derivation primitives.

use std::collections::HashMap;
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::{AllowEntry, Capability, Principal};
use crate::db::{begin_write, Db};
use crate::derivation::{
    self, AcquireRequestResult, ArtifactRoleAssigned, CanonicalDerivationRequest,
    CompleteDerivationRequest, CreateOrGetDerivationSeries, CreateOrJoinRequest,
    CurrentRevisionBasisResolver, DerivationApplicabilityBasis, DerivationAudiencePolicy,
    DerivationAudiencePrincipal, DerivationExecutionUsage, DerivationExecutorDescriptor,
    DerivationInput, DerivationOutputRef, DerivationRequestSnapshot, DerivationRequestSpec,
    DerivationRevisionCompleted, DerivationTarget, DerivationTargetBound, EffectiveSourceBoundary,
    OutputContractSelector, PublishRecordBodyRevision, RecipeRevisionRef,
    RequestRevisionApplicabilityGate, RevisionApplicabilityGate, RevisionConfirmed,
    RevisionRecognitionBasis, CHANGE_SUMMARY_ROLE,
};
use crate::error::{Error, Result};
use crate::store::{AppendSpec, EventAnnotations};

use super::{
    canonicalize_and_validate_change_summary, change_summary_recipe_definition,
    render_change_summary_output, ChangeSummaryContextRecord, ChangeSummaryInputManifest,
    ChangeSummaryManifestInput, ChangeSummaryQuery, ChangeSummaryResolver,
    ChangeSummarySourceEvent, CHANGE_SUMMARY_OUTPUT_CONTRACT_ID,
    CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION, CHANGE_SUMMARY_QUERY_CONTRACT_ID,
    CHANGE_SUMMARY_QUERY_CONTRACT_VERSION, CHANGE_SUMMARY_RECIPE_PROGRAM_ID,
};

const WORKFLOW_SCHEMA: &str = "native.change-summary.workflow.v1";
const SERIES_SCHEMA: &str = "native.change-summary.series.v1";
const DEFAULT_LEASE_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryRecipePin {
    pub publication_id: String,
    pub descriptor_sha256: String,
    pub expected_status_event_seq: i64,
}

impl ChangeSummaryRecipePin {
    fn revision(&self) -> RecipeRevisionRef {
        RecipeRevisionRef {
            definition_id: CHANGE_SUMMARY_RECIPE_PROGRAM_ID.into(),
            publication_id: self.publication_id.clone(),
            sha256: self.descriptor_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChangeSummaryCreateRequest {
    pub workflow_key: String,
    pub name: String,
    pub recipe: ChangeSummaryRecipePin,
    pub actor: String,
    pub run_key: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ChangeSummaryRequest {
    pub workflow_key: String,
    pub source_event_ids: Vec<String>,
    pub context_record_ids: Vec<String>,
    pub structured_result: Value,
    pub expected_recipe_status_event_seq: i64,
    pub actor: String,
    pub run_key: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeSummaryCandidate {
    pub request: DerivationRequestSnapshot,
    pub carrier_id: String,
    pub series_id: String,
    pub revision_id: Option<String>,
    pub created_request: bool,
    pub executed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSummaryConfirmation {
    pub workflow_key: String,
    pub carrier_id: String,
    pub assignment_id: String,
    pub confirmation_id: String,
    pub revision_id: String,
    pub event_id: String,
    pub event_seq: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeSummaryWorkflowInspection {
    pub schema: String,
    pub workflow_key: String,
    pub carrier_id: String,
    pub series_id: String,
    pub binding_id: String,
    pub assignment_id: String,
    pub selected_revision_id: Option<String>,
    pub selected_publication_id: Option<String>,
    pub confirmed_revision_id: Option<String>,
    pub confirmation_id: Option<String>,
    pub confirmed_body: Option<String>,
    pub request: Option<DerivationRequestSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangeSummaryQueryPage {
    pub items: Vec<derivation::ConfirmedArtifactInspection>,
    pub next_cursor: Option<derivation::ConfirmedArtifactCursor>,
}

#[derive(Debug, Clone)]
struct WorkflowIds {
    namespace_digest: String,
    carrier: String,
    series: String,
    binding: String,
    assignment: String,
}

fn nonblank(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::engine(format!(
            "change-summary {label} cannot be empty"
        )))
    } else {
        Ok(())
    }
}

fn stable_digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn ids(workflow_key: &str, audience_actor: &str) -> Result<WorkflowIds> {
    nonblank("workflow key", workflow_key)?;
    nonblank("audience actor", audience_actor)?;
    let digest = stable_digest(&format!("{audience_actor}\0{workflow_key}"));
    Ok(WorkflowIds {
        namespace_digest: digest.clone(),
        carrier: format!("change-summary:carrier:{digest}"),
        series: format!("change-summary:series:{digest}"),
        binding: format!("change-summary:binding:{digest}"),
        assignment: format!("change-summary:role:{digest}"),
    })
}

fn audience(
    actor: &str,
    is_member: bool,
    policy_anchor_id: &str,
) -> Result<(DerivationAudiencePolicy, String)> {
    let policy = DerivationAudiencePolicy {
        schema: derivation::DERIVATION_AUDIENCE_SCHEMA.into(),
        policy_anchor_id: policy_anchor_id.into(),
        principals: vec![DerivationAudiencePrincipal {
            account_id: actor.into(),
            is_member,
        }],
    };
    let digest = derivation::audience_policy_sha256(&policy)?;
    Ok((policy, digest))
}

async fn require_exact_workflow_audience(
    tx: &mut Transaction<'_, Sqlite>,
    ids: &WorkflowIds,
    workflow_key: &str,
    actor: &str,
    is_member: bool,
) -> Result<()> {
    let policy_is_exact: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records
            WHERE id=? AND type='Document' AND kind='note' AND deleted_at IS NULL
              AND policy_anchor_id=?)
           AND (SELECT COUNT(*) FROM policy_entries WHERE policy_anchor_id=?)=1
           AND EXISTS(SELECT 1 FROM policy_entries WHERE policy_anchor_id=?
             AND subject_kind='account' AND subject_id=?
             AND effect='allow' AND capability='manage')",
    )
    .bind(&ids.carrier)
    .bind(&ids.carrier)
    .bind(&ids.carrier)
    .bind(&ids.carrier)
    .bind(actor)
    .fetch_one(&mut **tx)
    .await?;
    if !policy_is_exact {
        return Err(Error::engine("change-summary workflow is unavailable"));
    }
    let definition: Option<String> =
        sqlx::query_scalar("SELECT definition FROM derivation_series WHERE id=?")
            .bind(&ids.series)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(definition) = definition else {
        return Err(Error::engine("change-summary workflow is unavailable"));
    };
    let definition: Value = serde_json::from_str(&definition)?;
    let recipe_revision: RecipeRevisionRef = serde_json::from_value(
        definition
            .get("recipe_revision")
            .cloned()
            .ok_or_else(|| Error::engine("change-summary workflow is unavailable"))?,
    )?;
    let (_, audience_sha256) = audience(actor, is_member, &ids.carrier)?;
    if definition != series_definition(workflow_key, &recipe_revision, &audience_sha256) {
        return Err(Error::engine("change-summary workflow is unavailable"));
    }
    Ok(())
}

async fn revision_recognition_basis_in(
    tx: &mut Transaction<'static, Sqlite>,
    revision_id: &str,
) -> Result<Option<RevisionRecognitionBasis>> {
    let row = sqlx::query(
        "SELECT series_id,id AS revision_id,definition_sha256,canonical_request,
                recipe_revision,effective_source_boundary,completion_metadata
           FROM derivation_revisions WHERE id=?",
    )
    .bind(revision_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok(RevisionRecognitionBasis {
            series_id: row.try_get("series_id")?,
            revision_id: row.try_get("revision_id")?,
            definition_sha256: row.try_get("definition_sha256")?,
            canonical_request: serde_json::from_str(
                &row.try_get::<String, _>("canonical_request")?,
            )?,
            recipe_revision: serde_json::from_str(&row.try_get::<String, _>("recipe_revision")?)?,
            effective_source_boundary: serde_json::from_str(
                &row.try_get::<String, _>("effective_source_boundary")?,
            )?,
            completion_metadata: serde_json::from_str(
                &row.try_get::<String, _>("completion_metadata")?,
            )?,
        })
    })
    .transpose()
}

async fn revision_is_current_for_principal(
    tx: &mut Transaction<'static, Sqlite>,
    principal: Principal<'_>,
    revision_id: &str,
) -> Result<bool> {
    let Some(basis) = revision_recognition_basis_in(tx, revision_id).await? else {
        return Ok(false);
    };
    let account = principal.account_id.map(str::to_owned);
    let is_member = principal.is_member;
    let membership = move |candidate: &str| {
        account
            .as_deref()
            .filter(|id| *id == candidate)
            .map(|_| is_member)
    };
    RequestRevisionApplicabilityGate::new(membership, ChangeSummaryCurrentBasis)
        .is_current_and_audience_available(tx, &basis)
        .await
}

fn budget() -> Value {
    json!({
        "max_input_bytes": 262144,
        "max_input_items": 19,
        "max_input_tokens": 32768,
        "max_output_bytes": 32768,
        "max_output_tokens": 4096
    })
}

fn series_definition(
    workflow_key: &str,
    recipe_revision: &RecipeRevisionRef,
    audience_sha256: &str,
) -> Value {
    json!({
        "schema": SERIES_SCHEMA,
        "workflow_key": workflow_key,
        "recipe_revision": recipe_revision,
        "audience_sha256": audience_sha256,
        "budget": budget(),
        "output_contract": {
            "id": CHANGE_SUMMARY_OUTPUT_CONTRACT_ID,
            "version": CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION
        }
    })
}

async fn require_exact_recipe(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    pin: &ChangeSummaryRecipePin,
    new_series: bool,
) -> Result<crate::recipe::RecipeReleaseInspection> {
    let release = if new_series {
        crate::recipe::require_recipe_release_for_new_series_on(
            tx,
            principal,
            CHANGE_SUMMARY_RECIPE_PROGRAM_ID,
            &pin.publication_id,
            pin.expected_status_event_seq,
        )
        .await?
    } else {
        crate::recipe::require_recipe_release_for_execution_on(
            tx,
            principal,
            CHANGE_SUMMARY_RECIPE_PROGRAM_ID,
            &pin.publication_id,
            pin.expected_status_event_seq,
        )
        .await?
    };
    if release.descriptor.program_id != CHANGE_SUMMARY_RECIPE_PROGRAM_ID
        || release.descriptor.runtime != crate::recipe::RECIPE_RUNTIME
        || release.descriptor_sha256 != pin.descriptor_sha256
        || release.descriptor.definition != change_summary_recipe_definition()?
    {
        return Err(Error::engine(
            "change-summary recipe pin does not name the exact packaged Program release",
        ));
    }
    Ok(release)
}

pub async fn create_or_reuse_change_summary(
    db: &Db,
    principal: Principal<'_>,
    request: ChangeSummaryCreateRequest,
) -> Result<ChangeSummaryWorkflowInspection> {
    let ids = ids(&request.workflow_key, &request.actor)?;
    nonblank("name", &request.name)?;
    nonblank("reason", &request.reason)?;
    if principal.account_id != Some(request.actor.as_str()) {
        return Err(Error::engine(
            "change-summary actor must match the authorized account principal",
        ));
    }
    let (_, audience_sha256) = audience(&request.actor, principal.is_member, &ids.carrier)?;
    let recipe_revision = request.recipe.revision();
    let definition = series_definition(&request.workflow_key, &recipe_revision, &audience_sha256);
    let mut tx = begin_write(db.write_pool()).await?;
    let carrier: Option<(String, String, Option<String>)> =
        sqlx::query_as("SELECT type,kind,deleted_at FROM records WHERE id=?")
            .bind(&ids.carrier)
            .fetch_optional(&mut *tx)
            .await?;
    let created_carrier = carrier.is_none();
    if let Some((record_type, kind, deleted_at)) = carrier {
        if record_type != "Document" || kind != "note" || deleted_at.is_some() {
            return Err(Error::engine(
                "change-summary carrier identity is occupied by a different record",
            ));
        }
        crate::authorization::require_capability_on(
            &mut tx,
            principal,
            &ids.carrier,
            Capability::Manage,
        )
        .await?;
    } else {
        crate::authorization::require_capability_on(
            &mut tx,
            principal,
            crate::schema::UNFILED_RECORD_ID,
            Capability::Edit,
        )
        .await?;
        let owner_id: Option<String> = sqlx::query_scalar(
            "SELECT record_id FROM bindings WHERE system='account' AND identifier=?
              AND is_canonical=1 ORDER BY record_id LIMIT 1",
        )
        .bind(&request.actor)
        .fetch_optional(&mut *tx)
        .await?;
        let mut payload = json!({
            "type":"Document",
            "kind":"note",
            "name":request.name,
            "home_id":crate::schema::UNFILED_RECORD_ID,
            "reason":request.reason
        });
        if let Some(owner_id) = owner_id {
            payload["owner_id"] = Value::String(owner_id);
        }
        crate::store::with_event_annotations(
            EventAnnotations {
                run_key: request.run_key.clone(),
                parent_key: None,
                intent: Some("create change-summary carrier".into()),
            },
            // The carrier id is the workflow's reuse key, so it is a derived
            // digest rather than a UUID; this seam carries the temporary,
            // narrowly-scoped exemption that admits exactly that one shape.
            crate::store::append_engine_derived_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: ids.carrier.clone(),
                    event_type: "record.created".into(),
                    payload,
                    actor: Some(request.actor.clone()),
                },
            ),
        )
        .await?;
        crate::authorization::replace_explicit_policy_on_with_reason(
            &mut tx,
            &request.actor,
            &ids.carrier,
            vec![AllowEntry::account(
                request.actor.clone(),
                Capability::Manage,
            )],
            &request.reason,
        )
        .await?;
    }
    let policy_is_exact: bool = sqlx::query_scalar(
        "SELECT records.policy_anchor_id=?
            AND (SELECT COUNT(*) FROM policy_entries WHERE policy_anchor_id=?)=1
            AND EXISTS(SELECT 1 FROM policy_entries WHERE policy_anchor_id=?
                 AND subject_kind='account' AND subject_id=? AND capability='manage')
           FROM records WHERE id=?",
    )
    .bind(&ids.carrier)
    .bind(&ids.carrier)
    .bind(&ids.carrier)
    .bind(&request.actor)
    .bind(&ids.carrier)
    .fetch_one(&mut *tx)
    .await?;
    if !policy_is_exact {
        return Err(Error::engine(
            "change-summary carrier does not have the exact private workflow audience",
        ));
    }
    let series_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM derivation_series WHERE id=? OR series_key=?)",
    )
    .bind(&ids.series)
    .bind(&ids.series)
    .fetch_one(&mut *tx)
    .await?;
    require_exact_recipe(&mut tx, principal, &request.recipe, !series_exists).await?;
    derivation::create_or_get_series_for_recipe_in(
        &mut tx,
        principal,
        &CreateOrGetDerivationSeries {
            id: ids.series.clone(),
            series_key: ids.series.clone(),
            definition,
            recipe_revision,
            expected_recipe_status_event_seq: request.recipe.expected_status_event_seq,
            idempotency_key: format!("change-summary:{}:series", ids.namespace_digest),
            actor: request.actor.clone(),
            run_key: request.run_key.clone(),
            reason: request.reason.clone(),
        },
    )
    .await?;
    let target = DerivationTarget::record_body(&ids.carrier);
    let binding: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT active_binding_id,generation,target_version FROM derivation_target_heads
          WHERE target_kind='record' AND target_record_id=? AND target_slot='body'",
    )
    .bind(&ids.carrier)
    .fetch_optional(&mut *tx)
    .await?
    .and_then(
        |(active, generation, version): (Option<String>, i64, i64)| {
            active.map(|id| (id, generation, version))
        },
    );
    if let Some((binding_id, _, _)) = binding {
        if binding_id != ids.binding {
            return Err(Error::engine(
                "change-summary carrier body is owned by a different derivation",
            ));
        }
    } else {
        crate::authorization::require_capability_on(
            &mut tx,
            principal,
            &ids.carrier,
            Capability::Edit,
        )
        .await?;
        derivation::append_derivation_event_in(
            &mut tx,
            derivation::NewDerivationEvent::authored(
                format!("change-summary:{}:bind", ids.namespace_digest),
                request.actor.clone(),
                request.run_key.clone(),
                request.reason.clone(),
                derivation::DerivationEventPayload::TargetBound(DerivationTargetBound {
                    binding_id: ids.binding.clone(),
                    series_id: ids.series.clone(),
                    target: target.clone(),
                    expected_target_version: 0,
                    generation: 1,
                    expected_body_event_id: None,
                    expected_body_sha256: None,
                }),
            )?,
        )
        .await?;
    }
    let role: Option<String> = sqlx::query_scalar(
        "SELECT active_assignment_id FROM derivation_artifact_role_heads
          WHERE target_kind='record' AND target_record_id=? AND target_slot='body' AND role=?",
    )
    .bind(&ids.carrier)
    .bind(CHANGE_SUMMARY_ROLE)
    .fetch_optional(&mut *tx)
    .await?
    .flatten();
    if let Some(assignment_id) = role {
        if assignment_id != ids.assignment {
            return Err(Error::engine(
                "change-summary carrier role is assigned to a different workflow",
            ));
        }
    } else {
        crate::authorization::require_capability_on(
            &mut tx,
            principal,
            &ids.carrier,
            Capability::Manage,
        )
        .await?;
        derivation::append_derivation_event_in(
            &mut tx,
            derivation::NewDerivationEvent::authored(
                format!("change-summary:{}:role", ids.namespace_digest),
                request.actor.clone(),
                request.run_key.clone(),
                request.reason.clone(),
                derivation::DerivationEventPayload::ArtifactRoleAssigned(ArtifactRoleAssigned {
                    assignment_id: ids.assignment.clone(),
                    target,
                    role: CHANGE_SUMMARY_ROLE.into(),
                    expected_role_head_event_id: None,
                }),
            )?,
        )
        .await?;
    }
    if created_carrier {
        db.commit_content(tx).await?;
    } else {
        tx.commit().await?;
    }
    inspect_change_summary(db, principal, &request.workflow_key).await
}

#[derive(Default)]
struct SnapshotEvidence {
    sources: HashMap<String, ChangeSummarySourceEvent>,
    contexts: HashMap<String, ChangeSummaryContextRecord>,
}

impl ChangeSummaryResolver for SnapshotEvidence {
    fn source_event(&self, event_id: &str) -> Result<Option<ChangeSummarySourceEvent>> {
        Ok(self.sources.get(event_id).cloned())
    }

    fn context_record(&self, record_id: &str) -> Result<Option<ChangeSummaryContextRecord>> {
        Ok(self.contexts.get(record_id).cloned())
    }
}

async fn audience_can_view(
    tx: &mut Transaction<'_, Sqlite>,
    audience: &DerivationAudiencePolicy,
    record_id: &str,
) -> Result<bool> {
    for member in &audience.principals {
        let capability = crate::authorization::effective_capability_on(
            tx,
            Principal::bound(&member.account_id, member.is_member),
            record_id,
        )
        .await?;
        if !capability.allows(Capability::View) {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn snapshot_evidence(
    tx: &mut Transaction<'_, Sqlite>,
    audience: &DerivationAudiencePolicy,
    source_ids: &[String],
    context_ids: &[String],
) -> Result<SnapshotEvidence> {
    let mut evidence = SnapshotEvidence::default();
    for event_id in source_ids {
        let record_id: Option<String> =
            sqlx::query_scalar("SELECT record_id FROM content_events WHERE id=?")
                .bind(event_id)
                .fetch_optional(&mut **tx)
                .await?;
        let Some(record_id) = record_id else {
            return Err(Error::engine("change-summary input is unavailable"));
        };
        if !audience_can_view(tx, audience, &record_id).await? {
            return Err(Error::engine("change-summary input is unavailable"));
        }
        let row = sqlx::query(
            "SELECT e.id,e.seq,e.record_id,e.payload,e.run_key,r.type,r.kind,r.deleted_at
               FROM content_events e JOIN records r ON r.id=e.record_id WHERE e.id=?",
        )
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine("change-summary input is unavailable"))?;
        let payload: Option<String> = row.try_get("payload")?;
        let payload: Value = payload
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
            .unwrap_or(Value::Null);
        evidence.sources.insert(
            event_id.clone(),
            ChangeSummarySourceEvent {
                event_id: row.try_get("id")?,
                event_seq: row.try_get("seq")?,
                run_key: row
                    .try_get::<Option<String>, _>("run_key")?
                    .ok_or_else(|| Error::engine("change-summary source event has no run key"))?,
                sha256: derivation::digest_json(&payload),
                record_id: record_id.clone(),
                record_type: row.try_get("type")?,
                record_kind: row.try_get("kind")?,
                record_is_live: row.try_get::<Option<String>, _>("deleted_at")?.is_none(),
                audience_can_view: true,
            },
        );
    }
    for record_id in context_ids {
        if !audience_can_view(tx, audience, record_id).await? {
            return Err(Error::engine("change-summary input is unavailable"));
        }
        let row = sqlx::query(
            "SELECT r.type,r.kind,r.deleted_at,e.id AS body_event_id,
                    json_extract(e.payload,'$.body') AS body
               FROM records r JOIN content_events e ON e.id=(
                    SELECT id FROM content_events WHERE record_id=r.id
                     AND json_type(payload,'$.body')='text' ORDER BY seq DESC LIMIT 1)
              WHERE r.id=?",
        )
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine("change-summary input is unavailable"))?;
        let record_type: String = row.try_get("type")?;
        let record_kind: String = row.try_get("kind")?;
        let body: String = row.try_get("body")?;
        evidence.contexts.insert(
            record_id.clone(),
            ChangeSummaryContextRecord {
                record_id: record_id.clone(),
                record_type: record_type.clone(),
                record_kind: record_kind.clone(),
                record_is_live: row.try_get::<Option<String>, _>("deleted_at")?.is_none(),
                audience_can_view: true,
                is_realised: record_type == "Outcome" && record_kind == "impact",
                current_body_event_id: row.try_get("body_event_id")?,
                current_body_sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
            },
        );
    }
    Ok(evidence)
}

fn manifest(query: &ChangeSummaryQuery, evidence: &SnapshotEvidence) -> ChangeSummaryInputManifest {
    let mut inputs = Vec::new();
    for event_id in &query.selection.source_event_ids {
        let source = &evidence.sources[event_id];
        inputs.push(ChangeSummaryManifestInput {
            ordinal: inputs.len() as u32,
            input_role: "source".into(),
            input_kind: "content_event".into(),
            portable_id: source.event_id.clone(),
            sha256: source.sha256.clone(),
            record_id: source.record_id.clone(),
        });
    }
    for record_id in &query.scope.context_record_ids {
        let context = &evidence.contexts[record_id];
        inputs.push(ChangeSummaryManifestInput {
            ordinal: inputs.len() as u32,
            input_role: "context".into(),
            input_kind: "record_body".into(),
            portable_id: context.current_body_event_id.clone(),
            sha256: context.current_body_sha256.clone(),
            record_id: context.record_id.clone(),
        });
    }
    ChangeSummaryInputManifest { inputs }
}

fn source_boundary(
    workflow_key: &str,
    query: &ChangeSummaryQuery,
    manifest: &ChangeSummaryInputManifest,
    evidence: &SnapshotEvidence,
) -> EffectiveSourceBoundary {
    let through_seq = query
        .selection
        .source_event_ids
        .iter()
        .map(|id| evidence.sources[id].event_seq)
        .max()
        .unwrap_or(0);
    let scope = manifest
        .inputs
        .iter()
        .filter(|input| input.input_role == "context")
        .map(|input| {
            let context = &evidence.contexts[&input.record_id];
            json!({
                "record_id":input.record_id,
                "portable_id":input.portable_id,
                "sha256":input.sha256,
                "record_type":context.record_type,
                "record_kind":context.record_kind,
                "record_is_live":context.record_is_live,
                "is_realised":context.is_realised
            })
        })
        .collect::<Vec<_>>();
    EffectiveSourceBoundary {
        after_seq: None,
        through_seq,
        resolved_scope_membership_sha256: derivation::digest_json(&json!(scope)),
        metadata: json!({
            "schema":"native.change-summary.boundary.v1",
            "workflow_key":workflow_key,
            "source_event_ids":query.selection.source_event_ids,
            "context_record_ids":query.scope.context_record_ids
        }),
    }
}

pub async fn request_change_summary(
    db: &Db,
    principal: Principal<'_>,
    request: ChangeSummaryRequest,
) -> Result<ChangeSummaryCandidate> {
    let ids = ids(&request.workflow_key, &request.actor)?;
    nonblank("reason", &request.reason)?;
    if principal.account_id != Some(request.actor.as_str()) {
        return Err(Error::engine(
            "change-summary actor must match the authorized account principal",
        ));
    }
    let (audience, audience_sha256) = audience(&request.actor, principal.is_member, &ids.carrier)?;
    let mut tx = begin_write(db.write_pool()).await?;
    crate::authorization::require_capability_on(&mut tx, principal, &ids.carrier, Capability::Edit)
        .await
        .map_err(|_| Error::engine("change-summary workflow does not exist"))?;
    let definition: String =
        sqlx::query_scalar("SELECT definition FROM derivation_series WHERE id=?")
            .bind(&ids.series)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| Error::engine("change-summary workflow has not been created"))?;
    let definition: Value = serde_json::from_str(&definition)?;
    let recipe_revision: RecipeRevisionRef = serde_json::from_value(
        definition
            .get("recipe_revision")
            .cloned()
            .ok_or_else(|| Error::engine("change-summary series has no recipe pin"))?,
    )?;
    let pin = ChangeSummaryRecipePin {
        publication_id: recipe_revision.publication_id.clone(),
        descriptor_sha256: recipe_revision.sha256.clone(),
        expected_status_event_seq: request.expected_recipe_status_event_seq,
    };
    require_exact_recipe(&mut tx, principal, &pin, false).await?;
    if definition != series_definition(&request.workflow_key, &recipe_revision, &audience_sha256) {
        return Err(Error::engine(
            "change-summary workflow definition or audience has changed",
        ));
    }
    let evidence = snapshot_evidence(
        &mut tx,
        &audience,
        &request.source_event_ids,
        &request.context_record_ids,
    )
    .await?;
    let query = ChangeSummaryQuery::canonical(
        request.source_event_ids.clone(),
        request.context_record_ids.clone(),
        &evidence,
    )?;
    let manifest = manifest(&query, &evidence);
    super::validate_change_summary_manifest(&query, &manifest, &evidence)?;
    let canonical = canonicalize_and_validate_change_summary(
        &request.structured_result,
        &query,
        &manifest,
        &evidence,
    )?;
    let rendered = render_change_summary_output(&canonical.result)?;
    let boundary = source_boundary(&request.workflow_key, &query, &manifest, &evidence);
    let head: (i64, i64, Option<String>) = sqlx::query_as(
        "SELECT generation,target_version,active_binding_id FROM derivation_target_heads
          WHERE target_kind='record' AND target_record_id=? AND target_slot='body'",
    )
    .bind(&ids.carrier)
    .fetch_one(&mut *tx)
    .await?;
    if head.2.as_deref() != Some(ids.binding.as_str()) {
        return Err(Error::engine(
            "change-summary carrier binding is not active",
        ));
    }
    let definition_sha256 = derivation::digest_json(&definition);
    let canonical_request = CanonicalDerivationRequest {
        query_contract: CHANGE_SUMMARY_QUERY_CONTRACT_ID.into(),
        query_contract_version: i64::from(CHANGE_SUMMARY_QUERY_CONTRACT_VERSION),
        selection: serde_json::to_value(&query.selection)?,
        scope: serde_json::to_value(&query.scope)?,
    };
    let live_target_basis = json!({
        "target":DerivationTarget::record_body(&ids.carrier),
        "binding_id":ids.binding,
        "binding_generation":head.0,
        "target_version":head.1
    });
    let selected_request: Option<(String, String)> = sqlx::query_as(
        "SELECT request.id,revision.completion_metadata
           FROM derivation_selected_publications selected
           JOIN derivation_requests request ON request.result_revision_id=selected.revision_id
           JOIN derivation_revisions revision ON revision.id=selected.revision_id
          WHERE selected.target_kind='record' AND selected.target_record_id=?
            AND selected.target_slot='body' AND request.series_id=? AND request.state='succeeded'",
    )
    .bind(&ids.carrier)
    .bind(&ids.series)
    .fetch_optional(&mut *tx)
    .await?;
    let target_basis = if let Some((request_id, completion_metadata)) = selected_request {
        let selected = derivation::inspect_request_in(&mut tx, &request_id)
            .await?
            .ok_or_else(|| Error::engine("change-summary selected request is missing"))?;
        let completion_metadata: Value = serde_json::from_str(&completion_metadata)?;
        let selected_result_sha256 = completion_metadata
            .get("structured_result")
            .map(derivation::digest_json);
        if selected.spec.definition_sha256 == definition_sha256
            && selected.spec.canonical_request == canonical_request
            && selected.spec.recipe_revision == recipe_revision
            && selected.spec.effective_source_boundary == boundary
            && selected.spec.budget == budget()
            && selected.spec.audience_policy.as_ref() == Some(&audience)
            && selected.spec.audience_sha256 == audience_sha256
            && selected_result_sha256.as_deref() == Some(canonical.sha256.as_str())
        {
            selected.spec.target_basis
        } else {
            live_target_basis
        }
    } else {
        live_target_basis
    };
    let spec = DerivationRequestSpec {
        series_id: ids.series.clone(),
        definition_sha256,
        canonical_request,
        recipe_revision: recipe_revision.clone(),
        effective_source_boundary: boundary.clone(),
        target_basis,
        budget: budget(),
        audience_policy: Some(audience),
        audience_sha256,
    };
    let joined = derivation::create_or_join_request_in(
        &mut tx,
        spec.clone(),
        CreateOrJoinRequest {
            requested_by: request.actor.clone(),
            requested_run_key: request.run_key.clone(),
        },
    )
    .await?;
    tx.commit().await?;
    if joined.request.state == derivation::DerivationRequestState::Succeeded {
        return Ok(ChangeSummaryCandidate {
            revision_id: joined.request.result_revision_id.clone(),
            request: joined.request,
            carrier_id: ids.carrier,
            series_id: ids.series,
            created_request: joined.created,
            executed: false,
        });
    }
    let acquired = derivation::acquire_request_for_controlled_execution(
        db,
        principal,
        &joined.request.id,
        &request.actor,
        request.run_key.as_deref(),
        request.expected_recipe_status_event_seq,
        Duration::from_secs(DEFAULT_LEASE_SECONDS),
    )
    .await?;
    let AcquireRequestResult::Acquired(lease) = acquired else {
        let current = derivation::inspect_request(db, &joined.request.id)
            .await?
            .ok_or_else(|| Error::engine("change-summary request disappeared"))?;
        return Ok(ChangeSummaryCandidate {
            revision_id: current.result_revision_id.clone(),
            request: current,
            carrier_id: ids.carrier,
            series_id: ids.series,
            created_request: joined.created,
            executed: false,
        });
    };
    let inputs = manifest
        .inputs
        .iter()
        .map(|input| {
            let metadata = if input.input_role == "source" {
                let source = &evidence.sources[&input.portable_id];
                json!({
                    "schema":"native.change-summary.input.v1",
                    "record_id":input.record_id,
                    "record_head_event_seq":source.event_seq
                })
            } else {
                let context = &evidence.contexts[&input.record_id];
                json!({
                    "schema":"native.change-summary.input.v1",
                    "record_id":input.record_id,
                    "record_state":{
                        "type":context.record_type,
                        "kind":context.record_kind,
                        "is_live":context.record_is_live,
                        "is_realised":context.is_realised
                    }
                })
            };
            DerivationInput {
                input_role: input.input_role.clone(),
                input_kind: input.input_kind.clone(),
                portable_id: input.portable_id.clone(),
                sha256: input.sha256.clone(),
                metadata,
            }
        })
        .collect::<Vec<_>>();
    let predecessor_revision_id: Option<String> = sqlx::query_scalar(
        "SELECT revision_id FROM derivation_selected_publications
          WHERE target_kind='record' AND target_record_id=? AND target_slot='body'",
    )
    .bind(&ids.carrier)
    .fetch_optional(db.pool())
    .await?;
    let revision_id = format!(
        "change-summary:revision:{}",
        joined.request.request_key_sha256
    );
    let publication_id = format!(
        "change-summary:publication:{}",
        joined.request.request_key_sha256
    );
    // The controlled completion path independently measures deterministic
    // byte counts. Resolve those same values from authoritative rows.
    let mut measured_input_bytes = 0_u64;
    for input in &manifest.inputs {
        measured_input_bytes += if input.input_kind == "content_event" {
            let payload: Option<String> =
                sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
                    .bind(&input.portable_id)
                    .fetch_one(db.pool())
                    .await?;
            let value: Value = payload
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?
                .unwrap_or(Value::Null);
            derivation::canonical_json(&value).len() as u64
        } else {
            let body: String = sqlx::query_scalar(
                "SELECT json_extract(payload,'$.body') FROM content_events WHERE id=?",
            )
            .bind(&input.portable_id)
            .fetch_one(db.pool())
            .await?;
            body.len() as u64
        };
    }
    let publication = PublishRecordBodyRevision {
        publication_idempotency_key: format!("{publication_id}:event"),
        revision_idempotency_key: format!("{revision_id}:event"),
        actor: request.actor.clone(),
        run_key: request.run_key.clone(),
        reason: request.reason,
        publication_id,
        binding_id: ids.binding.clone(),
        target: DerivationTarget::record_body(&ids.carrier),
        expected_generation: head.0,
        expected_target_version: head.1,
        body: rendered.body.clone(),
        revision: DerivationRevisionCompleted {
            id: revision_id.clone(),
            series_id: ids.series.clone(),
            predecessor_revision_id,
            canonical_request: spec.canonical_request.clone(),
            recipe_revision,
            effective_source_boundary: boundary,
            inputs,
            output_ref: DerivationOutputRef {
                output_kind: "content_event".into(),
                event_id: "assigned-at-publication".into(),
                sha256: "0".repeat(64),
            },
            completion_metadata: json!({
                "change_summary_result_sha256":canonical.sha256,
                "change_summary_result_canonical_json":canonical.canonical_json
            }),
        },
    };
    let completion = CompleteDerivationRequest {
        lease,
        expected_recipe_status_event_seq: request.expected_recipe_status_event_seq,
        structured_result: serde_json::to_value(&canonical.result)?,
        rendered_output: serde_json::to_value(&rendered)?,
        executor: DerivationExecutorDescriptor {
            provider: "native-ce".into(),
            model: "provided-structured-result".into(),
            executor_revision: "native.change-summary.provided.v1".into(),
            execution_profile_id: "native.change-summary.structured-output.v1".into(),
            capabilities: vec![crate::recipe::RecipeModelCapability::JsonSchemaOutput],
            parameters: json!({"temperature_milli":0,"max_output_tokens":4096}),
            usage: DerivationExecutionUsage {
                input_bytes: measured_input_bytes,
                input_items: manifest.inputs.len() as u64,
                input_tokens: 0,
                output_bytes: rendered.body.len() as u64,
                output_tokens: 0,
            },
        },
        publication,
    };
    let published = derivation::complete_request_with_publication(db, principal, completion)
        .await?
        .ok_or_else(|| Error::engine("change-summary execution lost its lease"))?;
    let current = derivation::inspect_request(db, &joined.request.id)
        .await?
        .ok_or_else(|| Error::engine("change-summary request disappeared"))?;
    Ok(ChangeSummaryCandidate {
        request: current,
        carrier_id: ids.carrier,
        series_id: ids.series,
        revision_id: Some(
            serde_json::from_str::<DerivationRevisionCompleted>(&published.revision_event.payload)?
                .id,
        ),
        created_request: joined.created,
        executed: true,
    })
}

pub async fn inspect_change_summary(
    db: &Db,
    principal: Principal<'_>,
    workflow_key: &str,
) -> Result<ChangeSummaryWorkflowInspection> {
    let actor = principal
        .account_id
        .ok_or_else(|| Error::engine("change-summary workflow does not exist"))?;
    let ids = ids(workflow_key, actor)?;
    let mut snapshot = db.pool().begin().await?;
    if require_exact_workflow_audience(
        &mut snapshot,
        &ids,
        workflow_key,
        actor,
        principal.is_member,
    )
    .await
    .is_err()
    {
        snapshot.rollback().await?;
        return Err(Error::engine("change-summary workflow does not exist"));
    }
    let selected: Option<(String, String)> = sqlx::query_as(
        "SELECT revision_id,publication_id FROM derivation_selected_publications
          WHERE target_kind='record' AND target_record_id=? AND target_slot='body'",
    )
    .bind(&ids.carrier)
    .fetch_optional(&mut *snapshot)
    .await?;
    if let Some((revision_id, _)) = &selected {
        if !revision_is_current_for_principal(&mut snapshot, principal, revision_id).await? {
            snapshot.rollback().await?;
            return Err(Error::engine("change-summary workflow does not exist"));
        }
    }
    let confirmed: Option<(String, String, String)> = sqlx::query_as(
        "SELECT c.revision_id,c.confirmation_id,p.output_event_id
           FROM derivation_confirmation_heads h
           JOIN derivation_revision_confirmations c ON c.confirmation_id=h.confirmation_id
           JOIN derivation_target_publications p ON p.publication_id=c.publication_id
          WHERE h.assignment_id=? AND h.confirmation_id IS NOT NULL",
    )
    .bind(&ids.assignment)
    .fetch_optional(&mut *snapshot)
    .await?;
    let confirmed_body = if let Some((_, _, output_event_id)) = &confirmed {
        sqlx::query_scalar("SELECT json_extract(payload,'$.body') FROM content_events WHERE id=?")
            .bind(output_event_id)
            .fetch_optional(&mut *snapshot)
            .await?
    } else {
        None
    };
    let request_row: Option<String> = sqlx::query_scalar(
        "SELECT id FROM derivation_requests WHERE series_id=? ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(&ids.series)
    .fetch_optional(&mut *snapshot)
    .await?;
    let request = if let Some(id) = request_row {
        derivation::inspect_request_in(&mut snapshot, &id).await?
    } else {
        None
    };
    snapshot.rollback().await?;
    Ok(ChangeSummaryWorkflowInspection {
        schema: WORKFLOW_SCHEMA.into(),
        workflow_key: workflow_key.into(),
        carrier_id: ids.carrier,
        series_id: ids.series,
        binding_id: ids.binding,
        assignment_id: ids.assignment,
        selected_revision_id: selected.as_ref().map(|value| value.0.clone()),
        selected_publication_id: selected.map(|value| value.1),
        confirmed_revision_id: confirmed.as_ref().map(|value| value.0.clone()),
        confirmation_id: confirmed.map(|value| value.1),
        confirmed_body,
        request,
    })
}

pub async fn confirm_change_summary(
    db: &Db,
    principal: Principal<'_>,
    workflow_key: &str,
    expected_revision_id: &str,
    actor: &str,
    run_key: Option<String>,
    reason: &str,
) -> Result<ChangeSummaryConfirmation> {
    if principal.account_id != Some(actor) {
        return Err(Error::engine("change-summary candidate is unavailable"));
    }
    let ids = ids(workflow_key, actor)?;
    let mut tx = begin_write(db.write_pool()).await?;
    require_exact_workflow_audience(&mut tx, &ids, workflow_key, actor, principal.is_member)
        .await
        .map_err(|_| Error::engine("change-summary candidate is unavailable"))?;
    let row = sqlx::query(
        "SELECT p.publication_id,p.revision_id,p.generation,p.target_version,p.output_sha256,
                r.input_manifest_sha256,h.head_event_id,h.confirmation_id AS current_confirmation_id,
                current.revision_id AS current_revision_id,current.confirmed_event_id,
                current.confirmed_event_seq
           FROM derivation_selected_publications s
           JOIN derivation_target_publications p ON p.publication_id=s.publication_id
           JOIN derivation_revisions r ON r.id=p.revision_id
           LEFT JOIN derivation_confirmation_heads h ON h.assignment_id=?
           LEFT JOIN derivation_revision_confirmations current
             ON current.confirmation_id=h.confirmation_id
          WHERE s.target_kind='record' AND s.target_record_id=? AND s.target_slot='body'",
    )
    .bind(&ids.assignment)
    .bind(&ids.carrier)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::engine("change-summary candidate does not exist"))?;
    let revision_id: String = row.try_get("revision_id")?;
    if revision_id != expected_revision_id {
        return Err(Error::engine("change-summary selected revision changed"));
    }
    if !revision_is_current_for_principal(&mut tx, principal, &revision_id).await? {
        return Err(Error::engine("change-summary candidate is unavailable"));
    }
    if row
        .try_get::<Option<String>, _>("current_revision_id")?
        .as_deref()
        == Some(revision_id.as_str())
    {
        let result = ChangeSummaryConfirmation {
            workflow_key: workflow_key.into(),
            carrier_id: ids.carrier,
            assignment_id: ids.assignment,
            confirmation_id: row
                .try_get::<Option<String>, _>("current_confirmation_id")?
                .expect("joined active confirmation has an id"),
            revision_id,
            event_id: row.try_get("confirmed_event_id")?,
            event_seq: row.try_get("confirmed_event_seq")?,
        };
        tx.rollback().await?;
        return Ok(result);
    }
    let predecessor = row
        .try_get::<Option<String>, _>("head_event_id")?
        .unwrap_or_else(|| "genesis".into());
    let confirmation_id = format!(
        "change-summary:confirmation:{}:{}:{}",
        ids.namespace_digest,
        stable_digest(&revision_id),
        stable_digest(&predecessor)
    );
    let event = derivation::confirm_revision_in(
        &mut tx,
        principal,
        format!("{confirmation_id}:event"),
        actor.into(),
        run_key,
        reason.into(),
        RevisionConfirmed {
            confirmation_id: confirmation_id.clone(),
            assignment_id: ids.assignment.clone(),
            target: DerivationTarget::record_body(&ids.carrier),
            role: CHANGE_SUMMARY_ROLE.into(),
            series_id: ids.series.clone(),
            revision_id: revision_id.clone(),
            publication_id: row.try_get("publication_id")?,
            binding_id: ids.binding.clone(),
            expected_generation: row.try_get("generation")?,
            expected_target_version: row.try_get("target_version")?,
            expected_input_manifest_sha256: row.try_get("input_manifest_sha256")?,
            expected_output_sha256: row.try_get("output_sha256")?,
            expected_confirmation_head_event_id: row.try_get("head_event_id")?,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ChangeSummaryConfirmation {
        workflow_key: workflow_key.into(),
        carrier_id: ids.carrier,
        assignment_id: ids.assignment,
        confirmation_id,
        revision_id,
        event_id: event.id,
        event_seq: event.seq,
    })
}

pub async fn revoke_change_summary(
    db: &Db,
    principal: Principal<'_>,
    workflow_key: &str,
    actor: &str,
    run_key: Option<String>,
    reason: &str,
) -> Result<ChangeSummaryConfirmation> {
    if principal.account_id != Some(actor) {
        return Err(Error::engine("change-summary confirmation is unavailable"));
    }
    let ids = ids(workflow_key, actor)?;
    let mut tx = begin_write(db.write_pool()).await?;
    crate::authorization::require_capability_on(&mut tx, principal, &ids.carrier, Capability::Edit)
        .await
        .map_err(|_| Error::engine("change-summary confirmation is unavailable"))?;
    let row = sqlx::query(
        "SELECT h.confirmation_id,h.head_event_id,c.revision_id
           FROM derivation_confirmation_heads h
           JOIN derivation_revision_confirmations c ON c.confirmation_id=h.confirmation_id
          WHERE h.assignment_id=? AND h.confirmation_id IS NOT NULL",
    )
    .bind(&ids.assignment)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::engine("change-summary confirmation does not exist"))?;
    let confirmation_id: String = row.try_get("confirmation_id")?;
    let revision_id: String = row.try_get("revision_id")?;
    let retraction_id = format!(
        "change-summary:retraction:{}:{}:{}",
        ids.namespace_digest,
        stable_digest(&confirmation_id),
        stable_digest(&row.try_get::<String, _>("head_event_id")?)
    );
    let event = derivation::retract_confirmation_in(
        &mut tx,
        principal,
        format!("{retraction_id}:event"),
        actor.into(),
        run_key,
        reason.into(),
        derivation::ConfirmationRetracted {
            retraction_id,
            confirmation_id: confirmation_id.clone(),
            assignment_id: ids.assignment.clone(),
            target: DerivationTarget::record_body(&ids.carrier),
            expected_confirmation_head_event_id: row.try_get("head_event_id")?,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(ChangeSummaryConfirmation {
        workflow_key: workflow_key.into(),
        carrier_id: ids.carrier,
        assignment_id: ids.assignment,
        confirmation_id,
        revision_id,
        event_id: event.id,
        event_seq: event.seq,
    })
}

pub struct ChangeSummaryCurrentBasis;

impl CurrentRevisionBasisResolver for ChangeSummaryCurrentBasis {
    fn current_basis<'a>(
        &'a self,
        snapshot: &'a mut Transaction<'static, Sqlite>,
        revision: &'a RevisionRecognitionBasis,
    ) -> BoxFuture<'a, Result<Option<DerivationApplicabilityBasis>>> {
        Box::pin(async move {
            let mut current = derivation::revision_applicability_basis(
                &revision.series_id,
                &revision.definition_sha256,
                revision.canonical_request.clone(),
                revision.recipe_revision.clone(),
                revision.effective_source_boundary.clone(),
                &revision.completion_metadata,
            )?;
            let workflow_key = revision
                .effective_source_boundary
                .metadata
                .get("workflow_key")
                .and_then(Value::as_str)
                .filter(|_| {
                    revision
                        .effective_source_boundary
                        .metadata
                        .get("schema")
                        .and_then(Value::as_str)
                        == Some("native.change-summary.boundary.v1")
                });
            let Some(workflow_key) = workflow_key else {
                return Ok(None);
            };
            if revision.recipe_revision.definition_id != CHANGE_SUMMARY_RECIPE_PROGRAM_ID {
                return Ok(None);
            }
            let series_row: Option<(String, String)> = sqlx::query_as(
                "SELECT definition,definition_sha256 FROM derivation_series WHERE id=?",
            )
            .bind(&revision.series_id)
            .fetch_optional(&mut **snapshot)
            .await?;
            let Some((series_definition_json, series_definition_sha256)) = series_row else {
                return Ok(None);
            };
            let stored_series_definition: Value = serde_json::from_str(&series_definition_json)?;
            current.definition_sha256 = series_definition_sha256;
            let release = sqlx::query(
                "SELECT descriptor,descriptor_sha256,status FROM recipe_releases
                  WHERE program_id=? AND publication_event_id=?",
            )
            .bind(CHANGE_SUMMARY_RECIPE_PROGRAM_ID)
            .bind(&revision.recipe_revision.publication_id)
            .fetch_optional(&mut **snapshot)
            .await?;
            let Some(release) = release else {
                return Ok(None);
            };
            let descriptor: crate::recipe::RecipeReleaseDescriptor =
                serde_json::from_str(&release.try_get::<String, _>("descriptor")?)?;
            if !matches!(
                release.try_get::<String, _>("status")?.as_str(),
                "published" | "deprecated"
            ) || release.try_get::<String, _>("descriptor_sha256")?
                != revision.recipe_revision.sha256
                || descriptor.program_id != CHANGE_SUMMARY_RECIPE_PROGRAM_ID
                || descriptor.runtime != crate::recipe::RECIPE_RUNTIME
                || descriptor.definition != change_summary_recipe_definition()?
            {
                return Ok(None);
            }
            let target = sqlx::query(
                "SELECT p.binding_id,p.generation,b.target_record_id,
                        h.active_binding_id,h.generation AS head_generation
                   FROM derivation_target_publications p
                   JOIN derivation_target_bindings b ON b.binding_id=p.binding_id
                   JOIN derivation_target_heads h ON h.target_kind=b.target_kind
                    AND h.target_record_id=b.target_record_id AND h.target_slot=b.target_slot
                  WHERE p.revision_id=?",
            )
            .bind(&revision.revision_id)
            .fetch_optional(&mut **snapshot)
            .await?;
            let Some(target) = target else {
                return Ok(None);
            };
            let binding_id: String = target.try_get("binding_id")?;
            let generation: i64 = target.try_get("generation")?;
            let carrier_id: String = target.try_get("target_record_id")?;
            if target
                .try_get::<Option<String>, _>("active_binding_id")?
                .as_deref()
                != Some(binding_id.as_str())
                || target.try_get::<i64, _>("head_generation")? != generation
            {
                return Ok(None);
            }
            let active_assignment: Option<String> = sqlx::query_scalar(
                "SELECT active_assignment_id FROM derivation_artifact_role_heads
                  WHERE target_kind='record' AND target_record_id=? AND target_slot='body'
                    AND role=?",
            )
            .bind(&carrier_id)
            .bind(CHANGE_SUMMARY_ROLE)
            .fetch_optional(&mut **snapshot)
            .await?
            .flatten();
            let request_identity: Option<String> = sqlx::query_scalar(
                "SELECT request_identity FROM derivation_requests
                  WHERE result_revision_id=? AND state='succeeded'",
            )
            .bind(&revision.revision_id)
            .fetch_optional(&mut **snapshot)
            .await?;
            let Some(request_identity) = request_identity else {
                return Ok(None);
            };
            let request_identity: Value = serde_json::from_str(&request_identity)?;
            let audience_policy: DerivationAudiencePolicy = serde_json::from_value(
                request_identity
                    .get("audience_policy")
                    .cloned()
                    .ok_or_else(|| {
                        Error::engine("change-summary request has no audience policy")
                    })?,
            )?;
            let Some(actor) = audience_policy
                .principals
                .as_slice()
                .first()
                .filter(|_| audience_policy.principals.len() == 1)
                .map(|principal| principal.account_id.as_str())
            else {
                return Ok(None);
            };
            let workflow_ids = ids(workflow_key, actor)?;
            if workflow_ids.series != revision.series_id
                || workflow_ids.carrier != carrier_id
                || workflow_ids.binding != binding_id
                || active_assignment.as_deref() != Some(workflow_ids.assignment.as_str())
            {
                return Ok(None);
            }
            let policy_is_exact: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM records
                    WHERE id=? AND deleted_at IS NULL AND policy_anchor_id=?)
                   AND (SELECT COUNT(*) FROM policy_entries WHERE policy_anchor_id=?)=1
                   AND EXISTS(SELECT 1 FROM policy_entries WHERE policy_anchor_id=?
                     AND subject_kind='account' AND subject_id=?
                     AND effect='allow' AND capability='manage')",
            )
            .bind(&carrier_id)
            .bind(&carrier_id)
            .bind(&carrier_id)
            .bind(&carrier_id)
            .bind(actor)
            .fetch_one(&mut **snapshot)
            .await?;
            if !policy_is_exact
                || audience_policy.policy_anchor_id != carrier_id
                || derivation::audience_policy_sha256(&audience_policy)? != current.audience_sha256
                || stored_series_definition
                    != series_definition(
                        workflow_key,
                        &revision.recipe_revision,
                        &current.audience_sha256,
                    )
            {
                return Ok(None);
            }
            let selection: super::ChangeSummarySelection =
                serde_json::from_value(current.canonical_request.selection.clone())?;
            let scope: super::ChangeSummaryScope =
                serde_json::from_value(current.canonical_request.scope.clone())?;
            let mut through_seq = 0_i64;
            for event_id in &selection.source_event_ids {
                let latest: Option<i64> = sqlx::query_scalar(
                    "SELECT MAX(latest.seq) FROM content_events selected
                       JOIN content_events latest ON latest.record_id=selected.record_id
                      WHERE selected.id=?",
                )
                .bind(event_id)
                .fetch_one(&mut **snapshot)
                .await?;
                through_seq = through_seq.max(latest.unwrap_or(0));
            }
            let mut scope_heads = Vec::with_capacity(scope.context_record_ids.len());
            for record_id in &scope.context_record_ids {
                let row = sqlx::query(
                    "SELECT r.type,r.kind,r.deleted_at,e.id,
                            json_extract(e.payload,'$.body') AS body
                       FROM records r JOIN content_events e ON e.id=(
                            SELECT id FROM content_events WHERE record_id=r.id
                             AND json_type(payload,'$.body')='text'
                            ORDER BY seq DESC LIMIT 1)
                      WHERE r.id=?",
                )
                .bind(record_id)
                .fetch_optional(&mut **snapshot)
                .await?;
                let Some(row) = row else { return Ok(None) };
                let body: String = row.try_get("body")?;
                let record_type: String = row.try_get("type")?;
                let record_kind: String = row.try_get("kind")?;
                let record_is_live = row.try_get::<Option<String>, _>("deleted_at")?.is_none();
                let is_realised = record_type == "Outcome" && record_kind == "impact";
                scope_heads.push(json!({
                    "record_id":record_id,
                    "portable_id":row.try_get::<String,_>("id")?,
                    "sha256":format!("{:x}",Sha256::digest(body.as_bytes())),
                    "record_type":record_type,
                    "record_kind":record_kind,
                    "record_is_live":record_is_live,
                    "is_realised":is_realised
                }));
            }
            current.effective_source_boundary.through_seq = through_seq;
            current
                .effective_source_boundary
                .resolved_scope_membership_sha256 = derivation::digest_json(&json!(scope_heads));
            Ok(Some(current))
        })
    }
}

pub async fn query_change_summaries(
    db: &Db,
    principal: Principal<'_>,
    after: Option<&derivation::ConfirmedArtifactCursor>,
    limit: usize,
    source_limit: usize,
) -> Result<ChangeSummaryQueryPage> {
    if principal.account_id.is_none() || !principal.is_member {
        return Ok(ChangeSummaryQueryPage {
            items: Vec::new(),
            next_cursor: None,
        });
    }
    let account = principal.account_id.map(str::to_owned);
    let is_member = principal.is_member;
    let membership = move |candidate: &str| {
        account
            .as_deref()
            .filter(|id| *id == candidate)
            .map(|_| is_member)
    };
    let gate = RequestRevisionApplicabilityGate::new(membership, ChangeSummaryCurrentBasis);
    let page = derivation::query_confirmed_artifacts(
        db,
        principal,
        CHANGE_SUMMARY_ROLE,
        &OutputContractSelector {
            id: CHANGE_SUMMARY_OUTPUT_CONTRACT_ID.into(),
            version: CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION,
        },
        after,
        limit,
        source_limit,
        &gate,
    )
    .await?;
    Ok(ChangeSummaryQueryPage {
        items: page.items,
        next_cursor: page.next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::FacetSetPayload;
    use crate::recipe::{
        canonical_recipe_definition, publish_recipe_release, PublishRecipeRelease,
    };
    use uuid::Uuid;

    const ACTOR: &str = "acct:change-summary-owner";

    #[test]
    fn workflow_identity_is_scoped_by_private_audience_actor() {
        let first = ids("same-workflow-key", "acct:first").unwrap();
        let second = ids("same-workflow-key", "acct:second").unwrap();
        assert_ne!(first.namespace_digest, second.namespace_digest);
        assert_ne!(first.carrier, second.carrier);
        assert_ne!(first.series, second.series);
        assert_ne!(first.binding, second.binding);
        assert_ne!(first.assignment, second.assignment);
    }

    async fn create_record_with_run(db: &Db, value: Value, run_key: Option<&str>) -> String {
        crate::store::with_event_annotations(
            EventAnnotations {
                run_key: run_key.map(str::to_owned),
                parent_key: None,
                intent: Some("change-summary workflow test fixture".into()),
            },
            crate::store::create_record_as(db, value, Some(ACTOR)),
        )
        .await
        .unwrap()
    }

    async fn publish_packaged_recipe(db: &Db, principal: Principal<'_>) -> ChangeSummaryRecipePin {
        let definition = change_summary_recipe_definition().unwrap();
        let body = canonical_recipe_definition(&definition).unwrap();
        let recipe_id = crate::store::install_historical_record_fixture(
            db,
            CHANGE_SUMMARY_RECIPE_PROGRAM_ID,
            json!({
                "type":"Program",
                "kind":"recipe",
                "name":"Packaged change-summary recipe",
                "body":body
            }),
            ACTOR,
        )
        .await
        .unwrap();
        crate::store::set_facet(
            db,
            &recipe_id,
            FacetSetPayload {
                key: "runtime".into(),
                value: Some(crate::recipe::RECIPE_RUNTIME.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            db,
            ACTOR,
            &recipe_id,
            vec![AllowEntry::account(ACTOR, Capability::Manage)],
        )
        .await
        .unwrap();
        let row = sqlx::query(
            "SELECT id,json_extract(payload,'$.body') AS body FROM content_events
              WHERE record_id=? AND json_type(payload,'$.body')='text'
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(&recipe_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let source_event_id: String = row.try_get("id").unwrap();
        let source_body: String = row.try_get("body").unwrap();
        let release = publish_recipe_release(
            db,
            principal,
            PublishRecipeRelease {
                publication_event_id: Uuid::new_v4().to_string(),
                program_id: recipe_id,
                source_event_id,
                source_sha256: format!("{:x}", Sha256::digest(source_body.as_bytes())),
                definition,
            },
        )
        .await
        .unwrap();
        ChangeSummaryRecipePin {
            publication_id: release.descriptor.publication_event_id,
            descriptor_sha256: release.descriptor_sha256,
            expected_status_event_seq: release.status_event_seq,
        }
    }

    async fn fixture(
        db: &Db,
        principal: Principal<'_>,
    ) -> (ChangeSummaryRecipePin, Vec<String>, Vec<String>, Value) {
        let pin = publish_packaged_recipe(db, principal).await;
        let mut source_event_ids = Vec::new();
        for (ordinal, run_key) in [
            "scout-chair-000001",
            "scout-chair-000002",
            "scout-chair-000003",
        ]
        .into_iter()
        .enumerate()
        {
            let record_id = create_record_with_run(
                db,
                json!({
                    "id":format!("c8a70000-0000-4000-8000-{:012}", ordinal + 1),
                    "type":"Document",
                    "kind":"note",
                    "name":format!("Source {ordinal}"),
                    "body":format!("authoritative run {ordinal}")
                }),
                Some(run_key),
            )
            .await;
            source_event_ids.push(
                sqlx::query_scalar(
                    "SELECT id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
                )
                .bind(record_id)
                .fetch_one(db.pool())
                .await
                .unwrap(),
            );
        }
        let mut context_record_ids = Vec::new();
        for (id, record_type, kind, body) in [
            (
                "c8a70000-0000-4000-8000-000000000011",
                "Resolution",
                "decision",
                "Explicit confirmation.",
            ),
            (
                "c8a70000-0000-4000-8000-000000000012",
                "Outcome",
                "impact",
                "Safer releases.",
            ),
            (
                "c8a70000-0000-4000-8000-000000000013",
                "WorkItem",
                "task",
                "Implement change summaries.",
            ),
        ] {
            context_record_ids.push(
                create_record_with_run(
                    db,
                    json!({"id":id,"type":record_type,"kind":kind,"name":id,"body":body}),
                    None,
                )
                .await,
            );
        }
        let mut tx = db.pool().begin().await.unwrap();
        let audience = audience(ACTOR, true, "unused").unwrap().0;
        let evidence =
            snapshot_evidence(&mut tx, &audience, &source_event_ids, &context_record_ids)
                .await
                .unwrap();
        let query = ChangeSummaryQuery::canonical(
            source_event_ids.clone(),
            context_record_ids.clone(),
            &evidence,
        )
        .unwrap();
        let manifest = manifest(&query, &evidence);
        tx.rollback().await.unwrap();
        let citations = manifest
            .inputs
            .iter()
            .map(|input| {
                json!({
                    "ordinal":input.ordinal,
                    "input_role":input.input_role,
                    "input_kind":input.input_kind,
                    "portable_id":input.portable_id,
                    "sha256":input.sha256
                })
            })
            .collect::<Vec<_>>();
        let source_groups = query
            .selection
            .source_event_ids
            .iter()
            .enumerate()
            .map(|(ordinal, event_id)| {
                json!({
                    "run_key":evidence.sources[event_id].run_key,
                    "source_ordinal":ordinal
                })
            })
            .collect::<Vec<_>>();
        let result = json!({
            "schema":"native.change-summary.v1",
            "effective_work_interval":{
                "started_at":"2026-08-01T09:00:00.000Z",
                "ended_at":"2026-08-03T17:30:00.000Z"
            },
            "renderer":{
                "id":super::super::CHANGE_SUMMARY_RENDERER_ID,
                "revision":super::super::CHANGE_SUMMARY_RENDERER_REVISION,
                "spec_sha256":super::super::CHANGE_SUMMARY_RENDERER_SHA256
            },
            "source_groups":source_groups,
            "title":"A safer release path",
            "overview":"Three runs converged on one shippable result.",
            "items":[{
                "heading":"Gate release on explicit confirmation",
                "summary":"The draft and shipping decision remain separate and linked.",
                "citations":citations,
                "materiality":{
                    "summary":"This preserves semantic human judgement.",
                    "references":[{
                        "record_id":"c8a70000-0000-4000-8000-000000000011",
                        "rationale":"Records the explicit-confirmation decision."
                    }]
                },
                "link_suggestions":{
                    "work_items":[{
                        "record_id":"c8a70000-0000-4000-8000-000000000013",
                        "relationship":"implements",
                        "rationale":"Owns the implementation."
                    }],
                    "outcomes":[{
                        "record_id":"c8a70000-0000-4000-8000-000000000012",
                        "relationship":"relates_to",
                        "rationale":"Contributes to the realised impact."
                    }]
                }
            }]
        });
        (pin, source_event_ids, context_record_ids, result)
    }

    #[tokio::test]
    async fn workflow_reuses_identical_result_and_keeps_confirmed_revision_until_correction_confirmed(
    ) {
        let db = crate::create_database(":memory:").await.unwrap();
        let principal = Principal::bound(ACTOR, true);
        let (pin, source_event_ids, context_record_ids, result) = fixture(&db, principal).await;
        create_or_reuse_change_summary(
            &db,
            principal,
            ChangeSummaryCreateRequest {
                workflow_key: "release:2026-08-04".into(),
                name: "Release change summary".into(),
                recipe: pin.clone(),
                actor: ACTOR.into(),
                run_key: Some("scout-chair-000010".into()),
                reason: "create a private change-summary workflow".into(),
            },
        )
        .await
        .unwrap();
        let make_request = |structured_result: Value| ChangeSummaryRequest {
            workflow_key: "release:2026-08-04".into(),
            source_event_ids: source_event_ids.clone(),
            context_record_ids: context_record_ids.clone(),
            structured_result,
            expected_recipe_status_event_seq: pin.expected_status_event_seq,
            actor: ACTOR.into(),
            run_key: Some("scout-chair-000011".into()),
            reason: "derive the grouped change summary".into(),
        };
        let first = request_change_summary(&db, principal, make_request(result.clone()))
            .await
            .unwrap();
        assert!(first.executed);
        let first_revision = first.revision_id.clone().unwrap();
        confirm_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            &first_revision,
            ACTOR,
            Some("scout-chair-000012".into()),
            "ship the grouped change",
        )
        .await
        .unwrap();
        let retry = request_change_summary(&db, principal, make_request(result.clone()))
            .await
            .unwrap();
        assert!(!retry.executed);
        assert_eq!(retry.revision_id.as_deref(), Some(first_revision.as_str()));

        let mut corrected_result = result;
        corrected_result["overview"] =
            json!("Three runs converged on one corrected, shippable result.");
        let correction = request_change_summary(&db, principal, make_request(corrected_result))
            .await
            .unwrap();
        assert!(correction.executed);
        let corrected_revision = correction.revision_id.clone().unwrap();
        assert_ne!(corrected_revision, first_revision);
        let before_confirmation = query_change_summaries(&db, principal, None, 10, 10)
            .await
            .unwrap();
        assert_eq!(before_confirmation.items.len(), 1);
        assert_eq!(before_confirmation.items[0].revision_id, first_revision);
        assert!(before_confirmation.items[0].draft_available);

        revoke_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            ACTOR,
            Some("scout-chair-000013".into()),
            "replace the confirmed wording",
        )
        .await
        .unwrap();
        let corrected_confirmation = confirm_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            &corrected_revision,
            ACTOR,
            Some("scout-chair-000014".into()),
            "ship the corrected wording",
        )
        .await
        .unwrap();
        let after_confirmation = query_change_summaries(&db, principal, None, 10, 10)
            .await
            .unwrap();
        assert_eq!(after_confirmation.items.len(), 1);
        assert_eq!(after_confirmation.items[0].revision_id, corrected_revision);
        assert!(after_confirmation.items[0]
            .confirmed_body
            .contains("Three runs converged on one corrected, shippable result."));
        assert_eq!(after_confirmation.items[0].source_runs.len(), 6);
        assert_eq!(
            after_confirmation.items[0]
                .source_runs
                .iter()
                .filter(|input| input.input_role == "source" && input.run_key.is_some())
                .count(),
            3
        );

        revoke_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            ACTOR,
            Some("scout-chair-000015".into()),
            "exercise same-revision reconfirmation",
        )
        .await
        .unwrap();
        let reconfirmed = confirm_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            &corrected_revision,
            ACTOR,
            Some("scout-chair-000016".into()),
            "reconfirm the same corrected revision",
        )
        .await
        .unwrap();
        assert_eq!(reconfirmed.revision_id, corrected_revision);
        assert_ne!(
            reconfirmed.confirmation_id,
            corrected_confirmation.confirmation_id
        );

        let undisclosed = inspect_change_summary(
            &db,
            Principal::bound("acct:outsider", true),
            "release:2026-08-04",
        )
        .await
        .unwrap_err();
        assert!(undisclosed
            .to_string()
            .contains("change-summary workflow does not exist"));

        let replay = crate::conformance::rebuild_and_diff_derivation(&db)
            .await
            .unwrap();
        assert!(replay
            .tables
            .iter()
            .all(|table| table.live == table.rebuilt && table.mismatches.is_empty()));

        let offboarded = query_change_summaries(&db, Principal::bound(ACTOR, false), None, 10, 10)
            .await
            .unwrap();
        assert!(offboarded.items.is_empty());
        assert!(
            inspect_change_summary(&db, Principal::bound(ACTOR, false), "release:2026-08-04",)
                .await
                .unwrap_err()
                .to_string()
                .contains("does not exist")
        );
        assert!(confirm_change_summary(
            &db,
            Principal::bound(ACTOR, false),
            "release:2026-08-04",
            &corrected_revision,
            ACTOR,
            None,
            "offboarded confirmation must fail",
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("unavailable"));
        let offboarded_revocation = revoke_change_summary(
            &db,
            Principal::bound(ACTOR, false),
            "release:2026-08-04",
            ACTOR,
            Some("scout-chair-000017".into()),
            "withdraw the confirmation after membership drift",
        )
        .await
        .unwrap();
        assert_eq!(
            offboarded_revocation.confirmation_id,
            reconfirmed.confirmation_id
        );
        let restored_after_offboarding = confirm_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            &corrected_revision,
            ACTOR,
            Some("scout-chair-000018".into()),
            "restore the confirmation after the safety-repair regression",
        )
        .await
        .unwrap();

        let carrier_id = after_confirmation.items[0].target_record_id.clone();
        crate::authorization::replace_explicit_policy(
            &db,
            ACTOR,
            &carrier_id,
            vec![
                AllowEntry::account(ACTOR, Capability::Manage),
                AllowEntry::account("acct:unexpected-reader", Capability::View),
            ],
        )
        .await
        .unwrap();
        let expanded_audience = query_change_summaries(&db, principal, None, 10, 10)
            .await
            .unwrap();
        assert!(expanded_audience.items.is_empty());
        assert!(inspect_change_summary(&db, principal, "release:2026-08-04")
            .await
            .unwrap_err()
            .to_string()
            .contains("does not exist"));
        assert!(confirm_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            &corrected_revision,
            ACTOR,
            None,
            "expanded audience confirmation must fail",
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("unavailable"));
        let expanded_policy_revocation = revoke_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            ACTOR,
            Some("scout-chair-000019".into()),
            "withdraw the confirmation after accidental policy expansion",
        )
        .await
        .unwrap();
        assert_eq!(
            expanded_policy_revocation.confirmation_id,
            restored_after_offboarding.confirmation_id
        );
        crate::authorization::replace_explicit_policy(
            &db,
            ACTOR,
            &carrier_id,
            vec![AllowEntry::account(ACTOR, Capability::Manage)],
        )
        .await
        .unwrap();
        confirm_change_summary(
            &db,
            principal,
            "release:2026-08-04",
            &corrected_revision,
            ACTOR,
            Some("scout-chair-000020".into()),
            "restore the confirmation after exact audience repair",
        )
        .await
        .unwrap();
        assert_eq!(
            query_change_summaries(&db, principal, None, 10, 10)
                .await
                .unwrap()
                .items
                .len(),
            1
        );

        crate::store::update_record(&db, &context_record_ids[1], json!({"kind":"milestone"}))
            .await
            .unwrap();
        let semantic_scope_changed = query_change_summaries(&db, principal, None, 10, 10)
            .await
            .unwrap();
        assert!(semantic_scope_changed.items.is_empty());
        crate::store::update_record(&db, &context_record_ids[1], json!({"kind":"impact"}))
            .await
            .unwrap();
        assert_eq!(
            query_change_summaries(&db, principal, None, 10, 10)
                .await
                .unwrap()
                .items
                .len(),
            1
        );

        crate::store::update_record(
            &db,
            &context_record_ids[0],
            json!({"body":"The contextual decision changed after confirmation."}),
        )
        .await
        .unwrap();
        let scope_changed = query_change_summaries(&db, principal, None, 10, 10)
            .await
            .unwrap();
        assert!(scope_changed.items.is_empty());
    }
}
