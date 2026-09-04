//! Generic, product-neutral derived-state substrate.
//!
//! `derivation_events` is an independent authoritative log. Its projections
//! retain stable series, immutable successful revisions, exact input
//! manifests, and failed attempts. Product workflows bind their own records
//! and semantics to this substrate; the substrate itself does not assign a
//! special record kind to a recipe or output.

mod applicability;
mod bindings;
mod confirmation;
mod events;
mod integrity;
mod persistence;
mod projector;
mod requests;
mod series;

pub use bindings::{
    bind_target, detach_target, inspect_target, publish_record_body_revision,
    DerivationBindingInspection, DerivationPublicationInspection, DerivationTarget,
    DerivationTargetBound, DerivationTargetDetached, DerivationTargetHead,
    DerivationTargetInspection, DerivationTargetPublished, PublishRecordBodyRevision,
    PublishedRecordBodyRevision,
};
pub use confirmation::{
    assign_artifact_role, confirm_revision, inspect_confirmed_artifact, query_confirmed_artifacts,
    retire_artifact_role, retract_confirmation, ArtifactRoleAssigned, ArtifactRoleRetired,
    ConfirmationRetracted, ConfirmedArtifactCursor, ConfirmedArtifactInspection,
    ConfirmedArtifactPage, CurrentRevisionBasisResolver, OutputContractSelector,
    RequestRevisionApplicabilityGate, RevisionApplicabilityGate, RevisionConfirmed,
    RevisionRecognitionBasis, SourceRunCursor, SourceRunInspection, CHANGE_SUMMARY_ROLE,
    MAX_CONFIRMED_ARTIFACT_PAGE_LIMIT, MAX_SOURCE_RUN_PAGE_LIMIT,
};
pub(crate) use confirmation::{confirm_revision_in, retract_confirmation_in};
pub use events::{
    canonical_json, digest_json, CanonicalDerivationRequest, DerivationAttemptFailed,
    DerivationEventPayload, DerivationEventRow, DerivationInput, DerivationOutputRef,
    DerivationRevisionCompleted, DerivationSeriesCreated, EffectiveSourceBoundary,
    NewDerivationEvent, RecipeRevisionRef, DERIVATION_EVENT_SCHEMA_VERSION, DERIVATION_EVENT_TYPES,
};
pub use integrity::state_violations;
#[allow(unused_imports)]
pub(crate) use persistence::append_derivation_event_in;
pub use persistence::{read_all_derivation_events, replay_derivations};
#[allow(unused_imports)]
pub(crate) use requests::acquire_or_steal_request_in;
pub use requests::{
    acquire_or_steal_request, audience_policy_sha256, complete_request_with_publication,
    create_or_join_request, fail_request, inspect_request, renew_request,
    revision_audience_is_available, wait_for_request, AcquireRequestResult,
    CompleteDerivationRequest, CreateOrJoinRequest, CreatedOrJoinedRequest,
    DerivationAudiencePolicy, DerivationAudiencePrincipal, DerivationExecutionUsage,
    DerivationExecutorDescriptor, DerivationRequestFailure, DerivationRequestLease,
    DerivationRequestSnapshot, DerivationRequestSpec, DerivationRequestState, RequestWaitOutcome,
    DERIVATION_AUDIENCE_SCHEMA, MAX_DERIVATION_LEASE_DURATION, MAX_DERIVATION_WAIT_DURATION,
};
pub(crate) use requests::{create_or_join_request_in, inspect_request_in};
pub(crate) use series::create_or_get_series_for_recipe_in;
pub use series::{
    create_or_get_series_for_recipe, inspect_series, inspect_series_by_key,
    CreateOrGetDerivationSeries, CreatedOrExistingDerivationSeries, DerivationSeriesInspection,
};

/// Acquire a durable derivation request only while its pinned governed recipe
/// release is eligible in the same serialized database snapshot.
///
/// Successful execution remains separate from explicit result confirmation;
/// this function only performs the authorization/status fence and lease
/// mutation needed to begin an attempt.
pub async fn acquire_request_for_controlled_execution(
    db: &crate::db::Db,
    principal: crate::authorization::Principal<'_>,
    request_id: &str,
    owner: &str,
    run_key: Option<&str>,
    expected_recipe_status_event_seq: i64,
    lease_duration: std::time::Duration,
) -> crate::Result<AcquireRequestResult> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let Some(request) = requests::inspect_request_in(&mut tx, request_id).await? else {
        tx.rollback().await?;
        return Ok(AcquireRequestResult::NotFound);
    };
    let definition_sha256: Option<String> =
        sqlx::query_scalar("SELECT definition_sha256 FROM derivation_series WHERE id=?")
            .bind(&request.spec.series_id)
            .fetch_optional(&mut *tx)
            .await?;
    if definition_sha256.as_deref() != Some(request.spec.definition_sha256.as_str()) {
        return Err(crate::Error::engine(
            "derivation request definition digest does not match its stable series",
        ));
    }
    let pinned_recipe = &request.spec.recipe_revision;
    let release = crate::recipe::require_recipe_release_for_execution_on(
        &mut tx,
        principal,
        &pinned_recipe.definition_id,
        &pinned_recipe.publication_id,
        expected_recipe_status_event_seq,
    )
    .await?;
    if release.descriptor_sha256 != pinned_recipe.sha256 {
        return Err(crate::Error::engine(
            "derivation request recipe digest does not match its governed release",
        ));
    }
    let result =
        requests::acquire_or_steal_request_in(&mut tx, request_id, owner, run_key, lease_duration)
            .await?;
    if matches!(result, AcquireRequestResult::Acquired(_)) {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(result)
}

#[cfg(test)]
mod binding_tests;
#[cfg(test)]
mod confirmation_tests;
#[cfg(test)]
mod request_tests;
#[cfg(test)]
mod tests;
pub use applicability::{
    compute_applicability, revision_applicability_basis, DerivationApplicability,
    DerivationApplicabilityBasis,
};
