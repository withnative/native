//! Pure, request-relative applicability over immutable basis vectors.
//!
//! No state is invalidated or refreshed here. Callers resolve the requested
//! basis and current audience proof separately, then compare values.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

use super::{
    CanonicalDerivationRequest, DerivationRequestSpec, EffectiveSourceBoundary, RecipeRevisionRef,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationApplicability {
    Current,
    Behind,
    ScopeChanged,
    DefinitionChanged,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationApplicabilityBasis {
    pub series_id: String,
    pub definition_sha256: String,
    pub canonical_request: CanonicalDerivationRequest,
    pub recipe_revision: RecipeRevisionRef,
    pub effective_source_boundary: EffectiveSourceBoundary,
    pub target_basis: Value,
    pub budget: Value,
    pub audience_sha256: String,
}

impl From<&DerivationRequestSpec> for DerivationApplicabilityBasis {
    fn from(value: &DerivationRequestSpec) -> Self {
        Self {
            series_id: value.series_id.clone(),
            definition_sha256: value.definition_sha256.clone(),
            canonical_request: value.canonical_request.clone(),
            recipe_revision: value.recipe_revision.clone(),
            effective_source_boundary: value.effective_source_boundary.clone(),
            target_basis: value.target_basis.clone(),
            budget: value.budget.clone(),
            audience_sha256: value.audience_sha256.clone(),
        }
    }
}

pub fn revision_applicability_basis(
    series_id: &str,
    definition_sha256: &str,
    canonical_request: CanonicalDerivationRequest,
    recipe_revision: RecipeRevisionRef,
    effective_source_boundary: EffectiveSourceBoundary,
    completion_metadata: &Value,
) -> Result<DerivationApplicabilityBasis> {
    let target_basis = completion_metadata
        .get("target_basis")
        .cloned()
        .ok_or_else(|| Error::engine("derivation completion is missing its target basis"))?;
    let budget = completion_metadata
        .get("budget")
        .cloned()
        .ok_or_else(|| Error::engine("derivation completion is missing its budget"))?;
    let audience_sha256 = completion_metadata
        .pointer("/audience/sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::engine("derivation completion is missing its audience digest"))?;
    Ok(DerivationApplicabilityBasis {
        series_id: series_id.into(),
        definition_sha256: definition_sha256.into(),
        canonical_request,
        recipe_revision,
        effective_source_boundary,
        target_basis,
        budget,
        audience_sha256: audience_sha256.into(),
    })
}

/// Compare a requested immutable basis to one completed revision basis.
///
/// `audience_available` is the caller's fail-closed revalidation result. This
/// function is deliberately pure: it performs no reads, writes, invalidation,
/// queueing, or request admission.
pub fn compute_applicability(
    requested: &DerivationApplicabilityBasis,
    revision: &DerivationApplicabilityBasis,
    audience_available: bool,
) -> DerivationApplicability {
    if !audience_available {
        return DerivationApplicability::Unavailable;
    }
    if requested.series_id != revision.series_id
        || requested.definition_sha256 != revision.definition_sha256
        || requested.canonical_request != revision.canonical_request
        || requested.recipe_revision != revision.recipe_revision
        || requested.target_basis != revision.target_basis
        || requested.budget != revision.budget
        || requested.audience_sha256 != revision.audience_sha256
        || requested.effective_source_boundary.after_seq
            != revision.effective_source_boundary.after_seq
        || requested.effective_source_boundary.metadata
            != revision.effective_source_boundary.metadata
    {
        return DerivationApplicability::DefinitionChanged;
    }
    if requested
        .effective_source_boundary
        .resolved_scope_membership_sha256
        != revision
            .effective_source_boundary
            .resolved_scope_membership_sha256
    {
        return DerivationApplicability::ScopeChanged;
    }
    match requested
        .effective_source_boundary
        .through_seq
        .cmp(&revision.effective_source_boundary.through_seq)
    {
        std::cmp::Ordering::Equal => DerivationApplicability::Current,
        std::cmp::Ordering::Greater => DerivationApplicability::Behind,
        std::cmp::Ordering::Less => DerivationApplicability::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn basis() -> DerivationApplicabilityBasis {
        DerivationApplicabilityBasis {
            series_id: "series:one".into(),
            definition_sha256: "1".repeat(64),
            canonical_request: CanonicalDerivationRequest {
                query_contract: "native.test.v1".into(),
                query_contract_version: 1,
                selection: json!({"all":true}),
                scope: json!({"collection":"one"}),
            },
            recipe_revision: RecipeRevisionRef {
                definition_id: "recipe:one".into(),
                publication_id: "publication:one".into(),
                sha256: "2".repeat(64),
            },
            effective_source_boundary: EffectiveSourceBoundary {
                after_seq: Some(0),
                through_seq: 10,
                resolved_scope_membership_sha256: "3".repeat(64),
                metadata: json!({}),
            },
            target_basis: json!({"binding_generation":1,"target_version":1}),
            budget: json!({"max_output_tokens":100}),
            audience_sha256: "4".repeat(64),
        }
    }

    #[test]
    fn applicability_matrix_is_request_relative_and_pure() {
        let revision = basis();
        assert_eq!(
            compute_applicability(&revision, &revision, true),
            DerivationApplicability::Current
        );
        let mut requested = revision.clone();
        requested.effective_source_boundary.through_seq = 11;
        assert_eq!(
            compute_applicability(&requested, &revision, true),
            DerivationApplicability::Behind
        );
        requested = revision.clone();
        requested
            .effective_source_boundary
            .resolved_scope_membership_sha256 = "5".repeat(64);
        assert_eq!(
            compute_applicability(&requested, &revision, true),
            DerivationApplicability::ScopeChanged
        );
        requested = revision.clone();
        requested.budget = json!({"max_output_tokens":101});
        assert_eq!(
            compute_applicability(&requested, &revision, true),
            DerivationApplicability::DefinitionChanged
        );
        assert_eq!(
            compute_applicability(&revision, &revision, false),
            DerivationApplicability::Unavailable
        );
    }
}
