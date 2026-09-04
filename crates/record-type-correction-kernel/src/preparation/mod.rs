//! Deterministic facts-to-preparation transform for governed record type
//! correction.
//!
//! Physical adapters own authorization, transaction/snapshot coherence, SQL,
//! error mapping and execution-time revalidation. Everything downstream of a
//! coherent snapshot — blocker wording, eligibility inputs, dependency
//! evidence, operation evidence, effect JSON, effect summary, canonical source
//! arguments and both digests — lives here so that identical facts produce
//! byte-identical canonical evidence on every backend.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{classify, Classification, ClassificationInput, Identity, MechanicalReason};

/// Guidance repeated in every prepared effect. Owned here so no adapter can
/// drift the wording a caller reads.
pub const NEW_BEARER_GUIDANCE: &str = "If identity continuity is ambiguous, create the correctly typed bearer explicitly; this operation never copies, relinks, archives or retires records.";

const CONFIRMED_APPROVAL: &str = "Human confirmation required before execution";
const AUTONOMOUS_APPROVAL: &str = "Autonomous same-run correction eligible";

/// Every governed blocker this operation can raise, with its canonical code
/// and detail.
///
/// Several `specialised_target_shape` variants exist on purpose: the three
/// adapters word that blocker differently today, and this refactor preserves
/// user-visible behaviour rather than unifying it. Naming each wording keeps
/// the strings in exactly one place while leaving the choice of wording with
/// the adapter that can actually observe the fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blocker {
    /// Engine-provisioned filing records have immutable identity.
    EngineFilingRecord,
    /// A `Message` target must be created atomically with its audience state.
    MessageTargetShape,
    /// A governed or targeted `Annotation` target must be created atomically.
    GovernedAnnotationTargetShape,
    /// Combined specialised-target wording used where the adapter does not
    /// distinguish `Message` from governed `Annotation` targets.
    SpecialisedTargetShape,
    /// A `Program` target whose governed kind or interpreter runtime does not
    /// match, as detected without the shared prospective-program validator.
    ProgramRuntimeTargetShape,
    /// The shared prospective-program validator rejected the target shape.
    ProspectiveProgramShape { detail: String },
    /// Semantic `Unit` identity cannot be corrected.
    SemanticUnit,
    /// A targeted `Annotation` cannot be corrected.
    TargetedAnnotation,
    /// Governed attribution identity cannot be corrected.
    GovernedAttribution,
    /// A `Message` with non-local delivery state cannot be corrected.
    MessageDeliveryState,
    /// Published artifact/module/recipe/derivation state fixes identity.
    SpecialisedAggregate,
    /// A preserved external identity binding rejects the target type/kind.
    IncompatibleIdentityBinding,
    /// Preserved state is missing a facet the target shape requires.
    RequiredFacetMissing { facet: String },
    /// Preserved facet values fail an absolute predicate of the target shape.
    IncompatibleFacetValue { detail: String },
}

impl Blocker {
    /// Canonical mechanical code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EngineFilingRecord => "engine_filing_record",
            Self::MessageTargetShape
            | Self::GovernedAnnotationTargetShape
            | Self::SpecialisedTargetShape
            | Self::ProgramRuntimeTargetShape
            | Self::ProspectiveProgramShape { .. } => "specialised_target_shape",
            Self::SemanticUnit => "semantic_unit",
            Self::TargetedAnnotation => "targeted_annotation",
            Self::GovernedAttribution => "governed_attribution",
            Self::MessageDeliveryState => "message_delivery_state",
            Self::SpecialisedAggregate => "specialised_aggregate",
            Self::IncompatibleIdentityBinding => "incompatible_identity_binding",
            Self::RequiredFacetMissing { .. } => "required_facet_missing",
            Self::IncompatibleFacetValue { .. } => "incompatible_facet_value",
        }
    }

    /// Canonical human-readable detail.
    pub fn detail(&self) -> String {
        match self {
            Self::EngineFilingRecord => {
                "engine-provisioned filing records have immutable identity".into()
            }
            Self::MessageTargetShape => {
                "Message identity must be created atomically with its audience state".into()
            }
            Self::GovernedAnnotationTargetShape => {
                "governed or targeted Annotation identity must be created atomically".into()
            }
            Self::SpecialisedTargetShape => {
                "the target identity must be created atomically with its specialised state".into()
            }
            Self::ProgramRuntimeTargetShape => {
                "Program correction requires its governed kind and exact interpreter runtime".into()
            }
            Self::ProspectiveProgramShape { detail } => detail.clone(),
            Self::SemanticUnit => "semantic Unit identity cannot be corrected".into(),
            Self::TargetedAnnotation => "a targeted Annotation cannot be corrected".into(),
            Self::GovernedAttribution => "governed attribution identity cannot be corrected".into(),
            Self::MessageDeliveryState => {
                "a Message with non-local delivery state cannot be corrected".into()
            }
            Self::SpecialisedAggregate => {
                "published artifact, module, recipe, or derivation state fixes this bearer's identity"
                    .into()
            }
            Self::IncompatibleIdentityBinding => {
                "a preserved external identity binding rejects the target type/kind".into()
            }
            Self::RequiredFacetMissing { facet } => {
                format!("preserved state is missing target-required facet '{facet}'")
            }
            Self::IncompatibleFacetValue { detail } => detail.clone(),
        }
    }

    /// Canonical reason carried into classification and the prepared effect.
    pub fn reason(&self) -> MechanicalReason {
        MechanicalReason {
            code: self.code().into(),
            detail: self.detail(),
        }
    }
}

/// One coherent, backend-neutral snapshot of everything the deterministic
/// transform needs.
///
/// Fields carry semantic names rather than backend row shapes: an adapter is
/// responsible for translating its own projection into these facts inside the
/// transaction that observed them.
#[derive(Clone, Debug)]
pub struct CorrectionFacts {
    /// Bearer whose identity is being corrected.
    pub record_id: String,
    /// Caller-supplied reason, already validated as non-blank by the adapter.
    pub reason: String,
    /// Bearer name as preserved by the correction.
    pub name: String,
    /// Digest of the preserved body; a correction never re-embeds it.
    pub body_digest: String,
    /// Bearer `updated_at` exactly as the adapter renders timestamps.
    pub updated_at: String,
    /// Highest authoritative content sequence before this correction.
    pub previous_seq: i64,
    /// Backend schema-state fence token.
    pub schema_state_revision: String,
    /// Stored identity before correction.
    pub current: Identity,
    /// Canonical target identity (target kind already canonicalized).
    pub target: Identity,
    /// Whether the target type/kind is active governed identity.
    pub target_active: bool,
    /// First-slice unique registry-provable wrong-type rule.
    pub unique_wrong_type_match: bool,
    /// Whether every relevant contribution belongs to the creating run.
    pub same_run_provenance: bool,
    /// Exact counts of preserved dependent state, by category.
    pub preserved_state_counts: BTreeMap<String, i64>,
    /// Bounded identifier previews of preserved dependent state, by category.
    pub bounded_identifiers: BTreeMap<String, Vec<String>>,
    /// Backend-specific append-only fence material folded into the dependency
    /// evidence object. Adapters differ in which logs they can fence on, and
    /// those differences are load-bearing, so the names and values stay with
    /// the adapter while the surrounding evidence shape stays here.
    pub dependency_fences: BTreeMap<String, Value>,
    /// Governed blockers the adapter observed.
    pub blockers: Vec<Blocker>,
}

/// The deterministic preparation derived from one [`CorrectionFacts`].
#[derive(Clone, Debug)]
pub struct CorrectionPlan {
    facts: CorrectionFacts,
    classification: Classification,
    bounded_identifiers_truncated: BTreeMap<String, bool>,
    dependency_evidence: Value,
    dependency_digest: String,
}

/// The signed preparation an executor consumes.
#[derive(Clone, Debug, Serialize)]
pub struct PreparedCorrection {
    pub canonical_source_arguments: Value,
    pub target_id: String,
    pub target: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect: Value,
    pub effect_summary: String,
    pub operation_evidence: Value,
}

/// Canonical digest of any correction evidence object: RFC 8785 canonical JSON
/// hashed with SHA-256 and rendered lowercase hex.
pub fn correction_digest(value: &Value) -> Result<String, serde_json::Error> {
    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(value)?)))
}

impl CorrectionPlan {
    /// Derive blockers, eligibility, dependency evidence and its digest.
    pub fn new(facts: CorrectionFacts) -> Result<Self, serde_json::Error> {
        let bounded_identifiers_truncated = facts
            .preserved_state_counts
            .iter()
            .map(|(key, count)| {
                (
                    key.clone(),
                    usize::try_from(*count).unwrap_or(usize::MAX)
                        > facts.bounded_identifiers.get(key).map_or(0, Vec::len),
                )
            })
            .collect::<BTreeMap<_, _>>();
        // A bounded preview must never turn an uninspected tail into
        // autonomous proof. The exact counts remain visible; execution can
        // proceed only as a confirmed correction when any identifier list was
        // truncated, when independent relationship or binding state exists, or
        // when provenance is not wholly the creating run's.
        let shared_use = !facts.same_run_provenance
            || facts
                .preserved_state_counts
                .get("relationships")
                .is_some_and(|count| *count > 0)
            || facts
                .preserved_state_counts
                .get("bindings")
                .is_some_and(|count| *count > 0)
            || bounded_identifiers_truncated.values().any(|value| *value);

        let classification = classify(ClassificationInput {
            current: facts.current.clone(),
            target: facts.target.clone(),
            target_active: facts.target_active,
            unique_wrong_type_match: facts.unique_wrong_type_match,
            same_run_provenance: facts.same_run_provenance,
            shared_use,
            blockers: facts.blockers.iter().map(Blocker::reason).collect(),
        });

        let mut dependency_evidence = json!({
            "previous_seq": facts.previous_seq,
            "updated_at": facts.updated_at,
            "schema_state_revision": facts.schema_state_revision,
            "counts": facts.preserved_state_counts,
            "bounded_ids": facts.bounded_identifiers,
        });
        let object = dependency_evidence
            .as_object_mut()
            .expect("dependency evidence is a JSON object");
        for (key, value) in &facts.dependency_fences {
            object.insert(key.clone(), value.clone());
        }
        let dependency_digest = correction_digest(&dependency_evidence)?;

        Ok(Self {
            facts,
            classification,
            bounded_identifiers_truncated,
            dependency_evidence,
            dependency_digest,
        })
    }

    pub fn facts(&self) -> &CorrectionFacts {
        &self.facts
    }

    pub fn classification(&self) -> &Classification {
        &self.classification
    }

    pub fn dependency_evidence(&self) -> &Value {
        &self.dependency_evidence
    }

    pub fn dependency_digest(&self) -> &str {
        &self.dependency_digest
    }

    pub fn confirmation_required(&self) -> bool {
        self.classification.eligibility.confirmation_required()
    }

    /// Canonical executor argument binding preparation to execution.
    pub fn execution_mode(&self) -> &'static str {
        self.classification.eligibility.execution_mode()
    }

    pub fn previous_seq(&self) -> i64 {
        self.facts.previous_seq
    }

    pub fn schema_state_revision(&self) -> &str {
        &self.facts.schema_state_revision
    }

    pub fn body_digest(&self) -> &str {
        &self.facts.body_digest
    }

    /// Prepared effect exactly as a caller reads it.
    pub fn effect(&self) -> Value {
        json!({
            "current": self.classification.current,
            "target": self.classification.target,
            "eligibility": self.classification.eligibility,
            "reasons": self.classification.reasons,
            "preserved_state_counts": self.facts.preserved_state_counts,
            "bounded_identifiers": self.facts.bounded_identifiers,
            "bounded_identifiers_truncated": self.bounded_identifiers_truncated,
            "incompatibilities": self.classification.reasons,
            "revision_guards": {
                "record_content_seq": self.facts.previous_seq,
                "schema_state_revision": self.facts.schema_state_revision,
                "dependent_state_digest": self.dependency_digest,
            },
            "identity_and_body": {
                "record_id_unchanged": true,
                "body_digest_unchanged": self.facts.body_digest,
            },
            "expected_changes": {
                "projection": ["type", "kind", "updated_at", "last_activity_at", "record_version"],
                "derived": ["governed_identity", "capabilities", "dispatch", "current_query_membership"],
            },
            "confirmation_required": self.confirmation_required(),
            "does_not_reembed_body": true,
            "new_bearer_guidance": NEW_BEARER_GUIDANCE,
        })
    }

    /// Operation evidence whose digest fences the prepared target state.
    pub fn operation_evidence(&self) -> Value {
        json!({
            "record_id": self.facts.record_id,
            "name": self.facts.name,
            "updated_at": self.facts.updated_at,
            "previous_seq": self.facts.previous_seq,
            "schema_state_revision": self.facts.schema_state_revision,
            "dependency_digest": self.dependency_digest,
            "confirmation_required": self.confirmation_required(),
        })
    }

    /// Human-facing target label.
    pub fn target_label(&self) -> String {
        format!("{} ({})", self.facts.name, self.facts.record_id)
    }

    /// One-line effect summary.
    pub fn effect_summary(&self) -> String {
        let approval = if self.confirmation_required() {
            CONFIRMED_APPROVAL
        } else {
            AUTONOMOUS_APPROVAL
        };
        format!(
            "{approval}: correct {} from {}/{} to {}/{}; record id and body digest remain unchanged",
            self.target_label(),
            self.classification.current.record_type,
            self.classification.current.kind,
            self.classification.target.record_type,
            self.classification.target.kind,
        )
    }

    /// Canonical arguments an executor must replay verbatim.
    pub fn canonical_source_arguments(&self) -> Value {
        json!({
            "record_id": self.facts.record_id,
            "target_type": self.classification.target.record_type,
            "target_kind": self.classification.target.kind,
            "reason": self.facts.reason,
            "if_content_seq": self.facts.previous_seq,
            "if_schema_state_revision": self.facts.schema_state_revision,
            "if_dependency_digest": self.dependency_digest,
            "mode": self.execution_mode(),
            "confirmation_required": self.confirmation_required(),
        })
    }

    /// Fence token binding content, schema and dependent state together.
    pub fn state_revision(&self) -> String {
        format!(
            "content-seq:{};schema:{};dependencies:{}",
            self.facts.previous_seq, self.facts.schema_state_revision, self.dependency_digest
        )
    }

    /// The whole prepared correction.
    pub fn prepared(&self) -> Result<PreparedCorrection, serde_json::Error> {
        let operation_evidence = self.operation_evidence();
        let target_state_digest = correction_digest(&operation_evidence)?;
        Ok(PreparedCorrection {
            canonical_source_arguments: self.canonical_source_arguments(),
            target_id: self.facts.record_id.clone(),
            target: self.target_label(),
            state_revision: self.state_revision(),
            target_state_digest,
            effect: self.effect(),
            effect_summary: self.effect_summary(),
            operation_evidence,
        })
    }
}

#[cfg(test)]
mod tests;
