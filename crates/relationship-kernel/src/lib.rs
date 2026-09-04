//! Storage-free governed relationship reduction.
//!
//! Physical adapters resolve event pins, load assertion heads, relationship
//! lifecycle state, and endpoint resolution. This crate owns the deterministic
//! effective outcome derived from those facts.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

mod reducer;

/// Immutable cross-assertion causality. The event pin is retained here because
/// it is part of the durable assertion-head serialization and digest contract,
/// even though reduction follows the assertion coordinate after the adapter
/// has verified the pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalAssertionParent {
    pub assertion_issuer_origin_db_id: String,
    pub assertion_id: String,
    pub head_event_issuer_origin_db_id: String,
    pub head_event_id: String,
    pub head_stream_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssertionHead {
    pub issuer_origin_db_id: String,
    pub assertion_id: String,
    pub stream_version: u64,
    pub stance: String,
    pub state: String,
    pub causal_parents: Vec<CausalAssertionParent>,
    /// True only when every causal-parent event pin is present and matches the
    /// named assertion stream, version, and relationship coordinate.
    pub causal_parents_resolved: bool,
    pub last_event_issuer_origin_db_id: String,
    pub last_event_id: String,
    pub local_admission_state: String,
    pub local_admission_class: Option<String>,
    pub local_policy_version: u64,
    pub local_evidence_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationshipProposition<'a> {
    pub relationship_type: &'a str,
    pub type_definition_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveOutcome {
    pub effective_state: &'static str,
    pub epistemic_state: &'static str,
    pub support_count: usize,
    pub contest_count: usize,
    pub admission_counts: BTreeMap<String, usize>,
}

/// Complete production facts for one effective relationship decision.
pub struct ReductionFacts<'a> {
    pub reducer_id: &'a str,
    pub reducer_version: u64,
    pub relationship_active: bool,
    pub endpoints_resolved: bool,
    pub proposition: RelationshipProposition<'a>,
    pub heads: &'a [AssertionHead],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReductionError {
    UnknownVersion,
    UnknownReducer,
}

impl fmt::Display for ReductionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownVersion => "unknown relationship reducer version",
            Self::UnknownReducer => "unknown relationship reducer",
        })
    }
}

impl std::error::Error for ReductionError {}

/// Validate the selected reducer before an adapter performs any contingent
/// physical reads. This preserves fail-closed error precedence while the
/// complete outcome remains owned by [`reduce_effective_relationship`].
pub fn validate_reducer(id: &str, version: u64) -> Result<(), ReductionError> {
    reducer::validate_reducer(id, version)
}

/// Reduce assertion semantics and apply relationship-level precedence once.
///
/// A retired relationship remains retired regardless of assertion evidence.
/// For a live relationship, any unresolved endpoint fails closed after the
/// selected assertion reducer has produced its counts.
pub fn reduce_effective_relationship(
    facts: ReductionFacts<'_>,
) -> Result<EffectiveOutcome, ReductionError> {
    reducer::reduce_effective_relationship(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ORIGIN: &str = "ndb_0123456789abcdef0123456789abcdef";

    #[test]
    fn assertion_head_serialization_preserves_the_durable_digest_shape() {
        let value = serde_json::to_value(AssertionHead {
            issuer_origin_db_id: ORIGIN.into(),
            assertion_id: "child".into(),
            stream_version: 1,
            stance: "support".into(),
            state: "active".into(),
            causal_parents: vec![CausalAssertionParent {
                assertion_issuer_origin_db_id: ORIGIN.into(),
                assertion_id: "parent".into(),
                head_event_issuer_origin_db_id: ORIGIN.into(),
                head_event_id: "00000000-0000-4000-8000-000000000000".into(),
                head_stream_version: 1,
            }],
            causal_parents_resolved: true,
            last_event_issuer_origin_db_id: ORIGIN.into(),
            last_event_id: "00000000-0000-4000-8000-000000000001".into(),
            local_admission_state: "admitted".into(),
            local_admission_class: Some("anchor".into()),
            local_policy_version: 1,
            local_evidence_digest: Some("a".repeat(64)),
        })
        .unwrap();
        assert_eq!(
            value,
            json!({
                "issuer_origin_db_id": ORIGIN,
                "assertion_id": "child",
                "stream_version": 1,
                "stance": "support",
                "state": "active",
                "causal_parents": [{
                    "assertion_issuer_origin_db_id": ORIGIN,
                    "assertion_id": "parent",
                    "head_event_issuer_origin_db_id": ORIGIN,
                    "head_event_id": "00000000-0000-4000-8000-000000000000",
                    "head_stream_version": 1
                }],
                "causal_parents_resolved": true,
                "last_event_issuer_origin_db_id": ORIGIN,
                "last_event_id": "00000000-0000-4000-8000-000000000001",
                "local_admission_state": "admitted",
                "local_admission_class": "anchor",
                "local_policy_version": 1,
                "local_evidence_digest": "a".repeat(64)
            })
        );
    }
}
