//! Governed semantic relationship definitions and proposition identity.
//!
//! These definitions describe semantics and admission only. They deliberately
//! have no capability-effect field: a relationship can never grant record
//! View, Edit, or Manage authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Error, Result};

// Phase 2 deliberately lands crate-private kernel seams before the Phase 3/5
// provenance and MCP callers. Keep them non-public without making that staged
// integration produce a wall of dead-code warnings.
#[allow(dead_code)]
mod events;
#[allow(dead_code)]
mod federation;
#[allow(dead_code)]
mod integrity;
#[cfg(test)]
mod kernel_tests;
pub(crate) mod legacy;
#[allow(dead_code)]
mod persistence;
#[allow(dead_code)]
mod projector;
mod reducer;

#[allow(unused_imports)]
pub(crate) use events::*;
#[allow(unused_imports)]
pub(crate) use federation::{
    export_native_relationships, ingest_verified_native_relationships, RelationshipExportStream,
    RelationshipFederationBackend, RelationshipFederationIngestResult,
    VerifiedRelationshipEnvelopeContext,
};
#[allow(unused_imports)]
pub(crate) use integrity::relationship_state_violations;
pub(crate) use native_relationship_kernel::CausalAssertionParent;
#[allow(unused_imports)] // Phase 3/5 consume the caller-owned transaction seam.
pub(crate) use persistence::{
    append_relationship_event_in, create_relationship_with_assertion,
    create_relationship_with_assertion_in, prepare_relationship_with_assertion,
};
pub(crate) use projector::{
    initialize_receiver_local_state_after_import_in,
    project_receiver_local_admissions_for_outputs_in, read_all_relationship_events,
    rebuild_receiver_local_state_in, refresh_receiver_local_admissions_for_attestation_in,
    replay_relationship_events, ReceiverAdmissionDecision,
};
pub const RELATIONSHIP_TYPE_SCHEMA_VERSION: u64 = 1;
pub const CORE_RELATIONSHIP_TYPE_MANIFEST_JSON: &str = include_str!("core_relationship_types.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointSemantics {
    Directed,
    Symmetric,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedRecordKind {
    pub record_type: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRule {
    pub role: String,
    pub minimum: u64,
    pub maximum: u64,
    pub allowed_record_kinds: Vec<AllowedRecordKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRoute {
    EditSubjectViewObject,
    EditEitherAnchorViewBoth,
    VerifiedEndpointBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityAnchorRule {
    Subject,
    EitherEndpoint,
    BoundEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionAdmissionClass {
    pub id: String,
    pub stance: String,
    pub route: AdmissionRoute,
    pub authority_anchor: AuthorityAnchorRule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReducerDefinition {
    pub id: String,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationLabels {
    pub forward: String,
    pub inverse: String,
    pub proposition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipTypeDefinition {
    pub schema_version: u64,
    pub id: String,
    pub relationship_type: String,
    pub endpoint_semantics: EndpointSemantics,
    pub endpoints: Vec<EndpointRule>,
    pub identity_bearing_qualifiers: Vec<String>,
    pub assertion_admission_classes: Vec<AssertionAdmissionClass>,
    pub reducer: ReducerDefinition,
    pub labels: PresentationLabels,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreRelationshipTypeManifest {
    pub schema_version: u64,
    pub relationship_types: Vec<RelationshipTypeDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropositionEndpoint {
    pub role: String,
    pub portable_ref: String,
}

pub fn core_relationship_type_manifest() -> Result<CoreRelationshipTypeManifest> {
    let manifest: CoreRelationshipTypeManifest =
        serde_json::from_str(CORE_RELATIONSHIP_TYPE_MANIFEST_JSON)?;
    if manifest.schema_version != RELATIONSHIP_TYPE_SCHEMA_VERSION {
        return Err(Error::engine(format!(
            "relationship manifest schema_version must be {RELATIONSHIP_TYPE_SCHEMA_VERSION}"
        )));
    }
    let mut types = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for definition in &manifest.relationship_types {
        definition.validate()?;
        if !types.insert(definition.relationship_type.as_str()) {
            return Err(Error::engine("duplicate governed relationship type"));
        }
        if !ids.insert(definition.id.as_str()) {
            return Err(Error::engine("duplicate relationship type definition id"));
        }
    }
    Ok(manifest)
}

impl RelationshipTypeDefinition {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RELATIONSHIP_TYPE_SCHEMA_VERSION
            || self.id != format!("{}.v{}", self.relationship_type, self.schema_version)
        {
            return Err(Error::engine(
                "invalid relationship type definition identity",
            ));
        }
        if self.relationship_type.trim().is_empty()
            || self.reducer.id.trim().is_empty()
            || self.reducer.version == 0
            || self.labels.forward.trim().is_empty()
            || self.labels.inverse.trim().is_empty()
            || self.labels.proposition.trim().is_empty()
        {
            return Err(Error::engine(
                "relationship type definition contains a blank field",
            ));
        }
        let mut roles = BTreeSet::new();
        for endpoint in &self.endpoints {
            if endpoint.role.trim().is_empty()
                || endpoint.minimum == 0
                || endpoint.maximum < endpoint.minimum
                || endpoint.allowed_record_kinds.is_empty()
                || !roles.insert(endpoint.role.as_str())
            {
                return Err(Error::engine("invalid relationship endpoint rule"));
            }
            for allowed in &endpoint.allowed_record_kinds {
                if allowed.record_type.trim().is_empty() || allowed.kind.trim().is_empty() {
                    return Err(Error::engine("blank allowed relationship endpoint kind"));
                }
            }
        }
        if self.endpoint_semantics == EndpointSemantics::Symmetric
            && (self.endpoints.len() != 1
                || self.endpoints[0].minimum != 2
                || self.endpoints[0].maximum != 2)
        {
            return Err(Error::engine(
                "symmetric relationship definitions require one two-member endpoint role",
            ));
        }
        if self.endpoint_semantics == EndpointSemantics::Directed
            && (self.endpoints.len() != 2
                || self
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.minimum != 1 || endpoint.maximum != 1))
        {
            return Err(Error::engine(
                "directed relationship definitions require two singleton endpoint roles",
            ));
        }
        let qualifier_count = self
            .identity_bearing_qualifiers
            .iter()
            .collect::<BTreeSet<_>>()
            .len();
        if qualifier_count != self.identity_bearing_qualifiers.len()
            || self
                .identity_bearing_qualifiers
                .iter()
                .any(|qualifier| qualifier.trim().is_empty())
        {
            return Err(Error::engine("invalid identity-bearing qualifiers"));
        }
        if self.assertion_admission_classes.is_empty()
            || self.assertion_admission_classes.iter().any(|class| {
                class.id.trim().is_empty()
                    || !matches!(class.stance.as_str(), "support" | "contest")
            })
        {
            return Err(Error::engine("invalid assertion admission class"));
        }
        Ok(())
    }

    /// Stable local reconciliation key. The definition id makes semantic
    /// revisions distinct. Symmetric endpoints are sorted by their canonical
    /// portable encoding; directed endpoint roles remain ordered.
    pub fn canonical_proposition_key(
        &self,
        endpoints: &[PropositionEndpoint],
        qualifiers: &BTreeMap<String, Value>,
    ) -> Result<String> {
        self.validate()?;
        let expected_qualifiers = self
            .identity_bearing_qualifiers
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let actual_qualifiers = qualifiers
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if actual_qualifiers != expected_qualifiers {
            return Err(Error::engine(
                "proposition qualifiers do not match the governed identity contract",
            ));
        }
        let mut encoded = endpoints
            .iter()
            .map(|endpoint| {
                if endpoint.role.trim().is_empty() || endpoint.portable_ref.trim().is_empty() {
                    return Err(Error::engine("proposition endpoint must not be blank"));
                }
                Ok(json!({"role":endpoint.role,"portable_ref":endpoint.portable_ref}))
            })
            .collect::<Result<Vec<_>>>()?;
        let supplied_role_counts =
            endpoints
                .iter()
                .fold(BTreeMap::new(), |mut counts, endpoint| {
                    *counts.entry(endpoint.role.as_str()).or_insert(0_u64) += 1;
                    counts
                });
        if supplied_role_counts.len() != self.endpoints.len()
            || self.endpoints.iter().any(|rule| {
                let count = supplied_role_counts
                    .get(rule.role.as_str())
                    .copied()
                    .unwrap_or(0);
                count < rule.minimum || count > rule.maximum
            })
            || supplied_role_counts
                .keys()
                .any(|role| !self.endpoints.iter().any(|rule| rule.role == *role))
        {
            return Err(Error::engine(
                "proposition endpoints do not satisfy governed role cardinality",
            ));
        }
        if self.endpoint_semantics == EndpointSemantics::Symmetric {
            encoded.sort_by_key(crate::derivation::canonical_json);
        } else {
            let role_order = self
                .endpoints
                .iter()
                .enumerate()
                .map(|(ordinal, rule)| (rule.role.as_str(), ordinal))
                .collect::<BTreeMap<_, _>>();
            if encoded.len() != role_order.len()
                || encoded.iter().any(|endpoint| {
                    endpoint["role"]
                        .as_str()
                        .is_none_or(|role| !role_order.contains_key(role))
                })
            {
                return Err(Error::engine(
                    "directed proposition endpoints do not match governed roles",
                ));
            }
            encoded.sort_by_key(|endpoint| {
                endpoint["role"]
                    .as_str()
                    .and_then(|role| role_order.get(role))
                    .copied()
                    .unwrap_or(usize::MAX)
            });
        }
        Ok(crate::derivation::digest_json(&json!({
            "relationship_type_definition": self.id,
            "endpoints": encoded,
            "qualifiers": qualifiers,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_closed_complete_and_has_no_capability_effect() {
        let manifest = core_relationship_type_manifest().unwrap();
        assert_eq!(
            manifest
                .relationship_types
                .iter()
                .map(|definition| definition.relationship_type.as_str())
                .collect::<Vec<_>>(),
            [
                "relates_to",
                "depends_on",
                "blocks",
                "assigned_to",
                "answerable_by"
            ]
        );
        assert!(!CORE_RELATIONSHIP_TYPE_MANIFEST_JSON.contains("capability"));
        let mut value: Value = serde_json::from_str(CORE_RELATIONSHIP_TYPE_MANIFEST_JSON).unwrap();
        value["relationship_types"][0]["capability_effect"] = json!("manage");
        assert!(serde_json::from_value::<CoreRelationshipTypeManifest>(value).is_err());
    }

    #[test]
    fn symmetric_keys_ignore_endpoint_order_but_directed_keys_do_not() {
        let manifest = core_relationship_type_manifest().unwrap();
        let definition = |name: &str| {
            manifest
                .relationship_types
                .iter()
                .find(|definition| definition.relationship_type == name)
                .unwrap()
        };
        let a = PropositionEndpoint {
            role: "participant".into(),
            portable_ref: "native-record:db:a".into(),
        };
        let b = PropositionEndpoint {
            role: "participant".into(),
            portable_ref: "native-record:db:b".into(),
        };
        let qualifiers = BTreeMap::new();
        assert_eq!(
            definition("relates_to")
                .canonical_proposition_key(&[a.clone(), b.clone()], &qualifiers)
                .unwrap(),
            definition("relates_to")
                .canonical_proposition_key(&[b, a], &qualifiers)
                .unwrap()
        );
        let subject = PropositionEndpoint {
            role: "subject".into(),
            portable_ref: "native-record:db:a".into(),
        };
        let object = PropositionEndpoint {
            role: "object".into(),
            portable_ref: "native-record:db:b".into(),
        };
        assert_eq!(
            definition("depends_on")
                .canonical_proposition_key(&[subject.clone(), object.clone()], &qualifiers)
                .unwrap(),
            definition("depends_on")
                .canonical_proposition_key(&[object.clone(), subject.clone()], &qualifiers)
                .unwrap()
        );
        let swapped_subject = PropositionEndpoint {
            role: "subject".into(),
            portable_ref: object.portable_ref.clone(),
        };
        let swapped_object = PropositionEndpoint {
            role: "object".into(),
            portable_ref: subject.portable_ref.clone(),
        };
        assert_ne!(
            definition("depends_on")
                .canonical_proposition_key(&[subject, object], &qualifiers)
                .unwrap(),
            definition("depends_on")
                .canonical_proposition_key(&[swapped_subject, swapped_object], &qualifiers)
                .unwrap()
        );
    }

    #[test]
    fn proposition_keys_reject_invalid_endpoint_role_cardinality() {
        let manifest = core_relationship_type_manifest().unwrap();
        let definition = |name: &str| {
            manifest
                .relationship_types
                .iter()
                .find(|definition| definition.relationship_type == name)
                .unwrap()
        };
        let endpoint = |role: &str, suffix: &str| PropositionEndpoint {
            role: role.into(),
            portable_ref: format!("native-record:db:{suffix}"),
        };
        let qualifiers = BTreeMap::new();
        for invalid in [
            vec![endpoint("participant", "a")],
            vec![
                endpoint("participant", "a"),
                endpoint("participant", "b"),
                endpoint("participant", "c"),
            ],
            vec![endpoint("participant", "a"), endpoint("subject", "b")],
        ] {
            assert!(definition("relates_to")
                .canonical_proposition_key(&invalid, &qualifiers)
                .is_err());
        }
        for invalid in [
            vec![endpoint("subject", "a")],
            vec![endpoint("subject", "a"), endpoint("subject", "b")],
            vec![endpoint("subject", "a"), endpoint("other", "b")],
        ] {
            assert!(definition("depends_on")
                .canonical_proposition_key(&invalid, &qualifiers)
                .is_err());
        }
    }
}
