use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Error, Result};

use super::{CausalAssertionParent, EndpointSemantics, PropositionEndpoint};

/// Closed migration/compatibility evidence carried only by the internal
/// `legacy_link.v1` definition. Ordinary governed relationship callers cannot
/// populate this envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyLinkEnvelopeV1 {
    pub schema_version: u64,
    pub relationship_token: String,
    pub note: Option<String>,
    pub created_at: String,
    pub source_facts: Vec<LegacyLinkSourceFactV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyLinkSourceFactV1 {
    pub ordinal: u64,
    pub content_event_id: String,
    pub operation: LegacyLinkOperation,
    pub actor: Option<String>,
    pub occurred_at: String,
    pub historical_provenance: LegacyHistoricalProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LegacyLinkOperation {
    Add,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LegacyHistoricalProvenance {
    Missing,
    Single { action_attestation_id: String },
    Multiple { action_attestation_ids: Vec<String> },
}

pub const RELATIONSHIP_EVENT_SCHEMA_VERSION: u64 = 1;
pub const RELATIONSHIP_EVENT_TYPES: [&str; 8] = [
    "relationship.created.v1",
    "relationship.superseded.v1",
    "relationship.retired.v1",
    "assertion.created.v1",
    "assertion.evidence_added.v1",
    "assertion.retracted.v1",
    "assertion.invalidated.v1",
    "assertion.restored.v1",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StreamKind {
    Relationship,
    Assertion,
}

impl StreamKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Relationship => "relationship",
            Self::Assertion => "assertion",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelationshipCoordinate {
    pub relationship_origin_db_id: String,
    pub relationship_id: String,
    pub relationship_revision: u64,
}

impl RelationshipCoordinate {
    pub(crate) fn validate(&self) -> Result<()> {
        if !crate::identity::is_database_id(&self.relationship_origin_db_id) {
            return Err(Error::engine(
                "invalid relationship origin database identity",
            ));
        }
        if !is_canonical_uuid_v4(&self.relationship_id) || self.relationship_revision != 1 {
            return Err(Error::engine("invalid immutable relationship coordinate"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelationshipEventCoordinate {
    pub issuer_origin_db_id: String,
    pub event_id: String,
}

impl RelationshipEventCoordinate {
    fn validate(&self) -> Result<()> {
        if !crate::identity::is_database_id(&self.issuer_origin_db_id)
            || !is_canonical_uuid_v4(&self.event_id)
        {
            return Err(Error::engine("invalid relationship event coordinate"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelationshipEndpoint {
    pub role: String,
    pub portable_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
}

impl RelationshipEndpoint {
    pub(crate) fn proposition_endpoint(&self) -> PropositionEndpoint {
        PropositionEndpoint {
            role: self.role.clone(),
            portable_ref: self.portable_ref.clone(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.role.trim().is_empty() || self.portable_ref.trim().is_empty() {
            return Err(Error::engine("relationship endpoint must not be blank"));
        }
        let (origin, decoded_record_id) =
            crate::identity::decode_native_record(&self.portable_ref)?;
        if let Some(record_id) = self.record_id.as_deref() {
            if record_id.trim().is_empty() || decoded_record_id != record_id {
                return Err(Error::engine(
                    "resolved relationship endpoint does not match its portable reference",
                ));
            }
        }
        if self.record_id.is_some() && !crate::identity::is_database_id(&origin) {
            return Err(Error::engine(
                "invalid resolved relationship endpoint origin",
            ));
        }
        for field in [self.record_type.as_deref(), self.record_kind.as_deref()]
            .into_iter()
            .flatten()
        {
            if field.trim().is_empty() {
                return Err(Error::engine(
                    "relationship endpoint metadata must not be blank",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelationshipCreatedV1 {
    pub schema_version: u64,
    pub relationship_revision: u64,
    pub relationship_type: String,
    pub type_definition_id: String,
    pub endpoint_semantics: EndpointSemantics,
    pub endpoints: Vec<RelationshipEndpoint>,
    pub identity_qualifiers: serde_json::Map<String, Value>,
    pub canonical_proposition_key: String,
    pub reducer_id: String,
    pub reducer_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_link: Option<LegacyLinkEnvelopeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelationshipSupersededV1 {
    pub schema_version: u64,
    pub successor: RelationshipCoordinate,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelationshipRetiredV1 {
    pub schema_version: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginAuthorityAnchor {
    pub endpoint_role: String,
    pub endpoint_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginAdmissionV1 {
    schema_version: u64,
    relationship_type_definition: String,
    admission_class: String,
    authority_anchor: OriginAuthorityAnchor,
    admission_rule: String,
    authorization_decision_digest: String,
    authoring_action_attestation_id: String,
}

fn validate_causal_assertion_parent(parent: &CausalAssertionParent) -> Result<()> {
    if !crate::identity::is_database_id(&parent.assertion_issuer_origin_db_id)
        || !crate::identity::is_database_id(&parent.head_event_issuer_origin_db_id)
        || parent.assertion_issuer_origin_db_id != parent.head_event_issuer_origin_db_id
        || !is_canonical_uuid_v4(&parent.assertion_id)
        || !is_canonical_uuid_v4(&parent.head_event_id)
        || parent.head_stream_version == 0
    {
        return Err(Error::engine("invalid causal assertion parent"));
    }
    Ok(())
}

impl OriginAdmissionV1 {
    pub(crate) fn from_local_authorization(
        authorization: crate::provenance::LocallyAuthorizedOriginAdmission,
    ) -> Self {
        let (
            relationship_type_definition,
            admission_class,
            endpoint_role,
            endpoint_ref,
            admission_rule,
            authorization_decision_digest,
            authoring_action_attestation_id,
        ) = authorization.into_parts();
        Self {
            schema_version: 1,
            relationship_type_definition,
            admission_class,
            authority_anchor: OriginAuthorityAnchor {
                endpoint_role,
                endpoint_ref,
            },
            admission_rule,
            authorization_decision_digest,
            authoring_action_attestation_id,
        }
    }

    pub(crate) fn from_legacy_authorization(
        admission_class: &str,
        authority_anchor_ref: String,
        authorization_decision_digest: String,
        authoring_action_attestation_id: String,
    ) -> Self {
        Self {
            schema_version: 1,
            relationship_type_definition: super::legacy::LEGACY_LINK_DEFINITION_ID.into(),
            admission_class: admission_class.into(),
            authority_anchor: OriginAuthorityAnchor {
                endpoint_role: "source".into(),
                endpoint_ref: authority_anchor_ref,
            },
            admission_rule: "edit_source_view_target.v1".into(),
            authorization_decision_digest,
            authoring_action_attestation_id,
        }
    }

    pub(crate) fn relationship_type_definition(&self) -> &str {
        &self.relationship_type_definition
    }

    pub(crate) fn admission_class(&self) -> &str {
        &self.admission_class
    }

    pub(crate) fn authority_anchor(&self) -> &OriginAuthorityAnchor {
        &self.authority_anchor
    }

    pub(crate) fn authoring_action_attestation_id(&self) -> &str {
        &self.authoring_action_attestation_id
    }

    pub(crate) fn admission_rule(&self) -> &str {
        &self.admission_rule
    }

    #[cfg(test)]
    pub(super) fn test_fixture(
        relationship_type_definition: &str,
        admission_class: &str,
        endpoint_role: &str,
        endpoint_ref: &str,
        admission_rule: &str,
        authorization_decision_digest: &str,
        authoring_action_attestation_id: &str,
    ) -> Self {
        Self {
            schema_version: 1,
            relationship_type_definition: relationship_type_definition.into(),
            admission_class: admission_class.into(),
            authority_anchor: OriginAuthorityAnchor {
                endpoint_role: endpoint_role.into(),
                endpoint_ref: endpoint_ref.into(),
            },
            admission_rule: admission_rule.into(),
            authorization_decision_digest: authorization_decision_digest.into(),
            authoring_action_attestation_id: authoring_action_attestation_id.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.relationship_type_definition.trim().is_empty()
            || self.admission_class.trim().is_empty()
            || self.authority_anchor.endpoint_role.trim().is_empty()
            || self.authority_anchor.endpoint_ref.trim().is_empty()
            || self.admission_rule.trim().is_empty()
            || self.authoring_action_attestation_id.trim().is_empty()
            || self.authorization_decision_digest.len() != 64
            || !self
                .authorization_decision_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::engine("invalid origin admission evidence"));
        }
        crate::identity::decode_native_record(&self.authority_anchor.endpoint_ref)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssertionCreatedV1 {
    pub schema_version: u64,
    pub relationship: RelationshipCoordinate,
    pub relationship_created_event: RelationshipEventCoordinate,
    pub stance: String,
    pub semantic_claimant: String,
    /// Caller-declared semantic representation context. This is portable
    /// assertion content, never verified delegation or receiver authority.
    pub on_behalf_of: Option<String>,
    pub rationale: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub causal_parents: Vec<CausalAssertionParent>,
    pub origin_admission: OriginAdmissionV1,
    pub authoring_action_attestation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssertionEvidenceAddedV1 {
    pub schema_version: u64,
    pub evidence_ref: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssertionStateChangedV1 {
    pub schema_version: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type", content = "payload")]
pub(crate) enum RelationshipEventPayload {
    #[serde(rename = "relationship.created.v1")]
    RelationshipCreated(RelationshipCreatedV1),
    #[serde(rename = "relationship.superseded.v1")]
    RelationshipSuperseded(RelationshipSupersededV1),
    #[serde(rename = "relationship.retired.v1")]
    RelationshipRetired(RelationshipRetiredV1),
    #[serde(rename = "assertion.created.v1")]
    AssertionCreated(AssertionCreatedV1),
    #[serde(rename = "assertion.evidence_added.v1")]
    AssertionEvidenceAdded(AssertionEvidenceAddedV1),
    #[serde(rename = "assertion.retracted.v1")]
    AssertionRetracted(AssertionStateChangedV1),
    #[serde(rename = "assertion.invalidated.v1")]
    AssertionInvalidated(AssertionStateChangedV1),
    #[serde(rename = "assertion.restored.v1")]
    AssertionRestored(AssertionStateChangedV1),
}

impl RelationshipEventPayload {
    pub(crate) const fn event_type(&self) -> &'static str {
        match self {
            Self::RelationshipCreated(_) => "relationship.created.v1",
            Self::RelationshipSuperseded(_) => "relationship.superseded.v1",
            Self::RelationshipRetired(_) => "relationship.retired.v1",
            Self::AssertionCreated(_) => "assertion.created.v1",
            Self::AssertionEvidenceAdded(_) => "assertion.evidence_added.v1",
            Self::AssertionRetracted(_) => "assertion.retracted.v1",
            Self::AssertionInvalidated(_) => "assertion.invalidated.v1",
            Self::AssertionRestored(_) => "assertion.restored.v1",
        }
    }

    pub(crate) const fn stream_kind(&self) -> StreamKind {
        match self {
            Self::RelationshipCreated(_)
            | Self::RelationshipSuperseded(_)
            | Self::RelationshipRetired(_) => StreamKind::Relationship,
            _ => StreamKind::Assertion,
        }
    }

    pub(crate) fn value(&self) -> Result<Value> {
        let tagged = serde_json::to_value(self)?;
        tagged
            .get("payload")
            .cloned()
            .ok_or_else(|| Error::engine("relationship event payload is missing"))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let nonblank_reason = |reason: &str| {
            if reason.trim().is_empty() {
                Err(Error::engine("relationship event reason must not be blank"))
            } else {
                Ok(())
            }
        };
        match self {
            Self::RelationshipCreated(payload) => {
                if payload.schema_version != RELATIONSHIP_EVENT_SCHEMA_VERSION
                    || payload.relationship_revision != 1
                    || payload.relationship_type.trim().is_empty()
                    || payload.type_definition_id.trim().is_empty()
                    || payload.canonical_proposition_key.len() != 64
                    || payload.reducer_id.trim().is_empty()
                    || payload.reducer_version == 0
                {
                    return Err(Error::engine("invalid relationship-created payload"));
                }
                for endpoint in &payload.endpoints {
                    endpoint.validate()?;
                }
                let endpoint_count = payload
                    .endpoints
                    .iter()
                    .map(|endpoint| (&endpoint.role, &endpoint.portable_ref))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len();
                if endpoint_count != payload.endpoints.len() {
                    return Err(Error::engine(
                        "relationship-created endpoints must be unique",
                    ));
                }
                if payload.type_definition_id == super::legacy::LEGACY_LINK_DEFINITION_ID {
                    return super::legacy::validate_created_payload(payload);
                }
                if payload.legacy_link.is_some() {
                    return Err(Error::engine(
                        "governed relationship payload cannot carry legacy link evidence",
                    ));
                }
                let manifest = super::core_relationship_type_manifest()?;
                let definition = manifest
                    .relationship_types
                    .iter()
                    .find(|definition| definition.id == payload.type_definition_id)
                    .ok_or_else(|| {
                        Error::engine("unknown governed relationship type definition")
                    })?;
                if definition.relationship_type != payload.relationship_type
                    || definition.endpoint_semantics != payload.endpoint_semantics
                    || definition.reducer.id != payload.reducer_id
                    || definition.reducer.version != payload.reducer_version
                {
                    return Err(Error::engine(
                        "relationship-created payload does not match its governed definition",
                    ));
                }
                for endpoint in &payload.endpoints {
                    let rule = definition
                        .endpoints
                        .iter()
                        .find(|rule| rule.role == endpoint.role)
                        .ok_or_else(|| Error::engine("unknown governed endpoint role"))?;
                    if !rule.allowed_record_kinds.iter().any(|allowed| {
                        (allowed.record_type == "*"
                            || endpoint.record_type.as_deref()
                                == Some(allowed.record_type.as_str()))
                            && (allowed.kind == "*"
                                || endpoint.record_kind.as_deref() == Some(allowed.kind.as_str()))
                    }) {
                        return Err(Error::engine(
                            "relationship endpoint kind is not admitted by its governed role",
                        ));
                    }
                }
                let qualifiers = payload.identity_qualifiers.clone().into_iter().collect();
                let endpoints = payload
                    .endpoints
                    .iter()
                    .map(RelationshipEndpoint::proposition_endpoint)
                    .collect::<Vec<_>>();
                if definition.canonical_proposition_key(&endpoints, &qualifiers)?
                    != payload.canonical_proposition_key
                {
                    return Err(Error::engine("canonical proposition key mismatch"));
                }
                Ok(())
            }
            Self::RelationshipSuperseded(payload) => {
                if payload.schema_version != 1 {
                    return Err(Error::engine("invalid relationship-superseded payload"));
                }
                payload.successor.validate()?;
                nonblank_reason(&payload.reason)
            }
            Self::RelationshipRetired(payload) => {
                if payload.schema_version != 1 {
                    return Err(Error::engine("invalid relationship-retired payload"));
                }
                nonblank_reason(&payload.reason)
            }
            Self::AssertionCreated(payload) => {
                if payload.schema_version != 1
                    || !matches!(payload.stance.as_str(), "support" | "contest")
                    || payload.semantic_claimant.trim().is_empty()
                    || payload.authoring_action_attestation_id.trim().is_empty()
                    || payload.authoring_action_attestation_id
                        != payload.origin_admission.authoring_action_attestation_id
                {
                    return Err(Error::engine("invalid assertion-created payload"));
                }
                payload.relationship.validate()?;
                payload.relationship_created_event.validate()?;
                payload.origin_admission.validate()?;
                if payload
                    .on_behalf_of
                    .as_deref()
                    .is_some_and(|subject| subject.trim().is_empty())
                {
                    return Err(Error::engine("assertion on_behalf_of must not be blank"));
                }
                if payload
                    .rationale
                    .as_deref()
                    .is_some_and(|rationale| rationale.trim().is_empty())
                {
                    return Err(Error::engine("assertion rationale must not be blank"));
                }
                let valid_from = payload
                    .valid_from
                    .as_deref()
                    .map(|value| canonical_utc_millis(value, "assertion valid_from"))
                    .transpose()?;
                let valid_until = payload
                    .valid_until
                    .as_deref()
                    .map(|value| canonical_utc_millis(value, "assertion valid_until"))
                    .transpose()?;
                if valid_from
                    .zip(valid_until)
                    .is_some_and(|(from, until)| from >= until)
                {
                    return Err(Error::engine(
                        "assertion valid_until must be after valid_from",
                    ));
                }
                if payload.origin_admission.relationship_type_definition
                    == super::legacy::LEGACY_LINK_DEFINITION_ID
                {
                    return super::legacy::validate_assertion_payload(payload);
                }
                let manifest = super::core_relationship_type_manifest()?;
                let definition = manifest
                    .relationship_types
                    .iter()
                    .find(|definition| {
                        definition.id == payload.origin_admission.relationship_type_definition
                    })
                    .ok_or_else(|| {
                        Error::engine("origin admission names an unknown type definition")
                    })?;
                let admission_class = definition
                    .assertion_admission_classes
                    .iter()
                    .find(|class| class.id == payload.origin_admission.admission_class)
                    .ok_or_else(|| {
                        Error::engine("origin admission names an unknown admission class")
                    })?;
                if admission_class.stance != payload.stance
                    || !definition.endpoints.iter().any(|endpoint| {
                        endpoint.role == payload.origin_admission.authority_anchor.endpoint_role
                    })
                    || (admission_class.authority_anchor == super::AuthorityAnchorRule::Subject
                        && payload.origin_admission.authority_anchor.endpoint_role != "subject")
                    || payload.origin_admission.admission_rule
                        != format!("{}.v1", admission_route_name(admission_class.route))
                {
                    return Err(Error::engine(
                        "origin admission does not match the governed stance, route, or anchor",
                    ));
                }
                let mut canonical_parents = payload.causal_parents.clone();
                for parent in &canonical_parents {
                    validate_causal_assertion_parent(parent)?;
                }
                canonical_parents.sort_by_key(|parent| {
                    crate::derivation::canonical_json(
                        &serde_json::to_value(parent).expect("causal parent serializes"),
                    )
                });
                canonical_parents.dedup();
                if canonical_parents != payload.causal_parents {
                    return Err(Error::engine(
                        "causal assertion parents must be unique and canonically ordered",
                    ));
                }
                if payload
                    .origin_admission
                    .relationship_type_definition
                    .trim()
                    .is_empty()
                {
                    return Err(Error::engine(
                        "invalid assertion origin admission definition",
                    ));
                }
                Ok(())
            }
            Self::AssertionEvidenceAdded(payload) => {
                if payload.schema_version != 1 || payload.evidence_ref.trim().is_empty() {
                    return Err(Error::engine("invalid assertion-evidence payload"));
                }
                nonblank_reason(&payload.reason)
            }
            Self::AssertionRetracted(payload)
            | Self::AssertionInvalidated(payload)
            | Self::AssertionRestored(payload) => {
                if payload.schema_version != 1 {
                    return Err(Error::engine("invalid assertion-state payload"));
                }
                nonblank_reason(&payload.reason)
            }
        }
    }
}

pub(crate) fn parse_event_payload(
    event_type: &str,
    value: Value,
) -> Result<RelationshipEventPayload> {
    if !RELATIONSHIP_EVENT_TYPES.contains(&event_type) {
        return Err(Error::engine("unknown relationship event type"));
    }
    let tagged = json!({"event_type": event_type, "payload": value});
    let payload: RelationshipEventPayload = serde_json::from_value(tagged)?;
    payload.validate()?;
    Ok(payload)
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RelationshipEventSpec {
    pub event_id: String,
    pub stream_id: String,
    pub expected_stream_version: i64,
    pub relationship: RelationshipCoordinate,
    pub payload: RelationshipEventPayload,
    pub actor: String,
    pub issuer_origin_db_id: String,
    pub occurred_at: String,
    pub ingested_at: String,
}

impl RelationshipEventSpec {
    pub(crate) fn stream_version(&self) -> Result<i64> {
        self.expected_stream_version
            .checked_add(1)
            .ok_or_else(|| Error::engine("relationship stream version overflow"))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.relationship.validate()?;
        self.payload.validate()?;
        if !is_canonical_uuid_v4(&self.event_id)
            || !is_canonical_uuid_v4(&self.stream_id)
            || self.actor.trim().is_empty()
            || self.expected_stream_version < 0
            || !crate::identity::is_database_id(&self.issuer_origin_db_id)
        {
            return Err(Error::engine("invalid relationship event envelope"));
        }
        canonical_utc_millis(&self.occurred_at, "relationship event occurred_at")?;
        canonical_utc_millis(&self.ingested_at, "relationship event ingested_at")?;
        if self.payload.stream_kind() == StreamKind::Relationship
            && (self.stream_id != self.relationship.relationship_id
                || self.issuer_origin_db_id != self.relationship.relationship_origin_db_id)
        {
            return Err(Error::engine(
                "relationship stream identity must equal its pinned relationship coordinate",
            ));
        }
        if let RelationshipEventPayload::AssertionCreated(created) = &self.payload {
            if created.relationship != self.relationship {
                return Err(Error::engine(
                    "assertion-created payload changed the pinned relationship coordinate",
                ));
            }
        }
        Ok(())
    }

    /// Canonical origin event commitment. Local `seq` and receiver ingest time
    /// are deliberately absent; no semantic path may use either as ordering.
    pub(crate) fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(crate::derivation::digest_json(&json!({
            "id": self.event_id,
            "stream_kind": self.payload.stream_kind().as_str(),
            "stream_id": self.stream_id,
            "stream_version": self.stream_version()?,
            "relationship_origin_db_id": self.relationship.relationship_origin_db_id,
            "relationship_id": self.relationship.relationship_id,
            "relationship_revision": self.relationship.relationship_revision,
            "type": self.payload.event_type(),
            "payload": self.payload.value()?,
            "actor": self.actor,
            "issuer_origin_db_id": self.issuer_origin_db_id,
            "occurred_at": self.occurred_at,
        })))
    }
}

fn is_canonical_uuid_v4(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| {
        parsed.get_version_num() == 4 && parsed.hyphenated().to_string() == value
    })
}

fn canonical_utc_millis(value: &str, label: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|_| Error::engine(format!("{label} must be RFC3339")))?;
    let canonical = parsed
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    if canonical != value {
        return Err(Error::engine(format!(
            "{label} must use canonical UTC millisecond form"
        )));
    }
    Ok(parsed)
}

fn admission_route_name(route: super::AdmissionRoute) -> &'static str {
    match route {
        super::AdmissionRoute::EditSubjectViewObject => "edit_subject_view_object",
        super::AdmissionRoute::EditEitherAnchorViewBoth => "edit_either_anchor_view_both",
        super::AdmissionRoute::VerifiedEndpointBinding => "verified_endpoint_binding",
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CreateRelationshipWithAssertion {
    pub relationship_event: RelationshipEventSpec,
    pub assertion_event: RelationshipEventSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppendedRelationshipEvent {
    pub seq: i64,
    pub stream_version: i64,
    pub exact_retry: bool,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatedRelationshipWithAssertion {
    pub relationship: AppendedRelationshipEvent,
    pub assertion: AppendedRelationshipEvent,
}
