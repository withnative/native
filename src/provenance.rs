//! Native-issued provenance for accepted content mutations.
//!
//! This module is deliberately separate from `store::EventAnnotations`.
//! Run keys, parent keys and intent are caller-authored correlation metadata;
//! the facts here come only from transport-established [`Caller`] context.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::authorization::Capability;
use crate::events::EventRow;
use crate::mcp::registry::Caller;
use crate::{Db, Error, Result};

/// The transport the server observed itself serving an accepted write on.
///
/// This is deliberately a THIRD axis, separate from `executor_kind` and from
/// principal association. Decision 425a001b: "the server observes which
/// transport it is serving; the caller cannot fake it either. It is simply a
/// *weaker fact* than 'an agent did this'." A write over MCP is genuinely
/// over MCP whether an agent or a person with an MCP credential made it, so
/// this value may drive a hedged *rendering* inference and must never be
/// folded into `executor_kind`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// A trusted first-party web/workbench tool route.
    Web,
    /// An MCP transport (stdio or the MCP HTTP listener).
    Mcp,
    /// An authenticated inbound webhook served by the hosting boundary.
    Webhook,
    /// A trusted in-process caller.
    Local,
    /// No host declared a transport. Never guessed into one of the others.
    #[default]
    Unknown,
}

impl Channel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Channel::Web => "web",
            Channel::Mcp => "mcp",
            Channel::Webhook => "webhook",
            Channel::Local => "local",
            Channel::Unknown => "unknown",
        }
    }

    pub fn from_stored(value: Option<&str>) -> Self {
        match value {
            Some("web") => Channel::Web,
            Some("mcp") => Channel::Mcp,
            Some("webhook") => Channel::Webhook,
            Some("local") => Channel::Local,
            _ => Channel::Unknown,
        }
    }

    /// Whether the channel is itself a durable server observation. `Unknown`
    /// is the honest absence of one, not a weaker observation of one.
    pub const fn is_observed(self) -> bool {
        !matches!(self, Channel::Unknown)
    }
}

pub const ACTION_ATTESTATION_SCHEMA_VERSION: i64 = 2;
pub const LEGACY_ACTION_ATTESTATION_SCHEMA_VERSION: i64 = 1;
pub const INTERACTION_RECEIPT_SCHEMA_VERSION: i64 = 1;
const ISSUER: &str = "native-ce";
/// V1 attests accepted actions whose exact outputs are content-event UUIDs.
/// Meta, policy, control, awareness-only, derivation-only and direct-write
/// mutations are intentionally outside this first boundary.
pub const V1_MUTATION_BOUNDARY: &str = "content_events";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedInteractionEvidence {
    pub receipt_id: String,
    pub principal: String,
    pub scope_digest: String,
    pub nonce: String,
    pub verifier: String,
    pub verified_at: String,
    pub evidence_digest: String,
    pub sealed_evidence_ref: Option<String>,
    pub retention_class: Option<String>,
    /// Generic trusted ingress binds directly to the canonical accepted action.
    /// Messaging's older verifier leaves this unset and uses its exact message
    /// scope digest compatibility contract instead.
    pub accepted_action_digest: Option<String>,
}

#[derive(Clone)]
pub struct ProvenanceInteractionTokenIssuer {
    key: [u8; 32],
    issuer_ref: String,
}

#[derive(Serialize, Deserialize)]
struct ProvenanceInteractionClaims {
    principal: String,
    scope_digest: String,
    nonce: String,
    expires_at: i64,
}

/// Canonical generic interaction scope. Target, revision, relation, polarity,
/// or any future accepted argument remains bound because the full argument
/// object participates in the JCS digest.
pub fn verified_action_scope(operation: &str, arguments: &Value) -> Value {
    json!({"operation":operation,"arguments":action_arguments(operation, arguments)})
}

fn action_digest_from_scope(scope: &Value) -> Result<String> {
    let operation = scope
        .get("operation")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::engine("provenance interaction scope requires operation"))?;
    let arguments = scope
        .get("arguments")
        .ok_or_else(|| Error::engine("provenance interaction scope requires arguments"))?;
    Ok(action_digest(operation, arguments))
}

impl ProvenanceInteractionTokenIssuer {
    pub fn random(issuer_ref: impl Into<String>) -> Self {
        use rand::RngCore;
        let mut key = [0_u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self {
            key,
            issuer_ref: issuer_ref.into(),
        }
    }

    pub fn issue(&self, principal: &str, scope: &Value, ttl_seconds: i64) -> Result<String> {
        if principal.trim().is_empty() || !(1..=300).contains(&ttl_seconds) {
            return Err(Error::engine(
                "invalid provenance interaction token request",
            ));
        }
        action_digest_from_scope(scope)?;
        let claims = ProvenanceInteractionClaims {
            principal: principal.into(),
            scope_digest: digest_json(scope),
            nonce: Uuid::new_v4().to_string(),
            expires_at: chrono::Utc::now().timestamp() + ttl_seconds,
        };
        let body =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(body.as_bytes());
        Ok(format!(
            "{body}.{}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }

    pub fn verify(
        &self,
        token: &str,
        principal: &str,
        scope: &Value,
    ) -> Result<VerifiedInteractionEvidence> {
        let accepted_action_digest = action_digest_from_scope(scope)?;
        let (body, signature) = token
            .split_once('.')
            .ok_or_else(|| Error::engine("invalid provenance interaction token"))?;
        let signature = hex::decode(signature)
            .map_err(|_| Error::engine("invalid provenance interaction token"))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(body.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| Error::engine("invalid provenance interaction token"))?;
        let claims: ProvenanceInteractionClaims = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| Error::engine("invalid provenance interaction token"))?,
        )?;
        let scope_digest = digest_json(scope);
        if claims.principal != principal
            || claims.scope_digest != scope_digest
            || claims.expires_at < chrono::Utc::now().timestamp()
        {
            return Err(Error::engine(
                "provenance interaction token binding mismatch or expired",
            ));
        }
        let evidence_digest = hex::encode(Sha256::digest(body.as_bytes()));
        let mut receipt_bytes = [0_u8; 16];
        receipt_bytes.copy_from_slice(
            &Sha256::digest(
                format!("{}:{}:{}", self.issuer_ref, claims.nonce, evidence_digest).as_bytes(),
            )[..16],
        );
        receipt_bytes[6] = (receipt_bytes[6] & 0x0f) | 0x50;
        receipt_bytes[8] = (receipt_bytes[8] & 0x3f) | 0x80;
        Ok(VerifiedInteractionEvidence {
            receipt_id: Uuid::from_bytes(receipt_bytes).to_string(),
            principal: principal.into(),
            scope_digest,
            nonce: claims.nonce,
            verifier: self.issuer_ref.clone(),
            verified_at: crate::store::now_iso(),
            evidence_digest,
            sealed_evidence_ref: None,
            retention_class: Some("digest".into()),
            accepted_action_digest: Some(accepted_action_digest),
        })
    }
}

#[derive(Clone, Debug)]
struct DispatchFacts {
    principal: String,
    executor_kind: String,
    /// Server-observed transport. Recorded ALONGSIDE `executor_kind`, never
    /// merged into it.
    channel: Channel,
    executor_ref: Option<String>,
    delegation_ref: Option<String>,
    interaction: Option<VerifiedInteractionEvidence>,
    interaction_scope_valid: bool,
    operation: String,
    action_commitment: String,
    action_digest: String,
    command_identity_digest: Option<String>,
    intent_digest: Option<String>,
}

#[derive(Default, Debug)]
struct DispatchState {
    appended_outputs: Vec<ActionOutput>,
    pending_attestation_ids: Vec<String>,
    issued_attestation_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputDomain {
    Content,
    Relationship,
}

impl OutputDomain {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Relationship => "relationship",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionOutput {
    pub domain: OutputDomain,
    pub event_id: String,
}

impl ActionOutput {
    pub(crate) fn content(event_id: impl Into<String>) -> Self {
        Self {
            domain: OutputDomain::Content,
            event_id: event_id.into(),
        }
    }

    pub(crate) fn relationship(event_id: impl Into<String>) -> Self {
        Self {
            domain: OutputDomain::Relationship,
            event_id: event_id.into(),
        }
    }
}

/// Proof object minted only after Native authorizes the governed relationship
/// route in the caller-owned write transaction. Imported/caller-authored JSON
/// can deserialize origin evidence, but cannot construct this local authority.
#[derive(Debug)]
pub(crate) struct LocallyAuthorizedOriginAdmission {
    relationship_type_definition: String,
    admission_class: String,
    authority_anchor_role: String,
    authority_anchor_ref: String,
    admission_rule: String,
    authorization_decision_digest: String,
    authoring_action_attestation_id: String,
}

impl LocallyAuthorizedOriginAdmission {
    pub(crate) fn into_parts(self) -> (String, String, String, String, String, String, String) {
        (
            self.relationship_type_definition,
            self.admission_class,
            self.authority_anchor_role,
            self.authority_anchor_ref,
            self.admission_rule,
            self.authorization_decision_digest,
            self.authoring_action_attestation_id,
        )
    }
}

/// Authorize one origin-admission claim against the exact endpoint snapshot
/// that will be embedded in `relationship.created.v1`. This is deliberately a
/// write-transaction API; no read preflight can mint the proof object.
#[allow(clippy::too_many_arguments, dead_code)] // transaction seam mirrors the governed proof inputs
pub(crate) async fn authorize_local_origin_admission_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    draft: &ActionAttestationDraft,
    relationship: &crate::relationship::RelationshipCreatedV1,
    stance: &str,
    admission_class_id: &str,
    authority_anchor_role: &str,
    authority_anchor_ref: &str,
) -> Result<LocallyAuthorizedOriginAdmission> {
    if caller.credential() != draft.facts.principal {
        return Err(Error::engine(
            "relationship admission caller binding mismatch",
        ));
    }
    let definition = crate::relationship::core_relationship_type_manifest()?
        .relationship_types
        .into_iter()
        .find(|definition| definition.id == relationship.type_definition_id)
        .ok_or_else(|| Error::engine("relationship admission type is not governed"))?;
    let admission = definition
        .assertion_admission_classes
        .iter()
        .find(|class| class.id == admission_class_id && class.stance == stance)
        .ok_or_else(|| Error::engine("relationship admission class is not governed"))?;
    let anchor = relationship
        .endpoints
        .iter()
        .find(|endpoint| {
            endpoint.role == authority_anchor_role && endpoint.portable_ref == authority_anchor_ref
        })
        .ok_or_else(|| Error::engine("relationship admission anchor does not exist"))?;
    if admission.authority_anchor == crate::relationship::AuthorityAnchorRule::Subject
        && authority_anchor_role != "subject"
    {
        return Err(Error::engine(
            "relationship admission anchor is not the subject",
        ));
    }
    let local_origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    for endpoint in &relationship.endpoints {
        let (origin, record_id) = crate::identity::decode_native_record(&endpoint.portable_ref)?;
        if origin != local_origin {
            return Err(Error::engine(
                "relationship admission endpoint does not exist",
            ));
        }
        crate::mcp::tools::require_record_in(
            tx,
            caller,
            "manage_relationships",
            &record_id,
            Capability::View,
        )
        .await?;
    }
    let (_, anchor_record_id) = crate::identity::decode_native_record(&anchor.portable_ref)?;
    let admission_rule = match admission.route {
        crate::relationship::AdmissionRoute::EditSubjectViewObject => {
            if authority_anchor_role != "subject" {
                return Err(Error::engine(
                    "relationship admission anchor is not the subject",
                ));
            }
            crate::mcp::tools::require_record_in(
                tx,
                caller,
                "manage_relationships",
                &anchor_record_id,
                Capability::Edit,
            )
            .await?;
            "edit_subject_view_object.v1"
        }
        crate::relationship::AdmissionRoute::EditEitherAnchorViewBoth => {
            crate::mcp::tools::require_record_in(
                tx,
                caller,
                "manage_relationships",
                &anchor_record_id,
                Capability::Edit,
            )
            .await?;
            "edit_either_anchor_view_both.v1"
        }
        crate::relationship::AdmissionRoute::VerifiedEndpointBinding => {
            let caller_person =
                crate::attribution::caller_person_in(tx, caller.credential()).await?;
            if caller_person.as_deref() != Some(anchor_record_id.as_str()) {
                return Err(Error::engine(
                    "manage_relationships: relationship endpoint does not exist",
                ));
            }
            "verified_endpoint_binding.v1"
        }
    };
    let authorization_decision_digest = digest_json(&json!({
        "schema_version": 1,
        "principal": draft.facts.principal,
        "operation": draft.facts.operation,
        "relationship_type_definition": definition.id,
        "admission_class": admission.id,
        "authority_anchor": {
            "endpoint_role": authority_anchor_role,
            "endpoint_ref": anchor.portable_ref,
        },
        "admission_rule": admission_rule,
    }));
    Ok(LocallyAuthorizedOriginAdmission {
        relationship_type_definition: definition.id,
        admission_class: admission.id.clone(),
        authority_anchor_role: authority_anchor_role.into(),
        authority_anchor_ref: anchor.portable_ref.clone(),
        admission_rule: admission_rule.into(),
        authorization_decision_digest,
        authoring_action_attestation_id: draft.id.clone(),
    })
}

/// Receiver-local proof that an origin admission was actually issued here,
/// remains valid, and is bound by its v2 action output set to the assertion
/// event being reduced. Foreign/imported evidence deliberately returns false.
#[allow(dead_code)] // consumed by the Phase 4 receiver-local admission projector
pub(crate) async fn verify_receiver_local_assertion_admission_in(
    tx: &mut Transaction<'_, Sqlite>,
    issuer_origin_db_id: &str,
    assertion_event_id: &str,
    origin_admission: &crate::relationship::OriginAdmissionV1,
) -> Result<bool> {
    let attestation_id = origin_admission.authoring_action_attestation_id();
    let row = sqlx::query(
        "SELECT a.schema_version,a.output_event_set_digest,
                a.issuer_origin_database_id,l.attestation_id IS NOT NULL AS local,
                COALESCE((SELECT status FROM provenance_attestation_validity_events validity
                           WHERE validity.attestation_id=a.id
                           ORDER BY ordinal DESC LIMIT 1),'valid') AS validity
           FROM provenance_action_attestations a
           LEFT JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id
          WHERE a.id=?",
    )
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if !row.try_get::<bool, _>("local")?
        || row.try_get::<String, _>("validity")? == "invalidated"
        || row.try_get::<String, _>("issuer_origin_database_id")? != issuer_origin_db_id
        || row.try_get::<i64, _>("schema_version")? != ACTION_ATTESTATION_SCHEMA_VERSION
    {
        return Ok(false);
    }
    let event = sqlx::query(
        "SELECT type,payload FROM relationship_events
          WHERE issuer_origin_db_id=? AND id=?",
    )
    .bind(issuer_origin_db_id)
    .bind(assertion_event_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(event) = event else {
        return Ok(false);
    };
    let event_type: String = event.try_get("type")?;
    let payload: String = event.try_get("payload")?;
    let parsed =
        crate::relationship::parse_event_payload(&event_type, serde_json::from_str(&payload)?)?;
    if !matches!(
        parsed,
        crate::relationship::RelationshipEventPayload::AssertionCreated(ref created)
            if &created.origin_admission == origin_admission
    ) {
        return Ok(false);
    }
    let members = sqlx::query(
        "SELECT ordinal,output_domain,output_event_id
           FROM provenance_action_outputs
          WHERE action_attestation_id=? ORDER BY ordinal",
    )
    .bind(attestation_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut outputs = Vec::with_capacity(members.len());
    let mut bound = false;
    for (expected, member) in members.into_iter().enumerate() {
        if member.try_get::<i64, _>("ordinal")? != i64::try_from(expected).unwrap_or(i64::MAX) {
            return Ok(false);
        }
        let domain: String = member.try_get("output_domain")?;
        let event_id: String = member.try_get("output_event_id")?;
        let output = match domain.as_str() {
            "content" => ActionOutput::content(event_id),
            "relationship" => ActionOutput::relationship(event_id),
            _ => return Ok(false),
        };
        bound |=
            output.domain == OutputDomain::Relationship && output.event_id == assertion_event_id;
        outputs.push(output);
    }
    Ok(bound
        && ordered_output_set_digest(&outputs)
            == row.try_get::<String, _>("output_event_set_digest")?)
}

#[derive(Clone, Debug)]
pub(crate) struct ProvenanceDispatch {
    facts: Arc<DispatchFacts>,
    state: Arc<Mutex<DispatchState>>,
}

/// A stable action identity reserved before output event identities exist.
/// Finalization must happen in the same transaction as the supplied events.
#[derive(Clone, Debug)]
pub(crate) struct ActionAttestationDraft {
    id: String,
    facts: Arc<DispatchFacts>,
}

impl ActionAttestationDraft {
    #[allow(dead_code)] // consumed by the attribution feature stacked on v31
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

tokio::task_local! {
    static TRUSTED_PROVENANCE: ProvenanceDispatch;
}

pub(crate) fn digest_json(value: &Value) -> String {
    crate::canonical_json::digest_json(value)
}

fn action_arguments(operation: &str, arguments: &Value) -> Value {
    let mut value = arguments.clone();
    if let Some(object) = value.as_object_mut() {
        for key in ["run_key", "parent_key", "agent_key"] {
            object.remove(key);
        }
        if operation == "manage_relationships" {
            if let Some(key) = object.get_mut("idempotency_key") {
                if let Some(value) = key.as_str() {
                    *key = Value::String(value.trim().to_string());
                }
            }
            for optional in ["identity_qualifiers", "causal_parents"] {
                if object.get(optional).is_some_and(|value| {
                    value.as_object().is_some_and(|value| value.is_empty())
                        || value.as_array().is_some_and(|value| value.is_empty())
                }) {
                    object.remove(optional);
                }
            }
            object.retain(|_, value| !value.is_null());
            for array_key in ["endpoints", "causal_parents"] {
                if let Some(array) = object.get_mut(array_key).and_then(Value::as_array_mut) {
                    array.sort_by_key(crate::canonical_json::canonical_json);
                    array.dedup();
                }
            }
        }
    }
    value
}

fn action_commitment(operation: &str, arguments: &Value) -> Value {
    json!({
        "operation": operation,
        // Only the digest enters durable provenance. Bodies, reasons, bearer
        // material, and other raw tool arguments remain in their owning domain.
        "arguments_digest": digest_json(&action_arguments(operation, arguments)),
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn commitment_is_exact(canonical: &Value, operation: &str, digest: &str) -> bool {
    let Some(object) = canonical.as_object() else {
        return false;
    };
    if object.len() != 2
        || object.get("operation").and_then(Value::as_str) != Some(operation)
        || !object.contains_key("arguments_digest")
    {
        return false;
    }
    let Some(arguments_digest) = object.get("arguments_digest").and_then(Value::as_str) else {
        return false;
    };
    is_sha256_hex(arguments_digest) && is_sha256_hex(digest) && digest_json(canonical) == digest
}

pub(crate) fn action_digest(operation: &str, arguments: &Value) -> String {
    digest_json(&action_commitment(operation, arguments))
}

fn command_identity_digest(arguments: &Value) -> Option<String> {
    arguments
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| digest_json(&json!(value)))
}

fn interaction_scope_digest(arguments: &Value) -> Option<String> {
    let action = arguments.get("action")?.as_str()?;
    let mut ids = if let Some(ids) = arguments.get("message_ids").and_then(Value::as_array) {
        ids.iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    } else {
        vec![arguments.get("message_id")?.as_str()?.to_string()]
    };
    ids.sort();
    let mut hash = Sha256::new();
    for id in ids {
        hash.update(id.as_bytes());
        hash.update([0]);
    }
    Some(digest_json(&json!({
        "action": action,
        "message_digest": hex::encode(hash.finalize()),
    })))
}

impl ProvenanceDispatch {
    pub(crate) fn from_caller(
        caller: &Caller,
        operation: &str,
        arguments: &Value,
        intent: Option<&str>,
    ) -> Self {
        let (executor_kind, executor_ref, delegation_ref) =
            if let Some(executor) = caller.verified_delegated_service() {
                (
                    "delegated_service".to_string(),
                    Some(format!("webhook:{}", executor.endpoint_id)),
                    Some(format!("webhook-credential:{}", executor.credential_id)),
                )
            } else if let Some(executor) = caller.verified_agent_executor() {
                (
                    "agent".to_string(),
                    Some(executor.executor_ref.clone()),
                    Some(executor.delegation_ref.clone()),
                )
            } else if let Some(interaction) = caller.verified_provenance_interaction() {
                (
                    "human".to_string(),
                    Some(interaction.verifier.clone()),
                    None,
                )
            } else if caller.is_trusted_local() {
                ("local".to_string(), Some("native-ce-local".into()), None)
            } else {
                (
                    "authenticated_principal".to_string(),
                    Some(caller.credential().to_string()),
                    None,
                )
            };
        let interaction = caller.verified_provenance_interaction().cloned();
        let accepted_digest = action_digest(operation, arguments);
        let action_commitment = String::from_utf8(crate::canonical_json::canonical_json(
            &action_commitment(operation, arguments),
        ))
        .expect("canonical JSON is UTF-8");
        let interaction_scope_valid = interaction.as_ref().is_none_or(|receipt| {
            receipt.accepted_action_digest.as_deref() == Some(accepted_digest.as_str())
                || (receipt.accepted_action_digest.is_none()
                    && interaction_scope_digest(arguments).as_deref()
                        == Some(receipt.scope_digest.as_str()))
        });
        Self {
            facts: Arc::new(DispatchFacts {
                principal: caller.credential().to_string(),
                executor_kind,
                channel: caller.channel(),
                executor_ref,
                delegation_ref,
                interaction,
                interaction_scope_valid,
                operation: operation.to_string(),
                action_commitment,
                action_digest: accepted_digest,
                command_identity_digest: command_identity_digest(arguments),
                intent_digest: intent.map(|value| digest_json(&json!(value))),
            }),
            state: Arc::new(Mutex::new(DispatchState::default())),
        }
    }

    pub(crate) async fn scope<F: Future>(&self, future: F) -> F::Output {
        TRUSTED_PROVENANCE.scope(self.clone(), future).await
    }

    pub(crate) fn receipt_ids(&self) -> Vec<String> {
        let state = self.state.lock().expect("provenance dispatch lock");
        state.issued_attestation_ids.clone()
    }
}

pub(crate) fn note_appended_output(domain: OutputDomain, event_id: &str) {
    let _ = TRUSTED_PROVENANCE.try_with(|dispatch| {
        let mut state = dispatch.state.lock().expect("provenance dispatch lock");
        let output = ActionOutput {
            domain,
            event_id: event_id.to_string(),
        };
        if !state.appended_outputs.contains(&output) {
            state.appended_outputs.push(output);
        }
    });
}

pub(crate) fn note_appended_event(event_id: &str) {
    note_appended_output(OutputDomain::Content, event_id);
}

pub(crate) fn reserve_action_attestation() -> Result<ActionAttestationDraft> {
    TRUSTED_PROVENANCE
        .try_with(|dispatch| ActionAttestationDraft {
            id: Uuid::new_v4().to_string(),
            facts: Arc::clone(&dispatch.facts),
        })
        .map_err(|_| Error::engine("trusted provenance context is unavailable"))
}

/// The executor identity that will be written into the accepted action's
/// attestation. Aggregate handlers use this instead of event.actor or the
/// authenticated routing principal when executor identity is semantic state.
pub(crate) fn accepted_executor_ref() -> Result<String> {
    TRUSTED_PROVENANCE
        .try_with(|dispatch| dispatch.facts.executor_ref.clone())
        .map_err(|_| Error::engine("trusted provenance context is unavailable"))?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::engine("accepted action has no verified executor identity"))
}

#[cfg(test)]
fn ordered_v1_event_set_digest(events: &[EventRow]) -> String {
    digest_json(&json!(events
        .iter()
        .map(|event| &event.id)
        .collect::<Vec<_>>()))
}

fn ordered_output_set_digest(outputs: &[ActionOutput]) -> String {
    digest_json(&json!(outputs
        .iter()
        .map(|output| json!({
            "domain": output.domain.as_str(),
            "event_id": output.event_id,
        }))
        .collect::<Vec<_>>()))
}

/// Persist one immutable action attestation and its exact ordered event set in
/// the caller-owned transaction. The caller decides the logical action boundary
/// by the exact `events` slice; this function neither appends nor commits.
pub(crate) async fn issue_action_attestation_in(
    tx: &mut Transaction<'static, Sqlite>,
    draft: ActionAttestationDraft,
    events: &[EventRow],
) -> Result<String> {
    let outputs = events
        .iter()
        .map(|event| ActionOutput::content(event.id.clone()))
        .collect::<Vec<_>>();
    issue_action_attestation_outputs_in(tx, draft, &outputs).await
}

/// Persist a schema-v2 action attestation over one exact ordered, domain-qualified
/// output set. Every member must have been captured by the current trusted
/// dispatch and must already exist in the caller-owned write transaction.
pub(crate) async fn issue_action_attestation_outputs_in(
    tx: &mut Transaction<'static, Sqlite>,
    draft: ActionAttestationDraft,
    outputs: &[ActionOutput],
) -> Result<String> {
    if outputs.is_empty() {
        return Err(Error::engine(
            "action attestation requires at least one accepted output event",
        ));
    }
    if let Some(receipt) = &draft.facts.interaction {
        if receipt.principal != draft.facts.principal {
            return Err(Error::engine(
                "verified interaction principal does not match the authenticated caller",
            ));
        }
        if !draft.facts.interaction_scope_valid {
            return Err(Error::engine(
                "verified interaction scope does not allow this accepted action",
            ));
        }
    }
    let emitted = TRUSTED_PROVENANCE
        .try_with(|dispatch| {
            dispatch
                .state
                .lock()
                .expect("provenance dispatch lock")
                .appended_outputs
                .clone()
        })
        .map_err(|_| Error::engine("trusted provenance context is unavailable"))?;
    let mut unique = std::collections::HashSet::new();
    for output in outputs {
        if !emitted.contains(output) {
            return Err(Error::engine(format!(
                "action attestation output {}:{} was not emitted by this accepted action",
                output.domain.as_str(),
                output.event_id
            )));
        }
        if !unique.insert((output.domain, output.event_id.as_str())) {
            return Err(Error::engine(
                "action attestation output event set contains a duplicate",
            ));
        }
        let exists: bool = match output.domain {
            OutputDomain::Content => {
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE id=?)")
                    .bind(&output.event_id)
                    .fetch_one(&mut **tx)
                    .await?
            }
            OutputDomain::Relationship => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM relationship_events WHERE id=? AND issuer_origin_db_id=(SELECT origin_db_id FROM database_identity WHERE singleton=1))",
                )
                .bind(&output.event_id)
                .fetch_one(&mut **tx)
                .await?
            }
        };
        if !exists {
            return Err(Error::engine(format!(
                "action attestation output {}:{} is not in the transaction",
                output.domain.as_str(),
                output.event_id
            )));
        }
    }

    if let Some(receipt) = &draft.facts.interaction {
        sqlx::query(
            "INSERT INTO provenance_interaction_receipts
                (id,schema_version,principal,scope_digest,nonce,verifier,verified_at,
                 evidence_digest,sealed_evidence_ref,retention_class)
             VALUES (?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&receipt.receipt_id)
        .bind(INTERACTION_RECEIPT_SCHEMA_VERSION)
        .bind(&receipt.principal)
        .bind(&receipt.scope_digest)
        .bind(&receipt.nonce)
        .bind(&receipt.verifier)
        .bind(&receipt.verified_at)
        .bind(&receipt.evidence_digest)
        .bind(&receipt.sealed_evidence_ref)
        .bind(&receipt.retention_class)
        .execute(&mut **tx)
        .await?;
        let stored = sqlx::query(
            "SELECT principal,scope_digest,nonce,verifier,evidence_digest
               FROM provenance_interaction_receipts WHERE id=?",
        )
        .bind(&receipt.receipt_id)
        .fetch_one(&mut **tx)
        .await?;
        let exact = stored.try_get::<String, _>("principal")? == receipt.principal
            && stored.try_get::<String, _>("scope_digest")? == receipt.scope_digest
            && stored.try_get::<String, _>("nonce")? == receipt.nonce
            && stored.try_get::<String, _>("verifier")? == receipt.verifier
            && stored.try_get::<String, _>("evidence_digest")? == receipt.evidence_digest;
        if !exact {
            return Err(Error::engine(
                "verified interaction receipt identity was reused with conflicting facts",
            ));
        }
    }

    let issued_at = crate::store::now_iso();
    let issuer_origin_database_id: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    sqlx::query(
        "INSERT INTO provenance_action_attestations
            (id,schema_version,principal,executor_kind,channel,executor_ref,delegation_ref,
             interaction_receipt_id,operation,action_commitment,action_digest,output_event_set_digest,
             issuer,issuer_origin_database_id,issued_at,command_identity_digest,intent_digest)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&draft.id)
    .bind(ACTION_ATTESTATION_SCHEMA_VERSION)
    .bind(&draft.facts.principal)
    .bind(&draft.facts.executor_kind)
    .bind(draft.facts.channel.as_str())
    .bind(&draft.facts.executor_ref)
    .bind(&draft.facts.delegation_ref)
    .bind(
        draft
            .facts
            .interaction
            .as_ref()
            .map(|receipt| &receipt.receipt_id),
    )
    .bind(&draft.facts.operation)
    .bind(&draft.facts.action_commitment)
    .bind(&draft.facts.action_digest)
    .bind(ordered_output_set_digest(outputs))
    .bind(ISSUER)
    .bind(&issuer_origin_database_id)
    .bind(&issued_at)
    .bind(&draft.facts.command_identity_digest)
    .bind(&draft.facts.intent_digest)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO provenance_local_attestation_authority
            (attestation_id,issuer_origin_database_id,principal,operation,
             command_identity_digest,anchored_at) VALUES (?,?,?,?,?,?)",
    )
    .bind(&draft.id)
    .bind(&issuer_origin_database_id)
    .bind(&draft.facts.principal)
    .bind(&draft.facts.operation)
    .bind(&draft.facts.command_identity_digest)
    .bind(&issued_at)
    .execute(&mut **tx)
    .await?;
    for (ordinal, output) in outputs.iter().enumerate() {
        sqlx::query(
            "INSERT INTO provenance_action_outputs
                (action_attestation_id,ordinal,output_domain,output_event_id)
             VALUES (?,?,?,?)",
        )
        .bind(&draft.id)
        .bind(i64::try_from(ordinal).map_err(|_| Error::engine("too many output events"))?)
        .bind(output.domain.as_str())
        .bind(&output.event_id)
        .execute(&mut **tx)
        .await?;
    }
    crate::relationship::project_receiver_local_admissions_for_outputs_in(tx, outputs).await?;
    note_pending_attestation(draft.id.clone());
    Ok(draft.id)
}

/// Finalize any governed outputs appended since the previous successful commit
/// in this trusted dispatch. Calls outside trusted mutation ingress are a no-op.
pub(crate) async fn issue_pending_action_in(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<Option<String>> {
    if TRUSTED_PROVENANCE.try_with(|_| ()).is_err() {
        return Ok(None);
    }
    let draft = reserve_action_attestation()?;
    issue_reserved_pending_action_in(tx, draft).await
}

/// Finalize the current request's still-unclaimed outputs with an identity
/// reserved before relationship assertions were authored. This lets a
/// composite command bind its origin-admission evidence to the same single
/// attestation that covers all content and relationship outputs.
pub(crate) async fn issue_reserved_pending_action_in(
    tx: &mut Transaction<'static, Sqlite>,
    draft: ActionAttestationDraft,
) -> Result<Option<String>> {
    let dispatch = match TRUSTED_PROVENANCE.try_with(Clone::clone) {
        Ok(dispatch) => dispatch,
        Err(_) => return Ok(None),
    };
    let candidates = dispatch
        .state
        .lock()
        .expect("provenance dispatch lock")
        .appended_outputs
        .clone();
    let mut outputs = Vec::new();
    for output in candidates {
        let claimed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM provenance_action_outputs
              WHERE output_domain=? AND output_event_id=?)",
        )
        .bind(output.domain.as_str())
        .bind(&output.event_id)
        .fetch_one(&mut **tx)
        .await?;
        let exists: bool = match output.domain {
            OutputDomain::Content => {
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE id=?)")
                    .bind(&output.event_id)
                    .fetch_one(&mut **tx)
                    .await?
            }
            OutputDomain::Relationship => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM relationship_events WHERE id=? AND issuer_origin_db_id=(SELECT origin_db_id FROM database_identity WHERE singleton=1))",
                )
                .bind(&output.event_id)
                .fetch_one(&mut **tx)
                .await?
            }
        };
        if !claimed && exists {
            outputs.push(output);
        }
    }
    if outputs.is_empty() {
        return Ok(None);
    }
    issue_action_attestation_outputs_in(tx, draft, &outputs)
        .await
        .map(Some)
}

fn note_pending_attestation(attestation_id: String) {
    let _ = TRUSTED_PROVENANCE.try_with(|dispatch| {
        dispatch
            .state
            .lock()
            .expect("provenance dispatch lock")
            .pending_attestation_ids
            .push(attestation_id);
    });
}

pub(crate) async fn pending_attestations_visible_in(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<Vec<String>> {
    let dispatch = match TRUSTED_PROVENANCE.try_with(Clone::clone) {
        Ok(dispatch) => dispatch,
        Err(_) => return Ok(Vec::new()),
    };
    let pending = dispatch
        .state
        .lock()
        .expect("provenance dispatch lock")
        .pending_attestation_ids
        .clone();
    let mut visible = Vec::new();
    for id in pending {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM provenance_action_attestations WHERE id=?)",
        )
        .bind(&id)
        .fetch_one(&mut **tx)
        .await?;
        if exists {
            visible.push(id);
        }
    }
    Ok(visible)
}

/// Publish only IDs proven visible in the transaction that just committed.
/// Concurrent transactions in one dispatch retain independent pending IDs.
pub(crate) fn confirm_committed_attestations(committed: &[String]) {
    let Ok(dispatch) = TRUSTED_PROVENANCE.try_with(Clone::clone) else {
        return;
    };
    let mut state = dispatch.state.lock().expect("provenance dispatch lock");
    state
        .pending_attestation_ids
        .retain(|id| !committed.contains(id));
    for id in committed {
        if !state.issued_attestation_ids.contains(id) {
            state.issued_attestation_ids.push(id.clone());
        }
    }
}

/// Attach an already-committed immutable receipt to an exact idempotent retry.
/// The operation handler calls this only after repeating its authorization and
/// reconstructing the original domain result in the same transaction.
pub(crate) fn note_replayed_action_attestation(attestation_id: String) {
    let _ = TRUSTED_PROVENANCE.try_with(|dispatch| {
        let mut state = dispatch.state.lock().expect("provenance dispatch lock");
        if !state.issued_attestation_ids.contains(&attestation_id) {
            state.issued_attestation_ids.push(attestation_id);
        }
    });
}

/// Transaction-scoped counterpart of [`lookup_authorized_command_attestation`].
/// Specialized aggregate handlers use this only after their complete
/// authorization and non-disclosure checks, keeping lookup and response
/// reconstruction in one snapshot.
pub(crate) async fn lookup_authorized_command_attestation_in(
    tx: &mut Transaction<'_, Sqlite>,
    principal: &str,
    operation: &str,
    arguments: &Value,
    intent: Option<&str>,
) -> Result<Option<String>> {
    let Some(command) = command_identity_digest(arguments) else {
        return Ok(None);
    };
    let row = sqlx::query(
        "SELECT a.id,a.action_digest,a.intent_digest
           FROM provenance_action_attestations a
           JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id
          WHERE a.principal=? AND a.operation=? AND a.command_identity_digest=?",
    )
    .bind(principal)
    .bind(operation)
    .bind(command)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.try_get::<String, _>("action_digest")? != action_digest(operation, arguments) {
        return Err(Error::engine(
            "idempotency command identity was reused with conflicting action input",
        ));
    }
    let expected_intent = intent.map(|value| digest_json(&json!(value)));
    if row.try_get::<Option<String>, _>("intent_digest")? != expected_intent {
        return Err(Error::engine(
            "idempotency command identity was reused under a different resolved intent",
        ));
    }
    Ok(Some(row.try_get("id")?))
}

/// Look up the original attestation only after the operation handler has
/// authorized the caller and resolved its durable idempotency result. This is
/// receipt attachment, not an authorization or mutation preflight.
pub(crate) async fn lookup_authorized_command_attestation(
    db: &Db,
    principal: &str,
    operation: &str,
    arguments: &Value,
    intent: Option<&str>,
) -> Result<Option<String>> {
    let Some(command) = command_identity_digest(arguments) else {
        return Ok(None);
    };
    let row = sqlx::query(
        "SELECT a.id,a.action_digest,a.intent_digest
           FROM provenance_action_attestations a
           JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id
          WHERE a.principal=? AND a.operation=? AND a.command_identity_digest=?",
    )
    .bind(principal)
    .bind(operation)
    .bind(command)
    .fetch_optional(db.write_pool())
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.try_get::<String, _>("action_digest")? != action_digest(operation, arguments) {
        return Err(Error::engine(
            "idempotency command identity was reused with conflicting action input",
        ));
    }
    let expected_intent = intent.map(|value| digest_json(&json!(value)));
    if row.try_get::<Option<String>, _>("intent_digest")? != expected_intent {
        return Err(Error::engine(
            "idempotency command identity was reused under a different resolved intent",
        ));
    }
    Ok(Some(row.try_get("id")?))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionAttestationSummary {
    pub id: String,
    pub schema_version: i64,
    pub executor_kind: String,
    pub has_verified_interaction: bool,
    /// `native_verified` requires a receiver-local issuance anchor. Portable
    /// source claims without that non-interchangeable anchor remain visible as
    /// `foreign_unverified` evidence.
    pub trust: AttestationTrust,
    pub operation: String,
    pub action_digest: String,
    pub output_event_set_digest: String,
    pub issuer: String,
    /// Stable source-database authority. Import preserves this identifier and
    /// never rewrites it to the receiving database's authority.
    pub issuer_origin_database_id: String,
    pub issued_at: String,
    pub intent_digest: Option<String>,
    /// Exact ordered, domain-qualified output membership. The legacy bare-ID
    /// list remains available for compatibility with v1 inspection clients.
    #[serde(default)]
    pub outputs: Vec<ActionOutput>,
    pub output_event_ids: Vec<String>,
    pub validity: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationTrust {
    NativeVerified,
    ForeignUnverified,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationWhy {
    pub principal: String,
    pub executor_ref_digest: Option<String>,
    pub delegation_present: bool,
    pub command_identity_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionDetail {
    Summary,
    Why,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // trusted host invalidation seam is intentionally not MCP-exposed
pub(crate) enum ValidityChange {
    Invalidated,
    Restored,
}

impl ValidityChange {
    fn as_str(self) -> &'static str {
        match self {
            Self::Invalidated => "invalidated",
            Self::Restored => "restored",
        }
    }
}

/// Trusted product seam for compromise/error handling. No MCP argument maps to
/// this function; host policy must authorize the issuer before calling it.
#[allow(dead_code)]
pub(crate) async fn append_validity_event_in(
    tx: &mut Transaction<'static, Sqlite>,
    attestation_id: &str,
    change: ValidityChange,
    reason: &str,
    issuer: &str,
) -> Result<String> {
    if reason.trim().is_empty() || issuer.trim().is_empty() {
        return Err(Error::engine(
            "provenance validity change requires reason and issuer",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let ordinal: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(ordinal), -1) + 1
           FROM provenance_attestation_validity_events WHERE attestation_id=?",
    )
    .bind(attestation_id)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO provenance_attestation_validity_events
            (id,attestation_id,ordinal,status,reason,issuer,issued_at) VALUES (?,?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(attestation_id)
    .bind(ordinal)
    .bind(change.as_str())
    .bind(reason)
    .bind(issuer)
    .bind(crate::store::now_iso())
    .execute(&mut **tx)
    .await?;
    crate::relationship::refresh_receiver_local_admissions_for_attestation_in(tx, attestation_id)
        .await?;
    Ok(id)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationInspection {
    pub attestation: ActionAttestationSummary,
    pub why: Option<AttestationWhy>,
    pub interaction: Option<VerifiedInteractionEvidenceView>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedInteractionEvidenceView {
    pub id: String,
    pub scope_digest: String,
    pub verifier_digest: String,
    pub verified_at: String,
    pub evidence_digest: String,
    pub retention_class: Option<String>,
    /// A sealed external reference was recorded. This does not claim the
    /// external bytes remain retained or retrievable.
    pub sealed_reference_recorded: bool,
}

/// Validate the immutable provenance substrate independently of bundle/file
/// hashes. Canonical interchange and conformance call this after foreign-key
/// validation so a self-consistent but semantically forged bundle fails closed.
pub async fn state_violations(db: &Db) -> Result<Vec<String>> {
    let mut connection = db.write_pool().acquire().await?;
    state_violations_on(&mut connection).await
}

pub(crate) fn state_violations_in<'a>(
    tx: &'a mut Transaction<'_, Sqlite>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>>> + Send + 'a>> {
    Box::pin(async move { state_violations_on(tx).await })
}

async fn state_violations_on(connection: &mut sqlx::SqliteConnection) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT id,schema_version,principal,operation,action_commitment,action_digest,output_event_set_digest,
                interaction_receipt_id,issuer_origin_database_id
           FROM provenance_action_attestations ORDER BY issued_at,id",
    )
    .fetch_all(&mut *connection)
    .await?;
    let mut violations = Vec::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        let canonical_text: String = row.try_get("action_commitment")?;
        match serde_json::from_str::<Value>(&canonical_text) {
            Ok(canonical) => {
                if String::from_utf8(crate::canonical_json::canonical_json(&canonical))
                    .ok()
                    .as_deref()
                    != Some(canonical_text.as_str())
                {
                    violations.push(format!("attestation {id} action commitment is not JCS"));
                }
                let operation: String = row.try_get("operation")?;
                let digest: String = row.try_get("action_digest")?;
                if !commitment_is_exact(&canonical, &operation, &digest) {
                    violations.push(format!("attestation {id} action digest is inconsistent"));
                }
            }
            Err(_) => violations.push(format!("attestation {id} action commitment is invalid")),
        }
        let issuer_origin_database_id: String = row.try_get("issuer_origin_database_id")?;
        if !crate::identity::is_database_id(&issuer_origin_database_id) {
            violations.push(format!(
                "attestation {id} issuer database authority is invalid"
            ));
        }
        let qualified_members = sqlx::query(
            "SELECT ordinal,output_domain,output_event_id
               FROM provenance_action_outputs
              WHERE action_attestation_id=? ORDER BY ordinal",
        )
        .bind(&id)
        .fetch_all(&mut *connection)
        .await?;
        if qualified_members.is_empty() {
            violations.push(format!("attestation {id} has no output events"));
        }
        let mut outputs = Vec::with_capacity(qualified_members.len());
        for (expected, member) in qualified_members.iter().enumerate() {
            if member.try_get::<i64, _>("ordinal")? != i64::try_from(expected).unwrap_or(i64::MAX) {
                violations.push(format!(
                    "attestation {id} output ordinals are not contiguous"
                ));
            }
            let domain: String = member.try_get("output_domain")?;
            let event_id: String = member.try_get("output_event_id")?;
            let exists: bool = match domain.as_str() {
                "content" => sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM content_events WHERE id=?)",
                )
                .bind(&event_id)
                .fetch_one(&mut *connection)
                .await?,
                "relationship" => sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM relationship_events WHERE id=? AND issuer_origin_db_id=(SELECT issuer_origin_database_id FROM provenance_action_attestations WHERE id=?))",
                )
                .bind(&event_id)
                .bind(&id)
                .fetch_one(&mut *connection)
                .await?,
                _ => false,
            };
            if !exists {
                violations.push(format!(
                    "attestation {id} output {domain}:{event_id} does not exist"
                ));
            }
            outputs.push(ActionOutput {
                domain: match domain.as_str() {
                    "content" => OutputDomain::Content,
                    "relationship" => OutputDomain::Relationship,
                    _ => continue,
                },
                event_id,
            });
        }
        let schema_version: i64 = row.try_get("schema_version")?;
        let stored_digest: String = row.try_get("output_event_set_digest")?;
        if schema_version == LEGACY_ACTION_ATTESTATION_SCHEMA_VERSION {
            let legacy_members = sqlx::query(
                "SELECT ordinal,output_event_id FROM provenance_action_events
                  WHERE action_attestation_id=? ORDER BY ordinal",
            )
            .bind(&id)
            .fetch_all(&mut *connection)
            .await?;
            let mut ids = Vec::with_capacity(legacy_members.len());
            for (expected, member) in legacy_members.iter().enumerate() {
                if member.try_get::<i64, _>("ordinal")?
                    != i64::try_from(expected).unwrap_or(i64::MAX)
                {
                    violations.push(format!(
                        "attestation {id} legacy output ordinals are not contiguous"
                    ));
                }
                ids.push(member.try_get::<String, _>("output_event_id")?);
            }
            if digest_json(&json!(ids)) != stored_digest {
                violations.push(format!(
                    "attestation {id} v1 output event digest is inconsistent"
                ));
            }
            let qualified_content = outputs
                .iter()
                .filter(|output| output.domain == OutputDomain::Content)
                .map(|output| output.event_id.as_str())
                .collect::<Vec<_>>();
            if outputs.len() != ids.len()
                || qualified_content != ids.iter().map(String::as_str).collect::<Vec<_>>()
            {
                violations.push(format!(
                    "attestation {id} v1 domain-qualified outputs differ from compatibility membership"
                ));
            }
        } else if schema_version == ACTION_ATTESTATION_SCHEMA_VERSION {
            if ordered_output_set_digest(&outputs) != stored_digest {
                violations.push(format!(
                    "attestation {id} v2 output event digest is inconsistent"
                ));
            }
        } else {
            violations.push(format!("attestation {id} has unsupported schema version"));
        }
        if let Some(receipt_id) = row.try_get::<Option<String>, _>("interaction_receipt_id")? {
            let receipt_principal: Option<String> = sqlx::query_scalar(
                "SELECT principal FROM provenance_interaction_receipts WHERE id=?",
            )
            .bind(receipt_id)
            .fetch_optional(&mut *connection)
            .await?;
            match receipt_principal {
                None => violations.push(format!("attestation {id} interaction receipt is missing")),
                Some(receipt_principal)
                    if receipt_principal != row.try_get::<String, _>("principal")? =>
                {
                    violations.push(format!(
                        "attestation {id} interaction receipt principal is inconsistent"
                    ));
                }
                Some(_) => {}
            }
        }
        let validity_ordinals = sqlx::query_scalar::<_, i64>(
            "SELECT ordinal FROM provenance_attestation_validity_events
              WHERE attestation_id=? ORDER BY ordinal",
        )
        .bind(&id)
        .fetch_all(&mut *connection)
        .await?;
        if validity_ordinals
            .iter()
            .enumerate()
            .any(|(expected, actual)| *actual != i64::try_from(expected).unwrap_or(i64::MAX))
        {
            violations.push(format!(
                "attestation {id} validity ordinals are not contiguous"
            ));
        }
    }
    let local_anchors = sqlx::query(
        "SELECT l.attestation_id,l.issuer_origin_database_id,l.principal AS anchor_principal,
                l.operation AS anchor_operation,l.command_identity_digest AS anchor_command,
                a.issuer,a.issuer_origin_database_id AS attestation_origin,
                a.principal AS attestation_principal,a.operation AS attestation_operation,
                a.command_identity_digest AS attestation_command,
                EXISTS(SELECT 1 FROM database_identity_audit d
                        WHERE d.new_origin_db_id=l.issuer_origin_database_id) AS origin_known
           FROM provenance_local_attestation_authority l
           LEFT JOIN provenance_action_attestations a ON a.id=l.attestation_id
          ORDER BY l.attestation_id",
    )
    .fetch_all(&mut *connection)
    .await?;
    for anchor in local_anchors {
        let id: String = anchor.try_get("attestation_id")?;
        let anchor_origin: String = anchor.try_get("issuer_origin_database_id")?;
        let attestation_origin: Option<String> = anchor.try_get("attestation_origin")?;
        let issuer: Option<String> = anchor.try_get("issuer")?;
        let origin_known: bool = anchor.try_get("origin_known")?;
        let anchor_principal: String = anchor.try_get("anchor_principal")?;
        let anchor_operation: String = anchor.try_get("anchor_operation")?;
        let anchor_command: Option<String> = anchor.try_get("anchor_command")?;
        if issuer.as_deref() != Some(ISSUER)
            || attestation_origin.as_deref() != Some(anchor_origin.as_str())
            || anchor
                .try_get::<Option<String>, _>("attestation_principal")?
                .as_deref()
                != Some(anchor_principal.as_str())
            || anchor
                .try_get::<Option<String>, _>("attestation_operation")?
                .as_deref()
                != Some(anchor_operation.as_str())
            || anchor.try_get::<Option<String>, _>("attestation_command")? != anchor_command
            || !origin_known
        {
            violations.push(format!(
                "attestation {id} local issuance authority is inconsistent"
            ));
        }
    }
    Ok(violations)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[allow(dead_code)] // consumed by the attribution feature stacked on v31
pub(crate) struct ActionAttestationEvidence {
    pub id: String,
    pub principal: String,
    pub executor_kind: String,
    pub executor_ref: Option<String>,
    pub delegation_ref: Option<String>,
    pub output_event_ids: Vec<String>,
    pub outputs: Vec<ActionOutput>,
}

async fn authorized_action_outputs_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    attestation_id: &str,
    authorized_attribution_id: Option<&str>,
) -> Result<Option<Vec<ActionOutput>>> {
    let rows = sqlx::query(
        "SELECT ordinal,output_domain,output_event_id
           FROM provenance_action_outputs
          WHERE action_attestation_id=? ORDER BY ordinal",
    )
    .bind(attestation_id)
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut outputs = Vec::with_capacity(rows.len());
    for (expected, row) in rows.into_iter().enumerate() {
        if row.try_get::<i64, _>("ordinal").unwrap_or(-1)
            != i64::try_from(expected).unwrap_or(i64::MAX)
        {
            return Ok(None);
        }
        let domain: String = row.try_get("output_domain")?;
        let event_id: String = row.try_get("output_event_id")?;
        let output = match domain.as_str() {
            "content" => {
                let record_id: Option<String> =
                    sqlx::query_scalar("SELECT record_id FROM content_events WHERE id=?")
                        .bind(&event_id)
                        .fetch_optional(&mut **tx)
                        .await?;
                let Some(record_id) = record_id else {
                    return Ok(None);
                };
                if authorized_attribution_id != Some(record_id.as_str())
                    && !crate::mcp::tools::can_record_in(tx, caller, &record_id, Capability::View)
                        .await?
                {
                    return Ok(None);
                }
                ActionOutput::content(event_id)
            }
            "relationship" => {
                let endpoints = sqlx::query_scalar::<_, Option<String>>(
                    "SELECT endpoint.record_id
                       FROM relationship_events event
                       JOIN relationship_endpoints endpoint
                         ON endpoint.relationship_origin_db_id=event.relationship_origin_db_id
                        AND endpoint.relationship_id=event.relationship_id
                      WHERE event.id=? AND event.issuer_origin_db_id=(
                            SELECT issuer_origin_database_id FROM provenance_action_attestations WHERE id=?)
                      ORDER BY endpoint.ordinal",
                )
                .bind(&event_id)
                .bind(attestation_id)
                .fetch_all(&mut **tx)
                .await?;
                if endpoints.is_empty() {
                    return Ok(None);
                }
                for record_id in endpoints {
                    let Some(record_id) = record_id else {
                        return Ok(None);
                    };
                    if !crate::mcp::tools::can_record_in(tx, caller, &record_id, Capability::View)
                        .await?
                    {
                        return Ok(None);
                    }
                }
                ActionOutput::relationship(event_id)
            }
            _ => return Ok(None),
        };
        outputs.push(output);
    }
    Ok(Some(outputs))
}

fn attested_output_digest_is_exact(
    schema_version: i64,
    outputs: &[ActionOutput],
    stored: &str,
) -> bool {
    match schema_version {
        LEGACY_ACTION_ATTESTATION_SCHEMA_VERSION => {
            outputs
                .iter()
                .all(|output| output.domain == OutputDomain::Content)
                && digest_json(&json!(outputs
                    .iter()
                    .map(|output| &output.event_id)
                    .collect::<Vec<_>>()))
                    == stored
        }
        ACTION_ATTESTATION_SCHEMA_VERSION => ordered_output_set_digest(outputs) == stored,
        _ => false,
    }
}

/// Transaction-scoped evidence validation for authored claims. Absence,
/// unreadable outputs, and a mismatched executor kind deliberately collapse to
/// one error so an evidence reference is not an authorization oracle.
#[allow(dead_code)] // consumed by the attribution feature stacked on v31
pub(crate) async fn validate_action_attestation_evidence_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    attestation_id: &str,
    required_executor_kind: Option<&str>,
) -> Result<ActionAttestationEvidence> {
    validate_action_attestation_evidence_scoped_in(
        tx,
        caller,
        attestation_id,
        required_executor_kind,
        None,
    )
    .await
}

/// Dedicated attribution reads authorize through the bearer rather than the
/// hidden Annotation record. Retain the same attestation integrity checks, but
/// allow output membership in that one already-authorized annotation.
pub(crate) async fn validate_attribution_attestation_evidence_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    attestation_id: &str,
    required_executor_kind: Option<&str>,
    annotation_id: &str,
) -> Result<ActionAttestationEvidence> {
    validate_action_attestation_evidence_scoped_in(
        tx,
        caller,
        attestation_id,
        required_executor_kind,
        Some(annotation_id),
    )
    .await
}

async fn validate_action_attestation_evidence_scoped_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    attestation_id: &str,
    required_executor_kind: Option<&str>,
    authorized_attribution_id: Option<&str>,
) -> Result<ActionAttestationEvidence> {
    let row = sqlx::query(
        "SELECT a.id,a.schema_version,a.principal,a.executor_kind,a.executor_ref,a.delegation_ref,
                a.operation,a.action_commitment,a.action_digest,a.output_event_set_digest,
                a.issuer_origin_database_id
           FROM provenance_action_attestations a
           JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id
          WHERE a.id=?",
    )
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let hidden = || Error::engine("provenance action attestation does not exist");
    let Some(row) = row else {
        return Err(hidden());
    };
    let executor_kind: String = row.try_get("executor_kind")?;
    if required_executor_kind.is_some_and(|required| required != executor_kind) {
        return Err(hidden());
    }
    let canonical_text: String = row.try_get("action_commitment")?;
    let canonical: Value = serde_json::from_str(&canonical_text).map_err(|_| hidden())?;
    let operation: String = row.try_get("operation")?;
    let digest: String = row.try_get("action_digest")?;
    let issuer_origin_database_id: String = row.try_get("issuer_origin_database_id")?;
    if String::from_utf8(crate::canonical_json::canonical_json(&canonical))
        .ok()
        .as_deref()
        != Some(canonical_text.as_str())
        || !commitment_is_exact(&canonical, &operation, &digest)
        || !crate::identity::is_database_id(&issuer_origin_database_id)
    {
        return Err(hidden());
    }
    let validity: Option<String> = sqlx::query_scalar(
        "SELECT status FROM provenance_attestation_validity_events
          WHERE attestation_id=? ORDER BY ordinal DESC LIMIT 1",
    )
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?;
    if validity.as_deref() == Some("invalidated") {
        return Err(hidden());
    }
    let Some(outputs) =
        authorized_action_outputs_in(tx, caller, attestation_id, authorized_attribution_id).await?
    else {
        return Err(hidden());
    };
    if !attested_output_digest_is_exact(
        row.try_get("schema_version")?,
        &outputs,
        &row.try_get::<String, _>("output_event_set_digest")?,
    ) {
        return Err(hidden());
    }
    let output_event_ids = outputs
        .iter()
        .map(|output| output.event_id.clone())
        .collect();
    Ok(ActionAttestationEvidence {
        id: row.try_get("id")?,
        principal: row.try_get("principal")?,
        executor_kind,
        executor_ref: row.try_get("executor_ref")?,
        delegation_ref: row.try_get("delegation_ref")?,
        output_event_ids,
        outputs,
    })
}

pub async fn inspect_action_attestation(
    db: &Db,
    caller: &Caller,
    attestation_id: &str,
    detail: InspectionDetail,
) -> Result<Option<AttestationInspection>> {
    if !state_violations(db).await?.is_empty() {
        return Err(Error::engine("provenance attestation state is invalid"));
    }
    let mut tx = db.write_pool().begin().await?;
    let result = inspect_action_attestation_in(&mut tx, caller, attestation_id, detail, None).await;
    match result {
        Ok(value) => {
            tx.rollback().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Inspect one attestation inside a caller-owned read snapshot.
///
/// Attribution reads pass the already-authorized hidden Annotation id so its
/// own authoring event may be explained without making that infrastructure
/// record generically readable. Every other output record still passes the
/// ordinary provenance visibility gate. Callers must validate global
/// provenance state before opening the snapshot.
pub(crate) async fn inspect_action_attestation_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    attestation_id: &str,
    detail: InspectionDetail,
    authorized_attribution_id: Option<&str>,
) -> Result<Option<AttestationInspection>> {
    let row = sqlx::query(
        "SELECT a.id,a.schema_version,a.principal,a.executor_kind,a.executor_ref,a.delegation_ref,
                a.interaction_receipt_id,a.operation,a.action_digest,a.output_event_set_digest,
                a.issuer,a.issuer_origin_database_id,a.issued_at,a.command_identity_digest,a.intent_digest,
                l.attestation_id IS NOT NULL AS native_verified
           FROM provenance_action_attestations a
           LEFT JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id
          WHERE a.id=?",
    )
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let Some(outputs) =
        authorized_action_outputs_in(tx, caller, attestation_id, authorized_attribution_id).await?
    else {
        return Ok(None);
    };
    if !attested_output_digest_is_exact(
        row.try_get("schema_version")?,
        &outputs,
        &row.try_get::<String, _>("output_event_set_digest")?,
    ) {
        return Ok(None);
    }
    let principal: String = row.try_get("principal")?;
    let interaction_receipt_id: Option<String> = row.try_get("interaction_receipt_id")?;
    let native_verified: bool = row.try_get("native_verified")?;
    let interaction = if detail == InspectionDetail::Why
        && native_verified
        && principal == caller.credential()
        && interaction_receipt_id.is_some()
    {
        let receipt = sqlx::query(
            "SELECT id,scope_digest,verifier,verified_at,evidence_digest,
                    retention_class,sealed_evidence_ref
               FROM provenance_interaction_receipts WHERE id=?",
        )
        .bind(interaction_receipt_id.as_deref())
        .fetch_optional(&mut **tx)
        .await?;
        receipt
            .map(|receipt| -> Result<_> {
                Ok(VerifiedInteractionEvidenceView {
                    id: receipt.try_get("id")?,
                    scope_digest: receipt.try_get("scope_digest")?,
                    verifier_digest: digest_json(&json!(receipt.try_get::<String, _>("verifier")?)),
                    verified_at: receipt.try_get("verified_at")?,
                    evidence_digest: receipt.try_get("evidence_digest")?,
                    retention_class: receipt.try_get("retention_class")?,
                    sealed_reference_recorded: receipt
                        .try_get::<Option<String>, _>("sealed_evidence_ref")?
                        .is_some(),
                })
            })
            .transpose()?
    } else {
        None
    };
    let validity = sqlx::query_scalar::<_, String>(
        "SELECT status FROM provenance_attestation_validity_events
          WHERE attestation_id=? ORDER BY ordinal DESC LIMIT 1",
    )
    .bind(attestation_id)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_else(|| "valid".into());
    let why = (detail == InspectionDetail::Why
        && native_verified
        && principal == caller.credential())
    .then(|| {
        let digest_secret = |value: Option<String>| value.map(|value| digest_json(&json!(value)));
        AttestationWhy {
            principal: principal.clone(),
            executor_ref_digest: digest_secret(row.try_get("executor_ref").ok().flatten()),
            delegation_present: row
                .try_get::<Option<String>, _>("delegation_ref")
                .ok()
                .flatten()
                .is_some(),
            command_identity_digest: row
                .try_get::<Option<String>, _>("command_identity_digest")
                .ok()
                .flatten(),
        }
    });
    Ok(Some(AttestationInspection {
        attestation: ActionAttestationSummary {
            id: row.try_get("id")?,
            schema_version: row.try_get("schema_version")?,
            executor_kind: row.try_get("executor_kind")?,
            has_verified_interaction: native_verified && interaction_receipt_id.is_some(),
            trust: if native_verified {
                AttestationTrust::NativeVerified
            } else {
                AttestationTrust::ForeignUnverified
            },
            operation: row.try_get("operation")?,
            action_digest: row.try_get("action_digest")?,
            output_event_set_digest: row.try_get("output_event_set_digest")?,
            issuer: row.try_get("issuer")?,
            issuer_origin_database_id: row.try_get("issuer_origin_database_id")?,
            issued_at: row.try_get("issued_at")?,
            intent_digest: row.try_get("intent_digest")?,
            output_event_ids: outputs
                .iter()
                .map(|output| output.event_id.clone())
                .collect(),
            outputs,
            validity,
        },
        why,
        interaction,
    }))
}

/// Bounded Summary inspection for attribution reads. Domain-qualified outputs
/// share the scalar authorization path so mixed-domain attestations cannot skip
/// relationship endpoint non-disclosure checks.
pub(crate) async fn inspect_action_attestation_summaries_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    requests: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Option<AttestationInspection>>> {
    if requests.is_empty() {
        return Ok(BTreeMap::new());
    }
    if requests.len() > crate::interpretation::MAX_INTERPRETATION_OUTPUT_RECORDS {
        return Err(Error::engine(
            "bounded provenance summary output authorization is unavailable",
        ));
    }
    let mut inspections = BTreeMap::new();
    for (attestation_id, authorized_attribution_id) in requests {
        let inspection = inspect_action_attestation_in(
            tx,
            caller,
            attestation_id,
            InspectionDetail::Summary,
            Some(authorized_attribution_id),
        )
        .await?;
        inspections.insert(attestation_id.clone(), inspection);
    }
    Ok(inspections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{CustomInteractionPolicy, ToolExposure, ToolRegistry};
    use crate::store::{append_batch, AppendSpec};

    #[test]
    fn verified_webhook_dispatch_has_truthful_delegated_attribution() {
        let caller = unsafe {
            Caller::authenticated("acct:issuer")
                .with_verified_delegated_service("endpoint-1", "credential-1")
                .unwrap()
        }
        .with_channel(Channel::Mcp);
        assert_eq!(caller.channel(), Channel::Webhook);
        let dispatch = ProvenanceDispatch::from_caller(
            &caller,
            "create_record",
            &json!({"name":"meeting"}),
            None,
        );
        assert_eq!(dispatch.facts.executor_kind, "delegated_service");
        assert_eq!(dispatch.facts.channel, Channel::Webhook);
        assert_eq!(
            dispatch.facts.executor_ref.as_deref(),
            Some("webhook:endpoint-1")
        );
        assert_eq!(
            dispatch.facts.delegation_ref.as_deref(),
            Some("webhook-credential:credential-1")
        );
    }

    #[test]
    fn action_digest_is_object_order_independent() {
        let first = serde_json::from_str(r#"{"z":1,"nested":{"b":2,"a":1}}"#).unwrap();
        let second = serde_json::from_str(r#"{"nested":{"a":1,"b":2},"z":1}"#).unwrap();
        assert_eq!(
            action_digest("update_record", &first),
            action_digest("update_record", &second)
        );
    }

    #[test]
    fn action_commitment_shape_is_exact_and_digest_only() {
        let valid = action_commitment("attach_text", &json!({"text":"private"}));
        let digest = digest_json(&valid);
        assert!(commitment_is_exact(&valid, "attach_text", &digest));
        let mut extra = valid.clone();
        extra
            .as_object_mut()
            .unwrap()
            .insert("text".into(), json!("private"));
        assert!(!commitment_is_exact(
            &extra,
            "attach_text",
            &digest_json(&extra)
        ));
        assert!(!commitment_is_exact(
            &json!({"operation":"attach_text","arguments_digest":"not-a-digest"}),
            "attach_text",
            &digest
        ));
    }

    #[test]
    fn ordered_event_digest_is_order_sensitive() {
        fn event(id: &str) -> EventRow {
            EventRow {
                local_seq: 1,
                id: id.into(),
                record_id: "record".into(),
                event_type: "record.updated".into(),
                payload: None,
                actor: None,
                run_key: None,
                parent_key: None,
                intent: None,
                created_at: "now".into(),
                causal_envelope: crate::events::CausalEnvelopeV1::complete(
                    crate::events::CausalFrontierV1::empty(),
                ),
            }
        }
        assert_ne!(
            ordered_v1_event_set_digest(&[event("a"), event("b")]),
            ordered_v1_event_set_digest(&[event("b"), event("a")])
        );
    }

    #[test]
    fn v2_output_digest_is_domain_qualified_and_order_sensitive() {
        let content = ActionOutput::content("same-event-id");
        let relationship = ActionOutput::relationship("same-event-id");
        assert_ne!(
            ordered_output_set_digest(std::slice::from_ref(&content)),
            ordered_output_set_digest(std::slice::from_ref(&relationship))
        );
        assert_ne!(
            ordered_output_set_digest(&[content.clone(), relationship.clone()]),
            ordered_output_set_digest(&[relationship, content])
        );
    }

    /// Pinned fixture record ids that are also interpolated into SQL text.
    /// Everything else in this module uses an inline pinned literal; these two
    /// need a name so the fixture and the SQL cannot drift apart.
    const PERSON_A_ID: &str = "b40ce000-0000-4000-8000-000000000004";
    const RECORD_RETRY_ID: &str = "b40ce000-0000-4000-8000-000000000020";

    fn create_spec(id: &str, name: &str) -> AppendSpec {
        AppendSpec {
            record_id: id.into(),
            event_type: "record.created".into(),
            payload: json!({"type":"Document","kind":"note","name":name}),
            actor: Some("acct:writer".into()),
        }
    }

    fn relationship_created(
        origin: &str,
        left_id: &str,
        left_kind: (&str, &str),
        right_id: &str,
        right_kind: (&str, &str),
        definition_id: &str,
    ) -> crate::relationship::RelationshipCreatedV1 {
        let definition = crate::relationship::core_relationship_type_manifest()
            .unwrap()
            .relationship_types
            .into_iter()
            .find(|definition| definition.id == definition_id)
            .unwrap();
        let roles = definition
            .endpoints
            .iter()
            .flat_map(|rule| std::iter::repeat_n(rule.role.as_str(), rule.minimum as usize))
            .collect::<Vec<_>>();
        let endpoints = vec![
            crate::relationship::RelationshipEndpoint {
                role: roles[0].into(),
                portable_ref: crate::identity::encode_native_record(origin, left_id).unwrap(),
                record_type: Some(left_kind.0.into()),
                record_kind: Some(left_kind.1.into()),
                record_id: Some(left_id.into()),
            },
            crate::relationship::RelationshipEndpoint {
                role: roles[1].into(),
                portable_ref: crate::identity::encode_native_record(origin, right_id).unwrap(),
                record_type: Some(right_kind.0.into()),
                record_kind: Some(right_kind.1.into()),
                record_id: Some(right_id.into()),
            },
        ];
        let key = definition
            .canonical_proposition_key(
                &endpoints
                    .iter()
                    .map(crate::relationship::RelationshipEndpoint::proposition_endpoint)
                    .collect::<Vec<_>>(),
                &BTreeMap::new(),
            )
            .unwrap();
        crate::relationship::RelationshipCreatedV1 {
            schema_version: 1,
            relationship_revision: 1,
            relationship_type: definition.relationship_type,
            type_definition_id: definition.id,
            endpoint_semantics: definition.endpoint_semantics,
            endpoints,
            identity_qualifiers: serde_json::Map::new(),
            canonical_proposition_key: key,
            reducer_id: definition.reducer.id,
            reducer_version: definition.reducer.version,
            legacy_link: None,
        }
    }

    #[tokio::test]
    async fn governed_routes_mint_only_transaction_authorized_origin_admission() {
        let db = crate::create_database(":memory:").await.unwrap();
        for (id, record_type, kind) in [
            ("b40ce000-0000-4000-8000-000000000001", "Document", "note"),
            (PERSON_A_ID, "Entity", "person"),
            ("b40ce000-0000-4000-8000-000000000005", "WorkItem", "task"),
        ] {
            crate::store::append(
                &db,
                AppendSpec {
                    record_id: id.into(),
                    event_type: "record.created".into(),
                    payload: json!({"type":record_type,"kind":kind,"name":id}),
                    actor: Some("local".into()),
                },
            )
            .await
            .unwrap();
        }
        sqlx::query(&format!(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical)
                 VALUES('{PERSON_A_ID}','account','local',1)"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let relates = relationship_created(
            &origin,
            "b40ce000-0000-4000-8000-000000000001",
            ("Document", "note"),
            PERSON_A_ID,
            ("Entity", "person"),
            "relates_to.v1",
        );
        let assigned = relationship_created(
            &origin,
            "b40ce000-0000-4000-8000-000000000005",
            ("WorkItem", "task"),
            PERSON_A_ID,
            ("Entity", "person"),
            "assigned_to.v1",
        );
        let caller = Caller::local();
        let dispatch = ProvenanceDispatch::from_caller(
            &caller,
            "manage_relationships",
            &json!({"action":"assert"}),
            None,
        );
        dispatch
            .scope(async {
                let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
                let draft = reserve_action_attestation().unwrap();
                authorize_local_origin_admission_in(
                    &mut tx,
                    &caller,
                    &draft,
                    &assigned,
                    "support",
                    "task_authorised_support",
                    "subject",
                    &assigned.endpoints[0].portable_ref,
                )
                .await
                .unwrap();
                assert!(authorize_local_origin_admission_in(
                    &mut tx,
                    &caller,
                    &draft,
                    &assigned,
                    "support",
                    "task_authorised_support",
                    "object",
                    &assigned.endpoints[1].portable_ref,
                )
                .await
                .is_err());
                authorize_local_origin_admission_in(
                    &mut tx,
                    &caller,
                    &draft,
                    &relates,
                    "support",
                    "anchor_authorised_support",
                    "participant",
                    &relates.endpoints[0].portable_ref,
                )
                .await
                .unwrap();
                authorize_local_origin_admission_in(
                    &mut tx,
                    &caller,
                    &draft,
                    &relates,
                    "contest",
                    "endpoint_bound_contest",
                    "participant",
                    &relates.endpoints[1].portable_ref,
                )
                .await
                .unwrap();
                assert!(authorize_local_origin_admission_in(
                    &mut tx,
                    &caller,
                    &draft,
                    &relates,
                    "contest",
                    "endpoint_bound_contest",
                    "participant",
                    &relates.endpoints[0].portable_ref,
                )
                .await
                .is_err());
                tx.rollback().await.unwrap();
            })
            .await;
        db.close().await;
    }

    #[tokio::test]
    async fn mixed_relationship_outputs_bind_v2_and_receiver_local_admission() {
        let db = crate::create_database(":memory:").await.unwrap();
        for id in [
            "b40ce000-0000-4000-8000-000000000002",
            "b40ce000-0000-4000-8000-000000000003",
        ] {
            crate::store::append(&db, create_spec(id, id))
                .await
                .unwrap();
        }
        let origin = crate::identity::database_id(&db).await.unwrap();
        let created = relationship_created(
            &origin,
            "b40ce000-0000-4000-8000-000000000002",
            ("Document", "note"),
            "b40ce000-0000-4000-8000-000000000003",
            ("Document", "note"),
            "relates_to.v1",
        );
        let caller = Caller::local();
        let dispatch = ProvenanceDispatch::from_caller(
            &caller,
            "manage_relationships",
            &json!({"action":"assert"}),
            None,
        );
        dispatch
            .scope(async {
                let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
                let content_output = crate::store::append_in(
                    &db,
                    &mut tx,
                    create_spec(
                        "b40ce000-0000-4000-8000-000000000007",
                        "relationship action",
                    ),
                )
                .await
                .unwrap();
                let draft = reserve_action_attestation().unwrap();
                let admission = authorize_local_origin_admission_in(
                    &mut tx,
                    &caller,
                    &draft,
                    &created,
                    "support",
                    "anchor_authorised_support",
                    "participant",
                    &created.endpoints[0].portable_ref,
                )
                .await
                .unwrap();
                let origin_admission =
                    crate::relationship::OriginAdmissionV1::from_local_authorization(admission);
                let assertion = crate::relationship::AssertionCreatedV1 {
                    schema_version: 1,
                    relationship: crate::relationship::RelationshipCoordinate {
                        relationship_origin_db_id: origin.clone(),
                        relationship_id: Uuid::new_v4().to_string(),
                        relationship_revision: 1,
                    },
                    relationship_created_event: crate::relationship::RelationshipEventCoordinate {
                        issuer_origin_db_id: origin.clone(),
                        event_id: Uuid::new_v4().to_string(),
                    },
                    stance: "support".into(),
                    semantic_claimant: accepted_executor_ref().unwrap(),
                    on_behalf_of: Some("semantic-subject:test".into()),
                    rationale: Some("test".into()),
                    valid_from: None,
                    valid_until: None,
                    causal_parents: Vec::new(),
                    origin_admission: origin_admission.clone(),
                    authoring_action_attestation_id: draft.id().into(),
                };
                let command = crate::relationship::prepare_relationship_with_assertion(
                    &origin,
                    caller.actor(),
                    &crate::store::now_iso(),
                    &crate::store::now_iso(),
                    created,
                    assertion,
                )
                .unwrap();
                crate::relationship::create_relationship_with_assertion_in(&mut tx, &command)
                    .await
                    .unwrap();
                let outputs = [
                    ActionOutput::content(content_output.id),
                    ActionOutput::relationship(command.relationship_event.event_id.clone()),
                    ActionOutput::relationship(command.assertion_event.event_id.clone()),
                ];
                issue_action_attestation_outputs_in(&mut tx, draft, &outputs)
                    .await
                    .unwrap();
                assert!(verify_receiver_local_assertion_admission_in(
                    &mut tx,
                    &origin,
                    &command.assertion_event.event_id,
                    &origin_admission,
                )
                .await
                .unwrap());
                let projected: (String, String, String, i64) = sqlx::query_as(
                    "SELECT l.local_admission_state,e.effective_state,e.epistemic_state,
                            (SELECT COUNT(*) FROM links WHERE id=?3)
                       FROM relationship_local_admissions l
                       JOIN relationship_assertion_heads a
                         ON a.issuer_origin_db_id=l.issuer_origin_db_id
                        AND a.assertion_id=l.assertion_id
                       JOIN effective_relationships e
                         ON e.relationship_origin_db_id=a.relationship_origin_db_id
                        AND e.relationship_id=a.relationship_id
                      WHERE l.issuer_origin_db_id=?1 AND l.assertion_id=?2",
                )
                .bind(&origin)
                .bind(&command.assertion_event.stream_id)
                .bind(format!(
                    "rel:{}:{}",
                    command
                        .relationship_event
                        .relationship
                        .relationship_origin_db_id,
                    command.relationship_event.stream_id
                ))
                .fetch_one(&mut *tx)
                .await
                .unwrap();
                assert_eq!(
                    projected,
                    ("admitted".into(), "active".into(), "supported".into(), 1)
                );
                let mut tampered_value = serde_json::to_value(&origin_admission).unwrap();
                tampered_value["authorization_decision_digest"] =
                    json!(digest_json(&json!("different decision")));
                let tampered: crate::relationship::OriginAdmissionV1 =
                    serde_json::from_value(tampered_value).unwrap();
                assert!(!verify_receiver_local_assertion_admission_in(
                    &mut tx,
                    &origin,
                    &command.assertion_event.event_id,
                    &tampered,
                )
                .await
                .unwrap());
                assert!(!verify_receiver_local_assertion_admission_in(
                    &mut tx,
                    "ndb_ffffffffffffffffffffffffffffffff",
                    &command.assertion_event.event_id,
                    &origin_admission,
                )
                .await
                .unwrap());
                append_validity_event_in(
                    &mut tx,
                    origin_admission.authoring_action_attestation_id(),
                    ValidityChange::Invalidated,
                    "test invalidation",
                    "test",
                )
                .await
                .unwrap();
                assert!(!verify_receiver_local_assertion_admission_in(
                    &mut tx,
                    &origin,
                    &command.assertion_event.event_id,
                    &origin_admission,
                )
                .await
                .unwrap());
                let invalidated: (String, String, i64) = sqlx::query_as(
                    "SELECT l.local_admission_state,e.effective_state,
                            (SELECT COUNT(*) FROM links WHERE id=?3)
                       FROM relationship_local_admissions l
                       JOIN relationship_assertion_heads a
                         ON a.issuer_origin_db_id=l.issuer_origin_db_id
                        AND a.assertion_id=l.assertion_id
                       JOIN effective_relationships e
                         ON e.relationship_origin_db_id=a.relationship_origin_db_id
                        AND e.relationship_id=a.relationship_id
                      WHERE l.issuer_origin_db_id=?1 AND l.assertion_id=?2",
                )
                .bind(&origin)
                .bind(&command.assertion_event.stream_id)
                .bind(format!(
                    "rel:{}:{}",
                    command
                        .relationship_event
                        .relationship
                        .relationship_origin_db_id,
                    command.relationship_event.stream_id
                ))
                .fetch_one(&mut *tx)
                .await
                .unwrap();
                assert_eq!(invalidated, ("unresolved".into(), "inactive".into(), 0));
                db.commit_content(tx).await.unwrap();
            })
            .await;
        let attestation_id = dispatch.receipt_ids().pop().unwrap();
        let row: (i64, i64, i64) = sqlx::query_as(
            "SELECT schema_version,
                    (SELECT COUNT(*) FROM provenance_action_outputs WHERE action_attestation_id=a.id),
                    (SELECT COUNT(*) FROM provenance_action_events WHERE action_attestation_id=a.id)
               FROM provenance_action_attestations a WHERE id=?",
        )
        .bind(&attestation_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(row, (2, 3, 0));
        let inspected =
            inspect_action_attestation(&db, &caller, &attestation_id, InspectionDetail::Summary)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            inspected.attestation.output_event_ids,
            inspected
                .attestation
                .outputs
                .iter()
                .map(|output| output.event_id.clone())
                .collect::<Vec<_>>()
        );
        let serialized = serde_json::to_value(inspected).unwrap();
        assert_eq!(
            serialized["attestation"]["outputs"],
            json!([
                {"domain":"content","event_id":serialized["attestation"]["output_event_ids"][0]},
                {"domain":"relationship","event_id":serialized["attestation"]["output_event_ids"][1]},
                {"domain":"relationship","event_id":serialized["attestation"]["output_event_ids"][2]},
            ])
        );
        let semantic_context: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT h.on_behalf_of,a.delegation_ref
               FROM relationship_assertion_heads h
               JOIN provenance_action_attestations a
                 ON a.id=h.authoring_action_attestation_id",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(semantic_context.0.as_deref(), Some("semantic-subject:test"));
        assert_eq!(
            semantic_context.1, None,
            "semantic on_behalf_of must never become verified delegation"
        );
        let rebuilt = crate::conformance::rebuild_and_diff_relationship(&db)
            .await
            .unwrap();
        assert!(rebuilt.equal, "{rebuilt:?}");
        assert!(state_violations(&db).await.unwrap().is_empty());
        db.close().await;
    }

    #[tokio::test]
    async fn trusted_dispatch_issues_one_atomic_attestation_for_ordered_batch() {
        let db = crate::create_database(":memory:").await.unwrap();
        let caller = Caller::authenticated("acct:writer");
        let arguments = json!({"name":"batch"});
        let dispatch = ProvenanceDispatch::from_caller(&caller, "create_record", &arguments, None);
        dispatch
            .scope(async {
                append_batch(
                    &db,
                    vec![
                        create_spec("b40ce000-0000-4000-8000-000000000006", "A"),
                        create_spec("b40ce000-0000-4000-8000-000000000009", "B"),
                    ],
                )
                .await
                .unwrap();
            })
            .await;
        let ids = dispatch.receipt_ids();
        assert_eq!(ids.len(), 1);
        let members: Vec<String> = sqlx::query_scalar(
            "SELECT output_event_id FROM provenance_action_outputs
              WHERE action_attestation_id=? ORDER BY ordinal",
        )
        .bind(&ids[0])
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(members.len(), 2);
        let stored_digest: String = sqlx::query_scalar(
            "SELECT output_event_set_digest FROM provenance_action_attestations WHERE id=?",
        )
        .bind(&ids[0])
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            stored_digest,
            ordered_output_set_digest(
                &members
                    .iter()
                    .map(ActionOutput::content)
                    .collect::<Vec<_>>()
            )
        );
        db.close().await;
    }

    #[tokio::test]
    async fn rollback_and_calls_without_trusted_ingress_issue_nothing() {
        let db = crate::create_database(":memory:").await.unwrap();
        crate::store::append(
            &db,
            create_spec("b40ce000-0000-4000-8000-000000000018", "outside"),
        )
        .await
        .unwrap();
        let caller = Caller::authenticated("acct:writer");
        let dispatch = ProvenanceDispatch::from_caller(
            &caller,
            "create_record",
            &json!({"name":"rolled back"}),
            None,
        );
        dispatch
            .scope(async {
                let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
                let event = crate::store::append_in(
                    &db,
                    &mut tx,
                    create_spec("b40ce000-0000-4000-8000-000000000021", "rollback"),
                )
                .await
                .unwrap();
                let draft = reserve_action_attestation().unwrap();
                issue_action_attestation_in(&mut tx, draft, &[event])
                    .await
                    .unwrap();
                tx.rollback().await.unwrap();

                // A later successful commit confirms only IDs visible in its
                // transaction; it neither publishes nor drains the rolled-back ID.
                crate::store::append(
                    &db,
                    create_spec("b40ce000-0000-4000-8000-000000000008", "committed"),
                )
                .await
                .unwrap();
            })
            .await;
        assert_eq!(dispatch.receipt_ids().len(), 1);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
        db.close().await;
    }

    #[tokio::test]
    async fn issuer_rejects_duplicate_and_missing_outputs_without_partial_writes() {
        let db = crate::create_database(":memory:").await.unwrap();
        let dispatch = ProvenanceDispatch::from_caller(
            &Caller::local(),
            "create_record",
            &json!({"name":"invalid output set"}),
            None,
        );
        dispatch
            .scope(async {
                let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
                let event = crate::store::append_in(
                    &db,
                    &mut tx,
                    create_spec("b40ce000-0000-4000-8000-000000000017", "invalid outputs"),
                )
                .await
                .unwrap();
                let output = ActionOutput::content(event.id);
                let duplicate = issue_action_attestation_outputs_in(
                    &mut tx,
                    reserve_action_attestation().unwrap(),
                    &[output.clone(), output],
                )
                .await
                .unwrap_err();
                assert!(duplicate.to_string().contains("contains a duplicate"));

                note_appended_output(OutputDomain::Relationship, "missing-event");
                let missing = issue_action_attestation_outputs_in(
                    &mut tx,
                    reserve_action_attestation().unwrap(),
                    &[ActionOutput::relationship("missing-event")],
                )
                .await
                .unwrap_err();
                assert!(missing.to_string().contains("is not in the transaction"));
                tx.rollback().await.unwrap();
            })
            .await;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert!(dispatch.receipt_ids().is_empty());
        db.close().await;
    }

    #[tokio::test]
    async fn generic_interaction_binds_the_full_canonical_action_scope() {
        let db = crate::create_database(":memory:").await.unwrap();
        let arguments = json!({
            "target":{"record_id":"record:claim","revision":"event:7"},
            "relation":"expresses_stance_of",
            "polarity":"affirming"
        });
        let scope = verified_action_scope("create_attribution", &arguments);
        let issuer = ProvenanceInteractionTokenIssuer::random("host-ui");
        let token = issuer.issue("acct:human", &scope, 60).unwrap();
        let caller = Caller::authenticated("acct:human")
            .with_provenance_interaction_token(&issuer, &token, &scope)
            .unwrap();
        let dispatch =
            ProvenanceDispatch::from_caller(&caller, "create_attribution", &arguments, None);
        dispatch
            .scope(crate::store::append(
                &db,
                create_spec("b40ce000-0000-4000-8000-000000000014", "generic"),
            ))
            .await
            .unwrap();
        assert_eq!(dispatch.receipt_ids().len(), 1);
        let kind: String = sqlx::query_scalar(
            "SELECT executor_kind FROM provenance_action_attestations WHERE id=?",
        )
        .bind(&dispatch.receipt_ids()[0])
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(kind, "human");
        let tampered_scope = verified_action_scope(
            "create_attribution",
            &json!({
                "target":{"record_id":"record:claim","revision":"event:8"},
                "relation":"expresses_stance_of",
                "polarity":"affirming"
            }),
        );
        assert!(Caller::authenticated("acct:human")
            .with_provenance_interaction_token(&issuer, &token, &tampered_scope)
            .is_err());
        db.close().await;
    }

    #[tokio::test]
    async fn verified_interaction_is_reused_but_unverified_parameters_cannot_forge_it() {
        let db = crate::create_database(":memory:").await.unwrap();
        let issuer = crate::awareness::HumanInteractionTokenIssuer::random("host-ui");
        let message_ids = vec!["message:a".to_string()];
        let token = issuer
            .issue("acct:human", "confirm", &message_ids, 60)
            .unwrap();
        let caller = Caller::authenticated("acct:human")
            .with_human_interaction_token(&issuer, &token, "confirm", &message_ids)
            .unwrap();
        let arguments = json!({"action":"confirm","message_ids":message_ids});
        let dispatch =
            ProvenanceDispatch::from_caller(&caller, "manage_messages", &arguments, None);
        dispatch
            .scope(async {
                crate::store::append(
                    &db,
                    create_spec("b40ce000-0000-4000-8000-000000000015", "h1"),
                )
                .await
                .unwrap();
                crate::store::append(
                    &db,
                    create_spec("b40ce000-0000-4000-8000-000000000016", "h2"),
                )
                .await
                .unwrap();
            })
            .await;
        assert_eq!(dispatch.receipt_ids().len(), 2);
        let receipts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM provenance_interaction_receipts")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(receipts, 1);
        let human_actions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM provenance_action_attestations
              WHERE executor_kind='human' AND interaction_receipt_id IS NOT NULL",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(human_actions, 2);

        let forged = ProvenanceDispatch::from_caller(
            &Caller::authenticated("acct:agent"),
            "create_record",
            &json!({"verified_human":true,"executor_kind":"human"}),
            None,
        );
        forged
            .scope(crate::store::append(
                &db,
                create_spec("b40ce000-0000-4000-8000-000000000013", "forged"),
            ))
            .await
            .unwrap();
        let kind: String = sqlx::query_scalar(
            "SELECT executor_kind FROM provenance_action_attestations
              WHERE principal='acct:agent'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(kind, "authenticated_principal");
        db.close().await;
    }

    #[tokio::test]
    async fn command_reuse_conflict_rolls_back_and_exact_lookup_returns_original() {
        let db = crate::create_database(":memory:").await.unwrap();
        let caller = Caller::authenticated("acct:writer");
        let arguments = json!({"idempotency_key":"same","name":"first"});
        let first = ProvenanceDispatch::from_caller(&caller, "create_record", &arguments, None);
        first
            .scope(crate::store::append(
                &db,
                create_spec("b40ce000-0000-4000-8000-000000000012", "first"),
            ))
            .await
            .unwrap();
        let original = first.receipt_ids().pop().unwrap();
        assert_eq!(
            lookup_authorized_command_attestation(
                &db,
                caller.credential(),
                "create_record",
                &arguments,
                None,
            )
            .await
            .unwrap(),
            Some(original)
        );
        let conflict = lookup_authorized_command_attestation(
            &db,
            caller.credential(),
            "create_record",
            &json!({"idempotency_key":"same","name":"different"}),
            None,
        )
        .await
        .unwrap_err();
        assert!(conflict.to_string().contains("conflicting action input"));
        let intent_conflict = lookup_authorized_command_attestation(
            &db,
            caller.credential(),
            "create_record",
            &arguments,
            Some("different resolved intent"),
        )
        .await
        .unwrap_err();
        assert!(intent_conflict
            .to_string()
            .contains("different resolved intent"));
        db.close().await;
    }

    #[tokio::test]
    async fn durable_commitment_never_stores_raw_arguments_or_command_identity() {
        let db = crate::create_database(":memory:").await.unwrap();
        let caller = Caller::authenticated("acct:writer");
        let forbidden = [
            "secret attachment body",
            "private operator reason",
            "bearer-token-value",
            "raw-command-key",
        ];
        let arguments = json!({
            "text":"secret attachment body",
            "reason":"private operator reason",
            "token":"bearer-token-value",
            "idempotency_key":"raw-command-key"
        });
        let dispatch = ProvenanceDispatch::from_caller(&caller, "attach_text", &arguments, None);
        dispatch
            .scope(crate::store::append(
                &db,
                create_spec("b40ce000-0000-4000-8000-000000000019", "private"),
            ))
            .await
            .unwrap();
        let row = sqlx::query(
            "SELECT action_commitment,action_digest,command_identity_digest
               FROM provenance_action_attestations WHERE id=?",
        )
        .bind(&dispatch.receipt_ids()[0])
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let durable = format!(
            "{}:{}:{}",
            row.try_get::<String, _>("action_commitment").unwrap(),
            row.try_get::<String, _>("action_digest").unwrap(),
            row.try_get::<String, _>("command_identity_digest").unwrap()
        );
        for value in forbidden {
            assert!(!durable.contains(value));
        }
        assert_eq!(
            row.try_get::<String, _>("command_identity_digest")
                .unwrap()
                .len(),
            64
        );
        db.close().await;
    }

    #[tokio::test]
    async fn validity_uses_monotonic_ordinal_even_at_the_same_timestamp() {
        let db = crate::create_database(":memory:").await.unwrap();
        let dispatch = ProvenanceDispatch::from_caller(
            &Caller::local(),
            "create_record",
            &json!({"name":"validity"}),
            None,
        );
        dispatch
            .scope(crate::store::append(
                &db,
                create_spec("b40ce000-0000-4000-8000-000000000025", "validity"),
            ))
            .await
            .unwrap();
        let attestation_id = dispatch.receipt_ids().pop().unwrap();
        let same_time = "2026-08-10T00:00:00.000Z";
        sqlx::query(
            "INSERT INTO provenance_attestation_validity_events
                (id,attestation_id,ordinal,status,reason,issuer,issued_at)
             VALUES ('zz-invalid',?,0,'invalidated','compromise','operator',?),
                    ('aa-restored',?,1,'restored','resolved','operator',?)",
        )
        .bind(&attestation_id)
        .bind(same_time)
        .bind(&attestation_id)
        .bind(same_time)
        .execute(db.write_pool())
        .await
        .unwrap();
        let inspected = inspect_action_attestation(
            &db,
            &Caller::local(),
            &attestation_id,
            InspectionDetail::Summary,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(inspected.attestation.validity, "restored");
        db.close().await;
    }

    #[tokio::test]
    async fn bulk_summary_inspection_matches_scalar_visibility_and_current_validity() {
        let db = crate::create_database(":memory:").await.unwrap();
        let dispatch = ProvenanceDispatch::from_caller(
            &Caller::local(),
            "create_record",
            &json!({"name":"bulk summary"}),
            None,
        );
        dispatch
            .scope(crate::store::append(
                &db,
                create_spec("b40ce000-0000-4000-8000-000000000010", "bulk summary"),
            ))
            .await
            .unwrap();
        let attestation_id = dispatch.receipt_ids().pop().unwrap();
        let mut validity_tx = db.write_pool().begin().await.unwrap();
        append_validity_event_in(
            &mut validity_tx,
            &attestation_id,
            ValidityChange::Invalidated,
            "test invalidation",
            "test",
        )
        .await
        .unwrap();
        append_validity_event_in(
            &mut validity_tx,
            &attestation_id,
            ValidityChange::Restored,
            "test restoration",
            "test",
        )
        .await
        .unwrap();
        validity_tx.commit().await.unwrap();

        let foreign_event = crate::store::append(
            &db,
            create_spec(
                "b40ce000-0000-4000-8000-000000000011",
                "bulk summary foreign",
            ),
        )
        .await
        .unwrap();
        let foreign_attestation_id = "foreign-bulk-summary".to_string();
        let foreign_commitment = action_commitment("foreign_create", &json!({}));
        let foreign_commitment_text =
            String::from_utf8(crate::canonical_json::canonical_json(&foreign_commitment)).unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_attestations
                (id,schema_version,principal,executor_kind,operation,action_commitment,
                 action_digest,output_event_set_digest,issuer,issuer_origin_database_id,issued_at)
             VALUES (?,1,'foreign:principal','authenticated_principal','foreign_create',?,?,?,
                     'foreign-native',?,'2026-08-11T00:00:00.000Z')",
        )
        .bind(&foreign_attestation_id)
        .bind(foreign_commitment_text)
        .bind(digest_json(&foreign_commitment))
        .bind(ordered_v1_event_set_digest(std::slice::from_ref(
            &foreign_event,
        )))
        .bind(origin)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_outputs
                (action_attestation_id,ordinal,output_domain,output_event_id)
             VALUES (?,0,'content',?)",
        )
        .bind(&foreign_attestation_id)
        .bind(&foreign_event.id)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_events
                (action_attestation_id,ordinal,output_event_id) VALUES (?,0,?)",
        )
        .bind(&foreign_attestation_id)
        .bind(&foreign_event.id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let requests = BTreeMap::from([
            (attestation_id.clone(), "unrelated-annotation".into()),
            (
                foreign_attestation_id.clone(),
                "unrelated-annotation".into(),
            ),
            ("missing-attestation".into(), "unrelated-annotation".into()),
        ]);
        for (caller, foreign_visible) in [
            (Caller::local(), true),
            (Caller::authenticated("acct:hidden"), false),
        ] {
            let mut tx = db.write_pool().begin().await.unwrap();
            let bulk = inspect_action_attestation_summaries_in(&mut tx, &caller, &requests)
                .await
                .unwrap();
            for (id, annotation_id) in &requests {
                let scalar = inspect_action_attestation_in(
                    &mut tx,
                    &caller,
                    id,
                    InspectionDetail::Summary,
                    Some(annotation_id),
                )
                .await
                .unwrap();
                assert_eq!(bulk.get(id).cloned().flatten(), scalar, "{id}");
            }
            if foreign_visible {
                assert_eq!(
                    bulk[&foreign_attestation_id]
                        .as_ref()
                        .unwrap()
                        .attestation
                        .trust,
                    AttestationTrust::ForeignUnverified
                );
            }
            tx.rollback().await.unwrap();
        }
        db.close().await;
    }

    #[tokio::test]
    async fn semantic_validator_rejects_an_attestation_without_output_membership() {
        let db = crate::create_database(":memory:").await.unwrap();
        let commitment = action_commitment("forged", &json!({}));
        let issuer_origin_database_id = crate::identity::database_id(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_attestations
                (id,schema_version,principal,executor_kind,operation,action_commitment,
                 action_digest,output_event_set_digest,issuer,issuer_origin_database_id,issued_at)
             VALUES ('forged',1,'acct:forger','authenticated_principal','forged',?,?,?,
                     'native-ce',?,'2026-08-10T00:00:00.000Z')",
        )
        .bind(String::from_utf8(crate::canonical_json::canonical_json(&commitment)).unwrap())
        .bind(digest_json(&commitment))
        .bind(digest_json(&json!([])))
        .bind(issuer_origin_database_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let violations = state_violations(&db).await.unwrap();
        assert!(violations
            .iter()
            .any(|violation| violation.contains("has no output events")));
        assert!(inspect_action_attestation(
            &db,
            &Caller::local(),
            "forged",
            InspectionDetail::Summary
        )
        .await
        .is_err());
        db.close().await;
    }

    #[tokio::test]
    async fn conformance_accepts_exact_v1_and_v2_and_reports_tamper_gaps_and_missing_outputs() {
        let db = crate::create_database(":memory:").await.unwrap();
        let v1_event = crate::store::append(
            &db,
            create_spec("b40ce000-0000-4000-8000-000000000023", "v1"),
        )
        .await
        .unwrap();
        let v2_event = crate::store::append(
            &db,
            create_spec("b40ce000-0000-4000-8000-000000000024", "v2"),
        )
        .await
        .unwrap();
        let tamper_event = crate::store::append(
            &db,
            create_spec("b40ce000-0000-4000-8000-000000000022", "tamper"),
        )
        .await
        .unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let commitment = action_commitment("imported", &json!({}));
        let commitment_text =
            String::from_utf8(crate::canonical_json::canonical_json(&commitment)).unwrap();
        let action_digest = digest_json(&commitment);

        sqlx::query(
            "INSERT INTO provenance_action_attestations
                (id,schema_version,principal,executor_kind,operation,action_commitment,
                 action_digest,output_event_set_digest,issuer,issuer_origin_database_id,issued_at)
             VALUES ('exact-v1',1,'foreign:principal','authenticated_principal','imported',?,?,?,
                     'foreign-native',?,'2026-08-11T00:00:00.000Z'),
                    ('exact-v2',2,'foreign:principal','authenticated_principal','imported',?,?,?,
                     'foreign-native',?,'2026-08-11T00:00:00.000Z')",
        )
        .bind(&commitment_text)
        .bind(&action_digest)
        .bind(ordered_v1_event_set_digest(std::slice::from_ref(&v1_event)))
        .bind(&origin)
        .bind(&commitment_text)
        .bind(&action_digest)
        .bind(ordered_output_set_digest(&[ActionOutput::content(
            &v2_event.id,
        )]))
        .bind(&origin)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_events
                (action_attestation_id,ordinal,output_event_id) VALUES ('exact-v1',0,?)",
        )
        .bind(&v1_event.id)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_outputs
                (action_attestation_id,ordinal,output_domain,output_event_id)
             VALUES ('exact-v1',0,'content',?),('exact-v2',0,'content',?)",
        )
        .bind(&v1_event.id)
        .bind(&v2_event.id)
        .execute(db.write_pool())
        .await
        .unwrap();
        assert!(state_violations(&db).await.unwrap().is_empty());

        let duplicate = sqlx::query(
            "INSERT INTO provenance_action_outputs
                (action_attestation_id,ordinal,output_domain,output_event_id)
             VALUES ('exact-v2',1,'content',?)",
        )
        .bind(&v2_event.id)
        .execute(db.write_pool())
        .await;
        assert!(duplicate.is_err());

        sqlx::query(
            "INSERT INTO provenance_action_attestations
                (id,schema_version,principal,executor_kind,operation,action_commitment,
                 action_digest,output_event_set_digest,issuer,issuer_origin_database_id,issued_at)
             VALUES ('tampered-v2',2,'foreign:principal','authenticated_principal','imported',?,?,?,
                     'foreign-native',?,'2026-08-11T00:00:00.000Z'),
                    ('gap-and-missing',2,'foreign:principal','authenticated_principal','imported',?,?,?,
                     'foreign-native',?,'2026-08-11T00:00:00.000Z')",
        )
        .bind(&commitment_text)
        .bind(&action_digest)
        .bind("0".repeat(64))
        .bind(&origin)
        .bind(&commitment_text)
        .bind(&action_digest)
        .bind(ordered_output_set_digest(&[ActionOutput::relationship(
            "missing-relationship-event",
        )]))
        .bind(&origin)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_outputs
                (action_attestation_id,ordinal,output_domain,output_event_id)
             VALUES ('tampered-v2',0,'content',?),
                    ('gap-and-missing',1,'relationship','missing-relationship-event')",
        )
        .bind(&tamper_event.id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let violations = state_violations(&db).await.unwrap();
        assert!(violations.iter().any(|violation| {
            violation.contains("tampered-v2 v2 output event digest is inconsistent")
        }));
        assert!(violations.iter().any(|violation| {
            violation.contains("gap-and-missing output ordinals are not contiguous")
        }));
        assert!(violations.iter().any(|violation| {
            violation.contains(
                "gap-and-missing output relationship:missing-relationship-event does not exist",
            )
        }));
        db.close().await;
    }

    #[tokio::test]
    async fn authorized_exact_retry_returns_original_receipt_without_another_event() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        registry
            .register_custom(
                "idempotent_provenance_fixture",
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::extension(true),
                "provenance retry fixture",
                json!({
                    "type":"object",
                    "properties":{"idempotency_key":{"type":"string"}},
                    "required":["idempotency_key"]
                }),
                |db, caller, _arguments| async move {
                    if caller.credential() != "acct:allowed" {
                        return Err(Error::engine("not authorized"));
                    }
                    let exists: bool = sqlx::query_scalar(&format!(
                        "SELECT EXISTS(SELECT 1 FROM records WHERE id='{RECORD_RETRY_ID}')"
                    ))
                    .fetch_one(db.write_pool())
                    .await?;
                    if !exists {
                        crate::store::append(&db, create_spec(RECORD_RETRY_ID, "retry")).await?;
                    }
                    Ok(json!({"id":RECORD_RETRY_ID}))
                },
            )
            .unwrap();
        let arguments = json!({"idempotency_key":"command:one"});
        let first = registry
            .call(
                db.clone(),
                Caller::authenticated("acct:allowed"),
                "idempotent_provenance_fixture",
                arguments.clone(),
            )
            .await
            .unwrap();
        let second = registry
            .call(
                db.clone(),
                Caller::authenticated("acct:allowed"),
                "idempotent_provenance_fixture",
                arguments.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            first["action_attestation_ids"],
            second["action_attestation_ids"]
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!(
                "SELECT COUNT(*) FROM content_events WHERE record_id='{RECORD_RETRY_ID}'"
            ))
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            1
        );
        let denied = registry
            .call(
                db.clone(),
                Caller::authenticated("acct:denied"),
                "idempotent_provenance_fixture",
                arguments,
            )
            .await
            .unwrap_err();
        assert_eq!(denied.to_string(), "not authorized");
        db.close().await;
    }
}
