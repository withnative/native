//! Closed `native.message.v1` export and destination ingest.
//!
//! This is a private child of the content append kernel. Its opaque envelope
//! context is deliberately not constructible by ordinary crate callers: a
//! future transport verifier will live under this module, while tests use the
//! deterministic adapter at the bottom of the file.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use super::{
    append_in, append_prepared_in, current_event_annotations, AppendSpec, NativeEventSource,
    PreparedEvent,
};
use crate::authorization::{AllowEntry, Capability};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::{
    CausalEnvelopeV1, CausalFrontierV1, CausalStatus, EventRow, LinkAddedPayload,
    MessageAudienceDeclaredPayload, MessageAudienceRecipient, MessageOriginDeclaredPayload,
};
use crate::identity::{BindingClaim, MutationContext, StubHints};

const CONTENT_VERSION_V1: &str = "native.message.v1";
const CONTENT_VERSION_V2: &str = "native.message.v2";
const CONTENT_VERSION: &str = CONTENT_VERSION_V2;
const MAX_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_JSON_DEPTH: usize = 16;
const MAX_PARTICIPANTS: usize = 128;
const MAX_MESSAGES: usize = 32;
const MAX_AUDIENCE: usize = 128;
const MAX_REFERENCES_PER_MESSAGE: usize = 128;
const MAX_REFERENCES_PER_BATCH: usize = 512;
const MAX_CAPABILITIES: usize = 32;
const MAX_PROSE_BYTES: usize = 128 * 1024;
const MAX_NAME_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_RECORD_ID_BYTES: usize = 4 * 1024;
const MAX_ALIASES: usize = 32;
const MAX_EXTENSION_BYTES: usize = 128 * 1024;
const MAX_MUTATIONS: usize = 1024;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const SUPPORTED_CAPABILITIES: [&str; 2] = ["message.created", "structured_references"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageBatchV1 {
    content_version: String,
    origin_db_id: String,
    participants: Vec<ParticipantDescriptorV1>,
    messages: Vec<MessageUnitV1>,
    #[serde(default)]
    required_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extensions: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParticipantDescriptorV1 {
    principal: String,
    origin_database_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin_person_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin_account_token: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    verified_aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extensions: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEventV1 {
    id: String,
    source_seq: i64,
    created_at: String,
    source_account_token: String,
    operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    causal_envelope: Option<CausalEnvelopeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalRecordRefV1 {
    origin_database_id: String,
    record_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageReferenceV1 {
    reference_id: String,
    relationship: String,
    target: ExternalRecordRefV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageUnitV1 {
    message_record_id: String,
    source_event: SourceEventV1,
    sender: usize,
    audience: Vec<usize>,
    kind: String,
    prose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expectation: Option<String>,
    /// Immutable authored communication origin. Absence is retained only for
    /// legacy native.message.v1 content and is never inferred from audience,
    /// destination filing or policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<MessageOriginDeclaredPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    thread: Option<ExternalRecordRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply_to: Option<ExternalRecordRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supersedes: Option<ExternalRecordRefV1>,
    #[serde(default)]
    references: Vec<MessageReferenceV1>,
    #[serde(default)]
    required_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extensions: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RelayState {
    Queued,
    Collected,
    Acknowledged,
}

impl RelayState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Collected => "collected",
            Self::Acknowledged => "acknowledged",
        }
    }
}

/// Authenticated outer-envelope facts. Fields and constructors remain private.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedEnvelopeContext {
    envelope_id: String,
    envelope_digest: [u8; 32],
    authenticated_sender_principal: String,
    recipient_principals: Vec<String>,
    destination_home_id: String,
    ingest_actor: String,
    relay_state: RelayState,
    received_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IngestStatus {
    Applied,
    Duplicate,
    PartiallyDuplicateBatchApplied,
    Rejected,
    Quarantined,
    RetryableFailure,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IngestResult {
    pub(crate) status: IngestStatus,
    pub(crate) code: String,
    pub(crate) retryable: bool,
    pub(crate) envelope_id: String,
    pub(crate) envelope_digest: String,
    pub(crate) message_ids: Vec<String>,
    pub(crate) event_ids: Vec<String>,
}

impl IngestResult {
    fn failure(context: &VerifiedEnvelopeContext, status: IngestStatus, code: &str) -> Self {
        Self {
            status,
            code: code.into(),
            retryable: status == IngestStatus::RetryableFailure,
            envelope_id: context.envelope_id.clone(),
            envelope_digest: hex::encode(context.envelope_digest),
            message_ids: Vec::new(),
            event_ids: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct PreparedUnit {
    wire: MessageUnitV1,
    canonical_payload: String,
    payload_digest: [u8; 32],
    fingerprint: [u8; 32],
    references: Vec<MessageReferenceV1>,
    causal_envelope: CausalEnvelopeV1,
}

#[derive(Debug)]
struct PreparedBatch {
    wire: MessageBatchV1,
    units: Vec<PreparedUnit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayClass {
    New,
    Existing,
    Repeated,
}

#[derive(Debug)]
struct SenderResolution {
    state: &'static str,
    record_id: Option<String>,
    actor: String,
    display_hint: Option<String>,
}

/// The transport-independent sealed entry point. It never exposes preserved-id
/// authority through MCP or the generic store API.
pub(crate) async fn ingest_verified_native_message(
    db: &Db,
    context: VerifiedEnvelopeContext,
    decrypted_content: &[u8],
) -> IngestResult {
    let prepared = match preflight(&context, decrypted_content) {
        Ok(prepared) => prepared,
        Err(PreflightFailure::Rejected(code)) => {
            return IngestResult::failure(&context, IngestStatus::Rejected, code)
        }
        Err(PreflightFailure::Quarantined(code)) => {
            return IngestResult::failure(&context, IngestStatus::Quarantined, code)
        }
    };
    let message_ids = prepared
        .units
        .iter()
        .map(|unit| unit.wire.message_record_id.clone())
        .collect::<Vec<_>>();
    let event_ids = prepared
        .units
        .iter()
        .map(|unit| unit.wire.source_event.id.clone())
        .collect::<Vec<_>>();
    match ingest_prepared(db, &context, prepared).await {
        Ok((inserted, duplicates, unknown_kind)) => {
            let status = if inserted == 0 {
                IngestStatus::Duplicate
            } else if duplicates > 0 {
                IngestStatus::PartiallyDuplicateBatchApplied
            } else {
                IngestStatus::Applied
            };
            IngestResult {
                status,
                code: if unknown_kind {
                    "applied_with_quarantined_kind".into()
                } else if status == IngestStatus::Duplicate {
                    "exact_duplicate".into()
                } else {
                    "applied".into()
                },
                retryable: false,
                envelope_id: context.envelope_id,
                envelope_digest: hex::encode(context.envelope_digest),
                message_ids,
                event_ids,
            }
        }
        Err(error) => {
            let message = error.to_string();
            let (status, code) = if message.contains("binding collision")
                || message.contains("reconciliation conflict")
            {
                (IngestStatus::Quarantined, "binding_conflict")
            } else if message.contains("identity collision")
                || message.contains("cannot claim an existing local record")
            {
                (IngestStatus::Rejected, "source_identity_collision")
            } else {
                (IngestStatus::RetryableFailure, "destination_write_failure")
            };
            let mut result = IngestResult::failure(&context, status, code);
            result.message_ids = message_ids;
            result.event_ids = event_ids;
            result
        }
    }
}

#[derive(Debug)]
enum PreflightFailure {
    Rejected(&'static str),
    Quarantined(&'static str),
}

fn preflight(
    context: &VerifiedEnvelopeContext,
    decrypted_content: &[u8],
) -> std::result::Result<PreparedBatch, PreflightFailure> {
    if context.envelope_id.trim().is_empty()
        || context.ingest_actor.trim().is_empty()
        || context.destination_home_id.trim().is_empty()
        || validate_timestamp(&context.received_at).is_err()
        || crate::identity::normalize_identifier(
            "native-principal",
            &context.authenticated_sender_principal,
        )
        .is_err()
    {
        return Err(PreflightFailure::Rejected(
            "invalid_verified_envelope_context",
        ));
    }
    if decrypted_content.is_empty() || decrypted_content.len() > MAX_CONTENT_BYTES {
        return Err(PreflightFailure::Rejected("content_size_limit"));
    }
    let value: Value = serde_json::from_slice(decrypted_content)
        .map_err(|_| PreflightFailure::Rejected("malformed_json"))?;
    validate_json_value(&value, 1)?;
    let content_version = value
        .get("content_version")
        .and_then(Value::as_str)
        .ok_or(PreflightFailure::Rejected("invalid_message_schema"))?;
    if !matches!(content_version, CONTENT_VERSION_V1 | CONTENT_VERSION_V2) {
        return Err(PreflightFailure::Quarantined("unsupported_version"));
    }
    let wire: MessageBatchV1 = serde_json::from_value(value)
        .map_err(|_| PreflightFailure::Rejected("invalid_message_schema"))?;
    if !crate::identity::is_database_id(&wire.origin_db_id) {
        return Err(PreflightFailure::Rejected("invalid_origin_database"));
    }
    if wire.participants.is_empty() || wire.participants.len() > MAX_PARTICIPANTS {
        return Err(PreflightFailure::Rejected("participant_limit"));
    }
    if wire.messages.is_empty() || wire.messages.len() > MAX_MESSAGES {
        return Err(PreflightFailure::Rejected("message_limit"));
    }
    validate_capabilities(&wire.required_capabilities)?;
    let mut extension_bytes = validate_extensions(wire.extensions.as_ref())?;
    let mut principals = BTreeSet::new();
    for participant in &wire.participants {
        if !crate::identity::is_database_id(&participant.origin_database_id)
            || crate::identity::normalize_identifier("native-principal", &participant.principal)
                .is_err()
            || !principals.insert(participant.principal.as_str())
        {
            return Err(PreflightFailure::Rejected("invalid_participant"));
        }
        if participant
            .origin_account_token
            .as_ref()
            .is_some_and(|token| crate::identity::normalize_identifier("account", token).is_err())
        {
            return Err(PreflightFailure::Rejected("invalid_participant_account"));
        }
        if participant
            .origin_person_record_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > MAX_RECORD_ID_BYTES)
            || participant.verified_aliases.len() > MAX_ALIASES
            || participant.verified_aliases.iter().any(|alias| {
                alias.is_empty()
                    || alias.len() > MAX_TOKEN_BYTES
                    || crate::identity::normalize_identifier("native-principal", alias).is_err()
            })
        {
            return Err(PreflightFailure::Rejected("invalid_participant_identity"));
        }
        if participant
            .display_hint
            .as_ref()
            .is_some_and(|name| name.is_empty() || name.len() > MAX_NAME_BYTES)
        {
            return Err(PreflightFailure::Rejected("participant_display_limit"));
        }
        extension_bytes += validate_extensions(participant.extensions.as_ref())?;
    }
    let outer_recipients = canonical_set(&context.recipient_principals)
        .ok_or(PreflightFailure::Rejected("invalid_outer_recipients"))?;
    if outer_recipients.iter().any(|principal| {
        crate::identity::normalize_identifier("native-principal", principal).is_err()
    }) {
        return Err(PreflightFailure::Rejected("invalid_outer_recipients"));
    }
    let mut total_references = 0usize;
    let mut mutation_budget = 0usize;
    let mut units = Vec::with_capacity(wire.messages.len());
    for message in &wire.messages {
        validate_uuid(&message.message_record_id)?;
        validate_uuid(&message.source_event.id)?;
        validate_timestamp(&message.source_event.created_at)?;
        if message.source_event.source_seq <= 0
            || message.source_event.source_seq > MAX_SAFE_INTEGER
            || message.source_event.operation != "message.created"
        {
            return Err(PreflightFailure::Rejected("invalid_source_event"));
        }
        let causal_envelope = match (
            wire.content_version.as_str(),
            message.source_event.causal_envelope.as_ref(),
        ) {
            (CONTENT_VERSION_V1, None) => {
                CausalEnvelopeV1::import_incomplete(CausalFrontierV1::empty())
            }
            (CONTENT_VERSION_V1, Some(_)) | (CONTENT_VERSION_V2, None) => {
                return Err(PreflightFailure::Rejected("invalid_causal_envelope"));
            }
            (CONTENT_VERSION_V2, Some(envelope))
                if envelope.status() != CausalStatus::LegacyUnknown =>
            {
                envelope.clone()
            }
            (CONTENT_VERSION_V2, Some(_)) => {
                return Err(PreflightFailure::Rejected("invalid_causal_envelope"));
            }
            _ => unreachable!("content version was dispatched above"),
        };
        causal_envelope
            .validate_for_event(&message.source_event.id)
            .map_err(|_| PreflightFailure::Rejected("invalid_causal_envelope"))?;
        if causal_envelope.status() == CausalStatus::Complete
            && causal_envelope.frontier().is_empty()
            && message.source_event.source_seq != 1
        {
            return Err(PreflightFailure::Rejected("invalid_causal_envelope"));
        }
        if message.sender >= wire.participants.len()
            || message.audience.len() > MAX_AUDIENCE
            || (message.audience.is_empty()
                && !matches!(
                    &message.origin,
                    Some(MessageOriginDeclaredPayload::Collection { .. })
                ))
        {
            return Err(PreflightFailure::Rejected("invalid_audience"));
        }
        let sender = &wire.participants[message.sender];
        if sender.origin_database_id != wire.origin_db_id
            || sender.principal != context.authenticated_sender_principal
            || sender.origin_account_token.as_deref()
                != Some(message.source_event.source_account_token.as_str())
        {
            return Err(PreflightFailure::Rejected("sender_mismatch"));
        }
        let mut audience_indices = BTreeSet::new();
        let mut audience_principals = Vec::with_capacity(message.audience.len());
        for index in &message.audience {
            if *index >= wire.participants.len()
                || *index == message.sender
                || !audience_indices.insert(*index)
            {
                return Err(PreflightFailure::Rejected("invalid_audience"));
            }
            audience_principals.push(wire.participants[*index].principal.clone());
        }
        let semantic_audience = canonical_set(&audience_principals)
            .ok_or(PreflightFailure::Rejected("invalid_audience"))?;
        if !semantic_audience
            .iter()
            .all(|principal| outer_recipients.binary_search(principal).is_ok())
        {
            return Err(PreflightFailure::Rejected("audience_mismatch"));
        }
        if message.kind.trim().is_empty() || message.kind.len() > MAX_NAME_BYTES {
            return Err(PreflightFailure::Rejected("invalid_message_kind"));
        }
        if message.prose.is_empty() || message.prose.len() > MAX_PROSE_BYTES {
            return Err(PreflightFailure::Rejected("prose_limit"));
        }
        if message
            .name
            .as_ref()
            .is_some_and(|name| name.is_empty() || name.len() > MAX_NAME_BYTES)
        {
            return Err(PreflightFailure::Rejected("name_limit"));
        }
        if let Some(expectation) = &message.expectation {
            if !crate::message_expectation::EXPECTATION_VALUES.contains(&expectation.as_str()) {
                return Err(PreflightFailure::Quarantined(
                    "unknown_required_expectation",
                ));
            }
        }
        validate_message_origin(&wire, message, sender)?;
        validate_capabilities(&message.required_capabilities)?;
        extension_bytes += validate_extensions(message.extensions.as_ref())?;
        if extension_bytes > MAX_EXTENSION_BYTES {
            return Err(PreflightFailure::Rejected("extension_limit"));
        }
        let references = normalized_references(&wire.origin_db_id, message)?;
        total_references += references.len();
        if references.len() > MAX_REFERENCES_PER_MESSAGE
            || total_references > MAX_REFERENCES_PER_BATCH
        {
            return Err(PreflightFailure::Rejected("reference_limit"));
        }
        mutation_budget += 5
            + usize::from(message.origin.is_some())
            + usize::from(
                matches!(
                    &message.origin,
                    Some(MessageOriginDeclaredPayload::Direct { .. })
                ) || message.origin.is_none(),
            )
            + message.audience.len() * 2
            + references.len() * 2;
        let audience_descriptors = message
            .audience
            .iter()
            .map(|index| &wire.participants[*index])
            .collect::<Vec<_>>();
        let canonical_semantic_payload = json!({
            "content_version": wire.content_version,
            "batch_required_capabilities": wire.required_capabilities,
            "batch_extensions": wire.extensions,
            "message": message,
            "sender": sender,
            "audience": audience_descriptors,
        });
        let canonical_payload = serde_jcs::to_vec(&canonical_semantic_payload)
            .map_err(|_| PreflightFailure::Rejected("canonicalization_failure"))?;
        let payload_digest: [u8; 32] = Sha256::digest(&canonical_payload).into();
        let fingerprint_input = json!({
            "content_version": wire.content_version,
            "origin_db_id": wire.origin_db_id,
            "source_event": message.source_event,
            "message_record_id": message.message_record_id,
            "source_principal": sender.principal,
            "source_account_token": message.source_event.source_account_token,
            "semantic_payload": canonical_semantic_payload,
        });
        let fingerprint: [u8; 32] = Sha256::digest(
            serde_jcs::to_vec(&fingerprint_input)
                .map_err(|_| PreflightFailure::Rejected("canonicalization_failure"))?,
        )
        .into();
        units.push(PreparedUnit {
            wire: message.clone(),
            canonical_payload: String::from_utf8(canonical_payload).expect("JCS JSON is UTF-8"),
            payload_digest,
            fingerprint,
            references,
            causal_envelope,
        });
    }
    if mutation_budget > MAX_MUTATIONS {
        return Err(PreflightFailure::Rejected("mutation_budget"));
    }
    validate_reference_graph(&wire, &units)?;
    Ok(PreparedBatch { wire, units })
}

fn validate_message_origin(
    batch: &MessageBatchV1,
    message: &MessageUnitV1,
    sender: &ParticipantDescriptorV1,
) -> std::result::Result<(), PreflightFailure> {
    let Some(origin) = &message.origin else {
        // Compatibility is deliberately one-way: old content stays unknown,
        // while every newly authored send is required by its authoring surface
        // to carry an explicit origin.
        return Ok(());
    };
    match origin {
        MessageOriginDeclaredPayload::Collection { collection_id } => {
            if collection_id.trim().is_empty()
                || collection_id.len() > MAX_RECORD_ID_BYTES + 64
                || collection_id.trim() != collection_id
            {
                return Err(PreflightFailure::Rejected("invalid_message_origin"));
            }
            let (_, source_collection_id) = crate::identity::decode_native_record(collection_id)
                .map_err(|_| PreflightFailure::Rejected("invalid_message_origin"))?;
            if source_collection_id.trim().is_empty()
                || source_collection_id.len() > MAX_RECORD_ID_BYTES
            {
                return Err(PreflightFailure::Rejected("invalid_message_origin"));
            }
        }
        MessageOriginDeclaredPayload::Direct { principals } => {
            let canonical = canonical_set(principals)
                .filter(|canonical| canonical == principals)
                .ok_or(PreflightFailure::Rejected("invalid_message_origin"))?;
            if canonical.is_empty()
                || canonical.iter().any(|principal| {
                    crate::identity::normalize_identifier("native-principal", principal).is_err()
                })
            {
                return Err(PreflightFailure::Rejected("invalid_message_origin"));
            }
            let participants = batch
                .participants
                .iter()
                .map(|participant| participant.principal.as_str())
                .collect::<BTreeSet<_>>();
            if !canonical
                .iter()
                .all(|principal| participants.contains(principal.as_str()))
                || !canonical
                    .iter()
                    .any(|principal| principal == &sender.principal)
            {
                return Err(PreflightFailure::Rejected("invalid_message_origin"));
            }
            // Addressing remains independent within a direct context, but it
            // cannot name somebody outside the context whose default policy
            // would prevent them from reading the Message.
            if message.audience.iter().any(|index| {
                !canonical
                    .iter()
                    .any(|principal| principal == &batch.participants[*index].principal)
            }) {
                return Err(PreflightFailure::Rejected("invalid_message_origin"));
            }
        }
    }
    Ok(())
}

fn canonical_set(values: &[String]) -> Option<Vec<String>> {
    let set = values.iter().cloned().collect::<BTreeSet<_>>();
    (set.len() == values.len()).then(|| set.into_iter().collect())
}

fn validate_json_value(value: &Value, depth: usize) -> std::result::Result<(), PreflightFailure> {
    if depth > MAX_JSON_DEPTH {
        return Err(PreflightFailure::Rejected("json_depth_limit"));
    }
    match value {
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .ok_or(PreflightFailure::Rejected("non_integer_number"))?;
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&integer) {
                return Err(PreflightFailure::Rejected("unsafe_integer"));
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_json_value(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_json_value(value, depth + 1)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_capabilities(values: &[String]) -> std::result::Result<(), PreflightFailure> {
    if values.len() > MAX_CAPABILITIES
        || canonical_set(values).is_none()
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > MAX_TOKEN_BYTES)
    {
        return Err(PreflightFailure::Rejected("capability_limit"));
    }
    if values
        .iter()
        .any(|value| !SUPPORTED_CAPABILITIES.contains(&value.as_str()))
    {
        return Err(PreflightFailure::Quarantined(
            "unsupported_required_capability",
        ));
    }
    Ok(())
}

fn validate_extensions(value: Option<&Value>) -> std::result::Result<usize, PreflightFailure> {
    let Some(value) = value else { return Ok(0) };
    let encoded =
        serde_jcs::to_vec(value).map_err(|_| PreflightFailure::Rejected("extension_limit"))?;
    if !value.is_object() || encoded.len() > MAX_EXTENSION_BYTES {
        return Err(PreflightFailure::Rejected("extension_limit"));
    }
    Ok(encoded.len())
}

fn validate_uuid(value: &str) -> std::result::Result<(), PreflightFailure> {
    let parsed = Uuid::parse_str(value).map_err(|_| PreflightFailure::Rejected("invalid_uuid"))?;
    if parsed.hyphenated().to_string() != value {
        return Err(PreflightFailure::Rejected("invalid_uuid"));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> std::result::Result<(), PreflightFailure> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| PreflightFailure::Rejected("invalid_timestamp"))?;
    if parsed
        .with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
        != value
    {
        return Err(PreflightFailure::Rejected("invalid_timestamp"));
    }
    Ok(())
}

fn normalized_references(
    source_origin_db_id: &str,
    message: &MessageUnitV1,
) -> std::result::Result<Vec<MessageReferenceV1>, PreflightFailure> {
    let mut references = message.references.clone();
    for (id, relationship, target) in [
        ("native:thread", "thread", message.thread.as_ref()),
        ("native:reply_to", "reply_to", message.reply_to.as_ref()),
        (
            "native:supersedes",
            "supersedes",
            message.supersedes.as_ref(),
        ),
    ] {
        if let Some(target) = target {
            references.push(MessageReferenceV1 {
                reference_id: id.into(),
                relationship: relationship.into(),
                target: target.clone(),
                display_label: None,
            });
        }
    }
    let mut ids = BTreeSet::new();
    for reference in &references {
        if reference.reference_id.trim().is_empty()
            || reference.reference_id.len() > MAX_TOKEN_BYTES
            || !ids.insert(reference.reference_id.as_str())
            || !matches!(
                reference.relationship.as_str(),
                "thread" | "reply_to" | "supersedes" | "mention" | "relates_to"
            )
            || !crate::identity::is_database_id(&reference.target.origin_database_id)
            || reference.target.record_id.trim().is_empty()
            || reference.target.record_id.len() > MAX_RECORD_ID_BYTES
            || reference
                .display_label
                .as_ref()
                .is_some_and(|label| label.is_empty() || label.len() > MAX_NAME_BYTES)
            || (matches!(reference.relationship.as_str(), "reply_to" | "supersedes")
                && reference.target.origin_database_id == source_origin_db_id
                && reference.target.record_id == message.message_record_id)
        {
            return Err(PreflightFailure::Rejected("invalid_reference"));
        }
        if let Some(binding) = &reference.target.binding {
            if binding.len() > MAX_RECORD_ID_BYTES + 64 {
                return Err(PreflightFailure::Rejected("invalid_reference_binding"));
            }
            let decoded = crate::identity::decode_native_record(binding)
                .map_err(|_| PreflightFailure::Rejected("invalid_reference_binding"))?;
            if decoded
                != (
                    reference.target.origin_database_id.clone(),
                    reference.target.record_id.clone(),
                )
            {
                return Err(PreflightFailure::Rejected("invalid_reference_binding"));
            }
        }
    }
    Ok(references)
}

fn validate_reference_graph(
    batch: &MessageBatchV1,
    units: &[PreparedUnit],
) -> std::result::Result<(), PreflightFailure> {
    let batch_ids = units
        .iter()
        .map(|unit| unit.wire.message_record_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut edges = BTreeMap::<&str, Vec<&str>>::new();
    for unit in units {
        for reference in &unit.references {
            if matches!(reference.relationship.as_str(), "reply_to" | "supersedes")
                && reference.target.origin_database_id == batch.origin_db_id
                && batch_ids.contains(reference.target.record_id.as_str())
            {
                edges
                    .entry(unit.wire.message_record_id.as_str())
                    .or_default()
                    .push(reference.target.record_id.as_str());
            }
        }
    }

    fn visit<'a>(
        node: &'a str,
        edges: &BTreeMap<&'a str, Vec<&'a str>>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> bool {
        if visited.contains(node) {
            return false;
        }
        if !visiting.insert(node) {
            return true;
        }
        if edges.get(node).is_some_and(|targets| {
            targets
                .iter()
                .any(|target| visit(target, edges, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(node);
        visited.insert(node);
        false
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    if batch_ids
        .iter()
        .any(|id| visit(id, &edges, &mut visiting, &mut visited))
    {
        return Err(PreflightFailure::Rejected("reference_cycle"));
    }
    Ok(())
}

async fn ingest_prepared(
    db: &Db,
    context: &VerifiedEnvelopeContext,
    prepared: PreparedBatch,
) -> Result<(usize, usize, bool)> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut first_by_event = HashMap::new();
    let mut first_by_record = HashMap::new();
    let mut classes = vec![ReplayClass::New; prepared.units.len()];
    for (index, unit) in prepared.units.iter().enumerate() {
        if let Some(first) = first_by_event.insert(unit.wire.source_event.id.clone(), index) {
            let first_unit: &PreparedUnit = &prepared.units[first];
            if first_unit.fingerprint != unit.fingerprint {
                return Err(Error::engine(format!(
                    "verified Native event identity collision for {}",
                    unit.wire.source_event.id
                )));
            }
            classes[index] = ReplayClass::Repeated;
            continue;
        }
        if let Some(first_event) = first_by_record.insert(
            unit.wire.message_record_id.clone(),
            unit.wire.source_event.id.clone(),
        ) {
            return Err(Error::engine(format!(
                "verified Native Message identity collision for {}: events {} and {} both claim it",
                unit.wire.message_record_id, first_event, unit.wire.source_event.id
            )));
        }
    }
    for (index, unit) in prepared.units.iter().enumerate() {
        if classes[index] == ReplayClass::Repeated {
            continue;
        }
        let existing = sqlx::query(
            "SELECT e.id,e.causal_envelope_version,e.causal_status,s.source_fingerprint
               FROM content_events e
               LEFT JOIN content_event_sources s ON s.event_id=e.id
              WHERE e.id=?",
        )
        .bind(&unit.wire.source_event.id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(existing) = existing {
            let fingerprint: Option<String> = existing.try_get("source_fingerprint")?;
            if fingerprint.as_deref() != Some(hex::encode(unit.fingerprint).as_str()) {
                return Err(Error::engine(format!(
                    "verified Native event identity collision for {}",
                    unit.wire.source_event.id
                )));
            }
            if existing.try_get::<i64, _>("causal_envelope_version")? != 1 {
                return Err(Error::engine("unsupported stored causal envelope version"));
            }
            let frontier = CausalFrontierV1::new(
                sqlx::query_scalar::<_, String>(
                    "SELECT parent_event_id FROM content_event_causal_frontier
                      WHERE event_id=? ORDER BY parent_event_id",
                )
                .bind(&unit.wire.source_event.id)
                .fetch_all(&mut *tx)
                .await?,
            )?;
            let stored_envelope = match existing.try_get::<String, _>("causal_status")?.as_str() {
                "complete" => CausalEnvelopeV1::complete(frontier),
                "import_incomplete" => CausalEnvelopeV1::import_incomplete(frontier),
                "legacy_unknown" if frontier.is_empty() => CausalEnvelopeV1::legacy_unknown(),
                _ => return Err(Error::engine("invalid stored causal envelope")),
            };
            if stored_envelope != unit.causal_envelope {
                return Err(Error::engine(format!(
                    "verified Native event causal identity collision for {}",
                    unit.wire.source_event.id
                )));
            }
            classes[index] = ReplayClass::Existing;
            continue;
        }
        let record_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=?)")
                .bind(&unit.wire.message_record_id)
                .fetch_one(&mut *tx)
                .await?;
        if record_exists {
            return Err(Error::engine(format!(
                "verified Native Message identity collision: new source event {} cannot claim an existing local record {}",
                unit.wire.source_event.id, unit.wire.message_record_id
            )));
        }
    }

    let internal_context = MutationContext {
        actor: &context.ingest_actor,
        reason: "Authenticated Native Message destination reconciliation.",
        run_key: None,
        parent_key: None,
        intent: Some("federated-message-ingest"),
        internal: true,
        source_read_authorized: false,
    };
    let mut sender_by_principal: HashMap<String, SenderResolution> = HashMap::new();
    let mut participant_records: HashMap<String, String> = HashMap::new();
    let mut inserted_indices = Vec::new();
    let mut unknown_kind = false;

    for (index, unit) in prepared.units.iter().enumerate() {
        if classes[index] != ReplayClass::New {
            continue;
        }
        let sender_descriptor = &prepared.wire.participants[unit.wire.sender];
        if !sender_by_principal.contains_key(&sender_descriptor.principal) {
            let resolution = resolve_sender(
                db,
                &mut tx,
                &internal_context,
                sender_descriptor,
                &unit.wire.source_event.source_account_token,
            )
            .await?;
            if let Some(record_id) = &resolution.record_id {
                participant_records.insert(sender_descriptor.principal.clone(), record_id.clone());
            }
            sender_by_principal.insert(sender_descriptor.principal.clone(), resolution);
        }
        for audience_index in &unit.wire.audience {
            let descriptor = &prepared.wire.participants[*audience_index];
            if !participant_records.contains_key(&descriptor.principal) {
                let record_id =
                    resolve_participant(db, &mut tx, &internal_context, descriptor).await?;
                participant_records.insert(descriptor.principal.clone(), record_id);
            }
        }
        let sender = &sender_by_principal[&sender_descriptor.principal];
        let event = prepared_event(
            &prepared.wire.origin_db_id,
            &context.destination_home_id,
            unit,
            sender,
            &sender_descriptor.principal,
        )?;
        append_prepared_in(db, &mut tx, event).await?;
        inserted_indices.push(index);
        unknown_kind |= unit.wire.kind != "text";
    }

    let batch_records = prepared
        .units
        .iter()
        .map(|unit| {
            (
                (
                    prepared.wire.origin_db_id.clone(),
                    unit.wire.message_record_id.clone(),
                ),
                unit.wire.message_record_id.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for index in inserted_indices.iter().copied() {
        let unit = &prepared.units[index];
        let sender_descriptor = &prepared.wire.participants[unit.wire.sender];
        let sender = &sender_by_principal[&sender_descriptor.principal];
        persist_provenance(db, &mut tx, context, unit, sender).await?;
        persist_references(db, &mut tx, unit, &batch_records).await?;
        if let Some(origin) = &unit.wire.origin {
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: unit.wire.message_record_id.clone(),
                    event_type: "message.origin.declared.v1".into(),
                    // The authenticated semantic origin is projected byte-for-
                    // byte as the same tagged value; destination filing never
                    // participates in this declaration.
                    payload: serde_json::to_value(origin)?,
                    actor: Some(sender.actor.clone()),
                },
            )
            .await?;
            if let MessageOriginDeclaredPayload::Direct { principals } = origin {
                let accounts = local_accounts_for_direct_origin(&mut tx, principals).await?;
                // A received direct Message must never inherit the destination
                // home's potentially broader visibility. The empty policy is
                // intentional when none of its principals resolve locally.
                crate::authorization::replace_explicit_policy_on(
                    &mut tx,
                    &context.ingest_actor,
                    &unit.wire.message_record_id,
                    accounts
                        .into_iter()
                        .map(|account| AllowEntry::account(account, Capability::View))
                        .collect(),
                )
                .await?;
            }
        } else {
            // Legacy wire content has no authenticated communication origin.
            // Preserve that uncertainty without borrowing the destination
            // home's potentially broad visibility.
            crate::authorization::replace_explicit_policy_on(
                &mut tx,
                &context.ingest_actor,
                &unit.wire.message_record_id,
                Vec::new(),
            )
            .await?;
        }
        if let Some(expectation) = &unit.wire.expectation {
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: unit.wire.message_record_id.clone(),
                    event_type: "facet.set".into(),
                    payload: json!({
                        "key": crate::message_expectation::EXPECTATION_FACET_KEY,
                        "value": expectation,
                        "vocab_ref": crate::meta::vocab_ref(
                            crate::message_expectation::EXPECTATION_VOCABULARY_ID,
                        ),
                    }),
                    actor: Some(sender.actor.clone()),
                },
            )
            .await?;
        }
        if let Some(sender_record_id) = &sender.record_id {
            let addressed_to = unit
                .wire
                .audience
                .iter()
                .map(|participant_index| {
                    let descriptor = &prepared.wire.participants[*participant_index];
                    Ok(MessageAudienceRecipient {
                        recipient_id: participant_records
                            .get(&descriptor.principal)
                            .cloned()
                            .ok_or_else(|| Error::engine("resolved audience record disappeared"))?,
                        principal: descriptor.principal.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: unit.wire.message_record_id.clone(),
                    event_type: "message.audience.declared".into(),
                    payload: serde_json::to_value(MessageAudienceDeclaredPayload {
                        sender_id: sender_record_id.clone(),
                        sender_principal: sender_descriptor.principal.clone(),
                        addressed_to,
                    })?,
                    actor: Some(sender.actor.clone()),
                },
            )
            .await?;
        }
    }
    db.commit_content(tx).await?;
    let inserted = inserted_indices.len();
    Ok((inserted, classes.len() - inserted, unknown_kind))
}

async fn local_accounts_for_direct_origin(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    principals: &[String],
) -> Result<Vec<String>> {
    let mut accounts = BTreeSet::new();
    for principal in principals {
        let resolved: Vec<String> = sqlx::query_scalar(
            "SELECT account.identifier
               FROM bindings principal
               JOIN bindings account ON account.record_id=principal.record_id
              WHERE principal.system='native-principal'
                AND principal.identifier=?
                AND account.system='account'
                AND account.is_canonical=1",
        )
        .bind(principal)
        .fetch_all(&mut **tx)
        .await?;
        accounts.extend(resolved);
    }
    Ok(accounts.into_iter().collect())
}

async fn resolve_sender(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    context: &MutationContext<'_>,
    descriptor: &ParticipantDescriptorV1,
    incoming_account: &str,
) -> Result<SenderResolution> {
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='native-principal' AND identifier=?",
    )
    .bind(&descriptor.principal)
    .fetch_optional(&mut **tx)
    .await?;
    let existing_is_federated_shadow = if let Some(record_id) = &existing {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM destination_message_ingest
                 WHERE sender_record_id=? AND sender_state='binding_only'
            )",
        )
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await?
    } else {
        false
    };
    let should_materialize = existing.is_some()
        || descriptor.origin_person_record_id.is_some()
        || descriptor.display_hint.is_some();
    if !should_materialize {
        return Ok(SenderResolution {
            state: "principal_only",
            record_id: None,
            actor: incoming_account.into(),
            display_hint: None,
        });
    }
    let mut claims = vec![BindingClaim {
        system: "native-principal".into(),
        identifier: descriptor.principal.clone(),
    }];
    if let Some(origin_record) = &descriptor.origin_person_record_id {
        claims.push(BindingClaim {
            system: "native-record".into(),
            identifier: crate::identity::encode_native_record(
                &descriptor.origin_database_id,
                origin_record,
            )?,
        });
    }
    let resolution = crate::identity::resolve_external_in(
        db,
        tx,
        context,
        &claims,
        &StubHints {
            record_type: Some("Entity".into()),
            kind: Some("person".into()),
            name: descriptor.display_hint.clone(),
        },
    )
    .await?;
    let mut actor: Option<String> = sqlx::query_scalar(
        "SELECT identifier FROM bindings
          WHERE record_id=? AND system='account' AND is_canonical=1",
    )
    .bind(&resolution.record_id)
    .fetch_optional(&mut **tx)
    .await?;
    if actor.is_none() {
        let local = format!("acct_{}", Uuid::new_v4().simple());
        crate::identity::add_binding_internal_in(
            tx,
            context.actor,
            context.reason,
            &resolution.record_id,
            "account",
            &local,
            true,
        )
        .await?;
        actor = Some(local);
    }
    crate::identity::add_binding_internal_in(
        tx,
        context.actor,
        context.reason,
        &resolution.record_id,
        "account",
        incoming_account,
        false,
    )
    .await?;
    Ok(SenderResolution {
        state: if existing.is_some() && !existing_is_federated_shadow {
            "known_person"
        } else {
            "binding_only"
        },
        record_id: Some(resolution.record_id),
        actor: actor.expect("canonical account was selected or created"),
        display_hint: descriptor.display_hint.clone(),
    })
}

async fn resolve_participant(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    context: &MutationContext<'_>,
    descriptor: &ParticipantDescriptorV1,
) -> Result<String> {
    let mut claims = vec![BindingClaim {
        system: "native-principal".into(),
        identifier: descriptor.principal.clone(),
    }];
    if let Some(origin_record) = &descriptor.origin_person_record_id {
        claims.push(BindingClaim {
            system: "native-record".into(),
            identifier: crate::identity::encode_native_record(
                &descriptor.origin_database_id,
                origin_record,
            )?,
        });
    }
    Ok(crate::identity::resolve_external_in(
        db,
        tx,
        context,
        &claims,
        &StubHints {
            record_type: Some("Entity".into()),
            kind: Some("person".into()),
            name: descriptor
                .display_hint
                .clone()
                .or_else(|| Some(descriptor.principal.clone())),
        },
    )
    .await?
    .record_id)
}

fn prepared_event(
    origin_db_id: &str,
    destination_home_id: &str,
    unit: &PreparedUnit,
    sender: &SenderResolution,
    source_principal: &str,
) -> Result<PreparedEvent> {
    let mut payload = json!({
        "type": "Message",
        "kind": unit.wire.kind,
        "body": unit.wire.prose,
        "home_id": destination_home_id,
        "persistence": "occurrent",
    });
    let object = payload
        .as_object_mut()
        .expect("Message payload is an object");
    if let Some(name) = &unit.wire.name {
        object.insert("name".into(), Value::String(name.clone()));
    }
    if let Some(owner_id) = &sender.record_id {
        object.insert("owner_id".into(), Value::String(owner_id.clone()));
    }
    let annotations = current_event_annotations();
    let source = NativeEventSource {
        origin_database_id: origin_db_id.into(),
        source_seq: unit.wire.source_event.source_seq,
        source_record_id: unit.wire.message_record_id.clone(),
        source_principal: source_principal.into(),
        fingerprint: unit.fingerprint,
    };
    let event = EventRow {
        local_seq: -1,
        id: unit.wire.source_event.id.clone(),
        record_id: unit.wire.message_record_id.clone(),
        event_type: "record.created".into(),
        payload: Some(serde_json::to_string(&payload)?),
        actor: Some(sender.actor.clone()),
        run_key: annotations.run_key,
        parent_key: annotations.parent_key,
        intent: annotations.intent,
        created_at: unit.wire.source_event.created_at.clone(),
        causal_envelope: unit.causal_envelope.clone(),
    };
    Ok(PreparedEvent {
        event,
        payload,
        native_source: Some(source),
        governed_causal_envelope: Some(unit.causal_envelope.clone()),
    })
}

async fn persist_provenance(
    _db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    context: &VerifiedEnvelopeContext,
    unit: &PreparedUnit,
    sender: &SenderResolution,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO replicated_message_provenance
            (source_event_id,content_version,operation,source_account_token,
             source_created_at,canonical_payload,payload_digest,envelope_id,envelope_digest)
         VALUES (?,?,?,?,?,?,?,?,?)",
    )
    .bind(&unit.wire.source_event.id)
    .bind(if unit.wire.source_event.causal_envelope.is_some() {
        CONTENT_VERSION_V2
    } else {
        CONTENT_VERSION_V1
    })
    .bind("message.created")
    .bind(&unit.wire.source_event.source_account_token)
    .bind(&unit.wire.source_event.created_at)
    .bind(&unit.canonical_payload)
    .bind(hex::encode(unit.payload_digest))
    .bind(&context.envelope_id)
    .bind(hex::encode(context.envelope_digest))
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO destination_message_ingest
            (message_id,source_event_id,relay_state,ingest_state,received_at,
             sender_state,sender_record_id,display_hint)
         VALUES (?,?,?,?,?,?,?,?)",
    )
    .bind(&unit.wire.message_record_id)
    .bind(&unit.wire.source_event.id)
    .bind(context.relay_state.as_str())
    .bind(if unit.wire.kind == "text" {
        "applied"
    } else {
        "quarantined_kind"
    })
    .bind(&context.received_at)
    .bind(sender.state)
    .bind(&sender.record_id)
    .bind(&sender.display_hint)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn persist_references(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    unit: &PreparedUnit,
    batch_records: &BTreeMap<(String, String), String>,
) -> Result<()> {
    for reference in &unit.references {
        let resolved = resolve_reference(tx, &reference.target, batch_records).await?;
        let source_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(reference)?));
        sqlx::query(
            "INSERT INTO replicated_message_references
                (source_message_id,reference_id,relationship,target_origin_db_id,
                 target_record_id,target_binding,display_label,source_digest,resolved_local_id)
             VALUES (?,?,?,?,?,?,?,?,?)",
        )
        .bind(&unit.wire.message_record_id)
        .bind(&reference.reference_id)
        .bind(&reference.relationship)
        .bind(&reference.target.origin_database_id)
        .bind(&reference.target.record_id)
        .bind(&reference.target.binding)
        .bind(&reference.display_label)
        .bind(source_digest)
        .bind(&resolved)
        .execute(&mut **tx)
        .await?;
        if let Some(target_id) = resolved {
            let relationship = match reference.relationship.as_str() {
                "thread" => "participates_in",
                "mention" => "mentions",
                other => other,
            };
            append_in(
                db,
                tx,
                AppendSpec {
                    record_id: unit.wire.message_record_id.clone(),
                    event_type: "link.added".into(),
                    payload: serde_json::to_value(LinkAddedPayload {
                        id: Some(stable_reference_link_id(
                            &unit.wire.message_record_id,
                            &reference.reference_id,
                        )),
                        source_id: unit.wire.message_record_id.clone(),
                        target_id,
                        relationship: relationship.into(),
                        note: reference.display_label.clone(),
                    })?,
                    actor: None,
                },
            )
            .await?;
        }
    }
    Ok(())
}

async fn resolve_reference(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    target: &ExternalRecordRefV1,
    batch_records: &BTreeMap<(String, String), String>,
) -> Result<Option<String>> {
    if let Some(id) =
        batch_records.get(&(target.origin_database_id.clone(), target.record_id.clone()))
    {
        return Ok(Some(id.clone()));
    }
    let exact: Option<String> = sqlx::query_scalar(
        "SELECT r.id FROM records r
          JOIN content_events e ON e.record_id=r.id AND e.type='record.created'
          JOIN content_event_sources s ON s.event_id=e.id
         WHERE r.id=? AND r.type='Message' AND s.origin_database_id=? AND s.source_record_id=?
         LIMIT 1",
    )
    .bind(&target.record_id)
    .bind(&target.origin_database_id)
    .bind(&target.record_id)
    .fetch_optional(&mut **tx)
    .await?;
    if exact.is_some() {
        return Ok(exact);
    }
    let Some(binding) = &target.binding else {
        return Ok(None);
    };
    Ok(sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='native-record' AND identifier=?",
    )
    .bind(binding)
    .fetch_optional(&mut **tx)
    .await?)
}

fn stable_reference_link_id(message_id: &str, reference_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"native-message-reference-v1\0");
    digest.update(message_id.as_bytes());
    digest.update([0]);
    digest.update(reference_id.as_bytes());
    format!("lnk:fed:{}", hex::encode(digest.finalize()))
}

/// Canonical export of real local Message records. Export seals each local
/// creation event with the same source fingerprint used by destination replay.
pub(crate) async fn export_native_messages(db: &Db, message_ids: &[String]) -> Result<Vec<u8>> {
    if message_ids.is_empty() || message_ids.len() > MAX_MESSAGES {
        return Err(Error::engine("export requires 1..=32 Message ids"));
    }
    let mut received = 0usize;
    for message_id in message_ids {
        let is_received: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM content_events e
                JOIN replicated_message_provenance p ON p.source_event_id=e.id
               WHERE e.record_id=? AND e.type='record.created' AND p.envelope_id IS NOT NULL)",
        )
        .bind(message_id)
        .fetch_one(db.write_pool())
        .await?;
        received += usize::from(is_received);
    }
    if received != 0 {
        if received != message_ids.len() {
            return Err(Error::engine(
                "one Message export cannot mix local events with received source events",
            ));
        }
        return export_received_native_messages(db, message_ids).await;
    }
    let mut sealed_v1 = 0usize;
    for message_id in message_ids {
        let is_sealed_v1: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM content_events e
                JOIN replicated_message_provenance p ON p.source_event_id=e.id
               WHERE e.record_id=? AND e.type='record.created'
                 AND p.envelope_id IS NULL
                 AND p.content_version='native.message.v1')",
        )
        .bind(message_id)
        .fetch_one(db.write_pool())
        .await?;
        sealed_v1 += usize::from(is_sealed_v1);
    }
    if sealed_v1 != 0 {
        if sealed_v1 != message_ids.len() {
            return Err(Error::engine(
                "one Message export cannot mix preserved v1 events with unsealed local events",
            ));
        }
        return export_preserved_native_messages(db, message_ids, false).await;
    }
    let origin_db_id = crate::identity::database_id(db).await?;
    let mut participants = Vec::<ParticipantDescriptorV1>::new();
    let mut participant_index = BTreeMap::<String, usize>::new();
    let mut messages = Vec::with_capacity(message_ids.len());
    for message_id in message_ids {
        let row = sqlx::query(
            "SELECT r.kind,r.name,r.body,r.owner_id,e.id AS event_id,e.seq,e.created_at,e.actor,
                    e.causal_envelope_version,e.causal_status
               FROM records r
               JOIN content_events e ON e.record_id=r.id AND e.type='record.created'
              WHERE r.id=? AND r.type='Message'
              ORDER BY e.seq LIMIT 1",
        )
        .bind(message_id)
        .fetch_optional(db.write_pool())
        .await?
        .ok_or_else(|| Error::engine(format!("Message '{message_id}' not found")))?;
        let owner_id: String = row
            .try_get::<Option<String>, _>("owner_id")?
            .ok_or_else(|| Error::engine("exportable Message requires an owner"))?;
        let sender_principal: String = sqlx::query_scalar(
            "SELECT identifier FROM bindings
              WHERE record_id=? AND system='native-principal' AND is_canonical=1",
        )
        .bind(&owner_id)
        .fetch_optional(db.write_pool())
        .await?
        .ok_or_else(|| Error::engine("exportable Message owner requires native-principal"))?;
        let source_account_token: String = row
            .try_get::<Option<String>, _>("actor")?
            .ok_or_else(|| Error::engine("exportable Message creation requires actor"))?;
        let actor_belongs_to_owner: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM bindings
                 WHERE record_id=? AND system='account' AND identifier=?
            )",
        )
        .bind(&owner_id)
        .bind(&source_account_token)
        .fetch_one(db.write_pool())
        .await?;
        if !actor_belongs_to_owner {
            return Err(Error::engine(
                "exportable Message creation actor must be bound to its owner",
            ));
        }
        let sender = participant_for_export(
            &mut participants,
            &mut participant_index,
            ParticipantDescriptorV1 {
                principal: sender_principal,
                origin_database_id: origin_db_id.clone(),
                origin_person_record_id: Some(owner_id),
                origin_account_token: Some(source_account_token.clone()),
                verified_aliases: Vec::new(),
                display_hint: None,
                extensions: None,
            },
        );
        let audience_rows = sqlx::query(
            "SELECT ma.principal_id,b.record_id,r.name
               FROM message_audiences ma
               LEFT JOIN bindings b ON b.system='native-principal' AND b.identifier=ma.principal_id
               LEFT JOIN records r ON r.id=b.record_id
              WHERE ma.message_id=? AND ma.source='addressed_to'
              ORDER BY ma.principal_id",
        )
        .bind(message_id)
        .fetch_all(db.write_pool())
        .await?;
        let mut audience = Vec::with_capacity(audience_rows.len());
        for recipient in audience_rows {
            let principal: String = recipient.try_get("principal_id")?;
            let record_id: Option<String> = recipient.try_get("record_id")?;
            let name: Option<String> = recipient.try_get("name")?;
            audience.push(participant_for_export(
                &mut participants,
                &mut participant_index,
                ParticipantDescriptorV1 {
                    principal,
                    origin_database_id: origin_db_id.clone(),
                    origin_person_record_id: record_id,
                    origin_account_token: None,
                    verified_aliases: Vec::new(),
                    display_hint: name.filter(|name| !name.is_empty()),
                    extensions: None,
                },
            ));
        }
        let expectation: Option<String> =
            sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key=?")
                .bind(message_id)
                .bind(crate::message_expectation::EXPECTATION_FACET_KEY)
                .fetch_optional(db.write_pool())
                .await?;
        let origin = export_message_origin(db, &origin_db_id, message_id).await?;
        if let Some(MessageOriginDeclaredPayload::Direct { principals }) = &origin {
            for principal in principals {
                if participant_index.contains_key(principal) {
                    continue;
                }
                let identity = sqlx::query(
                    "SELECT b.record_id,r.name FROM bindings b
                       LEFT JOIN records r ON r.id=b.record_id
                      WHERE b.system='native-principal' AND b.identifier=?",
                )
                .bind(principal)
                .fetch_optional(db.write_pool())
                .await?;
                let record_id = identity
                    .as_ref()
                    .map(|row| row.try_get::<String, _>("record_id"))
                    .transpose()?;
                let display_hint = identity
                    .as_ref()
                    .map(|row| row.try_get::<Option<String>, _>("name"))
                    .transpose()?
                    .flatten()
                    .filter(|name| !name.is_empty());
                participant_for_export(
                    &mut participants,
                    &mut participant_index,
                    ParticipantDescriptorV1 {
                        principal: principal.clone(),
                        origin_database_id: origin_db_id.clone(),
                        origin_person_record_id: record_id,
                        origin_account_token: None,
                        verified_aliases: Vec::new(),
                        display_hint,
                        extensions: None,
                    },
                );
            }
        }
        let link_rows = sqlx::query(
            "SELECT id,relationship,target_id,note FROM links
              WHERE source_id=? AND relationship IN
                    ('reply_to','supersedes','participates_in','mentions','relates_to')
              ORDER BY relationship,target_id,id",
        )
        .bind(message_id)
        .fetch_all(db.write_pool())
        .await?;
        let mut reply_to = None;
        let mut supersedes = None;
        let mut thread = None;
        let mut references = Vec::new();
        for link in link_rows {
            let relationship: String = link.try_get("relationship")?;
            let target_id: String = link.try_get("target_id")?;
            let target = ExternalRecordRefV1 {
                origin_database_id: origin_db_id.clone(),
                record_id: target_id.clone(),
                binding: Some(crate::identity::encode_native_record(
                    &origin_db_id,
                    &target_id,
                )?),
            };
            match relationship.as_str() {
                "reply_to" if reply_to.is_none() => reply_to = Some(target),
                "supersedes" if supersedes.is_none() => supersedes = Some(target),
                "participates_in" if thread.is_none() => thread = Some(target),
                "mentions" | "relates_to" => references.push(MessageReferenceV1 {
                    reference_id: format!("local:{}", link.try_get::<String, _>("id")?),
                    relationship: if relationship == "mentions" {
                        "mention".into()
                    } else {
                        relationship
                    },
                    target,
                    display_label: link.try_get("note")?,
                }),
                _ => {}
            }
        }
        let stored_name: String = row.try_get("name")?;
        let source_event_id: String = row.try_get("event_id")?;
        let causal_version: i64 = row.try_get("causal_envelope_version")?;
        if causal_version != 1 {
            return Err(Error::engine("unsupported stored causal envelope version"));
        }
        let frontier = CausalFrontierV1::new(
            sqlx::query_scalar::<_, String>(
                "SELECT parent_event_id FROM content_event_causal_frontier
                  WHERE event_id=? ORDER BY parent_event_id",
            )
            .bind(&source_event_id)
            .fetch_all(db.write_pool())
            .await?,
        )?;
        let causal_envelope = match row.try_get::<String, _>("causal_status")?.as_str() {
            "complete" => CausalEnvelopeV1::complete(frontier),
            "import_incomplete" => CausalEnvelopeV1::import_incomplete(frontier),
            // legacy_unknown is a storage-only migration state and is never a
            // wire claim. Its missing history is represented honestly on v2.
            "legacy_unknown" if frontier.is_empty() => {
                CausalEnvelopeV1::import_incomplete(CausalFrontierV1::empty())
            }
            _ => return Err(Error::engine("invalid stored causal envelope")),
        };
        messages.push(MessageUnitV1 {
            message_record_id: message_id.clone(),
            source_event: SourceEventV1 {
                id: source_event_id,
                source_seq: row.try_get("seq")?,
                created_at: row.try_get("created_at")?,
                source_account_token,
                operation: "message.created".into(),
                causal_envelope: Some(causal_envelope),
            },
            sender,
            audience,
            kind: row
                .try_get::<Option<String>, _>("kind")?
                .unwrap_or_default(),
            prose: row
                .try_get::<Option<String>, _>("body")?
                .unwrap_or_default(),
            name: (!stored_name.is_empty()).then_some(stored_name),
            expectation,
            origin,
            thread,
            reply_to,
            supersedes,
            required_capabilities: if references.is_empty() {
                Vec::new()
            } else {
                vec!["structured_references".into()]
            },
            references,
            extensions: None,
        });
    }
    let batch = MessageBatchV1 {
        content_version: CONTENT_VERSION.into(),
        origin_db_id,
        participants,
        messages,
        required_capabilities: vec!["message.created".into()],
        extensions: None,
    };
    let first = &batch.messages[0];
    let sender_principal = &batch.participants[first.sender].principal;
    let first_audience = first
        .audience
        .iter()
        .map(|index| batch.participants[*index].principal.as_str())
        .collect::<BTreeSet<_>>();
    if batch.messages.iter().skip(1).any(|message| {
        batch.participants[message.sender].principal.as_str() != sender_principal.as_str()
            || message
                .audience
                .iter()
                .map(|index| batch.participants[*index].principal.as_str())
                .collect::<BTreeSet<_>>()
                != first_audience
    }) {
        return Err(Error::engine(
            "one Message batch requires one sender and one exact audience",
        ));
    }
    let canonical = serde_jcs::to_vec(&batch)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    for message in &batch.messages {
        let sender = &batch.participants[message.sender];
        let audience_descriptors = message
            .audience
            .iter()
            .map(|index| &batch.participants[*index])
            .collect::<Vec<_>>();
        let canonical_semantic_payload = json!({
            "content_version": batch.content_version,
            "batch_required_capabilities": batch.required_capabilities,
            "batch_extensions": batch.extensions,
            "message": message,
            "sender": sender,
            "audience": audience_descriptors,
        });
        let canonical_payload = serde_jcs::to_vec(&canonical_semantic_payload)?;
        let payload_digest = hex::encode(Sha256::digest(&canonical_payload));
        let fingerprint_input = json!({
            "content_version": CONTENT_VERSION,
            "origin_db_id": batch.origin_db_id,
            "source_event": message.source_event,
            "message_record_id": message.message_record_id,
            "source_principal": sender.principal,
            "source_account_token": message.source_event.source_account_token,
            "semantic_payload": canonical_semantic_payload,
        });
        let fingerprint = hex::encode(Sha256::digest(serde_jcs::to_vec(&fingerprint_input)?));
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT source_fingerprint FROM content_event_sources WHERE event_id=?",
        )
        .bind(&message.source_event.id)
        .fetch_optional(&mut *tx)
        .await?;
        match existing {
            Some(existing) if existing != fingerprint => {
                return Err(Error::engine(format!(
                    "local Message export source identity collision for {}",
                    message.source_event.id
                )));
            }
            Some(_) => {}
            None => {
                sqlx::query(
                    "INSERT INTO content_event_sources
                        (event_id,origin_database_id,source_seq,source_record_id,
                         source_principal,source_fingerprint)
                     VALUES (?,?,?,?,?,?)",
                )
                .bind(&message.source_event.id)
                .bind(&batch.origin_db_id)
                .bind(message.source_event.source_seq)
                .bind(&message.message_record_id)
                .bind(&sender.principal)
                .bind(&fingerprint)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO replicated_message_provenance
                        (source_event_id,content_version,operation,source_account_token,
                         source_created_at,canonical_payload,payload_digest,envelope_id,envelope_digest)
                     VALUES (?,?,?,?,?,?,?,?,?)",
                )
                .bind(&message.source_event.id)
                .bind(CONTENT_VERSION)
                .bind("message.created")
                .bind(&message.source_event.source_account_token)
                .bind(&message.source_event.created_at)
                .bind(String::from_utf8(canonical_payload).expect("JCS JSON is UTF-8"))
                .bind(payload_digest)
                .bind(Option::<String>::None)
                .bind(Option::<String>::None)
                .execute(&mut *tx)
                .await?;
            }
        }
    }
    tx.commit().await?;
    Ok(canonical)
}

async fn export_received_native_messages(db: &Db, message_ids: &[String]) -> Result<Vec<u8>> {
    export_preserved_native_messages(db, message_ids, true).await
}

async fn export_preserved_native_messages(
    db: &Db,
    message_ids: &[String],
    received: bool,
) -> Result<Vec<u8>> {
    let mut origin_db_id: Option<String> = None;
    let mut batch_content_version: Option<String> = None;
    let mut required_capabilities: Option<Vec<String>> = None;
    let mut extensions: Option<Option<Value>> = None;
    let mut participant_slots = Vec::<Option<ParticipantDescriptorV1>>::new();
    let mut messages = Vec::with_capacity(message_ids.len());
    for message_id in message_ids {
        let provenance_predicate = if received {
            "p.envelope_id IS NOT NULL"
        } else {
            "p.envelope_id IS NULL AND p.content_version='native.message.v1'"
        };
        let row = sqlx::query(&format!(
            "SELECT e.id AS event_id,p.canonical_payload,p.payload_digest,
                    s.origin_database_id,s.source_fingerprint
               FROM content_events e
               JOIN content_event_sources s ON s.event_id=e.id
               JOIN replicated_message_provenance p ON p.source_event_id=e.id
              WHERE e.record_id=? AND e.type='record.created' AND {provenance_predicate}
              ORDER BY e.seq LIMIT 1"
        ))
        .bind(message_id)
        .fetch_one(db.write_pool())
        .await?;
        let source_origin: String = row.try_get("origin_database_id")?;
        let stored_payload_digest: String = row.try_get("payload_digest")?;
        let stored_source_fingerprint: String = row.try_get("source_fingerprint")?;
        if origin_db_id
            .as_ref()
            .is_some_and(|value| value != &source_origin)
        {
            return Err(Error::engine(
                "one received Message batch requires one source database",
            ));
        }
        origin_db_id.get_or_insert_with(|| source_origin.clone());
        let semantic: Value =
            serde_json::from_str(&row.try_get::<String, _>("canonical_payload")?)?;
        let canonical_semantic = serde_jcs::to_vec(&semantic)?;
        if hex::encode(Sha256::digest(&canonical_semantic)) != stored_payload_digest {
            return Err(Error::engine(
                "received Message provenance payload digest is inconsistent",
            ));
        }
        let content_version = semantic
            .get("content_version")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("received Message provenance has no content version"))?;
        if !matches!(content_version, CONTENT_VERSION_V1 | CONTENT_VERSION_V2) {
            return Err(Error::engine(
                "received Message provenance has unsupported content version",
            ));
        }
        if batch_content_version
            .as_deref()
            .is_some_and(|existing| existing != content_version)
        {
            return Err(Error::engine(
                "one received Message batch requires one content version",
            ));
        }
        batch_content_version.get_or_insert_with(|| content_version.to_owned());
        let capabilities: Vec<String> = serde_json::from_value(
            semantic
                .get("batch_required_capabilities")
                .cloned()
                .unwrap_or_else(|| json!([])),
        )?;
        if required_capabilities
            .as_ref()
            .is_some_and(|existing| existing != &capabilities)
        {
            return Err(Error::engine(
                "one received Message batch requires one capability contract",
            ));
        }
        required_capabilities.get_or_insert(capabilities);
        let batch_extensions = semantic
            .get("batch_extensions")
            .cloned()
            .filter(|value| !value.is_null());
        if extensions
            .as_ref()
            .is_some_and(|existing| existing != &batch_extensions)
        {
            return Err(Error::engine(
                "one received Message batch requires one extension contract",
            ));
        }
        extensions.get_or_insert(batch_extensions);
        let message: MessageUnitV1 = serde_json::from_value(
            semantic
                .get("message")
                .cloned()
                .ok_or_else(|| Error::engine("received Message provenance has no message"))?,
        )?;
        if message.message_record_id != *message_id {
            return Err(Error::engine(
                "received Message provenance names a different record",
            ));
        }
        if message.source_event.id != row.try_get::<String, _>("event_id")? {
            return Err(Error::engine(
                "received Message provenance names a different source event",
            ));
        }
        let sender: ParticipantDescriptorV1 = serde_json::from_value(
            semantic
                .get("sender")
                .cloned()
                .ok_or_else(|| Error::engine("received Message provenance has no sender"))?,
        )?;
        let audience: Vec<ParticipantDescriptorV1> = serde_json::from_value(
            semantic
                .get("audience")
                .cloned()
                .ok_or_else(|| Error::engine("received Message provenance has no audience"))?,
        )?;
        let fingerprint_input = json!({
            "content_version": content_version,
            "origin_db_id": source_origin,
            "source_event": message.source_event,
            "message_record_id": message.message_record_id,
            "source_principal": sender.principal,
            "source_account_token": message.source_event.source_account_token,
            "semantic_payload": semantic,
        });
        let recomputed_fingerprint =
            hex::encode(Sha256::digest(serde_jcs::to_vec(&fingerprint_input)?));
        if recomputed_fingerprint != stored_source_fingerprint {
            return Err(Error::engine(
                "received Message provenance source fingerprint is inconsistent",
            ));
        }
        let highest = message
            .audience
            .iter()
            .copied()
            .chain(std::iter::once(message.sender))
            .max()
            .unwrap_or(message.sender);
        let slot_count = participant_slots.len().max(highest + 1);
        participant_slots.resize_with(slot_count, || None);
        install_received_participant(&mut participant_slots, message.sender, sender)?;
        if audience.len() != message.audience.len() {
            return Err(Error::engine(
                "received Message provenance audience shape is inconsistent",
            ));
        }
        for (index, descriptor) in message.audience.iter().copied().zip(audience) {
            install_received_participant(&mut participant_slots, index, descriptor)?;
        }
        messages.push(message);
    }
    let source_origin = origin_db_id.ok_or_else(|| Error::engine("received batch is empty"))?;
    let mut known = participant_slots
        .iter()
        .filter_map(|participant| {
            participant
                .as_ref()
                .map(|participant| participant.principal.clone())
        })
        .collect::<BTreeSet<_>>();
    for message in &messages {
        if let Some(MessageOriginDeclaredPayload::Direct { principals }) = &message.origin {
            for principal in principals {
                if known.insert(principal.clone()) {
                    let descriptor = ParticipantDescriptorV1 {
                        principal: principal.clone(),
                        origin_database_id: source_origin.clone(),
                        origin_person_record_id: None,
                        origin_account_token: None,
                        verified_aliases: Vec::new(),
                        display_hint: None,
                        extensions: None,
                    };
                    if let Some(slot) = participant_slots.iter_mut().find(|slot| slot.is_none()) {
                        *slot = Some(descriptor);
                    } else {
                        participant_slots.push(Some(descriptor));
                    }
                }
            }
        }
    }
    let participants = participant_slots
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::engine("received Message provenance has unused participant slots"))?;
    serde_jcs::to_vec(&MessageBatchV1 {
        content_version: batch_content_version
            .ok_or_else(|| Error::engine("received batch is empty"))?,
        origin_db_id: source_origin,
        participants,
        messages,
        required_capabilities: required_capabilities.unwrap_or_default(),
        extensions: extensions.flatten(),
    })
    .map_err(Into::into)
}

fn install_received_participant(
    slots: &mut [Option<ParticipantDescriptorV1>],
    index: usize,
    descriptor: ParticipantDescriptorV1,
) -> Result<()> {
    let slot = slots
        .get_mut(index)
        .ok_or_else(|| Error::engine("received Message participant index is out of range"))?;
    if let Some(existing) = slot {
        if serde_jcs::to_vec(existing)? != serde_jcs::to_vec(&descriptor)? {
            return Err(Error::engine(
                "received Message batch has contradictory participant descriptors",
            ));
        }
    } else {
        *slot = Some(descriptor);
    }
    Ok(())
}

async fn export_message_origin(
    db: &Db,
    origin_db_id: &str,
    message_id: &str,
) -> Result<Option<MessageOriginDeclaredPayload>> {
    let state = sqlx::query(
        "SELECT status,origin_type,collection_id
           FROM message_origin_state WHERE message_id=?",
    )
    .bind(message_id)
    .fetch_optional(db.write_pool())
    .await?;
    let Some(state) = state else {
        return Ok(None);
    };
    if state.try_get::<String, _>("status")? != "declared" {
        return Ok(None);
    }
    match state
        .try_get::<Option<String>, _>("origin_type")?
        .as_deref()
    {
        Some("collection") => {
            let collection_id = state
                .try_get::<Option<String>, _>("collection_id")?
                .ok_or_else(|| Error::engine("declared Collection Message origin is incomplete"))?;
            // Received copies already retain the source-qualified address.
            // Preserve it across another hop rather than nesting it under the
            // current database's identity. Locally authored declarations use
            // an ordinary local record id and are qualified exactly once here.
            let collection_id = match crate::identity::decode_native_record(&collection_id) {
                Ok(_) => collection_id,
                Err(_) => crate::identity::encode_native_record(origin_db_id, &collection_id)?,
            };
            Ok(Some(MessageOriginDeclaredPayload::Collection {
                collection_id,
            }))
        }
        Some("direct") => {
            let principals = sqlx::query_scalar(
                "SELECT principal_id FROM message_origin_principals
                  WHERE message_id=? ORDER BY principal_id",
            )
            .bind(message_id)
            .fetch_all(db.write_pool())
            .await?;
            if principals.is_empty() {
                return Err(Error::engine(
                    "declared direct Message origin has no principals",
                ));
            }
            Ok(Some(MessageOriginDeclaredPayload::Direct { principals }))
        }
        Some(other) => Err(Error::engine(format!(
            "declared Message origin has unsupported type '{other}'"
        ))),
        None => Err(Error::engine("declared Message origin has no type")),
    }
}

fn participant_for_export(
    participants: &mut Vec<ParticipantDescriptorV1>,
    index: &mut BTreeMap<String, usize>,
    participant: ParticipantDescriptorV1,
) -> usize {
    if let Some(index) = index.get(&participant.principal) {
        let existing = &mut participants[*index];
        existing.origin_person_record_id = existing
            .origin_person_record_id
            .take()
            .or(participant.origin_person_record_id);
        existing.origin_account_token = existing
            .origin_account_token
            .take()
            .or(participant.origin_account_token);
        existing.display_hint = existing.display_hint.take().or(participant.display_hint);
        return *index;
    }
    let next = participants.len();
    index.insert(participant.principal.clone(), next);
    participants.push(participant);
    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::rebuild_and_diff;
    use crate::schema::UNFILED_RECORD_ID;

    const ORIGIN: &str = "ndb_11111111111111111111111111111111";
    const BOB_ORIGIN: &str = "ndb_22222222222222222222222222222222";
    const CAROL_ORIGIN: &str = "ndb_33333333333333333333333333333333";
    const AT: &str = "2026-08-03T10:11:12.123Z";

    // Pinned fixture record ids. `LOCAL_SENDER_ID`, `LOCAL_RECIPIENT_ID` and
    // `TRUSTED_ALICE_ID` are also interpolated into binding INSERT statements,
    // so those statements are built from these same constants.
    const LOCAL_SENDER_ID: &str = "4e910000-0000-4000-8000-000000000001";
    const LOCAL_RECIPIENT_ID: &str = "4e910000-0000-4000-8000-000000000002";
    const LOCAL_BEFORE_ID: &str = "4e910000-0000-4000-8000-000000000003";
    const FEDERATED_MESSAGE_INBOX_ID: &str = "4e910000-0000-4000-8000-000000000004";
    const CAROL_PRINCIPAL_OWNER_ID: &str = "4e910000-0000-4000-8000-000000000005";
    const CAROL_RECORD_OWNER_ID: &str = "4e910000-0000-4000-8000-000000000006";
    const TRUSTED_ALICE_ID: &str = "4e910000-0000-4000-8000-000000000007";

    fn participant(
        principal: &str,
        person: Option<&str>,
        name: Option<&str>,
    ) -> ParticipantDescriptorV1 {
        ParticipantDescriptorV1 {
            principal: principal.into(),
            origin_database_id: match principal {
                "native/bob" => BOB_ORIGIN,
                "native/carol" | "native/dana" => CAROL_ORIGIN,
                _ => ORIGIN,
            }
            .into(),
            origin_person_record_id: person.map(str::to_string),
            origin_account_token: (principal == "native/alice").then(|| "acct_remote_alice".into()),
            verified_aliases: Vec::new(),
            display_hint: name.map(str::to_string),
            extensions: None,
        }
    }

    fn message(id: u8, prose: &str) -> MessageUnitV1 {
        let frontier = if id == 1 {
            CausalFrontierV1::empty()
        } else {
            CausalFrontierV1::new([format!("10000000-0000-4000-8000-{:012}", id - 1)]).unwrap()
        };
        MessageUnitV1 {
            message_record_id: format!("20000000-0000-4000-8000-{id:012}"),
            source_event: SourceEventV1 {
                id: format!("10000000-0000-4000-8000-{id:012}"),
                source_seq: i64::from(id),
                created_at: AT.into(),
                source_account_token: "acct_remote_alice".into(),
                operation: "message.created".into(),
                causal_envelope: Some(CausalEnvelopeV1::complete(frontier)),
            },
            sender: 0,
            audience: vec![1, 2],
            kind: "text".into(),
            prose: prose.into(),
            name: None,
            expectation: Some("none".into()),
            origin: None,
            thread: None,
            reply_to: None,
            supersedes: None,
            references: Vec::new(),
            required_capabilities: Vec::new(),
            extensions: None,
        }
    }

    fn with_direct_origin(mut message: MessageUnitV1) -> MessageUnitV1 {
        message.origin = Some(MessageOriginDeclaredPayload::Direct {
            principals: vec![
                "native/alice".into(),
                "native/bob".into(),
                "native/carol".into(),
            ],
        });
        message
    }

    fn bytes(messages: Vec<MessageUnitV1>) -> Vec<u8> {
        serde_jcs::to_vec(&MessageBatchV1 {
            content_version: CONTENT_VERSION.into(),
            origin_db_id: ORIGIN.into(),
            participants: vec![
                participant("native/alice", Some("person-alice"), Some("Alice Remote")),
                participant("native/bob", Some("person-bob"), Some("Bob")),
                participant("native/carol", Some("person-carol"), Some("Carol")),
            ],
            messages,
            required_capabilities: vec!["message.created".into()],
            extensions: None,
        })
        .unwrap()
    }

    fn v1_bytes(mut messages: Vec<MessageUnitV1>) -> Vec<u8> {
        for message in &mut messages {
            message.source_event.causal_envelope = None;
        }
        serde_jcs::to_vec(&MessageBatchV1 {
            content_version: CONTENT_VERSION_V1.into(),
            origin_db_id: ORIGIN.into(),
            participants: vec![
                participant("native/alice", Some("person-alice"), Some("Alice Remote")),
                participant("native/bob", Some("person-bob"), Some("Bob")),
                participant("native/carol", Some("person-carol"), Some("Carol")),
            ],
            messages,
            required_capabilities: vec!["message.created".into()],
            extensions: None,
        })
        .unwrap()
    }

    struct FakeVerifiedTransport {
        envelope_id: &'static str,
        sender: &'static str,
        recipients: Vec<&'static str>,
    }

    impl FakeVerifiedTransport {
        fn remote_fixture() -> Self {
            Self {
                envelope_id: "env-test-1",
                sender: "native/alice",
                recipients: vec!["native/bob", "native/carol"],
            }
        }

        fn verified_context(&self, home: &str) -> VerifiedEnvelopeContext {
            VerifiedEnvelopeContext {
                envelope_id: self.envelope_id.into(),
                envelope_digest: Sha256::digest(self.envelope_id.as_bytes()).into(),
                authenticated_sender_principal: self.sender.into(),
                recipient_principals: self
                    .recipients
                    .iter()
                    .map(|value| (*value).into())
                    .collect(),
                destination_home_id: home.into(),
                ingest_actor: "acct_destination_ingest".into(),
                relay_state: RelayState::Acknowledged,
                received_at: "2026-08-03T10:11:13.000Z".into(),
            }
        }

        async fn deliver(&self, db: &Db, home: &str, content: &[u8]) -> IngestResult {
            ingest_verified_native_message(db, self.verified_context(home), content).await
        }
    }

    fn context(home: &str) -> VerifiedEnvelopeContext {
        FakeVerifiedTransport::remote_fixture().verified_context(home)
    }

    async fn install_local_message(db: &Db, message_id: &str) {
        for (id, principal) in [
            (LOCAL_SENDER_ID, "native/local-sender"),
            (LOCAL_RECIPIENT_ID, "native/local-recipient"),
        ] {
            crate::store::create_record(
                db,
                json!({"id":id,"type":"Entity","kind":"person","name":id}),
            )
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES (?,'native-principal',?,1)",
            )
            .bind(id)
            .bind(principal)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        sqlx::query(&format!(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) \
                 VALUES ('{LOCAL_SENDER_ID}','account','acct_local_sender',1)"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
        crate::store::create_record_as(
            db,
            json!({
                "id": message_id,
                "type":"Message",
                "kind":"text",
                "name":"",
                "body":"locally authored",
                "owner_id":LOCAL_SENDER_ID
            }),
            Some("acct_local_sender"),
        )
        .await
        .unwrap();
        crate::store::append(
            db,
            AppendSpec {
                record_id: message_id.into(),
                event_type: "facet.set".into(),
                payload: json!({
                    "key": crate::message_expectation::EXPECTATION_FACET_KEY,
                    "value": "reply",
                    "vocab_ref": crate::meta::vocab_ref(
                        crate::message_expectation::EXPECTATION_VOCABULARY_ID,
                    ),
                }),
                actor: Some("acct_local_sender".into()),
            },
        )
        .await
        .unwrap();
        crate::store::append(
            db,
            AppendSpec {
                record_id: message_id.into(),
                event_type: "link.added".into(),
                payload: serde_json::to_value(LinkAddedPayload {
                    id: Some(format!("local-mention-{message_id}")),
                    source_id: message_id.into(),
                    target_id: LOCAL_RECIPIENT_ID.into(),
                    relationship: "mentions".into(),
                    note: Some("Local recipient".into()),
                })
                .unwrap(),
                actor: Some("acct_local_sender".into()),
            },
        )
        .await
        .unwrap();
        crate::store::append(
            db,
            AppendSpec {
                record_id: message_id.into(),
                event_type: "message.audience.declared".into(),
                payload: serde_json::to_value(MessageAudienceDeclaredPayload {
                    sender_id: LOCAL_SENDER_ID.into(),
                    sender_principal: "native/local-sender".into(),
                    addressed_to: vec![MessageAudienceRecipient {
                        recipient_id: LOCAL_RECIPIENT_ID.into(),
                        principal: "native/local-recipient".into(),
                    }],
                })
                .unwrap(),
                actor: Some("acct_local_sender".into()),
            },
        )
        .await
        .unwrap();
    }

    async fn ingest_counts(db: &Db) -> (i64, i64, i64, i64, i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM records),
                    (SELECT COUNT(*) FROM bindings),
                    (SELECT COUNT(*) FROM content_events),
                    (SELECT COUNT(*) FROM replicated_message_provenance),
                    (SELECT COUNT(*) FROM destination_message_ingest),
                    (SELECT COUNT(*) FROM facet_values)",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn first_delivery_duplicate_and_collision_are_atomic() {
        let db = crate::create_database(":memory:").await.unwrap();
        let payload = bytes(vec![message(1, "hello")]);
        let applied =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &payload).await;
        assert_eq!(applied.status, IngestStatus::Applied);
        let duplicate =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &payload).await;
        assert_eq!(duplicate.status, IngestStatus::Duplicate);
        let collision = ingest_verified_native_message(
            &db,
            context(UNFILED_RECORD_ID),
            &bytes(vec![message(1, "tampered")]),
        )
        .await;
        assert_eq!(collision.status, IngestStatus::Rejected);
        let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind("20000000-0000-4000-8000-000000000001")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(body, "hello");
        let read = crate::query::read::get_record(&db, "20000000-0000-4000-8000-000000000001")
            .await
            .unwrap()
            .unwrap();
        let provenance = read.record.federation_provenance.unwrap();
        assert_eq!(provenance["direction"], "inbound");
        assert_eq!(provenance["inert"], true);
        assert_eq!(provenance["origin"]["database_id"], ORIGIN);
        assert_eq!(provenance["destination"]["relay_state"], "acknowledged");
    }

    #[tokio::test]
    async fn v1_import_is_explicitly_incomplete_and_relays_without_a_v2_upgrade() {
        let db = crate::create_database(":memory:").await.unwrap();
        let payload = v1_bytes(vec![message(18, "legacy causal envelope")]);
        let applied =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &payload).await;
        assert_eq!(applied.status, IngestStatus::Applied);

        let event_id = "10000000-0000-4000-8000-000000000018";
        let stored: (String, i64, String) = sqlx::query_as(
            "SELECT e.causal_status,
                    (SELECT COUNT(*) FROM content_event_causal_frontier f WHERE f.event_id=e.id),
                    p.content_version
               FROM content_events e
               JOIN replicated_message_provenance p ON p.source_event_id=e.id
              WHERE e.id=?",
        )
        .bind(event_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            stored,
            ("import_incomplete".into(), 0, CONTENT_VERSION_V1.into())
        );

        let relayed = export_native_messages(&db, &["20000000-0000-4000-8000-000000000018".into()])
            .await
            .unwrap();
        let relayed: Value = serde_json::from_slice(&relayed).unwrap();
        assert_eq!(relayed["content_version"], CONTENT_VERSION_V1);
        assert!(relayed["messages"][0]["source_event"]
            .get("causal_envelope")
            .is_none());
    }

    #[tokio::test]
    async fn v2_rejects_false_genesis_and_preserves_a_nonempty_frontier() {
        let rejected_db = crate::create_database(":memory:").await.unwrap();
        let mut false_genesis = message(19, "false genesis");
        false_genesis.source_event.causal_envelope =
            Some(CausalEnvelopeV1::complete(CausalFrontierV1::empty()));
        let rejected = ingest_verified_native_message(
            &rejected_db,
            context(UNFILED_RECORD_ID),
            &bytes(vec![false_genesis]),
        )
        .await;
        assert_eq!(rejected.status, IngestStatus::Rejected);
        assert_eq!(rejected.code, "invalid_causal_envelope");

        let db = crate::create_database(":memory:").await.unwrap();
        let payload = bytes(vec![message(20, "known causal parent")]);
        let applied =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &payload).await;
        assert_eq!(applied.status, IngestStatus::Applied);
        let stored: (String, String) = sqlx::query_as(
            "SELECT e.causal_status,f.parent_event_id
               FROM content_events e
               JOIN content_event_causal_frontier f ON f.event_id=e.id
              WHERE e.id=?",
        )
        .bind("10000000-0000-4000-8000-000000000020")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            stored,
            (
                "complete".into(),
                "10000000-0000-4000-8000-000000000019".into()
            )
        );

        let relayed = export_native_messages(&db, &["20000000-0000-4000-8000-000000000020".into()])
            .await
            .unwrap();
        let relayed: Value = serde_json::from_slice(&relayed).unwrap();
        assert_eq!(relayed["content_version"], CONTENT_VERSION_V2);
        assert_eq!(
            relayed["messages"][0]["source_event"]["causal_envelope"]["frontier"],
            json!(["10000000-0000-4000-8000-000000000019"])
        );
    }

    #[tokio::test]
    async fn mixed_batch_and_recipient_local_sequences_preserve_source_identity() {
        let b = crate::create_database(":memory:").await.unwrap();
        let c = crate::create_database(":memory:").await.unwrap();
        crate::store::create_record(
            &c,
            json!({"id":LOCAL_BEFORE_ID,"type":"Document","kind":"note","name":"before"}),
        )
        .await
        .unwrap();
        let first = bytes(vec![message(1, "one")]);
        assert_eq!(
            ingest_verified_native_message(&b, context(UNFILED_RECORD_ID), &first)
                .await
                .status,
            IngestStatus::Applied
        );
        let mixed = bytes(vec![message(1, "one"), message(2, "two")]);
        assert_eq!(
            ingest_verified_native_message(&b, context(UNFILED_RECORD_ID), &mixed)
                .await
                .status,
            IngestStatus::PartiallyDuplicateBatchApplied
        );
        assert_eq!(
            ingest_verified_native_message(&c, context(UNFILED_RECORD_ID), &first)
                .await
                .status,
            IngestStatus::Applied
        );
        let b_row: (i64, i64, String) = sqlx::query_as(
            "SELECT e.seq,s.source_seq,s.source_fingerprint FROM content_events e JOIN content_event_sources s ON s.event_id=e.id WHERE e.id=?",
        )
        .bind("10000000-0000-4000-8000-000000000001")
        .fetch_one(b.write_pool()).await.unwrap();
        let c_row: (i64, i64, String) = sqlx::query_as(
            "SELECT e.seq,s.source_seq,s.source_fingerprint FROM content_events e JOIN content_event_sources s ON s.event_id=e.id WHERE e.id=?",
        )
        .bind("10000000-0000-4000-8000-000000000001")
        .fetch_one(c.write_pool()).await.unwrap();
        assert_ne!(b_row.0, c_row.0);
        assert_eq!((b_row.1, b_row.2), (c_row.1, c_row.2));
        assert!(rebuild_and_diff(&b).await.unwrap().equal);
    }

    #[tokio::test]
    async fn unsupported_capability_and_bad_expectation_do_not_mutate() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut unsupported: MessageBatchV1 =
            serde_json::from_slice(&bytes(vec![message(3, "no")])).unwrap();
        unsupported
            .required_capabilities
            .push("future.execute".into());
        let result = ingest_verified_native_message(
            &db,
            context(UNFILED_RECORD_ID),
            &serde_jcs::to_vec(&unsupported).unwrap(),
        )
        .await;
        assert_eq!(result.status, IngestStatus::Quarantined);
        let mut bad = message(4, "no");
        bad.expectation = Some("read_receipt".into());
        let result =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &bytes(vec![bad]))
                .await;
        assert_eq!(result.status, IngestStatus::Quarantined);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM replicated_message_provenance")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn unknown_optional_extension_is_fingerprinted_and_unknown_kind_is_readable() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut input = message(5, "readable fallback");
        input.kind = "vendor.card".into();
        input.extensions = Some(json!({"vendor":{"optional":true}}));
        let result =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &bytes(vec![input]))
                .await;
        assert_eq!(result.status, IngestStatus::Applied);
        assert_eq!(result.code, "applied_with_quarantined_kind");
        let stored: (String, String) = sqlx::query_as(
            "SELECT r.body,d.ingest_state FROM records r JOIN destination_message_ingest d ON d.message_id=r.id WHERE r.id=?",
        ).bind("20000000-0000-4000-8000-000000000005").fetch_one(db.write_pool()).await.unwrap();
        assert_eq!(
            stored,
            ("readable fallback".into(), "quarantined_kind".into())
        );
    }

    #[tokio::test]
    async fn repeated_directory_hint_does_not_upgrade_a_binding_only_shadow() {
        let db = crate::create_database(":memory:").await.unwrap();
        for id in [6, 7] {
            let result = ingest_verified_native_message(
                &db,
                context(UNFILED_RECORD_ID),
                &bytes(vec![message(id, "same remote sender")]),
            )
            .await;
            assert_eq!(result.status, IngestStatus::Applied);
        }
        let states: Vec<String> = sqlx::query_scalar(
            "SELECT sender_state FROM destination_message_ingest ORDER BY message_id",
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(states, vec!["binding_only", "binding_only"]);
    }

    #[tokio::test]
    async fn changing_an_audience_principal_changes_source_identity_and_collides() {
        let db = crate::create_database(":memory:").await.unwrap();
        let original = bytes(vec![message(8, "audience is semantic")]);
        assert_eq!(
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &original)
                .await
                .status,
            IngestStatus::Applied
        );
        let mut changed: MessageBatchV1 = serde_json::from_slice(&original).unwrap();
        changed.participants[2] = participant("native/dana", Some("person-dana"), Some("Dana"));
        let mut changed_context = context(UNFILED_RECORD_ID);
        changed_context.recipient_principals = vec!["native/bob".into(), "native/dana".into()];
        let collision = ingest_verified_native_message(
            &db,
            changed_context,
            &serde_jcs::to_vec(&changed).unwrap(),
        )
        .await;
        assert_eq!(collision.status, IngestStatus::Rejected);
        assert_eq!(collision.code, "source_identity_collision");
    }

    #[tokio::test]
    async fn explicit_direct_origin_is_validated_fingerprinted_and_projected_unchanged() {
        let db = crate::create_database(":memory:").await.unwrap();
        let original = bytes(vec![with_direct_origin(message(21, "explicit direct"))]);
        let applied =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &original).await;
        assert_eq!(applied.status, IngestStatus::Applied);

        let event_payload: String = sqlx::query_scalar(
            "SELECT payload FROM content_events
              WHERE record_id=? AND type='message.origin.declared.v1'",
        )
        .bind("20000000-0000-4000-8000-000000000021")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&event_payload).unwrap(),
            json!({
                "type":"direct",
                "principals":["native/alice","native/bob","native/carol"]
            })
        );
        let state: (String, String, i64) = sqlx::query_as(
            "SELECT status,origin_type,participant_count
               FROM message_origin_state WHERE message_id=?",
        )
        .bind("20000000-0000-4000-8000-000000000021")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(state, ("declared".into(), "direct".into(), 3));
        let principals: Vec<String> = sqlx::query_scalar(
            "SELECT principal_id FROM message_origin_principals
              WHERE message_id=? ORDER BY principal_id",
        )
        .bind("20000000-0000-4000-8000-000000000021")
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            principals,
            vec!["native/alice", "native/bob", "native/carol"]
        );
        let canonical_payload: String = sqlx::query_scalar(
            "SELECT canonical_payload FROM replicated_message_provenance
              WHERE source_event_id=?",
        )
        .bind("10000000-0000-4000-8000-000000000021")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&canonical_payload).unwrap()["message"]["origin"],
            json!({
                "type":"direct",
                "principals":["native/alice","native/bob","native/carol"]
            })
        );

        let mut changed: MessageBatchV1 = serde_json::from_slice(&original).unwrap();
        changed.messages[0].origin = Some(MessageOriginDeclaredPayload::Collection {
            collection_id: crate::identity::encode_native_record(ORIGIN, "remote-channel").unwrap(),
        });
        let collision = ingest_verified_native_message(
            &db,
            context(UNFILED_RECORD_ID),
            &serde_jcs::to_vec(&changed).unwrap(),
        )
        .await;
        assert_eq!(collision.status, IngestStatus::Rejected);
        assert_eq!(collision.code, "source_identity_collision");
        assert!(rebuild_and_diff(&db).await.unwrap().equal);
    }

    #[tokio::test]
    async fn inbound_direct_origin_replaces_broad_home_visibility_with_exact_local_accounts() {
        const BROAD_HOME: &str = "31000000-0000-4000-8000-000000000001";
        const LOCAL_BOB: &str = "31000000-0000-4000-8000-000000000002";
        const UNRELATED: &str = "31000000-0000-4000-8000-000000000003";
        let db = crate::create_database(":memory:").await.unwrap();
        crate::store::create_record(
            &db,
            json!({"id":BROAD_HOME,"type":"Collection","kind":"folder","name":"Broad inbox"}),
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "acct_destination_ingest",
            BROAD_HOME,
            vec![AllowEntry::members(Capability::View)],
        )
        .await
        .unwrap();
        for (record_id, account) in [(LOCAL_BOB, "acct_local_bob"), (UNRELATED, "acct_unrelated")] {
            crate::store::create_record(
                &db,
                json!({"id":record_id,"type":"Entity","kind":"person","name":account}),
            )
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical)
                 VALUES (?,'account',?,1)",
            )
            .bind(record_id)
            .bind(account)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical)
             VALUES (?,'native-principal','native/bob',1)",
        )
        .bind(LOCAL_BOB)
        .execute(db.write_pool())
        .await
        .unwrap();
        assert!(crate::authorization::effective_capability(
            &db,
            crate::authorization::Principal::bound("acct_unrelated", true),
            BROAD_HOME,
        )
        .await
        .unwrap()
        .allows(Capability::View));

        let message_id = "20000000-0000-4000-8000-000000000029";
        let applied = ingest_verified_native_message(
            &db,
            context(BROAD_HOME),
            &bytes(vec![with_direct_origin(message(
                29,
                "private remote thread",
            ))]),
        )
        .await;
        assert_eq!(applied.status, IngestStatus::Applied);
        assert_eq!(
            crate::authorization::policy_mode(&db, message_id)
                .await
                .unwrap(),
            crate::authorization::PolicyMode::Explicit
        );
        assert!(crate::authorization::effective_capability(
            &db,
            crate::authorization::Principal::bound("acct_local_bob", true),
            message_id,
        )
        .await
        .unwrap()
        .allows(Capability::View));
        assert!(!crate::authorization::effective_capability(
            &db,
            crate::authorization::Principal::bound("acct_unrelated", true),
            message_id,
        )
        .await
        .unwrap()
        .allows(Capability::View));
    }

    #[tokio::test]
    async fn collection_origin_is_source_context_not_destination_filing() {
        let db = crate::create_database(":memory:").await.unwrap();
        let source_collection =
            crate::identity::encode_native_record(ORIGIN, "source-collection").unwrap();
        let mut input = message(27, "remote channel contribution");
        input.origin = Some(MessageOriginDeclaredPayload::Collection {
            collection_id: source_collection.clone(),
        });
        let applied =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &bytes(vec![input]))
                .await;
        assert_eq!(applied.status, IngestStatus::Applied);
        let projected: (String, String, Option<String>) = sqlx::query_as(
            "SELECT status,origin_type,collection_id
               FROM message_origin_state WHERE message_id=?",
        )
        .bind("20000000-0000-4000-8000-000000000027")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            projected,
            (
                "declared".into(),
                "collection".into(),
                Some(source_collection)
            )
        );
        let home: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id=?")
            .bind("20000000-0000-4000-8000-000000000027")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(home, UNFILED_RECORD_ID);

        let reexported_bytes =
            export_native_messages(&db, &["20000000-0000-4000-8000-000000000027".into()])
                .await
                .unwrap();
        let reexported: MessageBatchV1 = serde_json::from_slice(&reexported_bytes).unwrap();
        assert_eq!(
            reexported.messages[0].origin,
            Some(MessageOriginDeclaredPayload::Collection {
                collection_id: crate::identity::encode_native_record(ORIGIN, "source-collection")
                    .unwrap()
            })
        );
        let third = crate::create_database(":memory:").await.unwrap();
        let relayed =
            ingest_verified_native_message(&third, context(UNFILED_RECORD_ID), &reexported_bytes)
                .await;
        assert_eq!(relayed.status, IngestStatus::Applied);
        let third_origin: String =
            sqlx::query_scalar("SELECT collection_id FROM message_origin_state WHERE message_id=?")
                .bind("20000000-0000-4000-8000-000000000027")
                .fetch_one(third.write_pool())
                .await
                .unwrap();
        assert_eq!(
            third_origin,
            crate::identity::encode_native_record(ORIGIN, "source-collection").unwrap()
        );

        let source_event_id = &reexported.messages[0].source_event.id;
        let original_integrity: (String, String) = sqlx::query_as(
            "SELECT p.payload_digest,s.source_fingerprint
               FROM replicated_message_provenance p
               JOIN content_event_sources s ON s.event_id=p.source_event_id
              WHERE p.source_event_id=?",
        )
        .bind(source_event_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE replicated_message_provenance SET payload_digest=? WHERE source_event_id=?",
        )
        .bind("0".repeat(64))
        .bind(source_event_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let error = export_native_messages(&db, &["20000000-0000-4000-8000-000000000027".into()])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("payload digest is inconsistent"));
        sqlx::query(
            "UPDATE replicated_message_provenance SET payload_digest=? WHERE source_event_id=?",
        )
        .bind(&original_integrity.0)
        .bind(source_event_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query("UPDATE content_event_sources SET source_fingerprint=? WHERE event_id=?")
            .bind("0".repeat(64))
            .bind(source_event_id)
            .execute(db.write_pool())
            .await
            .unwrap();
        let error = export_native_messages(&db, &["20000000-0000-4000-8000-000000000027".into()])
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("source fingerprint is inconsistent"));
        assert_ne!(original_integrity.1, "0".repeat(64));
    }

    #[tokio::test]
    async fn malformed_origins_fail_before_mutation_and_legacy_absence_stays_unknown() {
        let db = crate::create_database(":memory:").await.unwrap();
        let invalid = [
            vec!["native/carol", "native/alice", "native/bob"],
            vec!["native/bob", "native/carol"],
            vec!["native/alice", "native/bob"],
            vec![
                "native/alice",
                "native/bob",
                "native/carol",
                "native/unknown",
            ],
        ];
        for (offset, principals) in invalid.into_iter().enumerate() {
            let mut input = message(22 + offset as u8, "invalid origin");
            input.origin = Some(MessageOriginDeclaredPayload::Direct {
                principals: principals.into_iter().map(str::to_string).collect(),
            });
            let rejected = ingest_verified_native_message(
                &db,
                context(UNFILED_RECORD_ID),
                &bytes(vec![input]),
            )
            .await;
            assert_eq!(rejected.status, IngestStatus::Rejected);
            assert_eq!(rejected.code, "invalid_message_origin");
        }
        let mut unqualified_collection = message(28, "unqualified collection origin");
        unqualified_collection.origin = Some(MessageOriginDeclaredPayload::Collection {
            collection_id: "source-collection".into(),
        });
        let rejected = ingest_verified_native_message(
            &db,
            context(UNFILED_RECORD_ID),
            &bytes(vec![unqualified_collection]),
        )
        .await;
        assert_eq!(rejected.status, IngestStatus::Rejected);
        assert_eq!(rejected.code, "invalid_message_origin");
        let event_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_events WHERE type='message.origin.declared.v1'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(event_count, 0);

        let legacy = ingest_verified_native_message(
            &db,
            context(UNFILED_RECORD_ID),
            &bytes(vec![message(26, "legacy origin unknown")]),
        )
        .await;
        assert_eq!(legacy.status, IngestStatus::Applied);
        let status: String =
            sqlx::query_scalar("SELECT status FROM message_origin_state WHERE message_id=?")
                .bind("20000000-0000-4000-8000-000000000026")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_ne!(status, "declared");
        let inferred: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM message_origin_principals WHERE message_id=?")
                .bind("20000000-0000-4000-8000-000000000026")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(inferred, 0);
        assert_eq!(
            crate::authorization::policy_mode(&db, "20000000-0000-4000-8000-000000000026")
                .await
                .unwrap(),
            crate::authorization::PolicyMode::Explicit
        );
        let legacy_grants: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM policy_entries WHERE policy_anchor_id=?")
                .bind("20000000-0000-4000-8000-000000000026")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(legacy_grants, 0);
    }

    #[tokio::test]
    async fn batch_extensions_are_semantic_and_aggregate_extension_budget_is_closed() {
        let db = crate::create_database(":memory:").await.unwrap();
        let original = bytes(vec![message(9, "batch metadata is semantic")]);
        assert_eq!(
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &original)
                .await
                .status,
            IngestStatus::Applied
        );
        let mut changed: MessageBatchV1 = serde_json::from_slice(&original).unwrap();
        changed.extensions = Some(json!({"vendor":{"mode":"different"}}));
        let collision = ingest_verified_native_message(
            &db,
            context(UNFILED_RECORD_ID),
            &serde_jcs::to_vec(&changed).unwrap(),
        )
        .await;
        assert_eq!(collision.status, IngestStatus::Rejected);
        assert_eq!(collision.code, "source_identity_collision");

        let mut oversized: MessageBatchV1 =
            serde_json::from_slice(&bytes(vec![message(10, "extension budget")])).unwrap();
        oversized.participants[0].extensions = Some(json!({"a":"x".repeat(70_000)}));
        oversized.participants[1].extensions = Some(json!({"b":"x".repeat(70_000)}));
        let rejected = ingest_verified_native_message(
            &db,
            context(UNFILED_RECORD_ID),
            &serde_jcs::to_vec(&oversized).unwrap(),
        )
        .await;
        assert_eq!(rejected.status, IngestStatus::Rejected);
        assert_eq!(rejected.code, "extension_limit");
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=?)")
            .bind("20000000-0000-4000-8000-000000000010")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn reference_cycles_and_mismatched_bindings_are_rejected_before_mutation() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut first = message(11, "cycle one");
        let mut second = message(12, "cycle two");
        first.reply_to = Some(ExternalRecordRefV1 {
            origin_database_id: ORIGIN.into(),
            record_id: second.message_record_id.clone(),
            binding: None,
        });
        second.reply_to = Some(ExternalRecordRefV1 {
            origin_database_id: ORIGIN.into(),
            record_id: first.message_record_id.clone(),
            binding: None,
        });
        let cycle = ingest_verified_native_message(
            &db,
            context(UNFILED_RECORD_ID),
            &bytes(vec![first, second]),
        )
        .await;
        assert_eq!(cycle.status, IngestStatus::Rejected);
        assert_eq!(cycle.code, "reference_cycle");

        let mut mismatch = message(13, "binding mismatch");
        mismatch.reply_to = Some(ExternalRecordRefV1 {
            origin_database_id: ORIGIN.into(),
            record_id: "remote-parent".into(),
            binding: Some(
                crate::identity::encode_native_record(ORIGIN, "different-parent").unwrap(),
            ),
        });
        let mismatch =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &bytes(vec![mismatch]))
                .await;
        assert_eq!(mismatch.status, IngestStatus::Rejected);
        assert_eq!(mismatch.code, "invalid_reference_binding");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM replicated_message_provenance")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn local_export_is_stable_sealed_and_loopback_is_inert() {
        let db = crate::create_database(":memory:").await.unwrap();
        let message_id = "30000000-0000-4000-8000-000000000001";
        install_local_message(&db, message_id).await;

        let first = export_native_messages(&db, &[message_id.into()])
            .await
            .unwrap();
        let second = export_native_messages(&db, &[message_id.into()])
            .await
            .unwrap();
        assert_eq!(first, second);
        let source_event_id: String = serde_json::from_slice::<MessageBatchV1>(&first)
            .unwrap()
            .messages[0]
            .source_event
            .id
            .clone();
        let source: (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT envelope_id,envelope_digest FROM replicated_message_provenance WHERE source_event_id=?",
        )
        .bind(&source_event_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(source, (None, None));

        let loopback_context = VerifiedEnvelopeContext {
            envelope_id: "env-loopback".into(),
            envelope_digest: Sha256::digest(b"env-loopback").into(),
            authenticated_sender_principal: "native/local-sender".into(),
            recipient_principals: vec!["native/local-recipient".into()],
            destination_home_id: UNFILED_RECORD_ID.into(),
            ingest_actor: "acct_destination_ingest".into(),
            relay_state: RelayState::Acknowledged,
            received_at: "2026-08-03T10:11:13.000Z".into(),
        };
        let loopback = ingest_verified_native_message(&db, loopback_context, &first).await;
        assert_eq!(loopback.status, IngestStatus::Duplicate);
        let destination_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM destination_message_ingest WHERE message_id=?",
        )
        .bind(message_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(destination_rows, 0);
    }

    #[tokio::test]
    async fn local_export_reads_explicit_origin_projection_without_legacy_inference() {
        let db = crate::create_database(":memory:").await.unwrap();
        let message_id = "30000000-0000-4000-8000-000000000004";
        install_local_message(&db, message_id).await;
        let unaddressed_id = "30000000-0000-4000-8000-000000000007";
        crate::store::create_record(
            &db,
            json!({"id":unaddressed_id,"type":"Entity","kind":"person","name":"Unaddressed participant"}),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical)
             VALUES (?,'native-principal','native/local-unaddressed',1)",
        )
        .bind(unaddressed_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        crate::store::append(
            &db,
            AppendSpec {
                record_id: message_id.into(),
                event_type: "message.origin.declared.v1".into(),
                payload: serde_json::to_value(MessageOriginDeclaredPayload::Direct {
                    principals: vec![
                        "native/local-recipient".into(),
                        "native/local-sender".into(),
                        "native/local-unaddressed".into(),
                    ],
                })
                .unwrap(),
                actor: Some("acct_local_sender".into()),
            },
        )
        .await
        .unwrap();

        let exported = export_native_messages(&db, &[message_id.into()])
            .await
            .unwrap();
        let batch: MessageBatchV1 = serde_json::from_slice(&exported).unwrap();
        assert_eq!(
            batch.messages[0].origin,
            Some(MessageOriginDeclaredPayload::Direct {
                principals: vec![
                    "native/local-recipient".into(),
                    "native/local-sender".into(),
                    "native/local-unaddressed".into(),
                ]
            })
        );
        assert!(batch
            .participants
            .iter()
            .any(|participant| participant.principal == "native/local-unaddressed"));
        let canonical_payload: String = sqlx::query_scalar(
            "SELECT canonical_payload FROM replicated_message_provenance
              WHERE source_event_id=?",
        )
        .bind(&batch.messages[0].source_event.id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&canonical_payload).unwrap()["message"]["origin"],
            json!({
                "type":"direct",
                "principals":["native/local-recipient","native/local-sender","native/local-unaddressed"]
            })
        );
        let relay = crate::create_database(":memory:").await.unwrap();
        let relay_context = VerifiedEnvelopeContext {
            envelope_id: "env-direct-relay".into(),
            envelope_digest: Sha256::digest(b"env-direct-relay").into(),
            authenticated_sender_principal: "native/local-sender".into(),
            recipient_principals: vec!["native/local-recipient".into()],
            destination_home_id: UNFILED_RECORD_ID.into(),
            ingest_actor: "acct_destination_ingest".into(),
            relay_state: RelayState::Acknowledged,
            received_at: "2026-08-03T10:11:13.000Z".into(),
        };
        assert_eq!(
            ingest_verified_native_message(&relay, relay_context, &exported)
                .await
                .status,
            IngestStatus::Applied
        );
        let relayed = export_native_messages(&relay, &[message_id.into()])
            .await
            .unwrap();
        let relayed: MessageBatchV1 = serde_json::from_slice(&relayed).unwrap();
        assert!(relayed
            .participants
            .iter()
            .any(|participant| participant.principal == "native/local-unaddressed"));

        let collection_id = "30000000-0000-4000-8000-000000000005";
        let collection_message_id = "30000000-0000-4000-8000-000000000006";
        let collection_db = crate::create_database(":memory:").await.unwrap();
        crate::store::create_record(
            &collection_db,
            json!({
                "id":collection_id,
                "type":"Collection",
                "kind":"folder",
                "name":"Source channel"
            }),
        )
        .await
        .unwrap();
        install_local_message(&collection_db, collection_message_id).await;
        crate::store::append(
            &collection_db,
            AppendSpec {
                record_id: collection_message_id.into(),
                event_type: "message.origin.declared.v1".into(),
                payload: serde_json::to_value(MessageOriginDeclaredPayload::Collection {
                    collection_id: collection_id.into(),
                })
                .unwrap(),
                actor: Some("acct_local_sender".into()),
            },
        )
        .await
        .unwrap();
        let exported = export_native_messages(&collection_db, &[collection_message_id.into()])
            .await
            .unwrap();
        let batch: MessageBatchV1 = serde_json::from_slice(&exported).unwrap();
        let origin_db_id = crate::identity::database_id(&collection_db).await.unwrap();
        assert_eq!(
            batch.messages[0].origin,
            Some(MessageOriginDeclaredPayload::Collection {
                collection_id: crate::identity::encode_native_record(&origin_db_id, collection_id,)
                    .unwrap()
            })
        );

        let channel_post_id = "30000000-0000-4000-8000-000000000008";
        crate::store::create_record_as(
            &collection_db,
            json!({
                "id":channel_post_id,
                "type":"Message",
                "kind":"text",
                "name":"",
                "body":"unaddressed channel post",
                "owner_id":LOCAL_SENDER_ID
            }),
            Some("acct_local_sender"),
        )
        .await
        .unwrap();
        crate::store::append(
            &collection_db,
            AppendSpec {
                record_id: channel_post_id.into(),
                event_type: "message.audience.declared".into(),
                payload: serde_json::to_value(MessageAudienceDeclaredPayload {
                    sender_id: LOCAL_SENDER_ID.into(),
                    sender_principal: "native/local-sender".into(),
                    addressed_to: Vec::new(),
                })
                .unwrap(),
                actor: Some("acct_local_sender".into()),
            },
        )
        .await
        .unwrap();
        crate::store::append(
            &collection_db,
            AppendSpec {
                record_id: channel_post_id.into(),
                event_type: "message.origin.declared.v1".into(),
                payload: serde_json::to_value(MessageOriginDeclaredPayload::Collection {
                    collection_id: collection_id.into(),
                })
                .unwrap(),
                actor: Some("acct_local_sender".into()),
            },
        )
        .await
        .unwrap();
        let channel_post_bytes = export_native_messages(&collection_db, &[channel_post_id.into()])
            .await
            .unwrap();
        let channel_post: MessageBatchV1 = serde_json::from_slice(&channel_post_bytes).unwrap();
        assert!(channel_post.messages[0].audience.is_empty());
        let destination = crate::create_database(":memory:").await.unwrap();
        let transport_context = VerifiedEnvelopeContext {
            envelope_id: "env-channel-transport".into(),
            envelope_digest: Sha256::digest(b"env-channel-transport").into(),
            authenticated_sender_principal: "native/local-sender".into(),
            recipient_principals: vec!["native/local-recipient".into()],
            destination_home_id: UNFILED_RECORD_ID.into(),
            ingest_actor: "acct_destination_ingest".into(),
            relay_state: RelayState::Acknowledged,
            received_at: "2026-08-03T10:11:13.000Z".into(),
        };
        assert_eq!(
            ingest_verified_native_message(&destination, transport_context, &channel_post_bytes)
                .await
                .status,
            IngestStatus::Applied
        );
    }

    #[tokio::test]
    async fn local_export_rejects_an_actor_not_bound_to_the_message_owner() {
        let db = crate::create_database(":memory:").await.unwrap();
        let message_id = "30000000-0000-4000-8000-000000000003";
        install_local_message(&db, message_id).await;
        sqlx::query(
            "DELETE FROM bindings WHERE system='account' AND identifier='acct_local_sender'",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) \
                 VALUES ('{LOCAL_RECIPIENT_ID}','account','acct_local_sender',1)"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
        let error = export_native_messages(&db, &[message_id.into()])
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("creation actor must be bound to its owner"));
        let sealed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_event_sources s JOIN content_events e ON e.id=s.event_id WHERE e.record_id=?",
        )
        .bind(message_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(sealed, 0);
    }

    #[tokio::test]
    async fn authored_a_to_b_is_queryable_with_inert_provenance_in_a_real_home() {
        let a = crate::create_database(":memory:").await.unwrap();
        let b = crate::create_database(":memory:").await.unwrap();
        let message_id = "30000000-0000-4000-8000-000000000002";
        let collection_id = FEDERATED_MESSAGE_INBOX_ID;
        install_local_message(&a, message_id).await;
        crate::store::create_record(
            &b,
            json!({
                "id":collection_id,
                "type":"Collection",
                "kind":"folder",
                "name":"Federated message inbox"
            }),
        )
        .await
        .unwrap();
        let exported = export_native_messages(&a, &[message_id.into()])
            .await
            .unwrap();
        let transport = FakeVerifiedTransport {
            envelope_id: "env-a-to-b",
            sender: "native/local-sender",
            recipients: vec!["native/local-recipient"],
        };
        let applied = transport.deliver(&b, collection_id, &exported).await;
        assert_eq!(applied.status, IngestStatus::Applied);

        let read = crate::query::read::get_record(&b, message_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.record.home_id.as_deref(), Some(collection_id));
        let read_provenance = read.record.federation_provenance.unwrap();
        assert_eq!(read_provenance["direction"], "inbound");
        assert_eq!(read_provenance["inert"], true);
        assert_eq!(read_provenance["origin"]["record_id"], message_id);
        let resolved_references = read_provenance["references"]["resolved"]
            .as_array()
            .unwrap();
        assert_eq!(resolved_references.len(), 1);
        assert_eq!(resolved_references[0]["relationship"], "mention");
        assert_eq!(
            resolved_references[0]["target"]["record_id"],
            LOCAL_RECIPIENT_ID
        );
        assert!(resolved_references[0]["local_record_id"].is_string());

        let output = crate::query::pipeline::run(
            &b,
            &[crate::query::pipeline::Step::filter(
                crate::query::pipeline::Filter {
                    types: vec!["Message".into()],
                    home_id: Some(collection_id.into()),
                    ..Default::default()
                },
            )],
            None,
            &crate::query::pipeline::PipelineOptions::default(),
        )
        .await
        .unwrap();
        match output {
            crate::query::pipeline::PipelineOutput::Records { records, .. } => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].id, message_id);
                assert_eq!(
                    records[0].federation_provenance.as_ref().unwrap()["direction"],
                    "inbound"
                );
            }
            other => panic!("expected records, got {other:?}"),
        }
        let expectation: (String, String) =
            sqlx::query_as("SELECT value,vocab_ref FROM facet_values WHERE record_id=? AND key=?")
                .bind(message_id)
                .bind(crate::message_expectation::EXPECTATION_FACET_KEY)
                .fetch_one(b.write_pool())
                .await
                .unwrap();
        assert_eq!(
            expectation,
            (
                "reply".into(),
                crate::meta::vocab_ref(crate::message_expectation::EXPECTATION_VOCABULARY_ID)
            )
        );
    }

    #[tokio::test]
    async fn unresolved_earlier_reply_stays_visible_without_inventing_expectation() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut reply = message(14, "reply with unavailable causal parent");
        reply.expectation = None;
        reply.reply_to = Some(ExternalRecordRefV1 {
            origin_database_id: ORIGIN.into(),
            record_id: "20000000-0000-4000-8000-000000000001".into(),
            binding: None,
        });
        let result =
            ingest_verified_native_message(&db, context(UNFILED_RECORD_ID), &bytes(vec![reply]))
                .await;
        assert_eq!(result.status, IngestStatus::Applied);
        let read = crate::query::read::get_record(&db, "20000000-0000-4000-8000-000000000014")
            .await
            .unwrap()
            .unwrap();
        let provenance = read.record.federation_provenance.unwrap();
        assert_eq!(
            provenance["references"]["resolved"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            provenance["references"]["unresolved"][0]["target"]["record_id"],
            "20000000-0000-4000-8000-000000000001"
        );
        let expectation_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM facet_values WHERE record_id=? AND key=?")
                .bind("20000000-0000-4000-8000-000000000014")
                .bind(crate::message_expectation::EXPECTATION_FACET_KEY)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(expectation_count, 0);
    }

    #[tokio::test]
    async fn late_identity_conflict_and_projector_failure_roll_back_every_ingest_write() {
        let conflict_db = crate::create_database(":memory:").await.unwrap();
        for id in [CAROL_PRINCIPAL_OWNER_ID, CAROL_RECORD_OWNER_ID] {
            crate::store::create_record(
                &conflict_db,
                json!({"id":id,"type":"Entity","kind":"person","name":id}),
            )
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES (?,'native-principal','native/carol',1)",
        )
        .bind(CAROL_PRINCIPAL_OWNER_ID)
        .execute(conflict_db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES (?,'native-record',?,1)",
        )
        .bind(CAROL_RECORD_OWNER_ID)
        .bind(crate::identity::encode_native_record(CAROL_ORIGIN, "person-carol").unwrap())
        .execute(conflict_db.write_pool())
        .await
        .unwrap();
        let before_conflict = ingest_counts(&conflict_db).await;
        let conflict = ingest_verified_native_message(
            &conflict_db,
            context(UNFILED_RECORD_ID),
            &bytes(vec![message(15, "late identity conflict")]),
        )
        .await;
        assert_eq!(conflict.status, IngestStatus::Quarantined);
        assert_eq!(conflict.code, "binding_conflict");
        assert_eq!(ingest_counts(&conflict_db).await, before_conflict);

        let projection_db = crate::create_database(":memory:").await.unwrap();
        let before_projection = ingest_counts(&projection_db).await;
        let projection = ingest_verified_native_message(
            &projection_db,
            context("missing-destination-home"),
            &bytes(vec![message(16, "invalid home must roll back")]),
        )
        .await;
        assert_eq!(projection.status, IngestStatus::RetryableFailure);
        assert_eq!(projection.code, "destination_write_failure");
        assert_eq!(ingest_counts(&projection_db).await, before_projection);
    }

    #[tokio::test]
    async fn concurrent_identical_delivery_applies_once() {
        let db = crate::create_database(":memory:").await.unwrap();
        let payload = bytes(vec![message(17, "concurrent replay")]);
        let left_context = context(UNFILED_RECORD_ID);
        let right_context = left_context.clone();
        let (left, right) = tokio::join!(
            ingest_verified_native_message(&db, left_context, &payload),
            ingest_verified_native_message(&db, right_context, &payload),
        );
        assert!(matches!(
            (left.status, right.status),
            (IngestStatus::Applied, IngestStatus::Duplicate)
                | (IngestStatus::Duplicate, IngestStatus::Applied)
        ));
        let projection_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE id=? AND record_id=?")
                .bind("10000000-0000-4000-8000-000000000017")
                .bind("20000000-0000-4000-8000-000000000017")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(projection_count, 1);
        let provenance_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM replicated_message_provenance WHERE source_event_id=?",
        )
        .bind("10000000-0000-4000-8000-000000000017")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(provenance_count, 1);
    }

    #[tokio::test]
    async fn normal_reads_distinguish_all_sender_trust_states_without_fake_people() {
        let known_db = crate::create_database(":memory:").await.unwrap();
        crate::store::create_record(
            &known_db,
            json!({"id":TRUSTED_ALICE_ID,"type":"Entity","kind":"person","name":"Trusted Alice"}),
        )
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) \
                 VALUES ('{TRUSTED_ALICE_ID}','native-principal','native/alice',1)"
        ))
        .execute(known_db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            ingest_verified_native_message(
                &known_db,
                context(UNFILED_RECORD_ID),
                &bytes(vec![message(18, "known sender")]),
            )
            .await
            .status,
            IngestStatus::Applied
        );
        let known =
            crate::query::read::get_record(&known_db, "20000000-0000-4000-8000-000000000018")
                .await
                .unwrap()
                .unwrap()
                .record
                .federation_provenance
                .unwrap();
        assert_eq!(known["sender"]["state"], "known_person");
        assert_eq!(known["sender"]["trusted_local_record_id"], TRUSTED_ALICE_ID);
        assert_eq!(known["sender"]["trusted_local_name"], "Trusted Alice");

        let shadow_db = crate::create_database(":memory:").await.unwrap();
        assert_eq!(
            ingest_verified_native_message(
                &shadow_db,
                context(UNFILED_RECORD_ID),
                &bytes(vec![message(19, "new remote shadow")]),
            )
            .await
            .status,
            IngestStatus::Applied
        );
        let shadow =
            crate::query::read::get_record(&shadow_db, "20000000-0000-4000-8000-000000000019")
                .await
                .unwrap()
                .unwrap()
                .record
                .federation_provenance
                .unwrap();
        assert_eq!(shadow["sender"]["state"], "binding_only");
        assert_eq!(shadow["sender"]["display_hint"], "Alice Remote");
        assert!(shadow["sender"]["trusted_local_record_id"].is_string());

        let principal_db = crate::create_database(":memory:").await.unwrap();
        let mut principal_batch: MessageBatchV1 =
            serde_json::from_slice(&bytes(vec![message(20, "principal only")])).unwrap();
        principal_batch.participants[0].origin_person_record_id = None;
        principal_batch.participants[0].display_hint = None;
        let principal_payload = serde_jcs::to_vec(&principal_batch).unwrap();
        assert_eq!(
            ingest_verified_native_message(
                &principal_db,
                context(UNFILED_RECORD_ID),
                &principal_payload,
            )
            .await
            .status,
            IngestStatus::Applied
        );
        let principal =
            crate::query::read::get_record(&principal_db, "20000000-0000-4000-8000-000000000020")
                .await
                .unwrap()
                .unwrap()
                .record
                .federation_provenance
                .unwrap();
        assert_eq!(principal["sender"]["state"], "principal_only");
        assert!(principal["sender"]["trusted_local_record_id"].is_null());
        assert!(principal["sender"]["trusted_local_name"].is_null());
        let sender_bindings: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bindings WHERE system='native-principal' AND identifier='native/alice'",
        )
        .fetch_one(principal_db.write_pool())
        .await
        .unwrap();
        assert_eq!(sender_bindings, 0);
    }
}
