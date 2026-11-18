//! Shared deferred-command WIRE DATA only. Serialized author/app evidence is
//! never authentication, a Caller, an acceptance witness or a cancellation grant.
//! No signature verifier, secret signer, clock, catalog, journal or dispatch lives
//! here. Hosting owns those boundaries; these helpers only preserve canonical
//! message bytes and the existing structural/operation validation behavior.
#![doc(hidden)]
use crate::{
    mcp::app_attribution::{self, AppAttribution},
    provenance::Channel,
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_AGE_MS: i64 = 30 * 60 * 1000;
pub const MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;
const V1_DOMAIN: &[u8] = b"native.hosted-outbox.DeferredCallV1\0";
const V2_DOMAIN: &[u8] = b"native.hosted-outbox.DeferredCallV2\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagingIdentity {
    pub audience: String,
    pub subject: String,
    pub organization: String,
}

/// Only non-secret facts extracted after ordinary credential verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", deny_unknown_fields)]
pub enum CredentialEvidence {
    OpaqueSession {
        session_id: String,
    },
    OAuth {
        issuer: String,
        subject: String,
        audience: Vec<String>,
        kid: String,
        algorithm: jsonwebtoken::Algorithm,
        key_thumbprint: String,
        iat: i64,
        exp: i64,
        jti: Option<String>,
        org_id: Option<String>,
        resource: String,
        /// Secondary-audience witness. Old images also populated this for
        /// ordinary primary tokens; replay classifies by the signed audience.
        /// Retain the field and null serialization for signed V1 compatibility.
        staging_identity: Option<Box<StagingIdentity>>,
    },
}

/// Observed by hosted ingress; signed for audit, never grants replay authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressEvidence {
    pub source: String,
    pub surface: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceIdentity {
    pub activity_epoch: i64,
    pub origin: String,
    pub created_at: String,
    pub provisioned_at: Option<String>,
}

/// Creation facts remain signed diagnostics. Only the never-reused catalog
/// generation proves membership continuity; role and invitation metadata stay live.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipIncarnation {
    pub created_at: String,
    pub source: String,
    pub invitation: Option<String>,
    pub generation: Option<i64>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Author {
    #[serde(default)]
    pub ingress: Option<IngressEvidence>,
    pub version: u16,
    /// Portable principal used for journal key reservation and event attribution.
    pub principal: String,
    pub hosting_user_id: String,
    pub workspace_id: String,
    pub account_id: String,
    pub person_id: Option<String>,
    pub workspace: WorkspaceIdentity,
    pub membership: MembershipIncarnation,
    /// None is retained only for migrated, unsigned v1 custody.
    pub credential: Option<CredentialEvidence>,
    pub channel: Channel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrigin {
    Client,
    Server,
}

/// Immutable replay source. Callers must validate and normalize before acceptance.
/// Meaning digest excludes presentation options and generated ids; resolved intent
/// digest pins provenance separately. Key origin/ids are chosen once, before dispatch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewEntry {
    pub entry_id: String,
    pub window_id: String,
    pub workspace_id: String,
    pub executor: String,
    pub operation: String,
    pub source_action: Option<String>,
    pub original_arguments: Value,
    pub prepared_arguments: Value,
    pub envelope_version: String,
    pub contract_version: String,
    pub contract_digest: String,
    pub producer_build: String,
    pub idempotency_key: String,
    pub key_origin: KeyOrigin,
    pub meaning_digest: String,
    pub resolved_intent_digest: Option<String>,
    pub stable_create_ids: Vec<String>,
    pub author: Author,
    pub run_key: String,
    pub parent_key: Option<String>,
    pub intent_text: Option<String>,
    pub depends_on: Vec<String>,
    pub touched_record_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowPublicKey {
    pub window_id: String,
    pub deployment_id: String,
    pub base_snapshot_digest: String,
    pub key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub version: u16,
    pub key_id: String,
    pub deadline: i64,
    pub envelope_digest: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAppEvidence {
    pub version: u16,
    pub package: String,
    pub package_version: String,
    pub install_event_id: String,
    pub assertion: String,
}
impl HostAppEvidence {
    /// Parses historical assertion data only. Every field is caller-constructible;
    /// this performs no current-install check and yields no authentication witness.
    pub fn claim(&self) -> Result<AppAttribution> {
        if self.version != 1 || self.assertion != app_attribution::ASSERTION_HOST {
            return Err(Error::auth("outbox_v2_app_evidence_unsupported"));
        }
        AppAttribution::new(&self.package, &self.package_version, &self.install_event_id)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MadeAt {
    pub reported_unix_ms: i64,
    pub source: String,
}
/// NewEntry is reused only as the immutable command-fact shape. Its nested
/// envelope_version MUST be 2; it is never handed to a V1 signer or executor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallV2 {
    pub version: u16,
    pub command: NewEntry,
    pub app: HostAppEvidence,
    pub made_at: MadeAt,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryV2 {
    pub call: CallV2,
    pub received_seq: i64,
    pub received_at: i64,
    pub attestation: Attestation,
}
pub fn digest(value: &impl Serialize) -> Result<String> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| Error::engine("outbox_noncanonical_value"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn intent_digest(intent: Option<&str>) -> Result<Option<String>> {
    intent.map(|text| digest(&text)).transpose()
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DeferredCallV1<'a> {
    purpose: &'static str,
    version: u16,
    window: &'a WindowPublicKey,
    received_seq: i64,
    received_at: i64,
    deadline: i64,
    envelope_digest: &'a str,
    call: &'a NewEntry,
}

pub fn v1_message(
    key: &WindowPublicKey,
    call: &NewEntry,
    seq: i64,
    at: i64,
    a: &Attestation,
) -> Result<Vec<u8>> {
    let data = DeferredCallV1 {
        purpose: "hosted-outbox-deferred-call",
        version: 1,
        window: key,
        received_seq: seq,
        received_at: at,
        deadline: a.deadline,
        envelope_digest: &a.envelope_digest,
        call,
    };
    let mut bytes = V1_DOMAIN.to_vec();
    bytes.extend(serde_jcs::to_vec(&data).map_err(|_| Error::engine("outbox_noncanonical_value"))?);
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(Error::auth("outbox_attestation_too_large"));
    }
    Ok(bytes)
}

pub fn validate_v1_digests(call: &NewEntry) -> Result<()> {
    if call.resolved_intent_digest != intent_digest(call.intent_text.as_deref())?
        || call.meaning_digest
            != crate::provenance::action_digest(&call.operation, &call.original_arguments)
    {
        return Err(Error::auth("outbox_digest_mismatch"));
    }
    if call.author.version != 1 || call.author.credential.is_none() || call.envelope_version != "1"
    {
        return Err(Error::auth("outbox_unsupported_evidence"));
    }
    Ok(())
}

#[cfg(feature = "mcp-executor-prototype")]
pub fn validate_operation(call: &NewEntry) -> Result<()> {
    let object = call
        .prepared_arguments
        .as_object()
        .ok_or_else(|| Error::auth("outbox_invalid_operation"))?;
    let common = [
        "reason",
        "run_key",
        "parent_key",
        "idempotency_key",
        "response_mode",
        "sources",
    ];
    let fields: &[&str] = match call.operation.as_str() {
        "create_record" => &[
            "id", "type", "kind", "name", "body", "home_id", "summary", "confirm",
        ],
        "update_record" => &["id", "record_id", "body_append"],
        _ => return Err(Error::auth("outbox_operation_not_eligible")),
    };
    if object
        .keys()
        .any(|k| !common.contains(&k.as_str()) && !fields.contains(&k.as_str()))
        || (call.operation == "create_record"
            && object.get("confirm").is_some_and(|v| !v.is_boolean()))
        || object
            .get("sources")
            .is_some_and(|s| s != &serde_json::json!([]))
        || object
            .get("idempotency_key")
            .and_then(serde_json::Value::as_str)
            != Some(&call.idempotency_key)
    {
        return Err(Error::auth("outbox_operation_not_eligible"));
    }
    let string = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
    };
    match call.operation.as_str() {
        "create_record"
            if matches!(
                (string("type"), string("kind")),
                (Some("Document"), Some("note")) | (Some("WorkItem"), Some("task"))
            ) && string("id").is_some() =>
        {
            Ok(())
        }
        "update_record"
            if string("id").is_some() != string("record_id").is_some()
                && string("body_append").is_some() =>
        {
            Ok(())
        }
        _ => Err(Error::auth("outbox_operation_not_eligible")),
    }
}

/// Common structure only; executor eligibility remains local to each caller crate.
pub fn validate_v2_structure(call: &CallV2) -> Result<()> {
    let c = &call.command;
    if call.version != 2
        || c.envelope_version != "2"
        || c.author.version != 1
        || c.author.credential.is_none()
        || c.executor != "records_write"
        || c.source_action.is_some()
        || call.made_at.source != "device_reported"
        || call.made_at.reported_unix_ms < 0
        || c.author.ingress.as_ref().is_none_or(|i| {
            i.source != "cookie"
                || !matches!(
                    i.surface.as_str(),
                    "mcp" | "mcp_database" | "tools" | "database_tools"
                )
        })
        || c.author
            .ingress
            .as_ref()
            .is_none_or(|i| match i.surface.as_str() {
                "mcp" | "mcp_database" => c.author.channel != Channel::Mcp,
                "tools" | "database_tools" => c.author.channel != Channel::Web,
                _ => true,
            })
        || c.resolved_intent_digest != intent_digest(c.intent_text.as_deref())?
        || c.meaning_digest != crate::provenance::action_digest(&c.operation, &c.original_arguments)
    {
        return Err(Error::auth("outbox_v2_evidence_invalid"));
    }
    if c.idempotency_key.trim() != c.idempotency_key || c.idempotency_key.is_empty() {
        return Err(Error::auth("outbox_v2_command_mismatch"));
    }
    for arguments in [&c.original_arguments, &c.prepared_arguments] {
        if arguments.get("run_key").and_then(|v| v.as_str()) != Some(&c.run_key)
            || arguments.get("parent_key").and_then(|v| v.as_str()) != c.parent_key.as_deref()
            || arguments.get("idempotency_key").and_then(|v| v.as_str()) != Some(&c.idempotency_key)
        {
            return Err(Error::auth("outbox_v2_command_mismatch"));
        }
    }
    let mut normalized = c.prepared_arguments.clone();
    if c.operation == "create_record" {
        let id = c.prepared_arguments["id"]
            .as_str()
            .ok_or_else(|| Error::auth("outbox_v2_command_mismatch"))?;
        if c.stable_create_ids != [id] {
            return Err(Error::auth("outbox_v2_command_mismatch"));
        }
        if c.original_arguments.get("id").is_none() {
            normalized
                .as_object_mut()
                .ok_or_else(|| Error::auth("outbox_v2_command_mismatch"))?
                .remove("id");
        }
    } else if !c.stable_create_ids.is_empty() {
        return Err(Error::auth("outbox_v2_command_mismatch"));
    }
    if crate::provenance::action_digest(&c.operation, &normalized) != c.meaning_digest {
        return Err(Error::auth("outbox_v2_command_mismatch"));
    }
    call.app.claim()?;
    Ok(())
}

/// Data validation using Core's own compile-time eligibility profile.
pub fn validate_v2_call(call: &CallV2) -> Result<()> {
    validate_v2_structure(call)?;
    #[cfg(feature = "mcp-executor-prototype")]
    validate_operation(&call.command)?;
    #[cfg(not(feature = "mcp-executor-prototype"))]
    return Err(Error::auth("outbox_v2_executor_unsupported"));
    #[cfg(feature = "mcp-executor-prototype")]
    Ok(())
}
#[derive(Serialize)]
struct DeferredCallV2<'a> {
    purpose: &'static str,
    version: u16,
    window: &'a WindowPublicKey,
    received_seq: i64,
    received_at: i64,
    deadline: i64,
    envelope_digest: &'a str,
    call: &'a CallV2,
}
pub fn v2_message(
    key: &WindowPublicKey,
    call: &CallV2,
    seq: i64,
    at: i64,
    a: &Attestation,
) -> Result<Vec<u8>> {
    let mut bytes = V2_DOMAIN.to_vec();
    bytes.extend(
        serde_jcs::to_vec(&DeferredCallV2 {
            purpose: "hosted-outbox-deferred-call",
            version: 2,
            window: key,
            received_seq: seq,
            received_at: at,
            deadline: a.deadline,
            envelope_digest: &a.envelope_digest,
            call,
        })
        .map_err(|_| Error::auth("outbox_noncanonical_value"))?,
    );
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(Error::auth("outbox_attestation_too_large"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;

/// Journal key reservation DATA. Entry allocation may change on retry; all
/// original command/app/author/time facts remain bound. Not authentication.
pub fn v2_reservation_digest(call: &CallV2) -> Result<String> {
    let mut value = call.clone();
    value.command.entry_id.clear();
    digest(&value)
}

/// STOP binding DATA over the complete original typed call, without new normalization.
pub fn v2_stop_target_digest(origin: &str, call: &CallV2) -> Result<String> {
    digest(&(origin, call))
}
/// Identity DATA only; fresh credential/ingress/channel are deliberately excluded.
pub fn stop_author_identity_digest(a: &Author) -> Result<String> {
    digest(&(
        &a.hosting_user_id,
        &a.account_id,
        &a.person_id,
        &a.principal,
        &a.workspace_id,
        &a.workspace,
        &a.membership,
    ))
}
