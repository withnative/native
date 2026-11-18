//! Dark original-signature INTEGRITY, conditional on a gateway-certified key
//! observation. Not remote attestation, custody, a Caller or cancellation grant.
//! Original bytes are the JCS argument, not an authenticated journal row/ledger.
#![doc(hidden)]
use super::{digest, Scope};
use crate::provenance::deferred_wire as wire;
use crate::{Error, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub const PIN_ENV: &str = "NATIVE_CE_CANCEL_ORIGINAL_PIN";
pub const ROLE: &str = "cancel_original_key_observation_v2";
pub const PURPOSE: &str = "cancel_original_integrity_only";
pub const AUDIENCE: &str = "native-ce:cancel-original-integrity:v2";
const DOMAIN: &[u8] = b"native.held-command.cancel-original.v2\0";
fn unavailable() -> Error {
    Error::auth("cancel_original_unavailable")
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub issuer: String,
    pub key_id: String,
    pub scope: Scope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u16,
    role: String,
    issuer: String,
    key_id: String,
    public_key: String,
    scope: Scope,
}
struct Pin {
    fingerprint: Fingerprint,
    key: VerifyingKey,
}
enum State {
    Disabled,
    Pinned(Box<Pin>),
    Invalid,
}
static STATE: OnceLock<State> = OnceLock::new();
fn load() -> Result<Option<Pin>> {
    let raw = match std::env::var(PIN_ENV) {
        Ok(s) => s,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    if raw.len() > 16 * 1024 {
        return Err(unavailable());
    }
    let c: Config = serde_json::from_str(&raw).map_err(|_| unavailable())?;
    c.scope.validate()?;
    if c.version != 2
        || c.role != ROLE
        || c.issuer.is_empty()
        || c.issuer.len() > 256
        || c.issuer.trim() != c.issuer
        || c.public_key.len() != 64
    {
        return Err(unavailable());
    }
    let bytes: [u8; 32] = hex::decode(&c.public_key)
        .map_err(|_| unavailable())?
        .try_into()
        .map_err(|_| unavailable())?;
    if hex::encode(bytes) != c.public_key || digest(&bytes) != c.key_id {
        return Err(unavailable());
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| unavailable())?;
    // A1 MUST have frozen its state first. Distinct role requires distinct key,
    // even when issuer/scope differ. Neither role can reinterpret the other.
    match super::STATE.get() {
        Some(super::State::Disabled) => {}
        Some(super::State::Pinned(p))
            if p.key.to_bytes() != bytes && p.fingerprint.key_id != c.key_id => {}
        _ => return Err(unavailable()),
    }
    if key.is_weak() {
        return Err(unavailable());
    }
    Ok(Some(Pin {
        fingerprint: Fingerprint {
            issuer: c.issuer,
            key_id: c.key_id,
            scope: c.scope,
        },
        key,
    }))
}
/// Fixed privileged startup only; no supplied key, reset or runtime rotation.
pub fn initialize_from_process() -> Result<()> {
    let state = STATE.get_or_init(|| match load() {
        Ok(None) => State::Disabled,
        Ok(Some(p)) => State::Pinned(Box::new(p)),
        Err(_) => State::Invalid,
    });
    if matches!(state, State::Invalid) {
        Err(unavailable())
    } else {
        Ok(())
    }
}
pub fn fingerprint() -> Result<Option<Fingerprint>> {
    match STATE.get() {
        Some(State::Disabled) => Ok(None),
        Some(State::Pinned(p)) => Ok(Some(p.fingerprint.clone())),
        _ => Err(unavailable()),
    }
}
/// Gateway-observed facts, never an independent release/code attestation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyObservation {
    pub source: String,
    pub observed_at: i64,
    pub epoch: i64,
    pub phase: String,
    pub key: wire::WindowPublicKey,
}
/// Redundant certified binding, independently recomputed from original data.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub original: super::Original,
    pub author: wire::Author,
    pub run_key: String,
    pub parent_key: Option<String>,
    pub stable_create_ids: Vec<String>,
    pub app: wire::HostAppEvidence,
    pub made_at: wire::MadeAt,
    pub command_identity_digest: String,
    pub app_context_digest: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub version: u16,
    pub issuer: String,
    pub key_id: String,
    pub audience: String,
    pub purpose: String,
    pub scope: Scope,
    pub nonce: String,
    pub issued_at: i64,
    pub deadline: i64,
    pub requester: wire::Author,
    pub credential_sha256: String,
    pub key_observation: KeyObservation,
    pub binding: Binding,
    pub original_bytes: String,
    pub original_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub claims: Claims,
    pub signature: String,
}
/// Historical app-context digest DATA only; no current install/authentication.
pub fn app_context_digest(app: &wire::HostAppEvidence) -> Result<String> {
    Ok(super::super::cancellation::app_digest(Some(&app.claim()?)))
}
/// Data-only canonical message builder. No signer or supplied-key verifier.
pub fn signing_message(claims: &Claims) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_jcs::to_vec(claims).map_err(|_| unavailable())?);
    if bytes.len() > super::MAX_BYTES {
        return Err(unavailable());
    }
    Ok(bytes)
}
pub struct OriginalIntegrity {
    digest: String,
}
impl OriginalIntegrity {
    pub fn original_sha256(&self) -> &str {
        &self.digest
    }
}
fn signature(text: &str) -> Result<Signature> {
    if text.len() != 128 {
        return Err(unavailable());
    }
    let bytes = hex::decode(text).map_err(|_| unavailable())?;
    if hex::encode(&bytes) != text {
        return Err(unavailable());
    }
    Signature::from_slice(&bytes).map_err(|_| unavailable())
}
fn fresh(c: &Claims) -> Result<()> {
    let now = chrono::Utc::now().timestamp_millis();
    if c.issued_at < 0
        || c.issued_at > now
        || c.key_observation.observed_at > now
        || c.deadline <= now
        || c.deadline <= c.issued_at
        || c.deadline
            .checked_sub(c.issued_at)
            .is_none_or(|n| n > 30_000)
    {
        return Err(unavailable());
    }
    Ok(())
}
/// No authentication/authority conversion. Replays within the snapshot may yield
/// the same integrity digest; this is not a one-shot cancellation operation.
pub fn inspect_packet(bytes: &[u8]) -> Result<OriginalIntegrity> {
    let c = verified_claims(bytes)?;
    Ok(OriginalIntegrity {
        digest: c.original_sha256,
    })
}
// Private shared verification, not a public conversion from the digest result.
pub(crate) fn verified_claims(bytes: &[u8]) -> Result<Claims> {
    if bytes.len() > super::MAX_BYTES {
        return Err(unavailable());
    }
    let pin = match STATE.get() {
        Some(State::Pinned(p)) => p,
        _ => return Err(unavailable()),
    };
    let packet: Packet = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
    if serde_jcs::to_vec(&packet).map_err(|_| unavailable())? != bytes {
        return Err(unavailable());
    }
    let c = &packet.claims;
    fresh(c)?;
    if c.version != 2
        || c.issuer != pin.fingerprint.issuer
        || c.key_id != pin.fingerprint.key_id
        || c.scope != pin.fingerprint.scope
        || c.purpose != PURPOSE
        || c.audience != AUDIENCE
        || uuid::Uuid::parse_str(&c.nonce).is_err()
        || c.original_bytes.is_empty()
        || c.original_bytes.len() > wire::MAX_WIRE_BYTES
        || digest(c.original_bytes.as_bytes()) != c.original_sha256
    {
        return Err(unavailable());
    }
    pin.key
        .verify_strict(&signing_message(c)?, &signature(&packet.signature)?)
        .map_err(|_| unavailable())?;
    verify_original(c).map_err(|_| unavailable())?;
    fresh(c)?;
    Ok(packet.claims)
}
pub(super) fn enrollment_pin() -> Result<(Fingerprint, [u8; 32])> {
    match STATE.get() {
        Some(State::Pinned(p)) => Ok((p.fingerprint.clone(), p.key.to_bytes())),
        _ => Err(unavailable()),
    }
}
fn verify_original(c: &Claims) -> Result<()> {
    let entry: wire::EntryV2 =
        serde_json::from_str(&c.original_bytes).map_err(|_| unavailable())?;
    if serde_jcs::to_vec(&entry).map_err(|_| unavailable())? != c.original_bytes.as_bytes() {
        return Err(unavailable());
    }
    wire::validate_v2_call(&entry.call)?;
    let call = &entry.call.command;
    let o = &c.key_observation;
    let k = &o.key;
    let a = &entry.attestation;
    if o.source != "authenticated_readonly_control"
        || o.observed_at < c.issued_at
        || o.observed_at >= c.deadline
        || o.epoch <= 0
        || !matches!(o.phase.as_str(), "accepting_frozen" | "draining")
        || !call.depends_on.is_empty()
        || k.window_id != call.window_id
        || wire::digest(&k.public_key)? != k.key_id
        || a.version != 2
        || a.key_id != k.key_id
        || a.envelope_digest != wire::digest(&entry.call)?
        || entry.received_seq <= 0
        || entry.received_at < 0
        || entry.received_at > o.observed_at
    {
        return Err(unavailable());
    }
    let mut original_deadline = entry
        .received_at
        .checked_add(wire::MAX_AGE_MS)
        .ok_or_else(unavailable)?;
    if let Some(wire::CredentialEvidence::OAuth { iat, exp, .. }) = &call.author.credential {
        if *iat < 0 || exp <= iat || iat.checked_mul(1000).is_none_or(|n| n > entry.received_at) {
            return Err(unavailable());
        }
        original_deadline = original_deadline.min(exp.checked_mul(1000).ok_or_else(unavailable)?);
    }
    if a.deadline <= entry.received_at || a.deadline > original_deadline {
        return Err(unavailable());
    }
    let key = VerifyingKey::from_bytes(&k.public_key).map_err(|_| unavailable())?;
    if key.is_weak() {
        return Err(unavailable());
    }
    key.verify_strict(
        &wire::v2_message(k, &entry.call, entry.received_seq, entry.received_at, a)?,
        &signature(&a.signature)?,
    )
    .map_err(|_| unavailable())?;
    // Root constructs its own catalogue from the compiled contracts; none of
    // these expectations can be chosen by the packet, gateway or requester.
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry)?;
    crate::mcp::register_surface_tools(&mut registry)?;
    let catalogue = crate::mcp::executor_prototype::HostedExecutorAdmission::new(
        &registry,
        &crate::mcp::ExperimentalExecutors::empty(),
    )?;
    if catalogue.deferred_contract_identity(&call.executor, &call.operation)
        != Some((&call.contract_version, &call.contract_digest))
    {
        return Err(unavailable());
    }
    let r = &c.requester;
    let mut expected = call.author.clone();
    expected.credential = r.credential.clone();
    expected.ingress = r.ingress.clone();
    expected.channel = r.channel;
    if expected != *r
        || r.version != 1
        || r.workspace_id != c.scope.workspace
        || r.workspace.origin != c.scope.origin
        || call.workspace_id != c.scope.workspace
        || r.membership.generation.is_none_or(|n| n <= 0)
        || r.workspace.activity_epoch < 0
        || r.credential.is_none()
        || c.credential_sha256 != wire::digest(&r.credential)?
    {
        return Err(unavailable());
    }
    match &r.credential {
        Some(wire::CredentialEvidence::OAuth { iat, exp, .. })
            if *iat < 0
                || exp <= iat
                || iat.checked_mul(1000).is_none_or(|n| n > c.issued_at)
                || exp.checked_mul(1000).is_none_or(|n| c.deadline > n) =>
        {
            return Err(unavailable())
        }
        _ => {}
    }
    // Current ingress may differ, but must still be genuine host-cookie ingress
    // in this delegated profile. It cannot renew or alter original app/intent.
    let mut current_call = entry.call.clone();
    current_call.command.author = r.clone();
    wire::validate_v2_structure(&current_call)?;
    let b = &c.binding;
    let original = super::Original {
        window: k.window_id.clone(),
        deployment: k.deployment_id.clone(),
        epoch: o.epoch,
        window_key_id: k.key_id.clone(),
        base_snapshot_digest: k.base_snapshot_digest.clone(),
        entry_id: call.entry_id.clone(),
        received_seq: entry.received_seq,
        received_at: entry.received_at,
        operation: call.operation.clone(),
        idempotency_key: call.idempotency_key.clone(),
        meaning_digest: call.meaning_digest.clone(),
        intent_digest: call.resolved_intent_digest.clone(),
        package: entry.call.app.package.clone(),
        package_version: entry.call.app.package_version.clone(),
        install_event_id: entry.call.app.install_event_id.clone(),
    };
    if b.original != original
        || b.author != call.author
        || b.run_key != call.run_key
        || b.parent_key != call.parent_key
        || b.stable_create_ids != call.stable_create_ids
        || b.app != entry.call.app
        || b.made_at != entry.call.made_at
        || Some(&b.command_identity_digest)
            != super::super::command_identity_digest(&call.prepared_arguments).as_ref()
        || b.app_context_digest
            != super::super::cancellation::app_digest(Some(&entry.call.app.claim()?))
    {
        return Err(unavailable());
    }
    Ok(())
}
#[cfg(test)]
pub(crate) mod tests;
