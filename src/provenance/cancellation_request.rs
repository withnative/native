//! Dark gateway PACKET INTEGRITY only. No original-command verifier, Caller,
//! cancellation seal, target permission, writer or transaction entry point.
#![doc(hidden)]
use crate::{Error, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const PIN_ENV: &str = "NATIVE_CE_CANCEL_PACKET_PIN";
pub const DOMAIN: &[u8] = b"native.held-command.cancel-packet.v1\0";
pub const PURPOSE: &str = "cancel_packet_integrity_only";
pub const AUDIENCE: &str = "native-ce:cancel-packet-integrity:v1";
pub const MAX_BYTES: usize = 4 * 1024 * 1024;
fn unavailable() -> Error {
    Error::auth("cancel_packet_unavailable")
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Wire facts, not authentication or permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub realm: String,
    pub public_origin: String,
    pub workspace: String,
    pub origin: String,
}
impl Scope {
    pub(crate) fn validate(&self) -> Result<()> {
        if [&self.realm, &self.workspace]
            .iter()
            .any(|s| s.is_empty() || s.len() > 256 || s.trim() != s.as_str())
            || !crate::identity::is_database_id(&self.origin)
            || url::Url::parse(&self.public_origin).ok().is_none_or(|u| {
                !matches!(u.scheme(), "http" | "https")
                    || u.origin().ascii_serialization() != self.public_origin
            })
        {
            return Err(unavailable());
        }
        Ok(())
    }
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
    if c.version != 1
        || c.issuer.is_empty()
        || c.issuer.len() > 256
        || c.issuer.trim() != c.issuer
        || c.public_key.len() != 64
    {
        return Err(unavailable());
    }
    let bytes = hex::decode(&c.public_key).map_err(|_| unavailable())?;
    if hex::encode(&bytes) != c.public_key || digest(&bytes) != c.key_id {
        return Err(unavailable());
    }
    let key = VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| unavailable())?)
        .map_err(|_| unavailable())?;
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
/// Privileged startup only, after the host's authority-lock/candidate checks.
/// No arguments, callbacks, reset, key injection or per-request initialization.
/// Missing config freezes Disabled; invalid config freezes refusal. Restart only.
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requester {
    pub user: String,
    pub principal: String,
    pub account: String,
    pub person: Option<String>,
    pub membership_generation: i64,
    pub activity_epoch: i64,
    pub credential_sha256: String,
    pub created_at: String,
    pub provisioned_at: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Original {
    pub window: String,
    pub deployment: String,
    pub epoch: i64,
    pub window_key_id: String,
    pub base_snapshot_digest: String,
    pub entry_id: String,
    pub received_seq: i64,
    pub received_at: i64,
    pub operation: String,
    pub idempotency_key: String,
    pub meaning_digest: String,
    pub intent_digest: Option<String>,
    pub package: String,
    pub package_version: String,
    pub install_event_id: String,
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
    pub requester: Requester,
    pub original: Original,
    /// JCS re-encoding of a gateway-verified V2 argument, not a journal payload
    /// string/index/ledger proof. Root A1 binds these bytes only; it does
    /// NOT decode/verify the original signature or grant original authority.
    pub original_bytes: String,
    pub original_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub claims: Claims,
    pub signature: String,
}
pub fn signing_message(claims: &Claims) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_jcs::to_vec(claims).map_err(|_| unavailable())?);
    if bytes.len() > MAX_BYTES {
        return Err(unavailable());
    }
    Ok(bytes)
}
/// No conversion into VerifiedHeldCommand, Caller, execution/cancel permission.
/// Only confirms a fresh gateway packet under the immutable configured pin.
pub struct VerifiedPacketIntegrity {
    digest: String,
}
impl VerifiedPacketIntegrity {
    pub fn original_sha256(&self) -> &str {
        &self.digest
    }
}
pub fn inspect_packet(bytes: &[u8]) -> Result<VerifiedPacketIntegrity> {
    if bytes.len() > MAX_BYTES {
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
    let now = chrono::Utc::now().timestamp_millis();
    if c.version != 1
        || c.issuer != pin.fingerprint.issuer
        || c.key_id != pin.fingerprint.key_id
        || c.scope != pin.fingerprint.scope
        || c.audience != AUDIENCE
        || c.purpose != PURPOSE
        || c.issued_at < 0
        || c.issued_at > now
        || c.deadline <= now
        || c.deadline <= c.issued_at
        || c.deadline
            .checked_sub(c.issued_at)
            .is_none_or(|v| v > 30_000)
        || uuid::Uuid::parse_str(&c.nonce).is_err()
        || c.original_sha256 != digest(c.original_bytes.as_bytes())
        || c.original_bytes.len() > 2 * 1024 * 1024
        || c.original_bytes.is_empty()
        || packet.signature.len() != 128
    {
        return Err(unavailable());
    }
    // The remaining signed facts are gateway claims, NOT independently checked
    // original facts or a target permission check. That is a separate A2 gate.
    let sig = hex::decode(&packet.signature).map_err(|_| unavailable())?;
    if hex::encode(&sig) != packet.signature {
        return Err(unavailable());
    }
    pin.key
        .verify_strict(
            &signing_message(c)?,
            &Signature::from_slice(&sig).map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
    Ok(VerifiedPacketIntegrity {
        digest: c.original_sha256.clone(),
    })
}
#[cfg(test)]
mod tests;

/// Successor purpose; independent immutable pin, never an A1 role upgrade.
pub mod original;

/// Distinct author-STOP purpose; old A1/A2b enrollment never promotes to it.
pub mod stop;

pub(crate) fn validate_stop_enrollment(key: &[u8; 32], scope: &Scope) -> Result<()> {
    match STATE.get() {
        Some(State::Disabled) => {}
        Some(State::Pinned(p)) if p.key.to_bytes() != *key => {}
        _ => return Err(unavailable()),
    }
    let (fingerprint, public) = original::enrollment_pin()?;
    if public == *key || fingerprint.scope != *scope {
        return Err(unavailable());
    }
    Ok(())
}
