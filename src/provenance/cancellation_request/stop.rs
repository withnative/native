//! Dark author-STOP wire DATA. Only the registry-owned committed operation
//! verifies authority; these public structs/message bytes grant nothing.
#![doc(hidden)]
use super::Scope;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
pub const ROLE: &str = "held_original_author_stop_v1";
pub const PURPOSE: &str = "held_command_author_stop";
pub const AUDIENCE: &str = "native-ce:held-command-stop:v1";
pub const PIN_ENV: &str = "NATIVE_CE_HELD_STOP_PIN";
pub const SIGNER_ENV: &str = "NATIVE_CE_HELD_STOP_SIGNER";
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
const DOMAIN: &[u8] = b"native.held-command.author-stop.v1\0";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub issuer: String,
    pub key_id: String,
    pub scope: Scope,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HolderBinding {
    pub raw_payload: String,
    pub raw_sha256: String,
    pub payload_bytes: i64,
    pub entry_id: String,
    pub window_id: String,
    pub workspace_id: String,
    pub principal: String,
    pub operation: String,
    pub idempotency_key: String,
    pub reservation_digest: String,
    pub received_seq: i64,
    pub ledger_phase: String,
    pub revision: i64,
    pub hold: String,
    pub deployment_id: String,
    pub epoch: i64,
    pub window_phase: String,
    pub base_snapshot: String,
    pub base_snapshot_digest: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub version: u16,
    pub issuer: String,
    pub key_id: String,
    pub scope: Scope,
    pub purpose: String,
    pub audience: String,
    pub target: String,
    pub nonce: String,
    pub issued_at: i64,
    pub deadline: i64,
    pub requester: crate::provenance::deferred_wire::Author,
    pub credential_sha256: String,
    pub original_packet: String,
    pub original_packet_sha256: String,
    pub holder: HolderBinding,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub claims: Claims,
    pub signature: String,
}
/// Receipt DATA returned only after the registry's canonical COMMIT. It is
/// neither a new authentication capability nor journal settlement authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommittedHeldStop {
    Cancelled { event_id: String },
    AlreadySaved { attestation_id: String },
}
pub fn signing_message(c: &Claims) -> Result<Vec<u8>> {
    let mut out = DOMAIN.to_vec();
    out.extend(serde_jcs::to_vec(c)?);
    if out.len() > MAX_BYTES {
        return Err(Error::auth("held_stop_unavailable"));
    }
    Ok(out)
}
/// Privileged immutable startup, no request-supplied key/config/reset.
pub fn initialize_from_process() -> Result<()> {
    super::super::initialize_held_stop()
}
pub fn fingerprint() -> Result<Option<Fingerprint>> {
    super::super::held_stop_fingerprint()
}

/// Complete attempt/target binding DATA, not a proof or authorization. The
/// target hash covers the existing typed CallV2 (all original args, meaning,
/// nullable intent, author/context/app and audit madeAt), with expected origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationBinding {
    pub entry_id: String,
    pub window_id: String,
    pub workspace_id: String,
    pub origin: String,
    pub principal: String,
    pub operation: String,
    pub idempotency_key: String,
    pub raw_sha256: String,
    pub payload_bytes: i64,
    pub reservation_digest: String,
    pub received_seq: i64,
    pub target_sha256: String,
    pub nonce: String,
    pub packet_sha256: String,
}
/// Pure data extraction only; caller-constructed claims do not establish trust.
pub fn observation_binding(c: &Claims, packet: &[u8]) -> Result<ObservationBinding> {
    let entry: super::super::deferred_wire::EntryV2 = serde_json::from_str(&c.holder.raw_payload)?;
    Ok(ObservationBinding {
        entry_id: c.holder.entry_id.clone(),
        window_id: c.holder.window_id.clone(),
        workspace_id: c.holder.workspace_id.clone(),
        origin: c.scope.origin.clone(),
        principal: c.holder.principal.clone(),
        operation: c.holder.operation.clone(),
        idempotency_key: c.holder.idempotency_key.clone(),
        raw_sha256: c.holder.raw_sha256.clone(),
        payload_bytes: c.holder.payload_bytes,
        reservation_digest: c.holder.reservation_digest.clone(),
        received_seq: c.holder.received_seq,
        target_sha256: super::super::deferred_wire::v2_stop_target_digest(
            &c.scope.origin,
            &entry.call,
        )?,
        nonce: c.nonce.clone(),
        packet_sha256: super::digest(packet),
    })
}
