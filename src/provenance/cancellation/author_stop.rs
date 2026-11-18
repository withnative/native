//! Actual author-STOP authority, private to Core. No portable seal constructor.
use super::*;
use crate::provenance::cancellation_request::{self as request, original, stop as wire};
use ed25519_dalek::{Signature, VerifyingKey};
use std::sync::OnceLock;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u16,
    role: String,
    issuer: String,
    key_id: String,
    public_key: String,
    scope: request::Scope,
}
struct Pin {
    fingerprint: wire::Fingerprint,
    key: VerifyingKey,
}
enum State {
    Disabled,
    Pinned(Box<Pin>),
    Invalid,
}
static STATE: OnceLock<State> = OnceLock::new();
fn unavailable() -> Error {
    Error::auth("held_stop_unavailable")
}
fn load() -> Result<Option<Pin>> {
    let raw = match std::env::var(wire::PIN_ENV) {
        Ok(s) => s,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    if raw.len() > 16 * 1024 {
        return Err(unavailable());
    }
    let c: Config = serde_json::from_str(&raw).map_err(|_| unavailable())?;
    c.scope.validate()?;
    let bytes: [u8; 32] = hex::decode(&c.public_key)
        .map_err(|_| unavailable())?
        .try_into()
        .map_err(|_| unavailable())?;
    if c.version != 1
        || c.role != wire::ROLE
        || c.issuer.is_empty()
        || c.issuer.len() > 256
        || c.issuer.trim() != c.issuer
        || hex::encode(bytes) != c.public_key
        || request::digest(&bytes) != c.key_id
    {
        return Err(unavailable());
    }
    request::validate_stop_enrollment(&bytes, &c.scope)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| unavailable())?;
    if key.is_weak() {
        return Err(unavailable());
    }
    Ok(Some(Pin {
        fingerprint: wire::Fingerprint {
            issuer: c.issuer,
            key_id: c.key_id,
            scope: c.scope,
        },
        key,
    }))
}
pub(crate) fn initialize() -> Result<()> {
    let s = STATE.get_or_init(|| match load() {
        Ok(None) => State::Disabled,
        Ok(Some(p)) => State::Pinned(Box::new(p)),
        Err(_) => State::Invalid,
    });
    if matches!(s, State::Invalid) {
        Err(unavailable())
    } else {
        Ok(())
    }
}
pub(crate) fn fingerprint() -> Result<Option<wire::Fingerprint>> {
    match STATE.get() {
        Some(State::Disabled) => Ok(None),
        Some(State::Pinned(p)) => Ok(Some(p.fingerprint.clone())),
        _ => Err(unavailable()),
    }
}
pub(super) fn fresh(c: &wire::Claims) -> Result<()> {
    let now = chrono::Utc::now().timestamp_millis();
    if c.issued_at < 0
        || c.issued_at > now
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
fn verified(bytes: &[u8]) -> Result<(wire::Claims, crate::provenance::deferred_wire::EntryV2)> {
    let pin = match STATE.get() {
        Some(State::Pinned(p)) => p,
        _ => return Err(unavailable()),
    };
    if bytes.len() > wire::MAX_BYTES {
        return Err(unavailable());
    }
    let p: wire::Packet = serde_json::from_slice(bytes).map_err(|_| unavailable())?;
    if serde_jcs::to_vec(&p)? != bytes {
        return Err(unavailable());
    }
    let c = &p.claims;
    fresh(c)?;
    if c.version != 1
        || c.issuer != pin.fingerprint.issuer
        || c.key_id != pin.fingerprint.key_id
        || c.scope != pin.fingerprint.scope
        || c.purpose != wire::PURPOSE
        || c.audience != wire::AUDIENCE
        || c.target != "canonical_command"
        || Uuid::parse_str(&c.nonce).is_err()
        || c.original_packet.len() > request::MAX_BYTES
        || request::digest(c.original_packet.as_bytes()) != c.original_packet_sha256
    {
        return Err(unavailable());
    }
    let signature_bytes = hex::decode(&p.signature).map_err(|_| unavailable())?;
    if hex::encode(&signature_bytes) != p.signature || p.signature.len() != 128 {
        return Err(unavailable());
    }
    pin.key
        .verify_strict(
            &wire::signing_message(c)?,
            &Signature::from_slice(&signature_bytes).map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
    // A2b remains a separate integrity purpose, not the authorization above.
    let nested = original::verified_claims(c.original_packet.as_bytes())?;
    if c.scope != nested.scope
        || c.requester != nested.requester
        || c.credential_sha256 != nested.credential_sha256
        || nested.issued_at < c.issued_at
        || c.deadline > nested.deadline
    {
        return Err(unavailable());
    }
    let h = &c.holder;
    if h.raw_payload.len() > crate::provenance::deferred_wire::MAX_WIRE_BYTES
        || h.payload_bytes != h.raw_payload.len() as i64
        || request::digest(h.raw_payload.as_bytes()) != h.raw_sha256
        || h.ledger_phase != "waiting"
        || h.revision <= 0
        || !matches!(h.hold.as_str(), "quarantined" | "executor_unqualified")
    {
        return Err(unavailable());
    }
    let entry: crate::provenance::deferred_wire::EntryV2 = serde_json::from_str(&h.raw_payload)?;
    if serde_jcs::to_vec(&entry)? != nested.original_bytes.as_bytes() {
        return Err(unavailable());
    }
    let call = &entry.call.command;
    let o = &nested.binding.original;
    let base: Value = serde_json::from_str(&h.base_snapshot)?;
    if h.entry_id != call.entry_id
        || h.window_id != call.window_id
        || h.workspace_id != call.workspace_id
        || h.principal != call.author.principal
        || h.operation != call.operation
        || h.idempotency_key != call.idempotency_key
        || h.received_seq != entry.received_seq
        || h.reservation_digest
            != crate::provenance::deferred_wire::v2_reservation_digest(&entry.call)?
        || h.deployment_id != o.deployment
        || h.epoch != o.epoch
        || h.window_phase != nested.key_observation.phase
        || h.base_snapshot_digest != o.base_snapshot_digest
        || request::digest(&serde_jcs::to_vec(&base)?) != h.base_snapshot_digest
    {
        return Err(unavailable());
    }
    fresh(c)?;
    Ok((p.claims, entry))
}
// Preliminary verified scope, never a seal/Caller/execution grant.
pub(crate) fn preflight(bytes: &[u8]) -> Result<request::Scope> {
    verified(bytes)
        .map(|(c, _)| c.scope)
        .map_err(|_| unavailable())
}
pub(crate) struct StagedStop {
    pub(crate) decision: StagedCancellation,
    pub(crate) binding: wire::ObservationBinding,
}

/// Verified DATA only, private to cancellation. Never a seal or Caller.
pub(super) struct VerifiedStopData {
    pub(super) claims: wire::Claims,
    pub(super) entry: crate::provenance::deferred_wire::EntryV2,
    pub(super) evidence: CancellationEvidence,
    pub(super) binding: wire::ObservationBinding,
}
pub(super) fn verified_data(bytes: &[u8]) -> Result<VerifiedStopData> {
    let (c, entry) = verified(bytes).map_err(|_| unavailable())?;
    let call = &entry.call.command;
    let evidence = CancellationEvidence {
        origin_db_id: c.scope.origin.clone(),
        principal: call.author.principal.clone(),
        operation: call.operation.clone(),
        command_identity_digest: command_identity_digest(&call.prepared_arguments)
            .ok_or_else(unavailable)?,
        action_digest: action_digest(&call.operation, &call.prepared_arguments),
        intent_digest: call.intent_text.as_ref().map(|t| digest_json(&json!(t))),
        app_context_digest: app_digest(Some(&entry.call.app.claim()?)),
    };
    evidence.validate()?;
    let binding = wire::observation_binding(&c, bytes)?;
    Ok(VerifiedStopData {
        claims: c,
        entry,
        evidence,
        binding,
    })
}
pub(super) async fn check_database(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    c: &wire::Claims,
) -> Result<()> {
    if db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite
        || db.has_enrolled_execution()
        || db.is_enrolled()
        || sqlx::query_scalar::<_, i64>("PRAGMA user_version")
            .fetch_one(&mut **tx)
            .await?
            != 94
        || sqlx::query_scalar::<_, String>(
            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
        )
        .fetch_one(&mut **tx)
        .await?
            != c.scope.origin
    {
        return Err(unavailable());
    }
    Ok(())
}

/// Called only by the registry AFTER its BEGIN IMMEDIATE. Same purpose and
/// original checks repeat here; no current holder lock/ownership is implied.
pub(crate) async fn stage(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    bytes: &[u8],
) -> Result<StagedStop> {
    let VerifiedStopData {
        claims: c,
        evidence,
        binding,
        ..
    } = verified_data(bytes)?;
    check_database(db, tx, &c).await?;
    // Production seal construction is ONLY behind the separate STOP purpose.
    let result = cancel_in(tx, &VerifiedHeldCommand(evidence)).await?;
    #[cfg(test)]
    tests::after_stage().await?;
    // Last authorization freshness decision immediately before returning for
    // COMMIT. Physical fsync completion is not atomically tied to wall time.
    fresh(&c)?;
    let receipt = match &result {
        StagedCancellation::Cancelled { event_id } => event_id,
        StagedCancellation::AlreadySaved { attestation_id } => attestation_id,
    };
    if receipt.is_empty() || receipt.len() > 256 {
        return Err(unavailable());
    }
    Ok(StagedStop {
        decision: result,
        binding,
    })
}

#[cfg(test)]
mod tests;
