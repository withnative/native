//! Shared deployment-secret keyring for hosted secrets.
//!
//! Format: JSON `{active_key_id, keys:[{id,key}]}` with 1–16 keys of 32
//! bytes and at most 16 KiB of JSON. Key material is zeroized and the
//! `Debug` impl is redacted. The plan keyring keeps its historic messages
//! byte-for-byte by passing its own context label; the bundle keyring
//! additionally rejects key ids longer than 16 bytes.

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

/// Raw JSON bound shared by every deployment keyring.
pub const KEYRING_MAX_BYTES: usize = 16 * 1024;
/// Retained-key bound shared by every deployment keyring.
pub const KEYRING_MAX_KEYS: usize = 16;
/// Every key decodes to exactly this many bytes.
pub const KEY_BYTES: usize = 32;
/// Plan key ids keep the historic 64-byte bound.
pub const PLAN_MAX_KEY_ID_LEN: usize = 64;
/// Bundle key ids are rejected past 16 bytes.
pub const BUNDLE_MAX_KEY_ID_LEN: usize = 16;

/// Message-only failure; carries shape information, never secret data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringError(String);

impl KeyringError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// Rendered message, safe to surface in startup errors.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for KeyringError {}

/// Strict deployment-secret keyring shared by the plan and bundle secrets.
pub struct DeploymentKeyring {
    active_key_id: String,
    keys: BTreeMap<String, Zeroizing<[u8; KEY_BYTES]>>,
}

impl std::fmt::Debug for DeploymentKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeploymentKeyring([redacted])")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringInput {
    active_key_id: String,
    keys: Vec<KeyInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyInput {
    id: String,
    key: String,
}

impl DeploymentKeyring {
    /// Parse with plan semantics (key ids up to 64 bytes).
    pub fn from_json(raw: &str) -> Result<Self, KeyringError> {
        Self::parse("hosted write plan keyring", raw, PLAN_MAX_KEY_ID_LEN)
    }

    /// Parse with bundle semantics (key ids up to 16 bytes).
    pub fn from_json_bundle(raw: &str) -> Result<Self, KeyringError> {
        Self::parse("app bundle keyring", raw, BUNDLE_MAX_KEY_ID_LEN)
    }

    /// Parse with an explicit key-id byte bound. Both constructors above
    /// are thin covers over this; exposed so future keyrings can reuse the
    /// shape without forking the parser.
    pub fn from_json_with_max_id_len(
        raw: &str,
        context: &str,
        max_id_len: usize,
    ) -> Result<Self, KeyringError> {
        Self::parse(context, raw, max_id_len)
    }

    fn parse(context: &str, raw: &str, max_id_len: usize) -> Result<Self, KeyringError> {
        if raw.len() > KEYRING_MAX_BYTES {
            return Err(KeyringError::new(format!(
                "{context} exceeds the 16 KiB limit"
            )));
        }
        let mut input: KeyringInput = serde_json::from_str(raw)
            .map_err(|_| KeyringError::new(format!("{context} is invalid JSON or shape")))?;
        if input.keys.is_empty() || input.keys.len() > KEYRING_MAX_KEYS {
            return Err(KeyringError::new(format!(
                "{context} must contain 1-16 keys"
            )));
        }
        // The historic plan message names the id rule without the
        // "keyring" word ("hosted write plan key ids ..."); every other
        // message keeps the full context. Derive the short form so both
        // stay byte-identical without a second label at every call site.
        let id_context = context.strip_suffix(" keyring").unwrap_or(context);
        validate_key_id(id_context, &input.active_key_id, max_id_len)?;
        let mut keys = BTreeMap::new();
        for mut entry in input.keys.drain(..) {
            validate_key_id(id_context, &entry.id, max_id_len)?;
            // Capture first, wipe, then propagate: a decode failure must
            // not return while the encoded secret is still unwiped.
            let decoded = base64::engine::general_purpose::STANDARD.decode(entry.key.as_bytes());
            entry.key.zeroize();
            let mut decoded = decoded
                .map_err(|_| KeyringError::new(format!("{context} contains an invalid key")))?;
            if decoded.len() != KEY_BYTES {
                decoded.zeroize();
                return Err(KeyringError::new(format!(
                    "{context} keys must decode to exactly 32 bytes"
                )));
            }
            let mut secret = [0_u8; KEY_BYTES];
            secret.copy_from_slice(&decoded);
            decoded.zeroize();
            if keys.insert(entry.id, Zeroizing::new(secret)).is_some() {
                return Err(KeyringError::new(format!(
                    "{context} contains a duplicate key id"
                )));
            }
        }
        if !keys.contains_key(&input.active_key_id) {
            return Err(KeyringError::new(format!(
                "{context} active key id is not retained"
            )));
        }
        Ok(Self {
            active_key_id: input.active_key_id,
            keys,
        })
    }

    /// Active key id; safe to log (an identifier, not key material).
    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    /// Number of retained keys (1–16 by construction).
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// True when `id` is retained (identifier check only).
    pub fn contains(&self, id: &str) -> bool {
        self.keys.contains_key(id)
    }

    /// Cloned copy of one retained secret. The caller owns the copy and
    /// its zeroization on drop.
    pub fn secret(&self, id: &str) -> Option<Zeroizing<[u8; KEY_BYTES]>> {
        self.keys.get(id).cloned()
    }

    /// Cloned copy of the active secret.
    pub fn active_secret(&self) -> Option<Zeroizing<[u8; KEY_BYTES]>> {
        self.secret(&self.active_key_id.clone())
    }
}

fn validate_key_id(context: &str, id: &str, max_id_len: usize) -> Result<(), KeyringError> {
    if id.is_empty()
        || id.len() > max_id_len
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(KeyringError::new(format!(
            "{context} key ids must be 1-{max_id_len} safe ASCII characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Memory wiping itself is not observable from safe Rust; this pins the
    // decode-failure branch the wipe guards, including its shape-only
    // message (no secret bytes leak into the error).
    #[test]
    fn invalid_base64_key_is_refused_without_leaking() {
        let raw = serde_json::json!({
            "active_key_id": "k1",
            "keys": [{"id": "k1", "key": "!!!not-base64!!!"}],
        })
        .to_string();
        let error = DeploymentKeyring::from_json(&raw).unwrap_err();
        assert_eq!(
            error.message(),
            "hosted write plan keyring contains an invalid key"
        );
        assert!(!error.message().contains("not-base64"));
    }
}
