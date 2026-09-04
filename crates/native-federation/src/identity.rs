//! Account-scoped federation identity custody and Cloud-eject continuity.
//!
//! This submodule complements the standalone relay transport. The relay
//! validates and stores already-encrypted envelopes; custody owns principal
//! keys, lifecycle transitions, and the client-side encryption profile gate.
//!
//! Content databases deliberately do not contain this state. A federation
//! principal belongs to an authenticated host account and its private keys are
//! individually wrapped in an owner-only vault. The public types in this
//! module contain JWKs and lifecycle evidence only; raw private bytes are
//! confined to short-lived, zeroized buffers inside the custody boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use age::secrecy::{ExposeSecret, SecretString};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

pub const FEDERATION_PROFILE: &str = super::crypto::PROFILE;
pub const CUSTODY_WRAPPER: &str = "xchacha20poly1305-v1";
pub const EJECT_PACKAGE_VERSION: u32 = 1;
pub const CUSTODY_KEY_ENV: &str = "NATIVE_FEDERATION_CUSTODY_KEY";
pub const CUSTODY_DIR_ENV: &str = "NATIVE_FEDERATION_CUSTODY_DIR";
const VAULT_VERSION: u32 = 1;
const IDENTITY_BUNDLE_VERSION: u32 = 1;
const EJECT_MAGIC: &[u8; 16] = b"NATIVE-EJECT\0\0\0\x01";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_IDENTITY_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENVELOPE_LIFETIME_DAYS: i64 = 30;
const STORE_SENTINEL: &str = "custody.initialized";
const STORE_SENTINEL_VERSION: &str = "native-federation-custody-store-v1";
const VAULT_INTEGRITY_PREFIX: &str = "hmac-sha-256:";

/// Current UTC time in the engine's canonical millisecond timestamp shape.
fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Explicit lifecycle of one account-scoped principal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalState {
    Unprovisioned,
    Active,
    RotationPending,
    PendingHandoff,
    Retired,
    Revoked,
    Corrupt,
}

/// A private key's single permitted job.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    Root,
    Signing,
    Encryption,
    Installation,
}

impl KeyPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Signing => "signing",
            Self::Encryption => "encryption",
            Self::Installation => "installation",
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
    DecryptOnly,
}

/// Public OKP JWK. It intentionally has no private `d` member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyRecord {
    pub purpose: KeyPurpose,
    pub jwk: PublicJwk,
    pub status: KeyStatus,
    pub not_before: String,
    pub not_after: Option<String>,
    pub installation_id: Option<String>,
    pub endpoint_origin: Option<String>,
}

/// Secret-free lifecycle evidence suitable for control-plane inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederationAuditEvent {
    pub event_id: String,
    pub principal_id: String,
    pub event_type: String,
    pub affected_kids: Vec<String>,
    pub document_version: u64,
    pub document_digest: Option<String>,
    pub handoff_id: Option<String>,
    pub actor: String,
    pub reason: String,
    pub result: String,
    pub occurred_at: String,
}

/// Everything an ordinary inspection path may reveal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederationPrincipal {
    pub account_id: String,
    pub network_id: String,
    pub principal_id: String,
    pub state: PrincipalState,
    pub document_version: u64,
    pub keys: Vec<PublicKeyRecord>,
    pub pending_handoff_id: Option<String>,
}

#[derive(Clone)]
pub struct CustodyMasterKey(Arc<Zeroizing<[u8; 32]>>);

impl fmt::Debug for CustodyMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CustodyMasterKey([REDACTED])")
    }
}

impl CustodyMasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Arc::new(Zeroizing::new(bytes)))
    }

    /// Decode an operator-provided, base64url-no-pad 32-byte wrapping key.
    pub fn from_base64url(value: &str) -> Result<Self> {
        let mut decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| Error::engine("federation custody wrapping key is not base64url"))?;
        if decoded.len() != 32 {
            decoded.zeroize();
            return Err(Error::engine(
                "federation custody wrapping key must contain exactly 32 bytes",
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        decoded.zeroize();
        Ok(Self::from_bytes(bytes))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct WrappedSecret {
    wrapper: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredKey {
    public: PublicKeyRecord,
    wrapped: WrappedSecret,
    generation: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingHandoff {
    handoff_id: String,
    expected_document_version: u64,
    source_installation_id: String,
    old_root_kid: String,
    new_root_kid: String,
    transition: RootTransition,
    old_key_kids: Vec<String>,
    decrypt_only_until: String,
    projected_principal_document: Value,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    account_id: String,
    network_id: String,
    principal_id: String,
    state: PrincipalState,
    document_version: u64,
    keys: Vec<StoredKey>,
    #[serde(default)]
    historical_keys: Vec<PublicKeyRecord>,
    pending: Option<PendingHandoff>,
    #[serde(default)]
    public_history: Vec<Value>,
    #[serde(default)]
    last_attestation: Option<DirectoryAttestation>,
    audit: Vec<FederationAuditEvent>,
    integrity: String,
}

/// Outcome of an installation endpoint re-stamp. Every refusal is a reportable
/// state rather than a failure, so a fleet sweep can distinguish an account
/// that is already correct from one it deliberately left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointUpdate {
    /// The stored origin was drifted and has been re-stamped.
    Updated,
    /// The stored origin already matched. No write happened.
    AlreadyCurrent,
    /// A rotation or handoff owns the key set. Re-stamping would write through
    /// an in-flight transition, so a later sweep should pick this account up.
    NotActive,
    /// An eject package is still awaiting source retirement. Bumping the
    /// document version inside that window would permanently strand the
    /// source, so the origin stays stale until the handoff resolves.
    AwaitingSourceRetirement,
    /// No active installation key for the configured installation id.
    NoInstallationKey,
    /// The account has never had custody. There is nothing to re-stamp, and
    /// provisioning will record the configured origin when it happens.
    Unprovisioned,
}

impl EndpointUpdate {
    /// Whether custody was written.
    pub fn changed(self) -> bool {
        self == EndpointUpdate::Updated
    }

    /// Operator-facing reason this account was left alone, if it was.
    pub fn skipped_reason(self) -> Option<&'static str> {
        match self {
            // Nothing is wrong with either of these, so neither counts as a
            // fleet left partly reconciled.
            EndpointUpdate::Updated
            | EndpointUpdate::AlreadyCurrent
            | EndpointUpdate::Unprovisioned => None,
            EndpointUpdate::NotActive => Some("principal is not active"),
            EndpointUpdate::AwaitingSourceRetirement => {
                Some("eject package awaits source retirement")
            }
            EndpointUpdate::NoInstallationKey => {
                Some("no active key for the configured installation")
            }
        }
    }
}

/// Owner-only filesystem custody used by self-hosted/stdio deployments and as
/// the local implementation seam for a platform-secret-backed Cloud volume.
#[derive(Clone)]
pub struct FileFederationCustody {
    root: Arc<PathBuf>,
    master_key: CustodyMasterKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyMode {
    Cloud,
    SelfHosted,
    Stdio,
}

impl fmt::Debug for FileFederationCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileFederationCustody")
            .field("root", &self.root)
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

impl FileFederationCustody {
    /// Resolve the deployment contract. Cloud/self-host custody lives beside
    /// the host control plane; stdio must name an owner-controlled location so
    /// the current working directory can never become accidental custody.
    pub fn from_environment(data_dir: &Path, mode: CustodyMode) -> Result<Self> {
        let encoded = std::env::var(CUSTODY_KEY_ENV).map_err(|_| {
            Error::engine(format!(
                "federation is disabled: {CUSTODY_KEY_ENV} is required"
            ))
        })?;
        let key = CustodyMasterKey::from_base64url(&encoded)?;
        let root = match mode {
            CustodyMode::Cloud => data_dir.join("federation-custody/cloud"),
            CustodyMode::SelfHosted => std::env::var_os(CUSTODY_DIR_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|| data_dir.join("federation-custody/self-hosted")),
            CustodyMode::Stdio => std::env::var_os(CUSTODY_DIR_ENV)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| {
                    Error::engine(format!(
                        "federation is disabled in stdio mode: {CUSTODY_DIR_ENV} is required"
                    ))
                })?,
        };
        Self::open(root, key)
    }

    /// Explicitly bootstrap a brand-new custody store. Ordinary startup must
    /// use [`Self::open`]; only an operator-controlled initialization path may
    /// create the durable store sentinel after total storage loss.
    pub fn initialize(root: impl Into<PathBuf>, master_key: CustodyMasterKey) -> Result<Self> {
        let root = std::path::absolute(root.into())?;
        match std::fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(Error::engine(
                    "federation custody root must be a real owner-controlled directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&root)?;
            }
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(&root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::engine(
                "federation custody root must be a real owner-controlled directory",
            ));
        }
        let root = std::fs::canonicalize(root)?;
        set_owner_only(&root, true)?;
        let sentinel = root.join(STORE_SENTINEL);
        if sentinel.exists() {
            return Self::open(root, master_key);
        }
        if std::fs::read_dir(&root)?.next().is_some() {
            return Err(Error::engine(
                "refusing to initialize a non-empty custody root without its sentinel",
            ));
        }
        let principals = root.join("principals");
        std::fs::create_dir_all(&principals)?;
        set_owner_only(&principals, true)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&sentinel)?;
        set_owner_only_file(&file)?;
        file.write_all(store_sentinel_value(&master_key).as_bytes())?;
        file.sync_all()?;
        sync_parent(&sentinel)?;
        Self::open(root, master_key)
    }

    /// Open an already initialized custody store. Missing roots, principal
    /// directories, or sentinels fail closed and are never recreated here.
    pub fn open(root: impl Into<PathBuf>, master_key: CustodyMasterKey) -> Result<Self> {
        let root = std::path::absolute(root.into())?;
        let metadata = std::fs::symlink_metadata(&root).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::engine(
                    "federation custody store is not initialized; explicit bootstrap is required",
                )
            } else {
                error.into()
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::engine(
                "federation custody root must be a real owner-controlled directory",
            ));
        }
        let root = std::fs::canonicalize(root)?;
        set_owner_only(&root, true)?;
        let sentinel = root.join(STORE_SENTINEL);
        let sentinel_metadata = std::fs::symlink_metadata(&sentinel).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::engine(
                    "federation custody sentinel is missing; refusing implicit reinitialization",
                )
            } else {
                error.into()
            }
        })?;
        if sentinel_metadata.file_type().is_symlink() || !sentinel_metadata.is_file() {
            return Err(Error::engine("federation custody sentinel is corrupt"));
        }
        let expected = store_sentinel_value(&master_key);
        if std::fs::read_to_string(&sentinel)? != expected {
            return Err(Error::engine(
                "federation custody sentinel authentication failed",
            ));
        }
        let principals = root.join("principals");
        let metadata = std::fs::symlink_metadata(&principals).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::engine("federation principals custody directory is missing")
            } else {
                error.into()
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::engine(
                "federation principals custody path must be a real directory",
            ));
        }
        set_owner_only(&principals, true)?;
        Ok(Self {
            root: Arc::new(root),
            master_key,
        })
    }

    pub fn inspect(&self, account_id: &str) -> FederationPrincipal {
        let _guard = match self.lock() {
            Ok(guard) => guard,
            Err(_) => return corrupt_view(account_id),
        };
        match self.read_vault(account_id) {
            Ok(Some(vault)) => self
                .validate_vault_for_account(vault, account_id)
                .map(|vault| public_view(&vault))
                .unwrap_or_else(|_| corrupt_view(account_id)),
            Ok(None) => match self.has_marker(account_id) {
                Ok(true) | Err(_) => corrupt_view(account_id),
                Ok(false) => FederationPrincipal {
                    account_id: account_id.to_owned(),
                    network_id: String::new(),
                    principal_id: String::new(),
                    state: PrincipalState::Unprovisioned,
                    document_version: 0,
                    keys: vec![],
                    pending_handoff_id: None,
                },
            },
            Err(_) => corrupt_view(account_id),
        }
    }

    /// Provision once, or return the already-provisioned principal. The
    /// process-wide file lock plus create/rename fence also serializes separate
    /// server processes sharing one volume.
    pub fn provision(
        &self,
        account_id: &str,
        network_id: &str,
        installation_id: &str,
        endpoint_origin: &str,
        actor: &str,
        now: &str,
    ) -> Result<FederationPrincipal> {
        validate_nonempty(account_id, "account id")?;
        validate_nonempty(network_id, "network id")?;
        validate_uuid(installation_id, "installation id")?;
        validate_origin(endpoint_origin)?;
        parse_time(now, "provisioning time")?;
        let _guard = self.lock()?;
        if let Some(vault) = self.read_vault(account_id)? {
            let vault = self.validate_vault_for_account(vault, account_id)?;
            if vault.network_id != network_id {
                return Err(Error::engine(
                    "federation account is already provisioned for another network",
                ));
            }
            self.ensure_marker(account_id)?;
            return Ok(public_view(&vault));
        }
        if self.has_marker(account_id)? {
            return Err(Error::engine(
                "federation custody vault is missing for a known account; state is corrupt",
            ));
        }

        // The marker is the fail-closed memory that this account had custody.
        // It is durable before key creation, so deleting or losing the vault
        // can never look like first provisioning and mint another principal.
        self.ensure_marker(account_id)?;
        // Base64url itself permits `-` and `_` at either edge, while the
        // federation principal grammar deliberately requires alphanumeric
        // edges. The fixed prefix/suffix keep every custody-generated id
        // valid without rejection sampling or reducing the random payload.
        let principal_id = format!("p{}p", random_b64(16));
        let mut keys = Vec::with_capacity(4);
        for purpose in [
            KeyPurpose::Root,
            KeyPurpose::Signing,
            KeyPurpose::Encryption,
            KeyPurpose::Installation,
        ] {
            keys.push(self.generate_stored_key(
                account_id,
                network_id,
                &principal_id,
                purpose,
                1,
                now,
                (purpose == KeyPurpose::Installation).then_some(installation_id),
                (purpose == KeyPurpose::Installation).then_some(endpoint_origin),
            )?);
        }
        let kids = keys.iter().map(|key| key.public.jwk.kid.clone()).collect();
        let mut vault = VaultFile {
            version: VAULT_VERSION,
            account_id: account_id.to_owned(),
            network_id: network_id.to_owned(),
            principal_id,
            state: PrincipalState::Active,
            document_version: 1,
            keys,
            historical_keys: vec![],
            pending: None,
            public_history: vec![],
            last_attestation: None,
            audit: vec![],
            integrity: String::new(),
        };
        push_audit(
            &mut vault,
            "principal.provisioned",
            kids,
            None,
            actor,
            "first federation provisioning",
            "succeeded",
            now,
        );
        self.write_vault(&vault)?;
        Ok(public_view(&vault))
    }

    /// Provision hosted account custody using the engine's canonical audit
    /// clock.
    #[doc(hidden)]
    pub fn provision_hosted_account(
        &self,
        account_id: &str,
        network_id: &str,
        installation_id: &str,
        endpoint_origin: &str,
        actor: &str,
    ) -> Result<FederationPrincipal> {
        self.provision(
            account_id,
            network_id,
            installation_id,
            endpoint_origin,
            actor,
            &now_iso(),
        )
    }

    /// Re-stamp the active installation key's endpoint origin after the
    /// deployment's public address changes.
    ///
    /// The endpoint origin is a mutable deployment attribute, not part of
    /// principal identity: a hostname cutover moves where peers reach this
    /// installation without changing which installation holds the account's
    /// keys. Nothing about the key material moves, so this bumps the document
    /// version and lets the next principal document re-sign the new origin
    /// rather than rotating anything.
    ///
    /// Idempotent, and refusals are reported rather than raised: a caller
    /// sweeping a fleet needs to tell "already correct" from "deliberately not
    /// attempted" without matching on error strings. Malformed arguments and
    /// corrupt custody are still errors.
    pub fn update_installation_endpoint(
        &self,
        account_id: &str,
        installation_id: &str,
        endpoint_origin: &str,
        actor: &str,
        now: &str,
        dry_run: bool,
    ) -> Result<EndpointUpdate> {
        validate_nonempty(account_id, "account id")?;
        validate_uuid(installation_id, "installation id")?;
        validate_origin(endpoint_origin)?;
        parse_time(now, "endpoint update time")?;
        let _guard = self.lock()?;
        // An account that has never had custody has no origin to re-stamp.
        // That is an ordinary state during a fleet sweep, not a failure: the
        // sweep provisions it separately, stamping the configured origin. A
        // vault that is missing behind a marker is still corrupt.
        let mut vault = match self.read_vault(account_id)? {
            Some(vault) => self.validate_vault_for_account(vault, account_id)?,
            None if self.has_marker(account_id)? => {
                return Err(Error::engine(
                    "federation custody vault is missing; state is corrupt",
                ))
            }
            None => return Ok(EndpointUpdate::Unprovisioned),
        };
        // An in-flight rotation or handoff owns the vault's key set. Callers
        // tolerate origin drift in those states instead of writing through
        // them; the next active-state connect re-stamps.
        if vault.state != PrincipalState::Active {
            return Ok(EndpointUpdate::NotActive);
        }
        // `create_eject_package` pins the source's exact document version and
        // leaves the vault Active; `retire_source_after_handoff` then requires
        // the attested version to be exactly one ahead. Bumping the version
        // inside that window would strand the source Active forever, with two
        // installations holding custody for one principal. Refuse instead.
        let mut open_handoffs = BTreeSet::new();
        for event in &vault.audit {
            match (event.event_type.as_str(), event.handoff_id.as_deref()) {
                ("handoff.package_created", Some(handoff)) => {
                    open_handoffs.insert(handoff);
                }
                ("handoff.source_retired", Some(handoff)) => {
                    open_handoffs.remove(handoff);
                }
                _ => {}
            }
        }
        if !open_handoffs.is_empty() {
            return Ok(EndpointUpdate::AwaitingSourceRetirement);
        }
        let index = vault.keys.iter().position(|key| {
            key.public.purpose == KeyPurpose::Installation
                && key.public.status == KeyStatus::Active
                && key.public.installation_id.as_deref() == Some(installation_id)
        });
        let Some(index) = index else {
            return Ok(EndpointUpdate::NoInstallationKey);
        };
        let previous = vault.keys[index].public.endpoint_origin.clone();
        if previous.as_deref() == Some(endpoint_origin) {
            return Ok(EndpointUpdate::AlreadyCurrent);
        }
        // Classification is shared with the dry run so the two can never
        // disagree, and the dry run returns before the single write below.
        if dry_run {
            return Ok(EndpointUpdate::Updated);
        }
        vault.keys[index].public.endpoint_origin = Some(endpoint_origin.to_owned());
        let kid = vault.keys[index].public.jwk.kid.clone();
        vault.document_version += 1;
        push_audit(
            &mut vault,
            "installation.endpoint_updated",
            vec![kid],
            None,
            actor,
            &format!(
                "endpoint origin changed from {} to {endpoint_origin}",
                previous.as_deref().unwrap_or("(unset)")
            ),
            "succeeded",
            now,
        );
        self.write_vault(&vault)?;
        Ok(EndpointUpdate::Updated)
    }

    /// Re-stamp hosted installation custody using the engine's canonical
    /// audit clock.
    #[doc(hidden)]
    pub fn update_hosted_installation_endpoint(
        &self,
        account_id: &str,
        installation_id: &str,
        endpoint_origin: &str,
        actor: &str,
        dry_run: bool,
    ) -> Result<EndpointUpdate> {
        self.update_installation_endpoint(
            account_id,
            installation_id,
            endpoint_origin,
            actor,
            &now_iso(),
            dry_run,
        )
    }

    pub fn sign_detached(
        &self,
        account_id: &str,
        purpose: KeyPurpose,
        typ: &str,
        payload: &Value,
    ) -> Result<String> {
        validate_signing_policy(purpose, typ)?;
        let _guard = self.lock()?;
        let vault = self.load_valid(account_id)?;
        if !matches!(
            vault.state,
            PrincipalState::Active | PrincipalState::RotationPending
        ) {
            return Err(Error::engine(format!(
                "federation signing disabled while principal is {:?}",
                vault.state
            )));
        }
        let key = unique_newest_active_key(&vault, purpose)?;
        let secret = self.unwrap_key(&vault, key)?;
        detached_jws_with_secret(&key.public.jwk, typ, payload, &secret)
    }

    pub fn begin_rotation(
        &self,
        account_id: &str,
        purpose: KeyPurpose,
        actor: &str,
        reason: &str,
        now: &str,
    ) -> Result<FederationPrincipal> {
        parse_time(now, "rotation time")?;
        if purpose == KeyPurpose::Root {
            return Err(Error::engine(
                "root rotation requires a dual-signed guarded transition",
            ));
        }
        let _guard = self.lock()?;
        let mut vault = self.load_valid(account_id)?;
        if vault.state != PrincipalState::Active {
            return Err(Error::engine("principal is not active for rotation"));
        }
        let old = unique_active_key(&vault, purpose)?;
        let generation = old.generation + 1;
        let installation_id = old.public.installation_id.clone();
        let endpoint_origin = old.public.endpoint_origin.clone();
        let new_key = self.generate_stored_key(
            &vault.account_id,
            &vault.network_id,
            &vault.principal_id,
            purpose,
            generation,
            now,
            installation_id.as_deref(),
            endpoint_origin.as_deref(),
        )?;
        let kid = new_key.public.jwk.kid.clone();
        vault.keys.push(new_key);
        vault.state = PrincipalState::RotationPending;
        vault.document_version += 1;
        push_audit(
            &mut vault,
            "key.rotation_started",
            vec![kid],
            None,
            actor,
            reason,
            "succeeded",
            now,
        );
        self.write_vault(&vault)?;
        Ok(public_view(&vault))
    }

    pub fn finish_rotation(
        &self,
        account_id: &str,
        purpose: KeyPurpose,
        actor: &str,
        reason: &str,
        now: &str,
    ) -> Result<FederationPrincipal> {
        let rotation_time = parse_time(now, "rotation time")?;
        let _guard = self.lock()?;
        let mut vault = self.load_valid(account_id)?;
        if vault.state != PrincipalState::RotationPending {
            return Err(Error::engine("principal has no rotation pending"));
        }
        let newest_generation = vault
            .keys
            .iter()
            .filter(|key| key.public.purpose == purpose && key.public.status == KeyStatus::Active)
            .map(|key| key.generation)
            .max()
            .ok_or_else(|| Error::engine("rotation has no active replacement key"))?;
        let mut affected = vec![];
        let mut retained = Vec::with_capacity(vault.keys.len());
        for mut key in vault.keys.drain(..) {
            if key.public.purpose == purpose
                && key.public.status == KeyStatus::Active
                && key.generation < newest_generation
            {
                affected.push(key.public.jwk.kid.clone());
                if purpose == KeyPurpose::Encryption {
                    key.public.status = KeyStatus::DecryptOnly;
                    key.public.not_after = Some(
                        (rotation_time + Duration::days(MAX_ENVELOPE_LIFETIME_DAYS))
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    );
                    retained.push(key);
                } else {
                    key.public.status = KeyStatus::Retired;
                    key.public.not_after = Some(now.to_owned());
                    vault.historical_keys.push(key.public);
                }
            } else {
                retained.push(key);
            }
        }
        vault.keys = retained;
        if affected.is_empty() {
            return Err(Error::engine("rotation is missing its former active key"));
        }
        affected.push(
            unique_newest_active_key(&vault, purpose)?
                .public
                .jwk
                .kid
                .clone(),
        );
        vault.state = PrincipalState::Active;
        vault.document_version += 1;
        push_audit(
            &mut vault,
            "key.rotation_committed",
            affected,
            None,
            actor,
            reason,
            "succeeded",
            now,
        );
        self.write_vault(&vault)?;
        Ok(public_view(&vault))
    }

    pub fn revoke_key(
        &self,
        account_id: &str,
        kid: &str,
        actor: &str,
        reason: &str,
        now: &str,
    ) -> Result<FederationPrincipal> {
        parse_time(now, "revocation time")?;
        if !["compromised", "cessation", "authorization_withdrawn"].contains(&reason) {
            return Err(Error::engine("federation revocation reason is invalid"));
        }
        let _guard = self.lock()?;
        let mut vault = self.load_valid(account_id)?;
        if !matches!(
            vault.state,
            PrincipalState::Active | PrincipalState::RotationPending
        ) {
            return Err(Error::engine(
                "only an active or rotating principal may revoke a key",
            ));
        }
        if !vault.keys.iter().any(|key| key.public.jwk.kid == kid) {
            return Err(Error::engine("unknown federation key id"));
        }
        let mut affected = Vec::with_capacity(vault.keys.len());
        for mut key in vault.keys.drain(..) {
            affected.push(key.public.jwk.kid.clone());
            key.public.status = if key.public.jwk.kid == kid {
                KeyStatus::Revoked
            } else {
                KeyStatus::Retired
            };
            key.public.not_after = Some(now.to_owned());
            vault.historical_keys.push(key.public);
        }
        vault.state = PrincipalState::Revoked;
        vault.pending = None;
        vault.document_version += 1;
        push_audit(
            &mut vault,
            "key.revoked",
            affected,
            None,
            actor,
            reason,
            "succeeded",
            now,
        );
        self.write_vault(&vault)?;
        Ok(public_view(&vault))
    }

    pub fn principal_document(&self, account_id: &str, issued_at: &str) -> Result<Value> {
        let issued = parse_time(issued_at, "principal document issuance time")?;
        let _guard = self.lock()?;
        let vault = self.load_valid(account_id)?;
        if vault.state != PrincipalState::Active && vault.state != PrincipalState::RotationPending {
            return Err(Error::engine(
                "principal document is unavailable in this lifecycle state",
            ));
        }
        build_signed_principal_document(self, &vault, issued)
    }

    pub fn audit_events(&self, account_id: &str) -> Result<Vec<FederationAuditEvent>> {
        let _guard = self.lock()?;
        Ok(self.load_valid(account_id)?.audit)
    }

    /// Retire the exporting source only after the authority has attested the
    /// matching handoff. This is a separate callback because Cloud and the new
    /// self-host normally use different custody providers.
    pub async fn retire_source_after_handoff(
        &self,
        account_id: &str,
        evidence: &DirectoryAttestation,
        directory: &dyn FederationDirectory,
        actor: &str,
        now: &str,
    ) -> Result<FederationPrincipal> {
        validate_uuid(&evidence.handoff_id, "handoff id")?;
        validate_sha256_digest(&evidence.document_digest, "directory document digest")?;
        parse_time(now, "source retirement time")?;
        directory.verify_attestation(evidence).await?;
        let _guard = self.lock()?;
        let mut vault = self.load_valid(account_id)?;
        if vault.state == PrincipalState::Retired {
            return Ok(public_view(&vault));
        }
        if vault.state != PrincipalState::Active
            || !vault.audit.iter().any(|event| {
                event.event_type == "handoff.package_created"
                    && event.handoff_id.as_deref() == Some(evidence.handoff_id.as_str())
            })
            || evidence.document_version != vault.document_version + 1
        {
            return Err(Error::engine(
                "source retirement does not match an authority-attested eject handoff",
            ));
        }
        let mut affected = vec![];
        for mut key in vault.keys.drain(..) {
            key.public.status = KeyStatus::Retired;
            key.public.not_after = Some(now.to_owned());
            affected.push(key.public.jwk.kid.clone());
            vault.historical_keys.push(key.public);
        }
        vault.state = PrincipalState::Retired;
        vault.document_version = evidence.document_version;
        vault.last_attestation = Some(evidence.clone());
        push_audit(
            &mut vault,
            "handoff.source_retired",
            affected,
            Some(evidence.handoff_id.clone()),
            actor,
            "authority attested destination and retired source installation",
            "succeeded",
            now,
        );
        if let Some(event) = vault.audit.last_mut() {
            event.document_digest = Some(evidence.document_digest.clone());
        }
        self.write_vault(&vault)?;
        Ok(public_view(&vault))
    }

    /// Erase imported decrypt-only material after the bounded envelope window.
    pub fn erase_expired_decrypt_only(
        &self,
        account_id: &str,
        actor: &str,
        now: &str,
    ) -> Result<FederationPrincipal> {
        let now_time = parse_time(now, "decrypt-only cleanup time")?;
        let _guard = self.lock()?;
        let mut vault = self.load_valid(account_id)?;
        let erased = vault
            .keys
            .iter()
            .filter(|key| {
                key.public.status == KeyStatus::DecryptOnly
                    && key
                        .public
                        .not_after
                        .as_deref()
                        .and_then(|value| parse_time(value, "decrypt-only expiry").ok())
                        .is_some_and(|expiry| now_time >= expiry)
            })
            .map(|key| key.public.jwk.kid.clone())
            .collect::<BTreeSet<_>>();
        let mut retained = Vec::with_capacity(vault.keys.len());
        for mut key in vault.keys.drain(..) {
            if erased.contains(&key.public.jwk.kid) {
                key.public.status = KeyStatus::Retired;
                vault.historical_keys.push(key.public);
            } else {
                retained.push(key);
            }
        }
        vault.keys = retained;
        if !erased.is_empty() {
            push_audit(
                &mut vault,
                "key.decrypt_only_erased",
                erased.into_iter().collect(),
                None,
                actor,
                "bounded envelope lifetime elapsed",
                "succeeded",
                now,
            );
            self.write_vault(&vault)?;
        }
        Ok(public_view(&vault))
    }

    fn lock(&self) -> Result<CustodyLock> {
        let path = self.root.join("custody.lock");
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::engine(
                    "federation custody lock must be a regular non-symlink file",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(Error::engine(
                "federation custody lock is not a regular file",
            ));
        }
        set_owner_only_file(&file)?;
        file.lock_exclusive()?;
        Ok(CustodyLock(file))
    }

    fn vault_path(&self, account_id: &str) -> PathBuf {
        self.root
            .join("principals")
            .join(format!("{}.vault.json", account_token(account_id)))
    }

    fn marker_path(&self, account_id: &str) -> PathBuf {
        self.root
            .join("principals")
            .join(format!("{}.provisioned", account_token(account_id)))
    }

    fn has_marker(&self, account_id: &str) -> Result<bool> {
        match std::fs::symlink_metadata(self.marker_path(account_id)) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
                Error::engine("federation custody provisioning marker is corrupt"),
            ),
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn ensure_marker(&self, account_id: &str) -> Result<()> {
        if self.has_marker(account_id)? {
            return Ok(());
        }
        let path = self.marker_path(account_id);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        set_owner_only_file(&file)?;
        file.write_all(b"native-federation-account-v1\n")?;
        file.sync_all()?;
        sync_parent(&path)
    }

    fn read_vault(&self, account_id: &str) -> Result<Option<VaultFile>> {
        let path = self.vault_path(account_id);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::engine(
                    "federation custody vault must be a regular non-symlink file",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let vault: VaultFile = serde_json::from_slice(&bytes).map_err(|_| {
            Error::engine("federation custody vault is malformed; state is corrupt")
        })?;
        Ok(Some(vault))
    }

    fn load_valid(&self, account_id: &str) -> Result<VaultFile> {
        let vault = match self.read_vault(account_id)? {
            Some(vault) => vault,
            None if self.has_marker(account_id)? => {
                return Err(Error::engine(
                    "federation custody vault is missing; state is corrupt",
                ));
            }
            None => return Err(Error::engine("federation custody is unprovisioned")),
        };
        self.validate_vault_for_account(vault, account_id)
    }

    fn validate_vault_for_account(&self, vault: VaultFile, account_id: &str) -> Result<VaultFile> {
        let vault = self.validate_vault(vault)?;
        if vault.account_id != account_id {
            return Err(Error::engine(
                "federation custody account binding mismatch; state is corrupt",
            ));
        }
        Ok(vault)
    }

    fn validate_vault(&self, vault: VaultFile) -> Result<VaultFile> {
        self.verify_vault_integrity(&vault)?;
        if vault.version != VAULT_VERSION
            || vault.account_id.is_empty()
            || vault.network_id.is_empty()
            || vault.principal_id.is_empty()
            || vault.document_version == 0
        {
            return Err(Error::engine("federation custody metadata is corrupt"));
        }
        let mut kids = BTreeSet::new();
        let mut active = BTreeMap::<KeyPurpose, usize>::new();
        for key in &vault.keys {
            if !kids.insert(key.public.jwk.kid.clone())
                || key.generation == 0
                || key.wrapped.wrapper != CUSTODY_WRAPPER
                || key.public.jwk.kid != expected_kid(&key.public.jwk, key.public.purpose)?
            {
                return Err(Error::engine("federation custody key metadata is corrupt"));
            }
            validate_public_key_record(&key.public)?;
            let secret = self.unwrap_key(&vault, key)?;
            if public_jwk(&secret, key.public.purpose)? != key.public.jwk {
                return Err(Error::engine("federation custody key/ciphertext mismatch"));
            }
            if key.public.status == KeyStatus::Active {
                *active.entry(key.public.purpose).or_default() += 1;
            }
        }
        for key in &vault.historical_keys {
            if !kids.insert(key.jwk.kid.clone())
                || key.jwk.kid != expected_kid(&key.jwk, key.purpose)?
                || key.status == KeyStatus::Active
            {
                return Err(Error::engine(
                    "federation custody historical key metadata is corrupt",
                ));
            }
            validate_public_key_record(key)?;
        }
        let maximum = if matches!(
            vault.state,
            PrincipalState::RotationPending | PrincipalState::PendingHandoff
        ) {
            2
        } else {
            1
        };
        if active.values().any(|count| *count == 0 || *count > maximum)
            || matches!(vault.state, PrincipalState::Active)
                && [
                    KeyPurpose::Root,
                    KeyPurpose::Signing,
                    KeyPurpose::Encryption,
                    KeyPurpose::Installation,
                ]
                .iter()
                .any(|purpose| active.get(purpose) != Some(&1))
        {
            return Err(Error::engine(
                "federation custody has duplicate or missing active key purposes",
            ));
        }
        if (vault.state == PrincipalState::PendingHandoff) != vault.pending.is_some() {
            return Err(Error::engine("federation custody handoff state is partial"));
        }
        if vault
            .pending
            .as_ref()
            .is_some_and(|pending| !pending.projected_principal_document.is_object())
        {
            return Err(Error::engine(
                "federation custody projected handoff document is missing",
            ));
        }
        if let Some(evidence) = &vault.last_attestation {
            validate_uuid(&evidence.handoff_id, "authority handoff id")?;
            validate_sha256_digest(&evidence.document_digest, "authority document digest")?;
        }
        Ok(vault)
    }

    fn write_vault(&self, vault: &VaultFile) -> Result<()> {
        let mut sealed = vault.clone();
        sealed.integrity = self.vault_integrity(&sealed)?;
        let bytes = serde_json::to_vec(&sealed)?;
        let destination = self.vault_path(&vault.account_id);
        match std::fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::engine(
                    "federation custody vault destination is not a regular file",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let temporary = destination.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let written = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            set_owner_only_file(&file)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(())
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&temporary, &destination) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        sync_parent(&destination)?;
        Ok(())
    }

    fn vault_integrity(&self, vault: &VaultFile) -> Result<String> {
        let payload = vault_integrity_payload(vault)?;
        let key = derive_custody_key(
            &self.master_key,
            b"native-federation-vault-integrity-key-v1",
        );
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
            .map_err(|_| Error::engine("federation vault integrity key is invalid"))?;
        mac.update(b"native-federation-vault-integrity-payload-v1\0");
        mac.update(&payload);
        Ok(format!(
            "{VAULT_INTEGRITY_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    fn verify_vault_integrity(&self, vault: &VaultFile) -> Result<()> {
        let encoded = vault
            .integrity
            .strip_prefix(VAULT_INTEGRITY_PREFIX)
            .ok_or_else(|| {
                Error::engine("federation custody vault integrity metadata is missing")
            })?;
        let supplied = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::engine("federation custody vault integrity is malformed"))?;
        if supplied.len() != 32 {
            return Err(Error::engine(
                "federation custody vault integrity has the wrong length",
            ));
        }
        let payload = vault_integrity_payload(vault)?;
        let key = derive_custody_key(
            &self.master_key,
            b"native-federation-vault-integrity-key-v1",
        );
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
            .map_err(|_| Error::engine("federation vault integrity key is invalid"))?;
        mac.update(b"native-federation-vault-integrity-payload-v1\0");
        mac.update(&payload);
        mac.verify_slice(&supplied)
            .map_err(|_| Error::engine("federation custody vault integrity check failed"))
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_stored_key(
        &self,
        account_id: &str,
        network_id: &str,
        principal_id: &str,
        purpose: KeyPurpose,
        generation: u64,
        now: &str,
        installation_id: Option<&str>,
        endpoint_origin: Option<&str>,
    ) -> Result<StoredKey> {
        let secret = Zeroizing::new(random_array());
        let jwk = public_jwk(&secret, purpose)?;
        let public = PublicKeyRecord {
            purpose,
            jwk,
            status: KeyStatus::Active,
            not_before: now.to_owned(),
            not_after: None,
            installation_id: installation_id.map(str::to_owned),
            endpoint_origin: endpoint_origin.map(str::to_owned),
        };
        let wrapped = self.wrap_secret(account_id, network_id, principal_id, &public, &secret)?;
        Ok(StoredKey {
            public,
            wrapped,
            generation,
        })
    }

    fn wrap_secret(
        &self,
        account_id: &str,
        network_id: &str,
        principal_id: &str,
        public: &PublicKeyRecord,
        secret: &[u8; 32],
    ) -> Result<WrappedSecret> {
        let cipher = XChaCha20Poly1305::new((&**self.master_key.0).into());
        let nonce_bytes = random_array::<24>();
        let nonce = XNonce::from(nonce_bytes);
        let aad = custody_aad(account_id, network_id, principal_id, public);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::engine("federation custody wrapping failed"))?;
        Ok(WrappedSecret {
            wrapper: CUSTODY_WRAPPER.to_owned(),
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    fn unwrap_key(&self, vault: &VaultFile, key: &StoredKey) -> Result<Zeroizing<[u8; 32]>> {
        if key.wrapped.wrapper != CUSTODY_WRAPPER {
            return Err(Error::engine("unknown federation custody wrapper"));
        }
        let nonce = XNonce::from(decode_array::<24>(&key.wrapped.nonce, "custody nonce")?);
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&key.wrapped.ciphertext)
            .map_err(|_| Error::engine("federation custody ciphertext is malformed"))?;
        let cipher = XChaCha20Poly1305::new((&**self.master_key.0).into());
        let aad = custody_aad(
            &vault.account_id,
            &vault.network_id,
            &vault.principal_id,
            &key.public,
        );
        let mut plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::engine("federation custody ciphertext failed authentication"))?;
        if plaintext.len() != 32 {
            plaintext.zeroize();
            return Err(Error::engine("federation custody secret length is corrupt"));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(secret)
    }
}

struct CustodyLock(File);

impl Drop for CustodyLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn public_view(vault: &VaultFile) -> FederationPrincipal {
    FederationPrincipal {
        account_id: vault.account_id.clone(),
        network_id: vault.network_id.clone(),
        principal_id: vault.principal_id.clone(),
        state: vault.state,
        document_version: vault.document_version,
        keys: vault
            .keys
            .iter()
            .map(|key| key.public.clone())
            .chain(vault.historical_keys.iter().cloned())
            .collect(),
        pending_handoff_id: vault
            .pending
            .as_ref()
            .map(|pending| pending.handoff_id.clone()),
    }
}

fn corrupt_view(account_id: &str) -> FederationPrincipal {
    FederationPrincipal {
        account_id: account_id.to_owned(),
        network_id: String::new(),
        principal_id: String::new(),
        state: PrincipalState::Corrupt,
        document_version: 0,
        keys: vec![],
        pending_handoff_id: None,
    }
}

fn unique_active_key(vault: &VaultFile, purpose: KeyPurpose) -> Result<&StoredKey> {
    let mut keys = vault
        .keys
        .iter()
        .filter(|key| key.public.purpose == purpose && key.public.status == KeyStatus::Active);
    let key = keys
        .next()
        .ok_or_else(|| Error::engine(format!("no active {purpose} federation key")))?;
    if keys.next().is_some() {
        return Err(Error::engine(format!(
            "more than one active {purpose} federation key"
        )));
    }
    Ok(key)
}

fn unique_newest_active_key(vault: &VaultFile, purpose: KeyPurpose) -> Result<&StoredKey> {
    vault
        .keys
        .iter()
        .filter(|key| key.public.purpose == purpose && key.public.status == KeyStatus::Active)
        .max_by_key(|key| key.generation)
        .ok_or_else(|| Error::engine(format!("no active {purpose} federation key")))
}

fn build_principal_document(
    custody: &FileFederationCustody,
    vault: &VaultFile,
    issued: DateTime<Utc>,
) -> Result<Value> {
    let root = unique_newest_active_key(vault, KeyPurpose::Root)?;
    let root_secret = custody.unwrap_key(vault, root)?;
    let signing = unique_newest_active_key(vault, KeyPurpose::Signing)?;
    let signing_secret = custody.unwrap_key(vault, signing)?;
    let principal = json!({
        "network_id": vault.network_id,
        "principal_id": vault.principal_id,
    });
    let mut operational = vec![];
    for key in vault.keys.iter().filter(|key| {
        matches!(
            key.public.purpose,
            KeyPurpose::Signing | KeyPurpose::Encryption
        ) && key.public.status != KeyStatus::DecryptOnly
    }) {
        let statement = json!({
            "statement_type": "native.operational-key-authorization",
            "protocol_version": "1.0",
            "principal": principal,
            "key": key.public,
            "issued_at": issued.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });
        let signature = detached_jws_with_secret(
            &root.public.jwk,
            "native-key-authorization+jws",
            &statement,
            &root_secret,
        )?;
        operational.push(json!({
            "purpose": key.public.purpose,
            "jwk": key.public.jwk,
            "status": key.public.status,
            "not_before": key.public.not_before,
            "not_after": key.public.not_after,
            "authorization": {"statement": statement, "signature": signature},
        }));
    }
    let mut installations = vec![];
    for key in vault.keys.iter().filter(|key| {
        key.public.purpose == KeyPurpose::Installation
            && key.public.status != KeyStatus::DecryptOnly
    }) {
        let scopes = json!([
            "directory.endpoint.update",
            "relay.acknowledge",
            "relay.collect"
        ]);
        let statement = json!({
            "statement_type": "native.installation-key-authorization",
            "protocol_version": "1.0",
            "principal": principal,
            "installation": {
                "installation_id": key.public.installation_id,
                "jwk": key.public.jwk,
                "status": key.public.status,
                "endpoint_origin": key.public.endpoint_origin,
                "scopes": scopes,
            },
            "issued_at": issued.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        });
        let signature = detached_jws_with_secret(
            &signing.public.jwk,
            "native-key-authorization+jws",
            &statement,
            &signing_secret,
        )?;
        installations.push(json!({
            "installation_id": key.public.installation_id,
            "jwk": key.public.jwk,
            "status": key.public.status,
            "endpoint_origin": key.public.endpoint_origin,
            "scopes": scopes,
            "authorization": {"statement": statement, "signature": signature},
        }));
    }
    Ok(json!({
        "document_type": "native.federation.principal",
        "protocol_version": "1.0",
        "profile": FEDERATION_PROFILE,
        "network_id": vault.network_id,
        "principal_id": vault.principal_id,
        "document_version": vault.document_version,
        "issued_at": issued.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "fresh_until": (issued + Duration::minutes(15)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "hard_expires_at": (issued + Duration::hours(24)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "root_keys": vault.keys.iter().filter(|key| key.public.purpose == KeyPurpose::Root).map(|key| json!({
            "jwk": key.public.jwk, "status": key.public.status,
            "not_before": key.public.not_before, "not_after": key.public.not_after,
        })).collect::<Vec<_>>(),
        "operational_keys": operational,
        "installations": installations,
        "verified_aliases": [], "delivery_endpoints": [],
        "supported_profiles": [FEDERATION_PROFILE], "capabilities": [],
        "required_capabilities": [], "extensions": {},
    }))
}

fn build_signed_principal_document(
    custody: &FileFederationCustody,
    vault: &VaultFile,
    issued: DateTime<Utc>,
) -> Result<Value> {
    let document = build_principal_document(custody, vault, issued)?;
    let signing = unique_newest_active_key(vault, KeyPurpose::Signing)?;
    let secret = custody.unwrap_key(vault, signing)?;
    let signature = detached_jws_with_secret(
        &signing.public.jwk,
        "native-principal+jws",
        &document,
        &secret,
    )?;
    Ok(json!({"document": document, "principal_signature": signature}))
}

fn detached_jws_with_secret(
    jwk: &PublicJwk,
    typ: &str,
    payload: &Value,
    secret: &[u8; 32],
) -> Result<String> {
    validate_jws_type(typ)?;
    validate_signing_policy(kid_purpose(&jwk.kid)?, typ)?;
    let protected = json!({"alg": "EdDSA", "kid": jwk.kid, "typ": typ});
    let protected = URL_SAFE_NO_PAD.encode(jcs(&protected)?);
    let payload = URL_SAFE_NO_PAD.encode(jcs(payload)?);
    let input = format!("{protected}.{payload}");
    let signature = SigningKey::from_bytes(secret).sign(input.as_bytes());
    Ok(format!(
        "{protected}..{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

/// Verify a detached federation JWS against exactly the supplied public JWK.
pub fn verify_detached_jws(
    jwk: &PublicJwk,
    typ: &str,
    payload: &Value,
    compact: &str,
) -> Result<()> {
    validate_jws_type(typ)?;
    let purpose = kid_purpose(&jwk.kid)?;
    validate_signing_policy(purpose, typ)?;
    if jwk.kty != "OKP"
        || jwk.crv != "Ed25519"
        || jwk.alg != "EdDSA"
        || jwk.use_ != "sig"
        || expected_kid(jwk, purpose)? != jwk.kid
    {
        return Err(Error::engine(
            "federation JWK kid does not match its thumbprint",
        ));
    }
    let parts = compact.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err(Error::engine("federation detached JWS shape is invalid"));
    }
    let protected_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| Error::engine("federation JWS protected header is invalid"))?;
    let protected: Value = serde_json::from_slice(&protected_bytes)?;
    if protected != json!({"alg": "EdDSA", "kid": jwk.kid, "typ": typ})
        || parts[0] != URL_SAFE_NO_PAD.encode(jcs(&protected)?)
    {
        return Err(Error::engine(
            "federation JWS protected header is not canonical or bound",
        ));
    }
    let x = decode_array::<32>(&jwk.x, "Ed25519 public JWK")?;
    let key =
        VerifyingKey::from_bytes(&x).map_err(|_| Error::engine("Ed25519 public JWK is invalid"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| Error::engine("federation JWS signature is invalid"))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| Error::engine("federation JWS signature length is invalid"))?;
    let input = format!("{}.{}", parts[0], URL_SAFE_NO_PAD.encode(jcs(payload)?));
    key.verify(input.as_bytes(), &signature)
        .map_err(|_| Error::engine("federation JWS signature verification failed"))
}

fn public_jwk(secret: &[u8; 32], purpose: KeyPurpose) -> Result<PublicJwk> {
    let (crv, alg, use_, public) = if purpose == KeyPurpose::Encryption {
        let secret = StaticSecret::from(*secret);
        let public = X25519PublicKey::from(&secret);
        ("X25519", "HPKE-3-KE", "enc", *public.as_bytes())
    } else {
        let signing = SigningKey::from_bytes(secret);
        (
            "Ed25519",
            "EdDSA",
            "sig",
            signing.verifying_key().to_bytes(),
        )
    };
    let mut jwk = PublicJwk {
        kty: "OKP".to_owned(),
        crv: crv.to_owned(),
        x: URL_SAFE_NO_PAD.encode(public),
        alg: alg.to_owned(),
        use_: use_.to_owned(),
        kid: String::new(),
    };
    jwk.kid = expected_kid(&jwk, purpose)?;
    Ok(jwk)
}

fn expected_kid(jwk: &PublicJwk, purpose: KeyPurpose) -> Result<String> {
    let thumbprint = json!({"crv": jwk.crv, "kty": jwk.kty, "x": jwk.x});
    Ok(format!(
        "n1.{}.{}",
        purpose.as_str(),
        URL_SAFE_NO_PAD.encode(Sha256::digest(jcs(&thumbprint)?))
    ))
}

fn kid_purpose(kid: &str) -> Result<KeyPurpose> {
    match kid.split('.').nth(1) {
        Some("root") => Ok(KeyPurpose::Root),
        Some("signing") => Ok(KeyPurpose::Signing),
        Some("encryption") => Ok(KeyPurpose::Encryption),
        Some("installation") => Ok(KeyPurpose::Installation),
        _ => Err(Error::engine("federation key id has an unknown purpose")),
    }
}

fn jcs(value: &Value) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| Error::engine(format!("JCS encoding failed: {error}")))
}

fn derive_custody_key(master_key: &CustodyMasterKey, domain: &[u8]) -> [u8; 32] {
    let mut kdf = <Hmac<Sha256> as Mac>::new_from_slice(&**master_key.0)
        .expect("HMAC accepts custody master keys");
    kdf.update(b"native-federation-custody-kdf-v1\0");
    kdf.update(domain);
    kdf.finalize().into_bytes().into()
}

fn store_sentinel_value(master_key: &CustodyMasterKey) -> String {
    let key = derive_custody_key(
        master_key,
        b"native-federation-custody-store-sentinel-key-v1",
    );
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC accepts derived custody keys");
    mac.update(STORE_SENTINEL_VERSION.as_bytes());
    format!(
        "{STORE_SENTINEL_VERSION}:{}\n",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn vault_integrity_payload(vault: &VaultFile) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(vault)?;
    value
        .as_object_mut()
        .ok_or_else(|| Error::engine("federation custody vault is not an object"))?
        .remove("integrity");
    jcs(&value)
}

fn custody_aad(
    account_id: &str,
    network_id: &str,
    principal_id: &str,
    public: &PublicKeyRecord,
) -> Vec<u8> {
    format!(
        "native-federation-custody-v1\0{account_id}\0{network_id}\0{principal_id}\0{}\0{}",
        public.purpose, public.jwk.kid
    )
    .into_bytes()
}

#[allow(clippy::too_many_arguments)]
fn push_audit(
    vault: &mut VaultFile,
    event_type: &str,
    affected_kids: Vec<String>,
    handoff_id: Option<String>,
    actor: &str,
    reason: &str,
    result: &str,
    now: &str,
) {
    vault.audit.push(FederationAuditEvent {
        event_id: Uuid::new_v4().to_string(),
        principal_id: vault.principal_id.clone(),
        event_type: event_type.to_owned(),
        affected_kids,
        document_version: vault.document_version,
        document_digest: None,
        handoff_id,
        actor: actor.to_owned(),
        reason: reason.to_owned(),
        result: result.to_owned(),
        occurred_at: now.to_owned(),
    });
}

fn account_token(account_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(account_id.as_bytes()))
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn random_b64(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::engine(format!("{label} is not base64url")))?;
    decoded
        .try_into()
        .map_err(|_| Error::engine(format!("{label} has the wrong length")))
}

fn parse_time(value: &str, label: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| Error::engine(format!("{label} is not RFC 3339")))
}

fn validate_nonempty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 255 || value.chars().any(char::is_whitespace) {
        return Err(Error::engine(format!("federation {label} is invalid")));
    }
    Ok(())
}

fn validate_uuid(value: &str, label: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| Error::engine(format!("federation {label} is not a UUID")))?;
    if parsed.hyphenated().to_string() != value {
        return Err(Error::engine(format!(
            "federation {label} is not canonical"
        )));
    }
    Ok(())
}

fn validate_origin(value: &str) -> Result<()> {
    let url =
        url::Url::parse(value).map_err(|_| Error::engine("federation endpoint is invalid"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.username() != ""
        || url.password().is_some()
    {
        return Err(Error::engine("federation endpoint must be an HTTPS origin"));
    }
    Ok(())
}

fn validate_public_key_record(key: &PublicKeyRecord) -> Result<()> {
    let expected_shape = if key.purpose == KeyPurpose::Encryption {
        key.jwk.kty == "OKP"
            && key.jwk.crv == "X25519"
            && key.jwk.alg == "HPKE-3-KE"
            && key.jwk.use_ == "enc"
    } else {
        key.jwk.kty == "OKP"
            && key.jwk.crv == "Ed25519"
            && key.jwk.alg == "EdDSA"
            && key.jwk.use_ == "sig"
    };
    let _ = decode_array::<32>(&key.jwk.x, "federation public key")?;
    if !expected_shape || key.jwk.kid != expected_kid(&key.jwk, key.purpose)? {
        return Err(Error::engine("federation public key thumbprint is invalid"));
    }
    let not_before = parse_time(&key.not_before, "public key not-before")?;
    if let Some(not_after) = key.not_after.as_deref() {
        if parse_time(not_after, "public key not-after")? < not_before {
            return Err(Error::engine(
                "federation public key validity interval is invalid",
            ));
        }
    }
    if key.purpose == KeyPurpose::Installation {
        validate_uuid(
            key.installation_id
                .as_deref()
                .ok_or_else(|| Error::engine("installation key has no installation id"))?,
            "installation id",
        )?;
        validate_origin(
            key.endpoint_origin
                .as_deref()
                .ok_or_else(|| Error::engine("installation key has no endpoint origin"))?,
        )?;
    } else if key.installation_id.is_some() || key.endpoint_origin.is_some() {
        return Err(Error::engine(
            "non-installation federation key has installation metadata",
        ));
    }
    Ok(())
}

fn validate_sha256_digest(value: &str, label: &str) -> Result<()> {
    let encoded = value
        .strip_prefix("sha-256:")
        .ok_or_else(|| Error::engine(format!("{label} has an invalid algorithm")))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::engine(format!("{label} is not base64url")))?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(Error::engine(format!(
            "{label} must be a canonical 32-byte SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_jws_type(value: &str) -> Result<()> {
    const TYPES: &[&str] = &[
        "native-principal+jws",
        "native-key-authorization+jws",
        "native-root-transition+jws",
        "native-envelope+jws",
        "native-request-proof+jws",
        "native-eject-manifest+jws",
    ];
    if !TYPES.contains(&value) {
        return Err(Error::engine("unsupported federation JWS type"));
    }
    Ok(())
}

fn validate_signing_policy(purpose: KeyPurpose, typ: &str) -> Result<()> {
    validate_jws_type(typ)?;
    let permitted = match purpose {
        KeyPurpose::Root => matches!(
            typ,
            "native-key-authorization+jws" | "native-root-transition+jws"
        ),
        KeyPurpose::Signing => matches!(
            typ,
            "native-principal+jws"
                | "native-key-authorization+jws"
                | "native-envelope+jws"
                | "native-eject-manifest+jws"
        ),
        KeyPurpose::Installation => typ == "native-request-proof+jws",
        KeyPurpose::Encryption => false,
    };
    if permitted {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "federation {purpose} key is not authorized for JWS type {typ}"
        )))
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if directory { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path, _directory: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_file(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_file(_file: &File) -> Result<()> {
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Client-side envelope encryption stays unavailable until the selected
/// JOSE–HPKE draft has a reviewed construction adapter. The standalone relay
/// independently validates and stores opaque already-encrypted envelopes; it
/// does not make this encryption/decryption capability available to clients.
pub trait FederationCrypto: Send + Sync {
    fn encrypt(&self, profile: &str, _plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, profile: &str, _ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProfileGatedFederationCrypto;

impl FederationCrypto for ProfileGatedFederationCrypto {
    fn encrypt(&self, profile: &str, _plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(unsupported_profile(profile))
    }

    fn decrypt(&self, profile: &str, _ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(unsupported_profile(profile))
    }
}

fn unsupported_profile(profile: &str) -> Error {
    let build = if cfg!(feature = "experimental-federation-hpke") {
        "experimental feature enabled, but no reviewed draft adapter is linked"
    } else {
        "experimental feature is disabled"
    };
    Error::engine(format!("unsupported_profile: {profile} ({build})"))
}

// Eject/adoption types and operations follow below. Keeping them in the same
// module prevents plaintext identity material from crossing a public API.

#[derive(Clone)]
pub struct EjectDestinationIdentity(age::x25519::Identity);

impl fmt::Debug for EjectDestinationIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EjectDestinationIdentity([REDACTED])")
    }
}

impl EjectDestinationIdentity {
    pub fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }

    pub fn recipient(&self) -> String {
        self.0.to_public().to_string()
    }

    /// Explicit secret export for an owner-managed destination identity file.
    /// This is not used by ordinary record/query surfaces.
    pub fn to_secret_string(&self) -> SecretString {
        self.0.to_string()
    }

    pub fn from_secret_string(value: &SecretString) -> Result<Self> {
        age::x25519::Identity::from_str(value.expose_secret())
            .map(Self)
            .map_err(|_| Error::engine("destination age identity is invalid"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EjectComponent {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EjectManifestBody {
    pub package_type: String,
    pub package_version: u32,
    pub profile: String,
    pub principal_network_id: String,
    pub principal_id: String,
    pub exporter_account_id: String,
    pub source_installation_id: String,
    pub expected_document_version: u64,
    pub handoff_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub destination_recipient: String,
    pub database: EjectComponent,
    pub identity_bundle: EjectComponent,
    pub exporter_signing_jwk: PublicJwk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEjectManifest {
    pub manifest: EjectManifestBody,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
struct ExportedPrivateKey {
    public: PublicKeyRecord,
    generation: u64,
    secret: String,
}

impl Drop for ExportedPrivateKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityBundle {
    version: u32,
    account_id: String,
    network_id: String,
    principal_id: String,
    document_version: u64,
    source_installation_id: String,
    handoff_id: String,
    keys: Vec<ExportedPrivateKey>,
    public_history: Vec<PublicKeyRecord>,
    source_principal_document: Value,
}

/// Authority evidence for one committed directory compare-and-swap. The
/// opaque attestation is interpreted only by the trusted directory adapter;
/// the typed fields make the lifecycle binding impossible to omit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryAttestation {
    pub handoff_id: String,
    pub document_version: u64,
    pub document_digest: String,
    pub authority_attestation: Value,
}

/// A directory mutation result. Only `Attested` activates the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryCommit {
    Attested(DirectoryAttestation),
    Unavailable,
    VersionConflict { current_document_version: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootTransition {
    pub statement: Value,
    pub old_root_signature: String,
    pub new_root_signature: String,
}

#[derive(Debug, Clone)]
pub struct RootTransitionRequest {
    pub handoff_id: String,
    pub expected_document_version: u64,
    pub principal: FederationPrincipal,
    pub transition: RootTransition,
    pub source_installation_id: String,
    pub projected_principal_document: Value,
}

pub trait FederationDirectory: Send + Sync {
    fn compare_and_swap<'a>(
        &'a self,
        request: &'a RootTransitionRequest,
    ) -> Pin<Box<dyn Future<Output = Result<DirectoryCommit>> + Send + 'a>>;

    /// Verify authority evidence against the adapter's configured trust root
    /// and current directory state. Custody never treats opaque caller data as
    /// sufficient retirement authority.
    fn verify_attestation<'a>(
        &'a self,
        evidence: &'a DirectoryAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EjectPackageResult {
    pub path: PathBuf,
    pub handoff_id: String,
    pub principal_id: String,
}

#[allow(clippy::too_many_arguments)]
pub fn create_eject_package(
    custody: &FileFederationCustody,
    authenticated_account_id: &str,
    database_snapshot: &Path,
    destination: &Path,
    destination_recipient: &str,
    source_installation_id: &str,
    created_at: &str,
    expires_at: &str,
) -> Result<EjectPackageResult> {
    let created = parse_time(created_at, "eject creation time")?;
    let expires = parse_time(expires_at, "eject expiry time")?;
    if expires <= created || expires > created + Duration::days(7) {
        return Err(Error::engine(
            "eject package expiry must be within seven days",
        ));
    }
    validate_uuid(source_installation_id, "source installation id")?;
    let recipient = age::x25519::Recipient::from_str(destination_recipient)
        .map_err(|_| Error::engine("destination age recipient is invalid"))?;
    let metadata = std::fs::symlink_metadata(database_snapshot)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(
            "eject database snapshot must be a regular file",
        ));
    }
    let _guard = custody.lock()?;
    let mut vault = custody.load_valid(authenticated_account_id)?;
    if vault.state != PrincipalState::Active {
        return Err(Error::engine(
            "only an active authenticated principal may eject identity",
        ));
    }
    let installation = vault.keys.iter().find(|key| {
        key.public.purpose == KeyPurpose::Installation
            && key.public.status == KeyStatus::Active
            && key.public.installation_id.as_deref() == Some(source_installation_id)
    });
    if installation.is_none() {
        return Err(Error::auth(
            "authenticated principal does not control the source installation",
        ));
    }
    let handoff_id = Uuid::new_v4().to_string();
    let mut exported = vec![];
    for key in vault
        .keys
        .iter()
        .filter(|key| key.public.status == KeyStatus::Active)
    {
        let secret = custody.unwrap_key(&vault, key)?;
        exported.push(ExportedPrivateKey {
            public: key.public.clone(),
            generation: key.generation,
            secret: URL_SAFE_NO_PAD.encode(secret.as_slice()),
        });
    }
    let signing = unique_active_key(&vault, KeyPurpose::Signing)?;
    let source_principal_document = build_signed_principal_document(custody, &vault, created)?;
    let bundle = IdentityBundle {
        version: IDENTITY_BUNDLE_VERSION,
        account_id: vault.account_id.clone(),
        network_id: vault.network_id.clone(),
        principal_id: vault.principal_id.clone(),
        document_version: vault.document_version,
        source_installation_id: source_installation_id.to_owned(),
        handoff_id: handoff_id.clone(),
        keys: exported,
        public_history: vault.historical_keys.clone(),
        source_principal_document,
    };
    let mut plaintext = Zeroizing::new(serde_json::to_vec(&bundle)?);
    let encrypted_bundle = age::encrypt(&recipient, &plaintext)
        .map_err(|error| Error::engine(format!("age identity encryption failed: {error}")))?;
    plaintext.zeroize();
    let database = digest_path(database_snapshot)?;
    let identity_bundle = component(&encrypted_bundle);
    let signing_jwk = signing.public.jwk.clone();
    let signing_kid = signing_jwk.kid.clone();
    let manifest = EjectManifestBody {
        package_type: "native.federation.eject".to_owned(),
        package_version: EJECT_PACKAGE_VERSION,
        profile: FEDERATION_PROFILE.to_owned(),
        principal_network_id: vault.network_id.clone(),
        principal_id: vault.principal_id.clone(),
        exporter_account_id: vault.account_id.clone(),
        source_installation_id: source_installation_id.to_owned(),
        expected_document_version: vault.document_version,
        handoff_id: handoff_id.clone(),
        created_at: created_at.to_owned(),
        expires_at: expires_at.to_owned(),
        destination_recipient: destination_recipient.to_owned(),
        database,
        identity_bundle,
        exporter_signing_jwk: signing_jwk.clone(),
    };
    let payload = serde_json::to_value(&manifest)?;
    let signing_secret = custody.unwrap_key(&vault, signing)?;
    let signature = detached_jws_with_secret(
        &signing_jwk,
        "native-eject-manifest+jws",
        &payload,
        &signing_secret,
    )?;
    let signed = SignedEjectManifest {
        manifest,
        signature,
    };
    write_package(destination, database_snapshot, &encrypted_bundle, &signed)?;
    push_audit(
        &mut vault,
        "handoff.package_created",
        vec![signing_kid],
        Some(handoff_id.clone()),
        authenticated_account_id,
        "authenticated principal exported its own encrypted identity bundle",
        "succeeded",
        created_at,
    );
    custody.write_vault(&vault)?;
    Ok(EjectPackageResult {
        path: destination.to_path_buf(),
        handoff_id,
        principal_id: vault.principal_id,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionHandoffResult {
    pub database_path: PathBuf,
    pub principal: FederationPrincipal,
    pub handoff_id: String,
    pub directory_state: PrincipalState,
    pub authority_evidence: Option<DirectoryAttestation>,
}

/// Verify and stage a `.native-eject`, then attempt the guarded directory
/// transition. Directory outage leaves a retryable `pending_handoff` vault;
/// a version conflict fails closed and never activates federation.
#[allow(clippy::too_many_arguments)]
pub async fn adopt_eject_package(
    custody: &FileFederationCustody,
    destination_account_id: &str,
    package: &Path,
    destination_database: &Path,
    destination_identity: &EjectDestinationIdentity,
    destination_installation_id: &str,
    destination_endpoint_origin: &str,
    directory: &dyn FederationDirectory,
    actor: &str,
    now: &str,
) -> Result<AdoptionHandoffResult> {
    adopt_eject_package_inner(
        custody,
        destination_account_id,
        package,
        destination_database,
        destination_identity,
        destination_installation_id,
        destination_endpoint_origin,
        directory,
        actor,
        now,
        true,
    )
    .await
}

/// Complete only the identity half after the held host applies database adoption.
/// has already verified, migrated, and published the database component.
#[allow(clippy::too_many_arguments)]
pub async fn adopt_eject_identity_after_database_adoption(
    custody: &FileFederationCustody,
    destination_account_id: &str,
    package: &Path,
    adopted_database: &Path,
    destination_identity: &EjectDestinationIdentity,
    destination_installation_id: &str,
    destination_endpoint_origin: &str,
    directory: &dyn FederationDirectory,
    actor: &str,
    now: &str,
) -> Result<AdoptionHandoffResult> {
    adopt_eject_package_inner(
        custody,
        destination_account_id,
        package,
        adopted_database,
        destination_identity,
        destination_installation_id,
        destination_endpoint_origin,
        directory,
        actor,
        now,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn adopt_eject_package_inner(
    custody: &FileFederationCustody,
    destination_account_id: &str,
    package: &Path,
    destination_database: &Path,
    destination_identity: &EjectDestinationIdentity,
    destination_installation_id: &str,
    destination_endpoint_origin: &str,
    directory: &dyn FederationDirectory,
    actor: &str,
    now: &str,
    stage_database: bool,
) -> Result<AdoptionHandoffResult> {
    validate_uuid(destination_installation_id, "destination installation id")?;
    validate_origin(destination_endpoint_origin)?;
    let now_time = parse_time(now, "adoption time")?;
    let (signed, database_offset, bundle_offset) = read_package_header(package)?;
    validate_manifest(&signed, now_time)?;
    let manifest_value = serde_json::to_value(&signed.manifest)?;
    verify_detached_jws(
        &signed.manifest.exporter_signing_jwk,
        "native-eject-manifest+jws",
        &manifest_value,
        &signed.signature,
    )?;
    if destination_identity.recipient() != signed.manifest.destination_recipient {
        return Err(Error::auth(
            "eject package was encrypted for another destination",
        ));
    }
    if stage_database {
        stage_database_component(
            package,
            database_offset,
            signed.manifest.database.size_bytes,
            destination_database,
            &signed.manifest.database.sha256,
        )?;
    } else {
        verify_existing_database_component(
            destination_database,
            signed.manifest.database.size_bytes,
            &signed.manifest.database.sha256,
        )?;
    }
    let encrypted = read_component(
        package,
        bundle_offset,
        signed.manifest.identity_bundle.size_bytes,
        MAX_IDENTITY_BUNDLE_BYTES,
    )?;
    if component(&encrypted) != signed.manifest.identity_bundle {
        return Err(Error::engine("eject identity bundle digest mismatch"));
    }
    let mut decrypted = Zeroizing::new(
        age::decrypt(&destination_identity.0, &encrypted)
            .map_err(|_| Error::auth("eject identity bundle could not be decrypted"))?,
    );
    let bundle: IdentityBundle = serde_json::from_slice(&decrypted)
        .map_err(|_| Error::engine("eject identity bundle is malformed"))?;
    validate_bundle(&signed.manifest, &bundle, destination_account_id)?;

    let request = {
        let _guard = custody.lock()?;
        if let Some(existing) = custody.read_vault(destination_account_id)? {
            let existing = custody.validate_vault_for_account(existing, destination_account_id)?;
            if existing.state == PrincipalState::PendingHandoff
                && existing.pending.as_ref().map(|p| p.handoff_id.as_str())
                    == Some(signed.manifest.handoff_id.as_str())
            {
                transition_request(&existing)?
            } else if existing.state == PrincipalState::Active
                && existing.principal_id == bundle.principal_id
                && existing.document_version == bundle.document_version + 1
            {
                decrypted.zeroize();
                return Ok(AdoptionHandoffResult {
                    database_path: destination_database.to_path_buf(),
                    principal: public_view(&existing),
                    handoff_id: bundle.handoff_id,
                    directory_state: PrincipalState::Active,
                    authority_evidence: existing.last_attestation.clone(),
                });
            } else {
                return Err(Error::engine(
                    "destination account already has different federation custody",
                ));
            }
        } else {
            if custody.has_marker(destination_account_id)? {
                return Err(Error::engine(
                    "destination federation custody vault is missing; state is corrupt",
                ));
            }
            custody.ensure_marker(destination_account_id)?;
            let pending = custody.stage_handoff(
                destination_account_id,
                &bundle,
                destination_installation_id,
                destination_endpoint_origin,
                actor,
                now,
            )?;
            custody.write_vault(&pending)?;
            transition_request(&pending)?
        }
    };
    decrypted.zeroize();
    finish_directory_attempt(
        custody,
        destination_account_id,
        destination_database,
        request,
        directory,
        actor,
        now,
    )
    .await
}

pub async fn retry_pending_handoff(
    custody: &FileFederationCustody,
    account_id: &str,
    database_path: &Path,
    directory: &dyn FederationDirectory,
    actor: &str,
    now: &str,
) -> Result<AdoptionHandoffResult> {
    parse_time(now, "handoff retry time")?;
    let request = {
        let _guard = custody.lock()?;
        let vault = custody.load_valid(account_id)?;
        if vault.state != PrincipalState::PendingHandoff {
            return Err(Error::engine("principal has no pending handoff"));
        }
        transition_request(&vault)?
    };
    finish_directory_attempt(
        custody,
        account_id,
        database_path,
        request,
        directory,
        actor,
        now,
    )
    .await
}

async fn finish_directory_attempt(
    custody: &FileFederationCustody,
    account_id: &str,
    database_path: &Path,
    request: RootTransitionRequest,
    directory: &dyn FederationDirectory,
    actor: &str,
    now: &str,
) -> Result<AdoptionHandoffResult> {
    let outcome = directory.compare_and_swap(&request).await?;
    if let DirectoryCommit::Attested(evidence) = &outcome {
        validate_directory_attestation(evidence, &request)?;
        directory.verify_attestation(evidence).await?;
    }
    let _guard = custody.lock()?;
    let mut vault = custody.load_valid(account_id)?;
    let pending = vault
        .pending
        .as_ref()
        .ok_or_else(|| Error::engine("pending handoff metadata disappeared"))?;
    if pending.handoff_id != request.handoff_id {
        return Err(Error::engine(
            "pending handoff changed during directory request",
        ));
    }
    match outcome {
        DirectoryCommit::Unavailable => {
            push_audit(
                &mut vault,
                "handoff.directory_pending",
                vec![],
                Some(request.handoff_id.clone()),
                actor,
                "directory unavailable; retry is safe",
                "pending",
                now,
            );
            custody.write_vault(&vault)?;
            Ok(AdoptionHandoffResult {
                database_path: database_path.to_path_buf(),
                principal: public_view(&vault),
                handoff_id: request.handoff_id,
                directory_state: PrincipalState::PendingHandoff,
                authority_evidence: None,
            })
        }
        DirectoryCommit::VersionConflict {
            current_document_version,
        } => {
            push_audit(
                &mut vault,
                "handoff.version_conflict",
                vec![],
                Some(request.handoff_id),
                actor,
                &format!("directory is already at version {current_document_version}"),
                "rejected",
                now,
            );
            custody.write_vault(&vault)?;
            Err(Error::engine(
                "federation handoff version conflict: another adoption or lifecycle mutation won",
            ))
        }
        DirectoryCommit::Attested(evidence) => {
            let pending = vault.pending.take().unwrap();
            let old = pending.old_key_kids.into_iter().collect::<BTreeSet<_>>();
            let decrypt_until = pending.decrypt_only_until;
            let mut retained = Vec::with_capacity(vault.keys.len());
            for mut key in vault.keys.drain(..) {
                if !old.contains(&key.public.jwk.kid) {
                    retained.push(key);
                } else if key.public.purpose == KeyPurpose::Encryption {
                    key.public.status = KeyStatus::DecryptOnly;
                    key.public.not_after = Some(decrypt_until.clone());
                    retained.push(key);
                } else {
                    key.public.status = KeyStatus::Retired;
                    key.public.not_after = Some(now.to_owned());
                    vault.historical_keys.push(key.public);
                }
            }
            vault.keys = retained;
            vault.state = PrincipalState::Active;
            vault.document_version = evidence.document_version;
            vault.last_attestation = Some(evidence.clone());
            let affected = vault
                .keys
                .iter()
                .filter(|key| key.public.status == KeyStatus::Active)
                .map(|key| key.public.jwk.kid.clone())
                .collect();
            push_audit(
                &mut vault,
                "handoff.committed",
                affected,
                Some(request.handoff_id.clone()),
                actor,
                "directory attested root transition and retired source installation",
                "succeeded",
                now,
            );
            if let Some(last) = vault.audit.last_mut() {
                last.document_digest = Some(evidence.document_digest.clone());
            }
            custody.write_vault(&vault)?;
            Ok(AdoptionHandoffResult {
                database_path: database_path.to_path_buf(),
                principal: public_view(&vault),
                handoff_id: request.handoff_id,
                directory_state: PrincipalState::Active,
                authority_evidence: Some(evidence),
            })
        }
    }
}

impl FileFederationCustody {
    #[allow(clippy::too_many_arguments)]
    fn stage_handoff(
        &self,
        destination_account_id: &str,
        bundle: &IdentityBundle,
        destination_installation_id: &str,
        destination_endpoint_origin: &str,
        actor: &str,
        now: &str,
    ) -> Result<VaultFile> {
        let mut imported = vec![];
        for key in &bundle.keys {
            let mut secret =
                Zeroizing::new(decode_array::<32>(&key.secret, "exported private key")?);
            if public_jwk(&secret, key.public.purpose)? != key.public.jwk {
                return Err(Error::engine(
                    "exported private key does not match its public JWK",
                ));
            }
            let wrapped = self.wrap_secret(
                destination_account_id,
                &bundle.network_id,
                &bundle.principal_id,
                &key.public,
                &secret,
            )?;
            secret.zeroize();
            imported.push(StoredKey {
                public: key.public.clone(),
                wrapped,
                generation: key.generation,
            });
        }
        let old_root = imported
            .iter()
            .find(|key| {
                key.public.purpose == KeyPurpose::Root && key.public.status == KeyStatus::Active
            })
            .ok_or_else(|| Error::engine("identity bundle has no active root"))?;
        let old_root_secret = self.unwrap_key(
            &VaultFile {
                version: VAULT_VERSION,
                account_id: destination_account_id.to_owned(),
                network_id: bundle.network_id.clone(),
                principal_id: bundle.principal_id.clone(),
                state: PrincipalState::PendingHandoff,
                document_version: bundle.document_version,
                keys: vec![],
                historical_keys: vec![],
                pending: None,
                public_history: vec![],
                last_attestation: None,
                audit: vec![],
                integrity: String::new(),
            },
            old_root,
        )?;
        let old_root_jwk = old_root.public.jwk.clone();
        let old_root_kid = old_root_jwk.kid.clone();
        let old_key_kids = imported
            .iter()
            .map(|key| key.public.jwk.kid.clone())
            .collect();
        let mut new_keys = vec![];
        for purpose in [
            KeyPurpose::Root,
            KeyPurpose::Signing,
            KeyPurpose::Encryption,
            KeyPurpose::Installation,
        ] {
            let old_generation = imported
                .iter()
                .filter(|key| key.public.purpose == purpose)
                .map(|key| key.generation)
                .max()
                .unwrap_or(0);
            new_keys.push(self.generate_stored_key(
                destination_account_id,
                &bundle.network_id,
                &bundle.principal_id,
                purpose,
                old_generation + 1,
                now,
                (purpose == KeyPurpose::Installation).then_some(destination_installation_id),
                (purpose == KeyPurpose::Installation).then_some(destination_endpoint_origin),
            )?);
        }
        let new_root = new_keys
            .iter()
            .find(|key| key.public.purpose == KeyPurpose::Root)
            .unwrap();
        let shell = VaultFile {
            version: VAULT_VERSION,
            account_id: destination_account_id.to_owned(),
            network_id: bundle.network_id.clone(),
            principal_id: bundle.principal_id.clone(),
            state: PrincipalState::PendingHandoff,
            document_version: bundle.document_version,
            keys: vec![],
            historical_keys: bundle.public_history.clone(),
            pending: None,
            audit: vec![],
            public_history: vec![],
            last_attestation: None,
            integrity: String::new(),
        };
        let new_root_secret = self.unwrap_key(&shell, new_root)?;
        let statement = json!({
            "statement_type": "native.root-transition",
            "protocol_version": "1.0",
            "principal": {"network_id": bundle.network_id, "principal_id": bundle.principal_id},
            "old_root_jwk": old_root_jwk,
            "new_root_jwk": new_root.public.jwk,
            "last_old_root_document_version": bundle.document_version,
            "activation_time": now,
            "reason": "cloud_eject_handoff",
            "handoff_id": bundle.handoff_id,
        });
        let transition = RootTransition {
            old_root_signature: detached_jws_with_secret(
                &old_root.public.jwk,
                "native-root-transition+jws",
                &statement,
                &old_root_secret,
            )?,
            new_root_signature: detached_jws_with_secret(
                &new_root.public.jwk,
                "native-root-transition+jws",
                &statement,
                &new_root_secret,
            )?,
            statement,
        };
        let new_root_kid = new_root.public.jwk.kid.clone();
        imported.extend(new_keys);
        let mut vault = VaultFile {
            version: VAULT_VERSION,
            account_id: destination_account_id.to_owned(),
            network_id: bundle.network_id.clone(),
            principal_id: bundle.principal_id.clone(),
            state: PrincipalState::PendingHandoff,
            document_version: bundle.document_version,
            keys: imported,
            historical_keys: bundle.public_history.clone(),
            pending: Some(PendingHandoff {
                handoff_id: bundle.handoff_id.clone(),
                expected_document_version: bundle.document_version,
                source_installation_id: bundle.source_installation_id.clone(),
                old_root_kid,
                new_root_kid,
                transition,
                old_key_kids,
                decrypt_only_until: (parse_time(now, "adoption time")?
                    + Duration::days(MAX_ENVELOPE_LIFETIME_DAYS))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                projected_principal_document: Value::Null,
            }),
            public_history: vec![bundle.source_principal_document.clone()],
            last_attestation: None,
            audit: vec![],
            integrity: String::new(),
        };
        push_audit(
            &mut vault,
            "handoff.staged",
            vec![],
            Some(bundle.handoff_id.clone()),
            actor,
            "identity bundle decrypted into quarantine and fresh keys generated",
            "pending",
            now,
        );
        let projected = project_handoff_vault(&vault)?;
        let signed =
            build_signed_principal_document(self, &projected, parse_time(now, "adoption time")?)?;
        vault
            .pending
            .as_mut()
            .expect("pending handoff was constructed")
            .projected_principal_document = signed;
        Ok(vault)
    }
}

fn transition_request(vault: &VaultFile) -> Result<RootTransitionRequest> {
    let pending = vault
        .pending
        .as_ref()
        .ok_or_else(|| Error::engine("missing pending handoff"))?;
    let principal = public_view(&project_handoff_vault(vault)?);
    Ok(RootTransitionRequest {
        handoff_id: pending.handoff_id.clone(),
        expected_document_version: pending.expected_document_version,
        principal,
        transition: pending.transition.clone(),
        source_installation_id: pending.source_installation_id.clone(),
        projected_principal_document: pending.projected_principal_document.clone(),
    })
}

fn project_handoff_vault(vault: &VaultFile) -> Result<VaultFile> {
    let pending = vault
        .pending
        .as_ref()
        .ok_or_else(|| Error::engine("missing pending handoff"))?;
    let old = pending.old_key_kids.iter().collect::<BTreeSet<_>>();
    let activation = pending.transition.statement["activation_time"]
        .as_str()
        .ok_or_else(|| Error::engine("handoff transition activation time is missing"))?;
    let mut projected = vault.clone();
    projected.state = PrincipalState::Active;
    projected.document_version = pending.expected_document_version + 1;
    projected.pending = None;
    for key in &mut projected.keys {
        if old.contains(&key.public.jwk.kid) {
            if key.public.purpose == KeyPurpose::Encryption {
                key.public.status = KeyStatus::DecryptOnly;
                key.public.not_after = Some(pending.decrypt_only_until.clone());
            } else {
                key.public.status = KeyStatus::Retired;
                key.public.not_after = Some(activation.to_owned());
            }
        }
    }
    Ok(projected)
}

fn validate_directory_attestation(
    evidence: &DirectoryAttestation,
    request: &RootTransitionRequest,
) -> Result<()> {
    validate_uuid(&evidence.handoff_id, "authority handoff id")?;
    validate_sha256_digest(&evidence.document_digest, "authority document digest")?;
    verify_projected_principal_document(request)?;
    let document = request.projected_principal_document["document"]
        .as_object()
        .ok_or_else(|| Error::engine("projected principal document is missing"))?;
    let digest = digest_value(&Value::Object(document.clone()))?;
    if evidence.handoff_id != request.handoff_id
        || evidence.document_version != request.expected_document_version + 1
        || evidence.document_digest != digest
        || evidence.authority_attestation.is_null()
    {
        return Err(Error::engine(
            "directory attestation does not bind the requested handoff document",
        ));
    }
    Ok(())
}

fn verify_projected_principal_document(request: &RootTransitionRequest) -> Result<()> {
    let signed = &request.projected_principal_document;
    let document = signed
        .get("document")
        .ok_or_else(|| Error::engine("projected principal document is missing"))?;
    if document["network_id"] != request.principal.network_id
        || document["principal_id"] != request.principal.principal_id
        || document["document_version"] != request.expected_document_version + 1
    {
        return Err(Error::engine(
            "projected principal document identity or version is invalid",
        ));
    }
    let new_root: PublicJwk =
        serde_json::from_value(request.transition.statement["new_root_jwk"].clone())
            .map_err(|_| Error::engine("root transition has no valid new root"))?;
    let active_root_matches = document["root_keys"].as_array().is_some_and(|roots| {
        roots.iter().any(|root| {
            root["jwk"] == serde_json::to_value(&new_root).unwrap_or(Value::Null)
                && root["status"] == "active"
        })
    });
    if !active_root_matches {
        return Err(Error::engine(
            "projected principal document does not activate the transitioned root",
        ));
    }
    let operational = document["operational_keys"]
        .as_array()
        .ok_or_else(|| Error::engine("projected operational keys are missing"))?;
    let mut active_signing = None;
    let mut active_encryption = 0usize;
    for key in operational {
        let statement = &key["authorization"]["statement"];
        let signature = key["authorization"]["signature"]
            .as_str()
            .ok_or_else(|| Error::engine("projected operational authorization is missing"))?;
        if statement["key"]["jwk"] != key["jwk"] || statement["key"]["status"] != key["status"] {
            return Err(Error::engine(
                "projected operational authorization is not bound to its key",
            ));
        }
        verify_detached_jws(
            &new_root,
            "native-key-authorization+jws",
            statement,
            signature,
        )?;
        if key["status"] == "active" && key["purpose"] == "signing" {
            if active_signing.is_some() {
                return Err(Error::engine(
                    "projected document has duplicate active signing keys",
                ));
            }
            active_signing = Some(serde_json::from_value::<PublicJwk>(key["jwk"].clone())?);
        }
        if key["status"] == "active" && key["purpose"] == "encryption" {
            active_encryption += 1;
        }
    }
    let active_signing = active_signing
        .ok_or_else(|| Error::engine("projected document has no active signing key"))?;
    if active_encryption != 1 {
        return Err(Error::engine(
            "projected document must have one active encryption key",
        ));
    }
    let installations = document["installations"]
        .as_array()
        .ok_or_else(|| Error::engine("projected installations are missing"))?;
    let mut active_installations = 0usize;
    for installation in installations {
        let statement = &installation["authorization"]["statement"];
        let signature = installation["authorization"]["signature"]
            .as_str()
            .ok_or_else(|| Error::engine("projected installation authorization is missing"))?;
        if statement["installation"]["jwk"] != installation["jwk"]
            || statement["installation"]["status"] != installation["status"]
        {
            return Err(Error::engine(
                "projected installation authorization is not bound to its key",
            ));
        }
        verify_detached_jws(
            &active_signing,
            "native-key-authorization+jws",
            statement,
            signature,
        )?;
        if installation["status"] == "active" {
            active_installations += 1;
        }
    }
    if active_installations != 1 {
        return Err(Error::engine(
            "projected document must have one active installation",
        ));
    }
    let principal_signature = signed["principal_signature"]
        .as_str()
        .ok_or_else(|| Error::engine("projected principal signature is missing"))?;
    verify_detached_jws(
        &active_signing,
        "native-principal+jws",
        document,
        principal_signature,
    )
}

fn validate_bundle(
    manifest: &EjectManifestBody,
    bundle: &IdentityBundle,
    destination_account_id: &str,
) -> Result<()> {
    if bundle.version != IDENTITY_BUNDLE_VERSION
        || bundle.network_id != manifest.principal_network_id
        || bundle.principal_id != manifest.principal_id
        || bundle.document_version != manifest.expected_document_version
        || bundle.source_installation_id != manifest.source_installation_id
        || bundle.handoff_id != manifest.handoff_id
        || bundle.account_id != manifest.exporter_account_id
    {
        return Err(Error::engine(
            "eject identity bundle does not match its signed manifest",
        ));
    }
    validate_nonempty(destination_account_id, "destination account id")?;
    let mut purposes = BTreeSet::new();
    let mut kids = BTreeSet::new();
    for key in &bundle.keys {
        if key.public.status != KeyStatus::Active
            || key.generation == 0
            || !purposes.insert(key.public.purpose)
            || !kids.insert(key.public.jwk.kid.clone())
        {
            return Err(Error::engine(
                "eject identity bundle active key set is invalid",
            ));
        }
        validate_public_key_record(&key.public)?;
    }
    for key in &bundle.public_history {
        if key.status == KeyStatus::Active || !kids.insert(key.jwk.kid.clone()) {
            return Err(Error::engine(
                "eject identity bundle public history is invalid",
            ));
        }
        validate_public_key_record(key)?;
    }
    for required in [
        KeyPurpose::Root,
        KeyPurpose::Signing,
        KeyPurpose::Encryption,
        KeyPurpose::Installation,
    ] {
        if !purposes.contains(&required) {
            return Err(Error::engine(
                "eject identity bundle is missing a required key purpose",
            ));
        }
    }
    let source_document = bundle
        .source_principal_document
        .get("document")
        .ok_or_else(|| Error::engine("identity bundle has no source principal document"))?;
    if source_document["network_id"] != manifest.principal_network_id
        || source_document["principal_id"] != manifest.principal_id
        || source_document["document_version"] != manifest.expected_document_version
    {
        return Err(Error::engine(
            "identity bundle source principal document does not match the manifest",
        ));
    }
    let signature = bundle.source_principal_document["principal_signature"]
        .as_str()
        .ok_or_else(|| Error::engine("identity bundle source principal signature is missing"))?;
    verify_detached_jws(
        &manifest.exporter_signing_jwk,
        "native-principal+jws",
        source_document,
        signature,
    )?;
    Ok(())
}

fn validate_manifest(signed: &SignedEjectManifest, now: DateTime<Utc>) -> Result<()> {
    let manifest = &signed.manifest;
    if manifest.package_type != "native.federation.eject"
        || manifest.package_version != EJECT_PACKAGE_VERSION
        || manifest.profile != FEDERATION_PROFILE
        || manifest.expected_document_version == 0
    {
        return Err(Error::engine(
            "unsupported or malformed Native eject package",
        ));
    }
    validate_uuid(&manifest.handoff_id, "handoff id")?;
    validate_uuid(&manifest.source_installation_id, "source installation id")?;
    let created = parse_time(&manifest.created_at, "eject creation time")?;
    let expires = parse_time(&manifest.expires_at, "eject expiry time")?;
    if expires <= created || now >= expires {
        return Err(Error::engine("Native eject package is expired"));
    }
    if manifest.identity_bundle.size_bytes > MAX_IDENTITY_BUNDLE_BYTES {
        return Err(Error::engine("Native eject identity bundle is too large"));
    }
    validate_sha256_digest(&manifest.database.sha256, "eject database digest")?;
    validate_sha256_digest(
        &manifest.identity_bundle.sha256,
        "eject identity bundle digest",
    )?;
    Ok(())
}

/// Verify a package manifest and extract only its content component. This is
/// used by the existing crash-safe database adoption planner; it never opens
/// or returns the encrypted identity bundle.
pub fn extract_eject_database(
    package: &Path,
    destination: &Path,
    now: &str,
) -> Result<SignedEjectManifest> {
    let (signed, database_offset, _) = read_package_header(package)?;
    validate_manifest(&signed, parse_time(now, "eject extraction time")?)?;
    let value = serde_json::to_value(&signed.manifest)?;
    verify_detached_jws(
        &signed.manifest.exporter_signing_jwk,
        "native-eject-manifest+jws",
        &value,
        &signed.signature,
    )?;
    stage_database_component(
        package,
        database_offset,
        signed.manifest.database.size_bytes,
        destination,
        &signed.manifest.database.sha256,
    )?;
    Ok(signed)
}

fn component(bytes: &[u8]) -> EjectComponent {
    EjectComponent {
        sha256: format!("sha-256:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))),
        size_bytes: bytes.len() as u64,
    }
}

fn digest_value(value: &Value) -> Result<String> {
    Ok(format!(
        "sha-256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(jcs(value)?))
    ))
}

fn digest_path(path: &Path) -> Result<EjectComponent> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(
            "digest input must be a regular non-symlink file",
        ));
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        size += read as u64;
    }
    Ok(EjectComponent {
        sha256: format!("sha-256:{}", URL_SAFE_NO_PAD.encode(hash.finalize())),
        size_bytes: size,
    })
}

fn write_package(
    destination: &Path,
    database: &Path,
    encrypted_bundle: &[u8],
    signed: &SignedEjectManifest,
) -> Result<()> {
    if destination.extension().and_then(|value| value.to_str()) != Some("native-eject") {
        return Err(Error::engine(
            "eject package filename must end in .native-eject",
        ));
    }
    let manifest = serde_json::to_vec(signed)?;
    if manifest.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::engine("eject manifest is too large"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| Error::engine("eject package destination has no parent"))?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::engine(
            "eject package parent must be a regular non-symlink directory",
        ));
    }
    let temporary = destination.with_extension(format!("partial-{}", Uuid::new_v4()));
    let written = (|| -> Result<()> {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        set_owner_only_file(&output)?;
        output.write_all(EJECT_MAGIC)?;
        output.write_all(&(manifest.len() as u64).to_be_bytes())?;
        output.write_all(&signed.manifest.database.size_bytes.to_be_bytes())?;
        output.write_all(&(encrypted_bundle.len() as u64).to_be_bytes())?;
        output.write_all(&manifest)?;
        std::io::copy(&mut File::open(database)?, &mut output)?;
        output.write_all(encrypted_bundle)?;
        output.sync_all()?;
        Ok(())
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = std::fs::hard_link(&temporary, destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = sync_parent(destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    std::fs::remove_file(&temporary)?;
    sync_parent(destination)?;
    Ok(())
}

fn read_package_header(path: &Path) -> Result<(SignedEjectManifest, u64, u64)> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine("Native eject package must be a regular file"));
    }
    let mut file = File::open(path)?;
    let mut magic = [0u8; 16];
    file.read_exact(&mut magic)?;
    if &magic != EJECT_MAGIC {
        return Err(Error::engine(
            "Native eject package magic/version is invalid",
        ));
    }
    let manifest_len = read_u64(&mut file)?;
    let database_len = read_u64(&mut file)?;
    let bundle_len = read_u64(&mut file)?;
    if manifest_len == 0
        || manifest_len > MAX_MANIFEST_BYTES
        || bundle_len > MAX_IDENTITY_BUNDLE_BYTES
    {
        return Err(Error::engine(
            "Native eject package component length is invalid",
        ));
    }
    let header_len = (EJECT_MAGIC.len() as u64)
        .checked_add(24)
        .ok_or_else(|| Error::engine("Native eject package framing overflow"))?;
    let database_offset = header_len
        .checked_add(manifest_len)
        .ok_or_else(|| Error::engine("Native eject package framing overflow"))?;
    let bundle_offset = database_offset
        .checked_add(database_len)
        .ok_or_else(|| Error::engine("Native eject package framing overflow"))?;
    let expected = bundle_offset
        .checked_add(bundle_len)
        .ok_or_else(|| Error::engine("Native eject package framing overflow"))?;
    if expected != metadata.len() {
        return Err(Error::engine(
            "Native eject package framing length is invalid",
        ));
    }
    let mut bytes = vec![0u8; manifest_len as usize];
    file.read_exact(&mut bytes)?;
    let signed: SignedEjectManifest = serde_json::from_slice(&bytes)?;
    if signed.manifest.database.size_bytes != database_len
        || signed.manifest.identity_bundle.size_bytes != bundle_len
    {
        return Err(Error::engine(
            "Native eject package header disagrees with manifest",
        ));
    }
    Ok((signed, database_offset, bundle_offset))
}

fn read_u64(file: &mut File) -> Result<u64> {
    let mut bytes = [0u8; 8];
    file.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

fn stage_database_component(
    package: &Path,
    offset: u64,
    size: u64,
    destination: &Path,
    expected_digest: &str,
) -> Result<()> {
    match std::fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::engine(
                    "adoption database destination must be a regular non-symlink file",
                ));
            }
            let existing = digest_path(destination)?;
            if existing.size_bytes == size && existing.sha256 == expected_digest {
                return Ok(());
            }
            return Err(Error::engine(
                "adoption database destination already exists with different bytes",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = destination
        .parent()
        .ok_or_else(|| Error::engine("adoption destination has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(Error::engine(
            "adoption database parent must be a regular non-symlink directory",
        ));
    }
    let temporary = destination.with_extension(format!("partial-{}", Uuid::new_v4()));
    let staged = (|| -> Result<()> {
        let mut source = File::open(package)?;
        source.seek(SeekFrom::Start(offset))?;
        let mut target = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        set_owner_only_file(&target)?;
        let copied = std::io::copy(&mut source.take(size), &mut target)?;
        target.sync_all()?;
        let digest = digest_path(&temporary)?;
        if copied != size || digest.size_bytes != size || digest.sha256 != expected_digest {
            return Err(Error::engine(
                "eject database component failed digest verification",
            ));
        }
        Ok(())
    })();
    if let Err(error) = staged {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = std::fs::hard_link(&temporary, destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = sync_parent(destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    std::fs::remove_file(&temporary)?;
    sync_parent(destination)?;
    Ok(())
}

fn verify_existing_database_component(
    destination: &Path,
    size: u64,
    expected_digest: &str,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::engine("identity handoff requires an already-adopted database")
        } else {
            error.into()
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(
            "identity handoff database must be a regular non-symlink file",
        ));
    }
    let actual = digest_path(destination)?;
    if actual.size_bytes != size || actual.sha256 != expected_digest {
        return Err(Error::engine(
            "already-adopted database does not match the signed eject manifest",
        ));
    }
    Ok(())
}

fn read_component(path: &Path, offset: u64, size: u64, maximum: u64) -> Result<Vec<u8>> {
    if size > maximum {
        return Err(Error::engine("eject component exceeds its size limit"));
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::engine("eject component offset overflow"))?;
    if end > std::fs::symlink_metadata(path)?.len() {
        return Err(Error::engine("eject component exceeds package framing"));
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0u8; size as usize];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
