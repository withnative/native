use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::crypto::{
    parse_ijson, sha256_digest, verify_compact, verify_detached, Ed25519Jwk, PROFILE,
};
use super::relay::RelayError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct PrincipalAddress {
    pub network_id: String,
    pub principal_id: String,
}

impl PrincipalAddress {
    pub fn storage_key(&self) -> String {
        format!("{}/{}", self.network_id, self.principal_id)
    }

    pub fn is_valid(&self) -> bool {
        super::address::valid_principal_address(&self.network_id, &self.principal_id)
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedCaller {
    pub principal: PrincipalAddress,
    pub installation_id: Option<String>,
    pub key_id: String,
    pub request_id: String,
    pub nonce: String,
    pub body_digest: String,
}

#[derive(Debug, Clone)]
pub enum RecipientAuthorization {
    Active,
    Rejected(&'static str),
}

pub trait DirectoryAuthority: Send + Sync + 'static {
    fn verify_request(
        &self,
        authorization: Option<&str>,
        operation: &str,
        audience: &str,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedCaller, RelayError>;

    fn verify_envelope_sender(
        &self,
        wrapper: &Value,
        now: DateTime<Utc>,
    ) -> Result<PrincipalAddress, RelayError>;

    fn authorize_recipient(
        &self,
        principal: &PrincipalAddress,
        encryption_key_id: &str,
        now: DateTime<Utc>,
    ) -> Result<RecipientAuthorization, RelayError>;
}

#[derive(Debug, Clone)]
struct SigningRecord {
    principal: PrincipalAddress,
    installation_id: Option<String>,
    jwk: Ed25519Jwk,
    status: String,
    purpose: KeyPurpose,
    scopes: HashSet<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyPurpose {
    Root,
    OperationalSigning,
    Installation,
}

#[derive(Debug, Clone)]
struct EncryptionRecord {
    status: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct PrincipalRecord {
    fresh_until: DateTime<Utc>,
    hard_expires_at: DateTime<Utc>,
    active: bool,
    encryption_keys: HashMap<String, EncryptionRecord>,
}

/// A deliberately injected, **preverified development adapter**.
///
/// This parser does not authenticate principal-document wrappers. Its caller
/// must establish the bytes through a separately authenticated authority
/// channel before construction. The standalone binary permits this adapter on
/// loopback by default and requires an explicit dangerous opt-in elsewhere.
/// Operated deployments should implement [`DirectoryAuthority`] with
/// descriptor/root verification and authenticated refresh.
#[derive(Debug, Clone)]
pub struct PreverifiedSnapshotAuthority {
    signing: HashMap<String, SigningRecord>,
    principals: HashMap<String, PrincipalRecord>,
}

impl PreverifiedSnapshotAuthority {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, RelayError> {
        let bytes = fs::read(path).map_err(|error| {
            RelayError::directory_unavailable(format!("authority snapshot: {error}"))
        })?;
        Self::from_slice(&bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, RelayError> {
        let root = parse_ijson(bytes, "invalid_request")?;
        let principals = root
            .get("principals")
            .and_then(Value::as_object)
            .ok_or_else(|| RelayError::invalid_request("authority snapshot has no principals"))?;
        let mut authority = Self {
            signing: HashMap::new(),
            principals: HashMap::new(),
        };
        let mut encryption_kids_seen = HashSet::new();

        for wrapper in principals.values() {
            let document = wrapper
                .get("document")
                .and_then(Value::as_object)
                .ok_or_else(|| RelayError::invalid_request("principal wrapper has no document"))?;
            if document.get("profile").and_then(Value::as_str) != Some(PROFILE) {
                continue;
            }
            let principal = PrincipalAddress {
                network_id: required_string(document, "network_id")?.to_owned(),
                principal_id: required_string(document, "principal_id")?.to_owned(),
            };
            if !principal.is_valid() {
                return Err(RelayError::invalid_request(
                    "authority snapshot has an invalid principal address",
                ));
            }
            let principal_key = principal.storage_key();
            if authority.principals.contains_key(&principal_key) {
                return Err(RelayError::invalid_request(
                    "authority snapshot repeats a principal address",
                ));
            }
            let fresh_until = timestamp(required_string(document, "fresh_until")?)?;
            let hard_expires_at = timestamp(required_string(document, "hard_expires_at")?)?;
            let active = document
                .get("status")
                .and_then(Value::as_str)
                .is_none_or(|status| status == "active");
            let mut encryption_keys = HashMap::new();

            for key in required_array(document, "root_keys")? {
                authority.insert_signing(&principal, None, key, KeyPurpose::Root, &[])?;
            }
            for key in required_array(document, "operational_keys")? {
                let purpose = required_string_obj(key, "purpose")?;
                if purpose == "signing" {
                    authority.insert_signing(
                        &principal,
                        None,
                        key,
                        KeyPurpose::OperationalSigning,
                        &["relay.submit", "relay.delivery.get"],
                    )?;
                } else if purpose == "encryption" {
                    let jwk = key
                        .get("jwk")
                        .and_then(Value::as_object)
                        .ok_or_else(|| RelayError::invalid_request("key has no JWK"))?;
                    let kid = required_string(jwk, "kid")?.to_owned();
                    if !encryption_kids_seen.insert(kid.clone()) {
                        return Err(RelayError::invalid_request(
                            "authority snapshot repeats an encryption kid",
                        ));
                    }
                    encryption_keys.insert(
                        kid,
                        EncryptionRecord {
                            status: required_string_obj(key, "status")?.to_owned(),
                            not_before: timestamp(required_string_obj(key, "not_before")?)?,
                            not_after: timestamp(required_string_obj(key, "not_after")?)?,
                        },
                    );
                }
            }
            for installation in required_array(document, "installations")? {
                let installation_id = required_string_obj(installation, "installation_id")?;
                let scopes = installation
                    .get("scopes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| RelayError::invalid_request("installation has no scopes"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>();
                authority.insert_signing(
                    &principal,
                    Some(installation_id.to_owned()),
                    installation,
                    KeyPurpose::Installation,
                    &scopes,
                )?;
            }
            authority.principals.insert(
                principal_key,
                PrincipalRecord {
                    fresh_until,
                    hard_expires_at,
                    active,
                    encryption_keys,
                },
            );
        }
        if authority.principals.is_empty() {
            return Err(RelayError::invalid_request(
                "authority snapshot contains no supported principals",
            ));
        }
        Ok(authority)
    }

    fn insert_signing(
        &mut self,
        principal: &PrincipalAddress,
        installation_id: Option<String>,
        value: &Value,
        purpose: KeyPurpose,
        scopes: &[&str],
    ) -> Result<(), RelayError> {
        let jwk: Ed25519Jwk = serde_json::from_value(
            value
                .get("jwk")
                .cloned()
                .ok_or_else(|| RelayError::invalid_request("key has no JWK"))?,
        )
        .map_err(|_| RelayError::invalid_request("invalid signing JWK"))?;
        let status = required_string_obj(value, "status")?.to_owned();
        let not_before = value
            .get("not_before")
            .and_then(Value::as_str)
            .map(timestamp)
            .transpose()?;
        let not_after = value
            .get("not_after")
            .and_then(Value::as_str)
            .map(timestamp)
            .transpose()?;
        if self.signing.contains_key(&jwk.kid) {
            return Err(RelayError::invalid_request(
                "authority snapshot repeats a signing kid",
            ));
        }
        self.signing.insert(
            jwk.kid.clone(),
            SigningRecord {
                principal: principal.clone(),
                installation_id,
                jwk,
                status,
                purpose,
                scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                not_before,
                not_after,
            },
        );
        Ok(())
    }

    fn fresh_principal(
        &self,
        principal: &PrincipalAddress,
        now: DateTime<Utc>,
    ) -> Result<&PrincipalRecord, RelayError> {
        let record = self
            .principals
            .get(&principal.storage_key())
            .ok_or_else(|| RelayError::unknown_principal("principal is not registered"))?;
        if !record.active {
            return Err(RelayError::principal_revoked("principal is revoked"));
        }
        if now >= record.fresh_until {
            let detail = if now >= record.hard_expires_at {
                "principal authority state is expired"
            } else {
                "principal authority state is stale"
            };
            return Err(RelayError::directory_unavailable(detail));
        }
        Ok(record)
    }
}

impl DirectoryAuthority for PreverifiedSnapshotAuthority {
    fn verify_request(
        &self,
        authorization: Option<&str>,
        operation: &str,
        audience: &str,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedCaller, RelayError> {
        let compact = authorization
            .and_then(|value| value.strip_prefix("NativeJWS "))
            .ok_or_else(|| RelayError::unauthorized("missing request proof"))?;
        let protected = compact
            .split('.')
            .next()
            .ok_or_else(|| RelayError::unauthorized("invalid request proof"))?;
        let header_bytes = super::crypto::decode_base64url(protected, "unauthorized")?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|_| RelayError::unauthorized("invalid request proof header"))?;
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| RelayError::unauthorized("request proof has no kid"))?;
        let signing = self
            .signing
            .get(kid)
            .ok_or_else(|| RelayError::unauthorized("unknown request proof key"))?;
        let payload = verify_compact(compact, &signing.jwk, "native-request-proof+jws")?;
        let object = payload
            .as_object()
            .ok_or_else(|| RelayError::unauthorized("invalid request proof payload"))?;
        const REQUEST_PROOF_FIELDS: [&str; 10] = [
            "protocol_version",
            "operation",
            "aud",
            "principal",
            "installation_id",
            "request_id",
            "body_digest",
            "created_at",
            "expires_at",
            "nonce",
        ];
        if object.len() != REQUEST_PROOF_FIELDS.len()
            || REQUEST_PROOF_FIELDS
                .iter()
                .any(|field| !object.contains_key(*field))
        {
            return Err(RelayError::unauthorized(
                "request proof member closure mismatch",
            ));
        }
        if required_string(object, "protocol_version")? != "1.0"
            || required_string(object, "operation")? != operation
            || required_string(object, "aud")? != audience
            || required_string(object, "body_digest")? != sha256_digest(body)
        {
            return Err(RelayError::unauthorized("request proof scope mismatch"));
        }
        let principal: PrincipalAddress = serde_json::from_value(
            object
                .get("principal")
                .cloned()
                .ok_or_else(|| RelayError::unauthorized("request proof has no principal"))?,
        )
        .map_err(|_| RelayError::unauthorized("invalid request proof principal"))?;
        let installation_id = match object.get("installation_id") {
            Some(Value::Null) => None,
            Some(Value::String(value)) => Some(value.to_owned()),
            _ => {
                return Err(RelayError::unauthorized(
                    "invalid request proof installation",
                ))
            }
        };
        if principal != signing.principal || installation_id != signing.installation_id {
            return Err(RelayError::unauthorized("request proof identity mismatch"));
        }
        self.fresh_principal(&principal, now)?;
        if signing.status == "revoked" {
            return Err(RelayError::key_revoked("request proof key is revoked"));
        }
        if signing.status != "active"
            || signing.not_before.is_some_and(|time| now < time)
            || signing.not_after.is_some_and(|time| now >= time)
        {
            return Err(RelayError::forbidden("request proof key is not active"));
        }
        let allowed = match signing.purpose {
            KeyPurpose::OperationalSigning => {
                matches!(operation, "relay.submit" | "relay.delivery.get")
            }
            KeyPurpose::Installation => signing.scopes.contains(operation),
            KeyPurpose::Root => false,
        };
        if !allowed {
            return Err(RelayError::forbidden("key lacks operation scope"));
        }
        let created_at_raw = required_string(object, "created_at")?;
        let expires_at_raw = required_string(object, "expires_at")?;
        let created_at = timestamp(created_at_raw)
            .map_err(|_| RelayError::unauthorized("invalid request proof time"))?;
        let expires_at = timestamp(expires_at_raw)
            .map_err(|_| RelayError::unauthorized("invalid request proof time"))?;
        if created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) != created_at_raw
            || expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) != expires_at_raw
            || expires_at <= created_at
            || expires_at - created_at > chrono::Duration::minutes(5)
            || now < created_at
            || now >= expires_at
        {
            return Err(RelayError::unauthorized(
                "request proof is outside its validity window",
            ));
        }
        let request_id = required_string(object, "request_id")?;
        let nonce = required_string(object, "nonce")?;
        if !uuid::Uuid::parse_str(request_id).is_ok_and(|request_id_value| {
            request_id_value.get_version_num() == 4 && request_id_value.to_string() == request_id
        }) || super::crypto::decode_base64url(nonce, "unauthorized")?.len() != 16
        {
            return Err(RelayError::unauthorized(
                "invalid request proof identifiers",
            ));
        }
        Ok(AuthenticatedCaller {
            principal,
            installation_id,
            key_id: kid.to_owned(),
            request_id: request_id.to_owned(),
            nonce: nonce.to_owned(),
            body_digest: required_string(object, "body_digest")?.to_owned(),
        })
    }

    fn verify_envelope_sender(
        &self,
        wrapper: &Value,
        now: DateTime<Utc>,
    ) -> Result<PrincipalAddress, RelayError> {
        let envelope = wrapper
            .get("envelope")
            .ok_or_else(|| RelayError::malformed_envelope("missing envelope"))?;
        let signature = wrapper
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| RelayError::malformed_envelope("missing envelope signature"))?;
        let object = envelope
            .as_object()
            .ok_or_else(|| RelayError::malformed_envelope("envelope must be an object"))?;
        let principal: PrincipalAddress = serde_json::from_value(
            object
                .get("sender_principal")
                .cloned()
                .ok_or_else(|| RelayError::malformed_envelope("missing sender"))?,
        )
        .map_err(|_| RelayError::malformed_envelope("invalid sender"))?;
        self.fresh_principal(&principal, now)?;
        let kid = required_string(object, "sender_key_id")?;
        let key = self
            .signing
            .get(kid)
            .ok_or_else(|| RelayError::signature_invalid("unknown envelope signing key"))?;
        if key.principal != principal || key.purpose != KeyPurpose::OperationalSigning {
            return Err(RelayError::signature_invalid(
                "envelope sender key mismatch",
            ));
        }
        if key.status == "revoked" {
            return Err(RelayError::key_revoked("envelope signing key is revoked"));
        }
        let created_at = timestamp(required_string(object, "created_at")?)?;
        if key.status != "active"
            || key.not_before.is_some_and(|time| created_at < time)
            || key.not_after.is_some_and(|time| created_at >= time)
        {
            return Err(RelayError::signature_invalid(
                "envelope signing key was not active at creation",
            ));
        }
        verify_detached(envelope, signature, &key.jwk, "native-envelope+jws")?;
        Ok(principal)
    }

    fn authorize_recipient(
        &self,
        principal: &PrincipalAddress,
        encryption_key_id: &str,
        now: DateTime<Utc>,
    ) -> Result<RecipientAuthorization, RelayError> {
        let record = match self.fresh_principal(principal, now) {
            Ok(record) => record,
            Err(error) if error.code == "unknown_principal" => {
                return Ok(RecipientAuthorization::Rejected("invalid_recipient"));
            }
            Err(error) if error.code == "principal_revoked" => {
                return Ok(RecipientAuthorization::Rejected("principal_revoked"));
            }
            Err(error) => return Err(error),
        };
        let Some(key) = record.encryption_keys.get(encryption_key_id) else {
            return Ok(RecipientAuthorization::Rejected("invalid_recipient"));
        };
        if key.status == "revoked" {
            return Ok(RecipientAuthorization::Rejected("key_revoked"));
        }
        if key.status != "active" || now < key.not_before || now >= key.not_after {
            return Ok(RecipientAuthorization::Rejected("invalid_recipient"));
        }
        Ok(RecipientAuthorization::Active)
    }
}

fn timestamp(value: &str) -> Result<DateTime<Utc>, RelayError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| RelayError::invalid_request("invalid RFC 3339 timestamp"))
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, RelayError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| RelayError::invalid_request(format!("missing {name}")))
}

fn required_string_obj<'a>(value: &'a Value, name: &str) -> Result<&'a str, RelayError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| RelayError::invalid_request(format!("missing {name}")))
}

fn required_array<'a>(
    object: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a Vec<Value>, RelayError> {
    object
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| RelayError::invalid_request(format!("missing {name}")))
}
