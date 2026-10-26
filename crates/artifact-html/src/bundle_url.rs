//! Signed reusable bundle-URL capabilities (Option B §1).
//!
//! Pure building block: no route, no config, no launch changes. [`issue`]
//! mints `cap` strings of the form `b64url(payload).b64url(tag)` for
//! `{artifact_origin}/artifact-runtime/v1/app/{hex}/{cap}`; [`verify`]
//! checks them against the verifier's own configured origin and hex.
//!
//! The cap and its fields are never logged: failures carry only a
//! [`Refusal`] discriminant, and this module emits no log records.

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use uuid::Uuid;

use native_artifact_runtime::deployment_keyring::DeploymentKeyring;

type HmacSha256 = Hmac<Sha256>;

/// Installed-app payload version; its encoding remains unchanged.
pub const CAP_VERSION: u8 = 0x01;
/// Preview payloads additionally bind a server-held, single-use consent receipt.
pub const PREVIEW_CAP_VERSION: u8 = 0x02;
/// Opaque frozen artifact delivery; grants no install or preview authority.
/// The former readable 0x03 format is deliberately no longer admitted.
pub const ARTIFACT_CAP_VERSION: u8 = 0x04;
/// Ordinary HTML only needs a short delivery lease, not an app session lease.
pub const ARTIFACT_LIFETIME_SECONDS: u64 = 300;
/// Supported clock skew in either direction (seconds).
pub const SKEW_SECONDS: u64 = 60;
/// `exp = iat + 3540`: one hour minus the 60 s skew reserve.
pub const LIFETIME_SECONDS: u64 = 3540;
/// Hard lifetime ceiling enforced at verify time (seconds).
pub const MAX_LIFETIME_SECONDS: u64 = 3600;
/// Reusable-URL bound, measured over the full URL (origin + route + hex).
pub const MAX_URL_BYTES: usize = 1536;
/// Route path between the origin and the hex; 25 bytes.
pub const ROUTE_PATH: &str = "/artifact-runtime/v1/app/";
/// HMAC domain string, separated from every other tag in the tree.
pub const TAG_DOMAIN: &str = "native.bundle-url.v1";

const TAG_BYTES: usize = 32;
/// Payload ceiling including the bounded preview receipt (535 + 1 + 64).
pub const MAX_PAYLOAD_BYTES: usize = 600;
const MAX_PREVIEW_RECEIPT_BYTES: usize = 64;

const MAX_KID_BYTES: usize = 16;
const MAX_PRINCIPAL_BYTES: usize = 64;
const MAX_DATABASE_BYTES: usize = 64;
const SESSION_BYTES: usize = 36;
const MAX_PACKAGE_BYTES: usize = 128;
const MAX_INSTALL_EVENT_BYTES: usize = 64;
const MAX_PARENT_ORIGIN_BYTES: usize = 128;

/// Why a cap was refused. Every variant maps to a 404 at the route; the
/// granularity exists so later slices can meter skew versus forgery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    UnknownKey,
    BadTag,
    Expired,
    NotYetValid,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Malformed => "bundle cap is malformed",
            Self::UnknownKey => "bundle cap key is unknown",
            Self::BadTag => "bundle cap tag mismatch",
            Self::Expired => "bundle cap is expired",
            Self::NotYetValid => "bundle cap is not yet valid",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for Refusal {}

/// Non-time fields for [`issue`]. The `kid` comes from the keyring's active
/// key id, `iat` comes from `now`, and `exp` is derived as `iat + 3540`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueFields {
    pub principal: String,
    pub database: String,
    pub session: String,
    pub package: String,
    pub install_event: String,
    pub parent_origin: String,
    pub adapter_revision: u64,
}

/// Trusted fields returned by [`verify`], valid only after the tag checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFields {
    pub kid: String,
    pub principal: String,
    pub database: String,
    pub session: String,
    pub package: String,
    pub install_event: String,
    pub parent_origin: String,
    pub adapter_revision: u64,
    pub iat: u64,
    pub exp: u64,
    /// Some always selects preview admission; it must never fall back to an
    /// installed-app check when the receipt is missing, expired or consumed.
    pub preview_receipt: Option<String>,
    pub artifact_render: bool,
}

/// Why issuance failed. `TooLong` is distinct so a later slice can fall
/// back to a ticket without storing any cap state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    InvalidField(&'static str),
    InvalidHex,
    TimeOverflow,
    TooLong,
}

impl std::fmt::Display for IssueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField(field) => {
                write!(formatter, "bundle field is out of bounds: {field}")
            }
            Self::InvalidHex => formatter.write_str("bundle hex is not 64 lowercase hex digits"),
            Self::TimeOverflow => formatter.write_str("bundle issue time overflows"),
            Self::TooLong => formatter.write_str("bundle URL exceeds 1,536 bytes"),
        }
    }
}

impl std::error::Error for IssueError {}

fn is_safe_id(id: &str, max: usize) -> bool {
    !id.is_empty()
        && id.len() <= max
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_hex(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn canonical_session(value: &str) -> bool {
    value.len() == SESSION_BYTES
        && Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

/// Exact-origin check reusing the launch surface's helper: the value must
/// already be canonical (no normalization drift), so `issue` can only mint
/// — and `verify` only accept — origins the serve checks will honor. This
/// inherits that helper's policy (HTTPS, HTTP loopback only, plus the
/// desktop `native-ui://app` literal).
fn is_exact_origin(value: &str) -> bool {
    crate::html::RuntimeConfig::exact_parent_origin(value).is_ok_and(|canonical| canonical == value)
}

/// Pure reverse-DNS package-id syntax, shared with the main crate's
/// `require_package`: dot-separated lowercase alphanumeric/hyphen labels,
/// at least two, each 1–32 bytes with no leading or trailing hyphen, and
/// at most 128 bytes overall. Length is folded in so one predicate covers
/// the whole field rule; callers that need distinct length messages (like
/// `require_package`) check length first and only consult this for shape.
pub fn is_valid_package_id(package: &str) -> bool {
    if package.len() > 128 {
        return false;
    }
    let mut labels = 0;
    for label in package.split('.') {
        labels += 1;
        if label.is_empty()
            || label.len() > 32
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return false;
        }
    }
    labels >= 2
}

fn url_len(artifact_origin: &str, hex: &str, cap: &str) -> usize {
    artifact_origin.len() + ROUTE_PATH.len() + hex.len() + 1 + cap.len()
}

/// Strict canonical unpadded base64url: rejects `=`, `+`, `/` and any
/// encoding whose trailing bits are not canonical, via re-encode comparison.
fn decode_canonical(part: &str) -> Option<Vec<u8>> {
    if part.is_empty() || part.bytes().any(|byte| matches!(byte, b'=' | b'+' | b'/')) {
        return None;
    }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decoded = engine.decode(part).ok()?;
    if engine.encode(&decoded) != part {
        return None;
    }
    Some(decoded)
}

fn push_field(payload: &mut Vec<u8>, bytes: &[u8]) {
    debug_assert!(bytes.len() <= u8::MAX as usize);
    payload.push(bytes.len() as u8);
    payload.extend_from_slice(bytes);
}

fn push_int(payload: &mut Vec<u8>, value: u64) {
    payload.push(8);
    payload.extend_from_slice(&value.to_be_bytes());
}

fn compute_tag(secret: &[u8], artifact_origin: &str, hex: &str, payload: &[u8]) -> [u8; TAG_BYTES] {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC accepts any key length; construction cannot fail");
    mac.update(TAG_DOMAIN.as_bytes());
    mac.update(&[0]);
    mac.update(artifact_origin.as_bytes());
    mac.update(&[0]);
    mac.update(hex.as_bytes());
    mac.update(&[0]);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn artifact_cipher(secret: &[u8]) -> chacha20poly1305::ChaCha20Poly1305 {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(b"native.artifact-render-cap.aead.v1");
    let key = mac.finalize().into_bytes();
    <chacha20poly1305::ChaCha20Poly1305 as chacha20poly1305::KeyInit>::new_from_slice(&key)
        .expect("HMAC-SHA256 produces a 256-bit key")
}

fn artifact_header_len(payload: &[u8]) -> Option<usize> {
    let len = usize::from(*payload.get(1)?);
    let end = 2 + len;
    let kid = std::str::from_utf8(payload.get(2..end)?).ok()?;
    is_safe_id(kid, MAX_KID_BYTES).then_some(end)
}

/// Leave only the format and deployment key id readable. A fresh nonce makes
/// the rest an opaque handle without process-local state or restart affinity.
fn seal_artifact_payload(secret: &[u8], payload: &[u8]) -> Result<Vec<u8>, IssueError> {
    let end = artifact_header_len(payload).ok_or(IssueError::InvalidField("kid"))?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let nonce_value: chacha20poly1305::Nonce = nonce.into();
    let ciphertext = artifact_cipher(secret)
        .encrypt(
            &nonce_value,
            Payload {
                msg: &payload[end..],
                aad: &payload[..end],
            },
        )
        .map_err(|_| IssueError::InvalidField("artifact_payload"))?;
    let mut sealed = payload[..end].to_vec();
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

fn open_artifact_payload(
    key_ring: &DeploymentKeyring,
    artifact_origin: &str,
    hex: &str,
    payload: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, Refusal> {
    let end = artifact_header_len(payload).ok_or(Refusal::Malformed)?;
    let kid = std::str::from_utf8(&payload[2..end]).map_err(|_| Refusal::Malformed)?;
    let secret = key_ring.secret(kid).ok_or(Refusal::UnknownKey)?;
    // Authenticate the original envelope and its origin/source binding before
    // decryption. The common parser below checks the same original bytes too.
    verify_tag(secret.as_slice(), artifact_origin, hex, payload, tag)?;
    let nonce = payload.get(end..end + 12).ok_or(Refusal::Malformed)?;
    let ciphertext = payload.get(end + 12..).ok_or(Refusal::Malformed)?;
    let nonce_value: chacha20poly1305::Nonce = <[u8; 12]>::try_from(nonce)
        .map_err(|_| Refusal::Malformed)?
        .into();
    let clear = artifact_cipher(secret.as_slice())
        .decrypt(
            &nonce_value,
            Payload {
                msg: ciphertext,
                aad: &payload[..end],
            },
        )
        .map_err(|_| Refusal::BadTag)?;
    let mut opened = payload[..end].to_vec();
    opened.extend_from_slice(&clear);
    Ok(opened)
}

fn verify_tag(
    secret: &[u8],
    artifact_origin: &str,
    hex: &str,
    payload: &[u8],
    tag: &[u8],
) -> Result<(), Refusal> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| Refusal::Malformed)?;
    mac.update(TAG_DOMAIN.as_bytes());
    mac.update(&[0]);
    mac.update(artifact_origin.as_bytes());
    mac.update(&[0]);
    mac.update(hex.as_bytes());
    mac.update(&[0]);
    mac.update(payload);
    mac.verify_slice(tag).map_err(|_| Refusal::BadTag)
}

/// Mint a cap for `hex` under the keyring's active key, with `iat = now`
/// and `exp = iat + 3540` (checked). No text field may be empty;
/// `parent_origin` must already be an exact canonical origin. Fails without
/// panic on out-of-bounds fields, a misshapen hex, time overflow, or a URL
/// over 1,536 bytes.
pub fn issue(
    key_ring: &DeploymentKeyring,
    artifact_origin: &str,
    hex: &str,
    fields: &IssueFields,
    now: u64,
) -> Result<String, IssueError> {
    let expires = now
        .checked_add(LIFETIME_SECONDS)
        .ok_or(IssueError::TimeOverflow)?;
    issue_cap(
        key_ring,
        artifact_origin,
        hex,
        fields,
        now,
        expires,
        None,
        false,
    )
}

/// Issue ordinary frozen artifact delivery, in a distinct signed domain byte.
/// `install_event` carries the artifact id, not a consent generation.
pub fn issue_artifact(
    key_ring: &DeploymentKeyring,
    artifact_origin: &str,
    hex: &str,
    fields: &IssueFields,
    now: u64,
) -> Result<String, IssueError> {
    let exp = now
        .checked_add(ARTIFACT_LIFETIME_SECONDS)
        .ok_or(IssueError::TimeOverflow)?;
    issue_cap(key_ring, artifact_origin, hex, fields, now, exp, None, true)
}

/// Issue a preview URL with the receipt's exact expiry. Delivery must also
/// recheck that server-held receipt, current session, source View and generation.
#[allow(clippy::too_many_arguments)]
pub fn issue_preview(
    key_ring: &DeploymentKeyring,
    artifact_origin: &str,
    hex: &str,
    fields: &IssueFields,
    receipt: &str,
    now: u64,
    expires: u64,
) -> Result<String, IssueError> {
    if !is_safe_id(receipt, MAX_PREVIEW_RECEIPT_BYTES) {
        return Err(IssueError::InvalidField("preview_receipt"));
    }
    issue_cap(
        key_ring,
        artifact_origin,
        hex,
        fields,
        now,
        expires,
        Some(receipt),
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_cap(
    key_ring: &DeploymentKeyring,
    artifact_origin: &str,
    hex: &str,
    fields: &IssueFields,
    now: u64,
    exp: u64,
    preview_receipt: Option<&str>,
    artifact_render: bool,
) -> Result<String, IssueError> {
    if artifact_origin.is_empty() {
        return Err(IssueError::InvalidField("artifact_origin"));
    }
    if !valid_hex(hex) {
        return Err(IssueError::InvalidHex);
    }
    if !is_safe_id(key_ring.active_key_id(), MAX_KID_BYTES) {
        return Err(IssueError::InvalidField("kid"));
    }
    if fields.principal.is_empty() || fields.principal.len() > MAX_PRINCIPAL_BYTES {
        return Err(IssueError::InvalidField("principal"));
    }
    if fields.database.is_empty() || fields.database.len() > MAX_DATABASE_BYTES {
        return Err(IssueError::InvalidField("database"));
    }
    if !canonical_session(&fields.session) {
        return Err(IssueError::InvalidField("session"));
    }
    // Package syntax lives here so both the cap and the main crate's
    // `require_package` share one predicate; length is folded into it.
    if !is_valid_package_id(&fields.package) {
        return Err(IssueError::InvalidField("package"));
    }
    if fields.install_event.is_empty() || fields.install_event.len() > MAX_INSTALL_EVENT_BYTES {
        return Err(IssueError::InvalidField("install_event"));
    }
    if fields.parent_origin.is_empty()
        || fields.parent_origin.len() > MAX_PARENT_ORIGIN_BYTES
        || !is_exact_origin(&fields.parent_origin)
    {
        return Err(IssueError::InvalidField("parent_origin"));
    }
    let lifetime = if artifact_render {
        ARTIFACT_LIFETIME_SECONDS
    } else {
        MAX_LIFETIME_SECONDS
    };
    if exp <= now || exp - now > lifetime {
        return Err(IssueError::InvalidField("expiry"));
    }

    let mut payload = Vec::with_capacity(128);
    payload.push(if artifact_render {
        ARTIFACT_CAP_VERSION
    } else if preview_receipt.is_some() {
        PREVIEW_CAP_VERSION
    } else {
        CAP_VERSION
    });
    push_field(&mut payload, key_ring.active_key_id().as_bytes());
    push_field(&mut payload, fields.principal.as_bytes());
    push_field(&mut payload, fields.database.as_bytes());
    push_field(&mut payload, fields.session.as_bytes());
    push_field(&mut payload, fields.package.as_bytes());
    push_field(&mut payload, fields.install_event.as_bytes());
    push_field(&mut payload, fields.parent_origin.as_bytes());
    push_int(&mut payload, fields.adapter_revision);
    push_int(&mut payload, now);
    push_int(&mut payload, exp);
    if let Some(receipt) = preview_receipt {
        push_field(&mut payload, receipt.as_bytes());
    }

    let secret = key_ring
        .active_secret()
        .ok_or(IssueError::InvalidField("kid"))?;
    let payload = if artifact_render {
        seal_artifact_payload(secret.as_slice(), &payload)?
    } else {
        payload
    };
    let tag = compute_tag(secret.as_slice(), artifact_origin, hex, &payload);
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let cap = format!("{}.{}", engine.encode(&payload), engine.encode(tag));
    if url_len(artifact_origin, hex, &cap) > MAX_URL_BYTES {
        return Err(IssueError::TooLong);
    }
    Ok(cap)
}

fn parse_int(raw: &[u8]) -> Option<u64> {
    if raw.len() != 8 {
        return None;
    }
    let bytes: [u8; 8] = raw.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Verify a cap against the verifier's own `artifact_origin` and install
/// `hex` at time `now`. Parsing is strict and bounded; the tag is checked
/// with `Mac::verify_slice` — the only tag comparison in this module — over
/// the original decoded payload, and fields stay untrusted until it passes.
pub fn verify(
    key_ring: &DeploymentKeyring,
    artifact_origin: &str,
    hex: &str,
    cap: &str,
    now: u64,
) -> Result<VerifiedFields, Refusal> {
    if artifact_origin.is_empty() || !valid_hex(hex) {
        return Err(Refusal::Malformed);
    }
    // Length gate before decoding anything.
    if url_len(artifact_origin, hex, cap) > MAX_URL_BYTES {
        return Err(Refusal::Malformed);
    }
    let (payload_b64, tag_b64) = cap.split_once('.').ok_or(Refusal::Malformed)?;
    if payload_b64.is_empty() || tag_b64.is_empty() || tag_b64.contains('.') {
        return Err(Refusal::Malformed);
    }
    let wire_payload = decode_canonical(payload_b64).ok_or(Refusal::Malformed)?;
    let tag = decode_canonical(tag_b64).ok_or(Refusal::Malformed)?;
    if tag.len() != TAG_BYTES {
        return Err(Refusal::Malformed);
    }
    if wire_payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Refusal::Malformed);
    }
    let payload = if wire_payload.first() == Some(&ARTIFACT_CAP_VERSION) {
        open_artifact_payload(key_ring, artifact_origin, hex, &wire_payload, &tag)?
    } else {
        wire_payload.clone()
    };
    let (version, mut rest) = payload.split_first().ok_or(Refusal::Malformed)?;
    if !matches!(
        *version,
        CAP_VERSION | PREVIEW_CAP_VERSION | ARTIFACT_CAP_VERSION
    ) {
        return Err(Refusal::Malformed);
    }
    let mut raw: [&[u8]; 11] = [&[]; 11];
    let field_count = if *version == PREVIEW_CAP_VERSION {
        11
    } else {
        10
    };
    for slot in raw[..field_count].iter_mut() {
        let (len_byte, tail) = rest.split_first().ok_or(Refusal::Malformed)?;
        let len = *len_byte as usize;
        if tail.len() < len {
            return Err(Refusal::Malformed);
        }
        let (field, next) = tail.split_at(len);
        *slot = field;
        rest = next;
    }
    if !rest.is_empty() {
        return Err(Refusal::Malformed);
    }

    let kid = std::str::from_utf8(raw[0]).map_err(|_| Refusal::Malformed)?;
    if !is_safe_id(kid, MAX_KID_BYTES) {
        return Err(Refusal::Malformed);
    }
    let text = |index: usize, max: usize| -> Result<&str, Refusal> {
        let value = std::str::from_utf8(raw[index]).map_err(|_| Refusal::Malformed)?;
        if value.is_empty() || value.len() > max {
            return Err(Refusal::Malformed);
        }
        Ok(value)
    };
    let principal = text(1, MAX_PRINCIPAL_BYTES)?;
    let database = text(2, MAX_DATABASE_BYTES)?;
    let session = text(3, SESSION_BYTES)?;
    if !canonical_session(session) {
        return Err(Refusal::Malformed);
    }
    let package = text(4, MAX_PACKAGE_BYTES)?;
    if !is_valid_package_id(package) {
        return Err(Refusal::Malformed);
    }
    let install_event = text(5, MAX_INSTALL_EVENT_BYTES)?;
    let parent_origin = text(6, MAX_PARENT_ORIGIN_BYTES)?;
    if !is_exact_origin(parent_origin) {
        return Err(Refusal::Malformed);
    }
    let adapter_revision = parse_int(raw[7]).ok_or(Refusal::Malformed)?;
    let iat = parse_int(raw[8]).ok_or(Refusal::Malformed)?;
    let exp = parse_int(raw[9]).ok_or(Refusal::Malformed)?;
    let preview_receipt = if *version == PREVIEW_CAP_VERSION {
        let receipt = text(10, MAX_PREVIEW_RECEIPT_BYTES)?;
        if !is_safe_id(receipt, MAX_PREVIEW_RECEIPT_BYTES) {
            return Err(Refusal::Malformed);
        }
        Some(receipt)
    } else {
        None
    };

    let secret = key_ring.secret(kid).ok_or(Refusal::UnknownKey)?;
    verify_tag(secret.as_slice(), artifact_origin, hex, &wire_payload, &tag)?;

    // Expiry, all checked: refuse `expired` unless iat < exp,
    // exp - iat <= 3600 and now < exp; `not_yet_valid` past the skew window.
    // Any overflow in the skew additions refuses `not_yet_valid`: extreme
    // clocks fail closed, never open, and never panic.
    if iat >= exp {
        return Err(Refusal::Expired);
    }
    let lifetime = if *version == ARTIFACT_CAP_VERSION {
        ARTIFACT_LIFETIME_SECONDS
    } else {
        MAX_LIFETIME_SECONDS
    };
    if exp - iat > lifetime {
        return Err(Refusal::Expired);
    }
    if now >= exp {
        return Err(Refusal::Expired);
    }
    if now
        .checked_add(SKEW_SECONDS)
        .is_none_or(|limit| iat > limit)
    {
        return Err(Refusal::NotYetValid);
    }
    if now
        .checked_add(MAX_LIFETIME_SECONDS)
        .is_none_or(|limit| exp > limit)
    {
        return Err(Refusal::NotYetValid);
    }

    Ok(VerifiedFields {
        artifact_render: *version == ARTIFACT_CAP_VERSION,
        kid: kid.to_owned(),
        principal: principal.to_owned(),
        database: database.to_owned(),
        session: session.to_owned(),
        package: package.to_owned(),
        install_event: install_event.to_owned(),
        parent_origin: parent_origin.to_owned(),
        adapter_revision,
        iat,
        exp,
        preview_receipt: preview_receipt.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ORIGIN: &str = "https://artifacts.example";
    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SESSION: &str = "123e4567-e89b-12d3-a456-426614174000";
    const IAT0: u64 = 1_700_000_000;

    fn test_keyring() -> DeploymentKeyring {
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let raw = json!({
            "active_key_id": "test-key-1",
            "keys": [{"id": "test-key-1", "key": key}],
        })
        .to_string();
        DeploymentKeyring::from_json_bundle(&raw).unwrap()
    }

    fn other_keyring() -> DeploymentKeyring {
        let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let raw = json!({
            "active_key_id": "other-key-1",
            "keys": [{"id": "other-key-1", "key": key}],
        })
        .to_string();
        DeploymentKeyring::from_json_bundle(&raw).unwrap()
    }

    fn test_fields() -> IssueFields {
        IssueFields {
            principal: "user-1".into(),
            database: "db-1".into(),
            session: SESSION.into(),
            package: "example.app".into(),
            install_event: "evt-1".into(),
            parent_origin: "https://app.example".into(),
            adapter_revision: crate::html::ADAPTER_REVISION,
        }
    }

    #[test]
    fn ordinary_artifact_cap_is_distinct_from_install_and_preview_authority() {
        let ring = test_keyring();
        let fields = test_fields();
        let hex = "a".repeat(64);
        let cap = issue_artifact(&ring, "https://artifact.example", &hex, &fields, 1000).unwrap();
        let verified = verify(&ring, "https://artifact.example", &hex, &cap, 1000).unwrap();
        assert!(verified.artifact_render);
        assert!(verified.preview_receipt.is_none());
        let installed = issue(&ring, "https://artifact.example", &hex, &fields, 1000).unwrap();
        assert!(
            !verify(&ring, "https://artifact.example", &hex, &installed, 1000)
                .unwrap()
                .artifact_render
        );
        let (payload, tag) = cap.split_once('.').unwrap();
        let mut bytes = b64url().decode(payload).unwrap();
        bytes[0] = CAP_VERSION;
        let forged = format!("{}.{}", b64url().encode(bytes), tag);
        assert!(verify(&ring, "https://artifact.example", &hex, &forged, 1000).is_err());
    }

    #[test]
    fn ordinary_artifact_cap_hides_caller_context_and_survives_keyring_reload() {
        let ring = test_keyring();
        let mut fields = test_fields();
        fields.principal = "principal-opaque-context-0123456789abcdef".into();
        fields.database = "database-opaque-context-0123456789abcdef".into();
        let cap = issue_artifact(&ring, ORIGIN, HEX, &fields, IAT0).unwrap();
        let (payload, _) = cap.split_once('.').unwrap();
        let wire = b64url().decode(payload).unwrap();
        assert_eq!(wire[0], ARTIFACT_CAP_VERSION);
        for value in [&fields.principal, &fields.database, &fields.session] {
            assert!(!wire
                .windows(value.len())
                .any(|part| part == value.as_bytes()));
        }
        assert_ne!(
            cap,
            issue_artifact(&ring, ORIGIN, HEX, &fields, IAT0).unwrap()
        );
        // A freshly constructed verifier needs only the durable deployment key,
        // never a process-local lookup table or readable caller identifiers.
        let verified = verify(&test_keyring(), ORIGIN, HEX, &cap, IAT0 + 299).unwrap();
        assert_eq!(verified.principal, fields.principal);
        assert_eq!(verified.database, fields.database);
        assert_eq!(verified.session, fields.session);
        assert_eq!(verified.exp - verified.iat, ARTIFACT_LIFETIME_SECONDS);
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, IAT0 + 300),
            Err(Refusal::Expired)
        );
        assert_eq!(
            verify(&ring, "https://another.example", HEX, &cap, IAT0),
            Err(Refusal::BadTag)
        );
        assert_eq!(
            verify(&ring, ORIGIN, &"a".repeat(64), &cap, IAT0),
            Err(Refusal::BadTag)
        );
    }

    #[test]
    fn ordinary_artifact_cap_refuses_readable_legacy_and_damaged_ciphertext() {
        let ring = test_keyring();
        let cap = issue_artifact(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        let (payload, tag) = cap.split_once('.').unwrap();
        let mut wire = b64url().decode(payload).unwrap();
        let tag = b64url().decode(tag).unwrap();
        let mut old = open_artifact_payload(&ring, ORIGIN, HEX, &wire, &tag).unwrap();
        old[0] = 0x03;
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &old),
                IAT0
            ),
            Err(Refusal::Malformed)
        );
        // Even a correctly framed outer MAC cannot turn malformed encrypted
        // bytes into a caller context. No claims are returned on either error.
        *wire.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &wire),
                IAT0
            ),
            Err(Refusal::BadTag)
        );
    }

    fn b64url() -> base64::engine::GeneralPurpose {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    }

    /// Sign arbitrary payload bytes with the test key, framing the tag per
    /// §1. Lets parse-rule tests carry valid tags, so a `Malformed` proves
    /// the parse rule fired rather than the tag check.
    fn sign_raw(key_ring: &DeploymentKeyring, origin: &str, hex: &str, payload: &[u8]) -> String {
        let secret = key_ring.secret("test-key-1").unwrap();
        let mut mac = HmacSha256::new_from_slice(secret.as_slice()).unwrap();
        mac.update(TAG_DOMAIN.as_bytes());
        mac.update(&[0]);
        mac.update(origin.as_bytes());
        mac.update(&[0]);
        mac.update(hex.as_bytes());
        mac.update(&[0]);
        mac.update(payload);
        let tag = mac.finalize().into_bytes();
        format!("{}.{}", b64url().encode(payload), b64url().encode(tag))
    }

    fn push_raw_field(payload: &mut Vec<u8>, bytes: &[u8]) {
        payload.push(bytes.len() as u8);
        payload.extend_from_slice(bytes);
    }

    fn push_raw_int(payload: &mut Vec<u8>, value: u64) {
        payload.push(8);
        payload.extend_from_slice(&value.to_be_bytes());
    }

    /// Payload mirroring [`test_fields`] but with caller-chosen times.
    fn payload_with_times(iat: u64, exp: u64) -> Vec<u8> {
        custom_payload(
            [
                "test-key-1".as_bytes(),
                b"user-1".as_slice(),
                b"db-1".as_slice(),
                SESSION.as_bytes(),
                b"example.app".as_slice(),
                b"evt-1".as_slice(),
                b"https://app.example".as_slice(),
            ],
            3,
            iat,
            exp,
        )
    }

    /// Payload with caller-chosen text fields (for empty/shape cases).
    fn custom_payload(texts: [&[u8]; 7], adapter: u64, iat: u64, exp: u64) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(CAP_VERSION);
        for field in texts {
            push_raw_field(&mut payload, field);
        }
        push_raw_int(&mut payload, adapter);
        push_raw_int(&mut payload, iat);
        push_raw_int(&mut payload, exp);
        payload
    }

    fn base_texts() -> [&'static [u8]; 7] {
        [
            b"test-key-1".as_slice(),
            b"user-1".as_slice(),
            b"db-1".as_slice(),
            SESSION.as_bytes(),
            b"example.app".as_slice(),
            b"evt-1".as_slice(),
            b"https://app.example".as_slice(),
        ]
    }

    #[test]
    fn preview_urls_match_the_shell_contract_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/preview-urls.json")).unwrap();
        for case in cases.as_array().unwrap() {
            let field = |name: &str| case["fields"][name].as_str().unwrap().to_owned();
            let fields = IssueFields {
                principal: field("principal"),
                database: field("database"),
                session: field("session"),
                package: field("package"),
                install_event: field("install_event"),
                parent_origin: field("parent_origin"),
                adapter_revision: crate::html::ADAPTER_REVISION,
            };
            let kid = case["kid"].as_str().unwrap();
            let ring = DeploymentKeyring::from_json_bundle(&json!({"active_key_id":kid,
                "keys":[{"id":kid,"key":base64::engine::general_purpose::STANDARD.encode([7u8;32])}]}).to_string()).unwrap();
            let origin = case["origin"].as_str().unwrap();
            let digest = case["digest"].as_str().unwrap();
            let receipt = case["receipt"].as_str().unwrap();
            let now = case["issued"].as_u64().unwrap();
            let cap = issue_preview(
                &ring,
                origin,
                digest,
                &fields,
                receipt,
                now,
                case["expires"].as_u64().unwrap(),
            )
            .unwrap();
            let url = format!("{origin}{ROUTE_PATH}{digest}/{cap}");
            assert_eq!(url, case["url"].as_str().unwrap(), "{}", case["label"]);
            assert_eq!(
                verify(&ring, origin, digest, &cap, now)
                    .unwrap()
                    .preview_receipt
                    .as_deref(),
                Some(receipt)
            );
            assert_eq!(
                b64url()
                    .decode(cap.split_once('.').unwrap().0)
                    .unwrap()
                    .len(),
                case["payload_bytes"].as_u64().unwrap() as usize
            );
        }
        assert_eq!(
            cases.as_array().unwrap().last().unwrap()["payload_bytes"],
            MAX_PAYLOAD_BYTES
        );
    }

    #[test]
    fn preview_cap_binds_receipt_mode_and_exact_expiry() {
        let ring = test_keyring();
        let cap = issue_preview(
            &ring,
            ORIGIN,
            HEX,
            &test_fields(),
            "review-1",
            IAT0,
            IAT0 + 120,
        )
        .unwrap();
        let got = verify(&ring, ORIGIN, HEX, &cap, IAT0).unwrap();
        assert_eq!(got.preview_receipt.as_deref(), Some("review-1"));
        assert_eq!(got.exp, IAT0 + 120);
        assert_eq!(got.install_event, "evt-1");
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, IAT0 + 120 + SKEW_SECONDS + 1),
            Err(Refusal::Expired)
        );
        let (payload, tag) = cap.split_once('.').unwrap();
        let mut payload = b64url().decode(payload).unwrap();
        assert_eq!(payload[0], PREVIEW_CAP_VERSION);
        // Even a valid signature cannot turn a receipt-bearing payload into
        // an installed-app payload: the old parser must reject trailing data.
        payload[0] = CAP_VERSION;
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &payload),
                IAT0
            ),
            Err(Refusal::Malformed)
        );
        payload[0] = PREVIEW_CAP_VERSION;
        *payload.last_mut().unwrap() = b'2';
        let tampered = format!("{}.{}", b64url().encode(&payload), tag);
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &tampered, IAT0),
            Err(Refusal::BadTag)
        );
        let installed = issue(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &installed, IAT0)
                .unwrap()
                .preview_receipt,
            None
        );
    }

    #[test]
    fn preview_cap_refuses_missing_receipt_and_invalid_lifetime() {
        let ring = test_keyring();
        for receipt in ["", "receipt/other", &"x".repeat(65)] {
            assert!(issue_preview(
                &ring,
                ORIGIN,
                HEX,
                &test_fields(),
                receipt,
                IAT0,
                IAT0 + 120
            )
            .is_err());
        }
        for expiry in [IAT0, IAT0 - 1, IAT0 + MAX_LIFETIME_SECONDS + 1] {
            assert!(
                issue_preview(&ring, ORIGIN, HEX, &test_fields(), "receipt", IAT0, expiry).is_err()
            );
        }
        let mut missing = payload_with_times(IAT0, IAT0 + 120);
        missing[0] = PREVIEW_CAP_VERSION;
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &missing),
                IAT0
            ),
            Err(Refusal::Malformed)
        );
    }

    #[test]
    fn round_trip_sets_exp_to_iat_plus_3540() {
        let ring = test_keyring();
        let cap = issue(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        assert_eq!(cap.matches('.').count(), 1);
        let got = verify(&ring, ORIGIN, HEX, &cap, IAT0).unwrap();
        assert_eq!(got.kid, "test-key-1");
        assert_eq!(got.principal, "user-1");
        assert_eq!(got.database, "db-1");
        assert_eq!(got.session, SESSION);
        assert_eq!(got.package, "example.app");
        assert_eq!(got.install_event, "evt-1");
        assert_eq!(got.parent_origin, "https://app.example");
        assert_eq!(got.adapter_revision, crate::html::ADAPTER_REVISION);
        assert_eq!(got.iat, IAT0);
        assert_eq!(got.exp, IAT0 + 3540);
    }

    #[test]
    fn flipped_payload_or_tag_bytes_refuse() {
        let ring = test_keyring();
        let cap = issue(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        let (payload_b64, tag_b64) = cap.split_once('.').unwrap();
        let payload = b64url().decode(payload_b64).unwrap();
        for index in 0..payload.len() {
            let mut mutated = payload.clone();
            mutated[index] ^= 0x01;
            let mutated_cap = format!("{}.{}", b64url().encode(&mutated), tag_b64);
            assert!(
                verify(&ring, ORIGIN, HEX, &mutated_cap, IAT0).is_err(),
                "payload byte {index} must refuse"
            );
        }
        let tag = b64url().decode(tag_b64).unwrap();
        for index in 0..tag.len() {
            let mut mutated = tag.clone();
            mutated[index] ^= 0x01;
            let mutated_cap = format!("{payload_b64}.{}", b64url().encode(&mutated));
            assert!(
                verify(&ring, ORIGIN, HEX, &mutated_cap, IAT0).is_err(),
                "tag byte {index} must refuse"
            );
        }
    }

    #[test]
    fn wrong_audience_or_hex_gives_bad_tag() {
        let ring = test_keyring();
        let cap = issue(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        assert_eq!(
            verify(&ring, "https://other.example", HEX, &cap, IAT0).unwrap_err(),
            Refusal::BadTag
        );
        let mut hex_bytes = HEX.as_bytes().to_vec();
        hex_bytes[63] = if hex_bytes[63] == b'e' { b'f' } else { b'e' };
        let other_hex = String::from_utf8(hex_bytes).unwrap();
        assert_eq!(
            verify(&ring, ORIGIN, &other_hex, &cap, IAT0).unwrap_err(),
            Refusal::BadTag
        );
    }

    #[test]
    fn unknown_kid_has_no_fallback() {
        let ring = test_keyring();
        let other = other_keyring();
        let cap = issue(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        assert_eq!(
            verify(&other, ORIGIN, HEX, &cap, IAT0).unwrap_err(),
            Refusal::UnknownKey
        );
    }

    #[test]
    fn non_canonical_base64_refuses() {
        let ring = test_keyring();
        let cap = issue(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        let (payload_b64, tag_b64) = cap.split_once('.').unwrap();
        let tail = &payload_b64[1..];
        // Padding, `+`, `/` and extra dots are all refused.
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &format!("{payload_b64}=.{tag_b64}"),
                IAT0
            )
            .unwrap_err(),
            Refusal::Malformed
        );
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &format!("+{tail}.{tag_b64}"), IAT0).unwrap_err(),
            Refusal::Malformed
        );
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &format!("/{tail}.{tag_b64}"), IAT0).unwrap_err(),
            Refusal::Malformed
        );
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &format!("{cap}.extra"), IAT0).unwrap_err(),
            Refusal::Malformed
        );
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &format!(".{cap}"), IAT0).unwrap_err(),
            Refusal::Malformed
        );
        // Non-canonical trailing bits: re-encode differs. `AQ` decodes one
        // zero byte canonically; `AR` decodes the same byte with nonzero
        // trailing bits and must refuse.
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &format!("AR.{tag_b64}"), IAT0).unwrap_err(),
            Refusal::Malformed
        );
        // A short tag decodes but is not 32 bytes.
        let short_tag = b64url().encode(&b64url().decode(tag_b64).unwrap()[..31]);
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &format!("{payload_b64}.{short_tag}"),
                IAT0
            )
            .unwrap_err(),
            Refusal::Malformed
        );
    }

    #[test]
    fn parse_rules_fire_with_valid_tags() {
        let ring = test_keyring();
        // Unknown purpose version.
        let mut payload = payload_with_times(IAT0, IAT0 + 3540);
        payload[0] = 0x7f;
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &payload),
                IAT0
            )
            .unwrap_err(),
            Refusal::Malformed
        );
        // Trailing bytes after the tenth field.
        let mut payload = payload_with_times(IAT0, IAT0 + 3540);
        payload.extend_from_slice(&[1, b'x']);
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &payload),
                IAT0
            )
            .unwrap_err(),
            Refusal::Malformed
        );
        // Principal over bounds measured in UTF-8 bytes: 33 `é` are 66 bytes.
        let mut payload = Vec::new();
        payload.push(CAP_VERSION);
        push_raw_field(&mut payload, b"test-key-1");
        push_raw_field(&mut payload, "é".repeat(33).as_bytes());
        push_raw_field(&mut payload, b"db-1");
        push_raw_field(&mut payload, SESSION.as_bytes());
        push_raw_field(&mut payload, b"example.app");
        push_raw_field(&mut payload, b"evt-1");
        push_raw_field(&mut payload, b"https://app.example");
        push_raw_int(&mut payload, 3);
        push_raw_int(&mut payload, IAT0);
        push_raw_int(&mut payload, IAT0 + 3540);
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &payload),
                IAT0
            )
            .unwrap_err(),
            Refusal::Malformed
        );
        // Non-UTF-8 text.
        let mut payload = Vec::new();
        payload.push(CAP_VERSION);
        push_raw_field(&mut payload, b"test-key-1");
        push_raw_field(&mut payload, &[0xff, 0xfe]);
        push_raw_field(&mut payload, b"db-1");
        push_raw_field(&mut payload, SESSION.as_bytes());
        push_raw_field(&mut payload, b"example.app");
        push_raw_field(&mut payload, b"evt-1");
        push_raw_field(&mut payload, b"https://app.example");
        push_raw_int(&mut payload, 3);
        push_raw_int(&mut payload, IAT0);
        push_raw_int(&mut payload, IAT0 + 3540);
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &payload),
                IAT0
            )
            .unwrap_err(),
            Refusal::Malformed
        );
        // Integer field length must be exactly 8.
        let mut payload = Vec::new();
        payload.push(CAP_VERSION);
        for field in [
            "test-key-1".as_bytes(),
            b"user-1".as_slice(),
            b"db-1".as_slice(),
            SESSION.as_bytes(),
            b"example.app".as_slice(),
            b"evt-1".as_slice(),
            b"https://app.example".as_slice(),
        ] {
            push_raw_field(&mut payload, field);
        }
        payload.push(4);
        payload.extend_from_slice(&[0, 0, 0, 3]);
        push_raw_int(&mut payload, IAT0);
        push_raw_int(&mut payload, IAT0 + 3540);
        assert_eq!(
            verify(
                &ring,
                ORIGIN,
                HEX,
                &sign_raw(&ring, ORIGIN, HEX, &payload),
                IAT0
            )
            .unwrap_err(),
            Refusal::Malformed
        );
    }

    #[test]
    fn malformed_text_shapes_refuse_for_every_text_field() {
        let ring = test_keyring();
        // Over bounds with otherwise-valid shapes, so removing only the
        // length check would accept them. Session is the exception: a
        // canonical UUID is exactly 36 bytes, so no over-length value can
        // be otherwise valid.
        let over_long: [Vec<u8>; 7] = [
            vec![b'k'; 17],
            vec![b'a'; 65],
            vec![b'a'; 65],
            vec![b'a'; 37],
            format!(
                "{}.{}.{}.{}",
                "a".repeat(32),
                "b".repeat(32),
                "c".repeat(32),
                "d".repeat(32)
            )
            .into_bytes(),
            vec![b'a'; 65],
            format!("https://{}.{}.example", "a".repeat(63), "b".repeat(58)).into_bytes(),
        ];
        for index in 0..7 {
            for bad in [&over_long[index][..], &[0xff]] {
                let mut texts = base_texts();
                texts[index] = bad;
                let payload = custom_payload(texts, 3, IAT0, IAT0 + 3540);
                assert_eq!(
                    verify(
                        &ring,
                        ORIGIN,
                        HEX,
                        &sign_raw(&ring, ORIGIN, HEX, &payload),
                        IAT0
                    )
                    .unwrap_err(),
                    Refusal::Malformed,
                    "text field {index} shape must refuse"
                );
            }
        }
    }

    #[test]
    fn wrong_integer_width_refuses_for_every_integer_field() {
        let ring = test_keyring();
        for slot in [7, 8, 9] {
            for width in [0u8, 4, 9] {
                let mut payload = Vec::new();
                payload.push(CAP_VERSION);
                for field in base_texts() {
                    push_raw_field(&mut payload, field);
                }
                for (position, value) in [3, IAT0, IAT0 + 3540].iter().enumerate() {
                    if 7 + position == slot {
                        payload.push(width);
                        payload.extend(std::iter::repeat_n(0xab, width as usize));
                    } else {
                        push_raw_int(&mut payload, *value);
                    }
                }
                assert_eq!(
                    verify(
                        &ring,
                        ORIGIN,
                        HEX,
                        &sign_raw(&ring, ORIGIN, HEX, &payload),
                        IAT0
                    )
                    .unwrap_err(),
                    Refusal::Malformed,
                    "int slot {slot} width {width} must refuse"
                );
            }
        }
    }

    #[test]
    fn oversized_url_refuses_on_both_sides() {
        let ring = test_keyring();
        let long_origin = format!("https://{}.example", "a".repeat(1400));
        assert_eq!(
            issue(&ring, &long_origin, HEX, &test_fields(), IAT0).unwrap_err(),
            IssueError::TooLong
        );
        let cap = issue(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        assert_eq!(
            verify(&ring, &long_origin, HEX, &cap, IAT0).unwrap_err(),
            Refusal::Malformed
        );
    }

    #[test]
    fn expiry_follows_the_per_clock_table() {
        let ring = test_keyring();
        let cap = issue(&ring, ORIGIN, HEX, &test_fields(), IAT0).unwrap();
        let exp = IAT0 + 3540;
        // Signer 60 s fast: accept on first load.
        verify(&ring, ORIGIN, HEX, &cap, IAT0 - 60).unwrap();
        // One second past the skew window: not yet valid.
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, IAT0 - 61).unwrap_err(),
            Refusal::NotYetValid
        );
        // Signer 60 s slow: accept.
        verify(&ring, ORIGIN, HEX, &cap, IAT0 + 60).unwrap();
        // Last second of life accepts; expiry itself refuses.
        verify(&ring, ORIGIN, HEX, &cap, exp - 1).unwrap();
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, exp).unwrap_err(),
            Refusal::Expired
        );
    }

    #[test]
    fn degenerate_times_refuse() {
        let ring = test_keyring();
        // iat == exp.
        let cap = sign_raw(&ring, ORIGIN, HEX, &payload_with_times(1000, 1000));
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, 999).unwrap_err(),
            Refusal::Expired
        );
        // iat > exp.
        let cap = sign_raw(&ring, ORIGIN, HEX, &payload_with_times(2000, 1000));
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, 999).unwrap_err(),
            Refusal::Expired
        );
        // exp - iat == 3601 exceeds the ceiling.
        let cap = sign_raw(&ring, ORIGIN, HEX, &payload_with_times(1000, 4601));
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, 1000).unwrap_err(),
            Refusal::Expired
        );
        // exp > now + 3600 with otherwise valid spacing.
        let cap = sign_raw(&ring, ORIGIN, HEX, &payload_with_times(1060, 4660));
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, 1000).unwrap_err(),
            Refusal::NotYetValid
        );
    }

    #[test]
    fn extreme_clocks_refuse_without_panic() {
        let ring = test_keyring();
        // Issuance at the top of the clock cannot reserve the lifetime.
        assert_eq!(
            issue(&ring, ORIGIN, HEX, &test_fields(), u64::MAX).unwrap_err(),
            IssueError::TimeOverflow
        );
        // iat == exp == MAX refuses as expired at any now.
        let cap = sign_raw(&ring, ORIGIN, HEX, &payload_with_times(u64::MAX, u64::MAX));
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, u64::MAX).unwrap_err(),
            Refusal::Expired
        );
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, 0).unwrap_err(),
            Refusal::Expired
        );
        // A verifier past the end of time refuses a live-shaped cap.
        let cap = sign_raw(&ring, ORIGIN, HEX, &payload_with_times(1000, 4540));
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, u64::MAX).unwrap_err(),
            Refusal::Expired
        );
        // Skew additions that overflow fail closed: a cap ending exactly
        // at MAX refuses one second before it, without panicking.
        let cap = sign_raw(
            &ring,
            ORIGIN,
            HEX,
            &payload_with_times(u64::MAX - 3540, u64::MAX),
        );
        assert_eq!(
            verify(&ring, ORIGIN, HEX, &cap, u64::MAX - 1).unwrap_err(),
            Refusal::NotYetValid
        );
    }

    #[test]
    fn bundle_keyring_rejects_long_or_unsafe_key_ids() {
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let raw = json!({
            "active_key_id": "12345678901234567",
            "keys": [{"id": "12345678901234567", "key": key}],
        })
        .to_string();
        assert!(DeploymentKeyring::from_json_bundle(&raw).is_err());
        let raw = json!({
            "active_key_id": "1234567890123456",
            "keys": [{"id": "1234567890123456", "key": key}],
        })
        .to_string();
        assert!(DeploymentKeyring::from_json_bundle(&raw).is_ok());
        let raw = json!({
            "active_key_id": "bad/id",
            "keys": [{"id": "bad/id", "key": key}],
        })
        .to_string();
        assert!(DeploymentKeyring::from_json_bundle(&raw).is_err());
    }

    #[test]
    fn empty_text_fields_refuse_at_verify() {
        let ring = test_keyring();
        for index in 0..7 {
            let mut texts = base_texts();
            texts[index] = b"";
            let payload = custom_payload(texts, 3, IAT0, IAT0 + 3540);
            assert_eq!(
                verify(
                    &ring,
                    ORIGIN,
                    HEX,
                    &sign_raw(&ring, ORIGIN, HEX, &payload),
                    IAT0
                )
                .unwrap_err(),
                Refusal::Malformed,
                "empty field {index} must refuse"
            );
        }
    }

    #[test]
    fn empty_text_fields_refuse_at_issue() {
        let ring = test_keyring();
        let mut fields = test_fields();
        fields.principal.clear();
        assert_eq!(
            issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap_err(),
            IssueError::InvalidField("principal")
        );
        let mut fields = test_fields();
        fields.database.clear();
        assert_eq!(
            issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap_err(),
            IssueError::InvalidField("database")
        );
        let mut fields = test_fields();
        fields.session.clear();
        assert_eq!(
            issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap_err(),
            IssueError::InvalidField("session")
        );
        let mut fields = test_fields();
        fields.package.clear();
        assert_eq!(
            issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap_err(),
            IssueError::InvalidField("package")
        );
        let mut fields = test_fields();
        fields.install_event.clear();
        assert_eq!(
            issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap_err(),
            IssueError::InvalidField("install_event")
        );
        let mut fields = test_fields();
        fields.parent_origin.clear();
        assert_eq!(
            issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap_err(),
            IssueError::InvalidField("parent_origin")
        );
    }

    #[test]
    fn package_syntax_refuses_at_issue_and_verify() {
        let ring = test_keyring();
        for bad in ["my-app", "Example.app", "-bad.app", "bad-.app", "a", ""] {
            let mut fields = test_fields();
            fields.package = bad.into();
            assert_eq!(
                issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap_err(),
                IssueError::InvalidField("package"),
                "{bad:?} must refuse at issue"
            );
            let mut texts = base_texts();
            texts[4] = bad.as_bytes();
            let payload = custom_payload(texts, 3, IAT0, IAT0 + 3540);
            assert_eq!(
                verify(
                    &ring,
                    ORIGIN,
                    HEX,
                    &sign_raw(&ring, ORIGIN, HEX, &payload),
                    IAT0
                )
                .unwrap_err(),
                Refusal::Malformed,
                "{bad:?} must refuse at verify"
            );
        }
    }

    #[test]
    fn parent_origin_must_be_exact_at_issue_and_verify() {
        let ring = test_keyring();
        // No scheme, a path, a query, a fragment, a trailing slash, and a
        // non-loopback plain-HTTP origin (the reused helper's scheme policy).
        let bad = [
            "not-an-origin",
            "https://app.example/path",
            "https://app.example?x=1",
            "https://app.example#frag",
            "https://app.example/",
            "http://app.example",
        ];
        for origin in bad {
            let mut fields = test_fields();
            fields.parent_origin = origin.into();
            assert_eq!(
                issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap_err(),
                IssueError::InvalidField("parent_origin"),
                "{origin} must refuse at issue"
            );
            let mut texts = base_texts();
            texts[6] = origin.as_bytes();
            let payload = custom_payload(texts, 3, IAT0, IAT0 + 3540);
            assert_eq!(
                verify(
                    &ring,
                    ORIGIN,
                    HEX,
                    &sign_raw(&ring, ORIGIN, HEX, &payload),
                    IAT0
                )
                .unwrap_err(),
                Refusal::Malformed,
                "{origin} must refuse at verify"
            );
        }
        // Controls: the loopback HTTP exception and the desktop literal the
        // helper allows still round-trip.
        for origin in ["http://localhost:3000", "native-ui://app"] {
            let mut fields = test_fields();
            fields.parent_origin = origin.into();
            let cap = issue(&ring, ORIGIN, HEX, &fields, IAT0).unwrap();
            let got = verify(&ring, ORIGIN, HEX, &cap, IAT0).unwrap();
            assert_eq!(got.parent_origin, origin);
        }
    }
}
