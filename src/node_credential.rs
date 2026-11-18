//! Request proofs for the dedicated node resource. Installing a public key
//! and validating the OAuth credential are responsibilities of the server.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const PROOF_HEADER: &str = "native-node-proof";
pub const VERIFY_ENROLLMENT_PATH: &str = "/internal/node/verify-enrollment";
/// Signed counterpart of the standby snapshot and delta export routes.
pub const REFRESH_PATH_PREFIX: &str = "/internal/node/refresh";

pub(crate) enum SendError {
    Proof,
    Http(reqwest::Error),
}

pub(crate) async fn send_request(
    client: &reqwest::Client,
    builder: reqwest::RequestBuilder,
    key: Option<&InstallKey>,
) -> std::result::Result<reqwest::Response, SendError> {
    let Some(key) = key else {
        return builder.send().await.map_err(SendError::Http);
    };
    let mut request = builder.build().map_err(SendError::Http)?;
    key.attach(&mut request).map_err(|_| SendError::Proof)?;
    client.execute(request).await.map_err(SendError::Http)
}

/// The key is loaded from the node's guarded private file and shared by
/// its ordinary read, reconciliation and refresh transports.
#[derive(Clone)]
pub(crate) struct InstallKey(std::sync::Arc<SigningKey>);

impl InstallKey {
    pub(crate) fn load(path: &std::path::Path) -> crate::Result<Self> {
        let secret = crate::credential_file::read_guarded_credential(path, "node install key")?;
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(&*secret, &mut *seed)
            .map_err(|_| crate::Error::engine("node install key encoding is invalid"))?;
        Ok(Self(std::sync::Arc::new(SigningKey::from_bytes(&seed))))
    }

    pub(crate) fn id(&self) -> String {
        hex::encode(self.0.verifying_key().to_bytes())
    }

    pub(crate) fn attach(&self, request: &mut reqwest::Request) -> crate::Result<()> {
        let invalid = || crate::Error::engine("cannot sign the installed node request");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs();
        let bearer = request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(invalid)?;
        let body = match request.body() {
            Some(body) => body.as_bytes().ok_or_else(invalid)?,
            None => &[],
        };
        let signed_body = if let Some(range) = request.headers().get(reqwest::header::RANGE) {
            if request.method() != reqwest::Method::GET || !body.is_empty() {
                return Err(invalid());
            }
            range.as_bytes()
        } else {
            body
        };
        let proof = sign(
            &self.0,
            now,
            bearer,
            request.method().as_str(),
            request.url().as_str(),
            signed_body,
        );
        request.headers_mut().insert(
            PROOF_HEADER,
            reqwest::header::HeaderValue::from_str(&proof).map_err(|_| invalid())?,
        );
        Ok(())
    }
}

const MAX_AGE_SECONDS: u64 = 60;
const MAX_FUTURE_SECONDS: u64 = 5;

/// Sign the request after token renewal and serialization. The target is the
/// absolute resource origin followed by the exact HTTP path and query.
pub fn sign(
    key: &SigningKey,
    unix_seconds: u64,
    bearer: &str,
    method: &str,
    target: &str,
    body: &[u8],
) -> String {
    let message = request_message(unix_seconds, bearer, method, target, body);
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&message).to_bytes());
    format!("{unix_seconds}.{signature}")
}

pub fn verify(
    key: &VerifyingKey,
    now: u64,
    bearer: &str,
    method: &str,
    target: &str,
    body: &[u8],
    proof: &str,
) -> bool {
    if proof.len() > 20 + 1 + 86 {
        return false;
    }
    let Some((timestamp, encoded)) = proof.split_once('.') else {
        return false;
    };
    let Ok(timestamp) = timestamp.parse::<u64>() else {
        return false;
    };
    if timestamp < now.saturating_sub(MAX_AGE_SECONDS)
        || timestamp > now.saturating_add(MAX_FUTURE_SECONDS)
    {
        return false;
    }
    let mut bytes = [0; 64];
    if URL_SAFE_NO_PAD.decode_slice(encoded, &mut bytes) != Ok(bytes.len()) {
        return false;
    }
    let message = request_message(timestamp, bearer, method, target, body);
    key.verify_strict(&message, &Signature::from_bytes(&bytes))
        .is_ok()
}

fn request_message(
    unix_seconds: u64,
    bearer: &str,
    method: &str,
    target: &str,
    body: &[u8],
) -> Vec<u8> {
    // Fixed-width digests bind the exact bytes even for inputs containing
    // delimiters. The domain keeps signatures distinct from other protocols.
    let mut message = b"native.node.request.v1\0".to_vec();
    message.extend(unix_seconds.to_be_bytes());
    for bytes in [
        bearer.as_bytes(),
        method.as_bytes(),
        target.as_bytes(),
        body,
    ] {
        message.extend(Sha256::digest(bytes));
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_requires_the_enrolled_key_and_exact_current_request() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let other = SigningKey::from_bytes(&[9; 32]).verifying_key();
        let public = key.verifying_key();
        let target = "https://node.example.test/internal/db?a=b";
        let body = br#"{"action":"abandon"}"#;
        let proof = sign(&key, 123, "grant", "POST", target, body);
        let check = |key, time, bearer, method, target, body, proof| {
            verify(key, time, bearer, method, target, body, proof)
        };
        assert!(check(&public, 123, "grant", "POST", target, body, &proof));
        assert!(!check(&other, 123, "grant", "POST", target, body, &proof));
        assert!(!check(&public, 123, "other", "POST", target, body, &proof));
        assert!(!check(&public, 123, "grant", "GET", target, body, &proof));
        assert!(!check(
            &public,
            123,
            "grant",
            "POST",
            "https://other.example.test/internal/db?a=b",
            body,
            &proof
        ));
        assert!(!check(&public, 123, "grant", "POST", target, b"{}", &proof));
        assert!(!check(&public, 184, "grant", "POST", target, body, &proof));
        assert!(!check(&public, 117, "grant", "POST", target, body, &proof));
        assert!(!check(&public, 123, "grant", "POST", target, body, ""));
    }
}
