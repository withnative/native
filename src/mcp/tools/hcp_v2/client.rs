//! Who is calling, and the pseudonym the person is known by to that caller.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::mcp::registry::Caller;

/// The provider identifier recorded in `recordedByProvider` (HCP v2 §3.5).
/// Host routing is not this module's concern; the identifier is the public
/// name of the endpoint that serves the protocol.
pub(super) const PROVIDER_ID: &str = "https://hcp.withnative.ai";

const UNKNOWN: &str = "unknown";

/// The HCP Client behind a call (HCP v2 §3.2.3), as far as Native knows it.
///
/// Native has the OAuth client id and nothing else: no registered client name
/// and no Client Operator. The id stands in for the name, and the operator is
/// recorded as unknown rather than invented (HCP v2 §3.2.8 asks registration to
/// supply both; that is future work in the OAuth layer, and this is the one
/// place it would plug in).
#[derive(Clone, Debug)]
pub(super) struct ClientIdentity {
    pub id: String,
    pub name: String,
    pub operator_id: String,
    pub operator_name: String,
}

impl ClientIdentity {
    /// `None` when the call carries no OAuth client id. HCP v2 §3.11
    /// (invariant 5) makes an operation with no attributable client not
    /// authorized, so the tools refuse it; they never fall back to a shared
    /// anonymous client.
    pub(super) fn of(caller: &Caller) -> Option<ClientIdentity> {
        let id = caller.oauth_client_id()?.to_string();
        Some(ClientIdentity {
            name: id.clone(),
            id,
            operator_id: UNKNOWN.into(),
            operator_name: UNKNOWN.into(),
        })
    }

    /// Native itself as the submitting client: what a revision made by editing
    /// the record in Native is attributed to.
    pub(super) fn native() -> ClientIdentity {
        ClientIdentity {
            id: "native".into(),
            name: "Native".into(),
            operator_id: "native".into(),
            operator_name: "Native".into(),
        }
    }

    /// `record.provenance.submittedByClient` (HCP v2 §3.5): the client and its
    /// operator as they stood when the version was recorded.
    pub(super) fn as_submitted_by(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "operator": { "id": self.operator_id, "name": self.operator_name },
        })
    }

    /// `record.provenance.authorizedUnder`. Native has no per-client grants:
    /// every client acts with the person's ordinary Native access. The value
    /// says so rather than naming a grant that does not exist.
    pub(super) fn implicit_grant(&self) -> String {
        format!("urn:native:hcp:ordinary-access:{}", self.id)
    }
}

/// Label of the sub-key subject pseudonyms are derived under, so the same
/// deployment secret can serve other purposes without sharing a key with them.
const PSEUDONYM_LABEL: &str = "hcp-v2-subject-pseudonym";

/// Smallest deployment secret accepted.
pub const MIN_PSEUDONYM_SECRET_BYTES: usize = 32;

/// The server-held key behind subject pseudonyms (HCP v2 §3.4).
///
/// A pseudonym is HMAC-SHA256 over the person's account identity and the
/// client id, keyed by a sub-key derived from a deployment secret with HKDF
/// (RFC 5869) under the label `hcp-v2-subject-pseudonym`. The same person and
/// client always derive the same identifier; two clients derive unrelated
/// ones; and nobody without the secret can compute or compare identifiers.
/// Nothing is stored in the person's workspace, so no member can plant, read
/// or replace it. **Rotating the secret changes every pseudonym for every
/// client.**
#[derive(Clone)]
pub struct PseudonymKey(std::sync::Arc<[u8; 32]>);

impl std::fmt::Debug for PseudonymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PseudonymKey(..)")
    }
}

impl PseudonymKey {
    /// Derive the pseudonym sub-key from the deployment secret. The secret
    /// must be at least [`MIN_PSEUDONYM_SECRET_BYTES`] of random bytes.
    pub fn from_secret(secret: &[u8]) -> crate::error::Result<PseudonymKey> {
        if secret.len() < MIN_PSEUDONYM_SECRET_BYTES {
            return Err(crate::error::Error::engine(format!(
                "the HCP v2 pseudonym secret must be at least {MIN_PSEUDONYM_SECRET_BYTES} bytes"
            )));
        }
        Ok(PseudonymKey(std::sync::Arc::new(hkdf_sha256(
            secret,
            PSEUDONYM_LABEL.as_bytes(),
        ))))
    }

    /// The identifier `client_id` sees for the person behind `person_id`
    /// (`claim.subject.id`, and the grant's `subject` and
    /// `authorizingPrincipal`).
    pub(super) fn pseudonym(&self, person_id: &str, client_id: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0[..]).expect("HMAC accepts a key of any length");
        // Length-prefixed, so ("ab", "c") and ("a", "bc") differ.
        for part in [person_id, client_id] {
            mac.update(&(part.len() as u64).to_be_bytes());
            mac.update(part.as_bytes());
        }
        let digest = mac.finalize().into_bytes();
        format!("urn:native:hcp:subject:{}", hex::encode(&digest[..16]))
    }
}

/// HKDF-SHA256 (RFC 5869) with an empty salt, one 32-byte output block.
fn hkdf_sha256(secret: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract = Hmac::<Sha256>::new_from_slice(&[0u8; 32]).expect("any key length");
    extract.update(secret);
    let prk = extract.finalize().into_bytes();
    let mut expand = Hmac::<Sha256>::new_from_slice(&prk).expect("any key length");
    expand.update(info);
    expand.update(&[1]);
    expand.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_matches_the_rfc_5869_vector_with_no_salt_and_no_info() {
        // RFC 5869 test case 3: the first 32 of its 42 output bytes.
        let okm = hkdf_sha256(&[0x0b; 22], &[]);
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
    }

    #[test]
    fn a_short_secret_is_refused() {
        assert!(PseudonymKey::from_secret(&[1; 31]).is_err());
        assert!(PseudonymKey::from_secret(&[1; 32]).is_ok());
    }

    #[test]
    fn pseudonyms_depend_on_person_client_and_secret() {
        let key = PseudonymKey::from_secret(&[7; 32]).unwrap();
        let other = PseudonymKey::from_secret(&[8; 32]).unwrap();
        let p = key.pseudonym("acct:alice", "client_one");
        assert_eq!(p, key.pseudonym("acct:alice", "client_one"));
        assert_ne!(p, key.pseudonym("acct:alice", "client_two"));
        assert_ne!(p, key.pseudonym("acct:bob", "client_one"));
        assert_ne!(p, other.pseudonym("acct:alice", "client_one"));
        assert_ne!(key.pseudonym("ab", "c"), key.pseudonym("a", "bc"));
    }
}
