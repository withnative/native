//! Locally minted record IDs, format v1 (UUIDv8).
//!
//! Each input is framed with an unsigned 64-bit big-endian byte length.
//! The first 128 SHA-256 bits are used, with UUID version/variant bits replaced.
//! Native's local author issuer is `native.kernel.principal`; foreign admission
//! must authenticate/qualify its own issuer before using this helper.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

pub fn qualified_principal(principal: &str) -> String {
    format!("native.kernel.principal:{principal}")
}

/// App installation and delegation are independent optional components. JSON
/// array framing fixes their order and distinguishes absence from empty strings.
/// App versions are deliberately excluded: an installation survives upgrades.
pub fn context(app_install: Option<&str>, delegation: Option<&str>) -> String {
    if app_install.is_none() && delegation.is_none() {
        "first-party".into()
    } else {
        serde_json::to_string(&("native.mint-context.v1", app_install, delegation)).unwrap()
    }
}

/// Mint from a caller-generated 256-bit CSPRNG nonce; returns canonical ID and
/// unpadded base64url nonce. Supplying the nonce also permits offline clients.
pub fn mint(principal: &str, context: &str, nonce: [u8; 32]) -> (String, String) {
    let mut hash = Sha256::new();
    for input in [
        b"native.record-id.v1".as_slice(),
        principal.as_bytes(),
        context.as_bytes(),
        &nonce,
    ] {
        hash.update((input.len() as u64).to_be_bytes());
        hash.update(input);
    }
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    (
        uuid::Uuid::from_bytes(bytes).to_string(),
        URL_SAFE_NO_PAD.encode(nonce),
    )
}

pub fn verify(principal: &str, context: &str, id: &str, nonce: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(nonce) else {
        return false;
    };
    let Ok(bytes) = <[u8; 32]>::try_from(bytes) else {
        return false;
    };
    let expected = mint(principal, context, bytes);
    expected.0 == id && expected.1 == nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mint_proof_boundaries() {
        let (id, nonce) = mint("issuer:alice", "first-party", [7; 32]);
        assert_eq!(id, "b4925d7c-017c-8d2b-b344-e72a5ed13d0a");
        assert!(verify("issuer:alice", "first-party", &id, &nonce));
        for (p, c, i, n) in [
            ("issuer:bob", "first-party", id.clone(), nonce.clone()),
            ("issuer:alice", "app", id.clone(), nonce.clone()),
            (
                "issuer:alice",
                "first-party",
                id.clone(),
                URL_SAFE_NO_PAD.encode([8; 32]),
            ),
            (
                "issuer:alice",
                "first-party",
                uuid::Uuid::new_v4().to_string(),
                nonce.clone(),
            ),
        ] {
            assert!(!verify(p, c, &i, &n));
        }
        assert_eq!(uuid::Uuid::parse_str(&id).unwrap().get_version_num(), 8);
        assert!(!verify("issuer:alice", "first-party", &id, &(nonce + "=")));
    }
}
