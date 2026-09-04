//! Canonical JSON encoding and hashing shared across engine subsystems.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// RFC 8785 JSON Canonicalization Scheme bytes. Array order is preserved;
/// callers must explicitly sort semantically unordered arrays first.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    serde_jcs::to_vec(value).expect("a serde_json::Value is JCS serializable")
}

/// Lowercase SHA-256 digest of a value's RFC 8785 canonical representation.
pub fn digest_json(value: &Value) -> String {
    hex::encode(Sha256::digest(canonical_json(value)))
}
