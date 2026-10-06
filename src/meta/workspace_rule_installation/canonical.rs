//! workspace_rule_canonical_v1: new store identities only.
//!
//! Decoded property names sort recursively by unsigned UTF-16 units BEFORE
//! escaping; arrays retain order. Pinned serde_jcs 0.1.0 renders primitives
//! (Unicode scalar strings, finite binary64, zero), never object ordering.
//! Exact signed/unsigned integer decimal rendering is the Native integer
//! extension: this recipe agrees with RFC 8785 on the I-JSON binary64/safe
//! integer subset, but is not unqualified RFC 8785 for full-width integers.
//! Input is serde_json::Value from closed typed snapshots, not raw JSON tokens.
//! Historical shared canonical_json/revision/settings/readset hashes stay put.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub(super) fn encode(value: &Value) -> Vec<u8> {
    fn write(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Object(object) => {
                let mut fields: Vec<_> = object.iter().collect();
                fields.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                out.push(b'{');
                for (index, (key, value)) in fields.into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    out.extend(serde_jcs::to_vec(key).expect("Unicode scalar property name"));
                    out.push(b':');
                    write(value, out);
                }
                out.push(b'}');
            }
            Value::Array(array) => {
                out.push(b'[');
                for (index, value) in array.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write(value, out);
                }
                out.push(b']');
            }
            // serde_json Number retains i64/u64 exactly and finite f64 distinctly.
            // Its Serialize dispatch plus the pinned primitive formatter preserves
            // full integer decimal digits and the existing binary64/zero rendering.
            _ => out.extend(serde_jcs::to_vec(value).expect("finite JSON primitive")),
        }
    }
    let mut bytes = Vec::new();
    write(value, &mut bytes);
    bytes
}

pub(super) fn digest(value: &Value) -> String {
    hex::encode(Sha256::digest(encode(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_utf16_and_native_integer_extension_cross_runtime_goldens() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/workspace-rule/canonical-v1.json"
        ))
        .unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let input: Value = serde_json::from_str(case["input"].as_str().unwrap()).unwrap();
            let actual = String::from_utf8(encode(&input)).unwrap();
            assert_eq!(actual, case["bytes"].as_str().unwrap(), "{}", case["id"]);
            assert_eq!(
                digest(&input),
                case["sha256"].as_str().unwrap(),
                "{}",
                case["id"]
            );
            // Exact old inputs, including escaped/Unicode keys and wide numbers,
            // retain historical bytes/hashes; no shared encoder rewrite.
            assert_eq!(
                String::from_utf8(crate::canonical_json::canonical_json(&input)).unwrap(),
                case["legacy_bytes"].as_str().unwrap(),
                "{}",
                case["id"]
            );
            assert_eq!(
                crate::canonical_json::digest_json(&input),
                case["legacy_sha256"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        }
    }

    #[test]
    fn source_numbers_retain_integer_extrema_and_pinned_binary64_zero() {
        let integers = serde_json::json!([i64::MIN, i64::MAX, u64::MAX, 9007199254740993u64]);
        assert_eq!(
            encode(&integers),
            b"[-9223372036854775808,9223372036854775807,18446744073709551615,9007199254740993]"
        );
        let float: Value = serde_json::from_str("9007199254740993.0").unwrap();
        assert!(float.as_number().unwrap().is_f64());
        assert_eq!(encode(&float), b"9007199254740992");
        assert_ne!(
            digest(&float),
            digest(&serde_json::json!(9007199254740993u64))
        );
        for zero in [
            serde_json::json!(-0.0),
            serde_json::json!(0.0),
            serde_json::json!(0),
        ] {
            assert_eq!(encode(&zero), b"0");
        }
    }
}
