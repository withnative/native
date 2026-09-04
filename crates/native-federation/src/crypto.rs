use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

use super::relay::RelayError;

pub const PROFILE: &str = "native-fed/experimental-jose-hpke-1";
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_JSON_DEPTH: usize = 32;
const MAX_CONTAINER_ITEMS: usize = 256;
const MAX_STRING_BYTES: usize = 4_096;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ed25519Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
}

impl Ed25519Jwk {
    pub fn verifying_key(&self) -> Result<VerifyingKey, RelayError> {
        if self.kty != "OKP" || self.crv != "Ed25519" || self.alg != "EdDSA" || self.use_ != "sig" {
            return Err(RelayError::signature_invalid("unsupported signing JWK"));
        }
        let raw = decode_base64url(&self.x, "signature_invalid")?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| RelayError::signature_invalid("invalid Ed25519 public key"))?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| RelayError::signature_invalid("invalid Ed25519 public key"))
    }
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>, RelayError> {
    fn write(value: &Value, out: &mut Vec<u8>) -> Result<(), RelayError> {
        match value {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
            Value::String(string) => serde_json::to_writer(out, string)
                .map_err(|_| RelayError::invalid_request("could not canonicalize JSON"))?,
            Value::Array(values) => {
                out.push(b'[');
                for (index, item) in values.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    write(item, out)?;
                }
                out.push(b']');
            }
            Value::Object(object) => {
                out.push(b'{');
                let mut keys: Vec<_> = object.keys().collect();
                keys.sort_unstable_by(|left, right| {
                    left.encode_utf16()
                        .collect::<Vec<_>>()
                        .cmp(&right.encode_utf16().collect::<Vec<_>>())
                });
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key)
                        .map_err(|_| RelayError::invalid_request("could not canonicalize JSON"))?;
                    out.push(b':');
                    write(&object[*key], out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }

    validate_ijson_value(value, 0)?;
    let mut bytes = Vec::new();
    write(value, &mut bytes)?;
    Ok(bytes)
}

/// Parse one complete profile JSON value while rejecting information that
/// `serde_json::Value` would otherwise normalize away (notably duplicate
/// object members). The original input bytes remain available to the caller
/// for request-proof body-digest verification.
pub fn parse_ijson(bytes: &[u8], code: &'static str) -> Result<Value, RelayError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| RelayError::named(code, format!("invalid I-JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| RelayError::named(code, format!("invalid I-JSON: {error}")))?;
    Ok(value)
}

fn validate_ijson_value(value: &Value, depth: usize) -> Result<(), RelayError> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => {
            let valid = number
                .as_i64()
                .is_some_and(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value))
                || number
                    .as_u64()
                    .is_some_and(|value| value <= MAX_SAFE_INTEGER as u64);
            if valid {
                Ok(())
            } else {
                Err(RelayError::invalid_request(
                    "I-JSON numbers must be safe integers",
                ))
            }
        }
        Value::String(value) => validate_string(value).map_err(RelayError::invalid_request),
        Value::Array(values) => {
            if depth >= MAX_JSON_DEPTH || values.len() > MAX_CONTAINER_ITEMS {
                return Err(RelayError::invalid_request("I-JSON bounds exceeded"));
            }
            for value in values {
                validate_ijson_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if depth >= MAX_JSON_DEPTH || object.len() > MAX_CONTAINER_ITEMS {
                return Err(RelayError::invalid_request("I-JSON bounds exceeded"));
            }
            for (key, value) in object {
                validate_string(key).map_err(RelayError::invalid_request)?;
                validate_ijson_value(value, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn validate_string(value: &str) -> Result<(), &'static str> {
    if value.len() > MAX_STRING_BYTES {
        Err("I-JSON string exceeds 4096 UTF-8 octets")
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct StrictValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor { depth: self.depth })
    }
}

struct StrictValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded I-JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
            return Err(E::custom("integer exceeds the I-JSON safe range"));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value > MAX_SAFE_INTEGER as u64 {
            return Err(E::custom("integer exceeds the I-JSON safe range"));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating-point numbers are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        validate_string(&value).map_err(E::custom)?;
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(A::Error::custom("JSON nesting exceeds 32"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed {
            depth: self.depth + 1,
        })? {
            if values.len() == MAX_CONTAINER_ITEMS {
                return Err(A::Error::custom("JSON array exceeds 256 items"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(A::Error::custom("JSON nesting exceeds 32"));
        }
        let mut object = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            validate_string(&key).map_err(A::Error::custom)?;
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom("duplicate object member"));
            }
            if object.len() == MAX_CONTAINER_ITEMS {
                return Err(A::Error::custom("JSON object exceeds 256 members"));
            }
            let value = map.next_value_seed(StrictValueSeed {
                depth: self.depth + 1,
            })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha-256:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

pub fn digest_value(value: &Value) -> Result<String, RelayError> {
    Ok(sha256_digest(&canonical_json(value)?))
}

pub fn decode_base64url(value: &str, code: &'static str) -> Result<Vec<u8>, RelayError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
    {
        return Err(RelayError::named(code, "non-canonical base64url"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RelayError::named(code, "invalid base64url"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(RelayError::named(code, "non-canonical base64url"));
    }
    Ok(decoded)
}

fn protected_header(kid: &str, typ: &str) -> Value {
    let mut header = Map::new();
    header.insert("alg".into(), Value::String("EdDSA".into()));
    header.insert("kid".into(), Value::String(kid.into()));
    header.insert("typ".into(), Value::String(typ.into()));
    Value::Object(header)
}

pub fn sign_detached(
    payload: &Value,
    signing_key: &SigningKey,
    kid: &str,
    typ: &str,
) -> Result<String, RelayError> {
    let protected = URL_SAFE_NO_PAD.encode(canonical_json(&protected_header(kid, typ))?);
    let payload = URL_SAFE_NO_PAD.encode(canonical_json(payload)?);
    let input = format!("{protected}.{payload}");
    let signature = signing_key.sign(input.as_bytes());
    Ok(format!(
        "{protected}..{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

pub fn verify_detached(
    payload: &Value,
    compact: &str,
    jwk: &Ed25519Jwk,
    typ: &str,
) -> Result<(), RelayError> {
    let parts: Vec<_> = compact.split('.').collect();
    if parts.len() != 3 || !parts[1].is_empty() {
        return Err(RelayError::signature_invalid("invalid detached JWS"));
    }
    verify_jws_parts(payload, parts[0], parts[2], jwk, typ, "signature_invalid")
}

pub fn verify_compact(compact: &str, jwk: &Ed25519Jwk, typ: &str) -> Result<Value, RelayError> {
    let parts: Vec<_> = compact.split('.').collect();
    if parts.len() != 3 || parts[1].is_empty() {
        return Err(RelayError::unauthorized("invalid request proof"));
    }
    let payload_bytes = decode_base64url(parts[1], "unauthorized")?;
    let payload = parse_ijson(&payload_bytes, "unauthorized")?;
    if canonical_json(&payload)? != payload_bytes {
        return Err(RelayError::unauthorized(
            "request proof payload is not canonical JSON",
        ));
    }
    verify_jws_parts(&payload, parts[0], parts[2], jwk, typ, "unauthorized")?;
    Ok(payload)
}

fn verify_jws_parts(
    payload: &Value,
    protected: &str,
    signature: &str,
    jwk: &Ed25519Jwk,
    typ: &str,
    error_code: &'static str,
) -> Result<(), RelayError> {
    let protected_bytes = decode_base64url(protected, error_code)?;
    let header = parse_ijson(&protected_bytes, error_code)?;
    if canonical_json(&header)? != protected_bytes || header != protected_header(&jwk.kid, typ) {
        return Err(RelayError::named(error_code, "invalid protected header"));
    }
    let signature = decode_base64url(signature, error_code)?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| RelayError::named(error_code, "invalid Ed25519 signature"))?;
    let payload = URL_SAFE_NO_PAD.encode(canonical_json(payload)?);
    let input = format!("{protected}.{payload}");
    jwk.verifying_key()?
        .verify(input.as_bytes(), &signature)
        .map_err(|_| RelayError::named(error_code, "signature verification failed"))
}

pub fn signing_key_from_base64url(seed: &str) -> Result<SigningKey, RelayError> {
    let bytes = decode_base64url(seed, "invalid_request")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| RelayError::invalid_request("relay signing seed must be 32 octets"))?;
    Ok(SigningKey::from_bytes(&bytes))
}
