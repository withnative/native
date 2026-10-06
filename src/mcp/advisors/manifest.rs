//! Advisor manifest (`advisor.json`) for the external advisor contract v0.
//!
//! The schema mirrors the TypeScript runner's `AdvisorManifest`
//! (`packages/advisor-runner/src/index.ts`): id, version, description,
//! endpoint, watches, context, budget_ms, enabled — plus an optional free-form
//! `settings` object the engine passes to in-process builtins. The manifest
//! bytes are designed to be storable verbatim as a Native record body later
//! (S8): no relative paths, the endpoint is a URL or a `builtin:<id>` scheme.
//!
//! [`manifest_digest`] is sha256 hex over the canonical JSON bytes (object
//! keys sorted recursively, no whitespace, UTF-8). It must stay byte-identical
//! to the runner's `manifestDigest`; see the golden-vectors test below.

use serde::{Deserialize, Serialize};

/// Fields the engine always sends, whether declared or not.
pub const BASE_CONTEXT_FIELDS: &[&str] = &["tool", "record_id", "record_type", "record_kind"];

/// Every `AdviceContext` field name an advisor may declare.
pub const ADVICE_CONTEXT_FIELDS: &[&str] = &[
    "tool",
    "record_id",
    "record_type",
    "record_kind",
    "record_name",
    "body_chars_before",
    "body_chars_after",
    "recent_body_revisions",
    "recent_same_run_append_streak",
    "links_out_count",
    "mentions_out_count",
    "run_key",
    "lifecycle_before",
    "lifecycle_after",
    "lifecycle_before_terminality",
    "lifecycle_after_terminality",
    "summary_changed_in_write",
    "summary_changed_since_active",
    "summary_present",
    "claim_held",
    "writer_holds_claim",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watches {
    pub tools: Vec<String>,
    pub types: Vec<String>,
    pub kinds: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisorManifest {
    pub id: String,
    pub version: String,
    pub description: String,
    pub endpoint: String,
    pub watches: Watches,
    pub context: Vec<String>,
    pub budget_ms: u64,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
}

/// Which scheme an endpoint uses. `builtin:<id>` addresses an in-process
/// advisor; anything else must be an absolute http(s) URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointKind {
    Http,
    Builtin(String),
}

pub fn endpoint_kind(endpoint: &str) -> Option<EndpointKind> {
    if let Some(id) = endpoint.strip_prefix("builtin:") {
        if id.is_empty() || id.chars().any(char::is_whitespace) {
            return None;
        }
        return Some(EndpointKind::Builtin(id.to_owned()));
    }
    match url::Url::parse(endpoint) {
        Ok(url) if url.scheme() == "http" || url.scheme() == "https" => Some(EndpointKind::Http),
        _ => None,
    }
}

fn is_non_empty_string(value: Option<&serde_json::Value>) -> bool {
    matches!(value, Some(serde_json::Value::String(s)) if !s.is_empty())
}

fn is_string_list(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .all(|item| matches!(item, serde_json::Value::String(s) if !s.is_empty())),
        _ => false,
    }
}

/// Validate a parsed `advisor.json` value, mirroring the runner's
/// `validateManifest` plus the engine-only `builtin:<id>` endpoint scheme.
/// Returns the typed manifest when valid, else a human-readable reason.
pub fn validate_manifest(raw: &serde_json::Value) -> Result<AdvisorManifest, String> {
    let object = raw
        .as_object()
        .ok_or_else(|| "manifest must be a JSON object".to_owned())?;
    if !is_non_empty_string(object.get("id")) {
        return Err("manifest.id must be a non-empty string".to_owned());
    }
    let id = object["id"].as_str().unwrap_or("?");
    if !is_non_empty_string(object.get("version")) {
        return Err(format!("manifest {id}: version must be a non-empty string"));
    }
    if !matches!(
        object.get("description"),
        Some(serde_json::Value::String(_))
    ) {
        return Err(format!("manifest {id}: description must be a string"));
    }
    let endpoint = object.get("endpoint").and_then(|value| value.as_str());
    match endpoint.and_then(endpoint_kind) {
        Some(_) => {}
        None => {
            return Err(format!(
                "manifest {id}: endpoint must be an absolute http(s) URL or builtin:<id>"
            ));
        }
    }
    let watches = object.get("watches").and_then(|value| value.as_object());
    let Some(watches) = watches else {
        return Err(format!("manifest {id}: watches must be an object"));
    };
    for key in ["tools", "types", "kinds"] {
        if !is_string_list(watches.get(key)) {
            return Err(format!(
                "manifest {id}: watches.{key} must be an array of non-empty strings"
            ));
        }
    }
    let context_ok = match object.get("context") {
        Some(serde_json::Value::Array(items)) => items.iter().all(|item| {
            matches!(item, serde_json::Value::String(name) if ADVICE_CONTEXT_FIELDS.contains(&name.as_str()))
        }),
        _ => false,
    };
    if !context_ok {
        return Err(format!(
            "manifest {id}: context must be an array of known AdviceContext field names"
        ));
    }
    let budget_ok = match object.get("budget_ms") {
        Some(serde_json::Value::Number(number)) => number.as_u64().is_some_and(|value| value > 0),
        _ => false,
    };
    // Integer-only, like the runner: a fractional budget cannot be enforced
    // identically on both sides, so it is rejected rather than rounded.
    if !budget_ok {
        return Err(format!(
            "manifest {id}: budget_ms must be a positive integer"
        ));
    }
    if !matches!(object.get("enabled"), Some(serde_json::Value::Bool(_))) {
        return Err(format!("manifest {id}: enabled must be a boolean"));
    }
    serde_json::from_value(raw.clone())
        .map_err(|error| format!("manifest {id}: invalid shape ({error})"))
}

/// Parse and validate raw `advisor.json` bytes, keeping the raw value so the
/// digest pins exactly what was on disk (unknown fields included).
pub fn parse_manifest(text: &str) -> Result<ParsedManifest, String> {
    let raw: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("manifest is not JSON ({error})"))?;
    let manifest = validate_manifest(&raw)?;
    let digest = digest_value(&raw);
    Ok(ParsedManifest {
        manifest,
        raw,
        digest,
    })
}

/// Canonical JSON: object keys sorted recursively, no whitespace, UTF-8.
/// Must stay byte-identical to the runner's `canonicalize` in
/// `packages/advisor-runner/src/index.ts` (which also drops `undefined`
/// values — no analogue exists in `serde_json::Value`).
///
/// Two contract rules keep the bytes identical across implementations:
/// - Keys sort by UTF-16 code-unit sequence (JavaScript `<` on strings),
///   not by Unicode scalar value. They differ for astral keys mixed with
///   keys in U+E000–U+FFFF (e.g. U+FFFF vs U+10000).
/// - Numbers render per `JSON.stringify`: integral floats drop the fraction
///   (`1.0` → `1`), negative zero renders as `0`. Integers beyond 2^53 are
///   NOT portable across the contract (precision loss on parse); keep
///   manifests and settings within the safe integer range.
pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) => value.to_string(),
        serde_json::Value::Number(number) => canonical_number(number),
        serde_json::Value::String(_) => serde_json::to_string(value).unwrap_or("null".into()),
        serde_json::Value::Array(items) => {
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| utf16_key_cmp(left, right));
            let mut out = String::from("{");
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                out.push_str(&canonical_json(&map[*key]));
            }
            out.push('}');
            out
        }
    }
}

/// Render a number the way `JSON.stringify` would: integers plainly,
/// integral floats without the fraction, negative zero as `0`.
fn canonical_number(number: &serde_json::Number) -> String {
    if number.is_i64() {
        return number.as_i64().unwrap_or(0).to_string();
    }
    if number.is_u64() {
        return number.as_u64().unwrap_or(0).to_string();
    }
    let float = number.as_f64().unwrap_or(f64::NAN);
    if float == 0.0 {
        return "0".to_owned();
    }
    if float.is_finite() && float.fract() == 0.0 && float.abs() < 9_007_199_254_740_992.0 {
        return format!("{}", float as i64);
    }
    number.to_string()
}

/// Compare object keys by UTF-16 code-unit sequence, matching JavaScript's
/// `<` on strings (which is what the runner's sort uses).
fn utf16_key_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16()
        .collect::<Vec<u16>>()
        .cmp(&right.encode_utf16().collect::<Vec<u16>>())
}

#[cfg(test)]
mod utf16_sort_tests {
    #[test]
    fn astral_key_sorts_before_ffff() {
        // Scalar order would put U+FFFF first; UTF-16 order puts the
        // surrogate pair (D800 DC00) first. The runner agrees with this.
        assert!("\u{ffff}" < "\u{10000}"); // scalar order: opposite
        assert_eq!(
            super::utf16_key_cmp("\u{ffff}", "\u{10000}"),
            std::cmp::Ordering::Greater
        );
    }
}

/// sha256 hex over the canonical bytes of a raw JSON value (UTF-8).
/// Always digest the validated raw value exactly as loaded — never the
/// re-serialized struct — so unknown fields and explicit nulls pin the same
/// digest on both sides of the contract.
pub fn digest_value(raw: &serde_json::Value) -> String {
    let canonical = canonical_json(raw);
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// A validated manifest plus the raw JSON it came from and its digest.
pub struct ParsedManifest {
    pub manifest: AdvisorManifest,
    pub raw: serde_json::Value,
    pub digest: String,
}

/// Wildcard-aware match: a `"*"` entry matches everything.
pub fn watches_match(patterns: &[String], value: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| pattern == "*" || pattern == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_raw() -> serde_json::Value {
        serde_json::json!({
            "id": "native.under_linked",
            "version": "0.1.0",
            "description": "Nudges when a record links too little.",
            "endpoint": "http://127.0.0.1:7788/advisors/native.under_linked",
            "watches": {"tools": ["update_record"], "types": ["WorkItem"], "kinds": ["*"]},
            "context": ["body_chars_after", "links_out_count"],
            "budget_ms": 150,
            "enabled": true
        })
    }

    #[test]
    fn valid_manifest_parses() {
        let manifest = validate_manifest(&valid_raw()).unwrap();
        assert_eq!(manifest.id, "native.under_linked");
        assert!(manifest.settings.is_none());
    }

    #[test]
    fn completion_context_fields_accepted() {
        let mut raw = valid_raw();
        raw["context"] = serde_json::json!([
            "lifecycle_before",
            "lifecycle_after",
            "lifecycle_before_terminality",
            "lifecycle_after_terminality",
            "summary_changed_in_write",
            "summary_changed_since_active",
            "summary_present",
            "claim_held",
            "writer_holds_claim",
        ]);
        let manifest = validate_manifest(&raw).unwrap();
        assert_eq!(manifest.context.len(), 9);
    }

    #[test]
    fn builtin_endpoint_accepted_with_settings() {
        let mut raw = valid_raw();
        raw["endpoint"] = serde_json::json!("builtin:test-nudge");
        raw["settings"] = serde_json::json!({"threshold": 3});
        let manifest = validate_manifest(&raw).unwrap();
        assert_eq!(
            endpoint_kind(&manifest.endpoint),
            Some(EndpointKind::Builtin("test-nudge".into()))
        );
        assert!(manifest.settings.is_some());
    }

    #[test]
    fn invalid_manifests_rejected() {
        let mut raw = valid_raw();
        raw["context"] = serde_json::json!(["no_such_field"]);
        assert!(validate_manifest(&raw).is_err());
        let mut raw = valid_raw();
        raw["endpoint"] = serde_json::json!("ftp://example.com/x");
        assert!(validate_manifest(&raw).is_err());
        let mut raw = valid_raw();
        raw["budget_ms"] = serde_json::json!(0);
        assert!(validate_manifest(&raw).is_err());
        // Fractional budgets are rejected, not rounded (contract rule).
        let mut raw = valid_raw();
        raw["budget_ms"] = serde_json::json!(150.5);
        assert!(validate_manifest(&raw).is_err());
    }

    #[test]
    fn numbers_follow_json_stringify() {
        let one = serde_json::from_str::<serde_json::Value>("1.0").unwrap();
        assert_eq!(canonical_json(&one), "1");
        let neg_zero = serde_json::from_str::<serde_json::Value>("-0").unwrap();
        assert_eq!(canonical_json(&neg_zero), "0");
        let plain = serde_json::from_str::<serde_json::Value>("42").unwrap();
        assert_eq!(canonical_json(&plain), "42");
    }

    #[test]
    fn digest_matches_golden_vectors() {
        // Fail-closed: the fixture is shared with the runner and must exist.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("packages/advisor-runner/test/fixtures/canonical-vectors.json");
        assert!(
            path.exists(),
            "canonical golden vectors missing: {} (rebase past the runner merge?)",
            path.display()
        );
        let text = std::fs::read_to_string(&path).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(&text).unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            assert_eq!(canonical_json(&vector["input"]), vector["canonical"]);
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(canonical_json(&vector["input"]).as_bytes());
            assert_eq!(hex::encode(hasher.finalize()), vector["sha256"]);
        }
    }
}
