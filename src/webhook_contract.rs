//! Shared structured-form wire contract for both storage engines.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    #[serde(default)]
    pub required: bool,
    pub max_length: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FormConfig {
    pub profile: String,
    pub home_id: String,
    pub record_type: String,
    pub record_kind: String,
    pub fields: BTreeMap<String, Field>,
    pub mappings: BTreeMap<String, String>,
    #[serde(default = "empty_object")]
    pub constants: Value,
}
fn empty_object() -> Value {
    serde_json::json!({})
}
fn invalid() -> Error {
    Error::engine("invalid webhook configuration")
}
fn ordinary_facet(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        && !crate::schema::ENGINE_RESERVED_FACET_KEYS.contains(&key)
        && !matches!(key, "blob_ref" | "owner" | "owner_id" | "authority")
}
fn target(key: &str) -> bool {
    matches!(key, "name" | "summary" | "body")
        || key.strip_prefix("facet:").is_some_and(|facet| {
            ordinary_facet(facet)
                && !matches!(
                    facet,
                    "stage" | "application_stage" | "role" | "home_id" | "access_policy"
                )
        })
}
impl FormConfig {
    pub fn validate(&self) -> Result<()> {
        if self.profile != "structured_form.v1"
            || self.home_id.is_empty()
            || self.home_id.len() > 200
            || self.record_type.is_empty()
            || self.record_kind.is_empty()
            || self.record_type.len() > 100
            || self.record_kind.len() > 100
            || matches!(
                self.record_type.as_str(),
                "Message" | "Annotation" | "Configuration" | "Collection" | "Identity"
            )
            || (self.record_type == "Document" && self.record_kind == "attachment")
            || self.fields.is_empty()
            || self.fields.len() > 32
            || self.mappings.is_empty()
        {
            return Err(invalid());
        }
        let mut targets = BTreeSet::new();
        for (key, field) in &self.fields {
            if key.is_empty()
                || key.len() > 64
                || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                || field.max_length == 0
                || field.max_length > 16384
            {
                return Err(invalid());
            }
        }
        for (source, dest) in &self.mappings {
            if !self.fields.contains_key(source) || !target(dest) || !targets.insert(dest.clone()) {
                return Err(invalid());
            }
        }
        let constants = self.constants.as_object().ok_or_else(invalid)?;
        for (key, value) in constants {
            if key == "facets" {
                for (facet, value) in value.as_object().ok_or_else(invalid)? {
                    if !ordinary_facet(facet)
                        || !value.is_string()
                        || value.as_str().unwrap().len() > 16384
                        || !targets.insert(format!("facet:{facet}"))
                    {
                        return Err(invalid());
                    }
                }
            } else if !matches!(
                key.as_str(),
                "name" | "summary" | "body" | "lifecycle" | "persistence" | "maturity"
            ) || !value.is_string()
                || value.as_str().unwrap().len() > 16384
                || !targets.insert(key.clone())
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn map(&self, fields: &BTreeMap<String, String>) -> Result<Value> {
        self.validate()?;
        if fields.keys().any(|k| !self.fields.contains_key(k))
            || self.fields.iter().any(|(k, r)| {
                fields.get(k).map_or(r.required, |v| {
                    v.len() > r.max_length || (r.required && v.trim().is_empty())
                })
            })
        {
            return Err(Error::engine("invalid_submission"));
        }
        let mut args = self.constants.clone();
        args["type"] = self.record_type.clone().into();
        args["kind"] = self.record_kind.clone().into();
        args["home_id"] = self.home_id.clone().into();
        for (key, dest) in &self.mappings {
            if let Some(value) = fields.get(key) {
                if let Some(facet) = dest.strip_prefix("facet:") {
                    if args.get("facets").is_none() {
                        args["facets"] = empty_object();
                    }
                    args["facets"][facet] = value.clone().into();
                } else {
                    args[dest] = value.clone().into();
                }
            }
        }
        if args["name"].as_str().is_none_or(|s| s.trim().is_empty()) {
            return Err(Error::engine("invalid_submission"));
        }
        Ok(args)
    }
}

// No Debug: even configuration can contain private system constants. Credential
// hashes are returned only to the hosted verifier, never management diagnostics.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub endpoint_id: String,
    pub issuer_user_id: String,
    pub issuer_principal: String,
    pub credential_id: String,
    pub credential_hash: String,
    pub config: FormConfig,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub profile: String,
    pub submission_id: String,
    pub fields: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub submission_key: String,
    pub payload_digest: String,
    pub delivery_id: String,
    pub record_id: String,
    pub attachment_id: String,
}
