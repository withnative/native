//! Value and definition model for the HCP preference tools.
//!
//! Mirrors ContextRouter's wire model at 0439d8f (conformance spec e5ae9ef,
//! section 5): dotted lowercase slugs, four value types, GLOBAL/LOCATION
//! scope, and a category derived from the slug rather than stored.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Marker that identifies the catalog body as an HCP preference catalog.
pub(super) const CATALOG_CONTRACT: &str = "native.hcp-preference-catalog.v1";

/// Sensitive definitions and their values are never exposed over `/hcp`.
///
/// ContextRouter withholds sensitive preferences from a client whose policy
/// has `allowSensitive: false`. Native has no per-client policy (decision
/// 87ce011 #4), so the endpoint takes the conservative single answer for every
/// client: sensitive material stays out of this interface. The person still
/// reads it in Native. A future per-client switch would replace this constant.
pub(super) const ALLOW_SENSITIVE: bool = false;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum ValueType {
    String,
    Boolean,
    Enum,
    Array,
}

impl ValueType {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::String => "STRING",
            Self::Boolean => "BOOLEAN",
            Self::Enum => "ENUM",
            Self::Array => "ARRAY",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum Scope {
    Global,
    Location,
}

impl Scope {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Global => "GLOBAL",
            Self::Location => "LOCATION",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Definition {
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub description: String,
    pub value_type: ValueType,
    pub scope: Scope,
    #[serde(default)]
    pub options: Option<Vec<String>>,
    #[serde(default)]
    pub is_sensitive: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub archived_at: Option<String>,
    /// The OAuth client that last wrote this definition through `/hcp`, for the
    /// `native` block's `recordedBy`. Absent on definitions written before it
    /// was recorded; never shown on the definition itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}

impl Definition {
    pub(super) fn category(&self) -> &str {
        category_of(&self.slug)
    }

    pub(super) fn is_active(&self) -> bool {
        self.archived_at.is_none()
    }

    /// `listPreferenceSlugs` entry.
    pub(super) fn catalog_entry(&self) -> Value {
        let mut entry = serde_json::Map::new();
        entry.insert("slug".into(), self.slug.clone().into());
        entry.insert("category".into(), self.category().into());
        if let Some(name) = &self.display_name {
            entry.insert("displayName".into(), name.clone().into());
        }
        entry.insert("description".into(), self.description.clone().into());
        entry.insert("valueType".into(), self.value_type.as_str().into());
        if let Some(options) = &self.options {
            entry.insert("options".into(), serde_json::json!(options));
        }
        entry.insert("scope".into(), self.scope.as_str().into());
        Value::Object(entry)
    }

    /// `mutatePreferences` definition output.
    pub(super) fn wire(&self) -> Value {
        serde_json::json!({
            "id": self.id,
            "slug": self.slug,
            "category": self.category(),
            "displayName": self.display_name,
            "description": self.description,
            "valueType": self.value_type.as_str(),
            "scope": self.scope.as_str(),
            "options": self.options,
            "isSensitive": self.is_sensitive,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "archivedAt": self.archived_at,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct Catalog {
    pub contract: String,
    #[serde(default)]
    pub definitions: Vec<Definition>,
}

impl Catalog {
    pub(super) fn empty() -> Self {
        Self {
            contract: CATALOG_CONTRACT.into(),
            definitions: Vec::new(),
        }
    }

    pub(super) fn active(&self, slug: &str) -> Option<&Definition> {
        self.definitions
            .iter()
            .find(|definition| definition.slug == slug && definition.is_active())
    }
}

/// The category is derived from the slug, never stored.
pub(super) fn category_of(slug: &str) -> &str {
    slug.split('.').next().unwrap_or(slug)
}

/// `/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/` — lowercase, at least one dot.
pub(super) fn valid_slug(slug: &str) -> bool {
    let mut parts = slug.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let mut chars = first.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_lowercase()) {
        return false;
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return false;
    }
    let mut rest = 0;
    for part in parts {
        rest += 1;
        if part.is_empty()
            || !part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return false;
        }
    }
    rest > 0
}

/// Validate a decoded value against its definition. `Err` carries the message
/// for `INVALID_PREFERENCE_VALUE`.
pub(super) fn validate_value(definition: &Definition, value: &Value) -> Result<(), String> {
    let ok = match definition.value_type {
        ValueType::String => value.is_string(),
        ValueType::Boolean => value.is_boolean(),
        ValueType::Enum => value.as_str().is_some_and(|candidate| {
            definition
                .options
                .as_ref()
                .is_some_and(|options| options.iter().any(|option| option == candidate))
        }),
        ValueType::Array => value.is_array(),
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "Value does not match {} for {}",
            definition.value_type.as_str(),
            definition.slug
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_rules_match_the_contract() {
        for ok in ["writing.length", "a.b.c", "food_diet.allergies_2", "a.0"] {
            assert!(valid_slug(ok), "{ok}");
        }
        for bad in [
            "",
            "writing",
            "Writing.length",
            "1a.b",
            "_a.b",
            "a..b",
            "a.b.",
            ".a.b",
            "a-b.c",
            "a.B",
        ] {
            assert!(!valid_slug(bad), "{bad}");
        }
        assert_eq!(category_of("writing.length.v2"), "writing");
    }
}
