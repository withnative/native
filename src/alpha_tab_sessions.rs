//! Optional `sessions` entries in an alpha-tab declaration (`session.body.v1`).
//!
//! Shared, dependency-free descriptor validation/canonicalisation consumed by
//! both the `manage_alpha_tabs` declaration gate (`crate::mcp::tools::alpha_tabs`)
//! and the control-event consent validation (`crate::control`). It deliberately
//! knows nothing about MCP tools, control, transport or authority: it only
//! pins the declared shape so the consent digest covers it.
//!
//! A declaration without `sessions` is untouched: [`canonical_sessions`]
//! returns `None` and callers must not add the key, so legacy canonical bytes
//! and digests stay byte-identical. `sessions` is optional and has no numeric
//! cap (the contract specifies none).

use serde_json::Value;

/// The only session kind this contract names today.
pub const SESSION_BODY_V1: &str = "session.body.v1";

/// Top-level declaration keys this contract reserves. The tool gate requires
/// `needs` + `effects` and permits optional `sessions`; nothing else.
pub const DECLARATION_KEYS: [&str; 3] = ["needs", "effects", "sessions"];
const SESSION_KEYS: [&str; 5] = ["session", "key", "scope", "mode", "presence"];
const SCOPE_KEYS: [&str; 2] = ["type", "kind"];

/// One declared session descriptor (`session.body.v1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDescriptor {
    pub key: String,
    pub scope_type: String,
    /// The record kind, or `"*"`; any non-empty string is accepted.
    pub scope_kind: String,
    pub mode: SessionMode,
    pub presence: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    Edit,
    View,
}

impl SessionMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Edit => "edit",
            Self::View => "view",
        }
    }
}

fn non_empty_string(value: Option<&Value>, what: &str) -> Result<String, String> {
    match value.and_then(Value::as_str) {
        Some(text) if !text.trim().is_empty() => Ok(text.to_string()),
        _ => Err(format!("{what} must be a non-empty string")),
    }
}

/// Parse the optional top-level `sessions` member of a declaration.
///
/// `None` (the key absent) yields an empty list; a present array is validated
/// entry by entry. Only the five descriptor keys, the `scope` pair and the
/// named `session.body.v1` are accepted; no cap is imposed.
pub fn parse_sessions(sessions: Option<&Value>) -> Result<Vec<SessionDescriptor>, String> {
    let Some(value) = sessions else {
        return Ok(Vec::new());
    };
    let entries = value.as_array().ok_or("sessions must be an array")?;
    let mut out = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or_else(|| format!("sessions[{index}] must be an object"))?;
        for key in object.keys() {
            if !SESSION_KEYS.contains(&key.as_str()) {
                return Err(format!("sessions[{index}] holds unknown key '{key}'"));
            }
        }
        match object.get("session").and_then(Value::as_str) {
            Some(SESSION_BODY_V1) => {}
            _ => {
                return Err(format!(
                    "sessions[{index}].session must be '{SESSION_BODY_V1}'"
                ))
            }
        }
        let key = non_empty_string(object.get("key"), &format!("sessions[{index}].key"))?;
        let scope = object
            .get("scope")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("sessions[{index}].scope must be an object"))?;
        for scope_key in scope.keys() {
            if !SCOPE_KEYS.contains(&scope_key.as_str()) {
                return Err(format!(
                    "sessions[{index}].scope holds unknown key '{scope_key}'"
                ));
            }
        }
        let scope_type =
            non_empty_string(scope.get("type"), &format!("sessions[{index}].scope.type"))?;
        let scope_kind =
            non_empty_string(scope.get("kind"), &format!("sessions[{index}].scope.kind"))?;
        let mode = match object.get("mode").and_then(Value::as_str) {
            Some("edit") => SessionMode::Edit,
            Some("view") => SessionMode::View,
            _ => return Err(format!("sessions[{index}].mode must be 'edit' or 'view'")),
        };
        let presence = object
            .get("presence")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("sessions[{index}].presence must be a boolean"))?;
        out.push(SessionDescriptor {
            key,
            scope_type,
            scope_kind,
            mode,
            presence,
        });
    }
    Ok(out)
}

/// Validate a whole declaration object's optional `sessions` member.
///
/// Legacy declarations are untouched: when `sessions` is absent this returns
/// `Ok(())` **without** imposing any key allowlist, so the control consent
/// seam does not narrow the object it already accepted. Only a present
/// `sessions` member is validated against the reserved descriptor shape.
pub fn validate_declaration_sessions(declaration: &Value) -> Result<(), String> {
    let object = declaration
        .as_object()
        .ok_or("declaration must be an object")?;
    match object.get("sessions") {
        None => Ok(()),
        Some(sessions) => parse_sessions(Some(sessions)).map(|_| ()),
    }
}

/// Deterministic canonical form of a present `sessions` array, or `None` when
/// the key is absent (so callers never add it to a legacy canonical object).
pub fn canonical_sessions(sessions: Option<&Value>) -> Result<Option<Vec<Value>>, String> {
    let Some(value) = sessions else {
        return Ok(None);
    };
    let mut descriptors = parse_sessions(Some(value))?;
    descriptors.sort_by(|left, right| {
        (
            &left.key,
            &left.scope_type,
            &left.scope_kind,
            left.mode.as_str(),
            left.presence,
        )
            .cmp(&(
                &right.key,
                &right.scope_type,
                &right.scope_kind,
                right.mode.as_str(),
                right.presence,
            ))
    });
    let canonical = descriptors
        .into_iter()
        .map(|descriptor| {
            serde_json::json!({
                "session": SESSION_BODY_V1,
                "key": descriptor.key,
                "scope": { "type": descriptor.scope_type, "kind": descriptor.scope_kind },
                "mode": descriptor.mode.as_str(),
                "presence": descriptor.presence,
            })
        })
        .collect();
    Ok(Some(canonical))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_sessions_are_none_and_present_ones_canonicalise_in_order() {
        assert_eq!(canonical_sessions(None).unwrap(), None);
        let value = json!([
            {"session": "session.body.v1", "key": "z", "scope": {"type": "B", "kind": "*"}, "mode": "view", "presence": false},
            {"session": "session.body.v1", "key": "a", "scope": {"type": "A", "kind": "note"}, "mode": "edit", "presence": true},
        ]);
        let canonical = canonical_sessions(Some(&value)).unwrap().unwrap();
        assert_eq!(canonical[0]["key"], json!("a"));
        assert_eq!(canonical[1]["key"], json!("z"));
        assert_eq!(canonical[0]["presence"], json!(true));
        assert_eq!(canonical[1]["scope"]["kind"], json!("*"));
    }

    #[test]
    fn malformed_sessions_descriptors_are_refused() {
        for bad in [
            json!([{"session": "other", "key": "k", "scope": {"type": "A", "kind": "note"}, "mode": "edit", "presence": true}]),
            json!([{"session": "session.body.v1", "key": "", "scope": {"type": "A", "kind": "note"}, "mode": "edit", "presence": true}]),
            json!([{"session": "session.body.v1", "key": "k", "scope": {"type": "A"}, "mode": "edit", "presence": true}]),
            json!([{"session": "session.body.v1", "key": "k", "scope": {"type": "A", "kind": "note"}, "mode": "edit", "presence": 1}]),
            json!([{"session": "session.body.v1", "key": "k", "scope": {"type": "A", "kind": "note"}, "mode": "edit", "presence": true, "x": 0}]),
            json!("not-an-array"),
        ] {
            assert!(parse_sessions(Some(&bad)).is_err(), "{bad}");
        }
        assert!(validate_declaration_sessions(&json!({"needs": [], "effects": [], "sessions": [
            {"session": "session.body.v1", "key": "k", "scope": {"type": "A", "kind": "*"}, "mode": "view", "presence": false}
        ]}))
        .is_ok());
        // A present but malformed `sessions` refuses; an absent one never
        // narrows the legacy object, even with extra fields.
        assert!(validate_declaration_sessions(
            &json!({"needs": [], "effects": [], "sessions": "no"})
        )
        .is_err());
        assert!(
            validate_declaration_sessions(&json!({"needs": [], "effects": [], "nope": []})).is_ok()
        );
        assert!(validate_declaration_sessions(&json!({"legacy": true, "whatever": 1})).is_ok());
    }
}
