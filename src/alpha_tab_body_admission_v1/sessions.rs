//! Immutable session.body.v1 declaration grammar from26f5a47.
use serde_json::Value;

pub const SESSION_BODY_V1: &str = "session.body.v1";

pub const DECLARATION_KEYS: [&str; 3] = ["needs", "effects", "sessions"];
const SESSION_KEYS: [&str; 5] = ["session", "key", "scope", "mode", "presence"];
const SCOPE_KEYS: [&str; 2] = ["type", "kind"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDescriptor {
    pub key: String,
    pub scope_type: String,
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
