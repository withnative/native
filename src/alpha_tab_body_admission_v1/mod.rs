//! Frozen structural alpha-tab-body-admission.v1, selected ONLY by adopted.v2.
//! Baseline26f5a47 + e04c241 descriptor; accepted P1 amendment separates SQL safety.
//! No SQL classifier, catalog, AST, preparation, dependency or execution calls.
//! This is commitment validation, not issuer authentication or SQL/effect authority.
//! Fresh genuine issuance and every actual SQL/effect execution retain current safety.
//! Widening these historical rules/bytes requires a new admission/event version.
mod effects;
mod sessions;
use crate::error::{Error, Result};
use effects::*;
use serde_json::{json, Value};
const TOOL: &str = "alpha-tab-body-admission.v1";
const SQL_SNAPSHOT_NEED: &str = "sql.snapshot.v1";
const SQL_SNAPSHOT_MAX_NEEDS: usize = 8;
const SQL_SNAPSHOT_KEY_MAX_CHARS: usize = 40;
const SQL_SNAPSHOT_LABEL_MAX_CHARS: usize = 120;
const SQL_SNAPSHOT_SQL_MAX_BYTES: usize = 4096;
const SQL_SNAPSHOT_MAX_PARAMS: usize = 8;
const SQL_PARAM_TEXT_DEFAULT_MAX_LEN: usize = 256;
const SQL_PARAM_TEXT_HARD_CAP: usize = 1024;
const FACET_SET_EFFECT: &str = "records.facet-set.v1";
const COMMENT_CREATE_EFFECT: &str = "comment.create.v1";
const COMMENT_CREATE_MAX_BODY_BYTES: usize = 4096;
const MESSAGE_REACT_EFFECT: &str = "message.react.v1";
const TITLE_SET_EFFECT: &str = "records.title-set.v1";
const ATTENTION_QUERY_NEED: &str = "attention.query.v1";
const RECORDS_SEARCH_NEED: &str = "records.search.v1";
const RECORDS_RESOLVE_REFERENCE_NEED: &str = "records.resolve_reference.v1";
const CANVAS_SCENE_NEED: &str = "canvas.scene.v1";
const RECORD_CHANGES_NEED: &str = "records.changes.v1";
// Snapshot of baseline spine + engine-dispatched + record-create + triage keys.
fn is_ordinary_facet_key(key: &str) -> bool {
    ![
        "lifecycle",
        "owner",
        "persistence",
        "maturity",
        "archived",
        "blob_ref",
        "runtime",
        "canvas.promoted_from",
        "retraction",
        "name",
        "body",
        "summary",
        "triage",
    ]
    .contains(&key)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlParam {
    pub name: String,
    pub param_type: SqlParamType,
    pub max_len: usize,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlParamType {
    Text,
    Integer,
    TimestampMs,
}

impl SqlParamType {
    fn as_str(&self) -> &'static str {
        match self {
            SqlParamType::Text => "text",
            SqlParamType::Integer => "integer",
            SqlParamType::TimestampMs => "timestamp_ms",
        }
    }

    fn parse(value: &str) -> Option<SqlParamType> {
        match value {
            "text" => Some(SqlParamType::Text),
            "integer" => Some(SqlParamType::Integer),
            "timestamp_ms" => Some(SqlParamType::TimestampMs),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlNeed {
    pub key: String,
    pub label: String,
    pub sql: String,
    pub params: Vec<SqlParam>,
}

pub(crate) fn valid_sql_need_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > SQL_SNAPSHOT_KEY_MAX_CHARS {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'.'
    })
}
fn valid_sql_param_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}
fn parse_sql_param_entry(entry: &Value) -> std::result::Result<SqlParam, String> {
    let object = entry
        .as_object()
        .ok_or_else(|| format!("{TOOL}: sql param entry must be an object [invalid_sql_need]"))?;
    let has_max_len = object.contains_key("max_len");
    let has_required = object.contains_key("required");
    let allowed = 2 + usize::from(has_max_len) + usize::from(has_required);
    if object.len() != allowed || !object.contains_key("name") || !object.contains_key("type") {
        return Err(format!(
            "{TOOL}: sql param entry must hold exactly 'name', 'type' with optional 'max_len' and 'required' [invalid_sql_need]"
        ));
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql param 'name' must be a string [invalid_sql_need]"))?;
    if !valid_sql_param_name(name) {
        return Err(format!(
            "{TOOL}: sql param 'name' must match ^[a-z][a-z0-9_]{{0,31}}$ [invalid_sql_need]"
        ));
    }
    let type_str = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql param 'type' must be a string [invalid_sql_need]"))?;
    let param_type = SqlParamType::parse(type_str).ok_or_else(|| {
        format!("{TOOL}: sql param 'type' must be one of text, integer, timestamp_ms [invalid_sql_need]")
    })?;
    let max_len = match object.get("max_len") {
        None => SQL_PARAM_TEXT_DEFAULT_MAX_LEN,
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                format!("{TOOL}: sql param 'max_len' must be an integer [invalid_sql_need]")
            })?;
            if raw == 0 || raw > SQL_PARAM_TEXT_HARD_CAP as u64 {
                return Err(format!(
                    "{TOOL}: sql param 'max_len' must be 1..=1024 [invalid_sql_need]"
                ));
            }
            raw as usize
        }
    };
    if param_type != SqlParamType::Text && has_max_len {
        return Err(format!(
            "{TOOL}: sql param 'max_len' applies only to text params [invalid_sql_need]"
        ));
    }
    let required = match object.get("required") {
        None => true,
        Some(Value::Bool(required)) => *required,
        Some(_) => {
            return Err(format!(
                "{TOOL}: sql param 'required' must be a boolean [invalid_sql_need]"
            ));
        }
    };
    Ok(SqlParam {
        name: name.to_string(),
        param_type,
        max_len,
        required,
    })
}
pub(crate) const BODY_READ_NEED: &str = "records.body.read.v1";
pub(crate) const BODY_READ_SCOPE: &str = "viewer-visible-current-bodies";

enum DeclarationNeed<'a> {
    Name(&'a str),
    Sql(SqlNeed),
    BodyRead,
}

fn classify_declaration_need(entry: &Value) -> std::result::Result<DeclarationNeed<'_>, String> {
    if let Some(name) = entry.as_str() {
        return Ok(DeclarationNeed::Name(name));
    }
    if entry.get("need").and_then(Value::as_str) == Some(BODY_READ_NEED) {
        let valid = entry.as_object().is_some_and(|object| {
            object.len() == 2
                && object.get("scope").and_then(Value::as_str) == Some(BODY_READ_SCOPE)
        });
        if !valid {
            return Err(format!(
                "{TOOL}: body read descriptor must hold exactly 'need' and 'scope' with scope '{BODY_READ_SCOPE}' [invalid_body_read_need]"
            ));
        }
        return Ok(DeclarationNeed::BodyRead);
    }
    parse_sql_need_entry(entry).map(DeclarationNeed::Sql)
}

fn body_read_descriptor_in(declaration: &Value) -> std::result::Result<bool, String> {
    let Some(entries) = declaration.get("needs").and_then(Value::as_array) else {
        return Ok(false);
    };
    if !entries
        .iter()
        .any(|entry| entry.get("need").and_then(Value::as_str) == Some(BODY_READ_NEED))
    {
        return Ok(false);
    }
    if entries.len() > 64 {
        return Err(format!(
            "{TOOL}: declaration 'needs' holds at most 64 entries [invalid_body_read_need]"
        ));
    }
    let mut count = 0;
    for entry in entries {
        match classify_declaration_need(entry)? {
            DeclarationNeed::BodyRead => count += 1,
            DeclarationNeed::Name(BODY_READ_NEED) => {
                return Err(format!(
                "{TOOL}: body read descriptor duplicates a string need [invalid_body_read_need]"
            ))
            }
            DeclarationNeed::Sql(need) if need.key == BODY_READ_NEED => {
                return Err(format!(
                    "{TOOL}: body read descriptor duplicates an SQL key [invalid_body_read_need]"
                ))
            }
            _ => {}
        }
    }
    if count != 1 {
        return Err(format!(
            "{TOOL}: declaration holds at most one body read descriptor [invalid_body_read_need]"
        ));
    }
    Ok(true)
}

pub(crate) fn parse_sql_need_entry(entry: &Value) -> std::result::Result<SqlNeed, String> {
    let object = entry.as_object().ok_or_else(|| {
        format!("{TOOL}: declaration 'needs' sql entry must be an object [invalid_sql_need]")
    })?;
    let has_params = object.contains_key("params");
    let allowed = 4 + usize::from(has_params);
    if object.len() != allowed
        || object.get("need").and_then(Value::as_str) != Some(SQL_SNAPSHOT_NEED)
        || !object.contains_key("key")
        || !object.contains_key("label")
        || !object.contains_key("sql")
    {
        return Err(format!(
            "{TOOL}: declaration 'needs' sql entry must hold exactly 'need', 'key', 'label' and 'sql' with optional 'params' [invalid_sql_need]"
        ));
    }
    let key = object
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql need 'key' must be a string [invalid_sql_need]"))?;
    if !valid_sql_need_key(key) {
        return Err(format!(
            "{TOOL}: sql need 'key' must match ^[a-z][a-z0-9_.]{{0,39}}$ [invalid_sql_need]"
        ));
    }
    if key == ATTENTION_QUERY_NEED
        || key == RECORDS_SEARCH_NEED
        || key == RECORDS_RESOLVE_REFERENCE_NEED
        || key == CANVAS_SCENE_NEED
        || key == RECORD_CHANGES_NEED
    {
        return Err(format!(
            "{TOOL}: sql need 'key' must not collide with a host need name [invalid_sql_need]"
        ));
    }
    let label = object
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql need 'label' must be a string [invalid_sql_need]"))?;
    if label.is_empty() || label.chars().count() > SQL_SNAPSHOT_LABEL_MAX_CHARS {
        return Err(format!(
            "{TOOL}: sql need 'label' must be 1..=120 characters [invalid_sql_need]"
        ));
    }
    let sql = object
        .get("sql")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql need 'sql' must be a string [invalid_sql_need]"))?;
    if sql.is_empty() || sql.len() > SQL_SNAPSHOT_SQL_MAX_BYTES {
        return Err(format!(
            "{TOOL}: sql need 'sql' must be 1..=4096 bytes [invalid_sql_need]"
        ));
    }
    let params = match object.get("params") {
        None => Vec::new(),
        Some(Value::Array(entries)) => {
            if entries.len() > SQL_SNAPSHOT_MAX_PARAMS {
                return Err(format!(
                    "{TOOL}: sql need '{key}' holds at most 8 params [invalid_sql_need]"
                ));
            }
            let mut parsed: Vec<SqlParam> = Vec::with_capacity(entries.len());
            for entry in entries {
                parsed.push(parse_sql_param_entry(entry)?);
            }
            let mut names: Vec<&str> = parsed.iter().map(|param| param.name.as_str()).collect();
            names.sort_unstable();
            for window in names.windows(2) {
                if window[0] == window[1] {
                    return Err(format!(
                        "{TOOL}: sql need '{key}' param '{}' is duplicated [invalid_sql_need]",
                        window[0]
                    ));
                }
            }
            parsed
        }
        Some(_) => {
            return Err(format!(
                "{TOOL}: sql need 'params' must be an array [invalid_sql_need]"
            ));
        }
    };
    Ok(SqlNeed {
        key: key.to_string(),
        label: label.to_string(),
        sql: sql.to_string(),
        params,
    })
}
fn canonical_sql_params(params: &[SqlParam]) -> Value {
    Value::Array(
        params
            .iter()
            .map(|param| {
                if param.param_type == SqlParamType::Text {
                    json!({
                        "name": param.name,
                        "type": param.param_type.as_str(),
                        "max_len": param.max_len,
                        "required": param.required,
                    })
                } else {
                    json!({
                        "name": param.name,
                        "type": param.param_type.as_str(),
                        "required": param.required,
                    })
                }
            })
            .collect(),
    )
}
fn validate_structure(declaration: &Value) -> Result<()> {
    let object = declaration
        .as_object()
        .ok_or_else(|| Error::engine(format!("{TOOL}: declaration must be an object")))?;
    for key in object.keys() {
        if !sessions::DECLARATION_KEYS.contains(&key.as_str()) {
            return Err(Error::engine(format!(
                "{TOOL}: declaration holds unknown key '{key}'"
            )));
        }
    }
    if !object.contains_key("needs") || !object.contains_key("effects") {
        return Err(Error::engine(format!(
            "{TOOL}: declaration must hold 'needs' and 'effects' (and optional 'sessions')"
        )));
    }
    let effect_entries = object["effects"]
        .as_array()
        .ok_or_else(|| Error::engine(format!("{TOOL}: declaration 'effects' must be an array")))?;
    if effect_entries.len() > 64 {
        return Err(Error::engine(format!(
            "{TOOL}: declaration 'effects' holds at most 64 entries"
        )));
    }

    for entry in effect_entries {
        if let Some(name) = entry.as_str() {
            if name == FACET_SET_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'records.facet-set.v1' consents to no key, values or need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name == COMMENT_CREATE_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'comment.create.v1' consents to no positions, cap or need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name == MESSAGE_REACT_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'message.react.v1' consents to no emoji or need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name == TITLE_SET_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'records.title-set.v1' consents to no need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name.trim().is_empty() || name.len() > 128 {
                return Err(Error::engine(format!(
                    "{TOOL}: declaration 'effects' entries must be 1..128 characters"
                )));
            }
        } else if entry.is_object() {
            if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(COMMENT_CREATE_EFFECT)
            {
                parse_comment_create_bound(entry).map_err(Error::engine)?;
            } else if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(MESSAGE_REACT_EFFECT)
            {
                parse_message_react_bound(entry).map_err(Error::engine)?;
            } else if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(TITLE_SET_EFFECT)
            {
                parse_title_set_bound(entry).map_err(Error::engine)?;
            } else {
                parse_facet_set_bound(entry).map_err(Error::engine)?;
            }
        } else {
            return Err(Error::engine(format!(
                "{TOOL}: declaration 'effects' entries must be strings or facet-set objects"
            )));
        }
    }
    let facet_sets = parse_facet_set_bounds(declaration).map_err(Error::engine)?;
    let comment_bounds = parse_comment_create_bounds(declaration).map_err(Error::engine)?;
    let react_bounds = parse_message_react_bounds(declaration).map_err(Error::engine)?;
    let title_bounds = parse_title_set_bounds(declaration).map_err(Error::engine)?;
    let need_entries = object["needs"]
        .as_array()
        .ok_or_else(|| Error::engine(format!("{TOOL}: declaration 'needs' must be an array")))?;
    if need_entries.len() > 64 {
        return Err(Error::engine(format!(
            "{TOOL}: declaration 'needs' holds at most 64 entries"
        )));
    }
    let mut needs = Vec::new();
    let mut sql_needs = Vec::new();
    for entry in need_entries {
        if let Some(name) = entry.as_str() {
            if name.trim().is_empty() || name.len() > 128 {
                return Err(Error::engine(format!(
                    "{TOOL}: declaration 'needs' entries must be 1..128 characters"
                )));
            }
            needs.push(name.to_string());
        } else if entry.is_object() {
            match classify_declaration_need(entry).map_err(Error::engine)? {
                DeclarationNeed::Sql(need) => sql_needs.push(need),
                DeclarationNeed::BodyRead => {}
                DeclarationNeed::Name(_) => unreachable!("object need"),
            }
        } else {
            return Err(Error::engine(format!(
                "{TOOL}: declaration 'needs' entries must be strings or sql.snapshot.v1 objects"
            )));
        }
    }
    if sql_needs.len() > SQL_SNAPSHOT_MAX_NEEDS {
        return Err(Error::engine(format!(
            "{TOOL}: declaration holds at most 8 sql.snapshot.v1 needs [invalid_sql_need]"
        )));
    }
    let mut keys: Vec<&str> = sql_needs.iter().map(|need| need.key.as_str()).collect();
    keys.sort_unstable();
    for window in keys.windows(2) {
        if window[0] == window[1] {
            return Err(Error::engine(format!(
                "{TOOL}: sql need key '{}' is duplicated [invalid_sql_need]",
                window[0]
            )));
        }
    }
    for key in &keys {
        if needs.iter().any(|name| name == key) {
            return Err(Error::engine(format!(
                "{TOOL}: sql need key '{key}' duplicates a string need [invalid_sql_need]"
            )));
        }
    }
    sql_needs.sort_by(|left, right| left.key.cmp(&right.key));
    for bound in &facet_sets {
        if !sql_needs.iter().any(|need| need.key == bound.need) {
            return Err(Error::engine(format!(
                "{TOOL}: facet-set bound targets undeclared need '{}' [invalid_effect]",
                bound.need
            )));
        }
    }
    for bound in &comment_bounds {
        if !sql_needs.iter().any(|need| need.key == bound.need) {
            return Err(Error::engine(format!(
                "{TOOL}: comment.create bound targets undeclared need '{}' [invalid_effect]",
                bound.need
            )));
        }
    }
    for bound in &react_bounds {
        if !sql_needs.iter().any(|need| need.key == bound.need) {
            return Err(Error::engine(format!(
                "{TOOL}: message.react bound targets undeclared need '{}' [invalid_effect]",
                bound.need
            )));
        }
    }
    for bound in &title_bounds {
        if !sql_needs.iter().any(|need| need.key == bound.need) {
            return Err(Error::engine(format!(
                "{TOOL}: title-set bound targets undeclared need '{}' [invalid_effect]",
                bound.need
            )));
        }
    }
    sessions::parse_sessions(object.get("sessions")).map_err(Error::engine)?;
    body_read_descriptor_in(declaration).map_err(Error::engine)?;
    Ok(())
}
pub(crate) fn canonical_declaration(declaration: &Value) -> Result<Value> {
    validate_structure(declaration)?;
    let names = |key: &str| -> Vec<String> {
        let mut out: Vec<String> = declaration
            .get(key)
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    };
    let body_read = body_read_descriptor_in(declaration).map_err(Error::engine)?;
    let mut sql_needs: Vec<Value> = Vec::new();
    if let Some(entries) = declaration.get("needs").and_then(Value::as_array) {
        for entry in entries {
            if entry.is_string() {
                continue;
            }
            let parsed = match classify_declaration_need(entry).map_err(Error::engine)? {
                DeclarationNeed::Sql(need) => need,
                DeclarationNeed::Name(_) | DeclarationNeed::BodyRead => continue,
            };
            if parsed.params.is_empty() {
                sql_needs.push(json!({
                    "key": parsed.key,
                    "label": parsed.label,
                    "need": SQL_SNAPSHOT_NEED,
                    "sql": parsed.sql,
                }));
            } else {
                sql_needs.push(json!({
                    "key": parsed.key,
                    "label": parsed.label,
                    "need": SQL_SNAPSHOT_NEED,
                    "sql": parsed.sql,
                    "params": canonical_sql_params(&parsed.params),
                }));
            }
        }
    }
    sql_needs.sort_by(|left, right| {
        let key = |value: &Value| {
            (
                value
                    .get("key")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                value
                    .get("sql")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            )
        };
        key(left).cmp(&key(right))
    });
    let mut effect_objects: Vec<Value> = Vec::new();
    if let Some(entries) = declaration.get("effects").and_then(Value::as_array) {
        for entry in entries {
            if entry.is_string() {
                continue;
            }
            if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(COMMENT_CREATE_EFFECT)
            {
                let bound = parse_comment_create_bound(entry).map_err(Error::engine)?;
                effect_objects.push(json!({
                    "effect": COMMENT_CREATE_EFFECT,
                    "positions": bound.positions,
                    "target": { "need": bound.need },
                    "max_body_bytes": bound.max_body_bytes,
                }));
                continue;
            }
            if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(MESSAGE_REACT_EFFECT)
            {
                let bound = parse_message_react_bound(entry).map_err(Error::engine)?;
                effect_objects.push(json!({
                    "effect": MESSAGE_REACT_EFFECT,
                    "emoji": bound.emoji,
                    "target": { "need": bound.need },
                }));
                continue;
            }
            if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(TITLE_SET_EFFECT)
            {
                let bound = parse_title_set_bound(entry).map_err(Error::engine)?;
                effect_objects.push(json!({
                    "effect": TITLE_SET_EFFECT,
                    "target": { "need": bound.need },
                }));
                continue;
            }
            let bound = parse_facet_set_bound(entry).map_err(Error::engine)?;
            effect_objects.push(json!({
                "effect": FACET_SET_EFFECT,
                "key": bound.key,
                "target": { "need": bound.need },
                "values": bound.values,
            }));
        }
    }
    effect_objects.sort_by_cached_key(crate::canonical_json::digest_json);
    let mut effects: Vec<Value> = names("effects").into_iter().map(Value::String).collect();
    effects.extend(effect_objects);
    let mut canonical = if sql_needs.is_empty() {
        json!({"needs": names("needs"), "effects": effects})
    } else {
        json!({"needs": names("needs"), "effects": effects, "sql_needs": sql_needs})
    };
    if declaration.get("sessions").is_some() {
        let sessions =
            sessions::canonical_sessions(declaration.get("sessions")).map_err(Error::engine)?;
        if let (Some(object), Some(list)) = (canonical.as_object_mut(), sessions) {
            object.insert("sessions".to_string(), Value::Array(list));
        }
    }
    if body_read {
        canonical
            .as_object_mut()
            .expect("canonical declaration object")
            .insert(
                "body_read_needs".into(),
                json!([{ "need": BODY_READ_NEED, "scope": BODY_READ_SCOPE }]),
            );
    }
    Ok(canonical)
}
pub(crate) fn declaration_digest(declaration: &Value) -> Result<String> {
    Ok(crate::canonical_json::digest_json(&canonical_declaration(
        declaration,
    )?))
}
pub(crate) fn has_body_descriptor(declaration: &Value) -> Result<bool> {
    validate_structure(declaration)?;
    body_read_descriptor_in(declaration).map_err(Error::engine)
}
pub(crate) fn install_digest(
    bundle_sha256_hex: &str,
    declaration_digest_hex: &str,
    runtime: &str,
) -> String {
    let input = json!({
        "bundle_sha256": bundle_sha256_hex,
        "declaration_digest": declaration_digest_hex,
        "runtime": runtime,
    });
    format!("sha256:{}", crate::canonical_json::digest_json(&input))
}

#[cfg(test)]
mod tests;
