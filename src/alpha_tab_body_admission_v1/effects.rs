//! Immutable structural effect bounds from26f5a47, alpha-tab-body-admission.v1.
use serde_json::Value;

use super::valid_sql_need_key;
use super::{
    is_ordinary_facet_key, COMMENT_CREATE_EFFECT, COMMENT_CREATE_MAX_BODY_BYTES, FACET_SET_EFFECT,
    MESSAGE_REACT_EFFECT, TITLE_SET_EFFECT,
};

const TOOL: &str = "manage_alpha_tabs";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageReactBound {
    pub emoji: Vec<String>,
    pub need: String,
}

pub const MESSAGE_REACT_EMOJIS: [&str; 5] = ["👍", "❤️", "😂", "🎉", "👀"];

pub fn parse_message_react_bound(entry: &Value) -> std::result::Result<MessageReactBound, String> {
    let object = entry.as_object().ok_or_else(|| {
        format!("{TOOL}: declaration 'effects' entries must be strings or message.react objects [invalid_effect]")
    })?;
    if object.len() != 3
        || !object.contains_key("effect")
        || !object.contains_key("emoji")
        || !object.contains_key("target")
    {
        return Err(format!(
            "{TOOL}: message.react bound must hold exactly 'effect', 'emoji' and 'target' [invalid_effect]"
        ));
    }
    let effect = object["effect"].as_str().ok_or_else(|| {
        format!("{TOOL}: message.react bound 'effect' must be a string [invalid_effect]")
    })?;
    if effect != MESSAGE_REACT_EFFECT {
        return Err(format!(
            "{TOOL}: unsupported object effect '{effect}' [invalid_effect]"
        ));
    }
    let emoji = object["emoji"].as_array().ok_or_else(|| {
        format!("{TOOL}: message.react bound 'emoji' must be an array [invalid_effect]")
    })?;
    if emoji.is_empty() || emoji.len() > MESSAGE_REACT_EMOJIS.len() {
        return Err(format!(
            "{TOOL}: message.react bound 'emoji' must hold 1..=5 canonical values [invalid_effect]"
        ));
    }
    let mut admitted = Vec::with_capacity(emoji.len());
    for value in emoji {
        let text = value.as_str().ok_or_else(|| {
            format!("{TOOL}: message.react bound 'emoji' entries must be strings [invalid_effect]")
        })?;
        if !MESSAGE_REACT_EMOJIS.contains(&text) {
            return Err(format!(
                "{TOOL}: message.react bound emoji '{text}' is not a canonical v1 picker value [invalid_effect]"
            ));
        }
        admitted.push(text.to_string());
    }
    admitted.sort();
    admitted.dedup();
    if admitted.len() != emoji.len() {
        return Err(format!(
            "{TOOL}: message.react bound 'emoji' must not duplicate [invalid_effect]"
        ));
    }
    let target = object["target"].as_object().ok_or_else(|| {
        format!("{TOOL}: message.react bound 'target' must be an object [invalid_effect]")
    })?;
    if target.len() != 1 || !target.contains_key("need") {
        return Err(format!(
            "{TOOL}: message.react bound 'target' must hold exactly 'need' [invalid_effect]"
        ));
    }
    let need = target["need"].as_str().ok_or_else(|| {
        format!("{TOOL}: message.react bound 'target.need' must be a string [invalid_effect]")
    })?;
    if !valid_sql_need_key(need) {
        return Err(format!(
            "{TOOL}: message.react bound 'target.need' must be a sql need key [invalid_effect]"
        ));
    }
    Ok(MessageReactBound {
        emoji: admitted,
        need: need.to_string(),
    })
}

pub fn parse_message_react_bounds(
    declaration: &Value,
) -> std::result::Result<Vec<MessageReactBound>, String> {
    let mut bounds = Vec::new();
    if let Some(entries) = declaration.get("effects").and_then(Value::as_array) {
        for entry in entries {
            let Some(object) = entry.as_object() else {
                continue;
            };
            if object.get("effect").and_then(Value::as_str) != Some(MESSAGE_REACT_EFFECT) {
                continue;
            }
            bounds.push(parse_message_react_bound(entry)?);
        }
    }
    let mut seen: Vec<&str> = bounds
        .iter()
        .flat_map(|bound| bound.emoji.iter().map(String::as_str))
        .collect();
    seen.sort_unstable();
    for window in seen.windows(2) {
        if window[0] == window[1] {
            return Err(format!(
                "{TOOL}: message.react emoji '{}' occurs in more than one bound [invalid_effect]",
                window[0]
            ));
        }
    }
    Ok(bounds)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TitleSetBound {
    pub need: String,
}

pub fn parse_title_set_bound(entry: &Value) -> std::result::Result<TitleSetBound, String> {
    let object = entry.as_object().ok_or_else(|| {
        format!("{TOOL}: declaration 'effects' entries must be strings or title-set objects [invalid_effect]")
    })?;
    if object.len() != 2 || !object.contains_key("effect") || !object.contains_key("target") {
        return Err(format!(
            "{TOOL}: title-set bound must hold exactly 'effect' and 'target' [invalid_effect]"
        ));
    }
    let effect = object["effect"].as_str().ok_or_else(|| {
        format!("{TOOL}: title-set bound 'effect' must be a string [invalid_effect]")
    })?;
    if effect != TITLE_SET_EFFECT {
        return Err(format!(
            "{TOOL}: unsupported object effect '{effect}' [invalid_effect]"
        ));
    }
    let target = object["target"].as_object().ok_or_else(|| {
        format!("{TOOL}: title-set bound 'target' must be an object [invalid_effect]")
    })?;
    if target.len() != 1 || !target.contains_key("need") {
        return Err(format!(
            "{TOOL}: title-set bound 'target' must hold exactly 'need' [invalid_effect]"
        ));
    }
    let need = target["need"].as_str().ok_or_else(|| {
        format!("{TOOL}: title-set bound 'target.need' must be a string [invalid_effect]")
    })?;
    if !valid_sql_need_key(need) {
        return Err(format!(
            "{TOOL}: title-set bound 'target.need' must be a sql need key [invalid_effect]"
        ));
    }
    Ok(TitleSetBound {
        need: need.to_string(),
    })
}

pub fn parse_title_set_bounds(
    declaration: &Value,
) -> std::result::Result<Vec<TitleSetBound>, String> {
    let mut bounds = Vec::new();
    if let Some(entries) = declaration.get("effects").and_then(Value::as_array) {
        for entry in entries {
            let Some(object) = entry.as_object() else {
                continue;
            };
            if object.get("effect").and_then(Value::as_str) != Some(TITLE_SET_EFFECT) {
                continue;
            }
            bounds.push(parse_title_set_bound(entry)?);
        }
    }
    if bounds.len() > 1 {
        return Err(format!(
            "{TOOL}: title-set bound occurs more than once; a declaration holds at most one [invalid_effect]"
        ));
    }
    Ok(bounds)
}

pub const FACET_SET_VALUES_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetSetBound {
    pub key: String,
    pub values: Vec<String>,
    pub need: String,
}

pub(crate) fn parse_facet_set_bound(entry: &Value) -> std::result::Result<FacetSetBound, String> {
    let object = entry.as_object().ok_or_else(|| {
        format!("{TOOL}: declaration 'effects' entries must be strings or facet-set objects [invalid_effect]")
    })?;
    if object.len() != 4
        || !object.contains_key("effect")
        || !object.contains_key("key")
        || !object.contains_key("values")
        || !object.contains_key("target")
    {
        return Err(format!(
            "{TOOL}: facet-set bound must hold exactly 'effect', 'key', 'values' and 'target' [invalid_effect]"
        ));
    }
    let effect = object["effect"].as_str().ok_or_else(|| {
        format!("{TOOL}: facet-set bound 'effect' must be a string [invalid_effect]")
    })?;
    if effect != FACET_SET_EFFECT {
        return Err(format!(
            "{TOOL}: unsupported object effect '{effect}' [invalid_effect]"
        ));
    }
    let key = object["key"].as_str().ok_or_else(|| {
        format!("{TOOL}: facet-set bound 'key' must be a string [invalid_effect]")
    })?;
    if key.trim().is_empty() || key.len() > 128 {
        return Err(format!(
            "{TOOL}: facet-set bound 'key' must be 1..128 characters [invalid_effect]"
        ));
    }
    if !is_ordinary_facet_key(key) {
        return Err(format!(
            "{TOOL}: facet-set bound key '{key}' is not an ordinary facet \
             (spine, engine-dispatched, record field or dedicated triage facet) \
             [invalid_effect]"
        ));
    }
    let values = object["values"].as_array().ok_or_else(|| {
        format!("{TOOL}: facet-set bound 'values' must be an array [invalid_effect]")
    })?;
    if values.is_empty() || values.len() > FACET_SET_VALUES_MAX {
        return Err(format!(
            "{TOOL}: facet-set bound 'values' must hold 1..=64 strings [invalid_effect]"
        ));
    }
    let mut admitted = Vec::with_capacity(values.len());
    for value in values {
        let text = value.as_str().ok_or_else(|| {
            format!("{TOOL}: facet-set bound 'values' entries must be strings [invalid_effect]")
        })?;
        if text.len() > 128 {
            return Err(format!(
                "{TOOL}: facet-set bound 'values' entries must be at most 128 characters [invalid_effect]"
            ));
        }
        admitted.push(text.to_string());
    }
    admitted.sort();
    admitted.dedup();
    if admitted.len() != values.len() {
        return Err(format!(
            "{TOOL}: facet-set bound 'values' must not duplicate [invalid_effect]"
        ));
    }
    let target = object["target"].as_object().ok_or_else(|| {
        format!("{TOOL}: facet-set bound 'target' must be an object [invalid_effect]")
    })?;
    if target.len() != 1 || !target.contains_key("need") {
        return Err(format!(
            "{TOOL}: facet-set bound 'target' must hold exactly 'need' [invalid_effect]"
        ));
    }
    let need = target["need"].as_str().ok_or_else(|| {
        format!("{TOOL}: facet-set bound 'target.need' must be a string [invalid_effect]")
    })?;
    if !valid_sql_need_key(need) {
        return Err(format!(
            "{TOOL}: facet-set bound 'target.need' must be a sql need key [invalid_effect]"
        ));
    }
    Ok(FacetSetBound {
        key: key.to_string(),
        values: admitted,
        need: need.to_string(),
    })
}

pub(crate) fn parse_facet_set_bounds(
    declaration: &Value,
) -> std::result::Result<Vec<FacetSetBound>, String> {
    let mut bounds = Vec::new();
    if let Some(entries) = declaration.get("effects").and_then(Value::as_array) {
        for entry in entries {
            if entry.is_string() {
                continue;
            }
            if let Some(effect) = entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
            {
                if effect == COMMENT_CREATE_EFFECT
                    || effect == MESSAGE_REACT_EFFECT
                    || effect == TITLE_SET_EFFECT
                {
                    continue;
                }
            }
            bounds.push(parse_facet_set_bound(entry)?);
        }
    }
    let mut keys: Vec<&str> = bounds.iter().map(|bound| bound.key.as_str()).collect();
    keys.sort_unstable();
    for window in keys.windows(2) {
        if window[0] == window[1] {
            return Err(format!(
                "{TOOL}: facet-set bound for key '{}' is duplicated [invalid_effect]",
                window[0]
            ));
        }
    }
    Ok(bounds)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentCreateBound {
    pub positions: Vec<String>,
    pub max_body_bytes: usize,
    pub need: String,
}

pub(crate) const COMMENT_CREATE_POSITIONS: [&str; 2] = ["reply", "root"];

pub(crate) fn parse_comment_create_bound(
    entry: &Value,
) -> std::result::Result<CommentCreateBound, String> {
    let object = entry.as_object().ok_or_else(|| {
        format!("{TOOL}: declaration 'effects' entries must be strings or comment.create objects [invalid_effect]")
    })?;
    if object.len() != 4
        || !object.contains_key("effect")
        || !object.contains_key("positions")
        || !object.contains_key("max_body_bytes")
        || !object.contains_key("target")
    {
        return Err(format!(
            "{TOOL}: comment.create bound must hold exactly 'effect', 'positions', 'max_body_bytes' and 'target' [invalid_effect]"
        ));
    }
    let effect = object["effect"].as_str().ok_or_else(|| {
        format!("{TOOL}: comment.create bound 'effect' must be a string [invalid_effect]")
    })?;
    if effect != COMMENT_CREATE_EFFECT {
        return Err(format!(
            "{TOOL}: unsupported object effect '{effect}' [invalid_effect]"
        ));
    }
    let positions = object["positions"].as_array().ok_or_else(|| {
        format!("{TOOL}: comment.create bound 'positions' must be an array [invalid_effect]")
    })?;
    if positions.is_empty() || positions.len() > COMMENT_CREATE_POSITIONS.len() {
        return Err(format!(
            "{TOOL}: comment.create bound 'positions' must hold 1..=2 of 'root'/'reply' [invalid_effect]"
        ));
    }
    let mut admitted = Vec::with_capacity(positions.len());
    for position in positions {
        let text = position.as_str().ok_or_else(|| {
            format!(
                "{TOOL}: comment.create bound 'positions' entries must be strings [invalid_effect]"
            )
        })?;
        if !COMMENT_CREATE_POSITIONS.contains(&text) {
            return Err(format!(
                "{TOOL}: comment.create bound position '{text}' must be 'root' or 'reply' [invalid_effect]"
            ));
        }
        admitted.push(text.to_string());
    }
    admitted.sort();
    admitted.dedup();
    if admitted.len() != positions.len() {
        return Err(format!(
            "{TOOL}: comment.create bound 'positions' must not duplicate [invalid_effect]"
        ));
    }
    let max_body_bytes = object
        .get("max_body_bytes")
        .and_then(|value| {
            value.as_u64().or_else(|| {
                value.as_f64().and_then(|float| {
                    (float.is_finite()
                        && float.fract() == 0.0
                        && (1.0..=COMMENT_CREATE_MAX_BODY_BYTES as f64).contains(&float))
                    .then_some(float as u64)
                })
            })
        })
        .ok_or_else(|| {
            format!(
                "{TOOL}: comment.create bound 'max_body_bytes' must be an integer [invalid_effect]"
            )
        })?;
    if max_body_bytes == 0 || max_body_bytes > COMMENT_CREATE_MAX_BODY_BYTES as u64 {
        return Err(format!(
            "{TOOL}: comment.create bound 'max_body_bytes' must hold 1..=4096 [invalid_effect]"
        ));
    }
    let target = object["target"].as_object().ok_or_else(|| {
        format!("{TOOL}: comment.create bound 'target' must be an object [invalid_effect]")
    })?;
    if target.len() != 1 || !target.contains_key("need") {
        return Err(format!(
            "{TOOL}: comment.create bound 'target' must hold exactly 'need' [invalid_effect]"
        ));
    }
    let need = target["need"].as_str().ok_or_else(|| {
        format!("{TOOL}: comment.create bound 'target.need' must be a string [invalid_effect]")
    })?;
    if !valid_sql_need_key(need) {
        return Err(format!(
            "{TOOL}: comment.create bound 'target.need' must be a sql need key [invalid_effect]"
        ));
    }
    Ok(CommentCreateBound {
        positions: admitted,
        max_body_bytes: max_body_bytes as usize,
        need: need.to_string(),
    })
}

pub(crate) fn parse_comment_create_bounds(
    declaration: &Value,
) -> std::result::Result<Vec<CommentCreateBound>, String> {
    let mut bounds = Vec::new();
    if let Some(entries) = declaration.get("effects").and_then(Value::as_array) {
        for entry in entries {
            let Some(object) = entry.as_object() else {
                continue;
            };
            if object.get("effect").and_then(Value::as_str) != Some(COMMENT_CREATE_EFFECT) {
                continue;
            }
            bounds.push(parse_comment_create_bound(entry)?);
        }
    }
    let mut seen: Vec<&str> = bounds
        .iter()
        .flat_map(|bound| bound.positions.iter().map(String::as_str))
        .collect();
    seen.sort_unstable();
    for window in seen.windows(2) {
        if window[0] == window[1] {
            return Err(format!(
                "{TOOL}: comment.create position '{}' occurs in more than one bound [invalid_effect]",
                window[0]
            ));
        }
    }
    Ok(bounds)
}
