//! App-neutral effect bound types (D7 §4C seam, tasks `07ae879` I1,
//! `da148be`, and N1 `b9fb9fd` pure move).
//!
//! Pure declaration parsing for the `records.facet-set.v1` consent object,
//! the `comment.create.v1` consent object, the `message.react.v1` consent
//! object `{effect, emoji:[...], target:{need}}` and the
//! `records.title-set.v1` consent object `{effect, target:{need}}` — no
//! database, no caller, no host. `alpha_tabs` re-exports the facet-set and
//! comment bounds so every call site compiles unchanged (D7 §6 N1).

use serde_json::Value;

use super::alpha_tabs::{valid_sql_need_key, SqlNeed};
use super::effect_admission::{AdmissionRefusal, AdmissionSource, UnconsentedReason};
use super::tab_effect_catalogue::{
    consent_shape, is_ordinary_facet_key, ConsentShape, TabEffectArm, BODY_SET_EFFECT,
    BODY_SET_MAX_BODY_BYTES, COMMENT_CREATE_EFFECT, COMMENT_CREATE_MAX_BODY_BYTES,
    FACET_SET_EFFECT, MESSAGE_REACT_EFFECT, TITLE_SET_EFFECT,
};

const TOOL: &str = "manage_alpha_tabs";

/// One consented governed message-reaction bound: the admitted emoji subset
/// (sorted at parse) and the consented static need whose delivered rows
/// bound the message. The object participates in the canonical digest, so
/// any widening changes the pin and requires re-adoption. The governed
/// reaction write path consumes it in-transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageReactBound {
    pub emoji: Vec<String>,
    pub need: String,
}

/// Canonical reaction emoji one react bound may admit. Must stay identical
/// to `MESSAGE_REACTION_EMOJIS` in `src/events.rs` and `MESSAGE_REACT_EMOJIS`
/// in `crates/artifact-runtime/src/mdx_v2.rs`.
pub const MESSAGE_REACT_EMOJIS: [&str; 5] = ["👍", "❤️", "😂", "🎉", "👀"];

/// Parse one message.react object effect entry. Pure; every refusal fails
/// the declaration (or the stored consent) closed — an invalid object never
/// digests as absent and never silently narrows to its bare name.
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

/// Parse every message.react object bound in a declaration's `effects`
/// array, in declared order. No emoji may occur in more than one bound
/// across `effects[]`, regardless of need — a fixed invocation emoji
/// therefore chooses exactly one consented need, since the manifest carries
/// no target-need field and the invocation chooses none. Duplicate
/// identical objects and overlapping emoji both refuse here.
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

/// Admit one invocation emoji against already-parsed bounds: the single
/// bound whose subset holds the emoji. Takes the parsed bound plus the
/// invocation, never the declaration — parsing stays with the caller, so
/// this stays source-neutral for the N2/N3 `DeclaringPackage` fold. Pure;
/// the guard arm calls this thinly after parsing the stored declaration.
pub(crate) fn admit_react_bound(
    bounds: &[MessageReactBound],
    emoji: &str,
) -> std::result::Result<MessageReactBound, String> {
    bounds
        .iter()
        .find(|bound| bound.emoji.iter().any(|allowed| allowed == emoji))
        .cloned()
        .ok_or_else(|| format!("emoji '{emoji}' is admitted by no message.react bound"))
}

/// One consented governed title-rename bound (task `da148be`): the
/// consented static need whose delivered rows bound the record. The object
/// participates in the canonical digest, so any change of need changes the
/// pin and requires re-adoption. There is no emoji/position discriminator,
/// so a declaration holds at most one title bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TitleSetBound {
    pub need: String,
}

/// Parse one records.title-set.v1 object effect entry. Pure; every refusal
/// fails the declaration (or the stored consent) closed — an invalid object
/// never digests as absent and never silently narrows to its bare name.
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

/// Parse every records.title-set.v1 object bound in a declaration's
/// `effects` array. At most one may occur: with no discriminator the
/// manifest carries no target-need field and the invocation chooses none,
/// so two bounds could never be told apart. Duplicate identical objects
/// refuse here too.
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

/// Admit the single parsed title bound. Takes the parsed bound plus the
/// invocation (which carries no discriminator), never the declaration —
/// parsing stays with the caller, so this stays source-neutral for the
/// N2/N3 `DeclaringPackage` fold. Pure; the guard arm calls this thinly
/// after parsing the stored declaration.
pub(crate) fn admit_title_bound(
    bounds: &[TitleSetBound],
) -> std::result::Result<TitleSetBound, String> {
    bounds
        .iter()
        .next()
        .cloned()
        .ok_or_else(|| "no title-set bound".to_string())
}

/// Dormant singleton Body replacement bound. Raw cap is not encoded eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySetBound {
    pub need: String,
    pub max_body_bytes: usize,
}

pub fn parse_body_set_bound(entry: &Value) -> std::result::Result<BodySetBound, String> {
    let invalid = |detail: &str| format!("{TOOL}: body-set {detail} [invalid_effect]");
    let object = entry
        .as_object()
        .ok_or_else(|| invalid("bound must be an object"))?;
    if object.len() != 3
        || object.get("effect").and_then(Value::as_str) != Some(BODY_SET_EFFECT)
        || !object.contains_key("max_body_bytes")
        || !object.contains_key("target")
    {
        return Err(invalid(
            "bound must hold exactly 'effect', 'max_body_bytes' and 'target'",
        ));
    }
    let cap = object["max_body_bytes"]
        .as_u64()
        .filter(|n| (1..=BODY_SET_MAX_BODY_BYTES as u64).contains(n))
        .ok_or_else(|| {
            invalid(&format!(
                "max_body_bytes must be an integer 1..={BODY_SET_MAX_BODY_BYTES}"
            ))
        })?;
    let target = object["target"]
        .as_object()
        .ok_or_else(|| invalid("target must be an object"))?;
    if target.len() != 1 {
        return Err(invalid("target must hold exactly 'need'"));
    }
    let need = target
        .get("need")
        .and_then(Value::as_str)
        .filter(|need| valid_sql_need_key(need))
        .ok_or_else(|| invalid("target must hold exactly one valid SQL need key"))?;
    Ok(BodySetBound {
        need: need.to_owned(),
        max_body_bytes: cap as usize,
    })
}

/// List and same-declaration need validation, including direct canonical callers.
/// Leave historical no-Body canonical handling unchanged.
pub fn parse_body_set_bounds(
    declaration: &Value,
) -> std::result::Result<Vec<BodySetBound>, String> {
    let explicit = |v: &Value| {
        v.as_str() == Some(BODY_SET_EFFECT)
            || v.get("effect").and_then(Value::as_str) == Some(BODY_SET_EFFECT)
    };
    let effects = declaration.get("effects");
    let present = effects.is_some_and(|v| match v.as_array() {
        Some(entries) => entries.iter().any(explicit),
        None => explicit(v),
    });
    if !present {
        return Ok(Vec::new());
    }
    let invalid = |detail: &str| format!("{TOOL}: body-set {detail} [invalid_effect]");
    let object = declaration
        .as_object()
        .ok_or_else(|| invalid("declaration must be an object"))?;
    let needs = object
        .get("needs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("declaration needs must be an array"))?;
    let effects = effects
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("declaration effects must be an array"))?;
    if object.len() != 2 || needs.len() > 64 || effects.len() > 64 {
        return Err(invalid(
            "declaration must hold exactly bounded arrays 'needs' and 'effects'",
        ));
    }
    let mut bounds = Vec::new();
    for entry in effects.iter().filter(|entry| explicit(entry)) {
        bounds.push(parse_body_set_bound(entry)?);
    }
    if bounds.len() != 1 {
        return Err(invalid(
            "bound occurs more than once; a declaration holds at most one",
        ));
    }
    let string_needs: Vec<_> = needs.iter().filter_map(Value::as_str).collect();
    let mut keys = std::collections::BTreeSet::new();
    for entry in needs.iter().filter(|entry| !entry.is_string()) {
        let Some(need) = super::alpha_tabs::parse_effect_target_need(entry)? else {
            continue;
        };
        if string_needs.contains(&need.key.as_str()) || !keys.insert(need.key) {
            return Err(invalid("SQL need is duplicated or shadows a string need"));
        }
    }
    if keys.len() > super::alpha_tabs::SQL_SNAPSHOT_MAX_NEEDS || !keys.contains(&bounds[0].need) {
        return Err(invalid(
            "bound targets an undeclared SQL need or too many SQL needs",
        ));
    }
    Ok(bounds)
}

/// Pure bound/need admission only; no body write or dynamic membership.
pub(crate) fn body_admission(
    declaration: &Value,
    entry_id: &str,
) -> std::result::Result<(BodySetBound, SqlNeed), (String, String)> {
    let refuse = |detail: String| {
        (
            "alpha_guard_effect_unconsented".to_owned(),
            format!("no usable body-set bound for entry '{entry_id}': {detail}"),
        )
    };
    let bound = parse_body_set_bounds(declaration)
        .map_err(refuse)?
        .into_iter()
        .next()
        .ok_or_else(|| refuse("no body-set bound".into()))?;
    let needs = declaration["needs"]
        .as_array()
        .ok_or_else(|| refuse("missing needs".into()))?;
    for entry in needs.iter().filter(|entry| !entry.is_string()) {
        let Some(need) = super::alpha_tabs::parse_effect_target_need(entry).map_err(refuse)? else {
            continue;
        };
        if need.key == bound.need {
            return Ok((bound, need));
        }
    }
    Err(refuse("undeclared SQL need".into()))
}

/// Maximum admitted values in one facet-set object bound: finite by
/// construction, mirroring the 64-entry declaration cap.
pub const FACET_SET_VALUES_MAX: usize = 64;

/// One consented narrowed facet write (task `81372d1` facet-set slice): the
/// facet key, the admitted literal values (sorted at parse), and the
/// consented static need whose delivered rows bound the target. The object
/// participates in the canonical digest, so any widening changes the pin
/// and requires re-adoption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetSetBound {
    pub key: String,
    pub values: Vec<String>,
    pub need: String,
}

/// Parse one facet-set object effect entry. Pure; every refusal fails the
/// declaration (or the stored consent) closed — an invalid object never
/// digests as absent and never silently narrows to its bare name.
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
    // Scope closure (task `81372d1`): a generic bound must not authorize
    // what the contract excludes — spine columns, engine-dispatched keys,
    // record fields (title/body), or the dedicated triage arm's facet (which
    // keeps its own effect and never routes through the generic arm). The
    // set is defined once in the catalogue (`is_ordinary_facet_key`) so
    // matcher and consent cannot drift; this runs at install parse, in
    // canonicalization, and in the guard's reparse, so forged stored
    // consent fails closed too.
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

/// Parse every facet-set object bound in a declaration's `effects` array,
/// in declared order. Shared by install-time validation and the guard's
/// consent check over the stored declaration, so both read the same bounds.
pub(crate) fn parse_facet_set_bounds(
    declaration: &Value,
) -> std::result::Result<Vec<FacetSetBound>, String> {
    let mut bounds = Vec::new();
    if let Some(entries) = declaration.get("effects").and_then(Value::as_array) {
        for entry in entries {
            if entry.is_string() {
                continue;
            }
            // Comment, react and title bounds parse through their own
            // parsers below; skipping here keeps the facet duplicate-key
            // rule independent of them.
            if let Some(effect) = entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
            {
                if effect == COMMENT_CREATE_EFFECT
                    || effect == MESSAGE_REACT_EFFECT
                    || effect == TITLE_SET_EFFECT
                    || effect == BODY_SET_EFFECT
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

/// One consented governed comment posting bound (task `b9fb9fd` family 1):
/// the admitted thread positions (sorted at parse), the consent-side UTF-8
/// byte cap, and the consented static need whose delivered rows bound the
/// bearer. The object participates in the canonical digest, so any widening
/// changes the pin and requires re-adoption. The governed comment write path
/// consumes it in-transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentCreateBound {
    pub positions: Vec<String>,
    pub max_body_bytes: usize,
    pub need: String,
}

/// Thread positions one comment bound may admit.
pub(crate) const COMMENT_CREATE_POSITIONS: [&str; 2] = ["reply", "root"];

/// Parse one comment.create object effect entry. Pure; every refusal fails
/// the declaration (or the stored consent) closed — an invalid object never
/// digests as absent and never silently narrows to its bare name.
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
    // Whole-number parity with the manifest bound (`deserialize_manifest_usize`
    // in `mdx_v2`): Kit `Number.isInteger` cannot distinguish `100` from
    // `100.0`/`1e2` after parsing, so accept a finite whole f64 in range
    // here too. Fractional, negative, boolean and string values fail closed.
    // Existing SQL/facet numeric parsing is untouched.
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

/// Parse every comment.create object bound in a declaration's `effects`
/// array, in declared order. No root/reply position may occur in more than
/// one bound across `effects[]`, regardless of need or cap — a fixed
/// manifest position therefore chooses exactly one consented need and cap,
/// since the manifest carries no target-need field and the invocation
/// chooses none. Distinct root-only and reply-only objects may use
/// different needs. Duplicate identical objects and overlapping positions
/// both refuse here.
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

/// Find the consented facet-set bound admitting a parsed manifest entry:
/// the bound key equals the entry facet, the entry carries a literal string
/// value inside the bound values, and the bound need names a declared
/// static need in the same consent. Anything else fails closed with the
/// install-consent refusal shape. Returns the bound with its parsed need so
/// the membership check re-runs that need's SQL without re-parsing.
pub(crate) fn facet_set_admission(
    declaration: &Value,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
) -> std::result::Result<(FacetSetBound, SqlNeed), (String, String)> {
    let bounds = parse_facet_set_bounds(declaration).map_err(|error| {
        (
            "alpha_guard_effect_unconsented".to_string(),
            format!("the personal alpha install holds no usable facet-set bound [{error}]"),
        )
    })?;
    facet_set_admission_with_bounds(declaration, entry, &bounds)
}

/// Select from an already parsed list so static admission parses once.
fn facet_set_admission_with_bounds(
    declaration: &Value,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    bounds: &[FacetSetBound],
) -> std::result::Result<(FacetSetBound, SqlNeed), (String, String)> {
    let unconsented = |detail: &str| {
        (
            "alpha_guard_effect_unconsented".to_string(),
            format!(
                "the personal alpha install does not consent to a facet-set bound for entry '{}' ({}); a declared interaction alone is never effect consent",
                entry.id, detail,
            ),
        )
    };
    let value: Option<&str> = match &entry.value {
        Some(native_artifact_runtime::mdx_v2::ValueSource::Literal { value }) => value.as_str(),
        _ => None,
    };
    let Some(admitted) = bounds.iter().find(|bound| {
        bound.key == entry.facet
            && value.is_some_and(|text| bound.values.iter().any(|allowed| allowed == text))
    }) else {
        return Err(unconsented(&format!("facet '{}'", entry.facet)));
    };
    super::alpha_tabs::body_read_descriptor_in(declaration)
        .map_err(|_| unconsented("unparsable target need"))?;
    let needs = declaration.get("needs").and_then(Value::as_array);
    let mut target = None;
    if let Some(entries) = needs {
        for item in entries {
            if !item.is_object() {
                continue;
            }
            match super::alpha_tabs::parse_effect_target_need(item) {
                Ok(Some(need)) if need.key == admitted.need => {
                    target = Some(need);
                    break;
                }
                Ok(_) => {}
                Err(_) => return Err(unconsented("unparsable target need")),
            }
        }
    }
    match target {
        Some(need) => Ok((admitted.clone(), need)),
        None => Err(unconsented(&format!("need '{}'", admitted.need))),
    }
}

/// Find the consented comment.create bound admitting a parsed manifest
/// position: the bound whose positions contain the entry's fixed position,
/// with the bound need resolved to a declared static need in the same
/// consent. Anything else fails closed with the install-consent refusal
/// shape. Returns the bound (whose `max_body_bytes` is the consent cap;
/// the later kernel enforces `min(manifest, consent)` and never requires
/// the manifest cap below it) with its parsed need, so a later membership
/// check can re-run that need's SQL without re-parsing.
///
/// Pure consent selection: this confers no replay or write authority, and
/// the manifest position arrives already validated — an unknown position
/// simply matches no bound.
pub(crate) fn comment_admission(
    declaration: &Value,
    entry_id: &str,
    position: &str,
) -> std::result::Result<(CommentCreateBound, SqlNeed), (String, String)> {
    let unconsented = |detail: &str| {
        (
            "alpha_guard_effect_unconsented".to_string(),
            format!(
                "the personal alpha install does not consent to a comment.create bound for entry '{entry_id}' ({detail}); a declared interaction alone is never effect consent",
            ),
        )
    };
    let bounds = parse_comment_create_bounds(declaration).map_err(|error| {
        (
            "alpha_guard_effect_unconsented".to_string(),
            format!("the personal alpha install holds no usable comment.create bound [{error}]"),
        )
    })?;
    let Some(admitted) = bounds
        .iter()
        .find(|bound| bound.positions.iter().any(|allowed| allowed == position))
    else {
        return Err(unconsented(&format!("position '{position}'")));
    };
    super::alpha_tabs::body_read_descriptor_in(declaration)
        .map_err(|_| unconsented("unparsable target need"))?;
    let needs = declaration.get("needs").and_then(Value::as_array);
    let mut target = None;
    if let Some(entries) = needs {
        for item in entries {
            if !item.is_object() {
                continue;
            }
            match super::alpha_tabs::parse_effect_target_need(item) {
                Ok(Some(need)) if need.key == admitted.need => {
                    target = Some(need);
                    break;
                }
                Ok(_) => {}
                Err(_) => return Err(unconsented("unparsable target need")),
            }
        }
    }
    match target {
        Some(need) => Ok((admitted.clone(), need)),
        None => Err(unconsented(&format!("need '{}'", admitted.need))),
    }
}

/// Find the consented message.react bound admitting an invocation emoji,
/// plus its declared static need. Pure and source-neutral: the bound search
/// runs over the parsed bounds and the need is resolved from the same
/// declaration. Moved here from `alpha_tabs` in N3a so the pure admission
/// entry point below can consume it; `alpha_tabs` re-exports it unchanged,
/// so every existing caller and refusal text is byte-identical.
pub(crate) fn react_admission(
    declaration: &Value,
    entry_id: &str,
    emoji: &str,
) -> std::result::Result<(MessageReactBound, SqlNeed), (String, String)> {
    let unconsented = |detail: &str| {
        (
            "alpha_guard_effect_unconsented".to_string(),
            format!(
                "the personal alpha install does not consent to a message.react bound for entry '{entry_id}' ({detail}); a declared interaction alone is never effect consent",
            ),
        )
    };
    let bounds = parse_message_react_bounds(declaration).map_err(|error| {
        (
            "alpha_guard_effect_unconsented".to_string(),
            format!("the personal alpha install holds no usable message.react bound [{error}]"),
        )
    })?;
    let admitted = admit_react_bound(&bounds, emoji).map_err(|detail| unconsented(&detail))?;
    super::alpha_tabs::body_read_descriptor_in(declaration)
        .map_err(|_| unconsented("unparsable target need"))?;
    let needs = declaration.get("needs").and_then(Value::as_array);
    let mut target = None;
    if let Some(entries) = needs {
        for item in entries {
            if !item.is_object() {
                continue;
            }
            match super::alpha_tabs::parse_effect_target_need(item) {
                Ok(Some(need)) if need.key == admitted.need => {
                    target = Some(need);
                    break;
                }
                Ok(_) => {}
                Err(_) => return Err(unconsented("unparsable target need")),
            }
        }
    }
    match target {
        Some(need) => Ok((admitted, need)),
        None => Err(unconsented(&format!("need '{}'", admitted.need))),
    }
}

/// Find the consented records.title-set.v1 bound plus its declared static
/// need. Pure and source-neutral: the bound parse and need resolution run
/// over the same declaration. Moved here from `alpha_tabs` in N3a so the
/// pure admission entry point below can consume it; `alpha_tabs` re-exports
/// it unchanged, so every existing caller and refusal text is
/// byte-identical.
pub(crate) fn title_admission(
    declaration: &Value,
    entry_id: &str,
) -> std::result::Result<(TitleSetBound, SqlNeed), (String, String)> {
    let unconsented = |detail: &str| {
        (
            "alpha_guard_effect_unconsented".to_string(),
            format!(
                "the personal alpha install does not consent to a title-set bound for entry '{entry_id}' ({detail}); a declared interaction alone is never effect consent",
            ),
        )
    };
    let bounds = parse_title_set_bounds(declaration).map_err(|error| {
        (
            "alpha_guard_effect_unconsented".to_string(),
            format!("the personal alpha install holds no usable title-set bound [{error}]"),
        )
    })?;
    let admitted = admit_title_bound(&bounds).map_err(|detail| unconsented(&detail))?;
    super::alpha_tabs::body_read_descriptor_in(declaration)
        .map_err(|_| unconsented("unparsable target need"))?;
    let needs = declaration.get("needs").and_then(Value::as_array);
    let mut target = None;
    if let Some(entries) = needs {
        for item in entries {
            if !item.is_object() {
                continue;
            }
            match super::alpha_tabs::parse_effect_target_need(item) {
                Ok(Some(need)) if need.key == admitted.need => {
                    target = Some(need);
                    break;
                }
                Ok(_) => {}
                Err(_) => return Err(unconsented("unparsable target need")),
            }
        }
    }
    match target {
        Some(need) => Ok((admitted, need)),
        None => Err(unconsented(&format!("need '{}'", admitted.need))),
    }
}

/// Validated, source-aware context for one pure admission decision (D7
/// §4C.2 N3a). `position` and `emoji` are the invocation's already-validated
/// discriminators for the comment and react rows; the other rows ignore
/// them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AdmissionContext<'a> {
    pub source: AdmissionSource,
    pub package: &'a str,
    pub position: Option<&'a str>,
    pub emoji: Option<&'a str>,
}

/// One admitted effect's consent result (D7 §4C.2 N3a). Object rows carry
/// the parsed bound plus its resolved static need, so a later membership
/// check re-runs that need's SQL without re-parsing; the legacy string rows
/// carry no bound and no invented need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Admitted {
    TasksLifecycle,
    Triage,
    FacetSet {
        bound: FacetSetBound,
        need: SqlNeed,
    },
    Comment {
        bound: CommentCreateBound,
        need: SqlNeed,
    },
    React {
        bound: MessageReactBound,
        need: SqlNeed,
    },
    Title {
        bound: TitleSetBound,
        need: SqlNeed,
    },
    Body {
        bound: BodySetBound,
        need: SqlNeed,
    },
}

/// Pure, source-aware admission for one catalogue arm (D7 §4C.2 N3a).
///
/// This decides only consent from the declaration and the validated context:
/// no I/O, no caller, no dynamic membership, and no authority beyond what
/// the row's consent shape grants. Object rows are source-neutral; a
/// `LegacyString` row is admitted only for an alpha install, so an app
/// declaration can never gain a historical bare-string effect merely because
/// the row still supports it. The generic facet arm keeps the historical
/// asymmetry: an empty or malformed bound list is the catalogue-miss
/// refusal, never a raw parser error.
///
/// Preconditions, not re-validated here: `arm` is the result of
/// [`super::tab_effect_catalogue::match_arm`] on the same facet `entry`, or
/// the effect selected by a validated object scope, and
/// `ctx.position`/`ctx.emoji` are the discriminators already validated by the
/// caller's scope screening. This helper does not validate the manifest
/// shape or the entry envelope itself.
///
/// Called by the alpha guard after pins and before later I/O. All current
/// catalogue arms have consent metadata. The total NoPackage fallback for
/// absent metadata is unreachable for them; unknown facet entries keep the
/// historical catalogue-miss refusal in the guard's pre-I/O screening.
pub(crate) fn admit(
    arm: TabEffectArm,
    declaration: &Value,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    ctx: &AdmissionContext<'_>,
) -> std::result::Result<Admitted, AdmissionRefusal> {
    let unconsented_effect = |required: &str| AdmissionRefusal::Unconsented {
        reason: UnconsentedReason::EffectNotConsented {
            package: ctx.package.to_string(),
            required_effect: required.to_string(),
        },
    };
    let Some(shape) = consent_shape(arm) else {
        return Err(AdmissionRefusal::NoPackage);
    };
    match shape {
        ConsentShape::LegacyString => {
            let required = super::tab_effect_catalogue::required_effect_name(arm)
                .unwrap_or(super::tab_effect_catalogue::ALPHA_TRIAGE_SET_EFFECT);
            // Alpha-only string consent: an app declaration must never gain
            // it, even when the string is present in its own declaration.
            if ctx.source == AdmissionSource::AppDeclaration {
                return Err(unconsented_effect(required));
            }
            let consented = declaration
                .get("effects")
                .and_then(Value::as_array)
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|effect| effect == required)
                });
            if !consented {
                return Err(unconsented_effect(required));
            }
            Ok(match arm {
                TabEffectArm::TasksLifecycle => Admitted::TasksLifecycle,
                TabEffectArm::Triage => Admitted::Triage,
                _ => unreachable!("legacy consent shape is TasksLifecycle/Triage only"),
            })
        }
        ConsentShape::Object => match arm {
            TabEffectArm::FacetSet => {
                // Historical generic-facet asymmetry: an empty or malformed
                // bound list keeps the catalogue-miss refusal, never a raw
                // parser error.
                let bounds = parse_facet_set_bounds(declaration).unwrap_or_default();
                if bounds.is_empty() {
                    return Err(AdmissionRefusal::Unconsented {
                        reason: UnconsentedReason::FacetCatalogueMiss {
                            entry_id: entry.id.clone(),
                            facet: entry.facet.clone(),
                        },
                    });
                }
                let (bound, need) = facet_set_admission_with_bounds(declaration, entry, &bounds)
                    .map_err(|(code, message)| AdmissionRefusal::NoUsableBound { code, message })?;
                Ok(Admitted::FacetSet { bound, need })
            }
            TabEffectArm::CommentCreate => {
                let Some(position) = ctx.position else {
                    return Err(AdmissionRefusal::ScopeUnsupported {
                        reason: super::effect_admission::ScopeUnsupportedReason::NonCommentEntry,
                    });
                };
                let (bound, need) = comment_admission(declaration, &entry.id, position)
                    .map_err(|(code, message)| AdmissionRefusal::NoUsableBound { code, message })?;
                Ok(Admitted::Comment { bound, need })
            }
            TabEffectArm::MessageReact => {
                let Some(emoji) = ctx.emoji else {
                    return Err(AdmissionRefusal::ScopeUnsupported {
                        reason: super::effect_admission::ScopeUnsupportedReason::NonReactEntry,
                    });
                };
                let (bound, need) = react_admission(declaration, &entry.id, emoji)
                    .map_err(|(code, message)| AdmissionRefusal::NoUsableBound { code, message })?;
                Ok(Admitted::React { bound, need })
            }
            TabEffectArm::TitleSet => {
                let (bound, need) = title_admission(declaration, &entry.id)
                    .map_err(|(code, message)| AdmissionRefusal::NoUsableBound { code, message })?;
                Ok(Admitted::Title { bound, need })
            }
            TabEffectArm::BodySet => {
                let (bound, need) = body_admission(declaration, &entry.id)
                    .map_err(|(code, message)| AdmissionRefusal::NoUsableBound { code, message })?;
                Ok(Admitted::Body { bound, need })
            }
            TabEffectArm::TasksLifecycle | TabEffectArm::Triage => {
                unreachable!("legacy consent shape handled above")
            }
        },
    }
}

#[cfg(test)]
mod admission_tests {
    use super::super::effect_admission::{
        render_refusal, AdmissionSource, ScopeUnsupportedReason, UnconsentedReason,
    };
    use super::super::tab_effect_catalogue::{TabEffectArm, ALPHA_GUARD_FACET};
    use super::*;
    use native_artifact_runtime::mdx_v2::{
        CommentBodyDecl, CommentCreateDecl, CommentPosition, InteractionEffect, InteractionEntry,
        MessageReactDecl, TitleSetDecl, ValueSource,
    };
    use serde_json::json;

    /// Render a refusal exactly as the alpha guard renders it. Expected
    /// strings are written out literally in each test; this only applies the
    /// shared renderer to the value under test.
    fn rendered(err: &AdmissionRefusal) -> (String, String) {
        render_refusal(AdmissionSource::AlphaTabInstall, err)
    }

    /// A realistic parsed-entry skeleton: every optional envelope is `None`
    /// and each test fills exactly the shape its arm matches. `admit` reads
    /// only identity/discriminator fields here; it does not re-validate the
    /// manifest shape (that is the scope-screening/match_row job).
    fn entry(effect: InteractionEffect) -> InteractionEntry {
        InteractionEntry {
            id: "e1".into(),
            label: "L".into(),
            effect,
            slots: Default::default(),
            facet: String::new(),
            value: None,
            create: None,
            comment: None,
            react: None,
            title: None,
            body: None,
        }
    }

    /// The Tasks lifecycle arm's matched entry shape: `facet.set` on the
    /// `lifecycle` spine with the literal `in_progress` value.
    fn tasks_lifecycle_entry() -> InteractionEntry {
        let mut e = entry(InteractionEffect::FacetSet);
        e.id = "start".into();
        e.facet = super::super::tab_effect_catalogue::TASKS_LIFECYCLE_FACET.into();
        e.value = Some(ValueSource::Literal {
            value: json!(super::super::tab_effect_catalogue::TASKS_LIFECYCLE_TARGET),
        });
        e
    }

    /// The triage arm's matched entry shape: any entry on the `triage` facet.
    fn triage_entry() -> InteractionEntry {
        let mut e = entry(InteractionEffect::FacetSet);
        e.id = "triage".into();
        e.facet = ALPHA_GUARD_FACET.into();
        e.value = Some(ValueSource::Literal {
            value: json!("in_progress"),
        });
        e
    }

    /// A generic facet-set entry on `facet` with a literal `value`.
    fn facet_entry(facet: &str, value: &str) -> InteractionEntry {
        let mut e = entry(InteractionEffect::FacetSet);
        e.id = "e1".into();
        e.facet = facet.into();
        e.value = Some(ValueSource::Literal {
            value: json!(value),
        });
        e
    }

    /// The comment arm's matched entry shape: a `comment.create` entry
    /// carrying its envelope.
    fn comment_entry() -> InteractionEntry {
        let mut e = entry(InteractionEffect::CommentCreate);
        e.id = "e1".into();
        e.comment = Some(CommentCreateDecl {
            position: CommentPosition::Root,
            body: CommentBodyDecl {
                input: "text".into(),
                max_bytes: 500,
            },
        });
        e
    }

    /// The react arm's matched entry shape: a `message.react` entry carrying
    /// its envelope.
    fn react_entry() -> InteractionEntry {
        let mut e = entry(InteractionEffect::MessageReact);
        e.id = "e1".into();
        e.react = Some(MessageReactDecl {
            emoji: vec!["👍".into()],
        });
        e
    }

    /// The title arm's matched entry shape: a `title.set` entry carrying its
    /// envelope.
    fn title_entry() -> InteractionEntry {
        let mut e = entry(InteractionEffect::TitleSet);
        e.id = "e1".into();
        e.title = Some(TitleSetDecl {});
        e
    }

    fn sql_need(key: &str) -> Value {
        json!({"need": "sql.snapshot.v1", "key": key, "label": "Rows",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL AND name LIKE 'thread-%' ORDER BY id ASC LIMIT 40"})
    }

    fn facet_decl() -> Value {
        json!({"needs": [sql_need("n1")], "effects": [{
            "effect": "records.facet-set.v1", "key": "priority",
            "values": ["low", "high"], "target": {"need": "n1"}}]})
    }

    fn comment_decl(positions: Value) -> Value {
        json!({"needs": [sql_need("n1")], "effects": [{
            "effect": "comment.create.v1", "positions": positions,
            "max_body_bytes": 100, "target": {"need": "n1"}}]})
    }

    fn react_decl(emoji: Value) -> Value {
        json!({"needs": [sql_need("n1")], "effects": [{
            "effect": "message.react.v1", "emoji": emoji, "target": {"need": "n1"}}]})
    }

    fn title_decl() -> Value {
        json!({"needs": [sql_need("n1")], "effects": [{
            "effect": "records.title-set.v1", "target": {"need": "n1"}}]})
    }

    fn alpha() -> AdmissionContext<'static> {
        AdmissionContext {
            source: AdmissionSource::AlphaTabInstall,
            package: "agent.test",
            position: None,
            emoji: None,
        }
    }

    fn app() -> AdmissionContext<'static> {
        AdmissionContext {
            source: AdmissionSource::AppDeclaration,
            ..alpha()
        }
    }

    #[test]
    fn body_static_admission_is_source_neutral_and_not_title_or_facet_consent() {
        let mut body = entry(InteractionEffect::BodySet);
        body.id = "e1".into();
        body.body = Some(native_artifact_runtime::mdx_v2::BodySetDecl { max_bytes: 32768 });
        let d = json!({"needs":[sql_need("n1")],"effects":[{
            "effect":BODY_SET_EFFECT,"max_body_bytes":123,"target":{"need":"n1"}}]});
        for ctx in [alpha(), app()] {
            let admitted = admit(TabEffectArm::BodySet, &d, &body, &ctx).unwrap();
            let Admitted::Body { bound, need } = admitted else {
                panic!("Body bound");
            };
            assert_eq!(
                bound,
                BodySetBound {
                    need: "n1".into(),
                    max_body_bytes: 123
                }
            );
            assert_eq!(need.key, "n1");
            let mut mixed = d.clone();
            mixed["needs"].as_array_mut().unwrap().push(json!({
                "need": "records.body.read.v1", "scope": "viewer-visible-current-bodies"
            }));
            let Admitted::Body { need, .. } =
                admit(TabEffectArm::BodySet, &mixed, &body, &ctx).unwrap()
            else {
                panic!("Mixed Body bound");
            };
            assert_eq!(need.key, "n1");
            mixed["effects"][0]["target"]["need"] = json!("records.body.read.v1");
            assert!(admit(TabEffectArm::BodySet, &mixed, &body, &ctx).is_err());
            mixed["effects"][0]["target"]["need"] = json!("n1");
            mixed["needs"][1]["scope"] = json!("unsupported-scope");
            assert!(admit(TabEffectArm::BodySet, &mixed, &body, &ctx).is_err());
            assert!(admit(TabEffectArm::BodySet, &title_decl(), &body, &ctx).is_err());
            assert!(admit(
                TabEffectArm::BodySet,
                &json!({"needs":[sql_need("n1")],"effects":[BODY_SET_EFFECT]}),
                &body,
                &ctx
            )
            .is_err());
        }
        assert_eq!(
            super::super::tab_effect_catalogue::match_arm(&body),
            Some(TabEffectArm::BodySet)
        );
        body.facet = ALPHA_GUARD_FACET.into(); // even malformed incidental facet cannot piggyback Triage
        assert_eq!(
            super::super::tab_effect_catalogue::match_arm(&body),
            Some(TabEffectArm::BodySet)
        );
    }

    #[test]
    fn each_arm_reports_its_consent_shape() {
        use super::super::tab_effect_catalogue::{consent_shape, ConsentShape};
        assert_eq!(
            consent_shape(TabEffectArm::TasksLifecycle),
            Some(ConsentShape::LegacyString)
        );
        assert_eq!(
            consent_shape(TabEffectArm::Triage),
            Some(ConsentShape::LegacyString)
        );
        for arm in [
            TabEffectArm::FacetSet,
            TabEffectArm::CommentCreate,
            TabEffectArm::MessageReact,
            TabEffectArm::TitleSet,
            TabEffectArm::BodySet,
        ] {
            assert_eq!(consent_shape(arm), Some(ConsentShape::Object), "{arm:?}");
        }
    }

    #[test]
    fn legacy_string_consent_is_alpha_only() {
        let triage = json!({"needs": [], "effects": ["task.triage-set.v1"]});
        let tasks = json!({"needs": [], "effects": ["tasks.lifecycle-set.v1"]});
        // Alpha installs admit the historical bare strings.
        assert_eq!(
            admit(TabEffectArm::Triage, &triage, &triage_entry(), &alpha()),
            Ok(Admitted::Triage)
        );
        assert_eq!(
            admit(
                TabEffectArm::TasksLifecycle,
                &tasks,
                &tasks_lifecycle_entry(),
                &alpha()
            ),
            Ok(Admitted::TasksLifecycle)
        );
        // Missing string consent: exact structured variant and literal
        // rendered alpha code/message (written out, not derived from the
        // helper under test).
        let absent = json!({"needs": [], "effects": []});
        let triage_err =
            admit(TabEffectArm::Triage, &absent, &triage_entry(), &alpha()).unwrap_err();
        assert_eq!(
            triage_err,
            AdmissionRefusal::Unconsented {
                reason: UnconsentedReason::EffectNotConsented {
                    package: "agent.test".into(),
                    required_effect: "task.triage-set.v1".into(),
                },
            }
        );
        assert_eq!(
            rendered(&triage_err),
            (
                "alpha_guard_effect_unconsented".to_string(),
                "the personal alpha install agent.test does not consent to task.triage-set.v1; a declared interaction alone is never effect consent".to_string(),
            )
        );
        let tasks_err = admit(
            TabEffectArm::TasksLifecycle,
            &absent,
            &tasks_lifecycle_entry(),
            &alpha(),
        )
        .unwrap_err();
        assert_eq!(
            tasks_err,
            AdmissionRefusal::Unconsented {
                reason: UnconsentedReason::EffectNotConsented {
                    package: "agent.test".into(),
                    required_effect: "tasks.lifecycle-set.v1".into(),
                },
            }
        );
        assert_eq!(
            rendered(&tasks_err),
            (
                "alpha_guard_effect_unconsented".to_string(),
                "the personal alpha install agent.test does not consent to tasks.lifecycle-set.v1; a declared interaction alone is never effect consent".to_string(),
            )
        );
        // An app declaration never gains legacy string consent, even when the
        // string is present in its own declaration: the same exact refusal.
        let triage_app = admit(TabEffectArm::Triage, &triage, &triage_entry(), &app()).unwrap_err();
        assert_eq!(
            triage_app,
            AdmissionRefusal::Unconsented {
                reason: UnconsentedReason::EffectNotConsented {
                    package: "agent.test".into(),
                    required_effect: "task.triage-set.v1".into(),
                },
            }
        );
        assert_eq!(
            rendered(&triage_app),
            (
                "alpha_guard_effect_unconsented".to_string(),
                "the personal alpha install agent.test does not consent to task.triage-set.v1; a declared interaction alone is never effect consent".to_string(),
            )
        );
        let tasks_app = admit(
            TabEffectArm::TasksLifecycle,
            &tasks,
            &tasks_lifecycle_entry(),
            &app(),
        )
        .unwrap_err();
        assert_eq!(
            tasks_app,
            AdmissionRefusal::Unconsented {
                reason: UnconsentedReason::EffectNotConsented {
                    package: "agent.test".into(),
                    required_effect: "tasks.lifecycle-set.v1".into(),
                },
            }
        );
        assert_eq!(
            rendered(&tasks_app),
            (
                "alpha_guard_effect_unconsented".to_string(),
                "the personal alpha install agent.test does not consent to tasks.lifecycle-set.v1; a declared interaction alone is never effect consent".to_string(),
            )
        );
    }

    #[test]
    fn object_consent_admits_literal_bounds_for_each_source() {
        let facet = facet_decl();
        let comment = comment_decl(json!(["root"]));
        let react = react_decl(json!(["👍"]));
        let title = title_decl();
        let mut alpha_ctx = alpha();
        alpha_ctx.position = Some("root");
        alpha_ctx.emoji = Some("👍");
        let app_ctx = AdmissionContext {
            source: AdmissionSource::AppDeclaration,
            ..alpha_ctx
        };
        let expected_need = || {
            SqlNeed {
            key: "n1".into(),
            label: "Rows".into(),
            sql: "SELECT id FROM records WHERE deleted_at IS NULL AND name LIKE 'thread-%' ORDER BY id ASC LIMIT 40".into(),
            params: Vec::new(),
            relations: Default::default(),
        }
        };

        // FacetSet: literal bound + need for alpha, then independently for app.
        assert_eq!(
            admit(
                TabEffectArm::FacetSet,
                &facet,
                &facet_entry("priority", "low"),
                &alpha_ctx
            ),
            Ok(Admitted::FacetSet {
                bound: FacetSetBound {
                    key: "priority".into(),
                    values: vec!["high".into(), "low".into()],
                    need: "n1".into(),
                },
                need: expected_need(),
            })
        );
        assert_eq!(
            admit(
                TabEffectArm::FacetSet,
                &facet,
                &facet_entry("priority", "low"),
                &app_ctx
            ),
            Ok(Admitted::FacetSet {
                bound: FacetSetBound {
                    key: "priority".into(),
                    values: vec!["high".into(), "low".into()],
                    need: "n1".into(),
                },
                need: expected_need(),
            })
        );

        // Comment: literal bound + need for alpha, then independently for app.
        assert_eq!(
            admit(
                TabEffectArm::CommentCreate,
                &comment,
                &comment_entry(),
                &alpha_ctx
            ),
            Ok(Admitted::Comment {
                bound: CommentCreateBound {
                    positions: vec!["root".into()],
                    max_body_bytes: 100,
                    need: "n1".into(),
                },
                need: expected_need(),
            })
        );
        assert_eq!(
            admit(
                TabEffectArm::CommentCreate,
                &comment,
                &comment_entry(),
                &app_ctx
            ),
            Ok(Admitted::Comment {
                bound: CommentCreateBound {
                    positions: vec!["root".into()],
                    max_body_bytes: 100,
                    need: "n1".into(),
                },
                need: expected_need(),
            })
        );

        // React: literal bound + need for alpha, then independently for app.
        assert_eq!(
            admit(
                TabEffectArm::MessageReact,
                &react,
                &react_entry(),
                &alpha_ctx
            ),
            Ok(Admitted::React {
                bound: MessageReactBound {
                    emoji: vec!["👍".into()],
                    need: "n1".into(),
                },
                need: expected_need(),
            })
        );
        assert_eq!(
            admit(TabEffectArm::MessageReact, &react, &react_entry(), &app_ctx),
            Ok(Admitted::React {
                bound: MessageReactBound {
                    emoji: vec!["👍".into()],
                    need: "n1".into(),
                },
                need: expected_need(),
            })
        );

        // Title: literal bound + need for alpha, then independently for app.
        assert_eq!(
            admit(TabEffectArm::TitleSet, &title, &title_entry(), &alpha_ctx),
            Ok(Admitted::Title {
                bound: TitleSetBound { need: "n1".into() },
                need: expected_need(),
            })
        );
        assert_eq!(
            admit(TabEffectArm::TitleSet, &title, &title_entry(), &app_ctx),
            Ok(Admitted::Title {
                bound: TitleSetBound { need: "n1".into() },
                need: expected_need(),
            })
        );
    }

    #[test]
    fn comment_position_and_react_emoji_selection() {
        let comment = comment_decl(json!(["root"]));
        let mut root = alpha();
        root.position = Some("root");
        let reply = AdmissionContext {
            position: Some("reply"),
            ..root
        };
        let no_position = AdmissionContext {
            position: None,
            ..root
        };

        // Valid root: literal bound and need fields.
        match admit(
            TabEffectArm::CommentCreate,
            &comment,
            &comment_entry(),
            &root,
        )
        .unwrap()
        {
            Admitted::Comment { bound, need } => {
                assert_eq!(
                    bound,
                    CommentCreateBound {
                        positions: vec!["root".into()],
                        max_body_bytes: 100,
                        need: "n1".into(),
                    }
                );
                assert_eq!(need.key, "n1");
                assert_eq!(need.label, "Rows");
                assert_eq!(need.sql, "SELECT id FROM records WHERE deleted_at IS NULL AND name LIKE 'thread-%' ORDER BY id ASC LIMIT 40");
            }
            other => panic!("expected Admitted::Comment, got {other:?}"),
        }
        // Position mismatch: exact structured pair and literal rendered
        // alpha code/message.
        let mismatch = admit(
            TabEffectArm::CommentCreate,
            &comment,
            &comment_entry(),
            &reply,
        )
        .unwrap_err();
        assert_eq!(
            mismatch,
            AdmissionRefusal::NoUsableBound {
                code: "alpha_guard_effect_unconsented".into(),
                message: "the personal alpha install does not consent to a comment.create bound for entry 'e1' (position 'reply'); a declared interaction alone is never effect consent".into(),
            }
        );
        assert_eq!(
            rendered(&mismatch),
            (
                "alpha_guard_effect_unconsented".to_string(),
                "the personal alpha install does not consent to a comment.create bound for entry 'e1' (position 'reply'); a declared interaction alone is never effect consent".to_string(),
            )
        );
        // Missing validated position: exact shape refusal, literal rendering.
        let no_pos = admit(
            TabEffectArm::CommentCreate,
            &comment,
            &comment_entry(),
            &no_position,
        )
        .unwrap_err();
        assert_eq!(
            no_pos,
            AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::NonCommentEntry
            }
        );
        assert_eq!(
            rendered(&no_pos),
            (
                "alpha_guard_unsupported_effect".to_string(),
                "the comment guard applies only to comment.create entries carrying a comment envelope".to_string(),
            )
        );

        // React emoji selection.
        let react = react_decl(json!(["👍"]));
        let mut thumbs = alpha();
        thumbs.emoji = Some("👍");
        let heart = AdmissionContext {
            emoji: Some("❤️"),
            ..thumbs
        };
        let no_emoji = AdmissionContext {
            emoji: None,
            ..thumbs
        };
        match admit(TabEffectArm::MessageReact, &react, &react_entry(), &thumbs).unwrap() {
            Admitted::React { bound, need } => {
                assert_eq!(
                    bound,
                    MessageReactBound {
                        emoji: vec!["👍".into()],
                        need: "n1".into(),
                    }
                );
                assert_eq!(need.key, "n1");
                assert_eq!(need.label, "Rows");
                assert_eq!(need.sql, "SELECT id FROM records WHERE deleted_at IS NULL AND name LIKE 'thread-%' ORDER BY id ASC LIMIT 40");
            }
            other => panic!("expected Admitted::React, got {other:?}"),
        }
        let emoji_err =
            admit(TabEffectArm::MessageReact, &react, &react_entry(), &heart).unwrap_err();
        assert_eq!(
            emoji_err,
            AdmissionRefusal::NoUsableBound {
                code: "alpha_guard_effect_unconsented".into(),
                message: "the personal alpha install does not consent to a message.react bound for entry 'e1' (emoji '❤️' is admitted by no message.react bound); a declared interaction alone is never effect consent".into(),
            }
        );
        assert_eq!(
            rendered(&emoji_err),
            (
                "alpha_guard_effect_unconsented".to_string(),
                "the personal alpha install does not consent to a message.react bound for entry 'e1' (emoji '❤️' is admitted by no message.react bound); a declared interaction alone is never effect consent".to_string(),
            )
        );
        let no_emoji_err = admit(
            TabEffectArm::MessageReact,
            &react,
            &react_entry(),
            &no_emoji,
        )
        .unwrap_err();
        assert_eq!(
            no_emoji_err,
            AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::NonReactEntry
            }
        );
        assert_eq!(
            rendered(&no_emoji_err),
            (
                "alpha_guard_unsupported_effect".to_string(),
                "the react guard applies only to message.react entries carrying a react envelope"
                    .to_string(),
            )
        );
    }

    #[test]
    fn facet_historical_catalogue_miss_is_preserved() {
        let facet = facet_entry("priority", "low");
        // No facet bounds at all: the historical catalogue miss, naming the
        // entry's own id and facet, with literal rendered code/message.
        let empty = json!({"needs": [], "effects": []});
        let miss = admit(TabEffectArm::FacetSet, &empty, &facet, &alpha()).unwrap_err();
        assert_eq!(
            miss,
            AdmissionRefusal::Unconsented {
                reason: UnconsentedReason::FacetCatalogueMiss {
                    entry_id: "e1".into(),
                    facet: "priority".into(),
                },
            }
        );
        assert_eq!(
            rendered(&miss),
            (
                "alpha_guard_facet_unconsented".to_string(),
                "the personal-install guard consents only to facet 'triage' or the tasks lifecycle arm; entry 'e1' targets 'priority'".to_string(),
            )
        );
        // A malformed bound object also yields the catalogue miss, never the
        // parser's own error.
        let malformed = json!({"needs": [], "effects": [{"effect": "records.facet-set.v1"}]});
        let miss2 = admit(TabEffectArm::FacetSet, &malformed, &facet, &alpha()).unwrap_err();
        assert_eq!(
            miss2,
            AdmissionRefusal::Unconsented {
                reason: UnconsentedReason::FacetCatalogueMiss {
                    entry_id: "e1".into(),
                    facet: "priority".into(),
                },
            }
        );
        assert_eq!(
            rendered(&miss2),
            (
                "alpha_guard_facet_unconsented".to_string(),
                "the personal-install guard consents only to facet 'triage' or the tasks lifecycle arm; entry 'e1' targets 'priority'".to_string(),
            )
        );
        // A well-formed bound that does not match the entry keeps the helper
        // refusal pair, with exact literal code/message.
        let other = facet_entry("status", "low");
        let bound_err = admit(TabEffectArm::FacetSet, &facet_decl(), &other, &alpha()).unwrap_err();
        assert_eq!(
            bound_err,
            AdmissionRefusal::NoUsableBound {
                code: "alpha_guard_effect_unconsented".into(),
                message: "the personal alpha install does not consent to a facet-set bound for entry 'e1' (facet 'status'); a declared interaction alone is never effect consent".into(),
            }
        );
        assert_eq!(
            rendered(&bound_err),
            (
                "alpha_guard_effect_unconsented".to_string(),
                "the personal alpha install does not consent to a facet-set bound for entry 'e1' (facet 'status'); a declared interaction alone is never effect consent".to_string(),
            )
        );
    }

    #[test]
    fn missing_and_malformed_needs_refuse_for_every_object_arm() {
        // Each bound targets need 'n1'; the absent declarations hold no need,
        // the malformed declarations hold an unparsable one.
        let malformed_need = json!({"need": "sql.snapshot.v1", "key": "n1"});
        let cases: [(TabEffectArm, Value, Value, InteractionEntry); 4] = [
            (
                TabEffectArm::FacetSet,
                json!({"needs": [], "effects": [{
                    "effect": "records.facet-set.v1", "key": "priority",
                    "values": ["low"], "target": {"need": "n1"}}]}),
                json!({"needs": [malformed_need.clone()], "effects": [{
                    "effect": "records.facet-set.v1", "key": "priority",
                    "values": ["low"], "target": {"need": "n1"}}]}),
                facet_entry("priority", "low"),
            ),
            (
                TabEffectArm::CommentCreate,
                json!({"needs": [], "effects": [{
                    "effect": "comment.create.v1", "positions": ["root"],
                    "max_body_bytes": 100, "target": {"need": "n1"}}]}),
                json!({"needs": [malformed_need.clone()], "effects": [{
                    "effect": "comment.create.v1", "positions": ["root"],
                    "max_body_bytes": 100, "target": {"need": "n1"}}]}),
                comment_entry(),
            ),
            (
                TabEffectArm::MessageReact,
                json!({"needs": [], "effects": [{
                    "effect": "message.react.v1", "emoji": ["👍"],
                    "target": {"need": "n1"}}]}),
                json!({"needs": [malformed_need.clone()], "effects": [{
                    "effect": "message.react.v1", "emoji": ["👍"],
                    "target": {"need": "n1"}}]}),
                react_entry(),
            ),
            (
                TabEffectArm::TitleSet,
                json!({"needs": [], "effects": [{
                    "effect": "records.title-set.v1", "target": {"need": "n1"}}]}),
                json!({"needs": [malformed_need], "effects": [{
                    "effect": "records.title-set.v1", "target": {"need": "n1"}}]}),
                title_entry(),
            ),
        ];
        let bound_kind = |arm: TabEffectArm| match arm {
            TabEffectArm::FacetSet => "facet-set",
            TabEffectArm::CommentCreate => "comment.create",
            TabEffectArm::MessageReact => "message.react",
            TabEffectArm::TitleSet => "title-set",
            TabEffectArm::BodySet => "body-set",
            TabEffectArm::TasksLifecycle | TabEffectArm::Triage => unreachable!(),
        };
        let mut ctx = alpha();
        ctx.position = Some("root");
        ctx.emoji = Some("👍");

        for (arm, absent, malformed, entry) in cases {
            let kind = bound_kind(arm);
            let absent_expected = format!(
                "the personal alpha install does not consent to a {kind} bound for entry 'e1' (need 'n1'); a declared interaction alone is never effect consent"
            );
            let absent_err = admit(arm, &absent, &entry, &ctx).unwrap_err();
            assert_eq!(
                absent_err,
                AdmissionRefusal::NoUsableBound {
                    code: "alpha_guard_effect_unconsented".into(),
                    message: absent_expected.clone(),
                },
                "{arm:?}"
            );
            assert_eq!(
                rendered(&absent_err),
                (
                    "alpha_guard_effect_unconsented".to_string(),
                    absent_expected
                ),
                "{arm:?}"
            );

            let malformed_expected = format!(
                "the personal alpha install does not consent to a {kind} bound for entry 'e1' (unparsable target need); a declared interaction alone is never effect consent"
            );
            let malformed_err = admit(arm, &malformed, &entry, &ctx).unwrap_err();
            assert_eq!(
                malformed_err,
                AdmissionRefusal::NoUsableBound {
                    code: "alpha_guard_effect_unconsented".into(),
                    message: malformed_expected.clone(),
                },
                "{arm:?}"
            );
            assert_eq!(
                rendered(&malformed_err),
                (
                    "alpha_guard_effect_unconsented".to_string(),
                    malformed_expected
                ),
                "{arm:?}"
            );
        }
    }
}
