//! Gated structured-value language core. Kept separate from link selectors.
use crate::meta::definition_artifact::LanguageCapabilities;
use crate::{error::Error, Result};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

pub mod text_formats;

pub const INTERPRETER: &str = "native.defn/5";
/// `/5` plus `text_format`, `max_length` and the W blank rule. Frozen: any
/// change to the format table, W or the length unit needs `/7`.
pub const INTERPRETER_V6: &str = "native.defn/6";
pub const NORMALIZATION: &str = "native.json-values/1";
pub const MAX_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_FIELDS: usize = 64;
pub const MAX_DESCRIPTORS: usize = 256;
pub const MAX_DEPTH: usize = 4;
pub const MAX_ITEMS: usize = 128;
pub const MAX_VALUE_NODES: usize = 1024;
pub const MAX_VALUE_BYTES: usize = 64 * 1024;
pub const MAX_TEXT_BYTES: usize = 4096;

/// Peek without constructing a Value tree or tightening legacy parsing.
/// Legacy duplicate markers retain last-key semantics; the new parser rejects
/// all duplicate keys once that final marker selects this language.
pub(crate) fn declares_language(raw: &str) -> Result<bool> {
    Ok(declared_language(raw)?.is_some())
}

/// The structured marker (`/5` or `/6`) the envelope's final `interpreter`
/// key selects, if any.
pub(crate) fn declared_language(raw: &str) -> Result<Option<&'static str>> {
    struct Marker;
    impl<'de> Visitor<'de> for Marker {
        type Value = Option<&'static str>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a definition envelope object")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Option<&'static str>, A::Error> {
            let mut selected = None;
            while let Some(key) = map.next_key::<String>()? {
                if key == "interpreter" {
                    let value: &serde_json::value::RawValue = map.next_value()?;
                    selected = match serde_json::from_str::<String>(value.get()).ok().as_deref() {
                        Some(INTERPRETER) => Some(INTERPRETER),
                        Some(INTERPRETER_V6) => Some(INTERPRETER_V6),
                        _ => None,
                    };
                } else {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
            Ok(selected)
        }
    }
    let mut de = serde_json::Deserializer::from_str(raw);
    let selected = serde::Deserializer::deserialize_map(&mut de, Marker)?;
    de.end()?;
    Ok(selected)
}

fn refusal(code: &str, path: &str) -> Error {
    Error::engine(format!("{code} at {path}"))
}
pub(crate) fn pointer(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}
fn keys(value: &Value, allowed: &[&str], path: &str) -> Result<()> {
    let obj = value
        .as_object()
        .ok_or_else(|| refusal("wrong_type", path))?;
    let mut unknown: Vec<_> = obj
        .keys()
        .filter(|k| !allowed.contains(&k.as_str()))
        .collect();
    unknown.sort();
    if let Some(key) = unknown.first() {
        return Err(refusal("unknown_member", &pointer(path, key)));
    }
    Ok(())
}

/// Bounded JSON parser: reject duplicates before Map insertion and bound
/// allocation/depth before building Value. Used at raw definition/request entry.
pub fn parse_json(raw: &str) -> Result<Value> {
    if raw.len() > MAX_INPUT_BYTES {
        return Err(refusal("limit_exceeded", ""));
    }
    let mut nodes = 0;
    let mut de = serde_json::Deserializer::from_str(raw);
    let value = Seed {
        depth: 0,
        nodes: &mut nodes,
        path: String::new(),
    }
    .deserialize(&mut de)?;
    de.end()?;
    Ok(value)
}
struct Seed<'a> {
    depth: usize,
    nodes: &'a mut usize,
    path: String,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        de: D,
    ) -> std::result::Result<Value, D::Error> {
        *self.nodes += 1;
        if self.depth > 32 || *self.nodes > 32768 {
            return Err(serde::de::Error::custom("limit_exceeded"));
        }
        // Capture the token before deserialize_any can round an overflowing
        // integer or an overprecise decimal to f64. RawValue borrows input.
        let raw: &serde_json::value::RawValue = serde::Deserialize::deserialize(de)?;
        if raw
            .get()
            .starts_with(|c: char| c == '-' || c.is_ascii_digit())
        {
            let number: serde_json::Number =
                serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
            if !number.is_i64()
                && !number.is_u64()
                && decimal_value(raw.get()) != decimal_value(&number.to_string())
            {
                return Err(serde::de::Error::custom(format!(
                    "number_precision_loss at {}",
                    self.path
                )));
            }
        }
        let mut inner = serde_json::Deserializer::from_str(raw.get());
        serde::Deserializer::deserialize_any(&mut inner, self).map_err(serde::de::Error::custom)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON without duplicate keys")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("wrong_type"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            depth: self.depth + 1,
            nodes: self.nodes,
            path: format!("{}/{}", self.path, values.len()),
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate_key"));
            }
            let value = map.next_value_seed(Seed {
                depth: self.depth + 1,
                nodes: self.nodes,
                path: pointer(&self.path, &key),
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

/// Decimal value as sign, significant digits and decimal exponent. This
/// compares numeric values without f64 conversion or expanding huge exponents.
fn decimal_value(token: &str) -> Option<(bool, String, i64)> {
    let negative = token.starts_with('-');
    let unsigned = token.trim_start_matches('-');
    let (mantissa, exponent) = unsigned.split_once(['e', 'E']).unwrap_or((unsigned, "0"));
    let exponent = exponent.parse::<i64>().ok()?;
    let fraction = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let mut digits = mantissa
        .replace('.', "")
        .trim_start_matches('0')
        .to_string();
    if digits.is_empty() {
        return Some((false, "0".into(), 0));
    }
    let mut power = exponent.checked_sub(i64::try_from(fraction).ok()?)?;
    while digits.ends_with('0') {
        digits.pop();
        power = power.checked_add(1)?;
    }
    Some((negative, digits, power))
}

/// Canonical object order, preserved array order and serde_json numeric
/// representation with floating signed zero canonicalized. Marker /1 pins these semantics.
pub fn normalize(value: &Value) -> Value {
    match value {
        Value::Object(obj) => {
            let mut names: Vec<_> = obj.keys().collect();
            names.sort();
            Value::Object(
                names
                    .into_iter()
                    .map(|name| (name.clone(), normalize(&obj[name])))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(normalize).collect()),
        Value::Number(number) if number.is_f64() && number.as_f64() == Some(0.0) => {
            Value::Number(serde_json::Number::from_f64(0.0).unwrap())
        }
        _ => value.clone(),
    }
}

pub(crate) fn validate_definition(doc: &Value) -> Result<Value> {
    keys(
        doc,
        &[
            "family",
            "version",
            "package_ref",
            "interpreter",
            "primary_type",
            "kinds",
        ],
        "",
    )?;
    let kinds = doc["kinds"]
        .as_array()
        .ok_or_else(|| refusal("wrong_type", "/kinds"))?;
    let mut legacy = doc.clone();
    let capabilities =
        crate::meta::definition_artifact::language_capabilities(doc["interpreter"].as_str());
    let text_formats = capabilities.supports_text_formats;
    legacy["interpreter"] = capabilities.scalar_base_interpreter.unwrap().into();
    for (i, kind) in kinds.iter().enumerate() {
        let path = format!("/kinds/{i}");
        keys(
            kind,
            &[
                "token",
                "description",
                "maturity",
                "identity",
                "fields",
                "links",
                "refines",
            ],
            &path,
        )?;
        let mut nodes = 0;
        validate_fields(
            &kind["fields"],
            0,
            &mut nodes,
            &pointer(&path, "fields"),
            text_formats,
        )?;
        let identity = &kind["identity"];
        keys(identity, &["mode", "field"], &pointer(&path, "identity"))?;
        crate::meta::definition_artifact::validate_defn4_field_identity(
            kind.as_object().unwrap(),
            identity.as_object().unwrap(),
            &path,
        )
        .map_err(|_| refusal("invalid_identity", &pointer(&path, "identity")))?;
        // Reuse /4's closed scalar metadata and link selectors while validating
        // structured descriptors above, before replacing them in this copy.
        for field in legacy["kinds"][i]["fields"].as_array_mut().unwrap() {
            if matches!(field["type"].as_str(), Some("object" | "list")) {
                *field = serde_json::json!({"name":field["name"],"type":"text","required":field["required"]});
            } else if field["type"] == "text" {
                // Validated above; the retained bytes are never altered, only
                // this temporary /4 copy, whose scalar keys are closed.
                let field = field.as_object_mut().unwrap();
                field.remove("text_format");
                field.remove("max_length");
            }
        }
    }
    Ok(legacy)
}

fn validate_fields(
    fields: &Value,
    depth: usize,
    nodes: &mut usize,
    path: &str,
    text_formats: bool,
) -> Result<()> {
    let fields = fields
        .as_array()
        .ok_or_else(|| refusal("wrong_type", path))?;
    if fields.len() > MAX_FIELDS {
        return Err(refusal("limit_exceeded", path));
    }
    let mut names = std::collections::HashSet::new();
    for (i, field) in fields.iter().enumerate() {
        let fp = format!("{path}/{i}");
        let name = field["name"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| refusal("wrong_type", &pointer(&fp, "name")))?;
        if !names.insert(name) {
            return Err(refusal("duplicate_name", &fp));
        }
        if !field["required"].is_boolean() {
            return Err(refusal("wrong_type", &pointer(&fp, "required")));
        }
        validate_descriptor(field, true, depth, nodes, &fp, text_formats)?;
    }
    Ok(())
}
fn validate_descriptor(
    desc: &Value,
    named: bool,
    depth: usize,
    nodes: &mut usize,
    path: &str,
    text_formats: bool,
) -> Result<()> {
    *nodes += 1;
    if *nodes > MAX_DESCRIPTORS {
        return Err(refusal("limit_exceeded", path));
    }
    let ty = desc["type"]
        .as_str()
        .ok_or_else(|| refusal("wrong_type", path))?;
    let mut allowed = vec!["type", "description"];
    if named {
        allowed.extend(["name", "required"]);
    }
    match ty {
        "object" => allowed.push("fields"),
        "list" => allowed.extend(["items", "max_items"]),
        "choice" => allowed.push("values"),
        "text" if text_formats => allowed.extend(["text_format", "max_length"]),
        scalar if crate::meta::definition_artifact::DEFN3_FIELD_TYPES.contains(&scalar) => (),
        _ => return Err(refusal("unknown_type", path)),
    }
    keys(desc, &allowed, path)?;
    if desc
        .get("description")
        .is_some_and(|d| !d.as_str().is_some_and(|s| !s.trim().is_empty()))
    {
        return Err(refusal("wrong_type", &pointer(path, "description")));
    }
    if ty == "text" && text_formats {
        if let Some(format) = desc.get("text_format") {
            let name = format
                .as_str()
                .ok_or_else(|| refusal("wrong_type", &pointer(path, "text_format")))?;
            if text_formats::find(name).is_none() {
                return Err(refusal(
                    "unknown_text_format",
                    &pointer(path, "text_format"),
                ));
            }
        }
        if let Some(limit) = desc.get("max_length") {
            if !limit
                .as_u64()
                .is_some_and(|n| (1..=MAX_TEXT_BYTES as u64).contains(&n))
            {
                return Err(refusal("limit_exceeded", &pointer(path, "max_length")));
            }
        }
    }
    if matches!(ty, "object" | "list") && depth >= MAX_DEPTH {
        return Err(refusal("limit_exceeded", path));
    }
    match ty {
        "object" => validate_fields(
            &desc["fields"],
            depth + 1,
            nodes,
            &pointer(path, "fields"),
            text_formats,
        )?,
        "list" => {
            if !desc["max_items"]
                .as_u64()
                .is_some_and(|n| (1..=MAX_ITEMS as u64).contains(&n))
            {
                return Err(refusal("limit_exceeded", &pointer(path, "max_items")));
            }
            validate_descriptor(
                &desc["items"],
                false,
                depth + 1,
                nodes,
                &pointer(path, "items"),
                text_formats,
            )?;
        }
        "choice" => {
            let values = desc["values"]
                .as_array()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| refusal("wrong_type", &pointer(path, "values")))?;
            let mut seen = std::collections::HashSet::new();
            for value in values {
                let s = value
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| refusal("wrong_type", &pointer(path, "values")))?;
                if !seen.insert(s) {
                    return Err(refusal("duplicate_value", &pointer(path, "values")));
                }
            }
        }
        _ => (),
    }
    Ok(())
}

/// Validate a record's fields against its kind's descriptors under the
/// retained language: `/5` uses Rust `trim` for blank required text, `/6`
/// adds the frozen blank set W, `text_format` and `max_length`.
pub(crate) fn validate_values(
    descriptors: &Value,
    fields: &Map<String, Value>,
    capabilities: &LanguageCapabilities,
) -> Result<()> {
    validate_value_budget(fields)?;
    validate_members(descriptors, fields, "", true, capabilities)
}
pub(crate) fn validate_value_budget(fields: &Map<String, Value>) -> Result<()> {
    let mut nodes = 1;
    let mut names: Vec<_> = fields.keys().collect();
    names.sort();
    for name in names {
        value_budget(&fields[name], &pointer("", name), &mut nodes, 1)?;
    }
    if serde_json::to_vec(&normalize(&Value::Object(fields.clone())))?.len() > MAX_VALUE_BYTES {
        return Err(refusal("limit_exceeded", ""));
    }
    Ok(())
}
fn value_budget(value: &Value, path: &str, nodes: &mut usize, depth: usize) -> Result<()> {
    *nodes += 1;
    if *nodes > MAX_VALUE_NODES || depth > MAX_DEPTH + 1 {
        return Err(refusal("limit_exceeded", path));
    }
    match value {
        Value::String(s) if s.len() > MAX_TEXT_BYTES => {
            return Err(refusal("limit_exceeded", path))
        }
        Value::Object(obj) => {
            let mut keys: Vec<_> = obj.keys().collect();
            keys.sort();
            for key in keys {
                value_budget(&obj[key], &pointer(path, key), nodes, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for (i, v) in values.iter().enumerate() {
                value_budget(v, &format!("{path}/{i}"), nodes, depth + 1)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn validate_members(
    desc: &Value,
    values: &Map<String, Value>,
    path: &str,
    top: bool,
    capabilities: &LanguageCapabilities,
) -> Result<()> {
    let fields = desc.as_array().ok_or_else(|| refusal("wrong_type", path))?;
    for field in fields {
        let name = field["name"].as_str().unwrap();
        let fp = pointer(path, name);
        match values.get(name) {
            None => {
                if field["required"] == true {
                    return Err(refusal("required_missing", &fp));
                }
            }
            Some(Value::Null) if top => {
                if field["required"] == true {
                    return Err(refusal("required_missing", &fp));
                }
            }
            Some(value) => validate_value(field, value, &fp, capabilities)?,
        }
    }
    let mut unknown: Vec<_> = values
        .keys()
        .filter(|name| !fields.iter().any(|f| f["name"].as_str() == Some(name)))
        .collect();
    unknown.sort();
    if let Some(name) = unknown.first() {
        return Err(refusal("unknown_member", &pointer(path, name)));
    }
    Ok(())
}
fn validate_value(
    desc: &Value,
    value: &Value,
    path: &str,
    capabilities: &LanguageCapabilities,
) -> Result<()> {
    if value.is_null() {
        return Err(refusal("null_not_supported", path));
    }
    let matched = match desc["type"].as_str().unwrap() {
        "object" => {
            let obj = value
                .as_object()
                .ok_or_else(|| refusal("wrong_type", path))?;
            validate_members(&desc["fields"], obj, path, false, capabilities)?;
            true
        }
        "list" => {
            let values = value
                .as_array()
                .ok_or_else(|| refusal("wrong_type", path))?;
            if values.len() as u64 > desc["max_items"].as_u64().unwrap() {
                return Err(refusal("limit_exceeded", path));
            }
            for (i, v) in values.iter().enumerate() {
                validate_value(&desc["items"], v, &format!("{path}/{i}"), capabilities)?;
            }
            true
        }
        "text" if capabilities.supports_text_formats => {
            let text = value.as_str().ok_or_else(|| refusal("wrong_type", path))?;
            validate_text(desc, text, path)?;
            true
        }
        "text" => value
            .as_str()
            .is_some_and(|s| desc["required"] != true || !s.trim().is_empty()),
        "integer" => crate::kernel::integer_spelling_matches(value),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "time" => value
            .as_str()
            .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()),
        "date" => value
            .as_str()
            .is_some_and(crate::kernel::is_calendar_date_or_rfc3339),
        "choice" => desc["values"].as_array().unwrap().contains(value),
        _ => false,
    };
    if matched {
        Ok(())
    } else {
        Err(refusal("wrong_type", path))
    }
}

/// `/6` text checks in the frozen order; the first failure wins and names the
/// path only, never the value: required not blank (W), format, length.
fn validate_text(desc: &Value, text: &str, path: &str) -> Result<()> {
    if desc["required"] == true && text_formats::is_blank(text) {
        return Err(refusal("wrong_type", path));
    }
    if let Some(name) = desc.get("text_format").and_then(Value::as_str) {
        if !text_formats::find(name).is_some_and(|format| format.matches(text)) {
            return Err(refusal("text_format_mismatch", path));
        }
    }
    if let Some(limit) = desc.get("max_length").and_then(Value::as_u64) {
        if text.chars().count() as u64 > limit {
            return Err(refusal("limit_exceeded", path));
        }
    }
    Ok(())
}

/// Discoverable contract for unfamiliar agents; examples remain app data.
/// Version-specific: only `/6` lists the text formats and `max_length`.
pub fn contract(interpreter: &str) -> Value {
    let mut contract = contract_v5();
    if interpreter != INTERPRETER_V6 {
        return contract;
    }
    contract["interpreter"] = INTERPRETER_V6.into();
    contract["limits"]["max_length"] = serde_json::json!({"min":1,"max":MAX_TEXT_BYTES});
    contract["limits"]["max_length_unit"] = "unicode_scalar_values".into();
    contract["text_formats"] = text_formats::TEXT_FORMATS
        .iter()
        .map(|format| {
            serde_json::json!({
                "name": format.name,
                "abnf": format.abnf,
                "description": format.description,
            })
        })
        .collect();
    contract["text_format_core_rules"] = text_formats::CORE_RULES.into();
    contract["blank_code_points"] = text_formats::BLANK_SET
        .iter()
        .map(|c| format!("U+{:04X}", *c as u32))
        .collect();
    contract["text_rules"] = serde_json::json!({
        "keys": "text_format and max_length are legal on text descriptors only, including list items",
        "required_blank": "required text containing only blank_code_points refuses as wrong_type",
        "check_order": ["required_blank", "text_format", "max_length"],
        "refusals": {"unknown_text_format":"definition","text_format_mismatch":"value","limit_exceeded":"definition or value"},
        "rewrites_values": false
    });
    contract
}

fn contract_v5() -> Value {
    serde_json::json!({
        "interpreter": INTERPRETER,
        "normalization": NORMALIZATION,
        "write_ingress": "raw JSON required; parsed-map APIs refuse",
        "objects": "closed",
        "lists": {"ordered":true,"duplicates":true},
        "absence": "omit optional members; top-level null deletes; nested null refuses",
        "revise": {"expected_revision_required":true,"token":"read.revision","scope":"record","replacement":"whole top-level field","conflict":"event-free; reread and reconcile"},
        "matching": {"mode":"whole top-level value equality","object_keys":"sorted UTF-8 bytes","array_order":"preserved","numbers":"i64/u64 exact; other numbers accepted only when f64 JSON round-trip preserves the decimal value; floating signed zero becomes 0.0; integer 1 differs from floating 1.0","nested_paths":false},
        "limits": {"input_bytes":MAX_INPUT_BYTES,"container_depth":MAX_DEPTH,"fields_per_object":MAX_FIELDS,"descriptors_per_kind":MAX_DESCRIPTORS,"max_items":MAX_ITEMS,"value_nodes":MAX_VALUE_NODES,"normalized_record_bytes":MAX_VALUE_BYTES,"text_bytes":MAX_TEXT_BYTES},
        "integer_spelling":"integer JSON representation only; decimal/exponent forms and -0 refuse",
        "semantic_rules":false,
        "text_locators_grant_authority":false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::definition_artifact::language_capabilities;
    use serde_json::json;

    fn envelope(interpreter: &str, fields: Value) -> Value {
        json!({"family":"fixture.text","version":1,"interpreter":interpreter,
            "primary_type":"Proof","kinds":[{"token":"proof","description":"Proof","maturity":"current",
            "identity":{"mode":"record"},"fields":fields,"links":[]}]})
    }
    fn define(interpreter: &str, fields: Value) -> Result<Value> {
        validate_definition(&envelope(interpreter, fields))
    }
    fn message(error: Error) -> String {
        error.to_string()
    }
    fn check(interpreter: &str, fields: Value, values: Value) -> Result<()> {
        let caps = language_capabilities(Some(interpreter));
        validate_values(&fields, values.as_object().unwrap(), &caps)
    }
    fn text(extra: Value) -> Value {
        let mut desc = json!([{"name":"t","type":"text","required":false}]);
        for (k, v) in extra.as_object().unwrap() {
            desc[0][k] = v.clone();
        }
        desc
    }

    #[test]
    fn v5_refuses_the_new_keys_with_unknown_member() {
        for key in [("text_format", json!("nonblank")), ("max_length", json!(5))] {
            let fields = text(json!({ key.0: key.1 }));
            let error = message(define(INTERPRETER, fields).unwrap_err());
            assert!(
                error.contains(&format!("unknown_member at /kinds/0/fields/0/{}", key.0)),
                "{error}"
            );
        }
    }

    #[test]
    fn v6_accepts_the_keys_on_text_only() {
        let ok = text(json!({"text_format":"snake_field","max_length":64}));
        define(INTERPRETER_V6, ok).unwrap();
        for name in text_formats::TEXT_FORMATS.iter().map(|f| f.name) {
            define(INTERPRETER_V6, text(json!({ "text_format": name }))).unwrap();
        }
        for (ty, extra) in [
            ("integer", json!({"max_length":5})),
            ("number", json!({"text_format":"nonblank"})),
            ("boolean", json!({"max_length":5})),
            ("date", json!({"text_format":"nonblank"})),
            ("time", json!({"max_length":5})),
        ] {
            let mut field = json!({"name":"t","type":ty,"required":false});
            let key = extra.as_object().unwrap().keys().next().unwrap().clone();
            field[&key] = extra[&key].clone();
            let error = message(define(INTERPRETER_V6, json!([field])).unwrap_err());
            assert!(
                error.contains(&format!("unknown_member at /kinds/0/fields/0/{key}")),
                "{error}"
            );
        }
        let choice =
            json!([{"name":"c","type":"choice","required":false,"values":["a"],"max_length":3}]);
        assert!(message(define(INTERPRETER_V6, choice).unwrap_err()).contains("unknown_member"));
        let object = json!([{"name":"o","type":"object","required":false,"text_format":"nonblank","fields":[]}]);
        assert!(message(define(INTERPRETER_V6, object).unwrap_err()).contains("unknown_member"));
        let list = json!([{"name":"l","type":"list","required":false,"max_items":3,"max_length":3,
            "items":{"type":"text"}}]);
        assert!(message(define(INTERPRETER_V6, list).unwrap_err()).contains("unknown_member"));
    }

    #[test]
    fn v6_keys_on_nested_and_list_item_descriptors() {
        let fields = json!([{"name":"o","type":"object","required":false,"fields":[
            {"name":"app","type":"text","required":true,"text_format":"dotted_id","max_length":128}]},
            {"name":"l","type":"list","required":false,"max_items":4,
             "items":{"type":"text","text_format":"uuid_v4v7"}}]);
        define(INTERPRETER_V6, fields).unwrap();
        let bad = json!([{"name":"l","type":"list","required":false,"max_items":4,
             "items":{"type":"text","text_format":"uuid"}}]);
        assert!(message(define(INTERPRETER_V6, bad).unwrap_err())
            .contains("unknown_text_format at /kinds/0/fields/0/items/text_format"));
        let bad = json!([{"name":"o","type":"object","required":false,"fields":[
            {"name":"x","type":"text","required":false,"max_length":0}]}]);
        assert!(message(define(INTERPRETER_V6, bad).unwrap_err())
            .contains("limit_exceeded at /kinds/0/fields/0/fields/0/max_length"));
    }

    #[test]
    fn v6_refuses_bad_key_values() {
        for name in [
            json!("UUID_V4V7"),
            json!("regex"),
            json!(""),
            json!("uuid_v4v7 "),
        ] {
            let error =
                message(define(INTERPRETER_V6, text(json!({"text_format":name}))).unwrap_err());
            assert!(
                error.contains("unknown_text_format at /kinds/0/fields/0/text_format"),
                "{error}"
            );
        }
        let error = message(define(INTERPRETER_V6, text(json!({"text_format":7}))).unwrap_err());
        assert!(
            error.contains("wrong_type at /kinds/0/fields/0/text_format"),
            "{error}"
        );
        for bad in [
            json!(0),
            json!(4097),
            json!(-1),
            json!(1.5),
            json!("5"),
            json!(true),
            json!(null),
            json!(5.0),
        ] {
            let error = message(
                define(INTERPRETER_V6, text(json!({"max_length":bad.clone()}))).unwrap_err(),
            );
            assert!(
                error.contains("limit_exceeded at /kinds/0/fields/0/max_length"),
                "{bad}: {error}"
            );
        }
        for ok in [1, 2, 4095, 4096] {
            define(INTERPRETER_V6, text(json!({"max_length":ok}))).unwrap();
        }
    }

    #[test]
    fn v6_definition_passes_the_v4_adapter_without_altering_the_input() {
        let doc = envelope(
            INTERPRETER_V6,
            json!([{"name":"t","type":"text","required":true,"text_format":"hex_colour","max_length":7},
                   {"name":"u","type":"text","required":false,"max_length":3}]),
        );
        let before = doc.clone();
        let legacy = validate_definition(&doc).unwrap();
        assert_eq!(doc, before);
        assert_eq!(legacy["interpreter"], "native.defn/4");
        for field in legacy["kinds"][0]["fields"].as_array().unwrap() {
            assert!(field.get("text_format").is_none() && field.get("max_length").is_none());
        }
        crate::meta::definition_artifact::validate_kernel_definition_bytes(&doc.to_string())
            .unwrap();
        // The same bytes under /5 are refused by the structured validator.
        let mut v5 = doc.clone();
        v5["interpreter"] = INTERPRETER.into();
        assert!(
            crate::meta::definition_artifact::validate_kernel_definition_bytes(&v5.to_string())
                .is_err()
        );
    }

    #[test]
    fn declared_language_reports_the_final_marker() {
        for (raw, expected) in [
            (r#"{"interpreter":"native.defn/5"}"#, Some(INTERPRETER)),
            (r#"{"interpreter":"native.defn/6"}"#, Some(INTERPRETER_V6)),
            (
                r#"{"interpreter":"native.defn/5","interpreter":"native.defn/6"}"#,
                Some(INTERPRETER_V6),
            ),
            (
                r#"{"interpreter":"native.defn/6","interpreter":"native.defn/4"}"#,
                None,
            ),
            (r#"{"interpreter":"native.defn/7"}"#, None),
            (r#"{}"#, None),
        ] {
            assert_eq!(declared_language(raw).unwrap(), expected, "{raw}");
        }
    }

    #[test]
    fn length_counts_unicode_scalar_values() {
        let fields = text(json!({"max_length":3}));
        let ok = |s: &str| check(INTERPRETER_V6, fields.clone(), json!({"t":s}));
        for s in ["", "a", "abc", "日本語", "😀😀😀", "é̃x"] {
            ok(s).unwrap();
        }
        for s in ["abcd", "日本語字", "😀😀😀😀", "e\u{301}e\u{301}"] {
            assert!(
                message(ok(s).unwrap_err()).contains("limit_exceeded at /t"),
                "{s}"
            );
        }
        // /5 does not know max_length: such a definition cannot exist, and the
        // value path ignores the key.
        check(INTERPRETER, fields, json!({"t":"abcdef"})).unwrap();
    }

    #[test]
    fn byte_ceiling_stays_alongside_max_length() {
        let fields = text(json!({"max_length":4096}));
        let ok = "ß".repeat(2048); // 4096 bytes, 2048 code points
        check(INTERPRETER_V6, fields.clone(), json!({"t":ok})).unwrap();
        check(
            INTERPRETER_V6,
            fields.clone(),
            json!({"t":"a".repeat(4096)}),
        )
        .unwrap();
        for over in ["ß".repeat(2049), "a".repeat(4097), "日".repeat(1366)] {
            assert!(
                message(check(INTERPRETER_V6, fields.clone(), json!({"t":over})).unwrap_err())
                    .contains("limit_exceeded at /t")
            );
        }
    }

    #[test]
    fn checks_run_required_blank_then_format_then_length() {
        let fields = json!([{"name":"t","type":"text","required":true,"text_format":"uuid_v4v7","max_length":5}]);
        let run =
            |s: &str| message(check(INTERPRETER_V6, fields.clone(), json!({"t":s})).unwrap_err());
        assert!(run("\u{3000}").contains("wrong_type at /t"));
        assert!(run("").contains("wrong_type at /t"));
        assert!(
            run("abcdefgh").contains("text_format_mismatch at /t"),
            "format before length"
        );
        let fields = json!([{"name":"t","type":"text","required":true,"text_format":"snake_field","max_length":5}]);
        let error = message(check(INTERPRETER_V6, fields, json!({"t":"abcdefgh"})).unwrap_err());
        assert!(error.contains("limit_exceeded at /t"), "{error}");
        // The refusal names the path only, never the value.
        assert!(!error.contains("abcdefgh"));
    }

    #[test]
    fn global_budget_runs_before_field_checks() {
        let fields = json!([{"name":"a","type":"text","required":false,"text_format":"snake_field"},
            {"name":"b","type":"text","required":false}]);
        let error = message(
            check(
                INTERPRETER_V6,
                fields,
                json!({"a":"NOT snake","b":"x".repeat(5000)}),
            )
            .unwrap_err(),
        );
        assert!(error.contains("limit_exceeded at /b"), "{error}");
    }

    #[test]
    fn required_blank_differs_between_v5_and_v6() {
        let fields = json!([{"name":"t","type":"text","required":true}]);
        // U+FEFF and U+FEFF U+3000: Rust trim keeps U+FEFF, W does not.
        for value in ["\u{FEFF}", "\u{FEFF}\u{3000}"] {
            check(INTERPRETER, fields.clone(), json!({"t":value})).unwrap();
            assert!(message(
                check(INTERPRETER_V6, fields.clone(), json!({"t":value})).unwrap_err()
            )
            .contains("wrong_type at /t"));
        }
        for value in ["", " ", "\u{3000}", "\u{0085}", "\t\n"] {
            assert!(
                check(INTERPRETER, fields.clone(), json!({"t":value})).is_err(),
                "{value:?}"
            );
            assert!(
                check(INTERPRETER_V6, fields.clone(), json!({"t":value})).is_err(),
                "{value:?}"
            );
        }
        for value in ["a", " a ", "\u{200B}"] {
            check(INTERPRETER, fields.clone(), json!({"t":value})).unwrap();
            check(INTERPRETER_V6, fields.clone(), json!({"t":value})).unwrap();
        }
        // Optional and list-item text without a format still accept "".
        check(INTERPRETER_V6, text(json!({})), json!({"t":""})).unwrap();
        let list = json!([{"name":"l","type":"list","required":false,"max_items":3,"items":{"type":"text"}}]);
        check(INTERPRETER_V6, list, json!({"l":["", "\u{FEFF}"]})).unwrap();
    }

    #[test]
    fn nonblank_on_optional_text_and_list_items() {
        let fields = text(json!({"text_format":"nonblank"}));
        check(INTERPRETER_V6, fields.clone(), json!({"t":" a "})).unwrap();
        for blank in ["", " ", "\u{3000}", "\u{FEFF}\u{3000}", "\u{0085}"] {
            assert!(message(
                check(INTERPRETER_V6, fields.clone(), json!({"t":blank})).unwrap_err()
            )
            .contains("text_format_mismatch at /t"));
        }
        let list = json!([{"name":"l","type":"list","required":false,"max_items":3,"items":{"type":"text","text_format":"nonblank"}}]);
        let error =
            message(check(INTERPRETER_V6, list, json!({"l":["a","b","\u{3000}"]})).unwrap_err());
        assert!(error.contains("text_format_mismatch at /l/2"), "{error}");
    }

    #[test]
    fn nested_refusals_carry_the_full_pointer() {
        let fields = json!([{"name":"definition","type":"object","required":true,"fields":[
            {"name":"filter","type":"object","required":false,"fields":[
              {"name":"terms","type":"list","required":false,"max_items":8,"items":{"type":"object","fields":[
                {"name":"field","type":"text","required":true,"text_format":"snake_field","max_length":64}]}}]}]}]);
        let terms: Vec<Value> = (0..4)
            .map(|i| json!({"field": if i == 3 { "Bad" } else { "good" }}))
            .collect();
        let error = message(
            check(
                INTERPRETER_V6,
                fields,
                json!({"definition":{"filter":{"terms":terms}}}),
            )
            .unwrap_err(),
        );
        assert!(
            error.contains("text_format_mismatch at /definition/filter/terms/3/field"),
            "{error}"
        );
    }

    #[test]
    fn non_string_values_and_trailing_newlines_refuse() {
        let fields = text(json!({"text_format":"hex_colour"}));
        assert!(
            message(check(INTERPRETER_V6, fields.clone(), json!({"t":7})).unwrap_err())
                .contains("wrong_type at /t")
        );
        check(INTERPRETER_V6, fields.clone(), json!({"t":"#aBcDeF"})).unwrap();
        assert!(
            message(check(INTERPRETER_V6, fields, json!({"t":"#aBcDeF\n"})).unwrap_err())
                .contains("text_format_mismatch at /t")
        );
    }

    #[test]
    fn contract_is_version_specific() {
        let v5 = contract(INTERPRETER);
        assert_eq!(v5["interpreter"], INTERPRETER);
        assert!(v5.get("text_formats").is_none());
        assert!(
            v5["limits"].get("max_length").is_none()
                && v5["limits"].get("max_length_unit").is_none()
        );
        let v6 = contract(INTERPRETER_V6);
        assert_eq!(v6["interpreter"], INTERPRETER_V6);
        assert_eq!(v6["limits"]["max_length"], json!({"min":1,"max":4096}));
        assert_eq!(v6["limits"]["max_length_unit"], "unicode_scalar_values");
        assert_eq!(v6["limits"]["text_bytes"], 4096);
        // Everything /5 says, /6 says too.
        for (key, value) in v5.as_object().unwrap() {
            if key != "interpreter" && key != "limits" {
                assert_eq!(&v6[key], value, "{key}");
            }
        }
    }

    /// Frozen for `/6`: any change to a name, a grammar, a description or W
    /// needs a new language marker, not an edit to this table.
    #[test]
    fn frozen_text_format_table() {
        let listed: Vec<(&str, &str, &str)> = text_formats::TEXT_FORMATS
            .iter()
            .map(|f| (f.name, f.abnf, f.description))
            .collect();
        let expected: Vec<(&str, &str, &str)> = vec![
            (
                "uuid_v4v7",
                "uuid-v4v7 = 8HEXLOW \"-\" 4HEXLOW \"-\" (\"4\" / \"7\") 3HEXLOW \"-\" 4HEXLOW \"-\" 12HEXLOW",
                "Canonical lowercase UUID with version nibble 4 or 7",
            ),
            (
                "record_locator",
                "record-locator = uuid-v4v7 / native-token\nnative-token = %x6E.61.74.69.76.65.3A LOWER *(LOWER / DIGIT / \"-\")",
                "A lowercase v4/v7 UUID, or a lowercase \"native:\" token; the prefix is case-sensitive",
            ),
            (
                "hex_colour",
                "hex-colour = \"#\" 6HEXANY",
                "A # followed by six hex digits of either case; case is not normalised",
            ),
            (
                "dotted_id",
                "dotted-id = segment 1*(\".\" segment)\nsegment = LOWER *(LOWER / DIGIT / \"-\")",
                "Two or more dot-separated lowercase segments of letters, digits and hyphens",
            ),
            (
                "versioned_token",
                "versioned-token = LOWER *(LOWER / DIGIT / \"-\") \"/\" %x31-39 *DIGIT",
                "A lowercase token, a slash and a positive version number without leading zeros",
            ),
            (
                "snake_field",
                "snake-field = LOWER *(LOWER / DIGIT / \"_\")",
                "A lowercase letter followed by lowercase letters, digits and underscores",
            ),
            (
                "nonblank",
                "nonblank = <a string containing at least one Unicode scalar value outside W>",
                "Any text containing at least one code point that is not in W",
            ),
        ];
        assert_eq!(listed, expected);
        assert_eq!(
            text_formats::CORE_RULES,
            "LOWER = %x61-7A\nDIGIT = %x30-39\nHEXLOW = DIGIT / %x61-66\nHEXANY = HEXLOW / %x41-46"
        );
        let blank: Vec<String> = text_formats::BLANK_SET
            .iter()
            .map(|c| format!("U+{:04X}", *c as u32))
            .collect();
        assert_eq!(
            blank.join(" "),
            "U+0009 U+000A U+000B U+000C U+000D U+0020 U+0085 U+00A0 U+1680 U+2000 U+2001 U+2002 \
             U+2003 U+2004 U+2005 U+2006 U+2007 U+2008 U+2009 U+200A U+2028 U+2029 U+202F U+205F \
             U+3000 U+FEFF"
        );
        // The contract publishes exactly this table.
        let published = contract(INTERPRETER_V6);
        let names: Vec<&str> = published["text_formats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "uuid_v4v7",
                "record_locator",
                "hex_colour",
                "dotted_id",
                "versioned_token",
                "snake_field",
                "nonblank"
            ]
        );
        assert_eq!(published["blank_code_points"].as_array().unwrap().len(), 26);
        assert_eq!(MAX_TEXT_BYTES, 4096);
    }
}
