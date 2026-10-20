//! A gated, pure view of retained definition semantics. No inheritance or migration.
use crate::meta::definition_artifact::{self as artifact, RevisionIdentity};
use crate::{error::Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldShape {
    pub name: String,
    pub value_type: String,
    pub json_type: String,
    pub required: bool,
    pub choices: Vec<Value>,
    pub text_format: Option<String>,
    pub max_length: Option<u64>,
    pub max_items: Option<u64>,
    pub description: Option<String>,
    pub fields: Vec<FieldShape>,
    pub items: Option<Box<FieldShape>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonExpressible {
    pub rule: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedShape {
    pub pin: RevisionIdentity,
    pub kind: String,
    pub interpreter: String,
    pub fields: Vec<FieldShape>,
    pub identity: Value,
    pub links: Vec<Value>,
    pub refines: Option<String>,
    pub maturity: Option<String>,
    pub description: Option<String>,
    pub definition_description: Option<String>,
    pub non_expressible: Vec<NonExpressible>,
}
fn string(v: &Value, key: &str) -> Option<String> {
    v[key].as_str().map(str::to_owned)
}
fn fields(v: &Value) -> Vec<FieldShape> {
    v.as_array().into_iter().flatten().map(field).collect()
}
fn field(v: &Value) -> FieldShape {
    FieldShape {
        name: string(v, "name").unwrap_or_default(),
        value_type: string(v, "type").unwrap_or_default(),
        json_type: match v["type"].as_str().unwrap_or("") {
            "text" | "choice" | "date" | "time" => "string",
            "list" => "array",
            t => t,
        }
        .into(),
        required: v["required"] == true,
        choices: v["values"].as_array().cloned().unwrap_or_default(),
        text_format: string(v, "text_format"),
        max_length: v["max_length"].as_u64(),
        max_items: v["max_items"].as_u64(),
        description: string(v, "description"),
        fields: if v["type"] == "object" {
            fields(&v["fields"])
        } else {
            vec![]
        },
        items: if v["type"] == "list" {
            v.get("items").map(|v| Box::new(field(v)))
        } else {
            None
        },
    }
}
impl TypedShape {
    /// Revalidate the supplied bytes, derive the digest from those exact bytes.
    pub fn from_bytes(bytes: &str, kind: &str) -> Result<Self> {
        artifact::validate_kernel_definition_bytes(bytes)?;
        let envelope = artifact::parse_artifact_envelope(bytes)?;
        let doc: Value = serde_json::from_str(bytes)?;
        let entry = envelope
            .kinds
            .as_array()
            .ok_or_else(|| Error::engine("definition omitted kinds array"))?
            .iter()
            .find(|v| v.as_str() == Some(kind) || v["token"].as_str() == Some(kind))
            .ok_or_else(|| Error::engine("kind absent from definition"))?;
        let interpreter = string(&doc, "interpreter").unwrap_or_else(|| "native.defn/1".into());
        let caps = artifact::language_capabilities(Some(&interpreter));
        let mut shape = Self {
            pin: RevisionIdentity {
                family: envelope.family,
                version: envelope.version,
                digest: artifact::digest_artifact_bytes(bytes.as_bytes()),
            },
            kind: kind.into(),
            interpreter,
            fields: if caps.supports_fields {
                fields(&entry["fields"])
            } else {
                vec![]
            },
            identity: if caps.supports_record_identity {
                entry["identity"].clone()
            } else if caps.supports_fields {
                json!({"field": entry["identity"]["field"]})
            } else {
                Value::Null
            },
            // /1 has no link semantics: even malformed metadata is opaque.
            links: if caps.supports_fields {
                entry["links"].as_array().cloned().unwrap_or_default()
            } else {
                vec![]
            },
            refines: string(entry, "refines"),
            maturity: string(entry, "maturity"),
            description: string(entry, "description"),
            definition_description: string(&doc, "description"),
            non_expressible: vec![],
        };
        fn retain_supported(fs: &mut [FieldShape], formats: bool) {
            for f in fs {
                if !formats {
                    f.text_format = None;
                    f.max_length = None;
                }
                if f.value_type != "choice" {
                    f.choices.clear();
                }
                retain_supported(&mut f.fields, formats);
                if let Some(item) = &mut f.items {
                    retain_supported(std::slice::from_mut(item), formats);
                }
            }
        }
        retain_supported(&mut shape.fields, caps.supports_text_formats);
        // Legacy link selectors use only primary_type+kind. In /2 and /3,
        // newer selector keys and relationship_ref are ignored extensions.
        if !caps.supports_closed_links {
            for link in &mut shape.links {
                let link = link
                    .as_object_mut()
                    .ok_or_else(|| Error::engine("definition link is not an object"))?;
                let target = link
                    .get("target")
                    .ok_or_else(|| Error::engine("definition link omitted target"))?;
                let target = json!({"primary_type":target["primary_type"],"kind":target["kind"]});
                link.insert("target".into(), target);
                link.remove("relationship_ref");
            }
        }
        shape.note("scope_adoption", "Creation requires current adoption and Edit permission in the selected home; the kernel checks both at commit.");
        shape.note("revise_state", "Revisions use the record's own pin and merged fields, preserve identity, and enforce the expected revision at commit.");
        if shape.identity.get("field").is_some() {
            shape.note("identity_uniqueness", "Identity field values are unique workspace-wide per family and kind; duplicates refuse as identity value unavailable.");
        }
        if caps.supports_structured_values {
            shape.note("value_budget", "The kernel limits UTF-8 text to 4096 bytes, normalized fields to 65536 bytes, value nodes to 1024 and value depth to 5; JSON Schema cannot count bytes or aggregate nodes.");
            shape.note("raw_json", "Raw structured ingress rejects duplicate keys, precision loss and input over 262144 bytes before JSON values exist.");
        }
        fn has(fs: &[FieldShape], ty: &str) -> bool {
            fs.iter().any(|f| {
                f.value_type == ty
                    || has(&f.fields, ty)
                    || f.items
                        .as_ref()
                        .is_some_and(|i| has(std::slice::from_ref(i), ty))
            })
        }
        if has(&shape.fields, "integer") {
            shape.note("integer_spelling", "The kernel requires an i64/u64 JSON integer representation; JSON Schema integers also accept integral decimal and exponent spellings.");
        }
        let grammar = match (has(&shape.fields, "time"), has(&shape.fields, "date")) {
            (true, true) => Some("Time uses chrono RFC3339 parsing; date also accepts round-tripping calendar dates."),
            (true, false) => Some("Time uses chrono RFC3339 parsing."),
            (false, true) => Some("Date accepts chrono RFC3339 timestamps or round-tripping calendar dates."),
            _ => None,
        };
        if let Some(grammar) = grammar {
            shape.note(
                "temporal_grammar",
                &format!(
                    "{grammar} Schema formats are annotations; the kernel checks this grammar."
                ),
            );
        }
        Ok(shape)
    }
    fn note(&mut self, rule: &str, reason: &str) {
        self.non_expressible.push(NonExpressible {
            rule: rule.into(),
            reason: reason.into(),
        });
    }
    fn structured(&self) -> bool {
        artifact::language_capabilities(Some(&self.interpreter)).supports_structured_values
    }
    fn blank_pattern(&self) -> &'static str {
        if self.interpreter == "native.defn/6" {
            "[^\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]"
        } else {
            "[^\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]"
        }
    }
    fn field_schema(&self, f: &FieldShape, top: bool, patch: bool) -> Value {
        let mut s = json!({"type":f.json_type});
        if let Some(d) = &f.description {
            s["description"] = json!(d);
        }
        if f.value_type == "integer" {
            s["minimum"] = json!(i64::MIN);
            s["maximum"] = json!(u64::MAX);
        }
        if f.value_type == "choice" {
            s["enum"] = json!(f.choices);
        }
        if f.value_type == "time" || f.value_type == "date" {
            s["format"] = json!(format!("native-{}", f.value_type));
        }
        if f.value_type == "text" {
            let caps = artifact::language_capabilities(Some(&self.interpreter));
            if caps.supports_record_identity && f.required {
                s["pattern"] = json!(self.blank_pattern());
            }
            if caps.supports_text_formats {
                if let Some(n) = f.max_length {
                    s["maxLength"] = json!(n);
                }
                if let Some(fmt) = &f.text_format {
                    let uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}";
                    let pattern = match fmt.as_str() {
                        "uuid_v4v7" => format!("^{uuid}$"),
                        "record_locator" => format!("^({uuid}|native:[a-z][a-z0-9-]*)$"),
                        "hex_colour" => "^#[0-9a-fA-F]{6}$".into(),
                        "dotted_id" => "^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$".into(),
                        "versioned_token" => "^[a-z][a-z0-9-]*/[1-9][0-9]*$".into(),
                        "snake_field" => "^[a-z][a-z0-9_]*$".into(),
                        "nonblank" => self.blank_pattern().into(),
                        _ => unreachable!(),
                    };
                    // Required blank and format restrictions must both hold.
                    s["allOf"] = if fmt == "nonblank" {
                        json!([{"pattern":pattern}])
                    } else {
                        json!([{"pattern":pattern},{"not":{"pattern":"[\r\n]"}}])
                    };
                }
            }
        }
        if f.value_type == "object" {
            s = self.members_schema(&f.fields, false, false);
        }
        if let Some(item) = &f.items {
            s["items"] = self.field_schema(item, false, false);
            s["maxItems"] = json!(f.max_items.unwrap());
        }
        if let Some(d) = &f.description {
            s["description"] = json!(d);
        }
        let identity = self.identity["field"].as_str() == Some(&f.name);
        if top && (patch || (!f.required && !identity)) {
            s = json!({"anyOf":[s,{"type":"null"}]});
        }
        s
    }
    fn members_schema(&self, fs: &[FieldShape], top: bool, patch: bool) -> Value {
        let properties: Map<String, Value> = fs
            .iter()
            .map(|f| (f.name.clone(), self.field_schema(f, top, patch)))
            .collect();
        let required: Vec<_> = fs
            .iter()
            .filter(|f| {
                !patch && (f.required || (top && self.identity["field"].as_str() == Some(&f.name)))
            })
            .map(|f| &f.name)
            .collect();
        json!({"type":"object","properties":properties,"required":required,
            "additionalProperties":if top && !self.structured() { json!({"type":"null"}) } else { json!(false) }})
    }
    pub fn fields_schema(&self) -> Value {
        self.members_schema(&self.fields, true, false)
    }
    pub fn create_schema(&self, homes: &[String]) -> Value {
        json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
            "properties":{"home":{"type":"string","enum":homes},"fields":self.fields_schema()},
            "required":["home","fields"],"additionalProperties":false})
    }
    pub fn revise_schema(&self) -> Value {
        json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
            "properties":{"id":{"type":"string"},"expected_revision":{"type":"integer"},"fields":self.members_schema(&self.fields,true,true)},
            "required":["id","expected_revision","fields"],"additionalProperties":false})
    }
    pub fn query_schema(&self) -> Value {
        self.query_schema_for(std::slice::from_ref(self))
    }
    fn query_schema_for(&self, shapes: &[TypedShape]) -> Value {
        let mut types =
            std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
        for shape in shapes {
            for f in &shape.fields {
                if !matches!(f.value_type.as_str(), "object" | "list") {
                    types
                        .entry(f.name.clone())
                        .or_default()
                        .insert(f.json_type.clone());
                }
            }
        }
        let props: Map<String, Value> = types
            .into_iter()
            .map(|(name, types)| {
                let mut alternatives: Vec<Value> =
                    types.into_iter().map(|t| json!({"type":t})).collect();
                // These branches advertise retained types without imposing create rules.
                // The kernel also accepts other scalar comparisons (possibly with no hits).
                alternatives.push(json!({"type":["string","number","boolean","null"]}));
                (name, json!({"anyOf":alternatives}))
            })
            .collect();
        json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{
            "field_equals":{"type":"object","properties":props,"additionalProperties":{"type":["string","number","boolean","null"]}},
            "linked_to":{"type":"object","properties":{"predicate":{"type":"string"},"id":{"type":"string"},"direction":{"enum":["out","in","either"]}},"required":["predicate","id","direction"],"additionalProperties":false},
            "limit":{"type":"integer","minimum":0},"cursor":{"type":"string"}},"additionalProperties":false})
    }
    pub fn record_schema(&self) -> Value {
        json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{
            "id":{"type":"string"},"fields":self.fields_schema(),"pin":{"const":self.pin}},"required":["id","fields","pin"]})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standard_shapes() {
        for entry in
            std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src/v2_standard")).unwrap()
        {
            let path = entry.unwrap().path();
            if !path.to_string_lossy().ends_with(".defn.json") {
                continue;
            }
            let bytes = std::fs::read_to_string(path).unwrap();
            let doc: Value = serde_json::from_str(&bytes).unwrap();
            for kind in doc["kinds"].as_array().unwrap() {
                let token = kind.as_str().or_else(|| kind["token"].as_str()).unwrap();
                let shape = TypedShape::from_bytes(&bytes, token).unwrap();
                assert_eq!(
                    shape.pin.digest,
                    artifact::digest_artifact_bytes(bytes.as_bytes())
                );
                for schema in [
                    shape.create_schema(&["home".into()]),
                    shape.revise_schema(),
                    shape.query_schema(),
                    shape.record_schema(),
                ] {
                    jsonschema::validator_for(&schema).unwrap();
                }
            }
        }
    }
}

#[cfg(test)]
mod conformance_tests;
/// Shared contract rules, emitted once by the harness beside the descriptors.
pub const TYPED_TOOL_RULES: &[&str] = &[
    "Kernel refusals are returned unchanged.",
    "Creation requires current adoption and Edit permission in the selected home; the kernel checks both at commit.",
    "Revise validates merged fields under the record's own pin, preserves identity, and uses expected_revision for compare-and-swap at commit; versions are not mapped.",
    "Queries span versions and visible homes; each hit includes its retained pin and revision.",
    "Older-version records may carry other fields, and scalar equality filters may match nothing.",
    "Query predicates are suggestions, not an allow-list: query_as accepts any predicate string and may return no matches.",
    "Use query direction in for incoming links, out for outgoing links, or either for either endpoint.",
    "Link cardinalities are declaration metadata.",
    "A declared direction either permits outgoing links and does not create symmetry.",
    "Use the generic link subcommand to create links.",
];
#[derive(Debug, Clone, Serialize)]
pub struct TypedTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(skip)]
    pub shape: TypedShape,
    #[serde(skip)]
    operation: String,
}
async fn retained_shape(
    db: &crate::db::Db,
    pin: &RevisionIdentity,
    kind: &str,
) -> Result<TypedShape> {
    let stored = crate::definition_registry::read_definition_artifact(
        db,
        &pin.family,
        pin.version,
        &pin.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("selected primary definition artifact is missing"))?;
    let shape = TypedShape::from_bytes(&stored.bytes, kind)?;
    if shape.pin != *pin {
        return Err(Error::engine("definition pin mismatch"));
    }
    Ok(shape)
}
fn tool_token(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
// The catalog is already caller-visible describe output (plus visible retained pins).
// Legacy targets select primary_type, not family; retain that distinction if unresolved.
fn link_target_words(target: &Value, catalog: &[Value]) -> String {
    if target["any_record"] == true {
        return "any record".into();
    }
    let kind = target["kind"].as_str().unwrap_or("unspecified");
    if let Some(family) = target["family"].as_str() {
        return format!("{family}/{kind}");
    }
    let primary = target["primary_type"].as_str().unwrap_or("unspecified");
    let families: std::collections::BTreeSet<_> = catalog
        .iter()
        .filter(|e| e["primary_type"] == primary && e["kind"] == kind)
        .filter_map(|e| e["family"].as_str())
        .collect();
    if families.is_empty() {
        format!("primary type {primary}/{kind} (family not visible)")
    } else {
        families
            .into_iter()
            .map(|family| format!("{family}/{kind}"))
            .collect::<Vec<_>>()
            .join(" or ")
    }
}
fn link_name(link: &Value) -> String {
    link["predicate"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| {
            let r = &link["relationship_ref"];
            format!(
                "relationship_ref {}/{} version {} relationship {}",
                r["namespace"].as_str().unwrap_or(""),
                r["package"].as_str().unwrap_or(""),
                r["version"],
                r["relationship"].as_str().unwrap_or("")
            )
        })
}
fn relationship_view(shape: &TypedShape, catalog: &[Value]) -> (String, Vec<String>) {
    let mut descriptions = std::collections::BTreeSet::new();
    let mut predicates = std::collections::BTreeSet::new();
    for link in &shape.links {
        if let Some(p) = link["predicate"].as_str() {
            predicates.insert(p.to_owned());
        }
        descriptions.insert(format!(
            "{} to {} ({}; cardinality {})",
            link_name(link),
            link_target_words(&link["target"], catalog),
            link["direction"].as_str().unwrap_or("unspecified"),
            link["cardinality"].as_str().unwrap_or("unspecified")
        ));
    }
    let primary_types: std::collections::BTreeSet<_> = catalog
        .iter()
        .filter(|e| e["family"] == shape.pin.family && e["kind"] == shape.kind)
        .filter_map(|e| e["primary_type"].as_str())
        .collect();
    for source in catalog {
        for link in source["links"].as_array().into_iter().flatten() {
            let target = &link["target"];
            let matches = target["any_record"] == true
                || (target["kind"] == shape.kind
                    && (target["family"] == shape.pin.family
                        || target["primary_type"]
                            .as_str()
                            .is_some_and(|p| primary_types.contains(p))));
            // Both legacy and /4 admission allow outgoing edges for out/either;
            // either does not create a symmetric edge. Incoming queries reverse the view.
            if !matches || !matches!(link["direction"].as_str(), Some("out" | "either")) {
                continue;
            }
            if let Some(p) = link["predicate"].as_str() {
                predicates.insert(p.to_owned());
            }
            descriptions.insert(format!(
                "{} from {}/{} (in; source {}; cardinality {})",
                link_name(link),
                source["family"].as_str().unwrap_or("unspecified"),
                source["kind"].as_str().unwrap_or("unspecified"),
                link["direction"].as_str().unwrap(),
                link["cardinality"].as_str().unwrap_or("unspecified")
            ));
        }
    }
    let prose = if descriptions.is_empty() {
        String::new()
    } else {
        format!(
            " Links: {}.",
            descriptions.into_iter().collect::<Vec<_>>().join("; ")
        )
    };
    (prose, predicates.into_iter().collect())
}
impl TypedShape {
    fn identity_description(&self) -> String {
        if let Some(field) = self.identity["field"].as_str() {
            format!("Identity is the {field} field, immutable and unique workspace-wide for this family and kind.")
        } else {
            "Each record has its own identity.".into()
        }
    }
    fn revise_identity_description(&self, visible: &[TypedShape]) -> String {
        // /1's implicit record identity and /3's explicit record mode mean the
        // same thing. Compare semantic identity fields, not raw metadata.
        let field = self.identity["field"].as_str();
        if visible
            .iter()
            .all(|s| s.identity["field"].as_str() == field)
        {
            return self.identity_description();
        }
        let mut text = "Identity by record pin:".to_owned();
        for shape in visible {
            text.push_str(&format!(" {}: ", shape.pin.value_string()));
            if shape.identity["field"].is_string() {
                text.push_str(&shape.identity_description());
            } else {
                text.push_str("Each record has its own identity; fields may be revised subject to this pin's schema.");
            }
        }
        text
    }
    fn tool_description(&self, operation: &str, relationships: &str, identity: &str) -> String {
        let mut text = [
            self.definition_description.as_deref(),
            self.description.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
        if text.is_empty() {
            text = format!("{} {}.", self.pin.family, self.kind);
        }
        fn descriptions(fs: &[FieldShape], prefix: &str, out: &mut String) {
            for f in fs {
                let path = format!("{prefix}{}", f.name);
                if let Some(d) = &f.description {
                    out.push_str(&format!(" {path}: {d}"));
                }
                descriptions(&f.fields, &format!("{path}."), out);
                if let Some(item) = &f.items {
                    descriptions(std::slice::from_ref(item), &format!("{path}[]"), out);
                }
            }
        }
        descriptions(&self.fields, "", &mut text);
        text.push(' ');
        text.push_str(identity);
        text.push_str(relationships);
        if let Some(base) = &self.refines {
            text.push_str(&format!(
                " Refines {base} as metadata; no fields are inherited."
            ));
        }
        // Equality filters do not perform create/patch field validation. Shared
        // state rules live in TYPED_TOOL_RULES; field identity is described above.
        if operation != "query" {
            for rule in &self.non_expressible {
                match rule.rule.as_str() {
                    "scope_adoption" | "revise_state" | "identity_uniqueness" => continue,
                    _ => {}
                }
                text.push(' ');
                text.push_str(&rule.reason);
            }
        }
        text.trim().to_owned()
    }
}
/// Same caller-visible adoption groups and creatable homes as describe_world_as.
/// Optional scope restricts discovery to one visible home, not a subtree.
pub async fn typed_tools_for(
    db: &crate::db::Db,
    principal: &str,
    scope: Option<&str>,
) -> Result<Vec<TypedTool>> {
    let world = crate::kernel::describe_world_as(db, principal).await?;
    let entries = world["definitions"]
        .as_array()
        .ok_or_else(|| Error::engine("describe omitted definitions"))?;
    let selected: Vec<_> = entries
        .iter()
        .filter(|e| {
            e["kind"].is_string()
                && scope.is_none_or(|scope| {
                    e["adoption"]["resolved_in"]
                        .as_array()
                        .is_some_and(|hs| hs.iter().any(|h| h == scope))
                })
        })
        .collect();
    let mut versions =
        std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    for e in selected
        .iter()
        .filter(|e| e["adoption"]["state"] == "adopted")
    {
        versions
            .entry(e["family"].as_str().unwrap().into())
            .or_default()
            .insert(e["adoption"]["pin"].to_string());
    }
    // Query discovery must not reveal historical fields belonging only to hidden records.
    let records = crate::kernel::list_records_as(db, principal).await?;
    let mut visible_pins: std::collections::BTreeSet<String> = records
        .iter()
        .filter_map(|r| r.pin.as_ref())
        .map(|p| serde_json::to_string(p).unwrap())
        .collect();
    for e in entries
        .iter()
        .filter(|e| e["adoption"]["state"] == "adopted")
    {
        let pin: RevisionIdentity = serde_json::from_value(e["adoption"]["pin"].clone())?;
        visible_pins.insert(serde_json::to_string(&pin)?);
    }
    let mut catalog_pins = visible_pins.clone();
    for e in entries
        .iter()
        .filter(|e| e["adoption"]["state"] != "adopted")
    {
        if let Some(pin) =
            crate::definition_registry::list_family_revisions(db, e["family"].as_str().unwrap())
                .await?
                .last()
        {
            // Generic describe exposes the newest installed pin for disabled scopes.
            catalog_pins.insert(serde_json::to_string(pin)?);
        }
    }
    let mut link_catalog = vec![];
    // Retained records may use declarations absent from today's adoption. Read their
    // verified definitions without disclosing definitions belonging only to hidden records.
    for encoded in &catalog_pins {
        let pin: RevisionIdentity = serde_json::from_str(encoded)?;
        let stored = crate::definition_registry::read_definition_artifact(
            db,
            &pin.family,
            pin.version,
            &pin.digest,
        )
        .await?
        .ok_or_else(|| Error::engine("visible retained definition is missing"))?;
        let doc: Value = serde_json::from_str(&stored.bytes)?;
        for kind in doc["kinds"].as_array().into_iter().flatten() {
            let Some(token) = kind
                .as_str()
                .or_else(|| kind["token"].as_str())
                .filter(|token| !token.is_empty())
            else {
                // /1 accepts arbitrary kind metadata; describe ignores these too.
                continue;
            };
            let shape = TypedShape::from_bytes(&stored.bytes, token)?;
            link_catalog.push(
                json!({"family":pin.family,"primary_type":doc["primary_type"],
                "kind":token,"links":shape.links}),
            );
        }
    }
    let mut tools = vec![];
    let mut names = std::collections::BTreeSet::new();
    for e in &selected {
        let adopted = e["adoption"]["state"] == "adopted";
        // An adopted query already spans disabled scopes and retained versions.
        if !adopted
            && selected.iter().any(|other| {
                other["adoption"]["state"] == "adopted"
                    && other["family"] == e["family"]
                    && other["kind"] == e["kind"]
            })
        {
            continue;
        }
        let pin: RevisionIdentity = if adopted {
            serde_json::from_value(e["adoption"]["pin"].clone())?
        } else {
            let family = e["family"].as_str().unwrap();
            let row:Option<(String,i64,String)>=sqlx::query_as("SELECT family, version, digest FROM definition_artifacts WHERE family = ? ORDER BY version DESC LIMIT 1").bind(family).fetch_optional(db.write_pool()).await?;
            let Some((family, version, digest)) = row else {
                continue;
            };
            RevisionIdentity {
                family,
                version: u32::try_from(version)
                    .map_err(|_| Error::engine("invalid definition version"))?,
                digest,
            }
        };
        let kind = e["kind"]
            .as_str()
            .ok_or_else(|| Error::engine("definition omitted kind"))?;
        let shape = retained_shape(db, &pin, kind).await?;
        let mut retained = vec![];
        for revision in crate::definition_registry::list_family_revisions(db, &pin.family).await? {
            // Installed bytes alone confer no visibility. Use the same pins as query
            // discovery: visible adoptions/records, plus this described pin.
            if revision != pin && !visible_pins.contains(&serde_json::to_string(&revision)?) {
                continue;
            }
            let stored = crate::definition_registry::read_definition_artifact(
                db,
                &revision.family,
                revision.version,
                &revision.digest,
            )
            .await?
            .ok_or_else(|| Error::engine("retained definition artifact is missing"))?;
            let envelope = artifact::parse_artifact_envelope(&stored.bytes)?;
            // A kind may itself have been introduced or removed between versions.
            if envelope
                .kinds
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some(kind) || v["token"].as_str() == Some(kind))
            {
                retained.push(retained_shape(db, &revision, kind).await?);
            }
        }
        let query_shapes: Vec<_> = retained
            .iter()
            .filter(|s| {
                s.pin == pin || visible_pins.contains(&serde_json::to_string(&s.pin).unwrap())
            })
            .cloned()
            .collect();
        let mut revise_schema = shape.revise_schema();
        revise_schema["properties"]["fields"] = json!({"anyOf":retained.iter()
            .map(|s| s.members_schema(&s.fields, true, true)).collect::<Vec<_>>()});
        let (relationship_description, predicates) = relationship_view(&shape, &link_catalog);
        let mut query_schema = shape.query_schema_for(&query_shapes);
        let predicate_schema =
            &mut query_schema["properties"]["linked_to"]["properties"]["predicate"];
        // query_as accepts every predicate string, even undeclared/legacy ones.
        // The enum supplies discoverable suggestions without narrowing that contract.
        *predicate_schema = if predicates.is_empty() {
            json!({"type":"string"})
        } else {
            json!({"anyOf":[{"enum":predicates},{"type":"string"}]})
        };
        let homes: Vec<String> = e["adoption"]["creatable_homes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .filter(|h| scope.is_none_or(|s| *h == s))
            .map(str::to_owned)
            .collect();
        let suffix = if versions.get(&pin.family).is_some_and(|pins| pins.len() > 1) {
            format!("_v{}", pin.version)
        } else {
            String::new()
        };
        for operation in ["create", "revise", "query"] {
            if (!adopted && operation != "query") || (operation == "create" && homes.is_empty()) {
                continue;
            }
            let name = format!(
                "{operation}_{}_{}{suffix}",
                tool_token(&pin.family),
                tool_token(kind)
            );
            if !names.insert(name.clone()) {
                return Err(Error::engine(format!("typed tool name collision: {name}")));
            }
            let input_schema = match operation {
                "create" => shape.create_schema(&homes),
                "revise" => revise_schema.clone(),
                _ => query_schema.clone(),
            };
            let mut described_shape = shape.clone();
            if operation == "revise" {
                for retained_shape in &query_shapes {
                    for rule in &retained_shape.non_expressible {
                        if !described_shape
                            .non_expressible
                            .iter()
                            .any(|r| r.rule == rule.rule && r.reason == rule.reason)
                        {
                            described_shape.non_expressible.push(rule.clone());
                        }
                    }
                }
            }
            let identity = if operation == "revise" {
                shape.revise_identity_description(&query_shapes)
            } else {
                shape.identity_description()
            };
            tools.push(TypedTool {
                name,
                description: described_shape.tool_description(
                    operation,
                    &relationship_description,
                    &identity,
                ),
                input_schema,
                shape: shape.clone(),
                operation: operation.into(),
            });
        }
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(tools)
}
fn validate_input(schema: &Value, input: &Value) -> Result<()> {
    let validator = jsonschema::validator_for(schema).map_err(|e| Error::engine(e.to_string()))?;
    validator
        .validate(input)
        .map_err(|e| Error::engine(format!("typed tool input: {e}")))
}
#[derive(Deserialize)]
struct RawFields<'a> {
    #[serde(borrow)]
    fields: &'a serde_json::value::RawValue,
}
fn raw_fields(raw: &str) -> Result<&str> {
    Ok(serde_json::from_str::<RawFields<'_>>(raw)?.fields.get())
}
/// Resolve descriptors anew; caller-supplied schemas/IR never confer authority.
/// Raw arguments retain duplicate-key/precision checks for structured fields.
pub async fn dispatch_typed_tool(
    db: &crate::db::Db,
    principal: &str,
    scope: Option<&str>,
    name: &str,
    raw: &str,
) -> Result<Value> {
    let tool = typed_tools_for(db, principal, scope)
        .await?
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| Error::engine("unknown typed tool"))?;
    let mut input: Value = serde_json::from_str(raw)?;
    let family = &tool.shape.pin.family;
    let kind = &tool.shape.kind;
    if tool.operation == "revise" {
        // Validate the fixed envelope before reading; fields are checked under the retained pin below.
        let mut envelope = tool.input_schema.clone();
        envelope["properties"]["fields"] = json!({"type":"object"});
        validate_input(&envelope, &input)?;
        let id = input["id"].as_str().unwrap().to_owned();
        let record = crate::kernel::read_record_as(db, principal, &id)
            .await?
            .ok_or_else(|| Error::engine(crate::kernel::HIDDEN_OR_MISSING))?;
        if record.family.as_deref() != Some(family) || record.kind.as_deref() != Some(kind) {
            return Err(Error::engine(
                "record does not belong to typed tool family and kind",
            ));
        }
        let pin = record
            .pin
            .as_ref()
            .ok_or_else(|| Error::engine("record carries no definition revision"))?;
        let retained = retained_shape(db, pin, kind).await?;
        if retained.structured() {
            input["fields"] = crate::structured_values::parse_json(raw_fields(raw)?)?;
        }
        validate_input(&retained.revise_schema(), &input)?;
        let expected = input["expected_revision"]
            .as_i64()
            .ok_or_else(|| Error::engine("expected_revision must fit i64"))?;
        crate::kernel::revise_json_as_expected(
            db,
            principal,
            &id,
            raw_fields(raw)?,
            Some(expected),
        )
        .await?;
        return Ok(
            json!({"id":id,"validated_pin":pin,"tool_pin":tool.shape.pin,"used_record_pin":pin!=&tool.shape.pin,
            "validation":"Validated against the record's own retained pin; no cross-version mapping."}),
        );
    }
    validate_input(&tool.input_schema, &input)?;
    if tool.operation == "create" && tool.shape.structured() {
        crate::structured_values::parse_json(raw_fields(raw)?)?;
    }
    if tool.operation == "create" {
        let home = input["home"].as_str().unwrap();
        // Recheck pin in the SAME write transaction as the existing kernel create path.
        let mut tx = crate::db::begin_write(db.write_pool()).await?;
        let effective = crate::kernel::resolve_effective_adoption(&mut tx, family, home).await?;
        if !matches!(effective,Some(crate::kernel::ScopedAdoption::Adopted(ref pin)) if pin==&tool.shape.pin)
        {
            return Err(Error::engine("typed tool adoption changed; refresh tools"));
        }
        let fields = raw_fields(raw)?;
        let id = crate::kernel::create_input_in(
            db,
            &mut tx,
            &mut crate::act::ActAllocation::new(),
            principal,
            family,
            kind,
            crate::kernel::FieldInput::Raw(fields),
            home,
        )
        .await?;
        tx.commit().await?;
        return Ok(json!({"id":id,"pin":tool.shape.pin}));
    }
    let eq: Vec<(&str, Value)> = input["field_equals"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    let linked = input.get("linked_to").map(|v| {
        (
            v["predicate"].as_str().unwrap(),
            v["id"].as_str().unwrap(),
            v["direction"].as_str().unwrap(),
        )
    });
    let limit = input
        .get("limit")
        .map(|v| {
            v.as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or_else(|| Error::engine("limit must fit usize"))
        })
        .transpose()?
        .unwrap_or(50);
    let page = crate::kernel::query_as(
        db,
        principal,
        family,
        kind,
        &eq,
        linked,
        limit,
        input["cursor"].as_str(),
    )
    .await?;
    let mut hits = vec![];
    for hit in page.hits {
        if let Some(record) = crate::kernel::read_record_as(db, principal, &hit.id).await? {
            hits.push(json!({"id":record.id,"fields":record.fields,"pin":record.pin,"revision":record.revision}));
        }
    }
    Ok(json!({"hits":hits,"cursor":page.cursor}))
}

#[cfg(test)]
mod tool_tests;
