//! Provisional pure facet-default compiler. Test-only until the retained contract
//! is accepted: no database, authorization decision, event or public operation.
use super::cascade::{self, SchemaConfigRow};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const GENERATOR: &str = "native.declared-relational-defaults";
const VERSION: &str = "facet-spike-1";
const INPUT_BYTES: usize = 256 * 1024;
const OUTPUT_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vocabulary {
    id: String,
    reference: String,
    /// Opaque source revision/evidence, not a claim of present authorization.
    evidence: Value,
    required_anchors: Vec<String>,
    values: Vec<VocabularyValue>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VocabularyValue {
    id: String,
    value: String,
    status: String,
    alias_of: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "mode", content = "keys", rename_all = "snake_case")]
enum Selection {
    Keys(BTreeSet<String>),
    All,
}
struct Input<'a> {
    workspace: &'a str,
    bearer: &'a str,
    source_identity: &'a str,
    record_type: &'a str,
    kind: Option<&'a str>,
    /// Exact logical direct home; not a security root or ancestor selector.
    home: &'a str,
    selection: Selection,
    schema: &'a [SchemaConfigRow],
    vocabularies: &'a [Vocabulary],
}
#[derive(Debug, Serialize)]
struct Proposal {
    manifest: Value,
    manifest_sha256: String,
    name: String,
    sql: String,
    output: Value,
    columns: BTreeMap<String, Value>,
    relations: BTreeMap<String, Value>,
}
#[derive(Debug, PartialEq, Eq)]
enum CompileError {
    Budget(&'static str),
    Invalid(&'static str),
    Unsupported(&'static str),
    MissingDeclaration(String),
    Deadline,
}
type Result<T> = std::result::Result<T, CompileError>;

fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(CompileError::Deadline)
    } else {
        Ok(())
    }
}
/// Count serialization before allocating canonical input/output buffers. Input
/// JSON is already parsed; this is not a raw-ingress/parser memory guarantee.
fn size(value: &impl Serialize, max: usize) -> Result<usize> {
    struct Counter(usize, usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.1.saturating_sub(self.0) {
                return Err(std::io::Error::other("compiler byte budget"));
            }
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0, max);
    serde_json::to_writer(&mut count, value).map_err(|_| CompileError::Budget("bytes"))?;
    Ok(count.0)
}
fn structure(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    if depth > 16 || *nodes >= 8192 {
        return Err(CompileError::Budget("input structure"));
    }
    *nodes += 1;
    match value {
        Value::Object(map) => {
            for child in map.values() {
                structure(child, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                structure(child, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.contains('\0') => {
            return Err(CompileError::Invalid("NUL in source"))
        }
        Value::String(text) if text.len() > INPUT_BYTES => {
            return Err(CompileError::Budget("bytes"))
        }
        _ => {}
    }
    Ok(())
}
fn canonical(value: &Value) -> Vec<u8> {
    native_artifact_runtime::mdx_v2::canonical_json_bytes(value)
}
fn digest(value: &Value) -> String {
    format!("{:x}", Sha256::digest(canonical(value)))
}
fn literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn label(key: &str) -> String {
    if key.len() <= 100
        && key.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        key.to_owned()
    } else {
        format!("f_{}", digest(&json!(["facet", key])))
    }
}
fn token(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || value.contains('\0') {
        Err(CompileError::Invalid("identity/context"))
    } else {
        Ok(())
    }
}
fn declaration_vocab(shape: &Value) -> Result<Option<&str>> {
    let a = shape.get("vocab");
    let b = shape.get("vocab_ref");
    if a.is_some() && b.is_some() && a != b {
        return Err(CompileError::Invalid("conflicting vocabularies"));
    }
    a.or(b)
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty())
                .ok_or(CompileError::Invalid("vocabulary reference"))
        })
        .transpose()
}

/// SQL literal map sorted by stored token. Resolve only one-hop canonical
/// aliases, matching the supported vocabulary contract; dangling/cyclic maps
/// refuse compilation rather than changing unknown values into plausible ones.
fn vocabulary_map(vocab: &Vocabulary) -> Result<Vec<(String, Option<String>)>> {
    token(&vocab.id)?;
    token(&vocab.reference)?;
    if vocab.values.len() > 64 || vocab.required_anchors.len() > 8 {
        return Err(CompileError::Budget("vocabulary"));
    }
    let mut ids = BTreeMap::new();
    let mut tokens = BTreeSet::new();
    for item in &vocab.values {
        token(&item.id)?;
        if item.value.len() > 512
            || !tokens.insert(&item.value)
            || ids.insert(&item.id, item).is_some()
            || !["active", "proposed", "deprecated"].contains(&item.status.as_str())
        {
            return Err(CompileError::Invalid("vocabulary values"));
        }
    }
    let mut mapping = Vec::new();
    for item in &vocab.values {
        let target = if let Some(alias) = &item.alias_of {
            let target = ids
                .get(alias)
                .ok_or(CompileError::Invalid("dangling vocabulary alias"))?;
            if target.alias_of.is_some() || target.status != "active" {
                return Err(CompileError::Invalid("noncanonical vocabulary alias"));
            }
            *target
        } else {
            item
        };
        mapping.push((
            item.value.clone(),
            (item.status != "proposed").then(|| target.value.clone()),
        ));
    }
    mapping.sort();
    Ok(mapping)
}

fn compile(input: Input<'_>, deadline: Instant) -> Result<Proposal> {
    check(deadline)?;
    for id in [
        input.workspace,
        input.bearer,
        input.source_identity,
        input.record_type,
        input.home,
    ] {
        token(id)?;
    }
    if let Some(kind) = input.kind {
        token(kind)?;
    }
    if input.schema.len() > 128 || input.vocabularies.len() > 32 {
        return Err(CompileError::Budget("input rows"));
    }
    let mut remaining = INPUT_BYTES;
    let mut nodes = 0;
    let mut ids = BTreeSet::new();
    for row in input.schema {
        check(deadline)?;
        token(&row.id)?;
        if row.created_at.len() > 64
            || row.name.as_ref().is_some_and(|s| s.len() > 512)
            || row.version_lineage.as_ref().is_some_and(|s| s.len() > 512)
        {
            return Err(CompileError::Budget("schema metadata"));
        }
        structure(&row.data, 0, &mut nodes)?;
        remaining -= size(row, remaining)?;
        if !ids.insert(&row.id)
            || !["pack", "user"].contains(&row.layer.as_str())
            || !row.data.is_object()
            || row.data.get("shapes").is_some_and(|v| !v.is_object())
        {
            return Err(CompileError::Invalid("schema rows"));
        }
    }
    let mut vocabulary_rows = 0;
    for vocab in input.vocabularies {
        check(deadline)?;
        if vocab.values.len() > 64 || vocab.required_anchors.len() > 8 {
            return Err(CompileError::Budget("vocabulary"));
        }
        for item in &vocab.values {
            if item.value.len() > 512 || item.value.contains('\0') {
                return Err(CompileError::Invalid("vocabulary token"));
            }
        }
        structure(&vocab.evidence, 0, &mut nodes)?;
        remaining -= size(vocab, remaining)?;
        vocabulary_rows += vocab.values.len();
        if vocabulary_rows > 256 {
            return Err(CompileError::Budget("vocabulary rows"));
        }
    }
    // Sorting borrowed rows avoids caller fetch order becoming semantics.
    let mut rows: Vec<_> = input.schema.iter().collect();
    rows.sort_by(|a, b| {
        (a.layer != "pack", &a.created_at, &a.id).cmp(&(b.layer != "pack", &b.created_at, &b.id))
    });
    let rows: Vec<_> = rows.into_iter().cloned().collect();
    if !cascade::scope_supplies_shape(&rows, input.record_type, input.kind, input.home) {
        return Err(CompileError::Invalid("home has no governing declaration"));
    }
    let effective =
        cascade::facets_for_record_context(&rows, input.record_type, input.kind, Some(input.home));
    let keys = match &input.selection {
        Selection::Keys(keys) => keys.clone(),
        Selection::All => effective
            .keys()
            .filter(|key| !crate::schema::SPINE_FACET_KEYS.contains(&key.as_str()))
            .cloned()
            .collect(),
    };
    if keys.is_empty() || keys.len() > 18 {
        return Err(CompileError::Budget("selected columns"));
    }
    for key in &keys {
        token(key)?;
        if crate::schema::SPINE_FACET_KEYS.contains(&key.as_str())
            || !matches!(
                crate::domain_transaction::classify_facet_key(key),
                crate::domain_transaction::FacetKeyClassification::Open
            )
        {
            return Err(CompileError::Invalid("reserved/shared field"));
        }
        if !effective.contains_key(key) {
            return Err(CompileError::MissingDeclaration(key.clone()));
        }
    }
    let kind_key = input.kind.map(|k| format!("{}:{k}", input.record_type));
    // Each applicable slot includes explicit absence for every selected key.
    // Keep row IDs/lineage and only selected fragments, not unrelated row data.
    let mut evidence = Vec::new();
    let mut governance_basis = Vec::new();
    for row in &rows {
        if row
            .applies_to_collection_id
            .as_deref()
            .is_some_and(|home| home != input.home)
        {
            continue;
        }
        for shape_key in std::iter::once(input.record_type).chain(kind_key.as_deref()) {
            if let Some(shape) = row.data.get("shapes").and_then(|v| v.get(shape_key)) {
                if row.applies_to_collection_id.as_deref() == Some(input.home) && shape.is_object()
                {
                    governance_basis.push(json!({"id":row.id,"layer":row.layer,"home":row.applies_to_collection_id,
                        "lineage":row.version_lineage,"created_at":row.created_at,"shape_key":shape_key,
                        "context":{"type":input.record_type,"kind":input.kind,"logical_home":input.home}}));
                }
                let empty = serde_json::Map::new();
                let facets = match shape.get("facets") {
                    None => &empty,
                    Some(value) => value
                        .as_object()
                        .ok_or(CompileError::Invalid("facet map"))?,
                };
                let selected: BTreeMap<_, _> = keys
                    .iter()
                    .map(|key| (key.clone(), facets.get(key).cloned().unwrap_or(Value::Null)))
                    .collect();
                // Rows containing only unrelated keys cannot perturb selected-key output.
                if selected.values().any(|v| !v.is_null())
                    || matches!(input.selection, Selection::All)
                {
                    evidence.push(json!({"id":row.id,"layer":row.layer,"home":row.applies_to_collection_id,
                        "lineage":row.version_lineage,"created_at":row.created_at,"shape_key":shape_key,"selected":selected}));
                }
            }
        }
    }
    let mut selected_vocabularies = Vec::new();
    let shared = [
        "id",
        "name",
        "type",
        "kind",
        "home_id",
        "archived",
        "lifecycle",
        "is_current",
    ];
    let mut labels: BTreeSet<String> = shared.iter().map(|s| s.to_string()).collect();
    let mut output: Vec<Value> = shared.iter().map(|name|json!({"name":name,"type":if *name=="id"{"identifier"}else if ["archived","is_current"].contains(name){"integer"}else{"text"},"nullable":!matches!(*name,"id"|"name"|"type"|"archived")})).collect();
    let mut columns: BTreeMap<String,Value> = shared.iter().map(|name|(name.to_string(),json!({"meaning":format!("Shared caller-visible records.{name}; no implicit archive/currentness filter"),"source_mapping":format!("records.{name}"),"vocabulary":null,"unit":null,"encoding":null}))).collect();
    let mut projections: Vec<String> = shared
        .iter()
        .map(|s| format!("r.{s} AS {}", quoted(s)))
        .collect();
    let mut joins = Vec::new();
    let mut declarations = BTreeMap::new();
    let mut relations = BTreeSet::from(["records", "facet_values"]);
    for (position, key) in keys.iter().enumerate() {
        check(deadline)?;
        let shape = &effective[key];
        if !shape.is_object() || shape.get("required").is_some_and(|v| !v.is_boolean()) {
            return Err(CompileError::Invalid("field declaration"));
        }
        if [
            "values",
            "options",
            "json_schema",
            "temporal_order",
            "format",
            "text_format",
            "max_length",
        ]
        .iter()
        .any(|key| shape.get(*key).is_some())
        {
            return Err(CompileError::Unsupported("inline constraints"));
        }
        let kind = match shape.get("type") {
            None => "text",
            Some(Value::String(t)) => t.as_str(),
            _ => return Err(CompileError::Invalid("field type")),
        };
        if !["text", "number", "date"].contains(&kind) || shape.get("type") == Some(&json!("text"))
        {
            return Err(CompileError::Unsupported("field type"));
        }
        let prose = match shape.get("description") {
            None => format!("Declared facet {key}; domain meaning unspecified"),
            Some(Value::String(prose)) if prose.len() <= 256 => prose.clone(),
            _ => return Err(CompileError::Invalid("field description")),
        };
        let unit = match shape.get("unit") {
            None => None,
            Some(Value::String(unit)) if unit.len() <= 128 => Some(unit.as_str()),
            _ => return Err(CompileError::Invalid("field unit")),
        };
        let vocab_ref = declaration_vocab(shape)?;
        if vocab_ref.is_some() && kind != "text" {
            return Err(CompileError::Unsupported("typed vocabulary field"));
        }
        let name = label(key);
        for n in [
            name.clone(),
            format!("{name}__raw"),
            format!("{name}__status"),
        ] {
            if !labels.insert(n) {
                return Err(CompileError::Invalid("output label collision"));
            }
        }
        let alias = format!("f{position}");
        joins.push(format!(
            "LEFT JOIN facet_values AS {alias} ON {alias}.record_id = r.id AND {alias}.key = {}",
            literal(key)
        ));
        let raw = format!("{alias}.value");
        let missing = format!("{alias}.record_id IS NULL OR {raw} IS NULL");
        let (usable, status, encoding) = if let Some(reference) = vocab_ref {
            let found: Vec<_> = input
                .vocabularies
                .iter()
                .filter(|v| {
                    v.reference == reference
                        || v.id == crate::meta::vocabulary::resolve_vocab_ref(reference)
                })
                .collect();
            if found.len() != 1 {
                return Err(CompileError::Invalid("unresolved/ambiguous vocabulary"));
            }
            let vocab = found[0];
            let mapping = vocabulary_map(vocab)?;
            let refs = BTreeSet::from([
                vocab.reference.clone(),
                vocab.id.clone(),
                format!("rec:{}", vocab.id),
            ]);
            let guard = format!(
                "({alias}.vocab_ref IS NULL OR {alias}.vocab_ref IN ({}))",
                refs.iter()
                    .map(|r| literal(r))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let arms = mapping
                .iter()
                .map(|(raw, value)| {
                    format!(
                        "WHEN {} THEN {}",
                        literal(raw),
                        value.as_ref().map_or_else(|| "NULL".into(), |v| literal(v))
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            let usable = if arms.is_empty() {
                "NULL".to_string()
            } else {
                format!("CASE WHEN {guard} THEN CASE {raw} {arms} ELSE NULL END ELSE NULL END")
            };
            let status = format!("CASE WHEN {missing} THEN 'missing' WHEN ({usable}) IS NOT NULL THEN 'valid' ELSE 'invalid' END");
            let mut frozen = vocab.clone();
            frozen.values.sort_by(|a, b| a.id.cmp(&b.id));
            frozen.required_anchors.sort();
            frozen.required_anchors.dedup();
            selected_vocabularies.push(json!({"field":key,"source":frozen,"mapping":mapping}));
            (
                usable,
                status,
                "frozen canonical vocabulary token; deprecated membership retained in manifest",
            )
        } else if kind == "number" {
            (format!("{alias}.value_num"),format!("CASE WHEN {missing} THEN 'missing' WHEN {alias}.value_num IS NOT NULL THEN 'valid' ELSE 'unclassified' END"),"binary64 numeric projection; original carrier not inferred")
        } else if kind == "date" {
            relations.insert("facet_times");
            let time = format!("d{position}");
            joins.push(format!("LEFT JOIN facet_times AS {time} ON {time}.record_id = r.id AND {time}.key = {} AND {time}.kind = 'date' AND {time}.all_day = 1",literal(key)));
            (format!("CASE WHEN {raw} IS NOT NULL THEN {time}.start_date ELSE NULL END"),format!("CASE WHEN {missing} THEN 'missing' WHEN {time}.start_date IS NOT NULL THEN 'valid' ELSE 'unclassified' END"),"calendar date from existing typed facet_times; no inferred timestamp")
        } else {
            (
                raw.clone(),
                format!("CASE WHEN {missing} THEN 'missing' ELSE 'valid' END"),
                "raw stored text; original JSON type unspecified",
            )
        };
        declarations.insert(key.clone(), shape.clone());
        for (column, expression, ty, nullable, meaning) in [
            (
                name.clone(),
                usable,
                if kind == "number" { "real" } else { "text" },
                true,
                format!("{prose}; {encoding}"),
            ),
            (
                format!("{name}__raw"),
                raw,
                "text",
                true,
                "Lossless stored facet text, including invalid/unclassified values".into(),
            ),
            (
                format!("{name}__status"),
                status,
                "text",
                false,
                "missing/valid/invalid/unclassified; no inference of original historical carrier"
                    .into(),
            ),
        ] {
            projections.push(format!("{expression} AS {}", quoted(&column)));
            output.push(json!({"name":column,"type":ty,"nullable":nullable}));
            let is_value = column == name;
            let column_encoding = if is_value {
                encoding
            } else if column.ends_with("__raw") {
                "stored UTF-8 text; original JSON carrier unspecified"
            } else {
                "read-status/v1: missing, valid, invalid, unclassified"
            };
            let source_cell = if !is_value {
                "facet_values.value and generated assessment"
            } else if kind == "date" {
                "facet_times.start_date"
            } else if kind == "number" {
                "facet_values.value_num"
            } else {
                "facet_values.value with frozen interpretation"
            };
            columns.insert(
                column,
                json!({"meaning":meaning,"source_mapping":format!("{source_cell}; key {key}"),
                "vocabulary":if is_value {vocab_ref} else {None},
                "unit":if is_value {unit} else {None},"encoding":column_encoding}),
            );
        }
    }
    if projections.iter().map(String::len).sum::<usize>()
        + joins.iter().map(String::len).sum::<usize>()
        > super::sql_contract::MAX_SQL_BYTES - 1024
    {
        return Err(CompileError::Budget("SQL bytes"));
    }
    let manifest = json!({"provisional":true,"generator":GENERATOR,"version":VERSION,"workspace":input.workspace,"bearer":input.bearer,
        "source_identity":input.source_identity,"context":{"type":input.record_type,"kind":input.kind,"logical_home":input.home,"membership":"direct members; kind null means kindless"},
        "selection":input.selection,"declarations":declarations,"context_evidence":evidence,"governance_basis":governance_basis,"vocabularies":selected_vocabularies,
        "inclusion":"all visible matching records, including archived/superseded; no inferred defaults"});
    let name = format!(
        "view_gen_{}",
        digest(&json!([
            input.workspace,
            GENERATOR,
            input.source_identity,
            input.record_type,
            input.kind,
            input.home,
            input.selection
        ]))
    );
    let sql = format!(
        "SELECT {}\nFROM records AS r\n{}\nWHERE r.type = {} AND {} AND r.home_id = {}",
        projections.join(",\n       "),
        joins.join("\n"),
        literal(input.record_type),
        input.kind.map_or_else(
            || "r.kind IS NULL".into(),
            |k| format!("r.kind = {}", literal(k))
        ),
        literal(input.home)
    );
    if sql.len() > super::sql_contract::MAX_SQL_BYTES {
        return Err(CompileError::Budget("SQL bytes"));
    }
    let relations = relations
        .into_iter()
        .map(|name| {
            let source = super::sql_contract::LOGICAL_RELATIONS
                .iter()
                .find(|r| r.name == name)
                .expect("fixed compiler source");
            (
                name.into(),
                json!({"identity":source.identity,"semantic_version":source.semantic_version}),
            )
        })
        .collect();
    let proposal = Proposal {
        manifest_sha256: digest(&manifest),
        manifest,
        name,
        sql,
        output: json!({"columns":output,"schema_sha256":digest(&json!(output)),"row_identity":["id"],"order":[{"column":"id","direction":"asc"}]}),
        columns,
        relations,
    };
    size(&proposal, OUTPUT_BYTES)?;
    check(deadline)?;
    Ok(proposal)
}

#[cfg(test)]
mod tests;
