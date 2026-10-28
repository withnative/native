//! Internal pure facet-default compiler. Inputs carry typed sealed provenance;
//! only the trusted resolver constructs production inputs. No emission or serving.
use super::cascade::{self, SchemaConfigRow};
use crate::named_views::v2;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const GENERATOR: &str = "native.declared-relational-defaults";
const INPUT_BYTES: usize = 256 * 1024;
const OUTPUT_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Vocabulary {
    pub(crate) id: String,
    pub(crate) reference: String,
    pub(crate) source: v2::Source,
    pub(crate) values: Vec<VocabularyValue>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VocabularyValue {
    pub(crate) source: v2::Source,
    pub(crate) id: String,
    pub(crate) value: String,
    pub(crate) status: String,
    pub(crate) alias_of: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "mode", content = "keys", rename_all = "snake_case")]
#[allow(dead_code)] // All is supported internally; no public generation selector yet.
pub(crate) enum Selection {
    Keys(BTreeSet<String>),
    All,
}
pub(crate) struct Input<'a> {
    pub(crate) workspace: &'a str,
    pub(crate) bearer: &'a str,
    pub(crate) source_identity: &'a str,
    pub(crate) record_type: &'a str,
    pub(crate) kind: Option<&'a str>,
    /// Exact logical direct home; not a security root or ancestor selector.
    pub(crate) home: &'a str,
    pub(crate) selection: Selection,
    pub(crate) schema: &'a [SchemaConfigRow],
    pub(crate) schema_sources: BTreeMap<String, v2::Source>,
    pub(crate) vocabularies: &'a [Vocabulary],
}
#[derive(Debug, Serialize)]
pub(crate) struct Proposal {
    pub(crate) manifest: v2::Manifest,
    pub(crate) manifest_sha256: String,
    pub(crate) name: String,
    pub(crate) sql: String,
    pub(crate) output: Value,
    pub(crate) columns: BTreeMap<String, Value>,
    pub(crate) relations: BTreeMap<String, Value>,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompileError {
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
pub(crate) fn size(value: &impl Serialize, max: usize) -> Result<usize> {
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

/// SQL literal map sorted by stored token. Resolve bounded canonical
/// alias chains; dangling/cyclic maps
/// refuse compilation rather than changing unknown values into plausible ones.
fn vocabulary_map(vocab: &Vocabulary) -> Result<Vec<(String, Option<String>)>> {
    token(&vocab.id)?;
    token(&vocab.reference)?;
    if vocab.values.len() > 64 {
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
        let mut target = item;
        let mut seen = BTreeSet::new();
        while let Some(alias) = &target.alias_of {
            if !seen.insert(&target.id) {
                return Err(CompileError::Invalid("cyclic vocabulary alias"));
            }
            target = ids
                .get(alias)
                .copied()
                .ok_or(CompileError::Invalid("dangling vocabulary alias"))?;
        }
        mapping.push((
            item.value.clone(),
            (item.status != "proposed" && target.status != "proposed")
                .then(|| target.value.clone()),
        ));
    }
    mapping.sort();
    Ok(mapping)
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
tokio::task_local! { static COMPILE_CALLS: std::cell::Cell<usize>; }
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn measured_compiles<T>(work: impl std::future::Future<Output = T>) -> (T, usize) {
    COMPILE_CALLS
        .scope(std::cell::Cell::new(0), async {
            let result = work.await;
            (result, COMPILE_CALLS.with(std::cell::Cell::get))
        })
        .await
}

pub(crate) fn compile(input: Input<'_>, deadline: Instant) -> Result<Proposal> {
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    let _ = COMPILE_CALLS.try_with(|n| n.set(n.get() + 1));
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
        if vocab.values.len() > 64 {
            return Err(CompileError::Budget("vocabulary"));
        }
        for item in &vocab.values {
            if item.value.len() > 512 || item.value.contains('\0') {
                return Err(CompileError::Invalid("vocabulary token"));
            }
        }
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
    let mut sources = Vec::new();
    let mut slots = Vec::new();
    let mut governance_basis = Vec::new();
    let mut source_indices = BTreeMap::new();
    for home in [None, Some(input.home)] {
        for shape_key in [Some(input.record_type), kind_key.as_deref()] {
            for layer in ["pack", "user"] {
                let mut fragments = Vec::new();
                if let Some(shape_key) = shape_key {
                    for row in rows.iter().filter(|r| {
                        r.layer == layer && r.applies_to_collection_id.as_deref() == home
                    }) {
                        let Some(shape) = row.data.get("shapes").and_then(|v| v.get(shape_key))
                        else {
                            continue;
                        };
                        if !shape.is_object() {
                            return Err(CompileError::Invalid("shape object"));
                        }
                        let empty = serde_json::Map::new();
                        let facets = match shape.get("facets") {
                            None => &empty,
                            Some(value) => value
                                .as_object()
                                .ok_or(CompileError::Invalid("facet map"))?,
                        };
                        let selected: Vec<_> = keys
                            .iter()
                            .filter_map(|k| facets.get(k).map(|v| (k, v)))
                            .collect();
                        if home.is_none() && selected.is_empty() {
                            continue;
                        }
                        let source = if let Some(i) = source_indices.get(&row.id) {
                            *i
                        } else {
                            let source = input
                                .schema_sources
                                .get(&row.id)
                                .ok_or(CompileError::Invalid("schema provenance missing"))?
                                .clone();
                            let i = sources.len();
                            sources.push(source);
                            source_indices.insert(row.id.clone(), i);
                            i
                        };
                        if home.is_some() {
                            governance_basis.push(v2::Governance {
                                source,
                                shape_key: shape_key.into(),
                                lineage: row.version_lineage.clone(),
                                created_at: row.created_at.clone(),
                            });
                        }
                        for (key, decl) in selected {
                            if !decl.is_object() {
                                return Err(CompileError::Invalid(
                                    "explicit declaration must be object",
                                ));
                            }
                            let decl = serde_json::from_value::<v2::Declaration>(decl.clone())
                                .map_err(|_| CompileError::Unsupported("closed declaration"))?;
                            fragments.push(v2::Fragment {
                                source,
                                key: key.clone(),
                                decl,
                                lineage: row.version_lineage.clone(),
                                created_at: row.created_at.clone(),
                            });
                        }
                    }
                }
                slots.push(v2::Slot {
                    scope: if home.is_some() {
                        v2::Scope::Home
                    } else {
                        v2::Scope::Global
                    },
                    layer: if layer == "pack" {
                        v2::Layer::Pack
                    } else {
                        v2::Layer::User
                    },
                    shape_key: shape_key.unwrap_or(input.record_type).into(),
                    fragments,
                });
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
    let mut output: Vec<Value> = shared.iter().map(|name|json!({"name":name,"type":if *name=="id"{"identifier"}else if ["archived","is_current"].contains(name){"boolean"}else{"text"},"nullable":!matches!(*name,"id"|"name"|"type")})).collect();
    let mut columns: BTreeMap<String,Value> = shared.iter().map(|name|(name.to_string(),json!({"meaning":format!("Shared caller-visible records.{name}; no implicit archive/currentness filter"),"source_mapping":format!("records.{name}"),"vocabulary":null,"unit":null,"encoding":null}))).collect();
    let mut projections: Vec<String> = shared
        .iter()
        .map(|s| {
            if ["archived", "is_current"].contains(s) {
                format!(
                    "CASE WHEN r.{s} = 1 THEN 1 WHEN r.{s} = 0 THEN 0 ELSE NULL END AS {}",
                    quoted(s)
                )
            } else {
                format!("r.{s} AS {}", quoted(s))
            }
        })
        .collect();
    let mut joins = Vec::new();
    let mut relations = BTreeSet::from(["records", "facet_values"]);
    for (position, key) in keys.iter().enumerate() {
        check(deadline)?;
        let mut normalized = effective[key].clone();
        if let Some(object) = normalized.as_object_mut() {
            object.retain(|_, v| !v.is_null());
        }
        let shape = &normalized;
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
            let status = format!("CASE WHEN {missing} THEN 'missing' WHEN NOT {guard} THEN 'invalid' WHEN ({usable}) IS NOT NULL THEN 'valid' ELSE 'unclassified' END");
            let source = intern(&mut sources, &vocab.source);
            let mut values: Vec<_> = vocab.values.iter().collect();
            values.sort_by(|a, b| a.id.cmp(&b.id));
            let values = values
                .into_iter()
                .map(|v| {
                    let mut target = v;
                    let mut seen = BTreeSet::new();
                    while let Some(id) = &target.alias_of {
                        if !seen.insert(&target.id) {
                            return Err(CompileError::Invalid("vocabulary cycle"));
                        }
                        target = vocab
                            .values
                            .iter()
                            .find(|v| &v.id == id)
                            .ok_or(CompileError::Invalid("vocabulary target"))?;
                    }
                    let source = intern(&mut sources, &v.source);
                    Ok(v2::VocabularyValue {
                        source,
                        id: v.id.clone(),
                        token: v.value.clone(),
                        status: serde_json::from_value(json!(v.status))
                            .map_err(|_| CompileError::Invalid("vocabulary status"))?,
                        alias_of: v.alias_of.clone(),
                        canonical_id: target.id.clone(),
                        canonical_token: target.value.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            selected_vocabularies.push(v2::Vocabulary {
                field: key.clone(),
                source,
                values,
            });
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
    let manifest = v2::Manifest {
        format: "native.generated-facets.v1".into(),
        workspace_id: input.workspace.into(),
        context: v2::Context {
            r#type: input.record_type.into(),
            kind: input.kind.map(str::to_owned),
            logical_home_id: input.home.into(),
        },
        selection: match input.selection {
            Selection::Keys(keys) => v2::Selection::Keys {
                keys: keys.into_iter().collect(),
            },
            Selection::All => v2::Selection::All,
        },
        sources,
        slots,
        governance_basis,
        vocabularies: selected_vocabularies,
    };
    manifest
        .validate()
        .map_err(|_| CompileError::Invalid("closed manifest"))?;
    let selector = selector(&manifest);
    let name = crate::named_views::contract::generated_name(
        input.workspace,
        GENERATOR,
        input.source_identity,
        &selector,
    );
    let sql = format!(
        "SELECT {}\nFROM records AS r\n{}\nWHERE r.type = {} AND {} AND r.home_id = {}\nORDER BY r.id",
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
        manifest_sha256: digest(
            &serde_json::to_value(&manifest).map_err(|_| CompileError::Invalid("manifest"))?,
        ),
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

pub(crate) fn selector(manifest: &v2::Manifest) -> String {
    String::from_utf8(canonical(
        &json!({"context":manifest.context,"selection":manifest.selection}),
    ))
    .expect("canonical JSON is UTF-8")
}

fn intern(sources: &mut Vec<v2::Source>, source: &v2::Source) -> usize {
    if let Some(i) = sources
        .iter()
        .position(|s| s.section == source.section && s.source_id == source.source_id)
    {
        return i;
    }
    let i = sources.len();
    sources.push(source.clone());
    i
}
