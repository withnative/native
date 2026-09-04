//! Graph-aware partial-success record creation.
//!
//! This module deliberately owns only batch-local concerns: caller refs,
//! dependency ordering, body-ref substitution, positional receipts and
//! dependency-failure propagation. Each admitted item is dispatched through
//! the ordinary `create_record` handler, so its authorization, validation,
//! provenance, projection and transaction boundaries remain authoritative.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use super::{lifecycle, parse_args, require_nonblank_reason, REASON_DESCRIPTION};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::interactions::ToolKind;
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::schema::contract::SPINE_TYPES;

const TOOL: &str = "create_many";
pub const MAX_CREATE_MANY: usize = 25;
const MAX_REF_LEN: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateManyArgs {
    reason: String,
    records: Vec<Map<String, Value>>,
    #[serde(default)]
    response_mode: ResponseMode,
}

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResponseMode {
    #[default]
    Summary,
    Verbose,
}

struct PreparedRecord {
    index: usize,
    local_ref: Option<String>,
    dependencies: BTreeSet<usize>,
    arguments: Value,
    materialized_body: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ItemState {
    Pending,
    Succeeded,
    Failed,
}

pub fn register_create_many_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::CreateMany,
        "Create up to 25 non-Message records as one dependency graph. Local refs support parent_ref, links[].target_ref, and [[ref]] body mentions. The graph is cycle-checked before writes; items then use create_record semantics in stable topological order. Failures block only dependants, and receipts preserve input positions with null ids for failures. Use response_mode=verbose for created record shapes.",
        json!({
            "type": "object",
            "properties": {
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION },
                "response_mode": { "type": "string", "enum": ["summary", "verbose"], "default": "summary" },
                "records": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_CREATE_MANY,
                    "items": {
                        "type": "object",
                        "properties": {
                            "ref": {
                                "type": "string",
                                "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,63}$",
                                "description": "Optional unique caller-local label for parent_ref, target_ref and [[ref]] references in this request."
                            },
                            "parent_ref": { "type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,63}$" },
                            "type": { "type": "string", "enum": SPINE_TYPES },
                            "id": {
                                "type": "string",
                                "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                            },
                            "kind": { "type": "string", "minLength": 1 },
                            "name": { "type": "string" },
                            "body": { "type": "string" },
                            "home_id": { "type": "string" },
                            "summary": { "type": "string" },
                            "lifecycle": { "type": "string" },
                            "owner_id": { "type": "string" },
                            "persistence": { "type": "string", "enum": ["enduring", "occurrent"] },
                            "maturity": { "type": "string" },
                            "facets": { "type": "object", "additionalProperties": true },
                            "links": {
                                "type": "array",
                                "items": {
                                    "oneOf": [
                                        {
                                            "type": "object",
                                            "properties": {
                                                "target_id": { "type": "string" },
                                                "relationship": { "type": "string" },
                                                "note": { "type": "string" }
                                            },
                                            "required": ["target_id", "relationship"],
                                            "additionalProperties": false
                                        },
                                        {
                                            "type": "object",
                                            "properties": {
                                                "target_ref": { "type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_-]{0,63}$" },
                                                "relationship": { "type": "string" },
                                                "note": { "type": "string" }
                                            },
                                            "required": ["target_ref", "relationship"],
                                            "additionalProperties": false
                                        }
                                    ]
                                }
                            },
                            "target": crate::mcp::tools::citations::target_schema()
                        },
                        "required": ["type", "kind"],
                        "additionalProperties": false,
                        "not": { "required": ["home_id", "parent_ref"] }
                    }
                }
            },
            "required": ["reason", "records"],
            "additionalProperties": false
        }),
        create_many,
    )
}

async fn create_many(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: CreateManyArgs = parse_args(TOOL, arguments)?;
    require_nonblank_reason(TOOL, &args.reason)?;
    if args.records.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: records must contain at least one item"
        )));
    }
    if args.records.len() > MAX_CREATE_MANY {
        return Err(Error::engine(format!(
            "{TOOL}: at most {MAX_CREATE_MANY} records may be created per call"
        )));
    }

    let prepared = preflight(args.records, &args.reason)?;
    let order = topological_order(&prepared)?;
    execute(db, caller, prepared, order, args.response_mode).await
}

fn preflight(records: Vec<Map<String, Value>>, reason: &str) -> Result<Vec<PreparedRecord>> {
    let mut ref_indexes = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        let Some(value) = record.get("ref") else {
            continue;
        };
        let local_ref = value.as_str().ok_or_else(|| {
            Error::engine(format!("{TOOL}: records[{index}].ref must be a string"))
        })?;
        validate_local_ref(index, "ref", local_ref)?;
        if let Some(previous) = ref_indexes.insert(local_ref.to_owned(), index) {
            return Err(Error::engine(format!(
                "{TOOL}: duplicate ref '{local_ref}' at records[{previous}] and records[{index}]"
            )));
        }
    }

    // Reserve every identity before materializing any edge. A referenced item
    // may appear later in request order. A malformed caller-supplied `id`
    // remains in that item's singular arguments so create_record rejects it;
    // the reserved fallback is used only internally and its dependants will be
    // suppressed after that item fails.
    let reserved_ids = records
        .iter()
        .map(|record| {
            record
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| Uuid::new_v4().to_string())
        })
        .collect::<Vec<_>>();

    let mut prepared = Vec::with_capacity(records.len());
    for (index, mut record) in records.into_iter().enumerate() {
        let local_ref = take_optional_string(&mut record, index, "ref")?;
        if !record.contains_key("id") {
            record.insert("id".into(), Value::String(reserved_ids[index].clone()));
        }
        record.insert("reason".into(), Value::String(reason.to_owned()));

        let mut dependencies = BTreeSet::new();
        if let Some(parent_ref) = take_optional_string(&mut record, index, "parent_ref")? {
            validate_local_ref(index, "parent_ref", &parent_ref)?;
            if record.contains_key("home_id") {
                return Err(Error::engine(format!(
                    "{TOOL}: records[{index}] may not supply both parent_ref and home_id"
                )));
            }
            let dependency = resolve_ref(&ref_indexes, index, "parent_ref", &parent_ref)?;
            dependencies.insert(dependency);
            record.insert(
                "home_id".into(),
                Value::String(reserved_ids[dependency].clone()),
            );
        }

        if let Some(links) = record.get_mut("links") {
            materialize_link_refs(links, index, &ref_indexes, &reserved_ids, &mut dependencies)?;
        }

        let materialized_body = match record.get("body").and_then(Value::as_str) {
            Some(body) => {
                let (body, body_dependencies) =
                    substitute_body_refs(body, &ref_indexes, &reserved_ids);
                dependencies.extend(body_dependencies);
                record.insert("body".into(), Value::String(body.clone()));
                Some(body)
            }
            None => None,
        };

        prepared.push(PreparedRecord {
            index,
            local_ref,
            dependencies,
            arguments: Value::Object(record),
            materialized_body,
        });
    }
    Ok(prepared)
}

fn validate_local_ref(index: usize, field: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_REF_LEN
        && value
            .bytes()
            .enumerate()
            .all(|(position, byte)| match byte {
                b'A'..=b'Z' | b'a'..=b'z' => true,
                b'0'..=b'9' | b'_' | b'-' => position > 0,
                _ => false,
            });
    if valid {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "{TOOL}: records[{index}].{field} must match [A-Za-z][A-Za-z0-9_-]{{0,63}}"
        )))
    }
}

fn take_optional_string(
    record: &mut Map<String, Value>,
    index: usize,
    field: &str,
) -> Result<Option<String>> {
    record
        .remove(field)
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                Error::engine(format!("{TOOL}: records[{index}].{field} must be a string"))
            })
        })
        .transpose()
}

fn resolve_ref(
    refs: &BTreeMap<String, usize>,
    index: usize,
    field: &str,
    value: &str,
) -> Result<usize> {
    refs.get(value).copied().ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: records[{index}].{field} refers to unknown local ref '{value}'"
        ))
    })
}

fn materialize_link_refs(
    links: &mut Value,
    record_index: usize,
    refs: &BTreeMap<String, usize>,
    reserved_ids: &[String],
    dependencies: &mut BTreeSet<usize>,
) -> Result<()> {
    let Some(links) = links.as_array_mut() else {
        return Ok(()); // The singular handler reports ordinary shape failures per item.
    };
    for (link_index, link) in links.iter_mut().enumerate() {
        let Some(link) = link.as_object_mut() else {
            continue;
        };
        let Some(target_ref) = link.remove("target_ref") else {
            continue;
        };
        let target_ref = target_ref.as_str().ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: records[{record_index}].links[{link_index}].target_ref must be a string"
            ))
        })?;
        validate_local_ref(record_index, "links[].target_ref", target_ref)?;
        if link.contains_key("target_id") {
            return Err(Error::engine(format!(
                "{TOOL}: records[{record_index}].links[{link_index}] may not supply both target_ref and target_id"
            )));
        }
        let dependency = resolve_ref(refs, record_index, "links[].target_ref", target_ref)?;
        dependencies.insert(dependency);
        link.insert(
            "target_id".into(),
            Value::String(reserved_ids[dependency].clone()),
        );
    }
    Ok(())
}

fn substitute_body_refs(
    body: &str,
    refs: &BTreeMap<String, usize>,
    reserved_ids: &[String],
) -> (String, BTreeSet<usize>) {
    let mut output = String::with_capacity(body.len());
    let mut dependencies = BTreeSet::new();
    let mut rest = body;
    while let Some(start) = rest.find("[[") {
        output.push_str(&rest[..start]);
        let candidate = &rest[start + 2..];
        let Some(end) = candidate.find("]]") else {
            output.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let local_ref = &candidate[..end];
        if let Some(dependency) = refs.get(local_ref).copied() {
            dependencies.insert(dependency);
            output.push_str("[[");
            output.push_str(&reserved_ids[dependency]);
            output.push_str("]]");
        } else {
            output.push_str("[[");
            output.push_str(local_ref);
            output.push_str("]]");
        }
        rest = &candidate[end + 2..];
    }
    output.push_str(rest);
    (output, dependencies)
}

fn topological_order(records: &[PreparedRecord]) -> Result<Vec<usize>> {
    let mut indegree = records
        .iter()
        .map(|record| record.dependencies.len())
        .collect::<Vec<_>>();
    let mut dependants = vec![Vec::new(); records.len()];
    for record in records {
        for dependency in &record.dependencies {
            dependants[*dependency].push(record.index);
        }
    }
    let mut ready = indegree
        .iter()
        .enumerate()
        .filter_map(|(index, degree)| (*degree == 0).then_some(index))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(records.len());
    while let Some(index) = ready.pop_first() {
        order.push(index);
        for dependant in &dependants[index] {
            indegree[*dependant] -= 1;
            if indegree[*dependant] == 0 {
                ready.insert(*dependant);
            }
        }
    }
    if order.len() == records.len() {
        return Ok(order);
    }
    let cycle = indegree
        .iter()
        .enumerate()
        .filter_map(|(index, degree)| (*degree > 0).then_some(index))
        .collect::<Vec<_>>();
    Err(Error::engine(format!(
        "{TOOL}: local-ref dependency cycle involves record indexes {cycle:?}; no records were written"
    )))
}

async fn execute(
    db: Db,
    caller: Caller,
    records: Vec<PreparedRecord>,
    order: Vec<usize>,
    response_mode: ResponseMode,
) -> Result<Value> {
    let mut states = vec![ItemState::Pending; records.len()];
    let mut ids = vec![Value::Null; records.len()];
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut body_digests = Vec::new();
    let mut verbose_results = Vec::new();

    for index in order {
        let record = &records[index];
        let failed_dependencies = record
            .dependencies
            .iter()
            .copied()
            .filter(|dependency| states[*dependency] == ItemState::Failed)
            .collect::<Vec<_>>();
        if !failed_dependencies.is_empty() {
            states[index] = ItemState::Failed;
            errors.push(item_error(
                record,
                "dependency_failed",
                format!("creation depends on failed record indexes {failed_dependencies:?}"),
                Some(failed_dependencies),
            ));
            continue;
        }
        if record.arguments.get("type").and_then(Value::as_str) == Some("Message") {
            states[index] = ItemState::Failed;
            errors.push(item_error(
                record,
                "unsupported_record_type",
                "Message creation is not supported by create_many; use create_record for a draft or manage_messages.send for delivery".into(),
                None,
            ));
            continue;
        }

        match lifecycle::create_record(db.clone(), caller.clone(), record.arguments.clone()).await {
            Ok(created) => {
                states[index] = ItemState::Succeeded;
                let id = created
                    .get("id")
                    .and_then(Value::as_str)
                    .expect("ordinary create_record success carries id")
                    .to_owned();
                ids[index] = Value::String(id.clone());
                if let Some(body) = &record.materialized_body {
                    if let Some(digest) = created.get("body_digest").and_then(Value::as_str) {
                        body_digests.push(json!({
                            "index": index,
                            "id": id,
                            "sha256": digest,
                            "chars": body.chars().count(),
                            "bytes": body.len(),
                        }));
                    }
                }
                for warning in created
                    .get("warnings")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let mut wrapped = match warning.as_object() {
                        Some(warning) => Value::Object(warning.clone()),
                        None => json!({"warning": warning}),
                    };
                    wrapped["index"] = json!(index);
                    if let Some(local_ref) = &record.local_ref {
                        wrapped["ref"] = json!(local_ref);
                    }
                    warnings.push(wrapped);
                }
                if response_mode == ResponseMode::Verbose {
                    verbose_results.push(json!({
                        "index": index,
                        "ref": record.local_ref,
                        "status": "created",
                        "record": created,
                    }));
                }
            }
            Err(error) => {
                states[index] = ItemState::Failed;
                errors.push(item_error(record, "create_failed", error.to_string(), None));
            }
        }
    }

    let mut result = json!({
        "ok": errors.is_empty(),
        "ids": ids,
    });
    errors.sort_by_key(|error| error["index"].as_u64().unwrap_or_default());
    warnings.sort_by_key(|warning| warning["index"].as_u64().unwrap_or_default());
    body_digests.sort_by_key(|digest| digest["index"].as_u64().unwrap_or_default());
    let object = result.as_object_mut().expect("create_many receipt object");
    if !errors.is_empty() {
        object.insert("errors".into(), Value::Array(errors));
    }
    if !warnings.is_empty() {
        object.insert("warnings".into(), Value::Array(warnings));
    }
    if !body_digests.is_empty() {
        object.insert("body_digests".into(), Value::Array(body_digests));
    }
    if response_mode == ResponseMode::Verbose {
        verbose_results.sort_by_key(|result| result["index"].as_u64().unwrap_or_default());
        object.insert("results".into(), Value::Array(verbose_results));
    }
    Ok(result)
}

fn item_error(
    record: &PreparedRecord,
    code: &str,
    message: String,
    dependency_indexes: Option<Vec<usize>>,
) -> Value {
    let mut error = json!({
        "index": record.index,
        "code": code,
        "message": message,
    });
    if let Some(local_ref) = &record.local_ref {
        error["ref"] = json!(local_ref);
    }
    if let Some(dependency_indexes) = dependency_indexes {
        error["dependency_indexes"] = json!(dependency_indexes);
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_refs_materialize_against_preassigned_ids_and_sort_stably() {
        let records = vec![
            json!({
                "ref":"child",
                "type":"Document",
                "kind":"note",
                "parent_ref":"folder",
                "body":"See [[folder]]",
                "links":[{"target_ref":"folder","relationship":"relates_to"}]
            })
            .as_object()
            .unwrap()
            .clone(),
            json!({
                "ref":"folder",
                "type":"Collection",
                "kind":"folder"
            })
            .as_object()
            .unwrap()
            .clone(),
        ];
        let prepared = preflight(records, "test graph").unwrap();
        let folder_id = prepared[1].arguments["id"].as_str().unwrap();
        assert_eq!(prepared[0].arguments["home_id"], folder_id);
        assert_eq!(prepared[0].arguments["links"][0]["target_id"], folder_id);
        assert_eq!(
            prepared[0].arguments["body"],
            format!("See [[{folder_id}]]")
        );
        assert_eq!(topological_order(&prepared).unwrap(), vec![1, 0]);
    }

    #[test]
    fn body_ref_cycles_are_rejected_before_execution() {
        let records = vec![
            json!({"ref":"a","type":"Document","kind":"note","body":"[[b]]"})
                .as_object()
                .unwrap()
                .clone(),
            json!({"ref":"b","type":"Document","kind":"note","body":"[[a]]"})
                .as_object()
                .unwrap()
                .clone(),
        ];
        let prepared = preflight(records, "test graph").unwrap();
        let error = topological_order(&prepared).unwrap_err().to_string();
        assert!(error.contains("dependency cycle"));
        assert!(error.contains("[0, 1]"));
    }

    #[test]
    fn unknown_wiki_refs_remain_literal_and_create_no_dependency() {
        let refs = BTreeMap::new();
        let (body, dependencies) = substitute_body_refs("Keep [[external]]", &refs, &[]);
        assert_eq!(body, "Keep [[external]]");
        assert!(dependencies.is_empty());
    }
}
