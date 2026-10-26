//! KernelV2 MDX rendering from an activated, exact imported source closure.
//! Inputs requiring a v1 collection resolver refuse until their native
//! equivalent is available; no custody JSON is executable on this path.
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) mod html_board;

use super::parse;
use crate::{authorization::Capability, db::Db, kernel, Error, Result};
use native_artifact_runtime::{mdx, mdx_v2};

#[derive(Clone, Copy)]
struct InputLimits {
    records: usize,
    bytes: usize,
}
impl InputLimits {
    const MDX: Self = Self {
        records: mdx_v2::MAX_INPUT_RECORDS,
        bytes: mdx_v2::MAX_INPUT_JSON_BYTES,
    };
    const HTML: Self = Self {
        records: crate::artifact_html::INPUT_RECORD_LIMIT,
        bytes: crate::artifact_html::INPUT_JSON_LIMIT,
    };
}

// Test-only rendezvous after input capture, before off-thread compilation.
#[cfg(test)]
tokio::task_local! {
    pub(crate) static RENDER_PAUSE: (std::sync::Arc<tokio::sync::Notify>, std::sync::Arc<tokio::sync::Notify>);
    pub(crate) static GOVERNED_QUERY_PAUSE: std::sync::Arc<tokio::sync::Barrier>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(alias = "record_id")]
    id: String,
    #[serde(default)]
    as_of: Option<Value>,
    #[serde(default)]
    parent_origin: Option<String>,
    #[serde(default)]
    include_timing: bool,
    #[serde(default)]
    revalidate: Option<Value>,
}

fn refusal(id: &str, code: &str, message: &str) -> Value {
    json!({
        "status":"error",
        "diagnostic": {
            "code":code,
            "message":message,
            "details":{"artifact_id":id,"runtime":mdx_v2::RUNTIME_ID}
        }
    })
}

fn source_field<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine(format!("render_artifact: activated {key} is invalid")))
}

pub(super) async fn collection_kind_on(
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<String>> {
    let Some(record) = kernel::read_record_on(tx, actor, id).await? else {
        return Ok(None);
    };
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let (record_type, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|pin| pin.version),
        primary.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    Ok(
        (!kernel::hq::tombstoned_on(tx, id).await? && record_type == Some("Collection"))
            .then(|| kind.map(str::to_owned))
            .flatten(),
    )
}

async fn authorized_schema_on(
    tx: &mut SqliteConnection,
    actor: &str,
) -> Result<Vec<crate::query::cascade::SchemaConfigRow>> {
    let mut schema = Vec::new();
    for row in kernel::v1_state::rows_on(tx, "schema_config").await? {
        let anchor = row["applies_to_collection_id"].as_str().map(str::to_owned);
        if let Some(anchor) = &anchor {
            let target = if anchor == "native:root" {
                crate::events::KERNEL_ROOT_ID
            } else {
                anchor.as_str()
            };
            if !kernel::kernel_effective_capability_on(tx, actor, target)
                .await?
                .allows(Capability::View)
            {
                continue;
            }
        }
        let value = |key| -> Result<String> { Ok(source_field(&row, key)?.to_owned()) };
        schema.push(crate::query::cascade::SchemaConfigRow {
            id: value("id")?,
            layer: value("layer")?,
            name: row["name"].as_str().map(str::to_owned),
            data: serde_json::from_str(&value("data")?)?,
            applies_to_collection_id: anchor,
            version_lineage: row["version_lineage"].as_str().map(str::to_owned),
            created_at: value("created_at")?,
        });
    }
    Ok(schema)
}

async fn input_record_on(
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
    schema: &[crate::query::cascade::SchemaConfigRow],
    interpreter: &crate::query::lifecycle::LifecycleInterpreter,
    include_archived: bool,
) -> Result<Option<Value>> {
    let Some(record) = kernel::read_record_on(tx, actor, id).await? else {
        return Ok(None);
    };
    if (!include_archived && record.archived) || kernel::hq::tombstoned_on(tx, id).await? {
        return Ok(None);
    }
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let (record_type, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|pin| pin.version),
        primary.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    let record_type = record_type.unwrap_or_default();
    let home = kernel::v1_state::lifecycle_bearer_on(tx, &record.home_id, Some(id)).await?;
    let lifecycle: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='lifecycle'")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .or_else(|| {
                record
                    .fields
                    .get("lifecycle")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
    let interpretation = serde_json::to_value(interpreter.interpret(
        record_type,
        kind,
        Some(&home),
        lifecycle.as_deref(),
    ))?;
    let shapes =
        crate::query::cascade::facets_for_record_context(schema, record_type, kind, Some(&home));
    let facets: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT key,value FROM kernel_facets WHERE record_id=? AND key!='archived' ORDER BY key",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let mut mapped = serde_json::Map::new();
    for (key, value) in facets {
        let mut cell = value.map_or(Value::Null, Value::String);
        if let Some(shape) = shapes.get(&key) {
            match shape["type"].as_str() {
                Some("number" | "object") if cell.is_string() => {
                    let decoded: Value = serde_json::from_str(cell.as_str().unwrap_or_default())?;
                    if (shape["type"] == "number" && !decoded.is_number())
                        || (shape["type"] == "object" && !decoded.is_object())
                    {
                        return Err(Error::engine("render_artifact: non-canonical typed facet"));
                    }
                    cell = decoded;
                }
                _ => {}
            }
        }
        mapped.insert(key, cell);
    }
    Ok(Some(json!({
        "id":id,"type":record_type,"kind":kind,
        "name":record.fields.get("title").or_else(|| record.fields.get("name")).and_then(Value::as_str).unwrap_or(""),
        "summary":record.fields.get("summary").and_then(Value::as_str),
        "lifecycle_interpretation":interpretation,
        "maturity":record.metadata.maturity,
        "persistence":record.metadata.persistence,
        "facets":mapped,
    })))
}

// Candidate discovery is not authority: input_record_on retains its caller
// View gate. An imported record-local policy deliberately
// puts the child in a different physical home from its logical folder.
async fn folder_member_ids_on(tx: &mut SqliteConnection, folder: &str) -> Result<Vec<String>> {
    let candidates: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT r.id,r.home_id FROM main.kernel_records r WHERE r.home_id IN (
 SELECT record_id FROM main.content_events WHERE type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id')=?1
 UNION SELECT ?1 UNION SELECT ?2)
 UNION SELECT r.id,r.home_id FROM main.kernel_legacy_sql_events p
 JOIN main.kernel_records r ON r.id=p.record_id
 JOIN main.content_events e ON e.seq=p.seq WHERE p.source_stream='snapshot_provenance'
 AND json_extract(e.payload,'$.legacy.payload.original_home')=?1
 UNION SELECT r.id,r.home_id FROM main.content_events move
 JOIN main.kernel_records r ON r.id=move.record_id WHERE move.type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2')
 AND json_extract(move.payload,'$.logical_home_id')=?1 ORDER BY 1"#,
    )
    .bind(folder)
    .bind(kernel::hq::v1_import_home_id(folder))
    .fetch_all(&mut *tx)
    .await?;
    let mut ids = Vec::new();
    for (id, home) in candidates {
        // Semantic membership uses the same logical home fold as the saved
        // filter below. Public home disclosure has a separate View check on
        // the parent; it must not determine semantic membership.
        if kernel::v1_state::lifecycle_bearer_on(tx, &home, Some(&id)).await? == folder {
            ids.push(id);
        }
    }
    Ok(ids)
}

async fn collection_records_on(
    tx: &mut SqliteConnection,
    actor: &str,
    collection_id: &str,
    kind: &str,
    schema: &[crate::query::cascade::SchemaConfigRow],
    interpreter: &crate::query::lifecycle::LifecycleInterpreter,
    limits: InputLimits,
) -> Result<Vec<Value>> {
    if kind == "query" {
        return saved_record_query_on(tx, actor, collection_id, schema, interpreter, limits).await;
    }
    let ids: Vec<String> = match kind {
        "folder" => folder_member_ids_on(tx, collection_id).await?,
        "selection" => {
            // V1 filters the selection seed with default include_archived=false
            // before traversing member_of. An archived input is valid, but its
            // selection traversal consequently yields no member rows.
            if kernel::hq::archived_on(tx, collection_id).await? {
                return Ok(Vec::new());
            }
            sqlx::query_scalar("SELECT DISTINCT source_id FROM kernel_generic_links WHERE target_id=? AND relationship='member_of' AND active=1 ORDER BY source_id")
                .bind(collection_id)
                .fetch_all(&mut *tx)
                .await?
        }
        _ => {
            return Err(Error::engine(
                "render_artifact: unsupported Collection kind",
            ))
        }
    };
    let mut records = Vec::new();
    for id in ids {
        if let Some(record) = input_record_on(tx, actor, &id, schema, interpreter, false).await? {
            if record["type"] == "Annotation"
                && hidden_input_kind(record["kind"].as_str()).is_some()
            {
                continue;
            }
            records.push(record);
            if records.len() > limits.records {
                return Err(Error::engine(
                    "render_artifact: named input exceeds record limit",
                ));
            }
        }
    }
    records.sort_by(|left, right| {
        left["name"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .cmp(&right["name"].as_str().unwrap_or("").to_lowercase())
            .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
    });
    Ok(records)
}

fn hidden_input_kind(kind: Option<&str>) -> Option<&'static str> {
    use crate::generated::kinds::CoreKind;
    [
        CoreKind::AnnotationComment,
        CoreKind::AnnotationCitation,
        CoreKind::AnnotationSuggestion,
    ]
    .into_iter()
    .find(|hidden| kind == Some(hidden.token()) || kind == Some(hidden.value_id()))
    .map(CoreKind::token)
}

fn filter_values(step: &Value, key: &str, actual: Option<&str>) -> Result<bool> {
    let Some(values) = step.get(key) else {
        return Ok(true);
    };
    let values = values
        .as_array()
        .ok_or_else(|| Error::engine("render_artifact: invalid saved query filter"))?;
    Ok(values.is_empty()
        || actual.is_some_and(|actual| {
            values.iter().any(|value| {
                value.as_str() == Some(actual)
                    || (key == "kinds"
                        && hidden_input_kind(Some(actual))
                            .is_some_and(|kind| hidden_input_kind(value.as_str()) == Some(kind)))
            })
        }))
}

async fn saved_filter_on(
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
    step: &Value,
    hidden_optins: &BTreeSet<&str>,
) -> Result<bool> {
    let keys = step
        .as_object()
        .ok_or_else(|| Error::engine("render_artifact: invalid saved query step"))?;
    if step["step"] != "filter"
        || keys.keys().any(|key| {
            ![
                "step",
                "home_id",
                "ids",
                "types",
                "kinds",
                "lifecycle",
                "include_archived",
                "facets",
            ]
            .contains(&key.as_str())
        })
    {
        return Err(Error::engine(
            "render_artifact: saved query filter unsupported",
        ));
    }
    if !filter_values(step, "ids", Some(id))? {
        return Ok(false);
    }
    // Filter metadata after the same View gate as read_record_on, without
    // hydrating bodies, owner disclosure or unused fields for every candidate.
    type FilterRow = (
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
    );
    let row: Option<FilterRow> = sqlx::query_as("SELECT home_id,primary_type,pin_family,pin_version,pin_digest,kind FROM kernel_records WHERE id=?")
        .bind(id).fetch_optional(&mut *tx).await?;
    let Some((home_id, primary, family, version, digest, kind)) = row else {
        return Ok(false);
    };
    if !kernel::kernel_effective_capability_on(tx, actor, id)
        .await?
        .allows(Capability::View)
        || (kernel::hq::archived_on(tx, id).await? && step["include_archived"] != true)
        || kernel::hq::tombstoned_on(tx, id).await?
    {
        return Ok(false);
    }
    let values: Vec<(String,String)> = sqlx::query_as("SELECT name,value_json FROM kernel_record_fields WHERE record_id=? AND name IN ('v1_type','v1_kind','lifecycle')")
        .bind(id).fetch_all(&mut *tx).await?;
    let mut fields = serde_json::Map::new();
    for (name, value) in values {
        fields.insert(name, serde_json::from_str(&value)?);
    }
    let pinned = family.is_some() && version.is_some() && digest.is_some();
    let (record_type, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        family.as_deref().filter(|_| pinned),
        version
            .filter(|_| pinned)
            .map(|v| u32::try_from(v).unwrap_or(0)),
        primary.as_deref(),
        kind.as_deref(),
        &fields,
    );
    if record_type == Some("Annotation")
        && hidden_input_kind(kind).is_some_and(|kind| !hidden_optins.contains(kind))
    {
        return Ok(false);
    }
    if let Some(filters) = step.get("facets") {
        for filter in filters
            .as_array()
            .ok_or_else(|| Error::engine("render_artifact: invalid saved facet filter"))?
        {
            let object = filter
                .as_object()
                .ok_or_else(|| Error::engine("render_artifact: invalid saved facet filter"))?;
            let key = filter["key"]
                .as_str()
                .ok_or_else(|| Error::engine("render_artifact: invalid saved facet key"))?;
            if object
                .keys()
                .any(|k| !["key", "value", "eq", "ne", "in"].contains(&k.as_str()))
            {
                return Err(Error::engine(
                    "render_artifact: saved facet operator unsupported",
                ));
            }
            let cell: Option<(String, Option<f64>)> = sqlx::query_as("SELECT value,value_num FROM kernel_facets WHERE record_id=? AND key=? AND value IS NOT NULL")
                .bind(id).bind(key).fetch_optional(&mut *tx).await?;
            let Some((cell, number)) = cell else {
                return Ok(false);
            };
            if let Some(expected) = filter
                .get("eq")
                .or_else(|| filter.get("value"))
                .filter(|v| !v.is_null())
            {
                if expected.as_str() != Some(cell.as_str()) {
                    return Ok(false);
                }
            }
            if filter
                .get("ne")
                .is_some_and(|v| v.as_str() == Some(cell.as_str()))
            {
                return Ok(false);
            }
            if let Some(values) = filter.get("in") {
                let values = values.as_array().ok_or_else(|| {
                    Error::engine("render_artifact: invalid saved facet membership")
                })?;
                if !values.iter().any(|v| match v {
                    Value::String(value) => value == &cell,
                    Value::Number(value) => {
                        value.as_f64().is_some_and(|value| number == Some(value))
                    }
                    _ => false,
                }) {
                    return Ok(false);
                }
            }
        }
    }
    let lifecycle: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='lifecycle'")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .or_else(|| {
                fields
                    .get("lifecycle")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
    let home_matches = if let Some(required) = step["home_id"].as_str() {
        required == kernel::v1_state::lifecycle_bearer_on(tx, &home_id, Some(id)).await?
    } else {
        true
    };
    Ok(home_matches
        && filter_values(step, "types", record_type)?
        && filter_values(step, "kinds", kind)?
        && filter_values(step, "lifecycle", lifecycle.as_deref())?)
}

async fn saved_record_query_on(
    tx: &mut SqliteConnection,
    actor: &str,
    collection_id: &str,
    schema: &[crate::query::cascade::SchemaConfigRow],
    interpreter: &crate::query::lifecycle::LifecycleInterpreter,
    limits: InputLimits,
) -> Result<Vec<Value>> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='query'")
            .bind(collection_id)
            .fetch_optional(&mut *tx)
            .await?;
    let query = match crate::mcp::tools::querying::inspect_saved_record_query(raw.as_deref()) {
        crate::mcp::tools::querying::SavedQueryInspection::Valid { query, .. } => query,
        _ => {
            return Err(Error::engine(
                "render_artifact: saved record query unavailable",
            ))
        }
    };
    let order = query["order"].as_str().unwrap_or("updated_desc");
    if ![
        "name_asc",
        "updated_desc",
        "created_desc",
        "last_activity_desc",
    ]
    .contains(&order)
    {
        return Err(Error::engine(
            "render_artifact: saved query order unsupported",
        ));
    }
    let steps = query["steps"]
        .as_array()
        .ok_or_else(|| Error::engine("render_artifact: saved query steps missing"))?;
    if !matches!(steps.len(), 1 | 3) || steps[0]["step"] != "filter" {
        return Err(Error::engine(
            "render_artifact: saved query pipeline unsupported",
        ));
    }
    let hidden_optins: BTreeSet<&str> = steps
        .iter()
        .filter_map(|step| step.get("kinds").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|kind| hidden_input_kind(Some(kind)))
        .collect();
    let mut ids: Vec<String> = if let Some(home) = steps[0]["home_id"].as_str() {
        folder_member_ids_on(tx, home).await?
    } else if let Some(only) = steps[0]["ids"].as_array().filter(|ids| !ids.is_empty()) {
        only.iter()
            .map(|id| {
                id.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Error::engine("render_artifact: invalid saved query id"))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let mut candidates =
            sqlx::QueryBuilder::<sqlx::Sqlite>::new("SELECT r.id FROM kernel_records r WHERE 1");
        let carrier = crate::v2_standard::v1_compat::FAMILY;
        let record_type = format!("CASE WHEN r.pin_family='{carrier}' AND r.pin_version=1 THEN (SELECT json_extract(t.value_json,'$') FROM kernel_record_fields t WHERE t.record_id=r.id AND t.name='v1_type') ELSE r.primary_type END");
        let lifecycle = "coalesce((SELECT f.value FROM kernel_facets f WHERE f.record_id=r.id AND f.key='lifecycle'),(SELECT json_extract(f.value_json,'$') FROM kernel_record_fields f WHERE f.record_id=r.id AND f.name='lifecycle'))";
        for (key, expression) in [("types", record_type.as_str()), ("lifecycle", lifecycle)] {
            if let Some(values) = steps[0][key].as_array().filter(|v| !v.is_empty()) {
                candidates
                    .push(" AND (")
                    .push(expression)
                    .push(") IN (SELECT value FROM json_each(")
                    .push_bind(serde_json::to_string(values)?)
                    .push("))");
            }
        }
        if let Some(kinds) = steps[0]["kinds"].as_array().filter(|v| !v.is_empty()) {
            use crate::generated::kinds::CoreKind;
            let mut kinds = kinds.clone();
            for hidden in [
                CoreKind::AnnotationComment,
                CoreKind::AnnotationCitation,
                CoreKind::AnnotationSuggestion,
            ] {
                if kinds
                    .iter()
                    .any(|v| hidden_input_kind(v.as_str()) == Some(hidden.token()))
                {
                    kinds.extend([json!(hidden.token()), json!(hidden.value_id())]);
                }
            }
            candidates.push(format!(" AND (CASE WHEN r.pin_family='{carrier}' AND r.pin_version=1 THEN (SELECT json_extract(k.value_json,'$') FROM kernel_record_fields k WHERE k.record_id=r.id AND k.name='v1_kind') ELSE r.kind END) IN (SELECT value FROM json_each("))
                .push_bind(serde_json::to_string(&kinds)?).push("))");
        }
        if let Some(filters) = steps[0]["facets"].as_array() {
            for filter in filters {
                if let Some(object) = filter
                    .as_object()
                    .filter(|o| {
                        o.keys()
                            .all(|k| ["key", "value", "eq", "ne", "in"].contains(&k.as_str()))
                    })
                    .filter(|o| o.get("in").is_none_or(Value::is_array))
                    .filter(|o| o.get("key").is_some_and(Value::is_string))
                {
                    let key = object["key"].as_str().expect("checked filter key");
                    candidates.push(" AND EXISTS(SELECT 1 FROM kernel_facets f WHERE f.record_id=r.id AND f.key=")
                        .push_bind(key.to_owned()).push(" AND f.value IS NOT NULL");
                    if let Some(expected) = object
                        .get("eq")
                        .or_else(|| object.get("value"))
                        .filter(|v| !v.is_null())
                    {
                        if let Some(text) = expected.as_str() {
                            candidates.push(" AND f.value=").push_bind(text.to_owned());
                        } else {
                            // The complete filter below compares eq/value as text.
                            candidates.push(" AND 0");
                        }
                    }
                    if let Some(text) = object.get("ne").and_then(Value::as_str) {
                        candidates.push(" AND f.value!=").push_bind(text.to_owned());
                    }
                    if let Some(values) = object.get("in").and_then(Value::as_array) {
                        candidates.push(" AND (0");
                        for value in values {
                            if let Some(text) = value.as_str() {
                                candidates.push(" OR f.value=").push_bind(text.to_owned());
                            } else if let Some(number) = value.as_f64() {
                                candidates.push(" OR f.value_num=").push_bind(number);
                            }
                        }
                        candidates.push(")");
                    }
                    candidates.push(")");
                }
            }
        }
        // Internal candidates only. Full filters, current visibility and input
        // hydration still run below; no body is loaded for an unrelated type
        // or a record lacking a required facet.
        candidates.push(" ORDER BY r.id");
        candidates.build_query_scalar().fetch_all(&mut *tx).await?
    };
    let mut filtered = Vec::new();
    for id in ids.drain(..) {
        if saved_filter_on(tx, actor, &id, &steps[0], &hidden_optins).await? {
            filtered.push(id);
        }
    }
    if steps.len() == 3 {
        let traverse = &steps[1];
        if traverse["step"] != "traverse"
            || traverse["target"] != "links"
            || !matches!(traverse["direction"].as_str(), Some("out" | "in"))
        {
            return Err(Error::engine(
                "render_artifact: saved traversal unsupported",
            ));
        }
        let relationship = traverse["relationship"]
            .as_str()
            .ok_or_else(|| Error::engine("render_artifact: traversal relation missing"))?;
        let mut traversed = BTreeMap::<String, ()>::new();
        for id in filtered {
            let incoming = traverse["direction"] == "in";
            let (anchor, target) = if incoming {
                ("target_id", "source_id")
            } else {
                ("source_id", "target_id")
            };
            let sql = format!("SELECT {target} FROM (SELECT source_id,target_id,relationship FROM kernel_generic_links WHERE active=1 UNION SELECT source_id,target_id,relationship FROM kernel_links UNION SELECT source_id,target_id,predicate AS relationship FROM kernel_link4_edges) WHERE {anchor}=? AND relationship=?");
            for next in sqlx::query_scalar::<_, String>(&sql)
                .bind(&id)
                .bind(relationship)
                .fetch_all(&mut *tx)
                .await?
            {
                traversed.insert(next, ());
            }
            if relationship == "relates_to" {
                let providers: Vec<(String,String)> = sqlx::query_as("SELECT p.state_json,p.subjects_json FROM kernel_provider_state p WHERE p.provider_key='relates_to.v1' AND p.id IN (SELECT aggregate_id FROM kernel_provider_subjects WHERE subject_id=?)")
                    .bind(&id).fetch_all(&mut *tx).await?;
                for (state, subjects) in providers {
                    let subjects: Vec<String> = serde_json::from_str(&subjects)?;
                    let mut visible = subjects.len() == 2 && subjects.contains(&id);
                    for subject in &subjects {
                        visible &= kernel::kernel_effective_capability_on(tx, actor, subject)
                            .await?
                            .allows(Capability::View);
                    }
                    if !visible {
                        continue;
                    }
                    for state in kernel::relates_to_port::active_states_from_states(&[state])? {
                        if subjects != vec![state.left.clone(), state.right.clone()] {
                            return Err(Error::engine(
                                "render_artifact: provider subjects changed",
                            ));
                        }
                        for assertion in state.assertions.iter().filter(|a| !a.retracted) {
                            if assertion.sources.is_empty() {
                                let other = if state.left == id {
                                    &state.right
                                } else {
                                    &state.left
                                };
                                traversed.insert(other.clone(), ());
                            } else {
                                for source in &assertion.sources {
                                    let (from, to) = if incoming {
                                        (&source.to, &source.from)
                                    } else {
                                        (&source.from, &source.to)
                                    };
                                    if from == &id {
                                        traversed.insert(to.clone(), ());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        filtered = Vec::new();
        for id in traversed.into_keys() {
            if saved_filter_on(tx, actor, &id, &steps[2], &hidden_optins).await? {
                filtered.push(id);
            }
        }
    }
    let all_matching: Option<String> = sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='input_membership' AND value IS NOT NULL")
        .bind(collection_id).fetch_optional(&mut *tx).await?;
    let unpaged = all_matching.as_deref() == Some("all_matching")
        && query.get("limit").is_none()
        && query.get("offset").is_none();
    let (offset, limit) = if unpaged {
        (0, None)
    } else {
        let (offset, limit) = saved_query_window(&query)?;
        filtered = order_saved_query_candidates_on(tx, filtered, &query, order).await?;
        (offset, Some(limit))
    };
    let mut records = Vec::new();
    let mut skipped = 0;
    for id in filtered {
        if let Some(record) = input_record_on(
            tx,
            actor,
            &id,
            schema,
            interpreter,
            steps
                .last()
                .is_some_and(|step| step["include_archived"] == true),
        )
        .await?
        {
            // Only successfully hydrated records consume offset/limit. Keep
            // reading until the page is full, without hydrating later pages.
            if skipped < offset {
                skipped += 1;
                continue;
            }
            records.push(record);
            if limit.is_some_and(|limit| records.len() == limit) {
                break;
            }
            if records.len() > limits.records {
                return Err(Error::engine(
                    "render_artifact: named input exceeds record limit",
                ));
            }
        }
    }
    records.sort_by(|left, right| {
        left["name"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .cmp(&right["name"].as_str().unwrap_or("").to_lowercase())
            .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
    });
    if records.len() > limits.records {
        return Err(Error::engine(
            "render_artifact: named input exceeds record limit",
        ));
    }
    Ok(records)
}

#[derive(sqlx::FromRow)]
struct InputOrderRow {
    id: String,
    name: String,
    created_at: String,
    updated_at: String,
    last_activity_at: String,
    number: Option<f64>,
    text: Option<String>,
}

async fn order_saved_query_candidates_on(
    tx: &mut SqliteConnection,
    ids: Vec<String>,
    query: &Value,
    order: &str,
) -> Result<Vec<String>> {
    use crate::query::pipeline::{self, FacetOrderDirection, FacetSortValue};
    let facet = query.get("facet_order").filter(|v| !v.is_null());
    let key = facet.and_then(|f| f["key"].as_str());
    let direction = if facet.is_some_and(|f| f["direction"] == "desc") {
        FacetOrderDirection::Desc
    } else {
        FacetOrderDirection::Asc
    };
    let rows: Vec<InputOrderRow> = sqlx::query_as(r#"SELECT r.id,
 coalesce((SELECT json_extract(f.value_json,'$') FROM kernel_record_fields f WHERE f.record_id=r.id AND f.name='title'),(SELECT json_extract(f.value_json,'$') FROM kernel_record_fields f WHERE f.record_id=r.id AND f.name='name'),'') AS name,
 coalesce((SELECT m.created_at FROM kernel_legacy_sql_events m WHERE m.record_id=r.id AND m.source_stream='snapshot_provenance' ORDER BY m.seq DESC LIMIT 1),r.created_at) AS created_at,
 coalesce((SELECT e.created_at FROM main.content_events e WHERE e.record_id=r.id ORDER BY e.seq DESC LIMIT 1),r.created_at) AS updated_at,
 coalesce(m.last_activity_at,r.created_at) AS last_activity_at,f.value_num AS number,f.value AS text
 FROM kernel_records r LEFT JOIN kernel_record_metadata m ON m.record_id=r.id
 LEFT JOIN kernel_facets f ON f.record_id=r.id AND f.key=?2
 WHERE r.id IN (SELECT value FROM json_each(?1))"#)
        .bind(serde_json::to_string(&ids)?).bind(key).fetch_all(&mut *tx).await?;
    let mut rows: Vec<_> = rows
        .into_iter()
        .map(|row| {
            let value = facet.and_then(|f| {
                if f["lane"] == "number" {
                    row.number.map(FacetSortValue::Number)
                } else {
                    row.text.clone().map(FacetSortValue::Text)
                }
            });
            (row, value)
        })
        .collect();
    rows.sort_by(|(a, av), (b, bv)| {
        let primary = if facet.is_some() {
            pipeline::compare_facet_values(av.as_ref(), bv.as_ref(), direction)
        } else {
            std::cmp::Ordering::Equal
        };
        primary
            .then_with(|| match order {
                "created_desc" => b.created_at.cmp(&a.created_at),
                "last_activity_desc" => b.last_activity_at.cmp(&a.last_activity_at),
                "name_asc" => a.name.cmp(&b.name),
                _ => b.updated_at.cmp(&a.updated_at),
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(rows.into_iter().map(|(row, _)| row.id).collect())
}

fn saved_query_window(query: &Value) -> Result<(usize, usize)> {
    use crate::query::pipeline;
    let defaults = pipeline::PipelineOptions::default();
    if query["limit"].as_i64().is_some_and(|limit| limit <= 0)
        || query["offset"].as_i64().is_some_and(|offset| offset < 0)
    {
        return Err(Error::engine("render_artifact: saved query window invalid"));
    }
    let offset = query["offset"].as_u64().unwrap_or(0) as usize;
    let limit = query["limit"]
        .as_i64()
        .unwrap_or(defaults.limit)
        .min(pipeline::MAX_LIMIT) as usize;
    Ok((offset, limit))
}

pub(super) struct BoundInput {
    runtime_input: Value,
    root_inputs: serde_json::Map<String, Value>,
    port_names: Vec<String>,
    pub(super) records_by_port: BTreeMap<String, BTreeSet<String>>,
    pub(super) collections_by_port: BTreeMap<String, String>,
}

pub(super) async fn facet_token_on(
    tx: &mut SqliteConnection,
    record_id: &str,
    facet: &str,
) -> Result<String> {
    if facet == "lifecycle" {
        let seq: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?")
                .bind(record_id)
                .fetch_one(&mut *tx)
                .await?;
        return Ok(format!("rec:{seq}"));
    }
    let seq: Option<i64> =
        sqlx::query_scalar("SELECT event_seq FROM kernel_facets WHERE record_id=? AND key=?")
            .bind(record_id)
            .bind(facet)
            .fetch_optional(&mut *tx)
            .await?;
    Ok(format!("obs:{}", seq.unwrap_or(0)))
}

pub(super) fn facet_entry_port(entry: &mdx_v2::InteractionEntry) -> Option<Option<&str>> {
    if !matches!(
        entry.effect,
        mdx_v2::InteractionEffect::FacetSet | mdx_v2::InteractionEffect::FacetUnset
    ) || entry.facet.is_empty()
        || (crate::schema::ENGINE_RESERVED_FACET_KEYS.contains(&entry.facet.as_str())
            && !(entry.facet == "lifecycle" && entry.effect == mdx_v2::InteractionEffect::FacetSet))
    {
        return None;
    }
    if entry.effect == mdx_v2::InteractionEffect::FacetSet {
        let supported = match entry.value.as_ref()? {
            mdx_v2::ValueSource::Literal { value } => value.is_string(),
            mdx_v2::ValueSource::Slot { slot } => entry.slots.get(slot).is_some_and(|declared| {
                matches!(&declared.domain, mdx_v2::SlotDomain::Values { values }
                    if values.iter().all(Value::is_string))
            }),
        };
        if !supported {
            return None;
        }
    }
    entry.slots.values().find_map(|slot| match &slot.domain {
        mdx_v2::SlotDomain::BoundInput { port } => Some(port.as_deref()),
        mdx_v2::SlotDomain::Values { .. } => None,
    })
}

fn declared_html_entry_port(entry: &mdx_v2::InteractionEntry) -> Option<&str> {
    if entry.slots.len() != 1 {
        return None;
    }
    match &entry.slots.values().next()?.domain {
        mdx_v2::SlotDomain::BoundInput { port: Some(port) }
            if !port.is_empty() && port != "default" =>
        {
            Some(port)
        }
        _ => None,
    }
}

async fn interaction_plan_on(
    tx: &mut SqliteConnection,
    actor: &str,
    interactions: &[mdx_v2::InteractionEntry],
    bound: &BoundInput,
    html: bool,
) -> Result<(BTreeMap<String, BTreeMap<String, String>>, Value)> {
    let mut supported = Vec::new();
    let mut records_by_port = BTreeMap::<String, BTreeSet<String>>::new();
    let mut create_destinations = BTreeMap::<String, String>::new();
    for entry in interactions {
        if html
            && matches!(
                entry.effect,
                mdx_v2::InteractionEffect::BodySet | mdx_v2::InteractionEffect::TitleSet
            )
        {
            // Same provisional named-cohort hint as v1. It grants no write:
            // invocation still requires a live personal-install guard, its
            // consented SQL target, current binding, Edit and CAS.
            if let Some(port) = declared_html_entry_port(entry) {
                if let Some(records) = bound.records_by_port.get(port) {
                    records_by_port.insert(port.to_owned(), records.clone());
                    supported.push(entry.id.clone());
                }
            }
            continue;
        }
        if entry.effect == mdx_v2::InteractionEffect::RecordCreate {
            let Some(create) = entry.create.as_ref().filter(|create| {
                crate::mcp::tools::artifacts::record_create_is_render_supported(create)
            }) else {
                continue;
            };
            let destination = match &create.destination {
                mdx_v2::RecordCreateDestination::Literal { record_id } => record_id.clone(),
                mdx_v2::RecordCreateDestination::BoundInput { port } => {
                    let Some(id) = bound.collections_by_port.get(port) else {
                        continue;
                    };
                    id.clone()
                }
            };
            if artifacts_destination_available(tx, actor, &destination).await? {
                let references = std::iter::once(&create.shape.record_type)
                    .chain(std::iter::once(&create.shape.kind))
                    .chain(create.shape.fields.values())
                    .chain(create.shape.facets.values())
                    .filter_map(|declaration| declaration.domain.bound_input_port())
                    .collect::<BTreeSet<_>>();
                if references.iter().all(|port| {
                    bound
                        .records_by_port
                        .get(*port)
                        .is_some_and(|records| !records.is_empty())
                }) {
                    for port in references {
                        records_by_port
                            .insert(port.to_owned(), bound.records_by_port[port].clone());
                    }
                    create_destinations.insert(entry.id.clone(), destination);
                    supported.push(entry.id.clone());
                }
            }
            continue;
        }
        let Some(port) = facet_entry_port(entry) else {
            continue;
        };
        match port {
            Some(port) if bound.records_by_port.contains_key(port) => {
                records_by_port.insert(port.to_owned(), bound.records_by_port[port].clone());
                supported.push(entry.id.clone());
            }
            None if !bound.records_by_port.is_empty() => {
                records_by_port.extend(bound.records_by_port.clone());
                supported.push(entry.id.clone());
            }
            _ => {}
        }
    }
    let mut editable = BTreeSet::new();
    let mut observed = BTreeMap::<String, BTreeMap<String, String>>::new();
    for (port, records) in &records_by_port {
        for record_id in records {
            if kernel::kernel_effective_capability_on(tx, actor, record_id)
                .await?
                .allows(Capability::Edit)
            {
                editable.insert(record_id.clone());
            }
            for entry in interactions {
                if html
                    && entry.effect == mdx_v2::InteractionEffect::TitleSet
                    && declared_html_entry_port(entry) == Some(port.as_str())
                {
                    observed.entry(record_id.clone()).or_default().insert(
                        "title".into(),
                        facet_token_on(tx, record_id, "lifecycle").await?,
                    );
                }
                if facet_entry_port(entry)
                    .is_some_and(|declared| declared.is_none_or(|declared| declared == port))
                {
                    let token = facet_token_on(tx, record_id, &entry.facet).await?;
                    observed
                        .entry(record_id.clone())
                        .or_default()
                        .insert(entry.facet.clone(), token);
                }
            }
        }
    }
    Ok((
        observed,
        json!({
            "supported_entries":supported,
            "editable_records":editable,
            "records_by_port":records_by_port,
            "create_destinations":create_destinations,
        }),
    ))
}

pub(super) async fn artifacts_destination_available(
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<bool> {
    Ok(
        collection_kind_on(tx, actor, id).await?.as_deref() == Some("folder")
            && !kernel::hq::archived_on(tx, id).await?
            && kernel::kernel_effective_capability_on(tx, actor, id)
                .await?
                .allows(Capability::Edit),
    )
}

fn quoted_sql_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[allow(clippy::too_many_arguments)]
async fn governed_sql_input(
    db: &Db,
    tx: &mut SqliteConnection,
    actor: &str,
    collection_id: &str,
    binding_seq: i64,
    declaration: &mdx_v2::InputDecl,
    _snapshot_seq: i64,
    limits: InputLimits,
) -> Result<Value> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='query'")
            .bind(collection_id)
            .fetch_optional(&mut *tx)
            .await?;
    let (definition, pinned) =
        match crate::mcp::tools::querying::inspect_saved_query(raw.as_deref()) {
            crate::mcp::tools::querying::SavedQueryInspection::GovernedSql { definition } => {
                (definition, None)
            }
            crate::mcp::tools::querying::SavedQueryInspection::GovernedSqlPinned { definition } => {
                definition.validate_current()?;
                (definition.static_shape(), Some(definition))
            }
            _ => return Err(Error::engine("render_artifact: governed query unavailable")),
        };
    if declaration.schema_sha256.as_deref() != Some(&definition.output.schema_sha256)
        || (!declaration.relations.is_empty()
            && (declaration.relations.len() != definition.relations.len()
                || declaration.relations.iter().any(|(name, pin)| {
                    definition.relations.get(name).is_none_or(|current| {
                        current.identity != pin.identity
                            || current.semantic_version != pin.semantic_version
                    })
                })))
    {
        return Err(Error::engine("render_artifact: governed query pin changed"));
    }
    let order = definition
        .output
        .order
        .iter()
        .map(|item| {
            format!(
                "{} {}",
                quoted_sql_identifier(&item.column),
                match item.direction {
                    crate::mcp::tools::querying::SavedSqlDirection::Asc => "ASC",
                    crate::mcp::tools::querying::SavedSqlDirection::Desc => "DESC",
                }
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let statement = format!(
        "SELECT * FROM ({}) AS saved_governed_projection ORDER BY {order} LIMIT {}",
        definition.sql,
        definition.bounds.rows.saturating_add(1)
    );
    #[cfg(test)]
    if let Ok(barrier) = GOVERNED_QUERY_PAUSE.try_with(Clone::clone) {
        barrier.wait().await;
    }
    let response = if let Some(pinned) = &pinned {
        super::query_pinned_saved_sql(db, actor, pinned).await?
    } else {
        super::sql::query_stored_saved_sql(
            db,
            actor,
            json!({"sql":statement,"parameters":definition.parameters}),
        )
        .await?
    };
    let columns = response["columns"]
        .as_array()
        .ok_or_else(|| Error::engine("render_artifact: governed columns missing"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::engine("render_artifact: governed column invalid"))
        })
        .collect::<Result<Vec<_>>>()?;
    let rows = response["rows"]
        .as_array()
        .cloned()
        .ok_or_else(|| Error::engine("render_artifact: governed rows missing"))?;
    let observed_seq = response["as_of_seq"]
        .as_i64()
        .ok_or_else(|| Error::engine("render_artifact: governed snapshot missing"))?;
    if !response["assumed_order"].is_null() {
        return Err(Error::engine(
            "render_artifact: governed order was not explicit",
        ));
    }
    let mut result = crate::query::sql_contract::QuerySqlResult {
        columns,
        row_count: rows.len(),
        rows,
        truncated: response["truncated"]
            .as_bool()
            .ok_or_else(|| Error::engine("render_artifact: governed truncation missing"))?,
        truncation_hint: response["truncation_hint"].as_str().map(str::to_owned),
        as_of_seq: observed_seq,
        now_ms_ms: response["now_ms_ms"].as_i64(),
        time_dependent: response["time_dependent"]
            .as_bool()
            .ok_or_else(|| Error::engine("render_artifact: governed clock missing"))?,
        assumed_order: None,
    };
    // The public relation receipt must not reveal a private global event head.
    result.as_of_seq = 0;
    let mut boundary = Sha256::new();
    boundary.update(actor.as_bytes());
    boundary.update(b"kernel-v2-governed-sql");
    let observation = crate::query::sql::GovernedSqlObservation {
        observed_at: chrono::Utc::now().to_rfc3339(),
        content_event_seq: None,
        lifecycle_event_seq: None,
        authorization_boundary: format!("kernel-v2.{:x}", boundary.finalize()),
        transient_watermark: None,
        transient_available: false,
    };
    let mut execution = crate::mcp::tools::querying::finish_saved_sql(
        &definition,
        &definition.parameters,
        "kernel-v2",
        observation,
        result,
    )?;
    // Imported relations have no public replay endpoint on v2 yet.
    execution["receipt"]["replayable"] = json!(false);
    if let Some(pinned) = pinned.as_ref().filter(|p| !p.roots().is_empty()) {
        let provenance = json!({"roots":response["view_provenance"]["roots"],"closure_digest":response["view_provenance"]["closure_digest"]});
        let query_sha256 = mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&json!([
            "native.saved-sql.v1.2",
            pinned
        ])));
        let snapshot = mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&json!([
            "native.pinned-sql-snapshot.v1",
            execution["receipt"]["snapshot"],
            query_sha256,
            provenance
        ])));
        execution["receipt"]["snapshot"] = json!(format!("native.snapshot.v1.{snapshot}"));
        execution["receipt"]["view_provenance"] = provenance;
        execution["receipt"]["query_sha256"] = json!(query_sha256);
        execution["receipt"]["relations"]=Value::Array(response["view_provenance"]["static_relations"].as_object().ok_or_else(||Error::engine("pinned SQL static provenance unavailable"))?.iter().map(|(name,pin)|json!({"name":name,"identity":pin["identity"],"semantic_version":pin["semantic_version"]})).collect());
    }
    let rows = execution["rows"].clone();
    let row_bytes = mdx_v2::canonical_json_bytes(&rows);
    if rows
        .as_array()
        .is_none_or(|rows| rows.len() > limits.records)
        || row_bytes.len() > limits.bytes
    {
        return Err(Error::engine(
            "render_artifact: governed input exceeds size limit",
        ));
    }
    let receipt = &execution["receipt"];
    let count = rows.as_array().map_or(0, Vec::len);
    let mut envelope = json!({
        "version":mdx_v2::RELATION_ENVELOPE,
        "source":{
            "kind":"collection","id":collection_id,"collection_kind":"query",
            "binding_revision":{"kind":"binding_event_seq","value":binding_seq},
            "content_revision":{"kind":"opaque_snapshot","token":receipt["snapshot"]},
            "execution_receipt":{
                "version":"native.governed-sql-port-receipt.v1",
                "observed_at":receipt["observed_at"],
                "row_count":receipt["row_count"],
                "truncated":receipt["truncated"],
                "completeness":receipt["completeness"],
                "replayable":false,
                "observation_window_hours":receipt["observation_window_hours"],
                "catalog_revision":receipt["catalog_revision"],
                "relations":receipt["relations"],
                "degraded_sources":receipt["degraded_sources"]
            }
        },
        "relation":{
            "grain":"governed_sql","key":definition.output.row_identity,
            "columns":definition.output.columns,
            "schema_sha256":definition.output.schema_sha256,
            "extent":{
                "complete":receipt["truncated"] == false,
                "returned":count,
                "total":if receipt["truncated"] == false {json!(count)} else {Value::Null},
                "truncated":receipt["truncated"],
                "source_completeness":receipt["completeness"]
            },
            "rows":rows,"rows_sha256":mdx::sha256_hex(&row_bytes)
        }
    });
    if execution["receipt"]["view_provenance"].is_object() {
        envelope["source"]["execution_receipt"]["version"] =
            json!("native.governed-sql-port-receipt.v2");
        envelope["source"]["execution_receipt"]["view_provenance"] =
            execution["receipt"]["view_provenance"].clone();
        envelope["source"]["execution_receipt"]["query_sha256"] =
            execution["receipt"]["query_sha256"].clone();
    }
    Ok(envelope)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn bound_inputs_on(
    db: &Db,
    tx: &mut SqliteConnection,
    actor: &str,
    artifact_id: &str,
    source_event_id: &str,
    manifest: &mdx_v2::ArtifactManifest,
    bindings: &[Value],
    grants: &[Value],
    snapshot_event_id: &str,
    snapshot_seq: i64,
) -> Result<BoundInput> {
    // The caller has already verified this runtime against the frozen source.
    // Sharing the resolver must not impose MDX's lower limits on HTML.
    let runtime: Option<String> = sqlx::query_scalar(
        "SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime' AND value IS NOT NULL",
    )
    .bind(artifact_id)
    .fetch_optional(&mut *tx)
    .await?;
    let limits = if runtime.as_deref() == Some(crate::artifact_html::RUNTIME_ID) {
        InputLimits::HTML
    } else {
        InputLimits::MDX
    };
    let schema = authorized_schema_on(tx, actor).await?;
    let interpreter = kernel::v1_state::interpreter_on(tx, actor).await?;
    let mut named = BTreeMap::<String, Value>::new();
    for binding in bindings {
        let port = source_field(binding, "port_name")?;
        let collection_id = source_field(binding, "collection_id")?;
        let binding_seq = binding["event_seq"]
            .as_i64()
            .ok_or_else(|| Error::engine("render_artifact: invalid binding event"))?;
        let declaration = manifest
            .inputs
            .get(port)
            .ok_or_else(|| Error::engine("render_artifact: activated undeclared input binding"))?;
        let kind = collection_kind_on(tx, actor, collection_id)
            .await?
            .ok_or_else(|| Error::engine("render_artifact: bound Collection unavailable"))?;
        if !matches!(kind.as_str(), "folder" | "selection" | "query") {
            return Err(Error::engine(
                "render_artifact: bound Collection kind unsupported on this deployment",
            ));
        }
        if declaration.schema_sha256.is_some() {
            if kind != "query" || declaration.envelope != mdx_v2::RELATION_ENVELOPE {
                return Err(Error::engine(
                    "render_artifact: governed input kind changed",
                ));
            }
            let envelope = governed_sql_input(
                db,
                tx,
                actor,
                collection_id,
                binding_seq,
                declaration,
                snapshot_seq,
                limits,
            )
            .await?;
            if named.insert(port.to_owned(), envelope).is_some() {
                return Err(Error::engine("render_artifact: duplicate activated input"));
            }
            continue;
        }
        let rows = collection_records_on(
            tx,
            actor,
            collection_id,
            &kind,
            &schema,
            &interpreter,
            limits,
        )
        .await?;
        let rows_value = Value::Array(rows);
        if declaration.envelope == mdx_v2::GROUPED_COUNT_ENVELOPE {
            let Some(mdx_v2::InputProjection::GroupedCount { axis }) =
                declaration.projection.as_ref()
            else {
                return Err(Error::engine(
                    "render_artifact: grouped-count projection missing",
                ));
            };
            // Aggregate the already caller-filtered records using v1's exact
            // axis validation, bounds, null bucket, ordering and digest.
            // V1 limits the aggregate envelope, not its unaggregated JSON.
            let records = serde_json::from_value::<Vec<crate::mcp::tools::artifacts::InputRecord>>(
                rows_value,
            )?;
            let envelope = crate::mcp::tools::artifacts::grouped_count_envelope(
                collection_id,
                &kind,
                binding_seq,
                axis,
                &records,
            )?;
            if named.insert(port.to_owned(), envelope).is_some() {
                return Err(Error::engine("render_artifact: duplicate activated input"));
            }
            continue;
        }
        let bytes = mdx_v2::canonical_json_bytes(&rows_value);
        if bytes.len() > limits.bytes {
            return Err(Error::engine(
                "render_artifact: named input exceeds byte limit",
            ));
        }
        let digest = mdx::sha256_hex(&bytes);
        let envelope = match declaration.envelope.as_str() {
            mdx_v2::COLLECTION_ENVELOPE => json!({
                "version":mdx_v2::COLLECTION_ENVELOPE,
                "collection":{"id":collection_id,"kind":kind},
                "projection":{"binding_event_seq":binding_seq},
                "records":rows_value,"records_sha256":digest,
            }),
            mdx_v2::RELATION_ENVELOPE if declaration.schema_sha256.is_none() => json!({
                "version":mdx_v2::RELATION_ENVELOPE,
                "source":{
                    "kind":"collection","id":collection_id,"collection_kind":kind,
                    "binding_revision":{"kind":"binding_event_seq","value":binding_seq},
                    "content_revision":{"kind":"content_event_seq","id":snapshot_event_id,"value":snapshot_seq},
                },
                "relation":{
                    "grain":"record","key":["id"],
                    "row_schema":mdx_v2::ARTIFACT_RECORD_SCHEMA,
                    "extent":{"complete":true,"returned":rows_value.as_array().map_or(0,Vec::len),"total":rows_value.as_array().map_or(0,Vec::len)},
                    "rows":rows_value,"rows_sha256":digest,
                },
            }),
            _ => {
                return Err(Error::engine(
                    "render_artifact: input envelope unsupported on this deployment",
                ))
            }
        };
        if named.insert(port.to_owned(), envelope).is_some() {
            return Err(Error::engine("render_artifact: duplicate activated input"));
        }
    }
    for (port, declaration) in &manifest.inputs {
        if declaration.required && !named.contains_key(port) {
            return Err(Error::engine("render_artifact: required input missing"));
        }
    }
    let mut root_inputs = serde_json::Map::new();
    for request in &manifest.capability_requests {
        let scope = if request.capability == "input.read" {
            let port = request.scope["port"]
                .as_str()
                .ok_or_else(|| Error::engine("render_artifact: invalid input.read scope"))?;
            let declaration = manifest
                .inputs
                .get(port)
                .filter(|decl| decl.expose_to_root)
                .ok_or_else(|| Error::engine("render_artifact: input is not root-readable"))?;
            let _ = declaration;
            json!({"artifact_port":port})
        } else {
            request.scope.clone()
        };
        let scope_sha = mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&scope));
        let granted = grants.iter().any(|grant| {
            grant["subject_kind"] == "artifact_source"
                && grant["subject_record_id"] == artifact_id
                && grant["subject_event_id"] == source_event_id
                && grant["capability"] == request.capability
                && grant["scope_sha256"] == scope_sha
                && grant["scope"].as_str().is_some_and(|raw| {
                    serde_json::from_str::<Value>(raw).ok().as_ref() == Some(&scope)
                })
        });
        if !granted {
            return Err(Error::engine(
                "render_artifact: exact source capability grant missing",
            ));
        }
        if request.capability == "input.read" {
            let port = request.scope["port"].as_str().unwrap_or_default();
            root_inputs.insert(
                port.to_owned(),
                named
                    .get(port)
                    .cloned()
                    .ok_or_else(|| Error::engine("render_artifact: root input missing"))?,
            );
        }
    }
    let mut records = BTreeMap::<String, Value>::new();
    let mut records_by_port = BTreeMap::<String, BTreeSet<String>>::new();
    let mut collections_by_port = BTreeMap::<String, String>::new();
    for (port, envelope) in &root_inputs {
        let mut ids = BTreeSet::new();
        if let Some(id) = envelope["collection"]["id"]
            .as_str()
            .or_else(|| envelope.pointer("/source/id").and_then(Value::as_str))
        {
            collections_by_port.insert(port.clone(), id.to_owned());
        }
        if let Some(rows) = envelope["records"]
            .as_array()
            .or_else(|| envelope.pointer("/relation/rows").and_then(Value::as_array))
        {
            for row in rows {
                if let Some(id) = row["id"].as_str() {
                    ids.insert(id.to_owned());
                    records.insert(id.to_owned(), row.clone());
                }
            }
        }
        records_by_port.insert(port.clone(), ids);
    }
    Ok(BoundInput {
        runtime_input: json!({
            "version":mdx_v2::NAMED_INPUT_ABI,"mode":"named",
            "inputs":root_inputs,"records":records.into_values().collect::<Vec<_>>()
        }),
        root_inputs,
        port_names: manifest.inputs.keys().cloned().collect(),
        records_by_port,
        collections_by_port,
    })
}

// Query receipts carry observation times and opaque snapshot tokens. Neither
// changes the values read by the artifact. Compare the rows, schema, relation
// versions, extent and current authorization rather than those fresh receipts.
fn comparable_input(input: &Value) -> Value {
    let mut input = input.clone();
    if let Some(inputs) = input["inputs"].as_object_mut() {
        for envelope in inputs.values_mut() {
            if envelope["relation"]["grain"] == "governed_sql" {
                envelope["source"]["content_revision"] = Value::Null;
                envelope["source"]["execution_receipt"]["observed_at"] = Value::Null;
            }
        }
    }
    input
}

#[cfg(test)]
pub(crate) async fn render(db: &Db, actor: &str, args: Value) -> Result<Value> {
    render_with_database(db, actor, None, args).await
}

pub(crate) async fn render_with_database(
    db: &Db,
    actor: &str,
    hosting_database: Option<&str>,
    args: Value,
) -> Result<Value> {
    let args: Args = parse("render_artifact", args)?;
    if args.as_of.is_some()
        || args.parent_origin.is_some()
        || args.revalidate.is_some()
        || args.include_timing
    {
        return Err(Error::engine(
            "render_artifact (kernel-v2): historical, HTML-parent, timing and conditional rendering are unsupported",
        ));
    }
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let Some(record) = kernel::read_record_on(&mut tx, actor, &args.id).await? else {
        return Ok(refusal(
            &args.id,
            "artifact_unavailable",
            "artifact is unavailable",
        ));
    };
    if let Some(outcome) =
        kernel::artifact_closures::exclusion_outcome_on(&mut tx, actor, &args.id).await?
    {
        return Ok(outcome);
    }
    let closure: Option<(String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT source_body,source_sha256,source_event_id,bindings,grants,event_seq FROM kernel_artifact_closures WHERE artifact_id=?",
    )
    .bind(&args.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((body, digest, source_event_id, bindings, grants, activation_seq)) = closure else {
        return Ok(refusal(
            &args.id,
            "artifact_source_unattested",
            "verified artifact source is unavailable on this deployment",
        ));
    };
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(&args.id)
            .fetch_one(&mut *tx)
            .await?;
    let kind = crate::v2_standard::v1_compat::v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|pin| pin.version),
        primary.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(&args.id)
            .fetch_optional(&mut *tx)
            .await?;
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT body,event_seq FROM kernel_record_bodies WHERE record_id=?")
            .bind(&args.id)
            .fetch_optional(&mut *tx)
            .await?;
    if !kernel::artifact_closures::is_artifact_kind_on(&mut tx, kind).await?
        || runtime.as_deref() != Some(mdx_v2::RUNTIME_ID)
        || current
            .as_ref()
            .is_none_or(|(live, seq)| live != &body || *seq > activation_seq)
        || mdx::sha256_hex(body.as_bytes()) != digest
    {
        return Ok(refusal(
            &args.id,
            "artifact_source_changed",
            "the attested artifact source is no longer current",
        ));
    }
    let parsed = match mdx_v2::parse_artifact(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return Ok(refusal(
                &args.id,
                "artifact_source_invalid",
                "the attested artifact source could not be compiled",
            ))
        }
    };
    let mdx_v2::Manifest::Artifact(manifest) = &parsed.manifest else {
        return Ok(refusal(
            &args.id,
            "artifact_source_invalid",
            "source is not an artifact",
        ));
    };
    if !parsed.imports.is_empty() {
        return Ok(refusal(
            &args.id,
            "module_closure_unavailable",
            "the imported module closure is unavailable on this deployment",
        ));
    }
    let bindings: Vec<Value> = serde_json::from_str(&bindings)?;
    // V1 reports a hidden input binding without disclosing its Collection.
    // Keep that refusal distinct from incompatible input data, under the same
    // caller snapshot used to resolve the input below.
    for binding in &bindings {
        // V1 resolves declared ports only. Frozen admission independently
        // rejects extraneous bindings; do not probe their targets here.
        if !manifest
            .inputs
            .contains_key(source_field(binding, "port_name")?)
        {
            continue;
        }
        let collection_id = source_field(binding, "collection_id")?;
        if !kernel::kernel_effective_capability_on(&mut tx, actor, collection_id)
            .await?
            .allows(Capability::View)
        {
            return Ok(refusal(
                &args.id,
                "binding_unavailable",
                "artifact input binding is unavailable",
            ));
        }
    }
    let grants: Vec<Value> = serde_json::from_str(&grants)?;
    let snapshot_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    // The global head may be a private install/custody event. Use a synthetic
    // v2 snapshot marker in the public relation receipt, never its event ID.
    let snapshot_event_id = format!("kernel-v2-snapshot:{snapshot_seq}");
    let bound = match bound_inputs_on(
        db,
        &mut tx,
        actor,
        &args.id,
        &source_event_id,
        manifest,
        &bindings,
        &grants,
        &snapshot_event_id,
        snapshot_seq,
    )
    .await
    {
        Ok(bound) => bound,
        Err(_) => {
            return Ok(refusal(
                &args.id,
                "named_input_unavailable",
                "an authorized artifact input is unavailable on this deployment",
            ))
        }
    };
    let (observed, availability) = if manifest.interactions.is_empty() {
        (BTreeMap::new(), None)
    } else {
        let (observed, availability) =
            interaction_plan_on(&mut tx, actor, &manifest.interactions, &bound, false).await?;
        (observed, Some(availability))
    };
    // Retain the actual authorized values, including record revisions and
    // collection membership. A workspace event head is not a read dependency.
    let expected_input = comparable_input(&bound.runtime_input);
    tx.rollback().await?;
    #[cfg(test)]
    if let Ok((captured, resume)) = RENDER_PAUSE.try_with(Clone::clone) {
        captured.notify_one();
        resume.notified().await;
    }
    let compiled = format!(
        "const native=globalThis.__nativeBridge.context(\"$root\");\n{}",
        parsed.compiled
    );
    let cache_key = mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&json!({
        "actor":actor,"artifact_id":args.id,"body_sha256":digest,
        "input":&bound.runtime_input
    })));
    let input = bound.runtime_input;
    let contexts = json!({"$root":{"inputs":bound.root_inputs}});
    let execution = tokio::task::spawn_blocking(move || {
        mdx_v2::render_verified(&compiled, Default::default(), &input, &contexts)
    })
    .await
    .map_err(|_| Error::engine("render_artifact (kernel-v2): compiler worker failed"))?;
    let tree = match execution {
        Ok((tree, _)) => tree,
        Err(failure) => {
            return Ok(refusal(&args.id, failure.code, &failure.message));
        }
    };
    // Compilation runs off the database thread. A permission loss or edit
    // during that interval must not return a tree from stale authority.
    let mut final_tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut final_tx, actor).await?;
    let fresh = kernel::read_record_on(&mut final_tx, actor, &args.id).await?;
    if fresh
        .as_ref()
        .is_none_or(|fresh| fresh.revision != record.revision)
    {
        return Ok(refusal(
            &args.id,
            "artifact_unavailable",
            "artifact is unavailable",
        ));
    }
    let latest: Option<(String, i64)> =
        sqlx::query_as("SELECT body,event_seq FROM kernel_record_bodies WHERE record_id=?")
            .bind(&args.id)
            .fetch_optional(&mut *final_tx)
            .await?;
    if latest
        .as_ref()
        .is_none_or(|(live, seq)| live != &body || *seq > activation_seq)
    {
        return Ok(refusal(
            &args.id,
            "artifact_source_changed",
            "the attested artifact source is no longer current",
        ));
    }
    // Re-resolve every input under current authority. This catches edits,
    // hidden/deleted records, traversals and newly added collection members,
    // while unrelated writes elsewhere in the workspace remain harmless.
    let fresh_bound = bound_inputs_on(
        db,
        &mut final_tx,
        actor,
        &args.id,
        &source_event_id,
        manifest,
        &bindings,
        &grants,
        &snapshot_event_id,
        snapshot_seq,
    )
    .await;
    if fresh_bound.map_or(true, |fresh| {
        comparable_input(&fresh.runtime_input) != expected_input
    }) {
        return Ok(refusal(
            &args.id,
            "artifact_snapshot_changed",
            "artifact inputs changed while rendering; retry",
        ));
    }
    final_tx.rollback().await?;
    let render_sha256 = crate::mcp::tools::artifacts::safe_tree_render_sha256(
        &tree,
        &serde_json::to_value(&manifest.interactions)?,
        &observed,
        availability.as_ref(),
    );
    let mut plan = json!({
        "kind":"safe_tree","version":"1","tree":tree,
        "provenance":{
            "record_id":args.id,"source_event_id":source_event_id,
            "event_seq":record.revision,"body_sha256":digest,
            "render_sha256":render_sha256
        },
        "cache":{"state":"miss","key":cache_key}
    });
    if !manifest.interactions.is_empty() {
        plan["interactions"] = serde_json::to_value(&manifest.interactions)?;
        plan["observed"] = serde_json::to_value(&observed)?;
        plan["interaction_availability"] = availability.unwrap();
    }
    if let Some(styles) = crate::mcp::tools::artifacts::styles_plan_field(
        hosting_database,
        &args.id,
        parsed.styles_sha256(),
        parsed.styles_flags(),
    ) {
        plan["styles"] = styles;
    }
    Ok(json!({
        "status":"rendered", "artifact_id":args.id,
        "runtime":mdx_v2::descriptor(),
        "input":{"version":mdx_v2::NAMED_INPUT_ABI,"mode":"named","ports":bound.port_names},
        "plan":plan
    }))
}

/// Resolve the stylesheet from the caller's current visible, attested body.
/// All failed checks are a single absence at the hosted route.
pub(crate) async fn stylesheet(
    db: &Db,
    actor: &str,
    artifact_id: &str,
    digest: &str,
) -> Result<Option<String>> {
    let mut tx = db.write_pool().begin().await?;
    let Some(record) = kernel::read_record_on(&mut tx, actor, artifact_id).await? else {
        return Ok(None);
    };
    let closure: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT source_body,source_sha256,event_seq FROM kernel_artifact_closures WHERE artifact_id=?",
    )
    .bind(artifact_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((body, source_sha, activation_seq)) = closure else {
        return Ok(None);
    };
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT body,event_seq FROM kernel_record_bodies WHERE record_id=?")
            .bind(artifact_id)
            .fetch_optional(&mut *tx)
            .await?;
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(artifact_id)
            .fetch_optional(&mut *tx)
            .await?;
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(artifact_id)
            .fetch_one(&mut *tx)
            .await?;
    let kind = crate::v2_standard::v1_compat::v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|pin| pin.version),
        primary.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    if kernel::hq::tombstoned_on(&mut tx, artifact_id).await?
        || !kernel::artifact_closures::is_artifact_kind_on(&mut tx, kind).await?
        || runtime.as_deref() != Some(mdx_v2::RUNTIME_ID)
        || current
            .as_ref()
            .is_none_or(|(live, seq)| live != &body || *seq > activation_seq)
        || mdx::sha256_hex(body.as_bytes()) != source_sha
    {
        return Ok(None);
    }
    tx.rollback().await?;
    let parsed = match mdx_v2::parse_artifact(&body) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(None),
    };
    let Some(styles) = parsed.styles.filter(|styles| styles.sha256 == digest) else {
        return Ok(None);
    };
    let mut final_tx = db.write_pool().begin().await?;
    let fresh = kernel::read_record_on(&mut final_tx, actor, artifact_id).await?;
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT body,event_seq FROM kernel_record_bodies WHERE record_id=?")
            .bind(artifact_id)
            .fetch_optional(&mut *final_tx)
            .await?;
    if fresh
        .as_ref()
        .is_none_or(|fresh| fresh.revision != record.revision)
        || current
            .as_ref()
            .is_none_or(|(live, seq)| live != &body || *seq > activation_seq)
    {
        return Ok(None);
    }
    final_tx.rollback().await?;
    Ok(Some(styles.css))
}

#[cfg(test)]
pub(crate) async fn testing_governed_sql_input(
    db: &Db,
    actor: &str,
    id: &str,
    schema: &str,
) -> Result<Value> {
    let declaration = mdx_v2::InputDecl {
        envelope: mdx_v2::RELATION_ENVELOPE.into(),
        required: true,
        expose_to_root: false,
        projection: None,
        schema_sha256: Some(schema.into()),
        relations: std::collections::BTreeMap::new(),
    };
    let mut tx = db.pool().begin().await?;
    let result =
        governed_sql_input(db, &mut tx, actor, id, 0, &declaration, 0, InputLimits::MDX).await;
    tx.rollback().await?;
    result
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn governed_order_escapes_embedded_identifier_quotes() {
        use sqlx::Connection;
        let quoted = super::quoted_sql_identifier("display\"name");
        assert_eq!(quoted, "\"display\"\"name\"");
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        let value: i64 = sqlx::query_scalar(&format!("SELECT 7 AS {quoted} ORDER BY {quoted} ASC"))
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert_eq!(value, 7);
    }
}
