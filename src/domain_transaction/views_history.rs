//! Portable caller-filtered record views shared by the Postgres and
//! Turso-local adapters.
//!
//! Adapters own snapshot acquisition and their physical relation views; this
//! module owns the logical fold and response shape. Every statement is a
//! source-reviewed template, so this cannot become caller SQL or a SQLite
//! fallback.

use std::collections::{hash_map::Entry, BTreeMap, HashMap, HashSet};

use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::authorization::{allows_record_with, Capability};
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;
use crate::portable_sql::{
    BindValue, ColumnSpec, DomainStatementExecutor, LogicalType, NormalizedRow, NormalizedValue,
    StatementKind, StatementTemplate,
};
use crate::query::{read, tree, FacetValueRow, LinkRow, RecordRow};

const DEFAULT_STRUCTURE_DEPTH: i64 = 3;
const MAX_WALK_DEPTH: i64 = 100;
const DEFAULT_STALE_AFTER_DAYS: i64 = 14;
const MAX_STALE_AFTER_DAYS: i64 = 3650;
const DEFAULT_DASHBOARD_LIMIT: usize = 20;
const MAX_DASHBOARD_LIMIT: usize = 200;
pub(super) const MAX_VIEW_CANDIDATES: i64 = 10_000;

#[derive(Clone)]
pub(super) struct PortableRecord {
    pub(super) row: RecordRow,
    pub(super) policy_anchor_id: Option<String>,
    pub(super) archived: bool,
}

#[derive(Default)]
pub(super) struct SnapshotRows {
    pub(super) records: HashMap<String, PortableRecord>,
    pub(super) links: Vec<LinkRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetStructureArgs {
    root_id: String,
    max_depth: Option<i64>,
    include_archived: Option<bool>,
    max_children_per_node: Option<i64>,
    #[serde(default)]
    exclude_types: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetDashboardArgs {
    scope: Option<String>,
    stale_after_days: Option<i64>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenderRecordArgs {
    id: String,
    include_interpretation: Option<bool>,
}

pub(crate) fn statement(
    relation: &'static str,
    fragments: &'static [&'static str],
) -> Result<StatementTemplate> {
    StatementTemplate::new(StatementKind::Select, relation, fragments).map_err(|error| {
        crate::domain_transaction::stable_storage_error("read portable record view", &error)
    })
}

pub(crate) fn storage_error(error: crate::portable_sql::SqlError) -> Error {
    crate::domain_transaction::stable_storage_error("read portable record view", &error)
}

pub(super) fn text(row: &NormalizedRow, field: &str) -> Result<String> {
    match row.get(field) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "portable record view returned invalid '{field}'"
        ))),
    }
}

pub(super) fn optional_text(row: &NormalizedRow, field: &str) -> Result<Option<String>> {
    match row.get(field) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "portable record view returned invalid '{field}'"
        ))),
    }
}

pub(super) fn boolean(row: &NormalizedRow, field: &str) -> Result<bool> {
    match row.get(field) {
        Some(NormalizedValue::Bool(value)) => Ok(*value),
        _ => Err(Error::engine(format!(
            "portable record view returned invalid '{field}'"
        ))),
    }
}

pub(super) fn record_columns() -> [ColumnSpec; 17] {
    [
        ColumnSpec::required("id", LogicalType::Text),
        ColumnSpec::required("type", LogicalType::Text),
        ColumnSpec::nullable("kind", LogicalType::Text),
        ColumnSpec::required("name", LogicalType::Text),
        ColumnSpec::nullable("body", LogicalType::Text),
        ColumnSpec::nullable("home_id", LogicalType::Text),
        ColumnSpec::nullable("lifecycle", LogicalType::Text),
        ColumnSpec::nullable("owner_id", LogicalType::Text),
        ColumnSpec::nullable("policy_anchor_id", LogicalType::Text),
        ColumnSpec::required("persistence", LogicalType::Text),
        ColumnSpec::nullable("maturity", LogicalType::Text),
        ColumnSpec::nullable("summary", LogicalType::Text),
        ColumnSpec::nullable("last_activity_at", LogicalType::Text),
        ColumnSpec::required("created_at", LogicalType::Text),
        ColumnSpec::required("updated_at", LogicalType::Text),
        ColumnSpec::nullable("deleted_at", LogicalType::Text),
        ColumnSpec::required("archived", LogicalType::Bool),
    ]
}

pub(super) fn record_from_row(raw: &NormalizedRow) -> Result<PortableRecord> {
    Ok(PortableRecord {
        row: RecordRow {
            id: text(raw, "id")?,
            record_type: text(raw, "type")?,
            kind: optional_text(raw, "kind")?,
            name: text(raw, "name")?,
            body: optional_text(raw, "body")?,
            home_id: optional_text(raw, "home_id")?,
            lifecycle: optional_text(raw, "lifecycle")?,
            lifecycle_interpretation: crate::query::lifecycle::LifecycleInterpretation::Absent(
                crate::query::lifecycle::AbsentLifecycleInterpretation {
                    axis: None,
                    vocabulary: None,
                },
            ),
            owner_id: optional_text(raw, "owner_id")?,
            persistence: text(raw, "persistence")?,
            maturity: optional_text(raw, "maturity")?,
            summary: optional_text(raw, "summary")?,
            last_activity_at: optional_text(raw, "last_activity_at")?,
            created_at: text(raw, "created_at")?,
            updated_at: text(raw, "updated_at")?,
            deleted_at: optional_text(raw, "deleted_at")?,
            communication_origin: None,
            federation_provenance: None,
        },
        policy_anchor_id: optional_text(raw, "policy_anchor_id")?,
        archived: boolean(raw, "archived")?,
    })
}

async fn fetch_records<E: DomainStatementExecutor>(
    executor: &mut E,
    query: &StatementTemplate,
    bindings: &[BindValue],
    bounded: bool,
) -> Result<HashMap<String, PortableRecord>> {
    let rows = executor
        .fetch_all(query, bindings, &record_columns())
        .await
        .map_err(storage_error)?;
    if bounded && rows.len() > MAX_VIEW_CANDIDATES as usize {
        return Err(Error::engine(format!(
            "portable record view candidate set exceeds {MAX_VIEW_CANDIDATES} records"
        )));
    }
    let mut records = HashMap::with_capacity(rows.len());
    for row in rows {
        let record = record_from_row(&row)?;
        records.insert(record.row.id.clone(), record);
    }
    Ok(records)
}

async fn structure_records<E: DomainStatementExecutor>(
    executor: &mut E,
    root_id: &str,
    max_depth: i64,
    include_boundary_children: bool,
) -> Result<HashMap<String, PortableRecord>> {
    let exact = statement(
        "records",
        &[
            "SELECT r.id,r.type,r.kind,r.name,NULL AS body,r.home_id,r.lifecycle,r.owner_id,r.policy_anchor_id,r.persistence,r.maturity,r.summary,r.last_activity_at,r.created_at,r.updated_at,r.deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r WHERE r.id = ",
            "",
        ],
    )?;
    let children = statement(
        "records",
        &[
            "SELECT r.id,r.type,r.kind,r.name,NULL AS body,r.home_id,r.lifecycle,r.owner_id,r.policy_anchor_id,r.persistence,r.maturity,r.summary,r.last_activity_at,r.created_at,r.updated_at,r.deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r WHERE r.home_id = ",
            " ORDER BY r.name,r.id LIMIT ",
            "",
        ],
    )?;
    let mut records =
        fetch_records(executor, &exact, &[BindValue::Text(root_id.into())], true).await?;
    let mut frontier = records.keys().cloned().collect::<Vec<_>>();
    let loaded_depth = max_depth.min(MAX_WALK_DEPTH) + i64::from(include_boundary_children);
    for _ in 0..loaded_depth {
        let mut next = Vec::new();
        for parent in frontier {
            let selected = fetch_records(
                executor,
                &children,
                &[
                    BindValue::Text(parent),
                    // Selection precedes caller policy filtering, so the
                    // presentation cap cannot safely be applied here. Keep
                    // the physical read bounded and apply the requested cap
                    // only after visibility/tombstone/archive filtering.
                    BindValue::Integer(MAX_VIEW_CANDIDATES + 1),
                ],
                true,
            )
            .await?;
            next.extend(selected.keys().cloned());
            records.extend(selected);
            if records.len() > MAX_VIEW_CANDIDATES as usize {
                return Err(Error::engine(format!(
                    "get_structure candidate set exceeds {MAX_VIEW_CANDIDATES} records"
                )));
            }
        }
        if next.is_empty() {
            break;
        }
        next.sort_by(|left, right| {
            records[left]
                .row
                .name
                .cmp(&records[right].row.name)
                .then(left.cmp(right))
        });
        frontier = next;
    }
    Ok(records)
}

async fn dashboard_records<E: DomainStatementExecutor>(
    executor: &mut E,
    scope: Option<&str>,
) -> Result<HashMap<String, PortableRecord>> {
    let Some(scope) = scope else {
        return fetch_records(
            executor,
            &statement(
                "records",
                &["SELECT r.id,r.type,r.kind,r.name,NULL AS body,r.home_id,r.lifecycle,r.owner_id,r.policy_anchor_id,r.persistence,r.maturity,r.summary,r.last_activity_at,r.created_at,r.updated_at,r.deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r ORDER BY r.id"],
            )?,
            &[],
            false,
        )
        .await;
    };
    let mut records = structure_records(executor, scope, MAX_WALK_DEPTH, false).await?;
    if records.len() >= MAX_VIEW_CANDIDATES as usize {
        return Err(Error::engine(format!(
            "get_dashboard scoped candidate set reaches the {MAX_VIEW_CANDIDATES}-record bound"
        )));
    }
    Ok(std::mem::take(&mut records))
}

async fn render_records<E: DomainStatementExecutor>(
    executor: &mut E,
    id: &str,
) -> Result<HashMap<String, PortableRecord>> {
    let exact = statement(
        "records",
        &[
            "SELECT r.id,r.type,r.kind,r.name,NULL AS body,r.home_id,r.lifecycle,r.owner_id,r.policy_anchor_id,r.persistence,r.maturity,r.summary,r.last_activity_at,r.created_at,r.updated_at,r.deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r WHERE r.id = ",
            "",
        ],
    )?;
    let mut records = fetch_records(executor, &exact, &[BindValue::Text(id.into())], true).await?;
    let mut current = records
        .get(id)
        .and_then(|record| record.row.home_id.clone());
    let mut seen = HashSet::new();
    for _ in 0..MAX_WALK_DEPTH {
        let Some(parent_id) = current else { break };
        if !seen.insert(parent_id.clone()) {
            break;
        }
        let parent = fetch_records(
            executor,
            &exact,
            &[BindValue::Text(parent_id.clone())],
            true,
        )
        .await?;
        current = parent
            .get(&parent_id)
            .and_then(|record| record.row.home_id.clone());
        records.extend(parent);
    }
    let children = fetch_records(
        executor,
        &statement(
            "records",
            &[
                "SELECT r.id,r.type,r.kind,r.name,NULL AS body,r.home_id,r.lifecycle,r.owner_id,r.policy_anchor_id,r.persistence,r.maturity,r.summary,r.last_activity_at,r.created_at,r.updated_at,r.deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r WHERE r.home_id = ",
                " ORDER BY r.name,r.id LIMIT ",
                "",
            ],
        )?,
        &[
            BindValue::Text(id.into()),
            BindValue::Integer(MAX_VIEW_CANDIDATES + 1),
        ],
        true,
    )
    .await?;
    records.extend(children);
    Ok(records)
}

async fn load_record_header<E: DomainStatementExecutor>(
    executor: &mut E,
    id: &str,
) -> Result<Option<PortableRecord>> {
    let mut records = fetch_records(
        executor,
        &statement(
            "records",
            &[
                "SELECT r.id,r.type,r.kind,r.name,NULL AS body,r.home_id,r.lifecycle,r.owner_id,r.policy_anchor_id,r.persistence,r.maturity,r.summary,r.last_activity_at,r.created_at,r.updated_at,r.deleted_at,EXISTS(SELECT 1 FROM facet_values f WHERE f.record_id=r.id AND f.key='archived') AS archived FROM {{relation}} r WHERE r.id = ",
                "",
            ],
        )?,
        &[BindValue::Text(id.into())],
        true,
    )
    .await?;
    Ok(records.remove(id))
}

async fn hydrate_link_endpoints<E: DomainStatementExecutor>(
    executor: &mut E,
    snapshot: &mut SnapshotRows,
) -> Result<()> {
    let mut endpoint_ids = snapshot
        .links
        .iter()
        .flat_map(|link| [&link.source_id, &link.target_id])
        .filter(|id| !snapshot.records.contains_key(id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    endpoint_ids.sort();
    endpoint_ids.dedup();
    if endpoint_ids.len() > MAX_VIEW_CANDIDATES as usize {
        return Err(Error::engine(format!(
            "portable record view link endpoint set exceeds {MAX_VIEW_CANDIDATES} records"
        )));
    }
    for endpoint_id in endpoint_ids {
        if let Some(endpoint) = load_record_header(executor, &endpoint_id).await? {
            snapshot.records.insert(endpoint_id, endpoint);
        }
    }
    Ok(())
}

async fn load_body<E: DomainStatementExecutor>(
    executor: &mut E,
    id: &str,
) -> Result<Option<String>> {
    let query = statement(
        "records",
        &["SELECT body FROM {{relation}} WHERE id = ", ""],
    )?;
    let rows = executor
        .fetch_all(
            &query,
            &[BindValue::Text(id.into())],
            &[ColumnSpec::nullable("body", LogicalType::Text)],
        )
        .await
        .map_err(storage_error)?;
    rows.first()
        .map(|row| optional_text(row, "body"))
        .transpose()
        .map(Option::flatten)
}

async fn load_facets<E: DomainStatementExecutor>(
    executor: &mut E,
    record: &PortableRecord,
) -> Result<Vec<FacetValueRow>> {
    let query = statement(
        "facet_values",
        &[
            "SELECT record_id,key,value,vocab_ref FROM {{relation}} WHERE record_id = ",
            " ORDER BY key LIMIT ",
            "",
        ],
    )?;
    let rows = executor
        .fetch_all(
            &query,
            &[
                BindValue::Text(record.row.id.clone()),
                BindValue::Integer(MAX_VIEW_CANDIDATES + 1),
            ],
            &[
                ColumnSpec::required("record_id", LogicalType::Text),
                ColumnSpec::required("key", LogicalType::Text),
                ColumnSpec::nullable("value", LogicalType::Text),
                ColumnSpec::nullable("vocab_ref", LogicalType::Text),
            ],
        )
        .await
        .map_err(storage_error)?;
    if rows.len() > MAX_VIEW_CANDIDATES as usize {
        return Err(Error::engine(format!(
            "render_record facet set exceeds {MAX_VIEW_CANDIDATES} rows"
        )));
    }
    let schema_rows = crate::query::cascade::schema_config_rows_with(executor).await?;
    let shapes = crate::query::cascade::facets_for_record_context(
        &schema_rows,
        &record.row.record_type,
        record.row.kind.as_deref(),
        None,
    );
    rows.iter()
        .map(|raw| {
            let key = text(raw, "key")?;
            // Engine-reserved keys can never appear in schema config
            // (assert_no_reserved_facet_keys refuses them), so the cascade
            // has no shape for them and an object-valued reserved facet
            // would otherwise decode as a raw JSON string with no error.
            let object_typed = shapes
                .get(&key)
                .and_then(|shape| shape.get("type"))
                .and_then(Value::as_str)
                == Some("object")
                || key == crate::canvas::PROMOTED_FROM_FACET_KEY;
            let value = optional_text(raw, "value")?.map(|stored| {
                if object_typed {
                    serde_json::from_str::<Value>(&stored)
                        .ok()
                        .filter(Value::is_object)
                        .unwrap_or(Value::String(stored))
                } else {
                    Value::String(stored)
                }
            });
            Ok(FacetValueRow {
                key,
                value,
                vocab_ref: optional_text(raw, "vocab_ref")?,
                // A valid-time view is a read of history, not of the current
                // assertion, so it issues no compare-and-set token.
                version: None,
            })
        })
        .collect()
}

async fn load_links<E: DomainStatementExecutor>(
    executor: &mut E,
    record_id: Option<&str>,
) -> Result<Vec<LinkRow>> {
    let (query, bindings) = match record_id {
        Some(id) => (
            statement("links", &["SELECT id,source_id,target_id,relationship,note,created_at FROM {{relation}} WHERE source_id = ", " OR target_id = ", " ORDER BY id LIMIT ", ""])?,
            vec![BindValue::Text(id.into()), BindValue::Text(id.into()), BindValue::Integer(MAX_VIEW_CANDIDATES + 1)],
        ),
        None => (
            statement("links", &["SELECT id,source_id,target_id,relationship,note,created_at FROM {{relation}} WHERE relationship IN ('blocks','depends_on') ORDER BY id LIMIT ", ""])?,
            vec![BindValue::Integer(MAX_VIEW_CANDIDATES + 1)],
        ),
    };
    let rows = executor
        .fetch_all(
            &query,
            &bindings,
            &[
                ColumnSpec::required("id", LogicalType::Text),
                ColumnSpec::required("source_id", LogicalType::Text),
                ColumnSpec::required("target_id", LogicalType::Text),
                ColumnSpec::required("relationship", LogicalType::Text),
                ColumnSpec::nullable("note", LogicalType::Text),
                ColumnSpec::required("created_at", LogicalType::Text),
            ],
        )
        .await
        .map_err(storage_error)?;
    if rows.len() > MAX_VIEW_CANDIDATES as usize {
        return Err(Error::engine(format!(
            "portable record view link candidate set exceeds {MAX_VIEW_CANDIDATES} rows"
        )));
    }
    rows.iter()
        .map(|raw| {
            Ok(LinkRow {
                id: text(raw, "id")?,
                source_id: text(raw, "source_id")?,
                target_id: text(raw, "target_id")?,
                relationship: text(raw, "relationship")?,
                note: optional_text(raw, "note")?,
                created_at: text(raw, "created_at")?,
            })
        })
        .collect()
}

async fn load_dashboard_links<E: DomainStatementExecutor>(
    executor: &mut E,
    records: &HashMap<String, PortableRecord>,
    scoped: bool,
) -> Result<Vec<LinkRow>> {
    if !scoped {
        return load_links(executor, None).await;
    }
    let mut ids = records.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    let mut batches = Vec::with_capacity(ids.len());
    for id in ids {
        batches.push(load_links(executor, Some(&id)).await?);
    }
    merge_scoped_dashboard_links(batches)
}

fn merge_scoped_dashboard_links(
    batches: impl IntoIterator<Item = Vec<LinkRow>>,
) -> Result<Vec<LinkRow>> {
    let mut links = BTreeMap::new();
    for link in batches
        .into_iter()
        .flatten()
        .filter(|link| link.relationship == "blocks" || link.relationship == "depends_on")
    {
        links.insert(link.id.clone(), link);
        if links.len() > MAX_VIEW_CANDIDATES as usize {
            return Err(Error::engine(format!(
                "get_dashboard scoped link set exceeds {MAX_VIEW_CANDIDATES} rows"
            )));
        }
    }
    Ok(links.into_values().collect())
}

pub(super) async fn hidden_ids<E: DomainStatementExecutor>(
    executor: &mut E,
    records: &HashMap<String, PortableRecord>,
) -> Result<(HashSet<String>, HashSet<String>)> {
    let mut hidden = HashSet::new();
    let mut suggestions = HashSet::new();
    for record in records.values() {
        if record.row.record_type == "Entity" && record.row.kind.as_deref() == Some("semantic-unit")
        {
            hidden.insert(record.row.id.clone());
            continue;
        }
        let Some(kind) = record.row.kind.as_deref() else {
            continue;
        };
        if record.row.record_type != "Annotation" {
            continue;
        }
        let resolution =
            crate::meta::kind::resolve_with(executor, &record.row.record_type, kind).await?;
        let suggestion = crate::generated::kinds::CoreKind::AnnotationSuggestion;
        if suggestion.matches(&resolution) {
            suggestions.insert(record.row.id.clone());
        }
        if [
            suggestion,
            crate::generated::kinds::CoreKind::AnnotationCitation,
            crate::generated::kinds::CoreKind::AnnotationComment,
            crate::generated::kinds::CoreKind::AnnotationAttribution,
        ]
        .iter()
        .any(|identity| identity.matches(&resolution))
        {
            hidden.insert(record.row.id.clone());
        }
    }
    Ok((hidden, suggestions))
}

pub(super) async fn visible_ids<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    snapshot: &SnapshotRows,
) -> Result<HashSet<String>> {
    let mut ids = snapshot.records.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    let mut audience_principals = HashSet::from([caller.credential().to_string()]);
    if !caller.is_trusted_local() {
        let principals = statement(
            "bindings",
            &["SELECT np.identifier FROM {{relation}} account_binding JOIN bindings np ON np.record_id=account_binding.record_id WHERE account_binding.system='account' AND account_binding.identifier=", " AND account_binding.is_canonical=1 AND np.system='native-principal' AND np.is_canonical=1 ORDER BY np.identifier LIMIT ", ""],
        )?;
        for row in executor
            .fetch_all(
                &principals,
                &[
                    BindValue::Text(caller.credential().into()),
                    BindValue::Integer(MAX_VIEW_CANDIDATES + 1),
                ],
                &[ColumnSpec::required("identifier", LogicalType::Text)],
            )
            .await
            .map_err(storage_error)?
        {
            audience_principals.insert(text(&row, "identifier")?);
        }
    }
    let mut visible = HashSet::new();
    for id in ids {
        let record = &snapshot.records[&id];
        // General record tools exclude governed attributions before policy
        // evaluation. Keep that exact order: a full attribution id must be as
        // undiscoverable here as it is through prefix resolution.
        if crate::authorization::is_attribution_record_with(executor, &id).await?
            || !allows_record_with(
                executor,
                crate::mcp::tools::principal(caller),
                &id,
                Capability::View,
            )
            .await?
        {
            continue;
        }
        let mut message_visible = caller.is_trusted_local() || record.row.record_type != "Message";
        if !message_visible {
            if let Some(owner) = record.row.owner_id.as_deref() {
                let owner_binding = statement(
                    "bindings",
                    &[
                        "SELECT EXISTS(SELECT 1 FROM {{relation}} WHERE record_id=",
                        " AND system='account' AND identifier=",
                        " AND is_canonical=1) AS owns",
                    ],
                )?;
                let rows = executor
                    .fetch_all(
                        &owner_binding,
                        &[
                            BindValue::Text(owner.into()),
                            BindValue::Text(caller.credential().into()),
                        ],
                        &[ColumnSpec::required("owns", LogicalType::Bool)],
                    )
                    .await
                    .map_err(storage_error)?;
                message_visible = match rows.first() {
                    Some(row) => boolean(row, "owns")?,
                    None => false,
                };
            }
        }
        if !message_visible {
            let audience = statement(
                "message_audiences",
                &[
                    "SELECT principal_id FROM {{relation}} WHERE message_id=",
                    " ORDER BY principal_id LIMIT ",
                    "",
                ],
            )?;
            let rows = executor
                .fetch_all(
                    &audience,
                    &[
                        BindValue::Text(id.clone()),
                        BindValue::Integer(MAX_VIEW_CANDIDATES + 1),
                    ],
                    &[ColumnSpec::required("principal_id", LogicalType::Text)],
                )
                .await
                .map_err(storage_error)?;
            message_visible = rows.iter().try_fold(false, |allowed, row| {
                Ok::<_, Error>(allowed || audience_principals.contains(&text(row, "principal_id")?))
            })?;
        }
        if message_visible {
            visible.insert(id);
        }
    }
    Ok(visible)
}

fn child_ids<'a>(records: &'a HashMap<String, PortableRecord>, parent: &str) -> Vec<&'a str> {
    let mut children = records
        .values()
        .filter(|record| record.row.home_id.as_deref() == Some(parent))
        .map(|record| record.row.id.as_str())
        .collect::<Vec<_>>();
    children.sort_by(|left, right| {
        records[*left]
            .row
            .name
            .cmp(&records[*right].row.name)
            .then(left.cmp(right))
    });
    children
}

pub(super) fn containment_path_visible(
    records: &HashMap<String, PortableRecord>,
    visible: &HashSet<String>,
    record_id: &str,
) -> bool {
    if record_id == crate::schema::ROOT_RECORD_ID {
        return true;
    }
    let mut current = records
        .get(record_id)
        .and_then(|record| record.row.home_id.as_deref());
    let mut seen = HashSet::new();
    while let Some(id) = current {
        if !seen.insert(id.to_string()) || !visible.contains(id) {
            return false;
        }
        if id == crate::schema::ROOT_RECORD_ID {
            return true;
        }
        current = records
            .get(id)
            .and_then(|record| record.row.home_id.as_deref());
    }
    false
}

pub(super) fn custody_boundary(
    records: &HashMap<String, PortableRecord>,
    record: &PortableRecord,
) -> bool {
    let Some(parent) = record.row.home_id.as_deref().and_then(|id| records.get(id)) else {
        return false;
    };
    record.policy_anchor_id.is_some()
        && parent.policy_anchor_id.is_some()
        && record.policy_anchor_id != parent.policy_anchor_id
}

pub(crate) async fn get_structure<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "get_structure";
    if arguments.get("as_of").is_some() {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "portable-domain",
            "get_structure historical projection",
        ));
    }
    let args: GetStructureArgs = crate::mcp::tools::parse_args(TOOL, arguments)?;
    let max_depth = args.max_depth.unwrap_or(DEFAULT_STRUCTURE_DEPTH);
    if max_depth < 0 {
        return Err(Error::engine(format!(
            "{TOOL}: max_depth must be greater than or equal to 0"
        )));
    }
    let max_children = args
        .max_children_per_node
        .unwrap_or(tree::DEFAULT_MAX_CHILDREN_PER_NODE);
    if !(0..=tree::MAX_CHILDREN_PER_NODE).contains(&max_children) {
        return Err(Error::engine(format!(
            "{TOOL}: max_children_per_node must be between 0 and {}",
            tree::MAX_CHILDREN_PER_NODE
        )));
    }
    let include_archived = args.include_archived.unwrap_or(false);
    for excluded in &args.exclude_types {
        if !crate::schema::SPINE_TYPES.contains(&excluded.as_str()) {
            return Err(Error::engine(format!(
                "{TOOL}: exclude_types entry '{excluded}' is not a spine type (closed set: {})",
                crate::schema::SPINE_TYPES.join(", ")
            )));
        }
    }
    let excluded: HashSet<&str> = args.exclude_types.iter().map(String::as_str).collect();
    let snapshot = SnapshotRows {
        // One header-only level beyond the requested boundary is required to
        // report canonical live/authorized immediate-child counts for the
        // root at depth zero and for every boundary node.
        records: structure_records(executor, &args.root_id, max_depth, true).await?,
        ..SnapshotRows::default()
    };
    let visible = visible_ids(executor, caller, &snapshot).await?;
    let (hidden, _) = hidden_ids(executor, &snapshot.records).await?;
    let Some(root) = snapshot.records.get(&args.root_id) else {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.root_id
        )));
    };
    if !visible.contains(&args.root_id) {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.root_id
        )));
    }
    if root.row.deleted_at.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: record {} is deleted (tombstoned)",
            args.root_id
        )));
    }
    if hidden.contains(&root.row.id) {
        return Ok(json!({
            "root_id": args.root_id,
            "max_depth": max_depth,
            "max_children_per_node": max_children,
            "nodes": [],
        }));
    }

    let eligible = |id: &str| {
        let record = &snapshot.records[id];
        record.row.deleted_at.is_none()
            && !hidden.contains(id)
            && (include_archived || !record.archived)
            && !excluded.contains(record.row.record_type.as_str())
            && visible.contains(id)
    };
    let mut nodes = Vec::new();
    let mut stack = vec![(args.root_id.clone(), 0_i64)];
    let mut visited = HashSet::new();
    while let Some((id, depth)) = stack.pop() {
        if !visited.insert(id.clone()) {
            continue;
        }
        let record = &snapshot.records[&id];
        let children = child_ids(&snapshot.records, &id)
            .into_iter()
            .filter(|child| eligible(child))
            .collect::<Vec<_>>();
        let child_count = children.len() as i64;
        let selected = children
            .into_iter()
            .take(max_children as usize)
            .collect::<Vec<_>>();
        if depth < max_depth.min(MAX_WALK_DEPTH) {
            for child in selected.into_iter().rev() {
                stack.push((child.to_string(), depth + 1));
            }
        }
        let home_id = record
            .row
            .home_id
            .clone()
            .filter(|home| visible.contains(home));
        nodes.push(json!({
            "id": record.row.id,
            "type": record.row.record_type,
            "kind": record.row.kind,
            "name": record.row.name,
            "home_id": home_id,
            "persistence": record.row.persistence,
            "last_activity_at": record.row.last_activity_at,
            "custody_boundary": custody_boundary(&snapshot.records, record),
            "containment_path_visible": containment_path_visible(&snapshot.records, &visible, &id),
            "depth": depth,
            "child_count": child_count,
            "archived": record.archived,
        }));
    }
    Ok(json!({
        "root_id": args.root_id,
        "max_depth": max_depth,
        "max_children_per_node": max_children,
        "nodes": nodes,
    }))
}

fn dashboard_entry(
    record: &PortableRecord,
    lifecycle_interpreter: &crate::query::lifecycle::LifecycleInterpreter,
) -> Value {
    json!({
        "id": record.row.id,
        "type": record.row.record_type,
        "kind": record.row.kind,
        "name": record.row.name,
        "lifecycle_interpretation": lifecycle_interpreter.interpret(
            &record.row.record_type,
            record.row.kind.as_deref(),
            record.row.home_id.as_deref(),
            record.row.lifecycle.as_deref(),
        ),
        "maturity": record.row.maturity,
        "last_activity_at": record.row.last_activity_at,
    })
}

/// KNOWN BACKEND DIVERGENCE from the SQLite `get_dashboard`
/// (`mcp::tools::orientation`), audited 2026-08 under record `ebded493` and
/// deliberately left standing there.
///
/// The SQLite tool routes each attention candidate through
/// `query::lifecycle::LifecycleInterpreter`, so a record whose lifecycle is
/// TERMINAL in its governing vocabulary — a completed or closed task — is
/// excluded from `active` and `stale` rather than ageing to the head of the
/// oldest-first neglect list, and the records whose lifecycle cannot be
/// interpreted are additionally reported in an `unclassified_lifecycle`
/// census. The partition below still does neither: `lifecycle.is_some()` is
/// an inclusion gate and the split is `last_activity_at` alone, which is
/// exactly the defect that was fixed on the SQLite path.
///
/// This is not an oversight and not a decision that terminality means
/// something different here. It was scoped out because the interpreter reads
/// `&Db`/`db.write_pool()` directly and has no executor-generic form, and
/// because these adapters are not being expanded in that change. Closing it
/// is filed as follow-up work; until then, do not read this function as the
/// portable definition of the attention buckets.
pub(crate) async fn get_dashboard<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "get_dashboard";
    let args: GetDashboardArgs = crate::mcp::tools::parse_args(TOOL, arguments)?;
    let stale_after_days = args.stale_after_days.unwrap_or(DEFAULT_STALE_AFTER_DAYS);
    if !(1..=MAX_STALE_AFTER_DAYS).contains(&stale_after_days) {
        return Err(Error::engine(format!(
            "{TOOL}: 'stale_after_days' must be between 1 and {MAX_STALE_AFTER_DAYS}"
        )));
    }
    let limit = args.limit.unwrap_or(DEFAULT_DASHBOARD_LIMIT);
    if limit == 0 || limit > MAX_DASHBOARD_LIMIT {
        return Err(Error::engine(format!(
            "{TOOL}: 'limit' must be between 1 and {MAX_DASHBOARD_LIMIT}"
        )));
    }
    let records = dashboard_records(executor, args.scope.as_deref()).await?;
    let links = load_dashboard_links(executor, &records, args.scope.is_some()).await?;
    let mut snapshot = SnapshotRows { records, links };
    hydrate_link_endpoints(executor, &mut snapshot).await?;
    let visible = visible_ids(executor, caller, &snapshot).await?;
    let (hidden, _) = hidden_ids(executor, &snapshot.records).await?;
    let lifecycle_interpreter = crate::query::lifecycle::LifecycleInterpreter::load_visible_with(
        executor,
        crate::mcp::tools::principal(caller),
    )
    .await?;
    let scope = if let Some(root) = args.scope.as_deref() {
        if !visible.contains(root) {
            return Err(Error::engine(format!(
                "{TOOL}: scope record {root} does not exist"
            )));
        }
        let mut scoped = HashSet::new();
        let mut stack = vec![root.to_string()];
        while let Some(id) = stack.pop() {
            if !scoped.insert(id.clone()) {
                continue;
            }
            stack.extend(
                child_ids(&snapshot.records, &id)
                    .into_iter()
                    .map(str::to_string),
            );
        }
        Some(scoped)
    } else {
        None
    };
    let in_scope = |id: &str| scope.as_ref().is_none_or(|ids| ids.contains(id));
    let ordinary = |record: &PortableRecord| {
        record.row.deleted_at.is_none()
            && !record.archived
            && !hidden.contains(&record.row.id)
            && visible.contains(&record.row.id)
            && in_scope(&record.row.id)
    };
    let cutoff = (Utc::now() - Duration::days(stale_after_days))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let mut attention = snapshot
        .records
        .values()
        .filter(|record| ordinary(record) && record.row.lifecycle.is_some())
        .collect::<Vec<_>>();
    attention.sort_by(|left, right| {
        right
            .row
            .last_activity_at
            .cmp(&left.row.last_activity_at)
            .then(left.row.id.cmp(&right.row.id))
    });
    let (active_all, mut stale_all): (Vec<_>, Vec<_>) = attention.into_iter().partition(|record| {
        record
            .row
            .last_activity_at
            .as_deref()
            .is_some_and(|at| at >= cutoff.as_str())
    });
    stale_all.reverse();
    let active_total = active_all.len();
    let stale_total = stale_all.len();
    let active = active_all
        .into_iter()
        .take(limit)
        .map(|record| dashboard_entry(record, &lifecycle_interpreter))
        .collect::<Vec<_>>();
    let stale = stale_all
        .into_iter()
        .take(limit)
        .map(|record| dashboard_entry(record, &lifecycle_interpreter))
        .collect::<Vec<_>>();

    let mut blocked = Vec::new();
    for record in snapshot.records.values().filter(|record| ordinary(record)) {
        let mut blocked_by = snapshot
            .links
            .iter()
            .filter(|link| link.target_id == record.row.id && link.relationship == "blocks")
            .filter(|link| {
                snapshot.records.get(&link.source_id).is_some_and(|other| {
                    other.row.deleted_at.is_none()
                        && !other.archived
                        && !hidden.contains(&other.row.id)
                        && visible.contains(&other.row.id)
                })
            })
            .map(|link| json!({"id":link.source_id,"relationship":"blocks"}))
            .collect::<Vec<_>>();
        let mut waiting_on = snapshot
            .links
            .iter()
            .filter(|link| link.source_id == record.row.id && link.relationship == "depends_on")
            .filter(|link| {
                snapshot.records.get(&link.target_id).is_some_and(|other| {
                    other.row.deleted_at.is_none()
                        && !other.archived
                        && !hidden.contains(&other.row.id)
                        && visible.contains(&other.row.id)
                })
            })
            .map(|link| json!({"id":link.target_id,"relationship":"depends_on"}))
            .collect::<Vec<_>>();
        blocked_by.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
        waiting_on.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
        if blocked_by.is_empty() && waiting_on.is_empty() {
            continue;
        }
        let mut entry = dashboard_entry(record, &lifecycle_interpreter);
        let object = entry.as_object_mut().expect("dashboard entry is an object");
        object.insert("blocked_by".into(), Value::Array(blocked_by));
        object.insert("waiting_on".into(), Value::Array(waiting_on));
        blocked.push(entry);
    }
    blocked.sort_by(|left, right| {
        right["last_activity_at"]
            .as_str()
            .cmp(&left["last_activity_at"].as_str())
            .then(left["id"].as_str().cmp(&right["id"].as_str()))
    });
    let blocked_total = blocked.len();
    blocked.truncate(limit);

    let mut counts: BTreeMap<Option<String>, i64> = BTreeMap::new();
    for record in snapshot.records.values().filter(|record| ordinary(record)) {
        *counts.entry(record.row.lifecycle.clone()).or_insert(0) += 1;
    }
    let mut buckets = counts.into_iter().collect::<Vec<_>>();
    buckets.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    let lifecycle_census = json!({
        "shape":"counts",
        "total":buckets.iter().map(|(_,count)| *count).sum::<i64>(),
        "buckets":buckets.into_iter().map(|(key,count)| json!({"key":key,"count":count})).collect::<Vec<_>>(),
    });
    Ok(json!({
        "scope": args.scope,
        "stale_after_days": stale_after_days,
        "stale_cutoff": cutoff,
        "limit": limit,
        "active": active,
        "active_total": active_total,
        "stale": stale,
        "stale_total": stale_total,
        "blocked": blocked,
        "blocked_total": blocked_total,
        "lifecycle_census": lifecycle_census,
    }))
}

pub(crate) async fn render_record<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "render_record";
    let args: RenderRecordArgs = crate::mcp::tools::parse_args(TOOL, arguments)?;
    if args.include_interpretation.unwrap_or(false) {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "portable-domain",
            "render_record interpretation projection",
        ));
    }
    let records = render_records(executor, &args.id).await?;
    if !records.contains_key(&args.id) {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.id
        )));
    }
    let mut snapshot = SnapshotRows {
        records,
        ..SnapshotRows::default()
    };
    let mut visible = visible_ids(executor, caller, &snapshot).await?;
    if !visible.contains(&args.id) {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.id
        )));
    }
    if snapshot.records[&args.id].row.deleted_at.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.id
        )));
    }
    // The target is already authorized. Hydrate only its owner header now so
    // the canonical post-filter can preserve a caller-visible owner without
    // disclosing or loading unrelated identities before target admission.
    if let Some(owner_id) = snapshot.records[&args.id].row.owner_id.clone() {
        if let Entry::Vacant(entry) = snapshot.records.entry(owner_id.clone()) {
            if let Some(owner) = load_record_header(executor, &owner_id).await? {
                entry.insert(owner);
            }
        }
    }
    snapshot.records.get_mut(&args.id).unwrap().row.body = load_body(executor, &args.id).await?;
    let target = snapshot.records[&args.id].clone();
    let facets = load_facets(executor, &target).await?;
    snapshot.links = load_links(executor, Some(&args.id)).await?;
    // Link rows are selected narrowly around the target. Load only their
    // endpoint headers so link rendering and governed-artifact counts have
    // the canonical names and authorization decisions without materializing
    // every record (or any unrelated body) in the logical database.
    hydrate_link_endpoints(executor, &mut snapshot).await?;
    visible = visible_ids(executor, caller, &snapshot).await?;
    let (hidden, suggestions) = hidden_ids(executor, &snapshot.records).await?;
    let record = &snapshot.records[&args.id];

    let mut links_out = snapshot
        .links
        .iter()
        .filter(|link| {
            link.source_id == args.id
                && visible.contains(&link.target_id)
                && snapshot
                    .records
                    .get(&link.target_id)
                    .is_some_and(|target| target.row.deleted_at.is_none())
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut links_in = snapshot
        .links
        .iter()
        .filter(|link| {
            link.target_id == args.id
                && visible.contains(&link.source_id)
                && snapshot
                    .records
                    .get(&link.source_id)
                    .is_some_and(|source| source.row.deleted_at.is_none())
        })
        .cloned()
        .collect::<Vec<_>>();
    let link_order = |left: &LinkRow, right: &LinkRow| {
        left.relationship
            .cmp(&right.relationship)
            .then(left.created_at.cmp(&right.created_at))
            .then(left.id.cmp(&right.id))
    };
    links_out.sort_by(link_order);
    links_in.sort_by(link_order);
    let links_out_count = links_out.len() as i64;
    let links_in_count = links_in.len() as i64;
    links_out.truncate(read::DEFAULT_ENRICH_LIMIT as usize);
    links_in.truncate(read::DEFAULT_ENRICH_LIMIT as usize);

    let mut children = child_ids(&snapshot.records, &args.id)
        .into_iter()
        .filter(|id| {
            let child = &snapshot.records[*id];
            child.row.deleted_at.is_none() && !hidden.contains(*id) && visible.contains(*id)
        })
        .map(|id| {
            let child = &snapshot.records[id];
            read::ChildSummary {
                id: child.row.id.clone(),
                record_type: child.row.record_type.clone(),
                kind: child.row.kind.clone(),
                name: child.row.name.clone(),
                archived: child.archived,
            }
        })
        .collect::<Vec<_>>();
    let child_count = children.len() as i64;
    children.truncate(read::DEFAULT_ENRICH_LIMIT as usize);
    // Suggestions derive access from this already-authorized bearer, matching
    // the canonical enriched-record contract; their independent filing policy
    // is not another disclosure gate.
    let suggestion_count = snapshot
        .links
        .iter()
        .filter(|link| link.target_id == args.id && link.relationship == "part_of")
        .filter(|link| suggestions.contains(&link.source_id))
        .filter(|link| {
            snapshot
                .records
                .get(&link.source_id)
                .is_some_and(|suggestion| {
                    suggestion.row.deleted_at.is_none() && visible.contains(&suggestion.row.id)
                })
        })
        .count() as i64;

    let mut ancestors = Vec::new();
    let mut current = record.row.home_id.as_deref();
    let mut seen = HashSet::new();
    while let Some(id) = current {
        if !seen.insert(id.to_string()) {
            break;
        }
        let Some(parent) = snapshot.records.get(id) else {
            break;
        };
        if visible.contains(id) {
            ancestors.push(tree::AncestorEntry {
                id: parent.row.id.clone(),
                record_type: parent.row.record_type.clone(),
                kind: parent.row.kind.clone(),
                name: parent.row.name.clone(),
            });
        }
        current = parent.row.home_id.as_deref();
    }
    ancestors.reverse();
    let facets = facets
        .into_iter()
        .filter(|facet| facet.key != crate::schema::ARCHIVED_FACET_KEY)
        .collect::<Vec<_>>();
    let mut record_row = record.row.clone();
    if record_row
        .owner_id
        .as_ref()
        .is_some_and(|owner| !visible.contains(owner))
    {
        record_row.owner_id = None;
    }
    if record_row
        .home_id
        .as_ref()
        .is_some_and(|home| !visible.contains(home))
    {
        record_row.home_id = None;
    }
    let enriched = read::EnrichedRecord {
        record: record_row,
        archived: record.archived,
        custody_boundary: custody_boundary(&snapshot.records, record),
        containment_path_visible: containment_path_visible(&snapshot.records, &visible, &args.id),
        bears_shape: false,
        kind_governance: None,
        facets,
        links_out,
        links_out_count,
        links_in,
        links_in_count,
        children,
        child_count,
        suggestions: None,
        suggestion_count,
        citations: None,
        citation_count: 0,
        comments: None,
        comment_count: 0,
        target: None,
        // The contribution projection is a live-Sqlite read
        // (`contribution::contribution_for_record_in` takes a Sqlite
        // transaction) over `content_events`, and the portable adapters reach
        // their data through source-reviewed statement templates instead.
        // Deliberately absent rather than overlooked, for the same reason
        // `include_interpretation` is refused above: portable adapters do not
        // serve an attribution projection until it is qualified for them.
        // `render_enriched_record_markdown` does not render contribution, so
        // absence here costs this view nothing today.
        contribution: None,
        ancestors,
    };
    let names = snapshot
        .records
        .iter()
        .map(|(id, record)| (id.clone(), record.row.name.clone()))
        .collect::<HashMap<_, _>>();
    Ok(json!({
        "id": args.id,
        "markdown": crate::mcp::tools::lifecycle::render_enriched_record_markdown(&enriched, &names),
    }))
}
