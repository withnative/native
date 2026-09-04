//! `query::cascade` — the pack → user `schema_config` resolver (finding 4),
//! and with it the crate's first READ path on `schema_config`.
//!
//! Sited in stage 1 deliberately: tools 14 (`resolve_facets`), 15
//! (`suggest_facet_values`) and 21 (`manage_schema_config`, rejection (a)) are
//! all consumers and none depends on another — building the resolver once here
//! is what keeps it from falling between stages.
//!
//! The v1 cascade is TWO layers, closest-wins (3057bba): user over pack, merged
//! per type and per facet key. An anchored row applies only to direct children
//! of `applies_to_collection_id`; it is never inherited through a subtree.
//! [`ResolvedCascade`] returns the pack view and the resolved view side by
//! side, because rejection (a) ("looser than pack", the interop floor) is a
//! judgement BETWEEN the two — a consumer with only the merged result could
//! not make it.

use serde::Serialize;
use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::db::Db;
use crate::error::Result;
use crate::meta::kind::list_active_on;
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, LogicalType,
    NormalizedValue, StatementKind, StatementTemplate,
};
use crate::schema::SPINE_TYPES;

use super::error::contract_violation;

/// A `schema_config` row, as read back. `data` is parsed JSON.
#[derive(Debug, Clone, Serialize)]
pub struct SchemaConfigRow {
    pub id: String,
    pub layer: String,
    pub name: Option<String>,
    pub data: Value,
    pub applies_to_collection_id: Option<String>,
    pub version_lineage: Option<String>,
    pub created_at: String,
}

/// The resolved two-layer cascade.
#[derive(Debug, Serialize)]
pub struct ResolvedCascade {
    /// The pack layer alone, merged: `{ shapes: { <type>: … } }`.
    pub pack: Value,
    /// Pack overlaid by user, closest-wins per type/kinds/facet-key — the
    /// effective shape the engine answers with.
    pub resolved: Value,
}

/// Read `schema_config` rows, optionally one layer. Rows come back in
/// application order (pack first, then user, `created_at` then id within a
/// layer) — the order [`resolve`] folds them in.
pub(crate) async fn schema_config_rows_in_pool(
    pool: &sqlx::SqlitePool,
    layer: Option<&str>,
) -> Result<Vec<SchemaConfigRow>> {
    if let Some(layer) = layer {
        if layer != "pack" && layer != "user" {
            return Err(contract_violation(format!(
                "schema_config layer must be 'pack' or 'user', got '{layer}'"
            )));
        }
    }
    let mut snapshot = pool.begin().await?;
    let result = {
        let mut executor = BorrowedSqliteStatementExecutor::new(&mut snapshot);
        schema_config_rows_with_layer(&mut executor, layer).await
    };
    match result {
        Ok(rows) => {
            snapshot.rollback().await?;
            Ok(rows)
        }
        Err(primary) => {
            let _ = snapshot.rollback().await;
            Err(primary)
        }
    }
}

pub async fn schema_config_rows(db: &Db, layer: Option<&str>) -> Result<Vec<SchemaConfigRow>> {
    if let Some(layer) = layer {
        if layer != "pack" && layer != "user" {
            return Err(contract_violation(format!(
                "schema_config layer must be 'pack' or 'user', got '{layer}'"
            )));
        }
    }
    let mut snapshot = db.write_pool().begin().await?;
    let result = {
        let mut executor = BorrowedSqliteStatementExecutor::new(&mut snapshot);
        schema_config_rows_with_layer(&mut executor, layer).await
    };
    match result {
        Ok(rows) => {
            snapshot.rollback().await?;
            Ok(rows)
        }
        Err(primary) => {
            let _ = snapshot.rollback().await;
            Err(primary)
        }
    }
}

/// Read schema rows through the live caller-authorization boundary. Global
/// rows are public governance; an anchored row is visible only when its bearer
/// is viewable by `principal`. `None` is the explicit trusted-local/internal
/// compatibility path.
pub async fn schema_config_rows_for_principal(
    db: &Db,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<SchemaConfigRow>> {
    schema_config_rows_for_principal_in_pool(db.write_pool(), principal).await
}

pub(crate) async fn schema_config_rows_for_principal_in_pool(
    pool: &sqlx::SqlitePool,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<SchemaConfigRow>> {
    let rows = schema_config_rows_in_pool(pool, None).await?;
    let Some(principal) = principal else {
        return Ok(rows);
    };
    let mut bearer_visibility = HashMap::new();
    let mut visible = Vec::with_capacity(rows.len());
    for row in rows {
        let allowed = match row.applies_to_collection_id.as_deref() {
            None => true,
            Some(bearer) => match bearer_visibility.get(bearer) {
                Some(allowed) => *allowed,
                None => {
                    let allowed =
                        crate::authorization::effective_capability_in_pool(pool, principal, bearer)
                            .await
                            .is_ok_and(|capability| {
                                capability.allows(crate::authorization::Capability::View)
                            });
                    bearer_visibility.insert(bearer.to_string(), allowed);
                    allowed
                }
            },
        };
        if allowed {
            visible.push(row);
        }
    }
    Ok(visible)
}

/// Transaction-scoped equivalent used when record authorization and schema
/// interpretation must share one SQLite snapshot.
pub(crate) async fn schema_config_rows_for_principal_on(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<SchemaConfigRow>> {
    let rows = schema_config_rows_in(tx).await?;
    let Some(principal) = principal else {
        return Ok(rows);
    };
    let mut bearer_visibility = HashMap::new();
    let mut visible = Vec::with_capacity(rows.len());
    for row in rows {
        let allowed = match row.applies_to_collection_id.as_deref() {
            None => true,
            Some(bearer) => match bearer_visibility.get(bearer) {
                Some(allowed) => *allowed,
                None => {
                    let allowed =
                        crate::authorization::effective_capability_on(tx, principal, bearer)
                            .await
                            .is_ok_and(|capability| {
                                capability.allows(crate::authorization::Capability::View)
                            });
                    bearer_visibility.insert(bearer.to_string(), allowed);
                    allowed
                }
            },
        };
        if allowed {
            visible.push(row);
        }
    }
    Ok(visible)
}

/// Overlay `layer`'s shapes onto `base`, closest-wins: per type, `kinds`
/// replaces wholesale and `facets` merges per key (the overlaying key wins
/// wholesale — facet shapes are units, not deep-merged).
fn overlay_shapes(base: &mut Map<String, Value>, layer: &Value) {
    let Some(shapes) = layer.get("shapes").and_then(Value::as_object) else {
        return;
    };
    for (shape_type, shape) in shapes {
        let target = base
            .entry(shape_type.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(target) = target.as_object_mut() else {
            continue;
        };
        if let Some(kinds) = shape.get("kinds") {
            target.insert("kinds".into(), kinds.clone());
        }
        if let Some(facets) = shape.get("facets").and_then(Value::as_object) {
            let merged = target
                .entry("facets")
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(merged) = merged.as_object_mut() {
                for (key, facet_shape) in facets {
                    merged.insert(key.clone(), facet_shape.clone());
                }
            }
        }
        // Any other shape-level keys: overlaying layer wins wholesale.
        for (key, value) in shape.as_object().into_iter().flatten() {
            if key != "kinds" && key != "facets" {
                target.insert(key.clone(), value.clone());
            }
        }
    }
}

fn shapes_value(map: Map<String, Value>) -> Value {
    let mut root = Map::new();
    root.insert("shapes".into(), Value::Object(map));
    Value::Object(root)
}

/// Fold already-fetched rows into the two-layer cascade. Rows with
/// `applies_to_collection_id` set are skipped (subtree overlays are v1-deferred,
/// 3057bba).
///
/// The fold is pure and order-sensitive: `rows` must be in the application order
/// [`schema_config_rows`] returns (pack before user). Exposed separately from
/// [`resolve`] so a caller that needs BOTH the cascade and the rows themselves —
/// `manage_schema_config`'s read arm — can derive them from one fetch instead of
/// two independent reads that a concurrent direct write could interleave.
pub fn resolve_from_rows(rows: &[SchemaConfigRow]) -> ResolvedCascade {
    let mut pack = Map::new();
    let mut resolved = Map::new();
    for row in rows.iter().filter(|r| r.applies_to_collection_id.is_none()) {
        if row.layer == "pack" {
            overlay_shapes(&mut pack, &row.data);
        }
        overlay_shapes(&mut resolved, &row.data);
    }
    ResolvedCascade {
        pack: shapes_value(pack),
        resolved: shapes_value(resolved),
    }
}

/// Resolve the two-layer cascade: fetch every row, then [`resolve_from_rows`].
pub async fn resolve(db: &Db) -> Result<ResolvedCascade> {
    let rows = schema_config_rows(db, None).await?;
    let mut resolved = resolve_from_rows(&rows);
    let mut conn = db.write_pool().acquire().await?;
    inject_kind_projection_on(&mut conn, &mut resolved.resolved).await?;
    Ok(resolved)
}

/// Inject the read-only compatibility projection from the authoritative kind
/// registry. Stored `shapes[T].kinds` values are ignored/overwritten.
pub async fn inject_kind_projection_on(
    conn: &mut sqlx::SqliteConnection,
    view: &mut Value,
) -> Result<()> {
    let root = view
        .as_object_mut()
        .expect("resolved cascade root is an object");
    let shapes = root
        .entry("shapes")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("resolved shapes is an object");
    for record_type in SPINE_TYPES {
        let kinds: Vec<Value> = list_active_on(conn, record_type)
            .await?
            .into_iter()
            .map(|kind| Value::String(kind.token))
            .collect();
        let shape = shapes
            .entry(record_type.to_string())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("base shape is an object");
        shape.insert("kinds".into(), Value::Array(kinds));
    }
    Ok(())
}

/// Read the ordered cascade rows through a caller-owned write transaction.
/// Schema authoring uses the rows themselves to calculate the prospective
/// overlay, so returning them avoids escaping to a second pool connection and
/// snapshot before the declaration is appended.
pub(crate) async fn schema_config_rows_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<SchemaConfigRow>> {
    let mut executor = BorrowedSqliteStatementExecutor::new(tx);
    schema_config_rows_with(&mut executor).await
}

pub(crate) async fn schema_config_rows_with<E: DomainStatementExecutor>(
    executor: &mut E,
) -> Result<Vec<SchemaConfigRow>> {
    schema_config_rows_with_layer(executor, None).await
}

async fn schema_config_rows_with_layer<E: DomainStatementExecutor>(
    executor: &mut E,
    layer: Option<&str>,
) -> Result<Vec<SchemaConfigRow>> {
    let statement = if layer.is_some() {
        StatementTemplate::new(
            StatementKind::Select,
            "schema_config",
            &[
                "SELECT id, layer, name, data, applies_to_collection_id, version_lineage, created_at FROM {{relation}} WHERE layer = ",
                " ORDER BY CASE layer WHEN 'pack' THEN 0 ELSE 1 END, created_at, id",
            ],
        )
    } else {
        StatementTemplate::new(
            StatementKind::Select,
            "schema_config",
            &[
                "SELECT id, layer, name, data, applies_to_collection_id, version_lineage, created_at FROM {{relation}} ORDER BY CASE layer WHEN 'pack' THEN 0 ELSE 1 END, created_at, id",
            ],
        )
    }
    .map_err(|error| {
        contract_violation(format!("read schema config: {}", error.stable_message()))
    })?;
    let bindings = layer
        .map(|layer| vec![BindValue::Text(layer.into())])
        .unwrap_or_default();
    let rows = executor
        .fetch_all(
            &statement,
            &bindings,
            &[
                ColumnSpec::required("id", LogicalType::Text),
                ColumnSpec::required("layer", LogicalType::Text),
                ColumnSpec::nullable("name", LogicalType::Text),
                ColumnSpec::required("data", LogicalType::Text),
                ColumnSpec::nullable("applies_to_collection_id", LogicalType::Text),
                ColumnSpec::nullable("version_lineage", LogicalType::Text),
                ColumnSpec::required("created_at", LogicalType::Text),
            ],
        )
        .await
        .map_err(|error| {
            contract_violation(format!("read schema config: {}", error.stable_message()))
        })?;
    rows.into_iter()
        .map(|row| {
            let required = |column: &str| match row.get(column) {
                Some(NormalizedValue::Text(value)) => Ok(value.clone()),
                _ => Err(contract_violation(format!(
                    "schema_config state column '{column}' is invalid"
                ))),
            };
            let optional = |column: &str| match row.get(column) {
                Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
                Some(NormalizedValue::Null) => Ok(None),
                _ => Err(contract_violation(format!(
                    "schema_config state column '{column}' is invalid"
                ))),
            };
            let id = required("id")?;
            let raw = required("data")?;
            let data = serde_json::from_str(&raw).map_err(|_| {
                contract_violation(format!(
                    "schema_config row '{id}' carries invalid JSON data"
                ))
            })?;
            Ok(SchemaConfigRow {
                id,
                layer: required("layer")?,
                name: optional("name")?,
                data,
                applies_to_collection_id: optional("applies_to_collection_id")?,
                version_lineage: optional("version_lineage")?,
                created_at: required("created_at")?,
            })
        })
        .collect()
}

/// Merge the base-type and optional kind-specific facet maps from one cascade
/// view. Base lands first and kind lands second, so specificity outranks layer:
/// the already-folded shape keys produce pack:T → user:T → pack:T:k → user:T:k.
///
/// This is the single read-time merge used by every cascade consumer. The
/// per-shape-key fold in [`resolve_from_rows`] deliberately stays unchanged.
pub fn facets_for_type(view: &Value, record_type: &str, kind: Option<&str>) -> Map<String, Value> {
    let facets_at = |shape_key: &str| {
        view.get("shapes")
            .and_then(|s| s.get(shape_key))
            .and_then(|t| t.get("facets"))
            .and_then(Value::as_object)
    };
    let mut facets = facets_at(record_type).cloned().unwrap_or_default();
    if let Some(kind) = kind {
        let shape_key = format!("{record_type}:{kind}");
        if let Some(kind_facets) = facets_at(&shape_key) {
            for (key, shape) in kind_facets {
                facets.insert(key.clone(), shape.clone());
            }
        }
    }
    facets
}

/// Apply the facet declarations for one exact shape key from rows in their
/// deterministic application order. `bearer_id = None` selects global rows;
/// `Some` selects rows anchored to that exact record. No ancestor walk occurs.
fn overlay_facet_slot(
    target: &mut Map<String, Value>,
    rows: &[SchemaConfigRow],
    bearer_id: Option<&str>,
    layer: &str,
    shape_key: &str,
) {
    for row in rows
        .iter()
        .filter(|row| row.layer == layer && row.applies_to_collection_id.as_deref() == bearer_id)
    {
        let Some(facets) = row
            .data
            .get("shapes")
            .and_then(|shapes| shapes.get(shape_key))
            .and_then(|shape| shape.get("facets"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        for (key, shape) in facets {
            target.insert(key.clone(), shape.clone());
        }
    }
}

fn overlay_shape_property_slot(
    target: &mut Option<Value>,
    rows: &[SchemaConfigRow],
    bearer_id: Option<&str>,
    layer: &str,
    shape_key: &str,
    property: &str,
) {
    for row in rows
        .iter()
        .filter(|row| row.layer == layer && row.applies_to_collection_id.as_deref() == bearer_id)
    {
        if let Some(value) = row
            .data
            .get("shapes")
            .and_then(|shapes| shapes.get(shape_key))
            .and_then(|shape| shape.get(property))
        {
            *target = Some(value.clone());
        }
    }
}

/// Resolve one shape-level property (currently used for `kinds`) at base
/// specificity for a direct-member context.
pub fn shape_property_for_record_context(
    rows: &[SchemaConfigRow],
    record_type: &str,
    bearer_id: Option<&str>,
    property: &str,
) -> Option<Value> {
    let mut value = None;
    for layer in ["pack", "user"] {
        overlay_shape_property_slot(&mut value, rows, None, layer, record_type, property);
    }
    if let Some(bearer_id) = bearer_id {
        for layer in ["pack", "user"] {
            overlay_shape_property_slot(
                &mut value,
                rows,
                Some(bearer_id),
                layer,
                record_type,
                property,
            );
        }
    }
    value
}

/// Resolve facets for one record context. The optional bearer is the record's
/// direct home folder, supplied by the caller after exactly one record lookup.
///
/// The order is intentionally written out: specificity outranks layer within
/// a scope, and bearer scope outranks every global slot:
/// global pack:T -> user:T -> pack:T:k -> user:T:k -> bearer pack:T ->
/// user:T -> pack:T:k -> user:T:k.
pub fn facets_for_record_context(
    rows: &[SchemaConfigRow],
    record_type: &str,
    kind: Option<&str>,
    bearer_id: Option<&str>,
) -> Map<String, Value> {
    let mut facets = Map::new();
    let kind_key = kind.map(|kind| format!("{record_type}:{kind}"));
    for layer in ["pack", "user"] {
        overlay_facet_slot(&mut facets, rows, None, layer, record_type);
    }
    if let Some(kind_key) = kind_key.as_deref() {
        for layer in ["pack", "user"] {
            overlay_facet_slot(&mut facets, rows, None, layer, kind_key);
        }
    }
    if let Some(bearer_id) = bearer_id {
        for layer in ["pack", "user"] {
            overlay_facet_slot(&mut facets, rows, Some(bearer_id), layer, record_type);
        }
        if let Some(kind_key) = kind_key.as_deref() {
            for layer in ["pack", "user"] {
                overlay_facet_slot(&mut facets, rows, Some(bearer_id), layer, kind_key);
            }
        }
    }
    facets
}

/// The pack-only interop floor for one record context. Scope remains more
/// specific than kind: a bearer pack:T declaration out-ranks global pack:T:k.
pub fn pack_facets_for_record_context(
    rows: &[SchemaConfigRow],
    record_type: &str,
    kind: Option<&str>,
    bearer_id: Option<&str>,
) -> Map<String, Value> {
    let mut facets = Map::new();
    overlay_facet_slot(&mut facets, rows, None, "pack", record_type);
    if let Some(kind) = kind {
        overlay_facet_slot(
            &mut facets,
            rows,
            None,
            "pack",
            &format!("{record_type}:{kind}"),
        );
    }
    if let Some(bearer_id) = bearer_id {
        overlay_facet_slot(&mut facets, rows, Some(bearer_id), "pack", record_type);
        if let Some(kind) = kind {
            overlay_facet_slot(
                &mut facets,
                rows,
                Some(bearer_id),
                "pack",
                &format!("{record_type}:{kind}"),
            );
        }
    }
    facets
}

fn provenance_slot(
    target: &mut Map<String, Value>,
    rows: &[SchemaConfigRow],
    bearer_id: Option<&str>,
    layer: &str,
    shape_key: &str,
) {
    for row in rows
        .iter()
        .filter(|row| row.layer == layer && row.applies_to_collection_id.as_deref() == bearer_id)
    {
        let Some(facets) = row
            .data
            .get("shapes")
            .and_then(|shapes| shapes.get(shape_key))
            .and_then(|shape| shape.get("facets"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        for key in facets.keys() {
            let source = match bearer_id {
                Some(bearer_id) => serde_json::json!({
                    "bearer_id": bearer_id,
                    "schema_row_id": row.id,
                    "layer": row.layer,
                    "shape_key": shape_key,
                }),
                None => Value::String(format!("{}:{shape_key}", row.layer)),
            };
            target.insert(key.clone(), source);
        }
    }
}

/// Provenance matching [`facets_for_record_context`]. Global sources retain
/// the established compact spelling; anchored sources expose the bearer and
/// schema-row identities required to explain the record-specific overlay.
pub fn provenance_for_record_context(
    rows: &[SchemaConfigRow],
    record_type: &str,
    kind: Option<&str>,
    bearer_id: Option<&str>,
) -> Map<String, Value> {
    let mut provenance = Map::new();
    let kind_key = kind.map(|kind| format!("{record_type}:{kind}"));
    for layer in ["pack", "user"] {
        provenance_slot(&mut provenance, rows, None, layer, record_type);
    }
    if let Some(kind_key) = kind_key.as_deref() {
        for layer in ["pack", "user"] {
            provenance_slot(&mut provenance, rows, None, layer, kind_key);
        }
    }
    if let Some(bearer_id) = bearer_id {
        for layer in ["pack", "user"] {
            provenance_slot(&mut provenance, rows, Some(bearer_id), layer, record_type);
        }
        if let Some(kind_key) = kind_key.as_deref() {
            for layer in ["pack", "user"] {
                provenance_slot(&mut provenance, rows, Some(bearer_id), layer, kind_key);
            }
        }
    }
    provenance
}

/// Whether `bearer_id` actually contributes an anchored shape declaration for
/// this type/kind. This drives the record-only `shape_bearer_id` response.
pub fn scope_supplies_shape(
    rows: &[SchemaConfigRow],
    record_type: &str,
    kind: Option<&str>,
    bearer_id: &str,
) -> bool {
    let kind_key = kind.map(|kind| format!("{record_type}:{kind}"));
    rows.iter().any(|row| {
        row.applies_to_collection_id.as_deref() == Some(bearer_id)
            && row.data.get("shapes").is_some_and(|shapes| {
                shapes.get(record_type).is_some_and(Value::is_object)
                    || kind_key.as_deref().is_some_and(|shape_key| {
                        shapes.get(shape_key).is_some_and(Value::is_object)
                    })
            })
    })
}

/// Derived capability predicate: no stored flag, only the existence of a
/// schema declaration currently anchored to this record.
pub fn bears_shape_from_rows(rows: &[SchemaConfigRow], record_id: &str) -> bool {
    rows.iter()
        .any(|row| row.applies_to_collection_id.as_deref() == Some(record_id))
}

/// Database form of [`bears_shape_from_rows`] for record reads that do not
/// already own a coherent schema-row snapshot.
pub(crate) async fn bears_shape_in_pool(pool: &sqlx::SqlitePool, record_id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM schema_config WHERE applies_to_collection_id = ?)",
    )
    .bind(record_id)
    .fetch_one(pool)
    .await?)
}

pub async fn bears_shape(db: &Db, record_id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM schema_config WHERE applies_to_collection_id = ?)",
    )
    .bind(record_id)
    .fetch_one(db.write_pool())
    .await?)
}

/// Kind-specific shape names available for `record_type`, sorted for a stable
/// tool response. This enumerates shapes, not every value allowed by `kinds`.
pub fn kind_shapes(view: &Value, record_type: &str) -> Vec<String> {
    let prefix = format!("{record_type}:");
    let mut kinds: Vec<String> = view
        .get("shapes")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|shapes| shapes.keys())
        .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
        .collect();
    kinds.sort();
    kinds.dedup();
    kinds
}

/// Resolve which shape supplied each effective facet key. Equal-specificity
/// rows follow normal application order; kind provenance then overlays base
/// provenance to match [`facets_for_type`].
pub fn provenance_for_type(
    rows: &[SchemaConfigRow],
    record_type: &str,
    kind: Option<&str>,
) -> Map<String, Value> {
    let provenance_at = |shape_key: &str| {
        let mut provenance = Map::new();
        for row in rows
            .iter()
            .filter(|row| row.applies_to_collection_id.is_none())
        {
            let Some(facets) = row
                .data
                .get("shapes")
                .and_then(|s| s.get(shape_key))
                .and_then(|shape| shape.get("facets"))
                .and_then(Value::as_object)
            else {
                continue;
            };
            for key in facets.keys() {
                provenance.insert(
                    key.clone(),
                    Value::String(format!("{}:{shape_key}", row.layer)),
                );
            }
        }
        provenance
    };

    let mut provenance = provenance_at(record_type);
    if let Some(kind) = kind {
        let shape_key = format!("{record_type}:{kind}");
        for (key, source) in provenance_at(&shape_key) {
            provenance.insert(key, source);
        }
    }
    provenance
}

/// Resolve the cascade as it would look after the incoming user row is
/// inserted or replaces its existing row. Used by write-time validation so a
/// single schema write can validate a kind-specific shape against the kind
/// registry and the rest of the prospective schema cascade.
pub fn resolve_after_user_write(
    rows: &[SchemaConfigRow],
    replacing_id: Option<&str>,
    data: &Value,
) -> ResolvedCascade {
    resolve_from_rows(&rows_after_user_write(rows, replacing_id, data, None))
}

/// Rows as they would look after a full-row user upsert. Record-scoped schema
/// authoring uses this to validate the same contextual cascade that will be
/// visible after projection.
pub(crate) fn rows_after_user_write(
    rows: &[SchemaConfigRow],
    replacing_id: Option<&str>,
    data: &Value,
    applies_to_collection_id: Option<&str>,
) -> Vec<SchemaConfigRow> {
    let mut prospective = rows.to_vec();
    let mut replaced = false;
    if let Some(id) = replacing_id {
        if let Some(row) = prospective
            .iter_mut()
            .find(|row| row.id == id && row.layer == "user")
        {
            row.data = data.clone();
            row.applies_to_collection_id = applies_to_collection_id.map(String::from);
            replaced = true;
        }
    }
    if !replaced {
        prospective.push(SchemaConfigRow {
            id: replacing_id.unwrap_or("<prospective-user-row>").to_string(),
            layer: "user".into(),
            name: None,
            data: data.clone(),
            applies_to_collection_id: applies_to_collection_id.map(String::from),
            version_lineage: None,
            created_at: String::new(),
        });
    }
    prospective
}

/// The resolved facet-shape map for one spine type and optional kind:
/// `{ <facet_key>: shape }`, empty if the cascade shapes nothing for it.
pub async fn resolve_for_type(
    db: &Db,
    record_type: &str,
    kind: Option<&str>,
) -> Result<Map<String, Value>> {
    let cascade = resolve(db).await?;
    Ok(facets_for_type(&cascade.resolved, record_type, kind))
}

/// The governing vocabulary for a facet key on a type and optional kind, if
/// the resolved shape names one (`vocab` / `vocab_ref` on the facet shape) —
/// the resolution tool 15 (`suggest_facet_values`) needs.
pub async fn governing_vocab(
    db: &Db,
    record_type: &str,
    kind: Option<&str>,
    facet_key: &str,
) -> Result<Option<String>> {
    let facets = resolve_for_type(db, record_type, kind).await?;
    Ok(facets.get(facet_key).and_then(|shape| {
        shape
            .get("vocab")
            .or_else(|| shape.get("vocab_ref"))
            .and_then(Value::as_str)
            .map(String::from)
    }))
}
