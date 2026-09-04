//! `schema_config` write auth — the system/meta-tier write API for the two-layer
//! shape cascade (pack -> user, 3057bba). EVENT-PROJECTED off `meta_events`
//! since decision ba9f97e; both write paths below are append-then-fold.
//!
//! `version_lineage` is unaffected and stays what it always was: the compat chain
//! for schema evolution, which is a different clock from the log. 982f4b2
//! mandated exactly this pairing — a meta history "distinct from the content
//! Event log" — and shipped only the lineage column; the log is the other half
//! finally arriving, not a replacement for it.
//!
//! This module carries the contract guard `manage_schema_config` promises
//! (docs/tool-surface.md, tool 21 rejection (b); Native task e035091 guard 2):
//!
//!   - **Engine-reserved facet keys are not user-configurable at all, in EITHER
//!     direction** — `archived` is the only reserved key in v1. Tightening is as
//!     breaking as loosening: `archive_record` writes the value itself, the
//!     projector fixes its representation (`'true'` archives, UNSET restores,
//!     anything else is refused) and default queries hard-dispatch on it, so
//!     ANY user shape over the key describes data the engine wholly owns. Note
//!     what that does and does not mean: no write path reads `schema_config`,
//!     so a user shape cannot block an engine write — it makes the resolved
//!     view contradict an invariant enforced here, which is why the guard sits
//!     with the key's owner. This is a stronger claim than the spine-facet
//!     rule (rejection (a), the interop floor): spine facets stay configurable
//!     but cannot be LOOSENED; reserved keys cannot be configured at all.
//!
//! Rejection (a) — spine-facet loosening — needs the resolved cascade to judge
//! "looser than pack", so it lands with the `resolve_facets` cascade resolver,
//! not here. Tracked on the tool build; noted so this file doesn't read as the
//! complete write-auth surface.

use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::meta::log::{append_meta_in, MetaAppendSpec};
use crate::schema::{ENGINE_RESERVED_FACET_KEYS, SPINE_FACET_KEYS};

/// Stable name and contents of the engine's recommended defaults pack.
///
/// The startup wiring lives separately; keeping the payload here gives that
/// path and direct seeder tests one canonical source. Kind membership lives in
/// the authoritative `kind:<Type>` registries, not in this shape payload.
pub const RECOMMENDED_PACK_NAME: &str = "@native/recommended";

pub fn recommended_pack_schema_config() -> Value {
    json!({
        "shapes": {
            // Per type-and-kind, so this one binding covers roots AND replies.
            // It must stay `required: false`: a reply's lifecycle is null by
            // rule, and the legacy pre-naming roots still carry null too.
            "Annotation:comment": {
                "facets": {
                    "lifecycle": {
                        "axis": { "key": "thread_state", "label": "Thread state" },
                        "vocab_ref": "comment-lifecycle",
                        "required": false
                    }
                }
            },
            // An exploration is an ordinary VISIBLE collection, not hidden
            // metadata. The namespaced key avoids colliding with unrelated
            // future uses of a globally indexed bare `selection_role`, and the
            // vocabulary governs which roles exist at all.
            "Collection:selection": {
                "facets": {
                    "decision.selection_role": {
                        "vocab_ref": "selection-role",
                        "required": false
                    }
                }
            },
            "Annotation:suggestion": {
                "facets": {
                    "proposal.precondition": {
                        "values": ["none", "span", "digest", "field_equals", "seq"],
                        "required": true
                    },
                    "anchor.old": {},
                    "anchor.base_digest": {},
                    "lifecycle": {
                        "axis": { "key": "proposal_disposition", "label": "Suggestion disposition" },
                        "vocab_ref": "suggestion-lifecycle",
                        "required": true
                    }
                }
            },
            "Document:definition": {
                "facets": {
                    "term": { "vocab_ref": "glossary", "required": true }
                }
            },
            "Document:artifact": {
                "facets": {
                    "runtime": { "vocab_ref": "artifact-runtime", "required": true }
                }
            },
            "Message": {
                "facets": {
                    "expectation": {
                        "vocab_ref": "message-expectation",
                        "required": true
                    }
                }
            },
            "Outcome:impact": {
                "facets": {
                    "impact": {
                        "type": "object",
                        "required": true,
                        "json_schema": {
                            "$schema": "https://json-schema.org/draft/2020-12/schema",
                            "type": "object",
                            "properties": {
                                "claim": {
                                    "type": "string",
                                    "pattern": "\\S"
                                },
                                "method": {
                                    "type": "string",
                                    "enum": ["declared", "derived"]
                                },
                                "effective_at": {
                                    "type": "string",
                                    "oneOf": [
                                        { "format": "date" },
                                        { "format": "date-time" }
                                    ]
                                },
                                "magnitude": {
                                    "type": "object",
                                    "properties": {
                                        "value": { "type": "number" },
                                        "unit": {
                                            "type": "string",
                                            "pattern": "\\S"
                                        },
                                        "per": {
                                            "type": "string",
                                            "pattern": "\\S"
                                        }
                                    },
                                    "required": ["value", "unit"],
                                    "additionalProperties": false
                                },
                                "measurement_window": {
                                    "type": "object",
                                    "properties": {
                                        "start": {
                                            "type": "string",
                                            "oneOf": [
                                                { "format": "date" },
                                                { "format": "date-time" }
                                            ]
                                        },
                                        "end": {
                                            "type": "string",
                                            "oneOf": [
                                                { "format": "date" },
                                                { "format": "date-time" }
                                            ]
                                        }
                                    },
                                    "required": ["start", "end"],
                                    "additionalProperties": false
                                }
                            },
                            "required": ["claim", "method", "effective_at"],
                            "additionalProperties": false
                        },
                        "temporal_order": [
                            {
                                "earlier": "measurement_window.start",
                                "later": "measurement_window.end"
                            }
                        ]
                    }
                }
            },
            "Program:module": {
                "facets": {
                    "runtime": { "vocab_ref": "artifact-runtime", "required": true }
                }
            },
            "Program:recipe": {
                "facets": {
                    "runtime": { "vocab_ref": "recipe-runtime", "required": true }
                }
            },
            "WorkItem:task": {
                "facets": {
                    "lifecycle": {
                        "axis": { "key": "work_status", "label": "Work status" },
                        "vocab_ref": "lifecycle",
                        "required": true
                    }
                }
            },
            "WorkItem:epic": {
                "facets": {
                    "lifecycle": {
                        "axis": { "key": "work_status", "label": "Work status" },
                        "vocab_ref": "lifecycle",
                        "required": true
                    }
                }
            }
        }
    })
}

/// Validate authored lifecycle-axis descriptors.
///
/// A lifecycle declaration becomes governed when it names `vocab` or
/// `vocab_ref`; governed declarations must say which domain question that
/// vocabulary answers. Axis descriptors are deliberately small and open:
/// their keys are not drawn from an engine enum, but both key and default
/// label must be nonblank strings and no uninterpreted extension members are
/// accepted in v1.
pub fn assert_valid_lifecycle_axes(data: &Value) -> Result<()> {
    let Some(shapes) = data.get("shapes").and_then(Value::as_object) else {
        return Ok(());
    };
    for (shape_key, shape) in shapes {
        let Some(lifecycle) = shape
            .get("facets")
            .and_then(Value::as_object)
            .and_then(|facets| facets.get("lifecycle"))
        else {
            continue;
        };
        let governed = lifecycle.get("vocab").is_some() || lifecycle.get("vocab_ref").is_some();
        let Some(axis) = lifecycle.get("axis") else {
            if governed {
                return Err(Error::engine(format!(
                    "governed lifecycle facet on shape '{shape_key}' requires axis with exactly nonblank string key and label"
                )));
            }
            continue;
        };
        let Some(axis) = axis.as_object() else {
            return Err(Error::engine(format!(
                "lifecycle axis on shape '{shape_key}' must be an object with exactly nonblank string key and label"
            )));
        };
        let valid_members = axis.len() == 2
            && ["key", "label"].into_iter().all(|member| {
                axis.get(member)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
            });
        if !valid_members {
            return Err(Error::engine(format!(
                "lifecycle axis on shape '{shape_key}' must contain exactly nonblank string key and label"
            )));
        }
    }
    Ok(())
}

/// `schema_config.data` input: a JSON object (`{ shapes: { <type>: { kinds,
/// facets } } }`) or raw JSON text.
#[derive(Debug, Clone)]
pub enum SchemaConfigData {
    Json(Value),
    Text(String),
}

impl From<Value> for SchemaConfigData {
    fn from(value: Value) -> Self {
        SchemaConfigData::Json(value)
    }
}

impl From<&str> for SchemaConfigData {
    fn from(value: &str) -> Self {
        SchemaConfigData::Text(value.to_string())
    }
}

impl From<String> for SchemaConfigData {
    fn from(value: String) -> Self {
        SchemaConfigData::Text(value)
    }
}

/// Options for the schema_config write paths.
#[derive(Debug, Clone, Default)]
pub struct SchemaConfigOptions {
    pub id: Option<String>,
    pub version_lineage: Option<String>,
    /// Optional direct-member anchor. The frozen column name says collection,
    /// but any record may bear a shape; no typehood claim is made here.
    pub applies_to_collection_id: Option<String>,
}

/// Error if the config data mentions an engine-reserved facet key. Direction-
/// agnostic by construction: the guard rejects the key's PRESENCE in any shape,
/// so there is no "tightening is fine" loophole.
pub fn assert_no_reserved_facet_keys(data: &Value) -> Result<()> {
    let shapes = data.get("shapes").and_then(Value::as_object);
    for (shape_type, shape) in shapes.into_iter().flatten() {
        let facets = shape.get("facets").and_then(Value::as_object);
        for key in facets.into_iter().flat_map(|f| f.keys()) {
            if ENGINE_RESERVED_FACET_KEYS.contains(&key.as_str()) {
                return Err(Error::engine(format!(
                    "cannot configure engine-reserved facet key '{key}' (shape '{shape_type}'): reserved keys are not user-configurable in either direction — the engine writes and dispatches on them (archive_record / default queries)"
                )));
            }
        }
    }
    Ok(())
}

/// Refuse a declared type on a spine facet from every schema layer. V1's
/// sanctioned spine carriers are strings, so accepting `type: "number"` would
/// make the resolved view advertise a promise no supported write can honour.
pub fn assert_no_spine_declared_types(data: &Value) -> Result<()> {
    let shapes = data.get("shapes").and_then(Value::as_object);
    for (shape_type, shape) in shapes.into_iter().flatten() {
        let facets = shape.get("facets").and_then(Value::as_object);
        for (key, facet) in facets.into_iter().flatten() {
            if SPINE_FACET_KEYS.contains(&key.as_str()) && facet.get("type").is_some() {
                return Err(Error::engine(format!(
                    "cannot configure declared type on spine facet '{key}' (shape '{shape_type}'): v1 spine arguments are string carriers, so no numeric type promise can be enforced there; omit `type` until a typed spine carrier exists"
                )));
            }
        }
    }
    Ok(())
}

/// Kind membership is governed through `manage_vocabularies`. Shape config may
/// continue to own `T:k` facet shapes, but may not author a second registry.
pub fn assert_no_authored_kind_arrays(data: &Value) -> Result<()> {
    let Some(shapes) = data.get("shapes").and_then(Value::as_object) else {
        return Ok(());
    };
    for (shape_key, shape) in shapes {
        if !shape_key.contains(':') && shape.get("kinds").is_some() {
            return Err(Error::engine(format!(
                "cannot author shapes['{shape_key}'].kinds: kind:<Type> vocabularies are authoritative; propose and promote values with manage_vocabularies instead"
            )));
        }
    }
    Ok(())
}

/// Message expectation is protocol content, not a user-shaped extension. The
/// recommended pack advertises the exact floor enforced by local and
/// federated creation, so allowing a user or anchored row to replace this one
/// facet would make schema introspection lie about the wire contract.
///
/// Omission is the supported way to inherit the pack declaration. The key
/// remains ordinary and configurable on every non-Message record type.
pub fn assert_no_message_expectation_overrides(data: &Value) -> Result<()> {
    let Some(shapes) = data.get("shapes").and_then(Value::as_object) else {
        return Ok(());
    };
    for (shape_key, shape) in shapes {
        if shape_key != "Message" && !shape_key.starts_with("Message:") {
            continue;
        }
        if shape
            .get("facets")
            .and_then(Value::as_object)
            .is_some_and(|facets| facets.contains_key("expectation"))
        {
            return Err(Error::engine(format!(
                "cannot override protocol facet 'expectation' on shape '{shape_key}': Message expectation must inherit the required message-expectation vocabulary floor"
            )));
        }
    }
    Ok(())
}

fn contains_json_ref(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key("$ref") || object.values().any(contains_json_ref)
        }
        Value::Array(values) => values.iter().any(contains_json_ref),
        _ => false,
    }
}

/// Validate the optional JSON Schema carried by a declared object facet.
///
/// Schemas are deliberately self-contained. Remote or local `$ref` retrieval
/// would turn an ordinary record write into network or filesystem IO and make
/// the supported write path depend on mutable external state.
pub fn assert_valid_object_facet_schemas(data: &Value) -> Result<()> {
    let shapes = data.get("shapes").and_then(Value::as_object);
    for (shape_key, shape) in shapes.into_iter().flatten() {
        let Some(facets) = shape.get("facets").and_then(Value::as_object) else {
            continue;
        };
        for (facet_key, facet) in facets {
            let declared_type = facet.get("type").and_then(Value::as_str);
            let schema = facet.get("json_schema");
            if schema.is_some() && declared_type != Some("object") {
                return Err(Error::engine(format!(
                    "facet '{facet_key}' on shape '{shape_key}' may declare json_schema only with type: \"object\""
                )));
            }
            if let Some(orderings) = facet.get("temporal_order") {
                if declared_type != Some("object") {
                    return Err(Error::engine(format!(
                        "facet '{facet_key}' on shape '{shape_key}' may declare temporal_order only with type: \"object\""
                    )));
                }
                let Some(orderings) = orderings.as_array() else {
                    return Err(Error::engine(format!(
                        "facet '{facet_key}' on shape '{shape_key}' temporal_order must be an array"
                    )));
                };
                for ordering in orderings {
                    let Some(ordering) = ordering.as_object() else {
                        return Err(Error::engine(format!(
                            "facet '{facet_key}' on shape '{shape_key}' temporal_order entries must be objects"
                        )));
                    };
                    if ordering.len() != 2
                        || ordering
                            .get("earlier")
                            .and_then(Value::as_str)
                            .is_none_or(str::is_empty)
                        || ordering
                            .get("later")
                            .and_then(Value::as_str)
                            .is_none_or(str::is_empty)
                    {
                        return Err(Error::engine(format!(
                            "facet '{facet_key}' on shape '{shape_key}' temporal_order entries require only non-empty string earlier and later paths"
                        )));
                    }
                }
            }
            let Some(schema) = schema else { continue };
            if !schema.is_object() {
                return Err(Error::engine(format!(
                    "facet '{facet_key}' on shape '{shape_key}' json_schema must be an object"
                )));
            }
            if contains_json_ref(schema) {
                return Err(Error::engine(format!(
                    "facet '{facet_key}' on shape '{shape_key}' json_schema must be self-contained; $ref is not supported"
                )));
            }
            jsonschema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .should_validate_formats(true)
                .build(schema)
                .map_err(|error| {
                    Error::engine(format!(
                        "facet '{facet_key}' on shape '{shape_key}' has invalid json_schema: {error}"
                    ))
                })?;
        }
    }
    Ok(())
}

fn value_at_dotted_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(value, |current, segment| current.get(segment))
}

fn parse_temporal(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()?
                .and_hms_opt(0, 0, 0)
                .map(|value| value.and_utc())
        })
}

/// Enforce one resolved object-facet declaration against a caller value.
pub fn validate_object_facet_value(shape: &Value, value: &Value) -> Result<()> {
    if let Some(schema) = shape.get("json_schema") {
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .build(schema)
            .map_err(|error| {
                Error::engine(format!("invalid resolved object facet schema: {error}"))
            })?;
        validator
            .validate(value)
            .map_err(|error| Error::engine(format!("does not match json_schema: {error}")))?;
    }

    for ordering in shape
        .get("temporal_order")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(earlier_path) = ordering.get("earlier").and_then(Value::as_str) else {
            continue;
        };
        let Some(later_path) = ordering.get("later").and_then(Value::as_str) else {
            continue;
        };
        let (Some(earlier), Some(later)) = (
            value_at_dotted_path(value, earlier_path).and_then(Value::as_str),
            value_at_dotted_path(value, later_path).and_then(Value::as_str),
        ) else {
            continue;
        };
        let earlier = parse_temporal(earlier).ok_or_else(|| {
            Error::engine(format!(
                "'{earlier_path}' must be an ISO full-date or RFC3339 date-time"
            ))
        })?;
        let later = parse_temporal(later).ok_or_else(|| {
            Error::engine(format!(
                "'{later_path}' must be an ISO full-date or RFC3339 date-time"
            ))
        })?;
        if earlier > later {
            return Err(Error::engine(format!(
                "'{earlier_path}' must not be later than '{later_path}'"
            )));
        }
    }
    Ok(())
}

fn parse_data(data: SchemaConfigData) -> Result<(Value, String)> {
    match data {
        SchemaConfigData::Text(text) => {
            let parsed: Value = serde_json::from_str(&text)
                .map_err(|_| Error::engine("schema_config data must be valid JSON"))?;
            if !parsed.is_object() {
                return Err(Error::engine(
                    "schema_config data must be a JSON object ({ shapes: ... })",
                ));
            }
            Ok((parsed, text))
        }
        SchemaConfigData::Json(value) => {
            if !value.is_object() {
                return Err(Error::engine(
                    "schema_config data must be a JSON object ({ shapes: ... })",
                ));
            }
            let json = serde_json::to_string(&value)?;
            Ok((value, json))
        }
    }
}

/// A user-layer schema write after all engine-owned, data-only guards have
/// passed. Keeping preparation separate lets higher-level callers open one
/// authoritative write transaction for their cascade checks, reports and the
/// eventual append without duplicating this module's guards.
pub(crate) struct PreparedUserSchemaConfigWrite {
    id: String,
    json: String,
    version_lineage: Option<String>,
    applies_to_collection_id: Option<String>,
}

impl PreparedUserSchemaConfigWrite {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

pub(crate) fn prepare_user_schema_config_write(
    data: impl Into<SchemaConfigData>,
    opts: SchemaConfigOptions,
) -> Result<PreparedUserSchemaConfigWrite> {
    let (parsed, json) = parse_data(data.into())?;
    assert_no_reserved_facet_keys(&parsed)?;
    assert_no_spine_declared_types(&parsed)?;
    assert_no_authored_kind_arrays(&parsed)?;
    assert_no_message_expectation_overrides(&parsed)?;
    assert_valid_lifecycle_axes(&parsed)?;
    assert_valid_object_facet_schemas(&parsed)?;
    Ok(PreparedUserSchemaConfigWrite {
        id: opts.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        json,
        version_lineage: opts.version_lineage,
        applies_to_collection_id: opts.applies_to_collection_id,
    })
}

/// Append a prepared user-layer write through a caller-owned serialized write
/// transaction. The caller owns commit so product-level validation and reports
/// can share this exact snapshot and transaction with the schema declaration.
pub(crate) async fn append_prepared_user_schema_config_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    prepared: PreparedUserSchemaConfigWrite,
    actor: Option<&str>,
) -> Result<String> {
    let PreparedUserSchemaConfigWrite {
        id,
        json,
        version_lineage,
        applies_to_collection_id,
    } = prepared;
    let existing: Option<String> =
        sqlx::query_scalar("SELECT layer FROM schema_config WHERE id = ?")
            .bind(&id)
            .fetch_optional(&mut **tx)
            .await?;
    if existing.as_deref().is_some_and(|layer| layer != "user") {
        return Err(Error::engine(format!(
            "cannot write schema_config row '{id}': it exists on the pack layer, which is seed-only — user configuration goes in a user-layer row"
        )));
    }
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            &id,
            "schema_config.set",
            json!({
                "layer": "user",
                "data": &json,
                "version_lineage": &version_lineage,
                "applies_to_collection_id": &applies_to_collection_id,
            }),
        )
        .with_actor(actor),
    )
    .await?;
    Ok(id)
}

/// Write the USER layer of the cascade — the single editable layer (pack rows
/// are seed-only). Runs the reserved-key guard before anything touches the
/// table. Returns the row id.
pub async fn write_user_schema_config(
    db: &Db,
    data: impl Into<SchemaConfigData>,
    opts: SchemaConfigOptions,
) -> Result<String> {
    write_user_schema_config_as(db, data, opts, None).await
}

pub async fn write_user_schema_config_as(
    db: &Db,
    data: impl Into<SchemaConfigData>,
    opts: SchemaConfigOptions,
    actor: Option<&str>,
) -> Result<String> {
    let prepared = prepare_user_schema_config_write(data, opts)?;
    // The layer guard: pack ids are deterministic, so an unguarded write would
    // let a user call silently rewrite a pack row's data while it stayed
    // layer='pack'. It used to ride on the upsert itself (`ON CONFLICT ... WHERE
    // layer = 'user'`, rows_affected 0 => rejection). Now that the fold owns the
    // write, the guard is an explicit read-check BEFORE the append — a guard
    // expressed as a projection-table UPDATE clause would have had to be
    // duplicated into the projector to survive replay, and re-running it at
    // replay is exactly what `crate::projector::meta` must not do.
    //
    // The check and the append share one write transaction, so a concurrent
    // pack seed cannot land between them.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let id = append_prepared_user_schema_config_in(&mut tx, prepared, actor).await?;
    tx.commit().await?;
    Ok(id)
}

/// Seed a PACK layer row (e.g. '@native/recommended'). Engine-shipped, so it is
/// not subject to user write auth — but the reserved-key guard still applies:
/// `archived` is engine-reserved from every layer, pack included (a pack that
/// shaped it would break its own engine).
pub async fn seed_pack_schema_config(
    db: &Db,
    name: &str,
    data: impl Into<SchemaConfigData>,
    opts: SchemaConfigOptions,
) -> Result<String> {
    let (parsed, json) = parse_data(data.into())?;
    assert_no_reserved_facet_keys(&parsed)?;
    assert_no_spine_declared_types(&parsed)?;
    assert_no_authored_kind_arrays(&parsed)?;
    assert_valid_lifecycle_axes(&parsed)?;
    let id = opts.id.unwrap_or_else(|| format!("pack:{name}"));
    // Engine-owned packs evolve. Re-running an identical seed is a log no-op,
    // while a changed compiled payload appends one authoritative replacement.
    // This is how current-schema databases acquire new recommended constraints
    // (for example Message expectation requiredness) without rewriting user
    // records or pretending the pack row is immutable application data.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let existing = sqlx::query(
        "SELECT layer, name, data, version_lineage, applies_to_collection_id
           FROM schema_config WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    let needs_write = match existing {
        None => true,
        Some(existing) => {
            let layer: String = existing.try_get("layer")?;
            let existing_name: Option<String> = existing.try_get("name")?;
            if layer != "pack" || existing_name.as_deref() != Some(name) {
                return Err(Error::engine(format!(
                    "cannot seed pack schema_config '{id}': existing row is layer '{layer}' named {:?}",
                    existing_name
                )));
            }
            let existing_data: String = existing.try_get("data")?;
            let existing_data: Value = serde_json::from_str(&existing_data).map_err(|_| {
                Error::engine(format!(
                    "pack schema_config row '{id}' carries invalid JSON data"
                ))
            })?;
            existing_data != parsed
                || existing
                    .try_get::<Option<String>, _>("version_lineage")?
                    .as_deref()
                    != opts.version_lineage.as_deref()
                || existing
                    .try_get::<Option<String>, _>("applies_to_collection_id")?
                    .as_deref()
                    != opts.applies_to_collection_id.as_deref()
        }
    };
    if needs_write {
        append_meta_in(
            &mut tx,
            MetaAppendSpec::with_payload(
                &id,
                "schema_config.set",
                json!({
                    "layer": "pack",
                    "name": name,
                    "data": &json,
                    "version_lineage": &opts.version_lineage,
                    "applies_to_collection_id": &opts.applies_to_collection_id,
                }),
            ),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(id)
}

/// Seed the canonical recommended pack contents. Idempotency is inherited from
/// [`seed_pack_schema_config`]. Database-open wiring is intentionally owned by
/// the separate seeder-wiring task.
pub async fn seed_recommended_pack_schema_config(db: &Db) -> Result<String> {
    seed_pack_schema_config(
        db,
        RECOMMENDED_PACK_NAME,
        recommended_pack_schema_config(),
        SchemaConfigOptions::default(),
    )
    .await
}

#[cfg(test)]
mod lifecycle_axis_tests {
    use super::*;

    #[test]
    fn governed_lifecycle_requires_an_exact_nonblank_axis_descriptor() {
        let shape = |axis: Value| {
            json!({
                "shapes": {
                    "WorkItem:custom": {
                        "facets": {
                            "lifecycle": {
                                "axis": axis,
                                "vocab_ref": "custom-lifecycle"
                            }
                        }
                    }
                }
            })
        };
        assert_valid_lifecycle_axes(&shape(json!({
            "key": "custom_state",
            "label": "Custom state"
        })))
        .unwrap();
        for invalid in [
            json!(null),
            json!({ "key": "", "label": "Custom state" }),
            json!({ "key": "custom_state" }),
            json!({ "key": "custom_state", "label": "Custom state", "extra": true }),
        ] {
            assert!(assert_valid_lifecycle_axes(&shape(invalid)).is_err());
        }
        assert!(assert_valid_lifecycle_axes(&json!({
            "shapes": {
                "WorkItem:custom": {
                    "facets": { "lifecycle": { "vocab_ref": "custom-lifecycle" } }
                }
            }
        }))
        .is_err());
    }
}
