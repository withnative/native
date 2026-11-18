//! Native user schema authoring. Guards and catalogue folds use the same
//! transaction; replay retains declarations without rechecking today's rights.
use super::*;
use crate::mcp::tools::meta as guards;
use crate::meta::schema_config::{self, SchemaConfigOptions};
use crate::query::cascade::{self, SchemaConfigRow};
use serde_json::{json, Value};

pub(crate) const EVENT: &str = "kernel.schema_config_written.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Written {
    pub id: String,
    pub data: Value,
    pub version_lineage: Option<String>,
    pub applies_to_collection_id: Option<String>,
}

pub(crate) fn validate_data(data: &Value) -> Result<()> {
    if !data.is_object() {
        return Err(Error::engine(
            "manage_schema_config: data must be a JSON object ({ shapes: ... })",
        ));
    }
    schema_config::assert_no_reserved_facet_keys(data)?;
    schema_config::assert_no_authored_kind_arrays(data)?;
    guards::assert_no_facet_cardinality(data)?;
    guards::assert_known_facet_types(data)?;
    schema_config::assert_valid_lifecycle_axes(data)?;
    schema_config::assert_valid_object_facet_schemas(data)?;
    schema_config::assert_no_message_expectation_overrides(data)?;
    Ok(())
}

pub(crate) fn target(scope: Option<&str>) -> &str {
    match scope {
        None | Some("native:root") | Some(KERNEL_ROOT_ID) => KERNEL_ROOT_ID,
        Some(scope) => scope,
    }
}

pub(crate) async fn existing_on(conn: &mut SqliteConnection, id: &str) -> Result<Option<Value>> {
    let raw: Option<String> = sqlx::query_scalar("SELECT payload FROM kernel_v1_state WHERE section='schema_config' AND json_extract(payload,'$.id')=?").bind(id).fetch_optional(conn).await?;
    raw.map(|r| serde_json::from_str(&r).map_err(Into::into))
        .transpose()
}
async fn rows_on(conn: &mut SqliteConnection) -> Result<Vec<SchemaConfigRow>> {
    let mut rows = v1_state::rows_on(conn, "schema_config")
        .await?
        .iter()
        .map(v1_state::schema_row)
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by(|a, b| {
        (a.layer != "pack", &a.created_at, &a.id).cmp(&(b.layer != "pack", &b.created_at, &b.id))
    });
    Ok(rows)
}
fn vocabulary_identity(vocabs: &[Value], reference: &str) -> String {
    let reference = crate::meta::vocabulary::resolve_vocab_ref(reference);
    vocabs
        .iter()
        .find(|v| v["id"] == reference || v["name"] == reference)
        .and_then(|v| v["id"].as_str())
        .unwrap_or(reference)
        .into()
}
fn facet_vocabulary(vocabs: &[Value], shape: &Value) -> Option<String> {
    shape
        .get("vocab")
        .or_else(|| shape.get("vocab_ref"))
        .and_then(Value::as_str)
        .map(|r| vocabulary_identity(vocabs, r))
}
fn canonicalise_spine(vocabs: &[Value], data: &mut Value) {
    for shape in data
        .get_mut("shapes")
        .and_then(Value::as_object_mut)
        .into_iter()
        .flat_map(|s| s.values_mut())
    {
        for (key, facet) in shape
            .get_mut("facets")
            .and_then(Value::as_object_mut)
            .into_iter()
            .flatten()
        {
            if !crate::schema::SPINE_FACET_KEYS.contains(&key.as_str()) {
                continue;
            }
            for field in ["vocab", "vocab_ref"] {
                if let Some(reference) = facet.get(field).and_then(Value::as_str) {
                    let id = vocabulary_identity(vocabs, reference);
                    if vocabs.iter().any(|v| v["id"] == id) {
                        facet[field] = json!(crate::meta::vocabulary::vocab_ref(&id));
                    }
                }
            }
        }
    }
}

/// Interpret the same joined facts as v1, including KindMetadataV1 validity.
fn assert_kind(vocabs: &[Value], values: &[Value], record_type: &str, kind: &str) -> Result<()> {
    use crate::portable_sql::{NormalizedRow, NormalizedValue};
    let vocab = vocabs
        .iter()
        .find(|v| v["name"] == format!("kind:{record_type}"));
    let value = vocab.and_then(|v| {
        values
            .iter()
            .find(|r| r["vocabulary_id"] == v["id"] && r["value"] == kind)
    });
    let mut joined = None;
    if let Some(value) = value {
        let mut row = NormalizedRow::new();
        for key in ["id", "status", "metadata", "alias_of"] {
            let cell = if key == "metadata" && value[key].is_object() {
                NormalizedValue::Text(serde_json::to_string(&value[key])?)
            } else {
                value[key]
                    .as_str()
                    .map(|s| NormalizedValue::Text(s.into()))
                    .unwrap_or(NormalizedValue::Null)
            };
            row.insert(key.into(), cell);
        }
        let canonical = value["alias_of"]
            .as_str()
            .and_then(|id| values.iter().find(|v| v["id"] == id));
        for (key, column) in [
            ("canonical_id", "id"),
            ("canonical_value", "value"),
            ("canonical_status", "status"),
            ("canonical_metadata", "metadata"),
        ] {
            row.insert(
                key.into(),
                canonical
                    .and_then(|r| r[column].as_str())
                    .map(|s| NormalizedValue::Text(s.into()))
                    .unwrap_or(NormalizedValue::Null),
            );
        }
        joined = Some(row);
    }
    let resolution = crate::meta::kind::resolve_identity_row(record_type, kind, joined.as_ref())?;
    if resolution.classification != crate::meta::kind::KindClassification::ActiveCanonical {
        return Err(Error::engine(format!("kind-specific schema shape '{record_type}:{kind}' requires an active canonical value in 'kind:{record_type}'; propose and promote it with manage_vocabularies first")));
    }
    Ok(())
}
fn assert_kinds(
    vocabs: &[Value],
    values: &[Value],
    rows: &[SchemaConfigRow],
    scope: Option<&str>,
) -> Result<()> {
    let shapes: Vec<String> = if let Some(scope) = scope {
        rows.iter()
            .filter(|r| {
                r.applies_to_collection_id.is_none()
                    || r.applies_to_collection_id.as_deref() == Some(scope)
            })
            .flat_map(|r| {
                r.data
                    .get("shapes")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|s| s.keys().cloned())
            })
            .collect()
    } else {
        cascade::resolve_from_rows(rows).resolved["shapes"]
            .as_object()
            .into_iter()
            .flat_map(|s| s.keys().cloned())
            .collect()
    };
    for key in shapes {
        if let Some((typ, kind)) = key.split_once(':') {
            assert_kind(vocabs, values, typ, kind)?;
        }
    }
    Ok(())
}
fn assert_spine(
    vocabs: &[Value],
    rows: &[SchemaConfigRow],
    data: &Value,
    scope: Option<&str>,
) -> Result<()> {
    let pack = cascade::resolve_from_rows(rows).pack;
    let targets = match scope {
        Some(scope) => guards::scoped_shape_targets(rows, data, scope),
        None => guards::shape_targets(&pack, data),
    };
    for (typ, kinds) in targets {
        for kind in kinds {
            let floor = match scope {
                Some(scope) => cascade::pack_facets_for_record_context(
                    rows,
                    &typ,
                    kind.as_deref(),
                    Some(scope),
                ),
                None => cascade::facets_for_type(&pack, &typ, kind.as_deref()),
            };
            let user = cascade::facets_for_type(data, &typ, kind.as_deref());
            for key in crate::schema::SPINE_FACET_KEYS {
                let (Some(pack_shape), Some(user_shape)) = (floor.get(key), user.get(key)) else {
                    continue;
                };
                let pack_vocab = facet_vocabulary(vocabs, pack_shape);
                let user_vocab = facet_vocabulary(vocabs, user_shape);
                if let Some(reason) = guards::schema_spine_loosening(
                    pack_shape,
                    user_shape,
                    pack_vocab.as_deref(),
                    user_vocab.as_deref(),
                )? {
                    return Err(Error::engine(format!("cannot loosen spine facet '{key}' on shape '{typ}': {reason}; the resolved pack shape for this scope is the interop floor")));
                }
            }
        }
    }
    Ok(())
}

async fn transition_on(conn: &mut SqliteConnection, p: &Written) -> Result<Vec<SchemaConfigRow>> {
    validate_data(&p.data)?;
    if p.applies_to_collection_id.as_deref() == Some(KERNEL_ROOT_ID) {
        return Err(Error::engine(
            "schema scope must use canonical native:root designation",
        ));
    }
    if p.id.trim().is_empty() {
        return Err(Error::engine("schema config id must not be blank"));
    }
    schema_config::prepare_user_schema_config_write(
        p.data.clone(),
        SchemaConfigOptions {
            id: Some(p.id.clone()),
            version_lineage: p.version_lineage.clone(),
            applies_to_collection_id: p.applies_to_collection_id.clone(),
        },
    )?;
    if existing_on(conn, &p.id)
        .await?
        .is_some_and(|r| r["layer"] != "user")
    {
        return Err(Error::engine(
            "cannot write a pack-layer schema config; pack rows are seed-only",
        ));
    }
    let vocabs = v1_state::rows_on(conn, "vocabularies").await?;
    let values = v1_state::rows_on(conn, "vocabulary_values").await?;
    let mut canonical = p.data.clone();
    canonicalise_spine(&vocabs, &mut canonical);
    if canonical != p.data {
        return Err(Error::engine(
            "schema spine vocabulary references must be canonical",
        ));
    }
    let rows = rows_on(conn).await?;
    let prospective = cascade::rows_after_user_write(
        &rows,
        Some(&p.id),
        &p.data,
        p.applies_to_collection_id.as_deref(),
    );
    assert_kinds(
        &vocabs,
        &values,
        &prospective,
        p.applies_to_collection_id.as_deref(),
    )?;
    assert_spine(
        &vocabs,
        &rows,
        &p.data,
        p.applies_to_collection_id.as_deref(),
    )?;
    if let Some(scope) = p.applies_to_collection_id.as_deref() {
        guards::assert_no_type_loosening_scoped(&rows, &p.data, scope)?;
        guards::assert_no_object_contract_loosening_scoped(&rows, &p.data, scope)?;
    } else {
        let pack = cascade::resolve_from_rows(&rows).pack;
        guards::assert_no_type_loosening(&pack, &p.data)?;
        guards::assert_no_object_contract_loosening(&pack, &p.data)?;
    }
    Ok(prospective)
}

async fn scope_manage_on(
    conn: &mut SqliteConnection,
    actor: &str,
    scope: Option<&str>,
) -> Result<()> {
    let target = target(scope);
    kernel_require(conn, actor, target, Capability::Manage).await?;
    if target != KERNEL_ROOT_ID {
        let typ: Option<String> = sqlx::query_scalar("SELECT CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(t.value_json,'$') ELSE r.primary_type END FROM kernel_records r LEFT JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' WHERE r.id=?").bind(target).fetch_optional(conn).await?.flatten();
        if typ.as_deref() != Some("Collection") {
            return Err(Error::engine(
                "manage_schema_config: applies_to_collection_id must name a Collection",
            ));
        }
    }
    Ok(())
}
async fn authorize_on(conn: &mut SqliteConnection, actor: &str, p: &Written) -> Result<()> {
    #[cfg(feature = "v2-kernel-probe")]
    app_installs::admit_dispatched_on(conn, actor).await?;
    scope_manage_on(conn, actor, p.applies_to_collection_id.as_deref()).await?;
    if let Some(old) = existing_on(conn, &p.id).await? {
        let old_scope = old["applies_to_collection_id"].as_str();
        if old_scope != p.applies_to_collection_id.as_deref() {
            scope_manage_on(conn, actor, old_scope).await?;
        }
    }
    Ok(())
}

async fn count_nonconforming_on(
    conn: &mut SqliteConnection,
    actor: &str,
    rows: &[SchemaConfigRow],
    scope: Option<&str>,
) -> Result<i64> {
    type Stored = (
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<f64>,
    );
    let stored:Vec<Stored> = sqlx::query_as("SELECT r.id,r.home_id,CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(t.value_json,'$') ELSE r.primary_type END,CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(k.value_json,'$') ELSE r.kind END,f.key,f.value,f.value_num FROM kernel_records r JOIN kernel_facets f ON f.record_id=r.id LEFT JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' WHERE r.primary_type IS NOT NULL AND f.value IS NOT NULL").fetch_all(&mut *conn).await?;
    let interpreter = v1_state::interpreter_on(conn, actor).await?;
    let mut count = 0;
    for (id, home, typ, kind, key, value, num) in stored {
        let bearer = v1_state::lifecycle_bearer_on(conn, &home, Some(&id)).await?;
        if scope.is_some_and(|scope| scope != bearer)
            || !kernel_effective_capability_on(conn, actor, &id)
                .await?
                .allows(Capability::View)
        {
            continue;
        }
        let kind = kind.map(|k| interpreter.canonical_imported_kind(&typ, &k));
        let shape = cascade::facets_for_record_context(rows, &typ, kind.as_deref(), Some(&bearer));
        if guards::schema_declared_value_nonconforming(&shape, &key, value.as_deref(), num) {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn write_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    mut p: Written,
    expected_revision: Option<&str>,
    acts: &mut crate::act::ActAllocation,
) -> Result<Value> {
    validate_data(&p.data)?;
    authorize_on(tx, actor, &p).await?;
    let current = schema_catalogue::revision_on(tx).await?;
    if expected_revision.is_some_and(|v| v != current) {
        return Err(Error::conflict("schema state revision conflict"));
    }
    let vocabs = v1_state::rows_on(tx, "vocabularies").await?;
    canonicalise_spine(&vocabs, &mut p.data);
    let prospective = transition_on(tx, &p).await?;
    let nonconforming = count_nonconforming_on(
        tx,
        actor,
        &prospective,
        p.applies_to_collection_id.as_deref(),
    )
    .await?;
    let old = existing_on(tx, &p.id).await?;
    let changed = old.as_ref().is_none_or(|old| {
        old["data"]
            .as_str()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .as_ref()
            != Some(&p.data)
            || old["version_lineage"] != json!(p.version_lineage)
            || old["applies_to_collection_id"] != json!(p.applies_to_collection_id)
    });
    let mut result = json!({"id":p.id,"layer":"user","applies_to_collection_id":p.applies_to_collection_id,"changed":changed,"nonconforming_stored_values":nonconforming,"nonconforming_value_scope":"visible records in the affected scope","type_enforcement":"forward-only on native open-facet admission; historical values are reported, not rejected or rewritten; spine declarations are rejected"});
    if p.data["shapes"]
        .as_object()
        .into_iter()
        .flat_map(|s| s.values())
        .filter_map(|shape| shape["facets"].as_object())
        .flat_map(|facets| facets.values())
        .any(|facet| {
            facet["type"]
                .as_str()
                .and_then(crate::typed_time::TimeFacetType::parse)
                .is_some()
        })
    {
        result["typed_time_support"] = json!({"native_write_validation":"forward-only at native facet admission","native_write_normalization":"not_available","native_write_timeline_projection":"not_available"});
    }
    if changed {
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&p)?));
        let pending = app_installs::start_app_action_in(
            db,
            tx,
            actor,
            "manage_schema_config.write",
            digest,
            None,
            acts,
        )
        .await?;
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: target(p.applies_to_collection_id.as_deref()).into(),
                event_type: EVENT.into(),
                payload: serde_json::to_value(&p)?,
                actor: Some(actor.into()),
            },
            acts,
        )
        .await?;
        if let Some(attribution) =
            app_installs::finish_app_action_in(db, tx, actor, pending, acts).await?
        {
            result["app_attribution"] = attribution;
        }
        result["act"] = json!(acts.get());
    }
    result["schema_state_revision"] = json!(schema_catalogue::revision_on(tx).await?);
    Ok(result)
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type == "kernel.facet_observed.v1" {
        let observation = hq::decode_facet_observation(event_payload(event)?)?;
        return assert_native_facet_conformance_on(conn, &event.record_id, &observation).await;
    }
    if event.event_type != EVENT {
        return Ok(());
    }
    let p: Written = event_payload(event)?;
    if event.record_id != target(p.applies_to_collection_id.as_deref()) {
        return Err(Error::engine(
            "schema config event anchor differs from its scope",
        ));
    }
    authorize_on(conn, event.actor.as_deref().unwrap_or_default(), &p).await?;
    transition_on(conn, &p).await?;
    Ok(())
}
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Written = event_payload(event)?;
    if event.record_id != target(p.applies_to_collection_id.as_deref()) {
        return Err(Error::engine(
            "schema config event anchor differs from its scope",
        ));
    }
    transition_on(conn, &p).await?;
    let created_at = existing_on(conn, &p.id)
        .await?
        .and_then(|v| v["created_at"].as_str().map(str::to_owned))
        .unwrap_or_else(|| event.created_at.clone());
    let row = json!({"id":p.id,"layer":"user","name":null,"data":serde_json::to_string(&p.data)?,"applies_to_collection_id":p.applies_to_collection_id,"version_lineage":p.version_lineage,"created_at":created_at});
    schema_catalogue::project_row_on(conn, event, "schema_config", &p.id, Some(row)).await
}

/// Forward-only admission for native facet observations. History/import folds
/// remain observational, and changing a declaration never rewrites old values.
pub(crate) async fn assert_native_facet_conformance_on(
    conn: &mut SqliteConnection,
    record: &str,
    observation: &hq::FacetObservation,
) -> Result<()> {
    if observation.value.is_none() {
        return Ok(());
    }
    type Context = (String, Option<String>, Option<String>);
    let context:Option<Context>=sqlx::query_as("SELECT r.home_id,CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(t.value_json,'$') ELSE r.primary_type END,CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(k.value_json,'$') ELSE r.kind END FROM kernel_records r LEFT JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' WHERE r.id=?").bind(record).fetch_optional(&mut *conn).await?;
    let Some((home, Some(typ), kind)) = context else {
        return Ok(());
    };
    let rows = rows_on(conn).await?;
    let interpreter = crate::query::lifecycle::LifecycleInterpreter::from_imported_rows(
        rows.clone(),
        v1_state::rows_on(conn, "vocabularies").await?,
        v1_state::rows_on(conn, "vocabulary_values").await?,
    )?;
    let kind = kind.map(|kind| interpreter.canonical_imported_kind(&typ, &kind));
    let bearer = v1_state::lifecycle_bearer_on(conn, &home, Some(record)).await?;
    let shape = cascade::facets_for_record_context(&rows, &typ, kind.as_deref(), Some(&bearer));
    let declared = shape.get(&observation.key).and_then(|v| v["type"].as_str());
    let Some(declared) = declared else {
        return Ok(());
    };
    if !crate::domain_transaction::DECLARED_FACET_TYPES.contains(&declared) {
        return Err(Error::engine("unsupported declared facet type"));
    }
    let number_consistent = if declared == "number" {
        observation
            .value
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .filter(Value::is_number)
            .and_then(|v| v.as_f64())
            == observation.value_num
    } else {
        observation.value_num.is_none()
    };
    if !number_consistent
        || guards::schema_declared_value_nonconforming(
            &shape,
            &observation.key,
            observation.value.as_deref(),
            observation.value_num,
        )
    {
        return Err(Error::engine(format!(
            "facet '{}' does not conform to declared type '{declared}'",
            observation.key
        )));
    }
    Ok(())
}
