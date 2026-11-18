//! Event-authoritative vocabulary editing over the kernel catalogue projection.
//! Imported provenance stays sealed; native edits carry their own content event.
use super::*;
use crate::meta::kind::KindMetadataV1;
use crate::meta::vocabulary::{self, VocabularyValueTerminality};
use serde_json::{json, Value};

pub(crate) const EVENT: &str = "kernel.vocabulary_mutated.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub(crate) enum Mutation {
    CreateVocabulary {
        name: String,
        id: Option<String>,
    },
    ProposeValue {
        vocabulary: String,
        value: String,
        gloss: Option<String>,
        #[serde(default)]
        ordinal: f64,
        #[serde(default)]
        terminality: VocabularyValueTerminality,
        metadata: Option<KindMetadataV1>,
    },
    ReorderValue {
        value_id: String,
        ordinal: f64,
    },
    SetGloss {
        value_id: String,
        gloss: Option<String>,
    },
    SetMetadata {
        value_id: String,
        metadata: KindMetadataV1,
    },
    PromoteValue {
        value_id: String,
    },
    DeprecateValue {
        value_id: String,
    },
    AliasValue {
        value_id: String,
        canonical_id: String,
    },
    DeleteValue {
        value_id: String,
    },
    DeleteVocabulary {
        vocabulary: String,
    },
}

pub(crate) async fn revision_on(conn: &mut SqliteConnection) -> Result<String> {
    let event_id: String =
        sqlx::query_scalar("SELECT id FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(conn)
            .await?;
    use sha2::{Digest, Sha256};
    Ok(format!(
        "schema-state-v2:{}",
        hex::encode(Sha256::digest(event_id.as_bytes()))
    ))
}

struct Transition {
    changes: Vec<(&'static str, String, Option<Value>)>,
    result: Value,
}
fn metadata(value: &Value) -> Result<Value> {
    match value.as_str() {
        Some(raw) => Ok(serde_json::from_str(raw)?),
        None => Ok(value.clone()),
    }
}
fn get<'a>(rows: &'a [Value], id: &str) -> Result<&'a Value> {
    rows.iter()
        .find(|r| r["id"] == id)
        .ok_or_else(|| Error::engine("vocabulary value does not exist"))
}
fn vocab<'a>(rows: &'a [Value], reference: &str) -> Result<&'a Value> {
    let reference = vocabulary::resolve_vocab_ref(reference);
    rows.iter()
        .find(|r| r["id"] == reference || r["name"] == reference)
        .ok_or_else(|| Error::engine("vocabulary does not exist"))
}
fn text<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row[key]
        .as_str()
        .ok_or_else(|| Error::engine(format!("invalid catalogue field {key}")))
}
fn validate_kind(vocab: &Value, value: &Value) -> Result<()> {
    if let Some(typ) = text(vocab, "name")?.strip_prefix("kind:") {
        if !crate::schema::SPINE_TYPES.contains(&typ) {
            return Err(Error::engine(
                "kind vocabulary does not name a closed spine type",
            ));
        }
        let metadata: KindMetadataV1 = serde_json::from_value(metadata(&value["metadata"])?)?;
        metadata.validate()?;
    }
    Ok(())
}
fn references_config(value: &Value, designators: &[String]) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(k, v)| {
            (["vocab", "vocab_ref"].contains(&k.as_str())
                && v.as_str()
                    .is_some_and(|s| designators.iter().any(|d| s == d)))
                || references_config(v, designators)
        }),
        Value::Array(rows) => rows.iter().any(|v| references_config(v, designators)),
        _ => false,
    }
}
async fn transition(
    conn: &mut SqliteConnection,
    mutation: &Mutation,
    created_at: &str,
) -> Result<Transition> {
    let vocabs = v1_state::rows_on(conn, "vocabularies").await?;
    let values = v1_state::rows_on(conn, "vocabulary_values").await?;
    let mut changes = vec![];
    let result = match mutation {
        Mutation::CreateVocabulary { name, id } => {
            let id = id
                .clone()
                .unwrap_or_else(|| vocabulary::vocabulary_id(name));
            if name.trim().is_empty() || id.trim().is_empty() {
                return Err(Error::engine("vocabulary name and id must be nonempty"));
            }
            if let Some(existing) = vocabs.iter().find(|v| {
                v["id"] == id || v["name"] == id || v["id"] == *name || v["name"] == *name
            }) {
                if existing["id"] != id || existing["name"] != *name {
                    return Err(Error::conflict("vocabulary identity conflict"));
                }
            } else {
                changes.push((
                    "vocabularies",
                    id.clone(),
                    Some(json!({"id":id,"name":name,"created_at":created_at})),
                ));
            }
            json!({"vocabulary_id":id,"name":name,"vocab_ref":vocabulary::vocab_ref(&id)})
        }
        Mutation::ProposeValue {
            vocabulary: reference,
            value,
            gloss,
            ordinal,
            terminality,
            metadata: kind_metadata,
        } => {
            if !ordinal.is_finite() {
                return Err(Error::engine("vocabulary value ordinal must be finite"));
            }
            let vocab = vocab(&vocabs, reference)?;
            let vid = text(vocab, "id")?;
            let id = vocabulary::value_id(vid, value);
            let meta = kind_metadata
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .unwrap_or_else(|| json!({}));
            let row = json!({"id":id,"vocabulary_id":vid,"value":value,"gloss":gloss,"status":"proposed","ordinal":ordinal,"terminality":terminality.as_str(),"metadata":serde_json::to_string(&meta)?,"alias_of":null,"created_at":created_at});
            validate_kind(vocab, &row)?;
            if !text(vocab, "name")?.starts_with("kind:") && kind_metadata.is_some() {
                return Err(Error::engine(
                    "kind metadata is only valid on kind:<Type> vocabularies",
                ));
            }
            if let Some(old) = values
                .iter()
                .find(|r| r["vocabulary_id"] == vid && r["value"] == *value)
            {
                if old["id"] != id
                    || !["proposed", "active"].contains(&old["status"].as_str().unwrap_or_default())
                    || old["gloss"] != row["gloss"]
                    || old["ordinal"].as_f64() != row["ordinal"].as_f64()
                    || old["terminality"] != row["terminality"]
                    || metadata(&old["metadata"])? != meta
                {
                    return Err(Error::conflict(
                        "vocabulary value identity/payload conflict",
                    ));
                }
            } else {
                changes.push(("vocabulary_values", id.clone(), Some(row)));
            }
            json!({"value_id":id,"vocabulary":reference,"value":value,"status":values.iter().find(|v|v["id"]==id).map(|v|v["status"].clone()).unwrap_or_else(||json!("proposed")),"ordinal":ordinal,"terminality":terminality,"metadata":kind_metadata})
        }
        Mutation::DeleteVocabulary {
            vocabulary: reference,
        } => {
            let vocab = vocab(&vocabs, reference)?;
            let id = text(vocab, "id")?;
            let name = text(vocab, "name")?;
            if vocabulary::is_seeded_vocabulary(name) {
                return Err(Error::engine("cannot delete seeded vocabulary"));
            }
            let refs = vec![
                id.to_owned(),
                format!("rec:{id}"),
                name.to_owned(),
                format!("rec:{name}"),
            ];
            let used: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM kernel_facets WHERE vocab_ref IN (?,?,?,?))",
            )
            .bind(&refs[0])
            .bind(&refs[1])
            .bind(&refs[2])
            .bind(&refs[3])
            .fetch_one(&mut *conn)
            .await?;
            let mut configured = false;
            for row in v1_state::rows_on(conn, "schema_config").await? {
                let data = metadata(&row["data"])?;
                configured |= references_config(&data, &refs);
            }
            if used || configured {
                return Err(Error::engine("cannot delete referenced vocabulary"));
            }
            for row in values.iter().filter(|r| r["vocabulary_id"] == id) {
                changes.push(("vocabulary_values", text(row, "id")?.into(), None));
            }
            changes.push(("vocabularies", id.into(), None));
            json!({"vocabulary":reference,"deleted":true})
        }
        mutation => {
            let id = match mutation {
                Mutation::ReorderValue { value_id, .. }
                | Mutation::SetGloss { value_id, .. }
                | Mutation::SetMetadata { value_id, .. }
                | Mutation::PromoteValue { value_id }
                | Mutation::DeprecateValue { value_id }
                | Mutation::AliasValue { value_id, .. }
                | Mutation::DeleteValue { value_id } => value_id,
                _ => unreachable!(),
            };
            let old = get(&values, id)?;
            let mut row = old.clone();
            let vocab = vocab(&vocabs, text(old, "vocabulary_id")?)?;
            let name = text(vocab, "name")?;
            let vid = text(vocab, "id")?;
            let mut records_quarantined = 0i64;
            match mutation {
                Mutation::ReorderValue { ordinal, .. } => {
                    if !ordinal.is_finite() {
                        return Err(Error::engine("vocabulary value ordinal must be finite"));
                    }
                    row["ordinal"] = json!(ordinal);
                }
                Mutation::SetGloss { gloss, .. } => row["gloss"] = json!(gloss),
                Mutation::SetMetadata { metadata: meta, .. } => {
                    if !name.starts_with("kind:") {
                        return Err(Error::engine(
                            "KindMetadataV1 may only be set on kind:<Type> values",
                        ));
                    }
                    meta.validate()?;
                    let next = serde_json::to_value(meta)?;
                    if metadata(&old["metadata"])? != next {
                        row["metadata"] = json!(serde_json::to_string(&next)?);
                    }
                }
                Mutation::PromoteValue { .. } => {
                    validate_kind(vocab, &row)?;
                    row["status"] = json!("active");
                    row["alias_of"] = Value::Null;
                }
                Mutation::DeprecateValue { .. } => {
                    if old["status"] == "active" && old["alias_of"].is_null() {
                        if let Some(typ) = name.strip_prefix("kind:") {
                            let tokens: Vec<Value> = values
                                .iter()
                                .filter(|v| v["id"] == *id || v["alias_of"] == *id)
                                .map(|v| v["value"].clone())
                                .collect();
                            records_quarantined =
                                kind_records_on(conn, typ, &tokens, false).await?;
                        }
                    }
                    row["status"] = json!("deprecated");
                }
                Mutation::AliasValue { canonical_id, .. } => {
                    let canonical = get(&values, canonical_id)?;
                    if id == canonical_id
                        || canonical["vocabulary_id"] != old["vocabulary_id"]
                        || !canonical["alias_of"].is_null()
                    {
                        return Err(Error::engine("alias requires a distinct canonical value in the same vocabulary; chains are forbidden"));
                    }
                    if name.starts_with("kind:") && canonical["status"] != "active" {
                        return Err(Error::engine("kind alias requires active canonical value"));
                    }
                    glossary_alias(conn, vid, old, canonical).await?;
                    row["alias_of"] = json!(canonical_id);
                    row["status"] = json!("deprecated");
                }
                Mutation::DeleteValue { .. } => {
                    if vocabulary::is_seeded_value(name, text(old, "value")?) {
                        return Err(Error::engine("cannot delete seeded vocabulary value"));
                    }
                    if values.iter().any(|v| v["alias_of"] == *id) {
                        return Err(Error::engine("cannot delete value referenced by aliases"));
                    }
                    let used: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_facets WHERE vocab_ref IN (?,?,?,?) AND value=?)").bind(vid).bind(format!("rec:{vid}")).bind(name).bind(format!("rec:{name}")).bind(text(old,"value")?).fetch_one(&mut *conn).await?;
                    let kinds: bool = if let Some(typ) = name.strip_prefix("kind:") {
                        kind_records_on(conn, typ, &[old["value"].clone()], true).await? > 0
                    } else {
                        false
                    };
                    if used || kinds {
                        return Err(Error::engine(
                            "cannot delete referenced vocabulary value, including tombstones",
                        ));
                    }
                }
                _ => unreachable!(),
            }
            if matches!(mutation, Mutation::DeleteValue { .. }) {
                changes.push(("vocabulary_values", id.clone(), None));
            } else if row != *old {
                changes.push(("vocabulary_values", id.clone(), Some(row.clone())));
            }
            match mutation {
                Mutation::ReorderValue { ordinal, .. } => {
                    json!({"value_id":id,"ordinal":ordinal,"reordered":true})
                }
                Mutation::SetGloss { gloss, .. } => {
                    json!({"value_id":id,"gloss":gloss,"gloss_set":true})
                }
                Mutation::SetMetadata { metadata, .. } => {
                    json!({"value_id":id,"metadata":metadata})
                }
                Mutation::PromoteValue { .. } => json!({"value_id":id,"status":"active"}),
                Mutation::DeprecateValue { .. } => {
                    json!({"value_id":id,"status":"deprecated","records_quarantined":records_quarantined})
                }
                Mutation::AliasValue { canonical_id, .. } => {
                    json!({"value_id":id,"status":"deprecated","alias_of":canonical_id})
                }
                Mutation::DeleteValue { .. } => json!({"value_id":id,"deleted":true}),
                _ => unreachable!(),
            }
        }
    };
    Ok(Transition { changes, result })
}

// Match the actual pinned compat carrier; arbitrary similarly named fields
// on an ordinary definition must never create v1 type/kind identity.
async fn kind_records_on(
    conn: &mut SqliteConnection,
    typ: &str,
    tokens: &[Value],
    include_deleted: bool,
) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM kernel_records r LEFT JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' WHERE (CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(t.value_json,'$') ELSE r.primary_type END)=? AND (CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(k.value_json,'$') ELSE r.kind END) IN (SELECT value FROM json_each(?)) AND (? OR NOT EXISTS(SELECT 1 FROM kernel_import_tombstones d WHERE d.record_id=r.id))")
        .bind(typ).bind(serde_json::to_string(tokens)?).bind(include_deleted).fetch_one(conn).await?)
}

async fn glossary_alias(
    conn: &mut SqliteConnection,
    vid: &str,
    old: &Value,
    canonical: &Value,
) -> Result<()> {
    if vid != "voc:glossary" {
        return Ok(());
    }
    let vocabs = v1_state::rows_on(conn, "vocabularies").await?;
    let values = v1_state::rows_on(conn, "vocabulary_values").await?;
    let kind_vocab = vocabs
        .iter()
        .find(|v| v["name"] == "kind:Document")
        .map(|v| v["id"].clone());
    let definitions: Vec<(String,String,String)> = sqlx::query_as("SELECT r.id,CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(k.value_json,'$') ELSE r.kind END,f.value FROM kernel_records r LEFT JOIN kernel_record_fields t ON t.record_id=r.id AND t.name='v1_type' LEFT JOIN kernel_record_fields k ON k.record_id=r.id AND k.name='v1_kind' JOIN kernel_record_metadata m ON m.record_id=r.id JOIN kernel_facets f ON f.record_id=r.id WHERE (CASE WHEN r.pin_family='native.v1.record' AND r.pin_version=1 THEN json_extract(t.value_json,'$') ELSE r.primary_type END)='Document' AND m.maturity='decided' AND f.key='term' AND f.vocab_ref IN ('voc:glossary','rec:voc:glossary') AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones d WHERE d.record_id=r.id) AND NOT EXISTS(SELECT 1 FROM kernel_lifecycle a WHERE a.record_id=r.id AND a.archived=1)").fetch_all(conn).await?;
    let mut resulting_definitions = 0;
    for (record, kind, term) in definitions {
        let governed_kind = values
            .iter()
            .find(|v| Some(&v["vocabulary_id"]) == kind_vocab.as_ref() && v["value"] == kind);
        let definition = governed_kind
            .and_then(|v| {
                if v["alias_of"].is_null() {
                    Some(v)
                } else {
                    values.iter().find(|c| c["id"] == v["alias_of"])
                }
            })
            .is_some_and(|v| v["value"] == "definition" && v["status"] == "active");
        if !definition {
            continue;
        }
        if old["value"] == term {
            return Err(Error::engine(format!("cannot alias glossary term while current agreed definition {record} uses it — retarget or supersede first")));
        }
        if let Some(value) = values
            .iter()
            .find(|v| v["vocabulary_id"] == vid && v["value"] == term)
        {
            let target = if value["id"] == old["id"] || value["alias_of"] == old["id"] {
                &canonical["id"]
            } else if value["alias_of"].is_null() {
                &value["id"]
            } else {
                &value["alias_of"]
            };
            if *target == canonical["id"] {
                resulting_definitions += 1;
            }
        }
    }
    if resulting_definitions > 1 {
        return Err(Error::engine(
            "glossary alias would merge distinct current agreed definitions",
        ));
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn mutate_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    mutation: Mutation,
    expected_revision: Option<&str>,
    acts: &mut crate::act::ActAllocation,
) -> Result<Value> {
    app_installs::admit_dispatched_on(tx, actor).await?;
    kernel_require(tx, actor, KERNEL_ROOT_ID, Capability::Manage).await?;
    let revision = revision_on(tx).await?;
    if expected_revision.is_some_and(|r| r != revision) {
        return Err(Error::conflict(format!(
            "schema state revision conflict: current {revision}"
        )));
    }
    let mut preview = transition(tx, &mutation, &chrono::Utc::now().to_rfc3339()).await?;
    if !preview.changes.is_empty() {
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&mutation)?));
        let pending = app_installs::start_app_action_in(
            db,
            tx,
            actor,
            "manage_vocabularies",
            digest,
            None,
            acts,
        )
        .await?;
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: KERNEL_ROOT_ID.into(),
                event_type: EVENT.into(),
                payload: serde_json::to_value(mutation)?,
                actor: Some(actor.into()),
            },
            acts,
        )
        .await?;
        if let Some(attribution) =
            app_installs::finish_app_action_in(db, tx, actor, pending, acts).await?
        {
            preview.result["app_attribution"] = attribution;
        }
        preview.result["act"] = json!(acts.get());
    }
    Ok(preview.result)
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type != EVENT {
        return Ok(());
    }
    if event.record_id != KERNEL_ROOT_ID {
        return Err(Error::engine(
            "vocabulary mutation requires kernel root stream",
        ));
    }
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| Error::auth("vocabulary mutation requires actor"))?;
    #[cfg(feature = "v2-kernel-probe")]
    app_installs::admit_dispatched_on(conn, actor).await?;
    kernel_require(conn, actor, KERNEL_ROOT_ID, Capability::Manage).await?;
    let mutation = event_payload(event)?;
    transition(conn, &mutation, &event.created_at).await?;
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.record_id != KERNEL_ROOT_ID {
        return Err(Error::engine(
            "vocabulary mutation requires kernel root stream",
        ));
    }
    let mutation = event_payload(event)?;
    let transition = transition(conn, &mutation, &event.created_at).await?;
    for (section, id, row) in transition.changes {
        project_row_on(conn, event, section, &id, row).await?;
    }
    Ok(())
}

/// Native catalogue folds preserve an imported primary-key tuple and source
/// origin while moving the observation and event position to the native event.
pub(crate) async fn project_row_on(
    conn: &mut SqliteConnection,
    event: &EventRow,
    section: &str,
    id: &str,
    row: Option<Value>,
) -> Result<()> {
    // Imported catalogue identities are JSON-encoded primary-key tuples,
    // not raw row IDs. Preserve an existing key and its source origin.
    let source_id: Option<String> = sqlx::query_scalar(
        "SELECT source_id FROM kernel_v1_state WHERE section=? AND json_extract(payload,'$.id')=?",
    )
    .bind(section)
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let source_id = source_id.unwrap_or(serde_json::to_string(&vec![id])?);
    match row {
        Some(row) => {
            sqlx::query("INSERT INTO kernel_v1_state(section,source_id,origin,payload,observed_at,event_seq) VALUES(?,?,'native:v2',?,?,?) ON CONFLICT(section,source_id) DO UPDATE SET payload=excluded.payload,observed_at=excluded.observed_at,event_seq=excluded.event_seq").bind(section).bind(&source_id).bind(serde_json::to_string(&row)?).bind(&event.created_at).bind(event.local_seq).execute(&mut *conn).await?;
        }
        None => {
            sqlx::query("DELETE FROM kernel_v1_state WHERE section=? AND source_id=?")
                .bind(section)
                .bind(&source_id)
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}
