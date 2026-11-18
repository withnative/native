//! Same-bearer correction for the two ordinary v1-compatible kernel carriers.
//! Body, facets, ownership and placement are separate projections and survive.
use super::*;
#[cfg(feature = "v2-kernel-probe")]
use serde_json::json;
use serde_json::Value;

pub(crate) const EVENT: &str = "kernel.record_type_corrected.v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corrected {
    previous_seq: i64,
    from: crate::record_type_correction::Identity,
    to: crate::record_type_correction::Identity,
    reason: String,
    record: KernelRecordPayload,
}

async fn identity_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<crate::record_type_correction::Identity> {
    let (typ, kind, family, version): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT primary_type,kind,pin_family,pin_version FROM kernel_records WHERE id=?",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    let fields: Vec<(String, String)> =
        sqlx::query_as("SELECT name,value_json FROM kernel_record_fields WHERE record_id=?")
            .bind(id)
            .fetch_all(&mut *conn)
            .await?;
    let fields = fields
        .into_iter()
        .map(|(k, v)| Ok((k, serde_json::from_str(&v)?)))
        .collect::<Result<serde_json::Map<String, Value>>>()?;
    let (typ, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        family.as_deref(),
        version.map(|v| v as u32),
        typ.as_deref(),
        kind.as_deref(),
        &fields,
    );
    Ok(crate::record_type_correction::Identity {
        record_type: typ
            .ok_or_else(|| Error::engine("record has no semantic type"))?
            .into(),
        kind: kind
            .ok_or_else(|| Error::engine("record has no semantic kind"))?
            .into(),
    })
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type != EVENT {
        return Ok(());
    }
    let p: Corrected = event_payload(event)?;
    kernel_require(
        conn,
        event.actor.as_deref().unwrap_or_default(),
        &event.record_id,
        Capability::Manage,
    )
    .await?;
    validate_before(conn, event, &p).await?;
    let pin = p
        .record
        .pin
        .as_ref()
        .ok_or_else(|| Error::engine("correction requires a pin"))?;
    if resolve_adoption_pin_only(conn, &pin.family, &p.record.home_id).await? != *pin {
        return Err(Error::conflict("type correction adoption changed"));
    }
    Ok(())
}

pub(crate) async fn require_unregistered_on(
    conn: &mut SqliteConnection,
    record: &str,
) -> Result<()> {
    let specialized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_link4_edges WHERE source_id=?1 OR target_id=?1) OR EXISTS(SELECT 1 FROM kernel_account_configs WHERE record_id=?1) OR EXISTS(SELECT 1 FROM kernel_message_people WHERE person_id=?1) OR EXISTS(SELECT 1 FROM kernel_app_package_sources WHERE artifact_id=?1) OR EXISTS(SELECT 1 FROM kernel_artifact_closures WHERE artifact_id=?1) OR EXISTS(SELECT 1 FROM kernel_app_installs WHERE json_extract(row_json,'$.artifact_id')=?1)")
        .bind(record).fetch_one(&mut *conn).await?;
    if specialized {
        return Err(Error::engine(
            "type correction: registered identity or typed links require a new bearer",
        ));
    }
    Ok(())
}

async fn validate_before(
    conn: &mut SqliteConnection,
    event: &EventRow,
    p: &Corrected,
) -> Result<()> {
    if p.reason.trim().is_empty()
        || p.from == p.to
        || !crate::schema::SPINE_TYPES.contains(&p.to.record_type.as_str())
    {
        return Err(Error::engine("invalid type correction"));
    }
    let head: Option<i64> =
        sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE record_id=? AND seq<?")
            .bind(&event.record_id)
            .bind(if event.local_seq < 0 {
                i64::MAX
            } else {
                event.local_seq
            })
            .fetch_one(&mut *conn)
            .await?;
    if head != Some(p.previous_seq) || identity_on(conn, &event.record_id).await? != p.from {
        return Err(Error::conflict("type correction: record changed"));
    }
    if matches!(
        p.from.record_type.as_str(),
        "Annotation" | "Message" | "Unit" | "Program"
    ) || (p.from.record_type == "Document" && p.from.kind == "attachment")
        || matches!(p.to.record_type.as_str(), "Annotation" | "Message" | "Unit")
        || (p.to.record_type == "Document" && p.to.kind == "attachment")
    {
        return Err(Error::engine(
            "type correction: specialized identity requires a new bearer",
        ));
    }
    require_unregistered_on(conn, &event.record_id).await?;
    let scoped: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_v1_state WHERE section='schema_config' AND json_extract(payload,'$.applies_to_collection_id')=?) OR EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=? AND EXISTS(SELECT 1 FROM kernel_records child WHERE child.home_id=kernel_roots.root_id AND child.id<>?))")
        .bind(&event.record_id).bind(&event.record_id).bind(&event.record_id).fetch_one(&mut *conn).await?;
    if scoped && p.from.record_type == "Collection" && p.to.record_type != "Collection" {
        return Err(Error::engine("type correction: dependent schema or filing scope requires retaining Collection identity"));
    }
    let (old_family, old_version): (Option<String>, Option<i64>) =
        sqlx::query_as("SELECT pin_family,pin_version FROM kernel_records WHERE id=?")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?;
    let ordinary = old_family.as_deref() == Some(crate::v2_standard::DOCUMENT_FAMILY)
        || (old_family.as_deref() == Some(crate::v2_standard::v1_compat::FAMILY)
            && old_version == Some(1));
    let pin = p
        .record
        .pin
        .as_ref()
        .ok_or_else(|| Error::engine("type correction requires a definition"))?;
    let target_family = if p.to.record_type == "Document" && p.to.kind == "note" {
        crate::v2_standard::DOCUMENT_FAMILY
    } else {
        crate::v2_standard::v1_compat::FAMILY
    };
    if !ordinary
        || pin.family != target_family
        || (target_family == crate::v2_standard::v1_compat::FAMILY && pin.version != 1)
    {
        return Err(Error::engine(
            "type correction requires an ordinary standard or compatible carrier",
        ));
    }
    let (home, owner): (String, Option<String>) =
        sqlx::query_as("SELECT home_id,owner_id FROM kernel_records WHERE id=?")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?;
    if p.record.home_id != home || p.record.owner_id != owner {
        return Err(Error::engine(
            "type correction cannot change authority or placement",
        ));
    }
    let fields = p
        .record
        .fields
        .as_ref()
        .ok_or_else(|| Error::engine("type correction fields missing"))?;
    let old: Vec<(String, String)> =
        sqlx::query_as("SELECT name,value_json FROM kernel_record_fields WHERE record_id=?")
            .bind(&event.record_id)
            .fetch_all(&mut *conn)
            .await?;
    let mut retained = serde_json::Map::new();
    for (name, value) in old {
        if name != "v1_type" && name != "v1_kind" {
            retained.insert(name, serde_json::from_str::<Value>(&value)?);
        }
    }
    let mut proposed = fields.clone();
    proposed.remove("v1_type");
    proposed.remove("v1_kind");
    if retained != proposed || p.record.origin.is_some() || p.record.basis.is_some() {
        return Err(Error::engine(
            "type correction must preserve all record fields and provenance",
        ));
    }
    let (typ, kind) = crate::v2_standard::v1_compat::v1_type_and_kind(
        p.record.pin.as_ref().map(|p| p.family.as_str()),
        p.record.pin.as_ref().map(|p| p.version),
        p.record.primary_type.as_deref(),
        p.record.kind.as_deref(),
        fields,
    );
    if typ != Some(p.to.record_type.as_str()) || kind != Some(p.to.kind.as_str()) {
        return Err(Error::engine(
            "type correction effect does not match its record",
        ));
    }
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Corrected = event_payload(event)?;
    validate_before(conn, event, &p).await?;
    let mut inner = event.clone();
    inner.payload = Some(serde_json::to_string(&p.record)?);
    project_kernel_record_created(conn, &inner).await
}

#[cfg(feature = "v2-kernel-probe")]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn correct_in(
    db: &Db,
    conn: &mut SqliteConnection,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    id: &str,
    target_type: &str,
    target_kind: &str,
    reason: &str,
) -> Result<Value> {
    let previous = read_record_on(conn, actor, id)
        .await?
        .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    kernel_require(conn, actor, id, Capability::Manage).await?;
    if !matches!(
        previous.family.as_deref(),
        Some(crate::v2_standard::DOCUMENT_FAMILY | crate::v2_standard::v1_compat::FAMILY)
    ) {
        return Err(Error::engine(
            "correct_record_type: a specialized native definition requires an explicit new bearer",
        ));
    }
    let mut fields = previous.fields.clone();
    if fields
        .keys()
        .any(|k| !["title", "summary", "lifecycle", "v1_type", "v1_kind"].contains(&k.as_str()))
    {
        return Err(Error::engine("correct_record_type: correction would discard definition-specific fields; create a new bearer"));
    }
    let from = identity_on(conn, id).await?;
    let (family, physical_type, physical_kind) =
        if target_type == "Document" && target_kind == "note" {
            fields.remove("v1_type");
            fields.remove("v1_kind");
            (crate::v2_standard::DOCUMENT_FAMILY, "Document", "note")
        } else {
            fields.insert("v1_type".into(), json!(target_type));
            fields.insert("v1_kind".into(), json!(target_kind));
            (
                crate::v2_standard::v1_compat::FAMILY,
                "V1",
                crate::v2_standard::v1_compat::KIND,
            )
        };
    let pin = select_adoption_pin(
        conn,
        family,
        physical_type,
        physical_kind,
        &previous.home_id,
    )
    .await?;
    let artifact = crate::definition_registry::read_definition_artifact_on(
        conn,
        family,
        pin.version,
        &pin.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("missing correction target definition"))?;
    validated_field_rows(conn, &artifact.bytes, family, physical_kind, &fields).await?;
    let interpreter = interpreter_for_bytes(&artifact.bytes)?.to_owned();
    let p = Corrected {
        previous_seq: previous.revision,
        from: from.clone(),
        to: crate::record_type_correction::Identity {
            record_type: target_type.into(),
            kind: target_kind.into(),
        },
        reason: reason.into(),
        record: KernelRecordPayload {
            home_id: previous.home_id,
            owner_id: previous.owner_id,
            primary_type: Some(physical_type.into()),
            kind: Some(physical_kind.into()),
            accession: Some(format!("{family}:{physical_kind}:{id}")),
            pin: Some(pin),
            interpreter: Some(interpreter),
            fields: Some(fields),
            origin: None,
            basis: None,
        },
    };
    let event = crate::store::append_on(
        db,
        conn,
        AppendSpec {
            record_id: id.into(),
            event_type: EVENT.into(),
            payload: serde_json::to_value(&p)?,
            actor: Some(actor.into()),
        },
        acts,
    )
    .await?;
    Ok(json!({"record_id":id,"changed":true,"from":from,"to":p.to,
        "event_id":event.id,"reason":reason,"act":acts.get()}))
}
