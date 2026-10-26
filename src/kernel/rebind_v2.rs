//! Gated, governed rebind used to exercise real binding races, never projection edits.
use super::links_v2::{endpoint, EndpointWitness};
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rebind {
    before: EndpointWitness,
    record: KernelRecordPayload,
}
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) async fn rebind_record_as(
    db: &Db,
    actor: &str,
    record: &str,
    family: &str,
    kind: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    kernel_require(&mut tx, actor, record, Capability::Manage).await?;
    let before = endpoint(&mut tx, record, i64::MAX).await?;
    let (home, owner): (String, Option<String>) =
        sqlx::query_as("SELECT home_id,owner_id FROM kernel_records WHERE id=?")
            .bind(record)
            .fetch_one(&mut *tx)
            .await?;
    let pin = resolve_adoption_pin_only(&mut tx, family, &home).await?;
    let artifact = crate::definition_registry::read_definition_artifact_on(
        &mut tx,
        family,
        pin.version,
        &pin.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("missing rebind definition"))?;
    let doc: serde_json::Value = serde_json::from_str(&artifact.bytes)?;
    let primary_type = doc["primary_type"]
        .as_str()
        .ok_or_else(|| Error::engine("missing rebind primary type"))?;
    let (_, identity) =
        validated_field_rows(&mut tx, &artifact.bytes, family, kind, fields).await?;
    let accession = match identity {
        IdentityOutcome::Field(_, value) => format!("{family}:{kind}:{value}"),
        IdentityOutcome::Record => format!("{family}:{kind}:{record}"),
        IdentityOutcome::Legacy => format!("{family}:{kind}:"),
    };
    let interpreter = interpreter_for_bytes(&artifact.bytes)?.to_string();
    let payload = Rebind {
        before,
        record: KernelRecordPayload {
            home_id: home,
            owner_id: owner,
            primary_type: Some(primary_type.into()),
            kind: Some(kind.into()),
            accession: Some(accession),
            pin: Some(pin),
            interpreter: Some(interpreter),
            fields: Some(fields.clone()),
            origin: None,
            basis: None,
        },
    };
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: record.into(),
            event_type: "kernel.record_rebound.v1".into(),
            payload: serde_json::to_value(payload)?,
            actor: Some(actor.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
pub(crate) async fn project(
    conn: &mut SqliteConnection,
    event: &EventRow,
    replay: bool,
) -> Result<()> {
    let p: Rebind = event_payload(event)?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| Error::engine("rebind requires an actor"))?;
    if event.record_id != p.before.record_id
        || endpoint(conn, &event.record_id, event.local_seq).await? != p.before
    {
        return Err(Error::conflict("rebind endpoint or binding head moved"));
    }
    let (home, owner): (String, Option<String>) =
        sqlx::query_as("SELECT home_id,owner_id FROM kernel_records WHERE id=?")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?;
    if p.record.home_id != home || p.record.owner_id != owner {
        return Err(Error::engine("rebind cannot alter authority"));
    }
    if !replay {
        if !kernel_effective_capability_on(conn, actor, &event.record_id)
            .await?
            .allows(Capability::Manage)
        {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
        let pin = p
            .record
            .pin
            .as_ref()
            .ok_or_else(|| Error::engine("rebind requires a definition pin"))?;
        if resolve_adoption_pin_only(conn, &pin.family, &home).await? != *pin {
            return Err(Error::conflict("rebind selection moved"));
        }
    }
    let mut inner = event.clone();
    inner.payload = Some(serde_json::to_string(&p.record)?);
    project_kernel_record_created(conn, &inner).await
}
