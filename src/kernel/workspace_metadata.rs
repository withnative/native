//! Host-imported workspace metadata. This reserved root stream is not a domain
//! record: ordinary record mutation cannot rename it, and replay needs no DDL.
use super::*;

pub const RECORD_ID: &str = "kernel:workspace-metadata";
pub(crate) const EVENT_TYPE: &str = "kernel.workspace_metadata_imported.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceMetadata {
    pub name: String,
    pub source_root_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

pub async fn read(db: &Db) -> Result<Option<WorkspaceMetadata>> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(RECORD_ID)
    .bind(EVENT_TYPE)
    .fetch_optional(db.pool())
    .await?;
    raw.map(|raw| serde_json::from_str(&raw).map_err(Into::into))
        .transpose()
}

pub(crate) async fn import_as(db: &Db, principal: &str, metadata: WorkspaceMetadata) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, principal).await?;
    hq::require_source_import_open(&mut tx).await?;
    let previous: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT payload,actor FROM content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1",
    ).bind(RECORD_ID).bind(EVENT_TYPE).fetch_optional(&mut *tx).await?;
    let payload = serde_json::to_value(&metadata)?;
    if let Some((raw, actor)) = previous {
        if actor.as_deref() != Some(principal) {
            return Err(Error::conflict(
                "workspace metadata belongs to a different import host",
            ));
        }
        if serde_json::from_str::<WorkspaceMetadata>(&raw)? == metadata {
            return Ok(());
        }
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: RECORD_ID.into(),
            event_type: EVENT_TYPE.into(),
            payload,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    hq::require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
    let metadata: WorkspaceMetadata = event_payload(event)?;
    if event.record_id != RECORD_ID || metadata.source_root_id != crate::schema::ROOT_RECORD_ID {
        return Err(Error::engine("invalid imported workspace root metadata"));
    }
    // The retained, host-attributed root stream is the metadata record. There
    // is no domain-row projection or open-time schema repair.
    Ok(())
}
