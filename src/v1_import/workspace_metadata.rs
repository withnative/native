//! Keep the v1 root's display metadata separate from domain record import.
use super::*;

pub(super) async fn import(db: &Db, host: &str, root: &Record) -> Result<()> {
    k::workspace_metadata::import_as(
        db,
        host,
        k::workspace_metadata::WorkspaceMetadata {
            name: root.name.clone(),
            source_root_id: root.id.clone(),
            summary: root.summary.clone(),
        },
    )
    .await?;
    Ok(())
}
