//! Sealed current reserved links, including the v1 root omitted as a record.
use super::*;
pub(super) async fn rows(
    source: &mut SqliteConnection,
) -> Result<Vec<(String, serde_json::Value)>> {
    let rows:Vec<String>=sqlx::query_scalar("SELECT json_object('id',id,'source_id',source_id,'target_id',target_id,'note',note,'created_at',created_at) FROM links WHERE relationship='surface_binding' ORDER BY id").fetch_all(source).await?;
    rows.into_iter()
        .map(|raw| {
            let value: serde_json::Value = serde_json::from_str(&raw)?;
            let id = value["id"]
                .as_str()
                .ok_or("surface binding id missing")?
                .to_owned();
            Ok((serde_json::to_string(&[id])?, value))
        })
        .collect()
}
pub(super) async fn receipt(
    db: &Db,
    host: &str,
    origin: &str,
    observed_at: String,
    snapshot: serde_json::Value,
    report: &mut Report,
) -> Result<()> {
    let Some(count) = report.state.sections.get("surface_bindings") else {
        return Err("surface binding capture missing".into());
    };
    if count.refused != 0 || count.verified != count.source + count.removed {
        return Ok(());
    }
    let row = k::v1_state::ImportedState {
        section: k::v1_state::SURFACE_CAPTURE.into(),
        source_id: "surface-bindings/v1".into(),
        origin: origin.into(),
        value_json: Some("{\"version\":1}".into()),
        account_principal: None,
        record_id: None,
        observed_at,
        snapshot,
    };
    k::v1_state::import_state_batch_as(db, host, &[row]).await?;
    report.state.surface_bindings_prepared = true;
    Ok(())
}
