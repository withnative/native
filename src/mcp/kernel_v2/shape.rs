//! Run v1's actual deterministic shape fold over authorized sealed catalogue
//! rows in one kernel snapshot. TEMP relations never enter a pooled successor.
use super::*;
use crate::authorization::Capability;

pub(super) async fn preview(db: &Db, actor: &str, arguments: Value) -> Result<Value> {
    let mut connection = db.pool().acquire().await?;
    connection.close_on_drop();
    let mut tx = sqlx::Connection::begin(&mut *connection).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let mut schema = Vec::new();
    for row in kernel::v1_state::rows_on(&mut tx, "schema_config").await? {
        if let Some(anchor) = row["applies_to_collection_id"].as_str() {
            let anchor = if anchor == "native:root" {
                crate::events::KERNEL_ROOT_ID
            } else {
                anchor
            };
            // An unresolved/invalid anchor grants no disclosure, just as the
            // governed SQL gate treats capability errors as hidden.
            if !matches!(kernel::kernel_effective_capability_on(&mut tx, actor, anchor).await,
                Ok(capability) if capability.allows(Capability::View))
            {
                continue;
            }
        }
        schema.push(row);
    }
    let vocabularies = kernel::v1_state::rows_on(&mut tx, "vocabularies").await?;
    let values = kernel::v1_state::rows_on(&mut tx, "vocabulary_values").await?;
    // These are deliberately data-only projections, not a v1 database and not
    // write admission. Column lists match the portable fold's three relations.
    for (name, columns, rows) in [
        (
            "schema_config",
            &[
                "id",
                "layer",
                "name",
                "data",
                "applies_to_collection_id",
                "version_lineage",
                "created_at",
            ][..],
            schema,
        ),
        (
            "vocabularies",
            &["id", "name", "created_at"][..],
            vocabularies,
        ),
        (
            "vocabulary_values",
            &[
                "id",
                "vocabulary_id",
                "value",
                "gloss",
                "status",
                "ordinal",
                "terminality",
                "metadata",
                "alias_of",
            ][..],
            values,
        ),
    ] {
        let projections = columns
            .iter()
            .map(|column| format!("json_extract(value,'$.{column}') AS \"{column}\""))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("CREATE TEMP TABLE {name} AS SELECT {projections} FROM json_each(?)");
        sqlx::query(&sql)
            .bind(serde_json::to_string(&rows)?)
            .execute(&mut *tx)
            .await?;
    }
    let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
        .fetch_one(&mut *tx)
        .await?;
    let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut tx);
    // The member path omits legacy event-head reads. Replace its basis below
    // with the real kernel snapshot, never fabricated v1 meta/content counters.
    let mut response = crate::domain_transaction::execute_preview_record_shape(
        &mut executor,
        &Caller::authenticated(actor),
        arguments,
        true,
    )
    .await?;
    response["advisory_basis"]["schema_state_revision"] =
        json!(format!("kernel-schema-state-v1:content:{head}"));
    response["advisory_basis"]["kernel_content_head"] = json!(head);
    if serde_json::to_vec(&response)?.len() > 65_536 {
        return Err(Error::engine(
            "preview_record_shape: response exceeds 65536 bytes",
        ));
    }
    tx.rollback().await?;
    Ok(response)
}
