//! Dark, engine-only publication of governed SQL. No tool registers views.
use super::*;
use crate::mcp::tools::querying::{validate_saved_sql, SavedSqlDefinition};
use sha2::{Digest, Sha256};

pub(crate) const EVENT: &str = "kernel.named_view_admitted.v1";
#[cfg(test)]
pub(crate) const KEY: &str = "named_view";
pub(crate) const MAX_BINDINGS: i64 = 8;
pub(crate) const MAX_CARRIER_BYTES: usize = 256 * 1024;

// Materialization and LEFT JOIN fix the driving side before facet lookups.
// Explicit preparation installs the optional partial index. seq + 0 avoids
// choosing a full-log rowid-order scan when that index exists. Older files
// remain readable through a scan; reads never create the missing index.
pub(crate) const DISCOVER_SQL: &str = "WITH admissions AS MATERIALIZED (
    SELECT record_id,seq,payload FROM main.content_events
    WHERE type='kernel.named_view_admitted.v1' ORDER BY seq + 0 LIMIT 9
) SELECT e.record_id,f.value,e.seq,e.payload FROM admissions e
LEFT JOIN main.kernel_facets f ON f.record_id=e.record_id AND f.key='named_view'
AND f.event_seq=e.seq";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub v: u32,
    pub name: String,
    pub definition_sha256: String,
    pub origin: String,
}

pub(crate) fn digest(definition: &SavedSqlDefinition) -> Result<String> {
    let bytes =
        native_artifact_runtime::mdx_v2::canonical_json_bytes(&serde_json::to_value(definition)?);
    if bytes.len() > MAX_CARRIER_BYTES {
        return Err(Error::engine("named view carrier exceeds 256 KiB"));
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if !name.starts_with("view_")
        || name.len() <= 5
        || name.len() > 128
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        || crate::query::sql_contract::is_logical_relation(name)
    {
        return Err(Error::engine(
            "named view name must be a lowercase view_ identifier (6..128 ASCII bytes)",
        ));
    }
    Ok(())
}

pub(crate) fn validate_definition(definition: &SavedSqlDefinition) -> Result<()> {
    digest(definition)?;
    validate_saved_sql(definition)?;
    crate::query::turso_ast_rules::validate_named_view_shape(&definition.sql)?;
    if !definition.parameters.is_empty() {
        return Err(Error::engine("named views cannot contain parameters"));
    }
    let profile = crate::query::sql_contract::QuerySqlProfile::SqliteLocal;
    if crate::query::sql_contract::rewrite_now_ms_calls(profile, &definition.sql, "?1")?.1 > 0
        || crate::query::sql_contract::rewrite_current_principal_calls(
            profile,
            &definition.sql,
            "?1",
        )?
        .1 > 0
    {
        return Err(Error::engine(
            "named views cannot contain clock or principal binds",
        ));
    }
    crate::query::sql::validate_kernel_v2_ad_hoc(&definition.sql)?;
    for (relation, column) in crate::query::sql::public_reads_ad_hoc(&definition.sql)? {
        if relation.starts_with("catalog_") {
            return Err(Error::engine("named views cannot depend on catalogs"));
        }
        let columns = crate::mcp::kernel_v2::sql::columns(&relation).ok_or_else(|| {
            Error::engine(format!(
                "named view relation '{relation}' unavailable on v2"
            ))
        })?;
        if !column.is_empty() && !columns.contains(&column.as_str()) {
            return Err(Error::engine(format!(
                "named view column '{relation}.{column}' unavailable on v2"
            )));
        }
    }
    Ok(())
}

/// Admission is repeated at the append boundary so raw append cannot bypass it.
pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type != EVENT {
        return Ok(());
    }
    let actor = event.actor.as_deref().unwrap_or_default();
    if !kernel_effective_capability_on(conn, actor, &event.record_id)
        .await?
        .allows(Capability::Manage)
        || read_record_on(conn, actor, &event.record_id)
            .await?
            .is_none()
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let binding: Binding = event_payload(event)?;
    validate_name(&binding.name)?;
    let raw: String = sqlx::query_scalar(
        "SELECT value FROM kernel_facets WHERE record_id=? AND key='query' AND value IS NOT NULL",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if raw.len() > MAX_CARRIER_BYTES {
        return Err(Error::engine("named view carrier exceeds 256 KiB"));
    }
    let definition: SavedSqlDefinition = serde_json::from_str(&raw)?;
    validate_definition(&definition)?;
    if binding.v != 1
        || binding.origin != "authored"
        || binding.definition_sha256 != digest(&definition)?
    {
        return Err(Error::engine(
            "named view binding version/origin/digest mismatch",
        ));
    }
    let rows: Vec<(String, Option<String>, i64, String)> =
        sqlx::query_as(DISCOVER_SQL).fetch_all(&mut *conn).await?;
    if rows.len() as i64 >= MAX_BINDINGS {
        return Err(Error::conflict("named view binding cap (8) reached"));
    }
    for (id, _, _, raw) in rows {
        let existing: Binding = serde_json::from_str(&raw)?;
        if id == event.record_id || existing.name.eq_ignore_ascii_case(&binding.name) {
            return Err(Error::conflict(
                "named view binding already exists or name unavailable",
            ));
        }
    }
    Ok(())
}

/// Deliberately crate-private and unregistered. An operator must explicitly
/// arrange admission; merely saving governed SQL never publishes a relation.
#[cfg(test)]
pub(crate) async fn publish(db: &Db, actor: &str, record: &str, name: &str) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    if !kernel_effective_capability_on(&mut tx, actor, record)
        .await?
        .allows(Capability::Manage)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let raw: String = sqlx::query_scalar(
        "SELECT value FROM kernel_facets WHERE record_id=? AND key='query' AND value IS NOT NULL",
    )
    .bind(record)
    .fetch_one(&mut *tx)
    .await?;
    if raw.len() > MAX_CARRIER_BYTES {
        return Err(Error::engine("named view carrier exceeds 256 KiB"));
    }
    let definition = serde_json::from_str(&raw)?;
    let binding = Binding {
        v: 1,
        name: name.into(),
        definition_sha256: digest(&definition)?,
        origin: "authored".into(),
    };
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: record.into(),
            event_type: EVENT.into(),
            payload: serde_json::to_value(binding)?,
            actor: Some(actor.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_view_names_are_closed_and_historic_facets_fold() {
        for name in ["view_tasks", "view_tasks_2"] {
            validate_name(name).unwrap();
        }
        for name in [
            "records",
            "view_",
            "View_tasks",
            "view_x;DROP TABLE records",
            "_v2_visible",
        ] {
            assert!(validate_name(name).is_err(), "{name}");
        }
        assert!(hq::validate_facet(&FacetObservation {
            key: KEY.into(),
            value: Some("{}".into()),
            value_num: None,
            vocab_ref: None,
            as_of: "2026-10-24T00:00:00Z".into()
        })
        .is_ok());
    }
}
