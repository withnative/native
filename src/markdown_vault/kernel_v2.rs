//! V2 source adapter only. Generation acquisition/admission stays with N1;
//! rendering and filesystem publication keep the existing vault contract.
use super::{SourceLink, SourceRecord, SourceSnapshot};
use crate::{authorization::Capability, db::Db, kernel, Error, Result};
use serde_json::Value;
use sqlx::{Connection, Row, SqliteConnection};
use std::collections::BTreeMap;

pub(crate) async fn snapshot(db: &Db, credential: &str) -> Result<SourceSnapshot> {
    let mut connection = db.pool().acquire().await?;
    // Production SQL staging owns TEMP state. Never return it to a pool,
    // including on cancellation, an invalid body, or an authorization failure.
    connection.close_on_drop();
    snapshot_on(&mut connection, credential).await
}

pub(crate) async fn snapshot_on(
    connection: &mut SqliteConnection,
    credential: &str,
) -> Result<SourceSnapshot> {
    let mut tx = connection.begin().await?;
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut *tx)
        .await?;
    if marker != crate::db::V2_APPLICATION_ID {
        return Err(Error::engine(
            "v2 Markdown vault requires an NKV2 generation",
        ));
    }
    let actors: Vec<String> = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(credential)
    .fetch_all(&mut *tx)
    .await?;
    let [actor] = actors.as_slice() else {
        return Err(Error::auth("vault account binding is unavailable"));
    };
    if !kernel::hosted_identity::admitted(&mut tx, actor).await? {
        return Err(Error::auth("database membership not found"));
    }
    // A vault needs its root, just as the v1 renderer does. Its name/summary
    // are disclosed only after the production root-capability check.
    kernel::kernel_require(
        &mut tx,
        actor,
        crate::events::KERNEL_ROOT_ID,
        Capability::View,
    )
    .await?;
    let act = crate::act::current_act(&mut tx).await?;
    let origin = origin(&mut tx).await?;
    let reads = ["records", "links", "facet_values"]
        .into_iter()
        .flat_map(|name| {
            crate::query::sql_contract::LOGICAL_RELATIONS
                .iter()
                .filter(move |relation| relation.name == name)
                .flat_map(move |relation| {
                    relation
                        .columns
                        .iter()
                        .map(move |column| (name.to_owned(), (*column).to_owned()))
                })
        })
        .collect();
    crate::mcp::kernel_v2::sql::install(&mut tx, actor, &reads).await?;
    let mut source = SourceSnapshot {
        origin,
        account: credential.into(),
        act,
        ..Default::default()
    };
    for row in sqlx::query("SELECT * FROM temp.records ORDER BY created_at,id")
        .fetch_all(&mut *tx)
        .await?
    {
        let mut metadata = BTreeMap::new();
        for key in [
            "summary",
            "lifecycle",
            "maturity",
            "created_at",
            "updated_at",
            "last_activity_at",
        ] {
            if let Some(value) = row.try_get::<Option<String>, _>(key)? {
                metadata.insert(key.into(), Value::String(value));
            }
        }
        if row.try_get::<i64, _>("successor_count")? > 0 {
            metadata.insert("superseded".into(), Value::Bool(true));
        }
        let record = SourceRecord {
            id: row.try_get("id")?,
            record_type: row
                .try_get::<Option<String>, _>("type")?
                .unwrap_or_else(|| "Record".into()),
            kind: row.try_get("kind")?,
            name: row.try_get("name")?,
            body: row.try_get("body")?,
            home_id: row.try_get("home_id")?,
            archived: row.try_get::<i64, _>("archived")? != 0,
            metadata,
            ..Default::default()
        };
        source.records.insert(record.id.clone(), record);
    }
    // Root metadata is a sealed import stream, not an ordinary domain row.
    // Native-created v2 databases have no stream and use the picker fallback.
    let root: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type='kernel.workspace_metadata_imported.v1' ORDER BY seq DESC LIMIT 1")
        .bind(kernel::workspace_metadata::RECORD_ID).fetch_optional(&mut *tx).await?;
    let root = root
        .map(|raw| serde_json::from_str::<kernel::workspace_metadata::WorkspaceMetadata>(&raw))
        .transpose()?;
    let mut metadata = BTreeMap::new();
    if let Some(summary) = root.as_ref().and_then(|root| root.summary.clone()) {
        metadata.insert("summary".into(), Value::String(summary));
    }
    source.records.insert(
        "native:root".into(),
        SourceRecord {
            id: "native:root".into(),
            record_type: "Collection".into(),
            kind: Some("folder".into()),
            name: Some(
                root.map(|root| root.name)
                    .unwrap_or_else(|| "Native workspace".into()),
            ),
            metadata,
            ..Default::default()
        },
    );
    layout_homes(&mut tx, &mut source).await?;
    for row in
        sqlx::query("SELECT record_id,key,value FROM temp.facet_values ORDER BY record_id,key,id")
            .fetch_all(&mut *tx)
            .await?
    {
        if let Some(record) = source
            .records
            .get_mut(&row.try_get::<String, _>("record_id")?)
        {
            record.facets.insert(
                row.try_get("key")?,
                row.try_get::<Option<String>, _>("value")?
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
        }
    }
    for row in sqlx::query("SELECT source_id,target_id,relationship,note FROM temp.links ORDER BY source_id,relationship,target_id,id").fetch_all(&mut *tx).await? {
        source.links.push(SourceLink { source_id: row.try_get("source_id")?, target_id: row.try_get("target_id")?, relationship: row.try_get("relationship")?, note: row.try_get("note")? });
    }
    // Never fetch an anchor whose endpoints weren't admitted by the same
    // production visible set. In particular, stale-home attachments and
    // comments use the production terminal-bearer visibility rule.
    for row in sqlx::query("SELECT a.annotation_id,a.selectors FROM kernel_comment_anchors a JOIN temp.records c ON c.id=a.annotation_id JOIN temp.records t ON t.id=a.target_record_id ORDER BY a.annotation_id").fetch_all(&mut *tx).await? {
        if let Some(record) = source.records.get_mut(&row.try_get::<String, _>("annotation_id")?) {
            record.anchors.push(serde_json::from_str(&row.try_get::<String, _>("selectors")?)?);
        }
    }
    // Owner and creator identities are emitted only as visible Person
    // records, never principal labels, auth bindings or private directory rows.
    for row in sqlx::query("SELECT r.id,d.record_id AS person FROM kernel_records r JOIN temp.records v ON v.id=r.id JOIN kernel_v1_state d ON d.section='account_directory' AND d.account_principal=r.owner_id JOIN temp.records p ON p.id=d.record_id WHERE p.type='Entity' AND p.kind='person'").fetch_all(&mut *tx).await? {
        if let Some(record) = source.records.get_mut(&row.try_get::<String, _>("id")?) {
            record.metadata.insert("owner".into(), Value::String(row.try_get("person")?));
        }
    }
    for row in sqlx::query("SELECT r.id,d.record_id AS person FROM temp.records r JOIN main.content_events first ON first.seq=(SELECT min(seq) FROM main.content_events WHERE record_id=r.id AND type IN ('kernel.record_created.v1','kernel.import_record_created.v1')) LEFT JOIN main.content_events provenance ON provenance.seq=(SELECT min(seq) FROM main.content_events WHERE record_id=r.id AND type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='v1.snapshot_provenance') JOIN kernel_principals a ON a.principal_id=coalesce(json_extract(provenance.payload,'$.legacy.payload.creator'),first.actor) OR a.auth_binding=json_extract(provenance.payload,'$.legacy.payload.creator') JOIN kernel_v1_state d ON d.section='account_directory' AND d.account_principal=a.principal_id JOIN temp.records p ON p.id=d.record_id WHERE p.type='Entity' AND p.kind='person'").fetch_all(&mut *tx).await? {
        if let Some(record) = source.records.get_mut(&row.try_get::<String, _>("id")?) {
            record.metadata.insert("author".into(), Value::String(row.try_get("person")?));
        }
    }
    tx.rollback().await?;
    Ok(source)
}

/// A policy home is not necessarily a domain folder record. The renderer's
/// home references describe paths, so flatten unnamed native containers to
/// the nearest represented visible ancestor. Never synthesize a folder name
/// or reinterpret policy: both maps come from production visibility staging.
async fn layout_homes(conn: &mut SqliteConnection, source: &mut SourceSnapshot) -> Result<()> {
    let parents: BTreeMap<String, Option<String>> = sqlx::query_as(
        "SELECT h.root_id,h.parent_id FROM main.kernel_roots h JOIN temp._v2_scopes v ON v.home_id=h.root_id WHERE v.valid AND v.home_view",
    ).fetch_all(&mut *conn).await?.into_iter().collect();
    let logical: BTreeMap<String, String> = sqlx::query_as(
        "SELECT m.home_id,m.record_id FROM temp._v2_home_map m JOIN temp.records r ON r.id=m.record_id",
    ).fetch_all(&mut *conn).await?.into_iter().collect();
    let represented: std::collections::BTreeSet<String> = source.records.keys().cloned().collect();
    for record in source.records.values_mut() {
        let mut home = record.home_id.clone();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(id) = home.as_deref() {
            if represented.contains(id) {
                break;
            }
            if id == crate::events::KERNEL_ROOT_ID {
                home = Some("native:root".into());
                break;
            }
            if let Some(folder) = logical.get(id) {
                home = Some(folder.clone());
                break;
            }
            if !seen.insert(id.to_owned()) {
                return Err(Error::engine("vault native home containment cycle"));
            }
            home = parents.get(id).cloned().flatten();
        }
        record.home_id = home;
    }
    Ok(())
}

/// Same lineage rule as N1: retained import origin, otherwise genesis UUID.
/// Deliberately independent of a pathname, current principal, or record count.
async fn origin(conn: &mut SqliteConnection) -> Result<String> {
    let origins: Vec<String> = sqlx::query_scalar("SELECT DISTINCT json_extract(payload,'$.legacy.payload.source_origin') FROM main.content_events WHERE type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='v1.snapshot_provenance' AND json_extract(payload,'$.legacy.payload.source_origin') IS NOT NULL ORDER BY 1").fetch_all(&mut *conn).await?;
    match origins.as_slice() {
        [origin] if crate::identity::is_database_id(origin) => Ok(origin.clone()),
        [] => {
            let id: String = sqlx::query_scalar(
                "SELECT id FROM main.content_events WHERE type=? ORDER BY seq LIMIT 1",
            )
            .bind(crate::events::KERNEL_GENESIS_EVENT)
            .fetch_one(conn)
            .await?;
            Ok(format!(
                "ndb_{}",
                uuid::Uuid::parse_str(&id)
                    .map_err(|_| Error::engine("vault v2 genesis is invalid"))?
                    .simple()
            ))
        }
        _ => Err(Error::engine("vault v2 source origins are ambiguous")),
    }
}
