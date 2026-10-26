//! Record-wide metadata, independent of every definition's fields. Import
//! snapshots retain the source values; only native record mutations touch activity.
use super::*;

pub(crate) const DDL: &str = "CREATE TABLE kernel_record_metadata (
 record_id TEXT PRIMARY KEY REFERENCES kernel_records(id), persistence TEXT NOT NULL,
 maturity TEXT, last_activity_at TEXT NOT NULL, event_seq INTEGER NOT NULL)";

/// Keep clock reads off overflow pages containing retained source payloads.
pub(crate) const CLOCK_INDEX: &str =
    "CREATE INDEX idx_kernel_record_event_clock ON content_events(record_id,seq,created_at)";

pub(crate) const REHOME_INDEX: &str = "CREATE INDEX idx_kernel_record_moves ON content_events(record_id,seq) WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2')";

// A tiny index over filing/annotation identities; never index body values.
pub(crate) const FILING_TYPE_INDEX: &str = "CREATE INDEX idx_kernel_record_filing_types ON kernel_record_fields(record_id) WHERE name='v1_type' AND value_json IN ('\"Annotation\"','\"Collection\"')";
// Cover both the presence probe and per-bearer carrier checks without reading
// the wide field-value table. The audience predicate itself stays unchanged.
pub(crate) const MESSAGE_TYPE_INDEX: &str = "CREATE INDEX idx_kernel_record_message_types ON kernel_record_fields(record_id) WHERE name='v1_type' AND value_json='\"Message\"'";
// Historical filing and directed-link candidates are structural supersets;
// their readers still authorize every record through the live kernel gate.
pub(crate) const HISTORICAL_HOME_EXPR: &str = "CASE WHEN type IN ('kernel.record_created.v1','kernel.record_created.v2','kernel.import_record_created.v1') THEN json_extract(payload,'$.home_id') WHEN type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') THEN json_extract(payload,'$.new_home_id') ELSE json_extract(payload,'$.record.home_id') END";
pub(crate) const HISTORICAL_HOME_TYPES: &str = "'kernel.record_created.v1','kernel.record_created.v2','kernel.import_record_created.v1','kernel.record_rehomed.v1','kernel.record_rehomed.v2','kernel.import_state_delta.v1'";
pub(crate) const HISTORICAL_HOME_INDEX: &str = "CREATE INDEX idx_kernel_historical_home ON content_events(CASE WHEN type IN ('kernel.record_created.v1','kernel.record_created.v2','kernel.import_record_created.v1') THEN json_extract(payload,'$.home_id') WHEN type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') THEN json_extract(payload,'$.new_home_id') ELSE json_extract(payload,'$.record.home_id') END,seq,record_id) WHERE type IN ('kernel.record_created.v1','kernel.record_created.v2','kernel.import_record_created.v1','kernel.record_rehomed.v1','kernel.record_rehomed.v2','kernel.import_state_delta.v1')";
pub(crate) const HISTORICAL_TARGET_INDEX: &str = "CREATE INDEX idx_kernel_historical_target ON content_events(coalesce(json_extract(payload,'$.target_id'),json_extract(payload,'$.target.record_id')),record_id,seq) WHERE type IN ('kernel.link_added.v1','kernel.link_removed.v1','kernel.link_added.v2')";

// Bindings, policies and unrelated provider events are not record mutations,
// even if a legacy identifier coincides with their stream identifier. Claims
// resolve their validated record subjects explicitly below.
const NATIVE_ACTIVITY_EVENTS: &[&str] = &[
    "kernel.record_created.v1",
    "kernel.metadata_set.v1",
    "kernel.body_set.v1",
    "kernel.facet_observed.v1",
    "kernel.archive_changed.v1",
    "kernel.record_deleted.v1",
    "kernel.record_revised.v1",
    "kernel.record_revised.v2",
    "kernel.record_rebound.v1",
    "kernel.record_rehomed.v1",
    "kernel.record_rehomed.v2",
    "kernel.link_added.v1",
    "kernel.link_added.v2",
    "kernel.link_removed.v1",
    "kernel.generic_link_added.v1",
    "kernel.generic_link_note_updated.v1",
    "kernel.generic_link_removed.v1",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct RecordMetadata {
    pub persistence: String,
    pub maturity: Option<String>,
    pub last_activity_at: String,
}
impl RecordMetadata {
    pub(crate) fn validate(&self) -> Result<()> {
        if !matches!(self.persistence.as_str(), "enduring" | "occurrent") {
            return Err(Error::engine("persistence must be enduring or occurrent"));
        }
        if chrono::DateTime::parse_from_rfc3339(&self.last_activity_at).is_err() {
            return Err(Error::engine("invalid record last_activity_at"));
        }
        Ok(())
    }
}

pub(crate) async fn read_on(conn: &mut SqliteConnection, id: &str) -> Result<RecordMetadata> {
    sqlx::query_as("SELECT persistence,maturity,last_activity_at FROM kernel_record_metadata WHERE record_id=?")
        .bind(id).fetch_one(conn).await.map_err(Into::into)
}
pub(crate) async fn fold_on(
    conn: &mut SqliteConnection,
    id: &str,
    metadata: &RecordMetadata,
    seq: i64,
) -> Result<()> {
    metadata.validate()?;
    sqlx::query("INSERT INTO kernel_record_metadata(record_id,persistence,maturity,last_activity_at,event_seq) VALUES(?,?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET persistence=excluded.persistence,maturity=excluded.maturity,last_activity_at=excluded.last_activity_at,event_seq=excluded.event_seq")
        .bind(id).bind(&metadata.persistence).bind(&metadata.maturity).bind(&metadata.last_activity_at).bind(seq).execute(conn).await?;
    Ok(())
}

/// Optional patch keys distinguish maturity clear from omission. The clock is
/// always the admitting event's timestamp, never a caller-controlled field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    persistence: Option<String>,
    #[serde(default)]
    maturity: Option<serde_json::Value>,
}
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    // Parse manually for explicit null: serde Option<Value> maps null to None.
    let value: serde_json::Value = event_payload(event)?;
    let patch: Patch = serde_json::from_value(value.clone())?;
    let mut metadata = read_on(conn, &event.record_id).await?;
    if value.get("persistence").is_some()
        && matches!(
            event.record_id.as_str(),
            crate::schema::ROOT_RECORD_ID | crate::schema::UNFILED_RECORD_ID
        )
    {
        return Err(Error::engine(
            "engine filing record persistence is immutable",
        ));
    }
    if patch.persistence.as_deref() == Some("occurrent") {
        let folder: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r WHERE r.id=? AND ((r.primary_type='Collection' AND r.kind='folder') OR (r.pin_family='native.v1.record' AND r.pin_version=1 AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=r.id AND f.name='v1_type' AND f.value_json='\"Collection\"') AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=r.id AND f.name='v1_kind' AND f.value_json='\"folder\"'))))")
            .bind(&event.record_id).fetch_one(&mut *conn).await?;
        if folder {
            let home = hq::v1_import_home_id(&event.record_id);
            let children: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r WHERE r.id<>? AND (r.home_id=? OR r.home_id IN (SELECT root_id FROM kernel_roots WHERE parent_id=?)))")
                .bind(&event.record_id).bind(&home).bind(&home).fetch_one(&mut *conn).await?;
            if children {
                return Err(Error::engine(
                    "folder still has live homed members; rehome its members first",
                ));
            }
        }
    }
    apply_patch(&mut metadata, &value, &event.created_at)?;
    fold_on(conn, &event.record_id, &metadata, event.local_seq).await
}

pub(crate) fn native_activity_event(typ: &str) -> bool {
    NATIVE_ACTIVITY_EVENTS.contains(&typ)
}

pub(crate) fn apply_patch(
    metadata: &mut RecordMetadata,
    value: &serde_json::Value,
    created_at: &str,
) -> Result<()> {
    let patch: Patch = serde_json::from_value(value.clone())?;
    if value.get("persistence").is_some() {
        metadata.persistence = patch
            .persistence
            .ok_or_else(|| Error::engine("cannot clear persistence"))?;
    }
    if value.get("maturity").is_some() {
        metadata.maturity = match patch.maturity {
            None => None,
            Some(serde_json::Value::String(s)) => Some(s),
            _ => return Err(Error::engine("maturity must be a string or null")),
        };
    }
    metadata.last_activity_at = created_at.to_owned();
    metadata.validate()
}

/// A native write touches only its own record, as v1 body/facet/link writes
/// do. Imported links and legacy attribution must not replace the frozen v1
/// activity clock with the migration time (or an old provenance timestamp).
pub(crate) async fn touch_event(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if matches!(
        event.event_type.as_str(),
        "kernel.record_created.v1" | "kernel.import_record_created.v1"
    ) {
        sqlx::query("INSERT INTO kernel_record_metadata(record_id,persistence,maturity,last_activity_at,event_seq) VALUES(?,'enduring',NULL,?,?)")
            .bind(&event.record_id).bind(&event.created_at).bind(event.local_seq).execute(conn).await?;
    } else if event.event_type == commit_port::PROVIDER_OUTCOME_EVENT {
        // Claims mutate record activity in v1. Resolve their already-validated
        // subject projection; the aggregate's stream ID is never a record ID.
        // Other provider aggregates cannot masquerade as record subjects.
        sqlx::query("UPDATE kernel_record_metadata SET last_activity_at=?,event_seq=? WHERE record_id IN (SELECT s.subject_id FROM kernel_provider_subjects s JOIN kernel_provider_state p ON p.id=s.aggregate_id WHERE p.id=? AND p.provider_key=? AND p.head=?)")
            .bind(&event.created_at).bind(event.local_seq).bind(&event.record_id)
            .bind(crate::v2_standard::claims_v1::PROVIDER_KEY).bind(event.local_seq)
            .execute(&mut *conn).await?;
        // The validated receipt retains the chosen editable anchor. The
        // designated legacy transform imports provenance, not native activity.
        sqlx::query("UPDATE kernel_record_metadata SET last_activity_at=?,event_seq=? WHERE record_id IN (SELECT json_extract(r.request_json,'$.anchor.record_id') FROM kernel_provider_receipts r JOIN kernel_provider_state p ON p.id=json_extract(r.request_json,'$.aggregate_id') JOIN kernel_principals a ON a.principal_id=r.principal_id WHERE p.id=? AND a.principal_id=? AND r.event_seq=? AND p.head=? AND p.provider_key=? AND coalesce(a.auth_binding,'')!=?)")
            .bind(&event.created_at).bind(event.local_seq).bind(&event.record_id).bind(event.actor.as_deref()).bind(event.local_seq).bind(event.local_seq)
            .bind(crate::v2_standard::relates_to::RELATIONSHIP)
            .bind(super::relates_to_port::HOST_TRANSFORM_BINDING)
            .execute(conn).await?;
    } else if native_activity_event(&event.event_type) {
        sqlx::query(
            "UPDATE kernel_record_metadata SET last_activity_at=?,event_seq=? WHERE record_id=?",
        )
        .bind(&event.created_at)
        .bind(event.local_seq)
        .bind(&event.record_id)
        .execute(conn)
        .await?;
    }
    Ok(())
}

pub async fn set_record_metadata_as(
    db: &Db,
    principal: &str,
    record: &str,
    persistence: Option<&str>,
    maturity: Option<Option<&str>>,
    expected_revision: i64,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::record_edit(&mut tx, principal, record, Some(expected_revision)).await?;
    let mut patch = serde_json::Map::new();
    if let Some(p) = persistence {
        patch.insert("persistence".into(), p.into());
    }
    if let Some(m) = maturity {
        patch.insert("maturity".into(), serde_json::to_value(m)?);
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: record.into(),
            event_type: "kernel.metadata_set.v1".into(),
            payload: patch.into(),
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Additive upgrade for older probe files. Derive defaults and native activity
/// from the existing log; absence of old v1 metadata is not invented provenance.
pub async fn ensure_record_metadata(db: &Db) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    super::legacy_history::ensure_schema(&mut tx).await?;
    super::messaging::ensure_schema(&mut tx).await?;
    for index in [
        CLOCK_INDEX,
        REHOME_INDEX,
        FILING_TYPE_INDEX,
        MESSAGE_TYPE_INDEX,
        HISTORICAL_HOME_INDEX,
        HISTORICAL_TARGET_INDEX,
    ] {
        sqlx::query(&index.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1))
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(super::hosted_identity::EVENT_INDEX_DDL)
        .execute(&mut *tx)
        .await?;
    super::v1_state::ensure_schema(&mut tx).await?;
    hq::ensure_tombstones(&mut tx).await?;
    sqlx::query(&DDL.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
        .execute(&mut *tx)
        .await?;
    let events = NATIVE_ACTIVITY_EVENTS
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(",");
    let claims = crate::v2_standard::claims_v1::PROVIDER_KEY;
    let relation = crate::v2_standard::relates_to::RELATIONSHIP;
    let transform = super::relates_to_port::HOST_TRANSFORM_BINDING;
    let latest = format!("FROM (SELECT e.created_at,e.seq FROM content_events e WHERE e.record_id=r.id AND e.type IN ({events}) UNION ALL SELECT e.created_at,e.seq FROM kernel_provider_subjects s JOIN kernel_provider_state p ON p.id=s.aggregate_id JOIN content_events e ON e.seq=p.head WHERE s.subject_id=r.id AND p.provider_key='{claims}' UNION ALL SELECT e.created_at,e.seq FROM kernel_provider_receipts pr JOIN kernel_provider_state p ON p.id=json_extract(pr.request_json,'$.aggregate_id') JOIN kernel_principals a ON a.principal_id=pr.principal_id JOIN content_events e ON e.seq=pr.event_seq WHERE json_extract(pr.request_json,'$.anchor.record_id')=r.id AND p.provider_key='{relation}' AND coalesce(a.auth_binding,'')!='{transform}') ORDER BY seq DESC LIMIT 1");
    sqlx::query(&format!("INSERT INTO kernel_record_metadata(record_id,persistence,maturity,last_activity_at,event_seq) SELECT r.id,'enduring',NULL,coalesce((SELECT created_at {latest}),r.created_at),coalesce((SELECT seq {latest}),r.created_seq) FROM kernel_records r WHERE NOT EXISTS(SELECT 1 FROM kernel_record_metadata m WHERE m.record_id=r.id)"))
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

/// One v2 content clock for SQL, write guards and private configuration receipts.
/// This includes facet/body/control events that do not revise typed fields.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn updated_clock_sql(record_expression: &str) -> String {
    format!("(SELECT created_at FROM main.content_events e WHERE e.record_id={record_expression} ORDER BY seq DESC LIMIT 1)")
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn updated_at_on(conn: &mut SqliteConnection, record: &str) -> Result<String> {
    Ok(sqlx::query_scalar(&format!(
        "SELECT strftime('%Y-%m-%dT%H:%M:%fZ',{})",
        updated_clock_sql("?")
    ))
    .bind(record)
    .fetch_one(conn)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn metadata_import_native_writes_permissions_cas_and_replay() {
        let (db, admin) = create_v2_database(":memory:", "account", "Admin", "account-a")
            .await
            .unwrap();
        let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        let viewer = create_principal(&db, "account", "Other", "account-b", &admin)
            .await
            .unwrap();
        let home = create_home(&db, KERNEL_ROOT_ID, Some(&[]), &admin)
            .await
            .unwrap();
        let id = Uuid::new_v4().to_string();
        let original = RecordMetadata {
            persistence: "occurrent".into(),
            maturity: Some("captured".into()),
            last_activity_at: "2022-01-02T03:04:05Z".into(),
        };
        let state = ImportRecordState {
            message: None,
            message_principal: None,
            metadata: Some(original.clone()),
            ..Default::default()
        };
        assert!(
            import_record_as(&db, &admin, &id, &home, Some(&admin), &state)
                .await
                .is_err()
        );
        import_record_as(&db, &host, &id, &home, Some(&admin), &state)
            .await
            .unwrap();
        let legacy = LegacyEvent {
            source: None,
            id: Uuid::new_v4().to_string(),
            event_type: "record.updated".into(),
            payload: json!({"maturity":"captured"}),
            created_at: "2021-01-01T00:00:00Z".into(),
            actor: Some("original-editor".into()),
            run_key: None,
        };
        import_event_as(&db, &host, &id, &legacy).await.unwrap();
        let before = read_record_as(&db, &admin, &id).await.unwrap().unwrap();
        assert_eq!(before.metadata, original);
        let mut tx = db.write_pool().begin().await.unwrap();
        let mut unrelated = crate::conformance::rebuild::read_all_events(&mut tx)
            .await
            .unwrap()
            .pop()
            .unwrap();
        unrelated.record_id = id.clone();
        unrelated.created_at = "2099-01-01T00:00:00Z".into();
        for event_type in [
            "kernel.provider_outcome.v1",
            "kernel.instruction_binding_updated.v1",
            "kernel.home_policy_replaced.v1",
        ] {
            unrelated.event_type = event_type.into();
            touch_event(&mut tx, &unrelated).await.unwrap();
        }
        assert_eq!(read_on(&mut tx, &id).await.unwrap(), original);
        tx.rollback().await.unwrap();

        assert!(before.fields.is_empty());
        assert!(read_record_as(&db, &viewer, &id).await.unwrap().is_none());
        assert!(
            set_record_metadata_as(&db, &viewer, &id, Some("enduring"), None, before.revision)
                .await
                .is_err()
        );
        for persistence in ["invalid", ""] {
            let dump = dump_all_kernel_tables(&db).await.unwrap();
            assert!(set_record_metadata_as(
                &db,
                &admin,
                &id,
                Some(persistence),
                None,
                before.revision
            )
            .await
            .is_err());
            assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
        }
        set_record_metadata_as(
            &db,
            &admin,
            &id,
            Some("enduring"),
            Some(None),
            before.revision,
        )
        .await
        .unwrap();
        let edited = read_record_as(&db, &admin, &id).await.unwrap().unwrap();
        assert_eq!(edited.metadata.persistence, "enduring");
        assert_eq!(edited.metadata.maturity, None);
        assert_ne!(edited.metadata.last_activity_at, original.last_activity_at);
        assert!(edited.revision > before.revision);
        assert!(set_record_metadata_as(
            &db,
            &admin,
            &id,
            None,
            Some(Some("stale")),
            before.revision
        )
        .await
        .is_err());
        set_body_as(&db, &admin, &id, "native text", edited.revision)
            .await
            .unwrap();
        let latest = read_record_as(&db, &admin, &id).await.unwrap().unwrap();
        let timestamp: String =
            sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq=?")
                .bind(latest.revision)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(latest.metadata.last_activity_at, timestamp);
        assert_eq!(latest.fields, before.fields);
        let dump = dump_all_kernel_tables(&db).await.unwrap();
        replay_all_projections(&db).await.unwrap();
        assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
    }

    #[tokio::test]
    async fn metadata_upgrade_backfills_older_native_records_once() {
        let (db, admin) = create_v2_database(":memory:", "account", "Admin", "account-a")
            .await
            .unwrap();
        let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        let id = Uuid::new_v4().to_string();
        import_record_as(
            &db,
            &host,
            &id,
            KERNEL_ROOT_ID,
            Some(&admin),
            &ImportRecordState::default(),
        )
        .await
        .unwrap();
        let before = read_record_as(&db, &admin, &id).await.unwrap().unwrap();
        set_body_as(&db, &admin, &id, "text", before.revision)
            .await
            .unwrap();
        let expected = read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap()
            .metadata;
        sqlx::query("DROP TABLE kernel_record_metadata")
            .execute(db.write_pool())
            .await
            .unwrap();
        ensure_record_metadata(&db).await.unwrap();
        assert_eq!(
            read_record_as(&db, &admin, &id)
                .await
                .unwrap()
                .unwrap()
                .metadata,
            expected
        );
        let dump = dump_all_kernel_tables(&db).await.unwrap();
        ensure_record_metadata(&db).await.unwrap();
        assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
    }
}
