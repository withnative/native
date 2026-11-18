//! Disposable caller-independent record cells. Authority and caller-relative
//! placement/currency stay in the reader's snapshot, never in these rows.
use super::*;

pub(crate) const TABLES: &[&str] = &[
    "kernel_sql_record_projection",
    "kernel_sql_record_projection_state",
];
#[cfg(feature = "v2-kernel-probe")]
const DDL: &[&str] = &[
    // No value affinities: json_extract can return numbers as well as text,
    // and the public relation must retain the original SQLite storage classes.
    "CREATE TABLE kernel_sql_record_projection (id TEXT PRIMARY KEY,type,kind,name,summary,lifecycle,persistence,maturity,archived,created_raw,updated_raw,activity_raw,deleted_raw)",
    "CREATE TABLE kernel_sql_record_projection_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation TEXT NOT NULL,fingerprint TEXT NOT NULL,frontier_seq INTEGER NOT NULL,build_after TEXT,ready INTEGER NOT NULL,written_at INTEGER NOT NULL)",
];

pub(crate) fn certification_object(o: &sql_event_projection::SchemaObject) -> bool {
    o.0 == "table" && TABLES.contains(&o.1.as_str())
}

async fn objects_on(
    conn: &mut SqliteConnection,
) -> Result<Vec<sql_event_projection::SchemaObject>> {
    let mut objects = sqlx::query_as("SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE tbl_name IN ('kernel_sql_record_projection','kernel_sql_record_projection_state') OR name IN ('kernel_sql_record_projection','kernel_sql_record_projection_state')").fetch_all(conn).await?;
    objects.sort();
    Ok(objects)
}

#[cfg(feature = "v2-kernel-probe")]
fn expected_objects() -> Vec<sql_event_projection::SchemaObject> {
    let mut objects: Vec<_> = DDL
        .iter()
        .map(|ddl| {
            let name = ddl.split_whitespace().nth(2).unwrap().to_owned();
            ("table".into(), name.clone(), name, Some((*ddl).into()))
        })
        .collect();
    // SQLite's implicit PK index is part of exact-DDL validation.
    objects.push((
        "index".into(),
        "sqlite_autoindex_kernel_sql_record_projection_1".into(),
        TABLES[0].into(),
        None,
    ));
    objects.sort();
    objects
}

pub(crate) async fn reset_on(conn: &mut SqliteConnection) -> Result<()> {
    if objects_on(conn).await?.is_empty() {
        return Ok(());
    }
    // Invalidation must work in non-probe builds too. Dropping only the known
    // state table makes every old reader's generation unusable immediately.
    sqlx::query("DROP TABLE IF EXISTS kernel_sql_record_projection_state")
        .execute(conn)
        .await?;
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
mod maintenance {
    use super::*;
    use sha2::{Digest, Sha256};
    pub(crate) const BATCH: i64 = 128;
    pub(crate) const MAX_TAIL: i64 = 4096;
    pub(crate) const CELLS: &[&str] = &[
        "id",
        "type",
        "kind",
        "name",
        "summary",
        "lifecycle",
        "persistence",
        "maturity",
        "archived",
        "created_raw",
        "updated_raw",
        "activity_raw",
        "deleted_raw",
    ];

    fn field(name: &str) -> String {
        format!("(SELECT json_extract(value_json,'$') FROM main.kernel_record_fields f WHERE f.record_id=r.id AND f.name='{name}')")
    }
    /// Store raw clocks. In particular SQLite's 'now' remains a statement-time
    /// expression on every read, just as it is in the permanent oracle.
    pub(crate) fn source_cells() -> Vec<String> {
        let carrier = format!(
            "r.pin_family='{}' AND r.pin_version=1",
            crate::v2_standard::v1_compat::FAMILY
        );
        vec![
            "r.id".into(),
            format!("CASE WHEN {carrier} THEN {} ELSE r.primary_type END",field("v1_type")),
            format!("CASE WHEN {carrier} THEN {} ELSE r.kind END",field("v1_kind")),
            format!("coalesce({},{},'')",field("title"),field("name")),
            field("summary"),
            format!("coalesce((SELECT value FROM main.kernel_facets f WHERE f.record_id=r.id AND f.key='lifecycle'),{})",field("lifecycle")),
            "(SELECT persistence FROM main.kernel_record_metadata m WHERE m.record_id=r.id)".into(),
            "(SELECT maturity FROM main.kernel_record_metadata m WHERE m.record_id=r.id)".into(),
            "coalesce((SELECT archived FROM main.kernel_lifecycle l WHERE l.record_id=r.id),0)".into(),
            "coalesce((SELECT m.created_at FROM main.kernel_legacy_sql_events m WHERE m.record_id=r.id AND m.source_stream='snapshot_provenance' ORDER BY m.seq DESC LIMIT 1),(SELECT json_extract(m.state,'$.created_at') FROM main.kernel_messages m WHERE m.message_id=r.id),r.created_at)".into(),
            record_metadata::updated_clock_sql("r.id"),
            "(SELECT last_activity_at FROM main.kernel_record_metadata m WHERE m.record_id=r.id)".into(),
            "(SELECT json_extract(e.payload,'$.evidence.deleted_at') FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.import_removed.v1' AND json_extract(e.payload,'$.kind')='record' ORDER BY e.seq DESC LIMIT 1)".into(),
        ]
    }
    pub(crate) fn fingerprint() -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(&(1, CELLS, source_cells())).expect("static projection SQL"),
        ))
    }
    #[derive(sqlx::FromRow, Debug)]
    struct State {
        generation: String,
        fingerprint: String,
        frontier_seq: i64,
        build_after: Option<String>,
        ready: bool,
        written_at: i64,
    }
    async fn state_on(conn: &mut SqliteConnection) -> Result<Option<State>> {
        Ok(sqlx::query_as("SELECT generation,fingerprint,frontier_seq,build_after,ready,written_at FROM main.kernel_sql_record_projection_state WHERE singleton=1").fetch_optional(conn).await?)
    }
    async fn head_on(conn: &mut SqliteConnection) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
                .fetch_one(conn)
                .await?,
        )
    }
    /// Rows can be touched by an event whose aggregate is not the record:
    /// retained headers and provider-subject metadata are separate inputs.
    pub(crate) fn changed_ids() -> &'static str {
        "SELECT record_id AS id FROM main.content_events WHERE seq>?1 AND seq<=?2 UNION SELECT record_id FROM main.kernel_legacy_sql_events WHERE seq>?1 AND seq<=?2 UNION SELECT record_id FROM main.kernel_record_metadata WHERE event_seq>?1 AND event_seq<=?2"
    }
    /// `changed_ids` without its metadata arm; pair with
    /// `changed_metadata_for` to test one record's metadata row by key.
    pub(crate) fn changed_event_ids() -> &'static str {
        "SELECT record_id AS id FROM main.content_events WHERE seq>?1 AND seq<=?2 UNION SELECT record_id FROM main.kernel_legacy_sql_events WHERE seq>?1 AND seq<=?2"
    }
    pub(crate) fn changed_metadata_for(id: &str) -> String {
        format!("SELECT 1 FROM main.kernel_record_metadata m WHERE m.record_id={id} AND m.event_seq>?1 AND m.event_seq<=?2")
    }
    pub(crate) async fn frontier_on(
        conn: &mut SqliteConnection,
        expected: Option<&str>,
    ) -> Result<Option<i64>> {
        let Some(expected) = expected else {
            return Ok(None);
        };
        if objects_on(conn).await? != expected_objects() {
            return Ok(None);
        }
        let Some(state) = state_on(conn).await? else {
            return Ok(None);
        };
        let head = head_on(conn).await?;
        Ok((state.ready
            && state.generation == expected
            && state.fingerprint == fingerprint()
            && state.frontier_seq <= head
            && head - state.frontier_seq <= MAX_TAIL)
            .then_some(state.frontier_seq))
    }
    fn source_error(error: &Error) -> bool {
        matches!(error,Error::Sqlx(sqlx::Error::Database(db)) if db.code().as_deref()==Some("1") && db.message()=="malformed JSON")
    }
    async fn refresh_on(conn: &mut SqliteConnection, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let encoded = serde_json::to_string(ids)?;
        sqlx::query("DELETE FROM main.kernel_sql_record_projection WHERE id IN (SELECT value FROM json_each(?))").bind(&encoded).execute(&mut *conn).await?;
        let insert=format!("INSERT INTO main.kernel_sql_record_projection({}) SELECT {} FROM main.kernel_records r WHERE r.id IN (SELECT value FROM json_each(?))",CELLS.join(","),source_cells().join(","));
        sqlx::query("SAVEPOINT record_projection_batch")
            .execute(&mut *conn)
            .await?;
        match sqlx::query(&insert)
            .bind(&encoded)
            .execute(&mut *conn)
            .await
            .map_err(Error::from)
        {
            Ok(_) => {
                sqlx::query("RELEASE record_projection_batch")
                    .execute(&mut *conn)
                    .await?;
            }
            Err(error) if source_error(&error) => {
                sqlx::query("ROLLBACK TO record_projection_batch; RELEASE record_projection_batch")
                    .execute(&mut *conn)
                    .await?;
                for id in ids {
                    match sqlx::query(&insert)
                        .bind(serde_json::to_string(&[id])?)
                        .execute(&mut *conn)
                        .await
                        .map_err(Error::from)
                    {
                        Ok(_) => {}
                        // An absent cache row permanently uses the lazy oracle.
                        // A malformed hidden value must never fail another caller.
                        Err(error) if source_error(&error) => {
                            tracing::warn!(
                                diagnostic = "record_projection_oracle",
                                "record projection retained an oracle row"
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
    async fn recreate_on(conn: &mut SqliteConnection) -> Result<()> {
        let objects = objects_on(conn).await?;
        for kind in ["trigger", "index", "view", "table"] {
            for object in objects
                .iter()
                .filter(|o| o.0 == kind && !o.1.starts_with("sqlite_autoindex_"))
            {
                let name = object.1.replace('"', "\"\"");
                sqlx::query(&format!("DROP {kind} IF EXISTS \"{name}\""))
                    .execute(&mut *conn)
                    .await?;
            }
        }
        for ddl in DDL {
            sqlx::query(ddl).execute(&mut *conn).await?;
        }
        Ok(())
    }
    pub(crate) async fn catch_up(db: &Db) -> Result<()> {
        let _single = db.sql_event_projection_handle.records.lock().await;
        loop {
            let mut read = db.pool().begin().await?;
            let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
                .fetch_one(&mut *read)
                .await?;
            if marker != crate::db::V2_APPLICATION_ID {
                return Ok(());
            }
            let objects = objects_on(&mut read).await?;
            let valid = objects == expected_objects();
            let state = if valid {
                state_on(&mut read).await?
            } else {
                None
            };
            let head = head_on(&mut read).await?;
            let fingerprint = fingerprint();
            let now = chrono::Utc::now().timestamp();
            // Compatible mixed builds do not repeatedly reset one another.
            if state.as_ref().is_some_and(|s| {
                s.fingerprint != fingerprint && s.written_at > now - 300 && s.written_at <= now + 60
            }) {
                return Ok(());
            }
            let reset = !valid
                || state
                    .as_ref()
                    .is_none_or(|s| s.fingerprint != fingerprint || s.frontier_seq > head);
            if let Some(s) = state.as_ref().filter(|s| !reset && s.ready) {
                if db.sql_record_projection_generation().as_deref() != Some(&s.generation) {
                    // Ordinary reuse trusts the transaction-maintained generation,
                    // as readers trust the other derived kernel projections.
                    // Re-deriving every row on each open would defeat the fast path.
                    db.trust_sql_record_projection_generation(Some(s.generation.clone()));
                }
            }
            if !reset
                && state.as_ref().is_some_and(|s| {
                    s.ready
                        && s.frontier_seq == head
                        && s.written_at > now - 60
                        && s.written_at <= now + 60
                })
            {
                return Ok(());
            }
            drop(read);
            let _admission = db.sql_event_projection_write_admission()?;
            let mut tx =
                crate::db::begin_write_labelled(db.write_pool(), "record_projection").await?;
            if sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                .fetch_one(&mut *tx)
                .await?
                != crate::db::V2_APPLICATION_ID
            {
                return Ok(());
            }
            // Compare the state after writer admission, never overwrite a
            // concurrent reset/frontier advance using an older read snapshot.
            if objects_on(&mut tx).await? != objects {
                continue;
            }
            if valid {
                let current = state_on(&mut tx).await?;
                if current.as_ref().map(|s| {
                    (
                        &s.generation,
                        &s.fingerprint,
                        s.frontier_seq,
                        &s.build_after,
                        s.ready,
                        s.written_at,
                    )
                }) != state.as_ref().map(|s| {
                    (
                        &s.generation,
                        &s.fingerprint,
                        s.frontier_seq,
                        &s.build_after,
                        s.ready,
                        s.written_at,
                    )
                }) {
                    continue;
                }
            }
            if reset {
                db.trust_sql_record_projection_generation(None);
                recreate_on(&mut tx).await?;
                let head = head_on(&mut tx).await?;
                sqlx::query("INSERT INTO kernel_sql_record_projection_state(singleton,generation,fingerprint,frontier_seq,build_after,ready,written_at) VALUES(1,?,?,?,NULL,0,?)").bind(uuid::Uuid::new_v4().to_string()).bind(&fingerprint).bind(head).bind(now).execute(&mut *tx).await?;
                tx.commit().await?;
                continue;
            }
            let s = state_on(&mut tx)
                .await?
                .expect("validated projection state");
            if !s.ready {
                let ids:Vec<String>=sqlx::query_scalar("SELECT id FROM main.kernel_records WHERE ?1 IS NULL OR id>?1 ORDER BY id LIMIT ?2").bind(&s.build_after).bind(BATCH).fetch_all(&mut *tx).await?;
                refresh_on(&mut tx, &ids).await?;
                if let Some(last) = ids.last() {
                    sqlx::query("UPDATE kernel_sql_record_projection_state SET build_after=?,written_at=? WHERE singleton=1").bind(last).bind(now).execute(&mut *tx).await?;
                } else {
                    sqlx::query("UPDATE kernel_sql_record_projection_state SET ready=1,written_at=? WHERE singleton=1").bind(now).execute(&mut *tx).await?;
                    db.trust_sql_record_projection_generation(Some(s.generation));
                }
            } else {
                let head = head_on(&mut tx).await?;
                // A bounded event interval limits each writer transaction.
                let through:i64=sqlx::query_scalar("SELECT coalesce(max(seq),?1) FROM (SELECT seq FROM main.content_events WHERE seq>?1 ORDER BY seq LIMIT ?2)").bind(s.frontier_seq).bind(BATCH).fetch_one(&mut *tx).await?;
                let ids: Vec<String> =
                    sqlx::query_scalar(&format!("SELECT id FROM ({}) ORDER BY id", changed_ids()))
                        .bind(s.frontier_seq)
                        .bind(through)
                        .fetch_all(&mut *tx)
                        .await?;
                refresh_on(&mut tx, &ids).await?;
                sqlx::query("UPDATE kernel_sql_record_projection_state SET frontier_seq=?,written_at=? WHERE singleton=1").bind(through).bind(now).execute(&mut *tx).await?;
                if through == head {
                    tx.commit().await?;
                    return Ok(());
                }
            }
            tx.commit().await?;
            tokio::task::yield_now().await;
        }
    }
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use maintenance::*;

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn kernel_v2_record_projection_reset_is_feature_independent_and_inert_when_absent() {
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        reset_on(&mut conn).await.unwrap();
        assert!(objects_on(&mut conn).await.unwrap().is_empty());
        sqlx::query("CREATE TABLE kernel_sql_record_projection(id TEXT PRIMARY KEY); CREATE TABLE kernel_sql_record_projection_state(singleton INTEGER PRIMARY KEY,generation TEXT); INSERT INTO kernel_sql_record_projection_state VALUES(1,'old-reader')").execute(&mut conn).await.unwrap();
        reset_on(&mut conn).await.unwrap();
        assert!(!objects_on(&mut conn)
            .await
            .unwrap()
            .iter()
            .any(|o| o.1 == TABLES[1]));
        // Data rows may survive invalidation, but no reader can trust the
        // prior generation until maintenance recreates a compatible state.
        assert!(objects_on(&mut conn)
            .await
            .unwrap()
            .iter()
            .any(|o| o.1 == TABLES[0]));
    }
}
