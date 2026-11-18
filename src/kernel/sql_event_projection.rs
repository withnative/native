//! Disposable, caller-independent headers for ordinary SQL event staging.
//! Never part of certified state. Readers may always ignore or lose this cache.
use super::*;

#[cfg(feature = "v2-kernel-probe")]
const PROJECTOR_SCHEMA_VERSION: i64 = 8;
pub(crate) const TABLES: &[&str] = &[
    "kernel_sql_event_projection",
    "kernel_sql_event_subject_sets",
    "kernel_sql_event_projection_state",
];
pub(crate) const DDL: &[&str] = &[
    "CREATE TABLE kernel_sql_event_projection (seq INTEGER PRIMARY KEY,id TEXT,record_id TEXT,type TEXT,created_at TEXT,created_at_ms INTEGER,actor TEXT,run_key TEXT,parent_key TEXT,origin TEXT NOT NULL,source_stream TEXT,hidden INTEGER NOT NULL,restricted INTEGER NOT NULL,owner TEXT,claim_sensitive INTEGER NOT NULL,selector TEXT NOT NULL,source_id TEXT,target_id TEXT,link_id TEXT,subject_set INTEGER,outer_anchor TEXT NOT NULL)",
    "CREATE TABLE kernel_sql_event_subject_sets (set_id INTEGER NOT NULL,subject_id TEXT NOT NULL,PRIMARY KEY(set_id,subject_id)) WITHOUT ROWID",
    "CREATE TABLE kernel_sql_event_projection_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),frontier_seq INTEGER NOT NULL,generation INTEGER NOT NULL,projector_version INTEGER NOT NULL,source_schema_digest TEXT NOT NULL,fingerprint_written_at INTEGER NOT NULL DEFAULT 0)",
];

const INDEX_DDL: &[&str] = &[
    "CREATE INDEX idx_kernel_sql_event_admission ON kernel_sql_event_projection(origin,source_stream,hidden,selector,subject_set,record_id,outer_anchor,restricted,owner,seq)",
    "CREATE INDEX idx_kernel_sql_event_actors ON kernel_sql_event_projection(origin,actor,seq)",
];

pub(crate) type SchemaObject = (String, String, String, Option<String>);

pub(crate) fn expected_objects() -> Vec<SchemaObject> {
    let mut objects = Vec::new();
    for ddl in DDL.iter().chain(INDEX_DDL) {
        let words: Vec<_> = ddl.split_whitespace().collect();
        let kind = words[1].to_ascii_lowercase();
        let name = words[2].to_owned();
        let table = if kind == "table" {
            name.clone()
        } else {
            ddl.split_once(" ON ")
                .unwrap()
                .1
                .split('(')
                .next()
                .unwrap()
                .to_owned()
        };
        objects.push((kind, name, table, Some((*ddl).to_owned())));
    }
    objects.sort();
    objects
}

/// Certification ignores only these disposable table/index names across builds.
/// Triggers, views and unknown names remain part of the certified inventory.
pub(crate) fn certification_object(object: &SchemaObject) -> bool {
    matches!(object.0.as_str(), "table" | "index")
        && (TABLES.contains(&object.1.as_str())
            || matches!(
                object.1.as_str(),
                "idx_kernel_sql_event_admission" | "idx_kernel_sql_event_actors"
            ))
}

pub(crate) async fn cache_objects_on(conn: &mut SqliteConnection) -> Result<Vec<SchemaObject>> {
    let mut objects: Vec<SchemaObject> = sqlx::query_as("SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE tbl_name IN ('kernel_sql_event_projection','kernel_sql_event_subject_sets','kernel_sql_event_projection_state') OR name IN ('kernel_sql_event_projection','kernel_sql_event_subject_sets','kernel_sql_event_projection_state','idx_kernel_sql_event_admission','idx_kernel_sql_event_actors')").fetch_all(conn).await?;
    objects.sort();
    Ok(objects)
}

pub(crate) async fn schema_valid_on(conn: &mut SqliteConnection) -> Result<bool> {
    Ok(cache_objects_on(conn).await? == expected_objects())
}

pub(crate) async fn ensure_schema_on(conn: &mut SqliteConnection) -> Result<()> {
    let objects = cache_objects_on(conn).await?;
    if objects != expected_objects() {
        // Decode only the fence, even from an older layout. Never trust rows
        // or execute DML against an unvalidated schema.
        let prior: Option<i64> =
            sqlx::query_scalar("SELECT max(generation) FROM kernel_sql_event_projection_state")
                .fetch_one(&mut *conn)
                .await
                .unwrap_or(None);
        if !objects.is_empty() {
            tracing::warn!(
                ?objects,
                "discarding SQL event cache with unexpected schema objects"
            );
        }
        // Drop attached triggers/indexes before any row write, including reset.
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
        for ddl in DDL.iter().chain(INDEX_DDL) {
            sqlx::query(ddl).execute(&mut *conn).await?;
        }
        if let Some(prior) = prior {
            sqlx::query("INSERT INTO kernel_sql_event_projection_state(singleton,frontier_seq,generation,projector_version,source_schema_digest) VALUES(1,0,?,0,'')").bind(fresh_generation(Some(prior))).execute(&mut *conn).await?;
        }
    }
    Ok(())
}

/// Lost schema/state must never reuse an opener's old generation proof.
fn fresh_generation(prior: Option<i64>) -> i64 {
    prior
        .filter(|g| *g >= 0)
        .and_then(|g| g.checked_add(1))
        .unwrap_or_else(|| {
            // A random positive 62-bit base leaves ample room for later increments.
            let bytes = *uuid::Uuid::new_v4().as_bytes();
            (i64::from_le_bytes(bytes[..8].try_into().unwrap()) & (i64::MAX >> 1)).max(1)
        })
}

/// Reset is shared by all feature sets: a non-probe replay/header repair must
/// invalidate a cache that a later probe build might otherwise reuse.
pub(crate) async fn reset_on(conn: &mut SqliteConnection, from: i64) -> Result<()> {
    if cache_objects_on(conn).await?.is_empty() {
        return Ok(());
    }
    ensure_schema_on(conn).await?;
    sqlx::query("DELETE FROM kernel_sql_event_projection WHERE ?1<=1 OR seq>=?1")
        .bind(from)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE kernel_sql_event_projection_state SET frontier_seq=min(frontier_seq,max(0,?1-1)),generation=max(0,generation)+1").bind(from).execute(&mut *conn).await?;
    if from <= 1 {
        sqlx::query("DELETE FROM kernel_sql_event_subject_sets")
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Canonical subject identity; ordering and duplicates cannot create another
/// interned set. Empty sets use ID zero and need no membership rows.
#[cfg(any(test, feature = "v2-kernel-probe"))]
fn subject_set(subjects: &str) -> Result<std::collections::BTreeSet<String>> {
    Ok(serde_json::from_str(subjects)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_v2_sql_event_projection_pure_mapping_and_subject_interning() {
        #[cfg(feature = "v2-kernel-probe")]
        {
            maintenance::assert_pure_header_mapping();
            maintenance::assert_selector_fingerprint();
        }
        assert_eq!(
            subject_set(r#"["b","a","a"]"#).unwrap(),
            subject_set(r#"["a","b"]"#).unwrap()
        );
        assert_ne!(
            subject_set(r#"["a","b"]"#).unwrap(),
            subject_set(r#"["a,b"]"#).unwrap()
        );
        assert!(subject_set("[]").unwrap().is_empty());
    }

    #[tokio::test]
    async fn kernel_v2_sql_event_projection_reset_is_feature_independent() {
        use sqlx::Connection;
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        ensure_schema_on(&mut conn).await.unwrap();
        sqlx::query("INSERT INTO kernel_sql_event_projection_state(singleton,frontier_seq,generation,projector_version,source_schema_digest) VALUES(1,120,41,1,'prior-probe')").execute(&mut conn).await.unwrap();
        reset_on(&mut conn, 0).await.unwrap();
        assert_eq!((0,42),sqlx::query_as::<_,(i64,i64)>("SELECT frontier_seq,generation FROM kernel_sql_event_projection_state WHERE singleton=1").fetch_one(&mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn kernel_v2_sql_event_projection_recreates_automatic_indexes() {
        use sqlx::Connection;
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        ensure_schema_on(&mut conn).await.unwrap();
        sqlx::query("DROP TABLE kernel_sql_event_subject_sets; CREATE TABLE kernel_sql_event_subject_sets(set_id INTEGER,subject_id TEXT,PRIMARY KEY(set_id,subject_id))").execute(&mut conn).await.unwrap();
        assert!(!schema_valid_on(&mut conn).await.unwrap());
        ensure_schema_on(&mut conn).await.unwrap();
        assert!(schema_valid_on(&mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn kernel_v2_sql_event_projection_recreated_fence() {
        use sqlx::Connection;
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE kernel_sql_event_projection_state(generation INTEGER); INSERT INTO kernel_sql_event_projection_state(generation) VALUES(918),(923)").execute(&mut conn).await.unwrap();
        ensure_schema_on(&mut conn).await.unwrap();
        assert_eq!(
            924,
            sqlx::query_scalar::<_, i64>(
                "SELECT generation FROM kernel_sql_event_projection_state"
            )
            .fetch_one(&mut conn)
            .await
            .unwrap()
        );
        // An absent/undecodable old fence gets a fresh random base at first fold.
        assert_ne!(fresh_generation(None), 0);
        assert_ne!(fresh_generation(None), fresh_generation(None));
    }

    #[tokio::test]
    async fn kernel_v2_sql_event_projection_cache_is_not_certified() {
        use sqlx::Connection;
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE kernel_test(id INTEGER PRIMARY KEY)")
            .execute(&mut conn)
            .await
            .unwrap();
        let before = projection_dump::dump_on(&mut conn).await.unwrap();
        ensure_schema_on(&mut conn).await.unwrap();
        sqlx::query("INSERT INTO kernel_sql_event_projection_state(singleton,frontier_seq,generation,projector_version,source_schema_digest) VALUES(1,100,2,1,'test')")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO kernel_sql_event_subject_sets(set_id,subject_id) VALUES(1,'subject')",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        assert_eq!(before, projection_dump::dump_on(&mut conn).await.unwrap());
    }
}

#[cfg(feature = "v2-kernel-probe")]
mod maintenance {
    use super::*;
    use sha2::{Digest, Sha256};

    pub(crate) const BATCH: i64 = 1024;
    pub(crate) const MAX_TAIL: i64 = 4096;

    fn semantic_inputs() -> Vec<String> {
        use crate::mcp::kernel_v2::{self, sql};
        vec![
            headers_sql(),
            reactions_sql(),
            inputs_sql(),
            sql::RECORD_EVENT_EXCLUSIONS_SQL.into(),
            sql::SELECTOR_EXCLUSION_GLOBS_SQL.into(),
            sql::PROJECTED_EVENT_EXCLUSIONS_SQL.into(),
            sql::V1_LINK_TYPES_SQL.into(),
            sql::GENERIC_LINK_PATTERN.into(),
            sql::LINK4_TYPE.into(),
            sql::PROVIDER_TYPE.into(),
            serde_json::to_string(kernel_v2::IMPORTED_EVENTS).unwrap(),
            serde_json::to_string(kernel_v2::LOGICAL_EVENT_TYPES).unwrap(),
            serde_json::to_string(&kernel_v2::LEGACY_RECEIPT_MAPPING).unwrap(),
        ]
    }
    fn fingerprint(inputs: &[String], schema_version: i64) -> i64 {
        let mut hash = Sha256::new();
        for text in inputs {
            hash.update((text.len() as u64).to_le_bytes());
            hash.update(text.as_bytes());
        }
        hash.update(schema_version.to_le_bytes());
        let bytes: [u8; 8] = hash.finalize()[..8].try_into().unwrap();
        i64::from_le_bytes(bytes) & i64::MAX
    }
    pub(crate) fn projector_version() -> i64 {
        static VERSION_HASH: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
        *VERSION_HASH.get_or_init(|| fingerprint(&semantic_inputs(), PROJECTOR_SCHEMA_VERSION))
    }
    #[cfg(test)]
    pub(crate) fn assert_selector_fingerprint() {
        assert!(lease_active(1_060, 1_000));
        assert!(!lease_active(1_061, 1_000));
        assert!(!lease_active(700, 1_000));
        assert!(lease_active(701, 1_000));
        let inputs = semantic_inputs();
        assert_eq!(
            projector_version(),
            fingerprint(&inputs, PROJECTOR_SCHEMA_VERSION)
        );
        // Every generated SQL, selector/exclusion/type list and logical mapping
        // independently invalidates the fingerprint. No source text is hashed.
        for index in 0..inputs.len() {
            let mut changed = inputs.clone();
            changed[index].push_str(" semantic change");
            assert_ne!(
                projector_version(),
                fingerprint(&changed, PROJECTOR_SCHEMA_VERSION)
            );
        }
        assert_ne!(
            projector_version(),
            fingerprint(&inputs, PROJECTOR_SCHEMA_VERSION + 1)
        );
    }

    pub(crate) async fn schema_digest_on(conn: &mut SqliteConnection) -> Result<String> {
        let mut objects: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetch_all(&mut *conn).await?;
        // The visible-set cache's derived access-epoch accelerator (Native
        // b171a9d) is created lazily on a serving handle's first write; it is
        // not source schema, so it must not reset this cache (exact name only).
        objects.retain(|object| {
            !certification_object(object)
                && !super::sql_record_projection::certification_object(object)
                && !super::stored_visibility::certification_object(object)
                && !(object.0 == "table"
                    && object.1 == crate::kernel::access_fence::ACCESS_EPOCH_TABLE)
        });
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&objects)?)))
    }

    #[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
    #[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
    struct Header {
        seq: i64,
        id: String,
        record_id: String,
        event_type: String,
        raw_created_at: String,
        created_at: Option<String>,
        created_at_ms: Option<i64>,
        actor: Option<String>,
        run_key: Option<String>,
        parent_key: Option<String>,
        origin: String,
        source_stream: Option<String>,
        hidden: bool,
        restricted: bool,
        owner: Option<String>,
        claim_sensitive: bool,
        selector: String,
        source_id: Option<String>,
        target_id: Option<String>,
        link_id: Option<String>,
        subjects: String,
        outer_anchor: String,
    }
    #[cfg_attr(test, derive(serde::Serialize))]
    struct Projected {
        header: Header,
        set_id: i64,
        subjects: std::collections::BTreeSet<String>,
    }
    /// Pure final mapping. SQLite supplies its exact timestamp normalization,
    /// retained selector inputs and reaction transition facts; no caller enters.
    fn project(mut header: Header) -> Result<Option<Projected>> {
        // These SQLite time-values mean the statement's current clock, even
        // though import admission only requires nonempty timestamp text.
        if ["now", "subsec", "subsecond"]
            .iter()
            .any(|v| header.raw_created_at.eq_ignore_ascii_case(v))
        {
            // The public content_events view evaluates this raw time-value in
            // the caller's statement, exactly as the permanent path does.
            header.created_at = Some(header.raw_created_at.clone());
            header.created_at_ms = None;
        }
        header.event_type = if header.origin == "legacy" {
            if header.event_type == crate::mcp::kernel_v2::LEGACY_RECEIPT_MAPPING.0 {
                crate::mcp::kernel_v2::LEGACY_RECEIPT_MAPPING.1
            } else {
                &header.event_type
            }
        } else {
            crate::mcp::kernel_v2::logical_event_type(&header.event_type)
        }
        .to_owned();
        let subjects = match subject_set(&header.subjects) {
            Ok(subjects) => subjects,
            Err(error) => {
                // Today only admitted legacy headers decode Vec<String>.
                // Mark this row; reads encountering its gates use that exact
                // path (and its exact error), while hidden rows stay harmless.
                tracing::warn!(seq=header.seq,%error,diagnostic="event_cache_subject_fallback","legacy subject set requires original staging");
                header.selector = "invalid-subjects".into();
                Default::default()
            }
        };
        Ok(Some(Projected {
            header,
            set_id: 0,
            subjects,
        }))
    }

    fn headers_sql() -> String {
        use crate::mcp::kernel_v2::sql::{
            GENERIC_LINK_PATTERN, LINK4_TYPE, PROJECTED_EVENT_EXCLUSIONS_SQL, PROVIDER_TYPE,
            V1_LINK_TYPES_SQL,
        };
        let native_globs = crate::mcp::kernel_v2::sql::native_event_globs_sql();
        let imported = crate::mcp::kernel_v2::IMPORTED_EVENTS
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(",");
        // CASE keeps JSON evaluation confined to event families whose current
        // selector decodes it. Ordinary native/legacy payloads are never read.
        format!(
            r#"WITH raw AS (
          SELECT e.seq,e.id,e.record_id,e.type AS event_type,e.created_at,e.actor,e.run_key,e.parent_key,
           'native' AS origin,NULL AS source_stream,0 AS hidden,0 AS restricted,NULL AS owner,0 AS claim_sensitive,
           CASE WHEN e.type='{LINK4_TYPE}' THEN 'link4'
                WHEN e.type IN ({V1_LINK_TYPES_SQL}) THEN 'link1'
                WHEN e.type LIKE '{GENERIC_LINK_PATTERN}' THEN 'generic'
                WHEN e.type='{PROVIDER_TYPE}' THEN 'provider' ELSE 'record' END AS selector,
           CASE WHEN e.type='{LINK4_TYPE}' THEN l.source_id WHEN e.type LIKE '{GENERIC_LINK_PATTERN}' THEN g.source_id ELSE e.record_id END AS source_id,
           CASE WHEN e.type='{LINK4_TYPE}' THEN l.target_id WHEN e.type LIKE '{GENERIC_LINK_PATTERN}' THEN g.target_id WHEN e.type IN ({V1_LINK_TYPES_SQL}) THEN CAST(json_extract(e.payload,'$.target_id') AS TEXT) END AS target_id,
           CASE WHEN e.type LIKE '{GENERIC_LINK_PATTERN}' THEN CAST(json_extract(e.payload,'$.link_id') AS TEXT) END AS link_id,
           CASE WHEN e.type='{PROVIDER_TYPE}' THEN (SELECT json_group_array(subject_id) FROM kernel_provider_subjects WHERE aggregate_id=e.record_id) ELSE '[]' END AS subjects,e.record_id AS outer_anchor
          FROM content_events e
          LEFT JOIN kernel_link4_edges l ON e.type='{LINK4_TYPE}' AND l.created_seq=e.seq
          LEFT JOIN kernel_generic_links g ON g.link_id=CASE WHEN e.type LIKE '{GENERIC_LINK_PATTERN}' THEN json_extract(e.payload,'$.link_id') END
          WHERE e.seq>?1 AND e.seq<=?2 AND e.type!='kernel.legacy_recorded.v1'
           AND {native_globs}
           AND e.type NOT IN ({imported},{PROJECTED_EVENT_EXCLUSIONS_SQL})
          UNION ALL
          SELECT e.seq,m.source_id,m.record_id,m.event_type,m.created_at,m.actor,m.run_key,m.parent_key,
           'legacy',m.source_stream,h.hidden,h.restricted,h.owner,h.claim_sensitive,'record',m.record_id,NULL,NULL,h.subjects,e.record_id
          FROM content_events e JOIN kernel_legacy_sql_events m ON m.seq=e.seq JOIN kernel_legacy_history h ON h.seq=e.seq
          WHERE e.seq>?1 AND e.seq<=?2 AND e.type='kernel.legacy_recorded.v1'
        ) SELECT seq,id,record_id,event_type,created_at AS raw_created_at,strftime('%Y-%m-%dT%H:%M:%fZ',created_at) AS created_at,
          CAST(strftime('%s',created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',created_at),4,3) AS INTEGER) AS created_at_ms,
          actor,run_key,parent_key,origin,source_stream,hidden,restricted,owner,claim_sensitive,selector,source_id,target_id,link_id,subjects,outer_anchor FROM raw"#
        )
    }

    fn reactions_sql() -> String {
        let state = messaging::STATE_JSON_SQL;
        let prev = messaging::PREVIOUS_STATE_JSON_SQL;
        let events = messaging::STATE_EVENTS_SQL;
        format!(
            r#"WITH states AS (
          SELECT e.*,json_extract({state},'$.reactions') AS reactions,
           (SELECT json_extract({prev},'$.reactions') FROM content_events p WHERE p.record_id=e.record_id AND p.seq<e.seq AND p.type IN {events} AND json_type({prev})='object' ORDER BY p.seq DESC LIMIT 1) AS previous
          FROM content_events e WHERE e.seq>?1 AND e.seq<=?2 AND e.type='kernel.message_state.v1' AND json_type({state})='object'
        ), changes AS (
          SELECT *,EXISTS(SELECT p.key,emoji.value FROM json_each(reactions) p,json_each(p.value) emoji EXCEPT SELECT p.key,emoji.value FROM json_each(previous) p,json_each(p.value) emoji) AS added,
           EXISTS(SELECT p.key,emoji.value FROM json_each(previous) p,json_each(p.value) emoji EXCEPT SELECT p.key,emoji.value FROM json_each(reactions) p,json_each(p.value) emoji) AS removed FROM states WHERE previous IS NOT NULL
        ) SELECT seq,id,record_id,CASE WHEN added THEN 'message.reaction.added.v1' ELSE 'message.reaction.removed.v1' END AS event_type,
          created_at AS raw_created_at,strftime('%Y-%m-%dT%H:%M:%fZ',created_at) AS created_at,
          CAST(strftime('%s',created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',created_at),4,3) AS INTEGER) AS created_at_ms,
          actor,run_key,parent_key,'native' AS origin,NULL AS source_stream,0 AS hidden,0 AS restricted,NULL AS owner,0 AS claim_sensitive,'reaction' AS selector,record_id AS source_id,NULL AS target_id,NULL AS link_id,'[]' AS subjects,record_id AS outer_anchor
          FROM changes WHERE added OR removed"#
        )
    }

    fn inputs_sql() -> String {
        use crate::mcp::kernel_v2::sql::{GENERIC_LINK_PATTERN, V1_LINK_TYPES_SQL};
        let state = messaging::STATE_JSON_SQL;
        let events = messaging::STATE_EVENTS_SQL;
        format!("SELECT CASE WHEN e.type LIKE '{GENERIC_LINK_PATTERN}' THEN CAST(json_extract(e.payload,'$.link_id') AS TEXT) WHEN e.type IN ({V1_LINK_TYPES_SQL}) THEN CAST(json_extract(e.payload,'$.target_id') AS TEXT) ELSE json_type({state}) END FROM content_events e WHERE e.seq>?1 AND e.seq<=?2 AND (e.type LIKE '{GENERIC_LINK_PATTERN}' OR e.type IN ({V1_LINK_TYPES_SQL}) OR e.type IN {events})")
    }

    /// Only deterministic source/decode failures may become durable markers.
    fn input_error(error: &Error) -> bool {
        match error {
            Error::Sqlx(sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_)) => true,
            Error::Sqlx(sqlx::Error::Database(db)) => {
                db.code().as_deref() == Some("1") && db.message() == "malformed JSON"
            }
            _ => false,
        }
    }

    #[cfg(test)]
    tokio::task_local! { static INJECT_READ_FAILURE: (); }
    #[cfg(test)]
    pub(crate) async fn with_injected_read_failure<F: std::future::Future>(work: F) -> F::Output {
        INJECT_READ_FAILURE.scope((), work).await
    }

    async fn load_headers_on(
        conn: &mut SqliteConnection,
        after: i64,
        end: i64,
    ) -> Result<Vec<Header>> {
        #[cfg(test)]
        if INJECT_READ_FAILURE.try_with(|_| ()).is_ok() {
            return Err(sqlx::Error::Io(std::io::Error::other(
                "injected event cache read failure",
            ))
            .into());
        }
        // Selectors may evaluate inputs later excluded from the public copy
        // (notably imported generic links). Exercise those same JSON functions,
        // including SQLite's JSON5/JSONB acceptance, without json_valid gates.
        let _: Vec<Option<String>> = sqlx::query_scalar(&inputs_sql())
            .bind(after)
            .bind(end)
            .fetch_all(&mut *conn)
            .await?;
        let mut headers: Vec<Header> = sqlx::query_as(&headers_sql())
            .bind(after)
            .bind(end)
            .fetch_all(&mut *conn)
            .await?;
        headers.extend(
            sqlx::query_as::<_, Header>(&reactions_sql())
                .bind(after)
                .bind(end)
                .fetch_all(&mut *conn)
                .await?,
        );
        Ok(headers)
    }

    fn oracle_only(seq: i64) -> Projected {
        Projected {
            header: Header {
                seq,
                id: format!("oracle-only:{seq}"),
                record_id: String::new(),
                event_type: String::new(),
                raw_created_at: String::new(),
                created_at: None,
                created_at_ms: None,
                actor: None,
                run_key: None,
                parent_key: None,
                origin: "oracle".into(),
                source_stream: None,
                hidden: false,
                restricted: false,
                owner: None,
                claim_sensitive: false,
                selector: "oracle-only".into(),
                source_id: None,
                target_id: None,
                link_id: None,
                subjects: "[]".into(),
                outer_anchor: String::new(),
            },
            set_id: 0,
            subjects: Default::default(),
        }
    }

    async fn project_range_on(
        conn: &mut SqliteConnection,
        after: i64,
        end: i64,
        warn: bool,
    ) -> Result<Vec<Projected>> {
        let headers = match load_headers_on(conn, after, end).await {
            Ok(headers) => headers,
            Err(error) if input_error(&error) => {
                // Exceptional inputs are isolated by source position; healthy
                // positions in this bounded batch still become cached headers.
                let positions: Vec<i64> = sqlx::query_scalar(
                    "SELECT seq FROM content_events WHERE seq>?1 AND seq<=?2 ORDER BY seq",
                )
                .bind(after)
                .bind(end)
                .fetch_all(&mut *conn)
                .await?;
                let mut rows = Vec::new();
                for seq in positions {
                    match load_headers_on(conn, seq - 1, seq).await {
                        Ok(headers) => {
                            for header in headers {
                                if let Some(row) = project(header)? {
                                    rows.push(row);
                                }
                            }
                        }
                        Err(error) if input_error(&error) => {
                            if warn {
                                tracing::warn!(seq,%error,diagnostic="event_cache_oracle_only","SQL event position requires permanent staging; continuing fold");
                            }
                            rows.push(oracle_only(seq));
                        }
                        Err(error) => return Err(error),
                    }
                }
                return Ok(rows);
            }
            Err(error) => return Err(error),
        };
        Ok(headers
            .into_iter()
            .map(project)
            .collect::<Result<Option<Vec<_>>>>()?
            .unwrap_or_default())
    }

    #[cfg(test)]
    pub(crate) fn assert_projection_golden() {
        let mut inputs: Vec<Header> = serde_json::from_str(r#"[{"seq":1,"id":"native","record_id":"record","event_type":"kernel.record_revised.v2","raw_created_at":"2026-11-09T00:00:00.1234Z","created_at":"2026-11-09T00:00:00.123Z","created_at_ms":1794182400123,"actor":"principal","run_key":"run","parent_key":"parent","origin":"native","source_stream":null,"hidden":false,"restricted":false,"owner":null,"claim_sensitive":false,"selector":"record","source_id":"record","target_id":null,"link_id":null,"subjects":"[]","outer_anchor":"record"},{"seq":2,"id":"retained","record_id":"legacy-record","event_type":"receipt.committed.v1","raw_created_at":"bad timestamp","created_at":null,"created_at_ms":null,"actor":"v1:account","run_key":"run","parent_key":"parent","origin":"legacy","source_stream":"content_events","hidden":true,"restricted":true,"owner":"owner","claim_sensitive":true,"selector":"record","source_id":"record","target_id":null,"link_id":null,"subjects":"[\"b\",\"a\",\"a\"]","outer_anchor":"different-home"},{"seq":3,"id":"link","record_id":"record","event_type":"kernel.generic_link_added.v1","raw_created_at":"NOW","created_at":"2026-11-09T00:00:00.123Z","created_at_ms":1794182400123,"actor":"principal","run_key":"run","parent_key":"parent","origin":"native","source_stream":null,"hidden":false,"restricted":false,"owner":null,"claim_sensitive":false,"selector":"generic","source_id":"source","target_id":"target","link_id":"edge","subjects":"[]","outer_anchor":"record"},{"seq":4,"id":"invalid-subjects","record_id":"legacy-record","event_type":"legacy.other","raw_created_at":"subsecond","created_at":null,"created_at_ms":null,"actor":"v1:account","run_key":"run","parent_key":"parent","origin":"legacy","source_stream":"content_events","hidden":true,"restricted":true,"owner":"owner","claim_sensitive":true,"selector":"record","source_id":"record","target_id":null,"link_id":null,"subjects":"[\"a\",1]","outer_anchor":"different-home"}]"#).unwrap();
        inputs.push(oracle_only(5).header);
        let rows: Vec<_> = inputs
            .into_iter()
            .map(|header| project(header).unwrap().unwrap())
            .collect();
        let actual =
            serde_json::json!({"projector_schema_version":PROJECTOR_SCHEMA_VERSION,"rows":rows});
        let expected: serde_json::Value = serde_json::from_str(r#"{"projector_schema_version":8,"rows":[{"header":{"seq":1,"id":"native","record_id":"record","event_type":"record.updated","raw_created_at":"2026-11-09T00:00:00.1234Z","created_at":"2026-11-09T00:00:00.123Z","created_at_ms":1794182400123,"actor":"principal","run_key":"run","parent_key":"parent","origin":"native","source_stream":null,"hidden":false,"restricted":false,"owner":null,"claim_sensitive":false,"selector":"record","source_id":"record","target_id":null,"link_id":null,"subjects":"[]","outer_anchor":"record"},"set_id":0,"subjects":[]},{"header":{"seq":2,"id":"retained","record_id":"legacy-record","event_type":"record.updated","raw_created_at":"bad timestamp","created_at":null,"created_at_ms":null,"actor":"v1:account","run_key":"run","parent_key":"parent","origin":"legacy","source_stream":"content_events","hidden":true,"restricted":true,"owner":"owner","claim_sensitive":true,"selector":"record","source_id":"record","target_id":null,"link_id":null,"subjects":"[\"b\",\"a\",\"a\"]","outer_anchor":"different-home"},"set_id":0,"subjects":["a","b"]},{"header":{"seq":3,"id":"link","record_id":"record","event_type":"link.added","raw_created_at":"NOW","created_at":"NOW","created_at_ms":null,"actor":"principal","run_key":"run","parent_key":"parent","origin":"native","source_stream":null,"hidden":false,"restricted":false,"owner":null,"claim_sensitive":false,"selector":"generic","source_id":"source","target_id":"target","link_id":"edge","subjects":"[]","outer_anchor":"record"},"set_id":0,"subjects":[]},{"header":{"seq":4,"id":"invalid-subjects","record_id":"legacy-record","event_type":"legacy.other","raw_created_at":"subsecond","created_at":"subsecond","created_at_ms":null,"actor":"v1:account","run_key":"run","parent_key":"parent","origin":"legacy","source_stream":"content_events","hidden":true,"restricted":true,"owner":"owner","claim_sensitive":true,"selector":"invalid-subjects","source_id":"record","target_id":null,"link_id":null,"subjects":"[\"a\",1]","outer_anchor":"different-home"},"set_id":0,"subjects":[]},{"header":{"seq":5,"id":"oracle-only:5","record_id":"","event_type":"","raw_created_at":"","created_at":null,"created_at_ms":null,"actor":null,"run_key":null,"parent_key":null,"origin":"oracle","source_stream":null,"hidden":false,"restricted":false,"owner":null,"claim_sensitive":false,"selector":"oracle-only","source_id":null,"target_id":null,"link_id":null,"subjects":"[]","outer_anchor":""},"set_id":0,"subjects":[]}]}"#).unwrap();
        assert_eq!(actual,expected,"if this change is intentional, bump PROJECTOR_SCHEMA_VERSION and update the golden rows");
    }

    #[cfg(test)]
    pub(crate) async fn assert_narrow_error_classes() {
        use sqlx::Connection;
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        let malformed =
            sqlx::query_scalar::<_, String>("SELECT json_extract('not json','$.link_id')")
                .fetch_one(&mut conn)
                .await
                .unwrap_err();
        assert!(input_error(&malformed.into()));
        let decode = sqlx::query_scalar::<_, String>("SELECT x'80'")
            .fetch_one(&mut conn)
            .await
            .unwrap_err();
        assert!(input_error(&decode.into()));
        let other_sql = sqlx::query("SELECT missing_column")
            .execute(&mut conn)
            .await
            .unwrap_err();
        assert!(!input_error(&other_sql.into()));
        assert!(!input_error(
            &sqlx::Error::Io(std::io::Error::other("transient I/O")).into()
        ));
        assert!(!input_error(&sqlx::Error::PoolTimedOut.into()));
    }

    #[cfg(test)]
    pub(crate) fn assert_pure_header_mapping() {
        let header = Header {
            seq: 1,
            id: "e".into(),
            record_id: "r".into(),
            event_type: "receipt.committed.v1".into(),
            raw_created_at: "invalid timestamp".into(),
            created_at: None,
            created_at_ms: None,
            actor: Some("v1:account".into()),
            run_key: Some("run".into()),
            parent_key: None,
            origin: "legacy".into(),
            source_stream: Some("content_events".into()),
            hidden: true,
            restricted: true,
            owner: Some("owner".into()),
            claim_sensitive: true,
            selector: "record".into(),
            source_id: Some("r".into()),
            target_id: None,
            link_id: None,
            subjects: r#"["b","a","a"]"#.into(),
            outer_anchor: "different-anchor".into(),
        };
        let projected = project(header).unwrap().unwrap();
        assert_eq!(projected.header.event_type, "record.updated");
        assert_eq!(projected.header.actor.as_deref(), Some("v1:account"));
        assert!(
            projected.header.hidden
                && projected.header.restricted
                && projected.header.claim_sensitive
        );
        assert_eq!(projected.subjects.len(), 2);
        assert_eq!(projected.header.created_at, None);
        assert_eq!(projected.header.created_at_ms, None);
        let mut native = projected.header;
        native.origin = "native".into();
        native.event_type = "kernel.record_revised.v2".into();
        let mut native = project(native).unwrap().unwrap().header;
        assert_eq!(native.event_type, "record.updated");
        native.raw_created_at = "NOW".into();
        assert_eq!(
            project(native)
                .unwrap()
                .unwrap()
                .header
                .created_at
                .as_deref(),
            Some("NOW")
        );
    }

    #[derive(Default, Debug)]
    pub(crate) struct Interner {
        generation: Option<i64>,
        frontier: i64,
        next: i64,
        ids: std::collections::BTreeMap<std::collections::BTreeSet<String>, i64>,
        yielded_to: Option<(i64, i64)>,
    }
    impl Interner {
        async fn synchronize(
            &mut self,
            conn: &mut SqliteConnection,
            generation: i64,
            frontier: i64,
        ) -> Result<()> {
            if self.generation == Some(generation) && self.frontier == frontier {
                return Ok(());
            }
            let members:Vec<(i64,String)>=sqlx::query_as("SELECT set_id,subject_id FROM kernel_sql_event_subject_sets ORDER BY set_id,subject_id").fetch_all(&mut *conn).await?;
            let mut sets =
                std::collections::BTreeMap::<i64, std::collections::BTreeSet<String>>::new();
            for (id, subject) in members {
                sets.entry(id).or_default().insert(subject);
            }
            self.next = sets
                .keys()
                .next_back()
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| Error::engine("event subject-set ID exhausted"))?;
            self.ids = sets
                .into_iter()
                .map(|(id, subjects)| (subjects, id))
                .collect();
            self.ids.insert(Default::default(), 0);
            self.generation = Some(generation);
            self.frontier = frontier;
            Ok(())
        }
        fn intern(&mut self, subjects: &std::collections::BTreeSet<String>) -> Result<i64> {
            if let Some(id) = self.ids.get(subjects) {
                return Ok(*id);
            }
            let id = self.next;
            self.next = self
                .next
                .checked_add(1)
                .ok_or_else(|| Error::engine("event subject-set ID exhausted"))?;
            self.ids.insert(subjects.clone(), id);
            Ok(id)
        }
    }

    /// One atomic batch. Captured generation is a fence against workers that
    /// observed a prefix before a reset. A stale worker cannot publish rows.
    #[cfg(test)]
    pub(crate) async fn batch_on(
        conn: &mut SqliteConnection,
        expected: i64,
        end: i64,
    ) -> Result<bool> {
        let frontier: i64 = sqlx::query_scalar(
            "SELECT frontier_seq FROM kernel_sql_event_projection_state WHERE singleton=1",
        )
        .fetch_one(&mut *conn)
        .await?;
        let mut interner = Interner::default();
        interner.synchronize(conn, expected, frontier).await?;
        batch_with_interner(conn, expected, end, &mut interner).await
    }
    async fn batch_with_interner(
        conn: &mut SqliteConnection,
        expected: i64,
        end: i64,
        interner: &mut Interner,
    ) -> Result<bool> {
        let Some((frontier,generation)): Option<(i64,i64)> = sqlx::query_as("SELECT frontier_seq,generation FROM kernel_sql_event_projection_state WHERE singleton=1").fetch_optional(&mut *conn).await? else { return Ok(false); };
        if generation != expected || end <= frontier {
            return Ok(false);
        }
        // Same completeness authority as readers; do not jump an older gap.
        legacy_history::require_sql_frontier_on(conn).await?;
        let end = end.min(frontier + BATCH);
        let mut projected = project_range_on(conn, frontier, end, true).await?;
        if interner.generation != Some(generation) || interner.frontier != frontier {
            return Ok(false);
        }
        let mut sets = std::collections::BTreeMap::new();
        for row in &mut projected {
            row.set_id = interner.intern(&row.subjects)?;
            sets.entry(row.set_id).or_insert(&row.subjects);
        }
        let pairs: Vec<_> = sets
            .into_iter()
            .flat_map(|(id, subjects)| subjects.iter().map(move |subject| (id, subject)))
            .collect();
        for chunk in pairs.chunks(400) {
            let mut q = sqlx::QueryBuilder::<Sqlite>::new(
                "INSERT OR IGNORE INTO kernel_sql_event_subject_sets(set_id,subject_id) ",
            );
            q.push_values(chunk, |mut q, (id, subject)| {
                q.push_bind(*id).push_bind(*subject);
            });
            q.build().execute(&mut *conn).await?;
        }
        for chunk in projected.chunks(100) {
            let mut q =
                sqlx::QueryBuilder::<Sqlite>::new("INSERT INTO kernel_sql_event_projection(seq,id,record_id,type,created_at,created_at_ms,actor,run_key,parent_key,origin,source_stream,hidden,restricted,owner,claim_sensitive,selector,source_id,target_id,link_id,subject_set,outer_anchor) ");
            q.push_values(chunk, |mut q, row| {
                let h = &row.header;
                q.push_bind(h.seq)
                    .push_bind(&h.id)
                    .push_bind(&h.record_id)
                    .push_bind(&h.event_type)
                    .push_bind(&h.created_at)
                    .push_bind(h.created_at_ms)
                    .push_bind(&h.actor)
                    .push_bind(&h.run_key)
                    .push_bind(&h.parent_key)
                    .push_bind(&h.origin)
                    .push_bind(&h.source_stream)
                    .push_bind(h.hidden)
                    .push_bind(h.restricted)
                    .push_bind(&h.owner)
                    .push_bind(h.claim_sensitive)
                    .push_bind(&h.selector)
                    .push_bind(&h.source_id)
                    .push_bind(&h.target_id)
                    .push_bind(&h.link_id)
                    .push_bind(row.set_id)
                    .push_bind(&h.outer_anchor);
            });
            q.build().execute(&mut *conn).await?;
        }
        let changed=sqlx::query("UPDATE kernel_sql_event_projection_state SET frontier_seq=?,fingerprint_written_at=unixepoch() WHERE singleton=1 AND generation=? AND frontier_seq=?")
            .bind(end).bind(expected).bind(frontier).execute(&mut *conn).await?.rows_affected();
        if changed != 1 {
            return Err(Error::engine(
                "event projection generation changed inside writer transaction",
            ));
        }
        interner.frontier = end;
        Ok(true)
    }

    type State = (i64, i64, i64, String, i64);
    async fn state_on(conn: &mut SqliteConnection) -> Result<Option<State>> {
        Ok(sqlx::query_as("SELECT frontier_seq,generation,projector_version,source_schema_digest,fingerprint_written_at FROM kernel_sql_event_projection_state WHERE singleton=1").fetch_optional(conn).await?)
    }

    #[derive(sqlx::FromRow)]
    struct CachedHeader {
        #[sqlx(flatten)]
        header: Header,
        subject_set: i64,
    }
    const CACHED_HEADERS:&str="SELECT seq,id,record_id,type AS event_type,created_at,created_at_ms,'' AS raw_created_at,actor,run_key,parent_key,origin,source_stream,hidden,restricted,owner,claim_sensitive,selector,source_id,target_id,link_id,'' AS subjects,outer_anchor,subject_set FROM kernel_sql_event_projection WHERE seq>?1 AND seq<=?2 ORDER BY seq";
    fn comparable(mut header: Header) -> Header {
        header.raw_created_at.clear();
        header.subjects.clear();
        header
    }

    /// A reopened file supplies untrusted bytes. Compare its full cached prefix
    /// with canonical caller-independent headers, including subject membership.
    /// This scan holds only a read snapshot, never the SQLite writer lock.
    async fn verify_prefix_on(
        conn: &mut SqliteConnection,
        frontier: i64,
        interner: &Interner,
    ) -> Result<bool> {
        let extra: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_sql_event_projection WHERE seq<=0 OR seq>?)",
        )
        .bind(frontier)
        .fetch_one(&mut *conn)
        .await?;
        if extra {
            return Ok(false);
        }
        let sets: std::collections::BTreeMap<_, _> = interner
            .ids
            .iter()
            .map(|(subjects, id)| (*id, subjects))
            .collect();
        let mut after = 0;
        while after < frontier {
            let end = (after + BATCH).min(frontier);
            let mut expected = project_range_on(conn, after, end, false).await?;
            expected.sort_by_key(|row| row.header.seq);
            let actual: Vec<CachedHeader> = sqlx::query_as(CACHED_HEADERS)
                .bind(after)
                .bind(end)
                .fetch_all(&mut *conn)
                .await?;
            if expected.len() != actual.len() {
                return Ok(false);
            }
            for (expected, actual) in expected.into_iter().zip(actual) {
                if sets.get(&actual.subject_set).copied() != Some(&expected.subjects)
                    || comparable(expected.header) != comparable(actual.header)
                {
                    return Ok(false);
                }
            }
            after = end;
        }
        Ok(true)
    }

    #[derive(Default, Debug, serde::Serialize)]
    pub(crate) struct FoldStats {
        pub(crate) batches: u64,
        pub(crate) lease_yields: u64,
        pub(crate) max_fold_lock_ms: f64,
        pub(crate) max_reset_lock_ms: f64,
        pub(crate) verification_ms: f64,
    }

    fn lease_active(written_at: i64, now: i64) -> bool {
        written_at > now - 300 && written_at <= now + 60
    }

    pub(crate) async fn catch_up(db: &Db) -> Result<FoldStats> {
        let mut stats = FoldStats::default();
        let mut interner = db.sql_event_projection_handle.interner.lock().await;
        loop {
            let mut read = db.pool().begin().await?;
            let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
                .fetch_one(&mut *read)
                .await?;
            if marker != crate::db::V2_APPLICATION_ID {
                db.trust_sql_event_projection_generation(-1);
                return Ok(stats);
            }
            let objects = cache_objects_on(&mut read).await?;
            if objects != expected_objects() {
                drop(read);
                let _admission = db.sql_event_projection_write_admission()?;
                let mut tx =
                    crate::db::begin_write_labelled(db.write_pool(), "event_projection").await?;
                let started = std::time::Instant::now();
                if sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                    .fetch_one(&mut *tx)
                    .await?
                    != crate::db::V2_APPLICATION_ID
                {
                    db.trust_sql_event_projection_generation(-1);
                    return Ok(stats);
                }
                ensure_schema_on(&mut tx).await?;
                tx.commit().await?;
                stats.max_reset_lock_ms = stats
                    .max_reset_lock_ms
                    .max(started.elapsed().as_secs_f64() * 1000.0);
                continue;
            }
            let digest = schema_digest_on(&mut read).await?;
            let state = state_on(&mut read).await?;
            let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
                .fetch_one(&mut *read)
                .await?;
            legacy_history::require_sql_frontier_on(&mut read).await?;
            // Five-minute database-owned lease: a different live projector
            // keeps ownership; this build stages through the permanent path.
            // Once idle for five minutes a new build may take over once.
            let now = chrono::Utc::now().timestamp();
            if let Some((_, generation, version, _, written_at)) =
                state.as_ref().filter(|(_, _, version, _, written_at)| {
                    *version > 0
                        && *version != projector_version()
                        && lease_active(*written_at, now)
                })
            {
                let owner = (*generation, *version);
                if interner.yielded_to != Some(owner) {
                    tracing::warn!(
                        generation,
                        version,
                        written_at,
                        diagnostic = "event_cache_lease_yield",
                        "another live projector owns the SQL event cache; using permanent staging"
                    );
                    stats.lease_yields += 1;
                }
                interner.yielded_to = Some(owner);
                db.trust_sql_event_projection_generation(-1);
                return Ok(stats);
            }
            interner.yielded_to = None;
            let mut reset = state.as_ref().is_some_and(|(f, g, v, d, _)| {
                *f < 0 || *f > head || *g < 0 || *v != projector_version() || *d != digest
            });
            if let Some((frontier, generation, _, _, written_at)) = &state {
                if !reset {
                    // Handle-local lookup acceleration, database-owned generation.
                    // Pool scans happen on the read connection, and only after a
                    // reset/another handle's frontier advance, never under writer.
                    if let Err(error) = interner
                        .synchronize(&mut read, *generation, *frontier)
                        .await
                    {
                        if !input_error(&error) {
                            db.trust_sql_event_projection_generation(-1);
                            return Err(error);
                        }
                        tracing::warn!(%error,diagnostic="event_cache_invalid_membership","discarding malformed cached subject membership");
                        reset = true;
                    }
                    if !reset && db.sql_event_projection_generation() != Some(*generation) {
                        let started = std::time::Instant::now();
                        reset = match verify_prefix_on(&mut read, *frontier, &interner).await {
                            Ok(valid) => !valid,
                            Err(error) => {
                                if !input_error(&error) {
                                    db.trust_sql_event_projection_generation(-1);
                                    return Err(error);
                                }
                                tracing::warn!(%error,diagnostic="event_cache_invalid_prefix","cached prefix validation failed");
                                true
                            }
                        };
                        stats.verification_ms += started.elapsed().as_secs_f64() * 1000.0;
                        if !reset {
                            db.trust_sql_event_projection_generation(*generation);
                        }
                    }
                    if !reset
                        && *frontier == head
                        && *written_at > now - 60
                        && *written_at <= now + 60
                    {
                        read.commit().await?;
                        return Ok(stats);
                    }
                }
            }
            read.commit().await?;
            let _admission = db.sql_event_projection_write_admission()?;
            let mut tx =
                crate::db::begin_write_labelled(db.write_pool(), "event_projection").await?;
            let started = std::time::Instant::now();
            // Another opener/fold/reset may have won while the read snapshot
            // was checked. Retry; never reset another handle merely for having
            // a different in-memory generation/frontier.
            if sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                .fetch_one(&mut *tx)
                .await?
                != crate::db::V2_APPLICATION_ID
            {
                db.trust_sql_event_projection_generation(-1);
                return Ok(stats);
            }
            if !schema_valid_on(&mut tx).await?
                || state_on(&mut tx).await? != state
                || schema_digest_on(&mut tx).await? != digest
            {
                tx.commit().await?;
                continue;
            }
            if reset {
                tracing::warn!(
                    ?state,
                    diagnostic = "event_cache_invalid_prefix",
                    "resetting invalid SQL event cache"
                );
                reset_on(&mut tx, 0).await?;
                sqlx::query("UPDATE kernel_sql_event_projection_state SET projector_version=?,source_schema_digest=?,fingerprint_written_at=unixepoch() WHERE singleton=1").bind(projector_version()).bind(&digest).execute(&mut *tx).await?;
                tx.commit().await?;
                stats.max_reset_lock_ms = stats
                    .max_reset_lock_ms
                    .max(started.elapsed().as_secs_f64() * 1000.0);
                continue;
            }
            if state.is_none() {
                sqlx::query("INSERT INTO kernel_sql_event_projection_state(singleton,frontier_seq,generation,projector_version,source_schema_digest,fingerprint_written_at) VALUES(1,0,?,?,?,unixepoch())").bind(fresh_generation(None)).bind(projector_version()).bind(&digest).execute(&mut *tx).await?;
                tx.commit().await?;
                continue;
            }
            let (frontier, generation, _, _, _) = state.unwrap();
            if head == frontier {
                sqlx::query("UPDATE kernel_sql_event_projection_state SET fingerprint_written_at=unixepoch() WHERE singleton=1").execute(&mut *tx).await?;
                tx.commit().await?;
                return Ok(stats);
            }
            let advanced = batch_with_interner(&mut tx, generation, head, &mut interner).await?;
            tx.commit().await?;
            stats.batches += 1;
            stats.max_fold_lock_ms = stats
                .max_fold_lock_ms
                .max(started.elapsed().as_secs_f64() * 1000.0);
            db.trust_sql_event_projection_generation(generation);
            if !advanced {
                tracing::warn!(
                    diagnostic = "event_cache_fold_did_not_advance",
                    "SQL event cache fold did not advance; original staging remains available"
                );
                return Ok(stats);
            }
        }
    }

    pub(crate) async fn frontier_on(
        conn: &mut SqliteConnection,
        expected: Option<i64>,
    ) -> Result<Option<i64>> {
        match checked_frontier_on(conn, expected).await {
            Ok(frontier) => Ok(frontier),
            Err(error) => {
                tracing::debug!(%error,"SQL event cache validation failed; using ordinary staging");
                Ok(None)
            }
        }
    }
    async fn checked_frontier_on(
        conn: &mut SqliteConnection,
        expected: Option<i64>,
    ) -> Result<Option<i64>> {
        let Some(expected) = expected else {
            return Ok(None);
        };
        if !schema_valid_on(conn).await? {
            return Ok(None);
        }
        let state:Option<(i64,i64,i64,String)>=sqlx::query_as("SELECT frontier_seq,generation,projector_version,source_schema_digest FROM main.kernel_sql_event_projection_state WHERE singleton=1").fetch_optional(&mut *conn).await?;
        let Some((frontier, generation, version, digest)) = state else {
            return Ok(None);
        };
        if frontier <= 0
            || generation != expected
            || version != projector_version()
            || digest != schema_digest_on(conn).await?
        {
            return Ok(None);
        }
        legacy_history::require_sql_frontier_on(conn).await?;
        let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
            .fetch_one(conn)
            .await?;
        Ok((head >= frontier && head - frontier <= MAX_TAIL).then_some(frontier))
    }
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use maintenance::*;
