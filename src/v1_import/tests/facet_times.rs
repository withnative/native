//! Synthetic v1 projector/query_sql oracle against the imported v2 surface.
use super::*;
use crate::authorization::{AllowEntry, Capability};
use crate::query::{principal::QueryPrincipal, sql, sql_contract::QuerySqlRequest};

#[path = "facet_times_history_scan.rs"]
mod history_scan;

/// Preserve the previous per-call implementation as an independent migration
/// oracle. It is test-only; no serving path can fall back to scanning history.
async fn assert_history_scan_equivalence(db: &Db) {
    let mut tx = db.pool().begin().await.unwrap();
    sqlx::query(
        "DROP TABLE IF EXISTS temp.facet_times; DROP TABLE IF EXISTS temp._v2_visible;
        CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY);
        INSERT INTO temp._v2_visible SELECT id FROM kernel_records",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    history_scan::stage(&mut tx).await.unwrap();
    let columns = "record_id,key,kind,all_day,start_date,end_date,start_ms,end_ms,tz,tzdb_version";
    let oracle: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT json_array({columns}) FROM temp.facet_times ORDER BY record_id,key"
    ))
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    let projected: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT json_array({columns}) FROM kernel_facet_time_rows ORDER BY record_id,key"
    ))
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        projected, oracle,
        "projected bytes must equal the previous history scan"
    );
    tx.rollback().await.unwrap();
}

const SQL: &str = "SELECT * FROM facet_times ORDER BY record_id,key";

async fn query_sql(
    db: &Db,
    principal: QueryPrincipal,
    statement: &str,
) -> crate::Result<sql::SqlResult> {
    sql::query_sql_request_ad_hoc(
        db.clone(),
        principal,
        QuerySqlRequest {
            sql: statement.into(),
            parameters: Vec::new(),
        },
    )
    .await
}

async fn fixture() -> (Fixture, Db, Db) {
    fixture_mode(true).await
}

async fn fixture_mode(history: bool) -> (Fixture, Db, Db) {
    fixture_extra(history, false, false).await
}

async fn fixture_extra(history: bool, malformed: bool, derived: bool) -> (Fixture, Db, Db) {
    fixture_shapes(history, malformed, derived, false).await
}

async fn fixture_shapes(
    history: bool,
    malformed: bool,
    derived: bool,
    all_shapes: bool,
) -> (Fixture, Db, Db) {
    let f = Fixture::new().await;
    // Standby uses a real-shaped synthetic origin, unlike the generic import
    // fixture's deliberately abbreviated token.
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("UPDATE database_identity SET origin_db_id='ndb_0123456789abcdef0123456789abcdef'")
        .await
        .unwrap();
    source.close().await.unwrap();
    let mut ids = vec!["task", "secret"];
    if derived {
        let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
            .await
            .unwrap();
        for (id, bearer) in [("comment-public", "task"), ("comment-private", "secret")] {
            sqlx::query("INSERT INTO records(id,type,kind,home_id,policy_anchor_id,created_at,updated_at,archived) VALUES(?,'Annotation','comment','folder','native:root','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0)").bind(id).execute(&mut source).await.unwrap();
            sqlx::query("INSERT INTO links VALUES(?,?,?,'part_of',NULL,'2026-01-01T00:00:00Z')")
                .bind(format!("bearer-{id}"))
                .bind(id)
                .bind(bearer)
                .execute(&mut source)
                .await
                .unwrap();
            ids.push(id);
        }
        source.close().await.unwrap();
        for (id, bearer) in [
            ("attachment-public", "task"),
            ("attachment-private", "secret"),
        ] {
            super::add_derived_attachment(&f, id, bearer, "person-a").await;
            ids.push(id);
        }
    }
    let v1 = crate::create_database(":memory:").await.unwrap();
    for id in &ids {
        let id = *id;
        sqlx::query("INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) VALUES(?,'Document','note',?,'native:root','native:root')")
            .bind(id).bind(id).execute(v1.write_pool()).await.unwrap();
        let mut entries = vec![AllowEntry::account("account-a", Capability::Manage)];
        if id == "task" || id.ends_with("-public") {
            entries.push(AllowEntry::account("account-b", Capability::View));
        }
        crate::authorization::replace_explicit_policy(&v1, "test:policy", id, entries)
            .await
            .unwrap();
        for payload in [
            json!({"key":"due","value":"2026-10-05","time_kind":"date"}),
            json!({"key":"due","value":"2026-10-06","time_kind":"date","as_of":"2020-01-01T00:00:00.000Z"}),
            json!({"key":"at","value":"1969-12-31T23:59:59.999Z","time_kind":"instant"}),
            json!({"key":"zoned","value":json!({"local":"2026-07-01T10:00","tz":"Europe/London","offset":"+00:00","tzdb":"1999a"}).to_string(),"time_kind":"zoned"}),
            json!({"key":"days","value":json!({"all_day":true,"start":"2028-02-28","end":"2028-03-01"}).to_string(),"time_kind":"when"}),
            json!({"key":"meeting","value":json!({"all_day":false,"start":{"local":"2026-10-24T10:00","tz":"Europe/London","offset":"+01:00","tzdb":"2025b"},"end":{"local":"2026-10-25T10:00","tz":"Europe/London","offset":"+00:00","tzdb":"2025b"}}).to_string(),"time_kind":"when"}),
            json!({"key":"gone","value":"2026-10-05","time_kind":"date"}),
            json!({"key":"untyped","value":"2026-10-05","time_kind":"date"}),
            json!({"key":"untyped","value":"still text"}),
            json!({"key":"raw_date","value":"2026-10-05"}),
            json!({"key":"history_only","value":"2026-10-05","time_kind":"date","as_of":"2030-01-01T00:00:00.000Z","observation_only":true}),
            // Neither future nor past observation-only values/unsets alter
            // current time. Even equal-as_of corrections stay observations.
            json!({"key":"due","value":"2020-01-01","time_kind":"date","as_of":"2030-01-01T00:00:00.000Z","observation_only":true}),
            json!({"key":"due","value":"2021-01-01","time_kind":"date","as_of":"2030-01-01T00:00:00.000Z","observation_only":true}),
        ].into_iter().chain(if all_shapes { vec![
            json!({"key":"when_instants","value":json!({"all_day":false,"start":"2026-10-24T09:00:00.000Z","end":"2026-10-25T10:00:00.000Z"}).to_string(),"time_kind":"when"}),
            json!({"key":"when_instant_to_zoned","value":json!({"all_day":false,"start":"2026-10-24T09:00:00.000Z","end":{"local":"2026-10-25T10:00","tz":"Europe/London","offset":"+00:00","tzdb":"1999a"}}).to_string(),"time_kind":"when"}),
            json!({"key":"when_zoned_to_instant","value":json!({"all_day":false,"start":{"local":"2026-10-24T10:00","tz":"Europe/London","offset":"+01:00","tzdb":"1999a"},"end":"2026-10-25T10:00:00.000Z"}).to_string(),"time_kind":"when"}),
            json!({"key":"when_cross_zones","value":json!({"all_day":false,"start":{"local":"2026-10-24T10:00","tz":"Europe/London","offset":"+01:00","tzdb":"1999a"},"end":{"local":"2026-10-24T12:00","tz":"America/New_York","offset":"-04:00","tzdb":"1999a"}}).to_string(),"time_kind":"when"}),
            json!({"key":"zoned_legacy_no_tzdb","value":json!({"local":"2026-07-01T10:00","tz":"Europe/London","offset":"+01:00"}).to_string(),"time_kind":"zoned"}),
        ] } else { Vec::new() }) {
            crate::store::append(
                &v1,
                crate::store::AppendSpec {
                    record_id: id.into(),
                    event_type: "facet.set".into(),
                    payload,
                    actor: None,
                },
            )
            .await
            .unwrap();
        }
        for (key, observation_only) in [("gone", false), ("due", true)] {
            crate::store::append(&v1, crate::store::AppendSpec {
                record_id:id.into(),event_type:"facet.unset".into(),
                payload:json!({"key":key,"as_of":"2031-01-01T00:00:00.000Z","observation_only":observation_only}),actor:None,
            }).await.unwrap();
        }
    }
    if derived {
        for (id, typ, kind, bearer) in [
            ("comment-public", "Annotation", "comment", "task"),
            ("comment-private", "Annotation", "comment", "secret"),
            ("attachment-public", "Document", "attachment", "task"),
            ("attachment-private", "Document", "attachment", "secret"),
        ] {
            sqlx::query("UPDATE records SET type=?,kind=? WHERE id=?")
                .bind(typ)
                .bind(kind)
                .bind(id)
                .execute(v1.write_pool())
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO links(id,source_id,target_id,relationship) VALUES(?,?,?,'part_of')",
            )
            .bind(format!("bearer-{id}"))
            .bind(id)
            .bind(bearer)
            .execute(v1.write_pool())
            .await
            .unwrap();
        }
    }
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    let events: Vec<(String,String,String,String)> = sqlx::query_as(
        "SELECT id,record_id,type,payload FROM content_events WHERE type IN ('facet.set','facet.unset') ORDER BY seq"
    ).fetch_all(v1.pool()).await.unwrap();
    for (i, (id, record, kind, payload)) in events.into_iter().enumerate() {
        // Deliberately reverse timestamp order: the import's event order is
        // different from the v1 sequence that defines current facet_times.
        let created = format!("2026-03-{:02}T00:00:00.000Z", 28 - i % 28);
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,payload,created_at) VALUES(?,?,?,?,?)",
        )
        .bind(id)
        .bind(record)
        .bind(kind)
        .bind(payload)
        .bind(created)
        .execute(&mut source)
        .await
        .unwrap();
    }
    let facets: Vec<(String, String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT record_id,key,value,vocab_ref FROM facet_values")
            .fetch_all(v1.pool())
            .await
            .unwrap();
    for (record, key, value, vocab) in facets {
        sqlx::query("INSERT INTO facet_values VALUES(?,?,?,NULL,?,'2026-03-01T00:00:00.000Z')")
            .bind(&record)
            .bind(&key)
            .bind(value)
            .bind(vocab)
            .execute(&mut source)
            .await
            .unwrap();
        sqlx::query("INSERT INTO facet_observations VALUES(?,?,'2026-03-01T00:00:00.000Z',9999)")
            .bind(record)
            .bind(key)
            .execute(&mut source)
            .await
            .unwrap();
    }
    if malformed {
        for record in ["task", "secret"] {
            for (key, kind, value) in [
                ("bad-date", "date", "not-a-date"),
                ("unknown-kind", "future-kind", "2026-10-05"),
            ] {
                sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at) VALUES(?,?,'facet.set',?,'2026-03-30T00:00:00.000Z')")
                    .bind(format!("bad-{record}-{key}")).bind(record).bind(json!({"key":key,"value":value,"time_kind":kind}).to_string()).execute(&mut source).await.unwrap();
                sqlx::query(
                    "INSERT INTO facet_values VALUES(?,?,?,NULL,NULL,'2026-03-01T00:00:00.000Z')",
                )
                .bind(record)
                .bind(key)
                .bind(value)
                .execute(&mut source)
                .await
                .unwrap();
                // Keep the synthetic source's current value and observation
                // projections consistent; otherwise the importer correctly
                // excludes the entire record before SQL can examine history.
                sqlx::query(
                    "INSERT INTO facet_observations VALUES(?,?,'2026-03-01T00:00:00.000Z',9999)",
                )
                .bind(record)
                .bind(key)
                .execute(&mut source)
                .await
                .unwrap();
            }
        }
    }
    source.close().await.unwrap();
    if !history {
        let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
            .await
            .unwrap();
        source.execute("CREATE TABLE facet_times(record_id TEXT,key TEXT,kind TEXT,all_day INTEGER,start_date TEXT,end_date TEXT,start_ms INTEGER,end_ms INTEGER,tz TEXT,tzdb_version TEXT)").await.unwrap();
        type TimeRow = (
            String,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<String>,
            Option<String>,
        );
        let times: Vec<TimeRow> =
            sqlx::query_as("SELECT * FROM facet_times ORDER BY record_id,key")
                .fetch_all(v1.pool())
                .await
                .unwrap();
        for (record, key, kind, all_day, start_date, end_date, start_ms, end_ms, tz, tzdb) in times
        {
            sqlx::query("INSERT INTO facet_times VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(record)
                .bind(key)
                .bind(kind)
                .bind(all_day)
                .bind(start_date)
                .bind(end_date)
                .bind(start_ms)
                .bind(end_ms)
                .bind(tz)
                .bind(tzdb)
                .execute(&mut source)
                .await
                .unwrap();
        }
        source.close().await.unwrap();
    }
    ids.push("private");
    let mut options = f.options(&ids, false);
    options.history = history;
    let report = run(options).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let v2 = f.db().await;
    super::app_state::app_roster(&v2, "account-a", &["account-a", "account-b"]).await;
    assert_history_scan_equivalence(&v2).await;
    (f, v1, v2)
}

#[tokio::test]
async fn facet_times_snapshot_only_import_matches_v1_without_retained_history() {
    let (_f, v1, v2) = fixture_mode(false).await;
    for account in ["account-a", "account-b"] {
        let expected = query_sql(&v1, QueryPrincipal::authenticated(account, true), SQL)
            .await
            .unwrap();
        let actual = ordinary_kernel_call(&v2, account, "query_sql", json!({"sql":SQL}))
            .await
            .unwrap();
        assert_eq!(actual["rows"], json!(expected.rows));
        assert_eq!(
            expected.rows.len(),
            if account == "account-a" { 10 } else { 5 }
        );
    }
    k::replay_all_projections(&v2).await.unwrap();
    let expected = query_sql(&v1, QueryPrincipal::authenticated("account-a", true), SQL)
        .await
        .unwrap();
    assert_eq!(
        ordinary_kernel_call(&v2, "account-a", "query_sql", json!({"sql":SQL}))
            .await
            .unwrap()["rows"],
        json!(expected.rows)
    );
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn facet_times_v1_v2_equivalence_current_writes_types_and_replay() {
    let (_f, v1, v2) = fixture().await;
    for account in ["account-a", "account-b"] {
        let expected = query_sql(&v1, QueryPrincipal::authenticated(account, true), SQL)
            .await
            .unwrap();
        let actual = ordinary_kernel_call(&v2, account, "query_sql", json!({"sql":SQL}))
            .await
            .unwrap();
        assert_eq!(actual["columns"], json!(expected.columns));
        assert_eq!(actual["rows"], json!(expected.rows));
        assert_eq!(
            expected.rows.len(),
            if account == "account-a" { 10 } else { 5 }
        );
        let due = expected.rows.iter().find(|r| r["key"] == "due").unwrap();
        assert_eq!(due["start_date"], "2026-10-06");
        assert_eq!(due["end_date"], "2026-10-07");
        let zoned = expected.rows.iter().find(|r| r["key"] == "zoned").unwrap();
        assert_eq!(zoned["tzdb_version"], "1999a");
        assert_eq!(zoned["start_ms"], 1_782_900_000_000i64);
        let typed = "SELECT typeof(record_id) AS record_id,typeof(key) AS key,typeof(kind) AS kind,typeof(all_day) AS all_day,typeof(start_date) AS start_date,typeof(end_date) AS end_date,typeof(start_ms) AS start_ms,typeof(end_ms) AS end_ms,typeof(tz) AS tz,typeof(tzdb_version) AS tzdb_version FROM facet_times ORDER BY facet_times.record_id,facet_times.key";
        let expected = query_sql(&v1, QueryPrincipal::authenticated(account, true), typed)
            .await
            .unwrap();
        let actual = ordinary_kernel_call(&v2, account, "query_sql", json!({"sql":typed}))
            .await
            .unwrap();
        assert_eq!(actual["rows"], json!(expected.rows));
    }
    let before = ordinary_kernel_call(&v2, "account-a", "query_sql", json!({"sql":SQL}))
        .await
        .unwrap();
    k::replay_all_projections(&v2).await.unwrap();
    assert_eq!(
        ordinary_kernel_call(&v2, "account-a", "query_sql", json!({"sql":SQL}))
            .await
            .unwrap()["rows"],
        before["rows"]
    );
    let catalog = ordinary_kernel_call(&v2,"account-a","query_sql",json!({"sql":"SELECT column_name FROM catalog_columns WHERE relation_name='facet_times' ORDER BY column_position"})).await.unwrap();
    assert_eq!(catalog["rows"].as_array().unwrap().len(), 10);
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn facet_times_live_visibility_and_native_untyped_changes() {
    let (_f, v1, v2) = fixture().await;
    let hidden = "SELECT record_id,key FROM facet_times WHERE record_id='secret' OR 1=1 ORDER BY record_id,key";
    let b = ordinary_kernel_call(&v2, "account-b", "query_sql", json!({"sql":hidden}))
        .await
        .unwrap();
    assert_eq!(b["rows"].as_array().unwrap().len(), 5);
    assert!(b["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["record_id"] == "task"));
    let a = k::resolve_principal_by_binding(&v2, "account-a")
        .await
        .unwrap()
        .unwrap()
        .0;
    let before = ordinary_kernel_call(&v2, "account-a", "query_sql", json!({"sql":SQL}))
        .await
        .unwrap();
    k::observe_facet_as(
        &v2,
        &a,
        "secret",
        &k::FacetObservation {
            key: "due".into(),
            value: Some("old observation".into()),
            value_num: None,
            vocab_ref: None,
            as_of: "1990-01-01T00:00:00.000Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        ordinary_kernel_call(&v2, "account-a", "query_sql", json!({"sql":SQL}))
            .await
            .unwrap()["rows"],
        before["rows"]
    );
    let mut conn = v2.pool().acquire().await.unwrap();
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id='task'")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    let anchor = k::kernel_policy_anchor_on(&mut conn, &home).await.unwrap();
    drop(conn);
    k::replace_home_policy(&v2, &a, &anchor, &[(&a, "manage")])
        .await
        .unwrap();
    // All subsequent reads, even COUNT(*) and a reused caller, see revocation.
    let after = ordinary_kernel_call(
        &v2,
        "account-b",
        "query_sql",
        json!({"sql":"SELECT count(*) AS n FROM facet_times"}),
    )
    .await
    .unwrap();
    assert_eq!(after["rows"][0]["n"], 0);
    crate::authorization::replace_explicit_policy(
        &v1,
        "test:policy",
        "task",
        vec![AllowEntry::account("account-a", Capability::Manage)],
    )
    .await
    .unwrap();
    let expected = query_sql(&v1, QueryPrincipal::authenticated("account-b", true), SQL)
        .await
        .unwrap();
    assert!(expected.rows.is_empty());
    ordinary_kernel_call(
        &v2,
        "account-a",
        "update_record",
        json!({"id":"secret","facets":{"due":"ordinary text","at":null}}),
    )
    .await
    .unwrap();
    let after = ordinary_kernel_call(
        &v2,
        "account-a",
        "query_sql",
        json!({"sql":"SELECT key FROM facet_times WHERE record_id='secret' ORDER BY key"}),
    )
    .await
    .unwrap();
    assert_eq!(
        after["rows"],
        json!([{"key":"days"},{"key":"meeting"},{"key":"zoned"}])
    );
    crate::store::append(
        &v1,
        crate::store::AppendSpec {
            record_id: "secret".into(),
            event_type: "facet.set".into(),
            payload: json!({"key":"due","value":"ordinary text"}),
            actor: None,
        },
    )
    .await
    .unwrap();
    crate::store::unset_facet(&v1, "secret", "at")
        .await
        .unwrap();
    let expected = query_sql(&v1, QueryPrincipal::authenticated("account-a", true), SQL)
        .await
        .unwrap();
    assert_eq!(
        ordinary_kernel_call(&v2, "account-a", "query_sql", json!({"sql":SQL}))
            .await
            .unwrap()["rows"],
        json!(expected.rows)
    );
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn facet_times_malformed_retained_rows_are_isolated_and_counted() {
    let (_f, v1, v2) = fixture_extra(true, true, false).await;
    for (account, dropped) in [("account-a", 4), ("account-b", 2)] {
        let expected = query_sql(&v1, QueryPrincipal::authenticated(account, true), SQL)
            .await
            .unwrap();
        let (actual, diagnostic) = crate::mcp::kernel_v2::sql::measured(ordinary_kernel_call(
            &v2,
            account,
            "query_sql",
            json!({"sql":SQL}),
        ))
        .await;
        assert_eq!(actual.unwrap()["rows"], json!(expected.rows));
        assert_eq!(diagnostic.invalid_facet_time_rows, dropped);
    }
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn facet_times_comments_and_attachments_follow_live_bearer_visibility() {
    let (_f, v1, v2) = fixture_extra(true, false, true).await;
    for account in ["account-a", "account-b"] {
        let actual = ordinary_kernel_call(&v2, account, "query_sql", json!({"sql":SQL}))
            .await
            .unwrap();
        for (id, visible) in [
            ("comment-public", true),
            ("attachment-public", true),
            ("comment-private", account == "account-a"),
            ("attachment-private", account == "account-a"),
        ] {
            assert_eq!(
                actual["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["record_id"] == id)
                    .count(),
                if visible { 5 } else { 0 },
                "{account}: {id}"
            );
        }
    }
    let admin = k::resolve_principal_by_binding(&v2, "account-a")
        .await
        .unwrap()
        .unwrap();
    let admin = admin.0;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id='task'")
        .fetch_one(v2.pool())
        .await
        .unwrap();
    let mut conn = v2.pool().acquire().await.unwrap();
    let anchor = k::kernel_policy_anchor_on(&mut conn, &home).await.unwrap();
    drop(conn);
    k::replace_home_policy(&v2, &admin, &anchor, &[(&admin, "manage")])
        .await
        .unwrap();
    let actual = ordinary_kernel_call(&v2, "account-b", "query_sql", json!({"sql":SQL}))
        .await
        .unwrap();
    assert!(actual["rows"].as_array().unwrap().is_empty());
    v1.close().await;
    v2.close().await;
}

/// Reproducible, synthetic scale evidence, never a wall-clock CI assertion.
/// CI exercises all callers once; set NATIVE_FACET_TIMES_TIMING_SAMPLES=20
/// (or higher) for a p95 run. Both engines use file databases and live guards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn facet_times_hq_scale_equivalence_and_timing() {
    use std::time::Instant;
    let f = Fixture::new().await;
    std::fs::write(&f.members, "account-a\naccount-b\naccount-c\naccount-d\n").unwrap();
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    // 12k extra records; 12k typed dates + 9k ordinary values; 2k older
    // observation-only dates. The eight base fixture records add two values.
    source.execute(r#"BEGIN;
        INSERT INTO bindings VALUES('person-c','account','account-c',1),('person-d','account','account-d',1);
        WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<12000)
        INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id,created_at,updated_at,archived)
        SELECT printf('scale-%05d',i),'WorkItem','task','Synthetic','folder','native:root','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0 FROM n;
        INSERT INTO facet_values SELECT id,'due','2026-10-06',NULL,NULL,'2026-01-01T00:00:00Z' FROM records WHERE id LIKE 'scale-%';
        INSERT INTO facet_values SELECT id,'priority','normal',NULL,NULL,'2026-01-01T00:00:00Z' FROM records WHERE id BETWEEN 'scale-00001' AND 'scale-09000';
        INSERT INTO content_events(id,record_id,type,payload,created_at)
        SELECT 'current-'||record_id||'-'||key,record_id,'facet.set',
          CASE WHEN key='due' THEN json_object('key',key,'value',value,'time_kind','date') ELSE json_object('key',key,'value',value) END,
          '2026-01-01T00:00:00Z' FROM facet_values WHERE record_id LIKE 'scale-%';
        INSERT INTO content_events(id,record_id,type,payload,created_at)
        SELECT 'old-'||id,id,'facet.set',json_object('key','due','value','2020-01-01','time_kind','date','as_of','2020-01-01T00:00:00Z','observation_only',json('true')),
          '2026-02-01T00:00:00Z' FROM records WHERE id BETWEEN 'scale-00001' AND 'scale-02000';
        INSERT INTO facet_observations SELECT record_id,json_extract(payload,'$.key'),coalesce(json_extract(payload,'$.as_of'),created_at),seq FROM content_events WHERE record_id LIKE 'scale-%';
        CREATE INDEX scale_facets_record ON facet_values(record_id,key);
        CREATE INDEX scale_observations_record ON facet_observations(record_id,key);
        CREATE INDEX scale_history_record ON content_events(record_id,seq);
        COMMIT;"#).await.unwrap();
    for (table, expected) in [
        ("records", 12000),
        ("facet_values", 21000),
        ("facet_observations", 23000),
    ] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {table} WHERE {} LIKE 'scale-%'",
            if table == "records" {
                "id"
            } else {
                "record_id"
            }
        ))
        .fetch_one(&mut source)
        .await
        .unwrap();
        assert_eq!(count, expected);
    }
    source.close().await.unwrap();
    let oracle_path = f._dir.path().join("v1-oracle.db");
    let v1 = crate::create_database(oracle_path.to_str().unwrap())
        .await
        .unwrap();
    let mut conn = v1.write_pool().acquire().await.unwrap();
    sqlx::query("ATTACH DATABASE ? AS corpus")
        .bind(f.source.to_str().unwrap())
        .execute(&mut *conn)
        .await
        .unwrap();
    conn.execute(r#"INSERT OR IGNORE INTO main.records(id,type,kind,name,home_id,policy_anchor_id)
          SELECT id,type,kind,name,home_id,'native:root' FROM corpus.records WHERE id LIKE 'scale-%' OR id IN ('native:root','folder');
        INSERT INTO main.facet_values(id,record_id,key,value,created_at)
          SELECT record_id||'-'||key,record_id,key,value,created_at FROM corpus.facet_values WHERE record_id LIKE 'scale-%';
        INSERT INTO main.facet_observations(id,record_id,key,value,op,as_of,observed_at,event_seq)
          SELECT id,record_id,json_extract(payload,'$.key'),json_extract(payload,'$.value'),'set',coalesce(json_extract(payload,'$.as_of'),created_at),created_at,seq FROM corpus.content_events WHERE record_id LIKE 'scale-%';
        INSERT INTO main.content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status)
          SELECT id,record_id,type,payload,created_at,1,'legacy_unknown' FROM corpus.content_events WHERE record_id LIKE 'scale-%';"#).await.unwrap();
    assert_eq!(
        crate::projector::rebuild_facet_times(&mut conn)
            .await
            .unwrap(),
        12000
    );
    conn.execute("DETACH DATABASE corpus").await.unwrap();
    drop(conn);
    crate::authorization::replace_explicit_policy(
        &v1,
        "test:policy",
        "native:root",
        vec![AllowEntry::members(Capability::View)],
    )
    .await
    .unwrap();
    let mut options = f.options(&[], false);
    options.all = true;
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let v2 = f.db().await;
    let accounts = ["account-a", "account-b", "account-c", "account-d"];
    super::app_state::app_roster(&v2, "account-a", &accounts).await;
    // No snapshot time array: exercise the retained-history fallback used by
    // existing history imports, rather than the new importer's fast snapshot.
    let retained_arrays:i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type='kernel.legacy_recorded.v1' AND json_type(payload,'$.legacy.payload.facet_times')='array'").fetch_one(v2.pool()).await.unwrap();
    assert_eq!(retained_arrays, 0);
    let count = ordinary_kernel_call(
        &v2,
        "account-a",
        "query_sql",
        json!({"sql":"SELECT count(*) AS n FROM facet_times"}),
    )
    .await
    .unwrap();
    assert_eq!(count["rows"][0]["n"], 12000);
    const STATEMENT: &str = "SELECT record_id,key,kind,all_day,start_date,end_date FROM facet_times WHERE all_day=1 AND start_date<'2026-10-08' AND end_date>'2026-10-01' ORDER BY start_date,record_id,key LIMIT 100";
    let expected = query_sql(
        &v1,
        QueryPrincipal::authenticated("account-a", true),
        STATEMENT,
    )
    .await
    .unwrap();
    assert_eq!(expected.rows.len(), 100);
    for account in accounts {
        let actual = ordinary_kernel_call(&v2, account, "query_sql", json!({"sql":STATEMENT}))
            .await
            .unwrap();
        assert_eq!(actual["rows"], json!(expected.rows));
    }
    let samples = std::env::var("NATIVE_FACET_TIMES_TIMING_SAMPLES")
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(1)
        .max(1);
    for (name, db) in [("v1", &v1), ("v2", &v2)] {
        let call = |account: &'static str| {
            let db = (*db).clone();
            async move {
                let start = Instant::now();
                if name == "v1" {
                    assert_eq!(
                        query_sql(&db, QueryPrincipal::authenticated(account, true), STATEMENT)
                            .await
                            .unwrap()
                            .rows
                            .len(),
                        100
                    );
                } else {
                    assert_eq!(
                        ordinary_kernel_call(&db, account, "query_sql", json!({"sql":STATEMENT}))
                            .await
                            .unwrap()["rows"]
                            .as_array()
                            .unwrap()
                            .len(),
                        100
                    );
                }
                start.elapsed().as_secs_f64() * 1000.0
            }
        };
        // Warm up every caller before collecting either mode.
        for account in accounts {
            call(account).await;
        }
        let mut single = Vec::new();
        for _ in 0..samples {
            single.push(call(accounts[0]).await);
        }
        let mut four = Vec::new();
        for _ in 0..samples {
            // Independent requests may decode in parallel, as on the server;
            // joining bare futures would serialize their Rust work in one task.
            let tasks = accounts.map(|account| tokio::spawn(call(account)));
            for task in tasks {
                four.push(task.await.unwrap());
            }
        }
        let p95 = |v: &mut Vec<f64>| {
            v.sort_by(f64::total_cmp);
            v[(v.len() * 95).div_ceil(100) - 1]
        };
        eprintln!("FACET_TIMES_TIMING engine={name} samples_single={} samples_four={} p95_single_ms={:.2} p95_four_ms={:.2} records=12000 values=21000 observations=23000 typed_rows=12000 history=true snapshot_arrays=false",single.len(),four.len(),p95(&mut single),p95(&mut four));
    }
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn facet_times_projection_readiness_preparation_and_replay() {
    let (_f, v1, v2) = fixture().await;
    let expected = k::projection_dump::dump(&v2).await.unwrap();
    for table in [
        "kernel_facet_time_rows",
        "kernel_facet_time_invalid",
        "kernel_facet_time_meta",
    ] {
        assert!(expected.tables.iter().any(|t| t.name == table));
    }
    sqlx::query("UPDATE kernel_facet_time_rows SET start_date='2099-01-01' WHERE key='due'")
        .execute(v2.write_pool())
        .await
        .unwrap();
    assert_ne!(
        expected.sha256,
        k::projection_dump::dump(&v2).await.unwrap().sha256,
        "N1 must digest the new cache rows"
    );
    k::prepare_v2_database(&v2).await.unwrap();
    assert_eq!(expected, k::projection_dump::dump(&v2).await.unwrap());
    // An older file lacks the additive projection. Serving refuses cleanly,
    // without repairing the file or issuing a SELECT against a missing table.
    sqlx::query(
        "DROP TABLE kernel_facet_time_rows; DROP TABLE kernel_facet_time_invalid;
        DROP TABLE kernel_facet_time_meta; DROP INDEX idx_kernel_facet_time_frontier",
    )
    .execute(v2.write_pool())
    .await
    .unwrap();
    let error = ordinary_kernel_call(&v2, "account-a", "query_sql", json!({"sql":SQL}))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("facet-time read projection is not ready"),
        "{error}"
    );
    assert!(!error.contains("no such table"));
    k::prepare_v2_database(&v2).await.unwrap();
    assert_eq!(expected, k::projection_dump::dump(&v2).await.unwrap());
    k::prepare_v2_database(&v2).await.unwrap();
    assert_eq!(expected, k::projection_dump::dump(&v2).await.unwrap());
    // Version mismatch, stale frontier and a sticky skipped-writer gap each
    // refuse. Preparation derives the exact same bytes from retained events.
    for update in ["version=99", "projected_seq=0", "gap_free=0"] {
        sqlx::query(&format!("UPDATE kernel_facet_time_meta SET {update}"))
            .execute(v2.write_pool())
            .await
            .unwrap();
        let error = ordinary_kernel_call(&v2, "account-a", "query_sql", json!({"sql":SQL}))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("facet-time read projection is not ready"),
            "{error}"
        );
        k::prepare_v2_database(&v2).await.unwrap();
        assert_eq!(expected, k::projection_dump::dump(&v2).await.unwrap());
    }
    k::replay_all_projections(&v2).await.unwrap();
    assert_eq!(expected, k::projection_dump::dump(&v2).await.unwrap());
    assert_history_scan_equivalence(&v2).await;
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn facet_times_projection_is_in_verified_standby_delta_and_full_replay() {
    let (_f, v1, v2) = fixture().await;
    let actor = k::resolve_principal_by_binding(&v2, "account-a")
        .await
        .unwrap()
        .unwrap()
        .0;
    let dump =
        crate::standby::kernel_v2_tests::assert_projection_delta_equivalence(&v2, || async {
            k::observe_facet_as(
                &v2,
                &actor,
                "task",
                &k::FacetObservation {
                    key: "due".into(),
                    value: Some("untyped live replacement".into()),
                    value_num: None,
                    vocab_ref: None,
                    as_of: "2040-01-01T00:00:00.000Z".into(),
                },
                None,
            )
            .await
            .unwrap();
        })
        .await;
    assert!(dump
        .tables
        .iter()
        .any(|t| t.name == "kernel_facet_time_rows" && t.rows == 9));
    assert_history_scan_equivalence(&v2).await;
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn facet_times_projection_skipped_writer_gap_stays_unready() {
    let (_f, v1, v2) = fixture().await;
    let actor = k::resolve_principal_by_binding(&v2, "account-a")
        .await
        .unwrap()
        .unwrap()
        .0;
    // Simulate an older writer that appended a relevant event but skipped
    // this new projection. A later current writer must not bless that gap.
    sqlx::query("UPDATE kernel_facet_time_meta SET projected_seq=0")
        .execute(v2.write_pool())
        .await
        .unwrap();
    k::observe_facet_as(
        &v2,
        &actor,
        "task",
        &k::FacetObservation {
            key: "due".into(),
            value: Some("untyped live replacement".into()),
            value_num: None,
            vocab_ref: None,
            as_of: "2040-01-01T00:00:00.000Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    let gap_free: i64 = sqlx::query_scalar("SELECT gap_free FROM kernel_facet_time_meta")
        .fetch_one(v2.pool())
        .await
        .unwrap();
    assert_eq!(gap_free, 0);
    assert!(k::verify_v2_ready(&v2).await.is_err());
    k::prepare_v2_database(&v2).await.unwrap();
    k::verify_v2_ready(&v2).await.unwrap();
    assert_history_scan_equivalence(&v2).await;
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn facet_times_projection_matches_history_scan_for_all_endpoint_shapes() {
    for history in [false, true] {
        let (_f, v1, v2) = fixture_shapes(history, false, false, true).await;
        for account in ["account-a", "account-b"] {
            let expected = query_sql(&v1, QueryPrincipal::authenticated(account, true), SQL)
                .await
                .unwrap();
            let actual = ordinary_kernel_call(&v2, account, "query_sql", json!({"sql":SQL}))
                .await
                .unwrap();
            assert_eq!(actual["rows"], json!(expected.rows));
            assert_eq!(
                expected.rows.len(),
                if account == "account-a" { 20 } else { 10 }
            );
        }
        let before = k::projection_dump::dump(&v2).await.unwrap();
        k::replay_all_projections(&v2).await.unwrap();
        assert_eq!(before, k::projection_dump::dump(&v2).await.unwrap());
        assert_history_scan_equivalence(&v2).await;
        v1.close().await;
        v2.close().await;
    }
}
