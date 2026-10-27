use super::*;
use serde_json::json;
use std::time::{Duration, Instant};

struct Fixture {
    _dir: tempfile::TempDir,
    db: Db,
    actor: String,
    host: String,
    anchor: String,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (db, actor) = kernel::create_v2_database(
            dir.path().join("proof.db").to_str().unwrap(),
            "account",
            "Admin",
            "acct:proof",
        )
        .await
        .unwrap();
        let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&actor, "manage")]), &actor)
            .await
            .unwrap();
        let anchor = kernel::create_record_as(&db, &actor, &home).await.unwrap();
        Self {
            anchor,
            _dir: dir,
            db,
            actor,
            host,
        }
    }
    async fn import(&self, section: &str, id: &str, value: Option<Value>) {
        kernel::v1_state::import_state_batch_as(
            &self.db,
            &self.host,
            &[wrapper(section, id, value)],
        )
        .await
        .unwrap();
    }
    async fn proof(&self) -> Proof {
        let snapshot = prepare(&self.db, deadline()).await.unwrap();
        let selected: Vec<_> = (0..snapshot.sources.len()).collect();
        snapshot
            .seal(&self.actor, &selected, std::slice::from_ref(&self.anchor))
            .await
            .unwrap()
    }
    async fn recheck(&self, p: &Proof) -> Result<Work> {
        let mut tx = crate::db::begin_write(self.db.write_pool()).await?;
        let result = p.recheck_on(&self.db, &mut tx, &self.actor).await;
        tx.rollback().await?;
        result
    }
    async fn event(&self, kind: &str, raw: &str) {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES(?,?,?,?,1,'legacy_unknown')")
            .bind(uuid::Uuid::new_v4().to_string()).bind(KERNEL_ROOT_ID).bind(kind).bind(raw).execute(self.db.write_pool()).await.unwrap();
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn wrapper(section: &str, id: &str, value: Option<Value>) -> kernel::v1_state::ImportedState {
    kernel::v1_state::ImportedState {
        section: section.into(),
        source_id: json!([id]).to_string(),
        origin: "fixture:v1".into(),
        value_json: value.map(|v| v.to_string()),
        account_principal: None,
        record_id: None,
        observed_at: "2026-10-27T00:00:00Z".into(),
        snapshot: json!({"origin_db_id":"fixture:v1"}),
    }
}

#[tokio::test]
async fn named_view_source_proof_snapshot_is_complete_sealed_and_accepts_four_by_sixty_four() {
    let f = Fixture::new().await;
    let mut rows = vec![];
    for v in 0..4 {
        rows.push(wrapper(
            "vocabularies",
            &format!("v{v}"),
            Some(json!({"id":format!("v{v}"),"name":format!("V{v}")})),
        ));
        for n in 0..64 {
            rows.push(wrapper("vocabulary_values",&format!("vv{v}:{n}"),Some(json!({"id":format!("vv{v}:{n}"),"vocabulary_id":format!("v{v}"),"value":format!("value{n}"),"status":"canonical","alias_of":null}))));
        }
    }
    for chunk in rows.chunks(256) {
        kernel::v1_state::import_state_batch_as(&f.db, &f.host, chunk)
            .await
            .unwrap();
    }
    let start = Instant::now();
    let snapshot = prepare(&f.db, deadline()).await.unwrap();
    let prepare_ms = start.elapsed().as_millis();
    assert_eq!(snapshot.sources.len(), 260);
    assert_eq!(snapshot.work.rows, 520); // State rows AND sealed wrappers.
    let mut conn = f.db.pool().acquire().await.unwrap();
    for s in &snapshot.sources {
        let event = super::super::read_event(&mut conn, &s.event_id, snapshot.head.0)
            .await
            .unwrap();
        assert_eq!(
            s.event_sha256,
            super::super::closure::source_digest(&event).unwrap()
        );
    }
    eprintln!(
        "source prepare: 260 sources, {} inspected bytes/{} rows, {} ms",
        snapshot.work.bytes, snapshot.work.rows, prepare_ms
    );
    let proof = snapshot
        .seal(
            &f.actor,
            &(0..260).collect::<Vec<_>>(),
            std::slice::from_ref(&f.anchor),
        )
        .await
        .unwrap();
    assert_eq!(f.recheck(&proof).await.unwrap().rows, 0); // S included, T=S.
}

#[tokio::test]
async fn named_view_source_proof_interval_catches_unknown_new_override_delete_and_isolated_alias() {
    let f = Fixture::new().await;
    f.import(
        "schema_config",
        "selected",
        Some(json!({"id":"selected","data":"{}"})),
    )
    .await;
    for (section, id, value) in [
        (
            "schema_config",
            "other-scope-new-override",
            Some(json!({"id":"other-scope-new-override","applies_to_collection_id":"elsewhere"})),
        ),
        ("schema_config", "selected", None),
        ("vocabularies", "unseen", Some(json!({"id":"unseen"}))),
    ] {
        let p = f.proof().await;
        f.import(section, id, value).await;
        assert!(f
            .recheck(&p)
            .await
            .unwrap_err()
            .to_string()
            .contains("view_source_changed"));
    }
    // A fresh baseline AFTER deletion; the alias is the only event in (S,T].
    f.import(
        "vocabulary_values",
        "old",
        Some(json!({"id":"old","vocabulary_id":"unseen","value":"old"})),
    )
    .await;
    f.import("vocabulary_values", "old", None).await;
    let p = f.proof().await;
    f.import(
        "vocabulary_values",
        "new-alias",
        Some(json!({"id":"new-alias","vocabulary_id":"unseen","alias_of":"old","value":"alias"})),
    )
    .await;
    let error = f.recheck(&p).await.unwrap_err().to_string();
    assert!(
        error.contains("catalog import since preparation"),
        "{error}"
    );
}

#[tokio::test]
async fn named_view_source_proof_window_charges_unrelated_events_and_bytes_before_parse() {
    let f = Fixture::new().await;
    let p = f.proof().await;
    for _ in 0..35 {
        f.event("fixture.unrelated", "{}").await;
    }
    let work = f.recheck(&p).await.unwrap();
    assert_eq!(work.rows, 35); // More than one keyset page, not just relevant rows.
    assert!(work.bytes > 35 * 24);
    let p = f.proof().await;
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<512) INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) SELECT printf('unrelated:%d',x),'fixture','fixture.unrelated','{}',1,'legacy_unknown' FROM n").execute(f.db.write_pool()).await.unwrap();
    let start = Instant::now();
    let work = f.recheck(&p).await.unwrap();
    assert_eq!(work.rows, 512);
    eprintln!(
        "source commit window: {} rows/{} bytes, {} ms",
        work.rows,
        work.bytes,
        start.elapsed().as_millis()
    );
    f.event("fixture.unrelated", "{}").await;
    let (result, counters) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let result = f.recheck(&p).await;
            (result, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("budget"));
    assert_eq!(counters[3], 512); // Not a 513th event or a whole extra page.
    let p = f.proof().await;
    f.event("fixture.unrelated", &"x".repeat(WINDOW_BYTES + 1))
        .await;
    let (result, trace) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let r = f.recheck(&p).await;
            (r, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("budget"));
    assert_eq!(&trace[..3], &[0, 0, 0]); // Oversized unrelated payload is not fetched either.
    let p = f.proof().await;
    f.event(kernel::v1_state::EVENT, &"{".repeat(WINDOW_BYTES + 1))
        .await;
    let (result, trace) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let r = f.recheck(&p).await;
            (r, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert!(result.unwrap_err().to_string().contains("budget"));
    assert_eq!(&trace[..3], &[0, 0, 0]);
}

#[tokio::test]
async fn named_view_source_proof_malformed_imports_refuse_but_valid_other_section_does_not() {
    let f = Fixture::new().await;
    for (kind, raw) in [
        (kernel::v1_state::EVENT, "{".to_owned()),
        (
            kernel::v1_state::EVENT,
            json!({"section":"schema_config","source_id":"x"}).to_string(),
        ),
        (
            "kernel.v1_state_imported.v2",
            serde_json::to_string(&wrapper("schema_config", "new", None)).unwrap(),
        ),
        (
            kernel::v1_state::EVENT,
            "{\"section\":\"runs\",\"section\":\"schema_config\"}".to_owned(),
        ),
    ] {
        let p = f.proof().await;
        f.event(kind, &raw).await;
        assert!(f.recheck(&p).await.is_err());
    }
    let p = f.proof().await;
    f.event(
        kernel::v1_state::EVENT,
        &serde_json::to_string(&wrapper(
            "onboarding_programmes",
            "unrelated",
            Some(json!({"id":"unrelated"})),
        ))
        .unwrap(),
    )
    .await;
    assert_eq!(f.recheck(&p).await.unwrap().rows, 1);
}

#[tokio::test]
async fn named_view_source_proof_state_and_wrapper_oversize_refuse_without_transport() {
    let f = Fixture::new().await;
    sqlx::query("INSERT INTO kernel_v1_state VALUES('schema_config','[\"large\"]','fixture',?,NULL,NULL,'2026-10-27T00:00:00Z',1)")
        .bind(json!({"id":"large","padding":"x".repeat(PREPARE_BYTES+1)}).to_string()).execute(f.db.write_pool()).await.unwrap();
    let (result, trace) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let r = prepare(&f.db, deadline()).await;
            (r, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert!(result.err().unwrap().to_string().contains("budget"));
    assert_eq!(&trace[..3], &[0, 0, 0]);
    sqlx::query("DELETE FROM kernel_v1_state")
        .execute(f.db.write_pool())
        .await
        .unwrap();
    // Small state, oversized wrapper: count wrapper bytes before fetching it.
    f.event(kernel::v1_state::EVENT, &"{".repeat(PREPARE_BYTES + 1))
        .await;
    let seq: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_v1_state VALUES('schema_config','[\"small\"]','fixture','{}',NULL,NULL,'2026-10-27T00:00:00Z',?)").bind(seq).execute(f.db.write_pool()).await.unwrap();
    let (result, trace) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let r = prepare(&f.db, deadline()).await;
            (r, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert!(result.err().unwrap().to_string().contains("budget"));
    assert_eq!(&trace[..3], &[1, 0, 0]);
}

#[tokio::test]
async fn named_view_source_proof_checks_exact_wrapper_origin_row_identity_and_event_uuid() {
    let f = Fixture::new().await;
    f.import("schema_config", "s", Some(json!({"id":"s","data":"{}"})))
        .await;
    let mut p = f.proof().await;
    p.refs[0].event_id = uuid::Uuid::new_v4().to_string();
    assert!(f
        .recheck(&p)
        .await
        .unwrap_err()
        .to_string()
        .contains("source reference changed"));
    for field in ["origin", "payload", "record_id", "observed_at"] {
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let old: Option<String> =
            sqlx::query_scalar(&format!("SELECT {field} FROM kernel_v1_state"))
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        sqlx::query(&format!("UPDATE kernel_v1_state SET {field}=?"))
            .bind(if field == "payload" {
                "{\"id\":\"tampered\"}"
            } else {
                "tampered"
            })
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(prepare(&f.db, deadline()).await.is_err(), "{field}");
        sqlx::query(&format!("UPDATE kernel_v1_state SET {field}=?"))
            .bind(old)
            .execute(f.db.write_pool())
            .await
            .unwrap();
    }
    let proof = f.proof().await;
    f.import("schema_config", "s", None).await;
    let mut replacement = wrapper("schema_config", "s", Some(json!({"id":"s"})));
    replacement.origin = "x".repeat(WINDOW_BYTES + 1);
    kernel::v1_state::import_state_batch_as(&f.db, &f.host, &[replacement])
        .await
        .unwrap();
    assert!(f
        .recheck(&proof)
        .await
        .unwrap_err()
        .to_string()
        .contains("source reference changed"));
}

#[tokio::test]
async fn named_view_source_proof_snapshot_identity_head_and_deadline_fail_closed() {
    let f = Fixture::new().await;
    let other = Fixture::new().await;
    let p = f.proof().await;
    let mut tx = crate::db::begin_write(other.db.write_pool()).await.unwrap();
    assert!(p
        .recheck_on(&other.db, &mut tx, &f.actor)
        .await
        .unwrap_err()
        .to_string()
        .contains("owner differs"));
    tx.rollback().await.unwrap();
    let mut p = f.proof().await;
    p.head.1 = "wrong-S-uuid".into();
    assert!(f
        .recheck(&p)
        .await
        .unwrap_err()
        .to_string()
        .contains("anchor changed"));
    let mut p = f.proof().await;
    p.head.0 += 1;
    assert!(f
        .recheck(&p)
        .await
        .unwrap_err()
        .to_string()
        .contains("anchor changed"));
    let mut p = f.proof().await;
    p.deadline = Instant::now();
    assert!(f
        .recheck(&p)
        .await
        .unwrap_err()
        .to_string()
        .contains("deadline"));
    assert!(prepare(&f.db, Instant::now()).await.is_err());
}

#[tokio::test]
async fn named_view_source_proof_rechecks_live_view_and_placement() {
    let f = Fixture::new().await;
    let home = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    let bearer = kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let s = prepare(&f.db, deadline()).await.unwrap();
    let p = s
        .seal(&f.actor, &[], std::slice::from_ref(&bearer))
        .await
        .unwrap();
    let new_home = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&f.db, &f.actor, &bearer, &new_home)
        .await
        .unwrap();
    assert!(f
        .recheck(&p)
        .await
        .unwrap_err()
        .to_string()
        .contains("placement changed"));
    let s = prepare(&f.db, deadline()).await.unwrap();
    let p = s
        .seal(&f.actor, &[], std::slice::from_ref(&bearer))
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_lifecycle VALUES(?,1)")
        .bind(&bearer)
        .execute(f.db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        f.recheck(&p).await.unwrap_err().to_string(),
        super::super::MISSING
    );
}

#[tokio::test]
async fn named_view_source_proof_commit_serializes_with_real_import() {
    let f = Fixture::new().await;
    let p = f.proof().await;
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let db = f.db.clone();
    let host = f.host.clone();
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let notify = started.clone();
    let import = tokio::spawn(async move {
        notify.notify_one();
        kernel::v1_state::import_state_batch_as(
            &db,
            &host,
            &[wrapper(
                "schema_config",
                "concurrent",
                Some(json!({"id":"concurrent"})),
            )],
        )
        .await
    });
    started.notified().await;
    assert_eq!(
        p.recheck_on(&f.db, &mut tx, &f.actor).await.unwrap().rows,
        0
    );
    assert!(!import.is_finished()); // Cannot enter writer until our commit ends.
    tx.commit().await.unwrap();
    import.await.unwrap().unwrap();
    assert!(f
        .recheck(&p)
        .await
        .unwrap_err()
        .to_string()
        .contains("catalog import"));
}

#[tokio::test]
async fn named_view_source_proof_sql_uses_keyset_rowid_and_metadata_bytelen() {
    let f = Fixture::new().await;
    let mut conn = f.db.pool().acquire().await.unwrap();
    let plan: Vec<(i64, i64, i64, String)> =
        sqlx::query_as(&format!("EXPLAIN QUERY PLAN {EVENT_PAGE}"))
            .bind(1)
            .bind(1000)
            .bind(PAGE)
            .fetch_all(&mut *conn)
            .await
            .unwrap();
    assert!(
        plan.iter().any(|p| p.3.contains("INTEGER PRIMARY KEY")
            && p.3.contains("rowid>?")
            && p.3.contains("rowid<?")),
        "{plan:?}"
    );
    let sql = state_page_sql(true);
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(&format!("EXPLAIN QUERY PLAN {sql}"))
        .bind("schema_config")
        .bind("")
        .bind(PAGE)
        .fetch_all(&mut *conn)
        .await
        .unwrap();
    assert!(
        plan.iter()
            .any(|p| p.3.contains("section=? AND source_id>?")),
        "{plan:?}"
    );
    let version: String = sqlx::query_scalar("SELECT sqlite_version()")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    let bytes: i64 = sqlx::query_scalar("SELECT octet_length('é')")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(bytes, 2);
    // The actual bundled VM marks direct TEXT Column reads BYTELEN (0xc0),
    // using record header lengths rather than loading overflow payload pages.
    let opcodes = sqlx::query(
        "EXPLAIN SELECT octet_length(payload) FROM kernel_v1_state WHERE section='schema_config'",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    assert!(opcodes
        .iter()
        .any(|r| r.get::<String, _>("opcode") == "Column" && r.get::<i64, _>("p5") == 0xc0));
    eprintln!(
        "SQLite {version}; rowid range and PK section/key plans; octet_length Column P5=0xc0"
    );
}

#[tokio::test]
async fn named_view_source_proof_view_loss_is_uniform_and_not_a_cached_permission() {
    let f = Fixture::new().await;
    let viewer =
        kernel::create_principal(&f.db, "account", "Viewer", "acct:proof-viewer", &f.actor)
            .await
            .unwrap();
    let home = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage"), (&viewer, "view")]),
        &f.actor,
    )
    .await
    .unwrap();
    let bearer = kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let snapshot = prepare(&f.db, deadline()).await.unwrap();
    let p = snapshot
        .seal(&viewer, &[], std::slice::from_ref(&bearer))
        .await
        .unwrap();
    kernel::replace_home_policy(&f.db, &f.actor, &home, &[(&f.actor, "manage")])
        .await
        .unwrap();
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    assert_eq!(
        p.recheck_on(&f.db, &mut tx, &viewer)
            .await
            .unwrap_err()
            .to_string(),
        super::super::MISSING
    );
}

#[test]
fn named_view_source_proof_counters_have_exact_row_byte_boundaries() {
    let mut work = Work::default();
    for _ in 0..PREPARE_ROWS {
        work.charge(0, PREPARE_ROWS, PREPARE_BYTES).unwrap();
    }
    assert!(work.charge(0, PREPARE_ROWS, PREPARE_BYTES).is_err());
    let mut work = Work::default();
    work.charge(WINDOW_BYTES as i64, WINDOW_ROWS, WINDOW_BYTES)
        .unwrap();
    assert!(work.charge(1, WINDOW_ROWS, WINDOW_BYTES).is_err());
}

#[tokio::test]
async fn named_view_source_proof_prepare_retains_s_while_new_row_commits() {
    let f = Fixture::new().await;
    let snapshot = prepare(&f.db, deadline()).await.unwrap();
    assert!(snapshot.sources().is_empty());
    f.import(
        "schema_config",
        "new-override",
        Some(json!({"id":"new-override"})),
    )
    .await;
    let proof = snapshot
        .seal(&f.actor, &[], std::slice::from_ref(&f.anchor))
        .await
        .unwrap();
    assert!(f
        .recheck(&proof)
        .await
        .unwrap_err()
        .to_string()
        .contains("catalog import"));
}

#[tokio::test]
async fn named_view_source_proof_retention_category_caps_are_independent_of_scan_capacity() {
    let f = Fixture::new().await;
    for n in 0..33 {
        f.import(
            "schema_config",
            &format!("s{n}"),
            Some(json!({"id":format!("s{n}")})),
        )
        .await;
    }
    let s = prepare(&f.db, deadline()).await.unwrap();
    let selected: Vec<_> = (0..s.sources().len()).collect();
    assert!(s
        .seal(&f.actor, &selected, std::slice::from_ref(&f.anchor))
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("category bound"));
    for n in 0..65 {
        f.import(
            "vocabulary_values",
            &format!("vv{n}"),
            Some(json!({"id":format!("vv{n}"),"vocabulary_id":"one","value":format!("v{n}")})),
        )
        .await;
    }
    let s = prepare(&f.db, deadline()).await.unwrap();
    let selected: Vec<_> = s
        .sources()
        .iter()
        .enumerate()
        .filter_map(|(n, r)| (r.section == "vocabulary_values").then_some(n))
        .collect();
    assert!(s
        .seal(&f.actor, &selected, std::slice::from_ref(&f.anchor))
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("category bound"));
}
