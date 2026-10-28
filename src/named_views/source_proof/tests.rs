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
        let mut tx = Writer::begin(&self.db, p.deadline).await?;
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

async fn export_copy(f: &Fixture, name: &str) -> std::path::PathBuf {
    let path = f._dir.path().join(name);
    sqlx::query("VACUUM main INTO ?")
        .bind(path.to_str().unwrap())
        .execute(f.db.write_pool())
        .await
        .unwrap();
    assert_eq!(&std::fs::read(&path).unwrap()[18..20], &[1, 1]);
    path
}
fn export_request(f: &Fixture, kind: &str, keys: &[&str]) -> super::super::export::Request {
    serde_json::from_value(json!({"actor":f.actor,"bearer":f.anchor,
        "record_type":"WorkItem","kind":kind,"home":"native:root",
        "selection":{"kind":"keys","keys":keys}}))
    .unwrap()
}

#[tokio::test]
async fn named_view_export_is_deterministic_physically_read_only_and_not_admission() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    let path = export_copy(&f, "export.db").await;
    let before = std::fs::read(&path).unwrap();
    let first =
        super::super::export::export_file(&path, export_request(&f, "task", &["area", "priority"]))
            .await
            .unwrap();
    let second =
        super::super::export::export_file(&path, export_request(&f, "task", &["priority", "area"]))
            .await
            .unwrap();
    assert_eq!(first, second);
    let mut all = export_request(&f, "task", &[]);
    all.selection = super::super::export::Selection::All;
    let all: Value =
        serde_json::from_slice(&super::super::export::export_file(&path, all).await.unwrap())
            .unwrap();
    assert_eq!(all["definition"]["generated"]["selection"]["kind"], "all");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(!std::path::Path::new(&format!("{}{suffix}", path.display())).exists());
    }
    // Byte equality includes event/binding counts, marker, schema and ACL state.
    let value: Value = serde_json::from_slice(&first).unwrap();
    assert!(value.get("proof").is_none());
    assert!(value["definition"]["generated"]["workspace_id"]
        .as_str()
        .unwrap()
        .starts_with("kernel:"));
    f.import("schema_config","new-override",Some(json!({"id":"new-override","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"Changed meaning"}}}}}).to_string(),"applies_to_collection_id":KERNEL_ROOT_ID,"version_lineage":null,"created_at":"2026-10-27T00:00:02Z"}))).await;
    let error = super::super::gate::testing(true,generated_operation(&f,json!({"action":"record_view_revision","id":f.anchor,"definition":value["definition"],"idempotency_key":"stale-export"}))).await.unwrap_err().to_string();
    assert!(error.contains("generated candidate differs"), "{error}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events WHERE type=?")
            .bind(super::super::REVISION)
            .fetch_one(f.db.pool())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn named_view_export_attention_subset_and_unsupported_shapes_are_honest() {
    let f = Fixture::new().await;
    // Source-only subset of HQ attention-v1: retain unsupported declarations
    // too, so selecting a subset cannot masquerade as full-shape support.
    f.import("schema_config","attention",Some(json!({"id":"attention","layer":"user","name":null,
        "data":json!({"shapes":{"WorkItem:attention":{"facets":{
        "for_person":{"required":true},"ask":{"required":true},"slip_count":{"type":"number"},
        "due":{"type":"when"},"snoozed_until":{"type":"instant"},
        "attention_kind":{"values":["decision","review","unblock","input"],"required":true},
        "options":{"type":"object","json_schema":{"type":"object"}}
    }}}}).to_string(),"applies_to_collection_id":KERNEL_ROOT_ID,"version_lineage":"attention-v1","created_at":"2026-10-27T00:00:00Z"}))).await;
    let path = export_copy(&f, "attention.db").await;
    let bytes = super::super::export::export_file(
        &path,
        export_request(&f, "attention", &["for_person", "ask", "slip_count"]),
    )
    .await
    .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["definition"]["columns"]["for_person"]["meaning"]
        .as_str()
        .unwrap()
        .contains("Declared facet for_person"));
    assert_eq!(
        v["definition"]["query"]["output"]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "slip_count")
            .unwrap()["type"],
        "real"
    );
    for key in ["due", "snoozed_until", "attention_kind", "options"] {
        let error =
            super::super::export::export_file(&path, export_request(&f, "attention", &[key]))
                .await
                .unwrap_err()
                .to_string();
        assert!(error.contains("Unsupported"), "{key}: {error}");
    }
    let mut absent = export_request(&f, "attention", &["ask"]);
    absent.bearer = "missing".into();
    let missing = super::super::export::export_file(&path, absent)
        .await
        .unwrap_err()
        .to_string();
    let mut hidden = export_request(&f, "attention", &["ask"]);
    hidden.actor = "not-a-principal".into();
    assert_eq!(
        super::super::export::export_file(&path, hidden)
            .await
            .unwrap_err()
            .to_string(),
        missing
    );
    assert_eq!(missing, super::super::MISSING);
    // Same real global declaration, no invented H governance: refuse honestly.
    f.import("schema_config", "attention", None).await;
    f.import("schema_config","attention-global",Some(json!({"id":"attention-global","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:attention":{"facets":{"ask":{"required":true}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"attention-v1","created_at":"2026-10-27T00:00:00Z"}))).await;
    let global = export_copy(&f, "global.db").await;
    let error =
        super::super::export::export_file(&global, export_request(&f, "attention", &["ask"]))
            .await
            .unwrap_err()
            .to_string();
    assert!(
        error.contains("home has no governing declaration"),
        "{error}"
    );
}

#[tokio::test]
async fn named_view_export_refuses_unsafe_files_and_pools_cannot_write() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    // An active WAL source is not an offline copy, even if readable locally.
    assert!(
        super::super::export::export_file(f.db.path(), export_request(&f, "task", &["area"]))
            .await
            .unwrap_err()
            .to_string()
            .contains("not WAL")
    );
    let path = export_copy(&f, "safe.db").await;
    let before = std::fs::read(&path).unwrap();
    let db = crate::db::open_offline_v2_export_at(&path).await.unwrap();
    for pool in [db.pool(), db.write_pool(), db.governed_pool()] {
        let error = sqlx::query("CREATE TABLE forbidden(x)")
            .execute(pool)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("readonly"), "{error}");
    }
    db.close().await;
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let sidecar = std::path::PathBuf::from(format!("{}-journal", path.display()));
    std::fs::write(sidecar, b"retained journal").unwrap();
    assert!(
        super::super::export::export_file(&path, export_request(&f, "task", &["area"]))
            .await
            .unwrap_err()
            .to_string()
            .contains("sidecar")
    );
    let missing = f._dir.path().join("missing.db");
    assert!(
        super::super::export::export_file(&missing, export_request(&f, "task", &["area"]))
            .await
            .is_err()
    );
    assert!(!missing.exists());
    let foreign = f._dir.path().join("foreign.db");
    std::fs::write(&foreign, &before).unwrap();
    {
        // Fixture-only marker substitution, never performed by the exporter.
        use sqlx::Connection;
        let mut conn = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(&foreign),
        )
        .await
        .unwrap();
        sqlx::query("PRAGMA application_id=0")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
    }
    assert!(
        super::super::export::export_file(&foreign, export_request(&f, "task", &["area"]))
            .await
            .unwrap_err()
            .to_string()
            .contains("marked v2")
    );
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
    let mut tx = Writer::begin(&other.db, p.deadline).await.unwrap();
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
    let mut tx = Writer::begin(&f.db, p.deadline).await.unwrap();
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
    let mut tx = Writer::begin(&f.db, p.deadline).await.unwrap();
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

#[tokio::test]
async fn named_view_source_proof_requires_actual_same_database_immediate_writer() {
    let f = Fixture::new().await;
    let foreign = Fixture::new().await;
    let p = f.proof().await;
    // Supplying the correct Db parameter cannot launder a foreign transaction.
    let mut tx = Writer::begin(&foreign.db, p.deadline).await.unwrap();
    assert!(p
        .recheck_on(&f.db, &mut tx, &f.actor)
        .await
        .unwrap_err()
        .to_string()
        .contains("same database writer"));
    // White-box corruption cannot launder the actual foreign connection either.
    tx.owner = f.db.clone();
    assert!(p
        .recheck_on(&f.db, &mut tx, &f.actor)
        .await
        .unwrap_err()
        .to_string()
        .contains("same database writer"));
    tx.rollback().await.unwrap();
    let mut read = Writer {
        owner: f.db.clone(),
        tx: f.db.pool().begin().await.unwrap(),
    };
    sqlx::query("SELECT count(*) FROM content_events")
        .fetch_one(&mut *read.tx)
        .await
        .unwrap();
    assert!(p
        .recheck_on(&f.db, &mut read, &f.actor)
        .await
        .unwrap_err()
        .to_string()
        .contains("same database writer"));
    read.rollback().await.unwrap();
    // Even a deferred transaction from the write pool is not BEGIN IMMEDIATE.
    let mut deferred = Writer {
        owner: f.db.clone(),
        tx: f.db.write_pool().begin().await.unwrap(),
    };
    assert!(p.recheck_on(&f.db, &mut deferred, &f.actor).await.is_err());
    deferred.rollback().await.unwrap();
    assert_eq!(f.recheck(&p).await.unwrap().rows, 0);
}

#[tokio::test]
async fn named_view_source_proof_deadline_maps_only_sqlite_interrupt() {
    let f = Fixture::new().await;
    let mut conn = f.db.pool().acquire().await.unwrap().detach();
    conn.lock_handle()
        .await
        .unwrap()
        .set_progress_handler(1, || false);
    let error = sqlx::query("SELECT count(*) FROM content_events")
        .fetch_one(&mut conn)
        .await
        .err()
        .unwrap();
    assert!(deadline_error(Error::Sqlx(error), Instant::now())
        .to_string()
        .contains("view_source_changed"));
    let other = Error::Sqlx(sqlx::Error::RowNotFound);
    assert!(matches!(
        deadline_error(other, Instant::now()),
        Error::Sqlx(sqlx::Error::RowNotFound)
    ));
}

fn generated_request(home: &str, keys: &[&str]) -> super::super::facet_resolver::Request {
    super::super::facet_resolver::Request {
        record_type: "WorkItem".into(),
        kind: Some("task".into()),
        home: home.into(),
        selection: crate::query::generated_facets::Selection::Keys(
            keys.iter().map(|s| s.to_string()).collect(),
        ),
    }
}
async fn declared(f: &Fixture, home: &str) {
    f.import("schema_config","global",Some(json!({"id":"global","layer":"pack","name":null,"data":json!({"shapes":{"WorkItem":{"facets":{"area":{"description":"Area"},"effort":{"type":"number"},"due":{"type":"date"},"priority":{"vocab_ref":"rec:priority"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"G1","created_at":"2026-10-27T00:00:00Z"}))).await;
    f.import("schema_config","local",Some(json!({"id":"local","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"description":"Governs direct members"}}}).to_string(),"applies_to_collection_id":home,"version_lineage":"H1","created_at":"2026-10-27T00:00:00Z"}))).await;
    f.import(
        "vocabularies",
        "priority",
        Some(json!({"id":"priority","name":"Priority"})),
    )
    .await;
    for (id, token, status, alias) in [
        ("high", "high", "active", None),
        ("old", "old", "deprecated", None),
        ("maybe", "maybe", "proposed", None),
        ("alias", "urgent", "active", Some("high")),
    ] {
        f.import("vocabulary_values",id,Some(json!({"id":id,"vocabulary_id":"priority","value":token,"status":status,"alias_of":alias}))).await;
    }
}
async fn candidate(
    f: &Fixture,
    home: &str,
    keys: &[&str],
) -> Result<super::super::facet_resolver::Prepared> {
    super::super::facet_resolver::prepare(
        &f.db,
        &f.actor,
        "trusted-workspace",
        &f.anchor,
        generated_request(home, keys),
        deadline(),
    )
    .await
}
#[tokio::test]
async fn named_view_source_proof_resolver_closed_candidate_is_canonical_and_frozen() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    let p = candidate(&f, KERNEL_ROOT_ID, &["priority", "area", "effort", "due"])
        .await
        .unwrap();
    let same = candidate(&f, KERNEL_ROOT_ID, &["due", "area", "priority", "effort"])
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&p.revision).unwrap(),
        serde_json::to_value(&same.revision).unwrap()
    );
    assert_eq!(p.name, p.revision.generated_name().unwrap());
    assert_eq!(p.revision.digest(), p.revision.definition_sha256);
    let def: super::super::v2::Definition =
        serde_json::from_value(p.revision.definition.clone()).unwrap();
    def.validate().unwrap();
    assert!(def.source_pins.is_empty());
    assert_eq!(
        def.query
            .output
            .columns
            .iter()
            .filter(|c| matches!(
                c.column_type,
                crate::mcp::tools::querying::SavedSqlColumnType::Boolean
            ))
            .count(),
        2
    );
    assert_eq!(def.generated.slots.len(), 8);
    assert_eq!(def.generated.governance_basis.len(), 1);
    assert_eq!(def.generated.sources.len(), 7);
    assert_eq!(p.required_catalog_sources, BTreeSet::from([0, 2])); // global winner + vocabulary; local governance/value rows advisory.
    let mut conn = f.db.pool().acquire().await.unwrap();
    for s in &def.generated.sources {
        let event = super::super::read_event(&mut conn, &s.event_id, i64::MAX)
            .await
            .unwrap();
        assert_eq!(
            s.event_sha256,
            super::super::closure::source_digest(&event).unwrap()
        );
    }
    drop(conn);
    assert_eq!(f.recheck(&p.proof).await.unwrap().rows, 0);
    let frozen = p.revision.definition.clone();
    f.import("vocabulary_values","new-alias",Some(json!({"id":"new-alias","vocabulary_id":"priority","value":"new","status":"active","alias_of":"high"}))).await;
    assert!(f.recheck(&p.proof).await.is_err());
    let newer = candidate(&f, KERNEL_ROOT_ID, &["priority", "area", "effort", "due"])
        .await
        .unwrap();
    assert_eq!(p.name, newer.name);
    assert_ne!(
        p.revision.definition_sha256,
        newer.revision.definition_sha256
    );
    assert_eq!(
        p.revision.definition, frozen,
        "A1 is retained, never regenerated by recheck"
    );
    assert!(!f.db.pool().is_closed());
}
#[tokio::test]
async fn named_view_source_proof_resolver_catches_new_override_and_requires_governance() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    let p = candidate(&f, KERNEL_ROOT_ID, &["area"]).await.unwrap();
    f.import("schema_config","override",Some(json!({"id":"override","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"type":"number"}}}}}).to_string(),"applies_to_collection_id":KERNEL_ROOT_ID,"version_lineage":"H2","created_at":"2026-10-27T00:00:01Z"}))).await;
    assert!(f.recheck(&p.proof).await.is_err());
    let next = candidate(&f, KERNEL_ROOT_ID, &["area"]).await.unwrap();
    assert_eq!(p.name, next.name);
    assert_ne!(p.revision.definition, next.revision.definition);
    f.import("schema_config", "local", None).await;
    f.import("schema_config", "override", None).await;
    assert!(candidate(&f, KERNEL_ROOT_ID, &["area"]).await.is_err());
}
#[tokio::test]
async fn named_view_source_proof_resolver_root_alias_and_folder_home_are_real_contexts() {
    let f = Fixture::new().await;
    // The selector alias denotes the kernel root even before imported staging
    // uses native:root as its logical label. Retain the actual staged label.
    declared(&f, KERNEL_ROOT_ID).await;
    let native = candidate(&f, "native:root", &["area"]).await.unwrap();
    let kernel = candidate(&f, KERNEL_ROOT_ID, &["area"]).await.unwrap();
    assert_eq!(native.revision.definition, kernel.revision.definition);
    assert_eq!(
        native.revision.definition["generated"]["context"]["logical_home_id"],
        KERNEL_ROOT_ID
    );
    kernel::import_home_policy_as(&f.db, &f.host, KERNEL_ROOT_ID, &[(&f.actor, "manage")])
        .await
        .unwrap();
    declared(&f, "native:root").await;
    let a = candidate(&f, "native:root", &["area"]).await.unwrap();
    let b = candidate(&f, KERNEL_ROOT_ID, &["area"]).await.unwrap();
    assert_eq!(a.revision.definition, b.revision.definition);
    assert_eq!(f.recheck(&a.proof).await.unwrap().rows, 0);
    // A real imported child-home binding points at a logical folder, not its
    // physical parent. Type fields model the imported v1 folder header only.
    let folder = kernel::create_record_as(&f.db, &f.actor, KERNEL_ROOT_ID)
        .await
        .unwrap();
    for (name, value) in [("v1_type", "\"Collection\""), ("v1_kind", "\"folder\"")] {
        sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) VALUES(?,?,?,1)")
            .bind(&folder)
            .bind(name)
            .bind(value)
            .execute(f.db.write_pool())
            .await
            .unwrap();
    }
    let child = kernel::v1_import_home_id(&folder);
    kernel::import_home_as(
        &f.db,
        &f.host,
        &child,
        &folder,
        KERNEL_ROOT_ID,
        &f.actor,
        None,
    )
    .await
    .unwrap();
    declared(&f, &folder).await;
    let logical = candidate(&f, &folder, &["area"]).await.unwrap();
    let physical = candidate(&f, &child, &["area"]).await.unwrap();
    assert_eq!(logical.revision.definition, physical.revision.definition);
    assert_eq!(
        logical.revision.definition["generated"]["context"]["logical_home_id"],
        folder
    );
    let home = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&f.db, &f.actor, &folder, &home)
        .await
        .unwrap();
    assert!(f
        .recheck(&logical.proof)
        .await
        .unwrap_err()
        .to_string()
        .contains("placement"));
}
#[tokio::test]
async fn named_view_source_proof_resolver_refuses_null_dangling_alias_and_absent_vocabulary() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    f.import("vocabulary_values","bad",Some(json!({"id":"bad","vocabulary_id":"priority","value":"bad","status":"active","alias_of":"missing"}))).await;
    assert!(candidate(&f, KERNEL_ROOT_ID, &["priority"]).await.is_err());
    f.import("vocabulary_values", "bad", None).await;
    f.import("vocabularies", "priority", None).await;
    assert!(candidate(&f, KERNEL_ROOT_ID, &["priority"]).await.is_err());
    f.import("schema_config","null-override",Some(json!({"id":"null-override","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":null}}}}).to_string(),"applies_to_collection_id":KERNEL_ROOT_ID,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))).await;
    assert!(candidate(&f, KERNEL_ROOT_ID, &["area"]).await.is_err());
}

#[tokio::test]
async fn named_view_source_proof_resolver_detects_new_real_root_alias_bearer() {
    let f = Fixture::new().await;
    kernel::import_home_policy_as(&f.db, &f.host, KERNEL_ROOT_ID, &[(&f.actor, "manage")])
        .await
        .unwrap();
    declared(&f, "native:root").await;
    let p = candidate(&f, "native:root", &["area"]).await.unwrap();
    kernel::import_record_as(
        &f.db,
        &f.host,
        "native:root",
        KERNEL_ROOT_ID,
        Some(&f.actor),
        &kernel::ImportRecordState::default(),
    )
    .await
    .unwrap();
    assert!(f
        .recheck(&p.proof)
        .await
        .unwrap_err()
        .to_string()
        .contains("placement"));
}

#[tokio::test]
async fn named_view_source_proof_home_mapping_charges_metadata_before_body_or_parse() {
    let f = Fixture::new().await;
    let fake_home = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO kernel_roots(root_id,parent_id,owner_id,created_seq,created_at) VALUES(?,?,?,1,'2026-10-27T00:00:00Z')")
        .bind(&fake_home)
        .bind(KERNEL_ROOT_ID)
        .bind(&f.actor)
        .execute(f.db.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES(?,?,'kernel.home_created.v1',?,1,'legacy_unknown')").bind(uuid::Uuid::new_v4().to_string()).bind(&fake_home).bind(json!({"source_record_id":"H","padding":"x".repeat(PREPARE_BYTES)}).to_string()).execute(f.db.write_pool()).await.unwrap();
    let mut snapshot = prepare(&f.db, deadline()).await.unwrap();
    let (result, trace) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let result = snapshot.logical_home(&f.actor, &fake_home).await;
            (result, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert_eq!(result.unwrap_err().to_string(), super::super::MISSING);
    assert_eq!(
        trace, [0; 4],
        "oversized context body never transported or decoded"
    );
    let home = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    let mut snapshot = prepare(&f.db, deadline()).await.unwrap();
    let (result, trace) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let result = snapshot.logical_home(&f.actor, &home).await;
            (result, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert_eq!(result.unwrap().0, home);
    assert_eq!(
        trace,
        [0, 1, 1, 0],
        "the counters observe valid context decoding"
    );
}

#[tokio::test]
async fn named_view_source_proof_root_witness_is_counted_only_in_prepare_and_window_protected() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    for _ in 0..35 {
        f.event("opaque.unrelated.v1", "{}").await;
    }
    let (p, read) = ROOT_HEADERS
        .scope(std::cell::Cell::new(0), async {
            let p = candidate(&f, KERNEL_ROOT_ID, &["area"]).await.unwrap();
            (p, ROOT_HEADERS.with(std::cell::Cell::get))
        })
        .await;
    assert!(
        read >= 35,
        "prepare inspected every root header, not a filtered LIMIT"
    );
    let plan: Vec<(i64, i64, i64, String)> =
        sqlx::query_as(&format!("EXPLAIN QUERY PLAN {}", context_page_sql()))
            .bind(KERNEL_ROOT_ID)
            .bind(0i64)
            .bind(i64::MAX)
            .bind(PAGE)
            .fetch_all(f.db.pool())
            .await
            .unwrap();
    assert!(
        plan.iter()
            .any(|p| p.3.contains("idx_content_events_record") && p.3.contains("seq>")),
        "{plan:?}"
    );
    let (result, read) = ROOT_HEADERS
        .scope(std::cell::Cell::new(0), async {
            let result = f.recheck(&p.proof).await;
            (result, ROOT_HEADERS.with(std::cell::Cell::get))
        })
        .await;
    assert_eq!(result.unwrap().rows, 0);
    assert_eq!(read, 0, "writer never scans historic root aliases");
    kernel::import_home_policy_as(&f.db, &f.host, KERNEL_ROOT_ID, &[(&f.actor, "manage")])
        .await
        .unwrap();
    assert!(f
        .recheck(&p.proof)
        .await
        .unwrap_err()
        .to_string()
        .contains("root context import"));
    let mut s = prepare(&f.db, deadline()).await.unwrap();
    // The shared row cap includes context headers even with zero new bodies.
    s.work.rows = PREPARE_ROWS - 1;
    assert!(s
        .logical_home(&f.actor, KERNEL_ROOT_ID)
        .await
        .unwrap_err()
        .to_string()
        .contains("budget"));
}

#[tokio::test]
async fn named_view_source_proof_record_bearer_is_not_a_structural_root_alias() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    let result = super::super::facet_resolver::prepare(
        &f.db,
        &f.actor,
        "workspace",
        "native:root",
        generated_request(KERNEL_ROOT_ID, &["area"]),
        deadline(),
    )
    .await;
    assert_eq!(
        result.err().unwrap().to_string(),
        super::super::MISSING,
        "a root home is not a definition record"
    );
    kernel::import_record_as(
        &f.db,
        &f.host,
        "native:root",
        KERNEL_ROOT_ID,
        Some(&f.actor),
        &kernel::ImportRecordState::default(),
    )
    .await
    .unwrap();
    let s = prepare(&f.db, deadline()).await.unwrap();
    let p = s
        .seal(&f.actor, &[], &["native:root".into()])
        .await
        .unwrap();
    assert!(p.anchors[0].record);
    let mut writer = Writer::begin(&f.db, p.deadline).await.unwrap();
    // White-box loss of the physical record in an uncommitted transaction:
    // recheck must refuse, not reinterpret its old ID as the structural home.
    sqlx::query("PRAGMA defer_foreign_keys=ON")
        .execute(&mut *writer.tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM kernel_records WHERE id='native:root'")
        .execute(&mut *writer.tx)
        .await
        .unwrap();
    assert_eq!(
        p.recheck_on(&f.db, &mut writer, &f.actor)
            .await
            .unwrap_err()
            .to_string(),
        super::super::MISSING
    );
    writer.rollback().await.unwrap();
}

#[tokio::test]
async fn named_view_source_proof_resolver_loads_vocab_before_ref_then_refuses_ambiguity() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    for reference in ["rec:priority", "rec:not-installed"] {
        f.import(
            "schema_config",
            "vocab-precedence",
            Some(json!({
                "id":"vocab-precedence", "layer":"user", "name":null,
                "data":json!({"shapes":{"WorkItem:task":{"facets":{"priority":{
                    "vocab":"rec:priority", "vocab_ref":reference
                }}}}}).to_string(), "applies_to_collection_id":KERNEL_ROOT_ID,
                "version_lineage":null, "created_at":"2026-10-27T00:00:01Z"
            })),
        )
        .await;
        let result = candidate(&f, KERNEL_ROOT_ID, &["priority"]).await;
        if reference == "rec:priority" {
            let prepared = result.unwrap();
            assert!(prepared.required_catalog_sources.len() >= 2);
        } else {
            let error = result.err().unwrap().to_string();
            assert!(error.contains("conflicting vocabularies"), "{error}");
            assert!(!error.contains("required vocabulary unavailable"), "the installed vocab must load before the compiler refuses conflicting aliases: {error}");
        }
    }
}

async fn imported_checkpoint_task(
    f: &Fixture,
    home: &str,
    id: &str,
    token: Option<&str>,
    vocab: Option<&str>,
    archived: bool,
) {
    let mut facets: Vec<_> = token
        .map(|value| kernel::FacetObservation {
            key: "priority".into(),
            value: Some(value.into()),
            value_num: None,
            vocab_ref: vocab.map(str::to_owned),
            as_of: "2026-10-27T00:00:00Z".into(),
        })
        .into_iter()
        .chain(std::iter::once(kernel::FacetObservation {
            key: "area".into(),
            value: Some("Engine".into()),
            value_num: None,
            vocab_ref: None,
            as_of: "2026-10-27T00:00:00Z".into(),
        }))
        .collect();
    if id == "task:high" || id == "task:alias" {
        for (key, value, number) in if id == "task:high" {
            [("effort", "3.5", Some(3.5)), ("due", "2026-10-27", None)]
        } else {
            [("effort", "many", None), ("due", "not-a-date", None)]
        } {
            facets.push(kernel::FacetObservation {
                key: key.into(),
                value: Some(value.into()),
                value_num: number,
                vocab_ref: None,
                as_of: "2026-10-27T00:00:00Z".into(),
            });
        }
    }
    let definition = kernel::ImportDefinition {
        pin: crate::meta::definition_artifact::RevisionIdentity {
            family: crate::v2_standard::v1_compat::FAMILY.into(),
            version: 1,
            digest: crate::meta::definition_artifact::digest_artifact_bytes(
                crate::v2_standard::v1_compat::DEFINITION.as_bytes(),
            ),
        },
        primary_type: "V1".into(),
        kind: "record".into(),
        fields: json!({"v1_type":"WorkItem","v1_kind":"task","title":format!("Task {id}")})
            .as_object()
            .unwrap()
            .clone(),
    };
    kernel::import_record_as(
        &f.db,
        &f.host,
        id,
        home,
        Some(&f.actor),
        &kernel::ImportRecordState {
            definition: Some(definition),
            facets,
            archived,
            ..Default::default()
        },
    )
    .await
    .unwrap();
}
async fn checkpoint_world() -> (Fixture, String) {
    let f = Fixture::new().await;
    let package = crate::v2_standard::v1_compat::package();
    let installed = kernel::install_package_as(&f.db, &f.actor, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &f.db,
        &f.actor,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &[],
    )
    .await
    .unwrap();
    let home = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    declared(&f, &home).await;
    for (id, token, reference, archived) in [
        ("task:high", Some("high"), Some("rec:priority"), false),
        ("task:alias", Some("urgent"), Some("rec:priority"), false),
        ("task:old", Some("old"), Some("rec:priority"), true),
        ("task:proposed", Some("maybe"), Some("rec:priority"), false),
        (
            "task:unknown",
            Some("new-token"),
            Some("rec:priority"),
            false,
        ),
        ("task:conflict", Some("high"), Some("rec:other"), false),
        ("task:missing", None, None, false),
    ] {
        imported_checkpoint_task(&f, &home, id, token, reference, archived).await;
    }
    kernel::import_event_as(&f.db,&f.host,"task:high",&kernel::LegacyEvent {
        source:None,id:uuid::Uuid::new_v4().to_string(),event_type:"v1.snapshot_provenance".into(),
        payload:json!({"record_id":"task:high","facet_times":[{"key":"due","value":"2026-10-27","kind":"date","all_day":1,"start_date":"2026-10-27","end_date":null,"start_ms":null,"end_ms":null,"tz":null,"tzdb_version":null}]}),
        created_at:"2026-10-27T00:00:00Z".into(),actor:None,run_key:None,
    }).await.unwrap();
    kernel::add_generic_link_as(
        &f.db,
        &f.actor,
        "task:high",
        "task:alias",
        "supersedes",
        None,
    )
    .await
    .unwrap();
    (f, home)
}
fn checkpoint_outer(
    p: &super::super::facet_resolver::Prepared,
) -> super::super::contract::SavedSqlV12 {
    use sha2::{Digest, Sha256};
    let def: super::super::v2::Definition =
        serde_json::from_value(p.revision.definition.clone()).unwrap();
    let mut q = def.query;
    q.sql = format!("SELECT g.id,g.name,g.area,g.priority,r.name AS joined_name FROM {} g LEFT JOIN records r ON r.id=g.id ORDER BY g.id", p.name);
    q.relations.retain(|name, _| name == "records");
    q.relations.insert(
        p.name.clone(),
        super::super::contract::Dependency::View(super::super::Pin {
            view_id: p.revision.view_id.clone(),
            revision_id: uuid::Uuid::new_v4().to_string(),
            definition_sha256: p.revision.definition_sha256.clone(),
            schema_sha256: q.output.schema_sha256.clone(),
        }),
    ); // Fixture-only tuple: no event is recorded or loaded by this adapter.
    let columns = json!([
        {"name":"id","type":"identifier","nullable":false},
        {"name":"name","type":"text","nullable":false},
        {"name":"area","type":"text","nullable":true},
        {"name":"priority","type":"text","nullable":true},
        {"name":"joined_name","type":"text","nullable":true}
    ]);
    q.output = serde_json::from_value(json!({"columns":columns,
        "schema_sha256":format!("{:x}", Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(&columns))),
        "row_identity":["id"],"order":[{"column":"id","direction":"asc"}]})).unwrap();
    q
}
// Saved SQL 1.2 retains one identifier column. Length-prefix the task ID
// before the logical edge ID (empty only for the unmatched row), so the outer
// query has an injective composite identity without changing the view's ID.
fn checkpoint_parent_outer(
    p: &super::super::facet_resolver::Prepared,
) -> super::super::contract::SavedSqlV12 {
    use sha2::{Digest, Sha256};
    let mut q = checkpoint_outer(p);
    q.sql = format!("SELECT CAST(length(g.id) AS TEXT)||':'||g.id||coalesce(l.id,'') AS id,g.id AS task_id,g.name,g.area,g.priority,l.id AS link_id,r.id AS parent_id,r.name AS parent_name FROM {} g LEFT JOIN links l ON l.source_id=g.id AND l.relationship='part_of' LEFT JOIN records r ON r.id=l.target_id ORDER BY task_id,parent_id,id", p.name);
    let links = crate::query::sql_contract::LOGICAL_RELATIONS
        .iter()
        .find(|r| r.name == "links")
        .unwrap();
    q.relations.insert(
        "links".into(),
        super::super::contract::Dependency::Static(
            crate::mcp::tools::querying::SavedSqlRelationDependency {
                identity: links.identity.into(),
                semantic_version: links.semantic_version,
            },
        ),
    );
    let columns = json!([
        {"name":"id","type":"identifier","nullable":false},
        {"name":"task_id","type":"identifier","nullable":false},
        {"name":"name","type":"text","nullable":false},
        {"name":"area","type":"text","nullable":true},
        {"name":"priority","type":"text","nullable":true},
        {"name":"link_id","type":"identifier","nullable":true},
        {"name":"parent_id","type":"identifier","nullable":true},
        {"name":"parent_name","type":"text","nullable":true}
    ]);
    q.output = serde_json::from_value(json!({"columns":columns,
        "schema_sha256":format!("{:x}", Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(&columns))),
        "row_identity":["id"],"order":[{"column":"task_id","direction":"asc"},{"column":"parent_id","direction":"asc"},{"column":"id","direction":"asc"}]})).unwrap();
    q
}

async fn checkpoint_join(f: &Fixture, p: &super::super::facet_resolver::Prepared) -> Result<Value> {
    checkpoint_read(f, p, &checkpoint_outer(p)).await
}
async fn checkpoint_read(
    f: &Fixture,
    p: &super::super::facet_resolver::Prepared,
    outer: &super::super::contract::SavedSqlV12,
) -> Result<Value> {
    use sqlx::Connection;
    let limit = deadline();
    let roots = outer.roots();
    let pin = roots
        .get(&p.name)
        .ok_or_else(|| Error::engine("checkpoint root missing"))?;
    if roots.len() != 1
        || pin.view_id != p.revision.view_id
        || pin.definition_sha256 != p.revision.definition_sha256
        || p.revision.definition["query"]["output"]["schema_sha256"] != pin.schema_sha256
    {
        return Err(Error::engine("checkpoint tuple mismatch"));
    }
    let mut conn = f.db.governed_pool().acquire().await?;
    let mut tx = conn.begin().await?;
    let result = async {
        p.inspect_on(&f.db, &mut tx, &f.actor, limit).await?;
        let validated = p.validate(limit).await?;
        assert!(validated
            .reads
            .contains(&("facet_values".into(), "value".into())));
        crate::mcp::kernel_v2::sql::generated_checkpoint_on(
            &mut tx,
            &f.actor,
            &p.name,
            &validated.definition.common(),
            outer,
            limit,
        )
        .await
    }
    .await;
    tx.rollback().await?;
    conn.lock_handle().await?.remove_progress_handler();
    result
}
#[tokio::test]
async fn named_view_source_proof_generated_candidate_uses_real_staging_saved12_and_both_named_gates(
) {
    let (f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let same = candidate(&f, &home, &["priority", "area"]).await.unwrap();
    assert_eq!(p.name, same.name);
    assert_eq!(
        serde_json::to_value(&p.revision).unwrap(),
        serde_json::to_value(&same.revision).unwrap()
    );
    let validated = p.validate(deadline()).await.unwrap();
    let actual =
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &validated.definition.query)
            .await
            .unwrap();
    let rows = actual["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 7);
    for row in rows {
        let id = row["id"].as_str().unwrap();
        assert_eq!(row["area"], "Engine");
        let (value, status) = match id {
            "task:high" | "task:alias" => (json!("high"), "valid"),
            "task:old" => (json!("old"), "valid"),
            "task:proposed" | "task:unknown" => (Value::Null, "unclassified"),
            "task:conflict" => (Value::Null, "invalid"),
            "task:missing" => (Value::Null, "missing"),
            _ => panic!("unexpected {id}"),
        };
        assert_eq!(row["priority"], value, "{row}");
        assert_eq!(row["priority__status"], status, "{row}");
        assert_eq!(row["archived"], json!(if id == "task:old" { 1 } else { 0 }));
        assert_eq!(
            row["is_current"],
            if id == "task:alias" {
                Value::Null
            } else {
                json!(1)
            }
        );
    }
    // The raw SQLite result uses signed 0/1; the existing saved-output boundary
    // normalizes only those exact values and validates all generated types.
    let typed = crate::mcp::tools::querying::finish_saved_sql(
        &validated.definition.query.static_shape(),
        &[],
        "fixture:checkpoint",
        crate::query::sql::GovernedSqlObservation {
            observed_at: "2026-10-27T00:00:00Z".into(),
            content_event_seq: actual["as_of_seq"].as_i64(),
            lifecycle_event_seq: None,
            authorization_boundary: "fixture-only-not-a-serving-receipt".into(),
            transient_watermark: None,
            transient_available: true,
        },
        crate::query::sql_contract::QuerySqlResult {
            columns: actual["columns"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap().to_owned())
                .collect(),
            rows: actual["rows"].as_array().unwrap().clone(),
            row_count: actual["row_count"].as_u64().unwrap() as usize,
            truncated: actual["truncated"].as_bool().unwrap(),
            truncation_hint: None,
            as_of_seq: actual["as_of_seq"].as_i64().unwrap(),
            now_ms_ms: None,
            time_dependent: false,
            assumed_order: None,
        },
    )
    .unwrap();
    assert!(typed["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["archived"].is_boolean()));
    let joined = checkpoint_join(&f, &p).await.unwrap();
    let generic = crate::mcp::kernel_v2::sql::query_sql(&f.db,&f.actor,json!({"sql":format!("SELECT r.id,r.name,a.value AS area,CASE WHEN p.vocab_ref='rec:other' THEN NULL WHEN p.value='urgent' THEN 'high' WHEN p.value IN ('high','old') THEN p.value ELSE NULL END AS priority,r.name AS joined_name FROM records r LEFT JOIN facet_values a ON a.record_id=r.id AND a.key='area' LEFT JOIN facet_values p ON p.record_id=r.id AND p.key='priority' WHERE r.type='WorkItem' AND r.kind='task' AND r.home_id='{}' ORDER BY r.id",home)})).await.unwrap();
    assert_eq!(joined["rows"], generic["rows"]);
    // The real named gates reject an invalid output/body; no generated exemption.
    let mut invalid = p;
    invalid.revision.definition["query"]["sql"] = json!("SELECT nope FROM records ORDER BY nope");
    invalid.revision.definition_sha256 = invalid.revision.digest();
    assert!(invalid.validate(deadline()).await.is_err());
}

#[tokio::test]
async fn named_view_source_proof_generated_parent_join_expands_and_orders_logical_edges() {
    let (f, home) = checkpoint_world().await;
    let parents = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    imported_checkpoint_task(&f, &parents, "parent:a", None, None, false).await;
    imported_checkpoint_task(&f, &parents, "parent:b", None, None, true).await;
    let mut edges = vec![];
    for (task, parent) in [
        ("task:high", "parent:b"),
        ("task:high", "parent:a"),
        ("task:alias", "parent:a"),
    ] {
        edges.push(
            kernel::add_generic_link_as(&f.db, &f.actor, task, parent, "part_of", None)
                .await
                .unwrap()
                .link,
        );
    }
    // Logical links expose active edges, not removed history. Other predicates
    // and the inverse direction must not become task-parent relationships.
    let removed =
        kernel::add_generic_link_as(&f.db, &f.actor, "task:old", "parent:b", "part_of", None)
            .await
            .unwrap();
    kernel::remove_generic_link_as(&f.db, &f.actor, "task:old", &removed.link.link_id)
        .await
        .unwrap();
    kernel::add_generic_link_as(&f.db, &f.actor, "task:old", "parent:a", "blocks", None)
        .await
        .unwrap();
    kernel::add_generic_link_as(&f.db, &f.actor, "parent:a", "task:missing", "part_of", None)
        .await
        .unwrap();
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let outer = checkpoint_parent_outer(&p);
    outer.validate_current().unwrap();
    let body = p.revision.definition["query"]["sql"].as_str().unwrap();
    let validators =
        crate::query::sql::NamedViewValidators::new(&[(p.name.clone(), body.into())]).unwrap();
    let (reads, labels) = validators.inspect_saved(&outer.sql).unwrap();
    assert_eq!(
        validators.inspect(&outer.sql).unwrap(),
        (reads.clone(), labels.clone())
    );
    assert_eq!(
        labels,
        outer
            .output
            .columns
            .iter()
            .map(|c| c.name.clone())
            .collect::<Vec<_>>()
    );
    for column in ["id", "source_id", "target_id", "relationship"] {
        assert!(
            reads.contains(&("links".into(), column.into())),
            "{reads:?}"
        );
    }
    let joined = checkpoint_read(&f, &p, &outer).await.unwrap();
    // Independently authored generic SQL over the same public logical sources,
    // with the same caller and active-edge semantics; no physical-table oracle.
    let generic = crate::mcp::kernel_v2::sql::query_sql(&f.db,&f.actor,json!({"sql":format!("WITH tasks AS (SELECT t.id,t.name,a.value AS area,CASE WHEN p.vocab_ref='rec:other' THEN NULL WHEN p.value='urgent' THEN 'high' WHEN p.value IN ('high','old') THEN p.value ELSE NULL END AS priority FROM records t LEFT JOIN facet_values a ON a.record_id=t.id AND a.key='area' LEFT JOIN facet_values p ON p.record_id=t.id AND p.key='priority' WHERE t.type='WorkItem' AND t.kind='task' AND t.home_id='{}') {}", home, outer.sql.replace(&p.name,"tasks"))})).await.unwrap();
    assert_eq!(joined["rows"], generic["rows"]);
    let rows = joined["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 8);
    let keys: Vec<_> = rows
        .iter()
        .map(|r| (r["task_id"].as_str().unwrap(), r["parent_id"].as_str()))
        .collect();
    assert_eq!(
        keys,
        vec![
            ("task:alias", Some("parent:a")),
            ("task:conflict", None),
            ("task:high", Some("parent:a")),
            ("task:high", Some("parent:b")),
            ("task:missing", None),
            ("task:old", None),
            ("task:proposed", None),
            ("task:unknown", None),
        ]
    );
    let unique: std::collections::BTreeSet<_> =
        rows.iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(unique.len(), rows.len());
    for row in rows {
        assert_eq!(
            row["id"],
            format!(
                "{}:{}{}",
                row["task_id"].as_str().unwrap().chars().count(),
                row["task_id"].as_str().unwrap(),
                row["link_id"].as_str().unwrap_or("")
            )
        );
        if row["parent_id"].is_null() {
            assert!(row["link_id"].is_null() && row["parent_name"].is_null());
        } else {
            assert!(edges.iter().any(|e| row["link_id"] == e.link_id));
        }
    }
    // Archived parent:b remains a visible logical record; this outer query
    // intentionally applies no additional archived/currentness filter.
    assert!(rows.iter().any(|r| r["parent_name"] == "Task parent:b"));
    assert_eq!(
        p.revision.definition["query"]["output"]["row_identity"],
        json!(["id"])
    );
}

#[tokio::test]
async fn named_view_source_proof_generated_parent_join_hides_parents_and_edges() {
    let (mut f, home) = checkpoint_world().await;
    let parents = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    imported_checkpoint_task(&f, &parents, "parent:visible", None, None, false).await;
    let other = kernel::create_principal(
        &f.db,
        "account",
        "Private",
        "acct:private-parents",
        &f.actor,
    )
    .await
    .unwrap();
    let private = kernel::create_home(&f.db, KERNEL_ROOT_ID, Some(&[(&other, "manage")]), &f.actor)
        .await
        .unwrap();
    imported_checkpoint_task(&f, &private, "parent:hidden", None, None, false).await;
    imported_checkpoint_task(&f, &private, "task:hidden", None, None, false).await;
    kernel::add_generic_link_as(
        &f.db,
        &f.actor,
        "task:high",
        "parent:visible",
        "part_of",
        None,
    )
    .await
    .unwrap();
    let admin = checkpoint_viewer(&mut f, &home).await;
    kernel::replace_home_policy(
        &f.db,
        &admin,
        &parents,
        &[(&admin, "manage"), (&f.actor, "view")],
    )
    .await
    .unwrap();
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let outer = checkpoint_parent_outer(&p);
    let before = checkpoint_read(&f, &p, &outer).await.unwrap();
    use sha2::{Digest, Sha256};
    let mut count = outer.clone();
    count.sql = format!("SELECT 'parent-rows' AS id,COUNT(*) AS n FROM {} g LEFT JOIN links l ON l.source_id=g.id AND l.relationship='part_of' LEFT JOIN records r ON r.id=l.target_id ORDER BY id",p.name);
    let columns = json!([{"name":"id","type":"identifier","nullable":false},{"name":"n","type":"integer","nullable":false}]);
    count.output = serde_json::from_value(json!({"columns":columns,"schema_sha256":format!("{:x}",Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(&columns))),"row_identity":["id"],"order":[{"column":"id","direction":"asc"}]})).unwrap();
    let before_count = checkpoint_read(&f, &p, &count).await.unwrap();
    let links_sql = json!({"sql":"SELECT id,source_id,target_id FROM links WHERE relationship='part_of' ORDER BY id"});
    let visible_links = crate::mcp::kernel_v2::sql::query_sql(&f.db, &f.actor, links_sql.clone())
        .await
        .unwrap();
    for (source, target) in [
        ("task:high", "parent:hidden"),
        ("task:missing", "parent:hidden"),
        ("task:hidden", "parent:visible"),
    ] {
        kernel::add_generic_link_as(&f.db, &admin, source, target, "part_of", None)
            .await
            .unwrap();
    }
    let owner_links = crate::mcp::kernel_v2::sql::query_sql(&f.db, &admin, links_sql.clone())
        .await
        .unwrap();
    assert!(owner_links["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["target_id"] == "parent:hidden"));
    assert!(owner_links["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["source_id"] == "task:hidden"));
    assert!(
        !kernel::kernel_effective_capability(&f.db, &f.actor, &private)
            .await
            .unwrap()
            .allows(crate::authorization::Capability::View)
    );
    // No per-link ACL is invented: logical links require both endpoints' View.
    // A hidden-parent edge cannot multiply a visible task, even COUNT(*).
    let after = checkpoint_read(&f, &p, &outer).await.unwrap();
    assert_eq!(before["rows"], after["rows"]);
    assert_eq!(before["row_count"], after["row_count"]);
    assert_eq!(before_count["rows"], json!([{"id":"parent-rows","n":7}]));
    assert_eq!(
        before_count["rows"],
        checkpoint_read(&f, &p, &count).await.unwrap()["rows"]
    );
    assert_eq!(
        visible_links["rows"],
        crate::mcp::kernel_v2::sql::query_sql(&f.db, &f.actor, links_sql)
            .await
            .unwrap()["rows"]
    );
    assert_eq!(
        after["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["task_id"] == "task:missing")
            .count(),
        1
    );
    // An absent and an existing-but-hidden parent ID produce identical successful
    // null-extension results, through the same validators and staging adapter.
    let hidden_query = super::super::contract::SavedSqlV12 {
        sql: outer.sql.replace(
            "r.id=l.target_id",
            "r.id=l.target_id AND r.id='parent:hidden'",
        ),
        ..outer.clone()
    };
    let absent_query = super::super::contract::SavedSqlV12 {
        sql: hidden_query.sql.replace("parent:hidden", "parent:absent"),
        ..hidden_query.clone()
    };
    assert_eq!(
        checkpoint_read(&f, &p, &hidden_query).await.unwrap()["rows"],
        checkpoint_read(&f, &p, &absent_query).await.unwrap()["rows"]
    );
}

#[tokio::test]
async fn named_view_source_proof_generated_frozen_mapping_and_required_absence() {
    let (f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let a1 = p.validate(deadline()).await.unwrap();
    f.import("vocabulary_values","high",Some(json!({"id":"high","vocabulary_id":"priority","value":"highest","status":"active","alias_of":null}))).await;
    let mut conn = f.db.pool().acquire().await.unwrap();
    assert!(p
        .inspect_on(&f.db, &mut conn, &f.actor, deadline())
        .await
        .unwrap());
    let a2 = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    assert_eq!(p.name, a2.name);
    assert_ne!(p.revision.definition_sha256, a2.revision.definition_sha256);
    let new = a2.validate(deadline()).await.unwrap();
    for (query, expected) in [
        (&a1.definition.query, "high"),
        (&new.definition.query, "highest"),
    ] {
        let result = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, query)
            .await
            .unwrap();
        assert_eq!(
            result["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == "task:alias")
                .unwrap()["priority"],
            expected
        );
    }
    // Value and governance deletions are advisory for retained A1, but removing
    // governance prevents a new proposal. No implicit publication is possible.
    f.import("vocabulary_values", "maybe", None).await;
    f.import("schema_config", "local", None).await;
    assert!(p
        .inspect_on(&f.db, &mut conn, &f.actor, deadline())
        .await
        .unwrap());
    assert!(candidate(&f, &home, &["priority"]).await.is_err());
    assert_eq!(
        checkpoint_join(&f, &p).await.unwrap()["rows"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    f.import("vocabularies", "priority", None).await;
    assert_eq!(
        p.inspect_on(&f.db, &mut conn, &f.actor, deadline())
            .await
            .unwrap_err()
            .to_string(),
        super::super::MISSING
    );
    // A source restored with a new event is drift, not a permanent tombstone.
    f.import(
        "vocabularies",
        "priority",
        Some(json!({"id":"priority","name":"Restored"})),
    )
    .await;
    assert!(p
        .inspect_on(&f.db, &mut conn, &f.actor, deadline())
        .await
        .unwrap());
    f.import("schema_config", "global", None).await;
    assert_eq!(
        p.inspect_on(&f.db, &mut conn, &f.actor, deadline())
            .await
            .unwrap_err()
            .to_string(),
        super::super::MISSING
    );
}

// Read through a shared non-owner identity: creating a private home as the
// fixture administrator still leaves that administrator with owner authority.
async fn checkpoint_viewer(f: &mut Fixture, home: &str) -> String {
    let admin = f.actor.clone();
    let reader =
        kernel::create_principal(&f.db, "account", "Reader", "acct:checkpoint-reader", &admin)
            .await
            .unwrap();
    let anchor_home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&f.anchor)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    for h in [anchor_home.as_str(), home] {
        kernel::replace_home_policy(&f.db, &admin, h, &[(&admin, "manage"), (&reader, "view")])
            .await
            .unwrap();
    }
    f.actor = reader;
    admin
}

#[tokio::test]
async fn named_view_source_proof_generated_live_visibility_precedes_source_diagnostics() {
    let (mut f, home) = checkpoint_world().await;
    let admin = checkpoint_viewer(&mut f, &home).await;
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let viewer =
        kernel::create_principal(&f.db, "account", "Other", "acct:checkpoint-other", &admin)
            .await
            .unwrap();
    let mut conn = f.db.pool().acquire().await.unwrap();
    assert_eq!(
        p.inspect_on(&f.db, &mut conn, &viewer, deadline())
            .await
            .unwrap_err()
            .to_string(),
        super::super::MISSING
    );
    let bearer = kernel::read_record_as(&f.db, &admin, &f.anchor)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&f.db, &admin, &f.anchor, true, bearer.revision)
        .await
        .unwrap();
    let archived = p
        .inspect_on(&f.db, &mut conn, &f.actor, deadline())
        .await
        .unwrap_err()
        .to_string();
    let bearer = kernel::read_record_as(&f.db, &admin, &f.anchor)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&f.db, &admin, &f.anchor, false, bearer.revision)
        .await
        .unwrap();
    kernel::replace_home_policy(&f.db, &admin, &home, &[(&viewer, "manage")])
        .await
        .unwrap();
    assert!(!kernel::kernel_effective_capability(&f.db, &f.actor, &home)
        .await
        .unwrap()
        .allows(crate::authorization::Capability::View));
    f.import("vocabularies", "priority", None).await;
    let hidden = p
        .inspect_on(&f.db, &mut conn, &f.actor, deadline())
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(hidden, archived);
    assert_eq!(hidden, super::super::MISSING);
    assert_eq!(
        checkpoint_join(&f, &p).await.unwrap_err().to_string(),
        super::super::MISSING
    );
}

#[tokio::test]
async fn named_view_source_proof_generated_staging_keeps_hidden_join_and_count_indistinguishable() {
    let (mut f, home) = checkpoint_world().await;
    let other = kernel::create_principal(
        &f.db,
        "account",
        "Private",
        "acct:checkpoint-private",
        &f.actor,
    )
    .await
    .unwrap();
    let hidden = kernel::create_home(&f.db, KERNEL_ROOT_ID, Some(&[(&other, "manage")]), &f.actor)
        .await
        .unwrap();
    imported_checkpoint_task(&f, &hidden, "task:hidden", Some("high"), None, false).await;
    checkpoint_viewer(&mut f, &home).await;
    assert!(
        !kernel::kernel_effective_capability(&f.db, &f.actor, &hidden)
            .await
            .unwrap()
            .allows(crate::authorization::Capability::View)
    );
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let mut outer = checkpoint_outer(&p);
    outer.sql = outer.sql.replace("r.id=g.id", "r.id='task:hidden'");
    let hidden_result = checkpoint_read(&f, &p, &outer).await.unwrap();
    assert!(hidden_result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["joined_name"].is_null()));
    outer.sql = outer.sql.replace("task:hidden", "task:nonexistent");
    assert_eq!(
        hidden_result["rows"],
        checkpoint_read(&f, &p, &outer).await.unwrap()["rows"]
    );
    // COUNT prunes all projected companion columns. Registry body expansion
    // must nevertheless stage the definition's whole read set.
    use sha2::{Digest, Sha256};
    let columns = json!([{"name":"id","type":"identifier","nullable":false},{"name":"n","type":"integer","nullable":false}]);
    outer.sql = format!(
        "SELECT 'visible-total' AS id, COUNT(*) AS n FROM {} WHERE area='Engine' ORDER BY id",
        p.name
    );
    outer.relations.retain(|name, _| name == &p.name);
    outer.output=serde_json::from_value(json!({"columns":columns,"schema_sha256":format!("{:x}",Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(&columns))),"row_identity":["id"],"order":[{"column":"id","direction":"asc"}]})).unwrap();
    assert_eq!(
        checkpoint_read(&f, &p, &outer).await.unwrap()["rows"],
        json!([{"id":"visible-total","n":7}])
    );
}

#[tokio::test]
async fn named_view_source_proof_generated_number_and_date_use_real_imported_projections() {
    let (f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["effort", "due"]).await.unwrap();
    let validated = p.validate(deadline()).await.unwrap();
    assert!(validated.reads.iter().any(|(r, _)| r == "facet_times"));
    let result =
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &validated.definition.query)
            .await
            .unwrap();
    let rows = result["rows"].as_array().unwrap();
    let high = rows.iter().find(|r| r["id"] == "task:high").unwrap();
    assert_eq!(high["effort"], 3.5);
    assert_eq!(high["due"], "2026-10-27");
    assert_eq!(high["due__status"], "valid");
    let ambiguous = rows.iter().find(|r| r["id"] == "task:alias").unwrap();
    for key in ["effort", "due"] {
        assert!(ambiguous[key].is_null());
        assert_eq!(ambiguous[format!("{key}__status")], "unclassified");
        assert!(!ambiguous[format!("{key}__raw")].is_null());
    }
    let sparse = rows.iter().find(|r| r["id"] == "task:missing").unwrap();
    assert_eq!(sparse["due__status"], "missing");
    assert!(sparse["due__raw"].is_null());
}

// Retained fixtures use canonical projector folds, not an emitter or publication
// API. This is intentionally not public v2 serving or activation qualification.
async fn retain_candidate(
    f: &Fixture,
    p: &super::super::facet_resolver::Prepared,
) -> super::super::Pin {
    p.validate(deadline()).await.unwrap();
    retain_revision(f, &p.revision).await
}
// Canonical replay deliberately permits an old profile; the read must still
// apply current profile checks before any advisory-comparison fallback.
async fn retain_revision(f: &Fixture, revision: &super::super::Revision) -> super::super::Pin {
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let act = crate::act::ActAllocation::new()
        .get_or_allocate(&mut tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,'2026-10-27T00:00:00Z',1,'legacy_unknown',?)")
        .bind(&id).bind(&f.anchor).bind(super::super::REVISION).bind(serde_json::to_string(revision).unwrap()).bind(act).execute(&mut *tx).await.unwrap();
    let e = super::super::read_event(&mut tx, &id, i64::MAX)
        .await
        .unwrap();
    crate::projector::project(&mut tx, &e).await.unwrap();
    tx.commit().await.unwrap();
    super::super::Pin {
        view_id: revision.view_id.clone(),
        revision_id: id,
        definition_sha256: revision.definition_sha256.clone(),
        schema_sha256: revision.definition["query"]["output"]["schema_sha256"]
            .as_str()
            .unwrap()
            .into(),
    }
}
fn retained_query(
    p: &super::super::facet_resolver::Prepared,
    pin: &super::super::Pin,
) -> super::super::contract::SavedSqlV12 {
    let d: super::super::v2::Definition =
        serde_json::from_value(p.revision.definition.clone()).unwrap();
    let mut q = d.query;
    q.sql = format!("SELECT * FROM {} ORDER BY id", p.name);
    q.relations = std::collections::BTreeMap::from([(
        p.name.clone(),
        super::super::contract::Dependency::View(pin.clone()),
    )]);
    q
}
use super::super::retained_facets::Drift;
fn known_drift(drift: Drift) -> bool {
    match drift {
        Drift::Unchanged => false,
        Drift::Changed => true,
        Drift::Unknown => panic!("fixture expects a complete current-catalog comparison"),
    }
}
async fn retained_read(
    f: &Fixture,
    pin: &super::super::Pin,
    q: &super::super::contract::SavedSqlV12,
) -> Result<(Value, bool, Work)> {
    retained_read_with_drift(f, pin, q)
        .await
        .map(|(rows, drift, work)| (rows, known_drift(drift), work))
}
async fn retained_read_with_drift(
    f: &Fixture,
    pin: &super::super::Pin,
    q: &super::super::contract::SavedSqlV12,
) -> Result<(Value, Drift, Work)> {
    use sqlx::Connection;
    let mut conn = f.db.governed_pool().acquire().await?;
    let mut tx = conn.begin().await?;
    let limit = deadline();
    tx.lock_handle()
        .await?
        .set_progress_handler(100, move || Instant::now() < limit);
    let result = async {
        let checked = super::super::retained_facets::inspect_on(
            &mut tx,
            &f.actor,
            "trusted-workspace",
            pin,
            limit,
        )
        .await?;
        let name = q.roots().keys().next().unwrap().clone();
        let rows = crate::mcp::kernel_v2::sql::generated_checkpoint_on(
            &mut tx,
            &f.actor,
            &name,
            &checked.definition.common(),
            q,
            limit,
        )
        .await?;
        Ok((rows, checked.drift, checked.work))
    }
    .await;
    tx.rollback().await?;
    conn.lock_handle().await?.remove_progress_handler();
    result
}
async fn inspect_retained(f: &Fixture, pin: &super::super::Pin) -> Result<bool> {
    inspect_retained_drift(f, pin).await.map(known_drift)
}
async fn inspect_retained_drift(f: &Fixture, pin: &super::super::Pin) -> Result<Drift> {
    let mut tx = f.db.governed_pool().begin().await?;
    let r = super::super::retained_facets::inspect_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        pin,
        deadline(),
    )
    .await
    .map(|c| c.drift);
    tx.rollback().await?;
    r
}

#[tokio::test]
async fn named_view_source_proof_retained_restart_snapshot_frozen_a1_and_explicit_a2() {
    use sqlx::Connection;
    let (mut f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    let frozen = p.revision.definition.clone();
    let name = p.name.clone();
    drop(p); // No Prepared, old actor grant or owned source Proof is retained.
    let reopened =
        kernel::open_marked_v2_database(f._dir.path().join("proof.db").to_str().unwrap())
            .await
            .unwrap();
    assert!(!reopened.same_handle(&f.db));
    f.db = reopened;
    let mut conn = f.db.governed_pool().acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let limit = deadline();
    let (checked, calls) = crate::query::generated_facets::measured_compiles(
        super::super::retained_facets::inspect_on(
            &mut tx,
            &f.actor,
            "trusted-workspace",
            &pin,
            limit,
        ),
    )
    .await;
    let checked = checked.unwrap();
    assert_eq!(calls, 0);
    assert!(checked.drift == Drift::Unchanged);
    f.import("vocabulary_values","new-value",Some(json!({"id":"new-value","vocabulary_id":"priority","value":"brand-new","status":"active","alias_of":null}))).await;
    kernel::observe_facet_as(
        &f.db,
        &f.actor,
        "task:high",
        &kernel::FacetObservation {
            key: "priority".into(),
            value: Some("brand-new".into()),
            value_num: None,
            vocab_ref: Some("rec:priority".into()),
            as_of: "2026-10-27T00:01:00Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    let old = crate::mcp::kernel_v2::sql::generated_checkpoint_on(
        &mut tx,
        &f.actor,
        &name,
        &checked.definition.common(),
        &q,
        limit,
    )
    .await
    .unwrap();
    assert_eq!(
        old["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "task:high")
            .unwrap()["priority"],
        "high"
    );
    let logical_events: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE name='content_events')",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(logical_events);
    let after_staging = super::super::retained_facets::inspect_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        &pin,
        limit,
    )
    .await
    .unwrap();
    assert!(
        after_staging.drift == Drift::Unchanged,
        "the same snapshot is still authoritative after logical TEMP staging"
    );
    tx.rollback().await.unwrap();
    conn.lock_handle().await.unwrap().remove_progress_handler();
    drop(conn);
    let (result, calls) =
        crate::query::generated_facets::measured_compiles(retained_read(&f, &pin, &q)).await;
    let (a1, drift, _) = result.unwrap();
    assert_eq!(calls, 0, "a read must never regenerate executable SQL");
    assert!(drift);
    let row = a1["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "task:high")
        .unwrap();
    assert!(row["priority"].is_null());
    assert_eq!(row["priority__status"], "unclassified");
    let a2 = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    assert_eq!(a2.name, name);
    assert_ne!(a2.revision.definition_sha256, pin.definition_sha256);
    let next = retain_candidate(&f, &a2).await;
    let (rows, drift, _) = retained_read(&f, &next, &retained_query(&a2, &next))
        .await
        .unwrap();
    assert!(!drift);
    assert_eq!(
        rows["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "task:high")
            .unwrap()["priority"],
        "brand-new"
    );
    let mut conn = f.db.pool().acquire().await.unwrap();
    let event = super::super::read_event(&mut conn, &pin.revision_id, i64::MAX)
        .await
        .unwrap();
    let stored: super::super::Revision =
        serde_json::from_str(event.payload.as_deref().unwrap()).unwrap();
    assert_eq!(
        stored.definition, frozen,
        "stored SQL, vocabulary mapping and columns stay frozen"
    );
}

#[tokio::test]
async fn named_view_source_proof_retained_selected_absence_all_keys_and_new_alias() {
    let (f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["area"]).await.unwrap();
    let pin = retain_candidate(&f, &p).await;
    let all = super::super::facet_resolver::prepare(
        &f.db,
        &f.actor,
        "trusted-workspace",
        &f.anchor,
        super::super::facet_resolver::Request {
            selection: crate::query::generated_facets::Selection::All,
            ..generated_request(&home, &[])
        },
        deadline(),
    )
    .await
    .unwrap();
    let all_pin = retain_candidate(&f, &all).await;
    assert!(!inspect_retained(&f, &pin).await.unwrap());
    assert!(!inspect_retained(&f, &all_pin).await.unwrap());
    f.import("schema_config","extra",Some(json!({"id":"extra","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"extra":{}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))).await;
    assert!(
        !inspect_retained(&f, &pin).await.unwrap(),
        "new unrelated key does not affect a keys selector"
    );
    assert!(
        inspect_retained(&f, &all_pin).await.unwrap(),
        "all observes the complete effective key set"
    );
    f.import("schema_config","extra",Some(json!({"id":"extra","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"extra":{},"area":{"type":"number"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))).await;
    assert!(
        inspect_retained(&f, &pin).await.unwrap(),
        "new override fills a previously absent selected fragment; old refs did not change"
    );
    let (a1, _, _) = retained_read(&f, &pin, &retained_query(&p, &pin))
        .await
        .unwrap();
    assert!(a1["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["area"] == "Engine"));
    // Deletion baseline does not make a later independent alias invisible.
    f.import("vocabulary_values", "maybe", None).await;
    let priority = candidate(&f, &home, &["priority"]).await.unwrap();
    let priority_pin = retain_candidate(&f, &priority).await;
    assert!(!inspect_retained(&f, &priority_pin).await.unwrap());
    f.import("vocabulary_values","isolated-alias",Some(json!({"id":"isolated-alias","vocabulary_id":"priority","value":"hot","status":"active","alias_of":"high"}))).await;
    assert!(
        inspect_retained(&f, &priority_pin).await.unwrap(),
        "complete set read catches new alias with every retained ref unchanged"
    );
}

#[tokio::test]
async fn named_view_source_proof_retained_required_sources_and_advisory_deletions() {
    let (f, home) = checkpoint_world().await;
    f.import("schema_config","older",Some(json!({"id":"older","layer":"pack","name":null,"data":json!({"shapes":{"WorkItem":{"facets":{"area":{"description":"superseded"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":null,"created_at":"2026-10-26T00:00:00Z"}))).await;
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    for (section, id) in [
        ("vocabulary_values", "alias"),
        ("schema_config", "older"),
        ("schema_config", "local"),
    ] {
        f.import(section, id, None).await;
        let (rows, drift, _) = retained_read(&f, &pin, &q).await.unwrap();
        assert!(drift);
        assert_eq!(
            rows["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == "task:alias")
                .unwrap()["priority"],
            "high"
        );
    }
    assert!(
        candidate(&f, &home, &["area", "priority"]).await.is_err(),
        "governance removal prevents a fresh proposal, not frozen serving"
    );
    f.import("schema_config", "global", None).await;
    assert_eq!(
        inspect_retained(&f, &pin).await.unwrap_err().to_string(),
        Error::engine(super::super::MISSING).to_string()
    );
    declared(&f, &home).await; // Present new refs behave like edits, not tombstone redaction.
    assert!(inspect_retained(&f, &pin).await.unwrap());
    f.import("vocabularies", "priority", None).await;
    assert_eq!(
        inspect_retained(&f, &pin).await.unwrap_err().to_string(),
        Error::engine(super::super::MISSING).to_string()
    );
    f.import(
        "vocabularies",
        "priority",
        Some(json!({"id":"priority","name":"Renamed"})),
    )
    .await;
    assert!(inspect_retained(&f, &pin).await.unwrap());
}

#[tokio::test]
async fn named_view_source_proof_retained_current_view_home_and_missing_before_budget() {
    let (mut f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    let admin = checkpoint_viewer(&mut f, &home).await;
    kernel::replace_home_policy(
        &f.db,
        &admin,
        &home,
        &[(&admin, "manage"), (&f.actor, "manage")],
    )
    .await
    .unwrap();
    assert!(!inspect_retained(&f, &pin).await.unwrap());
    kernel::replace_home_policy(
        &f.db,
        &admin,
        &home,
        &[(&admin, "manage"), (&f.actor, "view")],
    )
    .await
    .unwrap();
    assert!(!kernel::kernel_effective_capability(&f.db, &f.actor, &home)
        .await
        .unwrap()
        .allows(crate::authorization::Capability::Manage));
    assert!(
        !inspect_retained(&f, &pin).await.unwrap(),
        "a View-only caller needs no old actor or owner proof"
    );
    let (rows, _, _) = retained_read(&f, &pin, &q).await.unwrap();
    assert_eq!(rows["row_count"], 7);
    kernel::replace_home_policy(&f.db, &admin, &home, &[(&admin, "manage")])
        .await
        .unwrap();
    let hidden = inspect_retained(&f, &pin).await.unwrap_err().to_string();
    let mut missing = pin.clone();
    missing.view_id = "native.named-view:absent".into();
    assert_eq!(
        hidden,
        inspect_retained(&f, &missing)
            .await
            .unwrap_err()
            .to_string()
    );
    sqlx::query("INSERT INTO kernel_v1_state VALUES('schema_config','[\"large\"]','fixture',?,NULL,NULL,'2026-10-27T00:00:00Z',1)").bind(serde_json::to_string(&"x".repeat(PREPARE_BYTES+1)).unwrap()).execute(f.db.write_pool()).await.unwrap();
    assert_eq!(
        hidden,
        inspect_retained(&f, &pin).await.unwrap_err().to_string(),
        "hidden anchor refuses before oversized unrelated source metadata"
    );
    kernel::replace_home_policy(
        &f.db,
        &admin,
        &home,
        &[(&admin, "manage"), (&f.actor, "view")],
    )
    .await
    .unwrap();
    let (drift, trace) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let drift = inspect_retained_drift(&f, &pin).await.unwrap();
            (drift, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert_eq!(drift, Drift::Unknown);
    assert_eq!(
        trace[0], 0,
        "oversized state is charged before payload fetch or parsing"
    );
    f.import("schema_config", "global", None).await;
    assert_eq!(
        hidden,
        inspect_retained(&f, &pin).await.unwrap_err().to_string(),
        "required catalog absence also wins before the full scan budget"
    );
    declared(&f, &home).await;

    sqlx::query("DELETE FROM kernel_v1_state WHERE source_id='[\"large\"]'")
        .execute(f.db.write_pool())
        .await
        .unwrap();
    let private = kernel::create_home(&f.db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    kernel::rehome_record_as(&f.db, &admin, &f.anchor, &private)
        .await
        .unwrap();
    assert_eq!(
        hidden,
        inspect_retained(&f, &pin).await.unwrap_err().to_string(),
        "bearer moves use current View, not a retained permission grant"
    );
    let previous: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE record_id=?")
        .bind(&f.anchor)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    crate::store::append(
        &f.db,
        crate::store::AppendSpec {
            record_id: f.anchor.clone(),
            event_type: "kernel.record_deleted.v1".into(),
            payload: json!({"reason":"retained source fixture","previous_seq":previous}),
            actor: Some(admin.clone()),
        },
    )
    .await
    .unwrap();
    f.actor = admin;
    assert_eq!(
        hidden,
        inspect_retained(&f, &pin).await.unwrap_err().to_string(),
        "even the former owner cannot serve a deleted bearer"
    );
}

#[tokio::test]
async fn named_view_source_proof_retained_requires_read_transaction_and_caps_current_sources() {
    let (f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["area"]).await.unwrap();
    let pin = retain_candidate(&f, &p).await;
    let mut conn = f.db.governed_pool().acquire().await.unwrap();
    let error = super::super::retained_facets::inspect_on(
        &mut conn,
        &f.actor,
        "trusted-workspace",
        &pin,
        deadline(),
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("read snapshot"));
    drop(conn);
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    assert!(super::super::retained_facets::inspect_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        &pin,
        deadline()
    )
    .await
    .err()
    .unwrap()
    .to_string()
    .contains("read snapshot"));
    tx.rollback().await.unwrap();
    let q = retained_query(&p, &pin);
    let baseline = retained_read(&f, &pin, &q).await.unwrap().0;
    for n in 0..33 {
        let id = format!("new-{n:02}");
        f.import("schema_config",&id,Some(json!({"id":id,"layer":"user","name":null,"data":json!({"shapes":{"WorkItem":{"facets":{"area":{}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))).await;
    }
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
}

#[tokio::test]
async fn named_view_source_proof_retained_root_context_change_refuses_old_sql_scope() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    let p = candidate(&f, "native:root", &["area"]).await.unwrap();
    assert_eq!(
        p.revision.definition["generated"]["context"]["logical_home_id"],
        KERNEL_ROOT_ID
    );
    let pin = retain_candidate(&f, &p).await;
    assert!(!inspect_retained(&f, &pin).await.unwrap());
    f.import(
        "schema_config",
        "malformed-advisory",
        Some(json!({"id":"malformed-advisory"})),
    )
    .await;
    assert_eq!(
        inspect_retained_drift(&f, &pin).await.unwrap(),
        Drift::Unknown
    );
    // This changes actual logical records.home_id from kernel:root to
    // native:root. Continuing to run the old literal would misstate its scope.
    kernel::import_home_policy_as(&f.db, &f.host, KERNEL_ROOT_ID, &[(&f.actor, "manage")])
        .await
        .unwrap();
    let error = inspect_retained(&f, &pin).await.unwrap_err();
    assert!(
        error.to_string().contains("logical home context changed"),
        "{error}"
    );
    f.import("schema_config", "malformed-advisory", None).await;
    declared(&f, "native:root").await;
    let next = candidate(&f, "native:root", &["area"]).await.unwrap();
    assert_eq!(
        next.revision.definition["generated"]["context"]["logical_home_id"],
        "native:root"
    );
}

async fn import_checkpoint_folder(f: &Fixture, id: &str, kind: &str) {
    let definition = kernel::ImportDefinition {
        pin: crate::meta::definition_artifact::RevisionIdentity {
            family: crate::v2_standard::v1_compat::FAMILY.into(),
            version: 1,
            digest: crate::meta::definition_artifact::digest_artifact_bytes(
                crate::v2_standard::v1_compat::DEFINITION.as_bytes(),
            ),
        },
        primary_type: "V1".into(),
        kind: "record".into(),
        fields: json!({"v1_type":"Collection","v1_kind":kind,"title":"Folder"})
            .as_object()
            .unwrap()
            .clone(),
    };
    kernel::import_record_as(
        &f.db,
        &f.host,
        id,
        KERNEL_ROOT_ID,
        Some(&f.actor),
        &kernel::ImportRecordState {
            definition: Some(definition),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn named_view_source_proof_retained_folder_alias_membership_and_governing_context() {
    let (f, _) = checkpoint_world().await;
    let folder = "folder:generated";
    import_checkpoint_folder(&f, folder, "folder").await;
    let physical = kernel::v1_import_home_id(folder);
    kernel::import_home_as(
        &f.db,
        &f.host,
        &physical,
        folder,
        KERNEL_ROOT_ID,
        &f.actor,
        None,
    )
    .await
    .unwrap();
    declared(&f, folder).await;
    imported_checkpoint_task(&f, &physical, "task:folder", Some("high"), None, false).await;
    let p = candidate(&f, &physical, &["area"]).await.unwrap();
    let alias = candidate(&f, folder, &["area"]).await.unwrap();
    assert_eq!(p.revision.definition, alias.revision.definition);
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    let (rows, drift, _) = retained_read(&f, &pin, &q).await.unwrap();
    assert!(!drift);
    assert_eq!(rows["row_count"], 1);
    assert_eq!(rows["rows"][0]["id"], "task:folder");
    assert_eq!(rows["rows"][0]["home_id"], folder);
    let destination = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&f.db, &f.actor, folder, &destination)
        .await
        .unwrap();
    // A physical placement change with current View and the same logical
    // folder/direct-member semantics does not resurrect the old write proof.
    assert!(!inspect_retained(&f, &pin).await.unwrap());
    let revision = kernel::read_record_as(&f.db, &f.actor, folder)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::revise_json_as_expected(
        &f.db,
        &f.actor,
        folder,
        r#"{"v1_kind":"not-a-folder"}"#,
        Some(revision),
    )
    .await
    .unwrap();
    assert_eq!(
        inspect_retained(&f, &pin).await.unwrap_err().to_string(),
        Error::engine(super::super::MISSING).to_string()
    );
}

#[tokio::test]
async fn named_view_source_proof_retained_four_by_sixty_four_and_value_cap() {
    let (f, home) = checkpoint_world().await;
    let mut rows = vec![];
    let mut facets = serde_json::Map::new();
    for v in 0..4 {
        facets.insert(format!("f{v}"), json!({"vocab":format!("rec:v{v}")}));
        rows.push(wrapper(
            "vocabularies",
            &format!("v{v}"),
            Some(json!({"id":format!("v{v}"),"name":format!("V{v}")})),
        ));
        for n in 0..64 {
            rows.push(wrapper("vocabulary_values",&format!("v{v}:{n:02}"),Some(json!({"id":format!("v{v}:{n:02}"),"vocabulary_id":format!("v{v}"),"value":format!("t{n}"),"status":"active","alias_of":null}))));
        }
    }
    rows.push(wrapper("schema_config","four",Some(json!({"id":"four","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":facets}}}).to_string(),"applies_to_collection_id":home,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))));
    for chunk in rows.chunks(256) {
        kernel::v1_state::import_state_batch_as(&f.db, &f.host, chunk)
            .await
            .unwrap();
    }
    let p = candidate(&f, &home, &["f0", "f1", "f2", "f3"])
        .await
        .unwrap();
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    let baseline = retained_read(&f, &pin, &q).await.unwrap().0;
    assert!(!inspect_retained(&f, &pin).await.unwrap());
    f.import("vocabulary_values","v0:extra",Some(json!({"id":"v0:extra","vocabulary_id":"v0","value":"extra","status":"active","alias_of":null}))).await;
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
    f.import("vocabulary_values", "v0:extra", None).await;
    f.import("vocabulary_values","v0:00",Some(json!({"id":"v0:00","vocabulary_id":"v0","value":"x".repeat(513),"status":"active","alias_of":null}))).await;
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
}

async fn assert_frozen_unknown(
    f: &Fixture,
    pin: &super::super::Pin,
    q: &super::super::contract::SavedSqlV12,
    baseline: &Value,
) {
    let (result, calls) =
        crate::query::generated_facets::measured_compiles(retained_read_with_drift(f, pin, q))
            .await;
    let (rows, drift, _) = result.unwrap();
    assert_eq!(drift, Drift::Unknown);
    assert_eq!(rows["rows"], baseline["rows"]);
    assert_eq!(rows["columns"], baseline["columns"]);
    assert_eq!(calls, 0, "Unknown is not permission to regenerate A1");
}

#[tokio::test]
async fn named_view_source_proof_retained_all_key_and_governance_growth_is_unknown() {
    let (f, home) = checkpoint_world().await;
    let p = super::super::facet_resolver::prepare(
        &f.db,
        &f.actor,
        "trusted-workspace",
        &f.anchor,
        super::super::facet_resolver::Request {
            selection: crate::query::generated_facets::Selection::All,
            ..generated_request(&home, &[])
        },
        deadline(),
    )
    .await
    .unwrap();
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    let baseline = retained_read(&f, &pin, &q).await.unwrap().0;
    let facets: serde_json::Map<String, Value> =
        (0..19).map(|n| (format!("field{n}"), json!({}))).collect();
    f.import("schema_config", "growth", Some(json!({"id":"growth","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":facets}}}).to_string(),"applies_to_collection_id":home,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))).await;
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
    f.import("schema_config", "growth", None).await;
    // 33 anchored rows contribute 66 governance entries (two shapes each).
    // The 32-source bound dominates the 64-governance bound: do not raise one
    // just to reach the other. Both kinds of growth leave A1 usable.
    let imports: Vec<_> = (0..33).map(|n| {
        let id = format!("gov{n:02}");
        wrapper("schema_config", &id, Some(json!({"id":id,"layer":"user","name":null,"data":json!({"shapes":{"WorkItem":{},"WorkItem:task":{}}}).to_string(),"applies_to_collection_id":home,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"})))
    }).collect();
    kernel::v1_state::import_state_batch_as(&f.db, &f.host, &imports)
        .await
        .unwrap();
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
}

#[tokio::test]
async fn named_view_source_proof_retained_total_value_growth_is_unknown() {
    let (f, home) = checkpoint_world().await;
    let mut imports = vec![];
    let mut facets = serde_json::Map::new();
    for v in 0..5 {
        facets.insert(format!("f{v}"), json!({"vocab":format!("rec:v{v}")}));
        imports.push(wrapper(
            "vocabularies",
            &format!("v{v}"),
            Some(json!({"id":format!("v{v}"),"name":format!("V{v}")})),
        ));
        for n in 0..51 {
            imports.push(wrapper("vocabulary_values", &format!("v{v}:{n:02}"), Some(json!({"id":format!("v{v}:{n:02}"),"vocabulary_id":format!("v{v}"),"value":format!("t{n}"),"status":"active","alias_of":null}))));
        }
    }
    imports.push(wrapper("schema_config", "five", Some(json!({"id":"five","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":facets}}}).to_string(),"applies_to_collection_id":home,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))));
    for chunk in imports.chunks(256) {
        kernel::v1_state::import_state_batch_as(&f.db, &f.host, chunk)
            .await
            .unwrap();
    }
    let p = candidate(&f, &home, &["f0", "f1", "f2", "f3", "f4"])
        .await
        .unwrap();
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    let baseline = retained_read(&f, &pin, &q).await.unwrap().0;
    for n in 51..53 {
        f.import("vocabulary_values", &format!("v4:{n:02}"), Some(json!({"id":format!("v4:{n:02}"),"vocabulary_id":"v4","value":format!("t{n}"),"status":"active","alias_of":null}))).await;
    }
    // 257 total with every individual vocabulary still below 64.
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
}

#[tokio::test]
async fn named_view_source_proof_retained_malformed_current_rows_are_unknown_not_authority() {
    let (f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    let baseline = retained_read(&f, &pin, &q).await.unwrap().0;
    f.import(
        "schema_config",
        "unrelated",
        Some(json!({"id":"unrelated","data":"not json"})),
    )
    .await;
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
    f.import("schema_config", "unrelated", Some(json!({"id":"unrelated","layer":"user","name":null,"data":"not json","applies_to_collection_id":null,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))).await;
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
    f.import("schema_config", "unrelated", None).await;
    f.import("schema_config", "unsupported", Some(json!({"id":"unsupported","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":null}}).to_string(),"applies_to_collection_id":home,"version_lineage":null,"created_at":"2026-10-27T00:00:01Z"}))).await;
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
    f.import("schema_config", "unsupported", None).await;
    // Deliberate projection damage, not an allowed imported-state writer:
    // current row differs from its sealed wrapper. Provenance comparison is
    // unknown, but the separately checked required row is still present.
    sqlx::query("UPDATE kernel_v1_state SET origin='damaged' WHERE section='schema_config' AND source_id='[\"global\"]'")
        .execute(f.db.write_pool()).await.unwrap();
    assert_frozen_unknown(&f, &pin, &q, &baseline).await;
    f.import("vocabularies", "priority", None).await;
    assert_eq!(
        inspect_retained_drift(&f, &pin)
            .await
            .unwrap_err()
            .to_string(),
        Error::engine(super::super::MISSING).to_string()
    );
}

#[tokio::test]
async fn named_view_source_proof_retained_comparison_caps_do_not_mask_mandatory_failures() {
    use super::super::retained_facets::inspect_with_limits_on;
    use sqlx::Connection;
    let (f, home) = checkpoint_world().await;
    let p = candidate(&f, &home, &["area", "priority"]).await.unwrap();
    let pin = retain_candidate(&f, &p).await;
    let q = retained_query(&p, &pin);
    let baseline = retained_read(&f, &pin, &q).await.unwrap().0;
    let mut conn = f.db.governed_pool().acquire().await.unwrap();
    for limits in [
        ScanLimits {
            rows: 8,
            bytes: PREPARE_BYTES,
        },
        ScanLimits {
            rows: PREPARE_ROWS,
            bytes: 1,
        },
    ] {
        let mut tx = conn.begin().await.unwrap();
        let limit = deadline();
        let checked =
            inspect_with_limits_on(&mut tx, &f.actor, "trusted-workspace", &pin, limit, limits)
                .await
                .unwrap();
        assert_eq!(checked.drift, Drift::Unknown);
        assert!(checked.work.rows <= limits.rows + 1);
        let rows = crate::mcp::kernel_v2::sql::generated_checkpoint_on(
            &mut tx,
            &f.actor,
            &p.name,
            &checked.definition.common(),
            &q,
            limit,
        )
        .await
        .unwrap();
        assert_eq!(rows["rows"], baseline["rows"]);
        tx.rollback().await.unwrap();
        conn.lock_handle().await.unwrap().remove_progress_handler();
        // This test retains the connection across iterations, so perform the
        // same query-only reset the governed-pool release hook normally does.
        sqlx::query("PRAGMA query_only=OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    drop(conn);
    let mut tx = f.db.governed_pool().begin().await.unwrap();
    let mut invalid_pin = pin.clone();
    invalid_pin.definition_sha256 = "0".repeat(64);
    let invalid = inspect_with_limits_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        &invalid_pin,
        deadline(),
        ScanLimits { rows: 1, bytes: 1 },
    )
    .await
    .err()
    .unwrap();
    assert!(
        invalid.to_string().contains("view_revision_unavailable"),
        "{invalid}"
    );
    let error = inspect_with_limits_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        &pin,
        Instant::now(),
        ScanLimits { rows: 1, bytes: 1 },
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("deadline"), "{error}");
    tx.rollback().await.unwrap();
    // External cancellation/interruption before the deadline is a refusal,
    // not an advisory parse/work failure.
    let mut tx = f.db.governed_pool().begin().await.unwrap();
    tx.lock_handle()
        .await
        .unwrap()
        .set_progress_handler(1, || false);
    let cancelled = inspect_with_limits_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        &pin,
        deadline(),
        ScanLimits { rows: 1, bytes: 1 },
    )
    .await;
    tx.lock_handle().await.unwrap().remove_progress_handler();
    assert!(matches!(cancelled, Err(Error::Sqlx(_))));
    tx.rollback().await.unwrap();
    // A canonical retained definition can have a stale profile. It must not
    // bypass current-profile checks when a comparison is incomplete.
    let mut old = p.revision.clone();
    old.definition["query"]["catalog_revision"] = json!(0);
    old.definition_sha256 = old.digest();
    let old_pin = retain_revision(&f, &old).await;
    let mut tx = f.db.governed_pool().begin().await.unwrap();
    let error = inspect_with_limits_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        &old_pin,
        deadline(),
        ScanLimits { rows: 1, bytes: 1 },
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("profile/catalog pin"), "{error}");
    tx.rollback().await.unwrap();
    // Genuine SQL failures must never become Unknown. Open a fresh read
    // transaction after removing the table; write transactions refuse earlier.
    sqlx::query("DROP TABLE kernel_v1_state")
        .execute(f.db.write_pool())
        .await
        .unwrap();
    let mut tx = f.db.governed_pool().begin().await.unwrap();
    assert!(matches!(
        inspect_with_limits_on(
            &mut tx,
            &f.actor,
            "trusted-workspace",
            &pin,
            deadline(),
            ScanLimits { rows: 1, bytes: 1 }
        )
        .await,
        Err(Error::Sqlx(_))
    ));
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn named_view_generated_admission_recomputes_all_fields_and_enrolls_its_writer() {
    let f = Fixture::new().await;
    declared(&f, KERNEL_ROOT_ID).await;
    let workspace =
        super::super::generated::workspace_on(&mut f.db.pool().acquire().await.unwrap())
            .await
            .unwrap();
    let candidate = super::super::facet_resolver::prepare(
        &f.db,
        &f.actor,
        &workspace,
        &f.anchor,
        generated_request(KERNEL_ROOT_ID, &["area", "priority"]),
        deadline(),
    )
    .await
    .unwrap();
    let definition = candidate.revision.definition.clone();
    let admitted =
        super::super::generated::prepare(&f.db, &f.actor, &f.anchor, &definition, deadline())
            .await
            .unwrap();
    assert_eq!(admitted.revision().definition, definition);
    assert_eq!(admitted.name(), candidate.name);
    // A caller cannot alter executable SQL, output prose, or provenance while
    // claiming the same declared schema/generator. Full canonical comparison,
    // rather than a client digest assertion, is the trust boundary.
    for pointer in ["/description", "/query/sql", "/generated/workspace_id"] {
        let mut forged = definition.clone();
        *forged.pointer_mut(pointer).unwrap() = json!("caller replacement");
        assert!(
            super::super::generated::prepare(&f.db, &f.actor, &f.anchor, &forged, deadline(),)
                .await
                .is_err(),
            "{pointer}"
        );
    }
    let mut writer = Writer::begin(&f.db, deadline()).await.unwrap();
    admitted
        .recheck(&f.db, &mut writer, &f.actor)
        .await
        .unwrap();
    let state: i64 = sqlx::query_scalar("SELECT count(*) FROM main.content_events")
        .fetch_one(&mut **writer.transaction())
        .await
        .unwrap();
    assert!(state > 0);
    // Transfer the SAME already enrolled transaction to the existing content
    // commit hook. No second BEGIN or arbitrary connection enrollment exists.
    f.db.commit_kernel_content(writer.into_transaction())
        .await
        .unwrap();
    f.import("vocabulary_values", "new-alias", Some(json!({
        "id":"new-alias", "vocabulary_id":"priority", "value":"new", "status":"active", "alias_of":"high"
    }))).await;
    let mut writer = Writer::begin(&f.db, deadline()).await.unwrap();
    assert!(admitted
        .recheck(&f.db, &mut writer, &f.actor)
        .await
        .is_err());
    writer.rollback().await.unwrap();
}

// Exercise the registered production source handler. Publication receives the
// same owned preflight carried by the executor's live-owner guarded dispatch;
// owner-guard serialization itself remains covered by the executor fixtures.
async fn generated_operation(f: &Fixture, args: Value) -> Result<Value> {
    use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry, WritePlanExecution};
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry)?;
    crate::mcp::tools::register_surface_tools(&mut registry)?;
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry)?;
    let mut caller = Caller::authenticated("acct:proof")
        .with_hosting_context("proof", "workspace")
        .with_hosting_owner(true);
    let publication = matches!(
        args["action"].as_str(),
        Some("activate_view" | "unpublish_view")
    );
    if publication {
        caller = caller.with_write_plan_execution(WritePlanExecution {
            plan_id: "generated-test-plan".into(),
            effect_digest: "generated-test-effect".into(),
            executor: "records_write".into(),
            operation: args["action"].as_str().unwrap().into(),
        });
        let prepared = crate::mcp::kernel_v2::writes::named_views::prepare_commit(
            &f.db, &f.actor, &caller, &args,
        )
        .await?;
        return crate::mcp::kernel_v2::writes::named_views::with_prevalidated(
            prepared,
            registry.call_engine(
                EngineHandle::KernelV2(f.db.clone()),
                caller,
                "manage_named_views",
                args,
            ),
        )
        .await;
    }
    registry
        .call_engine(
            EngineHandle::KernelV2(f.db.clone()),
            caller,
            "manage_named_views",
            args,
        )
        .await
}
async fn host_candidate(f: &Fixture, home: &str) -> super::super::facet_resolver::Prepared {
    super::super::facet_resolver::prepare(
        &f.db,
        &f.actor,
        &super::super::generated::workspace_on(&mut f.db.pool().acquire().await.unwrap())
            .await
            .unwrap(),
        &f.anchor,
        generated_request(home, &["area", "priority"]),
        deadline(),
    )
    .await
    .unwrap()
}
#[tokio::test]
async fn named_view_generated_operations_draft_activate_discover_read_freeze_and_unpublish() {
    use super::super::{gate, Pin, REVISION};
    let (mut f, home) = checkpoint_world().await;
    let p = host_candidate(&f, &home).await;
    let draft_args = json!({"action":"record_view_revision","id":f.anchor,"definition":p.revision.definition,"idempotency_key":"generated-draft"});
    assert!(generated_operation(&f, draft_args.clone()).await.is_err()); // Default off.
    let draft = gate::testing(true, generated_operation(&f, draft_args.clone()))
        .await
        .unwrap();
    let pin: Pin = serde_json::from_value(draft["pin"].clone()).unwrap();
    let replay = gate::testing(true, generated_operation(&f, draft_args.clone()))
        .await
        .unwrap();
    assert_eq!(replay["pin"], draft["pin"]);
    assert_eq!(replay["replayed"], true);
    let mut other_key = draft_args.clone();
    other_key["idempotency_key"] = json!("generated-draft-other-key");
    let reused = gate::testing(true, generated_operation(&f, other_key))
        .await
        .unwrap();
    assert_eq!(reused["pin"], draft["pin"]);
    assert_eq!(reused["reused"], true);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM main.content_events WHERE type=?")
            .bind(REVISION)
            .fetch_one(f.db.pool())
            .await
            .unwrap(),
        1
    );
    let activation = json!({"action":"activate_view","id":f.anchor,"pin":pin,"name":p.name,
        "expected_binding_event_id":null,"idempotency_key":"generated-activate"});
    let published = gate::testing(true, generated_operation(&f, activation.clone()))
        .await
        .unwrap();
    let q = retained_query(&p, &pin);
    let reopened =
        kernel::open_marked_v2_database(f._dir.path().join("proof.db").to_str().unwrap())
            .await
            .unwrap();
    assert!(!reopened.same_handle(&f.db));
    f.db = reopened; // Serving has no old Prepared/proof/physical-connection grant.
                     // This is the real retained registry/staging/SavedSQL path, not the private
                     // checkpoint adapter or an in-memory Prepared used as a serving grant.
    let before = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &q)
        .await
        .unwrap();
    assert_eq!(before["rows"].as_array().unwrap().len(), 7);
    assert_eq!(
        before["view_provenance"]["generated_source_drift"][&pin.revision_id],
        "unchanged"
    );
    // Turning the producer off does not disable already retained SQL reads.
    assert_eq!(
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &q)
            .await
            .unwrap()["rows"],
        before["rows"]
    );
    let catalog = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        json!({"sql":"SELECT relation_name FROM catalog_view_definitions ORDER BY relation_name"}),
    )
    .await
    .unwrap();
    assert_eq!(catalog["rows"], json!([{"relation_name":p.name}]));
    let detail_args =
        json!({"action":"get_view_revision","view_id":pin.view_id,"revision_id":pin.revision_id});
    let detail = gate::testing(true, generated_operation(&f, detail_args.clone()))
        .await
        .unwrap();
    assert_eq!(detail["definition"], p.revision.definition);
    let query_record = kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) VALUES(?,'query',?,'2026-10-27',0)")
        .bind(&query_record).bind(serde_json::to_string(&q).unwrap())
        .execute(f.db.write_pool()).await.unwrap();
    let effects_before: i64 = sqlx::query_scalar("SELECT count(*) FROM main.content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let off = gate::testing(false, async {
        let raw = crate::mcp::kernel_v2::sql::query_sql(
            &f.db,
            &f.actor,
            json!({"sql":format!("SELECT * FROM {} ORDER BY id",p.name)}),
        )
        .await
        .unwrap();
        assert_eq!(raw["rows"], before["rows"]);
        let mut disabled_draft = draft_args.clone();
        disabled_draft["idempotency_key"] = json!("off-new-draft");
        assert!(generated_operation(&f, disabled_draft).await.is_err());
        let mut disabled_activation = activation.clone();
        disabled_activation["expected_binding_event_id"] = published["event_id"].clone();
        disabled_activation["idempotency_key"] = json!("off-new-activation");
        assert!(generated_operation(&f, disabled_activation).await.is_err());
        crate::mcp::kernel_v2::artifacts::testing_governed_sql_input(
            &f.db,
            &f.actor,
            &query_record,
            &q.output.schema_sha256,
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM main.content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap(),
        effects_before
    );
    assert_eq!(
        off["source"]["execution_receipt"]["version"],
        "native.governed-sql-port-receipt.v3"
    );
    let v3 = gate::testing(
        true,
        crate::mcp::kernel_v2::artifacts::testing_governed_sql_input(
            &f.db,
            &f.actor,
            &query_record,
            &q.output.schema_sha256,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        v3["source"]["execution_receipt"]["version"],
        "native.governed-sql-port-receipt.v3"
    );
    assert_eq!(off["relation"], v3["relation"]);
    assert_eq!(
        off["source"]["execution_receipt"]["view_provenance"],
        v3["source"]["execution_receipt"]["view_provenance"]
    );
    assert_eq!(
        v3["source"]["execution_receipt"]["view_provenance"]["generated_diagnostics"],
        json!([{"root":p.name,"drift":"unchanged","unknown_reason":null}])
    );
    let compiled =
        native_artifact_runtime::mdx::compile_v2_source("<Metric label=\"Receipt\" value={1} />")
            .unwrap();
    native_artifact_runtime::mdx_v2::render_verified(&compiled,Default::default(),&json!({"version":native_artifact_runtime::mdx_v2::NAMED_INPUT_ABI,"mode":"named","inputs":{"rows":v3},"records":[]}),&json!({"$root":{"inputs":{"rows":v3}}})).unwrap();
    f.import("vocabulary_values", "new-alias", Some(json!({"id":"new-alias","vocabulary_id":"priority","value":"new-token","status":"active","alias_of":"high"}))).await;
    let after = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &q)
        .await
        .unwrap();
    assert_eq!(after["rows"], before["rows"]);
    let changed_port = gate::testing(
        true,
        crate::mcp::kernel_v2::artifacts::testing_governed_sql_input(
            &f.db,
            &f.actor,
            &query_record,
            &q.output.schema_sha256,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        changed_port["source"]["execution_receipt"]["view_provenance"]["generated_diagnostics"][0]
            ["drift"],
        "changed"
    );
    assert_ne!(
        changed_port["source"]["content_revision"],
        v3["source"]["content_revision"]
    );
    let mut empty = q.clone();
    empty.sql = format!("SELECT * FROM {} WHERE 0 ORDER BY id", p.name);
    let mut count = q.clone();
    count.sql = format!(
        "SELECT 'count' AS id,COUNT(*) AS n FROM {} ORDER BY id",
        p.name
    );
    let columns = json!([{"name":"id","type":"identifier","nullable":false},{"name":"n","type":"integer","nullable":false}]);
    count.output=serde_json::from_value(json!({"columns":columns,"schema_sha256":native_artifact_runtime::mdx::sha256_hex(&native_artifact_runtime::mdx_v2::canonical_json_bytes(&columns)),"row_identity":["id"],"order":[{"column":"id","direction":"asc"}]})).unwrap();
    for (query, expected_rows) in [(empty, 0), (count, 1)] {
        sqlx::query("UPDATE kernel_facets SET value=? WHERE record_id=? AND key='query'")
            .bind(serde_json::to_string(&query).unwrap())
            .bind(&query_record)
            .execute(f.db.write_pool())
            .await
            .unwrap();
        let port = gate::testing(
            true,
            crate::mcp::kernel_v2::artifacts::testing_governed_sql_input(
                &f.db,
                &f.actor,
                &query_record,
                &query.output.schema_sha256,
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            port["relation"]["rows"].as_array().unwrap().len(),
            expected_rows
        );
        assert_eq!(
            port["source"]["execution_receipt"]["view_provenance"]["generated_diagnostics"][0]
                ["drift"],
            "changed"
        );
    }
    // Current comparison growth remains advisory in the ordinary port too.
    f.import("vocabulary_values", "oversized-token", Some(json!({"id":"oversized-token","vocabulary_id":"priority","value":"x".repeat(513),"status":"active","alias_of":null}))).await;
    sqlx::query("UPDATE kernel_facets SET value=? WHERE record_id=? AND key='query'")
        .bind(serde_json::to_string(&q).unwrap())
        .bind(&query_record)
        .execute(f.db.write_pool())
        .await
        .unwrap();
    let unknown_port = gate::testing(
        true,
        crate::mcp::kernel_v2::artifacts::testing_governed_sql_input(
            &f.db,
            &f.actor,
            &query_record,
            &q.output.schema_sha256,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        unknown_port["relation"]["rows"],
        changed_port["relation"]["rows"]
    );
    assert_eq!(
        unknown_port["source"]["execution_receipt"]["view_provenance"]["generated_diagnostics"],
        json!([{"root":p.name,"drift":"unknown","unknown_reason":"budget"}])
    );
    assert_ne!(
        unknown_port["source"]["content_revision"],
        changed_port["source"]["content_revision"]
    );
    assert_eq!(
        after["view_provenance"]["generated_source_drift"][&pin.revision_id],
        "changed"
    );
    let replay = gate::testing(true, generated_operation(&f, draft_args))
        .await
        .unwrap();
    assert_eq!(replay["pin"], draft["pin"]); // No regeneration on receipt retry.
                                             // Restore a supported current proposal subset before explicitly preparing A2.
    f.import("vocabulary_values", "oversized-token", None).await;
    let p2 = host_candidate(&f, &home).await;
    assert_eq!(p2.name, p.name);
    assert_ne!(p2.revision.definition_sha256, p.revision.definition_sha256);
    let a2 = gate::testing(true, generated_operation(&f,
        json!({"action":"record_view_revision","id":f.anchor,"definition":p2.revision.definition,"idempotency_key":"generated-a2"}))).await.unwrap();
    assert_ne!(a2["pin"], draft["pin"]);
    assert_eq!(
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &q)
            .await
            .unwrap()["rows"],
        before["rows"]
    );
    // Required absence refuses A1, but cannot trap its publication/name/slot.
    f.import("vocabularies", "priority", None).await;
    assert_eq!(
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &q)
            .await
            .unwrap_err()
            .to_string(),
        format!("query_sql [engine]: {}", super::super::MISSING)
    );
    let removed = gate::testing(true, generated_operation(&f,
        json!({"action":"unpublish_view","id":f.anchor,"expected_binding_event_id":published["event_id"],"idempotency_key":"generated-unpublish"}))).await.unwrap();
    assert_eq!(removed["operation"], "unpublish_view");
}

#[tokio::test]
async fn named_view_generated_published_parent_join_preserves_cardinality_and_privacy() {
    use super::super::{contract::Dependency, gate, Pin};
    let (mut f, home) = checkpoint_world().await;
    let parents = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    for id in ["parent:a", "parent:b"] {
        imported_checkpoint_task(&f, &parents, id, None, None, false).await;
    }
    for (task, parent) in [
        ("task:high", "parent:a"),
        ("task:high", "parent:b"),
        ("task:alias", "parent:a"),
    ] {
        kernel::add_generic_link_as(&f.db, &f.actor, task, parent, "part_of", None)
            .await
            .unwrap();
    }
    let p = host_candidate(&f, &home).await;
    let draft = gate::testing(
        true,
        generated_operation(
            &f,
            json!({
                "action":"record_view_revision","id":f.anchor,
                "definition":p.revision.definition,"idempotency_key":"parent-draft",
            }),
        ),
    )
    .await
    .unwrap();
    let pin: Pin = serde_json::from_value(draft["pin"].clone()).unwrap();
    gate::testing(
        true,
        generated_operation(
            &f,
            json!({
                "action":"activate_view","id":f.anchor,"name":p.name,"pin":pin,
                "expected_binding_event_id":null,"idempotency_key":"parent-activate",
            }),
        ),
    )
    .await
    .unwrap();
    let mut outer = checkpoint_parent_outer(&p);
    outer
        .relations
        .insert(p.name.clone(), Dependency::View(pin.clone()));
    outer.validate_current().unwrap();
    // The unchanged two gates inspect this actual generated SQL and the outer
    // join's honest length-prefixed task/edge identity, before public staging.
    let validators = crate::query::sql::NamedViewValidators::new(&[(
        p.name.clone(),
        p.revision.definition["query"]["sql"]
            .as_str()
            .unwrap()
            .into(),
    )])
    .unwrap();
    assert_eq!(
        validators.inspect_saved(&outer.sql).unwrap(),
        validators.inspect(&outer.sql).unwrap()
    );
    let admin = checkpoint_viewer(&mut f, &home).await;
    kernel::replace_home_policy(
        &f.db,
        &admin,
        &parents,
        &[(&admin, "manage"), (&f.actor, "view")],
    )
    .await
    .unwrap();
    let before = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &outer)
        .await
        .unwrap();
    // The normal governed artifact port preserves the expanding join and its
    // generated root summary; the receipt never invents one-row-per-task grain.
    // Provision the saved query as the administrator; the querying caller has
    // View only, and must not acquire Edit merely to exercise the port.
    let query_record = kernel::create_record_as(&f.db, &admin, &home)
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) VALUES(?,'query',?,'2026-10-27',0)")
        .bind(&query_record).bind(serde_json::to_string(&outer).unwrap())
        .execute(f.db.write_pool()).await.unwrap();
    let port = gate::testing(
        true,
        crate::mcp::kernel_v2::artifacts::testing_governed_sql_input(
            &f.db,
            &f.actor,
            &query_record,
            &outer.output.schema_sha256,
        ),
    )
    .await
    .unwrap();
    assert_eq!(port["relation"]["rows"], before["rows"]);
    assert_eq!(
        port["source"]["execution_receipt"]["version"],
        "native.governed-sql-port-receipt.v3"
    );
    assert_eq!(
        port["source"]["execution_receipt"]["view_provenance"]["generated_diagnostics"],
        json!([{"root":p.name,"drift":"unchanged","unknown_reason":null}])
    );
    let rows = before["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 8); // Seven task records; only high expands twice.
    assert_eq!(
        rows.iter().filter(|r| r["task_id"] == "task:high").count(),
        2
    );
    assert_eq!(
        rows.iter().filter(|r| r["task_id"] == "task:alias").count(),
        1
    );
    assert!(rows
        .iter()
        .any(|r| r["task_id"] == "task:missing" && r["parent_id"].is_null()));
    assert_eq!(
        crate::mcp::kernel_v2::sql::query_sql(&f.db, &f.actor, json!({"sql":outer.sql}))
            .await
            .unwrap()["rows"],
        before["rows"]
    );
    let private = kernel::create_home(&f.db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let reader = std::mem::replace(&mut f.actor, admin.clone());
    imported_checkpoint_task(&f, &private, "parent:hidden", None, None, false).await;
    imported_checkpoint_task(&f, &private, "task:hidden", None, None, false).await;
    f.actor = reader;
    for (source, target) in [
        ("task:high", "parent:hidden"),
        ("task:missing", "parent:hidden"),
        ("task:hidden", "parent:a"),
    ] {
        kernel::add_generic_link_as(&f.db, &admin, source, target, "part_of", None)
            .await
            .unwrap();
    }
    let after = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &outer)
        .await
        .unwrap();
    assert_eq!(
        before["rows"], after["rows"],
        "hidden edges must not expand visible rows"
    );
    let mut hidden = outer.clone();
    hidden.sql = hidden.sql.replace(
        "r.id=l.target_id",
        "r.id=l.target_id AND r.id='parent:hidden'",
    );
    let mut missing = hidden.clone();
    missing.sql = missing.sql.replace("parent:hidden", "parent:absent");
    assert_eq!(
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &hidden)
            .await
            .unwrap()["rows"],
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &missing)
            .await
            .unwrap()["rows"],
    );
    // COUNT also uses the full generated body and caller-filtered links, even
    // though no body-only facet column is selected by this outer statement.
    let count = crate::mcp::kernel_v2::sql::query_sql(&f.db,&f.actor,json!({
        "sql":format!("SELECT COUNT(*) AS n FROM {} g LEFT JOIN links l ON l.source_id=g.id AND l.relationship='part_of' LEFT JOIN records r ON r.id=l.target_id",p.name),
    })).await.unwrap();
    assert_eq!(count["rows"], json!([{"n":8}]));
    assert_eq!(
        after["view_provenance"]["generated_source_drift"][&pin.revision_id],
        "unchanged"
    );
}

#[tokio::test]
async fn named_view_generated_real_executor_guard_carries_proof_and_detects_import_races() {
    for change in [None, Some("alias"), Some("override")] {
        let (f, home) = checkpoint_world().await;
        let p = host_candidate(&f, &home).await;
        let interference=change.map(|kind| if kind=="alias" {
            wrapper("vocabulary_values","guard-alias",Some(json!({"id":"guard-alias","vocabulary_id":"priority","value":"guard-token","status":"active","alias_of":"high"})))
        } else {
            wrapper("schema_config","guard-override",Some(json!({"id":"guard-override","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"Concurrent override"}}}}}).to_string(),"applies_to_collection_id":home,"version_lineage":"guard-H","created_at":"2026-10-27T01:00:00Z"})))
        });
        crate::mcp::executor_prototype::named_views::tests::generated_publication_guard_fixture(
            &f.db,
            f._dir.path(),
            &f.actor,
            &f.anchor,
            &home,
            (p.revision.definition, &p.name),
            interference,
        )
        .await;
    }
}

#[tokio::test]
async fn named_view_generated_preflight_refuses_new_overrides_and_aliases_before_any_effect() {
    use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry};
    for alias in [false, true] {
        let (f, home) = checkpoint_world().await;
        let p = host_candidate(&f, &home).await;
        let args = json!({"action":"record_view_revision","id":f.anchor,"definition":p.revision.definition,"idempotency_key":"prepared-generated"});
        let caller = Caller::authenticated("acct:proof")
            .with_hosting_context("proof", "workspace")
            .with_hosting_owner(false);
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let prepared = super::super::gate::testing(
            true,
            crate::mcp::kernel_v2::writes::named_views::prepare_commit(
                &f.db, &f.actor, &caller, &args,
            ),
        )
        .await
        .unwrap();
        if alias {
            f.import("vocabulary_values", "isolated-new-alias", Some(json!({"id":"isolated-new-alias","vocabulary_id":"priority","value":"new-alias","status":"active","alias_of":"high"}))).await;
        } else {
            f.import("schema_config", "new-override", Some(json!({"id":"new-override","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"New winning declaration"}}}}}).to_string(),"applies_to_collection_id":home,"version_lineage":"H2","created_at":"2026-10-27T01:00:00Z"}))).await;
        }
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM main.content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        let error = super::super::gate::testing(
            true,
            crate::mcp::kernel_v2::writes::named_views::with_prevalidated(
                prepared,
                registry.call_engine(
                    EngineHandle::KernelV2(f.db.clone()),
                    caller,
                    "manage_named_views",
                    args,
                ),
            ),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("view_source_changed"), "{error}");
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM main.content_events")
                .fetch_one(f.db.pool())
                .await
                .unwrap()
        );
        assert!(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name='kernel_mcp_write_receipts')").fetch_one(f.db.pool()).await.unwrap());
    }
}

#[tokio::test]
async fn named_view_generated_empty_raw_saved_catalog_and_detail_keep_drift() {
    use super::super::{gate, Pin};
    let (f, home) = checkpoint_world().await;
    let p = host_candidate(&f, &home).await;
    let draft=gate::testing(true,generated_operation(&f,json!({"action":"record_view_revision","id":f.anchor,"definition":p.revision.definition,"idempotency_key":"empty-drift-draft"}))).await.unwrap();
    let pin: Pin = serde_json::from_value(draft["pin"].clone()).unwrap();
    gate::testing(true,generated_operation(&f,json!({"action":"activate_view","id":f.anchor,"name":p.name,"pin":pin,"expected_binding_event_id":null,"idempotency_key":"empty-drift-publish"}))).await.unwrap();
    let mut saved = retained_query(&p, &pin);
    saved.sql = format!("SELECT * FROM {} WHERE 0 ORDER BY id", p.name);
    for state in ["unchanged", "changed", "unknown"] {
        if state == "changed" {
            f.import("vocabulary_values","empty-alias",Some(json!({"id":"empty-alias","vocabulary_id":"priority","value":"empty-token","status":"active","alias_of":"high"}))).await;
        } else if state == "unknown" {
            f.import("vocabulary_values","empty-long",Some(json!({"id":"empty-long","vocabulary_id":"priority","value":"z".repeat(513),"status":"active","alias_of":null}))).await;
        }
        let raw = crate::mcp::kernel_v2::sql::query_sql(&f.db, &f.actor, json!({"sql":saved.sql}))
            .await
            .unwrap();
        let pinned = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &saved)
            .await
            .unwrap();
        let catalog=crate::mcp::kernel_v2::sql::query_sql(&f.db,&f.actor,json!({"sql":"SELECT relation_name FROM catalog_view_definitions WHERE 0 ORDER BY relation_name"})).await.unwrap();
        assert_eq!(catalog["rows"], json!([]));
        assert!(
            catalog.get("view_provenance").is_none(),
            "metadata candidates are not execution provenance: {catalog}"
        );
        for reply in [&raw, &pinned] {
            assert_eq!(reply["rows"], json!([]));
            assert_eq!(
                reply["view_provenance"]["generated_source_drift"][&pin.revision_id], state,
                "{reply}"
            );
            if state == "unknown" {
                assert_eq!(
                    reply["view_provenance"]["generated_unknown_reason"][&pin.revision_id],
                    "budget"
                );
            }
        }
        let detail=gate::testing(true,generated_operation(&f,json!({"action":"get_view_revision","view_id":pin.view_id,"revision_id":pin.revision_id}))).await.unwrap();
        assert_eq!(detail["source_drift"], state);
        assert_eq!(
            detail["definition"], p.revision.definition,
            "read never regenerates frozen output"
        );
        if state == "unknown" {
            assert_eq!(detail["source_drift_unknown_reason"], "budget");
        }
    }
}

#[tokio::test]
async fn named_view_generated_catalog_candidates_do_not_enter_executed_provenance() {
    use super::super::{
        contract::{Dependency, SavedSqlV12},
        gate, Pin,
    };
    let (f, home) = checkpoint_world().await;
    let p = host_candidate(&f, &home).await;
    let draft=gate::testing(true,generated_operation(&f,json!({"action":"record_view_revision","id":f.anchor,"definition":p.revision.definition,"idempotency_key":"catalog-gen"}))).await.unwrap();
    gate::testing(true,generated_operation(&f,json!({"action":"activate_view","id":f.anchor,"pin":draft["pin"],"name":p.name,"expected_binding_event_id":null,"idempotency_key":"catalog-gen-active"}))).await.unwrap();
    let bearer = kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let definition = super::super::testing_definition();
    let auth=gate::testing(true,generated_operation(&f,json!({"action":"record_view_revision","id":bearer,"definition":definition,"idempotency_key":"catalog-auth"}))).await.unwrap();
    let pin: Pin = serde_json::from_value(auth["pin"].clone()).unwrap();
    gate::testing(true,generated_operation(&f,json!({"action":"activate_view","id":bearer,"pin":pin,"name":"view_authored_catalog","expected_binding_event_id":null,"idempotency_key":"catalog-auth-active"}))).await.unwrap();
    let mut q: SavedSqlV12 = serde_json::from_value(definition["query"].clone()).unwrap();
    q.sql="SELECT a.id FROM view_authored_catalog a LEFT JOIN catalog_relations c ON c.relation_name='records' ORDER BY a.id".into();
    let relation = crate::query::sql_contract::LOGICAL_RELATIONS
        .iter()
        .find(|r| r.name == "catalog_relations")
        .unwrap();
    q.relations = std::collections::BTreeMap::from([
        (
            "view_authored_catalog".into(),
            Dependency::View(pin.clone()),
        ),
        (
            "catalog_relations".into(),
            Dependency::Static(crate::mcp::tools::querying::SavedSqlRelationDependency {
                identity: relation.identity.into(),
                semantic_version: relation.semantic_version,
            }),
        ),
    ]);
    q.validate_current().unwrap();
    let pinned = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &q)
        .await
        .unwrap();
    let raw = crate::mcp::kernel_v2::sql::query_sql(&f.db, &f.actor, json!({"sql":q.sql}))
        .await
        .unwrap();
    for result in [&pinned, &raw] {
        assert_eq!(result["view_provenance"]["has_generated_nodes"], false);
        assert_eq!(
            result["view_provenance"]["generated_source_drift"],
            json!({})
        );
        assert_eq!(
            result["view_provenance"]["roots"],
            json!({"view_authored_catalog":pin})
        );
    }
    let record = kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) VALUES(?,'query',?,'2026-10-27',0)").bind(&record).bind(serde_json::to_string(&q).unwrap()).execute(f.db.write_pool()).await.unwrap();
    let envelope = crate::mcp::kernel_v2::artifacts::testing_governed_sql_input(
        &f.db,
        &f.actor,
        &record,
        &q.output.schema_sha256,
    )
    .await
    .unwrap();
    assert_eq!(
        envelope["source"]["execution_receipt"]["version"],
        "native.governed-sql-port-receipt.v2"
    );
    assert!(envelope["source"]["execution_receipt"]["view_provenance"]
        .get("generated_diagnostics")
        .is_none());
}

#[tokio::test]
async fn named_view_generated_receipt_requires_complete_node_evidence_and_hides_child_ids() {
    use super::super::{
        closure, contract::Dependency, gate, receipt, retained_facets::Drift,
        source_proof::ComparisonReason, Pin,
    };
    let (f, home) = checkpoint_world().await;
    let p = host_candidate(&f, &home).await;
    let child = retain_candidate(&f, &p).await;
    let other = retain_candidate(&f, &p).await;
    let bearer = kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let mut definition = super::super::testing_definition();
    definition["query"]["sql"] =
        json!("SELECT a.id FROM view_child a LEFT JOIN view_other b ON b.id=a.id ORDER BY a.id");
    definition["query"]["relations"] = json!({"view_child":Dependency::View(child.clone()),"view_other":Dependency::View(other.clone())});
    let draft=gate::testing(true,generated_operation(&f,json!({"action":"record_view_revision","id":bearer,"definition":definition,"idempotency_key":"authored-over-generated"}))).await.unwrap();
    let root: Pin = serde_json::from_value(draft["pin"].clone()).unwrap();
    let unrelated_bearer = kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let unrelated = gate::testing(true, generated_operation(&f, json!({
        "action":"record_view_revision","id":unrelated_bearer,
        "definition":super::super::testing_definition(),"idempotency_key":"unrelated-authored-root",
    }))).await.unwrap();
    let unrelated: Pin = serde_json::from_value(unrelated["pin"].clone()).unwrap();
    let mut tx = f.db.pool().begin().await.unwrap();
    let plan = closure::resolve_on(
        &mut tx,
        &f.actor,
        &std::collections::BTreeMap::from([("view_neutral_alias".into(), root.clone())]),
        deadline(),
    )
    .await
    .unwrap();
    let summary = receipt::generated_summaries(&plan).unwrap().unwrap();
    assert_eq!(
        summary,
        json!([{"root":"view_neutral_alias","drift":"unchanged","unknown_reason":null}])
    );
    assert!(!summary.to_string().contains(&child.view_id));
    // A generated node shared by two roots is summarized under each subtree;
    // the unrelated authored root contributes no generated diagnostic.
    let diamond = closure::resolve_on(
        &mut tx,
        &f.actor,
        &std::collections::BTreeMap::from([
            ("view_neutral_alias".into(), root.clone()),
            ("view_shared".into(), child.clone()),
            ("view_unrelated".into(), unrelated),
        ]),
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        receipt::generated_summaries(&diamond).unwrap().unwrap(),
        json!([
            {"root":"view_neutral_alias","drift":"unchanged","unknown_reason":null},
            {"root":"view_shared","drift":"unchanged","unknown_reason":null},
        ])
    );
    let mut bad = plan.clone();
    bad.generated_drift.clear();
    assert!(receipt::generated_summaries(&bad).is_err());
    let mut bad = plan.clone();
    bad.generated_drift.insert(root.clone(), Drift::Changed);
    assert!(receipt::generated_summaries(&bad).is_err());
    let mut bad = plan.clone();
    bad.generated_drift.insert(child.clone(), Drift::Unknown);
    assert!(receipt::generated_summaries(&bad).is_err());
    let mut bad = plan.clone();
    bad.generated_unknown_reason
        .insert(child.clone(), ComparisonReason::Budget);
    assert!(receipt::generated_summaries(&bad).is_err());
    let mut changed = plan.clone();
    changed
        .generated_drift
        .insert(child.clone(), Drift::Changed);
    assert_eq!(
        receipt::generated_summaries(&changed).unwrap().unwrap()[0]["drift"],
        "changed"
    );
    changed
        .generated_drift
        .insert(child.clone(), Drift::Unknown);
    changed
        .generated_unknown_reason
        .insert(child.clone(), ComparisonReason::Budget);
    changed
        .generated_drift
        .insert(other.clone(), Drift::Unknown);
    changed
        .generated_unknown_reason
        .insert(other, ComparisonReason::Unsupported);
    assert_eq!(
        receipt::generated_summaries(&changed).unwrap().unwrap()[0]["unknown_reason"],
        "unsupported"
    );
    changed
        .generated_unknown_reason
        .insert(child, ComparisonReason::Integrity);
    assert_eq!(
        receipt::generated_summaries(&changed).unwrap().unwrap()[0]["unknown_reason"],
        "integrity"
    );
}

#[tokio::test]
async fn named_view_generated_closure_reuses_one_source_scan_and_metadata_skips_it() {
    let (f, home) = checkpoint_world().await;
    let p = host_candidate(&f, &home).await;
    let mut roots = std::collections::BTreeMap::new();
    for n in 0..8 {
        roots.insert(format!("view_scan_{n}"), retain_candidate(&f, &p).await);
    }
    let mut tx = f.db.pool().begin().await.unwrap();
    let one = std::collections::BTreeMap::from([(
        roots.first_key_value().unwrap().0.clone(),
        roots.first_key_value().unwrap().1.clone(),
    )]);
    let first = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            super::super::closure::resolve_on(&mut tx, &f.actor, &one, deadline())
                .await
                .unwrap();
            TRACE.with(std::cell::Cell::get)
        })
        .await;
    let all = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let plan = super::super::closure::resolve_on(&mut tx, &f.actor, &roots, deadline())
                .await
                .unwrap();
            assert_eq!(plan.generated_drift.len(), 8);
            TRACE.with(std::cell::Cell::get)
        })
        .await;
    assert!(first[Trace::StateFetch as usize] > 0);
    assert_eq!(
        first[Trace::StateFetch as usize],
        all[Trace::StateFetch as usize],
        "one complete bounded section snapshot for all eight pins"
    );
    let pin = roots.first_key_value().unwrap().1;
    let single = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            super::super::details::list_on(&mut tx, &f.actor, &pin.view_id, 1, None, deadline())
                .await
                .unwrap();
            TRACE.with(std::cell::Cell::get)
        })
        .await;
    let trace = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let list = super::super::details::list_on(
                &mut tx,
                &f.actor,
                &pin.view_id,
                8,
                None,
                deadline(),
            )
            .await
            .unwrap();
            assert_eq!(list["revisions"].as_array().unwrap().len(), 8);
            TRACE.with(std::cell::Cell::get)
        })
        .await;
    assert_eq!(
        trace[Trace::StateFetch as usize],
        0,
        "listing is metadata, not current source interpretation"
    );
    assert!(single[Trace::EventFetch as usize] > 0);
    assert_eq!(
        single[Trace::EventFetch as usize],
        trace[Trace::EventFetch as usize],
        "one context witness lookup for all versions sharing the same H/anchors"
    );
}

#[tokio::test]
async fn named_view_generated_archived_and_moved_visible_metadata_is_retrievable() {
    use super::super::gate;
    let (mut f, home) = checkpoint_world().await;
    let p = host_candidate(&f, &home).await;
    let pin = retain_candidate(&f, &p).await;
    gate::testing(true, generated_operation(&f,json!({"action":"activate_view","id":f.anchor,
        "pin":pin,"name":p.name,"expected_binding_event_id":null,"idempotency_key":"carrier-move-active"})))
        .await.unwrap();
    let admin = checkpoint_viewer(&mut f, &home).await;
    let query = retained_query(&p, &pin);
    let sql = json!({"sql":query.sql});
    let baseline = crate::mcp::kernel_v2::sql::query_sql(&f.db, &f.actor, sql.clone())
        .await
        .unwrap();
    assert!(!baseline["rows"].as_array().unwrap().is_empty());
    let r = kernel::read_record_as(&f.db, &admin, &f.anchor)
        .await
        .unwrap()
        .unwrap();
    let original_home = r.home_id.clone();
    assert_ne!(original_home, home, "carrier home is not retained source H");
    kernel::set_archived_as(&f.db, &admin, &f.anchor, true, r.revision)
        .await
        .unwrap();
    let mut tx = f.db.pool().begin().await.unwrap();
    let detail = super::super::details::get_on(
        &mut tx,
        &f.actor,
        &pin.view_id,
        &pin.revision_id,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(detail["definition"], p.revision.definition);
    assert_eq!(detail["diagnostic"], "view_context_unavailable");
    let list = super::super::details::list_on(&mut tx, &f.actor, &pin.view_id, 8, None, deadline())
        .await
        .unwrap();
    assert_eq!(list["revisions"][0]["diagnostic"], detail["diagnostic"]);
    assert_eq!(list["revisions"][0]["available"], false);
    tx.rollback().await.unwrap();
    assert!(
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &query)
            .await
            .is_err(),
        "archival still refuses execution"
    );
    let r = kernel::read_record_as(&f.db, &admin, &f.anchor)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&f.db, &admin, &f.anchor, false, r.revision)
        .await
        .unwrap();
    let next = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&admin, "manage"), (&f.actor, "view")]),
        &admin,
    )
    .await
    .unwrap();
    assert_ne!(next, home);
    // Move away and back without moving H or any required source anchor. A
    // final move isolates the later bearer-View loss from source-H visibility.
    for target in [&next, &original_home, &next] {
        kernel::rehome_record_as(&f.db, &admin, &f.anchor, target)
            .await
            .unwrap();
        let raw = crate::mcp::kernel_v2::sql::query_sql(&f.db, &f.actor, sql.clone())
            .await
            .unwrap();
        let pinned = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &query)
            .await
            .unwrap();
        assert_eq!(raw["rows"], baseline["rows"]);
        assert_eq!(pinned["rows"], baseline["rows"]);
        let mut tx = f.db.pool().begin().await.unwrap();
        let detail = super::super::details::get_on(
            &mut tx,
            &f.actor,
            &pin.view_id,
            &pin.revision_id,
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(detail["definition"], p.revision.definition);
        assert_eq!(detail["diagnostic"], json!(null));
        let list =
            super::super::details::list_on(&mut tx, &f.actor, &pin.view_id, 8, None, deadline())
                .await
                .unwrap();
        assert_eq!(list["revisions"][0]["diagnostic"], json!(null));
        assert_eq!(list["revisions"][0]["available"], true);
        tx.rollback().await.unwrap();
    }
    kernel::replace_home_policy(&f.db, &admin, &next, &[(&admin, "manage")])
        .await
        .unwrap();
    let mut tx = f.db.pool().begin().await.unwrap();
    let hidden = super::super::details::get_on(
        &mut tx,
        &f.actor,
        &pin.view_id,
        &pin.revision_id,
        deadline(),
    )
    .await
    .unwrap_err()
    .to_string();
    let absent = super::super::details::get_on(
        &mut tx,
        &f.actor,
        "native.named-view:absent",
        &pin.revision_id,
        deadline(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden, absent);
    assert_eq!(
        super::super::details::list_on(&mut tx, &f.actor, &pin.view_id, 8, None, deadline())
            .await
            .unwrap_err()
            .to_string(),
        hidden
    );
    tx.rollback().await.unwrap();
    for result in [
        crate::mcp::kernel_v2::sql::query_sql(&f.db, &f.actor, sql).await,
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &query).await,
    ] {
        assert!(result.unwrap_err().to_string().contains("view_missing"));
    }
}

#[tokio::test]
async fn named_view_generated_retained_single_long_value_is_unknown_without_changing_frozen_rows() {
    let (f, home) = checkpoint_world().await;
    let p = host_candidate(&f, &home).await;
    let pin = retain_candidate(&f, &p).await; // Canonical fixture, no producer/gate needed.
    let q = retained_query(&p, &pin);
    let before = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &q)
        .await
        .unwrap();
    f.import("vocabulary_values", "long-token", Some(json!({"id":"long-token","vocabulary_id":"priority","value":"x".repeat(513),"status":"active","alias_of":null}))).await;
    let after = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &q)
        .await
        .unwrap();
    assert_eq!(after["rows"], before["rows"]);
    assert_eq!(
        after["view_provenance"]["generated_source_drift"][&pin.revision_id],
        "unknown"
    );
    assert_eq!(
        after["view_provenance"]["generated_unknown_reason"][&pin.revision_id],
        "budget"
    );
    // A zero-row query still reports the retained-source diagnostic.
    let mut empty = q.clone();
    empty.sql = format!("SELECT * FROM {} WHERE 0 ORDER BY id", p.name);
    let empty = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &empty)
        .await
        .unwrap();
    assert_eq!(empty["rows"], json!([]));
    assert_eq!(
        empty["view_provenance"]["generated_source_drift"][&pin.revision_id],
        "unknown"
    );
}

#[tokio::test]
async fn named_view_generated_private_context_refuses_before_source_scan_budget() {
    let f = Fixture::new().await;
    let private = kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    declared(&f, &private).await;
    let p = host_candidate(&f, &private).await;
    let pin = retain_candidate(&f, &p).await;
    super::super::gate::testing(
        true,
        generated_operation(
            &f,
            json!({
                "action":"activate_view","id":f.anchor,"pin":pin,"name":p.name,
                "expected_binding_event_id":null,"idempotency_key":"private-catalog-active",
            }),
        ),
    )
    .await
    .unwrap();
    let viewer = kernel::create_principal(
        &f.db,
        "account",
        "Editor",
        "acct:generated-editor",
        &f.actor,
    )
    .await
    .unwrap();
    let bearer = kernel::read_record_as(&f.db, &f.actor, &f.anchor)
        .await
        .unwrap()
        .unwrap();
    kernel::replace_home_policy(
        &f.db,
        &f.actor,
        &bearer.home_id,
        &[(&f.actor, "manage"), (&viewer, "edit")],
    )
    .await
    .unwrap();
    for (actor, rows) in [
        (&f.actor, json!([{"relation_name":p.name}])),
        (&viewer, json!([])),
    ] {
        let (catalog, trace) = TRACE.scope(std::cell::Cell::new([0;4]), async {
            let catalog = crate::mcp::kernel_v2::sql::query_sql(&f.db, actor,
                json!({"sql":"SELECT relation_name FROM catalog_view_definitions ORDER BY relation_name"})).await.unwrap();
            (catalog,TRACE.with(std::cell::Cell::get))
        }).await;
        assert_eq!(catalog["rows"], rows);
        assert_eq!(trace[Trace::StateFetch as usize], 0);
    }
    let mut tx = f.db.pool().begin().await.unwrap();
    let hidden =
        super::super::details::get_on(&mut tx, &viewer, &pin.view_id, &pin.revision_id, deadline())
            .await
            .err()
            .unwrap()
            .to_string();
    let absent = super::super::details::get_on(
        &mut tx,
        &viewer,
        "native.named-view:absent",
        &pin.revision_id,
        deadline(),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert_eq!(hidden, absent);
    tx.rollback().await.unwrap();
    // Projection damage creates an oversized unrelated cell. The private
    // context must still be missing, without fetching/parsing section payloads.
    sqlx::query("INSERT INTO kernel_v1_state VALUES('schema_config','[\"oversized\"]','fixture',?,NULL,NULL,'2026-10-27T00:00:00Z',1)")
        .bind(serde_json::to_string(&"x".repeat(PREPARE_BYTES+1)).unwrap()).execute(f.db.write_pool()).await.unwrap();
    let (result, trace) = TRACE
        .scope(std::cell::Cell::new([0; 4]), async {
            let result = super::super::generated::prepare(
                &f.db,
                &viewer,
                &f.anchor,
                &p.revision.definition,
                deadline(),
            )
            .await;
            (result, TRACE.with(std::cell::Cell::get))
        })
        .await;
    assert_eq!(result.err().unwrap().to_string(), super::super::MISSING);
    assert_eq!(
        trace[0], 0,
        "no source-state payload was fetched before View"
    );
}

#[tokio::test]
async fn named_view_generated_metadata_list_preserves_authored_sql_availability() {
    let (f, _) = checkpoint_world().await;
    let mut revision = super::super::Revision {
        v: 1,
        view_id: format!("native.named-view:{}", f.anchor),
        definition_sha256: String::new(),
        definition: super::super::testing_definition(),
    };
    // Canonical retained history can outlive the schema/validator that admitted
    // it. No source pin has drifted; only real current SQL analysis catches this.
    revision.definition["query"]["sql"] =
        json!("SELECT no_such_current_column AS id FROM records ORDER BY id");
    revision.definition_sha256 = revision.digest();
    let pin = retain_revision(&f, &revision).await;
    let mut tx = f.db.pool().begin().await.unwrap();
    let inspected = super::super::closure::inspect_metadata_on(
        &mut tx,
        &f.actor,
        &std::collections::BTreeMap::from([("view_invalid_current".into(), pin.clone())]),
        deadline(),
    )
    .await
    .unwrap();
    assert!(!inspected.drifted);
    let list = super::super::details::list_on(&mut tx, &f.actor, &pin.view_id, 8, None, deadline())
        .await
        .unwrap();
    assert_eq!(list["revisions"][0]["available"], false);
    assert_eq!(
        list["revisions"][0]["diagnostic"],
        "view_source_invalidated"
    );
    let detail = super::super::details::get_on(
        &mut tx,
        &f.actor,
        &pin.view_id,
        &pin.revision_id,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(detail["definition"], revision.definition);
    assert_eq!(detail["diagnostic"], list["revisions"][0]["diagnostic"]);
}

#[tokio::test]
async fn named_view_generated_shared_unknown_never_masks_later_missing_source() {
    use super::super::{retained_facets, v2};
    let (f, home) = checkpoint_world().await;
    let area = candidate(&f, &home, &["area"]).await.unwrap();
    let priority = candidate(&f, &home, &["priority"]).await.unwrap();
    let area: v2::Definition = serde_json::from_value(area.revision.definition).unwrap();
    let priority: v2::Definition = serde_json::from_value(priority.revision.definition).unwrap();
    let workspace = area.generated.workspace_id.clone();
    f.import("vocabularies", "priority", None).await;
    let mut tx = f.db.pool().begin().await.unwrap();
    let mut shared = retained_facets::ComparisonSnapshot::default();
    let first = retained_facets::inspect_definition_shared_on(
        &mut tx,
        &f.actor,
        &workspace,
        &f.anchor,
        area,
        deadline(),
        ScanLimits {
            rows: 0,
            bytes: PREPARE_BYTES,
        },
        &mut shared,
    )
    .await
    .unwrap();
    assert_eq!(first.drift, Drift::Unknown);
    assert_eq!(first.unknown_reason, Some(ComparisonReason::Budget));
    let next = retained_facets::inspect_definition_shared_on(
        &mut tx,
        &f.actor,
        &workspace,
        &f.anchor,
        priority,
        deadline(),
        ScanLimits::default(),
        &mut shared,
    )
    .await;
    assert_eq!(next.err().unwrap().to_string(), super::super::MISSING);
}

#[tokio::test]
async fn named_view_generated_shared_scan_deadline_is_not_advisory_unknown() {
    use super::super::{retained_facets, v2};
    let (f, home) = checkpoint_world().await;
    let p = host_candidate(&f, &home).await;
    let definition: v2::Definition = serde_json::from_value(p.revision.definition).unwrap();
    let workspace = definition.generated.workspace_id.clone();
    let mut tx = f.db.pool().begin().await.unwrap();
    let until = deadline();
    let (result, trace) = TRACE
        .scope(
            std::cell::Cell::new([0; 4]),
            SCAN_EXPIRES.scope(std::cell::Cell::new(Some(until)), async {
                let result = retained_facets::inspect_definition_shared_on(
                    &mut tx,
                    &f.actor,
                    &workspace,
                    &f.anchor,
                    definition,
                    until,
                    ScanLimits::default(),
                    &mut retained_facets::ComparisonSnapshot::default(),
                )
                .await;
                (result, TRACE.with(std::cell::Cell::get))
            }),
        )
        .await;
    assert!(
        trace[Trace::StateFetch as usize] > 0,
        "deadline must expire inside the scan"
    );
    assert!(result.err().unwrap().to_string().contains("deadline"));
}
