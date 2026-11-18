use super::*;
use crate::mcp::{register_surface_tools, Caller, ToolRegistry};
use crate::standby::act_cut::read_authority_act_cut;
use crate::standby::act_delta::{build_authority_act_delta, validate_authority_act_delta};
use crate::standby::act_materialise::{
    apply_authority_act_delta_and_finalize_head, TrustedAuthorityActDelta,
};
use serde_json::json;
use std::time::{Duration, Instant};

fn integrity(c: &Connection) {
    for table in ["records_fts", "records_name_idx"] {
        c.execute_batch(&format!(
            "INSERT INTO {table}({table},rank) VALUES('integrity-check',1);"
        ))
        .unwrap();
    }
}
// Exact, storage-class-aware ordinary-row hash; FTS physical layout is intentionally excluded.
fn hashes(c: &Connection) -> BTreeMap<String, String> {
    use rusqlite::types::ValueRef;
    use sha2::{Digest, Sha256};
    let mut catalog: Vec<_> = catalog(c)
        .unwrap()
        .into_iter()
        .map(|t| (t.name, !t.rowid))
        .collect();
    catalog.push(("sqlite_sequence".into(), false));
    catalog
        .into_iter()
        .map(|(table, wr)| {
            let cols: Vec<(String, i64)> = c
                .prepare(&format!("PRAGMA table_info({})", ident(&table)))
                .unwrap()
                .query_map([], |r| Ok((r.get(1)?, r.get(5)?)))
                .unwrap()
                .map(std::result::Result::unwrap)
                .collect();
            let order = if wr {
                cols.iter()
                    .filter(|(_, pk)| *pk > 0)
                    .map(|(n, _)| ident(n))
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                "_rowid_".into()
            };
            let fields = if wr { "*" } else { "_rowid_,*" };
            let mut stmt = c
                .prepare(&format!(
                    "SELECT {fields} FROM {} ORDER BY {order}",
                    ident(&table)
                ))
                .unwrap();
            let width = stmt.column_count();
            let mut rows = stmt.query([]).unwrap();
            let mut h = Sha256::new();
            while let Some(row) = rows.next().unwrap() {
                h.update([0xff]);
                for i in 0..width {
                    match row.get_ref(i).unwrap() {
                        ValueRef::Null => h.update([0]),
                        ValueRef::Integer(v) => {
                            h.update([1]);
                            h.update(v.to_le_bytes());
                        }
                        ValueRef::Real(v) => {
                            h.update([2]);
                            h.update(v.to_bits().to_le_bytes());
                        }
                        ValueRef::Text(v) => {
                            h.update([3]);
                            h.update((v.len() as u64).to_le_bytes());
                            h.update(v);
                        }
                        ValueRef::Blob(v) => {
                            h.update([4]);
                            h.update((v.len() as u64).to_le_bytes());
                            h.update(v);
                        }
                    }
                }
            }
            (table, format!("{:x}", h.finalize()))
        })
        .collect()
}
fn logical(c: &Connection) -> BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    // Domain projections, with timestamps and generated association identities removed.
    [
        ("records","SELECT json_array(id,type,kind,name,body,home_id,lifecycle,owner_id,policy_anchor_id,persistence,maturity,summary,archived,is_current,successor_count,deleted_at IS NOT NULL) FROM records ORDER BY id"),
        ("links","SELECT json_array(source_id,target_id,relationship,note) FROM links ORDER BY source_id,target_id,relationship,note"),
        ("facets","SELECT json_array(record_id,key,value,vocab_ref) FROM facet_values ORDER BY record_id,key,value"),
        ("act","SELECT CAST(next_act AS TEXT) FROM act_state"),
    ].into_iter().map(|(name,sql)| {
        let mut h=Sha256::new();
        for value in c.prepare(sql).unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap() {
            let value=value.unwrap(); h.update((value.len() as u64).to_le_bytes()); h.update(value.as_bytes());
        }
        (name.into(),format!("{:x}",h.finalize()))
    }).collect()
}

async fn tool(reg: &ToolRegistry, db: &Db, caller: &Caller, op: &str, args: Value) -> Value {
    let result = reg
        .call(db.clone(), caller.clone(), op, args)
        .await
        .unwrap();
    db.drain_captures().await;
    result
}
fn note(n: usize) -> Value {
    let id = Uuid::new_v4().to_string();
    json!({"id":id,"type":"Document","kind":"note","name":format!("Pending rebase {n}"),"body":"productionrebase","reason":"Private rebase qualification","run_key":"scout-chair-k748b2","idempotency_key":format!("node-production-rebase-{id}-{n}")})
}

async fn head(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT next_act FROM act_state")
        .fetch_one(db.pool())
        .await
        .unwrap()
}
async fn cut(db: &Db, from: i64) -> TrustedAuthorityActDelta {
    let to = head(db).await;
    let cut = read_authority_act_cut(db, from, to).await.unwrap();
    let d = validate_authority_act_delta(&build_authority_act_delta(&cut).unwrap()).unwrap();
    let origin = d.authority_head().origin_database_id().to_string();
    TrustedAuthorityActDelta::assume_trusted_for_test(d, &origin, from, to).unwrap()
}
async fn vacuum(db: &Db, path: &Path) {
    sqlx::query("VACUUM INTO ?")
        .bind(path.to_str().unwrap())
        .execute(db.pool())
        .await
        .unwrap();
}
struct Fixture {
    dir: tempfile::TempDir,
    authority: Db,
    base: Db,
    manager: Arc<ForkManager>,
    key: ForkKey,
    caller: Caller,
    reg: ToolRegistry,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let authority = crate::create_database(dir.path().join("authority.db").to_str().unwrap())
            .await
            .unwrap();
        Self::from_authority(dir, authority, None).await
    }
    async fn from_authority(
        dir: tempfile::TempDir,
        authority: Db,
        account: Option<String>,
    ) -> Self {
        let account = match account {
            Some(a) => a,
            None => crate::identity::resolve_stdio_account_identity(&authority, None)
                .await
                .unwrap(),
        };
        let caller = Caller::for_node_pending_fork(account, "pending-test".into());
        let mut reg = ToolRegistry::new();
        register_surface_tools(&mut reg).unwrap();
        tool(
            &reg,
            &authority,
            &caller,
            "set_intent",
            json!({"run_key":"scout-chair-k748b2","intent":"Qualify production pending rebase"}),
        )
        .await;
        let path = dir.path().join("accepted.db");
        vacuum(&authority, &path).await;
        let base = crate::db::open_current_database_wal_read_only_at(&path)
            .await
            .unwrap();
        let manager = ForkManager::new(
            ForkArea::new(dir.path(), std::slice::from_ref(&path)).unwrap(),
            ForkLimits {
                max_forks: 1,
                max_reserved_bytes: 16 * 1024 * 1024 * 1024,
                growth_bytes: 128 * 1024 * 1024,
                ..Default::default()
            },
        )
        .unwrap();
        let key = ForkKey {
            window_id: "stable-generation-account".into(),
            workspace_id: "pending-test".into(),
        };
        manager.prepare(key.clone(), base.clone()).await.unwrap();
        while manager.state(&key).await == ForkState::Preparing {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(manager.state(&key).await, ForkState::Ready);
        manager.enable_rebase(&key).await.unwrap();
        Self {
            dir,
            authority,
            base,
            manager,
            key,
            caller,
            reg,
        }
    }
    async fn work(&self) -> Db {
        self.manager.test_working_db(&self.key).await.unwrap()
    }
    async fn dispatch(&self, operation: &str, args: Value) -> PreparedCall {
        let call = self
            .manager
            .prepare_call(&self.key, &self.caller, operation, args)
            .await
            .unwrap();
        self.replay(&call).await;
        call
    }
    async fn replay(&self, call: &PreparedCall) {
        let outcome = self
            .manager
            .dispatch(&self.key, &self.caller, call)
            .await
            .unwrap();
        self.manager
            .confirm_journaled(&self.key, &outcome)
            .await
            .unwrap();
    }
    async fn accept(&self, delta: &TrustedAuthorityActDelta) {
        let writer = crate::db::open_standby_head_writer(self.base.path())
            .await
            .unwrap();
        apply_authority_act_delta_and_finalize_head(&writer, delta)
            .await
            .unwrap();
        writer.close().await;
        self.manager
            .rebase_accepted(&self.key, delta, "fixture-journal-revision")
            .await
            .unwrap();
    }
    async fn close(self) {
        self.manager.discard(&self.key).await.unwrap();
        self.base.close().await;
        self.authority.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_capture_restores_every_ordinary_row_and_sequence() {
    let f = Fixture::new().await;
    let db = f.work().await;
    let before = hashes(&Connection::open(db.path()).unwrap());
    f.dispatch("create_record", note(0)).await;
    let slot = f.manager.entry(&f.key).await.unwrap();
    let entry = slot.inner.lock().await;
    let capture = entry.handle.as_ref().unwrap().capture.as_ref().unwrap();
    db.drain_captures().await;
    capture.undo().await.unwrap();
    assert_eq!(before, hashes(&Connection::open(db.path()).unwrap()));
    integrity(&Connection::open(db.path()).unwrap());
    drop(entry);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_and_pending_append_conform_to_fresh_copy_and_clear_caches() {
    let f = Fixture::new().await;
    let args = note(1000);
    let id = args["id"].as_str().unwrap();
    // Establish the common note with a first accepted delta.
    let from = head(&f.authority).await;
    tool(
        &f.reg,
        &f.authority,
        &f.caller,
        "create_record",
        args.clone(),
    )
    .await;
    f.accept(&cut(&f.authority, from).await).await;
    f.manager
        .finish_rebase(&f.key, head(&f.authority).await, "setup")
        .await
        .unwrap();
    let pending = json!({"id":id,"body_append":" pending","reason":"pending append","run_key":"scout-chair-k748b2","idempotency_key":"pending-append"});
    let call = f.dispatch("update_record", pending.clone()).await;
    let db = f.work().await;
    let handle = db.handle_id();
    db.ensure_workspace_index().await.unwrap();
    assert!(db.workspace_index_built_for_tests().await);
    let cached = tool(&f.reg, &db, &f.caller, "get_record", json!({"id":id})).await;
    assert!(cached.to_string().contains(" pending"));
    let from = head(&f.authority).await;
    tool(&f.reg,&f.authority,&f.caller,"update_record",json!({"id":id,"body_append":" accepted","reason":"accepted append","run_key":"scout-chair-k748b2"})).await;
    f.accept(&cut(&f.authority, from).await).await;
    assert!(!db.workspace_index_built_for_tests().await);
    assert_eq!(f.work().await.handle_id(), handle);
    f.replay(&call).await;
    f.manager
        .finish_rebase(&f.key, head(&f.authority).await, "new-journal")
        .await
        .unwrap();
    let result = tool(&f.reg, &db, &f.caller, "get_record", json!({"id":id})).await;
    assert!(result.to_string().contains(" accepted pending"), "{result}");
    let rp = f.dir.path().join("reference.db");
    vacuum(&f.authority, &rp).await;
    let reference = crate::db::open_existing_database_at(&rp).await.unwrap();
    tool(&f.reg, &reference, &f.caller, "update_record", pending).await;
    assert_eq!(
        logical(&Connection::open(db.path()).unwrap()),
        logical(&Connection::open(&rp).unwrap())
    );
    integrity(&Connection::open(db.path()).unwrap());
    reference.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_create_is_not_replayed_and_remaining_preview_survives() {
    let f = Fixture::new().await;
    let accepted = f.dispatch("create_record", note(1)).await;
    let remaining = f.dispatch("create_record", note(2)).await;
    let from = head(&f.authority).await;
    tool(
        &f.reg,
        &f.authority,
        &f.caller,
        "create_record",
        accepted.arguments().clone(),
    )
    .await;
    f.accept(&cut(&f.authority, from).await).await;
    // The node's receipt retirement removes accepted from its retained journal.
    f.replay(&remaining).await;
    assert_eq!(head(&f.work().await).await, head(&f.authority).await + 1);
    assert_eq!(
        f.manager.touched_record_ids(&f.key).await.unwrap(),
        vec![remaining.arguments()["id"].as_str().unwrap().to_owned()]
    );
    f.close().await;
}

struct Empty;
impl OrderedJournaledCalls for Empty {
    fn ordered_calls<'a>(
        &'a self,
        _: &'a ForkKey,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::Result<Vec<PreparedCall>>> + Send + 'a>,
    > {
        Box::pin(async { Ok(vec![]) })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inverse_conflict_and_capture_gap_use_full_rebuild() {
    for gap in [false, true] {
        let f = Fixture::new().await;
        let args = note(0);
        let call = f.dispatch("create_record", args.clone()).await;
        let db = f.work().await;
        let old_handle = db.handle_id();
        let c = Connection::open(db.path()).unwrap();
        if gap {
            c.execute_batch("UPDATE _node_pending_control SET enabled=0;")
                .unwrap();
        } else {
            c.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                false,
            )
            .unwrap();
            c.execute(
                "UPDATE records SET body='unobserved' WHERE id=?",
                [args["id"].as_str().unwrap()],
            )
            .unwrap();
        }
        drop(c);
        let from = head(&f.authority).await;
        tool(&f.reg, &f.authority, &f.caller, "create_record", note(10)).await;
        let delta = cut(&f.authority, from).await;
        let writer = crate::db::open_standby_head_writer(f.base.path())
            .await
            .unwrap();
        apply_authority_act_delta_and_finalize_head(&writer, &delta)
            .await
            .unwrap();
        writer.close().await;
        assert!(f
            .manager
            .rebase_accepted(&f.key, &delta, "j")
            .await
            .is_err());
        assert_eq!(f.manager.state(&f.key).await, ForkState::Dirty);
        assert!(db
            .path()
            .parent()
            .unwrap()
            .join("rebase-in-progress")
            .exists());
        f.manager.rebuild(&f.key, &Empty).await.unwrap();
        f.manager.enable_rebase(&f.key).await.unwrap();
        assert_ne!(f.work().await.handle_id(), old_handle);
        f.replay(&call).await;
        assert_eq!(head(&f.work().await).await, head(&f.authority).await + 1);
        integrity(&Connection::open(f.work().await.path()).unwrap());
        f.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_with_marker_discards_and_reconstructs() {
    let f = Fixture::new().await;
    let call = f.dispatch("create_record", note(0)).await;
    let work = f.work().await;
    let old_path = work.path().to_path_buf();
    std::fs::write(
        old_path.parent().unwrap().join("rebase-in-progress"),
        b"interrupted",
    )
    .unwrap();
    work.close().await;
    let Fixture {
        dir,
        authority,
        base,
        manager,
        key,
        caller,
        reg: _,
    } = f;
    drop(manager);
    let manager = ForkManager::new(
        ForkArea::new(dir.path(), &[base.path().to_path_buf()]).unwrap(),
        ForkLimits {
            max_forks: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!old_path.exists());
    manager.prepare(key.clone(), base.clone()).await.unwrap();
    while manager.state(&key).await == ForkState::Preparing {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    manager.enable_rebase(&key).await.unwrap();
    let outcome = manager.dispatch(&key, &caller, &call).await.unwrap();
    manager.confirm_journaled(&key, &outcome).await.unwrap();
    assert_eq!(
        outcome.touched_record_ids,
        vec![call.arguments()["id"].as_str().unwrap().to_owned()]
    );
    manager.discard(&key).await.unwrap();
    base.close().await;
    authority.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_refusal_preserves_ready_state_and_other_previews() {
    let f = Fixture::new().await;
    let target = note(1000);
    let id = target["id"].as_str().unwrap();
    let from = head(&f.authority).await;
    tool(
        &f.reg,
        &f.authority,
        &f.caller,
        "create_record",
        target.clone(),
    )
    .await;
    f.accept(&cut(&f.authority, from).await).await;
    f.manager
        .finish_rebase(&f.key, head(&f.authority).await, "setup")
        .await
        .unwrap();
    let append=f.dispatch("update_record",json!({"id":id,"body_append":" pending","reason":"pending","run_key":"scout-chair-k748b2","idempotency_key":"refused-append"})).await;
    let survivor = f.dispatch("create_record", note(0)).await;
    let from = head(&f.authority).await;
    tool(
        &f.reg,
        &f.authority,
        &f.caller,
        "delete_record",
        json!({"id":id,"reason":"accepted deletion","run_key":"scout-chair-k748b2"}),
    )
    .await;
    f.accept(&cut(&f.authority, from).await).await;
    // Domain/target refusal remains typed and cannot poison another command.
    assert!(matches!(
        f.manager.dispatch(&f.key, &f.caller, &append).await,
        Err(ForkError::RefusedInvalid(_)) | Err(ForkError::RefusedUnsupported(_))
    ));
    assert_eq!(f.manager.state(&f.key).await, ForkState::Ready);
    f.replay(&survivor).await;
    assert!(f
        .manager
        .touched_record_ids(&f.key)
        .await
        .unwrap()
        .contains(&survivor.arguments()["id"].as_str().unwrap().to_owned()));
    f.close().await;
}

/// Explicit qualification only. The supplied path must already be a plain-file
/// copy; this harness makes another private copy before opening any SQLite API.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual production rebase measurement; requires a private copied generation"]
async fn production_copy_free_rebase_costs() {
    let source = std::env::var("NATIVE_NODE_FORK_BENCH_DB").expect("already copied generation");
    for acts in [1, 50] {
        for n in [1, 10, 100] {
            let dir = tempfile::tempdir().unwrap();
            let authority_path = dir.path().join("authority.db");
            std::fs::copy(&source, &authority_path).unwrap();
            let authority = crate::db::open_existing_database_at(&authority_path)
                .await
                .unwrap();
            let account = crate::mcp::standby_stdio::resolve_standby_account_identity(
                &authority,
                std::env::var("NATIVE_NODE_FORK_BENCH_ACCOUNT")
                    .ok()
                    .as_deref(),
            )
            .await
            .unwrap();
            let f = Fixture::from_authority(dir, authority, Some(account)).await;
            let mut calls = vec![];
            for i in 0..n {
                calls.push(f.dispatch("create_record", note(i)).await);
            }
            let work = f.work().await;
            let handle = work.handle_id();
            let from = head(&f.authority).await;
            for i in 0..acts {
                tool(
                    &f.reg,
                    &f.authority,
                    &f.caller,
                    "create_record",
                    note(1000 + i),
                )
                .await;
            }
            let delta = cut(&f.authority, from).await;
            assert_eq!(
                delta.to_inclusive_act() - delta.from_exclusive_act(),
                acts as i64
            );
            let writer = crate::db::open_standby_head_writer(f.base.path())
                .await
                .unwrap();
            apply_authority_act_delta_and_finalize_head(&writer, &delta)
                .await
                .unwrap();
            writer.close().await;
            let snapshot = serde_json::to_string(
                &calls
                    .iter()
                    .map(|call| json!({"operation":call.operation(),"arguments":call.arguments()}))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let start = Instant::now();
            f.manager
                .rebase_accepted(&f.key, &delta, &snapshot)
                .await
                .unwrap();
            let rebase = start.elapsed();
            for call in &calls {
                f.replay(call).await;
            }
            f.manager
                .finish_rebase(&f.key, delta.to_inclusive_act(), &snapshot)
                .await
                .unwrap();
            let total = start.elapsed();
            eprintln!("NODE_PRODUCTION_REBASE acts={acts} n={n} undo_apply_ms={:.3} replay_publish_ms={:.3} total_ms={:.3}",rebase.as_secs_f64()*1000.,(total-rebase).as_secs_f64()*1000.,total.as_secs_f64()*1000.);
            assert_eq!(work.handle_id(), handle);
            assert_eq!(f.manager.copy_count_for_test(), 1);
            let rp = f.dir.path().join("reference.db");
            let start = Instant::now();
            vacuum(&f.authority, &rp).await;
            let reference = crate::db::open_existing_database_at(&rp).await.unwrap();
            for call in &calls {
                tool(
                    &f.reg,
                    &reference,
                    &f.caller,
                    call.operation(),
                    call.arguments().clone(),
                )
                .await;
            }
            eprintln!(
                "NODE_PRODUCTION_REBASE_REFERENCE acts={acts} n={n} copy_replay_ms={:.3}",
                start.elapsed().as_secs_f64() * 1000.
            );
            assert_eq!(
                logical(&Connection::open(work.path()).unwrap()),
                logical(&Connection::open(&rp).unwrap())
            );
            integrity(&Connection::open(work.path()).unwrap());
            reference.close().await;
            f.close().await;
        }
    }
}

#[test]
fn replace_conflict_policies_are_unsupported() {
    for ddl in [
        "CREATE TABLE bad(id INTEGER PRIMARY KEY ON CONFLICT REPLACE)",
        "CREATE TABLE bad(id INTEGER PRIMARY KEY ON CONFLICT /* policy */ REPLACE)",
        "CREATE TABLE bad(id INTEGER PRIMARY KEY); CREATE TRIGGER bad_replace AFTER INSERT ON bad BEGIN INSERT OR /* policy */ REPLACE INTO bad VALUES(new.id+1); END",
        "CREATE TABLE bad(id INTEGER PRIMARY KEY); CREATE TRIGGER bad_replace AFTER INSERT ON bad BEGIN INSERT OR REPLACE INTO bad VALUES(new.id+1); END",
        "CREATE TABLE bad(id INTEGER PRIMARY KEY); CREATE TRIGGER bad_replace AFTER INSERT ON bad BEGIN REPLACE INTO bad VALUES(new.id+1); END",
    ] {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(ddl).unwrap();
        assert!(reject_replace(&c).unwrap_err().to_string().contains("unsupported REPLACE"));
    }
    let safe = Connection::open_in_memory().unwrap();
    safe.execute_batch("CREATE TABLE safe(id INTEGER PRIMARY KEY, body TEXT DEFAULT 'OR REPLACE -- /* ''quoted'' */');").unwrap();
    reject_replace(&safe).unwrap();
}
#[test]
fn journal_binding_contains_digest_and_counts_without_payload() {
    let snapshot = r#"[{"body":"private note body"},{"body":"another body"}]"#;
    let binding = journal_binding(snapshot);
    assert_eq!(binding["entries"], 2);
    assert_eq!(binding["bytes"], snapshot.len());
    assert_eq!(
        binding["sha256"],
        hex::encode(Sha256::digest(snapshot.as_bytes()))
    );
    assert!(!binding.to_string().contains("private note"));
    assert!(!journal_binding("[]")["sha256"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn eligible_note_sql_never_uses_replace_conflict_resolution() {
    // Trace the real one-slot production writer, including interaction capture
    // and trigger programs, instead of assuming store helpers cannot change.
    unsafe extern "C" fn trace(
        kind: u32,
        ctx: *mut std::ffi::c_void,
        _: *mut std::ffi::c_void,
        sql: *mut std::ffi::c_void,
    ) -> i32 {
        if kind == rusqlite::ffi::SQLITE_TRACE_STMT as u32 && !sql.is_null() {
            let list = &*(ctx as *const std::sync::Mutex<Vec<String>>);
            let text = std::ffi::CStr::from_ptr(sql.cast())
                .to_string_lossy()
                .into_owned();
            list.lock().unwrap_or_else(|e| e.into_inner()).push(text);
        }
        0
    }
    let f = Fixture::new().await;
    let db = f.work().await;
    let traces = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    // Pin a separate strong reference for SQLite. If setup/dispatch panics,
    // retain it rather than leave a dangling callback on a live connection.
    let callback_context = Arc::into_raw(traces.clone());
    {
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut handle = connection.lock_handle().await.unwrap();
        unsafe {
            rusqlite::ffi::sqlite3_trace_v2(
                handle.as_raw_handle().as_ptr().cast(),
                rusqlite::ffi::SQLITE_TRACE_STMT as u32,
                Some(trace),
                callback_context.cast_mut().cast(),
            );
        }
    }
    let args = note(780);
    let id = args["id"].as_str().unwrap().to_owned();
    f.dispatch("create_record", args).await;
    f.dispatch("update_record", json!({"id":id,"body_append":" pending","reason":"trace plain append","run_key":"scout-chair-k748b2"})).await;
    db.drain_captures().await;
    {
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut handle = connection.lock_handle().await.unwrap();
        unsafe {
            rusqlite::ffi::sqlite3_trace_v2(
                handle.as_raw_handle().as_ptr().cast(),
                0,
                None,
                std::ptr::null_mut(),
            );
        }
    }
    // SAFETY: the sole writer is locked and its callback has been removed.
    unsafe {
        drop(Arc::from_raw(callback_context));
    }
    let connection = Connection::open(db.path()).unwrap();
    let shadows: BTreeSet<String> = connection
        .prepare("SELECT name FROM pragma_table_list WHERE schema='main' AND type='shadow'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(std::result::Result::unwrap)
        .collect();
    {
        let traces = traces.lock().unwrap();
        assert!(
            traces
                .iter()
                .any(|sql| sql.to_ascii_lowercase().contains("insert into records")),
            "writer trace missing: {traces:?}"
        );
        for sql in traces.iter() {
            let normalized = sql
                .to_ascii_uppercase()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if normalized.contains("OR REPLACE") || normalized.contains("REPLACE INTO") {
                let target = sql
                    .split_whitespace()
                    .skip_while(|word| !word.eq_ignore_ascii_case("INTO"))
                    .nth(1)
                    .unwrap_or("")
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .rsplit('.')
                    .next()
                    .unwrap_or("")
                    .trim_matches(['\'', '"', '`', '[', ']']);
                assert!(
                    sql.starts_with("-- ") && shadows.contains(target),
                    "eligible operation uses REPLACE outside verified FTS shadows: {sql}"
                );
            }
        }
    }
    f.manager.discard(&f.key).await.unwrap();
}
