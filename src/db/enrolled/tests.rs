//! Real SQLite/registered MCP consumers. Local Caller is bootstrap-only;
//! tested updates use account Edit policy and authenticated Callers.
use super::*;
use crate::authorization::{AllowEntry, Capability};
use crate::mcp::{Caller, ToolRegistry};
use serde_json::{json, Value};

struct Fixture {
    _root: Arc<tempfile::TempDir>,
    db: Db,
    path: std::path::PathBuf,
    id: String,
    instruction: String,
    runtime: String,
    registry: Arc<ToolRegistry>,
}
#[derive(Clone, Copy)]
enum Setup {
    Ordinary,
    MissingPack,
    VocabularyCollision,
    MissingGloss,
    ArtifactAlias,
    Strict,
    RequiredFacet,
}
impl Fixture {
    async fn new(needs_reconciliation: bool) -> Self {
        Self::configured(if needs_reconciliation {
            Setup::MissingPack
        } else {
            Setup::Ordinary
        })
        .await
    }
    async fn configured(setup: Setup) -> Self {
        let needs_reconciliation = matches!(
            setup,
            Setup::MissingPack | Setup::VocabularyCollision | Setup::MissingGloss
        );
        let root = Arc::new(tempfile::tempdir().unwrap());
        std::fs::create_dir(root.path().join("databases")).unwrap();
        let stage = root.path().join("stage.db");
        let mut source = crate::create_database(stage.to_str().unwrap())
            .await
            .unwrap();
        source._tmp = Some(root.clone());
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let mut ids = Vec::new();
        for (kind, name) in [
            ("note", "body"),
            ("instruction", "excluded"),
            ("note", "runtime"),
        ] {
            // Test-owned bootstrap while storage remains ordinary.
            let created = registry.call(source.clone(), Caller::local(), "create_record", json!({
                "type":"Document","kind":kind,"name":name,"body":"seed 🐋汉e\u{301}\r\n", "reason":"test bootstrap"
            })).await.unwrap();
            let id = created["id"].as_str().unwrap().to_owned();
            crate::authorization::replace_explicit_policy(
                &source,
                "test:bootstrap",
                &id,
                vec![AllowEntry::account("acct:alice", Capability::Edit)],
            )
            .await
            .unwrap();
            ids.push(id);
        }
        // This explicitly pre-enrollment row tests the transaction-side
        // runtime exclusion without pretending to provision executable code.
        sqlx::query("INSERT INTO facet_values(id,record_id,key,value) VALUES ('test-runtime-facet',?,'runtime','\"test-only\"')")
            .bind(&ids[2]).execute(source.write_pool()).await.unwrap();
        if matches!(setup, Setup::MissingPack) {
            sqlx::query("DELETE FROM schema_config WHERE id LIKE 'pack:%'")
                .execute(source.write_pool())
                .await
                .unwrap();
        }
        match setup {
            Setup::VocabularyCollision => {
                // The wrong id's NAME equals the canonical id. Keep all expected
                // value ids present: the former id-or-name check accepted it.
                let vid = crate::meta::vocabulary::vocabulary_id("lifecycle");
                sqlx::query(
                    "UPDATE vocabularies SET name='test:temporarily-reparenting' WHERE id=?",
                )
                .bind(&vid)
                .execute(source.write_pool())
                .await
                .unwrap();
                // FK-safe reparenting avoids deleting the seeded value ids.
                sqlx::query("INSERT INTO vocabularies(id,name,created_at) SELECT 'test:wrong-vocabulary',?,created_at FROM vocabularies WHERE id=?")
                    .bind(&vid).bind(&vid).execute(source.write_pool()).await.unwrap();
                sqlx::query("UPDATE vocabulary_values SET vocabulary_id='test:wrong-vocabulary' WHERE vocabulary_id=?")
                    .bind(&vid).execute(source.write_pool()).await.unwrap();
                sqlx::query("DELETE FROM vocabularies WHERE id=?")
                    .bind(&vid)
                    .execute(source.write_pool())
                    .await
                    .unwrap();
            }
            Setup::MissingGloss => {
                sqlx::query(
                    "UPDATE vocabulary_values SET gloss=NULL WHERE id='vv:voc:lifecycle:open'",
                )
                .execute(source.write_pool())
                .await
                .unwrap();
            }
            Setup::ArtifactAlias => {
                let vid = crate::meta::kind::kind_vocabulary_id("Document");
                let target: String = sqlx::query_scalar(
                    "SELECT id FROM vocabulary_values WHERE vocabulary_id=? AND value='artifact'",
                )
                .bind(&vid)
                .fetch_one(source.pool())
                .await
                .unwrap();
                sqlx::query("INSERT INTO vocabulary_values(id,vocabulary_id,value,status,alias_of) VALUES ('test:artifact-alias',?,'test_artifact_alias','active',?)")
                    .bind(vid).bind(target).execute(source.write_pool()).await.unwrap();
                sqlx::query("UPDATE records SET kind='test_artifact_alias' WHERE id=?")
                    .bind(&ids[0])
                    .execute(source.write_pool())
                    .await
                    .unwrap();
            }
            Setup::RequiredFacet => {
                sqlx::query("INSERT INTO schema_config(id,layer,data) VALUES ('test:required-shape','user',?)")
                    .bind(json!({"shapes":{"Document":{"facets":{"test_required":{"required":true}}}}}).to_string())
                    .execute(source.write_pool()).await.unwrap();
                sqlx::query("INSERT INTO facet_values(id,record_id,key,value) VALUES ('test:required-present',?,'test_required','\"retained\"')")
                    .bind(&ids[0]).execute(source.write_pool()).await.unwrap();
            }
            Setup::Strict => {
                crate::storage_profile::update_portability_policy(
                    &source,
                    crate::storage_profile::PortabilityPolicyUpdate {
                        if_policy_revision: 0,
                        enforcement: crate::storage_profile::PortabilityEnforcement::Strict,
                        target_profiles: vec![crate::storage_profile::StorageTarget {
                            id: "postgres-server".into(),
                            revision: 5,
                            mode: "network".into(),
                        }],
                        allow_conversions: vec![],
                    },
                )
                .await
                .unwrap();
            }
            _ => {}
        }
        source.drain_captures_for_tests().await;
        super::super::checkpoint_and_close_hosted_adoption_database(source)
            .await
            .unwrap();
        let generation = uuid::Uuid::new_v4().to_string();
        let path = root
            .path()
            .join("databases")
            .join(format!("{generation}.db"));
        let enrollment =
            crate::managed_custody::reserve_fresh_adoption(root.path(), &path, &generation)
                .unwrap();
        std::fs::copy(stage, &path).unwrap();
        enrollment.finalize().unwrap();
        // Constructor rejection is tested separately; this raw open does not
        // seed or alter enrolled metadata and is used only to inspect refusal.
        let mut db = if needs_reconciliation {
            super::super::open_existing_database_standby_read_only(path.to_str().unwrap())
                .await
                .unwrap()
        } else {
            super::super::open_existing_database_at(&path)
                .await
                .unwrap()
        };
        db._tmp = Some(root.clone());
        Self {
            _root: root,
            db,
            path,
            id: ids[0].clone(),
            instruction: ids[1].clone(),
            runtime: ids[2].clone(),
            registry: Arc::new(registry),
        }
    }
    async fn open_peer(&self) -> Db {
        let mut db = super::super::open_existing_database_at(&self.path)
            .await
            .unwrap();
        db._tmp = Some(self._root.clone());
        db
    }
    fn args(&self, append: &str) -> Value {
        json!({"id":self.id,"body_append":append,"reason":"test ordinary body change"})
    }
    async fn update(&self, arguments: Value) -> Result<Value> {
        self.registry
            .call(
                self.db.clone(),
                Caller::authenticated("acct:alice"),
                "update_record",
                arguments,
            )
            .await
    }
    async fn body(&self) -> String {
        sqlx::query_scalar::<_, Option<String>>("SELECT body FROM records WHERE id=?")
            .bind(&self.id)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
            .unwrap()
    }
    async fn events(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
}

fn gate(phase: Phase) -> (Arc<TestGate>, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    (
        Arc::new(TestGate {
            phase,
            entered: Mutex::new(Some(tx)),
            release: tokio::sync::Semaphore::new(0),
            outcome: Mutex::new(None),
            writer_close_ack: AtomicBool::new(false),
        }),
        rx,
    )
}
// Failure evidence is bounded and observational: never wait on the runner's
// locks or turn replacement pool housekeeping into a physical writer ACK.
fn cleanup_evidence(db: &Db, gate: &TestGate) -> String {
    let owner = db.execution_owner.as_ref().unwrap();
    let retained = owner.retained.try_lock().ok().map(|entries| {
        let admissions = entries
            .values()
            .take(JOB_CAPACITY)
            .map(|entry| {
                entry
                    .admissions
                    .try_lock()
                    .ok()
                    .map(|slot| usize::from(slot.is_some()))
            })
            .collect::<Option<Vec<_>>>()
            .map(|counts| counts.into_iter().sum::<usize>());
        (entries.len(), admissions)
    });
    format!(
        "writer_close_ack={}, accepted={}, retained(entries,admissions)={retained:?}, capture={:?}",
        gate.writer_close_ack.load(Ordering::Acquire),
        owner.accepted.load(Ordering::Acquire),
        db.capture_stats()
    )
}

async fn reached(rx: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("phase was not reached")
        .unwrap();
}
async fn accepted(owner: &ExecutionOwner, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let notified = owner.submitted.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if owner.accepted.load(Ordering::Acquire) == count {
                break;
            }
            notified.await;
        }
    })
    .await
    .expect("job was not accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_human_agent_body_projection_receipt_and_capture() {
    let fixture = Fixture::new(false).await;
    let issuer = crate::provenance::ProvenanceInteractionTokenIssuer::random("test-ui");
    let mut arguments = fixture.args("\r\n## Exact 🦀中文\r\n- [ ] task\r\n");
    arguments["if_body_digest"] = json!(hex::encode(sha2::Sha256::digest(
        fixture.body().await.as_bytes()
    )));
    arguments["run_key"] = json!("trowel-humid-8fx435");
    arguments["parent_key"] = json!("prairie-nail-1vd19r");
    let scope = crate::provenance::verified_action_scope("update_record", &arguments);
    let token = issuer.issue("acct:alice", &scope, 60).unwrap();
    let human = Caller::authenticated("acct:alice")
        .with_provenance_interaction_token(&issuer, &token, &scope)
        .unwrap();
    let result = fixture
        .registry
        .call(fixture.db.clone(), human, "update_record", arguments)
        .await
        .unwrap();
    let receipt = result["action_attestation_ids"][0].as_str().unwrap();
    let kind: String =
        sqlx::query_scalar("SELECT executor_kind FROM provenance_action_attestations WHERE id=?")
            .bind(receipt)
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
    assert_eq!(kind, "human");
    let annotations: (Option<String>,Option<String>) = sqlx::query_as("SELECT run_key,parent_key FROM content_events WHERE record_id=? AND type='record.updated' ORDER BY seq DESC LIMIT 1")
        .bind(&fixture.id).fetch_one(fixture.db.pool()).await.unwrap();
    assert_eq!(
        annotations,
        (
            Some("trowel-humid-8fx435".into()),
            Some("prairie-nail-1vd19r".into())
        )
    );

    let issuer = crate::awareness::HumanInteractionTokenIssuer::random("test-ui");
    let ids = vec!["message:test".to_owned()];
    let token = issuer
        .issue("acct:alice", "agent-executor:exec:deleg", &ids, 60)
        .unwrap();
    let agent = Caller::authenticated("acct:alice")
        .with_agent_executor_token(&issuer, &token, "exec", "deleg", &ids)
        .unwrap();
    let arguments = fixture.args("e\u{301}\r\n");
    let result = fixture
        .registry
        .call(fixture.db.clone(), agent, "update_record", arguments)
        .await
        .unwrap();
    let receipt = result["action_attestation_ids"][0].as_str().unwrap();
    let kind: String =
        sqlx::query_scalar("SELECT executor_kind FROM provenance_action_attestations WHERE id=?")
            .bind(receipt)
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
    assert_eq!(kind, "agent");
    assert_eq!(
        fixture.body().await,
        "seed 🐋汉e\u{301}\r\n\r\n## Exact 🦀中文\r\n- [ ] task\r\ne\u{301}\r\n"
    );
    let task_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM body_task_items WHERE record_id=?")
            .bind(&fixture.id)
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
    assert_eq!(task_count, 1, "real body task projection is retained");
    let before_refusal = fixture.events().await;
    let body_before_refusal = fixture.body().await;
    let mut stale = fixture.args(" must not persist after stale CAS");
    stale["if_unmodified_since"] = json!("2000-01-01T00:00:00.000Z");
    let refusal = fixture.update(stale).await.unwrap_err();
    assert!(
        refusal.to_string().contains("stale write conflict"),
        "{refusal}"
    );
    assert_eq!(fixture.events().await, before_refusal);
    assert_eq!(fixture.body().await, body_before_refusal);
    fixture
        .registry
        .call(
            fixture.db.clone(),
            Caller::authenticated("acct:alice"),
            "get_record",
            json!({"id":fixture.id}),
        )
        .await
        .unwrap();
    fixture.db.drain_captures_for_tests().await;
    let calls: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE actor='acct:alice'")
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
    let touches: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_touches t JOIN read_log_record_ids r ON t.record_ref=r.record_ref WHERE r.record_id=?")
        .bind(&fixture.id).fetch_one(fixture.db.pool()).await.unwrap();
    let attempts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_calls WHERE actor='acct:alice' AND tool='update_record'",
    )
    .fetch_one(fixture.db.pool())
    .await
    .unwrap();
    assert_eq!(
        attempts, 3,
        "exactly three registered mutation attempts were submitted"
    );
    let failed_attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE actor='acct:alice' AND tool='update_record' AND outcome='error'")
        .fetch_one(fixture.db.pool()).await.unwrap();
    assert_eq!(
        failed_attempts, 1,
        "the stale CAS attempt is retained without claiming a successful mutation"
    );
    assert_eq!(
        fixture.db.capture_stats().failed,
        0,
        "all three capture writes must succeed, including the refused mutation's envelope"
    );
    let reads: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_calls WHERE actor='acct:alice' AND tool='get_record'",
    )
    .fetch_one(fixture.db.pool())
    .await
    .unwrap();
    assert_eq!(
        reads, 0,
        "pure reads retain the disposable logging contract"
    );
    assert!(
        calls >= 3 && touches >= 1,
        "three retained mutation attempts (two successes plus stale-CAS refusal) must perform real capture dictionary/FK writes; pure get_record is disposable"
    );
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn authentication_cas_shape_and_excluded_routes_refuse_without_content_effects() {
    let fixture = Fixture::new(false).await;
    let before = fixture.events().await;
    let original = fixture.body().await;
    assert!(fixture
        .registry
        .call(
            fixture.db.clone(),
            Caller::authenticated("acct:stranger"),
            "update_record",
            fixture.args("bad")
        )
        .await
        .is_err());
    assert!(fixture.update(json!({"id":fixture.id,"body_append":"bad","reason":"test","if_body_digest":"0000000000000000000000000000000000000000000000000000000000000000"})).await.is_err());
    for args in [
        json!({"id":fixture.id,"name":"bad","body_set":"bad","reason":"test"}),
        json!({"ids":[fixture.id],"body_append":"bad","reason":"test"}),
        json!({"id":fixture.id,"reason":"no-op"}),
        json!({"id":fixture.id,"body_append":"bad","reason":"test","run_key":crate::runkey::SENTINEL}),
        json!({"id":fixture.id,"body_append":"bad","reason":"test","run_key":"new:test-agent"}),
    ] {
        assert!(fixture.update(args).await.is_err());
    }
    for (tool, args) in [
        ("delete_record", json!({"id":fixture.id,"reason":"test"})),
        ("batch_write", json!({"operations":[],"reason":"test"})),
        (
            "create_record",
            json!({"type":"Document","body":"bad","reason":"test"}),
        ),
    ] {
        assert!(fixture
            .registry
            .call(
                fixture.db.clone(),
                Caller::authenticated("acct:alice"),
                tool,
                args
            )
            .await
            .is_err());
    }
    for id in [&fixture.instruction, &fixture.runtime] {
        let before_row: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT kind,body FROM records WHERE id=?")
                .bind(id)
                .fetch_one(fixture.db.pool())
                .await
                .unwrap();
        let error = fixture
            .update(json!({"id":id,"body_append":"bad","reason":"test"}))
            .await
            .unwrap_err();
        if id == &fixture.instruction {
            assert_eq!(before_row.0.as_deref(), Some("instruction"));
            assert!(error.to_string().contains("non-instruction"));
        }
        let after_row: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT kind,body FROM records WHERE id=?")
                .bind(id)
                .fetch_one(fixture.db.pool())
                .await
                .unwrap();
        assert_eq!(after_row, before_row);
    }
    assert_eq!(fixture.events().await, before);
    assert_eq!(fixture.body().await, original);
    fixture.update(fixture.args(" good")).await.unwrap();
    fixture
        .db
        .execution_owner
        .as_ref()
        .unwrap()
        .check()
        .unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn permanent_guard_covers_read_write_governed_detached_cached_and_reconnected_connections() {
    let fixture = Fixture::new(false).await;
    assert!(
        super::super::open_host_control_plane_sqlite_pool(&fixture.path)
            .await
            .is_err()
    );
    for pool in [
        fixture.db.pool(),
        fixture.db.write_pool(),
        fixture.db.governed_pool(),
    ] {
        let mut connection = pool.acquire().await.unwrap();
        sqlx::query("SELECT COUNT(*) FROM records")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        // Repeat a cached read, then test denied preparation, not a role toggle.
        sqlx::query("SELECT COUNT(*) FROM records")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        for statement in [
            "UPDATE main.records SET body='bad'",
            "CREATE TABLE main.bypass(id)",
            "ATTACH ':memory:' AS extra",
            "INSERT INTO main.read_log_record_ids(record_id) VALUES ('bad')",
            "PRAGMA writable_schema=ON",
        ] {
            assert!(
                sqlx::query(statement)
                    .execute(&mut *connection)
                    .await
                    .is_err(),
                "{statement}"
            );
        }
        let mut detached = connection.detach();
        assert!(sqlx::query("DELETE FROM main.content_events")
            .execute(&mut detached)
            .await
            .is_err());
        detached.close().await.unwrap();
        let mut reconnected = pool.acquire().await.unwrap();
        assert!(sqlx::query("UPDATE main.records SET body='bad'")
            .execute(&mut *reconnected)
            .await
            .is_err());
    }
    let mut connection = fixture.db.governed_pool().acquire().await.unwrap();
    sqlx::query("CREATE TEMP TABLE temp.probe(value)")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("INSERT INTO temp.probe VALUES (42)")
        .execute(&mut *connection)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT value FROM temp.probe")
            .fetch_one(&mut *connection)
            .await
            .unwrap(),
        42
    );
    assert!(sqlx::query(
        "CREATE TEMP TRIGGER temp.bad AFTER INSERT ON probe BEGIN DELETE FROM main.records; END"
    )
    .execute(&mut *connection)
    .await
    .is_err());
    drop(connection);
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[test]
fn json_arrow_permission_requires_document_and_exact_installed_trigger() {
    use libsqlite3_sys::{SQLITE_DENY, SQLITE_FUNCTION, SQLITE_OK};
    let allowed_trigger = std::ffi::CString::new("content_event_claim_meta_insert").unwrap();
    let other_trigger = std::ffi::CString::new("unrelated_trigger").unwrap();
    let arrow = std::ffi::CString::new("->").unwrap();
    let double_arrow = std::ffi::CString::new("->>").unwrap();
    let unknown = std::ffi::CString::new("unreviewed_function").unwrap();
    for role in [Role::Ordinary, Role::Capture, Role::Document] {
        for trigger in [
            std::ptr::null(),
            other_trigger.as_ptr(),
            allowed_trigger.as_ptr(),
        ] {
            for function in [&arrow, &double_arrow, &unknown] {
                let expected = if role == Role::Document
                    && trigger == allowed_trigger.as_ptr()
                    && function == &arrow
                {
                    SQLITE_OK
                } else {
                    SQLITE_DENY
                };
                let result = unsafe {
                    authorize(
                        (&role as *const Role).cast_mut().cast(),
                        SQLITE_FUNCTION,
                        std::ptr::null(),
                        function.as_ptr(),
                        std::ptr::null(),
                        trigger,
                    )
                };
                assert_eq!(
                    result,
                    expected,
                    "role={role:?}, function={function:?}, exact_trigger={}",
                    trigger == allowed_trigger.as_ptr()
                );
            }
        }
    }
}

#[tokio::test]
async fn hex_is_an_ordinary_read_scalar_not_capture_or_document_permission() {
    let fixture = Fixture::new(false).await;
    let hex_name = std::ffi::CString::new("hex").unwrap();
    for role in [Role::Ordinary, Role::Capture, Role::Document] {
        let result = unsafe {
            authorize(
                (&role as *const Role).cast_mut().cast(),
                libsqlite3_sys::SQLITE_FUNCTION,
                std::ptr::null(),
                hex_name.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(
            result,
            if role == Role::Ordinary {
                libsqlite3_sys::SQLITE_OK
            } else {
                libsqlite3_sys::SQLITE_DENY
            },
            "{role:?}"
        );
    }
    for pool in [
        fixture.db.pool(),
        fixture.db.write_pool(),
        fixture.db.governed_pool(),
    ] {
        let value: String = sqlx::query_scalar("SELECT hex('汉🐋')")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(value, "E6B189F09F908B");
    }
    let capture = fixture.db.capture_write_pool().await.unwrap();
    assert!(sqlx::query("SELECT hex('汉🐋')")
        .fetch_one(capture)
        .await
        .is_err());
    let db = fixture.db.clone();
    let operation_db = db.clone();
    internal_job(db, async move {
        let mut tx = begin_document_write(&operation_db).await?;
        assert!(sqlx::query("SELECT hex('汉🐋')")
            .fetch_one(&mut *tx)
            .await
            .is_err());
        tx.rollback().await?;
        Ok(json!(null))
    })
    .await
    .unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_poison_refuses_capture_before_initialization_or_existing_pool_acquisition() {
    use crate::mcp::interactions::{with_capture_pre_policy_gate, CaptureTestGate};
    for initialized in [false, true] {
        let fixture = Fixture::new(false).await;
        let owner = fixture.db.execution_owner.as_ref().unwrap().clone();
        if initialized {
            fixture.db.capture_write_pool().await.unwrap();
        }
        assert_eq!(fixture.db.capture_pool.get().is_some(), initialized);
        // A physical connection made before poison must still fail the shared
        // install check afterwards. This directly tests install(), not SQLx's
        // callback retry scheduling, and grants no temporary role exception.
        let mut pending_install = SqliteConnection::connect_with(
            &super::super::enrolled_connect_options(&fixture.path)
                .unwrap()
                .optimize_on_close(false, None),
        )
        .await
        .unwrap();
        owner.poison();
        let error = fixture.db.capture_write_pool().await.unwrap_err();
        assert!(error.to_string().contains("poisoned"));
        assert_eq!(fixture.db.capture_pool.get().is_some(), initialized);
        assert!(
            install(&mut pending_install, owner.clone(), Role::Capture, None)
                .await
                .is_err()
        );
        pending_install.close().await.unwrap();

        let before = fixture.events().await;
        let barrier = crate::mcp::DeploymentMutationBarrier::default();
        let lease = deployment_lease(&barrier).await;
        let capture_gate = Arc::new(CaptureTestGate::default());
        let error = with_capture_pre_policy_gate(
            capture_gate.clone(),
            crate::mcp::scope_deployment_persistence(
                Some(lease),
                fixture.update(fixture.args(" refused after poison")),
            ),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("poisoned"));
        tokio::time::timeout(Duration::from_secs(5), capture_gate.wait_until_entered())
            .await
            .unwrap();
        assert_eq!(owner.accepted.load(Ordering::Acquire), 0);
        let stats = fixture.db.capture_stats();
        assert_eq!(stats.enqueued, 1);
        assert_eq!(stats.completed, 0);
        let mut freeze = Box::pin(barrier.freeze());
        assert!(
            futures::poll!(freeze.as_mut()).is_pending(),
            "the queued capture must retain its deployment lease until actual failure completion"
        );
        capture_gate.release();
        let frozen = tokio::time::timeout(Duration::from_secs(10), freeze)
            .await
            .unwrap();
        fixture.db.drain_captures_for_tests().await;
        let stats = fixture.db.capture_stats();
        assert_eq!(stats.enqueued, 1);
        assert_eq!(stats.completed, 1);
        assert_eq!(
            stats.failed, 1,
            "known poison remains a reported capture failure, not a silent discard"
        );
        assert_eq!(stats.dropped_full + stats.dropped_shutdown, 0);
        assert_eq!(fixture.db.capture_pool.get().is_some(), initialized);
        assert_eq!(fixture.events().await, before);
        drop(frozen);
    }
}

#[tokio::test]
async fn direct_json_arrow_is_denied_on_ordinary_governed_and_capture_connections() {
    let fixture = Fixture::new(false).await;
    for pool in [
        fixture.db.pool(),
        fixture.db.write_pool(),
        fixture.db.governed_pool(),
        fixture.db.capture_write_pool().await.unwrap(),
    ] {
        let mut connection = pool.acquire().await.unwrap();
        for statement in ["SELECT '{}' -> '$'", "SELECT '{}' ->> '$'"] {
            assert!(
                sqlx::query(statement)
                    .execute(&mut *connection)
                    .await
                    .is_err(),
                "{statement}"
            );
        }
    }
    // A content-enabled connection also denies direct expressions: its role is
    // permanent, but the required installed trigger context is absent here.
    let db = fixture.db.clone();
    let operation_db = db.clone();
    internal_job(db, async move {
        let mut tx = begin_document_write(&operation_db).await?;
        for statement in ["SELECT '{}' -> '$'", "SELECT '{}' ->> '$'"] {
            assert!(
                sqlx::query(statement).execute(&mut *tx).await.is_err(),
                "{statement}"
            );
        }
        tx.rollback().await?;
        Ok(json!(null))
    })
    .await
    .unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn external_main_and_attached_enrolled_kernel_inputs_refuse_before_first_mutation() {
    let fixture = Fixture::new(false).await;
    let mut external = SqliteConnection::connect_with(
        &super::super::connect_options(fixture.path.to_str().unwrap(), false).unwrap(),
    )
    .await
    .unwrap();
    assert!(require_content_connection(&mut external, None)
        .await
        .is_err());
    external.close().await.unwrap();
    let mut external = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(fixture._root.path().join("external-main.db"))
            .create_if_missing(true),
    )
    .await
    .unwrap();
    sqlx::query("ATTACH ? AS enrolled")
        .bind(fixture.path.to_str().unwrap())
        .execute(&mut external)
        .await
        .unwrap();
    let attached: String =
        sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name='enrolled'")
            .fetch_one(&mut external)
            .await
            .unwrap();
    assert_eq!(
        std::fs::canonicalize(&attached).unwrap(),
        std::fs::canonicalize(&fixture.path).unwrap()
    );
    let attached_owner =
        crate::managed_custody::execution_for_filename(std::path::Path::new(&attached))
            .unwrap()
            .unwrap();
    assert!(Arc::ptr_eq(
        &attached_owner,
        fixture.db.execution_owner.as_ref().unwrap()
    ));
    let before = fixture.events().await;
    assert!(crate::projector::replay(&mut external, &[]).await.is_err());
    assert_eq!(fixture.events().await, before);
    external.close().await.unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn enrolled_missing_compiled_pack_refuses_reconciliation_without_seeding() {
    let fixture = Fixture::new(true).await;
    let before = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM meta_events")
        .fetch_one(fixture.db.pool())
        .await
        .unwrap();
    assert!(super::super::open_existing_database_at(&fixture.path)
        .await
        .is_err());
    let after = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM meta_events")
        .fetch_one(fixture.db.pool())
        .await
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schema_config WHERE layer='pack'")
            .fetch_one(fixture.db.pool())
            .await
            .unwrap(),
        0
    );
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiter_cancellation_never_releases_shared_lane_before_physical_close() {
    for phase in [
        Phase::BeforeBegin,
        Phase::AfterBegin,
        Phase::AfterAppend,
        Phase::BeforeCommit,
        Phase::AfterCommit,
        Phase::BeforeClose,
    ] {
        let fixture = Fixture::new(false).await;
        let second = fixture.open_peer().await;
        let owner = fixture.db.execution_owner.as_ref().unwrap().clone();
        assert!(Arc::ptr_eq(
            &owner,
            second.execution_owner.as_ref().unwrap()
        ));
        let (first_gate, entered) = gate(phase);
        let registry = fixture.registry.clone();
        let db = fixture.db.clone();
        let arguments = fixture.args(" first");
        let held_gate = first_gate.clone();
        let waiter = tokio::spawn(async move {
            TEST_GATE
                .scope(
                    held_gate,
                    registry.call(
                        db,
                        Caller::authenticated("acct:alice"),
                        "update_record",
                        arguments,
                    ),
                )
                .await
        });
        reached(entered).await;
        waiter.abort(); // Only the response waiter, never the accepted job.
        let _ = waiter.await;
        let registry = fixture.registry.clone();
        let arguments = fixture.args(" second");
        let second_db = second.clone();
        let next = tokio::spawn(async move {
            registry
                .call(
                    second_db,
                    Caller::authenticated("acct:alice"),
                    "update_record",
                    arguments,
                )
                .await
        });
        accepted(&owner, 2).await;
        assert!(
            owner.lane.try_lock().is_err(),
            "first owns the lane through acknowledged close"
        );
        first_gate.release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(10), next)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(fixture.body().await, "seed 🐋汉e\u{301}\r\n first second");
        owner.check().unwrap();
        fixture.db.drain_captures_for_tests().await;
        fixture.db.close().await;
        second.drain_captures_for_tests().await;
        second.close().await;
    }
}

async fn internal_job<F>(db: Db, future: F) -> Result<Value>
where
    F: Future<Output = Result<Value>> + Send + 'static,
{
    let caller = Caller::authenticated("acct:alice");
    let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
        &caller,
        "update_record",
        &json!({"reason":"physical return test"}),
        None,
    );
    let admission_db = db.clone();
    crate::storage_profile::with_operation(
        &admission_db,
        "update_record",
        None,
        dispatch.scope(document_job(db, future)),
    )
    .await
}

#[tokio::test]
async fn begin_failure_and_queued_rollback_use_the_real_return_transfer() {
    let fixture = Fixture::new(false).await;
    let db = fixture.db.clone();
    assert!(internal_job(db, async {
        let slot = DOCUMENT_CONNECTION.with(Clone::clone);
        let connection = slot.lock().unwrap().take().unwrap();
        // SQLx consumes the owned checkout before this syntactic BEGIN failure.
        let _transaction: sqlx::Transaction<'static, sqlx::Sqlite> =
            sqlx::Transaction::begin(connection, Some("INVALID BEGIN".into())).await?;
        unreachable!()
    })
    .await
    .is_err());
    fixture
        .db
        .execution_owner
        .as_ref()
        .unwrap()
        .check()
        .unwrap();
    let before = fixture.body().await;
    let db = fixture.db.clone();
    let operation_db = db.clone();
    let id = fixture.id.clone();
    internal_job(db, async move {
        let mut transaction = begin_document_write(&operation_db).await?;
        sqlx::query("UPDATE records SET body='rolled back' WHERE id=?")
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        drop(transaction); // Genuine SQLx queued rollback before return/Shutdown.
        Ok(json!({"rolled_back":true}))
    })
    .await
    .unwrap();
    assert_eq!(fixture.body().await, before);
    fixture
        .update(fixture.args(" after rollback"))
        .await
        .unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn panic_after_begin_is_closed_then_permanently_poisoned() {
    let fixture = Fixture::new(false).await;
    let before = fixture.body().await;
    let db = fixture.db.clone();
    let operation_db = db.clone();
    assert!(internal_job(db, async move {
        let _transaction = begin_document_write(&operation_db).await?;
        panic!("test owned operation panic");
        #[allow(unreachable_code)]
        Ok(json!(null))
    })
    .await
    .is_err());
    assert!(fixture
        .update(fixture.args(" forbidden after panic"))
        .await
        .is_err());
    assert_eq!(fixture.body().await, before);
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn capacity_refuses_before_ticket_acceptance_and_handle_close_drains_only_its_jobs() {
    let fixture = Fixture::new(false).await;
    let owner = fixture.db.execution_owner.as_ref().unwrap().clone();
    let handle = Arc::new(HandleJobs::default());
    let mut tickets = Vec::new();
    for _ in 0..JOB_CAPACITY {
        tickets.push(handle.register(&owner).unwrap());
    }
    assert!(handle.register(&owner).is_err());
    assert_eq!(owner.accepted.load(Ordering::Acquire), JOB_CAPACITY);
    // These test-only tickets never created physical connections.
    for mut ticket in tickets {
        ticket.armed = false;
        drop(ticket);
    }
    owner.check().unwrap();
    let (held_gate, entered) = gate(Phase::AfterBegin);
    let registry = fixture.registry.clone();
    let db = fixture.db.clone();
    let args = fixture.args(" drained");
    let release = held_gate.clone();
    let waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(
                held_gate,
                registry.call(
                    db,
                    Caller::authenticated("acct:alice"),
                    "update_record",
                    args,
                ),
            )
            .await
    });
    reached(entered).await;
    fixture.db.execution_jobs.stop_submission();
    assert!(fixture.update(fixture.args(" too late")).await.is_err());
    let db = fixture.db.clone();
    let close = tokio::spawn(async move { db.close().await });
    assert!(owner.lane.try_lock().is_err());
    release.release.add_permits(1);
    waiter.await.unwrap().unwrap();
    close.await.unwrap();
    assert!(fixture.db.enrolled_retirement_complete());
    let reopened = fixture.open_peer().await;
    fixture
        .registry
        .call(
            reopened.clone(),
            Caller::authenticated("acct:alice"),
            "update_record",
            fixture.args(" independent handle"),
        )
        .await
        .unwrap();
    reopened.drain_captures_for_tests().await;
    reopened.close().await;
}

#[tokio::test]
async fn unmanaged_independent_opens_keep_existing_persistent_mutation_surface() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ordinary.db");
    let first = crate::create_database(path.to_str().unwrap())
        .await
        .unwrap();
    let second = super::super::open_existing_database_at(&path)
        .await
        .unwrap();
    assert!(!first.is_enrolled() && !second.is_enrolled());
    sqlx::query("CREATE TABLE unrestricted_test(value)")
        .execute(first.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO unrestricted_test VALUES (42)")
        .execute(second.write_pool())
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT value FROM unrestricted_test")
            .fetch_one(first.pool())
            .await
            .unwrap(),
        42
    );
    first.close().await;
    second.drain_captures_for_tests().await;
    second.close().await;
}

#[tokio::test]
async fn failed_explicit_rollback_still_closes_the_original_before_next_job() {
    let fixture = Fixture::new(false).await;
    let db = fixture.db.clone();
    let operation_db = db.clone();
    assert!(internal_job(db, async move {
        let mut transaction = begin_document_write(&operation_db).await?;
        // No content writes. Deliberately end SQLite's transaction while its
        // SQLx transaction remains owned, making the actual rollback fail.
        sqlx::query("COMMIT").execute(&mut *transaction).await?;
        transaction.rollback().await?;
        Ok(json!({"rollback_unexpectedly_succeeded":true}))
    })
    .await
    .is_err());
    fixture
        .db
        .execution_owner
        .as_ref()
        .unwrap()
        .check()
        .unwrap();
    fixture
        .update(fixture.args(" after failed rollback"))
        .await
        .unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn failed_physical_setup_poison_prevents_later_authority_and_volume_handoff() {
    let fixture = Fixture::new(false).await;
    let owner = fixture.db.execution_owner.as_ref().unwrap().clone();
    // Test-owned resource disappearance, outside the custody contract. This
    // produces a genuine immutable-readonly setup failure, not a mocked close.
    let (held_gate, entered) = gate(Phase::BeforeSetup);
    let release = held_gate.clone();
    let db = fixture.db.clone();
    let waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(held_gate, internal_job(db, async { Ok(json!(null)) }))
            .await
    });
    reached(entered).await;
    assert_eq!(owner.accepted.load(Ordering::Acquire), 1);
    std::fs::remove_file(&fixture.path).unwrap();
    release.release.add_permits(1);
    let error = waiter.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("open") || owner.check().is_err());
    assert!(owner.check().is_err());
    assert!(fixture.update(fixture.args(" rejected")).await.is_err());
    assert!(
        !fixture.db.drain_enrolled_execution_for_shutdown().await,
        "empty ticket count cannot turn poisoned cleanup into a handoff witness"
    );
    fixture.db.drain_captures_for_tests().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_cas_refusal_finishes_rollback_before_shared_next_writer() {
    let fixture = Fixture::new(false).await;
    let (held_gate, entered) = gate(Phase::BeforeRollback);
    let registry = fixture.registry.clone();
    let db = fixture.db.clone();
    let args = json!({"id":fixture.id,"body_append":"must not persist","reason":"test CAS refusal", "if_unmodified_since":"2000-01-01T00:00:00.000Z"});
    let release = held_gate.clone();
    let waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(
                held_gate,
                registry.call(
                    db,
                    Caller::authenticated("acct:alice"),
                    "update_record",
                    args,
                ),
            )
            .await
    });
    reached(entered).await;
    waiter.abort();
    let _ = waiter.await;
    let second = fixture.open_peer().await;
    let owner = fixture.db.execution_owner.as_ref().unwrap().clone();
    let registry = fixture.registry.clone();
    let args = fixture.args(" survived refusal");
    let db = second.clone();
    let next = tokio::spawn(async move {
        registry
            .call(
                db,
                Caller::authenticated("acct:alice"),
                "update_record",
                args,
            )
            .await
    });
    accepted(&owner, 2).await;
    assert!(owner.lane.try_lock().is_err());
    release.release.add_permits(1);
    next.await.unwrap().unwrap();
    assert_eq!(
        fixture.body().await,
        "seed 🐋汉e\u{301}\r\n survived refusal"
    );
    owner.check().unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
    second.drain_captures_for_tests().await;
    second.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_http_fallback_and_storage_leases_survive_waiter_loss_until_close_ack() {
    use crate::mcp::{DeploymentAdmission, DeploymentMutationBarrier, OperationAccess};
    let fixture = Fixture::new(false).await;
    let barrier = DeploymentMutationBarrier::default();
    let lease = match barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("update_record"),
            OperationAccess::Mutation,
        )
        .unwrap()
    {
        DeploymentAdmission::Writable(lease) => lease,
        DeploymentAdmission::FrozenRead => unreachable!(),
    };
    let (held_gate, entered) = gate(Phase::BeforeClose);
    let release = held_gate.clone();
    let registry = fixture.registry.clone();
    let db = fixture.db.clone();
    let arguments = fixture.args(" retains admissions");
    // Same existing-lease scope used by held's registry-without-barrier HTTP
    // fallback. It is not a test-minted deployment or Caller authority.
    let waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(
                held_gate,
                crate::mcp::scope_deployment_persistence(
                    Some(lease),
                    registry.call(
                        db,
                        Caller::authenticated("acct:alice"),
                        "update_record",
                        arguments,
                    ),
                ),
            )
            .await
    });
    reached(entered).await;
    waiter.abort();
    let _ = waiter.await;
    assert!(fixture
        .db
        .owned_portability_policy_gate()
        .try_write_owned()
        .is_err());
    let mut freeze = Box::pin(barrier.freeze());
    assert!(
        futures::poll!(freeze.as_mut()).is_pending(),
        "freeze must retain the admitted job's deployment lease"
    );
    release.release.add_permits(1);
    let frozen = tokio::time::timeout(Duration::from_secs(10), freeze)
        .await
        .unwrap();
    assert!(fixture
        .db
        .owned_portability_policy_gate()
        .try_write_owned()
        .is_ok());
    assert_eq!(
        fixture.body().await,
        "seed 🐋汉e\u{301}\r\n retains admissions",
        "operation evidence: {:?}",
        release.outcome.lock().unwrap()
    );
    drop(frozen);
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn readonly_process_probe() {
    let Some(path) = std::env::var_os("NATIVE_ENROLLED_READ_PROBE") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let db = super::super::open_existing_database_standby_read_only(path.to_str().unwrap())
        .await
        .unwrap();
    let mut connection = db.pool().acquire().await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert!(rows > 0);
    assert!(sqlx::query("ATTACH ':memory:' AS bypass")
        .execute(&mut *connection)
        .await
        .is_err());
    drop(connection);
    db.close().await;
}

#[tokio::test]
async fn read_only_other_process_keeps_observation_without_acquiring_writer_custody() {
    let fixture = Fixture::new(false).await;
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "db::enrolled::tests::readonly_process_probe",
            "--nocapture",
        ])
        .env("NATIVE_ENROLLED_READ_PROBE", &fixture.path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "readonly child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fixture
        .update(fixture.args(" owner still writable"))
        .await
        .unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

async fn deployment_lease(
    barrier: &crate::mcp::DeploymentMutationBarrier,
) -> crate::mcp::DeploymentPersistenceLease {
    match barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("update_record"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap()
    {
        crate::mcp::DeploymentAdmission::Writable(lease) => lease,
        crate::mcp::DeploymentAdmission::FrozenRead => unreachable!(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_timeout_retains_same_close_future_and_freeze_until_actual_ack() {
    let fixture = Fixture::new(false).await;
    let barrier = crate::mcp::DeploymentMutationBarrier::default();
    let lease = deployment_lease(&barrier).await;
    let (held_gate, entered) = gate(Phase::BeforeClose);
    let release = held_gate.clone();
    let registry = fixture.registry.clone();
    let db = fixture.db.clone();
    let args = fixture.args(" committed before timeout");
    let waiter = tokio::spawn(async move {
        TEST_CLEANUP_LIMIT
            .scope(
                Duration::ZERO,
                TEST_GATE.scope(
                    held_gate,
                    crate::mcp::scope_deployment_persistence(
                        Some(lease),
                        registry.call(
                            db,
                            Caller::authenticated("acct:alice"),
                            "update_record",
                            args,
                        ),
                    ),
                ),
            )
            .await
    });
    reached(entered).await;
    let error = waiter.await.unwrap().unwrap_err().to_string();
    assert!(
        error.contains("committed") && error.contains("quarantined"),
        "cleanup error: {error}; operation evidence: {:?}",
        release.outcome.lock().unwrap()
    );
    let owner = fixture.db.execution_owner.as_ref().unwrap();
    assert!(owner.check().is_err());
    assert_eq!(owner.retained.lock().unwrap().len(), 1);
    assert!(fixture
        .db
        .owned_portability_policy_gate()
        .try_write_owned()
        .is_err());
    let mut freeze = Box::pin(barrier.freeze());
    assert!(futures::poll!(freeze.as_mut()).is_pending());
    assert!(!fixture.db.execution_jobs.retirement_ready(Some(owner)));
    release.release.add_permits(1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let frozen = tokio::time::timeout_at(deadline, freeze)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "freeze did not drain: {error}; {}",
                cleanup_evidence(&fixture.db, &release)
            )
        });
    assert!(
        release.writer_close_ack.load(Ordering::Acquire),
        "{}",
        cleanup_evidence(&fixture.db, &release)
    );
    // Document-close/deployment freeze, capture settlement and storage-gate
    // acquisition are separate observations sharing the same deadline.
    tokio::time::timeout_at(deadline, fixture.db.drain_captures_for_tests())
        .await
        .unwrap_or_else(|error| {
            panic!(
                "capture settlement did not drain: {error}; {}",
                cleanup_evidence(&fixture.db, &release)
            )
        });
    // Deployment freeze does not synchronize readiness of the independent storage gate.
    let policy = tokio::time::timeout_at(
        deadline,
        fixture.db.owned_portability_policy_gate().write_owned(),
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "storage admissions did not drain: {error}; {}",
            cleanup_evidence(&fixture.db, &release)
        )
    });
    drop(policy);
    assert!(
        fixture.body().await.ends_with(" committed before timeout"),
        "operation evidence: {:?}",
        release.outcome.lock().unwrap()
    );
    assert!(fixture
        .update(fixture.args(" never admitted after poison"))
        .await
        .is_err());
    drop(frozen);
    fixture.db.drain_captures_for_tests().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_poller_abort_retains_admissions_and_runner_before_setup_and_close() {
    for phase in [Phase::BeforeSetup, Phase::BeforeClose] {
        let fixture = Fixture::new(false).await;
        let barrier = crate::mcp::DeploymentMutationBarrier::default();
        let lease = deployment_lease(&barrier).await;
        let (held_gate, entered) = gate(phase);
        let release = held_gate.clone();
        let registry = fixture.registry.clone();
        let db = fixture.db.clone();
        let args = fixture.args(" accepted abort");
        let waiter = tokio::spawn(async move {
            TEST_GATE
                .scope(
                    held_gate,
                    crate::mcp::scope_deployment_persistence(
                        Some(lease),
                        registry.call(
                            db,
                            Caller::authenticated("acct:alice"),
                            "update_record",
                            args,
                        ),
                    ),
                )
                .await
        });
        reached(entered).await;
        let owner = fixture.db.execution_owner.as_ref().unwrap().clone();
        let retained = owner
            .retained
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        retained.abort.lock().unwrap().as_ref().unwrap().abort();
        tokio::time::timeout(Duration::from_secs(5), async {
            while retained.running.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        let _ = waiter.await;
        assert!(owner.check().is_err());
        assert!(
            retained.future.lock().unwrap().is_some(),
            "abort must not drop the owned runner/connection"
        );
        assert!(fixture
            .db
            .owned_portability_policy_gate()
            .try_write_owned()
            .is_err());
        let mut freeze = Box::pin(barrier.freeze());
        assert!(futures::poll!(freeze.as_mut()).is_pending());
        // Same recovery used by stop_and_drain. No new mutation is accepted;
        // an already-started cleanup resumes from its retained future.
        owner.resume_retained();
        release.release.add_permits(1);
        if phase == Phase::BeforeClose {
            let frozen = tokio::time::timeout(Duration::from_secs(10), freeze)
                .await
                .unwrap();
            assert!(
                fixture.body().await.ends_with(" accepted abort"),
                "operation evidence: {:?}",
                release.outcome.lock().unwrap()
            );
            drop(frozen);
        } else {
            tokio::time::timeout(Duration::from_secs(5), async {
                while owner.accepted.load(Ordering::Acquire) != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            // No ACK exists after pre-setup loss. Conservative process-lifetime
            // retention is explicit: even an empty ticket set cannot freeze.
            assert!(futures::poll!(freeze.as_mut()).is_pending());
            assert!(retained.admissions.lock().unwrap().is_some());
            assert_eq!(fixture.body().await, "seed 🐋汉e\u{301}\r\n");
        }
        assert!(!fixture.db.drain_enrolled_execution_for_shutdown().await);
        fixture.db.drain_captures_for_tests().await;
    }
}

#[tokio::test]
async fn exact_vocabulary_id_collision_and_missing_lifecycle_gloss_refuse_without_meta_writes() {
    for setup in [Setup::VocabularyCollision, Setup::MissingGloss] {
        let fixture = Fixture::configured(setup).await;
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
        if matches!(setup, Setup::VocabularyCollision) {
            let wrong = crate::meta::vocabulary::get_vocabulary_on(
                &mut fixture.db.pool().acquire().await.unwrap(),
                "voc:lifecycle",
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                wrong.id, "test:wrong-vocabulary",
                "fixture must hit the old id-or-name fallback"
            );
            let values: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM vocabulary_values WHERE id LIKE 'vv:voc:lifecycle:%'",
            )
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
            assert!(values > 0);
        }
        let error = super::super::open_existing_database_at(&fixture.path)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reconciliation"));
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
        assert_eq!(before, after);
        fixture.db.drain_captures_for_tests().await;
        fixture.db.close().await;
    }
}

#[tokio::test]
async fn governed_query_sql_real_temp_contract_setup_and_cleanup() {
    let fixture = Fixture::new(false).await;
    // Occupy every other slot: the assertion must inspect the same physical
    // connection used by the real query, not a newly created empty connection.
    let mut held = Vec::new();
    for _ in 1..fixture.db.governed_pool().options().get_max_connections() {
        held.push(fixture.db.governed_pool().acquire().await.unwrap());
    }
    for _ in 0..2 {
        let result = fixture
            .registry
            .call(
                fixture.db.clone(),
                Caller::authenticated("acct:alice"),
                "query_sql",
                json!({"sql":format!("SELECT id,body FROM records WHERE id IN ('{}','{}','{}') ORDER BY id",fixture.id,fixture.instruction,fixture.runtime)}),
            )
            .await
            .unwrap();
        assert_eq!(result["row_count"], 3);
        let mut connection = fixture.db.governed_pool().acquire().await.unwrap();
        let predicate = "name LIKE '_query_sql_%' OR name IN ('records','content_events','links','facet_values','facet_observations','bindings','blobs','vocabularies','vocabulary_values','schema_config','record_lifecycle_interpretations','body_blocks','body_task_items')";
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM sqlite_temp_master WHERE {predicate}"
        ))
        .fetch_one(&mut *connection)
        .await
        .unwrap();
        let remaining: Vec<String> = if count != 0 {
            sqlx::query_scalar(&format!(
                "SELECT name FROM sqlite_temp_master WHERE {predicate} ORDER BY name LIMIT 16"
            ))
            .fetch_all(&mut *connection)
            .await
            .unwrap()
        } else {
            Vec::new()
        };
        assert_eq!(
            count, 0,
            "real governed contract must sanitize before reuse; remaining: {remaining:?}"
        );
    }
    drop(held);
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn artifact_alias_refuses_and_source_basis_fts_mentions_remain_real() {
    let alias = Fixture::configured(Setup::ArtifactAlias).await;
    let before = alias.events().await;
    let error = alias
        .update(alias.args(" excluded alias"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("non-artifact"));
    assert_eq!(alias.events().await, before);
    alias.db.drain_captures_for_tests().await;
    alias.db.close().await;
    let fixture = Fixture::new(false).await;
    let mut args = fixture.args(" interoperabilityneedle [[body]]");
    args["sources"] =
        json!([{"record_id":fixture.instruction,"reason":"read bootstrap instruction"}]);
    fixture.update(args).await.unwrap();
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='record.updated' ORDER BY seq DESC LIMIT 1")
        .bind(&fixture.id).fetch_one(fixture.db.pool()).await.unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        payload["basis"]["sources"][0]["record_id"],
        fixture.instruction
    );
    let fts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records_fts JOIN records r ON r.rowid=records_fts.rowid WHERE records_fts MATCH 'interoperabilityneedle' AND r.id=?")
        .bind(&fixture.id).fetch_one(fixture.db.pool()).await.unwrap();
    assert_eq!(fts, 1);
    let mentions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM record_mentions WHERE source_id=? AND authored_reference='body' AND form='wiki_name'",
    )
    .bind(&fixture.id)
    .fetch_one(fixture.db.pool())
    .await
    .unwrap();
    assert_eq!(mentions, 1);
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn strict_policy_is_retained_for_actual_enrolled_dispatch() {
    let fixture = Fixture::configured(Setup::Strict).await;
    let before = fixture.events().await;
    // Existing target permits guarded-write itself, but its aggregate domain
    // MCP capability is partial. Actual registry admission must refuse rather
    // than granting this unit a new strict-mode exemption.
    let error = fixture
        .update(fixture.args(" strict refused update"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("strict_portability_blocked"));
    assert_eq!(fixture.events().await, before);
    let owner = fixture.db.execution_owner.as_ref().unwrap();
    assert_eq!(owner.accepted.load(Ordering::Acquire), 0);
    assert!(owner.retained.lock().unwrap().is_empty());
    let error = internal_job(fixture.db.clone(), {
        let db = fixture.db.clone();
        async move {
            let _tx = begin_document_write(&db).await?;
            Ok(json!(null))
        }
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("strict_portability_blocked"));
    owner.check().unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn public_append_batch_and_nonempty_blob_replay_refuse_without_changes() {
    let fixture = Fixture::new(false).await;
    let before = fixture.events().await;
    let body = fixture.body().await;
    let spec = || crate::store::AppendSpec {
        record_id: fixture.id.clone(),
        event_type: "record.updated".into(),
        payload: json!({"body":"bypass"}),
        actor: Some("test:raw".into()),
    };
    assert!(crate::store::append(&fixture.db, spec()).await.is_err());
    assert!(crate::store::append_batch(&fixture.db, vec![spec()])
        .await
        .is_err());
    let mut raw = SqliteConnection::connect_with(
        &super::super::enrolled_connect_options(&fixture.path).unwrap(),
    )
    .await
    .unwrap();
    let event = crate::events::EventRow {
        local_seq: 1,
        id: "test:external-replay".into(),
        record_id: fixture.id.clone(),
        event_type: "annotation.target.set".into(),
        payload: Some(json!({"blob_id":"test:must-not-be-created"}).to_string()),
        actor: None,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: crate::store::now_iso(),
        causal_envelope: crate::events::CausalEnvelopeV1::default(),
        act: None,
    };
    assert!(
        crate::projector::replay_with_blob_placeholders(&mut raw, &[event])
            .await
            .is_err()
    );
    assert_eq!(fixture.events().await, before);
    assert_eq!(fixture.body().await, body);
    let blobs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE id='test:must-not-be-created'")
            .fetch_one(fixture.db.pool())
            .await
            .unwrap();
    assert_eq!(blobs, 0);
    raw.close().await.unwrap();
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn after_connect_install_failure_poison_prevents_retry_authority_and_retains_admissions() {
    let fixture = Fixture::new(false).await;
    let before = fixture.events().await;
    let error = TEST_CACHE_FAILURE
        .scope(true, fixture.update(fixture.args(" refused setup")))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("cache")
            || fixture
                .db
                .execution_owner
                .as_ref()
                .unwrap()
                .check()
                .is_err()
    );
    let owner = fixture.db.execution_owner.as_ref().unwrap();
    assert!(owner.check().is_err());
    assert_eq!(owner.document_installations.load(Ordering::Acquire), 1, "SQLx retry must never install a second content role after the injected after_connect failure");
    let retained = owner
        .retained
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert!(
        retained.admissions.lock().unwrap().is_some(),
        "SQLx hard-close is no ACK"
    );
    assert!(fixture.update(fixture.args(" cannot retry")).await.is_err());
    assert_eq!(fixture.events().await, before);
    assert!(!fixture.db.drain_enrolled_execution_for_shutdown().await);
}

#[tokio::test]
async fn required_facet_removal_refuses_before_dispatch_and_body_update_preserves_it() {
    let fixture = Fixture::configured(Setup::RequiredFacet).await;
    let before = fixture.events().await;
    assert!(fixture.update(json!({"id":fixture.id,"body_append":"not applied","reason":"test required removal","facets":{"test_required":null}})).await.is_err());
    assert_eq!(fixture.events().await, before);
    // Required violations depend on spine/facet values, not body. A supported
    // body-only operation cannot worsen them; the existing real post-validator
    // runs, and forbidden facet mutation receives no content authority.
    fixture
        .update(fixture.args(" required unchanged"))
        .await
        .unwrap();
    let value: String = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id=? AND key='test_required'",
    )
    .bind(&fixture.id)
    .fetch_one(fixture.db.pool())
    .await
    .unwrap();
    assert_eq!(value, "\"retained\"");
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}

#[tokio::test]
async fn private_options_preserve_filename_and_capture_opens_admitted_physical_file() {
    let path = Path::new("/tmp/test?query#fragment.db");
    assert_eq!(
        super::super::enrolled_immutable_options(path)
            .unwrap()
            .get_filename(),
        path
    );
    use std::os::unix::ffi::OsStringExt;
    let unrepresentable =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', b't', 0xff]));
    assert!(super::super::enrolled_immutable_options(&unrepresentable).is_err());
    assert!(super::super::enrolled_connect_options(&unrepresentable).is_err());
    let fixture = Fixture::new(false).await;
    let pool = fixture.db.capture_write_pool().await.unwrap();
    assert_eq!(pool.connect_options().get_filename(), &fixture.path);
    let mut connection = pool.acquire().await.unwrap();
    let mut locked = connection.lock_handle().await.unwrap();
    let raw = locked.as_raw_handle().as_ptr();
    let filename =
        unsafe { CStr::from_ptr(libsqlite3_sys::sqlite3_db_filename(raw, c"main".as_ptr())) }
            .to_str()
            .unwrap();
    let actual_owner = crate::managed_custody::execution_for_filename(Path::new(filename))
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(
        &actual_owner,
        fixture.db.execution_owner.as_ref().unwrap()
    ));
    let pointer =
        unsafe { libsqlite3_sys::sqlite3_get_clientdata(raw, CONTEXT_KEY.as_ptr().cast()) };
    assert!(!pointer.is_null());
    assert_eq!(
        unsafe { &*pointer.cast::<ConnectionContext>() }.role,
        Role::Capture
    );
    drop(locked);
    drop(connection);
    fixture.db.drain_captures_for_tests().await;
    fixture.db.close().await;
}
