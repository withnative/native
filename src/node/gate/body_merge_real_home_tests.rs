//! End-to-end node lineage proofs against an actual KernelV2 home operation.
use super::*;
use crate::body_merge_flag::{scoped, BodyMergeConfig, ScopedConfig};
use crate::events::KERNEL_ROOT_ID;
use crate::mcp::registry::{Caller as HomeCaller, EngineHandle, ToolRegistry};
use crate::node::unmerged::{RecoveryItem, RecoveryState};
use crate::{db::Db, kernel};

#[derive(Clone)]
struct World {
    db: Db,
    admin: String,
    home: String,
    admin_caller: HomeCaller,
}

async fn world() -> World {
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    kernel::prepare_v2_database(&db).await.unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&db, &admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let manifest: Value = serde_json::from_str(crate::meta::kind::CORE_KIND_MANIFEST_JSON).unwrap();
    let mut rows = Vec::new();
    for typ in ["Document", "WorkItem"] {
        rows.push((
            "vocabularies",
            json!({"id":format!("voc:kind:{typ}"),"name":format!("kind:{typ}")}),
        ));
        for entry in manifest["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["type"] == typ)
        {
            rows.push(("vocabulary_values", json!({"id":entry["value_id"], "vocabulary_id":format!("voc:kind:{typ}"), "value":entry["token"], "status":"active", "gloss":null,"ordinal":0,"terminality":"open","metadata":entry["metadata"].to_string(),"alias_of":null})));
        }
    }
    let rows = rows
        .into_iter()
        .map(|(section, row)| kernel::v1_state::ImportedState {
            section: section.into(),
            source_id: row["id"].as_str().unwrap().into(),
            origin: "merge-body-proof".into(),
            value_json: Some(row.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: "2026-10-28T00:00:00Z".into(),
            snapshot: json!({}),
        })
        .collect::<Vec<_>>();
    kernel::v1_state::import_state_batch_as(&db, &host, &rows)
        .await
        .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&viewer, "view")]), &admin)
        .await
        .unwrap();
    World {
        db,
        admin,
        home,
        admin_caller: HomeCaller::authenticated("acct:admin"),
    }
}

async fn record_in(w: &World, home: &str, body: &str) -> String {
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Merge target"}).to_string(),
        home,
    )
    .await
    .unwrap();
    set_body(w, &id, body).await;
    id
}
async fn record(w: &World, body: &str) -> String {
    record_in(w, &w.home.clone(), body).await
}
/// An ordinary body write by someone else, through the same tool surface.
async fn set_body(w: &World, id: &str, body: &str) {
    let revision = kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(&w.db, &w.admin, id, body, revision)
        .await
        .unwrap();
}

fn registry() -> ToolRegistry {
    let mut tools = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut tools).unwrap();
    crate::mcp::tools::register_surface_tools(&mut tools).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut tools).unwrap();
    tools
}

async fn version(w: &World, id: &str) -> String {
    let head: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?")
            .bind(id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    format!("rec:{head}")
}
async fn canonical(w: &World, id: &str) -> String {
    kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap()
        .body
        .unwrap_or_default()
}

struct HomeRig {
    world: World,
    gate: Arc<WriteGate>,
    upstream: Arc<Upstream>,
    requests: Arc<StdMutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
    _temp: tempfile::TempDir,
    // Keep the thread-local override alive for the whole current-thread
    // runtime, including the registry's independently spawned owned writer.
    _flag: ScopedConfig,
}
impl Drop for HomeRig {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl HomeRig {
    async fn new() -> Self {
        let flag = scoped(BodyMergeConfig {
            enabled: true,
            accounts: None,
        });
        let world = world().await;
        let temp = tempfile::tempdir().unwrap();
        let token = temp.path().join("token");
        fs::write(&token, "test-token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let socket_directory = temp.path().join("socket");
        fs::create_dir(&socket_directory).unwrap();
        fs::set_permissions(&socket_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let task = tokio::spawn({
            let world = world.clone();
            let requests = requests.clone();
            async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(serve_home(world.clone(), requests.clone(), socket));
                }
            }
        });
        let config = NodeConfig {
            working_note_appends: false,
            working_refusal_drafts: false,
            markdown_folder: None,
            hosted_base_url: format!("http://{address}"),
            home_id: world.home.clone(),
            db_id: "test-workspace".into(),
            credential_file: token,
            socket_directory,
            oauth_auth_file: None,
            node_install_key_file: None,
            node_install_id: None,
            standby_config: None,
            account_id: None,
            refresh_config: None,
            disk_floor_bytes: None,
            online_local_reads: None,
            local_reads_by_default: false,
            desktop_app_proof_transport: false,
            pending_fork_reads: false,
            hosted_kernel_v2: false,
            desktop_app_proof_resource_origin: None,
        };
        let mut gate_config = fast();
        // Kernel package execution is real work; avoid a fixture timeout
        // accidentally testing connection retry instead of lineage semantics.
        gate_config.attempt_timeout = Duration::from_secs(15);
        gate_config.budget = Duration::from_secs(30);
        let gate = Arc::new(WriteGate::open(&config.socket_directory, gate_config).unwrap());
        gate.set_kernel_v2_upstream(true);
        seed_hosted_contracts(&gate);
        let upstream = Arc::new(Upstream::new(config, Duration::from_secs(30)).unwrap());
        Self {
            world,
            gate,
            upstream,
            requests,
            task,
            _temp: temp,
            _flag: flag,
        }
    }
    async fn base(&self, id: &str) -> (String, String) {
        (
            version(&self.world, id).await,
            canonical(&self.world, id).await,
        )
    }
    async fn save(
        &self,
        id: &str,
        editor: &str,
        base: &(String, String),
        draft: &str,
        key: &str,
    ) -> Value {
        let mut message = tool_call(
            7,
            "call_executor",
            json!({
                "executor":"records_write","operation":"merge_body","run_key":"real-home-proof",
                "arguments":{"record_id":id,"base_version":base.0,"base_text":base.1,
                    "my_text":draft,"reason":"node lineage acceptance","idempotency_key":key}
            }),
        );
        message["params"]["_meta"] = json!({"native/body_merge":{"wait":"none","editor":editor}});
        let body = message.to_string();
        let caller = Caller::new(None, Cancel::new());
        let report = self
            .gate
            .forward(
                &self.upstream,
                &WriteRequest {
                    body: &body,
                    message: &message,
                    revision: None,
                    caller: &caller,
                    outage: None,
                    no_hold: false,
                },
                true,
            )
            .await;
        let reply: Value =
            serde_json::from_str(&report.reply.expect("node custody reply")).unwrap();
        assert_eq!(
            receipt(&reply)["outcome"],
            "saved_on_device",
            "save must enter node custody"
        );
        reply
    }
    async fn drain(&self) {
        assert_eq!(
            self.gate.drain(&self.upstream, None, None, None).await,
            queue::Halt::Empty
        );
        // Every contacted home is the real operation. Invalid lineage bases
        // would be recorded here as a real base_unverified refusal.
        for r in self.requests.lock().unwrap().iter() {
            assert_ne!(r["reason"], "base_unverified");
            assert_eq!(
                r["applied"], true,
                "real home must admit each submitted base: {r}"
            );
        }
    }
    fn sends(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn recovery(&self, id: &str) -> Vec<RecoveryItem> {
        self.gate
            .unmerged
            .list(Some(id), Some(RecoveryState::Open), true)
            .unwrap()
    }
}

async fn serve_home(
    w: World,
    requests: Arc<StdMutex<Vec<Value>>>,
    mut socket: tokio::net::TcpStream,
) {
    let Some(request) = read_request(&mut socket).await else {
        return;
    };
    if request["method"] == "initialize" {
        let reply =
            json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"2025-03-26"}});
        return respond(&mut socket, 200, "application/json", &reply.to_string()).await;
    }
    if request["method"] != "tools/call" {
        return respond(&mut socket, 202, "application/json", "").await;
    }
    let operation = request
        .pointer("/params/arguments/operation")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert_eq!(
        operation, "merge_body",
        "fixture must receive only actual home merge operations"
    );
    let arguments = request["params"]["arguments"]["arguments"].clone();
    let tools = registry();
    let answer = tools
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            w.admin_caller.clone(),
            operation,
            arguments,
        )
        .await;
    let result = match answer {
        Ok(body) => {
            requests.lock().unwrap().push(body.clone());
            json!({"content":[],"structuredContent":body,"isError":false})
        }
        Err(error) => panic!("real KernelV2 merge failed: {error}"),
    };
    let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
    respond(&mut socket, 200, "application/json", &reply.to_string()).await;
}

#[tokio::test(flavor = "current_thread")]
async fn node_real_home_three_saves_keep_remote_edit_at_every_step() {
    let rig = HomeRig::new().await;
    let id = record(&rig.world, "abc").await;
    let base = rig.base(&id).await;
    set_body(&rig.world, &id, "abC").await;
    rig.save(&id, "vault", &base, "Abc", "three-1").await;
    rig.drain().await;
    assert_eq!(canonical(&rig.world, &id).await, "AbC");
    rig.save(&id, "vault", &base, "ABc", "three-2").await;
    rig.drain().await;
    assert_eq!(canonical(&rig.world, &id).await, "ABC");
    rig.save(&id, "vault", &base, "ABcd", "three-3").await;
    rig.drain().await;
    assert_eq!(canonical(&rig.world, &id).await, "ABCd");
    assert_eq!(rig.sends(), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn node_real_home_peer_deletion_stale_draft_does_not_resurrect() {
    let rig = HomeRig::new().await;
    let id = record(&rig.world, "").await;
    let base = rig.base(&id).await;
    rig.save(&id, "vault", &base, "axb", "delete-1").await;
    rig.drain().await;
    set_body(&rig.world, &id, "ab").await;
    let before = rig.sends();
    rig.save(&id, "vault", &base, "axb", "delete-unchanged")
        .await;
    rig.drain().await;
    assert_eq!(rig.sends(), before);
    assert_eq!(canonical(&rig.world, &id).await, "ab");
    rig.save(&id, "vault", &base, "axb!", "delete-new").await;
    rig.drain().await;
    assert_eq!(canonical(&rig.world, &id).await, "ab!");
}

#[tokio::test(flavor = "current_thread")]
async fn node_real_home_undo_preserves_later_remote_edit() {
    for remote in [false, true] {
        let rig = HomeRig::new().await;
        let id = record(&rig.world, "abc").await;
        let base = rig.base(&id).await;
        rig.save(&id, "vault", &base, "Abc", "undo-1").await;
        rig.drain().await;
        if remote {
            set_body(&rig.world, &id, "AbC").await;
        }
        rig.save(&id, "vault", &base, "abc", "undo-2").await;
        rig.drain().await;
        assert_eq!(
            canonical(&rig.world, &id).await,
            if remote { "abC" } else { "abc" }
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn node_real_home_clear_and_continued_typing() {
    let rig = HomeRig::new().await;
    let id = record(&rig.world, "").await;
    let base = rig.base(&id).await;
    for (n, draft) in ["x", "", "Hello", "Hello world"].iter().enumerate() {
        rig.save(&id, "vault", &base, draft, &format!("typing-{n}"))
            .await;
        rig.drain().await;
        assert_eq!(canonical(&rig.world, &id).await, *draft);
    }
    assert!(rig.recovery(&id).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn node_real_home_two_editors_have_independent_lineages() {
    let rig = HomeRig::new().await;
    let id = record(&rig.world, "abc").await;
    let base = rig.base(&id).await;
    rig.save(&id, "vault", &base, "Abc", "editors-vault-1")
        .await;
    rig.drain().await;
    rig.save(&id, "agent", &base, "abC", "editors-agent-1")
        .await;
    rig.drain().await;
    assert_eq!(canonical(&rig.world, &id).await, "AbC");
    rig.save(&id, "vault", &base, "ABc", "editors-vault-2")
        .await;
    rig.drain().await;
    assert_eq!(canonical(&rig.world, &id).await, "ABC");
    let vault = rig.gate.lineages.load(&id, "vault").unwrap().unwrap();
    let agent = rig.gate.lineages.load(&id, "agent").unwrap().unwrap();
    assert_eq!(vault.d_prev, "ABc");
    assert_eq!(agent.d_prev, "abC");
}

#[tokio::test(flavor = "current_thread")]
async fn node_real_home_predecessor_clash_is_quarantined_and_owned_edits_update_one_item() {
    let rig = HomeRig::new().await;
    let id = record(&rig.world, "abc Z").await;
    let base = rig.base(&id).await;
    set_body(&rig.world, &id, "ayc Z").await;
    rig.save(&id, "vault", &base, "axc Z", "clash-1").await;
    rig.drain().await;
    assert_eq!(canonical(&rig.world, &id).await, "ayc Z");
    let first = rig.recovery(&id);
    assert_eq!(first.len(), 1);
    let passage = first[0].id.clone();
    rig.save(&id, "vault", &base, "axc Z!", "clash-free").await;
    rig.drain().await;
    assert_eq!(canonical(&rig.world, &id).await, "ayc Z!");
    let before = rig.sends();
    rig.save(&id, "vault", &base, "axxc Z!", "clash-owned")
        .await;
    rig.drain().await;
    assert_eq!(
        rig.sends(),
        before,
        "owned boundary edit is a recorded no-send"
    );
    let updated = rig.recovery(&id);
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].id, passage);
    assert_eq!(
        updated[0].passage.as_ref().unwrap().mine.as_deref(),
        Some("xx")
    );
    assert_eq!(canonical(&rig.world, &id).await, "ayc Z!");
}

#[tokio::test(flavor = "current_thread")]
async fn node_real_home_deleted_passage_keeps_both_boundary_extensions_in_recovery() {
    for draft in ["mine!", "!mine"] {
        let rig = HomeRig::new().await;
        let id = record(&rig.world, "base").await;
        let base = rig.base(&id).await;
        set_body(&rig.world, &id, "").await;
        rig.save(&id, "vault", &base, "mine", "boundary-1").await;
        rig.drain().await;
        let before = rig.sends();
        rig.save(&id, "vault", &base, draft, "boundary-2").await;
        rig.drain().await;
        assert_eq!(rig.sends(), before);
        assert_eq!(canonical(&rig.world, &id).await, "");
        let recovery = rig.recovery(&id);
        assert_eq!(recovery.len(), 1);
        assert_eq!(
            recovery[0].passage.as_ref().unwrap().mine.as_deref(),
            Some(draft)
        );
    }
}

#[path = "v2_holding_tests.rs"]
mod v2_holding_tests;
