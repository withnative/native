use super::*;
use crate::node::OnlineLocalReads;
use crate::standby::generation_store::tests::{observed, stage};
use axum::{
    body::Bytes, extract::State as HttpState, http::StatusCode, response::IntoResponse,
    routing::post, Router,
};
#[cfg(feature = "v2-kernel-probe")]
#[path = "default_reads_tests.rs"]
mod default_reads;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

fn anonymous_caller() -> Caller {
    Caller::new(None, Cancel::new())
}

const RECORD: &str = "70110000-0000-4000-8000-000000000001";
#[derive(Clone)]
struct Fake {
    db: crate::Db,
    operations: Vec<Value>,
    holding_describe_stall: Arc<AtomicBool>,
    holding_describe_stall_operation: Arc<std::sync::Mutex<Option<String>>>,
    holding_descriptions: Arc<std::sync::Mutex<BTreeMap<String, Value>>>,
    catalog_override: Arc<std::sync::Mutex<Option<Vec<Value>>>>,
    status: Arc<AtomicU16>,
    /// Override only data/bootstrap reads, leaving discovery and probes intact.
    read_reply: Arc<std::sync::Mutex<Option<(u16, String)>>>,
    account_reply: Arc<std::sync::Mutex<Option<(u16, String)>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    fail_reads: Arc<AtomicBool>,
    /// `describe_operation` reports `idempotency_key` for create_record.
    keyed_contract: Arc<AtomicBool>,
    /// The next N create_record calls answer 503.
    create_failures: Arc<AtomicU16>,
    /// `describe_operation` returns a schema that closes out `idempotency_key`.
    keyless_contract: Arc<AtomicBool>,
    /// Writes are refused as `DEPLOYMENT_READ_ONLY`.
    read_only: Arc<AtomicBool>,
    pause_probe: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
    hold_export: Arc<AtomicBool>,
    export_entered: Arc<tokio::sync::Notify>,
    export_resume: Arc<tokio::sync::Notify>,
    revision_bump: Arc<AtomicBool>,
    head_mismatch: Arc<AtomicU16>,
    head_selected_shape: Arc<std::sync::Mutex<Option<String>>>,
    head_maintenance: Arc<AtomicBool>,
    /// 0: unsupported; 1: valid delta; 2: corrupted transport digest.
    delta_mode: Arc<AtomicU16>,
    /// What `SELECT current_principal()` answers; `None` answers no rows.
    principal: Arc<std::sync::Mutex<Option<String>>>,
    pause_principal: Arc<AtomicBool>,
}
fn head_response_headers(
    fake: &Fake,
    operation: &str,
    mut response: axum::response::Response,
) -> axum::response::Response {
    if matches!(operation, "get_authority_act_head" | "authority_act_head") {
        if let Some(selected) = fake.head_selected_shape.lock().unwrap().as_ref() {
            response.headers_mut().insert(
                crate::standby::shapes::SELECTED_SHAPE_HEADER,
                selected.parse().unwrap(),
            );
        }
        if fake.head_maintenance.load(Ordering::Acquire) {
            response
                .headers_mut()
                .insert("x-native-read-only", "true".parse().unwrap());
        }
    }
    response
}
async fn hosted(
    HttpState(fake): HttpState<Fake>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    assert_eq!(
        headers[crate::client_compatibility::HEADER],
        crate::client_compatibility::advertisement()
    );
    let request: Value = serde_json::from_slice(&body).unwrap();
    fake.requests.lock().await.push(request.clone());
    let (executor, operation, _) = target(&request).unwrap_or_default();
    if matches!(
        operation.as_str(),
        "get_authority_act_head" | "authority_act_head"
    ) && (fake.head_selected_shape.lock().unwrap().is_some()
        || fake.head_maintenance.load(Ordering::Acquire))
    {
        assert_eq!(
            headers[crate::standby::shapes::ACCEPTED_SHAPES_HEADER],
            crate::standby::shapes::advertisement()
        );
    }
    if executor == "sql_read" && operation == "query_sql" {
        let override_reply = fake.account_reply.lock().unwrap().clone();
        if let Some((status, body)) = override_reply {
            return (
                StatusCode::from_u16(status).unwrap(),
                axum::Json(serde_json::from_str::<Value>(&body).unwrap()),
            )
                .into_response();
        }
    }
    if executor == "bootstrap" || (executor == "records_read" && operation == "get_record") {
        let reply = fake.read_reply.lock().unwrap().clone();
        if let Some((status, body)) = reply {
            return (
                StatusCode::from_u16(status).unwrap(),
                body.replace("$REQUEST_ID", &request["id"].to_string()),
            )
                .into_response();
        }
    }
    let status = fake.status.load(Ordering::Acquire);
    if status != 0 {
        if status == 200 {
            return head_response_headers(
                &fake,
                &operation,
                (StatusCode::OK, "broken protocol").into_response(),
            );
        }
        let response = (
            StatusCode::from_u16(status).unwrap(),
            "hosted refused or gateway failed",
        )
            .into_response();
        return head_response_headers(&fake, &operation, response);
    }
    let (executor, operation, _) = target(&request).unwrap_or_default();
    if executor == "describe_operation" {
        let stall_operation = fake
            .holding_describe_stall_operation
            .lock()
            .unwrap()
            .clone();
        if fake.holding_describe_stall.load(Ordering::Acquire)
            || stall_operation.as_deref() == Some(operation.as_str())
        {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        let description = fake
            .holding_descriptions
            .lock()
            .unwrap()
            .get(&operation)
            .cloned();
        if let Some(description) = description {
            return axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"result":{"isError":false,"content":[],"structuredContent":description}})).into_response();
        }
    }
    let result = if operation == "get_authority_act_head" || operation == "authority_act_head" {
        // Read the bump flag before the await so the common path holds no
        // extra state across it.
        let bump = status == 0 && fake.revision_bump.load(Ordering::Acquire);
        let head = crate::standby::delta_transport::observe_authority_act_head(&fake.db, "route-1")
            .await
            .unwrap();
        if fake.pause_probe.swap(false, Ordering::AcqRel) {
            fake.entered.notify_one();
            fake.resume.notified().await;
        }
        // Stub interchange-revision bump: the authority authors a revision
        // this build cannot read.
        let mut head_value = serde_json::to_value(&head).unwrap();
        if bump {
            head_value["head"]["native_interchange_revision"] =
                json!(crate::standby::REQUIRED_NATIVE_INTERCHANGE_REVISION + 1);
        }
        match fake.head_mismatch.load(Ordering::Acquire) {
            1 => head_value["route_database_id"] = json!("other-route"),
            2 => head_value["head"]["origin_database_id"] = json!("other-origin"),
            _ => (),
        }
        json!({"isError":false,"content":[],"structuredContent":head_value})
    } else if request["method"] == "tools/list" {
        json!({"tools":[{"name":"call_executor","description":"hosted cached tool","inputSchema":{"type":"object"}}]})
    } else if executor == "describe_operation" && fake.keyed_contract.load(Ordering::Acquire) {
        json!({"isError":false,"content":[],"structuredContent":{"input_schema":{"type":"object","properties":{"type":{"type":"string"},"idempotency_key":{"type":"string"}}}}})
    } else if executor == "describe_operation" && fake.keyless_contract.load(Ordering::Acquire) {
        json!({"isError":false,"content":[],"structuredContent":{"input_schema":{"type":"object","properties":{"type":{"type":"string"}},"additionalProperties":false}}})
    } else if operation == "create_record"
        && executor != "describe_operation"
        && fake.read_only.load(Ordering::Acquire)
    {
        json!({"isError":true,"content":[{"type":"text","text":"this Native deployment is temporarily read-only"}],"structuredContent":{"error_code":"DEPLOYMENT_READ_ONLY","applied":false,"retryable":true}})
    } else if operation == "create_record"
        && executor != "describe_operation"
        && fake
            .create_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
    {
        return (StatusCode::SERVICE_UNAVAILABLE, "gateway down").into_response();
    } else if operation == "authority_act_delta" && fake.delta_mode.load(Ordering::Acquire) != 0 {
        let from = target(&request).unwrap().2["arguments"]["from_exclusive_act"]
            .as_i64()
            .unwrap();
        let delta =
            crate::standby::delta_transport::observe_authority_act_delta(&fake.db, "route-1", from)
                .await
                .unwrap();
        let mut delta = serde_json::to_value(delta).unwrap();
        if fake.delta_mode.load(Ordering::Acquire) == 2 {
            delta["outer_sha256"] = json!("0".repeat(64));
        }
        json!({"isError":false,"content":[],"structuredContent":delta})
    } else if executor == "bootstrap" && request["params"]["arguments"]["format"] == "json" {
        // Like hosted: JSON format carries structuredContent; text does not.
        let payload = json!({"text":"hosted answer","run":{"run_key":"fake-run-key"}});
        json!({"isError":false,"content":[{"type":"text","text":payload.to_string()}],"structuredContent":payload})
    } else if executor == "sql_read" && request.to_string().contains("current_principal()") {
        let rows = fake
            .principal
            .lock()
            .unwrap()
            .clone()
            .map(|principal| json!([{"principal":principal}]))
            .unwrap_or_else(|| json!([]));
        if fake.pause_principal.swap(false, Ordering::AcqRel) {
            fake.entered.notify_one();
            fake.resume.notified().await;
        }
        json!({"isError":false,"content":[],"structuredContent":{"rows":rows}})
    } else if executor == "sql_read" {
        let rows = fake
            .catalog_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| fake.operations.clone());
        json!({"isError":false,"content":[],"structuredContent":{"rows":rows}})
    } else {
        if fake.fail_reads.load(Ordering::Acquire) && executor == "records_read" {
            return (StatusCode::BAD_GATEWAY, "gateway read failure").into_response();
        }
        json!({"isError":false,"content":[{"type":"text","text":"hosted answer"}]})
    };
    head_response_headers(
        &fake,
        &operation,
        axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result})).into_response(),
    )
}

async fn failed_export(
    HttpState(fake): HttpState<Fake>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    assert_eq!(headers["authorization"], "Bearer fixture-token");
    fake.export_entered.notify_one();
    if fake.hold_export.load(Ordering::Acquire) {
        fake.export_resume.notified().await;
    }
    (StatusCode::BAD_GATEWAY, "snapshot export unavailable").into_response()
}

struct FixtureReadPolicy {
    local_reads_by_default: bool,
    snapshot_age_seconds: i64,
    account_binding: &'static str,
}

struct Fixture {
    _dir: tempfile::TempDir,
    db: crate::Db,
    fake: Fake,
    http: tokio::task::JoinHandle<()>,
    node: Arc<Failover>,
    supervisor: StandbySupervisor,
    refresh: Option<BackgroundRefresh>,
    runtime: StandbyRuntimeConfig,
    store: GenerationStore,
    direct: AtomicBool,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_startup(None).await
    }
    // Some(true): accepted copy already on disk; Some(false): empty store.
    // None retains an installed fixture for the routing policy tests.
    async fn with_startup(startup: Option<bool>) -> Self {
        Self::with_refresh(startup, None, false).await
    }

    // refresh: Some(true) is configured, Some(false) has invalid config.
    async fn with_refresh(startup: Option<bool>, refresh: Option<bool>, hold_export: bool) -> Self {
        Box::pin(Self::build(startup, refresh, hold_export, None, false)).await
    }
    async fn online(max_age_seconds: u64) -> Self {
        Box::pin(Self::build(
            None,
            None,
            false,
            Some(OnlineLocalReads { max_age_seconds }),
            false,
        ))
        .await
    }
    async fn build(
        startup: Option<bool>,
        refresh: Option<bool>,
        hold_export: bool,
        online_local_reads: Option<OnlineLocalReads>,
        pending_fork_reads: bool,
    ) -> Self {
        Box::pin(Self::build_with_engine(
            startup,
            refresh,
            hold_export,
            online_local_reads,
            pending_fork_reads,
            false,
        ))
        .await
    }

    async fn build_with_engine(
        startup: Option<bool>,
        refresh: Option<bool>,
        hold_export: bool,
        online_local_reads: Option<OnlineLocalReads>,
        pending_fork_reads: bool,
        kernel_v2: bool,
    ) -> Self {
        Box::pin(Self::build_with_engine_and_policy(
            startup,
            refresh,
            hold_export,
            online_local_reads,
            pending_fork_reads,
            kernel_v2,
            false,
        ))
        .await
    }

    async fn build_with_engine_and_policy(
        startup: Option<bool>,
        refresh: Option<bool>,
        hold_export: bool,
        online_local_reads: Option<OnlineLocalReads>,
        pending_fork_reads: bool,
        kernel_v2: bool,
        local_reads_by_default: bool,
    ) -> Self {
        Box::pin(Self::build_with_engine_policy(
            startup,
            refresh,
            hold_export,
            online_local_reads,
            pending_fork_reads,
            kernel_v2,
            FixtureReadPolicy {
                local_reads_by_default,
                snapshot_age_seconds: 0,
                account_binding: "acct:fixture",
            },
        ))
        .await
    }
    async fn build_with_engine_policy(
        startup: Option<bool>,
        refresh: Option<bool>,
        hold_export: bool,
        online_local_reads: Option<OnlineLocalReads>,
        pending_fork_reads: bool,
        kernel_v2: bool,
        policy: FixtureReadPolicy,
    ) -> Self {
        let FixtureReadPolicy {
            local_reads_by_default,
            snapshot_age_seconds,
            account_binding,
        } = policy;
        let dir = tempfile::tempdir().unwrap();
        #[cfg(feature = "v2-kernel-probe")]
        let kernel = if kernel_v2 {
            Some(
                Box::pin(crate::kernel::create_v2_database(
                    ":memory:",
                    "account",
                    "Owner",
                    account_binding,
                ))
                .await
                .unwrap(),
            )
        } else {
            None
        };
        #[cfg(not(feature = "v2-kernel-probe"))]
        let kernel: Option<(crate::Db, String)> = {
            assert!(!kernel_v2);
            None
        };
        let db = match &kernel {
            Some((db, _)) => db.clone(),
            None => crate::create_database(":memory:").await.unwrap(),
        };
        let account = if kernel_v2 {
            account_binding.into()
        } else {
            crate::identity::resolve_stdio_account_identity(&db, None)
                .await
                .unwrap()
        };
        if !kernel_v2 {
            crate::store::create_record_as(
                &db,
                json!({"id":RECORD,"type":"Document","kind":"note","name":"local-first"}),
                Some(&account),
            )
            .await
            .unwrap();
        }
        if pending_fork_reads {
            let mut registry = crate::mcp::ToolRegistry::new();
            crate::mcp::register_surface_tools(&mut registry).unwrap();
            registry.call(db.clone(), crate::mcp::Caller::local_owner(account.clone()), "set_intent", json!({"run_key":"scout-chair-j748b2", "intent":"Prove pending fork visibility"})).await.unwrap();
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE run_key=? AND account_id=?)",
            )
            .bind("scout-chair-j748b2")
            .bind(&account)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert!(
                exists,
                "proof run must be canonical before the accepted snapshot"
            );
        }
        let origin = if kernel_v2 {
            crate::standby::delta_transport::observe_authority_act_head(&db, "route-1")
                .await
                .unwrap()
                .head()
                .origin_database_id()
                .to_string()
        } else {
            crate::identity::database_id(&db).await.unwrap()
        };
        let runtime = StandbyRuntimeConfig {
            replica_root: dir.path().join("replica"),
            hosted_route_database_id: "route-1".into(),
            origin_database_id: origin.clone(),
        };
        let store =
            GenerationStore::open(&runtime.replica_root, "route-1", Some(origin.clone())).unwrap();
        let provider = StandbyStatusProvider::for_status_only_reason(
            runtime.clone(),
            store.clone(),
            Some(observed()),
            StandbyStatusOnly {
                reason: "startup_readiness_pending".into(),
                candidate_count: 0,
                unusable_candidate_count: 0,
            },
            false,
            false,
        );
        let session = Arc::new(
            StandbyStdioSession::new(
                StandbySessionConfig {
                    runtime: runtime.clone(),
                    store: store.clone(),
                    observed: observed(),
                    surface: McpSurfaceMode::Executor,
                    profile: ExposureProfile::Complete,
                    experimental: ExperimentalExecutors::empty(),
                    selected_account: Some(account.clone()),
                    refresh_configured: false,
                    refresh_available: false,
                },
                provider.clone(),
            )
            .unwrap(),
        );
        let engine_kind = crate::mcp::registry::EngineKind::Sqlite;
        #[cfg(feature = "v2-kernel-probe")]
        let engine_kind = if kernel_v2 {
            crate::mcp::registry::EngineKind::KernelV2
        } else {
            engine_kind
        };
        let local = session
            .operation_rows_for_engine(provider, engine_kind)
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        if startup != Some(false) {
            let (snapshot, manifest) = stage(&store, &db, "node-fixture").await;
            if snapshot_age_seconds != 0 {
                // Qualify an actually old admitted checkpoint, rather than a
                // sync timestamp older than a newly captured snapshot (ignored).
                // A negative age dates it in the future: its age is unknown.
                let mut value: crate::standby_snapshot::StandbySnapshotManifest =
                    serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
                for timestamp in [&mut value.captured_at, &mut value.snapshot_completed_at] {
                    let time = chrono::DateTime::parse_from_rfc3339(timestamp).unwrap()
                        - chrono::Duration::seconds(snapshot_age_seconds);
                    *timestamp = time.to_rfc3339();
                }
                fs::write(&manifest, value.canonical_json().unwrap()).unwrap();
            }
            store
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap();
        }
        if startup.is_none() {
            let recovery = store.activate_for_startup(&observed()).await.unwrap();
            session.install_startup_outcome(recovery).await;
        }
        if refresh == Some(true) && startup != Some(false) {
            // Advance hosted beyond the accepted copy: delta refusal leads to
            // our fake binary endpoint's 502, while the old copy stays usable.
            crate::store::update_record(&db, RECORD, json!({"name":"local-next"}))
                .await
                .unwrap();
        }
        let fake = Fake {
            db: db.clone(),
            operations: local.clone(),
            holding_describe_stall: Default::default(),
            holding_describe_stall_operation: Default::default(),
            holding_descriptions: Default::default(),
            catalog_override: Default::default(),
            status: Arc::new(AtomicU16::new(0)),
            read_reply: Default::default(),
            account_reply: Default::default(),
            requests: Arc::new(Mutex::new(Vec::new())),
            fail_reads: Arc::new(AtomicBool::new(false)),
            principal: Default::default(),
            pause_principal: Default::default(),
            keyed_contract: Arc::new(AtomicBool::new(false)),
            create_failures: Arc::new(AtomicU16::new(0)),
            keyless_contract: Arc::new(AtomicBool::new(false)),
            read_only: Arc::new(AtomicBool::new(false)),
            pause_probe: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(tokio::sync::Notify::new()),
            resume: Arc::new(tokio::sync::Notify::new()),
            hold_export: Arc::new(AtomicBool::new(hold_export)),
            export_entered: Arc::new(tokio::sync::Notify::new()),
            export_resume: Arc::new(tokio::sync::Notify::new()),
            revision_bump: Arc::new(AtomicBool::new(false)),
            head_mismatch: Arc::new(AtomicU16::new(0)),
            head_selected_shape: Default::default(),
            head_maintenance: Default::default(),
            delta_mode: Arc::new(AtomicU16::new(0)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/mcp/{workspace}", post(hosted))
            .route(
                "/v1/databases/{workspace}/standby-snapshot/exports",
                post(failed_export),
            )
            .with_state(fake.clone());
        let http = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let credential = dir.path().join("token");
        fs::write(&credential, "fixture-token").unwrap();
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).unwrap();
        let standby_path = dir.path().join("standby.json");
        fs::write(
            &standby_path,
            json!({
                "replica_root":runtime.replica_root,
                "hosted_route_database_id":runtime.hosted_route_database_id,
                "origin_database_id":runtime.origin_database_id,
            })
            .to_string(),
        )
        .unwrap();
        let refresh_path = dir.path().join("refresh.json");
        fs::write(
            &refresh_path,
            if refresh == Some(false) {
                json!({})
            } else {
                json!({
                    "contract":"native.standby-refresh-config.v1", "version":1,
                    "hosted_origin":format!("http://{address}"), "credential_file":credential,
                    "refresh_interval_seconds":3600,
                })
            }
            .to_string(),
        )
        .unwrap();
        let config = NodeConfig {
            working_note_appends: false,
            markdown_folder: None,
            hosted_base_url: format!("http://{address}"),
            home_id: "home".into(),
            db_id: "route-1".into(),
            credential_file: credential,
            socket_directory: dir.path().join("socket"),
            oauth_auth_file: None,
            node_install_key_file: None,
            node_install_id: None,
            standby_config: startup.map(|_| standby_path),
            account_id: Some(account),
            refresh_config: refresh.map(|_| refresh_path),
            disk_floor_bytes: None,
            online_local_reads,
            local_reads_by_default,
            desktop_app_proof_transport: false,
            desktop_app_proof_resource_origin: local_reads_by_default
                .then(|| format!("http://{address}")),
            pending_fork_reads,
            hosted_kernel_v2: local_reads_by_default,
        };
        let (_listener, _guard) = bind_socket(&config).await.unwrap();
        let (supervisor, local, origin, background) = if startup.is_some() {
            let standby = start_standby_with_identity(&config, observed(), None)
                .unwrap()
                .unwrap();
            (
                standby.supervisor,
                standby.local,
                standby.origin,
                standby.refresh,
            )
        } else {
            (
                StandbySupervisor::start(session).unwrap(),
                local,
                origin,
                None,
            )
        };
        let config_socket_directory = config.socket_directory.clone();
        let upstream = Arc::new(Upstream::new(config, Duration::from_secs(5)).unwrap());
        let node = Arc::new(
            Failover::new(upstream, supervisor.dispatcher(), local, origin)
                .unwrap()
                .with_refresh_hints(background.as_ref().map(|r| r.hints()))
                .with_gate(Some(Arc::new(
                    WriteGate::open(
                        &config_socket_directory,
                        gate::GateConfig {
                            backoff_start: Duration::from_millis(10),
                            backoff_max: Duration::from_millis(50),
                            disk_floor_bytes: 0,
                            ..gate::GateConfig::default()
                        },
                    )
                    .unwrap(),
                ))),
        );
        Self {
            _dir: dir,
            db,
            fake,
            http,
            node,
            supervisor,
            refresh: background,
            runtime,
            store,
            direct: AtomicBool::new(false),
        }
    }
    async fn send(&self, message: Value) -> Value {
        self.send_protocol(message, crate::mcp::PROTOCOL_VERSION)
            .await
    }
    async fn send_protocol(&self, message: Value, protocol: &str) -> Value {
        let reply = self
            .node
            .route(
                &message.to_string(),
                message,
                Some(protocol),
                &self.direct,
                &anonymous_caller(),
            )
            .await
            .unwrap();
        serde_json::from_str(&reply).unwrap()
    }
    async fn finish(self) {
        self.node.shutdown_pending_fork().await.unwrap();
        drop(self.node);
        if let Some(refresh) = self.refresh {
            refresh.stop().await;
        }
        self.supervisor.shutdown().await.unwrap();
        self.fake.export_resume.notify_waiters();
        self.http.abort();
        self.db.close().await;
    }
}
fn read(wrapped: bool) -> Value {
    let mut envelope = json!({"operation":"get_record","arguments":{"ids":[RECORD]},"format":"json","run_key":"hosted-existing-run"});
    if wrapped {
        envelope["executor"] = json!("records_read");
    }
    json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":if wrapped {"call_executor"} else {"records_read"},"arguments":envelope}})
}
fn write() -> Value {
    json!({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":"create_record","arguments":{"type":"Document","kind":"note","name":"write","reason":"test write"}}}})
}
fn list() -> Value {
    json!({"jsonrpc":"2.0","id":44,"method":"tools/list"})
}
fn text(reply: &Value) -> String {
    reply["result"]["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn floor_ordering_and_unknown_heads_are_conservative() {
    let mut floor = Floor::default();
    floor.observe(0, 100, V1.into());
    let before = floor.pending;
    floor.begin_write();
    floor.finish_write(true);
    floor.observe(before, 100, V1.into());
    assert!(floor.unresolved);
    assert!(floor.label(Some(100)).unwrap().contains("at least act 100"));
    let after = floor.pending;
    floor.observe(after, 101, V1.into());
    assert!(!floor.unresolved);
    assert!(floor.label(Some(100)).is_some());
    assert!(floor.label(Some(101)).is_none());
    assert!(floor.label(None).is_some());
    floor.begin_write();
    floor.observe(floor.pending, 102, V1.into());
    assert!(
        floor.unresolved,
        "a probe while a write is in flight cannot resolve it"
    );
    floor.finish_write(true);
    assert!(
        floor.unresolved,
        "no successful post-write probe means unresolved"
    );
}

fn receipt(structured: Value) -> String {
    json!({"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":structured}})
        .to_string()
}

#[test]
fn receipt_act_reads_only_engine_receipt_positions() {
    assert_eq!(
        receipt_act(Some(&receipt(json!({"id":"r","act":7})))),
        Some(7)
    );
    // create_many compact acts: objects, or bare integers; max wins.
    assert_eq!(
        receipt_act(Some(&receipt(
            json!({"ok":true,"acts":[{"index":0,"act":4},{"index":1,"act":9},3]})
        ))),
        Some(9)
    );
    // Verbose create_many and artifact refresh receipts.
    assert_eq!(
        receipt_act(Some(&receipt(
            json!({"results":[{"record":{"act":5}},{"record":{"act":6}}],"refresh":{"record":{"act":8}}})
        ))),
        Some(8)
    );
    // Caller-authored metadata/body never counts.
    assert_eq!(
        receipt_act(Some(&receipt(
            json!({"id":"r","metadata":{"act":999},"body":{"act":998}})
        ))),
        None
    );
    assert_eq!(
        receipt_act(Some(&receipt(json!({"act":3,"metadata":{"act":999}})))),
        Some(3)
    );
    // Absent, malformed, non-positive, errors, refusals and held writes.
    assert_eq!(receipt_act(None), None);
    assert_eq!(receipt_act(Some("not json")), None);
    assert_eq!(receipt_act(Some(&receipt(json!({"act":"7"})))), None);
    assert_eq!(receipt_act(Some(&receipt(json!({"act":0})))), None);
    assert_eq!(receipt_act(Some(&receipt(json!({"act":-4})))), None);
    assert_eq!(
        receipt_act(Some(&receipt(json!({"act":7,"outcome":"refused"})))),
        None
    );
    assert_eq!(
        receipt_act(Some(&receipt(
            json!({"act":7,"outcome":"accepted_pending"})
        ))),
        None
    );
    let error = json!({"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x","data":{"act":7}}});
    assert_eq!(receipt_act(Some(&error.to_string())), None);
    let is_error =
        json!({"jsonrpc":"2.0","id":1,"result":{"isError":true,"structuredContent":{"act":7}}});
    assert_eq!(receipt_act(Some(&is_error.to_string())), None);
}

#[test]
fn receipt_raise_is_monotonic_and_leaves_resolution_to_the_probe() {
    let mut floor = Floor::default();
    floor.raise(10);
    assert_eq!(floor.act, Some(10));
    floor.raise(4);
    assert_eq!(floor.act, Some(10), "never lowers");
    floor.raise(0);
    floor.raise(-3);
    assert_eq!(floor.act, Some(10));
    floor.raise(12);
    assert_eq!(floor.act, Some(12));
    floor.begin_write();
    floor.finish_write(true);
    floor.raise(13);
    assert!(floor.unresolved, "a receipt does not resolve the floor");
    // A later probe at a lower head cannot lower it either.
    let pending = floor.pending;
    floor.observe(pending, 11, V1.into());
    assert_eq!(floor.act, Some(13));
}

const V1: &str = "v1:origin";
const V2: &str = "v2:origin:genesis-a";

#[test]
fn floor_from_another_act_lineage_re_anchors_only_when_quiescent() {
    // The VM node kept a v1 floor (68739) across the v1 to kernel-v2 cutover,
    // above every v2 head, which disabled online local reads for hours.
    let mut floor = Floor::default();
    floor.observe(0, 68739, V1.into());
    assert_eq!(floor.lineage.as_deref(), Some(V1));
    // A write in flight: keep the old floor and stay unresolved.
    floor.begin_write();
    let started = floor.pending;
    floor.observe(started, 66400, V2.into());
    assert_eq!(floor.act, Some(68739));
    assert!(floor.unresolved);
    floor.finish_write(false);
    // Quiescent probe in the new lineage: re-anchor to the hosted head.
    let started = floor.pending;
    floor.observe(started, 66400, V2.into());
    assert_eq!(floor.act, Some(66400));
    assert_eq!(floor.lineage.as_deref(), Some(V2));
    assert!(!floor.unresolved);
    assert!(floor.label(Some(66400)).is_none());
    // Within one lineage a lower head still never lowers the floor.
    floor.raise(66410);
    let started = floor.pending;
    floor.observe(started, 66405, V2.into());
    assert_eq!(floor.act, Some(66410));
    // A restore or re-cut inside v2 (new genesis) is another lineage.
    let started = floor.pending;
    floor.observe(started, 120, "v2:origin:genesis-b".into());
    assert_eq!(floor.act, Some(120));

    // A floor persisted before lineage tracking re-anchors only when it sits
    // above a kernel-v2 head.
    let mut legacy: Floor =
        serde_json::from_value(json!({"act":68739,"pending":7,"unresolved":false})).unwrap();
    assert_eq!(legacy.lineage, None);
    legacy.observe(7, 66400, V2.into());
    assert_eq!(legacy.act, Some(66400));
    let mut legacy: Floor =
        serde_json::from_value(json!({"act":100,"pending":0,"unresolved":false})).unwrap();
    legacy.observe(0, 120, V2.into());
    assert_eq!(legacy.act, Some(120));
    let mut legacy: Floor =
        serde_json::from_value(json!({"act":100,"pending":0,"unresolved":false})).unwrap();
    legacy.observe(0, 90, V1.into());
    assert_eq!(legacy.act, Some(100), "a v1 head keeps the old rule");
}

#[tokio::test]
async fn body_merge_hook_sequence_finishes_each_write_once() {
    // Body merges send through the gate (before_send/after_send) and then
    // report the receipt. Finishing the write a second time used to underflow
    // `active_writes`, so no probe was ever quiescent again.
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let node = fixture.node.as_ref();
    assert!(gate::Outage::before_send(node).await);
    gate::Outage::after_send(node, true).await;
    let receipt = json!({"jsonrpc":"2.0","id":1,"result":{"isError":false,
        "structuredContent":{"act":424242}}})
    .to_string();
    gate::Outage::note_receipt(node, Some(&receipt)).await;
    let state = node.state.lock().await;
    assert_eq!(state.persisted.floor.active_writes, 0);
    assert_eq!(state.persisted.floor.act, Some(424242));
    assert!(state.persisted.floor.unresolved);
    drop(state);
    fixture.finish().await;
}

#[tokio::test]
async fn health_auth_refusal_and_midflight_read_failover() {
    let fixture = Fixture::new().await;
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::Reachable);
    fixture.node.refresh_discovery().await;
    fixture.fake.status.store(401, Ordering::Release);
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::AuthRefused);
    let refused = fixture.send(read(true)).await;
    assert_eq!(refused["error"]["data"]["http_status"], 401);
    assert!(!refused.to_string().contains("local-first"));
    fixture.fake.status.store(200, Ordering::Release);
    fixture.node.probe().await;
    assert_eq!(
        fixture.node.state.lock().await.health,
        Health::ProtocolFailed
    );
    // A reachable hosted speaking malformed protocol is not "down":
    // the malformed hosted answer is forwarded, not replaced locally.
    let forwarded = fixture.send(read(true)).await;
    assert!(
        !forwarded.to_string().contains("local-first"),
        "{forwarded}"
    );
    assert_eq!(forwarded["error"]["data"]["outcome"], "unknown");
    assert_eq!(forwarded["error"]["data"]["http_status"], 200);
    fixture.fake.status.store(0, Ordering::Release);
    fixture.node.probe().await;
    fixture.fake.fail_reads.store(true, Ordering::Release);
    let local = fixture.send(read(true)).await;
    assert!(text(&local).contains("local-first"), "{local}");
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::Unreachable);
    // A write is never answered from the local copy. One the node may hold is
    // held for hosted (it is not applied locally); any other is refused.
    let mutation = fixture.send(write()).await;
    assert_eq!(
        mutation["result"]["structuredContent"]["outcome"], "accepted_pending",
        "{mutation}"
    );
    let other = json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"coordination_write","operation":"set_intent","arguments":{"intent":"x"}}}});
    assert_eq!(
        fixture.send(other).await["error"]["data"]["outcome"],
        "not_sent"
    );
    let cached = fixture.send(list()).await;
    assert_eq!(cached["id"], 44);
    assert_eq!(cached["result"]["tools"][0]["name"], "call_executor");
    fixture.finish().await;
}

#[tokio::test]
async fn revision_bump_keeps_forwarding_and_marks_local_stale() {
    let fixture = Fixture::new().await;
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::Reachable);
    // Stub a revision bump: hosted authors a newer interchange revision.
    fixture.fake.revision_bump.store(true, Ordering::Release);
    fixture.node.probe().await;
    assert_eq!(
        fixture.node.state.lock().await.health,
        Health::RevisionUnsupported
    );
    assert!(
        !fixture.node.state.lock().await.health.offline(),
        "forwarding must continue across a revision bump"
    );
    // Reads still forward to hosted, not to the stale local copy.
    let forwarded = fixture.send(read(true)).await;
    assert!(text(&forwarded).contains("hosted answer"), "{forwarded}");
    assert!(!text(&forwarded).contains("local-first"), "{forwarded}");
    // Local-only status reports the stale actionable state, in text and
    // in machine-readable structure with the actual age preserved.
    let status_request = json!({"jsonrpc":"2.0","id":46,"method":"tools/call","params":{"name":"standby_status","arguments":{"format":"json"}}});
    let status = fixture.send(status_request.clone()).await;
    assert!(
        text(&status).contains("newer interchange revision"),
        "{status}"
    );
    let structured = &status["result"]["structuredContent"];
    assert_eq!(
        structured["node_health"]["state"], "revision_unsupported",
        "{status}"
    );
    assert_eq!(
        structured["node_health"]["local_reads_stale"], true,
        "{status}"
    );
    assert!(
        structured["node_health"]["next_step"]
            .as_str()
            .is_some_and(|step| step.contains("Upgrade")),
        "{status}"
    );
    assert!(
        structured["degraded_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons
                .iter()
                .any(|reason| reason == "revision_unsupported")),
        "{status}"
    );
    assert!(
        structured["freshness"]["age_seconds"].is_number()
            || structured["freshness"]["age_seconds"].is_null(),
        "age fields keep their actual values, never rewritten: {status}"
    );
    // A later genuine outage keeps serving locally but retains the
    // revision incompatibility in both text and structure.
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::Unreachable);
    assert!(
        fixture.node.state.lock().await.revision_unsupported,
        "revision incompatibility survives a later outage"
    );
    let local = fixture.send(read(true)).await;
    assert!(text(&local).contains("local-first"), "{local}");
    let outage_status = &fixture.send(status_request.clone()).await["result"]["structuredContent"];
    assert_eq!(
        outage_status["node_health"]["state"], "revision_unsupported",
        "{outage_status}"
    );
    // Recovery on a compatible validated head clears health and flag.
    fixture.fake.status.store(0, Ordering::Release);
    fixture.fake.revision_bump.store(false, Ordering::Release);
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::Reachable);
    assert!(!fixture.node.state.lock().await.revision_unsupported);
    let recovered = &fixture.send(status_request).await["result"]["structuredContent"];
    assert!(
        recovered.get("node_health").is_none(),
        "compatible head clears the structured revision state: {recovered}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn offline_set_discovery_and_restart_are_bound_and_conservative() {
    let fixture = Fixture::new().await;
    fixture.node.refresh_discovery().await;
    let key = crate::mcp::PROTOCOL_VERSION;
    fixture.node.state.lock().await.health = Health::Unreachable;
    let local = fixture.send(read(true)).await;
    assert!(text(&local).contains("local-first"));
    assert!(text(&local).contains("this copy may be missing writes acknowledged by hosted"));
    let describe_ok = json!({"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"describe_operation","arguments":{"executor":"records_read","operation":"get_record"}}});
    let described = fixture.send(describe_ok).await;
    assert!(text(&described).contains("Availability:"), "{described}");
    let snapshot = fixture.node.state.lock().await.persisted.clone();
    let (file, recovered) = StateFile::open(
        &fixture.node.upstream.config.socket_directory,
        snapshot.binding.clone(),
    )
    .unwrap();
    assert_eq!(file.path, fixture.node.file.path);
    assert_eq!(
        recovered.discovery[key].tools,
        snapshot.discovery[key].tools
    );
    let restarted = Arc::new(
        Failover::new(
            fixture.node.upstream.clone(),
            fixture.supervisor.dispatcher(),
            fixture.node.local.clone(),
            snapshot.binding.origin.clone(),
        )
        .unwrap(),
    );
    restarted.state.lock().await.health = Health::Unreachable;
    let request = list();
    let cached = restarted
        .route(
            &request.to_string(),
            request,
            Some(key),
            &AtomicBool::new(false),
            &anonymous_caller(),
        )
        .await
        .unwrap();
    assert!(cached.contains("hosted cached tool"));
    drop(restarted);
    let account_inspect = fixture
        .node
        .local
        .iter()
        .find(|r| r["operation"] == "manage_account_config.inspect")
        .unwrap();
    let cache = snapshot.discovery.get(key);
    assert!(!fixture.node.supported(
        cache,
        account_inspect["executor"].as_str().unwrap(),
        "manage_account_config.inspect"
    ));
    {
        let mut state = fixture.node.state.lock().await;
        let row = state
            .persisted
            .discovery
            .get_mut(key)
            .unwrap()
            .operations
            .iter_mut()
            .find(|r| r["executor"] == "records_read" && r["operation"] == "get_record")
            .unwrap();
        row["contract_digest"] = json!("mismatch");
    }
    let refused = fixture.send(read(true)).await;
    assert_eq!(refused["error"]["data"]["outcome"], "unavailable_offline");
    let describe = json!({"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"describe_operation","arguments":{"executor":"records_read","operation":"get_record"}}});
    assert_eq!(
        fixture.send(describe).await["error"]["data"]["outcome"],
        "unavailable_offline"
    );
    let catalogue = json!({"jsonrpc":"2.0","id":46,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"sql_read","operation":"query_sql","arguments":{"sql":"SELECT executor, operation FROM catalog_operations WHERE executor = 'records_read' AND operation = 'get_record' ORDER BY executor, operation"},"format":"json"}}});
    let filtered = fixture.send(catalogue).await;
    assert_eq!(
        filtered["result"]["structuredContent"]["rows"],
        json!([]),
        "{filtered}"
    );
    assert!(text(&filtered).contains("offline surface"));
    {
        let mut state = fixture.node.state.lock().await;
        let row = state
            .persisted
            .discovery
            .get_mut(key)
            .unwrap()
            .operations
            .iter_mut()
            .find(|r| r["executor"] == "records_read" && r["operation"] == "get_record")
            .unwrap();
        row["contract_digest"] = fixture
            .node
            .local_row("records_read", "get_record")
            .unwrap()["contract_digest"]
            .clone();
        row["access"] = Value::Null;
    }
    assert_eq!(
        fixture.send(read(true)).await["error"]["data"]["outcome"],
        "unavailable_offline"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn cold_start_keeps_direct_shape_working_after_recovery() {
    let fixture = Fixture::new().await;
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    let direct_list = fixture.send(list()).await;
    assert!(direct_list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "records_read"));
    assert!(fixture.direct.load(Ordering::Acquire));
    assert!(text(&fixture.send(read(false)).await).contains("local-first"));
    let bootstrap = json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"bootstrap","arguments":{"format":"json"}}});
    let response = fixture.send(bootstrap).await;
    assert_eq!(
        response["result"]["structuredContent"]["outage_bootstrap"], true,
        "{response}"
    );
    fixture.fake.status.store(0, Ordering::Release);
    fixture.node.probe().await;
    let mut direct = read(false);
    direct["params"]["_meta"] = json!({"private-test":"preserved"});
    assert!(text(&fixture.send(direct).await).contains("hosted answer"));
    let requests = fixture.fake.requests.lock().await;
    let wrapped = requests
        .iter()
        .find(|r| r["id"] == 17 && r["params"]["name"] == "call_executor")
        .unwrap();
    assert_eq!(wrapped["params"]["arguments"]["executor"], "records_read");
    assert_eq!(
        wrapped["params"]["arguments"]["run_key"],
        "hosted-existing-run"
    );
    assert_eq!(wrapped["params"]["_meta"]["private-test"], "preserved");
    drop(requests);
    fixture.finish().await;
}

#[tokio::test]
async fn probe_started_before_write_cannot_resolve_and_failed_probe_retains_floor() {
    let fixture = Fixture::new().await;
    fixture.node.refresh_discovery().await;
    fixture.node.probe().await;
    fixture.fake.pause_probe.store(true, Ordering::Release);
    let node = fixture.node.clone();
    let probe = tokio::spawn(async move {
        node.probe().await;
    });
    fixture.fake.entered.notified().await;
    let _ = fixture.send(write()).await;
    assert!(fixture.node.state.lock().await.persisted.floor.unresolved);
    fixture.fake.status.store(502, Ordering::Release);
    fixture.fake.resume.notify_one();
    probe.await.unwrap();
    // The requested post-write probe fails; no older observation resolves it.
    fixture.node.probe().await;
    assert!(fixture.node.state.lock().await.persisted.floor.unresolved);
    let local = fixture.send(read(true)).await;
    assert!(text(&local).contains("this copy may be missing writes acknowledged by hosted"));
    let persisted = fixture.node.state.lock().await.persisted.clone();
    let (_, recovered) = StateFile::open(
        &fixture.node.upstream.config.socket_directory,
        persisted.binding,
    )
    .unwrap();
    assert!(recovered.floor.unresolved);
    assert_eq!(recovered.floor.pending, persisted.floor.pending);
    fixture.fake.status.store(0, Ordering::Release);
    fixture.node.probe().await;
    assert!(!fixture.node.state.lock().await.persisted.floor.unresolved);
    fixture.finish().await;
}

#[test]
fn wrapping_exclusions_and_envelope_preservation() {
    for name in [
        "bootstrap",
        "describe_operation",
        "call_executor",
        "standby_status",
    ] {
        let mut message = json!({"method":"tools/call","params":{"name":name,"arguments":{}}});
        let original = message.clone();
        wrap_direct(&mut message);
        assert_eq!(message, original);
    }
    let message = read(true);
    let (_, _, envelope) = target(&message).unwrap();
    assert_eq!(envelope["run_key"], "hosted-existing-run");
    assert!(envelope.get("executor").is_none());
}

#[tokio::test]
async fn node_recovers_preaccepted_generation_before_serving_offline_reads() {
    let fixture = Fixture::with_startup(Some(true)).await;
    // Composition returned without awaiting recovery on this listener runtime.
    assert!(text(&fixture.send(read(true)).await).contains("hosted answer"));
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    let reply = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let reply = fixture.send(read(true)).await;
            if reply["result"]["isError"] == false {
                break reply;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("preaccepted generation must finish startup readiness");
    assert!(text(&reply).contains("local-first"), "{reply}");
    fixture.finish().await;
}

#[tokio::test]
async fn node_startup_without_a_generation_reports_recovery_reason() {
    let fixture = Fixture::with_startup(Some(false)).await;
    let status = json!({"jsonrpc":"2.0","id":88,"method":"tools/call","params":{"name":"standby_status","arguments":{"format":"json"}}});
    let reply = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let reply = fixture.send(status.clone()).await;
            if reply.to_string().contains("no_usable_generation") {
                break reply;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("cold startup must replace startup_readiness_pending");
    assert!(
        !reply.to_string().contains("startup_readiness_pending"),
        "{reply}"
    );
    assert!(text(&fixture.send(read(true)).await).contains("hosted answer"));
    let local = fixture.send(local_only(read(true))).await;
    assert!(local.to_string().contains("unavailable_offline"), "{local}");
    fixture.finish().await;
}

#[tokio::test]
async fn outage_bootstrap_is_scoped_and_echoes_only_a_carried_key() {
    let fixture = Fixture::new().await;
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    let carried_key = "scout-chair-j748b2";
    assert!(matches!(
        crate::runkey::validate(Some(carried_key)),
        crate::runkey::KeyOutcome::Valid(_)
    ));
    for key in [None, Some(carried_key)] {
        let mut arguments = json!({"format":"json"});
        if let Some(key) = key {
            arguments["run_key"] = json!(key);
        }
        let request = json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"bootstrap","arguments":arguments}});
        let response = fixture.send(request.clone()).await;
        let payload = &response["result"]["structuredContent"];
        assert_eq!(payload["outage_bootstrap"], true, "{response}");
        assert_eq!(payload["node_routing"]["canonical_writes"], "unavailable");
        assert!(text(&response).contains("canonical writes are unavailable"));
        assert!(payload.get("run").is_none(), "{response}");
        assert_eq!(payload["outage"]["run_key"], json!(key));
        assert!(payload.get("session").is_none(), "{response}");
        assert!(payload.get("next_steps").is_none(), "{response}");
        assert!(!payload["outage"].to_string().contains("set_intent"));
        // Recovery must forward the exact bootstrap arguments to hosted.
        fixture.fake.status.store(0, Ordering::Release);
        fixture.node.probe().await;
        assert!(text(&fixture.send(request.clone()).await).contains("hosted answer"));
        assert!(fixture
            .fake
            .requests
            .lock()
            .await
            .iter()
            .any(|r| r == &request));
        fixture.fake.status.store(502, Ordering::Release);
        fixture.node.probe().await;
    }
    fixture.finish().await;
}

fn status_request() -> Value {
    json!({"jsonrpc":"2.0","id":88,"method":"tools/call","params":{"name":"standby_status","arguments":{"format":"json"}}})
}

async fn wait_status(fixture: &Fixture, predicate: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let reply = fixture.send(status_request()).await;
            let status = &reply["result"]["structuredContent"];
            if predicate(status) {
                break status.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("node standby status did not reach expected state")
}

#[tokio::test]
async fn node_watcher_serves_a_generation_accepted_after_startup() {
    let fixture = Fixture::with_startup(Some(true)).await;
    let initial = wait_status(&fixture, |s| s["mode"] == "standby").await;
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    assert!(text(&fixture.send(read(false)).await).contains("local-first"));
    crate::store::update_record(&fixture.db, RECORD, json!({"name":"local-next"}))
        .await
        .unwrap();
    let (snapshot, manifest) = stage(&fixture.store, &fixture.db, "node-late-copy").await;
    let accepted = fixture
        .store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    assert_ne!(initial["serving_generation"]["generation_id"], accepted.id);
    wait_status(&fixture, |s| {
        s["serving_generation"]["generation_id"] == accepted.id
    })
    .await;
    let response = fixture.send(read(false)).await;
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(text(&response).contains("local-next"));
    fixture.finish().await;
}

#[tokio::test]
async fn node_refresh_failure_keeps_generation_and_emits_cause_hints() {
    let fixture = Fixture::with_refresh(Some(true), Some(true), false).await;
    let failed = wait_status(&fixture, |s| {
        s["mode"] == "standby" && s["refresh"]["last_failure_class"] == "network"
    })
    .await;
    assert_eq!(failed["refresh"]["configured"], true);
    assert_eq!(failed["refresh"]["controller_available"], true);
    assert_eq!(failed["refresh"]["last_attempt_cause"], "startup");
    assert_eq!(failed["refresh"]["refresh_active"], false);
    let generation = failed["serving_generation"]["generation_id"].clone();
    assert!(text(&fixture.send(read(true)).await).contains("hosted answer"));
    let write = json!({"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_write","operation":"create_record","arguments":{}}}});
    assert!(text(&fixture.send(write).await).contains("hosted answer"));
    wait_status(&fixture, |s| {
        s["refresh"]["last_attempt_cause"] == "after_admitted_write"
            && s["refresh"]["refresh_active"] == false
    })
    .await;
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    assert!(text(&fixture.send(read(true)).await).contains("local-first"));
    fixture.fake.status.store(0, Ordering::Release);
    fixture.node.probe().await;
    let recovered = wait_status(&fixture, |s| {
        s["refresh"]["last_attempt_cause"] == "network_recovery"
            && s["refresh"]["refresh_active"] == false
    })
    .await;
    assert_eq!(recovered["serving_generation"]["generation_id"], generation);
    fixture.finish().await;
}

#[tokio::test]
async fn node_invalid_refresh_config_reports_unavailable_without_blocking_forwarding() {
    let fixture = Fixture::with_refresh(Some(true), Some(false), false).await;
    let status = wait_status(&fixture, |s| s["mode"] == "standby").await;
    assert_eq!(status["refresh"]["configured"], true);
    assert_eq!(status["refresh"]["controller_available"], false);
    assert!(text(&fixture.send(read(true)).await).contains("hosted answer"));
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    assert!(text(&fixture.send(read(true)).await).contains("local-first"));
    fixture.finish().await;
}

#[tokio::test]
async fn node_refresh_shutdown_cancels_inflight_export_and_releases_single_owner() {
    let mut fixture = Fixture::with_refresh(Some(false), Some(true), true).await;
    tokio::time::timeout(
        Duration::from_secs(30),
        fixture.fake.export_entered.notified(),
    )
    .await
    .unwrap();
    assert!(text(&fixture.send(read(true)).await).contains("hosted answer"));
    let config = crate::standby::StandbyRefreshConfig::from_json(
        &fs::read(
            fixture
                .node
                .upstream
                .config
                .refresh_config
                .as_ref()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let controller = crate::standby::StandbyRefreshController::new(
        fixture.runtime.clone(),
        config,
        fixture.store.clone(),
        observed(),
    )
    .unwrap();
    assert!(controller.try_acquire_daemon().unwrap().is_none());
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.refresh.take().unwrap().stop(),
    )
    .await
    .expect("refresh shutdown must not await the export response");
    let guard = controller
        .try_acquire_daemon()
        .unwrap()
        .expect("shutdown must release daemon guard");
    drop(guard);
    fixture.finish().await;
}

#[tokio::test]
async fn routed_write_is_journaled_keyed_and_retried_inside_the_call() {
    let fixture = Fixture::new().await;
    fixture.node.probe().await;
    fixture.fake.keyed_contract.store(true, Ordering::Release);
    fixture.fake.create_failures.store(2, Ordering::Release);
    let reply = fixture.send(write()).await;
    assert_eq!(reply["result"]["content"][0]["text"], "hosted answer");
    let requests = fixture.fake.requests.lock().await.clone();
    let creates: Vec<&Value> = requests
        .iter()
        .filter(|r| target(r).is_some_and(|(_, operation, _)| operation == "create_record"))
        .filter(|r| r.pointer("/params/name") != Some(&json!("describe_operation")))
        .collect();
    assert_eq!(creates.len(), 3, "two 503s then success");
    let keys: Vec<&str> = creates
        .iter()
        .map(|r| {
            r.pointer("/params/arguments/arguments/idempotency_key")
                .and_then(Value::as_str)
                .unwrap()
        })
        .collect();
    assert!(keys[0].starts_with("node-"));
    assert!(keys.iter().all(|key| *key == keys[0]), "{keys:?}");
    let gate = fixture.node.gate.as_ref().unwrap();
    assert_eq!(
        gate.status(&Default::default())["entry_counts"]["confirmed"],
        1
    );
    // The own-write floor still counts it, as for any forwarded write.
    assert!(fixture.node.state.lock().await.persisted.floor.pending >= 1);
    fixture.finish().await;
}

#[tokio::test]
async fn routed_write_without_a_keyed_contract_is_sent_once_and_saved() {
    let fixture = Fixture::new().await;
    fixture.node.probe().await;
    fixture.fake.keyless_contract.store(true, Ordering::Release);
    fixture.fake.create_failures.store(1, Ordering::Release);
    let reply = fixture.send(write()).await;
    assert_eq!(reply["error"]["data"]["http_status"], 503);
    assert_eq!(reply["error"]["data"]["outcome"], "unknown");
    let gate = fixture.node.gate.as_ref().unwrap();
    let status = gate.status(&Default::default());
    assert_eq!(status["uncertain"].as_array().unwrap().len(), 1);
    assert!(status["uncertain"][0]["idempotency_key"].is_null());
    fixture.finish().await;
}

#[tokio::test]
async fn confirm_down_needs_a_second_failure_that_is_an_outage() {
    let fixture = Fixture::new().await;
    // Hosted answers: not down.
    assert!(!fixture.node.confirm_down().await);
    // One failed forward marks health unreachable (reads rely on that) but
    // the follow-up probe reaches hosted, so the outage is not confirmed.
    fixture.node.state.lock().await.health = Health::Unreachable;
    assert!(!fixture.node.confirm_down().await);
    assert_eq!(fixture.node.state.lock().await.health, Health::Reachable);
    // Gateway failure on the probe: confirmed.
    fixture.fake.status.store(502, Ordering::Release);
    assert!(fixture.node.confirm_down().await);
    assert_eq!(fixture.node.state.lock().await.health, Health::Unreachable);
    fixture.finish().await;
}

#[tokio::test]
async fn confirm_down_ignores_answers_that_are_not_an_outage() {
    let fixture = Fixture::new().await;
    for (status, health) in [
        (401, Health::AuthRefused),
        (403, Health::AuthRefused),
        (200, Health::ProtocolFailed),
        (400, Health::ProtocolFailed),
    ] {
        fixture.fake.status.store(status, Ordering::Release);
        assert!(!fixture.node.confirm_down().await, "status {status}");
        assert_eq!(fixture.node.state.lock().await.health, health);
    }
    fixture.fake.status.store(0, Ordering::Release);
    fixture.fake.revision_bump.store(true, Ordering::Release);
    assert!(!fixture.node.confirm_down().await);
    assert_eq!(
        fixture.node.state.lock().await.health,
        Health::RevisionUnsupported
    );
    fixture.finish().await;
}

#[tokio::test]
async fn confirm_down_sees_a_refused_connection() {
    let fixture = Fixture::new().await;
    // A fresh client per probe would not reuse a pooled connection to the
    // old server; the probe client here may, so close the server and let any
    // pooled connection idle out is not needed: a dead listener refuses new
    // connections and the aborted task drops its accepted ones.
    fixture.http.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(fixture.node.confirm_down().await);
    fixture.finish().await;
}

/// The journal as `node_status` shows it, without the live free-disk figure.
fn journal_state(gate: &WriteGate) -> Value {
    let mut status = gate.status(&Default::default());
    status.as_object_mut().unwrap().remove("disk");
    status
}

fn create_requests(requests: &[Value]) -> Vec<&Value> {
    requests
        .iter()
        .filter(|r| target(r).is_some_and(|(_, operation, _)| operation == "create_record"))
        .filter(|r| r.pointer("/params/name") != Some(&json!("describe_operation")))
        .collect()
}

fn pending_info(reply: &Value) -> &Value {
    let info = &reply["result"]["structuredContent"];
    assert_eq!(info["outcome"], "accepted_pending", "{reply}");
    info
}

#[tokio::test]
async fn routed_write_is_held_when_hosted_answers_read_only() {
    let fixture = Fixture::new().await;
    fixture
        .node
        .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
        .await;
    fixture.node.probe().await;
    fixture.fake.read_only.store(true, Ordering::Release);
    let reply = fixture.send(write()).await;
    let info = pending_info(&reply);
    assert_eq!(info["reason"], "deployment_read_only");
    assert_eq!(info["may_already_be_applied"], false);
    let requests = fixture.fake.requests.lock().await.clone();
    let creates = create_requests(&requests);
    assert_eq!(creates.len(), 1, "sent once, not retried");
    assert_eq!(
        creates[0].pointer("/params/arguments/arguments/id"),
        Some(&info["record_id"]),
        "the ID returned is the one hosted was sent"
    );
    let gate = fixture.node.gate.as_ref().unwrap();
    assert_eq!(
        gate.status(&Default::default())["entry_counts"]["pending"],
        1
    );
    // Nothing reached hosted's store, so the next head check clears the
    // own-write floor as it does after any refused write.
    fixture.node.probe().await;
    assert!(!fixture.node.state.lock().await.persisted.floor.unresolved);
    drop(requests);
    fixture.finish().await;
}

#[tokio::test]
async fn routed_write_is_held_only_when_the_follow_up_check_also_fails() {
    let fixture = Fixture::new().await;
    fixture
        .node
        .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
        .await;
    fixture.node.probe().await;
    fixture.fake.keyed_contract.store(true, Ordering::Release);

    // One failed forward; hosted answers the follow-up check. Not held: the
    // write is retried inside the call and succeeds.
    fixture.fake.create_failures.store(1, Ordering::Release);
    let reply = fixture.send(write()).await;
    assert_eq!(reply["result"]["content"][0]["text"], "hosted answer");
    {
        let requests = fixture.fake.requests.lock().await.clone();
        assert_eq!(create_requests(&requests).len(), 2);
    }
    let gate = fixture.node.gate.as_ref().unwrap();
    assert!(gate.status(&Default::default())["entry_counts"]
        .get("pending")
        .is_none());

    // Hosted down for the forward and for the check: held at once.
    fixture.fake.status.store(502, Ordering::Release);
    let before = create_requests(&fixture.fake.requests.lock().await.clone()).len();
    let reply = fixture.send(write()).await;
    let info = pending_info(&reply);
    assert_eq!(info["reason"], "hosted_unreachable");
    assert_eq!(
        info["may_already_be_applied"], true,
        "a 502 may follow an apply"
    );
    let after = create_requests(&fixture.fake.requests.lock().await.clone()).len();
    assert_eq!(after, before + 1, "one attempt, then held");
    assert_eq!(
        gate.status(&Default::default())["entry_counts"]["pending"],
        1
    );
    // It may have committed, so the own-write floor stays conservative.
    assert!(fixture.node.state.lock().await.persisted.floor.unresolved);
    fixture.finish().await;
}

#[tokio::test]
async fn routed_write_is_held_when_the_connection_is_refused() {
    let fixture = Fixture::new().await;
    fixture
        .node
        .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
        .await;
    fixture.node.probe().await;
    fixture.http.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let reply = fixture.send(write()).await;
    let info = pending_info(&reply);
    assert_eq!(info["reason"], "hosted_unreachable");
    assert_eq!(
        info["may_already_be_applied"], false,
        "a refused connection means nothing was sent"
    );
    let gate = fixture.node.gate.as_ref().unwrap();
    assert_eq!(
        gate.status(&Default::default())["entry_counts"]["pending"],
        1
    );
    fixture.finish().await;
}

#[tokio::test]
async fn invalid_allowlisted_writes_are_not_sent_or_held_during_an_outage() {
    let fixture = Fixture::new().await;
    fixture
        .node
        .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
        .await;
    fixture.node.probe().await;
    fixture.http.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::Unreachable);
    let gate = fixture.node.gate.as_ref().unwrap();
    let before = journal_state(gate);
    let requests_before = fixture.fake.requests.lock().await.len();
    for wrapped in [true, false] {
        for (operation, arguments) in [
            ("create_record", json!({})),
            (
                "create_many",
                json!({"reason":"drill", "records":[{"type":"Document"}]}),
            ),
            (
                "manage_links.add",
                json!({"source_id":RECORD, "relationship":"relates_to"}),
            ),
        ] {
            let mut envelope =
                json!({"operation":operation, "arguments":arguments, "format":"json"});
            if wrapped {
                envelope["executor"] = json!("records_write");
            }
            let message = json!({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{
                "name":if wrapped {"call_executor"} else {"records_write"}, "arguments":envelope}});
            let reply = fixture.send(message).await;
            assert_eq!(reply["result"]["isError"], true, "{reply}");
            let failure = &reply["result"]["structuredContent"];
            assert_eq!(failure["outcome"], "not_sent", "{reply}");
            assert_eq!(
                failure["repair"]["code"], "operation_contract_repair",
                "{reply}"
            );
            assert_eq!(
                failure["repair"]["error_class"], "validation_failure",
                "{reply}"
            );
            assert_eq!(
                failure["repair"]["contract_digest"],
                fixture.node.local_row("records_write", operation).unwrap()["contract_digest"]
            );
            assert_eq!(
                journal_state(gate),
                before,
                "invalid write must not enter journal"
            );
        }
    }
    assert_eq!(fixture.fake.requests.lock().await.len(), requests_before);
    // A schema-valid create still follows the existing outage hold path.
    let reply = fixture.send(write()).await;
    pending_info(&reply);
    assert_eq!(journal_state(gate)["queue"]["pending"], 1);
    fixture.finish().await;
}

#[tokio::test]
async fn writes_use_hosted_admission_online_and_matching_cached_contracts_only_when_held() {
    for cache in ["matching", "missing", "different"] {
        let fixture = Fixture::new().await;
        fixture
            .node
            .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
            .await;
        {
            let mut state = fixture.node.state.lock().await;
            let rows = &mut state
                .persisted
                .discovery
                .get_mut(crate::mcp::PROTOCOL_VERSION)
                .unwrap()
                .operations;
            if cache == "missing" {
                rows.retain(|row| {
                    !(row["executor"] == "records_write" && row["operation"] == "create_record")
                });
            } else if cache == "different" {
                rows.iter_mut()
                    .find(|row| {
                        row["executor"] == "records_write" && row["operation"] == "create_record"
                    })
                    .unwrap()["contract_digest"] = json!("new-hosted-contract");
            }
        }
        // The newer hosted field is absent from this node's compiled schema.
        // Explicit key/id prevent the existing minting path from changing bytes.
        let mut online = write();
        online["params"]["arguments"]["arguments"]["future_optional"] = json!(true);
        online["params"]["arguments"]["arguments"]["idempotency_key"] = json!("online-key");
        online["params"]["arguments"]["arguments"]["id"] = json!(RECORD);
        // A stale outage flag must not constrain a hosted service that answers.
        fixture.node.state.lock().await.health = Health::Unreachable;
        assert!(text(&fixture.send(online.clone()).await).contains("hosted answer"));
        assert!(fixture
            .fake
            .requests
            .lock()
            .await
            .iter()
            .any(|request| request == &online));
        // An opaque send may have applied. Neither an unavailable/different
        // digest nor an older local schema may discard its hold and original
        // minted key; replay the exact call and let hosted decide.
        fixture.fake.status.store(502, Ordering::Release);
        let mut opaque = write();
        opaque["params"]["arguments"]["arguments"]["future_optional"] = json!(true);
        let held = fixture.send(opaque).await;
        let info = pending_info(&held);
        assert_eq!(info["may_already_be_applied"], true, "{cache}: {held}");
        let key = info["idempotency_key"].clone();
        assert!(key.is_string());
        let gate = fixture.node.gate.as_ref().unwrap();
        assert_eq!(journal_state(gate)["queue"]["pending"], 1);
        let requests = fixture.fake.requests.lock().await.clone();
        let sent = create_requests(&requests).last().copied().unwrap().clone();
        assert_eq!(
            sent["params"]["arguments"]["arguments"]["idempotency_key"],
            key
        );

        fixture.fake.status.store(0, Ordering::Release);
        fixture.node.probe().await;
        assert_eq!(
            gate.drain(
                &fixture.node.upstream,
                Some(&*fixture.node as &dyn gate::Outage),
                None,
                None,
            )
            .await,
            gate::queue::Halt::Empty,
        );
        let requests = fixture.fake.requests.lock().await.clone();
        let replayed = create_requests(&requests).last().copied().unwrap().clone();
        assert_eq!(
            replayed["params"]["arguments"], sent["params"]["arguments"],
            "{cache}: replay keeps the original call/key"
        );
        assert_eq!(journal_state(gate)["queue"]["pending"], 0);
        if cache != "matching" {
            fixture.fake.read_only.store(true, Ordering::Release);
            let refused = fixture.send(write()).await;
            assert_eq!(refused["error"]["data"]["outcome"], "not_sent", "{refused}");
            assert_eq!(
                journal_state(fixture.node.gate.as_ref().unwrap())["queue"]["pending"],
                0
            );
            fixture.fake.read_only.store(false, Ordering::Release);
        }
        fixture.http.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
        fixture.node.probe().await;
        let gate = fixture.node.gate.as_ref().unwrap();
        let before = journal_state(gate);
        let reply = fixture.send(write()).await;
        if cache == "matching" {
            pending_info(&reply);
            assert_eq!(journal_state(gate)["queue"]["pending"], 1);
        } else {
            assert_eq!(
                reply["error"]["data"]["outcome"], "not_sent",
                "{cache}: {reply}"
            );
            assert_eq!(journal_state(gate), before);
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn invalid_held_envelopes_are_repaired_without_journaling() {
    let fixture = Fixture::new().await;
    fixture
        .node
        .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
        .await;
    fixture.http.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;
    fixture.node.probe().await;
    let gate = fixture.node.gate.as_ref().unwrap();
    let before = journal_state(gate);
    for (field, value) in [("format", json!("bogus")), ("stray", json!(true))] {
        let mut request = write();
        request["params"]["arguments"][field] = value;
        let reply = fixture.send(request).await;
        assert_eq!(reply["result"]["isError"], true, "{reply}");
        assert_eq!(reply["result"]["structuredContent"]["outcome"], "not_sent");
        assert_eq!(
            reply["result"]["structuredContent"]["repair"]["error_class"],
            "validation_failure"
        );
        assert_eq!(journal_state(gate), before);
    }
    fixture.finish().await;
}

#[tokio::test]
async fn routed_write_is_not_held_for_auth_protocol_or_revision_problems() {
    for case in ["auth", "protocol", "revision"] {
        let fixture = Fixture::new().await;
        fixture.node.probe().await;
        fixture.fake.keyed_contract.store(true, Ordering::Release);
        match case {
            "auth" => fixture.fake.status.store(401, Ordering::Release),
            "protocol" => fixture.fake.status.store(200, Ordering::Release),
            _ => fixture.fake.revision_bump.store(true, Ordering::Release),
        }
        if case == "revision" {
            fixture.node.probe().await;
            assert_eq!(
                fixture.node.state.lock().await.health,
                Health::RevisionUnsupported
            );
        }
        let reply = fixture.send(write()).await;
        assert_ne!(
            reply["result"]["structuredContent"]["outcome"], "accepted_pending",
            "{case}: {reply}"
        );
        let gate = fixture.node.gate.as_ref().unwrap();
        assert!(
            gate.status(&Default::default())["entry_counts"]
                .get("pending")
                .is_none(),
            "{case}"
        );
        fixture.finish().await;
    }
}

fn local_only(mut message: Value) -> Value {
    message["params"]["_meta"] = json!({"native/route":"local", "private-test":"preserved"});
    message
}

#[tokio::test]
async fn local_only_reads_stay_local_with_healthy_hosted_and_preserve_policy() {
    let fixture = Fixture::new().await;
    fixture.node.probe().await;
    fixture.node.refresh_discovery().await;
    fixture.fake.requests.lock().await.clear();
    for health in [
        Health::Reachable,
        Health::ProtocolFailed,
        Health::RevisionUnsupported,
    ] {
        {
            let mut state = fixture.node.state.lock().await;
            state.health = health;
            state.revision_unsupported = health == Health::RevisionUnsupported;
        }
        for wrapped in [true, false] {
            let reply = fixture.send(local_only(read(wrapped))).await;
            assert!(text(&reply).contains("local-first"), "{reply}");
            assert!(
                reply["result"]["structuredContent"]["standby_context"]["serving_generation_id"]
                    .is_string(),
                "{reply}"
            );
            let freshness = &reply["result"]["structuredContent"]["standby_context"]["freshness"];
            assert!(freshness["age_seconds"].is_u64(), "{reply}");
            assert_eq!(
                freshness["target_rpo_seconds"],
                crate::standby::STANDBY_RPO_SECONDS
            );
        }
        if health == Health::ProtocolFailed {
            let reply = fixture.send(local_only(read(true))).await;
            assert!(
                text(&reply).contains("Hosted MCP protocol failed"),
                "{reply}"
            );
        }
        if health == Health::RevisionUnsupported {
            let reply = fixture.send(local_only(read(true))).await;
            assert_eq!(
                reply["result"]["structuredContent"]["node_health"]["local_reads_stale"], true,
                "{reply}"
            );
            assert!(
                text(&reply).contains("newer interchange revision"),
                "{reply}"
            );
        }
    }
    {
        let mut state = fixture.node.state.lock().await;
        state.health = Health::Reachable;
        state.revision_unsupported = false;
    }
    let bootstrap = local_only(
        json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"bootstrap","arguments":{"format":"json"}}}),
    );
    let response = fixture.send(bootstrap).await;
    assert_eq!(
        response["result"]["structuredContent"]["outage_bootstrap"], true,
        "{response}"
    );
    assert!(response["result"]["structuredContent"]["outage"]["run_key"].is_null());
    // The route hint must not strip the app carrier: a foreign/unknown
    // installation is still refused by the selected account's dispatcher.
    let mut attributed = local_only(read(true));
    attributed["params"]["_meta"]["native/app"] = json!("offline.test@1; install=missing-install");
    let refused = fixture.send(attributed).await;
    assert_eq!(refused["result"]["isError"], true, "{refused}");
    assert!(
        refused.to_string().contains("app_install_unknown"),
        "{refused}"
    );
    // An unsupported operation and a mismatched cached contract cannot escape
    // the existing standby policy merely because hosted is healthy.
    let mut unknown = local_only(read(true));
    unknown["params"]["arguments"]["operation"] = json!("unknown_read");
    assert_eq!(
        fixture.send(unknown).await["error"]["data"]["outcome"],
        "unavailable_offline"
    );
    {
        let mut state = fixture.node.state.lock().await;
        let row = state
            .persisted
            .discovery
            .get_mut(crate::mcp::PROTOCOL_VERSION)
            .unwrap()
            .operations
            .iter_mut()
            .find(|r| r["executor"] == "records_read" && r["operation"] == "get_record")
            .unwrap();
        row["contract_digest"] = json!("mismatch");
    }
    assert_eq!(
        fixture.send(local_only(read(true))).await["error"]["data"]["outcome"],
        "unavailable_offline"
    );
    assert!(fixture.fake.requests.lock().await.is_empty());
    // Unmarked ordinary reads still use hosted.
    assert!(text(&fixture.send(read(true)).await).contains("hosted answer"));
    fixture.finish().await;
}

#[tokio::test]
async fn local_only_unavailable_reader_never_uses_healthy_hosted() {
    let fixture = Fixture::with_startup(Some(false)).await;
    fixture.fake.requests.lock().await.clear();
    let reply = fixture.send(local_only(read(true))).await;
    // Status-only has no authorised serving catalogue. Refuse the data call
    // at local admission; bootstrap below still exposes diagnostic context.
    assert_eq!(reply["error"]["code"], -32000, "{reply}");
    assert_eq!(
        reply["error"]["data"],
        json!({"outcome":"unavailable_offline", "executor":"records_read", "operation":"get_record"}),
        "{reply}"
    );
    assert!(fixture.fake.requests.lock().await.is_empty());
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    let bootstrap = json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"bootstrap","arguments":{"format":"json"}}});
    let reply = fixture.send(bootstrap).await;
    let status = &reply["result"]["structuredContent"];
    assert_eq!(status["mode"], "status_only", "{reply}");
    assert_eq!(status["node_routing"]["read_source"], "local_status");
    assert_eq!(status["node_routing"]["canonical_writes"], "unavailable");
    assert!(status.get("read_only").is_none());
    assert!(status.get("writes_supported").is_none());
    assert_eq!(status["local_copy"]["read_only"], true);
    assert!(status["serving_generation"].is_null());
    assert!(!text(&reply).contains("reads from local_copy"));
    let rendered: Value =
        serde_json::from_str(reply["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(rendered, *status);
    fixture.finish().await;
}

#[tokio::test]
async fn local_only_writes_and_invalid_routes_never_forward_or_enter_gate() {
    let fixture = Fixture::new().await;
    let gate = fixture.node.gate.as_ref().unwrap();
    let before = journal_state(gate);
    for health in [Health::Reachable, Health::Unreachable, Health::AuthRefused] {
        fixture.node.state.lock().await.health = health;
        let reply = fixture.send(local_only(write())).await;
        assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
        for hint in [json!("locla"), Value::Null, json!(false), json!({})] {
            let mut request = local_only(write());
            request["params"]["_meta"]["native/route"] = hint;
            assert_eq!(
                fixture.send(request).await["error"]["data"]["outcome"],
                "not_sent"
            );
        }
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    assert_eq!(journal_state(gate), before);
    assert_eq!(fixture.node.state.lock().await.persisted.floor.pending, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn node_status_surfaces_report_bound_account_without_credentials() {
    for available in [true, false] {
        let fixture = if available {
            Fixture::new().await
        } else {
            Fixture::with_startup(Some(false)).await
        };
        let account = fixture.node.upstream.config.account_id.clone().unwrap();
        for name in ["standby_status", "node_status"] {
            let message = local_only(
                json!({"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":name,"arguments":{}}}),
            );
            let reply = route_message(
                &fixture.node.upstream,
                Some(&fixture.node),
                fixture.node.gate.as_ref(),
                None,
                &crate::node::agent_sessions::routing::test_ctx().0,
                &message.to_string(),
                message.clone(),
                Some(crate::mcp::PROTOCOL_VERSION),
                &fixture.direct,
                &anonymous_caller(),
            )
            .await
            .0
            .unwrap();
            let reply: Value = serde_json::from_str(&reply).unwrap();
            assert_eq!(
                reply["result"]["structuredContent"]["account_id"], account,
                "{reply}"
            );
            assert!(text(&reply).contains(&account), "{reply}");
            assert!(!reply.to_string().contains("fixture-token"));
        }
        assert!(fixture.fake.requests.lock().await.is_empty());
        fixture.finish().await;
    }
}

#[tokio::test]
async fn node_status_reports_how_hosted_was_last_found() {
    let fixture = Fixture::new().await;
    for (health, revision, word) in [
        (Health::Reachable, false, "reachable"),
        (Health::Unreachable, false, "unreachable"),
        (Health::AuthRefused, false, "auth_refused"),
        (Health::ProtocolFailed, false, "protocol_failed"),
        (Health::RevisionUnsupported, true, "revision_unsupported"),
    ] {
        {
            let mut state = fixture.node.state.lock().await;
            state.health = health;
            state.revision_unsupported = revision;
        }
        let message = local_only(
            json!({"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"node_status","arguments":{}}}),
        );
        let reply = route_message(
            &fixture.node.upstream,
            Some(&fixture.node),
            fixture.node.gate.as_ref(),
            None,
            &crate::node::agent_sessions::routing::test_ctx().0,
            &message.to_string(),
            message.clone(),
            Some(crate::mcp::PROTOCOL_VERSION),
            &fixture.direct,
            &anonymous_caller(),
        )
        .await
        .0
        .unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        let hosted = &reply["result"]["structuredContent"]["hosted"];
        assert_eq!(hosted["health"], word, "{reply}");
        assert_eq!(hosted["revision_unsupported"], revision, "{reply}");
    }
    fixture.finish().await;
}

#[tokio::test]
async fn node_status_says_hosted_is_not_checked_until_a_probe_has_settled_it() {
    let fixture = Fixture::new().await;
    let status = || async {
        let message = local_only(
            json!({"jsonrpc":"2.0","id":93,"method":"tools/call","params":{"name":"node_status","arguments":{}}}),
        );
        let reply = route_message(
            &fixture.node.upstream,
            Some(&fixture.node),
            fixture.node.gate.as_ref(),
            None,
            &crate::node::agent_sessions::routing::test_ctx().0,
            &message.to_string(),
            message.clone(),
            Some(crate::mcp::PROTOCOL_VERSION),
            &fixture.direct,
            &anonymous_caller(),
        )
        .await
        .0
        .unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        reply["result"]["structuredContent"]["hosted"].clone()
    };
    fixture.node.state.lock().await.checked = false;
    let before = status().await;
    assert_eq!(before["health"], "reachable", "the starting assumption");
    assert_eq!(before["checked"], false, "{before}");
    fixture.node.probe().await;
    let after = status().await;
    assert_eq!(
        (after["health"].as_str(), after["checked"].as_bool()),
        (Some("reachable"), Some(true)),
        "{after}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn the_queue_counts_its_sends_in_the_own_write_floor_and_survives_a_node_restart() {
    let fixture = Fixture::new().await;
    fixture
        .node
        .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
        .await;
    fixture.node.probe().await;
    fixture.fake.read_only.store(true, Ordering::Release);
    let reply = fixture.send(write()).await;
    let record_id = pending_info(&reply)["record_id"].clone();
    fixture.node.probe().await;
    let floor_before = fixture.node.state.lock().await.persisted.floor.pending;

    // Hosted recovers. The node sends the held write itself, once.
    fixture.fake.read_only.store(false, Ordering::Release);
    let gate = fixture.node.gate.as_ref().unwrap();
    let halt = gate
        .drain(
            &fixture.node.upstream,
            Some(&*fixture.node as &dyn gate::Outage),
            None,
            None,
        )
        .await;
    assert_eq!(halt, gate::queue::Halt::Empty);
    let requests = fixture.fake.requests.lock().await.clone();
    let creates = create_requests(&requests);
    assert_eq!(creates.len(), 2, "the refused first send, then the queue's");
    assert_eq!(
        creates[1].pointer("/params/arguments/arguments/id"),
        Some(&record_id)
    );
    assert_eq!(
        gate.status(&Default::default())["entry_counts"]["confirmed"],
        1
    );
    let floor = fixture.node.state.lock().await.persisted.floor.clone();
    assert!(floor.pending > floor_before, "the send is an own write");
    assert!(floor.unresolved, "until a head check after it");
    drop(requests);
    fixture.node.probe().await;
    assert!(!fixture.node.state.lock().await.persisted.floor.unresolved);
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_online_reads_forward_a_confirmed_account_mismatch_instead_of_refusing() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let request = read(true);
    assert!(fixture
        .node
        .try_online_local(&request, crate::mcp::PROTOCOL_VERSION, BOUND)
        .await
        .is_some());
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    fs::write(
        &fixture.node.upstream.config.credential_file,
        "renewed-b-token",
    )
    .unwrap();
    assert!(fixture
        .node
        .try_online_local(&request, crate::mcp::PROTOCOL_VERSION, BOUND)
        .await
        .is_none());
    fixture.fake.requests.lock().await.clear();
    let reply = fixture.send(request).await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(text(&reply), "hosted answer");
    assert_eq!(fixture.fake.requests.lock().await.len(), 1);
    fixture.finish().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_online_local_bootstrap_forwards_a_confirmed_account_mismatch() {
    let fixture = online_v2().await;
    let request = boot(556, json!({"format":"json"}));
    let initial = fixture
        .node
        .try_online_local(&request, crate::mcp::PROTOCOL_VERSION, BOUND)
        .await;
    if initial.is_none() {
        let context = fixture.node.dispatcher.serving_context();
        let floor = fixture.node.state.lock().await.persisted.floor.clone();
        panic!("initial local bootstrap declined: context={context:?}, floor={floor:?}");
    }
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    assert!(fixture
        .node
        .try_online_local_bootstrap(
            &request,
            crate::mcp::PROTOCOL_VERSION,
            BOUND,
            false,
            ReadCtx {
                session: None,
                local: false
            },
        )
        .await
        .is_none());
    fixture.fake.requests.lock().await.clear();
    let reply = fixture.send(request).await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["read_source"], "hosted",
        "{reply}"
    );
    assert_eq!(hosted_bootstraps(&fixture.fake.requests.lock().await), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_local_account_disclosure_omits_default_standing_and_login_advice_on_doubt() {
    for configured in [true, false] {
        let mut fixture = Fixture::new().await;
        online_ready(&fixture).await;
        if !configured {
            let node = Arc::get_mut(&mut fixture.node).unwrap();
            let mut config = node.upstream.config.clone();
            config.account_id = None;
            node.upstream = Arc::new(Upstream::new(config, Duration::from_secs(5)).unwrap());
        }
        for health in [Health::Reachable, Health::Unreachable, Health::AuthRefused] {
            fixture.node.state.lock().await.health = health;
            let reply = fixture.send(local_only(read(true))).await;
            assert_eq!(reply["result"]["isError"], false, "{reply}");
            let routing = &reply["result"]["structuredContent"]["node_routing"];
            for field in [
                "own_write_unresolved",
                "own_write_floor_act",
                "serving_head_act",
                "known_hosted_head_act",
                "behind_known_write",
            ] {
                assert!(routing.get(field).is_none(), "unexpected {field}: {reply}");
            }
            // An unverified binding must still be disclosed on the default
            // text path, which does not expose the structured routing state.
            let mut text_request = read(true);
            text_request["params"]["arguments"]
                .as_object_mut()
                .unwrap()
                .remove("format");
            let default_text_reply = fixture.send(local_only(text_request)).await;
            assert_eq!(
                default_text_reply["result"]["isError"], false,
                "{default_text_reply}"
            );
            assert!(default_text_reply["result"]
                .get("structuredContent")
                .is_none());
            if configured {
                assert_eq!(routing["account_verified"], false, "{reply}");
                assert!(
                    text(&default_text_reply).contains("has not been verified")
                        && text(&default_text_reply).contains("previously verified copy"),
                    "{default_text_reply}"
                );
            } else {
                assert!(routing.get("account_verified").is_none(), "{reply}");
                assert!(!text(&reply).contains("has not been verified"), "{reply}");
                assert!(
                    !text(&default_text_reply).contains("has not been verified"),
                    "{default_text_reply}"
                );
            }
            assert_eq!(
                routing.get("reauthenticate").is_some(),
                health == Health::AuthRefused,
                "{reply}"
            );
            assert_eq!(
                routing.get("next_step").is_some(),
                health == Health::AuthRefused,
                "{reply}"
            );
            assert_eq!(
                text(&reply).contains("native login"),
                health == Health::AuthRefused,
                "{reply}"
            );
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn local_only_auth_refusal_never_blocks_reads_and_preserves_status_introspection() {
    let fixture = Fixture::new().await;
    // Establish a real known credential refusal through the hosted probe.
    fixture.fake.status.store(401, Ordering::Release);
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::AuthRefused);
    fixture.fake.requests.lock().await.clear();
    let gate = fixture.node.gate.as_ref().unwrap();
    let journal = journal_state(gate);
    let floor = fixture.node.state.lock().await.persisted.floor.pending;
    // Authentication trouble is doubt about hosted, not evidence about the
    // copy (Richard, 10 Nov 2026): an explicit local read is served, never
    // refused, and the disclosure says hosted authentication needs attention.
    for request in [
        read(true),
        read(false),
        json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"bootstrap","arguments":{"format":"json"}}}),
    ] {
        let reply = fixture.send(local_only(request)).await;
        assert!(reply.get("error").is_none(), "{reply}");
        assert!(reply.get("result").is_some(), "{reply}");
    }
    let served = fixture.send(local_only(read(true))).await;
    assert!(text(&served).contains("local-first"), "{served}");
    // Writes are unchanged: a local route is read-only and nothing is sent.
    let reply = fixture.send(local_only(write())).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(reply.get("result").is_none(), "{reply}");
    for name in ["standby_status", "node_status"] {
        let request = local_only(
            json!({"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":name,"arguments":{}}}),
        );
        let reply = route_message(
            &fixture.node.upstream,
            Some(&fixture.node),
            Some(gate),
            None,
            &crate::node::agent_sessions::routing::test_ctx().0,
            &request.to_string(),
            request.clone(),
            Some(crate::mcp::PROTOCOL_VERSION),
            &fixture.direct,
            &anonymous_caller(),
        )
        .await
        .0
        .unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_eq!(
            reply["result"]["structuredContent"]["account_id"],
            json!(fixture.node.upstream.config.account_id),
            "{reply}"
        );
        if name == "standby_status" {
            // A usable verified local copy exists: authentication, not
            // generation unavailability, is the reason data was refused.
            assert_eq!(reply["result"]["structuredContent"]["mode"], "standby");
            assert!(reply["result"]["structuredContent"]["serving_generation"].is_object());
            assert_eq!(
                reply["result"]["structuredContent"]["node_routing"]["canonical_writes"],
                "authentication_refused"
            );
            assert!(text(&reply).contains("Hosted authentication was refused"));
        }
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    assert_eq!(journal_state(gate), journal);
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.pending,
        floor
    );
    // Unmarked requests still reach hosted and preserve its auth refusal.
    let ordinary = fixture.send(read(true)).await;
    assert_eq!(ordinary["error"]["data"]["http_status"], 401);
    fixture.finish().await;
}

#[tokio::test]
async fn a_local_route_write_is_refused_first_and_never_held_or_queued() {
    for mode in ["read_only", "down"] {
        let fixture = Fixture::new().await;
        fixture.node.probe().await;
        match mode {
            "read_only" => fixture.fake.read_only.store(true, Ordering::Release),
            _ => fixture.fake.status.store(502, Ordering::Release),
        }
        let requests_before = fixture.fake.requests.lock().await.len();
        let reply = fixture.send(local_only(write())).await;
        assert_ne!(
            reply["result"]["structuredContent"]["outcome"], "accepted_pending",
            "{mode}: {reply}"
        );
        assert_eq!(
            reply["error"]["data"]["outcome"], "not_sent",
            "{mode}: {reply}"
        );
        let gate = fixture.node.gate.as_ref().unwrap();
        let state = journal_state(gate);
        assert_eq!(state["queue"]["pending"], 0, "{mode}");
        assert_eq!(state["entry_counts"], json!({}), "{mode}");
        assert_eq!(
            fixture.fake.requests.lock().await.len(),
            requests_before,
            "{mode}: nothing reached hosted"
        );
        fixture.finish().await;
    }
}

#[tokio::test]
async fn every_allowlisted_write_of_an_outage_is_held_and_sent_in_order_after_recovery() {
    let fixture = Fixture::new().await;
    fixture
        .node
        .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
        .await;
    fixture.node.probe().await;
    fixture.fake.status.store(502, Ordering::Release);

    // The first write finds the outage and marks hosted unreachable.
    let first = fixture.send(write()).await;
    let first_info = pending_info(&first).clone();
    assert_eq!(fixture.node.state.lock().await.health, Health::Unreachable);
    // The second no longer takes the offline path: it is held too, behind the
    // first, for its own confirmed outage.
    let second = fixture.send(write()).await;
    let second_info = pending_info(&second).clone();
    assert_eq!(second_info["reason"], "hosted_unreachable");
    assert_eq!(second_info["queue_position"], 2);
    // A keyed repeat of the first gets its pending answer.
    let mut repeat = write();
    repeat["params"]["arguments"]["arguments"]["idempotency_key"] =
        first_info["idempotency_key"].clone();
    let again = fixture.send(repeat).await;
    assert_eq!(
        pending_info(&again)["journal_entry"],
        first_info["journal_entry"]
    );
    let gate = fixture.node.gate.as_ref().unwrap();
    assert_eq!(journal_state(gate)["queue"]["pending"], 2);

    // A write that may not be held still gets the old refusal.
    let other = json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"coordination_write","operation":"set_intent","arguments":{"intent":"x"}}}});
    let refused = fixture.send(other).await;
    assert_eq!(refused["error"]["data"]["outcome"], "not_sent");

    // Recovery: both are sent, oldest first.
    fixture.fake.status.store(0, Ordering::Release);
    let before = create_requests(&fixture.fake.requests.lock().await.clone()).len();
    let halt = gate
        .drain(
            &fixture.node.upstream,
            Some(&*fixture.node as &dyn gate::Outage),
            None,
            None,
        )
        .await;
    assert_eq!(halt, gate::queue::Halt::Empty);
    let requests = fixture.fake.requests.lock().await.clone();
    let sent: Vec<&Value> = create_requests(&requests)
        .into_iter()
        .skip(before)
        .collect();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0].pointer("/params/arguments/arguments/id"),
        Some(&first_info["record_id"])
    );
    assert_eq!(
        sent[1].pointer("/params/arguments/arguments/id"),
        Some(&second_info["record_id"])
    );
    drop(requests);
    fixture.finish().await;
}

#[test]
fn vault_defaults_to_a_sibling_of_the_standby_copy() {
    assert_eq!(
        default_vault_path(Path::new("/data/replica")),
        Some(PathBuf::from("/data/vault"))
    );
    assert_eq!(
        resolve_vault_path(&None, Some(Path::new("/data/replica"))).unwrap(),
        Some(PathBuf::from("/data/vault"))
    );
}

#[test]
fn vault_default_is_off_for_unsafe_derivations() {
    // The derived path would equal the local copy itself.
    assert_eq!(default_vault_path(Path::new("/data/vault")), None);
    assert_eq!(
        resolve_vault_path(&None, Some(Path::new("/data/vault"))).unwrap(),
        None
    );
    // The parent is the filesystem root: `/replica` would give `/vault`.
    assert_eq!(default_vault_path(Path::new("/replica")), None);
    assert_eq!(
        resolve_vault_path(&None, Some(Path::new("/replica"))).unwrap(),
        None
    );
}

#[test]
fn vault_off_switch_and_explicit_path_resolve() {
    let replica = PathBuf::from("/data/replica");
    let off = Some(MarkdownFolder::Disabled);
    assert_eq!(resolve_vault_path(&off, Some(&replica)).unwrap(), None);
    assert_eq!(resolve_vault_path(&off, None).unwrap(), None);
    let explicit = Some(MarkdownFolder::Explicit(PathBuf::from("/custom/vault")));
    assert_eq!(
        resolve_vault_path(&explicit, Some(&replica)).unwrap(),
        Some(PathBuf::from("/custom/vault"))
    );
    // An explicit path without a standby copy still errors.
    assert!(resolve_vault_path(&explicit, None).is_err());
    // No standby copy and no setting is simply off, without an error.
    assert_eq!(resolve_vault_path(&None, None).unwrap(), None);
}

#[test]
fn standby_without_a_copy_treats_default_and_off_as_off() {
    let config = |markdown_folder: Option<MarkdownFolder>| NodeConfig {
        working_note_appends: false,
        hosted_base_url: "https://h.example".into(),
        home_id: "h".into(),
        db_id: "d".into(),
        credential_file: PathBuf::from("/c"),
        socket_directory: PathBuf::from("/s"),
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
        desktop_app_proof_resource_origin: None,
        pending_fork_reads: false,
        hosted_kernel_v2: false,
        markdown_folder,
    };
    assert!(start_standby(&config(None), None).unwrap().is_none());
    assert!(start_standby(&config(Some(MarkdownFolder::Disabled)), None)
        .unwrap()
        .is_none());
    assert!(start_standby(
        &config(Some(MarkdownFolder::Explicit(PathBuf::from(
            "/custom/vault"
        )))),
        None
    )
    .is_err());
}

#[tokio::test]
async fn v1_hold_and_drain_use_monitor_flag_without_extra_head_probes() {
    let fixture = Fixture::new().await;
    fixture
        .node
        .refresh_catalogue(crate::mcp::PROTOCOL_VERSION, None)
        .await;
    fixture.node.probe().await;
    // Any accidental fresh probe blackholes here. Reading the persisted flag
    // must finish without issuing HTTP, even while hosted is blackholed.
    fixture.fake.pause_probe.store(true, Ordering::Release);
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        gate::Outage::held_replay_allowed(&*fixture.node)
    )
    .await
    .unwrap());
    fixture.fake.pause_probe.store(false, Ordering::Release);
    fixture.fake.status.store(502, Ordering::Release);
    // The monitor has already established the outage before counting holds.
    fixture.node.probe().await;
    assert!(gate::Outage::known_unreachable(&*fixture.node).await);
    fixture.fake.requests.lock().await.clear();
    let probes = |requests: &[Value]| {
        requests
            .iter()
            .filter(|r| target(r).is_some_and(|(_, op, _)| op == "authority_act_head"))
            .count()
    };
    // One confirm-down per write; the second also confirms the failed
    // backlog send before holding behind it. These are the existing v1 probes.
    for expected in [1, 3] {
        pending_info(&fixture.send(write()).await);
        assert_eq!(
            probes(&fixture.fake.requests.lock().await),
            expected,
            "only existing outage and failed-backlog confirmations"
        );
    }
    fixture.fake.status.store(0, Ordering::Release);
    fixture.fake.requests.lock().await.clear();
    fixture.fake.pause_probe.store(true, Ordering::Release);
    let gate = fixture.node.gate.as_ref().unwrap();
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(3),
            gate.drain(
                &fixture.node.upstream,
                Some(&*fixture.node as &dyn gate::Outage),
                None,
                None
            )
        )
        .await
        .unwrap(),
        gate::queue::Halt::Empty
    );
    assert_eq!(
        probes(&fixture.fake.requests.lock().await),
        0,
        "no per-entry probe during drain"
    );
    fixture.finish().await;
}

/// Hosted requests (forwarded) for the named operation.
async fn forwarded(fixture: &Fixture, operation: &str) -> usize {
    fixture
        .fake
        .requests
        .lock()
        .await
        .iter()
        .filter(|r| {
            target(r).is_some_and(|(executor, op, _)| {
                executor != "describe_operation" && op == operation
            })
        })
        .count()
}
async fn forwarded_reads(fixture: &Fixture) -> usize {
    forwarded(fixture, "get_record").await
}
async fn online_ready(fixture: &Fixture) {
    Box::pin(fixture.node.refresh_discovery()).await;
    let protocol = crate::mcp::PROTOCOL_VERSION;
    Box::pin(fixture.node.refresh_catalogue(protocol, None)).await;
    Box::pin(fixture.node.probe()).await;
    // Count user reads separately from SQL used to discover the catalogue.
    fixture.fake.requests.lock().await.clear();
}
async fn read_once(fixture: &Fixture) -> Value {
    Box::pin(fixture.send(read(true))).await
}
fn served_locally(reply: &Value) -> bool {
    text(reply).contains("local-first")
        && reply["result"]["structuredContent"]["standby_context"]["local_copy"]["read_only"]
            == true
}
async fn assert_forwarded(fixture: Fixture) {
    let reply = read_once(&fixture).await;
    assert_eq!(text(&reply), "hosted answer");
    assert_eq!(forwarded_reads(&fixture).await, 1);
    let query = sql_read(
        json!({"sql":"SELECT name FROM records ORDER BY name"}),
        true,
    );
    let reply = Box::pin(fixture.send(query)).await;
    assert!(
        reply["result"]["structuredContent"]["standby_context"].is_null(),
        "{reply}"
    );
    assert_eq!(forwarded(&fixture, "query_sql").await, 1);
    fixture.finish().await;
}
/// Rewrite the serving copy's persisted head (the file `live_serving` reads).
fn set_copy_head(fixture: &Fixture, head_act: i64) {
    let context = fixture.supervisor.dispatcher().serving_context().unwrap();
    let id = context.serving_generation_id.unwrap();
    // A checkpoint copy has no head file yet; write one the way a sync would.
    let head = json!({
        "contract":"native.standby-generation-head.v1","version":2,
        "generation_id":id,"head_act":head_act,"materialization":"snapshot",
        "synced_at":chrono::Utc::now().to_rfc3339(),"full_refresh_required":false,
    });
    let path = fixture
        .runtime
        .replica_root
        .join("accepted/heads")
        .join(format!("{id}.json"));
    fs::write(path, serde_json::to_vec(&head).unwrap()).unwrap();
    assert_eq!(
        fixture
            .store
            .generation_head(&id)
            .unwrap()
            .unwrap()
            .head_act,
        head_act
    );
}

const BOUND: u64 = 30;

#[tokio::test]
async fn online_local_reads_off_forwards_everything() {
    let fixture = Fixture::new().await;
    online_ready(&fixture).await;
    assert_forwarded(fixture).await;
}

#[tokio::test]
async fn online_local_reads_serve_a_fresh_copy_at_the_floor_locally() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    assert!(fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .floor
        .act
        .is_some());
    let reply = read_once(&fixture).await;
    assert!(served_locally(&reply), "{reply}");
    let context = &reply["result"]["structuredContent"]["standby_context"];
    assert_eq!(context["canonical_authority"], "hosted", "{reply}");
    assert!(context.get("read_only").is_none());
    assert!(context.get("writes_supported").is_none());
    assert!(context.get("full_status_tool").is_none());
    let routing = &reply["result"]["structuredContent"]["node_routing"];
    assert_eq!(routing["canonical_writes"], "forwarded_to_hosted");
    assert_eq!(routing["hosted_health"], "reachable");
    assert_eq!(routing["read_source"], "local_copy");
    // Ordinary reads name their source; write routing is stated at bootstrap
    // and ping, and stays exact in node_routing above.
    assert!(
        text(&reply).contains("Node routing: reads from local_copy."),
        "{reply}"
    );
    assert!(
        !text(&reply).contains("Writes are forwarded to hosted Native"),
        "{reply}"
    );
    assert!(!text(&reply).contains("may be missing writes"), "{reply}");
    assert_eq!(forwarded_reads(&fixture).await, 0);
    // Writes are never served locally.
    let written = Box::pin(fixture.send(write())).await;
    assert_eq!(text(&written), "hosted answer");
    assert_eq!(forwarded(&fixture, "create_record").await, 1);
    fixture.finish().await;
}

#[tokio::test]
async fn node_ping_and_bootstrap_disclose_write_routing_across_an_outage() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let ping = json!({"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"system_read","arguments":{"operation":"ping","format":"json"}}});
    let bootstrap = json!({"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"bootstrap","arguments":{"format":"json"}}});
    // A v1 member copy has only a reduced bootstrap, so it forwards (960f47f D).
    for (request, source) in [(ping.clone(), "local_copy"), (bootstrap.clone(), "hosted")] {
        let reply = fixture.send(request).await;
        let routing = &reply["result"]["structuredContent"]["node_routing"];
        assert_eq!(routing["read_source"], source, "{reply}");
        assert_eq!(
            routing["canonical_writes"], "forwarded_to_hosted",
            "{reply}"
        );
        assert!(text(&reply).contains("Writes are forwarded to hosted Native"));
        // JSON text must not retain the old ambiguous copy capabilities.
        let mut saw_copy_payload = false;
        for item in reply["result"]["content"].as_array().unwrap() {
            if let Some(payload) = item["text"]
                .as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
            {
                if let Some(copy) = payload.get("standby_context") {
                    saw_copy_payload = true;
                    assert!(copy.get("read_only").is_none(), "{item}");
                    assert!(copy.get("full_status_tool").is_none(), "{item}");
                    assert_eq!(copy["local_copy"]["writes_supported"], false);
                    assert_eq!(payload["node_routing"], *routing);
                }
            }
        }
        assert_eq!(saw_copy_payload, source == "local_copy", "{reply}");
    }
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    for request in [ping.clone(), bootstrap] {
        let reply = fixture.send(request).await;
        let payload = &reply["result"]["structuredContent"];
        assert_eq!(
            payload["node_routing"]["canonical_writes"], "unavailable",
            "{reply}"
        );
        assert_eq!(payload["node_routing"]["hosted_health"], "unreachable");
        assert!(text(&reply).contains("canonical writes are unavailable"));
    }
    fixture.fake.status.store(0, Ordering::Release);
    fixture.node.probe().await;
    let reply = fixture.send(ping).await;
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["canonical_writes"],
        "forwarded_to_hosted"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn text_format_bootstrap_keeps_hosted_text_visible() {
    // deb2b566: a text-format hosted answer has no structuredContent. The node
    // must not invent one holding only node_routing, or clients that prefer
    // structuredContent hide bootstrap's text and its run key.
    // Online local reads off: bootstrap goes to hosted and comes back as text.
    let fixture = Fixture::new().await;
    online_ready(&fixture).await;
    for arguments in [json!({}), json!({"format":"text"})] {
        let bootstrap = json!({"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"bootstrap","arguments":arguments}});
        let reply = fixture.send(bootstrap).await;
        assert!(
            reply["result"].get("structuredContent").is_none(),
            "{reply}"
        );
        let text = text(&reply);
        assert!(text.contains("hosted answer"), "{reply}");
        assert!(
            text.contains("Writes are forwarded to hosted Native"),
            "{reply}"
        );
    }
    fixture.finish().await;
}

fn hosted_bootstraps(requests: &[Value]) -> usize {
    requests
        .iter()
        .filter(|r| r.pointer("/params/name") == Some(&json!("bootstrap")))
        .count()
}

/// A kernel-v2 copy with online local reads, serving and ready.
#[cfg(feature = "v2-kernel-probe")]
async fn online_v2() -> Fixture {
    let fixture = Box::pin(Fixture::build_with_engine(
        Some(true),
        None,
        false,
        Some(OnlineLocalReads {
            max_age_seconds: BOUND,
        }),
        false,
        true,
    ))
    .await;
    tokio::time::timeout(Duration::from_secs(30), async {
        // Early restart handoff serves the copy before its background recheck
        // completes. That disclosed degradation deliberately sends legacy
        // online-local reads to hosted; these tests require a fully ready copy.
        while !fixture.node.dispatcher.serving_kernel_v2()
            || fixture
                .node
                .dispatcher
                .session_store()
                .startup_recheck_pending()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("v2 copy serving with its startup recheck complete");
    online_ready(&fixture).await;
    fixture
}

fn boot(id: u64, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"bootstrap","arguments":arguments}})
}

/// 960f47f item D, run-key option B: an eligible kernel-v2 copy answers
/// bootstrap and the node issues the run key; hosted is not called.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_online_local_bootstrap_issues_a_run_key_without_calling_hosted() {
    let fixture = online_v2().await;
    let reply = fixture.send(boot(93, json!({"format":"json"}))).await;
    let payload = &reply["result"]["structuredContent"];
    let key = payload["run"]["run_key"]
        .as_str()
        .unwrap_or_else(|| panic!("issued key: {reply}"))
        .to_owned();
    assert!(
        matches!(
            crate::runkey::validate_full(Some(&key)),
            crate::runkey::KeyOutcome::Valid(_)
        ),
        "{reply}"
    );
    assert_eq!(payload["engine"]["name"], "kernel-v2", "{reply}");
    assert!(payload.get("pending_obligations").is_none(), "{reply}");
    assert_eq!(payload["bootstrap_readiness"]["status"], "complete");
    assert_eq!(payload["run"]["status"], "pending_on_hosted", "{reply}");
    assert_eq!(payload["run"]["issued_by"], "node");
    assert_eq!(payload["run"]["durable"], false);
    assert_eq!(payload["session"]["run_key"], json!(key));
    assert_eq!(payload["session"]["reuse_required"], true);
    assert!(payload["session"]["guidance"]
        .as_str()
        .unwrap()
        .contains("set_intent with run_key='new'"));
    // Check emitted bytes, including the compatibility text after routing
    // annotation, rather than relying only on structured field lookup.
    assert!(payload.to_string().starts_with("{\"run\":"));
    assert!(text(&reply).starts_with("{\"run\":"));
    assert!(text(&reply)
        .chars()
        .take(256)
        .collect::<String>()
        .contains(&key));
    assert_eq!(payload["node_routing"]["read_source"], "local_copy");
    assert_eq!(
        payload["node_routing"]["canonical_writes"],
        "forwarded_to_hosted"
    );
    assert!(
        payload["standby_context"]["serving_generation_id"].is_string(),
        "{reply}"
    );
    // The copy's read-only runtime block must not contradict node_routing.
    assert!(payload["tool_exposure"].get("runtime").is_none(), "{reply}");
    assert!(text(&reply).contains("Read source: local_copy"), "{reply}");
    // `new` also issues a fresh key locally.
    let renewed = fixture
        .send(boot(94, json!({"format":"json","run_key":"new"})))
        .await;
    assert_eq!(
        renewed["result"]["structuredContent"]["run"]["issued_by"], "node",
        "{renewed}"
    );
    assert_ne!(
        renewed["result"]["structuredContent"]["run"]["run_key"],
        json!(key)
    );

    // Text format: like hosted, no structuredContent, and the key is visible.
    let plain = fixture.send(boot(95, json!({}))).await;
    assert!(
        plain["result"].get("structuredContent").is_none(),
        "{plain}"
    );
    let plain_text = text(&plain);
    let plain_key = plain_text
        .split("Run key: `")
        .nth(1)
        .and_then(|rest| rest.split('`').next())
        .unwrap_or_else(|| panic!("key in text: {plain}"))
        .to_owned();
    assert!(
        matches!(
            crate::runkey::validate_full(Some(&plain_key)),
            crate::runkey::KeyOutcome::Valid(_)
        ),
        "{plain}"
    );
    assert!(plain_text.contains("Read source: local_copy"), "{plain}");
    assert_eq!(plain_text.matches("Read source:").count(), 1, "{plain}");
    assert!(
        plain_text
            .chars()
            .take(256)
            .collect::<String>()
            .contains("Read source: local_copy"),
        "{plain}"
    );
    assert!(
        plain_text.contains("last matching hosted check/snapshot capture"),
        "{plain}"
    );
    assert!(!plain_text.contains("Hosted has newer changes"), "{plain}");
    assert!(!plain_text.contains("prior writes"), "{plain}");
    assert!(!plain_text.contains("not yet confirmed"), "{plain}");
    assert!(plain_text.contains("issued locally"), "{plain}");
    assert!(plain_text.starts_with("Run key: `"), "{plain}");
    assert!(plain_text
        .chars()
        .take(256)
        .collect::<String>()
        .contains(&plain_key));

    println!(
        "node bootstrap fixture: text={} complete_json_mcp_envelope={}",
        plain.to_string().len(),
        reply.to_string().len()
    );
    assert_eq!(hosted_bootstraps(&fixture.fake.requests.lock().await), 0);
    // Writes still go to hosted.
    let written = Box::pin(fixture.send(write())).await;
    assert_eq!(text(&written), "hosted answer");
    fixture.finish().await;
}

/// A carried key the copy does not hold goes to hosted, which knows whether the
/// run is new, open or closed.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_online_local_bootstrap_forwards_a_carried_key_the_copy_does_not_hold() {
    let fixture = online_v2().await;
    let key = crate::runkey::mint_fresh_agent_run(&Default::default()).unwrap();
    let reply = fixture
        .send(boot(97, json!({"format":"json","run_key":key})))
        .await;
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["read_source"], "hosted",
        "{reply}"
    );
    assert_eq!(hosted_bootstraps(&fixture.fake.requests.lock().await), 1);
    fixture.finish().await;
}

/// A v1 member copy has only a reduced bootstrap (obligations and some
/// instruction sources unavailable offline), so with hosted reachable it forwards.
#[tokio::test]
async fn online_local_bootstrap_forwards_a_reduced_member_copy_bootstrap() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let reply = fixture.send(boot(98, json!({"format":"json"}))).await;
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["read_source"], "hosted",
        "{reply}"
    );
    assert_eq!(hosted_bootstraps(&fixture.fake.requests.lock().await), 1);
    fixture.finish().await;
}

/// An ineligible copy forwards bootstrap to hosted unchanged: here the own-write
/// floor is ahead of the copy, as right after a write.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_online_local_bootstrap_forwards_when_the_copy_is_behind_the_floor() {
    let fixture = online_v2().await;
    fixture.node.state.lock().await.persisted.floor.act = Some(i64::MAX / 2);
    let reply = fixture.send(boot(96, json!({"format":"json"}))).await;
    assert_eq!(
        reply["result"]["structuredContent"]["node_routing"]["read_source"], "hosted",
        "{reply}"
    );
    assert_eq!(hosted_bootstraps(&fixture.fake.requests.lock().await), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn online_local_reads_forward_below_the_floor_without_a_local_read() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    {
        let mut state = fixture.node.state.lock().await;
        let act = state.persisted.floor.act.unwrap();
        state.persisted.floor.raise(act + 5);
    }
    assert_forwarded(fixture).await;
}

#[tokio::test]
async fn online_local_reads_use_the_copy_head_read_before_the_query() {
    // The copy's persisted head is behind the floor: forwarded, even though
    // the context a local answer would carry could not be trusted to say so.
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let floor = fixture.node.state.lock().await.persisted.floor.act.unwrap();
    set_copy_head(&fixture, floor - 1);
    assert_forwarded(fixture).await;
}

#[tokio::test]
async fn online_local_reads_serve_a_copy_whose_head_is_past_the_floor() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let floor = fixture.node.state.lock().await.persisted.floor.act.unwrap();
    set_copy_head(&fixture, floor + 3);
    let reply = read_once(&fixture).await;
    assert!(served_locally(&reply), "{reply}");
    assert_eq!(forwarded_reads(&fixture).await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn online_local_reads_forward_with_an_unresolved_write() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .floor
        .begin_write();
    assert_forwarded(fixture).await;
}

#[tokio::test]
async fn online_local_reads_forward_with_an_unknown_floor() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    fixture.node.state.lock().await.persisted.floor = Floor::default();
    assert_forwarded(fixture).await;
}

#[tokio::test]
async fn online_local_reads_forward_when_not_eligible() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    {
        let mut state = fixture.node.state.lock().await;
        let key = crate::mcp::PROTOCOL_VERSION;
        for row in state
            .persisted
            .discovery
            .get_mut(key)
            .unwrap()
            .operations
            .iter_mut()
            .filter(|r| r["operation"] == "get_record" || r["operation"] == "query_sql")
        {
            row["contract_digest"] = json!("mismatch");
        }
    }
    assert_forwarded(fixture).await;
}

fn sql_read(arguments: Value, wrapped: bool) -> Value {
    let mut envelope = json!({"operation":"query_sql","arguments":arguments,"format":"json",
        "run_key":"scout-chair-b748b2", "parent_key":"scout-chair-a748b2"});
    if wrapped {
        envelope["executor"] = json!("sql_read");
    }
    json!({"jsonrpc":"2.0","id":51,"method":"tools/call","params":{
        "name":if wrapped {"call_executor"} else {"sql_read"},"arguments":envelope,
        "_meta":{"private-test":"preserved"}}})
}

#[tokio::test]
async fn online_local_reads_serve_representative_data_sql_without_changing_its_envelope() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    // Independently authored recent-document and mixed-record list shapes.
    // Live app declarations belong to integration proofs with the app closure;
    // this public-source fixture tests routing and executor envelopes only.
    for sql in [
        "SELECT id, name FROM records WHERE type = 'Document' AND deleted_at IS NULL ORDER BY updated_at_ms DESC, id LIMIT 20",
        "SELECT id, name, home_id FROM records WHERE type IN ('Document', 'WorkItem') AND deleted_at IS NULL ORDER BY name, id LIMIT 20",
    ] {
        for wrapped in [false, true] {
            let reply = Box::pin(fixture.send(sql_read(json!({"sql":sql}), wrapped))).await;
            assert!(served_locally(&reply), "{reply}");
            assert!(
                reply["result"]["structuredContent"]["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["id"] == RECORD),
                "{reply}"
            );
            assert!(!text(&reply).contains("offline surface"), "{reply}");
        }
    }
    // Parameters, run correlation and format also survive the local path.
    for wrapped in [false, true] {
        let reply = Box::pin(fixture.send(sql_read(
            json!({
                "sql":"SELECT name FROM records WHERE id = ?1 ORDER BY id",
                "parameters":[{"type":"text","value":RECORD}]
            }),
            wrapped,
        )))
        .await;
        assert!(served_locally(&reply), "{reply}");
        assert_eq!(
            reply["result"]["structuredContent"]["run_context"]["run_key"], "scout-chair-b748b2",
            "{reply}"
        );
    }
    assert_eq!(forwarded(&fixture, "query_sql").await, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn online_local_reads_distinguish_sql_catalog_dependencies_from_names() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    for sql in [
        "SELECT executor FROM catalog_operations ORDER BY executor",
        "SELECT operation FROM \"catalog_operations\" ORDER BY operation",
        "SELECT count(*) AS n FROM catalog_operations",
        "SELECT EXISTS(SELECT 1 FROM catalog_operations) AS present",
        "SELECT name FROM records WHERE EXISTS(SELECT 1 FROM catalog_operations WHERE operation='query_sql') ORDER BY name",
        "WITH nested AS (SELECT * FROM catalog_operations) SELECT count(*) AS n FROM nested",
        "SELECT count(*) AS n FROM catalog_operations WHERE 0 LIMIT 0",
    ] {
        for wrapped in [false, true] {
            let request = sql_read(json!({"sql":sql}), wrapped);
            let reply = Box::pin(fixture.send(request.clone())).await;
            assert!(reply["result"]["structuredContent"]["standby_context"].is_null(), "{sql}: {reply}");
            assert_eq!(fixture.fake.requests.lock().await.last(), Some(&request));
        }
    }
    let before = forwarded(&fixture, "query_sql").await;
    for sql in [
        "SELECT name FROM records /* catalog_operations */ ORDER BY name",
        "SELECT name, 'catalog_operations' AS label FROM records ORDER BY name",
        "WITH catalog_operations AS (SELECT name FROM records) SELECT name FROM catalog_operations ORDER BY name",
    ] {
        let reply = Box::pin(fixture.send(sql_read(json!({"sql":sql}), true))).await;
        assert!(served_locally(&reply), "{sql}: {reply}");
    }
    assert_eq!(forwarded(&fixture, "query_sql").await, before);
    // Explicit local reads keep their offline-only catalogue and disclosure.
    let reply = Box::pin(fixture.send(local_only(sql_read(
        json!({
            "sql":"SELECT operation FROM catalog_operations ORDER BY operation"
        }),
        true,
    ))))
    .await;
    assert!(text(&reply).contains("offline surface"), "{reply}");
    assert_eq!(forwarded(&fixture, "query_sql").await, before);
    fixture.finish().await;
}

#[tokio::test]
async fn online_local_reads_leave_uninspectable_or_refused_sql_hosted() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    for arguments in [
        json!({"sql":"not sql"}),
        json!({"sql":"DELETE FROM records"}),
        json!({"sql":"SELECT name FROM records; SELECT 1"}),
        json!({"sql":"SELECT * FROM main.records"}),
        json!({"sql":"SELECT * FROM native_view_example"}),
        json!({"sql":"SELECT load_extension('forbidden')"}),
        json!({"sql":3}),
        // These inspect successfully but must still pass the dispatcher.
        json!({"sql":"SELECT name FROM records WHERE id=?1"}),
        json!({"sql":"SELECT name FROM records", "unexpected":true}),
    ] {
        let request = sql_read(arguments, true);
        let reply = Box::pin(fixture.send(request.clone())).await;
        assert!(
            reply["result"]["structuredContent"]["standby_context"].is_null(),
            "{reply}"
        );
        assert_eq!(fixture.fake.requests.lock().await.last(), Some(&request));
    }
    // An app carrier is never stripped to make a local query succeed: the
    // missing install refuses locally, then absent proof prevents forwarding.
    let mut request = sql_read(
        json!({"sql":"SELECT name FROM records ORDER BY name"}),
        false,
    );
    request["params"]["_meta"]["native/app"] = json!("offline.test@1; install=missing-install");
    let before = fixture.fake.requests.lock().await.len();
    let reply = Box::pin(fixture.send(request.clone())).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert_eq!(fixture.fake.requests.lock().await.len(), before);
    fixture.finish().await;
}

#[tokio::test]
async fn online_local_reads_wait_for_the_first_settled_probe() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    // As after a restart: floor persisted, but health only assumed.
    fixture.node.state.lock().await.checked = false;
    assert_forwarded(fixture).await;
}

#[tokio::test]
async fn online_local_reads_forward_unless_hosted_is_plainly_reachable() {
    for health in [Health::ProtocolFailed, Health::RevisionUnsupported] {
        let fixture = Fixture::online(BOUND).await;
        online_ready(&fixture).await;
        fixture.node.state.lock().await.health = health;
        assert_forwarded(fixture).await;
    }
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    fixture.node.state.lock().await.revision_unsupported = true;
    assert_forwarded(fixture).await;
}

#[tokio::test]
async fn online_local_reads_never_bypass_auth_refusal() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    fixture.node.state.lock().await.health = Health::AuthRefused;
    assert_forwarded(fixture).await;
}

#[tokio::test]
async fn online_local_reads_follow_a_write_through_the_probe() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    assert!(served_locally(&read_once(&fixture).await));
    let written = Box::pin(fixture.send(write())).await;
    assert_eq!(text(&written), "hosted answer");
    assert!(fixture.node.state.lock().await.persisted.floor.unresolved);
    // Unresolved: hosted answers.
    let during = read_once(&fixture).await;
    assert_eq!(text(&during), "hosted answer");
    assert_eq!(forwarded_reads(&fixture).await, 1);
    // The probe resolves it and the copy is at the floor again.
    Box::pin(fixture.node.probe()).await;
    assert!(!fixture.node.state.lock().await.persisted.floor.unresolved);
    let after = read_once(&fixture).await;
    assert!(served_locally(&after), "{after}");
    assert_eq!(forwarded_reads(&fixture).await, 1);
    fixture.finish().await;
}

#[tokio::test]
async fn online_local_reads_see_a_receipt_act_ahead_of_the_copy() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let floor = fixture.node.state.lock().await.persisted.floor.act.unwrap();
    {
        let mut state = fixture.node.state.lock().await;
        state.persisted.floor.raise(floor + 1);
    }
    // Even once the probe resolves, a copy behind the receipt act forwards.
    Box::pin(fixture.node.probe()).await;
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.act,
        Some(floor + 1)
    );
    assert_forwarded(fixture).await;
}

fn context_with(
    fixture_context: &crate::standby::StandbyResponseContext,
    edit: impl FnOnce(&mut crate::standby::StandbyResponseContext),
) -> crate::standby::StandbyResponseContext {
    let mut context = fixture_context.clone();
    edit(&mut context);
    context
}

#[tokio::test]
async fn pre_read_act_requires_a_fresh_undegraded_copy_inside_the_bound_and_floor() {
    use crate::standby::{StandbyFreshnessState, StandbyStatusMode};
    let fixture = Fixture::online(BOUND).await;
    let base = context_with(
        &fixture.supervisor.dispatcher().serving_context().unwrap(),
        |c| {
            c.serving_head_act = Some(100);
            c.freshness.age_seconds = Some(10);
            c.freshness.state = StandbyFreshnessState::Fresh;
            c.freshness_degraded = false;
            c.degraded_reasons.clear();
            c.mode = StandbyStatusMode::Standby;
        },
    );
    assert_eq!(pre_read_act(&base, 100, 30), Some(100));
    assert_eq!(pre_read_act(&base, 101, 30), None, "below the floor");
    assert_eq!(pre_read_act(&base, 100, 10), Some(100), "age at the bound");
    assert_eq!(pre_read_act(&base, 100, 9), None, "older than the bound");
    let no_age = context_with(&base, |c| c.freshness.age_seconds = None);
    assert_eq!(pre_read_act(&no_age, 1, 30), None);
    let no_head = context_with(&base, |c| c.serving_head_act = None);
    assert_eq!(pre_read_act(&no_head, 1, 30), None);
    let beyond = context_with(&base, |c| {
        c.freshness.state = StandbyFreshnessState::BeyondRpo
    });
    assert_eq!(pre_read_act(&beyond, 1, 30), None);
    let degraded = context_with(&base, |c| {
        c.freshness_degraded = true;
        c.degraded_reasons = vec!["database_busy"];
    });
    assert_eq!(pre_read_act(&degraded, 1, 30), None);
    let status_only = context_with(&base, |c| c.mode = StandbyStatusMode::StatusOnly);
    assert_eq!(pre_read_act(&status_only, 1, 30), None);
    fixture.finish().await;
}

#[test]
fn online_local_reads_bound_is_validated_at_config_load() {
    let base = |secs: u64| NodeConfig {
        working_note_appends: false,
        online_local_reads: Some(OnlineLocalReads {
            max_age_seconds: secs,
        }),
        ..serde_json::from_value(json!({
            "hosted_base_url":"https://example.test","home_id":"h","db_id":"d",
            "credential_file":"/x","socket_directory":"/y"
        }))
        .unwrap()
    };
    assert!(base(30).endpoint().is_ok());
    assert!(base(crate::standby::STANDBY_RPO_SECONDS).endpoint().is_ok());
    for bad in [0, crate::standby::STANDBY_RPO_SECONDS + 1] {
        let error = base(bad).endpoint().unwrap_err().to_string();
        assert!(
            error.contains("max_age_seconds") && error.contains("RPO"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn saver_writes_join_the_floor_only_when_online_local_reads_is_configured() {
    let off = Fixture::new().await;
    let outage = || Some(off.node.clone() as Arc<dyn gate::Outage>);
    assert!(saver_floor(&off.node.upstream.config, outage()).is_none());
    off.finish().await;
    let on = Fixture::online(BOUND).await;
    let outage = Some(on.node.clone() as Arc<dyn gate::Outage>);
    assert!(saver_floor(&on.node.upstream.config, outage).is_some());
    on.finish().await;
}

#[tokio::test]
async fn hosted_event_stream_exists_only_with_online_local_reads() {
    let off = Fixture::new().await;
    assert!(
        super::super::hosted_events::EventStream::for_config(
            &off.node.upstream,
            RefreshHints::default()
        )
        .is_none(),
        "option absent means no stream"
    );
    assert!(off.node.hosted_summary().await.get("events").is_none());
    off.finish().await;

    let on = Fixture::online(BOUND).await;
    let stream = super::super::hosted_events::EventStream::for_config(
        &on.node.upstream,
        RefreshHints::default(),
    )
    .expect("option present");
    assert_eq!(stream.status().summary()["state"], "connecting");
    let base = on.node.upstream.config.hosted_base_url.clone();
    assert_eq!(
        stream.url().as_str(),
        format!("{base}/databases/route-1/events")
    );
    // A base URL with a path prefix (and a trailing slash) keeps its prefix.
    let mut config = on.node.upstream.config.clone();
    config.hosted_base_url = format!("{base}/prefix/v1/");
    let upstream = Upstream::new(config, Duration::from_secs(5)).unwrap();
    let prefixed =
        super::super::hosted_events::EventStream::for_config(&upstream, RefreshHints::default())
            .unwrap();
    assert_eq!(
        prefixed.url().as_str(),
        format!("{base}/prefix/v1/databases/route-1/events")
    );
    on.finish().await;
}

#[tokio::test]
async fn hosted_event_stream_refusal_never_changes_failover_health() {
    use super::super::hosted_events::{EventStream, Timing};
    let fixture = Fixture::online(BOUND).await;
    let app = Router::new().route(
        "/databases/{db}/events",
        axum::routing::get(|| async { StatusCode::UNAUTHORIZED }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = reqwest::Url::parse(&format!(
        "http://{}/databases/route-1/events",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let stream = EventStream::new(
        url,
        fixture._dir.path().join("token"),
        Arc::new(|| {}),
        Timing::default(),
    )
    .unwrap();
    let status = stream.status();
    let task = tokio::spawn(stream.run());
    for _ in 0..100 {
        if status.summary()["state"] == "auth_refused" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(status.summary()["state"], "auth_refused");
    fixture.node.probe().await;
    let hosted = fixture.node.hosted_summary().await;
    assert_eq!(hosted["health"], "reachable");
    task.abort();
    server.abort();
    fixture.finish().await;
}

struct ChangesSocket {
    reader: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Drop for ChangesSocket {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl ChangesSocket {
    fn new(fixture: &Fixture, routed: bool) -> Self {
        let (peer, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(serve_routed_connection(
            server,
            fixture.node.upstream.clone(),
            routed.then(|| fixture.node.clone()),
            None,
            None,
            Arc::new(Admission::new()),
        ));
        let (reader, writer) = peer.into_split();
        Self {
            reader: tokio::io::BufReader::new(reader),
            writer,
            task: Some(task),
        }
    }
    async fn send(&mut self, request: Value) {
        self.writer
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        serde_json::from_str(&line).unwrap()
    }
}
fn follow_changes(fixture: &Fixture, after: Value) -> Value {
    json!({"jsonrpc":"2.0","id":101,"method":"native/changes/follow","params":{
        "account_id":fixture.node.upstream.config.account_id,
        "origin_database_id":fixture.runtime.origin_database_id,
        "after":after,
    }})
}
async fn wait_for_changes_followers(fixture: &Fixture, expected: bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while fixture.node.changes.has_followers() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn node_changes_socket_orders_coalesced_pushes_unfollows_and_resets_reconnects() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(follow_changes(&fixture, Value::Null)).await;
    let reply = socket.receive().await;
    assert_eq!(reply["id"], 101, "{reply}");
    assert_eq!(reply["result"]["contract"], "native.node-changes.v1");
    assert_eq!(reply["result"]["availability"]["local_copy"], "serving");
    assert_eq!(reply["result"]["reset_required"], true);
    let baseline = reply["result"]["cursor"].clone();
    let applied = reply["result"]["applied_act"].clone();
    let subscription = reply["result"]["subscription_id"].clone();
    socket
        .send(follow_changes(&fixture, baseline.clone()))
        .await;
    assert_eq!(
        socket.receive().await["error"]["data"]["reason"],
        "already_following"
    );
    // No await between these updates: the latest slot must disclose the gap.
    fixture
        .node
        .changes
        .note_floor(super::super::changes::Floor {
            act: Some(100),
            unresolved: true,
            ..Default::default()
        });
    fixture
        .node
        .changes
        .note_floor(super::super::changes::Floor {
            act: Some(101),
            unresolved: true,
            ..Default::default()
        });
    let pushed = socket.receive().await;
    assert_eq!(pushed["method"], "notifications/native_changes");
    assert_eq!(pushed["params"]["subscription_id"], subscription);
    assert_eq!(pushed["params"]["reset_required"], true);
    assert_eq!(
        pushed["params"]["applied_act"], applied,
        "a floor never advances the serving act"
    );
    socket.send(json!({"jsonrpc":"2.0","id":102,"method":"native/changes/unfollow","params":{"subscription_id":subscription}})).await;
    assert_eq!(socket.receive().await["result"]["unfollowed"], true);
    wait_for_changes_followers(&fixture, false).await;
    socket.send(follow_changes(&fixture, baseline)).await;
    assert_eq!(socket.receive().await["result"]["reset_required"], true);
    wait_for_changes_followers(&fixture, true).await;
    socket.writer.shutdown().await.unwrap();
    wait_for_changes_followers(&fixture, false).await;
    assert!(
        fixture.fake.requests.lock().await.is_empty(),
        "controls never forward"
    );
    drop(socket);
    fixture.finish().await;
}

#[tokio::test]
async fn node_changes_socket_refuses_wrong_binding_batches_and_missing_router_locally() {
    let fixture = Fixture::online(BOUND).await;
    let mut socket = ChangesSocket::new(&fixture, true);
    let mut wrong = follow_changes(&fixture, Value::Null);
    wrong["params"]["origin_database_id"] = json!("other-origin");
    let mut extra = follow_changes(&fixture, Value::Null);
    extra["params"]["sql"] = json!("SELECT 1");
    for (request, reason) in [
        (wrong, "binding_mismatch"),
        (extra, "invalid_params"),
        (
            json!({"jsonrpc":"2.0","id":1,"method":"native/changes/unknown","params":{}}),
            "unknown_changes_method",
        ),
        (
            json!([follow_changes(&fixture, Value::Null), read(true)]),
            "batch_refused",
        ),
    ] {
        socket.send(request).await;
        assert_eq!(socket.receive().await["error"]["data"]["reason"], reason);
    }
    let mut unrouted = ChangesSocket::new(&fixture, false);
    unrouted.send(follow_changes(&fixture, Value::Null)).await;
    assert_eq!(
        unrouted.receive().await["error"]["data"]["reason"],
        "changes_unavailable"
    );
    assert!(!fixture.node.changes.has_followers());
    assert!(fixture.fake.requests.lock().await.is_empty());
    drop(socket);
    drop(unrouted);
    fixture.finish().await;
}

#[tokio::test]
async fn node_changes_socket_cleans_follows_on_bad_frames_and_peer_loss() {
    let fixture = Fixture::online(BOUND).await;
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(follow_changes(&fixture, Value::Null)).await;
    socket.receive().await;
    // Oversized frame exits through an error, before ordinary EOF cleanup.
    let bytes = vec![b'x'; MAX_FRAME + 1];
    let _ = socket.writer.write_all(&bytes).await;
    wait_for_changes_followers(&fixture, false).await;
    drop(socket);
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(follow_changes(&fixture, Value::Null)).await;
    // Close while initialization/reply may still be in flight, allowing the
    // actual serving task to discover peer loss rather than aborting it.
    let task = socket.task.take().unwrap();
    drop(socket);
    let _ = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap();
    wait_for_changes_followers(&fixture, false).await;
    fixture.finish().await;
}

#[tokio::test]
async fn node_changes_reply_barrier_and_congested_unfollow_release_the_slot() {
    let fixture = Fixture::online(BOUND).await;
    let (peer, server) = UnixStream::pair().unwrap();
    let (_, write) = server.into_split();
    let writer = Arc::new(Mutex::new(write));
    let barrier = writer.lock().await;
    let node = fixture.node.clone();
    let output = writer.clone();
    let request = follow_changes(&fixture, Value::Null);
    let follow = tokio::spawn(async move {
        let mut connection = super::super::changes::Connection::default();
        connection
            .dispatch(Some(&node), &output, &request)
            .await
            .unwrap();
        connection
    });
    wait_for_changes_followers(&fixture, true).await;
    // Updates arrive while the follow reply cannot be written. They must not
    // overtake that reply, and a skipped stamp must be disclosed as a reset.
    fixture
        .node
        .changes
        .note_floor(super::super::changes::Floor {
            act: Some(100),
            ..Default::default()
        });
    fixture
        .node
        .changes
        .note_floor(super::super::changes::Floor {
            act: Some(101),
            ..Default::default()
        });
    drop(barrier);
    let mut connection = follow.await.unwrap();
    let (read, _) = peer.into_split();
    let mut read = tokio::io::BufReader::new(read);
    let mut line = String::new();
    read.read_line(&mut line).await.unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["id"], 101);
    line.clear();
    read.read_line(&mut line).await.unwrap();
    let push: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(push["method"], "notifications/native_changes");
    assert_eq!(push["params"]["reset_required"], true);
    // Unfollow cancels and releases the slot BEFORE attempting its own reply,
    // even when another writer is congested.
    let barrier = writer.lock().await;
    let node = fixture.node.clone();
    let output = writer.clone();
    let request = json!({"jsonrpc":"2.0","id":102,"method":"native/changes/unfollow","params":{"subscription_id":reply["result"]["subscription_id"]}});
    let unfollow =
        tokio::spawn(async move { connection.dispatch(Some(&node), &output, &request).await });
    wait_for_changes_followers(&fixture, false).await;
    drop(barrier);
    unfollow.await.unwrap().unwrap();
    fixture.finish().await;
}

#[tokio::test]
async fn node_changes_follow_reply_timeout_drops_its_reserved_slot() {
    let fixture = Fixture::online(BOUND).await;
    let (_peer, server) = UnixStream::pair().unwrap();
    let (_, write) = server.into_split();
    let writer = Arc::new(Mutex::new(write));
    let _barrier = writer.lock().await;
    let node = fixture.node.clone();
    let output = writer.clone();
    let request = follow_changes(&fixture, Value::Null);
    tokio::time::pause();
    let task = tokio::spawn(async move {
        let mut connection = super::super::changes::Connection::default();
        connection.dispatch(Some(&node), &output, &request).await
    });
    wait_for_changes_followers(&fixture, true).await;
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(task.await.unwrap().is_err());
    assert!(!fixture.node.changes.has_followers());
    tokio::time::resume();
    fixture.finish().await;
}

struct ChangesObserver(tokio::task::JoinHandle<()>);
impl Drop for ChangesObserver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn changes_quiet(socket: &mut ChangesSocket) {
    let mut line = String::new();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(40),
            socket.reader.read_line(&mut line)
        )
        .await
        .is_err(),
        "unexpected notification: {line}"
    );
}

#[tokio::test]
async fn node_changes_observer_waits_for_verified_reader_publication_and_reports_auth_refusal() {
    let fixture = Fixture::with_startup(Some(false)).await;
    let observer = ChangesObserver(tokio::spawn(fixture.node.clone().observe_changes()));
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(follow_changes(&fixture, Value::Null)).await;
    let initial = socket.receive().await;
    assert_eq!(
        initial["result"]["availability"]["local_copy"],
        "status_only"
    );
    assert!(initial["result"]["applied_act"].is_null());
    let (snapshot, manifest) = stage(&fixture.store, &fixture.db, "ui-publication").await;
    // A staged snapshot is not a serving reader, and repeated sampling does
    // not publish merely because another second of age elapsed.
    fixture.node.sample_changes().await;
    fixture.node.sample_changes().await;
    changes_quiet(&mut socket).await;
    let installed = fixture
        .store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    // Store acceptance precedes asynchronous device/readiness qualification.
    // Await that milestone explicitly: this test asserts publication ordering,
    // not a hardware-dependent qualification latency budget.
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if fixture
                .supervisor
                .dispatcher()
                .serving_context()
                .is_some_and(|context| {
                    context.serving_generation_id.as_deref() == Some(installed.id.as_str())
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("verified serving reader was not published");
    let published = socket.receive().await;
    assert_eq!(published["method"], "notifications/native_changes");
    assert_eq!(published["params"]["serving_generation_id"], installed.id);
    assert!(published["params"]["applied_act"].is_i64());
    assert_eq!(published["params"]["reset_required"], true);
    assert_eq!(published["params"]["availability"]["local_copy"], "serving");
    let read = Box::pin(fixture.send(local_only(read(true)))).await;
    assert!(text(&read).contains("local-first"), "{read}");
    // An observed refusal invalidates availability without inventing grant
    // knowledge or claiming a newer applied act.
    fixture.fake.status.store(401, Ordering::Release);
    Box::pin(fixture.node.probe()).await;
    let refused = socket.receive().await;
    assert_eq!(refused["params"]["availability"]["hosted"], "auth_refused");
    assert_eq!(
        refused["params"]["applied_act"],
        published["params"]["applied_act"]
    );
    assert_eq!(refused["params"]["reason"], "availability_changed");
    drop(socket);
    drop(observer);
    fixture.finish().await;
}

#[tokio::test]
async fn node_changes_observer_announces_applied_delta_not_rejected_or_staged_data() {
    use crate::standby::{StandbyRefreshConfig, StandbyRefreshController, StandbyRefreshOutcome};
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let observer = ChangesObserver(tokio::spawn(fixture.node.clone().observe_changes()));
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(follow_changes(&fixture, Value::Null)).await;
    let initial = socket.receive().await;
    crate::store::update_record(&fixture.db, RECORD, json!({"name":"node-stream-updated"}))
        .await
        .unwrap();
    let _staged = stage(&fixture.store, &fixture.db, "not-published").await;
    fixture.node.sample_changes().await;
    changes_quiet(&mut socket).await;
    let config = StandbyRefreshConfig::from_json(
        &fs::read(fixture._dir.path().join("refresh.json")).unwrap(),
    )
    .unwrap();
    let controller = StandbyRefreshController::new(
        fixture.runtime.clone(),
        config,
        fixture.store.clone(),
        observed(),
    )
    .unwrap();
    fixture.fake.delta_mode.store(2, Ordering::Release);
    assert!(Box::pin(controller.refresh_once(RefreshCause::Scheduled))
        .await
        .is_err());
    fixture.node.sample_changes().await;
    changes_quiet(&mut socket).await;
    fixture.fake.delta_mode.store(1, Ordering::Release);
    let outcome = Box::pin(controller.refresh_once(RefreshCause::Scheduled))
        .await
        .unwrap();
    assert!(
        matches!(outcome, StandbyRefreshOutcome::Advanced { .. }),
        "{outcome:?}"
    );
    let advanced = socket.receive().await;
    assert_eq!(
        advanced["params"]["serving_generation_id"],
        initial["result"]["serving_generation_id"]
    );
    assert!(
        advanced["params"]["applied_act"].as_i64().unwrap()
            > initial["result"]["applied_act"].as_i64().unwrap()
    );
    assert_eq!(advanced["params"]["reason"], "serving_advanced");
    let read = read_once(&fixture).await;
    assert!(text(&read).contains("node-stream-updated"), "{read}");
    assert_eq!(
        read["result"]["structuredContent"]["standby_context"]["serving_head_act"],
        advanced["params"]["applied_act"]
    );
    // An unchanged refresh and normal sampling do not push duplicate results.
    let outcome = Box::pin(controller.refresh_once(RefreshCause::Scheduled))
        .await
        .unwrap();
    assert!(matches!(outcome, StandbyRefreshOutcome::Unchanged { .. }));
    fixture.node.sample_changes().await;
    changes_quiet(&mut socket).await;
    drop(socket);
    drop(observer);
    fixture.finish().await;
}

#[tokio::test]
async fn node_changes_persisted_floor_and_failure_notifications_never_advance_application() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(follow_changes(&fixture, Value::Null)).await;
    let initial = socket.receive().await;
    let applied = initial["result"]["applied_act"].clone();
    assert!(gate::Outage::before_send(fixture.node.as_ref()).await);
    let began = socket.receive().await;
    assert_eq!(began["params"]["reason"], "write_floor_changed");
    assert_eq!(began["params"]["write_floor"]["unresolved"], true);
    let receipt =
        json!({"result":{"isError":false,"structuredContent":{"act":applied.as_i64().unwrap()+2}}})
            .to_string();
    gate::Outage::after_write(fixture.node.as_ref(), Some(&receipt)).await;
    let settled = socket.receive().await;
    assert_eq!(
        settled["params"]["write_floor"]["act"],
        applied.as_i64().unwrap() + 2
    );
    Box::pin(fixture.node.probe()).await;
    let probed = socket.receive().await;
    assert_eq!(probed["params"]["write_floor"]["unresolved"], false);
    // Force a local persistence refusal, rather than pretending an in-memory
    // floor was saved. No permissions or live files outside the fixture change.
    fs::remove_file(&fixture.node.file.path).unwrap();
    fs::create_dir(&fixture.node.file.path).unwrap();
    {
        let mut state = fixture.node.state.lock().await;
        assert!(!fixture.node.persist(&mut state));
    }
    let failed = socket.receive().await;
    assert_eq!(failed["params"]["write_floor"]["persistence_failed"], true);
    assert_eq!(failed["params"]["write_floor"]["unresolved"], true);
    fs::remove_dir(&fixture.node.file.path).unwrap();
    {
        let mut state = fixture.node.state.lock().await;
        assert!(fixture.node.persist(&mut state));
    }
    let recovered = socket.receive().await;
    assert_eq!(
        recovered["params"]["write_floor"]["persistence_failed"],
        false
    );
    for notification in [&began, &settled, &probed, &failed, &recovered] {
        assert_eq!(notification["params"]["applied_act"], applied);
    }
    drop(socket);
    fixture.finish().await;
}

#[tokio::test]
async fn node_changes_notification_timeout_signals_connection_failure_and_releases_follow() {
    let fixture = Fixture::online(BOUND).await;
    let (_peer, server) = UnixStream::pair().unwrap();
    let (_, write) = server.into_split();
    let writer = Arc::new(Mutex::new(write));
    let mut connection = super::super::changes::Connection::default();
    connection
        .dispatch(
            Some(&fixture.node),
            &writer,
            &follow_changes(&fixture, Value::Null),
        )
        .await
        .unwrap();
    let _barrier = writer.lock().await;
    tokio::time::pause();
    fixture
        .node
        .changes
        .note_floor(super::super::changes::Floor {
            act: Some(100),
            ..Default::default()
        });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::time::timeout(Duration::from_secs(1), connection.failed())
        .await
        .unwrap();
    wait_for_changes_followers(&fixture, false).await;
    tokio::time::resume();
    drop(connection);
    fixture.finish().await;
}

async fn enable_app_transport(fixture: &mut Fixture) {
    let node = Arc::get_mut(&mut fixture.node).unwrap();
    let mut config = node.upstream.config.clone();
    config.desktop_app_proof_transport = true;
    config.desktop_app_proof_resource_origin = Some("https://plugin.test".into());
    node.upstream = Arc::new(Upstream::new(config, Duration::from_secs(5)).unwrap());
}
fn proof_install(fixture: &Fixture) -> Value {
    json!({"jsonrpc":"2.0","id":900,"method":"native/app-proof/install","params":{
        "account_id":fixture.node.upstream.config.account_id,"hosted_db_id":fixture.node.upstream.config.db_id,
        "origin_database_id":fixture.runtime.origin_database_id,"resource_origin":"https://plugin.test","forwarding_origin":fixture.node.upstream.endpoint.origin().ascii_serialization(),
        "app":"docs@1; install=evt","proof":"socket-secret-proof","expires_in_ms":60000}})
}
fn app_call(mut message: Value) -> Value {
    message["params"]["_meta"] = json!({"native/app":"docs@1; install=evt"});
    message
}
#[tokio::test]
async fn app_socket_proofs_are_connection_bound_and_floor_settlement_is_preserved() {
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    online_ready(&fixture).await;
    let mut a = ChangesSocket::new(&fixture, true);
    let mut b = ChangesSocket::new(&fixture, true);
    a.send(proof_install(&fixture)).await;
    let installed = a.receive().await;
    assert_eq!(installed["result"]["ready"], true);
    assert!(!installed.to_string().contains("socket-secret-proof"));
    let before = fixture.node.state.lock().await.persisted.floor.clone();
    b.send(app_call(write())).await;
    assert_eq!(b.receive().await["error"]["data"]["outcome"], "not_sent");
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.pending,
        before.pending
    );
    assert_eq!(forwarded(&fixture, "create_record").await, 0);
    a.send(app_call(write())).await;
    let reply = a.receive().await;
    assert_eq!(text(&reply), "hosted answer");
    let floor = fixture.node.state.lock().await.persisted.floor.clone();
    assert_eq!(floor.active_writes, 0, "begin must be paired with settle");
    assert_eq!(
        floor.pending,
        before.pending + 2,
        "begin and possible commit each advance the monotonic fence"
    );
    assert!(floor.unresolved, "unknown receipt act retains floor");
    assert_eq!(forwarded(&fixture, "create_record").await, 1);
    assert_eq!(
        fixture
            .node
            .gate
            .as_ref()
            .unwrap()
            .status(&Default::default())["queue"]["pending"],
        0
    );
    // Behind an unresolved floor the read forwards with its attribution;
    // another connection has no proof and must refuse instead of stale-local.
    a.send(app_call(read(true))).await;
    assert_eq!(text(&a.receive().await), "hosted answer");
    b.send(app_call(read(true))).await;
    assert_eq!(b.receive().await["error"]["data"]["outcome"], "not_sent");
    fixture.fake.fail_reads.store(true, Ordering::Release);
    a.send(app_call(read(true))).await;
    let failed = a.receive().await;
    assert!(
        failed
            .pointer("/result/structuredContent/standby_context")
            .is_none(),
        "failed upstream app read cannot become stale-local: {failed}"
    );
    assert_eq!(fixture.node.state.lock().await.health, Health::Unreachable);
    let reads = forwarded_reads(&fixture).await;
    a.send(app_call(read(true))).await;
    assert_eq!(a.receive().await["error"]["data"]["outcome"], "not_sent");
    assert_eq!(
        forwarded_reads(&fixture).await,
        reads,
        "known offline app reads refuse without dispatch"
    );
    a.send(json!({"jsonrpc":"2.0","id":901,"method":"native/app-proof/clear","params":{}}))
        .await;
    assert_eq!(a.receive().await["result"]["cleared"], true);
    a.send(app_call(write())).await;
    assert_eq!(a.receive().await["error"]["data"]["outcome"], "not_sent");
    assert_eq!(forwarded(&fixture, "create_record").await, 1);
    drop(a);
    drop(b);
    fixture.finish().await;
}
#[tokio::test]
async fn app_transport_off_and_unknown_controls_never_forward_or_journal() {
    let fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    let mut socket = ChangesSocket::new(&fixture, true);
    for message in [
        proof_install(&fixture),
        json!({"jsonrpc":"2.0","id":901,"method":"native/app-proof/unknown","params":{"proof":"secret"}}),
        json!([proof_install(&fixture)]),
    ] {
        socket.send(message).await;
        let reply = socket.receive().await;
        assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
        assert!(!reply.to_string().contains("socket-secret-proof"));
    }
    socket.send(app_call(write())).await;
    assert_eq!(
        socket.receive().await["error"]["data"]["outcome"],
        "not_sent"
    );
    assert_eq!(forwarded(&fixture, "create_record").await, 0);
    assert_eq!(
        fixture
            .node
            .gate
            .as_ref()
            .unwrap()
            .status(&Default::default())["entry_counts"],
        json!({})
    );
    assert!(fixture
        .fake
        .requests
        .lock()
        .await
        .iter()
        .all(|r| !super::super::app_proof::is_control(r)));
    drop(socket);
    fixture.finish().await;
}

fn read_barrier(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"native/reads/barrier","params":{}})
}
fn assert_barrier_error(reply: &Value, reason: &str) {
    assert_eq!(
        reply["error"]["data"]["contract"], "native.reads-barrier.v1",
        "{reply}"
    );
    assert_eq!(reply["error"]["data"]["reason"], reason, "{reply}");
    assert_eq!(reply["error"]["data"]["read_ready"], false);
    assert!(reply["error"]["data"].get("outcome").is_none());
}
#[tokio::test]
async fn read_barrier_requires_optin_resource_policy_router_and_strict_local_controls() {
    for mode in 0..4 {
        let mut fixture = Fixture::online(BOUND).await;
        if mode != 0 {
            enable_app_transport(&mut fixture).await;
        }
        if mode == 1 || mode == 2 {
            let node = Arc::get_mut(&mut fixture.node).unwrap();
            let mut config = node.upstream.config.clone();
            if mode == 1 {
                config.desktop_app_proof_resource_origin = None;
            }
            if mode == 2 {
                config.online_local_reads = None;
            }
            node.upstream = Arc::new(Upstream::new(config, Duration::from_secs(5)).unwrap());
        }
        fixture.fake.requests.lock().await.clear();
        let mut socket = ChangesSocket::new(&fixture, mode != 3);
        socket.send(read_barrier(1)).await;
        assert_barrier_error(&socket.receive().await, "barrier_unavailable");
        assert!(fixture.fake.requests.lock().await.is_empty());
        drop(socket);
        fixture.finish().await;
    }
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    let mut socket = ChangesSocket::new(&fixture, true);
    let mut extra = read_barrier(1);
    extra["params"]["head_act"] = json!(100);
    let mut missing = read_barrier(2);
    missing.as_object_mut().unwrap().remove("params");
    for request in [
        extra,
        missing,
        json!({"jsonrpc":"2.0","method":"native/reads/barrier","params":{}}),
        json!({"jsonrpc":"2.0","id":3,"method":"native/reads/unknown","params":{}}),
        json!([read_barrier(4), write()]),
        json!({"jsonrpc":"2.0","id":5,"method":"native/reads/barrier","params":{"proof":"DO-NOT-ECHO"}}),
    ] {
        socket.send(request).await;
        let reply = socket.receive().await;
        assert_barrier_error(&reply, "barrier_unavailable");
        assert!(!reply.to_string().contains("DO-NOT-ECHO"));
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    drop(socket);
    fixture.finish().await;
}
#[tokio::test]
async fn read_barrier_issues_fresh_head_after_probe_lock_without_blocking_socket_or_claiming_applied(
) {
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    online_ready(&fixture).await;
    let mut observer = ChangesSocket::new(&fixture, true);
    observer.send(follow_changes(&fixture, Value::Null)).await;
    let initial = observer.receive().await;
    fixture.fake.pause_probe.store(true, Ordering::Release);
    let node = fixture.node.clone();
    let old_probe = tokio::spawn(async move {
        node.probe().await;
    });
    fixture.fake.entered.notified().await;
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(read_barrier(1)).await;
    socket.send(read_barrier(2)).await;
    assert_barrier_error(&socket.receive().await, "barrier_busy");
    socket.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"standby_status","arguments":{}}})).await;
    let status = socket.receive().await;
    assert_eq!(
        status["id"], 3,
        "ordinary request must finish while barrier waits"
    );
    crate::store::update_record(&fixture.db, RECORD, json!({"name":"http-committed"}))
        .await
        .unwrap();
    fixture.fake.resume.notify_one();
    old_probe.await.unwrap();
    let reply = socket.receive().await;
    let result = &reply["result"];
    assert_eq!(reply["id"], 1);
    assert_eq!(result["contract"], "native.reads-barrier.v1");
    assert!(uuid::Uuid::parse_str(result["barrier_id"].as_str().unwrap()).is_ok());
    assert!(
        result["head_act"].as_i64().unwrap() > initial["result"]["applied_act"].as_i64().unwrap()
    );
    assert_eq!(
        result["binding"],
        serde_json::to_value(fixture.node.app_proof_binding().await.unwrap()).unwrap()
    );
    assert_eq!(
        result["admission"],
        json!({"floor_persisted":true,"read_ready":false})
    );
    assert!(result.get("applied_act").is_none());
    // The earlier probe may publish its intermediate floor before the barrier.
    // Notifications can coalesce, so consume until the captured floor appears.
    let mut captured_floor_published = false;
    for _ in 0..2 {
        let changed = observer.receive().await;
        assert_eq!(changed["params"]["reason"], "write_floor_changed");
        assert_eq!(
            changed["params"]["applied_act"],
            initial["result"]["applied_act"]
        );
        assert!(
            changed["params"]["write_floor"]["act"].as_i64().unwrap()
                <= result["head_act"].as_i64().unwrap()
        );
        if changed["params"]["write_floor"]["act"] == result["head_act"] {
            captured_floor_published = true;
            break;
        }
    }
    assert!(captured_floor_published);
    let requests = fixture.fake.requests.lock().await;
    assert_eq!(
        requests
            .iter()
            .filter(|r| target(r).is_some_and(|(_, op, _)| op == "authority_act_head"))
            .count(),
        2
    );
    drop(requests);
    let persisted = fixture.node.state.lock().await.persisted.clone();
    let (_, recovered) = StateFile::open(
        &fixture.node.upstream.config.socket_directory,
        persisted.binding,
    )
    .unwrap();
    assert_eq!(recovered.floor.act, result["head_act"].as_i64());
    drop(socket);
    drop(observer);
    fixture.finish().await;
}
#[tokio::test]
async fn read_barrier_cancellation_releases_slot_and_never_dispatches_waiting_head() {
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    let lock = fixture.node.probe_lock.lock().await;
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(read_barrier(1)).await;
    socket.send(read_barrier(2)).await;
    assert_barrier_error(&socket.receive().await, "barrier_busy");
    socket
        .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}))
        .await;
    assert_barrier_error(&socket.receive().await, "barrier_cancelled");
    assert!(!fixture
        .fake
        .requests
        .lock()
        .await
        .iter()
        .any(|r| target(r).is_some_and(|(_, op, _)| op == "authority_act_head")));
    drop(lock);
    socket.send(read_barrier(3)).await;
    let first = socket.receive().await;
    assert!(first.get("result").is_some(), "{first}");
    socket.send(read_barrier(4)).await;
    let second = socket.receive().await;
    assert_ne!(
        first["result"]["barrier_id"],
        second["result"]["barrier_id"]
    );
    drop(socket);
    fixture.finish().await;
}
#[tokio::test]
async fn read_barrier_deadline_includes_probe_lock_and_releases_slot() {
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    let lock = fixture.node.probe_lock.lock().await;
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(read_barrier(1)).await;
    socket.send(read_barrier(2)).await;
    assert_barrier_error(&socket.receive().await, "barrier_busy");
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    assert_barrier_error(&socket.receive().await, "barrier_timeout");
    tokio::time::resume();
    assert!(fixture.fake.requests.lock().await.is_empty());
    drop(lock);
    socket.send(read_barrier(3)).await;
    assert!(socket.receive().await.get("result").is_some());
    drop(socket);
    fixture.finish().await;
}
#[tokio::test]
async fn read_barrier_close_cleans_waiting_task_without_mutating_floor() {
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    let before = fixture.node.state.lock().await.persisted.floor.clone();
    let lock = fixture.node.probe_lock.lock().await;
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(read_barrier(1)).await;
    socket.send(read_barrier(2)).await;
    assert_barrier_error(&socket.receive().await, "barrier_busy");
    let task = socket.task.take().unwrap();
    drop(socket);
    let _ = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("closed socket retained barrier task")
        .unwrap();
    assert!(fixture.fake.requests.lock().await.is_empty());
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.act,
        before.act
    );
    drop(lock);
    fixture.finish().await;
}
#[tokio::test]
async fn read_barrier_persistence_failure_and_uncertainty_are_honest() {
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    online_ready(&fixture).await;
    {
        let mut state = fixture.node.state.lock().await;
        state.persisted.floor.pending += 1;
        state.persisted.floor.unresolved = true;
        assert!(fixture.node.persist(&mut state));
    }
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(read_barrier(1)).await;
    assert!(socket.receive().await.get("result").is_some());
    assert!(fixture.node.state.lock().await.persisted.floor.unresolved);
    fs::remove_file(&fixture.node.file.path).unwrap();
    fs::create_dir(&fixture.node.file.path).unwrap();
    socket.send(read_barrier(2)).await;
    assert_barrier_error(&socket.receive().await, "barrier_persistence_failed");
    assert!(fixture.node.state.lock().await.persistence_failed);
    fs::remove_dir(&fixture.node.file.path).unwrap();
    drop(socket);
    fixture.finish().await;
}

#[tokio::test]
async fn read_barrier_refuses_authority_scope_and_protocol_failures_without_floor_import() {
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    online_ready(&fixture).await;
    let before = fixture.node.state.lock().await.persisted.floor.clone();
    let mut socket = ChangesSocket::new(&fixture, true);
    for mismatch in [1, 2] {
        fixture
            .fake
            .head_mismatch
            .store(mismatch, Ordering::Release);
        socket.send(read_barrier(1)).await;
        assert_barrier_error(&socket.receive().await, "barrier_unavailable");
        assert_eq!(
            fixture.node.state.lock().await.persisted.floor.act,
            before.act
        );
    }
    fixture.fake.head_mismatch.store(0, Ordering::Release);
    for status in [200, 401, 502] {
        fixture.fake.status.store(status, Ordering::Release);
        socket.send(read_barrier(2)).await;
        assert_barrier_error(&socket.receive().await, "barrier_unavailable");
        assert_eq!(
            fixture.node.state.lock().await.persisted.floor.act,
            before.act
        );
    }
    drop(socket);
    fixture.finish().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn receiver_node_probe_preserves_selected_shape_and_maintenance_boundaries() {
    let mut fixture = Fixture::build_with_engine_and_policy(
        Some(true),
        None,
        false,
        Some(OnlineLocalReads {
            max_age_seconds: BOUND,
        }),
        false,
        true,
        true,
    )
    .await;
    enable_app_transport(&mut fixture).await;
    online_ready(&fixture).await;
    assert_eq!(
        fixture.node.probe_observed().await,
        Health::Reachable,
        "headerless94"
    );
    let binding = fixture.node.app_proof_binding().await.unwrap();
    let before = serde_json::to_value(&fixture.node.state.lock().await.persisted.floor).unwrap();
    let known95 = crate::standby::shapes::v2(1, crate::standby::shapes::V2_95)
        .unwrap()
        .shape();
    let mut unknown = known95.clone();
    unknown.engine_schema = 96;
    for selected in [&known95, &unknown] {
        *fixture.fake.head_selected_shape.lock().unwrap() =
            Some(serde_json::to_string(selected).unwrap());
        assert_eq!(fixture.node.probe_observed().await, Health::ProtocolFailed);
        assert_eq!(
            fixture.node.capture_read_barrier(&binding).await,
            Err("barrier_unavailable")
        );
        assert_eq!(
            serde_json::to_value(&fixture.node.state.lock().await.persisted.floor).unwrap(),
            before
        );
    }
    let known94 = crate::standby::shapes::v2(1, crate::standby::shapes::V2_94)
        .unwrap()
        .shape();
    *fixture.fake.head_selected_shape.lock().unwrap() =
        Some(serde_json::to_string(&known94).unwrap());
    assert_eq!(fixture.node.probe_observed().await, Health::Reachable);
    // Only the private fixture's canonical source changes. The admitted94
    // serving generation is never prepared or mutated by this head proof.
    crate::standby::shapes::tests::upgrade_fixture_to_95(&fixture.db).await;
    *fixture.fake.head_selected_shape.lock().unwrap() =
        Some(serde_json::to_string(&known95).unwrap());
    assert_eq!(
        fixture.node.probe_observed().await,
        Health::Reachable,
        "exact95"
    );

    fixture.fake.head_maintenance.store(true, Ordering::Release);
    // A fully valid selected95 head still supplies no health or barrier
    // authority while its response is a maintenance snapshot.
    assert_eq!(fixture.node.probe_observed().await, Health::ProtocolFailed);
    assert_eq!(
        fixture.node.capture_read_barrier(&binding).await,
        Err("barrier_unavailable")
    );
    assert_eq!(
        serde_json::to_value(&fixture.node.state.lock().await.persisted.floor).unwrap(),
        before
    );
    *fixture.fake.head_selected_shape.lock().unwrap() =
        Some(serde_json::to_string(&unknown).unwrap());
    // Maintenance wins over selection/body acceptance, after auth/gateway.
    let classification = Arc::new(std::sync::Mutex::new(Health::ProtocolFailed));
    let client = ProbeHttp {
        compatibility: Default::default(),
        client: fixture.node.probe_client.clone(),
        endpoint: fixture.node.upstream.endpoint.clone(),
        classification,
        install_key: None,
    };
    let message = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"export","arguments":{"operation":"authority_act_head","arguments":{}}}});
    let error = match client
        .call_with_shape(String::new(), "fixture-token".into(), message.clone())
        .await
    {
        Ok(_) => panic!("maintenance cannot supply a selected head"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        Error::engine(crate::standby::delta_transport::MAINTENANCE_SNAPSHOT_ERROR).to_string()
    );
    for status in [0, 200] {
        fixture.fake.status.store(status, Ordering::Release);
        assert_eq!(fixture.node.probe_observed().await, Health::ProtocolFailed);
        assert_eq!(
            fixture.node.capture_read_barrier(&binding).await,
            Err("barrier_unavailable")
        );
        assert_eq!(
            serde_json::to_value(&fixture.node.state.lock().await.persisted.floor).unwrap(),
            before
        );
    }
    for (status, expected) in [
        (401, Health::AuthRefused),
        (403, Health::AuthRefused),
        (502, Health::Unreachable),
        (503, Health::Unreachable),
        (504, Health::Unreachable),
    ] {
        fixture.fake.status.store(status, Ordering::Release);
        assert_eq!(
            fixture.node.probe_observed().await,
            expected,
            "status{status} precedes maintenance and unknown selection"
        );
        assert_eq!(
            serde_json::to_value(&fixture.node.state.lock().await.persisted.floor).unwrap(),
            before
        );
    }
    fixture.fake.status.store(0, Ordering::Release);
    fixture
        .fake
        .head_maintenance
        .store(false, Ordering::Release);
    *fixture.fake.head_selected_shape.lock().unwrap() =
        Some(serde_json::to_string(&known95).unwrap());
    assert_eq!(fixture.node.probe_observed().await, Health::Reachable);
    assert!(fixture.node.capture_read_barrier(&binding).await.is_ok());
    fixture.finish().await;
}
#[tokio::test]
async fn read_barrier_deadline_bounds_dispatched_head_and_never_resolves_unknown_writes() {
    let mut fixture = Fixture::online(BOUND).await;
    enable_app_transport(&mut fixture).await;
    online_ready(&fixture).await;
    let before = fixture.node.state.lock().await.persisted.floor.clone();
    fixture.fake.pause_probe.store(true, Ordering::Release);
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(read_barrier(1)).await;
    fixture.fake.entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    assert_barrier_error(&socket.receive().await, "barrier_timeout");
    tokio::time::resume();
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.act,
        before.act
    );
    fixture.fake.resume.notify_one();
    socket.send(read_barrier(2)).await;
    assert!(socket.receive().await.get("result").is_some());
    drop(socket);
    fixture.finish().await;
}

async fn pending_fixture() -> Fixture {
    let fixture = Box::pin(Fixture::build(None, None, false, None, true)).await;
    Box::pin(online_ready(&fixture)).await;
    fixture.fake.status.store(502, Ordering::Release);
    Box::pin(fixture.node.probe()).await;
    fixture
}
fn pending_create() -> Value {
    let mut request = write();
    request["params"]["arguments"]["run_key"] = json!("scout-chair-j748b2");
    request["params"]["arguments"]["arguments"]["name"] = json!("quartzpendingproof");
    request["params"]["arguments"]["arguments"]["body"] = json!("quartzpendingproof body");
    request["params"]["arguments"]["arguments"]["idempotency_key"] = json!("pending-proof-create");
    request
}
fn pending_read(id: &str) -> Value {
    let mut request = read(true);
    request["params"]["arguments"]["arguments"]["ids"] = json!([id]);
    request
}
fn pending_search() -> Value {
    json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"records_read","arguments":{"operation":"search","arguments":{"query":"quartzpendingproof"},"format":"json"}}})
}
async fn assert_pending_visible(fixture: &Fixture, id: &str) -> (Value, Value) {
    let reply = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let reply = Box::pin(fixture.send(pending_read(id))).await;
            if reply["result"]["structuredContent"]["records"][0]["node_pending_preview"]["state"]
                == "pending"
            {
                break reply;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("node publishes pending get_record after background preparation");
    let record = &reply["result"]["structuredContent"]["records"][0];
    assert_eq!(record["id"], id, "{reply}");
    assert_eq!(
        record["node_pending_preview"]["state"], "pending",
        "{reply}"
    );
    assert!(record.get("version").is_none(), "{reply}");
    assert!(record.get("body_digest").is_none());
    assert!(record.get("contribution").is_none());
    let search = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let reply = Box::pin(fixture.send(pending_search())).await;
            if reply["result"]["structuredContent"]["hits"]
                .as_array()
                .is_some_and(|hits| {
                    hits.iter().any(|hit| {
                        hit["id"] == id && hit["node_pending_preview"]["state"] == "pending"
                    })
                })
            {
                break reply;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("node publishes pending search after background preparation");
    let hits = search["result"]["structuredContent"]["hits"]
        .as_array()
        .expect("search hits");
    assert_eq!(
        hits.iter().filter(|hit| hit["id"] == id).count(),
        1,
        "{search}"
    );
    assert!(
        hits.iter()
            .any(|hit| hit["id"] == id && hit["node_pending_preview"]["state"] == "pending"),
        "{search}"
    );
    (reply, search)
}

#[tokio::test]
async fn pending_fork_outage_note_is_immediately_readable_and_searchable() {
    let fixture = Box::pin(pending_fixture()).await;
    let base = fixture.node.dispatcher.pending_fork_base().unwrap();
    let before: (i64, i64) = sqlx::query_as(
        "SELECT next_act, (SELECT COUNT(*) FROM content_events) FROM act_state WHERE singleton=1",
    )
    .fetch_one(base.db.pool())
    .await
    .unwrap();
    let reply = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&reply)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    let after: (i64, i64) = sqlx::query_as(
        "SELECT next_act, (SELECT COUNT(*) FROM content_events) FROM act_state WHERE singleton=1",
    )
    .fetch_one(base.db.pool())
    .await
    .unwrap();
    assert_eq!(
        before, after,
        "read-only accepted state including WAL contents"
    );
    let untouched = Box::pin(fixture.send(read(true))).await;
    assert!(untouched["result"]["structuredContent"]["records"][0]
        .get("node_pending_preview")
        .is_none());
    drop(base);
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_restart_reconstructs_from_durable_journal() {
    let mut fixture = Box::pin(pending_fixture()).await;
    let reply = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&reply)["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let upstream = fixture.node.upstream.clone();
    let local = fixture.node.local.clone();
    let origin = fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .binding
        .origin
        .clone();
    // Stop the fork, destroy both manager and gate, then reopen the journal.
    fixture.node.shutdown_pending_fork().await.unwrap();
    let replacement = Arc::new(
        Failover::new(
            upstream.clone(),
            fixture.supervisor.dispatcher(),
            local,
            origin,
        )
        .unwrap(),
    );
    drop(std::mem::replace(&mut fixture.node, replacement));
    let node = Arc::try_unwrap(fixture.node)
        .ok()
        .unwrap()
        .with_gate(Some(Arc::new(
            WriteGate::open(
                &upstream.config.socket_directory,
                gate::GateConfig {
                    disk_floor_bytes: 0,
                    ..Default::default()
                },
            )
            .unwrap(),
        )));
    fixture.node = Arc::new(node);
    fixture.node.state.lock().await.health = Health::Unreachable;
    Box::pin(assert_pending_visible(&fixture, &id)).await;
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_base_acceptance_removes_preview_without_duplicates() {
    let fixture = Box::pin(pending_fixture()).await;
    let reply = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&reply)["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut second = pending_create();
    second["params"]["arguments"]["arguments"]["idempotency_key"] = json!("pending-proof-second");
    let second_reply = Box::pin(fixture.send(second)).await;
    let second_id = pending_info(&second_reply)["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let gate = fixture.node.gate.as_ref().unwrap();
    let entry = gate.fork_entries(0).unwrap().into_iter().next().unwrap();
    let mut args = entry.arguments.clone().unwrap();
    args["run_key"] = json!(entry.run_key);
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    let receipt = registry
        .call(
            fixture.db.clone(),
            crate::mcp::Caller::local_owner(
                fixture.node.upstream.config.account_id.clone().unwrap(),
            ),
            "create_record",
            args,
        )
        .await
        .unwrap();
    let frame = json!({"result":{"structuredContent":receipt}}).to_string();
    let act = receipt_act(Some(&frame)).expect("canonical receipt act");
    gate.journal
        .finish_held(
            &entry.id,
            super::super::journal::EntryState::Confirmed,
            Some("receipt"),
            "accepted".into(),
            Some(frame),
            false,
            None,
        )
        .unwrap();
    let retained = gate.journal.get(&entry.id).unwrap();
    assert!(
        retained.fork_arguments.is_some(),
        "accepted call lost replay payload: {retained:?}"
    );
    assert_eq!(retained.fork_accepted_act, Some(act));
    assert!(
        act > fixture
            .node
            .dispatcher
            .serving_context()
            .unwrap()
            .serving_head_act
            .unwrap()
    );
    // Still visible during refresh lag even though the sender settled it.
    Box::pin(assert_pending_visible(&fixture, &id)).await;
    let old_db = fixture
        .node
        .dispatcher
        .pending_fork_base()
        .unwrap()
        .db
        .clone();
    let (snapshot, manifest) = stage(&fixture.store, &fixture.db, "accepted-pending-proof").await;
    let installed = fixture
        .store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if fixture
                .supervisor
                .dispatcher()
                .serving_context()
                .is_some_and(|c| {
                    c.serving_generation_id.as_deref() == Some(&installed.id)
                        && c.serving_head_act.is_some_and(|a| a >= act)
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // No client call prompts retirement: background maintenance releases the lease.
    tokio::time::timeout(Duration::from_secs(10), async {
        while !old_db.pool().is_closed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("superseded generation retires without a client request");
    let reply = Box::pin(fixture.send(pending_read(&id))).await;
    let record = &reply["result"]["structuredContent"]["records"][0];
    assert_eq!(record["id"], id, "{reply}");
    assert!(record.get("node_pending_preview").is_none(), "{reply}");
    let search = Box::pin(fixture.send(pending_search())).await;
    let hits = search["result"]["structuredContent"]["hits"]
        .as_array()
        .unwrap();
    assert_eq!(hits.iter().filter(|h| h["id"] == id).count(), 1, "{search}");
    assert!(hits
        .iter()
        .find(|h| h["id"] == id)
        .unwrap()
        .get("node_pending_preview")
        .is_none());
    Box::pin(assert_pending_visible(&fixture, &second_id)).await;
    assert_eq!(
        fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Acquire),
        2,
        "a new generation requires a fresh private copy"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_prepare_never_delays_mutation_reply() {
    let fixture = Box::pin(pending_fixture()).await;
    fixture
        .node
        .pending_fork
        .prepare_delay_ms
        .store(2000, Ordering::Relaxed);
    let reply = tokio::time::timeout(
        Duration::from_secs(1),
        Box::pin(fixture.send(pending_create())),
    )
    .await
    .expect("mutation reply must not await delayed fork preparation");
    let id = pending_info(&reply)["record_id"].as_str().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Relaxed)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let reply = tokio::time::timeout(
        Duration::from_millis(500),
        Box::pin(fixture.send(pending_read(id))),
    )
    .await
    .expect("read falls back during prepare");
    assert!(!reply.to_string().contains("node_pending_preview"));
    Box::pin(assert_pending_visible(&fixture, id)).await;
    fixture.finish().await;
}

async fn assert_preview_failure_preserves_hosted_replay(fixture: &Fixture, held: &Value) {
    let gate = fixture.node.gate.as_ref().unwrap();
    let info = pending_info(held);
    let entry_id = info["journal_entry"].as_str().unwrap();
    let before = gate.journal.get(entry_id).unwrap();
    fixture.fake.status.store(0, Ordering::Release);
    fixture.fake.requests.lock().await.clear();
    assert_eq!(
        gate.drain(&fixture.node.upstream, None, None, None).await,
        super::super::gate::queue::Halt::Empty
    );
    let settled = gate.journal.get(entry_id).unwrap();
    assert_eq!(settled.state, super::super::journal::EntryState::Confirmed);
    assert_eq!(settled.answer.as_deref(), Some("receipt"));
    assert!(
        settled.fork_arguments.is_none(),
        "receipt without an act releases preview payload"
    );
    let requests = fixture.fake.requests.lock().await.clone();
    let creates = create_requests(&requests);
    assert_eq!(creates.len(), 1);
    assert_eq!(
        creates[0].pointer("/params/arguments/arguments"),
        before.arguments.as_ref()
    );
    assert_eq!(
        gate.drain(&fixture.node.upstream, None, None, None).await,
        super::super::gate::queue::Halt::Empty
    );
    let requests = fixture.fake.requests.lock().await.clone();
    assert_eq!(
        create_requests(&requests).len(),
        1,
        "settled entry is not sent twice"
    );
}

#[tokio::test]
async fn pending_fork_failure_backs_off_and_preserves_custody() {
    let fixture = Box::pin(pending_fixture()).await;
    fixture
        .node
        .pending_fork
        .fail_prepare
        .store(true, Ordering::Relaxed);
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Relaxed)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for _ in 0..5 {
        let read = Box::pin(fixture.send(pending_read(id))).await;
        assert!(!read.to_string().contains("node_pending_preview"));
    }
    assert_eq!(
        fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Relaxed),
        1
    );
    let entries = fixture.node.gate.as_ref().unwrap().fork_entries(0).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].state, super::super::journal::EntryState::Pending);
    assert!(entries[0].arguments.is_some());
    Box::pin(assert_preview_failure_preserves_hosted_replay(
        &fixture, &held,
    ))
    .await;
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_insufficient_headroom_preserves_hold_and_normal_reads() {
    let fixture = Box::pin(pending_fixture()).await;
    let gate = fixture.node.gate.as_ref().unwrap();
    // Gate floor is zero in this fixture: enough for the hold, not a fork.
    *gate.free_override.lock().unwrap() = Some(1);
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Relaxed),
        0
    );
    assert!(!fixture
        .node
        .upstream
        .config
        .socket_directory
        .join("hosted-outbox/forks")
        .exists());
    let read = Box::pin(fixture.send(pending_read(id))).await;
    assert!(!read.to_string().contains("node_pending_preview"));
    assert_eq!(gate.fork_entries(0).unwrap().len(), 1);
    Box::pin(assert_preview_failure_preserves_hosted_replay(
        &fixture, &held,
    ))
    .await;
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_online_search_keeps_hosted_first_routing() {
    let fixture = Box::pin(pending_fixture()).await;
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    fixture.fake.status.store(0, Ordering::Release);
    fixture.node.probe().await;
    let search = Box::pin(fixture.send(pending_search())).await;
    assert!(text(&search).contains("hosted answer"), "{search}");
    let record = Box::pin(fixture.send(pending_read(id))).await;
    assert_eq!(
        record["result"]["structuredContent"]["records"][0]["node_pending_preview"]["state"],
        "pending"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_disabled_creates_no_area_or_journal_fields() {
    let fixture = Box::pin(Fixture::new()).await;
    Box::pin(online_ready(&fixture)).await;
    let hosted = Box::pin(fixture.send(pending_search())).await;
    assert!(text(&hosted).contains("hosted answer"));
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    let held = Box::pin(fixture.send(pending_create())).await;
    pending_info(&held);
    let gate = fixture.node.gate.as_ref().unwrap();
    for entry in gate.fork_entries(0).unwrap() {
        let encoded = serde_json::to_value(entry).unwrap();
        assert!(encoded.get("fork_arguments").is_none());
        assert!(encoded.get("fork_run_key").is_none());
        assert!(encoded.get("fork_accepted_act").is_none());
    }
    assert!(!fixture
        .node
        .upstream
        .config
        .socket_directory
        .join("hosted-outbox/forks")
        .exists());
    let local = Box::pin(fixture.send(read(true))).await;
    assert!(!local.to_string().contains("node_pending_preview"));
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_bad_entry_does_not_hide_other_previews() {
    let fixture = Box::pin(pending_fixture()).await;
    let mut bad = pending_create();
    bad["params"]["arguments"]["run_key"] = json!("missing-agent-x12345");
    bad["params"]["arguments"]["arguments"]["idempotency_key"] = json!("bad-preview-run");
    let bad_reply = Box::pin(fixture.send(bad)).await;
    pending_info(&bad_reply);
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    assert_eq!(
        fixture
            .node
            .gate
            .as_ref()
            .unwrap()
            .fork_entries(0)
            .unwrap()
            .len(),
        2,
        "preview exclusion must not lose durable custody"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_disk_floor_discards_preview_before_another_client_call() {
    let fixture = Box::pin(pending_fixture()).await;
    let gate = fixture.node.gate.as_ref().unwrap();
    let root = fixture._dir.path().join("floor-copy");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("copy.sqlite"), vec![0; 1024]).unwrap();
    gate.set_copy_root(root);
    *gate.free_override.lock().unwrap() = Some(2 * 1024 * 1024 * 1024);
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    let area = fixture
        .node
        .upstream
        .config
        .socket_directory
        .join("hosted-outbox/forks");
    assert!(fs::read_dir(&area).unwrap().next().is_some());
    *gate.free_override.lock().unwrap() = Some(1);
    tokio::time::timeout(Duration::from_secs(5), async {
        while fs::read_dir(&area).unwrap().next().is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("maintenance discards preview after floor breach");
    // Space enough for a hold, but not another speculative copy.
    *gate.free_override.lock().unwrap() = Some(2049);
    let mut second = pending_create();
    second["params"]["arguments"]["arguments"]["idempotency_key"] = json!("disk-priority-second");
    let reply = Box::pin(fixture.send(second)).await;
    pending_info(&reply);
    assert_eq!(gate.fork_entries(0).unwrap().len(), 2);
    fixture.finish().await;
}

#[tokio::test]
async fn app_attributed_touched_records_never_use_pending_previews() {
    let mut fixture = Box::pin(pending_fixture()).await;
    enable_app_transport(&mut fixture).await;
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    let request = app_call(pending_read(id));
    let before = fixture.fake.requests.lock().await.len();
    let reply = Box::pin(fixture.send(request.clone())).await;
    assert_eq!(
        reply,
        json!({"jsonrpc":"2.0", "id":request["id"], "error":{
            "code":-32000,
            "message":"Hosted is unreachable; online app request was not sent",
            "data":{"outcome":"not_sent", "reason":"app_online_required"}
        }})
    );
    assert_eq!(fixture.fake.requests.lock().await.len(), before);
    assert!(!reply.to_string().contains("node_pending_preview"));

    // Explicit-local app routing follows main and cannot select the fork.
    let mut local = request.clone();
    local["params"]["_meta"]["native/route"] = json!("local");
    let reply = Box::pin(fixture.send(local)).await;
    assert!(
        !reply.to_string().contains("node_pending_preview"),
        "{reply}"
    );

    // On recovery a touched record cannot bypass connection proof validation.
    fixture.fake.status.store(0, Ordering::Release);
    Box::pin(fixture.node.probe()).await;
    let reply = Box::pin(fixture.send(request)).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(!reply.to_string().contains("node_pending_preview"));
    fixture.finish().await;
}

async fn enable_pending_read_barrier(fixture: &mut Fixture) {
    enable_app_transport(fixture).await;
    let node = Arc::get_mut(&mut fixture.node).unwrap();
    let mut config = node.upstream.config.clone();
    config.online_local_reads = Some(OnlineLocalReads {
        max_age_seconds: BOUND,
    });
    node.upstream = Arc::new(Upstream::new(config, Duration::from_secs(5)).unwrap());
}

#[tokio::test]
async fn pending_fork_read_barrier_withholds_previews_until_accepted_base_catches_up() {
    let mut fixture = Box::pin(pending_fixture()).await;
    Box::pin(enable_pending_read_barrier(&mut fixture)).await;
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    let base_act = fixture
        .node
        .dispatcher
        .serving_context()
        .unwrap()
        .serving_head_act;
    let unresolved = fixture.node.state.lock().await.persisted.floor.unresolved;

    fixture.node.state.lock().await.persistence_failed = true;
    let denied = Box::pin(fixture.send(pending_read(id))).await;
    assert!(!denied.to_string().contains("node_pending_preview"));
    fixture.node.state.lock().await.persistence_failed = false;

    crate::store::update_record(&fixture.db, RECORD, json!({"name":"barrier-write"}))
        .await
        .unwrap();
    fixture.fake.status.store(0, Ordering::Release);
    let mut socket = ChangesSocket::new(&fixture, true);
    socket.send(read_barrier(1000)).await;
    let capture = socket.receive().await;
    let act = capture["result"]["head_act"]
        .as_i64()
        .expect("ordered capture");
    assert!(Some(act) > base_act, "{capture}");
    assert_eq!(
        capture["result"]["admission"],
        json!({"floor_persisted":true,"read_ready":false})
    );
    assert_eq!(
        fixture
            .node
            .dispatcher
            .serving_context()
            .unwrap()
            .serving_head_act,
        base_act
    );
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.unresolved,
        unresolved
    );
    let mut local = pending_read(id);
    local["params"]["_meta"]["native/route"] = json!("local");
    for request in [pending_read(id), pending_search(), local] {
        let reply = Box::pin(fixture.send(request)).await;
        assert!(
            !reply.to_string().contains("node_pending_preview"),
            "{reply}"
        );
    }
    let (snapshot, manifest) =
        stage(&fixture.store, &fixture.db, "barrier-preview-caught-up").await;
    fixture
        .store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    assert_eq!(
        fixture.node.state.lock().await.persisted.floor.unresolved,
        unresolved
    );
    drop(socket);
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_rechecks_an_ordered_barrier_captured_during_preview() {
    let mut fixture = Box::pin(pending_fixture()).await;
    Box::pin(enable_pending_read_barrier(&mut fixture)).await;
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    *fixture.node.pending_fork.pause_preview.lock().unwrap() =
        Some((entered.clone(), resume.clone()));
    let captured = AtomicBool::new(false);
    let mut socket = ChangesSocket::new(&fixture, true);
    let reading = async {
        loop {
            let reply = Box::pin(fixture.send(pending_read(id))).await;
            if captured.load(Ordering::Acquire) {
                break reply;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let barrier = async {
        entered.notified().await;
        crate::store::update_record(&fixture.db, RECORD, json!({"name":"barrier-races-preview"}))
            .await
            .unwrap();
        fixture.fake.status.store(0, Ordering::Release);
        socket.send(read_barrier(1001)).await;
        let reply = socket.receive().await;
        assert!(
            reply["result"]["head_act"].as_i64().unwrap()
                > fixture
                    .node
                    .dispatcher
                    .serving_context()
                    .unwrap()
                    .serving_head_act
                    .unwrap()
        );
        captured.store(true, Ordering::Release);
        resume.notify_one();
    };
    let (reply, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(reading, barrier)
    })
    .await
    .expect("read and ordered capture finish");
    assert!(
        !reply.to_string().contains("node_pending_preview"),
        "{reply}"
    );
    assert_eq!(
        reply["result"]["structuredContent"]["records"][0]["status"],
        "not_found"
    );
    drop(socket);
    fixture.finish().await;
}

#[tokio::test]
async fn pending_fork_withholds_same_record_create_while_typed_merge_is_open() {
    let fixture = Box::pin(pending_fixture()).await;
    let held = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&held)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    let mut merge = pending_create();
    merge["params"]["arguments"]["operation"] = json!("merge_body");
    merge["params"]["arguments"]["arguments"] = json!({"record_id":id,
        "base_version":"rec:1", "base_text":"quartzpendingproof body",
        "my_text":"later typed edit", "reason":"same record ordering",
        "idempotency_key":"pending-proof-typed-merge"});
    merge["params"]["_meta"] = json!({"native/body_merge":{"wait":"none","editor":"proof"}});
    let saved = Box::pin(fixture.send(merge)).await;
    assert_eq!(
        saved["result"]["structuredContent"]["outcome"], "saved_on_device",
        "{saved}"
    );
    let gate = fixture.node.gate.as_ref().unwrap();
    let entry = gate
        .journal
        .merge_with_key("pending-proof-typed-merge")
        .unwrap();
    assert!(entry.fork_arguments.is_none());
    assert!(entry.fork_run_key.is_none());
    assert!(entry.fork_accepted_act.is_none());
    for state in [
        super::super::journal::EntryState::Pending,
        super::super::journal::EntryState::CommittedUnrecovered,
        super::super::journal::EntryState::ResultUnrecovered,
    ] {
        gate.journal.update(&entry.id, |e| e.state = state).unwrap();
        for request in [pending_read(id), pending_search()] {
            let reply = Box::pin(fixture.send(request)).await;
            assert!(
                !reply.to_string().contains("node_pending_preview"),
                "{reply}"
            );
        }
    }
    gate.journal
        .update(&entry.id, |e| {
            e.state = super::super::journal::EntryState::NotSent;
        })
        .unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    fixture.finish().await;
}

fn pending_controller(fixture: &Fixture) -> crate::standby::StandbyRefreshController {
    let config = crate::standby::StandbyRefreshConfig::from_json(
        &fs::read(fixture._dir.path().join("refresh.json")).unwrap(),
    )
    .unwrap();
    let mut controller = crate::standby::StandbyRefreshController::new(
        fixture.runtime.clone(),
        config,
        fixture.store.clone(),
        observed(),
    )
    .unwrap();
    let hints = crate::standby::RefreshHints::default();
    fixture.node.pending_fork.observe(&hints);
    controller.set_pending_observer_for_test(hints);
    controller
}
async fn pending_refresh(fixture: &Fixture, controller: &crate::standby::StandbyRefreshController) {
    fixture.fake.status.store(0, Ordering::Release);
    fixture.fake.delta_mode.store(1, Ordering::Release);
    let result = Box::pin(controller.refresh_once(RefreshCause::Scheduled))
        .await
        .unwrap();
    fixture.fake.status.store(502, Ordering::Release);
    assert!(
        matches!(
            result,
            crate::standby::StandbyRefreshOutcome::Advanced { .. }
        ),
        "{result:?}"
    );
}
async fn accepted_append(fixture: &Fixture, suffix: &str) {
    let mut reg = crate::mcp::ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut reg).unwrap();
    reg.call(fixture.db.clone(), crate::mcp::Caller::local_owner(fixture.node.upstream.config.account_id.clone().unwrap()),
        "update_record", json!({"id":RECORD,"body_append":suffix,"reason":"accepted delta","run_key":"scout-chair-j748b2"}))
        .await.unwrap();
}
fn pause_pending() -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
    (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    )
}
#[tokio::test]
async fn pending_fork_handoff_returns_while_owner_stalled_and_rebases_without_copy() {
    let fixture = Box::pin(pending_fixture()).await;
    let controller = pending_controller(&fixture);
    let reply = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&reply)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    let pause = pause_pending();
    *fixture.node.pending_fork.pause_rebase.lock().unwrap() = Some(pause.clone());
    accepted_append(&fixture, "accepted-slow-owner").await;
    // The paused owner never releases until AFTER refresh returns. An inline
    // callback fails this deadline; accepted publication must be independent.
    tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(pending_refresh(&fixture, &controller)),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pause.0.notified())
        .await
        .unwrap();
    let accepted = Box::pin(fixture.send(read(true))).await;
    assert!(
        text(&accepted).contains("accepted-slow-owner"),
        "{accepted}"
    );
    let pending = Box::pin(fixture.send(pending_read(id))).await;
    assert!(
        !pending.to_string().contains("node_pending_preview"),
        "{pending}"
    );
    pause.1.notify_one();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    assert_eq!(
        fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(
        fixture.node.pending_fork.copy_count_for_test().await,
        1,
        "successful handoffs must not invoke the database copy path"
    );
    fixture.finish().await;
}
#[tokio::test]
async fn pending_fork_delta_mid_replay_is_applied_once_without_copy() {
    let fixture = Box::pin(pending_fixture()).await;
    let controller = pending_controller(&fixture);
    let reply = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&reply)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    let mut append = pending_create();
    append["params"]["arguments"]["operation"] = json!("update_record");
    append["params"]["arguments"]["arguments"] = json!({"id":RECORD,
        "body_append":" quartzpendingproof pending-tail","reason":"pending append",
        "idempotency_key":"pending-proof-append"});
    let held = Box::pin(fixture.send(append)).await;
    let _ = pending_info(&held);
    Box::pin(assert_pending_visible(&fixture, RECORD)).await;
    let pause = pause_pending();
    *fixture.node.pending_fork.pause_replay.lock().unwrap() = Some(pause.clone());
    accepted_append(&fixture, "accepted-one").await;
    Box::pin(pending_refresh(&fixture, &controller)).await;
    tokio::time::timeout(Duration::from_secs(10), pause.0.notified())
        .await
        .unwrap();
    let area = fixture
        .node
        .upstream
        .config
        .socket_directory
        .join("hosted-outbox/forks");
    let markers: Vec<_> = fs::read_dir(area)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("rebase-in-progress"))
        .filter(|path| path.exists())
        .collect();
    assert_eq!(markers.len(), 1, "marker must cover paused replay");
    let marker_text = fs::read_to_string(&markers[0]).unwrap();
    let marker: Value = serde_json::from_str(&marker_text).unwrap();
    assert_eq!(
        marker["journal_revision"]["entries"], 2,
        "first rebase binds its actual journal"
    );
    assert_eq!(
        marker["journal_revision"]["sha256"].as_str().unwrap().len(),
        64
    );
    assert!(
        !marker_text.contains("pending-tail"),
        "marker must not persist note bodies"
    );
    accepted_append(&fixture, " accepted-two").await;
    tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(pending_refresh(&fixture, &controller)),
    )
    .await
    .unwrap();
    pause.1.notify_one();
    // The background owner can take its lock again after readiness. Assert
    // against the successful pending snapshots, not a fresh read that may
    // legitimately fall back to accepted state while that owner is busy.
    let (_, result) = Box::pin(assert_pending_visible(&fixture, id)).await;
    assert_eq!(
        fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Acquire),
        1
    );
    let (reply, _) = Box::pin(assert_pending_visible(&fixture, RECORD)).await;
    assert_eq!(
        reply["result"]["structuredContent"]["records"][0]["body"],
        "accepted-one accepted-two quartzpendingproof pending-tail",
        "{reply}"
    );
    // A speculative create survives both deltas without duplication.
    assert_eq!(
        result["result"]["structuredContent"]["hits"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|h| h["id"] == id)
            .count(),
        1
    );
    assert_eq!(
        fixture.node.pending_fork.copy_count_for_test().await,
        1,
        "successful handoffs must not invoke the database copy path"
    );
    fixture.finish().await;
}
#[tokio::test]
async fn pending_fork_rebase_panic_isolated_from_refresh_and_rebuilds() {
    let fixture = Box::pin(pending_fixture()).await;
    let controller = pending_controller(&fixture);
    let reply = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&reply)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    fixture
        .node
        .pending_fork
        .panic_rebase
        .store(true, Ordering::Release);
    accepted_append(&fixture, "accepted-before-panic").await;
    Box::pin(pending_refresh(&fixture, &controller)).await;
    Box::pin(assert_pending_visible(&fixture, id)).await;
    assert_eq!(
        fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Acquire),
        2
    );
    assert!(text(&Box::pin(fixture.send(read(true))).await).contains("accepted-before-panic"));
    fixture.finish().await;
}
#[tokio::test]
async fn pending_fork_head_mismatch_rebuilds_after_real_handoff() {
    let fixture = Box::pin(pending_fixture()).await;
    let controller = pending_controller(&fixture);
    let reply = Box::pin(fixture.send(pending_create())).await;
    let id = pending_info(&reply)["record_id"].as_str().unwrap();
    Box::pin(assert_pending_visible(&fixture, id)).await;
    fixture.node.pending_fork.mismatch_head_for_test().await;
    accepted_append(&fixture, "accepted-mismatch").await;
    Box::pin(pending_refresh(&fixture, &controller)).await;
    Box::pin(assert_pending_visible(&fixture, id)).await;
    assert_eq!(
        fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Acquire),
        2
    );
    fixture.finish().await;
}
#[tokio::test]
async fn pending_fork_enable_failure_cleans_copy_and_caches_unsupported_schema() {
    let fixture = Box::pin(pending_fixture()).await;
    fixture
        .node
        .pending_fork
        .fail_enable
        .store(true, Ordering::Release);
    let reply = Box::pin(fixture.send(pending_create())).await;
    let _ = pending_info(&reply);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if fixture.node.pending_fork.unsupported_for_test().await {
                // Wait for the installed failure and a complete retry window.
                tokio::time::sleep(Duration::from_secs(2)).await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fixture
            .node
            .pending_fork
            .prepare_attempts
            .load(Ordering::Acquire),
        1
    );
    let area = fixture
        .node
        .upstream
        .config
        .socket_directory
        .join("hosted-outbox/forks");
    for entry in fs::read_dir(area).unwrap() {
        assert!(
            !entry.unwrap().file_type().unwrap().is_dir(),
            "failed enable leaked its private copy"
        );
    }
    fixture.finish().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_local_catalogue_follows_startup_and_preserves_digest_refusal() {
    let fixture = Box::pin(Fixture::build_with_engine(
        Some(true),
        None,
        false,
        None,
        false,
        true,
    ))
    .await;
    fixture.node.refresh_discovery().await;
    tokio::time::timeout(Duration::from_secs(30), async {
        while !fixture.node.dispatcher.serving_kernel_v2() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("v2 cold recovery must publish an authorised reader");
    let mut request = read(true);
    request["params"]["arguments"]["arguments"]["ids"] = json!([crate::events::KERNEL_ROOT_ID]);
    let request = local_only(request);
    fixture.fake.requests.lock().await.clear();
    let reply = Box::pin(fixture.send(request.clone())).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["records"][0]["id"],
        crate::events::KERNEL_ROOT_ID,
        "{reply}"
    );
    assert!(
        reply["result"]["structuredContent"]["standby_context"]["serving_generation_id"]
            .is_string(),
        "{reply}"
    );
    assert!(
        fixture.fake.requests.lock().await.is_empty(),
        "explicit local read must not forward"
    );
    let rows = fixture.node.dispatcher.local_dispatcher().unwrap();
    let row = rows
        .operation_rows()
        .iter()
        .find(|r| r["executor"] == "records_read" && r["operation"] == "get_record")
        .unwrap();
    // The serving executor independently builds its contracts from the engine.
    // This catches a row helper accidentally reverting to the SQLite catalogue.
    let described = fixture
        .node
        .dispatcher
        .handle_message(json!({
            "jsonrpc":"2.0", "id":91, "method":"tools/call",
            "params":{"name":"describe_operation", "arguments":{
                "executor":"records_read", "operation":"get_record"
            }}
        }))
        .await
        .unwrap();
    assert_eq!(described["result"]["isError"], false, "{described}");
    assert!(
        described["result"]["structuredContent"]["contract_digest"].is_string(),
        "{described}"
    );
    assert_eq!(
        row["contract_digest"],
        described["result"]["structuredContent"]["contract_digest"]
    );
    assert_eq!(
        row["contract_digest"],
        fixture
            .fake
            .operations
            .iter()
            .find(|r| r["executor"] == "records_read" && r["operation"] == "get_record")
            .unwrap()["contract_digest"]
    );
    {
        let mut state = fixture.node.state.lock().await;
        let discovery = state
            .persisted
            .discovery
            .get_mut(crate::mcp::PROTOCOL_VERSION)
            .unwrap();
        let row = discovery
            .operations
            .iter_mut()
            .find(|r| r["executor"] == "records_read" && r["operation"] == "get_record")
            .unwrap();
        row["contract_digest"] = json!("different-contract");
    }
    let reply = Box::pin(fixture.send(request)).await;
    assert!(reply.to_string().contains("unavailable_offline"), "{reply}");
    assert!(fixture.fake.requests.lock().await.is_empty());
    drop(rows);
    fixture.finish().await;
}

#[test]
fn revision_reporting_distinguishes_known_lag_from_unavailable_current_comparison() {
    for (health, known, comparable, expected, lag) in [
        (
            Health::Reachable,
            Some(40),
            true,
            "matches_latest_known",
            Some(0),
        ),
        (
            Health::Reachable,
            Some(43),
            true,
            "behind_latest_known",
            Some(3),
        ),
        (
            Health::Unreachable,
            Some(40),
            true,
            "matches_latest_known",
            Some(0),
        ),
        (Health::Unreachable, None, true, "unknown", None),
        (Health::Reachable, Some(40), false, "unknown", None),
    ] {
        let context = json!({"freshness":{"age_seconds":900,"target_rpo_seconds":300}});
        let mut response = json!({"result":{"structuredContent":{},"content":[]}});
        let standing = Standing {
            serving_head_act: Some(40),
            known_hosted_head_act: known,
            behind_known_write: comparable.then_some(known.is_some_and(|h| h > 40)),
            last_successful_hosted_check_at: Some("2026-11-16T12:00:00Z".into()),
            ..Default::default()
        };
        annotate_node_routing_with(
            &mut response,
            health,
            true,
            "local_copy",
            Some(&standing),
            false,
            Some(&context),
            true,
        );
        let comparison =
            &response["result"]["structuredContent"]["node_routing"]["revision_comparison"];
        assert_eq!(comparison["state"], expected);
        assert_eq!(comparison["known_lag_acts"], json!(lag));
        assert_eq!(comparison["current_lag_known"], false);
        assert!(comparison["time_lag_seconds"].is_null());
        let prose = text(&response);
        assert!(!prose.contains("This copy is stale"), "{prose}");
        assert_eq!(
            prose.contains("Current hosted comparison is unavailable"),
            health == Health::Unreachable,
            "{prose}"
        );
    }
}

#[test]
fn bootstrap_disclosures_keep_conditional_uncertainty_and_full_diagnostics() {
    for (age, health, behind, degraded) in [
        (Some(12), Health::Reachable, false, false),
        (Some(401), Health::Unreachable, true, false),
        (None, Health::AuthRefused, false, true),
    ] {
        let context = json!({"freshness":{"age_seconds":age,"target_rpo_seconds":300},
            "degraded_reasons":if degraded {json!(["refresh_paused"])} else {json!([])}});
        let payload = json!({"run":{"run_key":"fixture-key"},"standby_context":context});
        let mut reply = json!({"result":{"structuredContent":payload,
            "content":[{"type":"text","text":payload.to_string()}]}});
        let standing = Standing {
            behind_known_write: Some(behind),
            serving_head_act: Some(40),
            known_hosted_head_act: Some(if behind { 41 } else { 40 }),
            ..Default::default()
        };
        annotate_node_routing_with(
            &mut reply,
            health,
            true,
            "local_copy",
            Some(&standing),
            false,
            Some(&context),
            true,
        );
        let content = reply["result"]["content"].as_array().unwrap();
        let line = content.last().unwrap()["text"].as_str().unwrap();
        assert_eq!(line.contains("Hosted has newer changes"), behind);
        assert_eq!(
            line.contains("Check age exceeds the refresh target"),
            age.is_some_and(|age| age > 300)
        );
        assert_eq!(line.contains("Copy refresh is degraded"), degraded);
        assert!(!line.contains("prior writes"));
        if age.is_none() {
            assert!(line.contains("matching hosted check age unknown"));
        }
        if health == Health::Unreachable {
            assert!(line.contains("canonical writes are unavailable"));
        }
        if health == Health::AuthRefused {
            assert!(line.contains("re-authenticate"));
        }
        let serialized: Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(serialized, reply["result"]["structuredContent"]);
        assert_eq!(
            serialized["standby_context"]["freshness"]["age_seconds"],
            json!(age)
        );
        assert_eq!(
            serialized["node_routing"]["known_hosted_head_act"],
            if behind { 41 } else { 40 }
        );
    }
}

#[tokio::test]
async fn holding_contract_discovery_is_durable_protocol_and_principal_bound() {
    let fixture = Fixture::new().await;
    let key = crate::mcp::PROTOCOL_VERSION;
    let bound = fixture.node.state.lock().await.persisted.binding.clone();
    *fixture.fake.principal.lock().unwrap() = Some(bound.account.clone());
    fixture.node.verify_account_if_credential_changed().await;
    let mut description = crate::mcp::executor_prototype::NodeOperationContracts::local()
        .unwrap()
        .holding_contract("records_write", "create_record")
        .unwrap()
        .description;
    description["source"]["tool_description"] = json!("Updated hosted source explanation");
    description["contract_digest"] = json!("description-only-hosted-digest");
    fixture
        .fake
        .holding_descriptions
        .lock()
        .unwrap()
        .insert("create_record".into(), description);
    let mut rows = fixture.fake.operations.clone();
    rows.iter_mut()
        .find(|row| row["executor"] == "records_write" && row["operation"] == "create_record")
        .unwrap()["contract_digest"] = json!("description-only-hosted-digest");
    *fixture.fake.catalog_override.lock().unwrap() = Some(rows);
    fixture.node.refresh_catalogue(key, None).await;
    fixture.node.refresh_holding_contracts(key).await;
    let evidence =
        gate::Outage::holding_contract(&*fixture.node, "records_write", "create_record", Some(key))
            .await
            .unwrap();
    assert!(
        crate::mcp::executor_prototype::NodeOperationContracts::local()
            .unwrap()
            .matches_holding_contract("records_write", "create_record", &evidence)
    );
    assert!(gate::Outage::holding_contract(
        &*fixture.node,
        "records_write",
        "create_record",
        Some("uncached-protocol")
    )
    .await
    .is_none());
    // A failed description lookup during maintenance retains coherent
    // last-known evidence; it does not create an age or availability deadline.
    fixture.fake.holding_descriptions.lock().unwrap().clear();
    fixture.node.refresh_catalogue(key, None).await;
    fixture.node.refresh_holding_contracts(key).await;
    assert_eq!(
        gate::Outage::holding_contract(&*fixture.node, "records_write", "create_record", Some(key))
            .await,
        Some(evidence.clone())
    );
    fixture.fake.read_only.store(true, Ordering::Release);
    let reply = fixture.send(write()).await;
    assert_eq!(
        pending_info(&reply)["contract_compatibility"],
        "source_description_only",
        "{reply}"
    );
    assert_eq!(pending_info(&reply)["preview_available"], false);
    let restarted = Failover::new(
        fixture.node.upstream.clone(),
        fixture.supervisor.dispatcher(),
        fixture.node.local.clone(),
        bound.origin.clone(),
    )
    .unwrap();
    restarted.state.lock().await.health = Health::Unreachable;
    assert_eq!(
        gate::Outage::holding_contract(&restarted, "records_write", "create_record", Some(key))
            .await,
        Some(evidence.clone())
    );
    // No age deadline is introduced: last-known, principal-bound evidence is
    // still custody evidence during an outage, and canonical replay rechecks.
    let token_path = &fixture.node.upstream.config.credential_file;
    let token = fs::read(token_path).unwrap();
    fs::write(token_path, "different-token").unwrap();
    assert!(gate::Outage::holding_contract(
        &restarted,
        "records_write",
        "create_record",
        Some(key)
    )
    .await
    .is_none());
    fs::write(token_path, token).unwrap();
    assert_eq!(
        gate::Outage::holding_contract(&restarted, "records_write", "create_record", Some(key))
            .await,
        Some(evidence)
    );
    {
        let mut state = restarted.state.lock().await;
        state.persisted.account_mismatch = true;
        restarted.persist(&mut state);
    }
    let mismatched = Failover::new(
        fixture.node.upstream.clone(),
        fixture.supervisor.dispatcher(),
        fixture.node.local.clone(),
        bound.origin.clone(),
    )
    .unwrap();
    assert!(gate::Outage::holding_contract(
        &mismatched,
        "records_write",
        "create_record",
        Some(key)
    )
    .await
    .is_none());
    for changed in ["account", "endpoint"] {
        let mut other = bound.clone();
        if changed == "account" {
            other.account = "different-account".into();
        } else {
            other.endpoint.push_str("/different-endpoint");
        }
        let (_, recovered) =
            StateFile::open(&fixture.node.upstream.config.socket_directory, other).unwrap();
        assert!(recovered.discovery.is_empty(), "{changed}");
    }
    fixture.finish().await;
}

#[tokio::test]
async fn holding_contract_discovery_requires_complete_coherent_authenticated_evidence() {
    let fixture = Fixture::new().await;
    let key = crate::mcp::PROTOCOL_VERSION;
    // An authenticated request alone does not establish which bound account
    // the bearer belongs to. Missing principal confirmation creates no evidence.
    let description = crate::mcp::executor_prototype::NodeOperationContracts::local()
        .unwrap()
        .holding_contract("records_write", "create_record")
        .unwrap()
        .description;
    fixture
        .fake
        .holding_descriptions
        .lock()
        .unwrap()
        .insert("create_record".into(), description.clone());
    fixture.node.refresh_catalogue(key, None).await;
    fixture.node.refresh_holding_contracts(key).await;
    assert!(gate::Outage::holding_contract(
        &*fixture.node,
        "records_write",
        "create_record",
        Some(key)
    )
    .await
    .is_none());
    let account = fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .binding
        .account
        .clone();
    *fixture.fake.principal.lock().unwrap() = Some(account);
    fixture.node.verify_account_if_credential_changed().await;
    for malformed in [true, false] {
        let mut changed = description.clone();
        if malformed {
            changed.as_object_mut().unwrap().remove("input_schema");
        } else {
            changed["contract_digest"] = json!("does-not-match-catalog");
        }
        fixture
            .fake
            .holding_descriptions
            .lock()
            .unwrap()
            .insert("create_record".into(), changed);
        fixture.node.refresh_catalogue(key, None).await;
        fixture.node.refresh_holding_contracts(key).await;
        assert!(gate::Outage::holding_contract(
            &*fixture.node,
            "records_write",
            "create_record",
            Some(key)
        )
        .await
        .is_none());
    }
    fixture.finish().await;
}

#[tokio::test]
async fn holding_contract_stalled_descriptions_do_not_delay_tools_list() {
    let fixture = Fixture::new().await;
    let account = fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .binding
        .account
        .clone();
    *fixture.fake.principal.lock().unwrap() = Some(account);
    fixture.node.verify_account_if_credential_changed().await;
    fixture
        .fake
        .holding_describe_stall
        .store(true, Ordering::Release);
    let response = tokio::time::timeout(Duration::from_secs(2), fixture.send(list()))
        .await
        .expect("tools/list must not await description acquisition");
    assert!(response["result"]["tools"].is_array(), "{response}");
    assert!(!fixture
        .fake
        .requests
        .lock()
        .await
        .iter()
        .any(|request| target(request)
            .is_some_and(|(executor, _, _)| executor == "describe_operation")));
    // Concurrent monitor refreshes skip the held turn instead of accumulating.
    let turn = fixture.node.holding_refresh.lock().await;
    tokio::time::timeout(
        Duration::from_millis(100),
        fixture
            .node
            .refresh_holding_contracts(crate::mcp::PROTOCOL_VERSION),
    )
    .await
    .unwrap();
    drop(turn);
    fixture.finish().await;
}

#[tokio::test]
async fn holding_contract_background_refresh_publishes_partial_progress() {
    let fixture = Fixture::new().await;
    let key = crate::mcp::PROTOCOL_VERSION;
    let account = fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .binding
        .account
        .clone();
    *fixture.fake.principal.lock().unwrap() = Some(account);
    fixture.node.verify_account_if_credential_changed().await;
    let description = crate::mcp::executor_prototype::NodeOperationContracts::local()
        .unwrap()
        .holding_contract("records_write", "create_record")
        .unwrap()
        .description;
    fixture
        .fake
        .holding_descriptions
        .lock()
        .unwrap()
        .insert("create_record".into(), description);
    *fixture
        .fake
        .holding_describe_stall_operation
        .lock()
        .unwrap() = Some("create_many".into());
    fixture.node.refresh_catalogue(key, None).await;
    tokio::time::timeout(
        Duration::from_secs(3),
        fixture.node.refresh_holding_contracts(key),
    )
    .await
    .unwrap();
    assert!(gate::Outage::holding_contract(
        &*fixture.node,
        "records_write",
        "create_record",
        Some(key)
    )
    .await
    .is_some());
    assert!(gate::Outage::holding_contract(
        &*fixture.node,
        "records_write",
        "create_many",
        Some(key)
    )
    .await
    .is_none());
    fixture.finish().await;
}

#[tokio::test]
async fn holding_contract_background_refresh_repairs_catalog_witness_without_client_discovery() {
    let fixture = Fixture::new().await;
    let key = crate::mcp::PROTOCOL_VERSION;
    // Simulate an older/inconclusive discovery cache whose rows are complete
    // but whose authenticated catalog witness needs repair after login settles.
    fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .discovery
        .entry(key.into())
        .or_default()
        .operations = fixture.fake.operations.clone();
    let account = fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .binding
        .account
        .clone();
    *fixture.fake.principal.lock().unwrap() = Some(account);
    fixture.node.verify_account_if_credential_changed().await;
    let description = crate::mcp::executor_prototype::NodeOperationContracts::local()
        .unwrap()
        .holding_contract("records_write", "create_record")
        .unwrap()
        .description;
    fixture
        .fake
        .holding_descriptions
        .lock()
        .unwrap()
        .insert("create_record".into(), description);
    for witness in [None, Some([0; 32])] {
        {
            let mut state = fixture.node.state.lock().await;
            let discovery = state.persisted.discovery.get_mut(key).unwrap();
            discovery.holding_catalog_credential = witness;
            discovery.holding_contracts.clear();
        }
        fixture.node.refresh_holding_contracts(key).await;
        assert!(gate::Outage::holding_contract(
            &*fixture.node,
            "records_write",
            "create_record",
            Some(key)
        )
        .await
        .is_some());
        assert_eq!(
            fixture.node.state.lock().await.persisted.discovery[key].holding_catalog_credential,
            fixture.node.credential_digest()
        );
    }
    assert!(!fixture
        .fake
        .requests
        .lock()
        .await
        .iter()
        .any(|request| request["method"] == "tools/list"));
    fixture.finish().await;
}

#[tokio::test]
async fn connection_binding_uses_admitted_owner_and_refuses_after_account_mismatch() {
    let fixture = Fixture::new().await;
    online_ready(&fixture).await;
    let scope = fixture
        .node
        .connection_scope()
        .await
        .expect("admitted fixture owner");
    assert_eq!(
        Some(scope.account_id.as_str()),
        fixture.node.upstream.config.account_id.as_deref()
    );
    assert_eq!(scope.database_id, fixture.node.upstream.config.db_id);
    let mut socket = ChangesSocket::new(&fixture, true);
    let request =
        json!({"jsonrpc":"2.0","id":790,"method":"native/connection/bind","params":scope});
    socket.send(request.clone()).await;
    assert_eq!(socket.receive().await["result"]["binding"], json!(scope));
    assert!(
        fixture
            .fake
            .requests
            .lock()
            .await
            .iter()
            .all(|request| !super::super::connection_binding::is_control(request)),
        "binding control never reaches hosted"
    );
    // Refusing a first bind ends that socket, even if the client pipelines MCP after it.
    let mut refused_socket = ChangesSocket::new(&fixture, true);
    let mut wrong_scope = scope.clone();
    wrong_scope.account_id = "acct_other".into();
    let wrong =
        json!({"jsonrpc":"2.0","id":791,"method":"native/connection/bind","params":wrong_scope});
    refused_socket
        .writer
        .write_all(format!("{wrong}\n{}\n", read(true)).as_bytes())
        .await
        .unwrap();
    assert_eq!(
        refused_socket.receive().await["error"]["data"]["reason"],
        "connection_binding_refused"
    );
    let mut extra = String::new();
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(2),
            refused_socket.reader.read_line(&mut extra)
        )
        .await
        .unwrap()
        .unwrap(),
        0
    );
    assert_eq!(
        forwarded_reads(&fixture).await,
        0,
        "pipelined read after refused bind must not forward"
    );
    drop(refused_socket);
    // The existing account verdict invalidates the pin before the next MCP request.
    fixture.node.state.lock().await.persisted.account_mismatch = true;
    assert!(fixture.node.connection_scope().await.is_none());
    socket.send(read(true)).await;
    let refused = socket.receive().await;
    assert_eq!(
        refused["error"]["data"]["reason"],
        "connection_binding_refused"
    );
    assert_eq!(forwarded_reads(&fixture).await, 0);
    drop(socket);
    let mut unavailable = ChangesSocket::new(&fixture, false);
    unavailable.send(request).await;
    assert_eq!(
        unavailable.receive().await["error"]["data"]["reason"],
        "connection_binding_refused"
    );
    drop(unavailable);
    fixture.finish().await;
}

#[tokio::test]
async fn holding_contract_absence_requires_authenticated_complete_catalogue() {
    let fixture = Fixture::new().await;
    let key = crate::mcp::PROTOCOL_VERSION;
    assert!(
        !gate::Outage::holding_operation_absent(
            &*fixture.node,
            "records_write",
            "removed_operation",
            None
        )
        .await
    );
    let account = fixture
        .node
        .state
        .lock()
        .await
        .persisted
        .binding
        .account
        .clone();
    *fixture.fake.principal.lock().unwrap() = Some(account);
    fixture.node.verify_account_if_credential_changed().await;
    // Fetch an actual complete catalogue with a present operation and an absent one.
    fixture.node.refresh_catalogue(key, None).await;
    assert!(
        gate::Outage::holding_operation_absent(
            &*fixture.node,
            "records_write",
            "removed_operation",
            None
        )
        .await
    );
    assert!(
        !gate::Outage::holding_operation_absent(
            &*fixture.node,
            "records_write",
            "create_record",
            None
        )
        .await
    );
    assert!(
        !gate::Outage::holding_operation_absent(
            &*fixture.node,
            "records_write",
            "removed_operation",
            Some("uncached-protocol")
        )
        .await
    );
    for witness in [None, Some([0; 32])] {
        fixture
            .node
            .state
            .lock()
            .await
            .persisted
            .discovery
            .get_mut(key)
            .unwrap()
            .holding_catalog_credential = witness;
        assert!(
            !gate::Outage::holding_operation_absent(
                &*fixture.node,
                "records_write",
                "removed_operation",
                None
            )
            .await
        );
    }
    // A complete empty catalogue also proves absence, but only while authenticated.
    *fixture.fake.catalog_override.lock().unwrap() = Some(Vec::new());
    fixture.node.refresh_catalogue(key, None).await;
    assert!(
        gate::Outage::holding_operation_absent(
            &*fixture.node,
            "records_write",
            "create_record",
            None
        )
        .await
    );
    // Restart may clear the live account check; the same verified custody
    // credential keeps authenticated absence usable without a freshness wait.
    {
        let mut state = fixture.node.state.lock().await;
        state.account_check = None;
        state.persisted.verified_custody_credential = fixture.node.credential_digest();
    }
    assert!(
        gate::Outage::holding_operation_absent(
            &*fixture.node,
            "records_write",
            "create_record",
            None
        )
        .await
    );
    fixture.node.state.lock().await.persisted.account_mismatch = true;
    assert!(
        !gate::Outage::holding_operation_absent(
            &*fixture.node,
            "records_write",
            "create_record",
            None
        )
        .await
    );
    fixture.node.state.lock().await.persisted.account_mismatch = false;
    fixture.node.state.lock().await.health = Health::AuthRefused;
    assert!(
        !gate::Outage::holding_operation_absent(
            &*fixture.node,
            "records_write",
            "create_record",
            None
        )
        .await
    );
    fixture.finish().await;
}

// These bytes determine on-disk identity. Changing either shape requires an
// explicit migration, or existing floors/held queues would silently disappear.
#[test]
fn saved_state_binding_shapes_keep_existing_paths() {
    let binding = saved_state_binding();
    assert_eq!(
        serde_json::to_string(&binding).unwrap(),
        r#"{"home":"home","route":"route","origin":"origin","account":"acct:test","endpoint":"https://plugin.withnative.ai"}"#
    );
    let custody = crate::node::journal::CustodyBinding {
        account_id: "acct:test".into(),
        database_id: "route".into(),
        origin_database_id: "origin".into(),
        history_lineage: "v2:genesis".into(),
        resource_origin: "https://plugin.withnative.ai".into(),
        install_id: None,
    };
    assert_eq!(
        String::from_utf8(crate::canonical_json::canonical_json(
            &serde_json::to_value(custody).unwrap()
        ))
        .unwrap(),
        r#"{"account_id":"acct:test","database_id":"route","history_lineage":"v2:genesis","origin_database_id":"origin","resource_origin":"https://plugin.withnative.ai"}"#
    );
}

fn saved_state_binding() -> Binding {
    Binding {
        home: "home".into(),
        route: "route".into(),
        origin: "origin".into(),
        account: "acct:test".into(),
        endpoint: "https://plugin.withnative.ai".into(),
    }
}

#[test]
fn saved_state_legacy_round_trip_and_corruption() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let binding = saved_state_binding();
    let (file, mut state) = StateFile::open(dir.path(), binding.clone()).unwrap();
    state.floor.act = Some(68739);
    state.floor.lineage = Some("v2:genesis".into());
    state.account_mismatch = true;
    let mut legacy = serde_json::to_value(&state).unwrap();
    legacy.as_object_mut().unwrap().remove("version");
    file.save(&state).unwrap();
    fs::write(&file.path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let (file, loaded) = StateFile::open(dir.path(), binding.clone()).unwrap();
    assert_eq!(loaded.version, 1);
    assert_eq!(runtime_declaration()["version"], loaded.version);
    assert_eq!(runtime_declaration()["missing_version"], "legacy_default_1");
    file.save(&loaded).unwrap();
    let mut saved: Value = serde_json::from_slice(&fs::read(&file.path).unwrap()).unwrap();
    assert_eq!(
        saved.as_object_mut().unwrap().remove("version"),
        Some(json!(1))
    );
    assert_eq!(saved, legacy);
    let mut with_future_field = legacy.clone();
    with_future_field["future_optional_field"] = json!("retained only until supported rewrite");
    fs::write(&file.path, serde_json::to_vec(&with_future_field).unwrap()).unwrap();
    let (supported, reloaded) = StateFile::open(dir.path(), binding.clone()).unwrap();
    supported.save(&reloaded).unwrap();
    let rewritten: Value = serde_json::from_slice(&fs::read(&file.path).unwrap()).unwrap();
    assert!(rewritten.get("future_optional_field").is_none());
    assert_eq!(
        runtime_declaration()["unknown_fields"],
        "ignored_not_round_tripped_on_rewrite"
    );

    // Syntax, type, missing required fields and binding errors still fail.
    let mut wrong_type = legacy.clone();
    wrong_type["floor"]["pending"] = json!("broken");
    let mut missing = legacy.clone();
    missing.as_object_mut().unwrap().remove("floor");
    let mut zero_version = legacy.clone();
    zero_version["version"] = json!(0);
    let mut wrong_binding = legacy.clone();
    wrong_binding["binding"]["account"] = json!("acct:other");
    for bytes in [
        b"{".to_vec(),
        serde_json::to_vec(&zero_version).unwrap(),
        serde_json::to_vec(&wrong_type).unwrap(),
        serde_json::to_vec(&missing).unwrap(),
        serde_json::to_vec(&wrong_binding).unwrap(),
    ] {
        fs::write(&file.path, &bytes).unwrap();
        assert!(StateFile::open(dir.path(), binding.clone()).is_err());
        assert_eq!(fs::read(&file.path).unwrap(), bytes);
    }
}

#[tokio::test]
async fn saved_state_newer_version_preserves_bytes_and_starts_conservatively() {
    let mut fixture = Fixture::online(BOUND).await;
    online_ready(&fixture).await;
    assert!(
        served_locally(&fixture.send(read(true)).await),
        "baseline copy is eligible for online local reads"
    );
    let binding = fixture.node.state.lock().await.persisted.binding.clone();
    let path = fixture.node.file.path.clone();
    // The payload is deliberately incompatible, including account evidence.
    // Only the version envelope has meaning to this older build.
    let bytes = b"{ \"version\": 2, \"floor\": [\"future floor\"], \"account_mismatch\": null, \"future\": true }\n";
    fs::write(&path, bytes).unwrap();
    let previous = &fixture.node.upstream;
    let mut config = previous.config.clone();
    config.desktop_app_proof_resource_origin =
        Some(previous.endpoint.origin().ascii_serialization());
    let upstream = Arc::new(Upstream {
        compatibility: Default::default(),
        config,
        endpoint: previous.endpoint.clone(),
        client: previous.client.clone(),
        oauth: previous.oauth.clone(),
        install_key: previous.install_key.clone(),
    });
    fixture.node = Arc::new(
        Failover::new(
            upstream,
            fixture.supervisor.dispatcher(),
            fixture.node.local.clone(),
            binding.origin.clone(),
        )
        .unwrap()
        .with_gate(fixture.node.gate.clone()),
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(fixture.node.connection_scope().await.is_none());
    assert!(
        fixture.node.hosted_summary().await["saved_state"]["message"]
            .as_str()
            .unwrap()
            .contains("shim socket binding is unavailable")
    );
    assert_eq!(
        fixture.node.hosted_summary().await["saved_state"]["newer_version"],
        2
    );
    assert!(
        fixture.node.hosted_summary().await["saved_state"]["message"]
            .as_str()
            .unwrap()
            .contains("newer build")
    );
    // Unconfirmed account evidence refuses local data without asserting a
    // switch or permanently pausing the off-default working path.
    {
        let state = fixture.node.state.lock().await;
        assert!(state.account_unconfirmed);
        assert!(!state.persisted.account_mismatch);
        assert_eq!(fixture.node.current_account_verdict(&state), None);
    }
    fixture.node.state.lock().await.health = Health::Unreachable;
    let reply = fixture.send(read(true)).await;
    assert_eq!(
        reply["error"]["data"]["reason"], "account_unconfirmed",
        "{reply}"
    );
    assert!(reply["error"]["data"]["next_step"]
        .as_str()
        .unwrap()
        .contains("Reconnect"));
    #[cfg(feature = "v2-kernel-probe")]
    assert!(!fixture.node.working.acknowledgements_paused());
    // Inconclusive or mismatched principal checks cannot expose the copy.
    *fixture.fake.principal.lock().unwrap() = None;
    fixture.node.probe().await;
    assert!(fixture.node.connection_scope().await.is_none());
    *fixture.fake.principal.lock().unwrap() = Some("acct_other".into());
    fixture.node.probe().await;
    assert!(fixture.node.connection_scope().await.is_none());
    let mismatch = account_changed_refusal(&read(true)).unwrap();
    assert!(mismatch.contains("The signed-in account is not the account this node is set up for"));
    assert!(fixture.node.state.lock().await.persisted.account_mismatch);
    *fixture.fake.principal.lock().unwrap() = Some(binding.account);
    fs::write(
        &fixture.node.upstream.config.credential_file,
        b"renewed-bound-account-token",
    )
    .unwrap();
    fixture.node.probe().await;
    assert!(fixture.node.connection_scope().await.is_some());
    assert!(
        !fixture.node.hosted_summary().await["saved_state"]["message"]
            .as_str()
            .unwrap()
            .contains("shim socket binding is unavailable")
    );
    fixture.node.refresh_discovery().await;
    let local = fixture.send(local_only(read(true))).await;
    assert!(text(&local).contains("local-first"), "{local}");
    // Normal hosted writes and queue send hooks retain their admission path;
    // only the floor is memory-only. Every online read still goes to hosted.
    let sent = fixture.fake.requests.lock().await.len();
    let reply = fixture.send(write()).await;
    assert!(reply.get("error").is_none(), "{reply}");
    assert!(fixture.fake.requests.lock().await.len() > sent);
    assert!(gate::Outage::before_send(&*fixture.node).await);
    gate::Outage::after_send(&*fixture.node, true).await;
    let reply = fixture.send(read(true)).await;
    assert!(text(&reply).contains("hosted answer"), "{reply}");
    let proof_binding = fixture.node.app_proof_binding().await.unwrap();
    let requests_before = fixture.fake.requests.lock().await.len();
    for _ in 0..2 {
        let reason = fixture
            .node
            .capture_read_barrier(&proof_binding)
            .await
            .unwrap_err();
        assert_eq!(reason, "saved_state_newer");
        let refusal: Value = serde_json::from_str(
            &super::super::read_barrier::error(&read_barrier(99), reason).unwrap(),
        )
        .unwrap();
        assert!(refusal["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Reads go to hosted"));
        assert_eq!(
            refusal["error"]["data"]["next_step"],
            "Upgrade the node to restore saved read barriers."
        );
    }
    assert_eq!(
        fixture.fake.requests.lock().await.len(),
        requests_before,
        "known incompatible saved state needs no repeated head probe"
    );
    fixture.fake.read_only.store(true, Ordering::Release);
    let held = fixture.send(write()).await;
    assert!(pending_info(&held)["record_id"].is_string(), "{held}");
    fixture.fake.read_only.store(false, Ordering::Release);
    let gate = fixture.node.gate.as_ref().unwrap();
    assert_eq!(
        gate.drain(
            &fixture.node.upstream,
            Some(&*fixture.node as &dyn gate::Outage),
            None,
            None
        )
        .await,
        gate::queue::Halt::Empty
    );
    let entry = pending_info(&held)["journal_entry"].as_str().unwrap();
    assert_eq!(
        gate.journal.get(entry).unwrap().state,
        super::super::journal::EntryState::Confirmed
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);

    {
        let state = fixture.node.state.lock().await;
        assert!(state.persisted.floor.unresolved);
        assert_eq!(
            standing_in(&state, Some(1), Some(V1), None).behind_known_write,
            None
        );
        assert_eq!(
            needs_hosted(
                &state,
                OwnWrites {
                    act: 1,
                    unresolved: false
                },
                1,
                Some(V1)
            ),
            Some("migration_unsettled")
        );
        assert!(fixture.node.file.save(&state.persisted).is_err());
    }
    // After account confirmation, continuity remains available in an outage.
    fixture.fake.status.store(502, Ordering::Release);
    fixture.node.probe().await;
    let reply = fixture.send(read(true)).await;
    assert!(text(&reply).contains("local-first"), "{reply}");
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // Each restart forgets the in-memory confirmation during an outage.
    let restarted = Arc::new(
        Failover::new(
            fixture.node.upstream.clone(),
            fixture.supervisor.dispatcher(),
            fixture.node.local.clone(),
            binding.origin.clone(),
        )
        .unwrap(),
    );
    assert!(restarted.connection_scope().await.is_none());
    let request = local_only(read(true));
    let refused = restarted
        .route(
            &request.to_string(),
            request,
            Some(crate::mcp::PROTOCOL_VERSION),
            &fixture.direct,
            &anonymous_caller(),
        )
        .await
        .unwrap();
    let refused: Value = serde_json::from_str(&refused).unwrap();
    assert_eq!(refused["error"]["data"]["reason"], "account_unconfirmed");
    assert_eq!(fs::read(&path).unwrap(), bytes);
    // Corrupt state still aborts construction through the same startup path.
    fs::write(&path, b"{").unwrap();
    assert!(Failover::new(
        fixture.node.upstream.clone(),
        fixture.supervisor.dispatcher(),
        fixture.node.local.clone(),
        binding.origin,
    )
    .is_err());
    fixture.finish().await;
}

/// Saved-state additions must bump the format version so rollback guards work.
#[test]
fn saved_state_v1_schema_requires_version_bump_for_shape_changes() {
    assert_eq!(
        STATE_VERSION, 1,
        "update the expected saved-state key sets for the new STATE_VERSION"
    );
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let (_, state) = StateFile::open(dir.path(), saved_state_binding()).unwrap();
    let saved = serde_json::to_value(state).unwrap();
    let keys = |value: &Value| {
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        keys
    };
    assert_eq!(
        keys(&saved),
        [
            "account_mismatch",
            "binding",
            "discovery",
            "floor",
            "kernel_v2",
            "observed_hosted_head",
            "verified_custody_credential",
            "version"
        ],
        "bump STATE_VERSION before changing the saved-state schema"
    );
    assert_eq!(
        keys(&saved["floor"]),
        ["act", "lineage", "pending", "unresolved"],
        "bump STATE_VERSION before changing the floor schema"
    );
}

#[tokio::test]
async fn update_required_account_probe_preserves_confirmed_mismatch_without_authenticating_payload()
{
    let fixture = Fixture::new().await;
    *fixture.fake.principal.lock().unwrap() = Some("acct_bbb".into());
    fixture.node.state.lock().await.account_check = None;
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    assert!(fixture.node.state.lock().await.persisted.account_mismatch);
    fixture.node.state.lock().await.account_check = None;
    *fixture.fake.account_reply.lock().unwrap() = Some((426,
        r#"{"error_code":"client_update_required","outcome":"refused","applied":false,"principal":"acct_aaa"}"#.into()));
    fixture.node.verify_account_against(Some("acct_aaa")).await;
    assert!(fixture.node.state.lock().await.persisted.account_mismatch);
    assert_eq!(
        fixture.node.upstream.compatibility.status()["status"],
        "demand_recorded"
    );
    fixture.finish().await;
}
