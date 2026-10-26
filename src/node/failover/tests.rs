use super::*;
use crate::standby::generation_store::tests::{observed, stage};
use axum::{
    body::Bytes, extract::State as HttpState, http::StatusCode, response::IntoResponse,
    routing::post, Router,
};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

fn anonymous_caller() -> Caller {
    Caller::new(None, Cancel::new())
}

const RECORD: &str = "70110000-0000-4000-8000-000000000001";
#[derive(Clone)]
struct Fake {
    db: crate::Db,
    operations: Vec<Value>,
    status: Arc<AtomicU16>,
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
}
async fn hosted(HttpState(fake): HttpState<Fake>, body: Bytes) -> axum::response::Response {
    let request: Value = serde_json::from_slice(&body).unwrap();
    fake.requests.lock().await.push(request.clone());
    let status = fake.status.load(Ordering::Acquire);
    if status != 0 {
        if status == 200 {
            return (StatusCode::OK, "broken protocol").into_response();
        }
        return (
            StatusCode::from_u16(status).unwrap(),
            "hosted refused or gateway failed",
        )
            .into_response();
    }
    let (executor, operation, _) = target(&request).unwrap_or_default();
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
        if bump {
            let mut head_value = serde_json::to_value(&head).unwrap();
            head_value["head"]["native_interchange_revision"] =
                json!(crate::standby::REQUIRED_NATIVE_INTERCHANGE_REVISION + 1);
            json!({"isError":false,"content":[],"structuredContent":head_value})
        } else {
            json!({"isError":false,"content":[],"structuredContent":head})
        }
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
    } else if executor == "sql_read" {
        json!({"isError":false,"content":[],"structuredContent":{"rows":fake.operations}})
    } else {
        if fake.fail_reads.load(Ordering::Acquire) && executor == "records_read" {
            return (StatusCode::BAD_GATEWAY, "gateway read failure").into_response();
        }
        json!({"isError":false,"content":[{"type":"text","text":"hosted answer"}]})
    };
    axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"result":result})).into_response()
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
        let dir = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let account = crate::identity::resolve_stdio_account_identity(&db, None)
            .await
            .unwrap();
        crate::store::create_record_as(
            &db,
            json!({"id":RECORD,"type":"Document","kind":"note","name":"local-first"}),
            Some(&account),
        )
        .await
        .unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
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
        let local = session
            .operation_rows(provider)
            .unwrap()
            .as_array()
            .unwrap()
            .clone();
        if startup != Some(false) {
            let (snapshot, manifest) = stage(&store, &db, "node-fixture").await;
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
            status: Arc::new(AtomicU16::new(0)),
            requests: Arc::new(Mutex::new(Vec::new())),
            fail_reads: Arc::new(AtomicBool::new(false)),
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
            markdown_folder: None,
            hosted_base_url: format!("http://{address}"),
            home_id: "home".into(),
            db_id: "route-1".into(),
            credential_file: credential,
            socket_directory: dir.path().join("socket"),
            oauth_auth_file: None,
            standby_config: startup.map(|_| standby_path),
            account_id: Some(account),
            refresh_config: refresh.map(|_| refresh_path),
            disk_floor_bytes: None,
        };
        let (_listener, _guard) = bind_socket(&config).await.unwrap();
        let (supervisor, local, origin, background) = if startup.is_some() {
            let standby = start_standby_with_identity(&config, observed())
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
        let reply = self
            .node
            .route(
                &message.to_string(),
                message,
                Some(crate::mcp::PROTOCOL_VERSION),
                &self.direct,
                &anonymous_caller(),
            )
            .await
            .unwrap();
        serde_json::from_str(&reply).unwrap()
    }
    async fn finish(self) {
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
    floor.observe(0, 100);
    let before = floor.pending;
    floor.begin_write();
    floor.finish_write(true);
    floor.observe(before, 100);
    assert!(floor.unresolved);
    assert!(floor.label(Some(100)).unwrap().contains("at least act 100"));
    let after = floor.pending;
    floor.observe(after, 101);
    assert!(!floor.unresolved);
    assert!(floor.label(Some(100)).is_some());
    assert!(floor.label(Some(101)).is_none());
    assert!(floor.label(None).is_some());
    floor.begin_write();
    floor.observe(floor.pending, 102);
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
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert_eq!(
        reply["result"]["structuredContent"]["standby_context"]["mode"], "status_only",
        "{reply}"
    );
    assert!(fixture.fake.requests.lock().await.is_empty());
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
                &message.to_string(),
                message.clone(),
                Some(crate::mcp::PROTOCOL_VERSION),
                &fixture.direct,
                &anonymous_caller(),
            )
            .await
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
            &message.to_string(),
            message.clone(),
            Some(crate::mcp::PROTOCOL_VERSION),
            &fixture.direct,
            &anonymous_caller(),
        )
        .await
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
            &message.to_string(),
            message.clone(),
            Some(crate::mcp::PROTOCOL_VERSION),
            &fixture.direct,
            &anonymous_caller(),
        )
        .await
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
async fn local_only_auth_refusal_blocks_data_but_preserves_status_introspection() {
    let fixture = Fixture::new().await;
    // Establish a real known credential refusal through the hosted probe.
    fixture.fake.status.store(401, Ordering::Release);
    fixture.node.probe().await;
    assert_eq!(fixture.node.state.lock().await.health, Health::AuthRefused);
    fixture.fake.requests.lock().await.clear();
    let gate = fixture.node.gate.as_ref().unwrap();
    let journal = journal_state(gate);
    let floor = fixture.node.state.lock().await.persisted.floor.pending;
    // Causal control: the old `local || health.offline()` branch dispatched
    // straight here even in AuthRefused. That exact unguarded edge returns
    // record data, so the refusal assertions below fail on the pre-fix route.
    let old_edge = fixture
        .node
        .offline(
            local_only(read(true)),
            crate::mcp::PROTOCOL_VERSION,
            &fixture.direct,
        )
        .await
        .unwrap();
    let old_edge: Value = serde_json::from_str(&old_edge).unwrap();
    assert!(text(&old_edge).contains("local-first"), "{old_edge}");
    assert!(old_edge.get("error").is_none(), "{old_edge}");
    for request in [
        read(true),
        read(false),
        write(),
        json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"bootstrap","arguments":{"format":"json"}}}),
    ] {
        let reply = fixture.send(local_only(request)).await;
        assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
        assert_eq!(reply["error"]["data"]["reason"], "auth_refused", "{reply}");
        assert!(reply.get("result").is_none(), "{reply}");
        assert!(!reply.to_string().contains("local-first"));
        assert!(!reply.to_string().contains(RECORD));
    }
    for name in ["standby_status", "node_status"] {
        let request = local_only(
            json!({"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":name,"arguments":{}}}),
        );
        let reply = route_message(
            &fixture.node.upstream,
            Some(&fixture.node),
            Some(gate),
            &request.to_string(),
            request.clone(),
            Some(crate::mcp::PROTOCOL_VERSION),
            &fixture.direct,
            &anonymous_caller(),
        )
        .await
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
        hosted_base_url: "https://h.example".into(),
        home_id: "h".into(),
        db_id: "d".into(),
        credential_file: PathBuf::from("/c"),
        socket_directory: PathBuf::from("/s"),
        oauth_auth_file: None,
        standby_config: None,
        account_id: None,
        refresh_config: None,
        disk_floor_bytes: None,
        markdown_folder,
    };
    assert!(start_standby(&config(None)).unwrap().is_none());
    assert!(start_standby(&config(Some(MarkdownFolder::Disabled)))
        .unwrap()
        .is_none());
    assert!(
        start_standby(&config(Some(MarkdownFolder::Explicit(PathBuf::from(
            "/custom/vault"
        )))))
        .is_err()
    );
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
