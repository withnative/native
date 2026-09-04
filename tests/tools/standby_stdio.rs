//! Process-boundary qualification for `mcp-stdio --standby`.
//!
//! Registry unit tests prove the policy table. These tests prove that the real
//! binary selects it, opens the real SQLite file without startup writes, and
//! cannot be bypassed through an exact-name JSON-RPC call.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use native_ce::standby::GenerationStore;
use native_ce::standby_snapshot::{
    CanonicalFrontierV1, ObservedInstalledConsumerIdentity, StandbyConsumerIdentity,
    StandbyConsumerPlatform, StandbySnapshotBytes, StandbySnapshotEngineIdentity,
    StandbySnapshotManifest, STANDBY_CONSUMER_CONTRACT, STANDBY_FRONTIER_CONTRACT,
    STANDBY_SNAPSHOT_MANIFEST_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FIXTURE_ID: &str = "70110000-0000-4000-8000-000000000001";
const WRITABLE_ID: &str = "70110000-0000-4000-8000-000000000002";
const HOSTED_ROUTE_ID: &str = "standby-process-route";

#[derive(Debug)]
struct ProcessOutput {
    status: ExitStatus,
    responses: Vec<Value>,
    stderr: String,
}

#[derive(Debug, PartialEq, Eq)]
struct FileEvidence {
    kind: &'static str,
    mode: u32,
    len: u64,
    sha256: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct SqlEvidence {
    content_head: i64,
    meta_head: i64,
    read_calls: i64,
    read_touches: i64,
    agent_runs: i64,
}

fn rpc(id: i64, method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}

fn tool_call(id: i64, name: &str, arguments: Value) -> Value {
    rpc(id, "tools/call", json!({"name":name,"arguments":arguments}))
}

fn run_mcp(path: &Path, standby: bool, messages: &[Value]) -> ProcessOutput {
    run_mcp_with_env(path, standby, messages, &[])
}

fn run_mcp_with_env(
    path: &Path,
    standby: bool,
    messages: &[Value],
    environment: &[(&str, String)],
) -> ProcessOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-stdio"));
    command
        .env_clear()
        .current_dir(path.parent().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    if standby {
        // Standby must override the configured default executor before it can
        // construct a plan store or telemetry sink.
        command.env("NATIVE_CE_MCP_SURFACE", "executor");
        command.arg("--standby");
    } else {
        command.env("NATIVE_CE_MCP_SURFACE", "legacy");
    }
    command.arg(path);

    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for message in messages {
        if let Err(error) = writeln!(stdin, "{message}") {
            // Startup refusals can close stdin before the harness writes its
            // first probe. Preserve the child's status and stderr as the test
            // evidence instead of racing that expected exit with BrokenPipe.
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
            break;
        }
    }
    drop(stdin);

    // Drain both pipes concurrently: tools/list is intentionally large enough
    // that waiting for process exit before reading can fill an OS pipe.
    let mut stdout = child.stdout.take().unwrap();
    let stdout = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let mut stderr = child.stderr.take().unwrap();
    let stderr = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("mcp-stdio did not exit after stdin reached EOF");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = String::from_utf8(stdout.join().unwrap()).unwrap();
    let stderr = String::from_utf8(stderr.join().unwrap()).unwrap();
    let responses = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("invalid JSON-RPC response ({error}): {line}\nstderr: {stderr}")
            })
        })
        .collect();
    ProcessOutput {
        status,
        responses,
        stderr,
    }
}

fn response(output: &ProcessOutput, id: i64) -> &Value {
    output
        .responses
        .iter()
        .find(|response| response["id"] == id)
        .unwrap_or_else(|| panic!("response {id} missing: {output:#?}"))
}

fn successful_tool(output: &ProcessOutput, id: i64) -> &Value {
    let result = &response(output, id)["result"];
    assert_eq!(result["isError"], false, "{result:#}");
    &result["structuredContent"]
}

fn mode(metadata: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

fn tree_evidence(root: &Path) -> BTreeMap<PathBuf, FileEvidence> {
    fn visit(root: &Path, path: &Path, evidence: &mut BTreeMap<PathBuf, FileEvidence>) {
        let mut entries = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for entry in entries {
            let metadata = std::fs::symlink_metadata(&entry).unwrap();
            let relative = entry.strip_prefix(root).unwrap().to_path_buf();
            if metadata.is_dir() {
                evidence.insert(
                    relative,
                    FileEvidence {
                        kind: "directory",
                        mode: mode(&metadata),
                        len: 0,
                        sha256: None,
                    },
                );
                visit(root, &entry, evidence);
            } else {
                let bytes = std::fs::read(&entry).unwrap();
                evidence.insert(
                    relative,
                    FileEvidence {
                        kind: "file",
                        mode: mode(&metadata),
                        len: metadata.len(),
                        sha256: Some(hex::encode(Sha256::digest(bytes))),
                    },
                );
            }
        }
    }

    let mut evidence = BTreeMap::new();
    visit(root, root, &mut evidence);
    evidence
}

fn sql_evidence(path: &Path) -> SqlEvidence {
    use rusqlite::OpenFlags;

    let connection = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let scalar = |sql: &str| connection.query_row(sql, [], |row| row.get(0)).unwrap();
    SqlEvidence {
        content_head: scalar("SELECT COALESCE(MAX(seq),0) FROM content_events"),
        meta_head: scalar("SELECT COALESCE(MAX(seq),0) FROM meta_events"),
        read_calls: scalar("SELECT COUNT(*) FROM read_log_calls"),
        read_touches: scalar("SELECT COUNT(*) FROM read_log_touches"),
        agent_runs: scalar("SELECT COUNT(*) FROM agent_runs"),
    }
}

async fn create_fixture(path: &Path) -> String {
    let db = native_ce::create_database(path.to_str().unwrap())
        .await
        .unwrap();
    let account = native_ce::identity::resolve_stdio_account_identity(&db, None)
        .await
        .unwrap();
    native_ce::store::create_record_as(
        &db,
        json!({
            "id": FIXTURE_ID,
            "type": "WorkItem",
            "kind": "task",
            "name": "Standby process fixture",
            "body": "This record must remain readable without changing accepted bytes."
        }),
        Some(&account),
    )
    .await
    .unwrap();
    let origin = native_ce::identity::database_id(&db).await.unwrap();
    db.close().await;

    // `Db::close` drains both pools concurrently and is not itself a WAL
    // checkpoint barrier. Quiesce the fixture before taking byte evidence so
    // a late writable close cannot make the standby process appear to have
    // folded the WAL into the main file.
    let connection = rusqlite::Connection::open(path).unwrap();
    connection.busy_timeout(Duration::from_secs(30)).unwrap();
    let (busy, log_frames, checkpointed): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(busy, 0, "fixture checkpoint must not be busy");
    assert_eq!(
        log_frames, checkpointed,
        "fixture WAL must be fully checkpointed"
    );
    origin
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_path(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
}

fn frontier_from_snapshot(path: &Path) -> CanonicalFrontierV1 {
    use rusqlite::OpenFlags;

    let connection = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let scalar = |sql: &str| connection.query_row(sql, [], |row| row.get(0)).unwrap();
    CanonicalFrontierV1 {
        contract: STANDBY_FRONTIER_CONTRACT.into(),
        version: 1,
        content_event_seq: scalar("SELECT COALESCE(MAX(seq),0) FROM content_events"),
        policy_event_seq: scalar("SELECT COALESCE(MAX(seq),0) FROM policy_events"),
        awareness_event_seq: scalar("SELECT COALESCE(MAX(seq),0) FROM awareness_events"),
        notification_candidate_event_seq: scalar(
            "SELECT COALESCE(MAX(seq),0) FROM notification_candidate_events",
        ),
        binding_audit_seq: scalar("SELECT COALESCE(MAX(seq),0) FROM binding_audit"),
        database_identity_audit_seq: scalar(
            "SELECT COALESCE(MAX(seq),0) FROM database_identity_audit",
        ),
        meta_event_seq: scalar("SELECT COALESCE(MAX(seq),0) FROM meta_events"),
        control_event_seq: scalar("SELECT COALESCE(MAX(seq),0) FROM control_events"),
        derivation_event_seq: scalar("SELECT COALESCE(MAX(seq),0) FROM derivation_events"),
        relationship_event_seq: scalar("SELECT COALESCE(MAX(seq),0) FROM relationship_events"),
        authorization_revision_epoch: scalar(
            "SELECT COALESCE((SELECT epoch FROM authorization_revision WHERE id=1),0)",
        ),
        storage_portability_policy_revision: scalar(
            "SELECT COALESCE((SELECT policy_revision FROM storage_portability_policy WHERE singleton=1),0)",
        ),
    }
}

fn write_runtime_config(path: &Path, replica_root: &Path, origin: &str) {
    std::fs::write(
        path,
        serde_json::to_vec(&json!({
            "replica_root": replica_root,
            "hosted_route_database_id": HOSTED_ROUTE_ID,
            "origin_database_id": origin,
        }))
        .unwrap(),
    )
    .unwrap();
}

fn create_private_empty_file(path: &Path) {
    std::fs::write(path, []).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn precreate_generation_lease(replica_root: &Path, generation_id: &str) {
    let path = replica_root
        .join("accepted/leases")
        .join(format!("{generation_id}.lock"));
    create_private_empty_file(&path);
}

async fn install_fixture_generation(
    replica_root: &Path,
    source_path: &Path,
    origin: &str,
) -> native_ce::standby::InstalledGeneration {
    let (snapshot_bytes, manifest, observed) = snapshot_fixture(source_path, origin).await;
    let store = GenerationStore::open(replica_root, HOSTED_ROUTE_ID, Some(origin.into())).unwrap();
    let snapshot_path = store.staging_dir().join("process-fixture.db");
    std::fs::write(&snapshot_path, snapshot_bytes).unwrap();
    let manifest_path = store.staging_dir().join("process-fixture.json");
    std::fs::write(&manifest_path, manifest.canonical_json().unwrap()).unwrap();
    store
        .install_staged(&snapshot_path, &manifest_path, &observed)
        .await
        .unwrap()
}

async fn snapshot_fixture(
    source_path: &Path,
    origin: &str,
) -> (
    Vec<u8>,
    StandbySnapshotManifest,
    ObservedInstalledConsumerIdentity,
) {
    let executable = Path::new(env!("CARGO_BIN_EXE_mcp-stdio"));
    let artifact_sha256 = sha256_path(executable);
    let consumer = StandbyConsumerIdentity {
        contract: STANDBY_CONSUMER_CONTRACT.into(),
        version: 1,
        platform: StandbyConsumerPlatform::LinuxX8664,
        source_sha: native_ce::FULL_GIT_SHA.into(),
        artifact_sha256: artifact_sha256.clone(),
        engine_schema_version: native_ce::CURRENT_ENGINE_SCHEMA_VERSION,
        ddl_sha256: native_ce::schema::FROZEN_DDL_SHA256.into(),
    };
    let observed = ObservedInstalledConsumerIdentity {
        platform: consumer.platform,
        source_sha: consumer.source_sha.clone(),
        artifact_sha256,
        engine_schema_version: consumer.engine_schema_version,
        ddl_sha256: consumer.ddl_sha256.clone(),
    };
    let export_source = native_ce::open_existing_database(source_path.to_str().unwrap())
        .await
        .unwrap();
    let export = native_ce::export::export_connected_db(&export_source, None)
        .await
        .unwrap();
    export_source.close().await;
    let snapshot_path = export.path();
    let snapshot_bytes = std::fs::read(&snapshot_path).unwrap();
    let frontier = frontier_from_snapshot(&snapshot_path);
    export.cleanup().await;
    let manifest = StandbySnapshotManifest {
        contract: STANDBY_SNAPSHOT_MANIFEST_CONTRACT.into(),
        version: 1,
        hosted_route_database_id: HOSTED_ROUTE_ID.into(),
        origin_database_id: origin.into(),
        captured_at: "2026-09-02T00:00:00Z".into(),
        snapshot_completed_at: "2026-09-02T00:00:01Z".into(),
        engine: StandbySnapshotEngineIdentity {
            name: native_ce::ENGINE_NAME.into(),
            source_sha: native_ce::FULL_GIT_SHA.into(),
            schema_version: native_ce::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: native_ce::schema::FROZEN_DDL_SHA256.into(),
        },
        consumer,
        frontier,
        snapshot: StandbySnapshotBytes {
            media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
            size_bytes: snapshot_bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&snapshot_bytes)),
        },
    };
    (snapshot_bytes, manifest, observed)
}

fn spawn_snapshot_endpoint(
    snapshot: Vec<u8>,
    manifest: StandbySnapshotManifest,
    bearer: &'static str,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let page_size = native_ce::mcp::SNAPSHOT_MAX_PAGE_BYTES;
    let request_count = snapshot.len().div_ceil(page_size);
    let sha256 = hex::encode(Sha256::digest(&snapshot));
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let accept_deadline = Instant::now() + Duration::from_secs(20);
        for page_index in 0..request_count {
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < accept_deadline,
                            "standby refresh did not request its hosted snapshot"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("standby refresh listener failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut buffer = [0_u8; 4096];
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0, "refresh client closed before its HTTP request");
                request.extend_from_slice(&buffer[..read]);
                assert!(
                    request.len() <= 64 * 1024,
                    "refresh HTTP request is unbounded"
                );
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let head = String::from_utf8(request[..header_end].to_vec()).unwrap();
            let mut lines = head.lines();
            let request_line = lines.next().unwrap();
            let expected_plain = format!("POST /mcp/{HOSTED_ROUTE_ID} HTTP/1.1");
            let expected_encoded = "POST /mcp/standby%2Dprocess%2Droute HTTP/1.1";
            assert!(
                request_line == expected_plain || request_line == expected_encoded,
                "refresh did not use the scoped hosted route: {request_line}"
            );
            let headers = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
                .collect::<BTreeMap<_, _>>();
            let expected_authorization = format!("Bearer {bearer}");
            assert_eq!(
                headers.get("authorization").map(String::as_str),
                Some(expected_authorization.as_str())
            );
            assert_eq!(
                headers.get("mcp-protocol-version").map(String::as_str),
                Some("2026-07-28")
            );
            assert_eq!(
                headers.get("mcp-method").map(String::as_str),
                Some("tools/call")
            );
            assert_eq!(headers.get("mcp-name").map(String::as_str), Some("export"));
            let content_length = headers["content-length"].parse::<usize>().unwrap();
            while request.len() < header_end + content_length {
                let mut buffer = [0_u8; 4096];
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0, "refresh request body ended early");
                request.extend_from_slice(&buffer[..read]);
            }
            let body: Value =
                serde_json::from_slice(&request[header_end..header_end + content_length]).unwrap();
            assert_eq!(body["method"], "tools/call");
            // Deployments serve the executor surface: the snapshot page is
            // reached through the `export` executor with an explicit operation,
            // never through a flat `export_snapshot` tool.
            assert_eq!(body["params"]["name"], "export");
            assert_eq!(body["params"]["arguments"]["operation"], "export_snapshot");
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            let arguments = &body["params"]["arguments"]["arguments"];
            let offset = page_index * page_size;
            assert_eq!(arguments["offset"], offset as u64);
            if page_index == 0 {
                assert!(arguments.get("export_id").is_none());
                assert_eq!(
                    arguments["standby_consumer"]["artifact_sha256"],
                    manifest.consumer.artifact_sha256
                );
            } else {
                assert_eq!(arguments["export_id"], "process-export");
                assert!(arguments.get("standby_consumer").is_none());
            }

            let end = (offset + page_size).min(snapshot.len());
            let bytes = &snapshot[offset..end];
            let structured = json!({
                "export_id":"process-export",
                "file_name":"native-ce-export.db",
                "media_type":STANDBY_SNAPSHOT_MEDIA_TYPE,
                "size_bytes":snapshot.len(),
                "sha256":sha256,
                "offset":offset,
                "length":bytes.len(),
                "eof":end == snapshot.len(),
                "data_base64":base64::engine::general_purpose::STANDARD.encode(bytes),
                "expires_in_seconds":60,
                "manifest":manifest,
            });
            let response = serde_json::to_vec(&json!({
                "jsonrpc":"2.0",
                "id":1,
                "result":{
                    "content":[{"type":"text","text":structured.to_string()}],
                    "structuredContent":structured,
                    "isError":false,
                    "resultType":"complete",
                    "_meta":{
                        "io.modelcontextprotocol/serverInfo":{"name":"native-ce","version":"test"}
                    }
                }
            }))
            .unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
        }
    });
    (origin, server)
}

#[tokio::test]
async fn standby_process_refreshes_in_background_for_the_next_activation() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64"))
        || !lowercase_hex(native_ce::FULL_GIT_SHA, 40)
    {
        return;
    }
    const BEARER: &str = "release-process-refresh-token";
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.db");
    let origin_id = create_fixture(&source_path).await;
    let (snapshot, manifest, _) = snapshot_fixture(&source_path, &origin_id).await;
    let (hosted_origin, server) = spawn_snapshot_endpoint(snapshot, manifest, BEARER);

    let replica_root = directory.path().join("replica");
    GenerationStore::open(&replica_root, HOSTED_ROUTE_ID, Some(origin_id.clone())).unwrap();
    let runtime_config = directory.path().join("standby.json");
    write_runtime_config(&runtime_config, &replica_root, &origin_id);
    let credential = directory.path().join("snapshot.credential");
    std::fs::write(&credential, format!("{BEARER}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let refresh_config = directory.path().join("refresh.json");
    std::fs::write(
        &refresh_config,
        serde_json::to_vec(&json!({
            "contract":"native.standby-refresh-config.v1",
            "version":1,
            "hosted_origin":hosted_origin,
            "credential_file":credential,
        }))
        .unwrap(),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-stdio"))
        .env_clear()
        .env("NATIVE_CE_MCP_SURFACE", "executor")
        .env("NATIVE_CE_STANDBY_REFRESH_CONFIG", &refresh_config)
        .arg("--standby")
        .arg(&runtime_config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();

    // The empty-store process enters status-only immediately while its
    // background startup trigger downloads and promotes for the next process.
    writeln!(
        stdin,
        "{}",
        rpc(
            1,
            "initialize",
            json!({"protocolVersion":"2024-11-05","capabilities":{}}),
        )
    )
    .unwrap();
    writeln!(
        stdin,
        "{}",
        tool_call(2, "get_record", json!({"ids":[FIXTURE_ID],"format":"json"}))
    )
    .unwrap();
    stdin.flush().unwrap();
    server.join().unwrap();
    let current = replica_root.join("accepted/current.json");
    let deadline = Instant::now() + Duration::from_secs(30);
    let state_path = replica_root.join("refresh/state.json");
    while Instant::now() < deadline {
        let complete = std::fs::read(&state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .is_some_and(|state| state["refresh_active"] == false);
        if current.is_file() && complete {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(current.is_file());
    writeln!(stdin, "{}", tool_call(3, "standby_status", json!({}))).unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    let first = child.wait_with_output().unwrap();
    assert!(first.status.success(), "{first:#?}");
    let first_responses = String::from_utf8(first.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let unavailable = first_responses
        .iter()
        .find(|value| value["id"] == 2)
        .unwrap();
    assert_eq!(unavailable["result"]["isError"], true);
    assert_eq!(
        unavailable["result"]["structuredContent"]["error_code"],
        "STANDBY_STATUS_ONLY"
    );
    let live_status = first_responses
        .iter()
        .find(|value| value["id"] == 3)
        .unwrap()["result"]["structuredContent"]
        .clone();
    assert_eq!(live_status["contract"], "native.standby-status.v1");
    assert_eq!(live_status["mode"], "status_only");
    assert!(live_status["serving_generation"].is_null());
    assert_eq!(live_status["freshness"]["state"], "unavailable");
    assert!(live_status["accepted_generation"]["generation_id"]
        .as_str()
        .is_some());
    assert_eq!(live_status["refresh"]["diagnostics"], "available");
    assert_eq!(live_status["refresh"]["refresh_active"], false);
    assert!(live_status["refresh"]["installed_generation_id"]
        .as_str()
        .is_some());
    assert_eq!(
        live_status["next_safe_action"],
        "restart the standby to activate the verified accepted generation"
    );

    let state: Value = serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
    assert_eq!(state["contract"], "native.standby-refresh-state.v1");
    assert_eq!(state["refresh_active"], false);
    assert_eq!(state["consecutive_failure_count"], 0);
    assert!(state["installed_generation_id"].as_str().is_some());
    assert_eq!(state["last_attempt_cause"], "startup");
    assert!(state["snapshot_captured_at"].as_str().is_some());

    let output = run_mcp(
        &runtime_config,
        true,
        &[
            rpc(
                1,
                "initialize",
                json!({"protocolVersion":"2024-11-05","capabilities":{}}),
            ),
            tool_call(2, "get_record", json!({"ids":[FIXTURE_ID],"format":"json"})),
        ],
    );
    assert!(output.status.success(), "{output:#?}");
    assert_eq!(successful_tool(&output, 2)["records"][0]["id"], FIXTURE_ID);
}

#[tokio::test]
async fn standby_process_serves_reads_rejects_writes_and_preserves_accepted_bytes() {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return;
    }
    if !lowercase_hex(native_ce::FULL_GIT_SHA, 40) {
        // Local Cargo builds are commonly stamped `dev`. They cannot honestly
        // create the release-pinned manifest needed to exercise serving; the
        // status-only and writable process tests below still run in that build.
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.db");
    let origin = create_fixture(&source_path).await;
    let replica_root = directory.path().join("replica");
    let installed = install_fixture_generation(&replica_root, &source_path, &origin).await;
    let config_path = directory.path().join("standby.json");
    write_runtime_config(&config_path, &replica_root, &origin);
    // Startup opens this lease even for a clean current generation. Seed it
    // before evidence capture so the assertion measures accepted-state
    // immutability rather than expected lease initialization.
    precreate_generation_lease(&replica_root, &installed.id);
    let before_sql = sql_evidence(&installed.snapshot_path);
    let before_tree = tree_evidence(&replica_root);

    let messages = vec![
        rpc(
            1,
            "initialize",
            json!({
                "protocolVersion":"2024-11-05",
                "capabilities":{},
                "clientInfo":{"name":"standby-process-test","version":"1"}
            }),
        ),
        rpc(2, "tools/list", json!({})),
        tool_call(3, "bootstrap", json!({"format":"json"})),
        tool_call(4, "get_record", json!({"ids":[FIXTURE_ID],"format":"json"})),
        tool_call(
            5,
            "get_history",
            json!({"record_id":FIXTURE_ID,"format":"json"}),
        ),
        tool_call(
            6,
            "get_structure",
            json!({"root_id":"native:root","format":"json"}),
        ),
        tool_call(
            7,
            "search",
            json!({"query":"Standby process fixture","format":"json"}),
        ),
        tool_call(
            8,
            "manage_relationships",
            json!({"action":"find","endpoint_record_id":FIXTURE_ID,"format":"json"}),
        ),
        tool_call(
            9,
            "create_record",
            json!({
                "id":"70110000-0000-4000-8000-000000000099",
                "type":"Document",
                "kind":"note",
                "name":"Must not exist",
                "reason":"Probe exact-name standby dispatch"
            }),
        ),
        tool_call(10, "manage_relationships", json!({"action":"assert"})),
        tool_call(11, "engine_info", json!({"format":"json"})),
        tool_call(12, "standby_status", json!({"format":"json"})),
        tool_call(13, "get_record", json!({"ids":[FIXTURE_ID]})),
    ];
    let output = run_mcp(&config_path, true, &messages);
    assert!(output.status.success(), "{output:#?}");
    assert!(output.stderr.is_empty(), "{}", output.stderr);

    assert_eq!(
        response(&output, 1)["result"]["protocolVersion"],
        "2024-11-05"
    );
    let tools = response(&output, 2)["result"]["tools"].as_array().unwrap();
    let names = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&"get_record"), "{names:?}");
    assert!(names.contains(&"manage_relationships"), "{names:?}");
    assert!(names.contains(&"standby_status"), "{names:?}");
    assert!(!names.contains(&"create_record"), "{names:?}");
    let relationship_descriptor = tools
        .iter()
        .find(|tool| tool["name"] == "manage_relationships")
        .unwrap()["inputSchema"]
        .to_string();
    assert!(relationship_descriptor.contains("find"));
    assert!(!relationship_descriptor.contains("assert"));

    let bootstrap = successful_tool(&output, 3);
    let runtime = &bootstrap["tool_exposure"]["runtime"];
    assert!(
        serde_json::to_vec(&bootstrap["tool_exposure"])
            .unwrap()
            .len()
            <= 8 * 1024
    );
    assert_eq!(runtime["contract"], "native.standby-status.v1");
    assert_eq!(runtime["mode"], "standby");
    assert_eq!(runtime["read_only"], true);
    assert_eq!(runtime["writes_supported"], false);
    assert_eq!(runtime["mutation_error"], "STANDBY_READ_ONLY");
    assert_eq!(runtime["projection"], "accepted_only");
    assert_eq!(runtime["pending_writes_supported"], false);
    assert_eq!(runtime["canonical_authority"], "hosted");
    assert_eq!(runtime["hosted_route_database_id"], HOSTED_ROUTE_ID);
    assert_eq!(runtime["origin_database_id"], origin);
    assert_eq!(runtime["serving_generation"]["generation_id"], installed.id);
    assert_eq!(
        runtime["accepted_generation"]["generation_id"],
        installed.id
    );
    assert_eq!(runtime["freshness"]["target_rpo_seconds"], 300);
    assert_eq!(runtime["freshness"]["target_refresh_interval_seconds"], 120);
    assert_eq!(runtime["serving_generation"]["frontier"]["version"], 1);
    assert_eq!(runtime["retained_generation_ids"], json!([installed.id]));
    assert_eq!(successful_tool(&output, 4)["records"][0]["id"], FIXTURE_ID);
    for id in [5, 6, 7, 8] {
        let result = successful_tool(&output, id);
        assert!(
            result.to_string().contains(FIXTURE_ID) || matches!(id, 6 | 8),
            "representative read {id} returned an unexpected payload: {result:#}"
        );
    }
    for id in [9, 10] {
        let result = &response(&output, id)["result"];
        assert_eq!(result["isError"], true, "{result:#}");
        assert_eq!(
            result["structuredContent"]["error_code"], "STANDBY_READ_ONLY",
            "{result:#}"
        );
    }
    let engine_runtime = &successful_tool(&output, 11)["runtime"];
    assert_eq!(engine_runtime["contract"], "native.standby-status.v1");
    assert_eq!(
        engine_runtime["serving_generation"]["generation_id"],
        installed.id
    );
    let status = successful_tool(&output, 12);
    assert_eq!(status["contract"], "native.standby-status.v1");
    assert_eq!(status["serving_generation"]["generation_id"], installed.id);
    let context = &successful_tool(&output, 4)["standby_context"];
    assert_eq!(context["mode"], "standby");
    assert_eq!(context["canonical_authority"], "hosted");
    assert_eq!(context["read_only"], true);
    assert_eq!(context["serving_generation_id"], installed.id);
    let rendered = response(&output, 13)["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(rendered.starts_with("Standby context:"), "{rendered}");
    assert!(
        rendered.contains("hosted Native is canonical"),
        "{rendered}"
    );

    let after_tree = tree_evidence(&replica_root);
    assert_eq!(
        after_tree, before_tree,
        "standby changed DB/WAL/SHM or directory state"
    );
    assert_eq!(sql_evidence(&installed.snapshot_path), before_sql);
}

#[test]
fn standby_process_without_a_usable_generation_serves_status_only() {
    let directory = tempfile::tempdir().unwrap();
    let replica_root = directory.path().join("replica");
    let origin = "ndb_0123456789abcdef0123456789abcdef";
    GenerationStore::open(&replica_root, HOSTED_ROUTE_ID, Some(origin.into())).unwrap();
    // A release-stamped build reaches generation activation and opens the
    // promotion lock even though the store is empty. A `dev` build enters
    // status-only mode one step earlier, so seed the file to make evidence
    // independent of build stamping.
    create_private_empty_file(&replica_root.join("accepted/promotion.lock"));
    let config_path = directory.path().join("standby.json");
    write_runtime_config(&config_path, &replica_root, origin);
    let before = tree_evidence(&replica_root);
    let messages = [
        rpc(
            1,
            "initialize",
            json!({"protocolVersion":"2024-11-05","capabilities":{}}),
        ),
        rpc(2, "tools/list", json!({})),
        tool_call(3, "bootstrap", json!({"format":"json"})),
        tool_call(4, "standby_status", json!({"format":"json"})),
        tool_call(5, "get_record", json!({"ids":[FIXTURE_ID]})),
        tool_call(6, "standby_status", json!({})),
    ];
    let output = run_mcp(&config_path, true, &messages);
    assert!(output.status.success(), "{output:#?}");
    let names = response(&output, 2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["bootstrap", "standby_status"]);
    let expected_reason = if lowercase_hex(native_ce::FULL_GIT_SHA, 40) {
        "no_usable_generation"
    } else {
        "installed_consumer_identity_unavailable"
    };
    let bootstrap = successful_tool(&output, 3);
    assert_eq!(bootstrap["contract"], "native.standby-status.v1");
    assert_eq!(bootstrap["mode"], "status_only");
    assert_eq!(bootstrap["status_only"]["reason"], expected_reason);
    assert!(bootstrap["serving_generation"].is_null());
    assert_eq!(bootstrap["freshness"]["state"], "unavailable");
    assert_eq!(bootstrap["writes_supported"], false);
    assert_eq!(bootstrap["mutation_error"], "STANDBY_STATUS_ONLY");
    assert_eq!(bootstrap["pending_writes_supported"], false);
    let status = successful_tool(&output, 4);
    assert_eq!(status["contract"], "native.standby-status.v1");
    assert_eq!(status["status_only"]["reason"], expected_reason);
    assert_eq!(response(&output, 5)["result"]["isError"], true);
    assert_eq!(
        response(&output, 5)["result"]["structuredContent"]["error_code"],
        "STANDBY_STATUS_ONLY"
    );
    let rendered = response(&output, 6)["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(rendered.contains("# Local standby status"), "{rendered}");
    assert!(rendered.contains("Degraded reasons:"), "{rendered}");
    assert!(rendered.contains("Next safe action:"), "{rendered}");
    assert_eq!(tree_evidence(&replica_root), before);
}

#[tokio::test]
async fn standby_process_refuses_a_raw_database_path_without_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("must-not-be-opened.db");
    create_fixture(&path).await;
    let before = std::fs::read(&path).unwrap();
    let output = run_mcp(
        &path,
        true,
        &[tool_call(
            1,
            "get_record",
            json!({"ids":[FIXTURE_ID],"format":"json"}),
        )],
    );
    assert!(!output.status.success(), "{output:#?}");
    assert!(output.responses.is_empty(), "{output:#?}");
    assert!(output.stderr.contains("invalid standby runtime config"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn ordinary_process_direct_database_remains_writable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("writable.db");
    create_fixture(&path).await;
    let writable = run_mcp(
        &path,
        false,
        &[tool_call(
            1,
            "create_record",
            json!({
                "id":WRITABLE_ID,
                "type":"Document",
                "kind":"note",
                "name":"Writable regression",
                "reason":"Prove ordinary mcp-stdio remains writable",
                "format":"json"
            }),
        )],
    );
    assert!(writable.status.success(), "{writable:#?}");
    assert_eq!(successful_tool(&writable, 1)["id"], WRITABLE_ID);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM records WHERE id=?1",
            [WRITABLE_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exists, 1);
}
