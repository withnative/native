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

use native_ce::standby::GenerationStore;
use native_ce::standby_snapshot::{
    CanonicalFrontierV1, ObservedInstalledConsumerIdentity, StandbyConsumerIdentity,
    StandbyConsumerPlatform, StandbyGenerationMaterialization, StandbySnapshotBytes,
    StandbySnapshotEngineIdentity, StandbySnapshotManifest, STANDBY_CONSUMER_CONTRACT,
    STANDBY_FRONTIER_CONTRACT, STANDBY_SNAPSHOT_MANIFEST_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FIXTURE_ID: &str = "70110000-0000-4000-8000-000000000001";
const WRITABLE_ID: &str = "70110000-0000-4000-8000-000000000002";
const HOSTED_ROUTE_ID: &str = "standby-process-route";

// Standby rehearsal hosts. Fixture generations must carry the real runner
// platform: the serving binary validates the accepted generation against its
// own observed identity, so a hardcoded linux-x86_64 generation cannot boot
// on macOS.
fn supported_standby_host() -> bool {
    cfg!(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
    ))
}

fn standby_test_platform() -> StandbyConsumerPlatform {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        StandbyConsumerPlatform::LinuxX8664
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        StandbyConsumerPlatform::MacosArm64
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        StandbyConsumerPlatform::MacosX64
    } else {
        panic!("standby process tests support only linux-x86_64, macos-arm64, and macos-x64");
    }
}

fn expected_standby_platform_string() -> &'static str {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-x86_64"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "macos-arm64"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "macos-x64"
    } else {
        panic!("standby process tests support only linux-x86_64, macos-arm64, and macos-x64");
    }
}

// The observed binary identity is authoritative: the fixture platform must
// match what the external binary actually reports, not synthetic metadata.
fn assert_binary_platform_matches_runner(binary: &Path) {
    let output = Command::new(binary)
        .arg("--standby-identity")
        .output()
        .expect("probe standby identity of the external test binary");
    assert!(
        output.status.success(),
        "standby identity probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let identity: Value =
        serde_json::from_slice(&output.stdout).expect("standby identity probe must return JSON");
    assert_eq!(
        identity.get("platform").and_then(Value::as_str),
        Some(expected_standby_platform_string()),
        "external test binary platform must match the rehearsal runner",
    );
}

#[derive(Debug)]
struct ProcessOutput {
    status: ExitStatus,
    responses: Vec<Value>,
    stderr: String,
}

fn assert_bounded_verification_diagnostics(stderr: &str) {
    assert!(
        assert_bounded_verification_receipts(stderr),
        "successful serving startup completion"
    );
}

// Status-only startup is a successful validation outcome with no ready reader.
// Keep the same closed formatter/event/field contract on connected transitions.
fn assert_bounded_verification_receipts(stderr: &str) -> bool {
    assert!(!stderr.is_empty(), "standby verification emits progress");
    assert!(stderr.ends_with('\n'), "complete diagnostic lines");
    assert!(
        stderr
            .bytes()
            .all(|byte| byte == b'\n' || (b' '..=b'~').contains(&byte)),
        "diagnostics contain printable ASCII and line feeds only"
    );
    let phases = [
        "candidate",
        "predecessor",
        "existing-generation",
        "hardened-generation",
        "startup-generation",
        "startup-snapshot",
        "byte-manifest-consumer-identity",
        "engine-manifest-state",
        "sqlite-integrity-foreign-keys",
        "observational-conformance",
        "awareness-projections",
        "successor-fence",
    ];
    let checks = [
        "required-tables",
        "event-log-shape",
        "meta-event-log-shape",
        "command-event-log-shapes",
        "derivation-request-shape",
        "home-contract",
        "rebuild-and-diff",
        "rebuild-and-diff-meta",
        "rebuild-and-diff-policy",
        "rebuild-and-diff-relationship",
        "rebuild-and-diff-control",
        "rebuild-and-diff-derivation",
        "provenance-state",
        "authorization-revision-state",
        "grant-revision-state",
        "authorization-policy-state",
        "control-event-log-state",
        "policy-event-log-state",
        "relationship-event-log-state",
        "portable-identity-state",
        "storage-portability-policy-state",
    ];
    let events: [(&str, &[&str]); 11] = [
        ("standby startup verification started", &[]),
        (
            "standby startup verification finished",
            &["elapsed_ms", "ok", "serving"],
        ),
        ("standby phase started", &["phase"]),
        ("standby phase finished", &["phase", "elapsed_ms", "ok"]),
        ("standby suite started", &[]),
        ("standby suite finished", &["elapsed_ms", "ok"]),
        ("standby check started", &["check"]),
        ("standby check finished", &["check", "elapsed_ms", "ok"]),
        ("standby connected handoff finished", &["ready", "attempt"]),
        (
            "standby writer contention window",
            &["domain", "transactions", "busy_retries", "failures"],
        ),
        ("standby writer contention slow", &["domain", "held_ms"]),
    ];
    let mut serving_completion = false;
    let mut startup_completion = false;
    for line in stderr.lines() {
        assert!(
            line.len() <= 256,
            "bounded diagnostic line ({} bytes)",
            line.len()
        );
        let (timestamp, message) = line
            .split_once("  INFO native_ce::standby::verification: ")
            .unwrap_or_else(|| panic!("unexpected standby diagnostic: {line}"));
        // The locked default fmt timer emits UTC with six fractional digits.
        // Check its shape without depending on the clock's value.
        let timestamp_shape = b"0000-00-00T00:00:00.000000Z";
        assert_eq!(timestamp.len(), timestamp_shape.len(), "formatter prefix");
        assert!(
            timestamp
                .bytes()
                .zip(timestamp_shape)
                .all(|(actual, expected)| {
                    if *expected == b'0' {
                        actual.is_ascii_digit()
                    } else {
                        actual == *expected
                    }
                }),
            "unexpected formatter prefix: {timestamp}"
        );
        let (event, required, field_text) = events
            .iter()
            .find_map(|(event, required)| {
                if message == *event {
                    Some((*event, *required, ""))
                } else {
                    message
                        .strip_prefix(event)
                        .and_then(|fields| fields.strip_prefix(' '))
                        .filter(|fields| !fields.is_empty())
                        .map(|fields| (*event, *required, fields))
                }
            })
            .unwrap_or_else(|| panic!("unexpected verification event: {message}"));
        let mut fields = BTreeMap::new();
        if !field_text.is_empty() {
            for field in field_text.split(' ') {
                let (key, value) = field.split_once('=').expect("key=value field");
                assert!(required.contains(&key), "unexpected field: {field}");
                assert!(
                    fields.insert(key, value).is_none(),
                    "duplicate verification field: {key}"
                );
                match key {
                    "phase" | "check" => {
                        let name = value
                            .strip_prefix('"')
                            .and_then(|name| name.strip_suffix('"'))
                            .expect("quoted fixed name");
                        let names = if key == "phase" {
                            &phases[..]
                        } else {
                            &checks[..]
                        };
                        assert!(names.contains(&name), "unexpected fixed name: {name}");
                    }
                    "domain" => assert!(
                        matches!(value, "\"workspace\"" | "\"host_catalog\""),
                        "fixed writer domain"
                    ),
                    "elapsed_ms" | "held_ms" | "transactions" | "busy_retries" | "failures" => {
                        assert!(
                            !value.is_empty()
                                && value.bytes().all(|byte| byte.is_ascii_digit())
                                && value.parse::<u128>().is_ok(),
                            "invalid duration: {value}"
                        )
                    }
                    "attempt" => {
                        assert!(matches!(value, "1" | "2" | "3"), "bounded handoff attempt")
                    }
                    "ok" | "serving" | "ready" => assert!(
                        value.parse::<bool>().is_ok(),
                        "invalid boolean outcome: {value}"
                    ),
                    _ => unreachable!("event fields are closed"),
                }
            }
        }
        for key in required {
            assert!(fields.contains_key(key), "missing {key} in {event}");
        }
        if event == "standby startup verification finished" {
            startup_completion |= fields["ok"].parse::<bool>().unwrap();
            serving_completion |=
                fields["ok"].parse::<bool>().unwrap() && fields["serving"].parse::<bool>().unwrap();
        }
    }
    assert!(
        startup_completion,
        "successful startup validation completion"
    );
    assert!(
        !stderr.contains(FIXTURE_ID),
        "record identifiers stay out of diagnostics"
    );
    assert!(
        !stderr.contains("run_key="),
        "run context stays out of diagnostics"
    );
    serving_completion
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

fn generated_native_local_entry() -> Option<(PathBuf, Vec<String>)> {
    let config_path = std::env::var_os("NATIVE_STANDBY_GENERATED_MCP_CONFIG")?;
    let config: Value = serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
    let entry = &config["mcpServers"]["native-local"];
    let command = entry["command"]
        .as_str()
        .expect("generated native-local command");
    let args = entry["args"]
        .as_array()
        .expect("generated native-local args")
        .iter()
        .map(|arg| {
            arg.as_str()
                .expect("generated native-local string arg")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert!(
        Path::new(command).is_absolute(),
        "native-local command must be absolute"
    );
    assert_eq!(args.first().map(String::as_str), Some("--standby"));
    assert!(args.get(1).is_some_and(|arg| Path::new(arg).is_absolute()));
    Some((PathBuf::from(command), args))
}

fn run_mcp_with_env(
    path: &Path,
    standby: bool,
    messages: &[Value],
    environment: &[(&str, String)],
) -> ProcessOutput {
    let generated_entry = generated_native_local_entry();
    let binary = generated_entry
        .as_ref()
        .map(|(command, _)| command.clone())
        .or_else(|| std::env::var_os("NATIVE_STANDBY_TEST_BINARY").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_mcp-stdio")));
    let mut command = Command::new(binary);
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
    if let Some((_, args)) = generated_entry {
        command.args(args);
    } else if standby {
        // Standby honours the configured surface: executor selects the
        // standby read-only executor constructor; an explicit legacy surface
        // still serves the native Legacy surface. Default to executor so the
        // executor path is exercised unless a caller pins legacy.
        let surface = environment
            .iter()
            .find(|(name, _)| *name == "NATIVE_CE_MCP_SURFACE")
            .map(|(_, value)| value.as_str())
            .unwrap_or("executor");
        command.env("NATIVE_CE_MCP_SURFACE", surface);
        command.arg("--standby").arg(path);
    } else {
        command.env("NATIVE_CE_MCP_SURFACE", "legacy");
        command.arg(path);
    }

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

    // Generous under parallel test load: a serving standby child builds the
    // executor catalogue over a physically read-only open, which can outrun
    // the former 20-second budget when several process tests share the host.
    let deadline = Instant::now() + Duration::from_secs(180);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let status = child.wait().unwrap();
            let stdout = String::from_utf8(stdout.join().unwrap()).unwrap_or_default();
            let stderr = String::from_utf8(stderr.join().unwrap()).unwrap_or_default();
            panic!("mcp-stdio did not exit after stdin reached EOF (status {status})\nstdout: {stdout}\nstderr: {stderr}");
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

fn frontier_from_snapshot(path: &Path) -> (CanonicalFrontierV1, i64) {
    use rusqlite::OpenFlags;

    let connection = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let scalar = |sql: &str| connection.query_row(sql, [], |row| row.get(0)).unwrap();
    let frontier = CanonicalFrontierV1 {
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
    };
    let head_act = scalar("SELECT next_act FROM act_state WHERE singleton=1");
    (frontier, head_act)
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
    let executable = std::env::var_os("NATIVE_STANDBY_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_mcp-stdio")));
    let artifact_sha256 = sha256_path(&executable);
    let consumer = StandbyConsumerIdentity {
        contract: STANDBY_CONSUMER_CONTRACT.into(),
        version: 1,
        platform: standby_test_platform(),
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
    let (frontier, head_act) = frontier_from_snapshot(&snapshot_path);
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
        head_act: Some(head_act),
        materialization: StandbyGenerationMaterialization::Snapshot,
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
    const CHUNK_SIZE: usize = 1024 * 1024;
    const API: &str = "native.standby-snapshot-export.v1";
    const HANDLE: &str = "0dc9aadc-46b9-438d-8fca-5f719a8d6dc7";
    let request_count = 2 + snapshot.len().div_ceil(CHUNK_SIZE);
    let sha256 = hex::encode(Sha256::digest(&snapshot));
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let accept_deadline = Instant::now() + Duration::from_secs(20);
        for request_index in 0..request_count {
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
            let base = format!("/v1/databases/{HOSTED_ROUTE_ID}/standby-snapshot/exports");
            let encoded_base = "/v1/databases/standby%2Dprocess%2Droute/standby-snapshot/exports";
            let suffix = if request_index == 0 {
                "".to_string()
            } else if request_index == 1 {
                format!("/{HANDLE}")
            } else {
                format!("/{HANDLE}/bytes")
            };
            let method = if request_index == 0 { "POST" } else { "GET" };
            let expected_plain = format!("{method} {base}{suffix} HTTP/1.1");
            let encoded_suffix = suffix.replace('-', "%2D");
            let expected_encoded = format!("{method} {encoded_base}{encoded_suffix} HTTP/1.1");
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
                headers.get("accept-encoding").map(String::as_str),
                Some("identity")
            );
            let content_length = headers
                .get("content-length")
                .map(|value| value.parse::<usize>().unwrap())
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let mut buffer = [0_u8; 4096];
                let read = stream.read(&mut buffer).unwrap();
                assert_ne!(read, 0, "refresh request body ended early");
                request.extend_from_slice(&buffer[..read]);
            }
            if request_index == 0 {
                let body: Value =
                    serde_json::from_slice(&request[header_end..header_end + content_length])
                        .unwrap();
                assert_eq!(body["contract"], API);
                assert_eq!(body["version"], 1);
                assert_eq!(
                    body["consumer"]["artifact_sha256"],
                    manifest.consumer.artifact_sha256
                );
                let response = serde_json::to_vec(&json!({
                    "api":API,"export_handle":HANDLE,"status":"pending",
                    "expires_at":"2026-09-29T23:59:59Z"
                }))
                .unwrap();
                write!(stream, "HTTP/1.1 202 Accepted\r\nx-native-export-api: {API}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                stream.write_all(&response).unwrap();
            } else if request_index == 1 {
                let response = serde_json::to_vec(&json!({
                    "api":API,"export_handle":HANDLE,"status":"ready",
                    "expires_at":"2026-09-29T23:59:59Z", "manifest":manifest,
                    "size_bytes":snapshot.len(),"sha256":sha256
                }))
                .unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nx-native-export-api: {API}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                stream.write_all(&response).unwrap();
            } else {
                let offset = (request_index - 2) * CHUNK_SIZE;
                let end = (offset + CHUNK_SIZE).min(snapshot.len());
                assert_eq!(
                    headers.get("range").map(String::as_str),
                    Some(format!("bytes={offset}-{}", end - 1).as_str())
                );
                let bytes = &snapshot[offset..end];
                write!(stream, "HTTP/1.1 206 Partial Content\r\nx-native-export-api: {API}\r\nContent-Type: {STANDBY_SNAPSHOT_MEDIA_TYPE}\r\nAccept-Ranges: bytes\r\nContent-Range: bytes {offset}-{}/{}\r\nETag: \"{sha256}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", end - 1, snapshot.len(), bytes.len()).unwrap();
                stream.write_all(bytes).unwrap();
            }
            stream.flush().unwrap();
        }
    });
    (origin, server)
}

#[tokio::test]
async fn standby_process_refreshes_in_background_for_the_next_activation() {
    if !supported_standby_host() || !lowercase_hex(native_ce::FULL_GIT_SHA, 40) {
        return;
    }
    const BEARER: &str = "release-process-refresh-token";
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.db");
    let origin_id = create_fixture(&source_path).await;
    let (snapshot, manifest, _) = snapshot_fixture(&source_path, &origin_id).await;
    let (hosted_origin, server) = spawn_snapshot_endpoint(snapshot, manifest, BEARER);

    let generated_entry = generated_native_local_entry();
    let (replica_root, runtime_config) = if let Some((_, args)) = generated_entry.as_ref() {
        let runtime_config = PathBuf::from(&args[1]);
        let mut config: Value =
            serde_json::from_slice(&std::fs::read(&runtime_config).unwrap()).unwrap();
        let replica_root = PathBuf::from(config["replica_root"].as_str().unwrap());
        config["hosted_route_database_id"] = Value::String(HOSTED_ROUTE_ID.into());
        config["origin_database_id"] = Value::String(origin_id.clone());
        std::fs::write(&runtime_config, serde_json::to_vec(&config).unwrap()).unwrap();
        (replica_root, runtime_config)
    } else {
        let replica_root = directory.path().join("replica");
        GenerationStore::open(&replica_root, HOSTED_ROUTE_ID, Some(origin_id.clone())).unwrap();
        let runtime_config = directory.path().join("standby.json");
        write_runtime_config(&runtime_config, &replica_root, &origin_id);
        (replica_root, runtime_config)
    };
    GenerationStore::open(&replica_root, HOSTED_ROUTE_ID, Some(origin_id.clone())).unwrap();
    let credential = directory.path().join("snapshot.credential");
    std::fs::write(&credential, format!("{BEARER}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // macOS temp directories commonly use /var, which aliases /private/var.
    // The credential loader intentionally rejects symlinked path components.
    let credential = std::fs::canonicalize(&credential).unwrap();
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

    let binary = generated_entry
        .as_ref()
        .map(|(command, _)| command.clone())
        .or_else(|| std::env::var_os("NATIVE_STANDBY_TEST_BINARY").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_mcp-stdio")));
    assert_binary_platform_matches_runner(&binary);
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("NATIVE_CE_MCP_SURFACE", "executor")
        .env("NATIVE_CE_STANDBY_REFRESH_CONFIG", &refresh_config);
    if let Some((_, args)) = generated_entry.as_ref() {
        command.args(args);
    } else {
        command.arg("--standby").arg(&runtime_config);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();

    // The empty-store process enters status-only immediately while its
    // background startup trigger downloads and promotes. This request still
    // captures status-only until the independent handoff finishes readiness.
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
        tool_call(2, "bootstrap", json!({"format":"json"}))
    )
    .unwrap();
    writeln!(
        stdin,
        "{}",
        tool_call(3, "get_record", json!({"ids":[FIXTURE_ID],"format":"json"}))
    )
    .unwrap();
    stdin.flush().unwrap();
    if server.join().is_err() {
        drop(stdin);
        let failed = child.wait_with_output().unwrap();
        let state = std::fs::read(replica_root.join("refresh/state.json")).ok();
        panic!("standby refresh endpoint failed; child: {failed:#?}; refresh state: {state:?}");
    }
    let current = replica_root.join("accepted/current.json");
    // Candidate admission includes all historical rebuilds before promotion.
    // The measured full suite can spend nearly 30 seconds in admission alone.
    let deadline = Instant::now() + Duration::from_secs(180);
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
    if !current.is_file() {
        drop(stdin);
        let failed = child.wait_with_output().unwrap();
        let state = std::fs::read_to_string(&state_path).ok();
        panic!(
            "standby refresh did not promote a generation; state: {state:?}; child stderr: {}",
            String::from_utf8_lossy(&failed.stderr)
        );
    }
    writeln!(stdin, "{}", tool_call(4, "standby_status", json!({}))).unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    let first = child.wait_with_output().unwrap();
    assert!(first.status.success(), "{first:#?}");
    let first_responses = String::from_utf8(first.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let bootstrap = first_responses
        .iter()
        .find(|value| value["id"] == 2)
        .unwrap();
    assert_eq!(bootstrap["result"]["isError"], false);
    assert_eq!(
        bootstrap["result"]["structuredContent"]["mode"],
        "status_only"
    );
    let unavailable = first_responses
        .iter()
        .find(|value| value["id"] == 3)
        .unwrap();
    assert_eq!(unavailable["result"]["isError"], true);
    assert_eq!(
        unavailable["result"]["structuredContent"]["error_code"],
        "STANDBY_STATUS_ONLY"
    );
    let live_status = first_responses
        .iter()
        .find(|value| value["id"] == 4)
        .unwrap()["result"]["structuredContent"]
        .clone();
    assert_eq!(live_status["contract"], "native.standby-status.v1");
    // Full status reports the captured generation, even if readiness advances
    // while the full accepted-store audit itself is running.
    if live_status["mode"] == "status_only" {
        assert!(live_status["serving_generation"].is_null());
        assert_eq!(live_status["freshness"]["state"], "unavailable");
        assert!(live_status["next_safe_action"]
            .as_str()
            .unwrap()
            .contains("full verification and readiness"));
    } else {
        assert_eq!(live_status["mode"], "standby");
        assert_eq!(
            live_status["serving_generation"]["generation_id"],
            live_status["accepted_generation"]["generation_id"]
        );
    }
    assert!(live_status["accepted_generation"]["generation_id"]
        .as_str()
        .is_some());
    assert_eq!(live_status["refresh"]["diagnostics"], "available");
    assert_eq!(live_status["refresh"]["refresh_active"], false);
    assert!(live_status["refresh"]["installed_generation_id"]
        .as_str()
        .is_some());

    let state: Value = serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
    assert_eq!(state["contract"], "native.standby-refresh-state.v1");
    assert_eq!(state["refresh_active"], false);
    assert_eq!(state["consecutive_failure_count"], 0);
    assert!(state["installed_generation_id"].as_str().is_some());
    assert_eq!(state["last_attempt_cause"], "startup");
    assert!(state["snapshot_captured_at"].as_str().is_some());

    let output = run_mcp_with_env(
        &runtime_config,
        true,
        &[
            rpc(
                1,
                "initialize",
                json!({"protocolVersion":"2024-11-05","capabilities":{}}),
            ),
            tool_call(2, "bootstrap", json!({"format":"json"})),
            tool_call(3, "get_record", json!({"ids":[FIXTURE_ID],"format":"json"})),
        ],
        &[("NATIVE_CE_MCP_SURFACE", "legacy".to_string())],
    );
    assert!(output.status.success(), "{output:#?}");
    assert_eq!(
        successful_tool(&output, 2)["tool_exposure"]["runtime"]["mode"],
        "standby"
    );
    assert_eq!(successful_tool(&output, 3)["records"][0]["id"], FIXTURE_ID);
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
    let output = run_mcp_with_env(
        &config_path,
        true,
        &messages,
        &[("NATIVE_CE_MCP_SURFACE", "legacy".to_string())],
    );
    assert!(output.status.success(), "{output:#?}");
    assert_bounded_verification_diagnostics(&output.stderr);

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
    // Standby capture suppression is structural (admission-time
    // `suppress_persistence`), never queued: no read-log write can be in
    // flight here, so equality is a genuine zero-state rather than a
    // delayed-capture artifact.
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
    if lowercase_hex(native_ce::FULL_GIT_SHA, 40) {
        assert!(names.contains(&"bootstrap") && names.contains(&"standby_status"));
        assert!(
            names.contains(&"records_read"),
            "stable unavailable read schema"
        );
        assert!(!names.contains(&"update_record"), "read-only discovery");
    } else {
        assert_eq!(names, vec!["bootstrap", "standby_status"]);
    }
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

/// Executor-surface standby journey against the real `mcp-stdio --standby`
/// binary with a verified serving generation.
///
/// The configured surface is the default `executor`, so this exercises the
/// `new_standby_read_only` constructor selection (no plan store, sidecar,
/// expiry, telemetry, or trace file) rather than the Legacy native surface.
/// Authoritative standby status uses the same frozen provider in executor
/// `bootstrap.tool_exposure.runtime` and the preserved `standby_status`
/// diagnostic. Both routes use this captured bundle's read-only database.
#[tokio::test]
async fn standby_executor_process_serves_generation_reads_refuses_writes() {
    if !supported_standby_host() {
        return;
    }
    if !lowercase_hex(native_ce::FULL_GIT_SHA, 40) {
        // A `dev`-stamped build cannot create the release-pinned manifest this
        // journey needs; it is not a pass and must be run with a full SHA.
        return;
    }
    const RUN_KEY: &str = "scout-chair-a748b2";
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.db");
    let origin = create_fixture(&source_path).await;
    // The store rejects symlinked ancestors; macOS tempdir may be under the
    // /var alias for /private/var, so pass its canonical root to the runtime.
    let replica_root = std::fs::canonicalize(directory.path())
        .unwrap()
        .join("replica");
    let installed = install_fixture_generation(&replica_root, &source_path, &origin).await;
    let config_path = directory.path().join("standby.json");
    write_runtime_config(&config_path, &replica_root, &origin);
    precreate_generation_lease(&replica_root, &installed.id);
    let before_sql = sql_evidence(&installed.snapshot_path);
    let before_tree = tree_evidence(&replica_root);

    let prepare = json!({
        "operation":"manage_record_policy.replace",
        "arguments":{
            "record_id":FIXTURE_ID,
            "entries":[{"subject":{"kind":"members"},"capability":"view"}],
            "if_policy_revision":"stale",
            "reason":"standby executor refusal probe"
        }
    });
    let execute = json!({
        "operation":"manage_record_policy.replace",
        "plan_id":"forged",
        "target":FIXTURE_ID,
        "effect_summary":"forged"
    });
    let read_arguments = json!({
        "operation":"get_record",
        "arguments":{"ids":[FIXTURE_ID]},
        "run_key":RUN_KEY,
        "format":"json"
    });
    let messages = vec![
        rpc(
            1,
            "initialize",
            json!({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"standby-executor-test","version":"1"}}),
        ),
        rpc(2, "tools/list", json!({})),
        tool_call(3, "bootstrap", json!({"format":"json"})),
        tool_call(4, "records_read", read_arguments.clone()),
        json!({
            "jsonrpc":"2.0",
            "id":5,
            "method":"tools/call",
            "params":{
                "name":"records_read",
                "arguments":read_arguments.clone(),
                "_meta":{
                    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities":{},
                    "io.modelcontextprotocol/clientInfo":{"name":"standby-executor-test","version":"1"}
                }
            }
        }),
        tool_call(6, "access_admin", prepare),
        tool_call(7, "access_admin", execute.clone()),
        tool_call(
            8,
            "records_write",
            json!({"operation":"update_record","arguments":{"id":FIXTURE_ID,"name":"must not change"}}),
        ),
        tool_call(9, "standby_status", json!({"format":"json"})),
    ];
    let output = run_mcp_with_env(&config_path, true, &messages, &[]);
    assert!(output.status.success(), "{output:#?}");
    assert_bounded_verification_diagnostics(&output.stderr);

    // Discovery advertises executor descriptors, not native tools, and the
    // surface marker is the standby one.
    let tools = response(&output, 2)["result"]["tools"].as_array().unwrap();
    let names = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    assert!(names.contains(&"bootstrap"), "{names:?}");
    assert!(names.contains(&"describe_operation"), "{names:?}");
    assert!(names.contains(&"records_read"), "{names:?}");
    assert!(!names.contains(&"create_record"), "{names:?}");
    assert_eq!(
        response(&output, 2)["result"]["_meta"]["nativeExecutor"]["surface"],
        "standby-read-only"
    );

    // Bootstrap carries the authentic provider generation/freshness/hosted
    // authority in both the executor summary and the modern result.
    let bootstrap = successful_tool(&output, 3);
    let runtime = &bootstrap["tool_exposure"]["runtime"];
    assert_eq!(runtime["contract"], "native.standby-status.v1");
    assert_eq!(runtime["mode"], "standby");
    assert_eq!(runtime["read_only"], true);
    assert_eq!(runtime["writes_supported"], false);
    assert_eq!(runtime["mutation_error"], "STANDBY_READ_ONLY");
    assert_eq!(runtime["canonical_authority"], "hosted");
    assert_eq!(runtime["hosted_route_database_id"], HOSTED_ROUTE_ID);
    assert_eq!(runtime["origin_database_id"], origin);
    assert_eq!(runtime["serving_generation"]["generation_id"], installed.id);
    assert_eq!(
        runtime["accepted_generation"]["generation_id"],
        installed.id
    );
    assert_eq!(runtime["freshness"]["target_rpo_seconds"], 300);

    // Legacy and modern cached `records_read.get_record` both delegate a real
    // read over the immutable open and echo the valid run key.
    for id in [4, 5] {
        let result = successful_tool(&output, id);
        assert_eq!(result["records"][0]["id"], FIXTURE_ID, "{result:#}");
        assert_eq!(result["run_context"]["run_key"], RUN_KEY, "{result:#}");
    }

    // Cached prepare, cached execute, and a direct mutation all refuse with
    // the stable read-only contract before plan access.
    for id in [6, 7, 8] {
        let result = &response(&output, id)["result"];
        assert_eq!(result["isError"], true, "{result:#}");
        assert_eq!(
            result["structuredContent"]["error_code"], "STANDBY_READ_ONLY",
            "{result:#}"
        );
    }
    // Connected discovery preserves its status-only diagnostic entry point.
    // The ready diagnostic uses this same bundle's caller, DB and provider.
    let status = &response(&output, 9)["result"];
    assert_eq!(status["isError"], false, "{status:#}");
    assert_eq!(
        status["structuredContent"]["serving_generation"]["generation_id"],
        installed.id
    );

    // No persistent bookkeeping, snapshot bytes, directory state, or plan
    // sidecar changed.
    assert_eq!(sql_evidence(&installed.snapshot_path), before_sql);
    let after_tree = tree_evidence(&replica_root);
    assert_eq!(after_tree, before_tree, "standby changed DB/dir state");
    assert!(
        !after_tree
            .keys()
            .any(|path| path.to_string_lossy().contains("write-plans")),
        "standby created a plan sidecar"
    );

    // Restart: a second activation serves the same generation from the same
    // bytes with no new state.
    let restarted = run_mcp_with_env(
        &config_path,
        true,
        &[
            tool_call(
                1,
                "records_read",
                json!({"operation":"get_record","arguments":{"ids":[FIXTURE_ID]},"format":"json"}),
            ),
            tool_call(2, "access_admin", execute),
        ],
        &[],
    );
    assert!(restarted.status.success(), "{restarted:#?}");
    assert_eq!(
        successful_tool(&restarted, 1)["records"][0]["id"],
        FIXTURE_ID
    );
    assert_eq!(
        response(&restarted, 2)["result"]["structuredContent"]["error_code"],
        "STANDBY_READ_ONLY"
    );
    assert_eq!(tree_evidence(&replica_root), before_tree);
    assert_eq!(sql_evidence(&installed.snapshot_path), before_sql);
}

/// Keep one real newline-framed process alive while an independent fixture
/// publisher accepts snapshots. No network refresh is configured in the child.
struct ConnectedMcp {
    verification_diagnostics: bool,
    refused_handoffs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    replies: std::sync::mpsc::Receiver<Value>,
    stdout: Option<std::thread::JoinHandle<()>>,
    stderr: Option<std::thread::JoinHandle<String>>,
}

impl ConnectedMcp {
    fn start(config: &Path, surface: &str) -> Self {
        let binary = std::env::var_os("NATIVE_STANDBY_TEST_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_mcp-stdio")));
        assert_binary_platform_matches_runner(&binary);
        let child = Command::new(binary)
            .env_clear()
            .env("NATIVE_CE_MCP_SURFACE", surface)
            .arg("--standby")
            .arg(config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut process = Self::from_child(child);
        process.verification_diagnostics = true;
        process
    }

    fn from_child(mut child: std::process::Child) -> Self {
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let refused_handoffs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refusal_count = refused_handoffs.clone();
        let (send, replies) = std::sync::mpsc::channel();
        let stdout = std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line.trim().is_empty() {
                    continue;
                }
                if send
                    .send(serde_json::from_str(&line).expect("real MCP frame"))
                    .is_err()
                {
                    break;
                }
            }
        });
        let stderr = std::thread::spawn(move || {
            use std::io::BufRead;
            let mut diagnostics = String::new();
            for line in std::io::BufReader::new(stderr).lines() {
                let line = line.unwrap();
                // Only a closed fixed event wakes the refusal assertion; the
                // complete strict formatter/field parser runs at process EOF.
                if line.ends_with("standby connected handoff finished ready=false attempt=1") {
                    refusal_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                diagnostics.push_str(&line);
                diagnostics.push('\n');
            }
            diagnostics
        });
        Self {
            verification_diagnostics: false,
            refused_handoffs,
            child,
            stdin,
            replies,
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn exchange(&mut self, message: Value) -> Value {
        // Exercise actual fragmented newline framing while the independent
        // worker may be warming a candidate. Incomplete input must not dispatch
        // or steal the one outstanding request's reply.
        let frame = message.to_string();
        let split = frame.len() / 2;
        for fragment in [&frame.as_bytes()[..split], &frame.as_bytes()[split..]] {
            self.stdin.as_mut().unwrap().write_all(fragment).unwrap();
            self.stdin.as_mut().unwrap().flush().unwrap();
            std::thread::sleep(Duration::from_millis(10));
            assert!(matches!(
                self.replies.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
        }
        self.stdin.as_mut().unwrap().write_all(b"\n").unwrap();
        self.stdin.as_mut().unwrap().flush().unwrap();
        let response = self
            .replies
            .recv_timeout(Duration::from_secs(180))
            .expect("connected MCP response");
        assert_eq!(response["id"], message["id"]);
        response
    }

    fn finish(mut self) {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.stdout.take().unwrap().join().unwrap();
                let stderr = self.stderr.take().unwrap().join().unwrap();
                assert!(status.success(), "{stderr}");
                if self.verification_diagnostics {
                    assert_bounded_verification_receipts(&stderr);
                } else {
                    assert!(stderr.is_empty(), "relay stdio diagnostics: {stderr}");
                }
                break;
            }
            assert!(Instant::now() < deadline, "connected MCP must drain on EOF");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn assert_connected_executor_manifest(response: &Value, descriptors: &Value) -> Value {
    let meta = &response["result"]["_meta"]["nativeExecutor"];
    assert_eq!(meta["surface"], "standby-read-only");
    assert_eq!(
        meta["manifestSha256"],
        hex::encode(Sha256::digest(serde_jcs::to_vec(descriptors).unwrap()))
    );
    assert_eq!(
        meta["descriptorBytes"],
        serde_json::to_vec(descriptors).unwrap().len()
    );
    meta.clone()
}

impl Drop for ConnectedMcp {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn connected_read(surface: &str, id: i64, modern: bool) -> Value {
    let mut request = if surface == "executor" {
        tool_call(
            id,
            "records_read",
            json!({"operation":"get_record", "arguments":{"ids":[FIXTURE_ID]}, "format":"json"}),
        )
    } else {
        tool_call(
            id,
            "get_record",
            json!({"ids":[FIXTURE_ID],"format":"json"}),
        )
    };
    if modern {
        request["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28", "io.modelcontextprotocol/clientCapabilities":{}});
    }
    request
}

fn await_connected_generation(
    child: &mut ConnectedMcp,
    surface: &str,
    generation: &str,
    name: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let reply = child.exchange(connected_read(surface, 10, true));
        let value = &reply["result"]["structuredContent"];
        if value["standby_context"]["serving_generation_id"] == generation {
            assert_eq!(reply["result"]["isError"], false, "{reply}");
            assert_eq!(value["records"][0]["name"], name, "{reply}");
            assert_eq!(value["standby_context"]["mode"], "standby");
            assert_eq!(value["standby_context"]["writes_supported"], false);
            let legacy = child.exchange(connected_read(surface, 11, false));
            assert_eq!(
                legacy["result"]["structuredContent"]["standby_context"]["serving_generation_id"],
                generation
            );
            assert_eq!(
                legacy["result"]["structuredContent"]["records"][0]["name"],
                name
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "accepted generation never became served: {reply}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[tokio::test]
async fn standby_connection_advances_external_acceptance_from_status_only_on_both_surfaces() {
    if !supported_standby_host() || !lowercase_hex(native_ce::FULL_GIT_SHA, 40) {
        return;
    }
    let mut surfaces = vec!["legacy"];
    #[cfg(feature = "mcp-executor-prototype")]
    surfaces.push("executor");
    for surface in surfaces {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.db");
        let origin = create_fixture(&source_path).await;
        let replica_root = std::fs::canonicalize(directory.path())
            .unwrap()
            .join("replica");
        GenerationStore::open(&replica_root, HOSTED_ROUTE_ID, Some(origin.clone())).unwrap();
        let config = directory.path().join("standby.json");
        write_runtime_config(&config, &replica_root, &origin);
        let mut connected = ConnectedMcp::start(&config, surface);
        // Cache discovery ONCE while status-only. The same advertised read
        // schema is usable after handoff, without another list or notification.
        let listing = connected.exchange(rpc(20, "tools/list", json!({})));
        let cached = listing["result"]["tools"].clone();
        let catalogue_meta =
            (surface == "executor").then(|| assert_connected_executor_manifest(&listing, &cached));
        let read_name = if surface == "executor" {
            "records_read"
        } else {
            "get_record"
        };
        let read_descriptor = cached
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == read_name)
            .expect("initial unavailable read catalogue");
        assert!(read_descriptor["description"]
            .as_str()
            .unwrap()
            .contains("STANDBY_STATUS_ONLY"));
        if surface == "executor" {
            assert!(
                read_descriptor["inputSchema"]["properties"]["operation"]["enum"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("get_record"))
            );
        }
        let unavailable = connected.exchange(connected_read(surface, 1, false));
        if let Some(meta) = &catalogue_meta {
            assert_eq!(
                &assert_connected_executor_manifest(&unavailable, &cached),
                meta
            );
        }
        assert_eq!(
            unavailable["result"]["structuredContent"]["error_code"],
            "STANDBY_STATUS_ONLY"
        );
        assert_eq!(
            unavailable["result"]["structuredContent"]["standby_context"]["mode"],
            "status_only"
        );
        assert!(
            unavailable["result"]["structuredContent"]["standby_context"]["serving_generation_id"]
                .is_null()
        );
        let first = install_fixture_generation(&replica_root, &source_path, &origin).await;
        await_connected_generation(
            &mut connected,
            surface,
            &first.id,
            "Standby process fixture",
        );
        let first_pointer = std::fs::read(replica_root.join("accepted/current.json")).unwrap();
        let source = native_ce::open_existing_database(source_path.to_str().unwrap())
            .await
            .unwrap();
        for name in ["external accepted two", "external accepted three"] {
            native_ce::store::update_record(&source, FIXTURE_ID, json!({"name":name}))
                .await
                .unwrap();
            let installed = install_fixture_generation(&replica_root, &source_path, &origin).await;
            await_connected_generation(&mut connected, surface, &installed.id, name);
            if let Some(meta) = &catalogue_meta {
                let read = connected.exchange(connected_read(surface, 23, false));
                assert_eq!(&assert_connected_executor_manifest(&read, &cached), meta);
            }
            let full =
                connected.exchange(tool_call(12, "standby_status", json!({"format":"json"})));
            assert_eq!(
                full["result"]["structuredContent"]["serving_generation"]["generation_id"],
                installed.id
            );
            assert_eq!(
                full["result"]["structuredContent"]["accepted_generation"]["generation_id"],
                installed.id
            );
        }
        let served_before_refusal = connected.exchange(connected_read(surface, 21, false))
            ["result"]["structuredContent"]["standby_context"]["serving_generation_id"]
            .clone();
        let account = native_ce::identity::resolve_stdio_account_identity(&source, None)
            .await
            .unwrap();
        native_ce::authorization::replace_explicit_policy(&source, &account, "native:root", vec![])
            .await
            .unwrap();
        native_ce::store::unset_facet(&source, "native:root", "owner")
            .await
            .unwrap();
        assert_eq!(
            native_ce::authorization::effective_capability(
                &source,
                native_ce::authorization::Principal::bound(&account, true),
                "native:root",
            )
            .await
            .unwrap(),
            native_ce::authorization::Capability::None
        );
        let refused = install_fixture_generation(&replica_root, &source_path, &origin).await;
        assert_ne!(json!(refused.id), served_before_refusal);
        // Acceptance has already run every FULL check. Actual caller readiness
        // must still refuse this candidate, preserving the old readable bundle.
        let deadline = Instant::now() + Duration::from_secs(180);
        while connected
            .refused_handoffs
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            assert!(
                Instant::now() < deadline,
                "candidate readiness must complete with refusal"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        let still_served = connected.exchange(connected_read(surface, 22, true));
        assert_eq!(
            still_served["result"]["structuredContent"]["standby_context"]["serving_generation_id"],
            served_before_refusal
        );
        // A malformed descriptor and then an older pointer cannot turn hot
        // handoff into startup fallback. Existing captured generation survives.
        let before = connected.exchange(connected_read(surface, 13, false));
        let final_generation = before["result"]["structuredContent"]["standby_context"]
            ["serving_generation_id"]
            .clone();
        for pointer in [b"malformed".to_vec(), first_pointer] {
            std::fs::write(replica_root.join("accepted/current.json"), pointer).unwrap();
            std::thread::sleep(Duration::from_millis(1100));
            let after = connected.exchange(connected_read(surface, 14, true));
            assert_eq!(
                after["result"]["structuredContent"]["standby_context"]["serving_generation_id"],
                final_generation
            );
            assert_eq!(
                after["result"]["structuredContent"]["records"][0]["name"],
                "external accepted three"
            );
        }
        let refusal = if surface == "executor" {
            tool_call(
                15,
                "records_write",
                json!({"operation":"update_record","arguments":{"id":FIXTURE_ID,"name":"must refuse"}}),
            )
        } else {
            tool_call(
                15,
                "update_record",
                json!({"id":FIXTURE_ID,"name":"must refuse"}),
            )
        };
        let write = connected.exchange(refusal);
        assert_eq!(write["result"]["isError"], true, "{write}");
        assert_eq!(
            write["result"]["structuredContent"]["error_code"],
            "STANDBY_READ_ONLY"
        );
        assert_eq!(
            write["result"]["structuredContent"]["standby_context"]["serving_generation_id"],
            final_generation
        );
        source.close().await;
        connected.finish();
        assert!(!tree_evidence(&replica_root)
            .keys()
            .any(|path| path.to_string_lossy().contains("write-plans")));
    }
}

#[cfg(target_os = "linux")]
struct RelayFixture {
    child: std::process::Child,
    stderr: Option<std::thread::JoinHandle<String>>,
}

#[cfg(target_os = "linux")]
impl RelayFixture {
    fn start(directory: &Path, consumer: &Path, config: &Path, account: &str) -> (Self, PathBuf) {
        use std::os::unix::process::CommandExt;
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/native-local-daemon.py");
        let socket = directory.join("relay/standby.sock");
        let mut child = Command::new("python3")
            .arg(script)
            .arg("serve")
            .arg("--socket")
            .arg(&socket)
            .arg("--scratch")
            .arg(directory.join("scratch"))
            .arg("--consumer")
            .arg(consumer)
            .arg("--config")
            .arg(config)
            .arg("--account")
            .arg(account)
            // A leaked controller would make the official child refuse startup.
            .env("NATIVE_CE_DB", directory.join("must-not-create.db"))
            .env(
                "NATIVE_CE_STANDBY_REFRESH_CONFIG",
                directory.join("must-not-load.json"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let stderr = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).unwrap();
            String::from_utf8(bytes).unwrap()
        });
        let mut relay = Self {
            child,
            stderr: Some(stderr),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        while !socket.exists() {
            assert!(
                relay.child.try_wait().unwrap().is_none(),
                "fixture relay rejected status-only startup"
            );
            assert!(Instant::now() < deadline, "fixture relay did not listen");
            std::thread::sleep(Duration::from_millis(25));
        }
        (relay, socket)
    }

    fn stop(mut self) {
        self.interrupt();
        let stderr = self.stderr.take().unwrap().join().unwrap();
        assert!(
            stderr.contains("kernel connected mode=status_only"),
            "{stderr}"
        );
        assert!(
            !stderr.contains("standby refresh is unavailable"),
            "refresh environment must be cleared"
        );
    }

    fn interrupt(&mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGINT);
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
                self.child.wait().unwrap();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for RelayFixture {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            self.interrupt();
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mcp-executor-prototype"))]
#[tokio::test]
async fn configured_owner_relay_keeps_one_stdio_connection_across_external_generations() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !lowercase_hex(native_ce::FULL_GIT_SHA, 40) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let source_path = root.join("source.db");
    let origin = create_fixture(&source_path).await;
    let source = native_ce::open_existing_database(source_path.to_str().unwrap())
        .await
        .unwrap();
    let account = native_ce::identity::resolve_stdio_account_identity(&source, None)
        .await
        .unwrap();
    let replica_root = root.join("replica");
    GenerationStore::open(&replica_root, HOSTED_ROUTE_ID, Some(origin.clone())).unwrap();
    let config = root.join("standby.json");
    write_runtime_config(&config, &replica_root, &origin);
    let consumer = std::env::var_os("NATIVE_STANDBY_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_mcp-stdio")));
    let (relay, socket) = RelayFixture::start(&root, &consumer, &config, &account);
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(std::fs::metadata(&socket).unwrap().uid(), unsafe {
        libc::getuid()
    });
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/native-local-daemon.py");
    let child = Command::new("python3")
        .env_clear()
        .arg(script)
        .arg("stdio")
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut connected = ConnectedMcp::from_child(child);
    let listing = connected.exchange(rpc(20, "tools/list", json!({})));
    let cached = listing["result"]["tools"].clone();
    // The owner relay projects bootstrap/audit schemas. Its receipt explicitly
    // retains the official child's manifest, rather than hashing local schemas.
    let catalogue_meta =
        listing["result"]["_meta"]["nativeLocalRelay"]["upstreamNativeExecutor"].clone();
    assert_eq!(catalogue_meta["surface"], "standby-read-only");
    assert!(listing["result"]["_meta"]["nativeExecutor"].is_null());
    let read_descriptor = cached
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "records_read")
        .expect("status-only relay exposes unavailable read schemas");
    assert!(read_descriptor["description"]
        .as_str()
        .unwrap()
        .contains("STANDBY_STATUS_ONLY"));
    assert!(
        read_descriptor["inputSchema"]["properties"]["operation"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("get_record"))
    );
    let metadata = connected.exchange(tool_call(
        1,
        "bootstrap",
        json!({"format":"json","run_key":"ignored-local"}),
    ));
    assert_eq!(
        metadata["result"]["structuredContent"]["workspace_reads_available"],
        false
    );
    assert_eq!(
        metadata["result"]["structuredContent"]["standby_context"]["mode"],
        "status_only"
    );
    assert!(
        metadata["result"]["structuredContent"]["standby_context"]["serving_generation_id"]
            .is_null()
    );
    for name in ["relay accepted one", "relay accepted two"] {
        native_ce::store::update_record(&source, FIXTURE_ID, json!({"name":name}))
            .await
            .unwrap();
        let generation = install_fixture_generation(&replica_root, &source_path, &origin).await;
        await_connected_generation(&mut connected, "executor", &generation.id, name);
        let read = connected.exchange(connected_read("executor", 23, true));
        assert_eq!(read["result"]["_meta"]["nativeExecutor"], catalogue_meta);
        for tool in ["bootstrap", "standby_status"] {
            let metadata = connected.exchange(tool_call(
                2,
                tool,
                json!({"format":"json","parent_key":"ignored-parent"}),
            ));
            assert_eq!(
                metadata["result"]["structuredContent"]["workspace_reads_available"],
                true
            );
            assert_eq!(
                metadata["result"]["structuredContent"]["standby_context"]["serving_generation_id"],
                generation.id
            );
            assert!(
                metadata["result"]["structuredContent"]["standby_context"]["freshness"]
                    ["age_seconds"]
                    .as_u64()
                    .is_some()
            );
            assert_eq!(
                metadata["result"]["structuredContent"]["full_audit_available_on_this_connection"],
                false
            );
            assert!(metadata["result"]["structuredContent"]
                .get("run_key")
                .is_none());
        }
    }
    let refusal = connected.exchange(tool_call(
        3,
        "records_write",
        json!({"operation":"update_record","arguments":{"id":FIXTURE_ID,"name":"must refuse"}}),
    ));
    assert_eq!(
        refusal["result"]["structuredContent"]["error_code"],
        "STANDBY_READ_ONLY"
    );
    let audit = connected.exchange(tool_call(
        4,
        "system_read",
        json!({"operation":"engine_info","arguments":{}}),
    ));
    assert_eq!(
        audit["result"]["structuredContent"]["error_code"],
        "LOCAL_FULL_AUDIT_SEPARATE"
    );
    connected.finish();
    relay.stop();
    assert!(!root.join("must-not-create.db").exists());
    source.close().await;
}
