use super::*;
use crate::native_cli::node_client::MAX_REPLY_BYTES;
use crate::native_cli::setup::tests::*;
use crate::native_cli::setup::{setup, NODE_FILE};
use crate::node::NodeConfig;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixListener;

const ROUTE: &str = "route-1";
const SECRET_BODY: &str = "SECRET-BODY-TEXT-must-never-be-printed";

fn service_line() -> Option<ServiceInfo> {
    Some(ServiceInfo {
        line: "installed, running, enabled (/home/u/.config/systemd/user/native.service)".into(),
        installed: Some(true),
        running: Some(true),
    })
}

fn options(config_dir: &Path) -> StatusOptions {
    StatusOptions {
        config_dir: config_dir.to_path_buf(),
        timeout: Duration::from_secs(5),
        service: service_line(),
    }
}

// ---- a real node against the fake hosted server ---------------------------------------

pub(crate) struct Running {
    pub(crate) hosted: Arc<Hosted>,
    pub(crate) install: Install,
    pub(crate) socket: PathBuf,
    /// Held for its `Drop`, which stops the node.
    pub(crate) _node: NodeThread,
}

/// The node on its own thread with a large stack, as it runs in production:
/// its futures are too deep for a test thread's default stack in a debug build.
pub(crate) struct NodeThread {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
    finished: Arc<std::sync::atomic::AtomicBool>,
}

impl NodeThread {
    pub(crate) fn start(config: NodeConfig) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = finished.clone();
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    tokio::select! {
                        _ = crate::node::serve(config) => {}
                        _ = stopped => {}
                    }
                });
                done.store(true, std::sync::atomic::Ordering::SeqCst);
            })
            .unwrap();
        Self {
            stop: Some(stop),
            handle: Some(handle),
            finished,
        }
    }

    fn is_finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for NodeThread {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// One journalled write to plant before the node starts.
pub(crate) struct Seed {
    id: String,
    seq: u64,
    state: &'static str,
    accepted: String,
    title: String,
}

impl Seed {
    fn pending(seq: u64, accepted: &str, title: &str) -> Self {
        Self {
            id: format!("held-{seq:04}"),
            seq,
            state: "pending",
            accepted: accepted.to_owned(),
            title: title.to_owned(),
        }
    }
}

/// Write held writes, as the node would have journalled them.
fn seed_writes(socket_directory: &Path, seeds: &[Seed]) {
    use std::os::unix::fs::DirBuilderExt as _;
    let journal = socket_directory.join("journal");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&journal)
        .unwrap();
    for seed in seeds {
        let entry = json!({
            "version": 1,
            "id": seed.id,
            "state": seed.state,
            "received_at": seed.accepted,
            "received_unix_ms": 1_792_656_000_000u64 + seed.seq,
            "updated_at": seed.accepted,
            "executor": "records_write",
            "operation": "create_record",
            "tool": "call_executor",
            "run_key": "run-1",
            "attempts": 0,
            "arguments_digest": "d",
            "arguments_bytes": 99,
            "arguments": {"name": seed.title, "body": SECRET_BODY},
            "seq": seed.seq,
            "title": seed.title,
            "hold_reason": "hosted_unreachable",
            "envelope": {"run_key": "run-1", "format": "json"},
        });
        let path = journal.join(format!("{}.json", seed.id));
        std::fs::write(&path, serde_json::to_vec(&entry).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// Set up, give the node an accepted copy, and serve it. `hosted_down_first`
/// shuts the fake hosted server before the node starts; `held` seeds a write.
async fn start_node(hosted_down_first: bool, seeds: &[Seed]) -> Running {
    start_node_with(hosted_down_first, seeds, None).await
}

/// As [`start_node`], with an engine answering hosted's tool calls from the start.
pub(crate) async fn start_node_with(
    hosted_down_first: bool,
    seeds: &[Seed],
    engine: Option<crate::native_cli::setup::tests::McpHook>,
) -> Running {
    let hosted = start_hosted(&[(ROUTE, "owner", "Native HQ")]).await;
    *hosted.engine.lock().unwrap() = engine;
    let install = signed_in(&hosted, 3600).await;
    setup(super::super::setup::tests::options(&hosted, &install))
        .await
        .unwrap();
    let config: NodeConfig =
        serde_json::from_slice(&std::fs::read(install.config.join(NODE_FILE)).unwrap()).unwrap();
    {
        let standby = crate::standby::StandbyRuntimeConfig::from_json(
            &std::fs::read(install.config.join("standby.json")).unwrap(),
        )
        .unwrap();
        let store = crate::standby::generation_store::GenerationStore::open(
            &standby.replica_root,
            &standby.hosted_route_database_id,
            Some(standby.origin_database_id.clone()),
        )
        .unwrap();
        let (snapshot, manifest) =
            crate::standby::generation_store::tests::stage(&store, hosted.db(), "status-fixture")
                .await;
        store
            .install_staged(
                &snapshot,
                &manifest,
                &crate::standby::generation_store::tests::observed(),
            )
            .await
            .unwrap();
    }
    if !seeds.is_empty() {
        seed_writes(&config.socket_directory, seeds);
    }
    if hosted_down_first {
        hosted.shut_down();
    }
    // A local build is stamped `dev` and cannot serve a copy; see the setup test.
    crate::node::set_test_consumer_identity(Some(
        crate::standby::generation_store::tests::observed(),
    ));
    let socket = config.socket_path();
    let node = NodeThread::start(config);
    for _ in 0..200 {
        if tokio::net::UnixStream::connect(&socket).await.is_ok() {
            break;
        }
        assert!(!node.is_finished(), "the node exited early");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Running {
        hosted,
        install,
        socket,
        _node: node,
    }
}

/// Collect until `done` holds (the node's background work needs a moment).
async fn collect_until(running: &Running, done: impl Fn(&Report) -> bool) -> Report {
    let mut last = None;
    for _ in 0..150 {
        let report = collect(options(&running.install.config)).await;
        if done(&report) {
            return report;
        }
        last = Some(report);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the report never reached the expected state: {:#?}", last);
}

/// A client call through the node, as an agent would make: it makes the node
/// try hosted (and notice it is down).
async fn poke_hosted(socket: &Path) {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read);
    for request in [
        json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"poke","version":"1"},"capabilities":{}}}),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_executor","arguments":{"executor":"records_read","operation":"get_record","arguments":{"ids":["x"]}}}}),
    ] {
        write
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let mut reply = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), lines.read_line(&mut reply)).await;
    }
}

#[tokio::test]
async fn online_status_names_the_mode_the_copy_and_the_account() {
    let running = start_node(false, &[]).await;
    let report = collect_until(&running, |r| {
        r.local_copy
            .as_ref()
            .is_some_and(|c| c.accepted && c.age_seconds.is_some())
    })
    .await;
    assert_eq!(report.node.state, NodeState::Running);
    let mode = report.mode.as_ref().unwrap();
    assert_eq!(mode.hosted, "reachable");
    assert!(
        mode.summary.starts_with("hosted reachable"),
        "{}",
        mode.summary
    );
    let copy = report.local_copy.as_ref().unwrap();
    assert_eq!(copy.age_basis.as_deref(), Some("accepted_generation"));
    assert_eq!(copy.rpo_seconds, 300);
    assert_eq!(report.account.as_deref(), Some(ACCOUNT));
    let text = render_text(&report);
    assert!(text.contains("Mode:        hosted reachable"), "{text}");
    assert!(
        text.contains("Local copy:") && text.contains("accepted copy synced"),
        "{text}"
    );
    assert!(
        text.contains(ACCOUNT) && text.contains("Service:     installed, running"),
        "{text}"
    );
    assert!(text.contains("Held writes: none waiting"), "{text}");
    // A local build's copy is not serving yet, which is honest "degraded".
    assert_eq!((report.health, report.exit_code), (Health::Degraded, 1));
    assert!(report.problems.iter().any(|p| p.contains("not serving")));
    // No token ever appears.
    assert!(!text.contains(BEARER) && !serde_json::to_string(&report).unwrap().contains(BEARER));
}

#[tokio::test]
async fn an_unreachable_hosted_is_reported_with_the_local_copy_age() {
    let running = start_node(false, &[]).await;
    collect_until(&running, |r| {
        r.local_copy.as_ref().is_some_and(|c| c.accepted)
    })
    .await;
    running.hosted.shut_down();
    poke_hosted(&running.socket).await;
    let report = collect_until(&running, |r| {
        r.mode.as_ref().is_some_and(|m| m.hosted == "unreachable")
    })
    .await;
    let mode = report.mode.as_ref().unwrap();
    assert!(
        mode.summary.starts_with("hosted unreachable"),
        "{}",
        mode.summary
    );
    let copy = report.local_copy.as_ref().unwrap();
    assert!(copy.accepted && copy.age_seconds.is_some(), "{copy:?}");
    let text = render_text(&report);
    assert!(text.contains("Mode:        hosted unreachable"), "{text}");
    assert!(text.contains("synced") && text.contains("ago"), "{text}");
    assert_eq!((report.health, report.exit_code), (Health::Degraded, 1));
    assert!(report.problems.iter().any(|p| p.contains("unreachable")));
}

#[tokio::test]
async fn a_held_write_is_listed_without_its_body() {
    let running = start_node(
        true,
        &[Seed::pending(
            1,
            "2026-10-22T08:00:00.000Z",
            "Quarterly plan",
        )],
    )
    .await;
    let report = collect_until(&running, |r| {
        r.held_writes.as_ref().is_some_and(|h| h.waiting > 0)
    })
    .await;
    let held = report.held_writes.as_ref().unwrap();
    assert_eq!((held.waiting, held.pending), (1, 1), "{held:#?}");
    assert_eq!(
        held.oldest_accepted_at.as_deref(),
        Some("2026-10-22T08:00:00.000Z")
    );
    assert_eq!(held.counts.get("pending"), Some(&1));
    let write = &held.recent[0];
    assert_eq!(write.operation, "create_record");
    assert_eq!(write.title.as_deref(), Some("Quarterly plan"));
    assert_eq!(write.state, "pending");
    assert_eq!(write.reason.as_deref(), Some("hosted_unreachable"));
    let text = render_text(&report);
    assert!(
        text.contains(
            "Held writes: 1 waiting (1 pending); oldest accepted 2026-10-22T08:00:00.000Z"
        ),
        "{text}"
    );
    assert!(
        text.contains("- create_record \"Quarterly plan\": pending (hosted_unreachable)"),
        "{text}"
    );
    // The body is in the journal file but in neither rendering.
    let json = serde_json::to_string(&report).unwrap();
    assert!(!text.contains(SECRET_BODY) && !json.contains(SECRET_BODY));
    assert_eq!((report.health, report.exit_code), (Health::Degraded, 1));
    assert!(report.problems.iter().any(|p| p.contains("held write")));
}

// ---- when the node cannot be read -----------------------------------------------------------

async fn configured_install() -> (Arc<Hosted>, Install, NodeConfig) {
    let hosted = start_hosted(&[(ROUTE, "owner", "Native HQ")]).await;
    let install = signed_in(&hosted, 3600).await;
    setup(super::super::setup::tests::options(&hosted, &install))
        .await
        .unwrap();
    let config: NodeConfig =
        serde_json::from_slice(&std::fs::read(install.config.join(NODE_FILE)).unwrap()).unwrap();
    (hosted, install, config)
}

#[tokio::test]
async fn no_node_running_is_exit_2_with_a_message_that_says_how_to_start_it() {
    let (_hosted, install, config) = configured_install().await;
    let report = collect(options(&install.config)).await;
    assert_eq!(report.node.state, NodeState::NoSocket);
    assert_eq!((report.health, report.exit_code), (Health::Down, 2));
    let text = render_text(&report);
    assert!(
        text.starts_with("Native node: the node is not running (no socket at "),
        "{text}"
    );
    assert!(text.contains("native service install"), "{text}");
    assert!(report.mode.is_none() && report.local_copy.is_none() && report.held_writes.is_none());
    assert!(text.contains("Service:"), "the service line is still shown");

    // A stale socket file: nothing listens on it.
    std::fs::create_dir_all(&config.socket_directory).unwrap();
    drop(UnixListener::bind(config.socket_path()).unwrap());
    let report = collect(options(&install.config)).await;
    assert_eq!(
        report.node.state,
        NodeState::StaleSocket,
        "{:?}",
        report.node
    );
    assert_eq!(report.exit_code, 2);
    assert!(render_text(&report).contains("nothing listens"));
}

#[tokio::test]
async fn missing_and_invalid_node_json_are_misconfiguration() {
    let dir = tempfile::tempdir().unwrap();
    let report = collect(options(dir.path())).await;
    assert_eq!(
        (report.node.state, report.exit_code),
        (NodeState::NoConfig, 2)
    );
    assert!(render_text(&report).contains("native setup"));
    std::fs::write(dir.path().join(NODE_FILE), b"{\"hosted_base_url\": 7}").unwrap();
    let report = collect(options(dir.path())).await;
    assert_eq!(
        (report.node.state, report.exit_code),
        (NodeState::InvalidConfig, 2)
    );
    std::fs::write(dir.path().join(NODE_FILE), b"not json").unwrap();
    assert_eq!(
        collect(options(dir.path())).await.node.state,
        NodeState::InvalidConfig
    );
}

/// A stand-in node on the real socket path that behaves as scripted.
async fn fake_node(config: &NodeConfig, behaviour: &'static str) -> tokio::task::JoinHandle<()> {
    std::fs::create_dir_all(&config.socket_directory).unwrap();
    let listener = UnixListener::bind(config.socket_path()).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read);
                let mut line = String::new();
                if behaviour == "close" {
                    return;
                }
                while lines.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let request: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    line.clear();
                    if behaviour == "silent" {
                        continue;
                    }
                    if behaviour == "flood" {
                        // A reply with no end: far more than the reader will hold.
                        let blob = vec![b'x'; 256 * 1024];
                        let _ = write.write_all(&blob).await;
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        return;
                    }
                    let id = request["id"].clone();
                    let name = request["params"]["name"].as_str().unwrap_or("");
                    // Before every real reply: a notification, and a late reply to
                    // some earlier request that carries other contents.
                    let stale = behaviour == "stale_first";
                    if stale {
                        for noise in [
                            json!({"jsonrpc":"2.0","method":"notifications/message","params":{"data":"hello"}}),
                            json!({"jsonrpc":"2.0","id":987654,"result":{"isError":true,"content":[{"type":"text","text":"STALE"}],"structuredContent":{"hosted":{"health":"auth_refused"}}}}),
                        ] {
                            let _ = write.write_all(format!("{noise}\n").as_bytes()).await;
                        }
                    }
                    if let Some(kind) = behaviour.strip_prefix("old_").or(stale.then_some("full")) {
                        // A node from before `order`: lists oldest first, and does not say so.
                        let structured = match name {
                            "standby_status" => Some(serving_status(42, "fresh")),
                            "node_status" => {
                                let total: u64 = if kind == "truncated" { 12 } else { 3 };
                                let shown = total.min(5);
                                let mut node = quiet_node("reachable");
                                node["held_writes"] = json!({
                                    "matched": total, "shown": shown, "counts": {"pending": total},
                                    "writes": (1..=shown).map(|n| json!({"state":"pending","operation":"create_record","title":format!("Write {n}"),"accepted_at":"2026-10-22T08:00:00Z"})).collect::<Vec<_>>(),
                                });
                                node["queue"] = json!({"pending": total, "bytes": 1, "oldest_accepted_at": "2026-10-22T08:00:00Z"});
                                Some(node)
                            }
                            _ => None,
                        };
                        let reply = match structured {
                            Some(structured) => {
                                json!({"jsonrpc":"2.0","id":id,"result":{"isError":false,"content":[],"structuredContent":structured}})
                            }
                            None => {
                                json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-03-26"}})
                            }
                        };
                        let _ = write.write_all(format!("{reply}\n").as_bytes()).await;
                        continue;
                    }
                    let reply = match (request["method"].as_str(), name, behaviour) {
                        (Some("initialize"), _, _) => {
                            json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-03-26"}})
                        }
                        (_, "node_status", "no_status") => {
                            json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,"content":[{"type":"text","text":"status is not available\nbecause reasons"}]}})
                        }
                        _ => {
                            json!({"jsonrpc":"2.0","id":id,"result":{"isError":false,"content":[],"structuredContent":{}}})
                        }
                    };
                    let _ = write.write_all(format!("{reply}\n").as_bytes()).await;
                }
            });
        }
    })
}

#[tokio::test]
async fn a_node_that_rejects_stays_silent_or_cannot_report_is_its_own_state() {
    for (behaviour, expected) in [
        ("close", NodeState::PeerRejected),
        ("silent", NodeState::NotAnswering),
        ("no_status", NodeState::StatusUnavailable),
    ] {
        let (_hosted, install, config) = configured_install().await;
        let task = fake_node(&config, behaviour).await;
        let mut opts = options(&install.config);
        opts.timeout = Duration::from_millis(500);
        let report = collect(opts).await;
        assert_eq!(
            report.node.state, expected,
            "{behaviour}: {:?}",
            report.node
        );
        assert_eq!(
            (report.health, report.exit_code),
            (Health::Down, 2),
            "{behaviour}"
        );
        let text = render_text(&report);
        match expected {
            NodeState::PeerRejected => assert!(text.contains("UID"), "{text}"),
            NodeState::NotAnswering => assert!(text.contains("not answering"), "{text}"),
            _ => assert!(
                text.contains(
                    "could not report its status: status is not available because reasons"
                ),
                "{text}"
            ),
        }
        task.abort();
    }
}

#[tokio::test]
async fn a_late_reply_to_another_request_is_never_taken_for_the_answer() {
    // The same node, with and without stray replies and notifications before
    // each answer: the reports must be identical, and none of the stray content
    // may appear in them.
    let mut reports = Vec::new();
    for behaviour in ["old_full", "stale_first"] {
        let (_hosted, install, config) = configured_install().await;
        let task = fake_node(&config, behaviour).await;
        let report = collect(options(&install.config)).await;
        task.abort();
        let mut value = serde_json::to_value(&report).unwrap();
        // Each run has its own directories.
        value["node"]["config"] = Value::Null;
        value["node"]["socket"] = Value::Null;
        reports.push(value);
    }
    assert_eq!(reports[0], reports[1]);
    let text = reports[1].to_string();
    assert!(
        !text.contains("STALE") && !text.contains("auth_refused"),
        "{text}"
    );
    assert_eq!(reports[1]["node"]["state"], "running");
}

// ---- the report from canned replies (the node's real field names) ------------------------------

fn serving_status(age: u64, freshness: &str) -> Value {
    json!({
        "contract": "native.standby-status.v1", "mode": "standby",
        "observed_at": "2026-10-22T10:00:00.000Z",
        "freshness": {"state": freshness, "age_seconds": age, "target_rpo_seconds": 300,
            "target_refresh_interval_seconds": 60, "beyond_rpo": age > 300},
        "serving_generation": {"generation_id": "g", "captured_at": "2026-10-22T09:59:00.000Z", "synced_at": "2026-10-22T09:59:18.000Z"},
        "accepted_generation": {"generation_id": "g", "synced_at": "2026-10-22T09:59:18.000Z"},
        "refresh": {"controller_available": true, "diagnostics": "available", "consecutive_failure_count": 0, "last_failure_class": null, "last_failure": null, "last_attempt_at": "2026-10-22T09:59:58.000Z"},
        "consumer_compatible": true,
        "degraded": false, "degraded_reasons": [],
        "account_id": ACCOUNT,
    })
}

fn quiet_node(hosted: &str) -> Value {
    json!({
        "account_id": ACCOUNT,
        "entry_counts": {},
        "held_writes": {"matched": 0, "shown": 0, "counts": {}, "writes": []},
        "queue": {"pending": 0, "bytes": 0, "oldest_accepted_at": null},
        "hosted": {"health": hosted, "checked": true, "revision_unsupported": hosted == "revision_unsupported"},
    })
}

fn report_of(standby: Value, node: Value) -> Report {
    build(
        Path::new("/c/node.json"),
        Path::new("/d/run/node.sock"),
        Observed {
            standby: Ok(standby),
            node,
        },
        service_line(),
    )
}

#[test]
fn a_serving_fresh_copy_with_nothing_waiting_is_healthy_and_exit_0() {
    let report = report_of(serving_status(42, "fresh"), quiet_node("reachable"));
    assert_eq!((report.health, report.exit_code), (Health::Healthy, 0));
    assert!(report.problems.is_empty());
    let text = render_text(&report);
    assert!(
        text.starts_with(&format!("Native node: running, healthy ({ACCOUNT})")),
        "{text}"
    );
    assert!(
        text.contains("Mode:        hosted reachable; local copy serving"),
        "{text}"
    );
    assert!(
        text.contains("Local copy:  synced 42s ago (fresh, within the 5m 0s target)"),
        "{text}"
    );
    assert!(text.contains("Held writes: none waiting"));
}

#[test]
fn unreachable_hosted_with_a_serving_copy_says_it_serves_local_reads() {
    let report = report_of(serving_status(95, "fresh"), quiet_node("unreachable"));
    assert_eq!((report.health, report.exit_code), (Health::Degraded, 1));
    let text = render_text(&report);
    assert!(
        text.contains("Mode:        hosted unreachable; serving local reads"),
        "{text}"
    );
    assert!(text.contains("synced 1m 35s ago"), "{text}");
}

#[test]
fn a_copy_past_the_rpo_is_stale_and_auth_refusal_is_its_own_mode() {
    let report = report_of(
        serving_status(900, "beyond_rpo"),
        quiet_node("auth_refused"),
    );
    let copy = report.local_copy.as_ref().unwrap();
    assert_eq!(copy.stale, Some(true));
    assert_eq!(report.exit_code, 1);
    let text = render_text(&report);
    assert!(text.contains("stale, beyond the 5m 0s target"), "{text}");
    assert!(
        text.contains("Mode:        hosted refused the node's credentials"),
        "{text}"
    );
    assert!(report.problems.iter().any(|p| p.contains("native login")));
}

#[test]
fn while_following_is_paused_age_alone_is_not_called_fresh() {
    let mut status = serving_status(30, "fresh");
    status["node_health"] = json!({"state": "revision_unsupported", "local_reads_stale": true});
    status["degraded_reasons"] = json!(["revision_unsupported"]);
    status["degraded"] = json!(true);
    let report = report_of(status, quiet_node("revision_unsupported"));
    let copy = report.local_copy.as_ref().unwrap();
    assert!(copy.following_paused);
    assert_eq!(
        copy.stale,
        Some(true),
        "paused following is stale whatever the age"
    );
    assert_eq!(
        copy.freshness, "stale_revision",
        "never `fresh` while paused"
    );
    assert_eq!(copy.age_seconds, Some(30), "the actual age is kept");
    let text = render_text(&report);
    assert!(text.contains("following is paused"), "{text}");
    assert!(!text.contains("fresh, within"), "{text}");
    assert_eq!(report.exit_code, 1);
}

#[test]
fn the_last_refresh_failure_is_shown_with_its_class() {
    let mut status = serving_status(120, "fresh");
    status["refresh"]["last_failure_class"] = json!("network");
    status["refresh"]["last_failure"] = json!("hosted did not answer\nthe head probe");
    status["refresh"]["consecutive_failure_count"] = json!(3);
    let report = report_of(status, quiet_node("reachable"));
    let text = render_text(&report);
    assert!(
        text.contains(
            "last refresh failed (network): hosted did not answer the head probe [3 in a row]"
        ),
        "{text}"
    );
    assert_eq!(report.exit_code, 1);
}

#[test]
fn held_writes_show_counts_the_newest_five_and_never_bodies() {
    let mut node = quiet_node("reachable");
    let writes: Vec<Value> = (1..=8)
        .map(|n| {
            json!({"id": format!("w{n}"), "state": if n % 2 == 0 { "hosted_pending" } else { "pending" },
                "operation": "create_record", "title": format!("Write {n}"),
                "accepted_at": format!("2026-10-22T08:0{n}:00Z"), "reason": "hosted_unreachable",
                "detail": SECRET_BODY, "arguments": {"body": SECRET_BODY}, "seq": n})
        })
        .collect();
    node["held_writes"] = json!({"matched": 8, "shown": 8, "counts": {"pending": 4, "hosted_pending": 4}, "writes": writes});
    node["queue"] =
        json!({"pending": 4, "bytes": 10, "oldest_accepted_at": "2026-10-22T08:01:00Z"});
    node["entry_counts"] = json!({"uncertain": 2});
    let report = report_of(serving_status(10, "fresh"), node);
    let held = report.held_writes.as_ref().unwrap();
    assert_eq!(held.pending, 4);
    assert_eq!(held.counts.get("hosted_pending"), Some(&4));
    assert_eq!(held.counts.get("uncertain"), Some(&2));
    assert_eq!(held.waiting, 4 + 4 + 2);
    assert_eq!(held.recent.len(), 5);
    assert_eq!(held.recent[0].title.as_deref(), Some("Write 8"));
    assert_eq!(held.recent[4].title.as_deref(), Some("Write 4"));
    assert_eq!(held.more, 3);
    let text = render_text(&report);
    assert!(text.contains("Held writes: 10 waiting (4 pending, 4 hosted_pending, 2 uncertain); oldest accepted 2026-10-22T08:01:00Z"), "{text}");
    assert!(text.contains("... and 3 more"), "{text}");
    assert!(
        !text.contains(SECRET_BODY)
            && !serde_json::to_string(&report)
                .unwrap()
                .contains(SECRET_BODY)
    );
    assert_eq!(report.exit_code, 1);
}

#[test]
fn a_node_without_a_local_copy_reports_that_honestly() {
    let report = build(
        Path::new("/c/node.json"),
        Path::new("/d/run/node.sock"),
        Observed {
            standby: Err("node standby is not configured".into()),
            node: json!({"account_id": ACCOUNT, "held_writes": {"matched": 0, "counts": {}, "writes": []}, "queue": {"pending": 0}}),
        },
        None,
    );
    assert!(report.local_copy.is_none());
    let mode = report.mode.as_ref().unwrap();
    assert_eq!(mode.hosted, "unknown");
    assert!(
        mode.summary
            .contains("no local copy (node standby is not configured)"),
        "{}",
        mode.summary
    );
    assert_eq!(report.exit_code, 1);
    assert!(render_text(&report).contains("Local copy:  none"));
}

#[test]
fn human_ages_are_short() {
    for (seconds, expected) in [
        (0, "0s"),
        (59, "59s"),
        (60, "1m 0s"),
        (312, "5m 12s"),
        (7380, "2h 3m"),
        (93_600, "1d 2h"),
    ] {
        assert_eq!(human_age(seconds), expected);
    }
}

// ---- --json -------------------------------------------------------------------------------------

/// The `native.status.v1` shape: every key present, with its type.
fn assert_schema(value: &Value) {
    let object = value.as_object().expect("an object");
    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    for key in [
        "schema",
        "health",
        "exit_code",
        "node",
        "mode",
        "local_copy",
        "held_writes",
        "account",
        "service",
        "problems",
    ] {
        assert!(keys.contains(&key), "missing {key}: {value}");
    }
    assert_eq!(object.len(), 10, "no extra top-level keys: {keys:?}");
    assert_eq!(value["schema"], SCHEMA);
    assert!(["healthy", "degraded", "down"].contains(&value["health"].as_str().unwrap()));
    assert!(value["exit_code"].is_i64() && value["problems"].is_array());
    let node = value["node"].as_object().unwrap();
    for key in ["state", "detail", "config", "socket"] {
        assert!(node.contains_key(key), "node.{key}");
    }
    assert!(value["node"]["state"].is_string());
    if value["node"]["state"] == "running" {
        let mode = &value["mode"];
        for key in ["hosted", "serving", "status_only_reason", "summary"] {
            assert!(mode.get(key).is_some(), "mode.{key}");
        }
        let held = &value["held_writes"];
        for key in [
            "waiting",
            "pending",
            "oldest_accepted_at",
            "counts",
            "recent",
            "more",
            "recent_available",
        ] {
            assert!(held.get(key).is_some(), "held_writes.{key}");
        }
        assert!(
            held["waiting"].is_u64()
                && held["counts"].is_object()
                && held["recent"].is_array()
                && held["recent_available"].is_boolean()
        );
        for write in held["recent"].as_array().unwrap() {
            for key in ["operation", "title", "state", "reason", "accepted_at"] {
                assert!(write.get(key).is_some(), "recent.{key}");
            }
            assert_eq!(
                write.as_object().unwrap().len(),
                5,
                "only the named fields: {write}"
            );
        }
        if let Some(copy) = value["local_copy"].as_object() {
            for key in [
                "serving",
                "accepted",
                "freshness",
                "age_seconds",
                "age_basis",
                "rpo_seconds",
                "stale",
                "following_paused",
                "last_refresh_failure",
                "consecutive_failures",
                "degraded_reasons",
            ] {
                assert!(copy.contains_key(key), "local_copy.{key}");
            }
        }
    } else {
        assert!(
            value["mode"].is_null()
                && value["local_copy"].is_null()
                && value["held_writes"].is_null()
        );
    }
}

#[test]
fn json_output_matches_the_schema_for_healthy_degraded_and_down() {
    let healthy = serde_json::to_value(report_of(
        serving_status(42, "fresh"),
        quiet_node("reachable"),
    ))
    .unwrap();
    assert_schema(&healthy);
    assert_eq!(
        (healthy["health"].as_str(), healthy["exit_code"].as_i64()),
        (Some("healthy"), Some(0))
    );
    assert_eq!(healthy["local_copy"]["age_seconds"], 42);
    assert_eq!(healthy["local_copy"]["stale"], false);
    assert_eq!(healthy["mode"]["hosted"], "reachable");
    assert_eq!(healthy["account"], ACCOUNT);

    let mut node = quiet_node("unreachable");
    node["held_writes"]["writes"] = json!([{"state":"pending","operation":"create_record","title":"T","reason":"hosted_unreachable","accepted_at":"2026-10-22T08:00:00Z","arguments":{"body":SECRET_BODY}}]);
    node["held_writes"]["matched"] = json!(1);
    node["queue"]["pending"] = json!(1);
    let degraded =
        serde_json::to_value(report_of(serving_status(400, "beyond_rpo"), node)).unwrap();
    assert_schema(&degraded);
    assert_eq!(
        (degraded["health"].as_str(), degraded["exit_code"].as_i64()),
        (Some("degraded"), Some(1))
    );
    assert_eq!(degraded["local_copy"]["stale"], true);
    assert!(!degraded.to_string().contains(SECRET_BODY));

    let down = serde_json::to_value(report_down(
        down(NodeState::NoSocket, "not running", None, None),
        None,
    ))
    .unwrap();
    assert_schema(&down);
    assert_eq!(
        (down["health"].as_str(), down["exit_code"].as_i64()),
        (Some("down"), Some(2))
    );
    assert_eq!(down["node"]["state"], "no_socket");
}

#[tokio::test]
async fn json_from_a_real_node_matches_the_schema() {
    let running = start_node(
        true,
        &[Seed::pending(
            1,
            "2026-10-22T08:00:00.000Z",
            "Quarterly plan",
        )],
    )
    .await;
    let report = collect_until(&running, |r| {
        r.held_writes.as_ref().is_some_and(|h| h.waiting > 0)
    })
    .await;
    let value = serde_json::to_value(&report).unwrap();
    assert_schema(&value);
    assert_eq!(value["node"]["state"], "running");
    assert_eq!(value["held_writes"]["recent"][0]["title"], "Quarterly plan");
    assert!(!value.to_string().contains(SECRET_BODY));
}

// ---- review fixes -------------------------------------------------------------------------------

/// Remove or replace the value at `pointer` in a JSON document.
fn without(mut value: Value, pointer: &str) -> Value {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    let parent_value = if parent.is_empty() {
        Some(&mut value)
    } else {
        value.pointer_mut(parent)
    };
    parent_value.unwrap().as_object_mut().unwrap().remove(key);
    value
}

#[test]
fn healthy_needs_positive_evidence_of_every_condition() {
    let healthy = report_of(serving_status(42, "fresh"), quiet_node("reachable"));
    assert_eq!((healthy.health, healthy.exit_code), (Health::Healthy, 0));

    // A missing field is a problem with a reason, never a pass.
    for (pointer, expected) in [
        (
            "/degraded",
            "did not report whether the local copy is degraded",
        ),
        (
            "/degraded_reasons",
            "did not list the local copy's degradation reasons",
        ),
        (
            "/consumer_compatible",
            "reader compatibility is not confirmed",
        ),
        (
            "/refresh/controller_available",
            "refresh controller is not available",
        ),
        (
            "/refresh/diagnostics",
            "refresh diagnostics are not reported",
        ),
        (
            "/refresh/consecutive_failure_count",
            "did not report refresh failures",
        ),
        ("/account_id", "did not report its account"),
    ] {
        let mut node = quiet_node("reachable");
        let status = if pointer == "/account_id" {
            node = without(node, "/account_id");
            without(serving_status(42, "fresh"), "/account_id")
        } else {
            without(serving_status(42, "fresh"), pointer)
        };
        let report = report_of(status, node);
        assert_eq!(
            (report.health, report.exit_code),
            (Health::Degraded, 1),
            "{pointer}"
        );
        assert!(
            report.problems.iter().any(|p| p.contains(expected)),
            "{pointer}: {:?}",
            report.problems
        );
    }
    // Node-level facts.
    for (pointer, expected) in [
        ("/hosted", "did not report hosted health"),
        ("/held_writes", "did not report its held writes"),
        ("/queue", "did not report its held writes"),
    ] {
        let report = report_of(
            serving_status(42, "fresh"),
            without(quiet_node("reachable"), pointer),
        );
        assert_eq!(report.exit_code, 1, "{pointer}");
        assert!(
            report.problems.iter().any(|p| p.contains(expected)),
            "{pointer}: {:?}",
            report.problems
        );
    }
    // A "fresh" label with no usable age is only a claim: not stale, not
    // healthy, and said to be missing.
    for age in [Value::Null, json!("42")] {
        let mut status = serving_status(42, "fresh");
        status["freshness"]["age_seconds"] = age;
        let report = report_of(status, quiet_node("reachable"));
        let copy = report.local_copy.as_ref().unwrap();
        assert_eq!(copy.freshness, "fresh");
        assert_eq!((copy.age_seconds, copy.stale), (None, None));
        assert_eq!((report.health, report.exit_code), (Health::Degraded, 1));
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("did not report the local copy's age")),
            "{:?}",
            report.problems
        );
    }
    // And a freshness that is not "fresh" at all stays unconfirmed.
    let mut status = serving_status(42, "unavailable");
    status["freshness"]["age_seconds"] = Value::Null;
    let report = report_of(status, quiet_node("reachable"));
    assert_eq!(report.exit_code, 1);
    assert!(report
        .problems
        .iter()
        .any(|p| p.contains("freshness is not confirmed")));
}

#[test]
fn nothing_waiting_needs_every_count_it_rests_on() {
    // Empty or partial held_writes / queue objects do not say "none waiting".
    for (label, mutate) in [
        ("empty held_writes", ("/held_writes", json!({}))),
        ("empty queue", ("/queue", json!({}))),
        (
            "held_writes without counts",
            ("/held_writes", json!({"matched": 0, "writes": []})),
        ),
        (
            "held_writes without matched",
            ("/held_writes", json!({"counts": {}, "writes": []})),
        ),
        (
            "held_writes without writes",
            ("/held_writes", json!({"matched": 0, "counts": {}})),
        ),
        ("queue without pending", ("/queue", json!({"bytes": 0}))),
        ("pending not a number", ("/queue", json!({"pending": "0"}))),
    ] {
        let mut node = quiet_node("reachable");
        let (pointer, value) = mutate;
        *node.pointer_mut(pointer).unwrap() = value;
        let report = report_of(serving_status(42, "fresh"), node);
        assert_eq!(
            (report.health, report.exit_code),
            (Health::Degraded, 1),
            "{label}"
        );
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("did not report its held writes")),
            "{label}: {:?}",
            report.problems
        );
    }
    // The complete, empty shape is what "none waiting" means.
    let report = report_of(serving_status(42, "fresh"), quiet_node("reachable"));
    assert_eq!(report.exit_code, 0);
    assert!(render_text(&report).contains("Held writes: none waiting"));
}

#[test]
fn every_degradation_flag_the_node_reports_is_a_problem_by_name() {
    let mut status = serving_status(42, "fresh");
    status["degraded"] = json!(true);
    status["degraded_reasons"] = json!([
        "database_busy",
        "refresh_controller_unavailable",
        "reader_not_upgraded",
        "refresh_authentication_failing"
    ]);
    status["refresh"]["controller_available"] = json!(false);
    let report = report_of(status, quiet_node("reachable"));
    assert_eq!(report.exit_code, 1);
    for flag in [
        "local copy: database_busy",
        "local copy: refresh_controller_unavailable",
        "local copy: reader_not_upgraded",
        "local copy: refresh_authentication_failing",
        "the refresh controller is not available",
        "the local copy reports itself degraded",
    ] {
        assert!(
            report.problems.iter().any(|p| p == flag),
            "{flag}: {:?}",
            report.problems
        );
    }
    assert_eq!(
        report.local_copy.as_ref().unwrap().degraded_reasons.len(),
        4
    );
}

#[test]
fn before_its_first_probe_hosted_is_not_yet_checked_not_reachable() {
    let mut node = quiet_node("reachable");
    node["hosted"]["checked"] = json!(false);
    let report = report_of(serving_status(42, "fresh"), node);
    let mode = report.mode.as_ref().unwrap();
    assert_eq!(mode.hosted, "not_checked");
    assert!(
        mode.summary.starts_with("hosted not yet checked"),
        "{}",
        mode.summary
    );
    assert_eq!((report.health, report.exit_code), (Health::Degraded, 1));
    assert!(report
        .problems
        .iter()
        .any(|p| p.contains("not been checked yet")));
    // A node that does not say at all is not assumed to have checked.
    let report = report_of(
        serving_status(42, "fresh"),
        without(quiet_node("reachable"), "/hosted/checked"),
    );
    assert_eq!(report.mode.as_ref().unwrap().hosted, "not_checked");
    assert_eq!(report.exit_code, 1);
}

#[test]
fn a_stale_revision_is_stale_with_its_real_age_never_fresh() {
    for (label, status, node) in [
        (
            "local_reads_stale only",
            {
                let mut s = serving_status(30, "fresh");
                s["node_health"] = json!({"state": "reachable", "local_reads_stale": true});
                s
            },
            quiet_node("reachable"),
        ),
        ("hosted revision flag only", serving_status(30, "fresh"), {
            let mut n = quiet_node("reachable");
            n["hosted"]["revision_unsupported"] = json!(true);
            n
        }),
        (
            "revision_unsupported health",
            serving_status(30, "fresh"),
            quiet_node("revision_unsupported"),
        ),
    ] {
        let report = report_of(status, node);
        let copy = report.local_copy.as_ref().unwrap();
        assert_eq!(copy.stale, Some(true), "{label}");
        assert_eq!(copy.freshness, "stale_revision", "{label}");
        assert_eq!(copy.age_seconds, Some(30), "{label}");
        assert!(copy.following_paused, "{label}");
        let text = render_text(&report);
        assert!(
            text.contains("synced 30s ago (stale: following is paused"),
            "{label}: {text}"
        );
        assert!(!text.contains("fresh"), "{label}: {text}");
        assert_eq!(report.exit_code, 1, "{label}");
    }
}

#[tokio::test]
async fn node_json_errors_never_echo_the_file_only_where_the_problem_is() {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in [
        (
            "unknown field",
            r#"{"hosted_base_url":"https://h.example","SECRET_SENTINEL_FIELD_9f3a":1}"#,
        ),
        (
            "wrong type",
            r#"{"hosted_base_url":"https://h.example","home_id":"h","db_id":"d","credential_file":"/c","socket_directory":"/s","account_id":["SECRET_SENTINEL_VALUE_9f3a"]}"#,
        ),
        ("not json", "SECRET_SENTINEL_RAW_9f3a is not json"),
    ] {
        std::fs::write(dir.path().join(NODE_FILE), content).unwrap();
        let report = collect(options(dir.path())).await;
        assert_eq!(report.node.state, NodeState::InvalidConfig, "{name}");
        let detail = report.node.detail.clone().unwrap();
        assert!(detail.contains("line 1, column"), "{name}: {detail}");
        let everything = format!(
            "{}\n{}",
            render_text(&report),
            serde_json::to_string(&report).unwrap()
        );
        assert!(
            !everything.contains("SECRET_SENTINEL"),
            "{name}: {everything}"
        );
    }
}

#[tokio::test]
async fn a_peer_that_sends_more_than_the_limit_is_cut_off_at_once() {
    let (_hosted, install, config) = configured_install().await;
    let task = fake_node(&config, "flood").await;
    let started = std::time::Instant::now();
    let report = collect_with(
        options(&install.config),
        Limits {
            max_reply: 4096,
            peer_uid: crate::node::current_uid(),
        },
    )
    .await;
    assert_eq!(
        report.node.state,
        NodeState::NotAnswering,
        "{:?}",
        report.node
    );
    assert!(
        report
            .node
            .detail
            .as_deref()
            .unwrap()
            .contains("larger than 4096 bytes"),
        "{:?}",
        report.node
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "gave up as soon as the limit was passed"
    );
    assert_eq!(report.exit_code, 2);
    task.abort();
}

#[tokio::test]
async fn a_socket_whose_peer_is_another_user_is_refused_before_anything_is_sent() {
    let (_hosted, install, config) = configured_install().await;
    // The server runs as this user, so name a different one as the expected peer.
    let listener = UnixListener::bind({
        std::fs::create_dir_all(&config.socket_directory).unwrap();
        config.socket_path()
    })
    .unwrap();
    let received = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = received.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stream);
                let mut line = String::new();
                if lines.read_line(&mut line).await.unwrap_or(0) > 0 {
                    seen.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            });
        }
    });
    let report = collect_with(
        options(&install.config),
        Limits {
            max_reply: MAX_REPLY_BYTES,
            peer_uid: crate::node::current_uid() + 1,
        },
    )
    .await;
    assert_eq!(
        report.node.state,
        NodeState::PermissionDenied,
        "{:?}",
        report.node
    );
    assert!(report
        .node
        .detail
        .as_deref()
        .unwrap()
        .contains("another user"));
    assert_eq!(report.exit_code, 2);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !received.load(std::sync::atomic::Ordering::SeqCst),
        "nothing was sent to that peer"
    );
    task.abort();
}

/// Ask the node directly for `node_status`.
async fn raw_node_status(socket: &Path, arguments: Value) -> Value {
    let stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read);
    let mut reply = String::new();
    for request in [
        json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"raw","version":"1"},"capabilities":{}}}),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"node_status","arguments":arguments}}),
    ] {
        write
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        reply.clear();
        lines.read_line(&mut reply).await.unwrap();
    }
    serde_json::from_str::<Value>(&reply).unwrap()["result"]["structuredContent"].clone()
}

#[tokio::test]
async fn the_newest_writes_are_found_even_beyond_five_hundred() {
    let seeds: Vec<Seed> = (1..=600)
        .map(|n| {
            Seed::pending(
                n,
                &format!("2026-10-22T08:{:02}:{:02}.000Z", n / 60, n % 60),
                &format!("Write {n}"),
            )
        })
        .collect();
    let running = start_node(true, &seeds).await;
    let report = collect_until(&running, |r| {
        r.held_writes.as_ref().is_some_and(|h| h.waiting >= 600)
    })
    .await;
    let held = report.held_writes.as_ref().unwrap();
    assert_eq!(held.waiting, 600);
    assert_eq!(held.recent.len(), 5);
    let titles: Vec<_> = held
        .recent
        .iter()
        .map(|w| w.title.clone().unwrap())
        .collect();
    assert_eq!(
        titles,
        [
            "Write 600",
            "Write 599",
            "Write 598",
            "Write 597",
            "Write 596"
        ]
    );
    assert_eq!(held.more, 595);
    assert_eq!(
        held.oldest_accepted_at.as_deref(),
        Some("2026-10-22T08:00:01.000Z")
    );
    // The default order is unchanged for every other caller.
    let default_order = raw_node_status(&running.socket, json!({"limit": 3})).await;
    assert_eq!(default_order["held_writes"]["order"], "oldest_first");
    assert_eq!(
        default_order["held_writes"]["writes"][0]["title"],
        "Write 1"
    );
    let newest = raw_node_status(
        &running.socket,
        json!({"limit": 3, "order": "newest_first"}),
    )
    .await;
    assert_eq!(newest["held_writes"]["order"], "newest_first");
    assert_eq!(newest["held_writes"]["writes"][0]["title"], "Write 600");
    assert_eq!(newest["held_writes"]["matched"], 600);
}

#[tokio::test]
async fn the_oldest_write_is_taken_across_every_waiting_state() {
    let mut older = Seed::pending(1, "2026-10-22T07:00:00.000Z", "Older, already with hosted");
    older.state = "hosted_pending";
    let newer = Seed::pending(2, "2026-10-22T08:00:00.000Z", "Newer, still queued");
    let running = start_node(true, &[older, newer]).await;
    let report = collect_until(&running, |r| {
        r.held_writes.as_ref().is_some_and(|h| h.waiting >= 2)
    })
    .await;
    let held = report.held_writes.as_ref().unwrap();
    assert_eq!((held.pending, held.waiting), (1, 2));
    assert_eq!(held.counts.get("hosted_pending"), Some(&1));
    // The send queue's oldest is 08:00; the oldest write needing attention is 07:00.
    assert_eq!(
        held.oldest_accepted_at.as_deref(),
        Some("2026-10-22T07:00:00.000Z")
    );
}

async fn report_from_old_node(behaviour: &'static str) -> Report {
    let (_hosted, install, config) = configured_install().await;
    let task = fake_node(&config, behaviour).await;
    let report = collect(options(&install.config)).await;
    task.abort();
    report
}

#[tokio::test]
async fn an_old_node_that_ignores_order_never_has_its_oldest_writes_called_the_newest() {
    // 12 held, the node sent its oldest five without saying how they are ordered.
    let report = report_from_old_node("old_truncated").await;
    assert_eq!(report.node.state, NodeState::Running, "{:?}", report.node);
    let held = report.held_writes.as_ref().unwrap();
    assert_eq!(held.waiting, 12);
    assert!(!held.recent_available);
    assert!(held.recent.is_empty(), "{:?}", held.recent);
    let text = render_text(&report);
    assert!(
        text.contains(
            "recent writes unavailable from this node version; restart the node after upgrading"
        ),
        "{text}"
    );
    assert!(
        !text.contains("Write 1") && !text.contains("Write 5"),
        "{text}"
    );
    assert_eq!(
        serde_json::to_value(&report).unwrap()["held_writes"]["recent_available"],
        false
    );

    // Only three held: the whole list came back, so its tail is genuinely the newest.
    let report = report_from_old_node("old_complete").await;
    let held = report.held_writes.as_ref().unwrap();
    assert!(held.recent_available);
    let titles: Vec<_> = held
        .recent
        .iter()
        .map(|w| w.title.clone().unwrap())
        .collect();
    assert_eq!(titles, ["Write 3", "Write 2", "Write 1"]);
    assert!(!render_text(&report).contains("unavailable from this node version"));
}
