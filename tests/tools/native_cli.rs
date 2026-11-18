//! `native` binary slice 1: local stdio serve, help/version, node passthrough.
#![cfg(feature = "mcp-executor-prototype")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

fn mcp_stdio_binary() -> &'static str {
    // `cargo check --all-targets` does not inject executable paths; tests do.
    #[allow(clippy::option_env_unwrap)]
    option_env!("CARGO_BIN_EXE_mcp-stdio")
        .expect("the mcp-stdio binary path must be supplied when this test runs")
}

struct StdioClient {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: Receiver<String>,
    next_id: u64,
}

impl StdioClient {
    fn native(directory: &std::path::Path, db_name: &str) -> Self {
        Self::native_with_umask(directory, db_name, None)
    }

    fn native_with_umask(
        directory: &std::path::Path,
        db_name: &str,
        umask: Option<libc::mode_t>,
    ) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_native"));
        command
            .env_clear()
            .env("NATIVE_CE_MCP_SURFACE", "executor")
            .current_dir(directory)
            .arg("mcp")
            .arg("--local")
            .arg(directory.join(db_name))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // Hermetic hostile umask for the child only: runs after fork, before
        // exec, so the test process (and its parallel neighbours) keep theirs.
        if let Some(mask) = umask {
            use std::os::unix::process::CommandExt as _;
            unsafe {
                command.pre_exec(move || {
                    libc::umask(mask);
                    Ok(())
                });
            }
        }
        if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Self {
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin: Some(stdin),
            responses,
            next_id: 0,
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let request = json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params});
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{request}").unwrap();
        stdin.flush().unwrap();
        let line = self
            .responses
            .recv_timeout(Duration::from_secs(30))
            .unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], self.next_id, "{response}");
        assert!(response.get("error").is_none(), "{response}");
        response["result"].clone()
    }

    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.rpc("tools/call", json!({"name":tool,"arguments":arguments}))
    }

    fn run_key(&self, bootstrap: &Value) -> String {
        let structured = &bootstrap["structuredContent"];
        structured["run"]["run_key"]
            .as_str()
            .or_else(|| structured["session"]["run_key"].as_str())
            .unwrap()
            .to_string()
    }
}

impl Drop for StdioClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn native_mcp_local_initialises_creates_and_reads_back() {
    let directory = tempfile::tempdir().unwrap();
    let mut client = StdioClient::native(directory.path(), "slice1.db");
    client.rpc(
        "initialize",
        json!({
            "protocolVersion":"2024-11-05", "capabilities":{},
            "clientInfo":{"name":"native-slice1-test","version":"1"}
        }),
    );
    let bootstrap = client.call("bootstrap", json!({"format":"json"}));
    assert_eq!(bootstrap["isError"], false, "{bootstrap}");
    let run_key = client.run_key(&bootstrap);
    let created = client.call(
        "records_write",
        json!({
            "operation":"create_record",
            "arguments":{
                "type":"Document","kind":"note",
                "name":"slice-1 note","body":"hello slice 1",
                "reason":"native slice-1 integration test"
            },
            "run_key":run_key, "format":"json"
        }),
    );
    assert_eq!(created["isError"], false, "{created}");
    let id = created["structuredContent"]["id"].as_str().unwrap();
    let read = client.call(
        "records_read",
        json!({
            "operation":"get_record",
            "arguments":{"ids":[id]},
            "run_key":run_key, "format":"json"
        }),
    );
    assert_eq!(read["isError"], false, "{read}");
    let records = read["structuredContent"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{read}");
    assert_eq!(records[0]["body"], json!("hello slice 1"), "{read}");
    assert!(directory.path().join("slice1.db").exists());
}
fn native_output(args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_native"))
        .args(args)
        .env_clear()
        .output()
        .unwrap();
    let status = output.status;
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    (status, stdout, stderr)
}

#[test]
fn native_help_and_version_cover_every_subcommand() {
    let (status, stdout, _) = native_output(&["--help"]);
    assert!(status.success());
    assert!(stdout.contains("usage: native"), "{stdout}");
    assert!(stdout.contains("mcp --local"), "{stdout}");
    assert!(stdout.contains("node serve"), "{stdout}");
    let (status, stdout, _) = native_output(&["--version"]);
    assert!(status.success());
    assert!(stdout.starts_with("native "), "{stdout}");
    for args in [
        &["mcp", "--help"][..],
        &["node", "--help"][..],
        &["node", "serve", "--help"][..],
        &["node", "connect", "--help"][..],
    ] {
        let (status, stdout, _) = native_output(args);
        assert!(status.success(), "{args:?}");
        assert!(stdout.contains("usage: native"), "{stdout}");
    }
    let (status, _, stderr) = native_output(&["bogus"]);
    assert_eq!(status.code(), Some(2), "{stderr}");
}

/// `native node connect` pipes bytes exactly like `mcp-stdio node connect`.
/// Drive both shims against the same scripted socket server and compare:
/// non-empty stdin must arrive byte-identical, and stdout must match.
#[test]
fn native_node_connect_matches_mcp_stdio_byte_for_byte() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    const INPUT: &[u8] =
        b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"ping\",\"params\":{}}\n";
    const RESPONSE: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n";

    fn scripted_exchange(binary: &str, input: &[u8]) -> (bool, Vec<u8>, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("node.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (sender, receiver) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            let mut seen = Vec::new();
            // The shim half-closes after stdin EOF; read until then, then reply.
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            use std::io::Write as _;
            stream.write_all(RESPONSE).unwrap();
            sender.send(seen).unwrap();
        });
        let mut child = Command::new(binary)
            .arg("node")
            .arg("connect")
            .arg("--socket")
            .arg(&socket)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        server.join().unwrap();
        let seen = receiver.recv_timeout(Duration::from_secs(20)).unwrap();
        (output.status.success(), output.stdout, seen)
    }

    let (native_ok, native_out, native_seen) =
        scripted_exchange(env!("CARGO_BIN_EXE_native"), INPUT);
    let (stdio_ok, stdio_out, stdio_seen) = scripted_exchange(mcp_stdio_binary(), INPUT);
    assert!(native_ok, "native node connect failed");
    assert!(stdio_ok, "mcp-stdio node connect failed");
    assert_eq!(native_seen, INPUT, "native relayed stdin lossy");
    assert_eq!(stdio_seen, INPUT, "mcp-stdio relayed stdin lossy");
    assert_eq!(native_out, stdio_out, "shim bytes differ");
    assert_eq!(native_out, RESPONSE.to_vec());
}

/// Both CLI entry points must survive a server close, reconnect in the same
/// process, and still exit cleanly once the agent closes stdin.
#[test]
fn node_connect_reconnects_when_the_server_closes_first() {
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;

    const RESPONSE: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"gone\":true}}\n";
    const REQUEST: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"ping\"}\n";
    const RESUMED: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":10,\"result\":{\"back\":true}}\n";

    fn reconnect_then_close(binary: &str) -> (bool, Vec<u8>) {
        struct Cleanup(Child);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("node.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (reconnected, connection) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let accept = || {
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                loop {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            break stream;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "shim did not connect");
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    }
                }
            };
            let mut first = accept();
            first.write_all(RESPONSE).unwrap();
            drop(first);

            let mut second = accept();
            second
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            reconnected.send(()).unwrap();
            let mut reader = BufReader::new(second.try_clone().unwrap());
            let mut request = Vec::new();
            reader.read_until(b'\n', &mut request).unwrap();
            assert_eq!(request, REQUEST);
            second.write_all(RESUMED).unwrap();
            // Closing agent stdin still half-closes the socket and drains replies.
            let mut remaining = Vec::new();
            reader.read_to_end(&mut remaining).unwrap();
            assert!(remaining.is_empty(), "unexpected replay after reconnect");
        });
        let mut child = Cleanup(
            Command::new(binary)
                .arg("node")
                .arg("connect")
                .arg("--socket")
                .arg(&socket)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdin = child.0.stdin.take().unwrap();
        connection
            .recv_timeout(Duration::from_secs(20))
            .expect("shim did not reconnect while stdin remained open");
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "shim exited on server EOF"
        );
        stdin.write_all(REQUEST).unwrap();
        drop(stdin);

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{binary} did not exit after agent stdin closed"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = Vec::new();
        child
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        server.join().unwrap();
        (status.success(), stdout)
    }

    let (native_ok, native_out) = reconnect_then_close(env!("CARGO_BIN_EXE_native"));
    let (stdio_ok, stdio_out) = reconnect_then_close(mcp_stdio_binary());
    assert!(native_ok, "native did not exit cleanly after stdin EOF");
    assert!(stdio_ok, "mcp-stdio did not exit cleanly after stdin EOF");
    assert_eq!(native_out, stdio_out, "shim bytes differ");
    assert_eq!(native_out, [RESPONSE, RESUMED].concat());
}

/// `native mcp --local` locks down what it creates even under a hostile
/// umask: a nested database directory lands at 0700 and the database plus
/// its WAL files at 0600. The child runs under umask 0 (via a fork-time hook
/// that touches only the child), so 0644/0755 would show without the fix.
#[cfg(unix)]
#[test]
fn native_mcp_local_locks_down_database_and_directory_modes() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().unwrap();
    let mut client =
        StdioClient::native_with_umask(directory.path(), "vault/data/perms.db", Some(0));
    client.rpc(
        "initialize",
        json!({
            "protocolVersion":"2024-11-05", "capabilities":{},
            "clientInfo":{"name":"native-perms-test","version":"1"}
        }),
    );
    let bootstrap = client.call("bootstrap", json!({"format":"json"}));
    assert_eq!(bootstrap["isError"], false, "{bootstrap}");
    let run_key = client.run_key(&bootstrap);
    let created = client.call(
        "records_write",
        json!({
            "operation":"create_record",
            "arguments":{
                "type":"Document","kind":"note",
                "name":"perms probe","body":"mode check",
                "reason":"native slice-1 permissions test"
            },
            "run_key":run_key, "format":"json"
        }),
    );
    assert_eq!(created["isError"], false, "{created}");

    let mode = |path: &std::path::Path| {
        std::fs::metadata(path)
            .unwrap_or_else(|_| panic!("missing {}", path.display()))
            .permissions()
            .mode()
            & 0o777
    };
    let db = directory.path().join("vault/data/perms.db");
    assert_eq!(mode(&directory.path().join("vault/data")), 0o700);
    assert_eq!(mode(&db), 0o600);
    // Committed frames sit in the WAL while the server holds its pools open,
    // with shared memory alongside it. Both inherit the process umask.
    for suffix in ["-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{}{suffix}", db.display()));
        assert_eq!(mode(&sidecar), 0o600, "{sidecar:?}");
    }
}

/// Exercise the real foreground entry point: recovery must not depend on a
/// systemd/launchd definition, and a re-exec must release the socket lock.
#[tokio::test]
async fn native_restart_reexecutes_foreground_node_and_diagnoses_without_a_service_unit() {
    use native_ce::native_cli::{recovery, status};
    use std::os::unix::fs::PermissionsExt;
    struct Node(Child);
    impl Drop for Node {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    // macOS spells its temporary directory through /var, a symlink. Use its
    // canonical parent so the fixture preserves the node's no-symlink guard.
    let temporary_root = std::env::temp_dir().canonicalize().unwrap();
    let directory = tempfile::tempdir_in(temporary_root).unwrap();
    let credential = directory.path().join("credential");
    std::fs::write(&credential, "fixture-token-do-not-collect").unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = directory.path().join("node.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "hosted_base_url":"http://127.0.0.1:1", "home_id":"home-1", "db_id":"route-1",
            "credential_file":credential, "socket_directory":directory.path().join("socket"),
            "account_id":"acct_fixture", "disk_floor_bytes":0
        }))
        .unwrap(),
    )
    .unwrap();
    let stderr = directory.path().join("node-stderr.log");
    std::fs::write(&stderr, "isolated node stderr marker\n").unwrap();
    let stderr_file = std::fs::OpenOptions::new()
        .append(true)
        .open(&stderr)
        .unwrap();
    let mut node = Node(
        Command::new(env!("CARGO_BIN_EXE_native"))
            .args(["node", "serve", "--config"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr_file)
            .spawn()
            .unwrap(),
    );
    let before = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(value) =
                recovery::control(&config, "native/node/diagnostics", Duration::from_secs(1)).await
            {
                break value;
            }
            assert!(node.0.try_wait().unwrap().is_none(), "fixture node exited");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(before["restart_supported"], true);
    assert!(before["async_tasks"]["pending"].is_array());
    recovery::restart(&config, Duration::from_secs(30))
        .await
        .unwrap();
    let after = recovery::control(&config, "native/node/diagnostics", Duration::from_secs(5))
        .await
        .unwrap();
    assert_ne!(before["instance_id"], after["instance_id"]);
    assert_eq!(
        before["pid"], after["pid"],
        "restart should replace, not detach, the process"
    );
    let report = status::collect(status::StatusOptions {
        config_path: config.clone(),
        timeout: Duration::from_secs(1),
        service: None,
    })
    .await;
    let path = directory.path().join("diagnosis.json");
    recovery::diagnose(&config, &report, Some(path.clone()))
        .await
        .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("fixture-token-do-not-collect"));
    let bundle: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bundle["contract"], "native.node-diagnosis.v1");
    assert_eq!(bundle["recent_log"]["source"], "stderr_file");
    assert!(bundle["recent_log"]["text"]
        .as_str()
        .unwrap()
        .contains("isolated node stderr marker"));
    assert!(bundle["live_diagnostics"]["async_tasks"]["pending"].is_array());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        recovery::diagnose(&config, &report, Some(path))
            .await
            .is_err(),
        "never overwrite a diagnosis file"
    );
}

/// Exercise argv[0] dispatch through a real symlink to the native executable.
#[cfg(unix)]
fn legacy_alias(directory: &std::path::Path) -> std::path::PathBuf {
    let alias = directory.join("mcp-stdio");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_native"), &alias).unwrap();
    alias
}

/// Bound every exit assertion while retaining stdin: ordinary runtime teardown
/// would otherwise wait forever for Tokio's uncancellable blocking input read.
#[cfg(unix)]
fn wait_for_legacy_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("legacy alias did not exit within ten seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn native_legacy_alias_initializes_and_reads_local_mcp() {
    let directory = tempfile::tempdir().unwrap();
    let alias = legacy_alias(directory.path());
    let mut command = Command::new(alias);
    command
        .env_clear()
        .env("NATIVE_CE_MCP_SURFACE", "executor")
        // This positional legacy argument would be rejected by native's parser.
        .arg(directory.path().join("legacy.db"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut client = StdioClient::spawn(command);
    let initialized = client.rpc(
        "initialize",
        json!({"protocolVersion":"2024-11-05", "capabilities":{},
            "clientInfo":{"name":"legacy-alias-test","version":"1"}}),
    );
    assert_eq!(
        initialized["serverInfo"]["version"],
        native_ce::engine_version_string()
    );
    let bootstrap = client.call("bootstrap", json!({"format":"json"}));
    assert_eq!(bootstrap["isError"], false, "{bootstrap}");
    let run_key = client.run_key(&bootstrap);
    let read = client.call(
        "records_read",
        json!({"operation":"get_record", "arguments":{"ids":["native:root"]},
            "run_key":run_key, "format":"json"}),
    );
    assert_eq!(read["isError"], false, "{read}");
    let records = read["structuredContent"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{read}");
    assert_eq!(records[0]["id"], "native:root", "{read}");
    assert!(directory.path().join("legacy.db").is_file());
    drop(client.stdin.take());
    assert!(wait_for_legacy_exit(&mut client.child).success());
}

#[cfg(unix)]
#[test]
fn native_legacy_alias_node_connect_invalid_arguments_exit_with_stdin_open() {
    use std::io::Read as _;
    let directory = tempfile::tempdir().unwrap();
    let alias = legacy_alias(directory.path());
    for args in [
        vec!["node", "connect", "--socket"],
        vec![
            "node",
            "connect",
            "--socket",
            "unused.sock",
            "--expect-account",
            "owner",
        ],
    ] {
        let mut child = Command::new(&alias)
            .args(&args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Leave the pipe open throughout the bounded wait.
        let status = wait_for_legacy_exit(&mut child);
        assert_eq!(status.code(), Some(1), "{args:?}");
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(
            stderr.contains("mcp-stdio node: configuration or transport failed:"),
            "{stderr}"
        );
    }
}

#[cfg(unix)]
#[test]
fn native_legacy_alias_node_connect_binding_refusal_exits_with_stdin_open() {
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;
    let directory = tempfile::tempdir().unwrap();
    let alias = legacy_alias(directory.path());
    let socket = directory.path().join("node.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let accept = || loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "alias never connected"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        let mut stream = accept();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["method"], "native/connection/bind");
        writeln!(
            stream,
            "{}",
            json!({"jsonrpc":"2.0", "id":request["id"],
            "result":{"contract":"native.connection-binding.v1", "binding":request["params"]}})
        )
        .unwrap();
        // Receive a client frame so the shim has started reading stdin, then
        // force reconnect. The next blocking stdin read remains pending.
        line.clear();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let ping: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ping["method"], "ping");
        drop(stream);
        let mut stream = accept();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        line.clear();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["method"], "native/connection/bind");
        writeln!(
            stream,
            "{}",
            json!({"jsonrpc":"2.0", "id":request["id"],
            "error":{"code":-32000,"message":"fixture binding refused"}})
        )
        .unwrap();
    });
    let mut child = Command::new(alias)
        .args(["node", "connect", "--socket"])
        .arg(socket)
        .args([
            "--expect-account",
            "owner",
            "--expect-database",
            "workspace",
            "--expect-origin",
            "https://native.test",
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Trigger Tokio's blocking stdin reader before the definite binding refusal.
    // Keep the pipe open so shutdown_background is required for process exit.
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
        .unwrap();
    let status = wait_for_legacy_exit(&mut child);
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    server.join().unwrap();
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("binding"), "{stderr}");
}

#[test]
fn runtime_describe_is_deterministic_without_installation_state() {
    let directory = tempfile::tempdir().unwrap();
    // Instrumented children must keep contributing coverage without writing
    // their default_%m_%p.profraw files into the directory under observation.
    let profiles = tempfile::tempdir().unwrap();
    let profile_file = std::env::var_os("LLVM_PROFILE_FILE")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| profiles.path().join("runtime-describe-%m-%p.profraw"));
    // Preserve relative caller patterns relative to the caller, not child cwd.
    let profile_file = if profile_file.is_absolute() {
        profile_file
    } else {
        std::env::current_dir().unwrap().join(profile_file)
    };
    let invalid = directory.path().join("not-a-directory");
    std::fs::write(&invalid, b"must remain untouched").unwrap();
    let probe = || {
        Command::new(env!("CARGO_BIN_EXE_native"))
            .env_clear()
            .env("LLVM_PROFILE_FILE", &profile_file)
            .env("HOME", &invalid)
            .env("XDG_CONFIG_HOME", &invalid)
            .env("XDG_DATA_HOME", &invalid)
            .env("NATIVE_CONFIG_DIR", &invalid)
            .env("NATIVE_STANDBY_HOME", &invalid)
            .env("RUST_LOG", "trace")
            .current_dir(directory.path())
            .args(["runtime", "describe", "--json"])
            .output()
            .unwrap()
    };
    let first = probe();
    assert!(first.status.success(), "{:?}", first.stderr);
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, probe().stdout);
    let report: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["contract"], "native.runtime-capabilities.v1");
    assert_eq!(report["qualification"], "compiled_declaration");
    assert_eq!(report["edges"], json!([]));
    assert_eq!(report["build_and_wire"]["source"], native_ce::FULL_GIT_SHA);
    assert_eq!(std::fs::read(&invalid).unwrap(), b"must remain untouched");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    let bad = Command::new(env!("CARGO_BIN_EXE_native"))
        .env("LLVM_PROFILE_FILE", &profile_file)
        .args(["runtime", "describe", "--json", "extra"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
}
