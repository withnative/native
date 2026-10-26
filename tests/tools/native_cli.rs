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
    stdin: ChildStdin,
    responses: Receiver<String>,
    next_id: u64,
}

impl StdioClient {
    fn native(directory: &std::path::Path, db_name: &str) -> Self {
        Self::native_with_umask(directory, db_name, None)
    }

    fn native_with_umask(directory: &std::path::Path, db_name: &str, umask: Option<u32>) -> Self {
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
            stdin,
            responses,
            next_id: 0,
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let request = json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params});
        writeln!(self.stdin, "{request}").unwrap();
        self.stdin.flush().unwrap();
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

/// A server that closes its end while the shim's stdin stays open must still
/// let the shim exit: the download arm completes and the stateless shim goes
/// with it instead of hanging on the open stdin read.
#[test]
fn node_connect_exits_when_the_server_closes_first() {
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;

    const RESPONSE: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"gone\":true}}\n";

    fn early_close(binary: &str) -> (bool, Vec<u8>) {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("node.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            use std::io::Write as _;
            stream.write_all(RESPONSE).unwrap();
            // Close immediately without reading: stdin stays open below.
        });
        let mut child = Command::new(binary)
            .arg("node")
            .arg("connect")
            .arg("--socket")
            .arg(&socket)
            .env_clear()
            // Held open and never EOF: the shim must exit anyway.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        server.join().unwrap();
        let stdin = child.stdin.take().unwrap();
        // Bounded wait: poll for exit so a hung shim fails the test instead
        // of hanging it. `Child::wait_timeout` does not exist; `try_wait`
        // plus a deadline is the stable equivalent.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let outcome = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let _ = stdin;
        match outcome {
            Some(status) => {
                let mut stdout = Vec::new();
                child
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_end(&mut stdout)
                    .unwrap();
                (status.success(), stdout)
            }
            None => {
                child.kill().unwrap();
                panic!("{binary} hung after the server closed first");
            }
        }
    }

    let (native_ok, native_out) = early_close(env!("CARGO_BIN_EXE_native"));
    let (stdio_ok, stdio_out) = early_close(mcp_stdio_binary());
    assert!(native_ok, "native did not exit cleanly");
    assert!(stdio_ok, "mcp-stdio did not exit cleanly");
    assert_eq!(native_out, stdio_out, "shim bytes differ");
    assert_eq!(native_out, RESPONSE.to_vec());
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
