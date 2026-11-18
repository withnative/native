//! Owner-local node recovery; no service definition or canonical writes involved.
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use super::node_client::{read_config, Connection, Limits};

pub async fn control(config_path: &Path, method: &str, timeout: Duration) -> Result<Value, String> {
    let config = read_config(config_path).map_err(|node| node.detail.unwrap_or_default())?;
    let mut connection = Connection::open(
        "native recovery",
        config_path,
        &config.socket_path(),
        timeout,
        &Limits::standard(),
    )
    .await
    .map_err(|node| node.detail.unwrap_or_default())?;
    let reply = connection
        .exchange(
            json!({"jsonrpc":"2.0", "method":method, "params":{}}),
            false,
        )
        .await?;
    reply
        .get("result")
        .filter(|result| result.is_object())
        .cloned()
        .ok_or_else(|| {
            "this node does not support local recovery; update the node, or use its service manager"
                .into()
        })
}

/// Restart only after the node explicitly accepts the local protocol. An old
/// node never receives a signal that might terminate it instead of restarting.
pub async fn restart(config_path: &Path, timeout: Duration) -> Result<(), String> {
    let before = control(config_path, "native/node/restart", Duration::from_secs(5)).await?;
    if before["contract"] != "native.node-restart.v1" || before["accepted"] != true {
        return Err("the node did not accept the restart; no automatic retry was sent".into());
    }
    let old_instance = before["instance_id"]
        .as_str()
        .ok_or("restart reply has no instance identity")?;
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if let Ok(after) = control(
            config_path,
            "native/node/diagnostics",
            remaining.min(Duration::from_secs(2)),
        )
        .await
        {
            if after["contract"] == "native.node-diagnostics.v1"
                && after["instance_id"]
                    .as_str()
                    .is_some_and(|id| id != old_instance)
            {
                return Ok(());
            }
        }
    }
    Err("restart was accepted, but the replacement node did not answer in time; inspect `native status` and the node log; do not blindly retry".into())
}

/// One private file with status, a live dump of instrumented pending futures,
/// and recent process logs. Missing components are explicit, not empty success.
pub async fn diagnose(
    config_path: &Path,
    report: &super::status::Report,
    output: Option<PathBuf>,
) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let live = control(
        config_path,
        "native/node/diagnostics",
        Duration::from_secs(5),
    )
    .await;
    // Peer credentials remain usable even if the node's event loop cannot reply.
    let peer_pid = match read_config(config_path) {
        Ok(config) => Connection::open(
            "native diagnosis",
            config_path,
            &config.socket_path(),
            Duration::from_secs(2),
            &Limits::standard(),
        )
        .await
        .ok()
        .and_then(|peer| peer.peer_pid()),
        Err(_) => None,
    };
    let journal = match peer_pid {
        Some(pid) => recent_log(u64::from(pid)).await,
        None => {
            json!({"available":false, "reason":"cannot establish the node process PID from its owner-only socket"})
        }
    };
    let live = match live {
        Ok(value) => value,
        Err(reason) => json!({"available":false,"reason":reason}),
    };
    let bundle = json!({
        "contract":"native.node-diagnosis.v1", "created_at":chrono::Utc::now().to_rfc3339(),
        "status":report, "live_diagnostics":live, "recent_log":journal,
        "sharing":"Review this file before sharing: status may include record titles and logs may contain operational details. Configuration files and the held-write journal are not included.",
    });
    let path = output.unwrap_or_else(|| {
        PathBuf::from(format!("native-diagnosis-{}.json", uuid::Uuid::new_v4()))
    });
    let bytes = serde_json::to_vec_pretty(&bundle).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("cannot create diagnosis file: {e}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("cannot save diagnosis file: {e}"))?;
    Ok(path)
}

const LOG_BYTES: u64 = 256 * 1024;

/// Read the actual stderr file when a launcher redirects it (notably launchd).
/// Never consume a pipe, socket or terminal belonging to the running node.
async fn stderr_path(pid: u64) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(PathBuf::from(format!("/proc/{pid}/fd/2")))
    }
    #[cfg(target_os = "macos")]
    {
        let mut command = tokio::process::Command::new("/usr/sbin/lsof");
        command.args(["-a", "-p", &pid.to_string(), "-d", "2", "-Fn"]);
        let (bytes, truncated, success) = bounded_output(command, 16 * 1024).await?;
        if truncated || !success {
            return None;
        }
        String::from_utf8_lossy(&bytes).lines().find_map(|line| {
            line.strip_prefix('n')
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

async fn stderr_tail(pid: u64) -> Option<Value> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let path = stderr_path(pid).await?;
    if !tokio::fs::metadata(&path).await.ok()?.is_file() {
        return None;
    }
    // O_NONBLOCK/O_NOCTTY also make a raced replacement with a FIFO/TTY harmless.
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(&path)
        .await
        .ok()?;
    let metadata = file.metadata().await.ok()?;
    if !metadata.is_file() {
        return None;
    }
    let length = metadata.len();
    file.seek(std::io::SeekFrom::Start(length.saturating_sub(LOG_BYTES)))
        .await
        .ok()?;
    let mut bytes = Vec::new();
    file.take(LOG_BYTES).read_to_end(&mut bytes).await.ok()?;
    Some(
        json!({"available":true, "source":"stderr_file", "truncated":length > LOG_BYTES,
        "text":String::from_utf8_lossy(&bytes)}),
    )
}

async fn recent_log(pid: u64) -> Value {
    if let Ok(Some(file)) = tokio::time::timeout(Duration::from_secs(10), stderr_tail(pid)).await {
        return file;
    }
    let mut command = if cfg!(target_os = "macos") {
        let mut command = tokio::process::Command::new("log");
        command.args([
            "show",
            "--last",
            "1h",
            "--style",
            "syslog",
            "--predicate",
            &format!("processIdentifier == {pid}"),
        ]);
        command
    } else {
        let mut command = tokio::process::Command::new("journalctl");
        command.args([
            "--user",
            &format!("_PID={pid}"),
            "--since=-1h",
            "-n",
            "200",
            "--no-pager",
            "-o",
            "short-iso",
        ]);
        command
    };
    command.kill_on_drop(true);
    match bounded_output(command, LOG_BYTES).await {
        Some((bytes, truncated, success)) => json!({"available":success, "source":"platform_log",
            "stderr_file":"unavailable (not a readable regular file)",
            "truncated":truncated, "text":String::from_utf8_lossy(&bytes)}),
        None => {
            json!({"available":false, "reason":"recent log could not be collected within 10 seconds"})
        }
    }
}

async fn bounded_output(
    mut command: tokio::process::Command,
    limit: u64,
) -> Option<(Vec<u8>, bool, bool)> {
    command
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let read = async {
        use tokio::io::AsyncReadExt;
        let mut child = command.spawn().ok()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()?
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .await
            .ok()?;
        let truncated = bytes.len() as u64 > limit;
        if truncated {
            bytes.truncate(limit as usize);
            let _ = child.kill().await;
            return Some((bytes, true, true));
        }
        let success = child.wait().await.ok()?.success();
        Some((bytes, false, success))
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn restart_refuses_an_old_nodes_reply_without_retry_or_signal_fallback() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let directory = tempfile::tempdir().unwrap();
        let socket_dir = directory.path().join("socket");
        std::fs::create_dir(&socket_dir).unwrap();
        let listener = tokio::net::UnixListener::bind(socket_dir.join("node.sock")).unwrap();
        let config = directory.path().join("node.json");
        std::fs::write(
            &config,
            serde_json::to_vec(&json!({
                "hosted_base_url":"http://127.0.0.1:1", "home_id":"home", "db_id":"route",
                "credential_file":directory.path().join("unused"), "socket_directory":socket_dir
            }))
            .unwrap(),
        )
        .unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["method"], "native/node/restart");
            write
                .write_all(
                    format!(
                        "{}\n",
                        json!({"jsonrpc":"2.0", "id":request["id"], "result":{}})
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            // A second connection would mean the client retried an uncertain restart.
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let error = restart(&config, Duration::from_secs(1)).await.unwrap_err();
        assert!(error.contains("did not accept"));
        server.await.unwrap();
    }
}
