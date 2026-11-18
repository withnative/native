//! Consumer-neutral, read-only agent-sessions broker config.
//!
//! `agent-sessions.json` lives in the node's `socket_directory` and is absent
//! by default (absent ⇒ the feature is off, like `sessions.json` for the
//! saver). A present but invalid file fails visibly at startup.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::credential_file::validate_credential_path;
use crate::error::{Error, Result};

/// Sibling config file name, read from the node's working directory
/// (`socket_directory`). Absent means the broker is off.
pub const AGENT_SESSIONS_FILE: &str = "agent-sessions.json";
/// Contract string for the sibling config file.
pub const AGENT_SESSIONS_CONTRACT: &str = "native.node.agent-sessions.v1";

/// Bound on the password env file the broker reads per connect.
const MAX_ENV_FILE_BYTES: usize = 64 * 1024;

/// Versioned broker config (`native.node.agent-sessions.v1`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionsConfig {
    /// Must equal [`AGENT_SESSIONS_CONTRACT`].
    pub contract: String,
    pub daemon: DaemonRef,
    /// Optional outbound channel to hosted. Absent or `{"enabled": false}`
    /// means no channel; only `{"enabled": true}` connects.
    #[serde(default)]
    pub remote: Option<RemoteConfig>,
}

/// Outbound channel opt-in to hosted (`remote: {"enabled": true}`).
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// When true the node opens the hosted node channel; otherwise it does
    /// not connect. Defaults to false when the key is missing.
    #[serde(default)]
    pub enabled: bool,
}

impl AgentSessionsConfig {
    fn validate(&self) -> Result<()> {
        if self.contract != AGENT_SESSIONS_CONTRACT {
            return Err(Error::engine(format!(
                "unsupported agent-sessions contract: {}",
                self.contract
            )));
        }
        self.daemon.validate()?;
        Ok(())
    }

    /// True only for `remote: {"enabled": true}`.
    pub fn remote_enabled(&self) -> bool {
        self.remote.is_some_and(|r| r.enabled)
    }
}

/// Which daemon the broker follows.
///
/// `url` is plaintext `ws://` by design: the broker talks to a loopback or
/// tailnet daemon on a trusted local interface, and the password (when used)
/// is re-read from its env file on every connect rather than stored.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonRef {
    /// Daemon WebSocket URL including path, e.g. `ws://100.83.127.4:6767/ws`.
    pub(crate) url: String,
    /// Expected daemon `serverId` from the hello `server_info` acceptance. A
    /// mismatch fails closed (host unreachable + diagnostic).
    pub(crate) server_id: String,
    pub(crate) auth: DaemonAuth,
}

impl DaemonRef {
    fn validate(&self) -> Result<()> {
        if self.server_id.trim().is_empty() {
            return Err(Error::engine(
                "agent-sessions daemon.server_id must be nonempty",
            ));
        }
        validate_ws_url(&self.url)?;
        self.auth.validate()?;
        Ok(())
    }
}

/// How the broker authenticates its own daemon hello.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind")]
pub enum DaemonAuth {
    /// Read `key` from the dotenv-style file at `path` on every connect.
    /// The secret is never stored in the config; only path + key are kept.
    #[serde(rename = "password_env_file")]
    PasswordEnvFile { path: String, key: String },
    /// Reuse the saver's local-credential reading from `$PASEO_HOME`.
    #[serde(rename = "local_credential")]
    LocalCredential { paseo_home: String },
}

impl DaemonAuth {
    fn validate(&self) -> Result<()> {
        match self {
            Self::PasswordEnvFile { path, key } => {
                if path.trim().is_empty() {
                    return Err(Error::engine(
                        "agent-sessions daemon.auth.path must be nonempty",
                    ));
                }
                if key.trim().is_empty() {
                    return Err(Error::engine(
                        "agent-sessions daemon.auth.key must be nonempty",
                    ));
                }
                let path = PathBuf::from(path);
                validate_credential_path(&path, "agent-sessions daemon auth").map_err(|e| {
                    Error::engine(format!(
                        "agent-sessions daemon.auth.path is not an absolute unambiguous path: {e}"
                    ))
                })?;
                Ok(())
            }
            Self::LocalCredential { paseo_home } => {
                if paseo_home.trim().is_empty() {
                    return Err(Error::engine(
                        "agent-sessions daemon.auth.paseo_home must be nonempty",
                    ));
                }
                Ok(())
            }
        }
    }
}

fn validate_ws_url(url: &str) -> Result<()> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(Error::engine("agent-sessions daemon.url must be nonempty"));
    }
    let lower = trimmed.to_lowercase();
    let rest = if lower.strip_prefix("ws://").is_some() {
        &trimmed["ws://".len()..]
    } else if lower.strip_prefix("wss://").is_some() {
        &trimmed["wss://".len()..]
    } else {
        return Err(Error::engine(
            "agent-sessions daemon.url must be a ws:// or wss:// URL",
        ));
    };
    // Host present, and an explicit path (the daemon serves `/ws`; a bare
    // `/` answers HTTP 400).
    let Some((_host, path)) = rest.split_once('/') else {
        return Err(Error::engine(
            "agent-sessions daemon.url must include a path (e.g. /ws)",
        ));
    };
    if path.is_empty() {
        return Err(Error::engine(
            "agent-sessions daemon.url must include a path (e.g. /ws)",
        ));
    }
    if _host.trim().is_empty() {
        return Err(Error::engine("agent-sessions daemon.url has no host"));
    }
    Ok(())
}

/// Loaded broker config plus resolved working paths.
#[derive(Debug, Clone)]
pub struct LoadedAgentSessions {
    /// Config as parsed (holds paths/keys only, never secrets).
    pub config: AgentSessionsConfig,
}

/// Load the optional sibling config. `Ok(None)` when `agent-sessions.json`
/// is absent: the broker is off (default). A present but invalid file, an
/// unsupported contract, or a missing node `account_id` fails visibly.
pub fn load_agent_sessions(
    working_dir: &Path,
    account_id: Option<&str>,
) -> Result<Option<LoadedAgentSessions>> {
    let path = working_dir.join(AGENT_SESSIONS_FILE);
    let raw = match std::fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::engine(format!(
                "cannot read agent-sessions config: {e}"
            )));
        }
        Ok(raw) => raw,
    };
    if account_id.is_none_or(|id| id.trim().is_empty()) {
        return Err(Error::engine(
            "agent-sessions requires an explicit node account_id",
        ));
    }
    let config: AgentSessionsConfig = serde_json::from_slice(&raw)
        .map_err(|e| Error::engine(format!("invalid agent-sessions config: {e}")))?;
    config.validate()?;
    Ok(Some(LoadedAgentSessions { config }))
}

/// Read the password for `key` from a dotenv-style env file. Re-read on every
/// connect so rotation is picked up; the value lives only in the returned
/// zeroized buffer and never in the config's `Debug`.
pub fn read_password_from_env_file(path: &str, key: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use zeroize::Zeroizing;
    let fs_path = PathBuf::from(path);
    validate_credential_path(&fs_path, "agent-sessions daemon auth")
        .map_err(|e| Error::engine(format!("agent-sessions daemon auth path is unusable: {e}")))?;
    let metadata = std::fs::symlink_metadata(&fs_path)
        .map_err(|e| Error::engine(format!("cannot read agent-sessions daemon auth file: {e}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::engine(
            "agent-sessions daemon auth file is not a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let owned = std::fs::metadata(&fs_path).map_err(|e| {
            Error::engine(format!("cannot read agent-sessions daemon auth file: {e}"))
        })?;
        if owned.uid() != unsafe { libc::geteuid() } || owned.permissions().mode() & 0o077 != 0 {
            return Err(Error::engine(
                "agent-sessions daemon auth file is not owner-only",
            ));
        }
        if owned.nlink() != 1 {
            return Err(Error::engine(
                "agent-sessions daemon auth file must not be hard-linked",
            ));
        }
    }
    let bytes = std::fs::read(&fs_path)
        .map_err(|e| Error::engine(format!("cannot read agent-sessions daemon auth file: {e}")))?;
    if bytes.len() > MAX_ENV_FILE_BYTES {
        return Err(Error::engine(
            "agent-sessions daemon auth file exceeded its bound",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::engine("agent-sessions daemon auth file is not UTF-8"))?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `export KEY=value` and `KEY=value` both accepted.
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((name, mut value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != key {
            continue;
        }
        value = value.trim();
        // Strip one layer of matching quotes.
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = &value[1..value.len() - 1];
        }
        if value.is_empty() {
            return Err(Error::engine(
                "agent-sessions daemon auth password is empty",
            ));
        }
        return Ok(Zeroizing::new(value.as_bytes().to_vec()));
    }
    Err(Error::engine(
        "agent-sessions daemon auth key not found in env file",
    ))
}

/// Expand a leading `~/` against `$HOME`, like the saver does.
pub fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &Path, body: &[u8]) {
        std::fs::write(dir.join(AGENT_SESSIONS_FILE), body).unwrap();
    }

    #[test]
    fn absent_config_disables_broker() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_agent_sessions(dir.path(), Some("acct"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn invalid_config_fails_visibly() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), b"{not json");
        assert!(load_agent_sessions(dir.path(), Some("acct")).is_err());
    }

    #[test]
    fn wrong_contract_fails_visibly() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            br#"{"contract":"other","daemon":{"url":"ws://127.0.0.1:1/ws","server_id":"s","auth":{"kind":"local_credential","paseo_home":"~"}}}"#,
        );
        assert!(load_agent_sessions(dir.path(), Some("acct")).is_err());
    }

    #[test]
    fn missing_account_refuses_to_enable() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            br#"{"contract":"native.node.agent-sessions.v1","daemon":{"url":"ws://127.0.0.1:1/ws","server_id":"s","auth":{"kind":"local_credential","paseo_home":"~"}}}"#,
        );
        assert!(load_agent_sessions(dir.path(), None).is_err());
        assert!(load_agent_sessions(dir.path(), Some("")).is_err());
    }

    #[test]
    fn bare_slash_path_and_bad_urls_fail_visibly() {
        for url in [
            "ws://127.0.0.1:1/",
            "ws://127.0.0.1:1",
            "http://127.0.0.1:1/ws",
            "",
            "ws://",
        ] {
            let dir = tempfile::tempdir().unwrap();
            write_config(
                dir.path(),
                format!(
                    r#"{{"contract":"native.node.agent-sessions.v1","daemon":{{"url":{url:?},"server_id":"s","auth":{{"kind":"local_credential","paseo_home":"~"}}}}}}"#
                )
                .as_bytes(),
            );
            assert!(
                load_agent_sessions(dir.path(), Some("acct")).is_err(),
                "{url}"
            );
        }
    }

    #[test]
    fn valid_password_config_loads() {
        let dir = tempfile::tempdir().unwrap();
        write_config(
            dir.path(),
            br#"{"contract":"native.node.agent-sessions.v1","daemon":{"url":"ws://100.83.127.4:6767/ws","server_id":"srv_x","auth":{"kind":"password_env_file","path":"/tmp/p.env","key":"PASEO_PASSWORD"}}}"#,
        );
        let loaded = load_agent_sessions(dir.path(), Some("acct"))
            .unwrap()
            .expect("enabled");
        assert_eq!(loaded.config.daemon.server_id, "srv_x");
    }

    #[test]
    fn secrets_never_format() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("p.env");
        std::fs::write(&env, "PASEO_PASSWORD=super-secret-value\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        write_config(
            dir.path(),
            format!(
                r#"{{"contract":"native.node.agent-sessions.v1","daemon":{{"url":"ws://127.0.0.1:1/ws","server_id":"srv_x","auth":{{"kind":"password_env_file","path":{},"key":"PASEO_PASSWORD"}}}}}}"#,
                serde_json::to_string(env.to_str().unwrap()).unwrap()
            )
            .as_bytes(),
        );
        let loaded = load_agent_sessions(dir.path(), Some("acct"))
            .unwrap()
            .expect("enabled");
        let password =
            read_password_from_env_file(env.to_str().unwrap(), "PASEO_PASSWORD").unwrap();
        assert_eq!(password.as_slice(), b"super-secret-value");
        let debug = format!("{:?}", loaded.config);
        assert!(
            !debug.contains("super-secret-value"),
            "config Debug must never carry the secret: {debug}"
        );
        // The password buffer itself formats through zeroize; assert the raw
        // secret is not recoverable from the config's rendering either way.
        assert!(!debug.contains("PASEO_PASSWORD="));
    }

    #[test]
    fn missing_key_fails_visibly() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join("p.env");
        std::fs::write(&env, "OTHER=1\n").unwrap();
        assert!(read_password_from_env_file(env.to_str().unwrap(), "PASEO_PASSWORD").is_err());
    }
}
