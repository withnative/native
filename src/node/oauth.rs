//! OAuth access-token renewal for the local node (increment 3a).
//!
//! Same protocol as the out-of-repo Python renewer
//! (`native-local-auth.py`): same auth-file contract, same `<auth>.lock`
//! flock, same 90 s renewal threshold, same expected `token_endpoint`
//! check, atomic 0600 writes with fsync, same access-token file output.
//!
//! Cut-over safety: this module uses the same lock file (`<auth-path>.lock`)
//! and re-reads the auth file under the lock, so the node and the Python
//! renewer can run together safely during cut-over without double renewal.

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::credential_file::validate_credential_path;
use crate::error::{Error, Result};

/// Expected standby OAuth contract, mirroring the Python renewer.
pub const CONTRACT: &str = "native.local-standby-oauth.v1";
/// Renewal grant contract for installs enrolled as the dedicated node client
/// (`native login-node`). Only this contract carries the dedicated audience
/// the grant was issued for; the legacy contract above always renews against
/// the fixed standby resource, ignoring any extra `resource` field.
pub const DEDICATED_CONTRACT: &str = "native.dedicated-node-oauth.v1";
/// Expected token endpoint, mirroring the Python renewer.
pub const TOKEN_ENDPOINT: &str = "https://plucky-discovery-38.authkit.app/oauth2/token";
/// Resource used by the fixed Native standby OAuth contract. Keep it on
/// renewal too: the issuer's default audience is not the Native MCP resource.
pub const RESOURCE: &str = "https://plugin.withnative.ai/mcp";
/// Renew once the token is within this of expiry (ms), mirroring the script.
pub const RENEW_BEFORE_MS: i64 = 90_000;
/// Bounds on `expires_in` accepted from the token endpoint (seconds).
pub const MIN_LIFETIME_SECS: i64 = 90;
pub const MAX_LIFETIME_SECS: i64 = 86_400;
/// Bound on the auth JSON file; the reader never loads more.
const MAX_AUTH_BYTES: usize = 65_536;
/// Bound on a bearer/refresh token value.
const MAX_TOKEN_LEN: usize = 4096;
/// Renewal-loop poll interval: about every 45 s (within the 30–60 s band).
pub const RENEW_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(45);
/// HTTP timeout for a single token-endpoint POST.
pub const RENEW_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Outcome of one renewal attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenewOutcome {
    /// Auth file was fresh; token file was still converged.
    Fresh,
    /// A refresh grant was redeemed and both files were rewritten.
    Renewed,
}

/// Renewal failure kinds. Messages never carry secrets.
#[derive(Debug)]
pub enum RenewError {
    /// Auth file or response failed validation (no secrets in message).
    Refused(String),
    /// Transport / timeout / protocol failure (no secrets in message).
    Transport(String),
    /// The provider rejected the refresh grant. Persistent: do not retry
    /// in a tight loop; the grant needs operator attention.
    InvalidGrant,
}

impl std::fmt::Display for RenewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(message) | Self::Transport(message) => write!(f, "{message}"),
            Self::InvalidGrant => write!(f, "refresh grant rejected (invalid_grant)"),
        }
    }
}

impl From<RenewError> for Error {
    fn from(error: RenewError) -> Self {
        Error::engine(error.to_string())
    }
}

fn owner_uid() -> u32 {
    // SAFETY: geteuid has no preconditions or pointer arguments.
    unsafe { libc::geteuid() }
}

fn valid_token(value: &serde_json::Value) -> bool {
    match value.as_str() {
        Some(token) => {
            !token.is_empty()
                && token.len() <= MAX_TOKEN_LEN
                && !token.chars().any(char::is_whitespace)
        }
        None => false,
    }
}

/// Guarded auth-file read mirroring `private_read` in the Python renewer:
/// absolute non-symlink path, owner-only 0600 regular file, single link,
/// bounded size. Returns the parsed JSON value.
fn read_auth_file(path: &Path) -> std::result::Result<serde_json::Value, RenewError> {
    validate_credential_path(path, "node oauth")
        .map_err(|_| RenewError::Refused("oauth auth file path refused".into()))?;
    let symlink_meta = fs::symlink_metadata(path)
        .map_err(|_| RenewError::Refused("oauth auth file unavailable".into()))?;
    if symlink_meta.file_type().is_symlink() || !symlink_meta.is_file() {
        return Err(RenewError::Refused(
            "oauth auth file is not a regular file".into(),
        ));
    }
    // O_NOFOLLOW: refuse a last-component symlink even under races.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| RenewError::Refused("oauth auth file unavailable".into()))?;
    let meta = file
        .metadata()
        .map_err(|_| RenewError::Refused("oauth auth file unavailable".into()))?;
    if !meta.is_file()
        || meta.uid() != owner_uid()
        || meta.nlink() != 1
        || meta.permissions().mode() & 0o777 != 0o600
    {
        return Err(RenewError::Refused(
            "oauth auth file must be owner-only".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take((MAX_AUTH_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RenewError::Refused("oauth auth file unreadable".into()))?;
    if bytes.len() > MAX_AUTH_BYTES {
        return Err(RenewError::Refused("oauth auth file too large".into()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| RenewError::Refused("oauth auth file is not JSON".into()))
}

/// Atomic 0600 write with fsync, mirroring `atomic_private_write`.
pub(crate) fn atomic_private_write(
    path: &Path,
    data: &[u8],
) -> std::result::Result<(), RenewError> {
    validate_credential_path(path, "node oauth")
        .map_err(|_| RenewError::Refused("oauth destination path refused".into()))?;
    let parent = path
        .parent()
        .ok_or_else(|| RenewError::Refused("oauth destination path refused".into()))?;
    // mkstemp-style temp file in the same directory, mode 0600.
    let mut temp_path: PathBuf;
    let mut temp: File;
    loop {
        let name = format!(".auth-{}-{}", std::process::id(), rand_suffix());
        temp_path = parent.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(&temp_path)
        {
            Ok(file) => {
                temp = file;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(RenewError::Refused("oauth destination unwritable".into()));
            }
        }
    }
    let result = (|| -> std::result::Result<(), RenewError> {
        temp.write_all(data)
            .map_err(|_| RenewError::Refused("oauth write failed".into()))?;
        temp.flush()
            .map_err(|_| RenewError::Refused("oauth write failed".into()))?;
        temp.sync_all()
            .map_err(|_| RenewError::Refused("oauth write failed".into()))?;
        drop(temp);
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RenewError::Refused("oauth write failed".into()))?;
        fs::rename(&temp_path, path)
            .map_err(|_| RenewError::Refused("oauth write failed".into()))?;
        let dir =
            File::open(parent).map_err(|_| RenewError::Refused("oauth write failed".into()))?;
        dir.sync_all()
            .map_err(|_| RenewError::Refused("oauth write failed".into()))?;
        Ok(())
    })();
    let _ = fs::remove_file(&temp_path);
    result
}

fn rand_suffix() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    hasher.finish()
}

/// Current time in Unix milliseconds.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// True when the grant is within the renewal window (or already expired).
pub fn is_due(expires_at_ms: i64, now_ms: i64) -> bool {
    expires_at_ms <= now_ms.saturating_add(RENEW_BEFORE_MS)
}

fn expires_at_of(auth: &serde_json::Value) -> i64 {
    auth.get("expires_at")
        .and_then(|v| {
            if let Some(ms) = v.as_i64() {
                Some(ms)
            } else if let Some(ms) = v.as_u64() {
                i64::try_from(ms).ok()
            } else {
                v.as_f64().map(|ms| ms as i64)
            }
        })
        .unwrap_or(0)
}

/// Open (creating 0600) the `<auth>.lock` file without locking.
fn open_lock_file(auth_path: &Path) -> std::result::Result<File, RenewError> {
    let mut lock_path = auth_path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    if let Some(parent) = lock_path.parent() {
        validate_credential_path(&lock_path, "node oauth")
            .map_err(|_| RenewError::Refused("oauth lock path refused".into()))?;
        let _ = parent;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .map_err(|_| RenewError::Refused("oauth lock unavailable".into()))
}

/// How often a contended lock is retried. Acquisition polls instead of
/// parking a blocking thread in `lock_exclusive()`: a caller that gives up
/// (deadline, cancellation) just drops this future and leaves nothing behind,
/// where an abandoned blocking worker would sit on the lock and a file
/// descriptor for as long as another process held it.
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(25);

async fn acquire_auth_lock(auth_path: &Path) -> std::result::Result<File, RenewError> {
    use fs2::FileExt as _;
    let file = open_lock_file(auth_path)?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(LOCK_POLL).await;
            }
            Err(_) => return Err(RenewError::Refused("oauth lock unavailable".into())),
        }
    }
}

/// Read-only: is the saved grant inside its renewal window (or expired)?
/// Applies the same guarded read and contract check as a renewal pass, but
/// takes no lock and writes nothing, so a caller that must not touch the
/// credential files (a dry run) can ask without side effects.
pub(crate) fn grant_is_due(
    auth_path: &Path,
    expected_endpoint: &str,
) -> std::result::Result<bool, RenewError> {
    let auth = read_auth_file(auth_path)?;
    validate_auth_contract(&auth, expected_endpoint)?;
    Ok(is_due(expires_at_of(&auth), now_ms()))
}

/// Keep a dedicated grant paired with its install and resource origin.
/// Legacy nodes continue to handle an unavailable renewal file on demand.
pub(crate) fn check_install_grant(
    auth_path: &Path,
    expected_endpoint: &str,
    hosted_origin: &url::Origin,
    enrolled: bool,
) -> std::result::Result<(), RenewError> {
    let auth = match read_auth_file(auth_path) {
        Ok(auth) => auth,
        Err(_) if !enrolled => return Ok(()),
        Err(error) => return Err(error),
    };
    let dedicated = auth["contract"] == DEDICATED_CONTRACT;
    let refused =
        || RenewError::Refused("dedicated OAuth grant and node install must be paired".into());
    if dedicated != enrolled {
        return Err(refused());
    }
    if dedicated {
        let (_, _, _, resource) = validate_auth_contract(&auth, expected_endpoint)?;
        if !url::Url::parse(&resource).is_ok_and(|resource| &resource.origin() == hosted_origin) {
            return Err(refused());
        }
    }
    Ok(())
}

/// Build the token-endpoint client: reqwest, no redirects, no retries.
pub fn renew_client() -> std::result::Result<reqwest::Client, RenewError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(RENEW_HTTP_TIMEOUT)
        .build()
        .map_err(|_| RenewError::Transport("oauth http client failed".into()))
}

fn validate_auth_contract(
    auth: &serde_json::Value,
    expected_endpoint: &str,
) -> std::result::Result<(String, String, String, String), RenewError> {
    let contract = auth.get("contract").and_then(|v| v.as_str());
    if contract != Some(CONTRACT) && contract != Some(DEDICATED_CONTRACT) {
        return Err(RenewError::Refused(
            "unsupported oauth configuration".into(),
        ));
    }
    if auth.get("token_endpoint").and_then(|v| v.as_str()) != Some(expected_endpoint) {
        return Err(RenewError::Refused(
            "unsupported oauth configuration".into(),
        ));
    }
    let access = auth.get("access_token").cloned().unwrap_or_default();
    let refresh = auth.get("refresh_token").cloned().unwrap_or_default();
    let client_id = auth.get("client_id").and_then(|v| v.as_str()).unwrap_or("");
    if !valid_token(&access) || !valid_token(&refresh) {
        return Err(RenewError::Refused("missing oauth grant".into()));
    }
    if client_id.is_empty() || client_id.len() > MAX_TOKEN_LEN {
        return Err(RenewError::Refused("missing oauth grant".into()));
    }
    // Only the dedicated enrollment contract carries the audience the grant
    // was issued for; renewal echoes it back so the grant keeps its audience
    // across rotations. The legacy contract always renews against the fixed
    // standby audience, ignoring any extra `resource` field an externally
    // produced file may carry.
    let resource = if contract == Some(DEDICATED_CONTRACT) {
        match auth.get("resource") {
            Some(value) => match value.as_str() {
                Some(resource) if valid_resource(resource) => resource.to_owned(),
                _ => {
                    return Err(RenewError::Refused(
                        "unsupported oauth configuration".into(),
                    ));
                }
            },
            None => {
                return Err(RenewError::Refused(
                    "unsupported oauth configuration".into(),
                ));
            }
        }
    } else {
        RESOURCE.to_owned()
    };
    Ok((
        access.as_str().unwrap().to_owned(),
        refresh.as_str().unwrap().to_owned(),
        client_id.to_owned(),
        resource,
    ))
}

/// Stored `resource` values are written by enrollment and echoed back to the
/// token endpoint on renewal. The shape mirrors [`valid_token`]: opaque,
/// bounded, no whitespace.
fn valid_resource(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TOKEN_LEN && !value.chars().any(char::is_whitespace)
}

pub(crate) fn check_refresh_response(
    refreshed: &serde_json::Value,
    current_refresh: &str,
) -> std::result::Result<(String, String, i64), RenewError> {
    let token = refreshed.get("access_token").cloned().unwrap_or_default();
    let replacement = refreshed
        .get("refresh_token")
        .cloned()
        .unwrap_or_else(|| serde_json::Value::String(current_refresh.to_owned()));
    let lifetime = refreshed.get("expires_in");
    let token_type = refreshed
        .get("token_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Lifetime must be a JSON number (not bool), within (90, 86400].
    let lifetime_secs: Option<i64> = match lifetime {
        Some(v) if v.is_i64() => v.as_i64(),
        Some(v) if v.is_u64() => i64::try_from(v.as_u64().unwrap_or(0)).ok(),
        Some(v) if v.is_f64() => Some(v.as_f64().unwrap_or(0.0) as i64),
        _ => None,
    };
    let lifetime_secs = lifetime_secs.unwrap_or(-1);
    if !valid_token(&token)
        || !valid_token(&replacement)
        || !(MIN_LIFETIME_SECS < lifetime_secs && lifetime_secs <= MAX_LIFETIME_SECS)
        || token_type.to_lowercase() != "bearer"
    {
        return Err(RenewError::Refused("unusable refresh response".into()));
    }
    Ok((
        token.as_str().unwrap().to_owned(),
        replacement.as_str().unwrap().to_owned(),
        lifetime_secs,
    ))
}

fn is_invalid_grant(status: reqwest::StatusCode, body: &serde_json::Value) -> bool {
    if status == reqwest::StatusCode::BAD_REQUEST {
        if body.get("error").and_then(|v| v.as_str()) == Some("invalid_grant") {
            return true;
        }
        // Some providers nest the code one level deeper.
        if body.pointer("/error/error").and_then(|v| v.as_str()) == Some("invalid_grant") {
            return true;
        }
    }
    // Heuristic fallback: body names the grant even with an odd status.
    body.get("error").and_then(|v| v.as_str()) == Some("invalid_grant")
}

/// One renewal pass under the shared `<auth>.lock`.
///
/// Re-reads the auth file after acquiring the lock, so a concurrent renewer
/// (Python or node) that already rotated wins and no double renewal happens.
/// Always converges the access-token file from the (re-read) auth state.
/// Never logs or returns secrets; errors are categories only.
pub async fn renew_once(
    auth_path: &Path,
    token_path: &Path,
    expected_endpoint: &str,
    client: &reqwest::Client,
) -> std::result::Result<RenewOutcome, RenewError> {
    let _lock = acquire_auth_lock(auth_path).await?;
    let mut auth = read_auth_file(auth_path)?;
    let (access, refresh, client_id, resource) = validate_auth_contract(&auth, expected_endpoint)?;
    if !is_due(expires_at_of(&auth), now_ms()) {
        atomic_private_write(token_path, access.as_bytes())?;
        return Ok(RenewOutcome::Fresh);
    }
    let response = client
        .post(expected_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "native-local-standby-auth")
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("refresh_token", refresh.as_str()),
            ("resource", resource.as_str()),
        ])
        .send()
        .await
        .map_err(|_| RenewError::Transport("oauth token endpoint unreachable".into()))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| RenewError::Transport("oauth token endpoint unreadable".into()))?;
    if bytes.len() > MAX_AUTH_BYTES {
        return Err(RenewError::Refused("oauth response too large".into()));
    }
    // Error bodies are small JSON; parse failures are generic refusals.
    let payload: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        if status.is_success() {
            RenewError::Refused("unusable refresh response".into())
        } else {
            RenewError::Transport("oauth token endpoint error".into())
        }
    })?;
    if !status.is_success() {
        if is_invalid_grant(status, &payload) {
            return Err(RenewError::InvalidGrant);
        }
        return Err(RenewError::Transport("oauth token endpoint error".into()));
    }
    let (token, replacement, lifetime) = check_refresh_response(&payload, &refresh)?;
    if let Some(object) = auth.as_object_mut() {
        object.insert(
            "access_token".into(),
            serde_json::Value::String(token.clone()),
        );
        object.insert(
            "refresh_token".into(),
            serde_json::Value::String(replacement),
        );
        object.insert(
            "expires_at".into(),
            serde_json::Value::from(now_ms().saturating_add(lifetime.saturating_mul(1000))),
        );
    }
    let serialized = serde_json::to_vec(&auth)
        .map_err(|_| RenewError::Refused("oauth auth serialization failed".into()))?;
    // Persist the rotated refresh grant before publishing its access token.
    atomic_private_write(auth_path, &serialized)?;
    atomic_private_write(token_path, token.as_bytes())?;
    Ok(RenewOutcome::Renewed)
}

/// How long an interactive login waits for the shared `<auth>.lock` before
/// giving up (a running renewer holds it only for one token POST).
const LOGIN_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) struct LoginGrant<'a> {
    pub(crate) token_endpoint: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) access_token: &'a str,
    pub(crate) refresh_token: &'a str,
    pub(crate) lifetime_secs: i64,
}

/// Publish the grant from an interactive `native login`: take the same
/// `<auth>.lock` the renewer takes, write the auth file (rotating refresh
/// grant first), then the access-token file the node sends. Both are atomic
/// 0600 writes. Returns the grant's `expires_at` (Unix ms). The caller has
/// already validated the token response with [`check_refresh_response`].
pub async fn store_login_grant(
    auth_path: &Path,
    token_path: &Path,
    token_endpoint: &str,
    client_id: &str,
    access_token: &str,
    refresh_token: &str,
    lifetime_secs: i64,
) -> std::result::Result<i64, RenewError> {
    store_grant(
        auth_path,
        token_path,
        LoginGrant {
            token_endpoint,
            client_id,
            access_token,
            refresh_token,
            lifetime_secs,
        },
        None,
    )
    .await
}

/// Publish the grant from an enrolled node sign-in (`native login-node`)
/// under the dedicated enrollment contract: the same lock, atomic 0600
/// writes and repair semantics as [`store_login_grant`], plus the dedicated
/// resource the grant was issued for. Renewal echoes that stored resource
/// back instead of the fixed standby one, so the grant keeps its dedicated
/// audience across rotations. The caller has already validated the token
/// response with [`check_refresh_response`] and verified the enrollment with
/// hosted.
pub(crate) async fn store_enrollment_grant(
    auth_path: &Path,
    token_path: &Path,
    grant: LoginGrant<'_>,
    resource: &str,
) -> std::result::Result<i64, RenewError> {
    store_grant(auth_path, token_path, grant, Some(resource)).await
}

/// Shared grant writer: one lock acquisition, then the auth file (rotating
/// refresh grant first) and the access-token file, both atomic 0600 writes.
/// `None` writes the legacy standby shape; `Some` writes the dedicated
/// enrollment contract carrying that resource.
async fn store_grant(
    auth_path: &Path,
    token_path: &Path,
    grant: LoginGrant<'_>,
    dedicated_resource: Option<&str>,
) -> std::result::Result<i64, RenewError> {
    if let Some(resource) = dedicated_resource {
        if !valid_resource(resource) {
            return Err(RenewError::Refused(
                "unsupported oauth configuration".into(),
            ));
        }
    }
    let _lock = tokio::time::timeout(LOGIN_LOCK_WAIT, acquire_auth_lock(auth_path))
        .await
        .map_err(|_| RenewError::Refused("oauth lock busy".into()))??;
    let expires_at = now_ms().saturating_add(grant.lifetime_secs.saturating_mul(1000));
    let mut auth = serde_json::json!({
        "contract": if dedicated_resource.is_some() {
            DEDICATED_CONTRACT
        } else {
            CONTRACT
        },
        "token_endpoint": grant.token_endpoint,
        "access_token": grant.access_token,
        "refresh_token": grant.refresh_token,
        "client_id": grant.client_id,
        "expires_at": expires_at,
    });
    if let Some(resource) = dedicated_resource {
        auth["resource"] = serde_json::Value::String(resource.to_owned());
    }
    let serialized = serde_json::to_vec(&auth)
        .map_err(|_| RenewError::Refused("oauth auth serialization failed".into()))?;
    atomic_private_write(auth_path, &serialized)?;
    atomic_private_write(token_path, grant.access_token.as_bytes())?;
    Ok(expires_at)
}

/// Persistent renewal state for one node binding.
///
/// `invalid_grant` is sticky: once the provider rejects the refresh token,
/// automatic renewal stops retrying in a tight loop and `before_send` fails
/// closed with a clear message until the operator repairs the grant.
pub struct OAuthRenewer {
    auth_path: PathBuf,
    token_path: PathBuf,
    expected_endpoint: String,
    client: reqwest::Client,
    state: tokio::sync::Mutex<RenewerState>,
}

#[derive(Default)]
struct RenewerState {
    invalid_grant: bool,
    consecutive_failures: u32,
}

impl OAuthRenewer {
    /// Build a renewer. The token file is the node's `credential_file`;
    /// the auth file is the new optional `oauth_auth_file` config.
    pub fn new(
        auth_path: PathBuf,
        token_path: PathBuf,
        expected_endpoint: String,
        client: reqwest::Client,
    ) -> Self {
        Self {
            auth_path,
            token_path,
            expected_endpoint,
            client,
            state: tokio::sync::Mutex::new(RenewerState::default()),
        }
    }

    /// True once the provider has rejected the refresh grant.
    pub async fn is_invalid_grant(&self) -> bool {
        self.state.lock().await.invalid_grant
    }

    /// Background poll: renew when due, back off on transient failure,
    /// park on `invalid_grant`. Logs categories only, never secrets.
    pub async fn check_and_renew(&self) {
        if self.is_invalid_grant().await {
            return;
        }
        match renew_once(
            &self.auth_path,
            &self.token_path,
            &self.expected_endpoint,
            &self.client,
        )
        .await
        {
            Ok(_) => {
                self.state.lock().await.consecutive_failures = 0;
            }
            Err(RenewError::InvalidGrant) => {
                self.state.lock().await.invalid_grant = true;
                tracing::warn!("node oauth renewal halted: refresh grant rejected");
            }
            Err(_) => {
                let mut state = self.state.lock().await;
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                tracing::warn!("node oauth renewal failed");
            }
        }
    }

    /// Renew before a send only when the grant is already expired.
    /// Transient failures log and let the send proceed with the current
    /// credential; `invalid_grant` fails closed. Never retries the send.
    pub async fn ensure_fresh_before_send(&self) -> Result<()> {
        if self.is_invalid_grant().await {
            return Err(Error::engine(
                "node oauth grant rejected (invalid_grant); repair the auth file",
            ));
        }
        let expired = read_auth_file(&self.auth_path)
            .map(|auth| expires_at_of(&auth) <= now_ms())
            .unwrap_or(true);
        if !expired {
            return Ok(());
        }
        match renew_once(
            &self.auth_path,
            &self.token_path,
            &self.expected_endpoint,
            &self.client,
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(RenewError::InvalidGrant) => {
                self.state.lock().await.invalid_grant = true;
                tracing::warn!("node oauth renewal halted: refresh grant rejected");
                Err(Error::engine(
                    "node oauth grant rejected (invalid_grant); repair the auth file",
                ))
            }
            Err(_) => {
                tracing::warn!("node oauth renewal failed");
                Ok(())
            }
        }
    }

    /// Backoff after transient failures: 45 s, doubling to at most ~12 min.
    pub async fn poll_delay(&self) -> std::time::Duration {
        let failures = self.state.lock().await.consecutive_failures;
        if failures == 0 {
            return RENEW_POLL_INTERVAL;
        }
        let shifted = RENEW_POLL_INTERVAL
            .as_secs()
            .saturating_mul(1u64 << failures.min(4));
        std::time::Duration::from_secs(shifted.min(720))
    }
}

/// Poll loop for `serve`: check about every 30–60 s, renew when due.
pub async fn renewal_loop(renewer: std::sync::Arc<OAuthRenewer>) {
    loop {
        renewer.check_and_renew().await;
        if renewer.is_invalid_grant().await {
            // Parked: re-check hourly in case the operator repaired the file.
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            renewer.state.lock().await.invalid_grant = false;
            continue;
        }
        let delay = renewer.poll_delay().await;
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::StatusCode, routing::post, Router};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc as StdArc;

    #[derive(Clone)]
    struct Fake {
        hits: StdArc<std::sync::atomic::AtomicUsize>,
        status: StatusCode,
        body: serde_json::Value,
        seen: StdArc<std::sync::Mutex<Vec<String>>>,
    }

    async fn token_route(
        State(fake): State<Fake>,
        body: String,
    ) -> (StatusCode, axum::Json<serde_json::Value>) {
        fake.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(body.contains("grant_type=refresh_token"));
        fake.seen.lock().unwrap().push(body);
        (fake.status, axum::Json(fake.body.clone()))
    }

    fn refresh_resource(body: &str) -> String {
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect::<std::collections::HashMap<String, String>>()["resource"]
            .clone()
    }

    async fn start_fake(status: StatusCode, body: serde_json::Value) -> (String, Fake) {
        let fake = Fake {
            hits: StdArc::new(std::sync::atomic::AtomicUsize::new(0)),
            status,
            body,
            seen: StdArc::new(std::sync::Mutex::new(Vec::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/oauth2/token", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/oauth2/token", post(token_route))
            .with_state(fake.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (url, fake)
    }

    fn write_auth(dir: &Path, endpoint: &str, expires_at: i64) -> (PathBuf, PathBuf) {
        let auth_path = dir.join("auth.json");
        let token_path = dir.join("native.token");
        let auth = serde_json::json!({
            "contract": CONTRACT,
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "client_id": "test-client",
            "expires_at": expires_at,
            "token_endpoint": endpoint,
        });
        fs::write(&auth_path, serde_json::to_vec(&auth).unwrap()).unwrap();
        fs::set_permissions(&auth_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&token_path, "old-access").unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        (auth_path, token_path)
    }

    fn test_client() -> reqwest::Client {
        renew_client().unwrap()
    }

    #[tokio::test]
    async fn fresh_token_is_not_renewed() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "new", "refresh_token": "r",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(dir.path(), &url, now_ms() + 3_600_000);
        let outcome = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap();
        assert_eq!(outcome, RenewOutcome::Fresh);
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(fs::read_to_string(&token_path).unwrap(), "old-access");
    }

    #[tokio::test]
    async fn due_token_is_renewed_and_rotated() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "new-access", "refresh_token": "new-refresh",
                "expires_in": 3600, "token_type": "bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(dir.path(), &url, now_ms() - 1_000);
        let outcome = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap();
        assert_eq!(outcome, RenewOutcome::Renewed);
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        let auth: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth_path).unwrap()).unwrap();
        assert_eq!(auth["access_token"], "new-access");
        assert_eq!(auth["refresh_token"], "new-refresh");
        assert!(auth["expires_at"].as_i64().unwrap() > now_ms());
        assert_eq!(fs::read_to_string(&token_path).unwrap(), "new-access");
        assert_eq!(fs::metadata(&auth_path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&token_path).unwrap().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn concurrent_locker_wins_without_double_renewal() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "late", "refresh_token": "late-r",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(dir.path(), &url, now_ms() - 1_000);
        // Hold the shared lock, then let a renewer block on it.
        let lock_path = PathBuf::from(format!("{}.lock", auth_path.display()));
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        {
            use fs2::FileExt as _;
            holder.lock_exclusive().unwrap();
        }
        let auth_clone = auth_path.clone();
        let token_clone = token_path.clone();
        let url_clone = url.clone();
        let renew_task = tokio::spawn(async move {
            renew_once(&auth_clone, &token_clone, &url_clone, &test_client()).await
        });
        // Give the renewer a moment to block, then rotate under our lock.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let fresh = serde_json::json!({
            "contract": CONTRACT, "access_token": "fresh-access",
            "refresh_token": "fresh-refresh", "client_id": "test-client",
            "expires_at": now_ms() + 3_600_000, "token_endpoint": url,
        });
        atomic_private_write(&auth_path, &serde_json::to_vec(&fresh).unwrap()).unwrap();
        atomic_private_write(&token_path, b"fresh-access").unwrap();
        drop(holder);
        let outcome = renew_task.await.unwrap().unwrap();
        assert_eq!(outcome, RenewOutcome::Fresh);
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(fs::read_to_string(&token_path).unwrap(), "fresh-access");
    }

    #[tokio::test]
    async fn a_held_lock_can_be_given_up_on_without_leaving_anything_behind() {
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, _token_path) = write_auth(dir.path(), "http://127.0.0.1:1/t", now_ms() + 1);
        let lock_path = PathBuf::from(format!("{}.lock", auth_path.display()));
        let holder = open_lock_file(&auth_path).unwrap();
        {
            use fs2::FileExt as _;
            holder.lock_exclusive().unwrap();
        }
        // Descriptors open on the lock file, other than the holder's own.
        let lock_fds = || {
            let target = fs::canonicalize(&lock_path).unwrap();
            fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| fs::read_link(entry.unwrap().path()).ok())
                .filter(|link| *link == target)
                .count()
        };
        let before = lock_fds();
        for _ in 0..20 {
            let attempt = tokio::time::timeout(
                std::time::Duration::from_millis(60),
                acquire_auth_lock(&auth_path),
            )
            .await;
            assert!(attempt.is_err(), "the lock is held elsewhere");
        }
        assert_eq!(
            lock_fds(),
            before,
            "abandoned acquisitions leave no descriptor behind"
        );
        // Once released, acquisition succeeds promptly (no orphan took it).
        drop(holder);
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            acquire_auth_lock(&auth_path),
        )
        .await
        .expect("lock free after the holder let go");
        assert!(got.is_ok());
    }

    #[tokio::test]
    async fn invalid_grant_becomes_persistent_error_state() {
        let (url, fake) = start_fake(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "invalid_grant"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(dir.path(), &url, now_ms() - 1_000);
        let client = test_client();
        let error = renew_once(&auth_path, &token_path, &url, &client)
            .await
            .unwrap_err();
        assert!(matches!(error, RenewError::InvalidGrant));
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Renewer surfaces the same state and parks instead of tight-looping.
        let renewer = StdArc::new(OAuthRenewer::new(
            auth_path.clone(),
            token_path.clone(),
            url.clone(),
            client,
        ));
        renewer.check_and_renew().await;
        assert!(renewer.is_invalid_grant().await);
        let before = fake.hits.load(std::sync::atomic::Ordering::SeqCst);
        renewer.check_and_renew().await;
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), before);
        assert!(renewer.ensure_fresh_before_send().await.is_err());
    }

    #[tokio::test]
    async fn endpoint_mismatch_is_refused_without_network() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "x", "refresh_token": "y",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(
            dir.path(),
            "https://example.invalid/oauth2/token",
            now_ms() - 1_000,
        );
        let error = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap_err();
        assert!(matches!(error, RenewError::Refused(_)));
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn symlinked_or_insecure_auth_file_is_refused() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "x", "refresh_token": "y",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(dir.path(), &url, now_ms() - 1_000);
        // Symlinked auth path is refused.
        let link = dir.path().join("auth-link.json");
        std::os::unix::fs::symlink(&auth_path, &link).unwrap();
        let error = renew_once(&link, &token_path, &url, &test_client())
            .await
            .unwrap_err();
        assert!(matches!(error, RenewError::Refused(_)));
        // Group-readable auth file is refused.
        fs::set_permissions(&auth_path, fs::Permissions::from_mode(0o640)).unwrap();
        let error = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap_err();
        assert!(matches!(error, RenewError::Refused(_)));
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        // Restore for drop; unusable refresh responses are also refused.
        fs::set_permissions(&auth_path, fs::Permissions::from_mode(0o600)).unwrap();
        let (bad_url, _) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "x", "refresh_token": "y",
                "expires_in": 10, "token_type": "Bearer"}),
        )
        .await;
        let (auth_path, token_path) = write_auth(dir.path(), &bad_url, now_ms() - 1_000);
        let error = renew_once(&auth_path, &token_path, &bad_url, &test_client())
            .await
            .unwrap_err();
        assert!(matches!(error, RenewError::Refused(_)));
    }

    #[tokio::test]
    async fn login_grant_waits_for_the_renewer_lock_and_is_then_renewable() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "x", "refresh_token": "y",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let auth_path = dir.path().join("auth.json");
        let token_path = dir.path().join("native.token");
        let holder = open_lock_file(&auth_path).unwrap();
        {
            use fs2::FileExt as _;
            holder.lock_exclusive().unwrap();
        }
        let (a, t, u) = (auth_path.clone(), token_path.clone(), url.clone());
        let store = tokio::spawn(async move {
            store_login_grant(
                &a,
                &t,
                &u,
                "client-1",
                "login-access",
                "login-refresh",
                3600,
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(!store.is_finished(), "login must wait for the shared lock");
        assert!(!token_path.exists());
        drop(holder);
        let expires_at = store.await.unwrap().unwrap();
        assert!(expires_at > now_ms());
        assert_eq!(fs::read_to_string(&token_path).unwrap(), "login-access");
        assert_eq!(fs::metadata(&auth_path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&token_path).unwrap().mode() & 0o777, 0o600);
        // The node's own renewer accepts what login wrote.
        let outcome = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap();
        assert_eq!(outcome, RenewOutcome::Fresh);
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn legacy_grant_without_resource_renews_against_the_standby_resource() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "new-access", "refresh_token": "new-refresh",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(dir.path(), &url, now_ms() - 1_000);
        let outcome = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap();
        assert_eq!(outcome, RenewOutcome::Renewed);
        let seen = fake.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(refresh_resource(&seen[0]), RESOURCE);
    }

    #[tokio::test]
    async fn enrollment_grant_keeps_its_dedicated_resource_on_renewal() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "new-access", "refresh_token": "new-refresh",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dedicated = "https://node.example.test/node";
        let dir = tempfile::tempdir().unwrap();
        let auth_path = dir.path().join("auth.json");
        let token_path = dir.path().join("native.token");
        store_enrollment_grant(
            &auth_path,
            &token_path,
            LoginGrant {
                token_endpoint: &url,
                client_id: "node-client-1",
                access_token: "enrolled-access",
                refresh_token: "enrolled-refresh",
                lifetime_secs: 3600,
            },
            dedicated,
        )
        .await
        .unwrap();
        // The stored grant carries the dedicated contract and audience.
        let stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth_path).unwrap()).unwrap();
        assert_eq!(stored["contract"], DEDICATED_CONTRACT);
        assert_eq!(stored["resource"], dedicated);
        assert_eq!(fs::read_to_string(&token_path).unwrap(), "enrolled-access");
        // Backdate past the renewal window: the renewer must echo the stored
        // resource, not the standby one.
        let mut backdated = stored;
        backdated["expires_at"] = serde_json::Value::from(now_ms() - 1_000);
        atomic_private_write(&auth_path, &serde_json::to_vec(&backdated).unwrap()).unwrap();
        let outcome = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap();
        assert_eq!(outcome, RenewOutcome::Renewed);
        let seen = fake.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(refresh_resource(&seen[0]), dedicated);
    }

    #[tokio::test]
    async fn dedicated_grant_with_unknown_resource_is_refused_without_network() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "x", "refresh_token": "y",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(dir.path(), &url, now_ms() - 1_000);
        let mut auth: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth_path).unwrap()).unwrap();
        auth["contract"] = serde_json::Value::from(DEDICATED_CONTRACT);
        auth["resource"] = serde_json::Value::from("not a resource");
        atomic_private_write(&auth_path, &serde_json::to_vec(&auth).unwrap()).unwrap();
        let error = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap_err();
        assert!(matches!(error, RenewError::Refused(_)));
        assert_eq!(fake.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn legacy_grant_ignores_an_extra_resource_field() {
        let (url, fake) = start_fake(
            StatusCode::OK,
            serde_json::json!({"access_token": "new-access", "refresh_token": "new-refresh",
                "expires_in": 3600, "token_type": "Bearer"}),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (auth_path, token_path) = write_auth(dir.path(), &url, now_ms() - 1_000);
        // An externally produced legacy file may carry an extra resource;
        // the legacy contract still renews against the standby audience.
        let mut auth: serde_json::Value =
            serde_json::from_slice(&fs::read(&auth_path).unwrap()).unwrap();
        auth["resource"] = serde_json::Value::from("https://node.example.test/node");
        atomic_private_write(&auth_path, &serde_json::to_vec(&auth).unwrap()).unwrap();
        let outcome = renew_once(&auth_path, &token_path, &url, &test_client())
            .await
            .unwrap();
        assert_eq!(outcome, RenewOutcome::Renewed);
        let seen = fake.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(refresh_resource(&seen[0]), RESOURCE);
    }
}
