//! `native login`: sign in to hosted Native and write the two guarded files
//! the node already reads.
//!
//! Public-client Authorization Code with PKCE (S256), RFC 8252 loopback
//! redirect:
//!
//! 1. Discover the authorization server from the hosted origin's RFC 9728
//!    protected-resource metadata, then its RFC 8414 metadata.
//! 2. Register a client dynamically (RFC 7591) and save the registration next
//!    to the auth file; a later login reuses it.
//! 3. Open the browser (or print the URL) and wait on a one-shot 127.0.0.1
//!    listener. With `--no-browser` the full callback URL may instead be pasted
//!    on stdin.
//! 4. Check `state`, exchange the code, and publish the grant through
//!    [`oauth::store_login_grant`]: the node's own lock, atomic 0600 writes.
//!
//! Tokens, the authorization code and the PKCE verifier are never printed or
//! logged; error text carries categories and OAuth error codes only.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::error::{Error, Result};
use crate::node::oauth;

/// Hosted origin used when `--hosted` is not given. The OAuth resource is
/// `<origin>/mcp`; see the base-URL notes in the task record.
pub const DEFAULT_HOSTED_ORIGIN: &str = "https://plugin.withnative.ai";
/// How long to wait for the browser callback unless told otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
/// File names inside the config directory.
pub const TOKEN_FILE: &str = "native.token";
pub const AUTH_FILE: &str = "native-auth.json";
pub const CLIENT_FILE: &str = "oauth-client.json";

const CLIENT_CONTRACT: &str = "native.cli-oauth-client.v1";
const CALLBACK_PATH: &str = "/callback";
const MAX_JSON_BYTES: usize = 65_536;
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ID_LEN: usize = 4096;

/// How the authorization URL reaches the person.
pub enum BrowserMode {
    /// Open the system browser; print the URL as a fallback.
    System,
    /// Print the URL only (`--no-browser`).
    PrintOnly,
    /// Test seam: hand the URL to a closure that plays the browser.
    #[cfg(test)]
    Hook(Box<dyn Fn(String) + Send + Sync>),
}

/// What went wrong, for callers that act on it (the tests, the binary's exit
/// code and hints) without parsing message text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginErrorKind {
    /// Anything else: discovery, registration, I/O, malformed responses.
    Other,
    /// The config directory is not ours or is writable by others.
    ConfigDirUnsafe,
    /// The authorization server's token endpoint is not one the node renews.
    UnsupportedAuthorizationServer,
    /// No valid callback arrived before the deadline.
    TimedOut,
    /// A callback with the right `state` carried an OAuth error.
    AuthorizationDenied,
    /// The token endpoint refused the code exchange.
    TokenRefused,
    /// Interrupted (Ctrl-C or SIGTERM) before the grant was written.
    Interrupted,
}

/// A failed login. The message carries categories and OAuth error codes only,
/// never tokens, codes or verifiers.
#[derive(Debug)]
pub struct LoginError {
    pub kind: LoginErrorKind,
    message: String,
    /// The attempt used a registration saved by an earlier login.
    used_saved_registration: bool,
}

impl LoginError {
    fn new(kind: LoginErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            used_saved_registration: false,
        }
    }

    fn using_saved_registration(mut self, used: bool) -> Self {
        self.used_saved_registration = used;
        self
    }

    /// When a login that reused a saved client registration ends without a
    /// usable callback, that registration may be what the authorization server
    /// is rejecting (it shows an error page and never redirects back).
    pub fn reset_hint(&self) -> Option<&'static str> {
        let relevant = matches!(
            self.kind,
            LoginErrorKind::TimedOut
                | LoginErrorKind::AuthorizationDenied
                | LoginErrorKind::TokenRefused
        );
        (relevant && self.used_saved_registration).then_some(
            "This login reused the client registration saved by an earlier login. \
             If the sign-in page showed an error, retry with `native login --reset` \
             to register a new client.",
        )
    }
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for LoginError {}

impl From<Error> for LoginError {
    fn from(error: Error) -> Self {
        Self::new(LoginErrorKind::Other, error.to_string())
    }
}

impl From<oauth::RenewError> for LoginError {
    fn from(error: oauth::RenewError) -> Self {
        Self::new(LoginErrorKind::Other, error.to_string())
    }
}

pub struct LoginOptions {
    /// Hosted origin (`scheme://host[:port]`), the root of discovery.
    pub hosted_origin: String,
    /// Directory for the credential, auth and registration files.
    pub config_dir: PathBuf,
    /// The token endpoint the node's renewer accepts. Login refuses an
    /// authorization server that names any other, since the node would then
    /// never be able to renew the grant.
    pub expected_token_endpoint: String,
    pub browser: BrowserMode,
    /// Lines pasted by the person (the full callback URL), if offered.
    pub paste: Option<Box<dyn AsyncBufRead + Send + Unpin>>,
    pub timeout: Duration,
    /// Discard the saved client registration and register a new client.
    pub reset: bool,
}

#[derive(Debug)]
pub struct LoginOutcome {
    pub credential_file: PathBuf,
    pub auth_file: PathBuf,
    pub client_file: PathBuf,
    pub client_reused: bool,
    pub expires_at_ms: i64,
}

/// Config and secrets directory: `$XDG_CONFIG_HOME/native` or
/// `~/.config/native` on Linux, `~/Library/Application Support/Native` on macOS.
pub fn default_config_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok().filter(|v| !v.is_empty());
    #[cfg(target_os = "macos")]
    {
        home.map(|h| PathBuf::from(h).join("Library/Application Support/Native"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|h| PathBuf::from(h).join(".config")))
            .map(|base| base.join("native"))
    }
}

pub async fn login(options: LoginOptions) -> std::result::Result<LoginOutcome, LoginError> {
    let LoginOptions {
        hosted_origin,
        config_dir,
        expected_token_endpoint,
        browser,
        paste,
        timeout,
        reset,
    } = options;
    let origin = parse_hosted_origin(&hosted_origin)?;
    let insecure_loopback_ok = is_http_loopback(&origin);
    let config_dir = prepare_config_dir(&config_dir)?;
    let token_path = config_dir.join(TOKEN_FILE);
    let auth_path = config_dir.join(AUTH_FILE);
    let client_path = config_dir.join(CLIENT_FILE);

    let http = oauth::renew_client()?;
    let discovery = discover(&http, &origin, insecure_loopback_ok).await?;
    if discovery.token_endpoint != expected_token_endpoint {
        return Err(LoginError::new(
            LoginErrorKind::UnsupportedAuthorizationServer,
            "this authorization server's token endpoint is not one the node can renew; \
             refusing to sign in",
        ));
    }

    // Bind first: the redirect URI (and so the registration) needs the port.
    let saved = if reset {
        match std::fs::remove_file(&client_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(Error::engine("cannot discard the saved client registration").into())
            }
        }
        None
    } else {
        load_saved_client(&client_path, &discovery.issuer)
    };
    let (listener, saved) = bind_callback_listener(saved).await?;
    let port = listener
        .local_addr()
        .map_err(|_| Error::engine("cannot read the callback listener address"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
    let (client_id, client_reused) = match saved {
        Some(saved) => (saved.client_id, true),
        None => {
            let client_id = register_client(&http, &discovery, &redirect_uri).await?;
            save_client(&client_path, &discovery.issuer, &client_id, &redirect_uri)?;
            (client_id, false)
        }
    };

    let verifier = random_urlsafe(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_urlsafe(32);
    let authorize_url =
        authorization_url(&discovery, &client_id, &redirect_uri, &state, &challenge)?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<CallbackEvent>();
    let accept_task = tokio::spawn(accept_callbacks(listener, state.clone(), tx.clone()));
    let paste_task = paste.map(|reader| {
        tokio::spawn(read_pasted_callbacks(
            reader,
            Url::parse(&redirect_uri).expect("redirect uri is a valid url"),
            state.clone(),
            tx.clone(),
        ))
    });
    drop(tx);

    present_url(browser, &authorize_url, paste_task.is_some());
    let waited = tokio::time::timeout(timeout, rx.recv()).await;
    accept_task.abort();
    if let Some(task) = &paste_task {
        task.abort();
    }
    let code = match waited {
        Err(_) => {
            return Err(LoginError::new(
                LoginErrorKind::TimedOut,
                format!(
                    "timed out after {} seconds waiting for the sign-in callback; \
                     run `native login` again",
                    timeout.as_secs()
                ),
            )
            .using_saved_registration(client_reused))
        }
        Ok(None) => return Err(Error::engine("sign-in callback channel closed").into()),
        Ok(Some(CallbackEvent::Failed(kind, reason))) => {
            return Err(LoginError::new(kind, reason).using_saved_registration(client_reused))
        }
        Ok(Some(CallbackEvent::Code(code))) => code,
    };

    let tokens = exchange_code(
        &http,
        &discovery,
        &client_id,
        &redirect_uri,
        &code,
        &verifier,
        &client_path,
    )
    .await
    .map_err(|error| error.using_saved_registration(client_reused))?;
    let expires_at_ms = oauth::store_login_grant(
        &auth_path,
        &token_path,
        &discovery.token_endpoint,
        &client_id,
        &tokens.access,
        &tokens.refresh,
        tokens.lifetime_secs,
    )
    .await?;
    Ok(LoginOutcome {
        credential_file: token_path,
        auth_file: auth_path,
        client_file: client_path,
        client_reused,
        expires_at_ms,
    })
}

// ---- terminal ---------------------------------------------------------------

/// Turns terminal echo off while it exists and puts the terminal back on drop,
/// so a pasted callback address (it carries the authorization code) is not
/// echoed to the screen or scrollback.
pub struct EchoGuard {
    fd: std::os::fd::RawFd,
    saved: libc::termios,
}

impl EchoGuard {
    /// `None` when `fd` is not a terminal (or echo is already off): nothing to
    /// hide, nothing to restore.
    pub fn disable(fd: std::os::fd::RawFd) -> Option<Self> {
        // SAFETY: plain libc calls on an integer fd and a zeroed termios that
        // tcgetattr fully initialises before it is read.
        unsafe {
            if libc::isatty(fd) != 1 {
                return None;
            }
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut saved) != 0 || saved.c_lflag & libc::ECHO == 0 {
                return None;
            }
            let mut quiet = saved;
            quiet.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(fd, libc::TCSANOW, &quiet) != 0 {
                return None;
            }
            Some(Self { fd, saved })
        }
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: restores the attributes read in `disable`.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

/// Ctrl-C, SIGTERM and SIGHUP, already registered. Build it *before* calling
/// [`login_on_terminal`]: from then on these signals are queued rather than
/// taking their default action, so one arriving before or just after echo is
/// switched off still reaches the guard's cleanup instead of killing the
/// process with the terminal left silent.
pub struct InterruptSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

impl InterruptSignals {
    /// Install the three handlers. Needs a running (or entered) tokio runtime.
    /// An error means no handler is in place; the caller must not go on to
    /// change the terminal.
    pub fn register() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    /// Completes when any of the three has been received (including one that
    /// arrived after registration but before this was first polled).
    pub async fn wait(mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
            _ = self.hangup.recv() => {}
        }
    }
}

/// [`login`] for an interactive terminal: echo on `tty_fd` (stdin) is off for
/// the whole wait and restored on every way out - success, error, timeout, or
/// `interrupt` completing (the binary passes [`InterruptSignals::wait`]). A panic
/// unwinds through the guard too.
pub async fn login_on_terminal(
    options: LoginOptions,
    tty_fd: std::os::fd::RawFd,
    interrupt: impl std::future::Future<Output = ()>,
) -> std::result::Result<LoginOutcome, LoginError> {
    let _echo = EchoGuard::disable(tty_fd);
    tokio::select! {
        outcome = login(options) => outcome,
        () = interrupt => Err(LoginError::new(
            LoginErrorKind::Interrupted,
            "interrupted before the sign-in completed",
        )),
    }
}

// ---- configuration directory ------------------------------------------

/// Create the directory (and missing parents) 0700, then return its canonical
/// path: the node's guards refuse a path that traverses a symlink. A directory
/// that already exists is used as it is only if it is ours and not writable by
/// group or others; its modes are never changed.
pub(crate) fn prepare_config_dir(dir: &Path) -> std::result::Result<PathBuf, LoginError> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    if dir.as_os_str().is_empty() {
        return Err(Error::engine("config directory path is empty").into());
    }
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(Error::engine("config directory path is not a directory").into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(dir)
                .map_err(|_| Error::engine("cannot create the config directory"))?;
        }
        Err(_) => return Err(Error::engine("cannot read the config directory").into()),
    }
    let canonical = std::fs::canonicalize(dir)
        .map_err(|_| Error::engine("cannot resolve the config directory"))?;
    let meta = std::fs::metadata(&canonical)
        .map_err(|_| Error::engine("cannot read the config directory"))?;
    // SAFETY: geteuid has no preconditions or pointer arguments.
    let euid = unsafe { libc::geteuid() };
    config_dir_problem(meta.uid(), meta.mode(), euid).map_or(Ok(canonical.clone()), |problem| {
        Err(LoginError::new(
            LoginErrorKind::ConfigDirUnsafe,
            format!(
                "refusing to use the config directory {}: it {problem}",
                canonical.display()
            ),
        ))
    })
}

/// Why a directory with this owner and mode cannot hold credentials, if so.
fn config_dir_problem(owner: u32, mode: u32, euid: u32) -> Option<&'static str> {
    if owner != euid {
        Some("is owned by another user")
    } else if mode & 0o022 != 0 {
        Some("is writable by group or others (fix it with `chmod go-w`)")
    } else {
        None
    }
}

// ---- discovery ----------------------------------------------------------

#[derive(Debug)]
struct Discovery {
    resource: String,
    issuer: String,
    authorization_endpoint: Url,
    token_endpoint: String,
    registration_endpoint: Option<Url>,
}

pub(crate) fn parse_hosted_origin(raw: &str) -> Result<Url> {
    let url = Url::parse(raw.trim()).map_err(|_| Error::engine("--hosted is not a valid URL"))?;
    let bare = (url.path() == "" || url.path() == "/")
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !bare {
        return Err(Error::engine(
            "--hosted must be an origin like https://host (no path, query or credentials)",
        ));
    }
    if url.scheme() == "http" && !is_http_loopback(&url) {
        return Err(Error::engine("--hosted must use https"));
    }
    Ok(url)
}

fn is_http_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn require_secure(url: &Url, what: &str, insecure_loopback_ok: bool) -> Result<()> {
    let ok = url.host_str().is_some()
        && url.fragment().is_none()
        && (url.scheme() == "https" || (insecure_loopback_ok && is_http_loopback(url)));
    if ok {
        Ok(())
    } else {
        Err(Error::engine(format!("{what} must be an https URL")))
    }
}

async fn get_json(http: &reqwest::Client, url: &Url) -> Result<Option<serde_json::Value>> {
    let response = http
        .get(url.clone())
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|_| Error::engine("cannot reach the hosted sign-in service"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(Error::engine(format!(
            "sign-in discovery failed (HTTP {})",
            status.as_u16()
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| Error::engine("sign-in discovery response unreadable"))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(Error::engine("sign-in discovery response too large"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Error::engine("sign-in discovery response is not JSON"))
}

fn str_field<'a>(doc: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    doc.get(key)
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
}

async fn discover(
    http: &reqwest::Client,
    origin: &Url,
    insecure_loopback_ok: bool,
) -> Result<Discovery> {
    // RFC 9728: the bare well-known path first (hosted serves both forms),
    // then the form suffixed with the resource path.
    let mut doc = None;
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let url = origin
            .join(path)
            .map_err(|_| Error::engine("cannot form the discovery URL"))?;
        if let Some(found) = get_json(http, &url).await? {
            doc = Some(found);
            break;
        }
    }
    let doc = doc.ok_or_else(|| Error::engine("hosted Native publishes no sign-in metadata"))?;
    let resource = str_field(&doc, "resource")
        .ok_or_else(|| Error::engine("protected-resource metadata names no resource"))?
        .to_owned();
    let resource_url = Url::parse(&resource)
        .map_err(|_| Error::engine("protected-resource metadata resource is not a URL"))?;
    if resource_url.fragment().is_some()
        || resource_url.query().is_some()
        || !same_origin(&resource_url, origin)
    {
        return Err(Error::engine(
            "protected-resource metadata names a resource outside the hosted origin",
        ));
    }
    let issuer = doc
        .get("authorization_servers")
        .and_then(|v| v.as_array())
        .and_then(|list| list.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::engine("protected-resource metadata names no authorization server"))?
        .to_owned();
    let issuer_url = Url::parse(&issuer)
        .map_err(|_| Error::engine("authorization server issuer is not a URL"))?;
    require_secure(
        &issuer_url,
        "authorization server issuer",
        insecure_loopback_ok,
    )?;

    // RFC 8414: well-known segment inserted between host and issuer path.
    let issuer_path = issuer_url.path().trim_end_matches('/').to_owned();
    let mut as_doc = None;
    for well_known in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ] {
        let mut url = issuer_url.clone();
        url.set_path(&format!("{well_known}{issuer_path}"));
        url.set_query(None);
        if let Some(found) = get_json(http, &url).await? {
            as_doc = Some(found);
            break;
        }
    }
    let as_doc =
        as_doc.ok_or_else(|| Error::engine("authorization server publishes no metadata"))?;
    if str_field(&as_doc, "issuer") != Some(issuer.as_str()) {
        return Err(Error::engine(
            "authorization server metadata issuer does not match",
        ));
    }
    if let Some(methods) = as_doc
        .get("code_challenge_methods_supported")
        .and_then(|v| v.as_array())
    {
        if !methods.iter().any(|m| m.as_str() == Some("S256")) {
            return Err(Error::engine(
                "authorization server does not support PKCE S256",
            ));
        }
    }
    let endpoint = |key: &str, what: &str| -> Result<Url> {
        let raw = str_field(&as_doc, key)
            .ok_or_else(|| Error::engine(format!("authorization server metadata lacks {what}")))?;
        let url = Url::parse(raw)
            .map_err(|_| Error::engine(format!("authorization server {what} is not a URL")))?;
        require_secure(&url, what, insecure_loopback_ok)?;
        Ok(url)
    };
    let authorization_endpoint = endpoint("authorization_endpoint", "authorization endpoint")?;
    endpoint("token_endpoint", "token endpoint")?;
    let registration_endpoint = if str_field(&as_doc, "registration_endpoint").is_some() {
        Some(endpoint("registration_endpoint", "registration endpoint")?)
    } else {
        None
    };
    Ok(Discovery {
        resource,
        issuer,
        authorization_endpoint,
        // Compared verbatim with the node's expected endpoint, so keep the
        // advertised string rather than a re-serialised URL.
        token_endpoint: str_field(&as_doc, "token_endpoint")
            .unwrap_or_default()
            .to_owned(),
        registration_endpoint,
    })
}

// ---- client registration --------------------------------------------------

struct SavedClient {
    client_id: String,
    port: u16,
}

/// A saved registration is reusable only for the authorization server that
/// issued it and only with the loopback callback it registered.
fn load_saved_client(path: &Path, issuer: &str) -> Option<SavedClient> {
    let bytes = std::fs::read(path)
        .ok()
        .filter(|b| b.len() <= MAX_JSON_BYTES)?;
    let doc: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    if str_field(&doc, "contract")? != CLIENT_CONTRACT || str_field(&doc, "issuer")? != issuer {
        return None;
    }
    let client_id = str_field(&doc, "client_id")?;
    let redirect = Url::parse(str_field(&doc, "redirect_uri")?).ok()?;
    if client_id.len() > MAX_ID_LEN
        || redirect.scheme() != "http"
        || redirect.host_str() != Some("127.0.0.1")
        || redirect.path() != CALLBACK_PATH
    {
        return None;
    }
    Some(SavedClient {
        client_id: client_id.to_owned(),
        port: redirect.port()?,
    })
}

fn save_client(path: &Path, issuer: &str, client_id: &str, redirect_uri: &str) -> Result<()> {
    let doc = serde_json::json!({
        "contract": CLIENT_CONTRACT,
        "issuer": issuer,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    });
    let bytes = serde_json::to_vec(&doc)
        .map_err(|_| Error::engine("cannot serialize the client registration"))?;
    oauth::atomic_private_write(path, &bytes)?;
    Ok(())
}

/// Bind the one-shot listener. A saved registration pins the callback port, so
/// try that port first; if it is taken, fall back to an ephemeral port and
/// register afresh (the saved registration no longer matches).
async fn bind_callback_listener(
    saved: Option<SavedClient>,
) -> Result<(TcpListener, Option<SavedClient>)> {
    if let Some(saved) = saved {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", saved.port)).await {
            return Ok((listener, Some(saved)));
        }
    }
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|_| Error::engine("cannot open a loopback port for the sign-in callback"))?;
    Ok((listener, None))
}

async fn register_client(
    http: &reqwest::Client,
    discovery: &Discovery,
    redirect_uri: &str,
) -> Result<String> {
    let endpoint = discovery.registration_endpoint.clone().ok_or_else(|| {
        Error::engine("authorization server does not offer dynamic client registration")
    })?;
    let response = http
        .post(endpoint)
        .json(&serde_json::json!({
            "client_name": "Native CLI",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .map_err(|_| Error::engine("cannot reach the client registration endpoint"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| Error::engine("client registration response unreadable"))?;
    if !status.is_success() || bytes.len() > MAX_JSON_BYTES {
        return Err(Error::engine(format!(
            "client registration refused (HTTP {})",
            status.as_u16()
        )));
    }
    let doc: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| Error::engine("client registration response is not JSON"))?;
    let client_id = str_field(&doc, "client_id")
        .filter(|id| id.len() <= MAX_ID_LEN && !id.chars().any(char::is_whitespace))
        .ok_or_else(|| Error::engine("client registration returned no usable client_id"))?;
    Ok(client_id.to_owned())
}

// ---- authorization ------------------------------------------------------------

fn random_urlsafe(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn authorization_url(
    discovery: &Discovery,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
) -> Result<Url> {
    let mut url = discovery.authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("resource", &discovery.resource);
    Ok(url)
}

fn present_url(browser: BrowserMode, url: &Url, pasteable: bool) {
    match browser {
        BrowserMode::PrintOnly => {
            eprintln!("Open this address in a browser to sign in to Native:");
            println!("{url}");
            if pasteable {
                eprintln!(
                    "\nIf the browser is on another machine, it will fail to load the \
                     final page: copy that page's full address and paste it here."
                );
            }
        }
        BrowserMode::System => {
            if open_system_browser(url.as_str()) {
                eprintln!("Opening your browser to sign in to Native.");
                eprintln!("If it does not open, visit:");
            } else {
                eprintln!("Could not open a browser. Open this address to sign in to Native:");
            }
            println!("{url}");
        }
        #[cfg(test)]
        BrowserMode::Hook(hook) => hook(url.to_string()),
    }
}

fn open_system_browser(url: &str) -> bool {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    match std::process::Command::new(opener)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            true
        }
        Err(_) => false,
    }
}

// ---- callback handling ---------------------------------------------------------

enum CallbackEvent {
    Code(String),
    Failed(LoginErrorKind, String),
}

/// A request to the callback address, classified.
enum Callback {
    /// Missing or wrong `state`: not part of this login attempt. Answered
    /// with a 400 and otherwise ignored, so a stray request cannot end the
    /// login.
    Foreign,
    /// Carries this attempt's `state`: its outcome is final.
    Final(std::result::Result<String, (LoginErrorKind, String)>),
}

/// Interpret the query of a callback: the authorization code, or why not.
fn parse_callback_query(query: Option<&str>, expected_state: &str) -> Callback {
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }
    if state.as_deref() != Some(expected_state) {
        return Callback::Foreign;
    }
    if let Some(error) = error {
        let safe: String = error
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            .take(64)
            .collect();
        return Callback::Final(Err((
            LoginErrorKind::AuthorizationDenied,
            format!("sign-in was not completed (error: {safe})"),
        )));
    }
    Callback::Final(match code {
        Some(code) if !code.is_empty() && code.len() <= MAX_ID_LEN => Ok(code),
        _ => Err((
            LoginErrorKind::Other,
            "sign-in callback carried no authorization code".to_owned(),
        )),
    })
}

async fn accept_callbacks(
    listener: TcpListener,
    state: String,
    tx: tokio::sync::mpsc::UnboundedSender<CallbackEvent>,
) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        // Per-connection task: a browser's idle speculative connection must
        // not stall the real callback behind it.
        tokio::spawn(handle_connection(stream, state.clone(), tx.clone()));
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    state: String,
    tx: tokio::sync::mpsc::UnboundedSender<CallbackEvent>,
) {
    let request =
        match tokio::time::timeout(REQUEST_READ_TIMEOUT, read_request_head(&mut stream)).await {
            Ok(Some(head)) => head,
            _ => return,
        };
    let target = request_target(&request);
    let Some(target) = target else {
        respond(&mut stream, 400, "Bad request.").await;
        return;
    };
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if path != CALLBACK_PATH {
        respond(&mut stream, 404, "Not found.").await;
        return;
    }
    match parse_callback_query(query, &state) {
        Callback::Foreign => {
            respond(
                &mut stream,
                400,
                "This is not the sign-in callback for the login in progress.",
            )
            .await;
        }
        Callback::Final(Ok(code)) => {
            respond(
                &mut stream,
                200,
                "Signed in to Native. You can close this tab and return to your terminal.",
            )
            .await;
            let _ = tx.send(CallbackEvent::Code(code));
        }
        Callback::Final(Err((kind, reason))) => {
            respond(
                &mut stream,
                400,
                "Sign-in was not completed. Return to your terminal.",
            )
            .await;
            let _ = tx.send(CallbackEvent::Failed(kind, reason));
        }
    }
}

async fn read_request_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        head.extend_from_slice(&chunk[..read]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(head);
        }
        if head.len() > MAX_REQUEST_BYTES {
            return None;
        }
    }
}

/// The request target of a `GET`, or `None` for anything else.
fn request_target(head: &[u8]) -> Option<&str> {
    let line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    (parts.next()? == "GET").then_some(())?;
    parts.next()
}

async fn respond(stream: &mut TcpStream, status: u16, message: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let body =
        format!("<!doctype html><meta charset=\"utf-8\"><title>Native</title><p>{message}</p>");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// `--no-browser`: lines pasted on stdin. A line must be the full callback URL
/// (it is checked against the registered redirect). Other text is ignored with
/// a hint, as is a callback whose `state` is not this attempt's.
async fn read_pasted_callbacks(
    mut reader: Box<dyn AsyncBufRead + Send + Unpin>,
    redirect: Url,
    state: String,
    tx: tokio::sync::mpsc::UnboundedSender<CallbackEvent>,
) {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        let pasted = match Url::parse(text) {
            Ok(url) if same_origin(&url, &redirect) && url.path() == redirect.path() => url,
            _ => {
                eprintln!("That is not the sign-in callback address; paste the full address.");
                continue;
            }
        };
        let event = match parse_callback_query(pasted.query(), &state) {
            Callback::Foreign => {
                eprintln!("That callback is not for this sign-in attempt; ignoring it.");
                continue;
            }
            Callback::Final(Ok(code)) => CallbackEvent::Code(code),
            Callback::Final(Err((kind, reason))) => CallbackEvent::Failed(kind, reason),
        };
        let _ = tx.send(event);
        return;
    }
}

// ---- token exchange ------------------------------------------------------------

struct Tokens {
    access: String,
    refresh: String,
    lifetime_secs: i64,
}

async fn exchange_code(
    http: &reqwest::Client,
    discovery: &Discovery,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
    client_path: &Path,
) -> std::result::Result<Tokens, LoginError> {
    let response = http
        .post(&discovery.token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
            ("resource", discovery.resource.as_str()),
        ])
        .send()
        .await
        .map_err(|_| Error::engine("cannot reach the token endpoint"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| Error::engine("token endpoint response unreadable"))?;
    let payload: Option<serde_json::Value> = if bytes.len() <= MAX_JSON_BYTES {
        serde_json::from_slice(&bytes).ok()
    } else {
        None
    };
    if !status.is_success() {
        let code = payload
            .as_ref()
            .and_then(|p| p.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown");
        let code: String = code
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            .take(64)
            .collect();
        if code == "invalid_client" {
            // The saved registration is no longer accepted: drop it so the
            // next login registers afresh.
            let _ = std::fs::remove_file(client_path);
        }
        return Err(LoginError::new(
            LoginErrorKind::TokenRefused,
            format!(
                "the token endpoint refused the sign-in (HTTP {}, error: {code})",
                status.as_u16()
            ),
        ));
    }
    let payload = payload.ok_or_else(|| Error::engine("token endpoint response is not JSON"))?;
    // Same validation as a refresh response; an empty "current" refresh token
    // makes a missing refresh_token a refusal rather than a fallback.
    let (access, refresh, lifetime_secs) = oauth::check_refresh_response(&payload, "")?;
    Ok(Tokens {
        access,
        refresh,
        lifetime_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Query, State};
    use axum::http::{header::LOCATION, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::collections::HashMap;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A local stand-in for hosted Native (resource metadata) and its
    /// authorization server (metadata, registration, authorize, token).
    #[derive(Default)]
    struct Fake {
        base: Mutex<String>,
        registrations: AtomicUsize,
        registered_redirects: Mutex<Vec<String>>,
        token_hits: AtomicUsize,
        issued: Mutex<HashMap<String, HashMap<String, String>>>,
        token_requests: Mutex<Vec<HashMap<String, String>>>,
        token_error: Mutex<Option<&'static str>>,
        /// Client ids the authorize endpoint refuses to redirect for.
        rejected_clients: Mutex<Vec<String>>,
        /// HTTP statuses the callback listener gave to stray requests.
        stray_statuses: Mutex<Vec<u16>>,
        counter: AtomicUsize,
    }

    impl Fake {
        fn base(&self) -> String {
            self.base.lock().unwrap().clone()
        }
        fn token_endpoint(&self) -> String {
            format!("{}/oauth2/token", self.base())
        }
    }

    async fn resource_metadata(State(fake): State<Arc<Fake>>) -> Json<serde_json::Value> {
        let base = fake.base();
        Json(serde_json::json!({
            "resource": format!("{base}/mcp"),
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
        }))
    }

    async fn as_metadata(State(fake): State<Arc<Fake>>) -> Json<serde_json::Value> {
        let base = fake.base();
        Json(serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/oauth2/token"),
            "registration_endpoint": format!("{base}/register"),
            "code_challenge_methods_supported": ["S256"],
        }))
    }

    async fn register(
        State(fake): State<Arc<Fake>>,
        Json(body): Json<serde_json::Value>,
    ) -> impl IntoResponse {
        assert_eq!(body["token_endpoint_auth_method"], "none");
        let n = fake.registrations.fetch_add(1, Ordering::SeqCst) + 1;
        fake.registered_redirects
            .lock()
            .unwrap()
            .push(body["redirect_uris"][0].as_str().unwrap().to_owned());
        (
            StatusCode::CREATED,
            Json(serde_json::json!({ "client_id": format!("client-{n}") })),
        )
    }

    async fn authorize(
        State(fake): State<Arc<Fake>>,
        Query(params): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["resource"], format!("{}/mcp", fake.base()));
        assert!(!params.contains_key("scope"));
        if fake
            .rejected_clients
            .lock()
            .unwrap()
            .contains(&params["client_id"])
        {
            // An error page, never a redirect back to the client.
            return (StatusCode::BAD_REQUEST, "unknown client").into_response();
        }
        let code = format!("code-{}", fake.counter.fetch_add(1, Ordering::SeqCst) + 1);
        let mut location = Url::parse(&params["redirect_uri"]).unwrap();
        location
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &params["state"]);
        fake.issued.lock().unwrap().insert(code, params);
        (StatusCode::FOUND, [(LOCATION, location.to_string())]).into_response()
    }

    async fn token(State(fake): State<Arc<Fake>>, body: String) -> impl IntoResponse {
        fake.token_hits.fetch_add(1, Ordering::SeqCst);
        let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        fake.token_requests.lock().unwrap().push(form.clone());
        if let Some(error) = *fake.token_error.lock().unwrap() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": error })),
            );
        }
        let invalid = || {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_grant" })),
            )
        };
        let Some(issued) = fake
            .issued
            .lock()
            .unwrap()
            .get(form.get("code").map(String::as_str).unwrap_or(""))
            .cloned()
        else {
            return invalid();
        };
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes()));
        if form["grant_type"] != "authorization_code"
            || challenge != issued["code_challenge"]
            || form["redirect_uri"] != issued["redirect_uri"]
            || form["client_id"] != issued["client_id"]
            || form["resource"] != issued["resource"]
        {
            return invalid();
        }
        let n = fake.counter.fetch_add(1, Ordering::SeqCst);
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "access_token": format!("access-{n}"),
                "refresh_token": format!("refresh-{n}"),
                "expires_in": 3600,
                "token_type": "bearer",
            })),
        )
    }

    async fn start_fake() -> Arc<Fake> {
        let fake = Arc::new(Fake::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        *fake.base.lock().unwrap() = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(resource_metadata),
            )
            .route("/.well-known/oauth-authorization-server", get(as_metadata))
            .route("/register", post(register))
            .route("/authorize", get(authorize))
            .route("/oauth2/token", post(token))
            .with_state(fake.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        fake
    }

    /// What the person does with the sign-in address.
    #[derive(Clone, Copy, PartialEq)]
    enum Person {
        /// The browser follows the redirect back to the loopback listener.
        Browser,
        /// Stray requests hit the callback first, then the real callback.
        BrowserAfterStrays,
        /// Only a callback carrying a different `state` ever arrives.
        BrowserWrongStateOnly,
        /// Headless: junk, then the callback address, pasted on stdin.
        Pastes,
        /// Headless: junk, a callback with another `state`, then the real one.
        PastesAfterStrays,
        /// Headless: only a callback with another `state` is pasted.
        PastesWrongStateOnly,
        /// Never completes the sign-in.
        Walks,
    }

    /// The Location the fake authorization server redirects to, or `None` when
    /// it shows an error page instead.
    async fn approve(authorize_url: &str) -> Option<String> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = http.get(authorize_url).send().await.unwrap();
        if response.status() != StatusCode::FOUND {
            return None;
        }
        Some(response.headers()[LOCATION].to_str().unwrap().to_owned())
    }

    fn with_state(location: &str, state: &str) -> String {
        let mut url = Url::parse(location).unwrap();
        let kept: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(k, _)| k != "state")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.query_pairs_mut()
            .clear()
            .extend_pairs(kept)
            .append_pair("state", state);
        url.to_string()
    }

    fn options(
        fake: &Arc<Fake>,
        config_dir: PathBuf,
        person: Person,
        timeout: Duration,
    ) -> LoginOptions {
        let (mut paste, mut writer) = (None, None);
        if matches!(
            person,
            Person::Pastes | Person::PastesAfterStrays | Person::PastesWrongStateOnly
        ) {
            let (client, server) = tokio::io::duplex(8192);
            paste =
                Some(Box::new(tokio::io::BufReader::new(server))
                    as Box<dyn AsyncBufRead + Send + Unpin>);
            writer = Some(Mutex::new(Some(client)));
        }
        let strays = fake.clone();
        let browser = BrowserMode::Hook(Box::new(move |url: String| {
            let writer = writer.as_ref().and_then(|w| w.lock().unwrap().take());
            let fake = strays.clone();
            tokio::spawn(async move {
                let Some(good) = approve(&url).await else {
                    return;
                };
                match person {
                    Person::Browser => {
                        let _ = reqwest::get(good).await;
                    }
                    Person::BrowserAfterStrays | Person::BrowserWrongStateOnly => {
                        let mut bare = Url::parse(&good).unwrap();
                        bare.set_query(None);
                        let mut other = bare.clone();
                        other.set_path("/elsewhere");
                        let mut statuses = Vec::new();
                        for stray in [bare.to_string(), with_state(&good, "not-the-state")] {
                            statuses.push(reqwest::get(stray).await.unwrap().status().as_u16());
                        }
                        statuses.push(reqwest::get(other).await.unwrap().status().as_u16());
                        *fake.stray_statuses.lock().unwrap() = statuses;
                        if person == Person::BrowserAfterStrays {
                            let _ = reqwest::get(good).await;
                        }
                    }
                    Person::Pastes | Person::PastesAfterStrays | Person::PastesWrongStateOnly => {
                        let mut writer = writer.unwrap();
                        let mut lines = vec!["not a url".to_owned()];
                        if person != Person::Pastes {
                            lines.push(with_state(&good, "not-the-state"));
                        }
                        if person != Person::PastesWrongStateOnly {
                            lines.push(format!("  {good}  "));
                        }
                        for line in lines {
                            writer
                                .write_all(format!("{line}\n").as_bytes())
                                .await
                                .unwrap();
                        }
                        // Hold the pipe open: EOF must not end the wait early.
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    Person::Walks => {}
                }
            });
        }));
        LoginOptions {
            hosted_origin: fake.base(),
            config_dir,
            expected_token_endpoint: fake.token_endpoint(),
            browser,
            paste,
            timeout,
            reset: false,
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o777
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    const WAIT: Duration = Duration::from_secs(20);

    #[tokio::test]
    async fn browser_login_writes_both_guarded_files() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config/native");
        let outcome = login(options(&fake, config.clone(), Person::Browser, WAIT))
            .await
            .unwrap();
        assert!(!outcome.client_reused);

        // Directories are 0700; every file is 0600 in the canonical config dir.
        assert_eq!(mode(&config), 0o700);
        let config = std::fs::canonicalize(config).unwrap();
        assert_eq!(outcome.credential_file, config.join(TOKEN_FILE));
        assert_eq!(outcome.auth_file, config.join(AUTH_FILE));
        for file in [
            &outcome.credential_file,
            &outcome.auth_file,
            &outcome.client_file,
        ] {
            assert_eq!(mode(file), 0o600, "{}", file.display());
        }

        // The auth file is the node's contract, bound to the discovered endpoint.
        let auth = read_json(&outcome.auth_file);
        assert_eq!(auth["contract"], oauth::CONTRACT);
        assert_eq!(auth["token_endpoint"], fake.token_endpoint());
        assert_eq!(auth["client_id"], "client-1");
        assert!(auth["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("refresh-"));
        let access = auth["access_token"].as_str().unwrap();
        assert_eq!(
            std::fs::read_to_string(&outcome.credential_file).unwrap(),
            access
        );
        let expires_at = auth["expires_at"].as_i64().unwrap();
        assert_eq!(expires_at, outcome.expires_at_ms);
        assert!(expires_at > oauth_now_ms() + 3_000_000);

        // The registered client is the loopback callback, saved with its issuer.
        let client = read_json(&outcome.client_file);
        assert_eq!(client["issuer"], fake.base());
        assert_eq!(client["client_id"], "client-1");
        let redirects = fake.registered_redirects.lock().unwrap().clone();
        assert_eq!(redirects.len(), 1);
        assert!(
            redirects[0].starts_with("http://127.0.0.1:") && redirects[0].ends_with("/callback")
        );
        assert_eq!(client["redirect_uri"], redirects[0]);

        // The code exchange was a PKCE exchange for the resource (the fake
        // verified verifier against challenge, redirect and resource).
        let requests = fake.token_requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["grant_type"], "authorization_code");
        assert!(requests[0]["code_verifier"].len() >= 43);

        // The node's own renewer accepts the files as a fresh grant.
        let outcome = oauth::renew_once(
            &outcome.auth_file,
            &outcome.credential_file,
            &fake.token_endpoint(),
            &oauth::renew_client().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(outcome, oauth::RenewOutcome::Fresh);
    }

    fn oauth_now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    #[tokio::test]
    async fn no_browser_paste_path_completes_login() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let outcome = login(options(
            &fake,
            dir.path().join("native"),
            Person::Pastes,
            WAIT,
        ))
        .await
        .unwrap();
        let auth = read_json(&outcome.auth_file);
        assert_eq!(auth["client_id"], "client-1");
        assert_eq!(
            std::fs::read_to_string(&outcome.credential_file).unwrap(),
            auth["access_token"].as_str().unwrap()
        );
        assert_eq!(mode(&outcome.auth_file), 0o600);
    }

    #[tokio::test]
    async fn stray_callbacks_are_answered_and_do_not_end_the_login() {
        for person in [Person::BrowserAfterStrays, Person::PastesAfterStrays] {
            let fake = start_fake().await;
            let dir = tempfile::tempdir().unwrap();
            let outcome = login(options(&fake, dir.path().join("native"), person, WAIT))
                .await
                .unwrap();
            assert_eq!(fake.token_hits.load(Ordering::SeqCst), 1);
            assert!(outcome.credential_file.exists());
            if person == Person::BrowserAfterStrays {
                // Bare callback and wrong state: 400. Another path: 404.
                assert_eq!(*fake.stray_statuses.lock().unwrap(), [400, 400, 404]);
            }
        }
    }

    #[tokio::test]
    async fn a_callback_with_the_wrong_state_never_completes_the_login() {
        for person in [Person::BrowserWrongStateOnly, Person::PastesWrongStateOnly] {
            let fake = start_fake().await;
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("native");
            let error = login(options(
                &fake,
                config.clone(),
                person,
                Duration::from_millis(700),
            ))
            .await
            .unwrap_err();
            assert_eq!(error.kind, LoginErrorKind::TimedOut, "{error}");
            assert_eq!(fake.token_hits.load(Ordering::SeqCst), 0);
            assert!(!config.join(TOKEN_FILE).exists());
            assert!(!config.join(AUTH_FILE).exists());
        }
    }

    #[tokio::test]
    async fn saved_registration_is_reused_on_the_next_login() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native");
        let first = login(options(&fake, config.clone(), Person::Browser, WAIT))
            .await
            .unwrap();
        let second = login(options(&fake, config.clone(), Person::Browser, WAIT))
            .await
            .unwrap();
        assert!(!first.client_reused);
        assert!(second.client_reused);
        assert_eq!(fake.registrations.load(Ordering::SeqCst), 1);
        assert_eq!(fake.token_hits.load(Ordering::SeqCst), 2);
        let requests = fake.token_requests.lock().unwrap().clone();
        assert_eq!(requests[0]["client_id"], "client-1");
        assert_eq!(requests[1]["client_id"], "client-1");
        // The second login replaced the grant in the same files.
        let auth = read_json(&second.auth_file);
        assert_eq!(auth["client_id"], "client-1");
        assert_eq!(
            std::fs::read_to_string(&second.credential_file).unwrap(),
            auth["access_token"].as_str().unwrap()
        );
    }

    #[tokio::test]
    async fn a_registration_from_another_authorization_server_is_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CLIENT_FILE);
        save_client(
            &path,
            "https://as.example",
            "c1",
            "http://127.0.0.1:4455/callback",
        )
        .unwrap();
        assert_eq!(
            load_saved_client(&path, "https://as.example").unwrap().port,
            4455
        );
        assert!(load_saved_client(&path, "https://other.example").is_none());
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load_saved_client(&path, "https://as.example").is_none());
    }

    #[tokio::test]
    async fn waiting_for_a_callback_times_out() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native");
        let started = std::time::Instant::now();
        let error = login(options(
            &fake,
            config.clone(),
            Person::Walks,
            Duration::from_millis(400),
        ))
        .await
        .unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::TimedOut, "{error}");
        assert!(
            error.reset_hint().is_none(),
            "no saved registration was used"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(fake.token_hits.load(Ordering::SeqCst), 0);
        assert!(!config.join(TOKEN_FILE).exists());
        assert!(!config.join(AUTH_FILE).exists());
    }

    #[tokio::test]
    async fn an_authorization_server_the_node_cannot_renew_is_refused_early() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(&fake, dir.path().join("native"), Person::Browser, WAIT);
        opts.expected_token_endpoint =
            "https://plucky-discovery-38.authkit.app/oauth2/token".to_owned();
        let error = login(opts).await.unwrap_err();
        assert_eq!(
            error.kind,
            LoginErrorKind::UnsupportedAuthorizationServer,
            "{error}"
        );
        // Refused before anything was registered, opened or written.
        assert_eq!(fake.registrations.load(Ordering::SeqCst), 0);
        assert!(!dir.path().join("native").join(CLIENT_FILE).exists());
    }

    #[tokio::test]
    async fn a_rejected_client_drops_the_saved_registration() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native");
        login(options(&fake, config.clone(), Person::Browser, WAIT))
            .await
            .unwrap();
        *fake.token_error.lock().unwrap() = Some("invalid_client");
        let error = login(options(&fake, config.clone(), Person::Browser, WAIT))
            .await
            .unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::TokenRefused, "{error}");
        assert!(error.to_string().contains("invalid_client"), "{error}");
        assert!(error.reset_hint().is_some());
        assert!(!config.join(CLIENT_FILE).exists());
        *fake.token_error.lock().unwrap() = None;
        let third = login(options(&fake, config, Person::Browser, WAIT))
            .await
            .unwrap();
        assert!(!third.client_reused);
        assert_eq!(fake.registrations.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn callback_queries_are_interpreted_strictly() {
        fn code(callback: Callback) -> std::result::Result<String, (LoginErrorKind, String)> {
            match callback {
                Callback::Final(result) => result,
                Callback::Foreign => panic!("expected a final callback"),
            }
        }
        assert_eq!(
            code(parse_callback_query(Some("code=abc&state=s1"), "s1")).unwrap(),
            "abc"
        );
        // Without this attempt's state, nothing is final.
        for query in [
            Some("code=abc"),
            None,
            Some("code=abc&state=s2"),
            Some("error=x"),
        ] {
            assert!(matches!(
                parse_callback_query(query, "s1"),
                Callback::Foreign
            ));
        }
        // With it, errors and missing codes are final failures.
        let (kind, message) = code(parse_callback_query(
            Some("error=access_denied&state=s1"),
            "s1",
        ))
        .unwrap_err();
        assert_eq!(kind, LoginErrorKind::AuthorizationDenied);
        assert!(message.contains("access_denied"));
        // Server-supplied error text cannot inject into our message.
        let (_, odd) =
            code(parse_callback_query(Some("error=a%20b%0Ac&state=s1"), "s1")).unwrap_err();
        assert_eq!(odd, "sign-in was not completed (error: abc)");
        assert_eq!(
            code(parse_callback_query(Some("state=s1"), "s1"))
                .unwrap_err()
                .0,
            LoginErrorKind::Other
        );
    }

    #[tokio::test]
    async fn a_rejected_saved_registration_is_recovered_with_reset() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native");
        let first = login(options(&fake, config.clone(), Person::Browser, WAIT))
            .await
            .unwrap();
        assert!(!first.client_reused);

        // The authorization server now rejects that client at the authorize
        // step: an error page, no redirect, so no callback ever arrives.
        fake.rejected_clients
            .lock()
            .unwrap()
            .push("client-1".into());
        let error = login(options(
            &fake,
            config.clone(),
            Person::Browser,
            Duration::from_millis(600),
        ))
        .await
        .unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::TimedOut, "{error}");
        let hint = error
            .reset_hint()
            .expect("a hint to reset the registration");
        assert!(hint.contains("native login --reset"), "{hint}");
        assert_eq!(fake.registrations.load(Ordering::SeqCst), 1);

        // `--reset` discards the saved client and registers a new one.
        let mut reset = options(&fake, config.clone(), Person::Browser, WAIT);
        reset.reset = true;
        let recovered = login(reset).await.unwrap();
        assert!(!recovered.client_reused);
        assert_eq!(fake.registrations.load(Ordering::SeqCst), 2);
        assert_eq!(read_json(&recovered.auth_file)["client_id"], "client-2");
        assert_eq!(read_json(&recovered.client_file)["client_id"], "client-2");

        // And the new registration is the one reused from now on.
        let again = login(options(&fake, config, Person::Browser, WAIT))
            .await
            .unwrap();
        assert!(again.client_reused);
        assert_eq!(fake.registrations.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_config_dir_must_be_ours_and_not_writable_by_others() {
        assert_eq!(config_dir_problem(1000, 0o40700, 1000), None);
        assert_eq!(config_dir_problem(1000, 0o40755, 1000), None);
        assert!(config_dir_problem(0, 0o40700, 1000)
            .unwrap()
            .contains("another user"));
        assert!(config_dir_problem(1000, 0o40775, 1000)
            .unwrap()
            .contains("writable by group or others"));
        assert!(config_dir_problem(1000, 0o40707, 1000).is_some());
        assert!(config_dir_problem(1000, 0o41777, 1000).is_some());
    }

    #[tokio::test]
    async fn an_existing_config_dir_writable_by_others_is_refused_and_left_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        for dir_mode in [0o777, 0o775, 0o757] {
            let fake = start_fake().await;
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("native");
            std::fs::create_dir(&config).unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(dir_mode)).unwrap();
            let error = login(options(&fake, config.clone(), Person::Browser, WAIT))
                .await
                .unwrap_err();
            assert_eq!(error.kind, LoginErrorKind::ConfigDirUnsafe, "{error}");
            assert_eq!(
                mode(&config),
                dir_mode,
                "the directory's mode is not changed"
            );
            assert_eq!(std::fs::read_dir(&config).unwrap().count(), 0);
            assert_eq!(fake.registrations.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn an_existing_private_or_readable_config_dir_is_used_as_it_is() {
        use std::os::unix::fs::PermissionsExt as _;
        for dir_mode in [0o700, 0o755] {
            let fake = start_fake().await;
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("native");
            std::fs::create_dir(&config).unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(dir_mode)).unwrap();
            let outcome = login(options(&fake, config.clone(), Person::Browser, WAIT))
                .await
                .unwrap();
            assert_eq!(
                mode(&config),
                dir_mode,
                "the directory's mode is not changed"
            );
            assert_eq!(mode(&outcome.auth_file), 0o600);
        }
    }

    #[tokio::test]
    async fn a_config_dir_owned_by_another_user_is_refused() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // root owns /usr
        }
        let error = prepare_config_dir(Path::new("/usr")).unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::ConfigDirUnsafe, "{error}");
        assert!(error.to_string().contains("another user"), "{error}");
    }

    // ---- terminal echo ------------------------------------------------

    /// A pseudo-terminal pair; the master must stay open while the slave is used.
    fn open_pty() -> (std::fs::File, std::fs::File) {
        use std::os::fd::FromRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        // SAFETY: plain libc pty setup; the master fd is owned by the File.
        let master = unsafe {
            let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(fd >= 0, "cannot open a pseudo-terminal");
            assert_eq!(libc::grantpt(fd), 0);
            assert_eq!(libc::unlockpt(fd), 0);
            std::fs::File::from_raw_fd(fd)
        };
        // SAFETY: the master fd is open; ptsname returns a valid C string.
        let name = unsafe {
            use std::os::fd::AsRawFd as _;
            let name = libc::ptsname(master.as_raw_fd());
            assert!(!name.is_null());
            std::ffi::CStr::from_ptr(name).to_str().unwrap().to_owned()
        };
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(name)
            .unwrap();
        (master, slave)
    }

    fn echo_on(tty: &std::fs::File) -> bool {
        use std::os::fd::AsRawFd as _;
        // SAFETY: tcgetattr fills a zeroed termios for an open fd.
        unsafe {
            let mut attrs: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(tty.as_raw_fd(), &mut attrs), 0);
            attrs.c_lflag & libc::ECHO != 0
        }
    }

    #[test]
    fn echo_guard_hides_echo_and_restores_it_on_drop() {
        use std::os::fd::AsRawFd as _;
        let (_master, tty) = open_pty();
        assert!(echo_on(&tty), "a fresh terminal echoes");
        let guard = EchoGuard::disable(tty.as_raw_fd()).expect("a terminal");
        assert!(!echo_on(&tty));
        drop(guard);
        assert!(echo_on(&tty));
        // Not a terminal: nothing to hide, nothing to restore.
        let null = std::fs::File::open("/dev/null").unwrap();
        assert!(EchoGuard::disable(null.as_raw_fd()).is_none());
    }

    /// How a terminal login ends, for the echo-restoration test.
    #[derive(Clone, Copy, Debug)]
    enum Exit {
        Success,
        Failure,
        Timeout,
        Interrupt,
    }

    const SIGNAL_CHILD_ENV: &str = "NATIVE_LOGIN_SIGNAL_CHILD";
    const SIGNAL_CHILD_TEST: &str = "native_cli::login::tests::signal_child";
    /// Child modes: the parent sends the signal once echo is off, or the child
    /// raises `before-login:<signo>` against itself.
    const WHILE_ECHO_OFF: &str = "while-echo-off";

    /// Not a test of its own: the subprocess body for
    /// `a_signal_at_startup_still_restores_terminal_echo`. It does what the
    /// `native` binary does - register the real signal handlers, then run
    /// `login_on_terminal` on stdin (a terminal) - against a local fake
    /// server, and exits 0 only if the signal ended the login cleanly.
    #[tokio::test]
    async fn signal_child() {
        let Ok(mode) = std::env::var(SIGNAL_CHILD_ENV) else {
            return;
        };
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let signals = InterruptSignals::register().unwrap();
        println!("registered");
        if let Some(signo) = mode.strip_prefix("before-login:") {
            // The signal arrives after registration but before echo is touched
            // and before the login future is polled: queued, not fatal.
            // SAFETY: raising a signal in this process, whose handler is installed.
            assert_eq!(unsafe { libc::raise(signo.parse().unwrap()) }, 0);
        }
        let opts = options(&fake, dir.path().join("native"), Person::Walks, WAIT);
        let result = login_on_terminal(opts, libc::STDIN_FILENO, signals.wait()).await;
        assert_eq!(
            result.err().map(|e| e.kind),
            Some(LoginErrorKind::Interrupted)
        );
        println!("interrupted-ok");
    }

    /// A child process that is killed if it outlives its deadline or the test
    /// unwinds. The kill goes through `std::process::Child`, which never
    /// signals a child it has already reaped, so a recycled pid cannot be hit.
    struct ChildGuard {
        child: Arc<Mutex<std::process::Child>>,
        cancel: Option<std::sync::mpsc::Sender<()>>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }

    impl ChildGuard {
        fn new(child: std::process::Child, limit: Duration) -> Self {
            let child = Arc::new(Mutex::new(child));
            let (cancel, cancelled) = std::sync::mpsc::channel::<()>();
            let owned = child.clone();
            let watchdog = std::thread::spawn(move || {
                // A message or a dropped sender both mean "stand down".
                if cancelled.recv_timeout(limit) == Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                {
                    let _ = owned.lock().unwrap().kill();
                }
            });
            Self {
                child,
                cancel: Some(cancel),
                watchdog: Some(watchdog),
            }
        }

        fn id(&self) -> u32 {
            self.child.lock().unwrap().id()
        }

        /// Poll rather than block, so the watchdog can take the lock to kill.
        fn wait(&self) -> std::process::ExitStatus {
            loop {
                if let Some(status) = self.child.lock().unwrap().try_wait().unwrap() {
                    return status;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            drop(self.cancel.take());
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
            let mut child = self.child.lock().unwrap();
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// A signal at startup used to take its default action in the window
    /// between echo going off and the handlers being installed, leaving the
    /// terminal silent. Runs the real registration in a subprocess on a
    /// pseudo-terminal, delivers each signal at both edges of that window, and
    /// checks the terminal afterwards.
    #[test]
    fn a_signal_at_startup_still_restores_terminal_echo() {
        use std::io::{BufRead as _, Read as _};
        use std::process::{Command, Stdio};
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            for mode in [WHILE_ECHO_OFF.to_owned(), format!("before-login:{signal}")] {
                let (_master, tty) = open_pty();
                assert!(echo_on(&tty));
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args([
                        SIGNAL_CHILD_TEST,
                        "--exact",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(SIGNAL_CHILD_ENV, &mode)
                    .stdin(Stdio::from(tty.try_clone().unwrap()))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                let stdout = child.stdout.take().unwrap();
                let mut stderr = child.stderr.take().unwrap();
                let guard = ChildGuard::new(child, Duration::from_secs(60));
                let mut lines = std::io::BufReader::new(stdout);
                if mode == WHILE_ECHO_OFF {
                    let mut line = String::new();
                    while !line.contains("registered") {
                        line.clear();
                        assert!(
                            lines.read_line(&mut line).unwrap() > 0,
                            "child exited early"
                        );
                    }
                    let deadline = std::time::Instant::now() + Duration::from_secs(20);
                    while echo_on(&tty) {
                        assert!(std::time::Instant::now() < deadline, "echo never went off");
                        std::thread::yield_now();
                    }
                    // SAFETY: the child is spawned by us and not yet reaped.
                    assert_eq!(unsafe { libc::kill(guard.id() as libc::pid_t, signal) }, 0);
                }
                let status = guard.wait();
                let mut out = String::new();
                lines.read_to_string(&mut out).unwrap();
                let mut errors = String::new();
                stderr.read_to_string(&mut errors).unwrap();
                assert!(
                    status.success() && out.contains("interrupted-ok"),
                    "{mode}: {status:?}\n{out}\n{errors}"
                );
                assert!(echo_on(&tty), "{mode}: echo left off");
            }
        }
    }

    #[tokio::test]
    async fn terminal_echo_is_off_while_waiting_and_restored_on_every_exit() {
        use std::os::fd::AsRawFd as _;
        for exit in [Exit::Success, Exit::Failure, Exit::Timeout, Exit::Interrupt] {
            let (_master, tty) = open_pty();
            let fake = start_fake().await;
            let dir = tempfile::tempdir().unwrap();
            let (person, timeout) = match exit {
                Exit::Success | Exit::Failure => (Person::Browser, WAIT),
                Exit::Timeout => (Person::Walks, Duration::from_millis(500)),
                Exit::Interrupt => (Person::Walks, WAIT),
            };
            let mut opts = options(&fake, dir.path().join("native"), person, timeout);
            if matches!(exit, Exit::Failure) {
                opts.expected_token_endpoint = "https://as.invalid/oauth2/token".into();
            }
            let interrupted = matches!(exit, Exit::Interrupt);
            let (result, echo_while_waiting) = tokio::join!(
                login_on_terminal(opts, tty.as_raw_fd(), async move {
                    if interrupted {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }),
                async {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    echo_on(&tty)
                }
            );
            let kind = result.as_ref().err().map(|e| e.kind);
            match exit {
                Exit::Success => assert!(result.is_ok()),
                Exit::Failure => {
                    assert_eq!(kind, Some(LoginErrorKind::UnsupportedAuthorizationServer))
                }
                Exit::Timeout => assert_eq!(kind, Some(LoginErrorKind::TimedOut)),
                Exit::Interrupt => assert_eq!(kind, Some(LoginErrorKind::Interrupted)),
            }
            if matches!(exit, Exit::Timeout | Exit::Interrupt) {
                assert!(!echo_while_waiting, "echo is off while waiting ({exit:?})");
            }
            assert!(echo_on(&tty), "echo is restored after {exit:?}");
        }
    }

    #[test]
    fn hosted_origin_must_be_a_bare_https_origin() {
        assert!(parse_hosted_origin("https://plugin.withnative.ai").is_ok());
        assert!(parse_hosted_origin("https://plugin.withnative.ai/").is_ok());
        assert!(parse_hosted_origin("https://plugin.withnative.ai/mcp").is_err());
        assert!(parse_hosted_origin("http://plugin.withnative.ai").is_err());
        assert!(parse_hosted_origin("http://127.0.0.1:9").is_ok());
        assert!(parse_hosted_origin("https://u:p@plugin.withnative.ai").is_err());
        assert!(parse_hosted_origin("not a url").is_err());
    }
}
