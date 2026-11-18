//! `native login-node`: opt-in enrollment of a standalone or CE install as the
//! dedicated node OAuth client (754402f's approved first delivery).
//!
//! Legacy `native login`, `setup` and the pilot route are untouched: this flow
//! lives in its own module, writes the node's own guarded grant files into a
//! separate config directory by default, and never performs dynamic client
//! registration.
//!
//! 1. Load or create the install's unique Ed25519 signing key
//!    (`node-install-key`, owner-only 0600, 64 hex chars of raw seed). The
//!    operator gets only the public half: the install id (hex public key) is
//!    printed for the operator to register alongside the provisioned per-node
//!    public client id.
//! 2. Run the existing PKCE Authorization Code flow against the
//!    operator-provisioned **public** client id, the explicit dedicated
//!    resource URL (which must sit on the same hosted origin) and the
//!    registered 127.0.0.1 callback port. The port is bound exactly: a taken
//!    port fails instead of falling back, and no registration endpoint is
//!    ever contacted.
//! 3. Verify the enrollment with hosted *before* persisting anything: an empty
//!    POST to `<origin>/internal/node/verify-enrollment` carries the access
//!    token as bearer and a [`node_credential`](crate::node_credential) proof
//!    over the absolute origin plus the exact path. Hosted must answer 200
//!    with the `account_id` and the `install_id` (hex of this install's
//!    public key). Anything else — refusal, mismatch, unreadable shape —
//!    persists nothing.
//! 4. Only then store the grant with [`oauth::store_enrollment_grant`], which
//!    records the dedicated resource so renewal keeps echoing it back instead
//!    of the standby audience, plus a `node-enrollment.json` record of the
//!    verified binding.
//!
//! Repair and retry semantics mirror `login`: stray or wrong-state callbacks
//! are answered and ignored, pasting validates the full callback address, the
//! shared `<auth>.lock` serialises against a running renewer, and existing
//! grants are never overwritten silently — a repeat run refuses unless
//! `--force` is given, and `--force` still refuses foreign or legacy grants
//! (a grant without this flow's client id and dedicated resource).
//!
//! Tokens, the authorization code and the PKCE verifier are never printed or
//! logged; error text carries categories and OAuth error codes only.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use url::Url;

use crate::error::{Error, Result};
use crate::node::oauth;
use crate::node_credential;

use super::login::{
    self, accept_callbacks, authorization_url, discover, exchange_code, is_http_loopback,
    parse_hosted_origin, prepare_config_dir, present_url, random_urlsafe, read_pasted_callbacks,
    same_origin, AuthorizationCode, LoginError, LoginErrorKind,
};

/// File holding the install's unique Ed25519 private key: the 64 hex chars of
/// the raw 32-byte seed, owner-only 0600. The operator sees only the public
/// half (the printed install id), never this file.
pub const INSTALL_KEY_FILE: &str = "node-install-key";
/// File recording the hosted-verified enrollment binding.
pub const ENROLLMENT_FILE: &str = "node-enrollment.json";
/// Contract marker on the enrollment record (not read back by the node).
const ENROLLMENT_CONTRACT: &str = "native.cli-node-enrollment.v1";
/// Bound on the enrollment verification response body.
const MAX_VERIFY_BYTES: usize = 65_536;

pub struct NodeLoginOptions {
    /// Hosted origin (`scheme://host[:port]`), the root of discovery and of
    /// the dedicated resource and verification target.
    pub hosted_origin: String,
    /// Directory for the signing key, grant and enrollment record. Defaults
    /// to a dedicated directory so legacy grants are never touched.
    pub config_dir: PathBuf,
    /// The token endpoint the node's renewer accepts. Enrollment refuses an
    /// authorization server that names any other, since the node would then
    /// never be able to renew the grant.
    pub expected_token_endpoint: String,
    /// Operator-provisioned per-node *public* client id (no secret).
    pub client_id: String,
    /// Explicit dedicated resource URL on the hosted origin.
    pub resource: String,
    /// Registered 127.0.0.1 callback port. Bound exactly; never 0.
    pub port: u16,
    pub browser: login::BrowserMode,
    /// Lines pasted by the person (the full callback URL), if offered.
    pub paste: Option<Box<dyn tokio::io::AsyncBufRead + Send + Unpin>>,
    pub timeout: Duration,
    /// Re-enroll over this flow's own earlier grant. Foreign or legacy
    /// grants are still refused.
    pub force: bool,
}

#[derive(Debug)]
pub struct NodeLoginOutcome {
    pub credential_file: PathBuf,
    pub auth_file: PathBuf,
    pub key_file: PathBuf,
    pub enrollment_file: PathBuf,
    pub account_id: String,
    pub install_id: String,
    pub expires_at_ms: i64,
}

/// Config and secrets directory for enrolled nodes:
/// `$XDG_CONFIG_HOME/native-node` or `~/.config/native-node` on Linux,
/// `~/Library/Application Support/NativeNode` on macOS. Separate from the
/// legacy login directory so enrollment never shares files with it.
pub fn default_enrollment_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok().filter(|v| !v.is_empty());
    #[cfg(target_os = "macos")]
    {
        home.map(|h| PathBuf::from(h).join("Library/Application Support/NativeNode"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|h| PathBuf::from(h).join(".config")))
            .map(|base| base.join("native-node"))
    }
}

pub async fn login_node(
    options: NodeLoginOptions,
) -> std::result::Result<NodeLoginOutcome, LoginError> {
    let NodeLoginOptions {
        hosted_origin,
        config_dir,
        expected_token_endpoint,
        client_id,
        resource,
        port,
        browser,
        paste,
        timeout,
        force,
    } = options;
    let client_id = valid_client_id(&client_id)?;
    if port == 0 {
        return Err(LoginError::new(
            LoginErrorKind::Other,
            "--port must name the registered callback port, not 0",
        ));
    }
    let origin = parse_hosted_origin(&hosted_origin)?;
    let insecure_loopback_ok = is_http_loopback(&origin);
    let resource = valid_dedicated_resource(&resource, &origin, insecure_loopback_ok)?;
    let config_dir = prepare_config_dir(&config_dir)?;
    let token_path = config_dir.join(login::TOKEN_FILE);
    let auth_path = config_dir.join(login::AUTH_FILE);
    let key_path = config_dir.join(INSTALL_KEY_FILE);
    let record_path = config_dir.join(ENROLLMENT_FILE);
    refuse_existing_grant(&auth_path, &token_path, &client_id, &resource, force)?;

    let signing = load_or_create_signing_key(&key_path)?;
    let install_id = hex::encode(signing.verifying_key().to_bytes());
    // The operator registers this public half out of band; it is printed
    // before any network so a failed run still leaves a usable key.
    eprintln!("Install id for the operator to register:\n{install_id}");

    let http = oauth::renew_client()?;
    let discovery = discover(&http, &origin, insecure_loopback_ok).await?;
    if discovery.token_endpoint != expected_token_endpoint {
        return Err(LoginError::new(
            LoginErrorKind::UnsupportedAuthorizationServer,
            "this authorization server's token endpoint is not one the node can renew; \
             refusing to enroll",
        ));
    }

    // The registered port, bound exactly: no ephemeral fallback and no
    // dynamic registration — the client id is provisioned, not created.
    let listener = TcpListener::bind(("127.0.0.1", port)).await.map_err(|_| {
        LoginError::new(
            LoginErrorKind::Other,
            format!("cannot bind the registered callback port 127.0.0.1:{port}"),
        )
    })?;
    let redirect_uri = format!("http://127.0.0.1:{port}{}", login::CALLBACK_PATH);

    let verifier = random_urlsafe(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_urlsafe(32);
    let authorize_url = authorization_url(
        &discovery,
        &client_id,
        &redirect_uri,
        &state,
        &challenge,
        &resource,
    )?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<login::CallbackEvent>();
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
    // Abort schedules cancellation; joining ensures the listener is
    // destroyed before return, including timeout/error paths with no
    // later await.
    let _ = accept_task.await;
    if let Some(task) = &paste_task {
        task.abort();
    }
    let code = match waited {
        Err(_) => {
            return Err(LoginError::new(
                LoginErrorKind::TimedOut,
                format!(
                    "timed out after {} seconds waiting for the sign-in callback; \
                     run `native login-node` again",
                    timeout.as_secs()
                ),
            ));
        }
        Ok(None) => return Err(Error::engine("sign-in callback channel closed").into()),
        Ok(Some(login::CallbackEvent::Failed(kind, reason))) => {
            return Err(LoginError::new(kind, reason));
        }
        Ok(Some(login::CallbackEvent::Code(code))) => code,
    };

    let tokens = exchange_code(
        &http,
        &discovery,
        &client_id,
        AuthorizationCode {
            redirect_uri: &redirect_uri,
            code: &code,
            verifier: &verifier,
        },
        &resource,
        None,
    )
    .await?;

    // Verify the enrollment with hosted before persisting anything: a
    // refused or mismatched binding leaves no grant behind.
    let account_id =
        verify_enrollment(&http, &origin, &tokens.access, &signing, &install_id).await?;

    let record = serde_json::json!({
        "contract": ENROLLMENT_CONTRACT,
        "client_id": client_id,
        "resource": resource,
        "token_endpoint": discovery.token_endpoint,
        "account_id": account_id,
        "install_id": install_id,
    });
    let serialized = serde_json::to_vec(&record)
        .map_err(|_| Error::engine("cannot serialize the enrollment record"))?;
    oauth::atomic_private_write(&record_path, &serialized)?;
    let expires_at_ms = oauth::store_enrollment_grant(
        &auth_path,
        &token_path,
        oauth::LoginGrant {
            token_endpoint: &discovery.token_endpoint,
            client_id: &client_id,
            access_token: &tokens.access,
            refresh_token: &tokens.refresh,
            lifetime_secs: tokens.lifetime_secs,
        },
        &resource,
    )
    .await?;
    Ok(NodeLoginOutcome {
        credential_file: token_path,
        auth_file: auth_path,
        key_file: key_path,
        enrollment_file: record_path,
        account_id,
        install_id,
        expires_at_ms,
    })
}

/// [`login_node`] for an interactive terminal: echo on `tty_fd` (stdin) is off
/// for the whole wait and restored on every way out — success, error, timeout,
/// or `interrupt` completing. A panic unwinds through the guard too.
pub async fn login_node_on_terminal(
    options: NodeLoginOptions,
    tty_fd: std::os::fd::RawFd,
    interrupt: impl std::future::Future<Output = ()>,
) -> std::result::Result<NodeLoginOutcome, LoginError> {
    let _echo = login::EchoGuard::disable(tty_fd);
    tokio::select! {
        outcome = login_node(options) => outcome,
        () = interrupt => Err(LoginError::new(
            LoginErrorKind::Interrupted,
            "interrupted before the enrollment completed",
        )),
    }
}

// ---- validation -------------------------------------------------------------

/// The operator-provisioned public client id: opaque, bounded, no whitespace.
fn valid_client_id(raw: &str) -> Result<String> {
    let id = raw.trim();
    if id.is_empty() || id.len() > login::MAX_ID_LEN || id.chars().any(char::is_whitespace) {
        return Err(Error::engine(
            "--client-id must be the provisioned public client id",
        ));
    }
    Ok(id.to_owned())
}

/// The dedicated resource URL: an https URL (http only for loopback hosted
/// origins under test) on the same hosted origin, with no query, fragment or
/// credentials.
fn valid_dedicated_resource(raw: &str, origin: &Url, insecure_loopback_ok: bool) -> Result<String> {
    let url = Url::parse(raw.trim()).map_err(|_| Error::engine("--resource is not a valid URL"))?;
    let bare = url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    let secure = url.scheme() == "https" || (insecure_loopback_ok && is_http_loopback(&url));
    if url.host_str().is_none() || !bare || !secure || !same_origin(&url, origin) {
        return Err(Error::engine(
            "--resource must be a dedicated resource URL on the hosted origin",
        ));
    }
    Ok(raw.trim().to_owned())
}

/// Never overwrite silently: without `--force` any existing grant file
/// refuses; with `--force` only this flow's own earlier dedicated grant
/// (dedicated contract, same client id and dedicated resource) may be
/// replaced. Legacy and foreign grants are always refused, whatever extra
/// fields they carry.
fn refuse_existing_grant(
    auth_path: &Path,
    token_path: &Path,
    client_id: &str,
    resource: &str,
    force: bool,
) -> std::result::Result<(), LoginError> {
    if !auth_path.exists() && !token_path.exists() {
        return Ok(());
    }
    if !force {
        return Err(LoginError::new(
            LoginErrorKind::AlreadyEnrolled,
            "this directory already holds a grant; refusing to overwrite it \
             (run again with --force to re-enroll this install)",
        ));
    }
    let own = std::fs::read(auth_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .is_some_and(|auth| {
            auth.get("contract").and_then(|v| v.as_str()) == Some(oauth::DEDICATED_CONTRACT)
                && auth.get("client_id").and_then(|v| v.as_str()) == Some(client_id)
                && auth.get("resource").and_then(|v| v.as_str()) == Some(resource)
        });
    if own {
        return Ok(());
    }
    Err(LoginError::new(
        LoginErrorKind::AlreadyEnrolled,
        "refusing to overwrite a foreign or legacy grant; back it up and remove it, \
         or enroll into another directory",
    ))
}

// ---- install signing key ----------------------------------------------------

/// Load the install's unique signing key, creating and persisting a fresh one
/// when absent. The file holds the 64 hex chars of the raw 32-byte seed,
/// owner-only 0600; a present but unreadable key is an error rather than a
/// silent rotation, so the operator registration keeps pointing at this
/// install.
fn load_or_create_signing_key(key_path: &Path) -> std::result::Result<SigningKey, LoginError> {
    match std::fs::read(key_path) {
        Ok(bytes) => {
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                Error::engine(
                    "the existing install signing key is unusable; remove it and run again",
                )
            })?;
            let raw = hex::decode(text.trim()).map_err(|_| {
                Error::engine(
                    "the existing install signing key is unusable; remove it and run again",
                )
            })?;
            if raw.len() != 32 {
                return Err(Error::engine(
                    "the existing install signing key is unusable; remove it and run again",
                )
                .into());
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            let key = SigningKey::from_bytes(&seed);
            oauth::atomic_private_write(key_path, hex::encode(seed).as_bytes())?;
            Ok(key)
        }
        Err(_) => Err(Error::engine("cannot read the install signing key").into()),
    }
}

// ---- hosted verification ----------------------------------------------------

/// Current time in Unix seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Empty POST over the absolute origin plus the exact verification path,
/// proven by the install key. Returns the bound account id. The caller
/// persists nothing until this succeeds.
async fn verify_enrollment(
    http: &reqwest::Client,
    origin: &Url,
    access_token: &str,
    signing: &SigningKey,
    install_id: &str,
) -> std::result::Result<String, LoginError> {
    let target = format!(
        "{}{}",
        origin.as_str().trim_end_matches('/'),
        node_credential::VERIFY_ENROLLMENT_PATH
    );
    let proof = node_credential::sign(signing, now_secs(), access_token, "POST", &target, b"");
    let response = http
        .post(&target)
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {access_token}"))
        .header(node_credential::PROOF_HEADER, proof)
        .send()
        .await
        .map_err(|_| Error::engine("cannot reach the enrollment verification endpoint"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| Error::engine("enrollment verification response unreadable"))?;
    if bytes.len() > MAX_VERIFY_BYTES {
        return Err(Error::engine("enrollment verification response too large").into());
    }
    let payload: Option<serde_json::Value> = serde_json::from_slice(&bytes).ok();
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
        return Err(LoginError::new(
            LoginErrorKind::EnrollmentRefused,
            format!(
                "hosted refused the enrollment verification (HTTP {}, error: {code})",
                status.as_u16()
            ),
        ));
    }
    let payload =
        payload.ok_or_else(|| Error::engine("enrollment verification response is not JSON"))?;
    let account_id = payload
        .get("account_id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty() && id.len() <= login::MAX_ID_LEN)
        .ok_or_else(|| {
            LoginError::new(
                LoginErrorKind::EnrollmentRefused,
                "hosted verified the enrollment without an account binding",
            )
        })?;
    let returned = payload
        .get("install_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if returned != install_id {
        return Err(LoginError::new(
            LoginErrorKind::EnrollmentRefused,
            "hosted bound the enrollment to a different install key",
        ));
    }
    Ok(account_id.to_owned())
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
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt as _;

    const PROVISIONED_CLIENT: &str = "node-client-7";
    const ACCOUNT_ID: &str = "account-1";

    /// What the person does with the sign-in address.
    #[derive(Clone, Copy, PartialEq)]
    enum Person {
        /// The browser follows the redirect back to the loopback listener.
        Browser,
        /// Only a callback carrying a different `state` ever arrives.
        BrowserWrongStateOnly,
        /// Headless: junk, then the callback address, pasted on stdin.
        Pastes,
        /// Never completes the sign-in.
        Walks,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum VerifyMode {
        Ok,
        Unauthorized,
        WrongKey,
    }

    struct VerifySeen {
        proof: String,
        target: String,
        body_len: usize,
    }

    /// A local stand-in for hosted Native: resource metadata, the
    /// authorization server (metadata, authorize, token — but no dynamic
    /// registration endpoint, which enrollment must never need), and the
    /// enrollment verification route. The verification route checks the
    /// install proof against the key the CLI wrote, exactly like hosted.
    struct Fake {
        base: Mutex<String>,
        key_path: Mutex<Option<PathBuf>>,
        issued: Mutex<HashMap<String, HashMap<String, String>>>,
        token_hits: AtomicUsize,
        authorize_seen: Mutex<Vec<HashMap<String, String>>>,
        token_seen: Mutex<Vec<HashMap<String, String>>>,
        verify_seen: Mutex<Vec<VerifySeen>>,
        verify_hits: AtomicUsize,
        verify_mode: Mutex<VerifyMode>,
        counter: AtomicUsize,
    }

    impl Fake {
        fn base(&self) -> String {
            self.base.lock().unwrap().clone()
        }
        fn dedicated(&self) -> String {
            format!("{}/node", self.base())
        }
        fn token_endpoint(&self) -> String {
            format!("{}/oauth2/token", self.base())
        }
        fn install_key(&self) -> SigningKey {
            let path = self.key_path.lock().unwrap().clone().unwrap();
            let hexed = std::fs::read_to_string(path).unwrap();
            let raw = hex::decode(hexed.trim()).unwrap();
            assert_eq!(raw.len(), 32);
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            SigningKey::from_bytes(&seed)
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
        // Deliberately no `registration_endpoint`: enrollment uses its
        // operator-provisioned client and must never register.
        Json(serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/oauth2/token"),
            "code_challenge_methods_supported": ["S256"],
        }))
    }

    async fn authorize(
        State(fake): State<Arc<Fake>>,
        Query(params): Query<HashMap<String, String>>,
    ) -> impl IntoResponse {
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["client_id"], PROVISIONED_CLIENT);
        // The dedicated resource, not the discovered default.
        assert_eq!(params["resource"], fake.dedicated());
        assert!(!params.contains_key("scope"));
        let redirect = Url::parse(&params["redirect_uri"]).unwrap();
        assert_eq!(redirect.host_str(), Some("127.0.0.1"));
        assert_eq!(redirect.path(), login::CALLBACK_PATH);
        assert!(redirect.port().unwrap_or(0) != 0);
        fake.authorize_seen.lock().unwrap().push(params.clone());
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
        fake.token_seen.lock().unwrap().push(form.clone());
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
            || form["client_id"] != PROVISIONED_CLIENT
            || form["resource"] != fake.dedicated()
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

    async fn verify(
        State(fake): State<Arc<Fake>>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> impl IntoResponse {
        fake.verify_hits.fetch_add(1, Ordering::SeqCst);
        let refused = || {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "node_credential_required" })),
            )
        };
        let mode = *fake.verify_mode.lock().unwrap();
        if mode == VerifyMode::Unauthorized {
            return refused();
        }
        let Some(bearer) = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        else {
            return refused();
        };
        let Some(proof) = headers
            .get(node_credential::PROOF_HEADER)
            .and_then(|v| v.to_str().ok())
        else {
            return refused();
        };
        let target = format!("{}{}", fake.base(), node_credential::VERIFY_ENROLLMENT_PATH);
        fake.verify_seen.lock().unwrap().push(VerifySeen {
            proof: proof.to_owned(),
            target: target.clone(),
            body_len: body.len(),
        });
        if !body.is_empty() {
            return refused();
        }
        let key = fake.install_key();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if !node_credential::verify(
            &key.verifying_key(),
            now,
            bearer,
            "POST",
            &target,
            &body,
            proof,
        ) {
            return refused();
        }
        let install_id = match mode {
            VerifyMode::Ok => hex::encode(key.verifying_key().to_bytes()),
            VerifyMode::WrongKey => hex::encode(
                SigningKey::from_bytes(&[9u8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            VerifyMode::Unauthorized => unreachable!(),
        };
        (
            StatusCode::OK,
            Json(serde_json::json!({ "account_id": ACCOUNT_ID, "install_id": install_id })),
        )
    }

    async fn start_fake() -> Arc<Fake> {
        let fake = Arc::new(Fake {
            base: Mutex::new(String::new()),
            key_path: Mutex::new(None),
            issued: Mutex::new(HashMap::new()),
            token_hits: AtomicUsize::new(0),
            authorize_seen: Mutex::new(Vec::new()),
            token_seen: Mutex::new(Vec::new()),
            verify_seen: Mutex::new(Vec::new()),
            verify_hits: AtomicUsize::new(0),
            verify_mode: Mutex::new(VerifyMode::Ok),
            counter: AtomicUsize::new(0),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        *fake.base.lock().unwrap() = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(resource_metadata),
            )
            .route("/.well-known/oauth-authorization-server", get(as_metadata))
            .route("/authorize", get(authorize))
            .route("/oauth2/token", post(token))
            .route(node_credential::VERIFY_ENROLLMENT_PATH, post(verify))
            .with_state(fake.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        fake
    }

    /// The Location the fake authorization server redirects to, or `None`
    /// when the client is unknown (never for the provisioned client).
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

    fn free_port() -> u16 {
        // Bound and released: the enrollment rebinding races the shared OS
        // allocator, but only this test uses the port afterwards.
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn options(
        fake: &Arc<Fake>,
        config_dir: PathBuf,
        person: Person,
        port: u16,
        timeout: Duration,
        force: bool,
    ) -> NodeLoginOptions {
        let (mut paste, mut writer) = (None, None);
        if person == Person::Pastes {
            let (client, server) = tokio::io::duplex(8192);
            paste = Some(Box::new(tokio::io::BufReader::new(server))
                as Box<dyn tokio::io::AsyncBufRead + Send + Unpin>);
            writer = Some(Mutex::new(Some(client)));
        }
        let browser = login::BrowserMode::Hook(Box::new(move |url: String| {
            let writer = writer.as_ref().and_then(|w| w.lock().unwrap().take());
            tokio::spawn(async move {
                let Some(good) = approve(&url).await else {
                    return;
                };
                match person {
                    Person::Browser => {
                        let _ = reqwest::get(good).await;
                    }
                    Person::BrowserWrongStateOnly => {
                        let _ = reqwest::get(with_state(&good, "not-the-state")).await;
                    }
                    Person::Pastes => {
                        let mut writer = writer.unwrap();
                        for line in ["not a url".to_owned(), format!("  {good}  ")] {
                            writer
                                .write_all(format!("{line}\n").as_bytes())
                                .await
                                .unwrap();
                        }
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    Person::Walks => {}
                }
            });
        }));
        *fake.key_path.lock().unwrap() = Some(config_dir.join(INSTALL_KEY_FILE));
        NodeLoginOptions {
            hosted_origin: fake.base(),
            config_dir,
            expected_token_endpoint: fake.token_endpoint(),
            client_id: PROVISIONED_CLIENT.to_owned(),
            resource: fake.dedicated(),
            port,
            browser,
            paste,
            timeout,
            force,
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
    async fn enrollment_uses_dedicated_claims_and_persists_the_verified_grant() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native-node");
        let port = free_port();
        let outcome = login_node(options(
            &fake,
            config.clone(),
            Person::Browser,
            port,
            WAIT,
            false,
        ))
        .await
        .unwrap();
        assert_eq!(outcome.account_id, ACCOUNT_ID);

        // The install key is the 64 hex chars of the seed, owner-only; the
        // install id is the hex of its public half.
        let seed_hex = std::fs::read_to_string(&outcome.key_file).unwrap();
        assert_eq!(seed_hex.len(), 64);
        let seed = hex::decode(seed_hex.trim()).unwrap();
        assert_eq!(seed.len(), 32);
        let mut seed_raw = [0u8; 32];
        seed_raw.copy_from_slice(&seed);
        let expected_install =
            hex::encode(SigningKey::from_bytes(&seed_raw).verifying_key().to_bytes());
        assert_eq!(outcome.install_id, expected_install);
        assert_eq!(expected_install.len(), 64);

        // Directories are 0700; every file is 0600 in the canonical dir.
        assert_eq!(mode(&config), 0o700);
        let config = std::fs::canonicalize(config).unwrap();
        assert_eq!(outcome.credential_file, config.join(login::TOKEN_FILE));
        assert_eq!(outcome.auth_file, config.join(login::AUTH_FILE));
        for file in [
            &outcome.credential_file,
            &outcome.auth_file,
            &outcome.key_file,
            &outcome.enrollment_file,
        ] {
            assert_eq!(mode(file), 0o600, "{}", file.display());
        }

        // The grant carries the dedicated audience, and the record binds it.
        let auth = read_json(&outcome.auth_file);
        assert_eq!(auth["contract"], oauth::DEDICATED_CONTRACT);
        assert_eq!(auth["token_endpoint"], fake.token_endpoint());
        assert_eq!(auth["client_id"], PROVISIONED_CLIENT);
        assert_eq!(auth["resource"], fake.dedicated());
        assert_eq!(
            std::fs::read_to_string(&outcome.credential_file).unwrap(),
            auth["access_token"].as_str().unwrap()
        );
        let record = read_json(&outcome.enrollment_file);
        assert_eq!(record["account_id"], ACCOUNT_ID);
        assert_eq!(record["install_id"], expected_install);
        assert_eq!(record["client_id"], PROVISIONED_CLIENT);
        assert_eq!(record["resource"], fake.dedicated());

        // The authorize request used the provisioned client, the dedicated
        // resource and the exact registered port — never the discovered
        // default resource, and with no dynamic registration to consult.
        let authorized = fake.authorize_seen.lock().unwrap().clone();
        assert_eq!(authorized.len(), 1);
        let redirect = Url::parse(&authorized[0]["redirect_uri"]).unwrap();
        assert_eq!(redirect.port(), Some(port));

        // The code exchange echoed the dedicated resource for the same
        // client and redirect.
        let exchanges = fake.token_seen.lock().unwrap().clone();
        assert_eq!(exchanges.len(), 1);
        assert_eq!(exchanges[0]["resource"], fake.dedicated());

        // The verification was an empty POST to the absolute origin plus
        // the exact path, proven by the install key.
        {
            let seen = fake.verify_seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(
                seen[0].target,
                format!("{}{}", fake.base(), node_credential::VERIFY_ENROLLMENT_PATH)
            );
            assert_eq!(seen[0].body_len, 0);
            assert!(!seen[0].proof.is_empty());
        }

        // The node's own renewer accepts the stored grant as fresh, and a
        // later renewal keeps echoing the dedicated resource.
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

    #[tokio::test]
    async fn paste_flow_completes_enrollment() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let outcome = login_node(options(
            &fake,
            dir.path().join("native-node"),
            Person::Pastes,
            free_port(),
            WAIT,
            false,
        ))
        .await
        .unwrap();
        assert_eq!(outcome.account_id, ACCOUNT_ID);
        assert_eq!(fake.verify_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn verify_refusal_persists_nothing() {
        let fake = start_fake().await;
        *fake.verify_mode.lock().unwrap() = VerifyMode::Unauthorized;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native-node");
        let error = login_node(options(
            &fake,
            config.clone(),
            Person::Browser,
            free_port(),
            WAIT,
            false,
        ))
        .await
        .unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::EnrollmentRefused, "{error}");
        assert_eq!(fake.token_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fake.verify_hits.load(Ordering::SeqCst), 1);
        // The exchange happened, but the refused binding left no grant, no
        // record, and no token behind. Only the key remains for the retry.
        assert!(!config.join(login::AUTH_FILE).exists());
        assert!(!config.join(login::TOKEN_FILE).exists());
        assert!(!config.join(ENROLLMENT_FILE).exists());
        assert_eq!(
            hex::decode(
                std::fs::read_to_string(config.join(INSTALL_KEY_FILE))
                    .unwrap()
                    .trim()
            )
            .unwrap()
            .len(),
            32
        );
    }

    #[tokio::test]
    async fn mismatched_install_id_persists_nothing() {
        let fake = start_fake().await;
        *fake.verify_mode.lock().unwrap() = VerifyMode::WrongKey;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native-node");
        let error = login_node(options(
            &fake,
            config.clone(),
            Person::Browser,
            free_port(),
            WAIT,
            false,
        ))
        .await
        .unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::EnrollmentRefused, "{error}");
        assert!(!config.join(login::AUTH_FILE).exists());
        assert!(!config.join(login::TOKEN_FILE).exists());
        assert!(!config.join(ENROLLMENT_FILE).exists());
    }

    /// A legacy-shaped grant the enrollment must never touch. With
    /// `extra_resource`, the legacy file also carries a resource field, as an
    /// externally produced file might: still legacy, still refused.
    fn write_legacy_grant(config: &Path, extra_resource: bool) {
        std::fs::create_dir_all(config).unwrap();
        // Enrollment requires an owner-only directory, like the real one.
        std::fs::set_permissions(config, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut auth = serde_json::json!({
            "contract": oauth::CONTRACT,
            "token_endpoint": "https://example.invalid/oauth2/token",
            "access_token": "legacy-access",
            "refresh_token": "legacy-refresh",
            "client_id": "legacy-client-1",
            "expires_at": 9_999_999_999_999_i64,
        });
        if extra_resource {
            auth["resource"] = serde_json::Value::from("https://node.example.test/node");
        }
        std::fs::write(
            config.join(login::AUTH_FILE),
            serde_json::to_vec(&auth).unwrap(),
        )
        .unwrap();
        std::fs::write(config.join(login::TOKEN_FILE), "legacy-access").unwrap();
        std::fs::write(
            config.join("oauth-client.json"),
            "{\"client_id\":\"legacy-client-1\"}",
        )
        .unwrap();
    }

    fn dir_snapshot(config: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut entries: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(config)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), std::fs::read(&path).unwrap())
            })
            .collect();
        entries.sort();
        entries
    }

    #[tokio::test]
    async fn legacy_grants_are_never_overwritten() {
        for (force, extra_resource) in [false, true]
            .into_iter()
            .flat_map(|force| [false, true].map(|extra| (force, extra)))
        {
            let fake = start_fake().await;
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("native");
            write_legacy_grant(&config, extra_resource);
            let before = dir_snapshot(&config);
            let error = login_node(options(
                &fake,
                config.clone(),
                Person::Browser,
                free_port(),
                WAIT,
                force,
            ))
            .await
            .unwrap_err();
            assert_eq!(error.kind, LoginErrorKind::AlreadyEnrolled, "{error}");
            // Byte-identical: no grant touched, and no key, record or new
            // grant appeared beside the legacy files.
            assert_eq!(dir_snapshot(&config), before);
            assert_eq!(fake.token_hits.load(Ordering::SeqCst), 0);
            assert_eq!(fake.verify_hits.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn re_enrollment_needs_force_and_keeps_the_install_key() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native-node");
        let port = free_port();
        let first = login_node(options(
            &fake,
            config.clone(),
            Person::Browser,
            port,
            WAIT,
            false,
        ))
        .await
        .unwrap();
        let before = dir_snapshot(&config);

        // A repeat run refuses rather than overwriting its own grant.
        let error = login_node(options(
            &fake,
            config.clone(),
            Person::Browser,
            port,
            WAIT,
            false,
        ))
        .await
        .unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::AlreadyEnrolled, "{error}");
        assert_eq!(dir_snapshot(&config), before);

        // `--force` re-enrolls the same install: same key and install id, a
        // fresh grant. (Both outcomes share the config directory, so capture
        // the first grant before the second run overwrites it.)
        let first_access = read_json(&first.auth_file)["access_token"].clone();
        let second = login_node(options(
            &fake,
            config.clone(),
            Person::Browser,
            port,
            WAIT,
            true,
        ))
        .await
        .unwrap();
        assert_eq!(second.install_id, first.install_id);
        assert_eq!(
            std::fs::read(config.join(INSTALL_KEY_FILE)).unwrap(),
            std::fs::read(&first.key_file).unwrap()
        );
        assert_eq!(
            read_json(&second.auth_file)["contract"],
            oauth::DEDICATED_CONTRACT
        );
        assert_ne!(read_json(&second.auth_file)["access_token"], first_access);
    }

    #[tokio::test]
    async fn a_callback_with_the_wrong_state_never_completes_enrollment() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native-node");
        let error = login_node(options(
            &fake,
            config.clone(),
            Person::BrowserWrongStateOnly,
            free_port(),
            Duration::from_millis(700),
            false,
        ))
        .await
        .unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::TimedOut, "{error}");
        assert_eq!(fake.token_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fake.verify_hits.load(Ordering::SeqCst), 0);
        assert!(!config.join(login::AUTH_FILE).exists());
        assert!(!config.join(login::TOKEN_FILE).exists());
    }

    #[tokio::test]
    async fn foreign_resource_and_bad_arguments_fail_before_any_network() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        // A resource off the hosted origin, a missing client id and a
        // zero port all fail before discovery or any other network use, and
        // before any directory is created.
        let mut foreign = options(
            &fake,
            dir.path().join("bad-resource"),
            Person::Walks,
            free_port(),
            WAIT,
            false,
        );
        foreign.resource = "https://other.example.test/node".to_owned();
        let mut empty_client = options(
            &fake,
            dir.path().join("bad-client"),
            Person::Walks,
            free_port(),
            WAIT,
            false,
        );
        empty_client.client_id = "   ".to_owned();
        let zero_port = options(
            &fake,
            dir.path().join("bad-port"),
            Person::Walks,
            0,
            WAIT,
            false,
        );
        for bad in [foreign, empty_client, zero_port] {
            let missing = bad.config_dir.clone();
            let error = login_node(bad).await.unwrap_err();
            assert_eq!(error.kind, LoginErrorKind::Other, "{error}");
            assert!(!missing.exists());
        }
        assert_eq!(fake.token_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fake.verify_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_occupied_registered_port_fails_without_fallback() {
        let fake = start_fake().await;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("native-node");
        // Hold the registered port: enrollment must fail on it rather than
        // fall back to an ephemeral one (which would break the registration).
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let error = login_node(options(
            &fake,
            config.clone(),
            Person::Browser,
            port,
            WAIT,
            false,
        ))
        .await
        .unwrap_err();
        assert_eq!(error.kind, LoginErrorKind::Other, "{error}");
        assert!(format!("{error}").contains(&port.to_string()));
        // Discovery ran, but no exchange and no verification were attempted,
        // and nothing was persisted.
        assert_eq!(fake.token_hits.load(Ordering::SeqCst), 0);
        assert_eq!(fake.verify_hits.load(Ordering::SeqCst), 0);
        assert!(fake.authorize_seen.lock().unwrap().is_empty());
        assert!(!config.join(login::AUTH_FILE).exists());
        assert!(!config.join(login::TOKEN_FILE).exists());
        drop(held);
    }
}
