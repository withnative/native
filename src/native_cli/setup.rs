//! `native setup`: turn a signed-in install into a working hosted-node
//! configuration, with no hand edits.
//!
//! After `native login` has written the credential and renewal files, setup
//! discovers everything else from hosted Native itself and writes the three
//! config files the node reads:
//!
//! * `node.json` ([`NodeConfig`]),
//! * the standby config ([`StandbyRuntimeConfig`]),
//! * the refresh config ([`StandbyRefreshConfig`]).
//!
//! Order: identity (`/auth/me`) -> workspace choice -> canonical account
//! (`SELECT current_principal()` on the chosen workspace) -> authority head
//! (`export.authority_act_head`, checked by the same transport the refresh uses)
//! -> standby config -> refresh config -> `node.json` last, so a half-finished
//! setup never leaves a `node.json` pointing at missing files. Every write is
//! atomic, fsynced and 0600; directories are 0700. Re-running makes no change
//! when nothing differs; a differing existing file is refused unless `--force`,
//! and the refusal shows what would change.
//!
//! One origin is used for every hosted call: the OAuth resource's origin (the
//! host the bearer's audience is bound to and the live node already talks to).
//! Config files carry no secrets; tokens are never printed.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::credential_file::read_guarded_credential;
use crate::error::Error;
use crate::native_cli::login::{
    self, parse_hosted_origin, prepare_config_dir, AUTH_FILE, TOKEN_FILE,
};
use crate::node::oauth;
use crate::node::NodeConfig;
use crate::standby::delta_transport::{executor_call, AuthorityActTransport};
use crate::standby::generation_store::GenerationStore;
use crate::standby::{
    StandbyRefreshConfig, StandbyRuntimeConfig, REFRESH_CONFIG_CONTRACT as REFRESH_CONTRACT,
};

pub const NODE_FILE: &str = "node.json";
pub const STANDBY_FILE: &str = "standby.json";
pub const REFRESH_FILE: &str = "standby-refresh.json";

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Keys a person may have added to `node.json` by hand that setup does not
/// generate; they survive a regeneration.
const PRESERVED_NODE_KEYS: [&str; 2] = ["disk_floor_bytes", "markdown_folder"];
/// Likewise for the refresh config's tuning.
const REFRESH_TUNING_KEYS: [&str; 3] = [
    "refresh_interval_seconds",
    "full_refresh_min_interval_seconds",
    "full_refresh_repair_retry_seconds",
];
/// Bound on a config file setup will read.
const MAX_CONFIG_BYTES: usize = 64 * 1024;
/// The fields each config file's schema defines; nothing else is ever shown.
const NODE_KEYS: [&str; 11] = [
    "hosted_base_url",
    "home_id",
    "db_id",
    "account_id",
    "credential_file",
    "oauth_auth_file",
    "socket_directory",
    "standby_config",
    "refresh_config",
    "disk_floor_bytes",
    "markdown_folder",
];
const STANDBY_KEYS: [&str; 3] = [
    "replica_root",
    "hosted_route_database_id",
    "origin_database_id",
];
const REFRESH_KEYS: [&str; 7] = [
    "contract",
    "version",
    "hosted_origin",
    "credential_file",
    "refresh_interval_seconds",
    "full_refresh_min_interval_seconds",
    "full_refresh_repair_retry_seconds",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupErrorKind {
    /// No usable login: run `native login` first.
    NotSignedIn,
    /// The account owns no workspace the node can follow.
    NoWorkspace,
    /// More than one workspace matches (or none was named): pick one.
    ChooseWorkspace,
    /// An existing config differs and `--force` was not given.
    Conflict,
    /// A config input or the socket directory is not something setup (or the
    /// node) will use: a symlink, a file or directory that is not ours, a
    /// directory with the wrong mode.
    UnsafeConfig,
    /// A dry run found the saved sign-in due for renewal; it will not renew.
    RenewalNeeded,
    Other,
}

/// A failed setup. Messages never contain tokens.
#[derive(Debug)]
pub struct SetupError {
    pub kind: SetupErrorKind,
    message: String,
}

impl SetupError {
    fn new(kind: SetupErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SetupError {}

impl From<Error> for SetupError {
    fn from(error: Error) -> Self {
        Self::new(SetupErrorKind::Other, error.to_string())
    }
}

impl From<oauth::RenewError> for SetupError {
    fn from(error: oauth::RenewError) -> Self {
        Self::new(SetupErrorKind::Other, error.to_string())
    }
}

impl From<login::LoginError> for SetupError {
    fn from(error: login::LoginError) -> Self {
        Self::new(SetupErrorKind::Other, error.to_string())
    }
}

type Result<T> = std::result::Result<T, SetupError>;

pub struct SetupOptions {
    /// Hosted origin; the same one `native login` used.
    pub hosted_origin: String,
    /// Where `native login` put the credential and renewal files; the config
    /// files go here too.
    pub config_dir: PathBuf,
    /// The local copy and the node's socket live here.
    pub data_dir: PathBuf,
    /// A workspace id, an unambiguous id prefix, or its exact name.
    pub workspace: Option<String>,
    /// Overwrite existing config files that differ.
    pub force: bool,
    /// Work out and report the changes without writing anything.
    pub dry_run: bool,
    /// The token endpoint the node's renewer accepts (see `login`).
    pub expected_token_endpoint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileChange {
    Created,
    Updated,
    Unchanged,
}

#[derive(Debug)]
pub struct ConfigFile {
    pub path: PathBuf,
    pub change: FileChange,
}

#[derive(Debug)]
pub struct SetupOutcome {
    pub node_config: PathBuf,
    pub workspace_id: String,
    pub workspace_name: Option<String>,
    pub account_id: String,
    pub origin_database_id: String,
    /// The three files in the order they are (or would be) written.
    pub files: Vec<ConfigFile>,
    /// What differs from the files already on disk (empty for a first setup
    /// or a re-run that changes nothing): shown for `--dry-run` and `--force`.
    pub differences: Vec<String>,
    /// Paths actually written, in write order; empty on a dry run or re-run.
    pub written: Vec<PathBuf>,
    pub dry_run: bool,
}

/// Data directory: `$XDG_DATA_HOME/native` or `~/.local/share/native` on Linux,
/// `~/Library/Application Support/Native` on macOS.
pub fn default_data_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok().filter(|v| !v.is_empty());
    #[cfg(target_os = "macos")]
    {
        home.map(|h| PathBuf::from(h).join("Library/Application Support/Native"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::env::var("XDG_DATA_HOME")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|h| PathBuf::from(h).join(".local/share")))
            .map(|base| base.join("native"))
    }
}

pub async fn setup(options: SetupOptions) -> Result<SetupOutcome> {
    let SetupOptions {
        hosted_origin,
        config_dir,
        data_dir,
        workspace,
        force,
        dry_run,
        expected_token_endpoint,
    } = options;
    let origin_url = parse_hosted_origin(&hosted_origin)?;
    let origin = origin_url.origin().ascii_serialization();
    let config_dir = existing_private_dir(&config_dir)?;
    let token_path = config_dir.join(TOKEN_FILE);
    let auth_path = config_dir.join(AUTH_FILE);

    // Config inputs are checked before anything else is read or sent: a
    // symlink or foreign file here must never get as far as a diff.
    let existing_standby = read_existing(&config_dir.join(STANDBY_FILE))?;
    let existing_refresh = read_existing(&config_dir.join(REFRESH_FILE))?;
    let existing_node = read_existing(&config_dir.join(NODE_FILE))?;

    // 0. A fresh bearer. A real run takes the node's own renewal pass (shared
    //    lock, 90 s window). A dry run never writes: it only asks whether the
    //    grant is due, and stops if so.
    let http = oauth::renew_client()?;
    if !auth_path.exists() || !token_path.exists() {
        return Err(not_signed_in());
    }
    if dry_run {
        match oauth::grant_is_due(&auth_path, &expected_token_endpoint) {
            Ok(false) => {}
            Ok(true) => {
                return Err(SetupError::new(
                    SetupErrorKind::RenewalNeeded,
                    "the saved sign-in is due for renewal and a dry run does not renew it; \
                     run `native login`, or let the node renew it, then retry",
                ))
            }
            Err(_) => return Err(not_signed_in()),
        }
    } else {
        match oauth::renew_once(&auth_path, &token_path, &expected_token_endpoint, &http).await {
            Ok(_) => {}
            Err(oauth::RenewError::InvalidGrant) => {
                return Err(SetupError::new(
                    SetupErrorKind::NotSignedIn,
                    "the saved sign-in was rejected; run `native login` again",
                ))
            }
            Err(error) => {
                return Err(SetupError::new(
                    SetupErrorKind::Other,
                    format!("cannot refresh the saved sign-in ({error}); run `native login` again"),
                ))
            }
        }
    }
    let bearer = read_guarded_credential(&token_path, "setup")?;
    let bearer = std::str::from_utf8(&bearer)
        .map_err(|_| Error::engine("credential is not UTF-8"))?
        .to_owned();

    // 1. Identity and workspace choice.
    let candidates = owned_workspaces(&http, &origin, &bearer).await?;
    let chosen = choose_workspace(&candidates, workspace.as_deref())?;

    // 2. The canonical account, as the workspace itself knows the caller.
    let account_id = canonical_account(&http, &origin, &chosen.id, &bearer).await?;

    // 3. The authority head: learn the origin database id, then confirm it
    //    with the transport the refresh uses (route, origin pin, contract).
    let origin_database_id = authority_origin(&http, &origin, &chosen.id, &bearer).await?;
    AuthorityActTransport::new(&origin, &chosen.id, &origin_database_id, &bearer)?
        .head()
        .await?;

    // 4. Plan the three files.
    let data_dir = private_dir(&data_dir, !dry_run)?;
    let replica_root = data_dir.join("replica");
    let socket_directory = data_dir.join("run");
    let standby_path = config_dir.join(STANDBY_FILE);
    let refresh_path = config_dir.join(REFRESH_FILE);
    let node_path = config_dir.join(NODE_FILE);

    let standby = json!({
        "replica_root": replica_root,
        "hosted_route_database_id": chosen.id,
        "origin_database_id": origin_database_id,
    });
    let mut refresh = json!({
        "contract": REFRESH_CONTRACT,
        "version": 1,
        "hosted_origin": origin,
        "credential_file": token_path,
    });
    keep_hand_added(&mut refresh, &existing_refresh, &REFRESH_TUNING_KEYS);
    let mut node = json!({
        "hosted_base_url": origin,
        "home_id": format!("hosted:{}", host_label(&origin_url)),
        "db_id": chosen.id,
        "account_id": account_id,
        "credential_file": token_path,
        "oauth_auth_file": auth_path,
        "socket_directory": socket_directory,
        "standby_config": standby_path,
        "refresh_config": refresh_path,
    });
    keep_hand_added(&mut node, &existing_node, &PRESERVED_NODE_KEYS);

    // The real loaders accept what we are about to write.
    StandbyRuntimeConfig::from_json(&to_bytes(&standby))?;
    StandbyRefreshConfig::from_json(&to_bytes(&refresh)).map_err(|error| {
        SetupError::new(
            SetupErrorKind::Other,
            format!(
                "the refresh config would be invalid ({error}); check the tuning settings \
                 kept from the existing {REFRESH_FILE}"
            ),
        )
    })?;
    serde_json::from_value::<NodeConfig>(node.clone())
        .map_err(|error| Error::engine(format!("generated node config is invalid: {error}")))?;

    let plan = [
        (standby_path, standby, existing_standby, &STANDBY_KEYS[..]),
        (refresh_path, refresh, existing_refresh, &REFRESH_KEYS[..]),
        (node_path.clone(), node, existing_node, &NODE_KEYS[..]),
    ];
    let mut files = Vec::new();
    let mut conflicts = Vec::new();
    for (path, wanted, existing, known) in &plan {
        let change = match existing {
            Existing::Absent => FileChange::Created,
            Existing::Json(existing) if existing == wanted => FileChange::Unchanged,
            Existing::Json(existing) => {
                conflicts.push(describe_difference(path, existing, wanted, known));
                FileChange::Updated
            }
            Existing::NotJson => {
                conflicts.push(format!(
                    "{} is not valid JSON and would be replaced (its contents are not shown)",
                    path.display()
                ));
                FileChange::Updated
            }
        };
        files.push(ConfigFile {
            path: path.clone(),
            change,
        });
    }
    // The node's own rule for an existing socket directory, asked before it
    // is handed over (setup never changes the mode of a directory it did not
    // create).
    if let Err(error) = crate::node::check_socket_directory(&socket_directory) {
        return Err(SetupError::new(
            SetupErrorKind::UnsafeConfig,
            format!(
                "{} exists but the node would refuse it ({error}); it must be a real \
                 directory you own with mode 0700. Fix it (chmod 700) or remove it, then re-run \
                 setup",
                socket_directory.display()
            ),
        ));
    }
    // Likewise the local copy's directory, against the generation store's own
    // rule: an existing replica directory must be owner-only.
    if let Err(error) = GenerationStore::check_existing_root(&replica_root) {
        return Err(SetupError::new(
            SetupErrorKind::UnsafeConfig,
            format!(
                "{} exists but the local copy would refuse it ({error}); it must be a real \
                 directory with no group or other access. Fix it (chmod 700) or remove it, then \
                 re-run setup",
                replica_root.display()
            ),
        ));
    }
    if !conflicts.is_empty() && !force && !dry_run {
        return Err(SetupError::new(
            SetupErrorKind::Conflict,
            format!(
                "existing configuration differs from what setup would write; nothing was changed. \
                 Re-run with --force to replace it.\n{}",
                conflicts.join("\n")
            ),
        ));
    }

    // 5. Write: standby, refresh, then node.json last. Not transactional: if
    //    a later write fails, files already written stay. node.json is last
    //    and a route mismatch fails closed, so the remedy is to re-run setup.
    let mut written = Vec::new();
    if !dry_run {
        private_dir(&replica_root, true)?;
        private_dir(&socket_directory, true)?;
        for ((path, wanted, _, _), file) in plan.iter().zip(&files) {
            if file.change == FileChange::Unchanged {
                continue;
            }
            #[cfg(test)]
            let injected = FAIL_NTH_WRITE.with(|n| {
                let left = n.get();
                n.set(left.saturating_sub(1));
                left == 1
            });
            #[cfg(not(test))]
            let injected = false;
            let result = if injected {
                Err(oauth::RenewError::Refused("injected write failure".into()))
            } else {
                oauth::atomic_private_write(path, &to_bytes(wanted))
            };
            if let Err(error) = result {
                let done = if written.is_empty() {
                    "no file was changed".to_owned()
                } else {
                    format!(
                        "already written: {}",
                        written
                            .iter()
                            .map(|p: &PathBuf| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                return Err(Error::engine(format!(
                    "setup stopped while writing {} ({}); {done}. Setup is not transactional: \
                     re-run `native setup` (with --force if it reports differences) to finish",
                    path.display(),
                    Error::from(error)
                ))
                .into());
            }
            written.push(path.clone());
        }
    }
    Ok(SetupOutcome {
        node_config: node_path,
        workspace_id: chosen.id,
        workspace_name: chosen.name,
        account_id,
        origin_database_id,
        files,
        differences: conflicts,
        written,
        dry_run,
    })
}

fn not_signed_in() -> SetupError {
    SetupError::new(
        SetupErrorKind::NotSignedIn,
        "not signed in (no saved credential found); run `native login` first",
    )
}

fn host_label(origin: &url::Url) -> String {
    match (origin.host_str(), origin.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn to_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("config serialises");
    bytes.push(b'\n');
    bytes
}

/// The config dir must already hold the login files; it is checked, never
/// created here.
fn existing_private_dir(dir: &Path) -> Result<PathBuf> {
    if !dir.is_dir() {
        return Err(not_signed_in());
    }
    Ok(prepare_config_dir(dir)?)
}

/// A private (0700, ours) directory: checked if present, created if asked.
fn private_dir(dir: &Path, create: bool) -> Result<PathBuf> {
    if create || dir.exists() {
        return Ok(prepare_config_dir(dir)?);
    }
    if !dir.is_absolute() {
        return Err(Error::engine("data directory must be an absolute path").into());
    }
    Ok(dir.to_path_buf())
}

#[cfg(test)]
thread_local! {
    /// Test seam: fail the nth config write of this thread's next setup
    /// (1-based; 0 means none).
    static FAIL_NTH_WRITE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// An existing config file, as far as setup is willing to know it.
enum Existing {
    Absent,
    Json(Value),
    /// A regular file we own that is not JSON. Its contents are never shown.
    NotJson,
}

fn unsafe_input(path: &Path, why: &str) -> SetupError {
    SetupError::new(
        SetupErrorKind::UnsafeConfig,
        format!(
            "refusing to read {}: it {why}. Setup only reads config files that are regular \
             files you own; move or remove it and re-run setup",
            path.display()
        ),
    )
}

/// Read an existing config file the way the credential readers read theirs:
/// no symlinks (not even as the last component), a regular single-link file
/// owned by this user, opened `O_NOFOLLOW` and re-checked on the open
/// descriptor, size-bounded. A symlink to the credential files must never be
/// followed into a diff.
fn read_existing(path: &Path) -> Result<Existing> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Existing::Absent),
        Err(_) => return Err(Error::engine(format!("cannot read {}", path.display())).into()),
    };
    // SAFETY: geteuid has no preconditions or pointer arguments.
    let euid = unsafe { libc::geteuid() };
    if meta.file_type().is_symlink() {
        return Err(unsafe_input(path, "is a symbolic link"));
    }
    if !meta.is_file() {
        return Err(unsafe_input(path, "is not a regular file"));
    }
    if meta.uid() != euid {
        return Err(unsafe_input(path, "is owned by another user"));
    }
    if meta.nlink() != 1 {
        return Err(unsafe_input(path, "has more than one hard link"));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| unsafe_input(path, "could not be opened safely"))?;
    let opened = file
        .metadata()
        .map_err(|_| unsafe_input(path, "could not be inspected"))?;
    if !opened.is_file()
        || (opened.dev(), opened.ino()) != (meta.dev(), meta.ino())
        || opened.uid() != euid
        || opened.nlink() != 1
    {
        return Err(unsafe_input(path, "changed while it was being opened"));
    }
    let mut bytes = Vec::new();
    file.take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::engine(format!("cannot read {}", path.display())))?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Ok(Existing::NotJson);
    }
    Ok(serde_json::from_slice(&bytes)
        .map(Existing::Json)
        .unwrap_or(Existing::NotJson))
}

/// Hand-added settings in an existing config carry over, so regenerating it
/// does not undo someone's tuning. The merged result is validated by the
/// caller with the real loader.
fn keep_hand_added(wanted: &mut Value, existing: &Existing, keys: &[&str]) {
    let (Existing::Json(Value::Object(existing)), Some(object)) =
        (existing, wanted.as_object_mut())
    else {
        return;
    };
    for key in keys {
        if let Some(value) = existing.get(*key) {
            object.insert((*key).to_owned(), value.clone());
        }
    }
}

/// A field name that looks like it could hold a secret.
fn looks_secret(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["token", "secret", "key", "password", "bearer", "credential"]
        .iter()
        .any(|word| name.contains(word))
        // The one known field that names a secret's *path*, never its value.
        && name != "credential_file"
}

/// How an old value is shown: only plain scalars of modest length.
fn display_old(value: &Value) -> String {
    match value {
        Value::String(text) if text.chars().count() <= 200 => value.to_string(),
        Value::Number(_) | Value::Bool(_) | Value::Null => value.to_string(),
        _ => "(value not shown)".to_owned(),
    }
}

/// Field-by-field differences, old -> new, over the schema's own fields only.
/// Old values of fields outside the schema, or whose names look secret, are
/// never printed: the file may not be what it should be.
fn describe_difference(path: &Path, existing: &Value, wanted: &Value, known: &[&str]) -> String {
    let empty = Map::new();
    let old = existing.as_object().unwrap_or(&empty);
    let new = wanted.as_object().unwrap_or(&empty);
    let mut lines = vec![format!("{} would change:", path.display())];
    let mut unrecognised = 0usize;
    let keys: std::collections::BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    for key in keys {
        let shown_old = |value: &Value| {
            if known.contains(&key.as_str()) && !looks_secret(key) {
                display_old(value)
            } else {
                "(hidden)".to_owned()
            }
        };
        if !known.contains(&key.as_str()) {
            if old.contains_key(key) && new.get(key) != old.get(key) {
                unrecognised += 1;
            }
            continue;
        }
        match (old.get(key), new.get(key)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => lines.push(format!("  {key}: {} -> {b}", shown_old(a))),
            (Some(a), None) => lines.push(format!("  {key}: {} -> (removed)", shown_old(a))),
            (None, Some(b)) => lines.push(format!("  {key}: (absent) -> {b}")),
            (None, None) => {}
        }
    }
    if unrecognised > 0 {
        lines.push(format!(
            "  {unrecognised} unrecognised field(s) would be removed (names and values not shown)"
        ));
    }
    lines.join("\n")
}

// ---- hosted discovery ------------------------------------------------------

#[derive(Clone, Debug)]
struct Workspace {
    id: String,
    name: Option<String>,
}

async fn authed_get(
    http: &reqwest::Client,
    origin: &str,
    path: &str,
    bearer: &str,
) -> Result<Value> {
    let response = http
        .get(format!("{origin}{path}"))
        .bearer_auth(bearer)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|_| Error::engine("cannot reach hosted Native"))?;
    read_json_response(response, path).await
}

async fn read_json_response(response: reqwest::Response, what: &str) -> Result<Value> {
    let status = response.status();
    if matches!(status.as_u16(), 401 | 403) {
        return Err(SetupError::new(
            SetupErrorKind::NotSignedIn,
            "hosted Native refused the saved sign-in; run `native login` again",
        ));
    }
    if !status.is_success() {
        return Err(Error::engine(format!("{what} failed (HTTP {})", status.as_u16())).into());
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error::engine(format!("{what} response was interrupted")))?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(Error::engine(format!("{what} response too large")).into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::engine(format!("{what} response is not JSON")).into())
}

/// Workspaces the signed-in user owns (only an owner can read the authority
/// head the node follows), with display names when hosted will give them.
async fn owned_workspaces(
    http: &reqwest::Client,
    origin: &str,
    bearer: &str,
) -> Result<Vec<Workspace>> {
    let me = authed_get(http, origin, "/auth/me", bearer).await?;
    let databases = me
        .get("databases")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::engine("/auth/me returned no workspace list"))?;
    let mut owned: Vec<Workspace> = databases
        .iter()
        .filter(|db| db.get("role").and_then(Value::as_str) == Some("owner"))
        .filter_map(|db| db.get("id").and_then(Value::as_str))
        .map(|id| Workspace {
            id: id.to_owned(),
            name: None,
        })
        .collect();
    if owned.is_empty() {
        return Err(SetupError::new(
            SetupErrorKind::NoWorkspace,
            "this account owns no workspace; the local node follows a workspace you own",
        ));
    }
    // Names are a courtesy: a failure here must not block setup.
    if let Ok(directory) = authed_get(http, origin, "/auth/workspaces", bearer).await {
        for entry in directory
            .get("workspaces")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(id), Some(name)) = (
                entry.get("id").and_then(Value::as_str),
                entry.get("name").and_then(Value::as_str),
            ) else {
                continue;
            };
            if let Some(workspace) = owned.iter_mut().find(|w| w.id == id) {
                workspace.name = Some(name.to_owned());
            }
        }
    }
    Ok(owned)
}

fn listing(candidates: &[Workspace]) -> String {
    candidates
        .iter()
        .map(|w| match &w.name {
            Some(name) => format!("  {}  {name}", w.id),
            None => format!("  {}", w.id),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn choose_workspace(candidates: &[Workspace], wanted: Option<&str>) -> Result<Workspace> {
    let Some(wanted) = wanted.map(str::trim).filter(|w| !w.is_empty()) else {
        return match candidates {
            [only] => Ok(only.clone()),
            _ => Err(SetupError::new(
                SetupErrorKind::ChooseWorkspace,
                format!(
                    "you own more than one workspace; choose one with --workspace <id or name>:\n{}",
                    listing(candidates)
                ),
            )),
        };
    };
    // Exact id, then exact name (any case), then a unique id prefix.
    let by_id: Vec<_> = candidates.iter().filter(|w| w.id == wanted).collect();
    let by_name: Vec<_> = candidates
        .iter()
        .filter(|w| {
            w.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(wanted))
        })
        .collect();
    let by_prefix: Vec<_> = candidates
        .iter()
        .filter(|w| wanted.len() >= 4 && w.id.starts_with(wanted))
        .collect();
    for matches in [by_id, by_name, by_prefix] {
        match matches.as_slice() {
            [] => continue,
            [one] => return Ok((*one).clone()),
            many => {
                return Err(SetupError::new(
                    SetupErrorKind::ChooseWorkspace,
                    format!(
                        "\"{wanted}\" matches more than one workspace; use its id:\n{}",
                        listing(&many.iter().map(|w| (*w).clone()).collect::<Vec<_>>())
                    ),
                ))
            }
        }
    }
    Err(SetupError::new(
        SetupErrorKind::ChooseWorkspace,
        format!(
            "no workspace you own matches \"{wanted}\"; choose from:\n{}",
            listing(candidates)
        ),
    ))
}

/// One authenticated MCP `tools/call` to a workspace's route; returns the
/// structured result.
async fn mcp_structured(
    http: &reqwest::Client,
    origin: &str,
    db_id: &str,
    bearer: &str,
    body: Value,
) -> Result<Value> {
    let tool_name = body
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let route = percent_encoding::utf8_percent_encode(db_id, percent_encoding::NON_ALPHANUMERIC);
    let response = http
        .post(format!("{origin}/mcp/{route}"))
        .bearer_auth(bearer)
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("MCP-Protocol-Version", crate::mcp::PROTOCOL_VERSION)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", &tool_name)
        .json(&body)
        .send()
        .await
        .map_err(|_| Error::engine("cannot reach hosted Native"))?;
    let envelope = read_json_response(response, "hosted workspace call").await?;
    if envelope.get("error").is_some()
        || envelope.pointer("/result/isError") == Some(&Value::Bool(true))
    {
        return Err(Error::engine("hosted Native refused the workspace call").into());
    }
    if let Some(structured) = envelope.pointer("/result/structuredContent") {
        return Ok(structured.clone());
    }
    envelope
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or_else(|| Error::engine("hosted Native returned no structured result").into())
}

/// The caller's canonical `acct_...` token. `/auth/me`'s `user.id` is the
/// catalog user UUID, a different namespace; the node's account binding is the
/// engine principal the workspace itself records for the caller.
async fn canonical_account(
    http: &reqwest::Client,
    origin: &str,
    db_id: &str,
    bearer: &str,
) -> Result<String> {
    let body = executor_call(
        "sql_read",
        "query_sql",
        json!({"sql": "SELECT current_principal() AS principal"}),
        Some("json"),
    );
    let result = mcp_structured(http, origin, db_id, bearer, body).await?;
    let principal = result
        .pointer("/rows/0/principal")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::engine("hosted Native did not report your account"))?;
    let ok = principal.starts_with("acct_")
        && principal.len() > 5
        && principal.len() <= 256
        && principal
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'));
    if !ok {
        return Err(Error::engine("hosted Native reported an unusable account id").into());
    }
    Ok(principal.to_owned())
}

/// The workspace's portable origin database id, from its authority head.
async fn authority_origin(
    http: &reqwest::Client,
    origin: &str,
    db_id: &str,
    bearer: &str,
) -> Result<String> {
    // Export is not advertised directly on the hosted lean tool surface.
    let mut body = executor_call("export", "authority_act_head", json!({}), None);
    body["params"]["name"] = json!("call_executor");
    body["params"]["arguments"]["executor"] = json!("export");
    let result = mcp_structured(http, origin, db_id, bearer, body).await?;
    let id = result
        .pointer("/head/origin_database_id")
        .and_then(Value::as_str)
        .filter(|id| crate::identity::is_database_id(id))
        .ok_or_else(|| Error::engine("hosted Native reported no usable authority head"))?;
    Ok(id.to_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::extract::{Path as AxPath, State};
    use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::TcpListener;

    pub(crate) const BEARER: &str = "setup-test-bearer";
    pub(crate) const ACCOUNT: &str = "acct_0123456789abcdef0123456789abcdef";
    pub(crate) const WS_A: &str = "aaaa1111-0000-4000-8000-000000000001";
    const WS_B: &str = "bbbb2222-0000-4000-8000-000000000002";
    const WS_C: &str = "bbbb3333-0000-4000-8000-000000000003";

    /// A local stand-in for hosted Native: identity, workspaces, the
    /// workspace's own account, the authority head, and a token endpoint.
    /// A hosted engine for tests: JSON-RPC request in, reply out.
    pub(crate) type McpHook = Arc<
        dyn Fn(Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Value>> + Send>>
            + Send
            + Sync,
    >;

    pub(crate) struct Hosted {
        pub(crate) base: String,
        /// The serving task; aborting it makes the fake unreachable.
        pub(crate) server: Mutex<Option<tokio::task::JoinHandle<()>>>,
        /// (id, role, name)
        workspaces: Mutex<Vec<(String, String, String)>>,
        accepted_bearer: Mutex<String>,
        /// Request log: "GET /auth/me", "POST /mcp/<db> sql_read", ...
        pub(crate) log: Mutex<Vec<String>>,
        /// Answers `tools/list` and `tools/call` (but not the two calls setup
        /// makes) when set: a test's stand-in for hosted's real engine.
        pub(crate) engine: Mutex<Option<McpHook>>,
        db: crate::Db,
        _dir: tempfile::TempDir,
    }

    fn authorised(hosted: &Hosted, headers: &HeaderMap) -> bool {
        headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == format!("Bearer {}", hosted.accepted_bearer.lock().unwrap()))
    }

    async fn auth_me(
        State(h): State<Arc<Hosted>>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        h.log.lock().unwrap().push("GET /auth/me".into());
        if !authorised(&h, &headers) {
            return (StatusCode::UNAUTHORIZED, Json(json!({})));
        }
        let databases: Vec<Value> = h
            .workspaces
            .lock()
            .unwrap()
            .iter()
            .map(|(id, role, _)| json!({"id": id, "role": role, "kind": "shared", "mcp_path": format!("/mcp/{id}")}))
            .collect();
        // user.id is the catalog UUID, deliberately not the account token.
        (
            StatusCode::OK,
            Json(json!({"user": {"id": WS_A, "email": "a@example.test"}, "databases": databases})),
        )
    }

    async fn auth_workspaces(
        State(h): State<Arc<Hosted>>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        h.log.lock().unwrap().push("GET /auth/workspaces".into());
        if !authorised(&h, &headers) {
            return (StatusCode::UNAUTHORIZED, Json(json!({})));
        }
        let entries: Vec<Value> = h
            .workspaces
            .lock()
            .unwrap()
            .iter()
            .map(|(id, _, name)| json!({"id": id, "name": name, "availability": "available"}))
            .collect();
        (StatusCode::OK, Json(json!({"workspaces": entries})))
    }

    async fn mcp(
        State(h): State<Arc<Hosted>>,
        AxPath(db_id): AxPath<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        let name = body["params"]["name"].as_str().unwrap_or("").to_owned();
        let method = body["method"].as_str().unwrap_or("").to_owned();
        h.log.lock().unwrap().push(format!(
            "POST /mcp/{db_id} {name}{}",
            if name.is_empty() { method.as_str() } else { "" }
        ));
        if !authorised(&h, &headers) {
            return (StatusCode::UNAUTHORIZED, Json(json!({})));
        }
        // Match the hosted lean surface: export is only reachable through
        // call_executor. A direct call must not silently pass this fixture.
        if name == "export" {
            return (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0", "id": body["id"],
                    "result": {"content": [], "isError": true, "structuredContent": {
                        "repair": {"code": "call_executor_required", "retry_ready": true}
                    }}
                })),
            );
        }
        let executor = if name == "call_executor" {
            body["params"]["arguments"]["executor"]
                .as_str()
                .unwrap_or("")
        } else {
            name.as_str()
        };
        // With an engine in place, it answers everything but the two calls
        // setup makes.
        let hook = h.engine.lock().unwrap().clone();
        if let Some(hook) = hook {
            let sql = body["params"]["arguments"]["arguments"]["sql"]
                .as_str()
                .unwrap_or("");
            let setup_call = sql.contains("current_principal()")
                || (executor == "export"
                    && body["params"]["arguments"]["operation"] == "authority_act_head");
            if !setup_call && matches!(method.as_str(), "tools/call" | "tools/list" | "initialize")
            {
                if let Some(reply) = hook(body.clone()).await {
                    return (StatusCode::OK, Json(reply));
                }
            }
        }
        // Anything but the two calls setup makes is a plain empty tool result,
        // which is all a node's background refresh needs to fail politely.
        let structured = match (executor, body["params"]["arguments"]["operation"].as_str()) {
            ("sql_read", Some("query_sql")) => {
                let sql = body["params"]["arguments"]["arguments"]["sql"]
                    .as_str()
                    .unwrap_or("");
                if sql.contains("current_principal()") {
                    assert_eq!(body["params"]["arguments"]["format"], "json");
                    json!({"columns": ["principal"], "rows": [{"principal": ACCOUNT}], "row_count": 1})
                } else {
                    // A node's own catalogue query: nothing to report.
                    json!({"columns": [], "rows": [], "row_count": 0})
                }
            }
            ("export", Some("authority_act_head")) => serde_json::to_value(
                crate::standby::delta_transport::observe_authority_act_head(&h.db, &db_id)
                    .await
                    .unwrap(),
            )
            .unwrap(),
            _ if method == "tools/call" => json!({"unsupported": true}),
            _ => json!({}),
        };
        (
            StatusCode::OK,
            Json(json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "content": [{"type": "text", "text": structured.to_string()}],
                    "structuredContent": structured,
                    "isError": false,
                },
            })),
        )
    }

    async fn token(State(h): State<Arc<Hosted>>, body: String) -> Json<Value> {
        assert!(body.contains("grant_type=refresh_token"));
        h.log.lock().unwrap().push("POST /oauth2/token".into());
        *h.accepted_bearer.lock().unwrap() = "renewed-bearer".into();
        Json(
            json!({"access_token": "renewed-bearer", "refresh_token": "renewed-refresh",
            "expires_in": 3600, "token_type": "bearer"}),
        )
    }

    pub(crate) async fn start_hosted(workspaces: &[(&str, &str, &str)]) -> Arc<Hosted> {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::create_database(dir.path().join("authority.db").to_str().unwrap())
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hosted = Arc::new(Hosted {
            base: format!("http://{}", listener.local_addr().unwrap()),
            server: Mutex::new(None),
            workspaces: Mutex::new(
                workspaces
                    .iter()
                    .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
                    .collect(),
            ),
            accepted_bearer: Mutex::new(BEARER.into()),
            log: Mutex::new(Vec::new()),
            engine: Mutex::new(None),
            db,
            _dir: dir,
        });
        serve(&hosted, listener);
        hosted
    }

    fn serve(hosted: &Arc<Hosted>, listener: TcpListener) {
        let app = Router::new()
            .route("/auth/me", get(auth_me))
            .route("/auth/workspaces", get(auth_workspaces))
            .route("/mcp/{db}", post(mcp))
            .route("/oauth2/token", post(token))
            .with_state(hosted.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        *hosted.server.lock().unwrap() = Some(task);
    }

    impl Hosted {
        /// The fake authority's database (its origin id is what setup records).
        pub(crate) fn db(&self) -> &crate::Db {
            &self.db
        }

        /// Stop serving: later connections are refused.
        pub(crate) fn shut_down(&self) {
            if let Some(task) = self.server.lock().unwrap().take() {
                task.abort();
            }
        }

        /// Serve again on the address it had before `shut_down`.
        pub(crate) async fn restart(self: &Arc<Self>) {
            let address = self.base.trim_start_matches("http://");
            let listener = TcpListener::bind(address).await.unwrap();
            serve(self, listener);
        }
    }

    pub(crate) struct Install {
        _dir: tempfile::TempDir,
        pub(crate) config: PathBuf,
        pub(crate) data: PathBuf,
    }

    /// What `native login` leaves behind, written with the same writer it uses.
    pub(crate) async fn signed_in(hosted: &Hosted, lifetime_secs: i64) -> Install {
        let dir = tempfile::tempdir().unwrap();
        let config = std::fs::canonicalize(dir.path()).unwrap().join("config");
        let data = std::fs::canonicalize(dir.path()).unwrap().join("data");
        let config = prepare_config_dir(&config).unwrap();
        oauth::store_login_grant(
            &config.join(AUTH_FILE),
            &config.join(TOKEN_FILE),
            &format!("{}/oauth2/token", hosted.base),
            "client-1",
            BEARER,
            "refresh-1",
            lifetime_secs,
        )
        .await
        .unwrap();
        Install {
            _dir: dir,
            config,
            data,
        }
    }

    pub(crate) fn options(hosted: &Hosted, install: &Install) -> SetupOptions {
        SetupOptions {
            hosted_origin: hosted.base.clone(),
            config_dir: install.config.clone(),
            data_dir: install.data.clone(),
            workspace: None,
            force: false,
            dry_run: false,
            expected_token_endpoint: format!("{}/oauth2/token", hosted.base),
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o777
    }

    fn json_of(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn setup_writes_configs_the_real_loaders_accept_node_json_last() {
        let hosted =
            start_hosted(&[(WS_A, "owner", "Native HQ"), (WS_B, "member", "Shared")]).await;
        let install = signed_in(&hosted, 3600).await;
        let outcome = setup(options(&hosted, &install)).await.unwrap();

        // Written in order, node.json last.
        let config = &install.config;
        assert_eq!(
            outcome.written,
            [
                config.join(STANDBY_FILE),
                config.join(REFRESH_FILE),
                config.join(NODE_FILE)
            ]
        );
        assert_eq!(outcome.workspace_id, WS_A);
        assert_eq!(outcome.workspace_name.as_deref(), Some("Native HQ"));
        assert_eq!(
            outcome.account_id, ACCOUNT,
            "the engine principal, not /auth/me user.id"
        );

        // Parse with the real loaders.
        let node: NodeConfig =
            serde_json::from_slice(&std::fs::read(config.join(NODE_FILE)).unwrap()).unwrap();
        let standby =
            StandbyRuntimeConfig::from_json(&std::fs::read(config.join(STANDBY_FILE)).unwrap())
                .unwrap();
        let refresh =
            StandbyRefreshConfig::from_json(&std::fs::read(config.join(REFRESH_FILE)).unwrap())
                .unwrap();
        assert_eq!(node.hosted_base_url, hosted.base);
        assert_eq!(
            node.home_id,
            format!(
                "hosted:{}",
                host_label(&url::Url::parse(&hosted.base).unwrap())
            )
        );
        assert_eq!(node.db_id, WS_A);
        assert_eq!(node.account_id.as_deref(), Some(ACCOUNT));
        assert_eq!(node.credential_file, config.join(TOKEN_FILE));
        assert_eq!(
            node.oauth_auth_file.as_deref(),
            Some(config.join(AUTH_FILE).as_path())
        );
        assert_eq!(
            node.standby_config.as_deref(),
            Some(config.join(STANDBY_FILE).as_path())
        );
        assert_eq!(
            node.refresh_config.as_deref(),
            Some(config.join(REFRESH_FILE).as_path())
        );
        assert_eq!(node.socket_directory, install.data.join("run"));
        assert_eq!(standby.hosted_route_database_id, node.db_id);
        assert_eq!(standby.replica_root, install.data.join("replica"));
        assert!(crate::identity::is_database_id(&standby.origin_database_id));
        assert_eq!(refresh.hosted_origin, hosted.base);
        assert_eq!(refresh.credential_file, node.credential_file);

        // Modes: files 0600, directories 0700.
        for file in [STANDBY_FILE, REFRESH_FILE, NODE_FILE] {
            assert_eq!(mode(&config.join(file)), 0o600, "{file}");
        }
        for dir in [
            &install.data,
            &install.data.join("replica"),
            &install.data.join("run"),
        ] {
            assert_eq!(mode(dir), 0o700, "{}", dir.display());
        }
        // No secret in any config file.
        for file in [STANDBY_FILE, REFRESH_FILE, NODE_FILE] {
            let text = std::fs::read_to_string(config.join(file)).unwrap();
            assert!(
                !text.contains(BEARER) && !text.contains("refresh-1"),
                "{file}"
            );
        }

        // Discovery order: identity, names, account, then the head.
        let log = hosted.log.lock().unwrap().clone();
        assert_eq!(
            &log[..3],
            [
                "GET /auth/me",
                "GET /auth/workspaces",
                &format!("POST /mcp/{WS_A} sql_read")
            ]
        );
        assert_eq!(log[3], format!("POST /mcp/{WS_A} call_executor"));
    }

    #[tokio::test]
    async fn rerunning_setup_changes_nothing() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        setup(options(&hosted, &install)).await.unwrap();
        let stamps = |install: &Install| {
            [STANDBY_FILE, REFRESH_FILE, NODE_FILE].map(|f| {
                std::fs::metadata(install.config.join(f))
                    .unwrap()
                    .modified()
                    .unwrap()
            })
        };
        let before = stamps(&install);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let again = setup(options(&hosted, &install)).await.unwrap();
        assert!(again.written.is_empty());
        assert!(again.differences.is_empty());
        assert!(again
            .files
            .iter()
            .all(|f| f.change == FileChange::Unchanged));
        assert_eq!(stamps(&install), before, "files were not rewritten");
    }

    #[tokio::test]
    async fn a_differing_node_json_is_refused_unless_forced_and_hand_tuning_survives() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        setup(options(&hosted, &install)).await.unwrap();
        let node_path = install.config.join(NODE_FILE);
        let mut edited = json_of(&node_path);
        edited["home_id"] = json!("my-own-label");
        edited["disk_floor_bytes"] = json!(12345);
        std::fs::write(&node_path, serde_json::to_vec(&edited).unwrap()).unwrap();
        let before = std::fs::read(&node_path).unwrap();

        let error = setup(options(&hosted, &install)).await.unwrap_err();
        assert_eq!(error.kind, SetupErrorKind::Conflict, "{error}");
        let message = error.to_string();
        assert!(
            message.contains("home_id") && message.contains("my-own-label"),
            "{message}"
        );
        assert!(message.contains("--force"));
        assert_eq!(
            std::fs::read(&node_path).unwrap(),
            before,
            "nothing was changed"
        );

        // A dry run reports the same difference and still writes nothing.
        let mut dry = options(&hosted, &install);
        dry.dry_run = true;
        let outcome = setup(dry).await.unwrap();
        assert!(outcome.written.is_empty() && !outcome.differences.is_empty());
        assert_eq!(std::fs::read(&node_path).unwrap(), before);

        // Forced: replaced, hand-added tuning kept, and the change is shown.
        let mut forced = options(&hosted, &install);
        forced.force = true;
        let outcome = setup(forced).await.unwrap();
        assert_eq!(outcome.written, std::slice::from_ref(&node_path));
        assert!(outcome.differences[0].contains("home_id"));
        let rewritten = json_of(&node_path);
        assert_eq!(
            rewritten["home_id"],
            json!(format!(
                "hosted:{}",
                host_label(&url::Url::parse(&hosted.base).unwrap())
            ))
        );
        assert_eq!(rewritten["disk_floor_bytes"], json!(12345));
        assert_eq!(mode(&node_path), 0o600);
    }

    #[tokio::test]
    async fn several_workspaces_need_a_choice_and_workspace_selects_one() {
        let hosted = start_hosted(&[
            (WS_A, "owner", "Native HQ"),
            (WS_B, "owner", "Side Project"),
            (WS_C, "owner", "Side Notes"),
            ("cccc4444-0000-4000-8000-000000000004", "member", "Not Mine"),
        ])
        .await;
        let install = signed_in(&hosted, 3600).await;

        // No choice: an error that lists the owned workspaces (and only those).
        let error = setup(options(&hosted, &install)).await.unwrap_err();
        assert_eq!(error.kind, SetupErrorKind::ChooseWorkspace);
        let message = error.to_string();
        for needle in [WS_A, WS_B, WS_C, "Native HQ", "Side Project", "--workspace"] {
            assert!(message.contains(needle), "{needle}: {message}");
        }
        assert!(!message.contains("Not Mine"));
        assert!(!install.config.join(NODE_FILE).exists());

        // Ambiguous and unknown choices are refused the same way.
        for (wanted, fragment) in [
            ("bbbb", "more than one"),
            ("side", "no workspace"),
            ("nope", "no workspace"),
        ] {
            let mut opts = options(&hosted, &install);
            opts.workspace = Some(wanted.into());
            let error = setup(opts).await.unwrap_err();
            assert_eq!(error.kind, SetupErrorKind::ChooseWorkspace, "{wanted}");
            assert!(error.to_string().contains(fragment), "{wanted}: {error}");
        }
        // A workspace you only belong to cannot be chosen.
        let mut opts = options(&hosted, &install);
        opts.workspace = Some("cccc4444".into());
        assert_eq!(
            setup(opts).await.unwrap_err().kind,
            SetupErrorKind::ChooseWorkspace
        );

        // By name (any case), by unique id prefix, by exact id.
        for (wanted, expected) in [("side project", WS_B), ("bbbb3", WS_C), (WS_A, WS_A)] {
            let install = signed_in(&hosted, 3600).await;
            let mut opts = options(&hosted, &install);
            opts.workspace = Some(wanted.into());
            let outcome = setup(opts).await.unwrap();
            assert_eq!(outcome.workspace_id, expected, "{wanted}");
            assert_eq!(
                json_of(&install.config.join(NODE_FILE))["db_id"],
                json!(expected)
            );
        }
    }

    #[tokio::test]
    async fn an_account_that_owns_no_workspace_and_a_missing_login_are_explained() {
        let hosted = start_hosted(&[(WS_B, "member", "Shared")]).await;
        let install = signed_in(&hosted, 3600).await;
        let error = setup(options(&hosted, &install)).await.unwrap_err();
        assert_eq!(error.kind, SetupErrorKind::NoWorkspace, "{error}");

        let empty = tempfile::tempdir().unwrap();
        let mut opts = options(&hosted, &install);
        opts.config_dir = std::fs::canonicalize(empty.path()).unwrap();
        let error = setup(opts).await.unwrap_err();
        assert_eq!(error.kind, SetupErrorKind::NotSignedIn, "{error}");
        assert!(error.to_string().contains("native login"));
    }

    #[tokio::test]
    async fn an_expired_token_is_renewed_before_discovery() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        // A grant that is already inside the renewal window.
        let install = signed_in(&hosted, 1).await;
        setup(options(&hosted, &install)).await.unwrap();
        let log = hosted.log.lock().unwrap().clone();
        assert_eq!(log[0], "POST /oauth2/token", "{log:?}");
        assert_eq!(
            std::fs::read_to_string(install.config.join(TOKEN_FILE)).unwrap(),
            "renewed-bearer"
        );
    }

    #[tokio::test]
    async fn a_failed_write_never_leaves_a_node_json_behind_and_says_to_rerun() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        // The second write (the refresh config) fails after standby.json landed.
        FAIL_NTH_WRITE.with(|n| n.set(2));
        let error = setup(options(&hosted, &install)).await.unwrap_err();
        FAIL_NTH_WRITE.with(|n| n.set(0));
        assert_eq!(error.kind, SetupErrorKind::Other, "{error}");
        let message = error.to_string();
        assert!(message.contains("re-run `native setup`"), "{message}");
        assert!(
            message.contains(STANDBY_FILE) && message.contains("already written"),
            "{message}"
        );
        assert!(install.config.join(STANDBY_FILE).exists());
        assert!(!install.config.join(REFRESH_FILE).exists());
        assert!(
            !install.config.join(NODE_FILE).exists(),
            "node.json is last"
        );
        // Re-running finishes the job.
        let outcome = setup(options(&hosted, &install)).await.unwrap();
        assert_eq!(
            outcome.written,
            [
                install.config.join(REFRESH_FILE),
                install.config.join(NODE_FILE)
            ]
        );
    }

    /// Text that must never reach output: the bearer and refresh token.
    fn assert_no_secrets(text: &str) {
        for secret in [BEARER, "refresh-1", "LEAK-ME-ACCESS", "LEAK-ME-REFRESH"] {
            assert!(!text.contains(secret), "{secret} leaked into: {text}");
        }
    }

    #[tokio::test]
    async fn a_config_that_links_to_the_credential_files_is_refused_without_a_leak() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        for config_file in [NODE_FILE, STANDBY_FILE, REFRESH_FILE] {
            for target in [AUTH_FILE, TOKEN_FILE] {
                for hard in [false, true] {
                    let install = signed_in(&hosted, 3600).await;
                    let link = install.config.join(config_file);
                    let target_path = install.config.join(target);
                    if hard {
                        std::fs::hard_link(&target_path, &link).unwrap();
                    } else {
                        std::os::unix::fs::symlink(&target_path, &link).unwrap();
                    }
                    let before = std::fs::read(&target_path).unwrap();
                    for (force, dry_run) in [(false, false), (false, true), (true, false)] {
                        let mut opts = options(&hosted, &install);
                        opts.force = force;
                        opts.dry_run = dry_run;
                        let error = setup(opts).await.unwrap_err();
                        let context = format!(
                            "{config_file} -> {target} hard={hard} force={force} dry={dry_run}"
                        );
                        assert_eq!(
                            error.kind,
                            SetupErrorKind::UnsafeConfig,
                            "{context}: {error}"
                        );
                        assert_no_secrets(&error.to_string());
                        assert!(error.to_string().contains(config_file), "{context}");
                    }
                    assert_eq!(
                        std::fs::read(&target_path).unwrap(),
                        before,
                        "credentials untouched"
                    );
                    assert!(!install.config.join(NODE_FILE).exists() || config_file == NODE_FILE);
                }
            }
        }
        // Not a regular file either.
        let install = signed_in(&hosted, 3600).await;
        std::fs::create_dir(install.config.join(NODE_FILE)).unwrap();
        let error = setup(options(&hosted, &install)).await.unwrap_err();
        assert_eq!(error.kind, SetupErrorKind::UnsafeConfig, "{error}");
    }

    #[tokio::test]
    async fn a_diff_shows_only_schema_fields_and_hides_everything_else() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        // A regular file that happens to carry credential-shaped fields.
        let node_path = install.config.join(NODE_FILE);
        std::fs::write(
            &node_path,
            serde_json::to_vec(&json!({
                "home_id": "old-home",
                "access_token": "LEAK-ME-ACCESS",
                "refresh_token": "LEAK-ME-REFRESH",
                "api_key": "LEAK-ME-ACCESS",
                "nested": {"anything": "LEAK-ME-REFRESH"},
                "db_id": "x".repeat(500),
            }))
            .unwrap(),
        )
        .unwrap();
        let error = setup(options(&hosted, &install)).await.unwrap_err();
        assert_eq!(error.kind, SetupErrorKind::Conflict, "{error}");
        let message = error.to_string();
        assert_no_secrets(&message);
        assert!(message.contains("old-home"), "{message}");
        assert!(message.contains("unrecognised field"), "{message}");
        assert!(
            message.contains("(value not shown)"),
            "the long value is capped: {message}"
        );
        assert!(!message.contains("api_key") && !message.contains("access_token"));
        let mut dry = options(&hosted, &install);
        dry.dry_run = true;
        let outcome = setup(dry).await.unwrap();
        assert_no_secrets(&outcome.differences.join("\n"));
    }

    #[tokio::test]
    async fn a_dry_run_writes_nothing_and_never_renews_the_credentials() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        let stamp = |name: &str| {
            let path = install.config.join(name);
            let meta = std::fs::metadata(&path).unwrap();
            (
                std::fs::read(&path).unwrap(),
                meta.ino(),
                meta.mtime(),
                meta.mtime_nsec(),
            )
        };
        let before = (stamp(AUTH_FILE), stamp(TOKEN_FILE));
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut dry = options(&hosted, &install);
        dry.dry_run = true;
        let outcome = setup(dry).await.unwrap();
        assert!(outcome.written.is_empty());
        assert_eq!(
            (stamp(AUTH_FILE), stamp(TOKEN_FILE)),
            before,
            "contents, inode and mtime"
        );
        for file in [NODE_FILE, STANDBY_FILE, REFRESH_FILE] {
            assert!(!install.config.join(file).exists());
        }
        assert!(!install.data.exists(), "no directories either");

        // A grant due for renewal: a dry run stops instead of renewing it.
        let due = signed_in(&hosted, 1).await;
        let before = (
            std::fs::read(due.config.join(AUTH_FILE)).unwrap(),
            std::fs::read(due.config.join(TOKEN_FILE)).unwrap(),
        );
        hosted.log.lock().unwrap().clear();
        let mut dry = options(&hosted, &due);
        dry.dry_run = true;
        let error = setup(dry).await.unwrap_err();
        assert_eq!(error.kind, SetupErrorKind::RenewalNeeded, "{error}");
        assert!(error.to_string().contains("native login"));
        assert!(
            hosted.log.lock().unwrap().is_empty(),
            "no request of any kind"
        );
        assert_eq!(
            (
                std::fs::read(due.config.join(AUTH_FILE)).unwrap(),
                std::fs::read(due.config.join(TOKEN_FILE)).unwrap()
            ),
            before
        );
    }

    #[tokio::test]
    async fn a_socket_directory_the_node_would_refuse_is_refused_up_front() {
        use std::os::unix::fs::PermissionsExt as _;
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        let run = install.data.join("run");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::set_permissions(&install.data, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).unwrap();
        for dry_run in [false, true] {
            let mut opts = options(&hosted, &install);
            opts.dry_run = dry_run;
            let error = setup(opts).await.unwrap_err();
            assert_eq!(error.kind, SetupErrorKind::UnsafeConfig, "{error}");
            assert!(
                error.to_string().contains("0700") && error.to_string().contains("run"),
                "{error}"
            );
            assert_eq!(
                mode(&run),
                0o755,
                "an existing directory's mode is never changed"
            );
            assert!(!install.config.join(NODE_FILE).exists());
            assert!(!install.config.join(STANDBY_FILE).exists());
        }
        // The same directory at 0700 is exactly what the node accepts.
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        setup(options(&hosted, &install)).await.unwrap();
        assert_eq!(mode(&run), 0o700);
    }

    #[tokio::test]
    async fn a_replica_directory_the_local_copy_would_refuse_is_refused_up_front() {
        use std::os::unix::fs::PermissionsExt as _;
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        let replica = install.data.join("replica");
        std::fs::create_dir_all(&replica).unwrap();
        std::fs::set_permissions(&install.data, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&replica, std::fs::Permissions::from_mode(0o755)).unwrap();
        for dry_run in [false, true] {
            let mut opts = options(&hosted, &install);
            opts.dry_run = dry_run;
            let error = setup(opts).await.unwrap_err();
            assert_eq!(error.kind, SetupErrorKind::UnsafeConfig, "{error}");
            let message = error.to_string();
            assert!(
                message.contains("replica") && message.contains("chmod 700"),
                "{message}"
            );
            assert_eq!(
                mode(&replica),
                0o755,
                "an existing directory's mode is never changed"
            );
            for file in [NODE_FILE, STANDBY_FILE, REFRESH_FILE] {
                assert!(
                    !install.config.join(file).exists(),
                    "{file} written before the check"
                );
            }
        }
        // A private replica directory whose store subdirectory is group-readable
        // is refused the same way, since the store checks every level.
        std::fs::set_permissions(&replica, std::fs::Permissions::from_mode(0o700)).unwrap();
        let accepted = replica.join("accepted");
        std::fs::create_dir(&accepted).unwrap();
        std::fs::set_permissions(&accepted, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            setup(options(&hosted, &install)).await.unwrap_err().kind,
            SetupErrorKind::UnsafeConfig
        );
        std::fs::set_permissions(&accepted, std::fs::Permissions::from_mode(0o700)).unwrap();
        setup(options(&hosted, &install)).await.unwrap();
        assert_eq!(mode(&replica), 0o700);
    }

    #[test]
    fn the_replica_check_agrees_with_what_the_generation_store_does() {
        use std::os::unix::fs::PermissionsExt as _;
        for dir_mode in [0o700, 0o750, 0o705, 0o755, 0o777] {
            let dir = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(dir.path()).unwrap().join("replica");
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(dir_mode)).unwrap();
            let checked = GenerationStore::check_existing_root(&root);
            let opened = GenerationStore::open(&root, "route", None);
            assert_eq!(checked.is_ok(), opened.is_ok(), "mode {dir_mode:o}");
        }
        // Partially populated trees: every combination of present levels, with
        // and without one owner-only violation among them, must be judged as
        // `open` judges it (it creates what is missing, then checks the rest).
        let levels = [
            "",
            "accepted",
            "accepted/staging",
            "accepted/generations",
            "accepted/leases",
            "accepted/heads",
        ];
        for have_accepted in [false, true] {
            for leaves in 0u8..16 {
                let present: Vec<&str> = std::iter::once(levels[0])
                    .chain(have_accepted.then_some(levels[1]))
                    .chain(
                        (0..4)
                            .filter(|i| have_accepted && leaves & (1 << i) != 0)
                            .map(|i| levels[2 + i]),
                    )
                    .collect();
                // None, or each present level in turn made group-readable.
                for bad in std::iter::once(None).chain(present.iter().copied().map(Some)) {
                    let dir = tempfile::tempdir().unwrap();
                    let root = std::fs::canonicalize(dir.path()).unwrap().join("replica");
                    for level in &present {
                        let path = root.join(level);
                        std::fs::create_dir_all(&path).unwrap();
                    }
                    for level in &present {
                        let wanted = if Some(*level) == bad { 0o755 } else { 0o700 };
                        std::fs::set_permissions(
                            root.join(level),
                            std::fs::Permissions::from_mode(wanted),
                        )
                        .unwrap();
                    }
                    let checked = GenerationStore::check_existing_root(&root);
                    let opened = GenerationStore::open(&root, "route", None);
                    assert_eq!(
                        checked.is_ok(),
                        opened.is_ok(),
                        "present {present:?}, bad {bad:?}: check {checked:?}, open {:?}",
                        opened.as_ref().err()
                    );
                    assert_eq!(
                        opened.is_ok(),
                        bad.is_none(),
                        "present {present:?}, bad {bad:?}"
                    );
                }
            }
        }
        // Nothing there yet: the store would create it all.
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("fresh");
        assert!(!GenerationStore::check_existing_root(&root).unwrap());
        assert!(!root.exists(), "the check creates nothing");
    }

    #[tokio::test]
    async fn hand_tuned_refresh_settings_survive_regeneration_and_are_validated() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        setup(options(&hosted, &install)).await.unwrap();
        let refresh_path = install.config.join(REFRESH_FILE);
        let mut tuned = json_of(&refresh_path);
        tuned["refresh_interval_seconds"] = json!(120);
        tuned["full_refresh_min_interval_seconds"] = json!(3600);
        tuned["full_refresh_repair_retry_seconds"] = json!(300);
        std::fs::write(&refresh_path, serde_json::to_vec(&tuned).unwrap()).unwrap();

        // Tuning alone is not a difference: nothing is rewritten.
        let outcome = setup(options(&hosted, &install)).await.unwrap();
        assert!(outcome.written.is_empty() && outcome.differences.is_empty());

        // A forced rewrite caused by a real difference keeps the tuning.
        tuned["hosted_origin"] = json!("https://elsewhere.example");
        std::fs::write(&refresh_path, serde_json::to_vec(&tuned).unwrap()).unwrap();
        let mut forced = options(&hosted, &install);
        forced.force = true;
        let outcome = setup(forced).await.unwrap();
        assert_eq!(outcome.written, std::slice::from_ref(&refresh_path));
        let rewritten = json_of(&refresh_path);
        assert_eq!(rewritten["hosted_origin"], json!(hosted.base));
        assert_eq!(rewritten["refresh_interval_seconds"], json!(120));
        assert_eq!(rewritten["full_refresh_min_interval_seconds"], json!(3600));
        assert_eq!(rewritten["full_refresh_repair_retry_seconds"], json!(300));
        StandbyRefreshConfig::from_json(&std::fs::read(&refresh_path).unwrap()).unwrap();

        // Tuning the real loader rejects is reported, not written.
        let mut broken = rewritten.clone();
        broken["refresh_interval_seconds"] = json!(0);
        std::fs::write(&refresh_path, serde_json::to_vec(&broken).unwrap()).unwrap();
        let before = std::fs::read(&refresh_path).unwrap();
        let mut forced = options(&hosted, &install);
        forced.force = true;
        let error = setup(forced).await.unwrap_err();
        assert!(error.to_string().contains("tuning"), "{error}");
        assert_eq!(std::fs::read(&refresh_path).unwrap(), before);
    }

    #[tokio::test]
    async fn force_replaces_a_config_that_is_not_json_without_showing_it() {
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        for file in [NODE_FILE, STANDBY_FILE, REFRESH_FILE] {
            let install = signed_in(&hosted, 3600).await;
            let path = install.config.join(file);
            std::fs::write(&path, "{ this is LEAK-ME-ACCESS, not json").unwrap();
            let before = std::fs::read(&path).unwrap();

            let error = setup(options(&hosted, &install)).await.unwrap_err();
            assert_eq!(error.kind, SetupErrorKind::Conflict, "{file}: {error}");
            assert!(error.to_string().contains("not valid JSON"), "{error}");
            assert!(error.to_string().contains("--force"));
            assert_no_secrets(&error.to_string());
            assert_eq!(std::fs::read(&path).unwrap(), before);

            let mut dry = options(&hosted, &install);
            dry.dry_run = true;
            let outcome = setup(dry).await.unwrap();
            assert!(outcome
                .differences
                .iter()
                .any(|d| d.contains("not valid JSON")));
            assert_no_secrets(&outcome.differences.join("\n"));
            assert_eq!(std::fs::read(&path).unwrap(), before);

            let mut forced = options(&hosted, &install);
            forced.force = true;
            let outcome = setup(forced).await.unwrap();
            assert_no_secrets(&outcome.differences.join("\n"));
            assert!(outcome.written.contains(&path));
            assert!(json_of(&path).is_object());
            assert_eq!(mode(&path), 0o600);
        }
    }

    #[tokio::test]
    async fn the_node_serves_from_the_generated_config() {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
        let hosted = start_hosted(&[(WS_A, "owner", "Native HQ")]).await;
        let install = signed_in(&hosted, 3600).await;
        setup(options(&hosted, &install)).await.unwrap();
        let config: NodeConfig =
            serde_json::from_slice(&std::fs::read(install.config.join(NODE_FILE)).unwrap())
                .unwrap();
        let socket = config.socket_path();
        // A local build is stamped `dev` and cannot serve a standby copy; the
        // node otherwise runs exactly as `native node serve` would.
        crate::node::set_test_consumer_identity(Some(
            crate::standby::generation_store::tests::observed(),
        ));
        let server = tokio::spawn(crate::node::serve(config));

        let mut stream = None;
        for _ in 0..200 {
            if let Ok(connected) = tokio::net::UnixStream::connect(&socket).await {
                stream = Some(connected);
                break;
            }
            assert!(!server.is_finished(), "the node exited: {:?}", server.await);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (read, mut write) = stream.expect("the node's socket").into_split();
        let mut lines = BufReader::new(read);
        for request in [
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"setup-test","version":"1"},"capabilities":{}}}),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"node_status","arguments":{}}}),
        ] {
            write
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
        }
        let mut reply = String::new();
        for _ in 0..2 {
            reply.clear();
            tokio::time::timeout(Duration::from_secs(15), lines.read_line(&mut reply))
                .await
                .expect("a node reply")
                .unwrap();
        }
        let status: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(status["id"], 1, "{status}");
        assert_eq!(
            status.pointer("/result/structuredContent/account_id"),
            Some(&json!(ACCOUNT)),
            "{status}"
        );
        server.abort();
    }
}
