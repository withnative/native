//! `native service install|uninstall|status`: run `native node serve --config
//! <node.json>` as a per-user background service.
//!
//! * **Linux**: a systemd user unit, `native.service`, in
//!   `$XDG_CONFIG_HOME/systemd/user` (default `~/.config/systemd/user`).
//! * **macOS**: a launchd agent, `ai.withnative.node`, in
//!   `~/Library/LaunchAgents`, logging under `~/Library/Logs/Native`.
//!
//! The unit name is `native.service`, not `native-node.service`: a hand-installed
//! `native-node.service` (the pre-CLI set-up) can exist beside ours, and we never
//! read, write or stop it. Files we write carry a marker line; a unit of our name
//! without that marker is someone else's and is refused unless `--force`, and
//! `uninstall` only ever removes our own. A launchd job of our label that was not
//! loaded from our own plist is never booted out.
//!
//! The directory a definition lives in may be reached through symlinks (a
//! dotfiles manager often links `~/.config`): it is resolved once, must be ours
//! and not writable by group or others, and every read, write, rename and
//! unlink then happens inside that resolved directory.
//!
//! The logic is split so it can be tested without a service manager: rendering
//! and planning are pure, every command goes through the [`Runner`] trait, and
//! the paths come from a [`ServiceContext`] (tests point it at a temporary HOME).

use std::path::{Path, PathBuf};

use crate::node::NodeConfig;

/// Systemd unit name.
pub const UNIT_NAME: &str = "native.service";
/// launchd label (and plist stem).
pub const LAUNCHD_LABEL: &str = "ai.withnative.node";
/// Recognises the files we wrote.
pub const MARKER: &str = "Managed by `native service`";
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_ERROR_DETAIL: usize = 400;
const MAX_REASON: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceErrorKind {
    /// `node.json` is missing: run `native setup`.
    NoNodeConfig,
    /// `node.json` does not pass the node's loader.
    InvalidNodeConfig,
    /// A unit of our name exists that we did not write.
    ForeignUnit,
    /// Our unit exists but differs from what we would write.
    UnitDiffers,
    /// A launchd job of our label is loaded from something other than our plist.
    ForeignJob,
    /// A path cannot safely go into a service definition.
    InvalidPath,
    /// The directory for the definition is not ours or is writable by others.
    UnsafeDirectory,
    /// The service manager refused a command, or could not be asked.
    CommandFailed,
    Other,
}

#[derive(Debug)]
pub struct ServiceError {
    pub kind: ServiceErrorKind,
    message: String,
}

impl ServiceError {
    fn new(kind: ServiceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    fn other(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::Other, message)
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ServiceError {}

type Result<T> = std::result::Result<T, ServiceError>;

// ---- running commands ---------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct CommandOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// The only way this module touches the service manager.
pub trait Runner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput>;
}

/// Runs the real commands.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
        let output = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()?;
        Ok(CommandOutput {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// A short, single-line reason a command did not give an answer.
fn reason(program: &str, out: &CommandOutput) -> String {
    let line = out
        .stderr
        .lines()
        .chain(out.stdout.lines())
        .map(str::trim)
        .find(|l| !l.is_empty());
    let text = match (line, out.code) {
        (Some(line), _) => line.to_owned(),
        (None, Some(code)) => format!("`{program}` exited {code}"),
        (None, None) => format!("`{program}` was terminated by a signal"),
    };
    text.chars().take(MAX_REASON).collect()
}

fn run(runner: &dyn Runner, program: &str, args: &[&str]) -> Result<CommandOutput> {
    runner.run(program, args).map_err(|error| {
        ServiceError::new(
            ServiceErrorKind::CommandFailed,
            format!("cannot run `{program}`: {error}"),
        )
    })
}

/// Run a command that must succeed.
fn run_ok(runner: &dyn Runner, program: &str, args: &[&str]) -> Result<CommandOutput> {
    let output = run(runner, program, args)?;
    if output.success() {
        return Ok(output);
    }
    let detail: String = output
        .stderr
        .trim()
        .chars()
        .take(MAX_ERROR_DETAIL)
        .collect();
    let hint = if program == "systemctl" && detail.contains("bus") {
        " (is there a systemd user session? try logging in directly, or set XDG_RUNTIME_DIR)"
    } else {
        ""
    };
    Err(ServiceError::new(
        ServiceErrorKind::CommandFailed,
        format!(
            "`{program} {}` failed ({}): {detail}{hint}. Fix that and re-run `native service install`",
            args.join(" "),
            output
                .code
                .map_or("terminated by a signal".to_owned(), |c| format!("exit {c}")),
        ),
    ))
}

/// Transport or permission failures are never "absent", whatever else the text
/// says (`Failed to connect to bus: No such file or directory` is a missing
/// socket, not a missing unit).
fn is_transport_error(text: &str) -> bool {
    [
        "failed to connect",
        "bus",
        "connection refused",
        "transport endpoint",
        "access denied",
        "permission denied",
        "operation not permitted",
        "interactive authentication",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

/// Does a failed `systemctl` stop/disable mean *this unit* is not there? Only
/// when the output names our unit and says it is not loaded or does not exist
/// (`Unit native.service not loaded.`, `Unit file native.service does not
/// exist.`). Generic "not found" or ENOENT text does not count.
fn systemd_unit_absent(out: &CommandOutput) -> bool {
    let text = format!("{} {}", out.stderr, out.stdout).to_ascii_lowercase();
    !is_transport_error(&text)
        && text.contains(UNIT_NAME)
        && ["not loaded", "does not exist", "could not be found"]
            .iter()
            .any(|needle| text.contains(needle))
}

/// Does a failed `launchctl` call mean the job is not loaded? Exit 113, or
/// launchd's own "Could not find service"; `bootout` of a job that is not
/// there also fails with exit 3 and "No such process".
fn launchd_job_absent(out: &CommandOutput) -> bool {
    let text = format!("{} {}", out.stderr, out.stdout).to_ascii_lowercase();
    if is_transport_error(&text) {
        return false;
    }
    out.code == Some(113)
        || text.contains("could not find service")
        || (out.code == Some(3) && text.contains("no such process"))
}

// ---- context -----------------------------------------------------------------

/// Everything the service needs to know about where things are.
#[derive(Clone, Debug)]
pub struct ServiceContext {
    pub platform: Platform,
    /// Directory holding the unit (systemd user dir) or plist (LaunchAgents).
    /// May be reached through symlinks; see [`resolve_dir`].
    pub unit_dir: PathBuf,
    /// macOS log directory (`~/Library/Logs/Native`); unused on Linux.
    pub log_dir: PathBuf,
    /// Absolute, canonical path of the `native` binary to run.
    pub exe: PathBuf,
    /// Absolute path of the `node.json` to serve.
    pub node_config: PathBuf,
    /// This user. Directories we write into must be owned by it; it is also the
    /// launchd `gui/<uid>` domain.
    pub uid: u32,
}

impl ServiceContext {
    /// The real environment: this binary, this user's directories, and the
    /// `node.json` in `config_dir`. `install` needs that file to exist
    /// (`needs_node_config`); `uninstall` and `status` do not.
    pub fn detect(config_dir: &Path, needs_node_config: bool) -> Result<Self> {
        let home = std::env::var("HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| ServiceError::other("HOME is not set"))?;
        let platform = Platform::current();
        let unit_dir = match platform {
            Platform::MacOs => home.join("Library/LaunchAgents"),
            Platform::Linux => std::env::var("XDG_CONFIG_HOME")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"))
                .join("systemd/user"),
        };
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|_| ServiceError::other("cannot find this program's own path"))?;
        let node_config = config_dir.join(crate::native_cli::setup::NODE_FILE);
        let node_config = match std::fs::canonicalize(&node_config) {
            Ok(path) => path,
            Err(_) if needs_node_config => return Err(no_node_config()),
            Err(_) => node_config,
        };
        // SAFETY: getuid has no preconditions or pointer arguments.
        let uid = unsafe { libc::getuid() };
        Ok(Self {
            platform,
            unit_dir,
            log_dir: home.join("Library/Logs/Native"),
            exe,
            node_config,
            uid,
        })
    }

    fn file_name(&self) -> String {
        match self.platform {
            Platform::Linux => UNIT_NAME.to_owned(),
            Platform::MacOs => format!("{LAUNCHD_LABEL}.plist"),
        }
    }

    /// Where the definition is, as the person would write it (not resolved).
    pub fn unit_path(&self) -> PathBuf {
        self.unit_dir.join(self.file_name())
    }

    fn launchd_domain(&self) -> String {
        format!("gui/{}", self.uid)
    }

    fn launchd_target(&self) -> String {
        format!("{}/{LAUNCHD_LABEL}", self.launchd_domain())
    }
}

fn no_node_config() -> ServiceError {
    ServiceError::new(
        ServiceErrorKind::NoNodeConfig,
        "no node.json found; run `native setup` first",
    )
}

/// node.json must exist and pass the node's own loader before a service is
/// pointed at it.
fn check_node_config(path: &Path) -> Result<()> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(no_node_config()),
        Err(_) => return Err(ServiceError::other("cannot read node.json")),
    };
    let mut bytes = Vec::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ServiceError::other("cannot read node.json"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(ServiceError::new(
            ServiceErrorKind::InvalidNodeConfig,
            "node.json is too large to be a node config",
        ));
    }
    serde_json::from_slice::<NodeConfig>(&bytes).map_err(|error| {
        ServiceError::new(
            ServiceErrorKind::InvalidNodeConfig,
            // serde's message can quote file content (an unknown field's name,
            // a value): say only where the problem is.
            format!(
                "node.json is not a valid node config (line {}, column {}); run `native setup` again",
                error.line(),
                error.column()
            ),
        )
    })?;
    Ok(())
}

// ---- rendering (pure) -----------------------------------------------------------

fn invalid_path(path: &Path, why: &str) -> ServiceError {
    ServiceError::new(
        ServiceErrorKind::InvalidPath,
        format!(
            "refusing to put the path {:?} in a service definition: {why}",
            path.display().to_string()
        ),
    )
}

/// An absolute, normalised, printable UTF-8 path: no control characters, no
/// empty, `.` or `..` components, no trailing slash.
fn check_path_text(path: &Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid_path(path, "it is not valid UTF-8"))?;
    if !path.is_absolute() {
        return Err(invalid_path(path, "it is not absolute"));
    }
    if text.chars().any(|c| c.is_control()) {
        return Err(invalid_path(path, "it contains a control character"));
    }
    let normalised = text.len() > 1
        && text
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if !normalised {
        return Err(invalid_path(path, "it is not a normalised absolute path"));
    }
    Ok(text)
}

/// The executable systemd will run. Beyond [`check_path_text`], systemd's own
/// executable check (`string_is_safe`) refuses quotes, backslashes and DEL.
fn check_executable(path: &Path) -> Result<&str> {
    let text = check_path_text(path)?;
    if text
        .chars()
        .any(|c| matches!(c, '"' | '\'' | '\\' | '\u{7f}'))
    {
        return Err(invalid_path(
            path,
            "systemd does not accept quotes, backslashes or control characters in an executable path",
        ));
    }
    Ok(text)
}

/// The executable word: systemd expands `%` specifiers in it but never `$`
/// (environment substitution applies to arguments only), so only `%` is
/// doubled. Quoting keeps spaces in one word; `check_executable` already ruled
/// out every character that would need a backslash.
fn systemd_executable_word(text: &str) -> String {
    format!("\"{}\"", text.replace('%', "%%"))
}

/// An argument word: quoted, with `\`, `"`, the `%` specifier and the `$`
/// substitution escaped.
fn systemd_argument_word(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// The systemd user unit.
pub fn render_systemd_unit(exe: &Path, node_config: &Path) -> Result<String> {
    let exe = systemd_executable_word(check_executable(exe)?);
    let config = systemd_argument_word(check_path_text(node_config)?);
    Ok(format!(
        "# {MARKER}. Do not edit; `native service install --force` rewrites it.\n\
         [Unit]\n\
         Description=Native local hosted node (native node serve)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} node serve --config {config}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         UMask=0077\n\
         NoNewPrivileges=true\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    ))
}

fn xml_escape(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// The launchd agent plist. The comment carries no `--` (illegal inside an
/// XML comment).
pub fn render_launchd_plist(exe: &Path, node_config: &Path, log_dir: &Path) -> Result<String> {
    let exe = xml_escape(check_path_text(exe)?);
    let config = xml_escape(check_path_text(node_config)?);
    let out_log = xml_escape(check_path_text(&log_dir.join("node.out.log"))?);
    let err_log = xml_escape(check_path_text(&log_dir.join("node.err.log"))?);
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <!-- {MARKER}. Do not edit; rewrite it with the install command's force option. -->\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{LAUNCHD_LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{exe}</string>\n\
         \t\t<string>node</string>\n\
         \t\t<string>serve</string>\n\
         \t\t<string>--config</string>\n\
         \t\t<string>{config}</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<dict>\n\
         \t\t<key>SuccessfulExit</key>\n\
         \t\t<false/>\n\
         \t</dict>\n\
         \t<key>ThrottleInterval</key>\n\
         \t<integer>5</integer>\n\
         \t<key>Umask</key>\n\
         \t<integer>63</integer>\n\
         \t<key>StandardOutPath</key>\n\
         \t<string>{out_log}</string>\n\
         \t<key>StandardErrorPath</key>\n\
         \t<string>{err_log}</string>\n\
         </dict>\n\
         </plist>\n"
    ))
}

fn render(ctx: &ServiceContext) -> Result<String> {
    match ctx.platform {
        Platform::Linux => render_systemd_unit(&ctx.exe, &ctx.node_config),
        Platform::MacOs => render_launchd_plist(&ctx.exe, &ctx.node_config, &ctx.log_dir),
    }
}

// ---- the directory and the files in it ---------------------------------------------

/// Resolve a directory once and vet it. The path may go through symlinks (a
/// dotfiles manager linking `~/.config` is normal); the *resolved* directory
/// must be a directory owned by `uid` that group and others cannot write to.
/// Returns `None` when it does not exist and `create` is false. Everything done
/// afterwards uses the returned path.
fn resolve_dir(dir: &Path, uid: u32, create: bool) -> Result<Option<PathBuf>> {
    use std::os::unix::fs::DirBuilderExt as _;
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(ServiceError::new(
                ServiceErrorKind::UnsafeDirectory,
                format!("{} is not a directory", dir.display()),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(None);
            }
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|_| {
                    ServiceError::other(format!("cannot create the directory {}", dir.display()))
                })?;
        }
        Err(_) => {
            return Err(ServiceError::other(format!(
                "cannot inspect {}",
                dir.display()
            )))
        }
    }
    let resolved = std::fs::canonicalize(dir)
        .map_err(|_| ServiceError::other(format!("cannot resolve {}", dir.display())))?;
    vet_chain(&resolved, uid, dir)?;
    Ok(Some(resolved))
}

/// Who owns a directory, as far as the ancestor check is concerned. Tests can
/// pretend a path has another owner, since they cannot chown.
fn owner_of(path: &Path, meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    #[cfg(test)]
    if let Some(fake) = FAKE_OWNERS.with(|owners| {
        owners
            .borrow()
            .iter()
            .find(|(fake_path, _)| fake_path == path)
            .map(|(_, uid)| *uid)
    }) {
        return fake;
    }
    let _ = path;
    meta.uid()
}

#[cfg(test)]
thread_local! {
    static FAKE_OWNERS: std::cell::RefCell<Vec<(PathBuf, u32)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The StrictModes rule, applied to the canonical chain from `/` down to the
/// directory itself, one real entry at a time with `symlink_metadata`:
///
/// * a canonical path contains no symlinks, so one found here means an entry
///   was swapped after resolution: refused, not followed;
/// * every ancestor is a directory owned by this user or root and not writable
///   by group or others (unless sticky, as `/tmp` is);
/// * the directory itself is owned by this user and not writable by group or
///   others.
///
/// If nobody else can write to any directory in the chain, nobody can rename an
/// entry and put a symlink in its place, so the path resolved once stays the
/// path every later operation uses. Checking each entry without following
/// links means a link to a trusted directory cannot pass for the directory.
fn vet_chain(resolved: &Path, uid: u32, requested: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let unsafe_chain = |at: &Path, problem: &str, is_final: bool| {
        let message = if is_final {
            format!(
                "refusing to use {} (resolved from {}): it {problem}. Fix its owner or mode \
                 (chmod go-w) and re-run",
                resolved.display(),
                requested.display()
            )
        } else {
            format!(
                "refusing to use {}: its ancestor {} {problem}, so someone else could swap \
                 the directory for a different one while this runs. Fix that directory's \
                 owner or mode (chmod go-w) and re-run",
                resolved.display(),
                at.display()
            )
        };
        ServiceError::new(ServiceErrorKind::UnsafeDirectory, message)
    };
    let mut at = PathBuf::new();
    let mut components = resolved.components().peekable();
    while let Some(component) = components.next() {
        at.push(component.as_os_str());
        let is_final = components.peek().is_none();
        let meta = std::fs::symlink_metadata(&at)
            .map_err(|_| ServiceError::other(format!("cannot inspect {}", at.display())))?;
        if meta.file_type().is_symlink() {
            return Err(unsafe_chain(
                &at,
                "is a symbolic link where a resolved path has none (it was changed while this ran)",
                is_final,
            ));
        }
        if !meta.is_dir() {
            return Err(unsafe_chain(&at, "is not a directory", is_final));
        }
        let owner = owner_of(&at, &meta);
        let sticky = meta.mode() & 0o1000 != 0;
        let writable = meta.mode() & 0o022 != 0;
        let problem = if is_final {
            if owner != uid {
                Some("is owned by another user")
            } else if writable {
                Some("is writable by group or others")
            } else {
                None
            }
        } else if owner != uid && owner != 0 {
            Some("is owned by another user")
        } else if writable && !sticky {
            Some("is writable by group or others")
        } else {
            None
        };
        if let Some(problem) = problem {
            return Err(unsafe_chain(&at, problem, is_final));
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Existing {
    Absent,
    /// Written by us; the text is what is on disk.
    Ours(String),
    /// Something else is at our name (another program's file, a symlink, an
    /// unreadable or oversized file).
    Foreign,
}

fn read_existing(path: &Path) -> Result<Existing> {
    use std::io::Read as _;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Existing::Absent),
        Err(_) => {
            return Err(ServiceError::other(format!(
                "cannot inspect {}",
                path.display()
            )))
        }
    };
    if !meta.is_file() {
        return Ok(Existing::Foreign);
    }
    let mut bytes = Vec::new();
    let read = std::fs::File::open(path).and_then(|file| {
        file.take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
    });
    if read.is_err() || bytes.len() > MAX_FILE_BYTES {
        return Ok(Existing::Foreign);
    }
    match String::from_utf8(bytes) {
        Ok(text) if text.lines().take(4).any(|line| line.contains(MARKER)) => {
            Ok(Existing::Ours(text))
        }
        _ => Ok(Existing::Foreign),
    }
}

/// Lines that differ between two renderings (no secrets live in either).
fn line_difference(old: &str, new: &str) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = Vec::new();
    out.extend(
        old_lines
            .iter()
            .filter(|l| !new_lines.contains(l))
            .map(|l| format!("  - {l}")),
    );
    out.extend(
        new_lines
            .iter()
            .filter(|l| !old_lines.contains(l))
            .map(|l| format!("  + {l}")),
    );
    out.join("\n")
}

/// A fresh temp file in `dir`: exclusive creation (never an existing file, never
/// through a link), unpredictable name, mode 0600 until it is finished.
fn create_temp(dir: &Path) -> Result<(std::fs::File, PathBuf)> {
    use rand::RngCore as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    for _ in 0..16 {
        let mut random = [0u8; 8];
        rand::rng().fill_bytes(&mut random);
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!(
            ".native-service-{}-{suffix}.tmp",
            std::process::id()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => break,
        }
    }
    Err(ServiceError::other(format!(
        "cannot create a temporary file in {}",
        dir.display()
    )))
}

/// Write `dir/name` atomically: a new exclusive temp file, mode set on the open
/// descriptor, fsync, rename, fsync of the directory. On failure only the temp
/// file this call created is removed.
fn write_atomic(dir: &Path, name: &str, text: &str, mode: u32) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let target = dir.join(name);
    let (mut file, temp) = create_temp(dir)?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(text.as_bytes())?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temp, &target)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(|_| ServiceError::other(format!("cannot write {}", target.display())))
}

// ---- asking the service manager ---------------------------------------------------------

/// A manager's answer to a state question: a definite word, or why it could not
/// answer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Known(String),
    Unknown(String),
}

const ACTIVE_WORDS: [&str; 8] = [
    "active",
    "inactive",
    "failed",
    "activating",
    "deactivating",
    "reloading",
    "maintenance",
    "refreshing",
];
const ENABLED_WORDS: [&str; 14] = [
    "enabled",
    "enabled-runtime",
    "linked",
    "linked-runtime",
    "alias",
    "masked",
    "masked-runtime",
    "static",
    "indirect",
    "disabled",
    "generated",
    "transient",
    "bad",
    "not-found",
];

fn systemctl_word(runner: &dyn Runner, verb: &str, words: &[&str]) -> Answer {
    match runner.run("systemctl", &["--user", verb, UNIT_NAME]) {
        Err(error) => Answer::Unknown(format!("cannot run `systemctl`: {error}")),
        Ok(out) => {
            let word = out.stdout.trim();
            if words.contains(&word) {
                Answer::Known(word.to_owned())
            } else {
                Answer::Unknown(reason("systemctl", &out))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Launchd {
    Loaded {
        /// The plist the job was loaded from, if `launchctl print` said.
        plist: Option<PathBuf>,
        state: Option<String>,
    },
    NotLoaded,
    Unknown(String),
}

fn launchd_probe(ctx: &ServiceContext, runner: &dyn Runner) -> Launchd {
    let out = match runner.run("launchctl", &["print", &ctx.launchd_target()]) {
        Ok(out) => out,
        Err(error) => return Launchd::Unknown(format!("cannot run `launchctl`: {error}")),
    };
    if out.success() {
        let field = |name: &str| {
            out.stdout
                .lines()
                .find_map(|line| line.trim().strip_prefix(name))
                .map(|v| v.trim().to_owned())
        };
        return Launchd::Loaded {
            plist: field("path = ").map(PathBuf::from),
            state: field("state = "),
        };
    }
    if launchd_job_absent(&out) {
        Launchd::NotLoaded
    } else {
        Launchd::Unknown(reason("launchctl", &out))
    }
}

/// Is the loaded job ours: loaded from our own plist file, which carries our marker?
fn loaded_job_is_ours(plist: &Option<PathBuf>, ours: &Path, existing: &Existing) -> bool {
    let (Some(loaded), Existing::Ours(_)) = (plist, existing) else {
        return false;
    };
    match (std::fs::canonicalize(loaded), std::fs::canonicalize(ours)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn foreign_job(plist: &Option<PathBuf>) -> ServiceError {
    let from = plist
        .as_ref()
        .map_or("somewhere launchctl did not say".to_owned(), |p| {
            p.display().to_string()
        });
    ServiceError::new(
        ServiceErrorKind::ForeignJob,
        format!(
            "a launchd job named {LAUNCHD_LABEL} is loaded from {from}, which is not the plist \
             `native service` wrote; refusing to unload it. Unload it yourself \
             (launchctl bootout gui/<uid>/{LAUNCHD_LABEL}) if it is stale, then re-run"
        ),
    )
}

// ---- install --------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Created,
    Updated,
    Unchanged,
}

#[derive(Debug)]
pub struct InstallReport {
    pub unit_path: PathBuf,
    pub change: Change,
    /// Things worth telling the person (linger, logs).
    pub notes: Vec<String>,
}

pub fn install(ctx: &ServiceContext, runner: &dyn Runner, force: bool) -> Result<InstallReport> {
    check_node_config(&ctx.node_config)?;
    // Rendering validates every path; nothing is created before it passes.
    let wanted = render(ctx)?;
    let dir = resolve_dir(&ctx.unit_dir, ctx.uid, true)?
        .ok_or_else(|| ServiceError::other("cannot create the service directory"))?;
    let name = ctx.file_name();
    let path = dir.join(&name);
    let existing = read_existing(&path)?;
    let change = match &existing {
        Existing::Absent => Change::Created,
        Existing::Ours(on_disk) if *on_disk == wanted => Change::Unchanged,
        Existing::Ours(on_disk) => {
            if !force {
                return Err(ServiceError::new(
                    ServiceErrorKind::UnitDiffers,
                    format!(
                        "{} exists and differs from what this `native` would install \
                         (for example, it was installed from another binary or config):\n{}\n\
                         Re-run with --force to replace it.",
                        ctx.unit_path().display(),
                        line_difference(on_disk, &wanted)
                    ),
                ));
            }
            Change::Updated
        }
        Existing::Foreign => {
            if !force {
                return Err(ServiceError::new(
                    ServiceErrorKind::ForeignUnit,
                    format!(
                        "{} exists but was not written by `native service`; refusing to \
                         overwrite it. Move it aside, or re-run with --force to replace it.",
                        ctx.unit_path().display()
                    ),
                ));
            }
            Change::Updated
        }
    };

    let mut notes = Vec::new();
    match ctx.platform {
        Platform::Linux => {
            write_changed(&dir, &name, &wanted, change)?;
            // A definition systemd has not loaded yet: a changed file, or an
            // identical one left by an earlier run that failed after writing.
            let stale = change != Change::Unchanged || need_daemon_reload(runner);
            if stale {
                run_ok(runner, "systemctl", &["--user", "daemon-reload"])?;
            }
            // A running process keeps its old definition until restarted. With
            // --force an active service is always restarted, even when the file
            // is identical: that is how a restart refused earlier is retried.
            let restart = (stale && change != Change::Created) || force;
            if restart
                && systemctl_word(runner, "is-active", &ACTIVE_WORDS)
                    == Answer::Known("active".into())
            {
                run_ok(runner, "systemctl", &["--user", "restart", UNIT_NAME]).map_err(
                    |error| {
                        ServiceError::new(
                            ServiceErrorKind::CommandFailed,
                            format!(
                            "the new definition is on disk (and loaded) but {UNIT_NAME} is still \
                             running its previous process: {error}. Restart it with \
                             `systemctl --user restart {UNIT_NAME}`, or re-run \
                             `native service install --force`"
                        ),
                        )
                    },
                )?;
            }
            run_ok(
                runner,
                "systemctl",
                &["--user", "enable", "--now", UNIT_NAME],
            )?;
            if let Some(note) = linger_note(ctx, runner) {
                notes.push(note);
            }
        }
        Platform::MacOs => {
            let probe = launchd_probe(ctx, runner);
            let loaded = match &probe {
                Launchd::Unknown(why) => {
                    return Err(ServiceError::new(
                        ServiceErrorKind::CommandFailed,
                        format!("cannot tell whether {LAUNCHD_LABEL} is loaded: {why}"),
                    ))
                }
                Launchd::NotLoaded => false,
                Launchd::Loaded { plist, .. } => {
                    // Never touch a job that is not ours, even with --force.
                    if !loaded_job_is_ours(plist, &path, &existing) {
                        return Err(foreign_job(plist));
                    }
                    true
                }
            };
            resolve_dir(&ctx.log_dir, ctx.uid, true)?;
            let target = ctx.launchd_target();
            // A changed plist, or --force, replaces the running job.
            let replace_job = loaded && (change != Change::Unchanged || force);
            if replace_job {
                run_ok(runner, "launchctl", &["bootout", &target])?;
            }
            write_changed(&dir, &name, &wanted, change)?;
            if replace_job || !loaded {
                let path_text = check_path_text(&path)?.to_owned();
                run_ok(
                    runner,
                    "launchctl",
                    &["bootstrap", &ctx.launchd_domain(), &path_text],
                )?;
            }
            notes.push(format!("logs: {}", ctx.log_dir.display()));
        }
    }
    Ok(InstallReport {
        unit_path: ctx.unit_path(),
        change,
        notes,
    })
}

fn write_changed(dir: &Path, name: &str, text: &str, change: Change) -> Result<()> {
    if change == Change::Unchanged {
        return Ok(());
    }
    write_atomic(dir, name, text, 0o644)
}

fn need_daemon_reload(runner: &dyn Runner) -> bool {
    runner
        .run(
            "systemctl",
            &["--user", "show", "-p", "NeedDaemonReload", UNIT_NAME],
        )
        .ok()
        .filter(CommandOutput::success)
        .is_some_and(|out| out.stdout.trim() == "NeedDaemonReload=yes")
}

/// Without lingering, a systemd user service stops at logout and starts only at
/// login. Tell the person; never change it ourselves.
fn linger_note(ctx: &ServiceContext, runner: &dyn Runner) -> Option<String> {
    let uid = ctx.uid.to_string();
    let lingering = runner
        .run("loginctl", &["show-user", &uid, "-p", "Linger"])
        .ok()
        .filter(CommandOutput::success)
        .is_some_and(|out| out.stdout.trim() == "Linger=yes");
    (!lingering).then(|| {
        "lingering is off, so the service will only run while you are logged in. To keep it \
         running after logout and start it at boot, run: loginctl enable-linger"
            .to_owned()
    })
}

// ---- uninstall ------------------------------------------------------------------------------

#[derive(Debug)]
pub struct UninstallReport {
    pub unit_path: PathBuf,
    pub removed: bool,
}

pub fn uninstall(ctx: &ServiceContext, runner: &dyn Runner) -> Result<UninstallReport> {
    let not_installed = || UninstallReport {
        unit_path: ctx.unit_path(),
        removed: false,
    };
    let Some(dir) = resolve_dir(&ctx.unit_dir, ctx.uid, false)? else {
        return Ok(not_installed());
    };
    let path = dir.join(ctx.file_name());
    let existing = read_existing(&path)?;
    match existing {
        Existing::Absent => return Ok(not_installed()),
        Existing::Foreign => {
            return Err(ServiceError::new(
                ServiceErrorKind::ForeignUnit,
                format!(
                    "{} was not written by `native service`; leaving it alone",
                    ctx.unit_path().display()
                ),
            ))
        }
        Existing::Ours(_) => {}
    }
    match ctx.platform {
        Platform::Linux => {
            // Stopping must be confirmed before the file goes: a unit file
            // removed under a running service would leave it unmanaged.
            let out = run(
                runner,
                "systemctl",
                &["--user", "disable", "--now", UNIT_NAME],
            )?;
            if !out.success() && !systemd_unit_absent(&out) {
                return Err(ServiceError::new(
                    ServiceErrorKind::CommandFailed,
                    format!(
                        "could not stop and disable {UNIT_NAME} ({}); the unit file was kept",
                        reason("systemctl", &out)
                    ),
                ));
            }
            std::fs::remove_file(&path)
                .map_err(|_| ServiceError::other(format!("cannot remove {}", path.display())))?;
            run_ok(runner, "systemctl", &["--user", "daemon-reload"]).map_err(|error| {
                ServiceError::new(
                    ServiceErrorKind::CommandFailed,
                    format!("the unit file was removed, but {error}"),
                )
            })?;
        }
        Platform::MacOs => {
            match launchd_probe(ctx, runner) {
                Launchd::Unknown(why) => {
                    return Err(ServiceError::new(
                        ServiceErrorKind::CommandFailed,
                        format!(
                        "cannot tell whether {LAUNCHD_LABEL} is loaded ({why}); the plist was kept"
                    ),
                    ))
                }
                Launchd::NotLoaded => {}
                Launchd::Loaded { plist, .. } => {
                    if !loaded_job_is_ours(&plist, &path, &existing) {
                        return Err(foreign_job(&plist));
                    }
                    let out = run(runner, "launchctl", &["bootout", &ctx.launchd_target()])?;
                    if !out.success() && !launchd_job_absent(&out) {
                        return Err(ServiceError::new(
                            ServiceErrorKind::CommandFailed,
                            format!(
                                "could not unload {LAUNCHD_LABEL} ({}); the plist was kept",
                                reason("launchctl", &out)
                            ),
                        ));
                    }
                }
            }
            std::fs::remove_file(&path)
                .map_err(|_| ServiceError::other(format!("cannot remove {}", path.display())))?;
        }
    }
    Ok(UninstallReport {
        unit_path: ctx.unit_path(),
        removed: true,
    })
}

// ---- status ---------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    No,
    Ours,
    /// Something of our name that we did not write.
    Foreign,
}

#[derive(Debug)]
pub struct StatusReport {
    pub unit_path: PathBuf,
    pub installed: Installed,
    /// `None` when not installed or the manager could not answer.
    pub running: Option<bool>,
    /// The manager's own word for the state (`active`, `inactive`, ...).
    pub state: Option<String>,
    pub enabled: Option<bool>,
    /// Why the manager could not say (bus error, permission, missing tool).
    pub unknown: Option<String>,
}

impl std::fmt::Display for StatusReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.installed {
            Installed::No => write!(f, "not installed ({})", self.unit_path.display()),
            Installed::Foreign => write!(
                f,
                "{} exists but was not written by native; not managed",
                self.unit_path.display()
            ),
            Installed::Ours => {
                if let Some(why) = &self.unknown {
                    return write!(
                        f,
                        "installed, state unknown: {why} ({})",
                        self.unit_path.display()
                    );
                }
                let running = match (self.running, &self.state) {
                    (Some(true), _) => "running".to_owned(),
                    (Some(false), Some(state)) => format!("not running ({state})"),
                    (Some(false), None) => "not running".to_owned(),
                    (None, _) => "state unknown".to_owned(),
                };
                let enabled = match self.enabled {
                    Some(true) => ", enabled",
                    Some(false) => ", not enabled",
                    None => "",
                };
                write!(
                    f,
                    "installed, {running}{enabled} ({})",
                    self.unit_path.display()
                )
            }
        }
    }
}

pub fn status(ctx: &ServiceContext, runner: &dyn Runner) -> Result<StatusReport> {
    let mut report = StatusReport {
        unit_path: ctx.unit_path(),
        installed: Installed::No,
        running: None,
        state: None,
        enabled: None,
        unknown: None,
    };
    let Some(dir) = resolve_dir(&ctx.unit_dir, ctx.uid, false)? else {
        return Ok(report);
    };
    let path = dir.join(ctx.file_name());
    let existing = read_existing(&path)?;
    report.installed = match existing {
        Existing::Absent => Installed::No,
        Existing::Foreign => Installed::Foreign,
        Existing::Ours(_) => Installed::Ours,
    };
    if report.installed != Installed::Ours {
        return Ok(report);
    }
    match ctx.platform {
        Platform::Linux => {
            match systemctl_word(runner, "is-active", &ACTIVE_WORDS) {
                Answer::Known(word) => {
                    report.running = Some(word == "active");
                    report.state = Some(word);
                }
                Answer::Unknown(why) => report.unknown = Some(why),
            }
            match systemctl_word(runner, "is-enabled", &ENABLED_WORDS) {
                Answer::Known(word) => report.enabled = Some(word.starts_with("enabled")),
                Answer::Unknown(why) => {
                    report.unknown.get_or_insert(why);
                }
            }
        }
        Platform::MacOs => match launchd_probe(ctx, runner) {
            Launchd::Loaded { state, .. } => {
                report.running = Some(state.as_deref() == Some("running"));
                report.state = state;
                report.enabled = Some(true);
            }
            Launchd::NotLoaded => {
                report.running = Some(false);
                report.state = Some("not loaded".to_owned());
                report.enabled = Some(false);
            }
            Launchd::Unknown(why) => report.unknown = Some(why),
        },
    }
    if report.unknown.is_some() {
        report.running = None;
        report.enabled = None;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;
    use std::sync::Mutex;

    /// Records every command and answers from a script; anything unscripted
    /// succeeds with no output. Nothing here can reach a real service manager.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        script: Vec<(&'static str, CommandOutput)>,
    }

    impl Fake {
        fn answering(script: Vec<(&'static str, CommandOutput)>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                script,
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn clear(&self) {
            self.calls.lock().unwrap().clear();
        }
    }

    impl Runner for Fake {
        fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CommandOutput> {
            let line = format!("{program} {}", args.join(" "));
            self.calls.lock().unwrap().push(line.clone());
            Ok(self
                .script
                .iter()
                .find(|(prefix, _)| line.starts_with(prefix))
                .map(|(_, out)| out.clone())
                .unwrap_or(CommandOutput {
                    code: Some(0),
                    ..Default::default()
                }))
        }
    }

    fn out(code: i32, stdout: &str) -> CommandOutput {
        CommandOutput {
            code: Some(code),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        ctx: ServiceContext,
    }

    fn fixture(platform: Platform) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap();
        let config_dir = home.join("cfg");
        std::fs::create_dir_all(&config_dir).unwrap();
        let node_config = config_dir.join("node.json");
        std::fs::write(
            &node_config,
            serde_json::to_vec(&serde_json::json!({
                "hosted_base_url": "https://h.example",
                "home_id": "h",
                "db_id": "d",
                "credential_file": config_dir.join("native.token"),
                "socket_directory": home.join("data/run"),
            }))
            .unwrap(),
        )
        .unwrap();
        let ctx = ServiceContext {
            platform,
            unit_dir: match platform {
                Platform::Linux => home.join(".config/systemd/user"),
                Platform::MacOs => home.join("Library/LaunchAgents"),
            },
            log_dir: home.join("Library/Logs/Native"),
            exe: PathBuf::from("/opt/native/bin/native"),
            node_config,
            uid: unsafe { libc::getuid() },
        };
        Fixture {
            _dir: dir,
            home,
            ctx,
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn the_unit_is_the_example_pointed_at_this_binary() {
        let unit = render_systemd_unit(
            Path::new("/opt/native/bin/native"),
            Path::new("/home/u/.config/native/node.json"),
        )
        .unwrap();
        assert_eq!(
            unit,
            "# Managed by `native service`. Do not edit; `native service install --force` rewrites it.\n\
             [Unit]\n\
             Description=Native local hosted node (native node serve)\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart=\"/opt/native/bin/native\" node serve --config \"/home/u/.config/native/node.json\"\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             UMask=0077\n\
             NoNewPrivileges=true\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        );
        // The executable keeps `$` (systemd never substitutes in it) but
        // doubles `%` (specifiers apply); an argument escapes both.
        let tricky = render_systemd_unit(
            Path::new("/opt/my native/bin/na$ti%ve"),
            Path::new("/home/u/x y/n\\o\"d$e%.json"),
        )
        .unwrap();
        assert!(
            tricky.contains(
                "ExecStart=\"/opt/my native/bin/na$ti%%ve\" node serve --config \"/home/u/x y/n\\\\o\\\"d$$e%%.json\""
            ),
            "{tricky}"
        );
        // An executable systemd would refuse is refused before anything is
        // written: quotes, backslashes, control characters, DEL, non-normal
        // or relative paths. A newline cannot start a new directive.
        for bad in [
            "/opt/na\"tive",
            "/opt/na'tive",
            "/opt/na\\tive",
            "/opt/na\ntive\nExecStart=/bin/sh",
            "/opt/na\u{7f}tive",
            "/opt/../native",
            "/opt/./native",
            "/opt//native",
            "/opt/native/",
            "native",
            "/",
        ] {
            let error = render_systemd_unit(Path::new(bad), Path::new("/c/node.json")).unwrap_err();
            assert_eq!(error.kind, ServiceErrorKind::InvalidPath, "{bad:?}");
        }
        assert!(render_systemd_unit(Path::new("/a/native"), Path::new("relative")).is_err());
        assert!(render_systemd_unit(Path::new("/a/native"), Path::new("/c/no\nde.json")).is_err());
    }

    #[test]
    fn the_plist_runs_at_load_restarts_on_failure_and_logs_under_the_logs_dir() {
        let plist = render_launchd_plist(
            Path::new("/Applications/N & Co/native"),
            Path::new("/Users/u/Library/Application Support/Native/node.json"),
            Path::new("/Users/u/Library/Logs/Native"),
        )
        .unwrap();
        for needle in [
            "<!-- Managed by `native service`.",
            "<key>Label</key>\n\t<string>ai.withnative.node</string>",
            "<string>/Applications/N &amp; Co/native</string>",
            "<string>node</string>\n\t\t<string>serve</string>\n\t\t<string>--config</string>",
            "<string>/Users/u/Library/Application Support/Native/node.json</string>",
            "<key>RunAtLoad</key>\n\t<true/>",
            "<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>",
            "<key>Umask</key>\n\t<integer>63</integer>",
            "<key>StandardOutPath</key>\n\t<string>/Users/u/Library/Logs/Native/node.out.log</string>",
            "<key>StandardErrorPath</key>\n\t<string>/Users/u/Library/Logs/Native/node.err.log</string>",
        ] {
            assert!(plist.contains(needle), "{needle}\n{plist}");
        }
        assert!(!plist.contains("N & Co"), "values are XML-escaped");
    }

    #[test]
    fn linux_install_writes_our_unit_reloads_enables_and_notes_linger() {
        let f = fixture(Platform::Linux);
        let runner = Fake::answering(vec![("loginctl show-user", out(0, "Linger=no\n"))]);
        let report = install(&f.ctx, &runner, false).unwrap();
        assert_eq!(report.change, Change::Created);
        assert_eq!(
            report.unit_path,
            f.home.join(".config/systemd/user/native.service")
        );
        let text = std::fs::read_to_string(&report.unit_path).unwrap();
        assert_eq!(text, render(&f.ctx).unwrap());
        assert!(text.contains("Restart=on-failure") && text.contains("UMask=0077"));
        assert!(text.contains("NoNewPrivileges=true") && text.contains("WantedBy=default.target"));
        assert_eq!(mode(&report.unit_path), 0o644);
        let linger = format!("loginctl show-user {} -p Linger", f.ctx.uid);
        assert_eq!(
            runner.calls(),
            [
                "systemctl --user daemon-reload",
                "systemctl --user enable --now native.service",
                linger.as_str(),
            ]
        );
        // Lingering is off: say so, and never turn it on ourselves.
        assert_eq!(report.notes.len(), 1);
        assert!(report.notes[0].contains("only run while you are logged in"));
        assert!(report.notes[0].contains("loginctl enable-linger"));
        assert!(runner.calls().iter().all(|c| !c.contains("enable-linger")));

        // With lingering on there is nothing to say.
        let other = fixture(Platform::Linux);
        let runner = Fake::answering(vec![("loginctl show-user", out(0, "Linger=yes\n"))]);
        assert!(install(&other.ctx, &runner, false)
            .unwrap()
            .notes
            .is_empty());
    }

    #[test]
    fn installing_twice_changes_nothing() {
        let f = fixture(Platform::Linux);
        let runner = Fake::default();
        let first = install(&f.ctx, &runner, false).unwrap();
        let meta = std::fs::metadata(&first.unit_path).unwrap();
        runner.clear();
        let second = install(&f.ctx, &runner, false).unwrap();
        assert_eq!(second.change, Change::Unchanged);
        let after = std::fs::metadata(&second.unit_path).unwrap();
        assert_eq!(
            (meta.ino(), meta.mtime(), meta.mtime_nsec()),
            (after.ino(), after.mtime(), after.mtime_nsec())
        );
        // No reload for an unchanged unit systemd has already loaded; enabling
        // is idempotent and also starts a service someone stopped.
        assert_eq!(
            runner.calls()[..2],
            [
                "systemctl --user show -p NeedDaemonReload native.service",
                "systemctl --user enable --now native.service"
            ]
        );
    }

    #[test]
    fn install_needs_a_valid_node_json_and_touches_nothing_without_one() {
        let f = fixture(Platform::Linux);
        let runner = Fake::default();
        std::fs::remove_file(&f.ctx.node_config).unwrap();
        let error = install(&f.ctx, &runner, false).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::NoNodeConfig);
        assert!(error.to_string().contains("native setup"));
        std::fs::write(&f.ctx.node_config, b"{\"hosted_base_url\": 1}").unwrap();
        let error = install(&f.ctx, &runner, false).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::InvalidNodeConfig, "{error}");
        std::fs::write(&f.ctx.node_config, b"not json").unwrap();
        assert_eq!(
            install(&f.ctx, &runner, false).unwrap_err().kind,
            ServiceErrorKind::InvalidNodeConfig
        );
        assert!(runner.calls().is_empty());
        assert!(!f.ctx.unit_path().exists());
        assert!(!f.ctx.unit_dir.exists());
    }

    #[test]
    fn a_bad_node_json_is_reported_by_position_never_by_content() {
        let f = fixture(Platform::Linux);
        for content in [
            r#"{"hosted_base_url":"https://h.example","SECRET_SENTINEL_FIELD":1}"#,
            r#"{"hosted_base_url":["SECRET_SENTINEL_VALUE"]}"#,
        ] {
            std::fs::write(&f.ctx.node_config, content).unwrap();
            let error = install(&f.ctx, &Fake::default(), false).unwrap_err();
            assert_eq!(error.kind, ServiceErrorKind::InvalidNodeConfig);
            let message = error.to_string();
            assert!(message.contains("line 1, column"), "{message}");
            assert!(!message.contains("SECRET_SENTINEL"), "{message}");
        }
    }

    #[test]
    fn a_foreign_unit_of_our_name_is_refused_unless_forced() {
        let f = fixture(Platform::Linux);
        let path = f.ctx.unit_path();
        std::fs::create_dir_all(&f.ctx.unit_dir).unwrap();
        std::fs::write(&path, "[Service]\nExecStart=/bin/true\n").unwrap();
        let runner = Fake::default();
        let error = install(&f.ctx, &runner, false).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::ForeignUnit);
        assert!(error.to_string().contains("--force"));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[Service]\nExecStart=/bin/true\n"
        );
        assert!(runner.calls().is_empty());
        // A symlink at our name is foreign too, and is replaced, not followed.
        std::fs::remove_file(&path).unwrap();
        let target = f.home.join("elsewhere.service");
        std::fs::write(&target, "precious").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            install(&f.ctx, &runner, false).unwrap_err().kind,
            ServiceErrorKind::ForeignUnit
        );
        let forced = install(&f.ctx, &runner, true).unwrap();
        assert_eq!(forced.change, Change::Updated);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "precious");
        assert!(std::fs::read_to_string(&path).unwrap().contains(MARKER));
        assert!(runner
            .calls()
            .contains(&"systemctl --user daemon-reload".to_owned()));
    }

    #[test]
    fn our_own_unit_that_differs_is_refused_with_a_diff_unless_forced() {
        let f = fixture(Platform::Linux);
        let runner = Fake::default();
        install(&f.ctx, &runner, false).unwrap();
        let mut moved = f.ctx.clone();
        moved.exe = PathBuf::from("/usr/local/bin/native");
        let error = install(&moved, &runner, false).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::UnitDiffers);
        let message = error.to_string();
        assert!(
            message.contains("- ExecStart=\"/opt/native/bin/native\""),
            "{message}"
        );
        assert!(
            message.contains("+ ExecStart=\"/usr/local/bin/native\""),
            "{message}"
        );
        assert!(std::fs::read_to_string(f.ctx.unit_path())
            .unwrap()
            .contains("/opt/native/bin/native"));
        runner.clear();
        let forced = install(&moved, &runner, true).unwrap();
        assert_eq!(forced.change, Change::Updated);
        assert!(std::fs::read_to_string(f.ctx.unit_path())
            .unwrap()
            .contains("/usr/local/bin/native"));
        assert_eq!(runner.calls()[0], "systemctl --user daemon-reload");
    }

    #[test]
    fn a_hand_installed_native_node_service_is_never_touched() {
        let f = fixture(Platform::Linux);
        std::fs::create_dir_all(&f.ctx.unit_dir).unwrap();
        let theirs = f.ctx.unit_dir.join("native-node.service");
        std::fs::write(
            &theirs,
            "[Service]\nExecStart=/home/u/.local/bin/mcp-stdio node serve\n",
        )
        .unwrap();
        let before = std::fs::read(&theirs).unwrap();
        let runner = Fake::default();
        install(&f.ctx, &runner, false).unwrap();
        uninstall(&f.ctx, &runner).unwrap();
        // Even with a foreign unit of our own name present, force and
        // uninstall go nowhere near it.
        assert_eq!(std::fs::read(&theirs).unwrap(), before);
        for call in runner.calls() {
            assert!(!call.contains("native-node"), "{call}");
        }
    }

    #[test]
    fn uninstall_stops_removes_only_our_unit_and_leaves_configs_and_data() {
        let f = fixture(Platform::Linux);
        let data = f.home.join("data/run");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("keep"), "x").unwrap();
        let runner = Fake::default();
        install(&f.ctx, &runner, false).unwrap();
        runner.clear();
        let report = uninstall(&f.ctx, &runner).unwrap();
        assert!(report.removed && !report.unit_path.exists());
        assert_eq!(
            runner.calls(),
            [
                "systemctl --user disable --now native.service",
                "systemctl --user daemon-reload"
            ]
        );
        assert!(f.ctx.node_config.exists() && data.join("keep").exists());

        // Nothing installed: nothing to do, no commands.
        runner.clear();
        let again = uninstall(&f.ctx, &runner).unwrap();
        assert!(!again.removed);
        assert!(runner.calls().is_empty());

        // A foreign unit of our name is refused and kept.
        std::fs::create_dir_all(&f.ctx.unit_dir).unwrap();
        std::fs::write(f.ctx.unit_path(), "not ours").unwrap();
        let error = uninstall(&f.ctx, &runner).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::ForeignUnit);
        assert_eq!(
            std::fs::read_to_string(f.ctx.unit_path()).unwrap(),
            "not ours"
        );
        assert!(runner.calls().is_empty());
    }

    /// A runner that cannot run anything, as when `systemctl` is not installed.
    struct Broken;

    impl Runner for Broken {
        fn run(&self, program: &str, _: &[&str]) -> std::io::Result<CommandOutput> {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{program}: not found"),
            ))
        }
    }

    fn failing(code: i32, stderr: &str) -> CommandOutput {
        CommandOutput {
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    /// What `launchctl print` says for a job loaded from `plist`.
    fn loaded(plist: &Path, state: &str) -> CommandOutput {
        out(
            0,
            &format!(
                "ai.withnative.node = {{\n\tpath = {}\n\tstate = {state}\n}}\n",
                plist.display()
            ),
        )
    }

    fn plist_path(f: &Fixture) -> PathBuf {
        f.ctx.unit_dir.join("ai.withnative.node.plist")
    }

    fn gui(f: &Fixture) -> String {
        format!("gui/{}/ai.withnative.node", f.ctx.uid)
    }

    #[test]
    fn status_reports_installed_running_and_enabled_in_one_line() {
        let f = fixture(Platform::Linux);
        let runner = Fake::answering(vec![
            ("systemctl --user is-active", out(0, "active\n")),
            ("systemctl --user is-enabled", out(0, "enabled\n")),
        ]);
        assert_eq!(
            status(&f.ctx, &runner).unwrap().to_string(),
            format!("not installed ({})", f.ctx.unit_path().display())
        );
        install(&f.ctx, &Fake::default(), false).unwrap();
        let report = status(&f.ctx, &runner).unwrap();
        assert_eq!(report.running, Some(true));
        assert_eq!(
            report.to_string(),
            format!(
                "installed, running, enabled ({})",
                f.ctx.unit_path().display()
            )
        );
        let stopped = Fake::answering(vec![
            ("systemctl --user is-active", out(3, "inactive\n")),
            ("systemctl --user is-enabled", out(1, "disabled\n")),
        ]);
        assert_eq!(
            status(&f.ctx, &stopped).unwrap().to_string(),
            format!(
                "installed, not running (inactive), not enabled ({})",
                f.ctx.unit_path().display()
            )
        );
        let failed = Fake::answering(vec![
            ("systemctl --user is-active", out(3, "failed\n")),
            ("systemctl --user is-enabled", out(0, "enabled\n")),
        ]);
        assert!(status(&f.ctx, &failed)
            .unwrap()
            .to_string()
            .contains("not running (failed)"));
        std::fs::write(f.ctx.unit_path(), "not ours").unwrap();
        let foreign = status(&f.ctx, &runner).unwrap();
        assert_eq!(foreign.installed, Installed::Foreign);
        assert!(foreign.to_string().contains("not written by native"));
    }

    #[test]
    fn status_says_unknown_with_a_reason_when_the_manager_cannot_answer() {
        let f = fixture(Platform::Linux);
        install(&f.ctx, &Fake::default(), false).unwrap();
        let bus = Fake::answering(vec![(
            "systemctl",
            failing(1, "Failed to connect to bus: No medium found\n"),
        )]);
        let report = status(&f.ctx, &bus).unwrap();
        assert_eq!((report.running, report.enabled), (None, None));
        assert_eq!(
            report.to_string(),
            format!(
                "installed, state unknown: Failed to connect to bus: No medium found ({})",
                f.ctx.unit_path().display()
            )
        );
        let denied = Fake::answering(vec![("systemctl", failing(1, "Access denied\n"))]);
        assert!(status(&f.ctx, &denied)
            .unwrap()
            .to_string()
            .contains("state unknown: Access denied"));
        // Output that is not a state word is not a state.
        let odd = Fake::answering(vec![("systemctl", out(0, "who knows\n"))]);
        let report = status(&f.ctx, &odd).unwrap();
        assert!(report.unknown.is_some() && report.running.is_none());
        let missing = status(&f.ctx, &Broken).unwrap().to_string();
        assert!(
            missing.contains("state unknown: cannot run `systemctl`"),
            "{missing}"
        );

        let m = fixture(Platform::MacOs);
        install(
            &m.ctx,
            &Fake::answering(vec![("launchctl print", out(113, ""))]),
            false,
        )
        .unwrap();
        let denied = Fake::answering(vec![(
            "launchctl print",
            failing(1, "Operation not permitted\n"),
        )]);
        let shown = status(&m.ctx, &denied).unwrap().to_string();
        assert!(
            shown.contains("state unknown: Operation not permitted"),
            "{shown}"
        );
        assert!(!shown.contains("not running"));
    }

    #[test]
    fn a_failing_systemctl_is_reported_with_its_reason_and_the_remedy() {
        let f = fixture(Platform::Linux);
        let runner = Fake::answering(vec![(
            "systemctl --user daemon-reload",
            CommandOutput {
                code: Some(1),
                stdout: String::new(),
                stderr: "Failed to connect to bus: No medium found".into(),
            },
        )]);
        let error = install(&f.ctx, &runner, false).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::CommandFailed);
        let message = error.to_string();
        assert!(
            message.contains("No medium found") && message.contains("systemd user session"),
            "{message}"
        );
        assert!(message.contains("re-run `native service install`"));
    }

    #[test]
    fn a_changed_unit_restarts_a_running_service_and_checks_the_result() {
        let f = fixture(Platform::Linux);
        install(&f.ctx, &Fake::default(), false).unwrap();
        let mut moved = f.ctx.clone();
        moved.exe = PathBuf::from("/usr/local/bin/native");

        // Running: reload, restart (so the new definition runs), then enable.
        let running = Fake::answering(vec![("systemctl --user is-active", out(0, "active\n"))]);
        install(&moved, &running, true).unwrap();
        assert_eq!(
            running.calls()[..4],
            [
                "systemctl --user daemon-reload",
                "systemctl --user is-active native.service",
                "systemctl --user restart native.service",
                "systemctl --user enable --now native.service",
            ]
        );
        // Not running: no restart; `enable --now` starts it with the new unit.
        let mut moved_again = f.ctx.clone();
        moved_again.exe = PathBuf::from("/usr/local/bin/native2");
        let stopped = Fake::answering(vec![("systemctl --user is-active", out(3, "inactive\n"))]);
        install(&moved_again, &stopped, true).unwrap();
        assert!(stopped.calls().iter().all(|c| !c.contains("restart")));
        // A restart that fails is an error, not a quiet success.
        let mut third = f.ctx.clone();
        third.exe = PathBuf::from("/usr/local/bin/native3");
        let refused = Fake::answering(vec![
            ("systemctl --user is-active", out(0, "active\n")),
            (
                "systemctl --user restart",
                failing(1, "Job for native.service failed\n"),
            ),
        ]);
        let error = install(&third, &refused, true).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::CommandFailed);
        assert!(error.to_string().contains("Job for native.service failed"));

        // An identical file that systemd has not loaded (an earlier run died
        // after writing) is reloaded and restarted too; one it has loaded is not.
        let stale = Fake::answering(vec![
            ("systemctl --user show", out(0, "NeedDaemonReload=yes\n")),
            ("systemctl --user is-active", out(0, "active\n")),
        ]);
        let again = install(&third, &Fake::default(), true).unwrap();
        assert_eq!(again.change, Change::Unchanged);
        install(&third, &stale, false).unwrap();
        let calls = stale.calls();
        assert!(
            calls.contains(&"systemctl --user daemon-reload".to_owned()),
            "{calls:?}"
        );
        assert!(
            calls.contains(&"systemctl --user restart native.service".to_owned()),
            "{calls:?}"
        );
    }

    #[test]
    fn macos_install_creates_private_logs_writes_the_plist_and_bootstraps_it() {
        let f = fixture(Platform::MacOs);
        // Not loaded yet: `launchctl print` fails with "not found".
        let runner = Fake::answering(vec![("launchctl print", out(113, ""))]);
        let report = install(&f.ctx, &runner, false).unwrap();
        let plist = plist_path(&f);
        assert_eq!(report.unit_path, plist);
        assert_eq!(
            std::fs::read_to_string(&plist).unwrap(),
            render(&f.ctx).unwrap()
        );
        assert_eq!(mode(&f.ctx.log_dir), 0o700);
        assert_eq!(
            runner.calls(),
            [
                format!("launchctl print {}", gui(&f)),
                format!("launchctl bootstrap gui/{} {}", f.ctx.uid, plist.display()),
            ]
        );
        assert!(report.notes[0].contains("Library/Logs/Native"));

        // Unchanged and loaded from our plist: nothing to do at all.
        let loaded_ours = Fake::answering(vec![("launchctl print", loaded(&plist, "running"))]);
        let again = install(&f.ctx, &loaded_ours, false).unwrap();
        assert_eq!(again.change, Change::Unchanged);
        assert_eq!(
            loaded_ours.calls(),
            [format!("launchctl print {}", gui(&f))]
        );

        // Changed (forced) and loaded from our plist: unload, rewrite, load.
        let mut moved = f.ctx.clone();
        moved.exe = PathBuf::from("/usr/local/bin/native");
        assert_eq!(
            install(&moved, &loaded_ours, false).unwrap_err().kind,
            ServiceErrorKind::UnitDiffers
        );
        loaded_ours.clear();
        install(&moved, &loaded_ours, true).unwrap();
        assert_eq!(
            loaded_ours.calls(),
            [
                format!("launchctl print {}", gui(&f)),
                format!("launchctl bootout {}", gui(&f)),
                format!("launchctl bootstrap gui/{} {}", f.ctx.uid, plist.display()),
            ]
        );
    }

    #[test]
    fn a_launchd_job_that_is_not_loaded_from_our_plist_is_never_booted_out() {
        let elsewhere = PathBuf::from("/Library/LaunchAgents/other.plist");
        // Our plist is absent but the label is loaded from some other file.
        let f = fixture(Platform::MacOs);
        let runner = Fake::answering(vec![("launchctl print", loaded(&elsewhere, "running"))]);
        let error = install(&f.ctx, &runner, true).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::ForeignJob, "{error}");
        assert!(error
            .to_string()
            .contains("/Library/LaunchAgents/other.plist"));
        assert_eq!(runner.calls(), [format!("launchctl print {}", gui(&f))]);
        assert!(
            !plist_path(&f).exists() && !f.ctx.log_dir.exists(),
            "nothing written"
        );

        // Our plist is on disk and ours, but the job came from elsewhere.
        install(
            &f.ctx,
            &Fake::answering(vec![("launchctl print", out(113, ""))]),
            false,
        )
        .unwrap();
        let runner = Fake::answering(vec![("launchctl print", loaded(&elsewhere, "running"))]);
        let mut moved = f.ctx.clone();
        moved.exe = PathBuf::from("/usr/local/bin/native");
        assert_eq!(
            install(&moved, &runner, true).unwrap_err().kind,
            ServiceErrorKind::ForeignJob
        );
        assert_eq!(
            install(&f.ctx, &runner, false).unwrap_err().kind,
            ServiceErrorKind::ForeignJob
        );
        assert!(runner
            .calls()
            .iter()
            .all(|c| !c.contains("bootout") && !c.contains("bootstrap")));

        // A foreign file at our path that the loaded job came from: still not ours.
        let g = fixture(Platform::MacOs);
        std::fs::create_dir_all(&g.ctx.unit_dir).unwrap();
        std::fs::write(plist_path(&g), "<plist/>").unwrap();
        let runner = Fake::answering(vec![(
            "launchctl print",
            loaded(&plist_path(&g), "running"),
        )]);
        assert_eq!(
            install(&g.ctx, &runner, true).unwrap_err().kind,
            ServiceErrorKind::ForeignJob
        );
        assert_eq!(std::fs::read_to_string(plist_path(&g)).unwrap(), "<plist/>");

        // Loaded, but launchctl does not say from where: cannot show it is ours.
        let h = fixture(Platform::MacOs);
        let runner = Fake::answering(vec![("launchctl print", out(0, "state = running\n"))]);
        assert_eq!(
            install(&h.ctx, &runner, true).unwrap_err().kind,
            ServiceErrorKind::ForeignJob
        );

        // launchctl cannot say whether anything is loaded: stop, change nothing.
        let i = fixture(Platform::MacOs);
        let runner = Fake::answering(vec![(
            "launchctl print",
            failing(1, "Operation not permitted\n"),
        )]);
        let error = install(&i.ctx, &runner, true).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::CommandFailed);
        assert!(error.to_string().contains("Operation not permitted"));
        assert!(!plist_path(&i).exists());
    }

    #[test]
    fn macos_install_checks_its_bootout_and_bootstrap_results() {
        let f = fixture(Platform::MacOs);
        let plist = plist_path(&f);
        install(
            &f.ctx,
            &Fake::answering(vec![("launchctl print", out(113, ""))]),
            false,
        )
        .unwrap();
        let before = std::fs::read(&plist).unwrap();
        let mut moved = f.ctx.clone();
        moved.exe = PathBuf::from("/usr/local/bin/native");
        let stuck = Fake::answering(vec![
            ("launchctl print", loaded(&plist, "running")),
            (
                "launchctl bootout",
                failing(5, "Boot-out failed: 5: Input/output error\n"),
            ),
        ]);
        let error = install(&moved, &stuck, true).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::CommandFailed);
        assert!(error.to_string().contains("Input/output error"));
        assert_eq!(
            std::fs::read(&plist).unwrap(),
            before,
            "not rewritten if it could not be unloaded"
        );

        let refused = Fake::answering(vec![
            ("launchctl print", out(113, "")),
            (
                "launchctl bootstrap",
                failing(5, "Bootstrap failed: 5: Input/output error\n"),
            ),
        ]);
        let g = fixture(Platform::MacOs);
        let error = install(&g.ctx, &refused, false).unwrap_err();
        assert!(error.to_string().contains("Bootstrap failed"), "{error}");
    }

    #[test]
    fn macos_uninstall_boots_out_checks_the_result_and_keeps_logs() {
        let f = fixture(Platform::MacOs);
        let plist = plist_path(&f);
        let loaded_ours = Fake::answering(vec![("launchctl print", loaded(&plist, "running"))]);
        install(
            &f.ctx,
            &Fake::answering(vec![("launchctl print", out(113, ""))]),
            false,
        )
        .unwrap();
        let report = status(&f.ctx, &loaded_ours).unwrap();
        assert_eq!(report.running, Some(true));
        assert!(report
            .to_string()
            .starts_with("installed, running, enabled"));
        let waiting = Fake::answering(vec![("launchctl print", loaded(&plist, "waiting"))]);
        assert_eq!(
            status(&f.ctx, &waiting).unwrap().state.as_deref(),
            Some("waiting")
        );
        let unloaded = Fake::answering(vec![("launchctl print", out(113, ""))]);
        assert!(status(&f.ctx, &unloaded)
            .unwrap()
            .to_string()
            .contains("not running (not loaded)"));

        // A bootout that cannot be confirmed keeps the plist.
        let stuck = Fake::answering(vec![
            ("launchctl print", loaded(&plist, "running")),
            ("launchctl bootout", failing(1, "Operation not permitted\n")),
        ]);
        let error = uninstall(&f.ctx, &stuck).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::CommandFailed);
        assert!(error.to_string().contains("plist was kept"));
        assert!(plist.exists());
        // ... and so does not being able to ask at all.
        let blind = Fake::answering(vec![(
            "launchctl print",
            failing(1, "Operation not permitted\n"),
        )]);
        assert_eq!(
            uninstall(&f.ctx, &blind).unwrap_err().kind,
            ServiceErrorKind::CommandFailed
        );
        assert!(plist.exists());
        // A job loaded from somewhere else is not ours to unload.
        let foreign = Fake::answering(vec![(
            "launchctl print",
            loaded(Path::new("/x/other.plist"), "running"),
        )]);
        assert_eq!(
            uninstall(&f.ctx, &foreign).unwrap_err().kind,
            ServiceErrorKind::ForeignJob
        );
        assert!(plist.exists());

        // A bootout that says "nothing there" is fine; success removes only the plist.
        let gone = Fake::answering(vec![
            ("launchctl print", loaded(&plist, "running")),
            (
                "launchctl bootout",
                failing(3, "Boot-out failed: 3: No such process\n"),
            ),
        ]);
        let removed = uninstall(&f.ctx, &gone).unwrap();
        assert!(removed.removed && !plist.exists());
        assert!(f.ctx.log_dir.exists(), "logs are left alone");
        assert!(f.ctx.node_config.exists());
        assert_eq!(
            gone.calls(),
            [
                format!("launchctl print {}", gui(&f)),
                format!("launchctl bootout {}", gui(&f))
            ]
        );
    }

    #[test]
    fn linux_uninstall_keeps_the_unit_when_stopping_cannot_be_confirmed() {
        let f = fixture(Platform::Linux);
        install(&f.ctx, &Fake::default(), false).unwrap();
        let unit = f.ctx.unit_path();
        let bus = Fake::answering(vec![(
            "systemctl --user disable",
            failing(1, "Failed to connect to bus: No medium found\n"),
        )]);
        let error = uninstall(&f.ctx, &bus).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::CommandFailed);
        assert!(error.to_string().contains("unit file was kept"), "{error}");
        assert!(unit.exists());
        assert!(bus.calls().iter().all(|c| !c.contains("daemon-reload")));
        let cannot_run = uninstall(&f.ctx, &Broken).unwrap_err();
        assert_eq!(cannot_run.kind, ServiceErrorKind::CommandFailed);
        assert!(unit.exists());
        // "Not loaded / does not exist" means there was nothing to stop.
        let absent = Fake::answering(vec![(
            "systemctl --user disable",
            failing(
                1,
                "Failed to disable unit: Unit file native.service does not exist.\n",
            ),
        )]);
        assert!(uninstall(&f.ctx, &absent).unwrap().removed);
        assert!(!unit.exists());
    }

    #[test]
    fn a_planted_link_at_a_predictable_temp_name_is_never_written_through() {
        let f = fixture(Platform::Linux);
        std::fs::create_dir_all(&f.ctx.unit_dir).unwrap();
        let victim = f.ctx.unit_dir.join("native-node.service");
        std::fs::write(
            &victim,
            "[Service]\nExecStart=/home/u/.local/bin/mcp-stdio node serve\n",
        )
        .unwrap();
        let outside = f.home.join("outside.txt");
        std::fs::write(&outside, "precious").unwrap();
        let before = (
            std::fs::read(&victim).unwrap(),
            std::fs::read(&outside).unwrap(),
        );
        // The old predictable names: a hard link to a victim, a symlink out.
        let pid = std::process::id();
        std::fs::hard_link(
            &victim,
            f.ctx.unit_dir.join(format!(".native-service-{pid}.tmp")),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, f.ctx.unit_dir.join(".native-service.tmp")).unwrap();
        let report = install(&f.ctx, &Fake::default(), false).unwrap();
        assert_eq!(report.change, Change::Created);
        assert_eq!(
            (
                std::fs::read(&victim).unwrap(),
                std::fs::read(&outside).unwrap()
            ),
            before
        );
        assert!(std::fs::read_to_string(f.ctx.unit_path())
            .unwrap()
            .contains(MARKER));
        // Our own temp files are gone; the planted ones are untouched.
        let mut leftovers: Vec<String> = std::fs::read_dir(&f.ctx.unit_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".native-service"))
            .collect();
        leftovers.sort();
        let mut planted = vec![
            ".native-service.tmp".to_owned(),
            format!(".native-service-{pid}.tmp"),
        ];
        planted.sort();
        assert_eq!(leftovers, planted);

        // A write that fails removes only the temp file it created.
        let g = fixture(Platform::Linux);
        std::fs::create_dir_all(g.ctx.unit_path().join("inner")).unwrap();
        let error = install(&g.ctx, &Fake::default(), true).unwrap_err();
        assert!(error.to_string().contains("cannot write"), "{error}");
        assert!(g.ctx.unit_path().join("inner").is_dir());
        assert!(std::fs::read_dir(&g.ctx.unit_dir).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[test]
    fn a_symlinked_unit_directory_that_we_own_works_and_stays_inside_it() {
        let f = fixture(Platform::Linux);
        // A dotfiles manager: ~/.config is a link to a directory we own.
        let real = f.home.join("dotfiles/config");
        std::fs::create_dir_all(real.join("systemd/user")).unwrap();
        std::os::unix::fs::symlink(&real, f.home.join(".config")).unwrap();
        let runner = Fake::default();
        let report = install(&f.ctx, &runner, false).unwrap();
        assert_eq!(
            report.unit_path,
            f.home.join(".config/systemd/user/native.service")
        );
        let physical = real.join("systemd/user/native.service");
        assert!(std::fs::read_to_string(&physical).unwrap().contains(MARKER));
        assert_eq!(
            install(&f.ctx, &runner, false).unwrap().change,
            Change::Unchanged
        );
        assert!(status(
            &f.ctx,
            &Fake::answering(vec![
                ("systemctl --user is-active", out(0, "active\n")),
                ("systemctl --user is-enabled", out(0, "enabled\n")),
            ])
        )
        .unwrap()
        .to_string()
        .starts_with("installed, running"));
        assert!(uninstall(&f.ctx, &runner).unwrap().removed);
        assert!(!physical.exists());

        // A unit file that is a link out of the directory is foreign: uninstall
        // refuses it and never follows it to remove what it points at.
        let outside = f.home.join("outside.service");
        std::fs::write(&outside, format!("# {MARKER}\n")).unwrap();
        std::os::unix::fs::symlink(&outside, &physical).unwrap();
        assert_eq!(
            uninstall(&f.ctx, &runner).unwrap_err().kind,
            ServiceErrorKind::ForeignUnit
        );
        assert!(outside.exists() && physical.symlink_metadata().is_ok());
    }

    #[test]
    fn a_unit_directory_owned_by_someone_else_or_writable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        // Another owner (the context says who "we" are; the real owner differs).
        let f = fixture(Platform::Linux);
        std::fs::create_dir_all(&f.ctx.unit_dir).unwrap();
        let mut stranger = f.ctx.clone();
        stranger.uid = f.ctx.uid + 1;
        let runner = Fake::default();
        for result in [
            install(&stranger, &runner, true).map(|_| ()),
            uninstall(&stranger, &runner).map(|_| ()),
            status(&stranger, &runner).map(|_| ()),
        ] {
            let error = result.unwrap_err();
            assert_eq!(error.kind, ServiceErrorKind::UnsafeDirectory, "{error}");
            assert!(
                error.to_string().contains("owned by another user"),
                "{error}"
            );
        }
        assert!(runner.calls().is_empty());
        assert!(!f.ctx.unit_path().exists());

        // Group- or world-writable.
        for bits in [0o775, 0o757, 0o777, 0o770] {
            let g = fixture(Platform::Linux);
            std::fs::create_dir_all(&g.ctx.unit_dir).unwrap();
            std::fs::set_permissions(&g.ctx.unit_dir, std::fs::Permissions::from_mode(bits))
                .unwrap();
            let error = install(&g.ctx, &runner, true).unwrap_err();
            assert_eq!(
                error.kind,
                ServiceErrorKind::UnsafeDirectory,
                "{bits:o}: {error}"
            );
            assert!(error.to_string().contains("writable by group or others"));
            assert_eq!(mode(&g.ctx.unit_dir), bits, "its mode is not changed");
            assert!(!g.ctx.unit_path().exists());
        }
        // A group-readable (not writable) directory is fine.
        let ok = fixture(Platform::Linux);
        std::fs::create_dir_all(&ok.ctx.unit_dir).unwrap();
        std::fs::set_permissions(&ok.ctx.unit_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        install(&ok.ctx, &runner, false).unwrap();
        // A symlink whose target is such a directory is judged by the target.
        let link = fixture(Platform::Linux);
        let target = link.home.join("shared");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::create_dir_all(link.ctx.unit_dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link.ctx.unit_dir).unwrap();
        assert_eq!(
            install(&link.ctx, &runner, true).unwrap_err().kind,
            ServiceErrorKind::UnsafeDirectory
        );
    }

    fn with_fake_owner<T>(path: &Path, uid: u32, body: impl FnOnce() -> T) -> T {
        FAKE_OWNERS.with(|o| o.borrow_mut().push((path.to_path_buf(), uid)));
        let result = body();
        FAKE_OWNERS.with(|o| o.borrow_mut().clear());
        result
    }

    #[test]
    fn every_ancestor_of_the_unit_directory_must_be_safe_like_strict_modes() {
        use std::os::unix::fs::PermissionsExt as _;
        let runner = Fake::default();
        // A group-writable ancestor: someone in that group could swap the
        // directory below it. Refused, naming the ancestor.
        let f = fixture(Platform::Linux);
        let shared = f.home.join("shared");
        let mut ctx = f.ctx.clone();
        ctx.unit_dir = shared.join("systemd/user");
        std::fs::create_dir_all(&ctx.unit_dir).unwrap();
        for bits in [0o775, 0o757, 0o777] {
            std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(bits)).unwrap();
            for result in [
                install(&ctx, &runner, true).map(|_| ()),
                uninstall(&ctx, &runner).map(|_| ()),
                status(&ctx, &runner).map(|_| ()),
            ] {
                let error = result.unwrap_err();
                assert_eq!(
                    error.kind,
                    ServiceErrorKind::UnsafeDirectory,
                    "{bits:o}: {error}"
                );
                let message = error.to_string();
                assert!(
                    message.contains("its ancestor") && message.contains(shared.to_str().unwrap()),
                    "{message}"
                );
                assert!(message.contains("writable by group or others"), "{message}");
            }
            assert!(!ctx.unit_path().exists());
        }
        // A sticky world-writable ancestor (like /tmp) is fine.
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
        install(&ctx, &runner, false).unwrap();
        assert!(uninstall(&ctx, &runner).unwrap().removed);
        // A private ancestor is fine; so is one that is root's (simulated).
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        with_fake_owner(&shared, 0, || install(&ctx, &runner, false).unwrap());
        // An ancestor owned by another non-root user is refused.
        let error = with_fake_owner(&shared, ctx.uid + 4242, || {
            install(&ctx, &runner, true).unwrap_err()
        });
        assert_eq!(error.kind, ServiceErrorKind::UnsafeDirectory);
        assert!(
            error.to_string().contains("owned by another user")
                && error.to_string().contains(shared.to_str().unwrap())
        );
        // The macOS log directory gets the same walk.
        let m = fixture(Platform::MacOs);
        let mut mac = m.ctx.clone();
        mac.log_dir = m.home.join("loose/Logs/Native");
        std::fs::create_dir_all(m.home.join("loose")).unwrap();
        std::fs::set_permissions(m.home.join("loose"), std::fs::Permissions::from_mode(0o775))
            .unwrap();
        let error = install(
            &mac,
            &Fake::answering(vec![("launchctl print", out(113, ""))]),
            false,
        )
        .unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::UnsafeDirectory, "{error}");
        assert!(error.to_string().contains("loose"));
    }

    #[test]
    fn a_symlink_in_the_resolved_chain_is_a_swap_and_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = fixture(Platform::Linux);
        let uid = f.ctx.uid;
        // A trusted, private directory the attacker would like the check to see.
        let trusted = f.home.join("trusted");
        std::fs::create_dir_all(trusted.join("systemd/user")).unwrap();
        // The chain as it would look after resolution, with an ancestor entry
        // replaced by a symlink to that trusted directory.
        let swapped = f.home.join("swapped");
        std::os::unix::fs::symlink(&trusted, &swapped).unwrap();
        let chain = swapped.join("systemd/user");
        let error = vet_chain(&chain, uid, &chain).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::UnsafeDirectory);
        let message = error.to_string();
        assert!(
            message.contains("symbolic link") && message.contains("its ancestor"),
            "{message}"
        );
        assert!(message.contains(swapped.to_str().unwrap()), "{message}");
        // The same for the directory itself.
        let link_final = f.home.join("final-link");
        std::os::unix::fs::symlink(trusted.join("systemd/user"), &link_final).unwrap();
        let error = vet_chain(&link_final, uid, &link_final).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        // A canonical chain of real directories passes.
        vet_chain(&trusted.join("systemd/user"), uid, &chain).unwrap();

        // End to end: a symlinked unit directory is still fine (resolution
        // removes the link before the chain is vetted)...
        let real = f.home.join("dotfiles");
        std::fs::create_dir_all(real.join("systemd/user")).unwrap();
        let mut linked = f.ctx.clone();
        linked.unit_dir = f.home.join("cfglink/systemd/user");
        std::os::unix::fs::symlink(&real, f.home.join("cfglink")).unwrap();
        install(&linked, &Fake::default(), false).unwrap();
        assert!(real.join("systemd/user/native.service").exists());
        // ... and the walk reaches a link whose target is group-writable even
        // though the link itself is ours: the target's own mode is judged.
        std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o775)).unwrap();
        let chain = trusted.join("systemd/user");
        assert!(vet_chain(&chain, uid, &chain)
            .unwrap_err()
            .to_string()
            .contains("writable by group or others"));
    }

    #[test]
    fn the_ancestors_of_a_real_home_pass_the_check() {
        let home = std::env::var("HOME").expect("HOME");
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let resolved = std::fs::canonicalize(&home).unwrap();
        vet_chain(&resolved, uid, &resolved).unwrap_or_else(|e| panic!("{e}"));
        // And a tmp-based home, as the other tests use, passes the whole check.
        let f = fixture(Platform::Linux);
        assert!(resolve_dir(&f.home, f.ctx.uid, false).unwrap().is_some());
    }

    #[test]
    fn a_refused_restart_is_reported_as_not_running_the_new_definition_and_force_retries_it() {
        let f = fixture(Platform::Linux);
        install(&f.ctx, &Fake::default(), false).unwrap();
        let mut moved = f.ctx.clone();
        moved.exe = PathBuf::from("/usr/local/bin/native");
        // Reload succeeds, restart is refused, the old process keeps running.
        let refusing = Fake::answering(vec![
            ("systemctl --user is-active", out(0, "active\n")),
            (
                "systemctl --user restart",
                failing(1, "Job for native.service canceled.\n"),
            ),
        ]);
        let error = install(&moved, &refusing, true).unwrap_err();
        assert_eq!(error.kind, ServiceErrorKind::CommandFailed);
        let message = error.to_string();
        assert!(message.contains("new definition is on disk"), "{message}");
        assert!(
            message.contains("still running its previous process"),
            "{message}"
        );
        assert!(
            message.contains("systemctl --user restart native.service"),
            "{message}"
        );
        assert!(
            message.contains("native service install --force"),
            "{message}"
        );
        assert!(
            message.contains("Job for native.service canceled"),
            "{message}"
        );
        assert!(std::fs::read_to_string(f.ctx.unit_path())
            .unwrap()
            .contains("/usr/local/bin/native"));

        // The retry without --force sees an identical file and a loaded
        // definition: that is exactly the state the message warns about, so it
        // does not restart (and says nothing of the old process).
        let quiet = Fake::answering(vec![
            ("systemctl --user show", out(0, "NeedDaemonReload=no\n")),
            ("systemctl --user is-active", out(0, "active\n")),
        ]);
        assert_eq!(
            install(&moved, &quiet, false).unwrap().change,
            Change::Unchanged
        );
        assert!(quiet.calls().iter().all(|c| !c.contains("restart")));

        // --force restarts an active service even though nothing changed.
        let retry = Fake::answering(vec![("systemctl --user is-active", out(0, "active\n"))]);
        let report = install(&moved, &retry, true).unwrap();
        assert_eq!(report.change, Change::Unchanged);
        assert!(
            retry
                .calls()
                .contains(&"systemctl --user restart native.service".to_owned()),
            "{:?}",
            retry.calls()
        );
        // A stopped service is not restarted by --force; `enable --now` starts it.
        let stopped = Fake::answering(vec![("systemctl --user is-active", out(3, "inactive\n"))]);
        install(&moved, &stopped, true).unwrap();
        assert!(stopped.calls().iter().all(|c| !c.contains("restart")));
    }

    #[test]
    fn force_also_replaces_a_running_launchd_job_with_an_identical_plist() {
        let f = fixture(Platform::MacOs);
        let plist = plist_path(&f);
        install(
            &f.ctx,
            &Fake::answering(vec![("launchctl print", out(113, ""))]),
            false,
        )
        .unwrap();
        let running = Fake::answering(vec![("launchctl print", loaded(&plist, "running"))]);
        install(&f.ctx, &running, true).unwrap();
        assert_eq!(
            running.calls(),
            [
                format!("launchctl print {}", gui(&f)),
                format!("launchctl bootout {}", gui(&f)),
                format!("launchctl bootstrap gui/{} {}", f.ctx.uid, plist.display()),
            ]
        );
    }

    #[test]
    fn a_bus_error_is_an_error_not_absence_in_uninstall_and_status() {
        let bus_enoent = "Failed to connect to bus: No such file or directory\n";
        let f = fixture(Platform::Linux);
        install(&f.ctx, &Fake::default(), false).unwrap();
        let unit = f.ctx.unit_path();
        // Uninstall: the unit is kept and the reason is shown.
        for text in [
            bus_enoent,
            "Failed to connect to bus: Connection refused\n",
            "No such file or directory\n",
            "Unit not found.\n",
        ] {
            let runner = Fake::answering(vec![("systemctl --user disable", failing(1, text))]);
            let error = uninstall(&f.ctx, &runner).unwrap_err();
            assert_eq!(error.kind, ServiceErrorKind::CommandFailed, "{text}");
            assert!(error.to_string().contains("unit file was kept"), "{error}");
            assert!(unit.exists(), "{text}");
        }
        // Even text that names our unit is not "absent" when it is a bus error.
        let both = Fake::answering(vec![(
            "systemctl --user disable",
            failing(
                1,
                "Failed to connect to bus: native.service does not exist\n",
            ),
        )]);
        assert!(uninstall(&f.ctx, &both).is_err() && unit.exists());
        // Only messages about this unit mean "nothing to stop".
        for text in [
            "Failed to stop native.service: Unit native.service not loaded.\n",
            "Failed to disable unit: Unit file native.service does not exist.\n",
        ] {
            let g = fixture(Platform::Linux);
            install(&g.ctx, &Fake::default(), false).unwrap();
            let runner = Fake::answering(vec![("systemctl --user disable", failing(1, text))]);
            assert!(uninstall(&g.ctx, &runner).unwrap().removed, "{text}");
        }
        // Status says unknown, with the real reason, for the same output.
        let bus = Fake::answering(vec![("systemctl", failing(1, bus_enoent))]);
        let shown = status(&f.ctx, &bus).unwrap().to_string();
        assert!(
            shown.contains("state unknown: Failed to connect to bus: No such file or directory"),
            "{shown}"
        );
        assert!(!shown.contains("not running") && !shown.contains("not installed"));

        // launchctl: only exit 113 / "Could not find service" is absence.
        let m = fixture(Platform::MacOs);
        install(
            &m.ctx,
            &Fake::answering(vec![("launchctl print", out(113, ""))]),
            false,
        )
        .unwrap();
        let plist = plist_path(&m);
        for text in [
            "Could not find service \"ai.withnative.node\" in domain for user gui: 501\n",
            "",
        ] {
            let absent = Fake::answering(vec![("launchctl print", failing(113, text))]);
            assert!(status(&m.ctx, &absent)
                .unwrap()
                .to_string()
                .contains("not running (not loaded)"));
        }
        let broken = Fake::answering(vec![(
            "launchctl print",
            failing(
                1,
                "Could not connect to the service manager: No such file or directory\n",
            ),
        )]);
        let shown = status(&m.ctx, &broken).unwrap().to_string();
        assert!(
            shown.contains("state unknown: Could not connect"),
            "{shown}"
        );
        assert_eq!(
            uninstall(&m.ctx, &broken).unwrap_err().kind,
            ServiceErrorKind::CommandFailed
        );
        assert!(plist.exists());
        let bootout_bus = Fake::answering(vec![
            ("launchctl print", loaded(&plist, "running")),
            (
                "launchctl bootout",
                failing(3, "Failed to connect to bus: No such process\n"),
            ),
        ]);
        assert!(uninstall(&m.ctx, &bootout_bus).is_err() && plist.exists());
    }

    /// A strict-enough XML check for the plist: prolog, DOCTYPE, comments
    /// without `--`, balanced and well-nested tags, only the five predefined
    /// entities (or numeric references), no raw `<` or `&` in text, and the
    /// plist shape (`<plist><dict>` whose children alternate key and value).
    fn assert_well_formed_plist(xml: &str) {
        fn check_text(text: &str) {
            let mut rest = text;
            assert!(
                !rest.contains('<') && !rest.contains('>') || !rest.contains('<'),
                "raw < in text: {text}"
            );
            while let Some(at) = rest.find('&') {
                let tail = &rest[at..];
                let end = tail
                    .find(';')
                    .unwrap_or_else(|| panic!("bare & in {text:?}"));
                let entity = &tail[1..end];
                let numeric = entity.strip_prefix('#').is_some_and(|d| {
                    !d.is_empty() && d.chars().all(|c| c.is_ascii_hexdigit() || c == 'x')
                });
                assert!(
                    ["amp", "lt", "gt", "quot", "apos"].contains(&entity) || numeric,
                    "bad entity &{entity}; in {text:?}"
                );
                rest = &tail[end + 1..];
            }
        }
        let mut rest = xml;
        assert!(
            rest.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
            "prolog"
        );
        rest = &rest[rest.find("?>").unwrap() + 2..];
        let mut stack: Vec<String> = Vec::new();
        let mut seen_root = false;
        let mut dict_children: Vec<String> = Vec::new();
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix("<!--") {
                let end = after.find("-->").expect("unterminated comment");
                let body = &after[..end];
                assert!(!body.contains("--"), "`--` inside a comment: {body}");
                assert!(!body.ends_with('-'), "comment ends with `-`");
                rest = &after[end + 3..];
            } else if rest.starts_with("<!DOCTYPE") {
                assert!(stack.is_empty() && !seen_root);
                rest = &rest[rest.find('>').unwrap() + 1..];
            } else if let Some(after) = rest.strip_prefix("</") {
                let end = after.find('>').expect("unterminated end tag");
                let name = &after[..end];
                assert_eq!(stack.pop().as_deref(), Some(name), "mis-nested </{name}>");
                rest = &after[end + 1..];
            } else if let Some(after) = rest.strip_prefix('<') {
                let end = after.find('>').expect("unterminated tag");
                let inner = &after[..end];
                let empty = inner.ends_with('/');
                let inner = inner.trim_end_matches('/');
                let name = inner.split_whitespace().next().unwrap().to_owned();
                assert!(
                    name.chars().all(|c| c.is_ascii_alphanumeric()),
                    "tag name {name}"
                );
                for attribute in inner[name.len()..].split_whitespace() {
                    let (key, value) = attribute.split_once('=').expect("attribute without value");
                    assert!(
                        !key.is_empty()
                            && value.len() >= 2
                            && value.starts_with('"')
                            && value.ends_with('"'),
                        "attribute {attribute}"
                    );
                }
                if stack.is_empty() {
                    assert!(!seen_root && name == "plist", "one root element, <plist>");
                    seen_root = true;
                }
                if stack == ["plist", "dict"] {
                    dict_children.push(name.clone());
                }
                if !empty {
                    stack.push(name);
                }
                rest = &after[end + 1..];
            } else {
                let end = rest.find('<').unwrap_or(rest.len());
                let text = &rest[..end];
                if !stack.is_empty() {
                    check_text(text);
                } else {
                    assert!(text.trim().is_empty(), "text outside the root: {text:?}");
                }
                rest = &rest[end..];
            }
        }
        assert!(
            stack.is_empty() && seen_root,
            "unclosed elements: {stack:?}"
        );
        assert!(
            dict_children.len().is_multiple_of(2),
            "dict children must pair up"
        );
        for pair in dict_children.chunks(2) {
            assert_eq!(pair[0], "key", "{dict_children:?}");
            assert_ne!(pair[1], "key", "{dict_children:?}");
        }
    }

    #[test]
    fn the_whole_plist_is_well_formed_xml_and_its_comment_has_no_double_dash() {
        let plain = render_launchd_plist(
            Path::new("/Applications/Native/native"),
            Path::new("/Users/u/Library/Application Support/Native/node.json"),
            Path::new("/Users/u/Library/Logs/Native"),
        )
        .unwrap();
        assert_well_formed_plist(&plain);
        assert!(plain.contains(MARKER));
        // Awkward but legal paths stay well-formed.
        let awkward = render_launchd_plist(
            Path::new("/Apps/A&B <x> \"q\" 'a'/native"),
            Path::new("/Users/u/it's & that/node.json"),
            Path::new("/Users/u/Logs & more"),
        )
        .unwrap();
        assert_well_formed_plist(&awkward);
        // The checker itself rejects what it is meant to catch.
        for bad in [
            plain.replace("Do not edit;", "Do not edit -- really;"),
            awkward.replace("&amp;", "&"),
            plain.replace("</dict>\n</plist>", "</plist>"),
            plain.replace("<true/>", "<true>"),
        ] {
            assert!(std::panic::catch_unwind(|| assert_well_formed_plist(&bad)).is_err());
        }
    }
}
