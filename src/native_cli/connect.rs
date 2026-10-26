//! `native connect`: register the local database with coding-agent tools.
//!
//! Registers `<current exe> mcp --local <db>` as the `native-local` MCP
//! server in Claude Code (`claude mcp ... --scope user`) and Codex
//! (`codex mcp ...`), and optionally drops a short pointer block into a
//! notes folder's `AGENTS.md` / `CLAUDE.md`. Flag shapes were checked against
//! this machine's `--help`: `claude mcp list/get` take no `--json` (text is
//! parsed), `codex mcp list/get` take `--json`, `claude mcp add/remove` use
//! `--scope user`, `codex mcp add` is `add <name> -- <cmd...>`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The MCP server name this command owns. Never touch `native`.
pub const SERVER_NAME: &str = "native-local";
/// The hosted-plugin server name; `connect` never adds, removes or edits it.
pub const HOSTED_NAME: &str = "native";
/// Vault block markers; the block is replaced in place on re-run.
pub const BLOCK_BEGIN: &str = "<!-- native:begin -->";
pub const BLOCK_END: &str = "<!-- native:end -->";
/// The short pointer text placed inside the vault block.
pub const BLOCK_TEXT: &str =
    "This folder's notes have been imported into a local Native workspace. \
To find current work, decisions and how notes relate, use the `native-local` MCP tools \
(start with bootstrap) before reading files one by one. The Markdown files remain readable, \
but Native is where changes should be recorded.";
/// Vault files managed inside `--vault <dir>`.
pub const VAULT_FILES: [&str; 2] = ["AGENTS.md", "CLAUDE.md"];

/// Parsed `native connect` options (binary-tested arg parsing lives here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub db: Option<PathBuf>,
    pub vault: Option<PathBuf>,
    pub clients: Vec<String>,
    pub dry_run: bool,
    pub json: bool,
    pub create_db: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            db: None,
            vault: None,
            clients: vec!["claude".to_owned(), "codex".to_owned()],
            dry_run: false,
            json: false,
            create_db: false,
        }
    }
}

/// Usage text; the binary prints it for `connect --help`.
pub fn connect_usage() -> String {
    format!(
        "usage: native connect [--db <path>] [--vault <dir>] [--clients claude,codex] [--dry-run] [--json] [--create-db]\n\
         \n\
         Register the local Native database with coding-agent tools.\n\
         Database: --db (default {}) or an absolute path. The registered\n\
         server command is: <current native exe> mcp --local <db>. The file\n\
         must already exist unless --create-db is given.\n\
         \n\
         options:\n\
         \x20 --db <path>          database to serve (default: the local database path)\n\
         \x20 --vault <dir>        add a short Native pointer block to <dir>/AGENTS.md and <dir>/CLAUDE.md\n\
         \x20 --clients <list>     comma-separated subset of claude,codex (default: claude,codex)\n\
         \x20 --dry-run            show what would change, change nothing\n\
         \x20 --json               one JSON object with per-client and per-vault-file statuses\n\
         \x20 --create-db          register even when the database file does not exist yet\n\
         \n\
         The entry is named `native-local`. An entry with the same command is\n\
         left as unchanged; one made by `native connect` (ends with\n\
         `mcp --local <path>` from a `native` executable) is replaced, any\n\
         other entry is left as a conflict. The hosted `native` entry is never touched.\n\
         \n\
         Malformed vault blocks are reported and left alone. The exit status\n\
         is 1 when any client or file ends in conflict, malformed or error.",
        crate::native_cli::default_local_db_path().display()
    )
}

/// Parse `connect` args; `Err` carries a human message (binary adds usage).
pub fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut opts = Options::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--db" => {
                index += 1;
                let Some(v) = args.get(index) else {
                    return Err("--db needs a value".to_owned());
                };
                opts.db = Some(PathBuf::from(v));
            }
            "--vault" => {
                index += 1;
                let Some(v) = args.get(index) else {
                    return Err("--vault needs a value".to_owned());
                };
                opts.vault = Some(PathBuf::from(v));
            }
            "--clients" => {
                index += 1;
                let Some(v) = args.get(index) else {
                    return Err("--clients needs a value".to_owned());
                };
                let list: Vec<String> = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                if list.is_empty() {
                    return Err("--clients needs a value".to_owned());
                }
                for name in &list {
                    if name != "claude" && name != "codex" {
                        return Err(format!("unknown client: {name} (want claude,codex)"));
                    }
                }
                opts.clients = list;
            }
            "--dry-run" => opts.dry_run = true,
            "--json" => opts.json = true,
            "--create-db" => opts.create_db = true,
            other => return Err(format!("unexpected argument: {other}")),
        }
        index += 1;
    }
    Ok(opts)
}

/// One command run's outcome (kept tiny so tests can fake it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Per-client result in the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientReport {
    pub client: String,
    pub status: String,
    pub command: Vec<String>,
    pub detail: String,
}

/// Per-vault-file result in the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultReport {
    pub path: PathBuf,
    pub status: String,
    pub detail: String,
}

/// Full `connect` outcome; the binary renders it as text or JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub db: PathBuf,
    pub command: Vec<String>,
    pub dry_run: bool,
    pub clients: Vec<ClientReport>,
    pub vault: Vec<VaultReport>,
}

/// Whether anything needs attention: any client in conflict or error, or
/// any vault file left malformed or failed. Skipped clients are fine.
pub fn has_failures(report: &Report) -> bool {
    report
        .clients
        .iter()
        .any(|c| matches!(c.status.as_str(), "conflict" | "error"))
        || report
            .vault
            .iter()
            .any(|v| matches!(v.status.as_str(), "malformed" | "error"))
}

/// Process exit code for a report: 1 when [`has_failures`], else 0.
pub fn exit_code(report: &Report) -> u8 {
    u8::from(has_failures(report))
}

/// Runner indirection so unit tests can use fake `claude`/`codex` scripts
/// on a temporary PATH instead of the real tools.
pub struct Deps<'a> {
    pub current_exe: PathBuf,
    pub run: &'a dyn Fn(&str, &[&str]) -> CmdOutput,
    pub find_on_path: &'a dyn Fn(&str) -> Option<PathBuf>,
}

/// Look up `name` on PATH (the `find_on_path` half of [`Deps`]).
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    // `metadata` follows symlinks: both `claude` and `codex` on this
    // machine are symlinks to versioned installs or shims.
    matches!(std::fs::metadata(path), Ok(meta) if {
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    })
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Run `program args...`, capturing output (the `run` half of [`Deps`]).
pub fn run_command(program: &str, args: &[&str]) -> CmdOutput {
    match std::process::Command::new(program).args(args).output() {
        Ok(out) => CmdOutput {
            status: out.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(err) => CmdOutput {
            status: 127,
            stdout: String::new(),
            stderr: err.to_string(),
        },
    }
}

/// Absolute form of the database path (relative joins the process cwd).
pub fn resolve_db(requested: Option<&Path>) -> PathBuf {
    match requested {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path),
        None => crate::native_cli::default_local_db_path(),
    }
}

/// The MCP server command to register: the current exe plus args.
pub fn desired_command(exe: &Path, db: &Path) -> Vec<String> {
    vec![
        exe.to_string_lossy().into_owned(),
        "mcp".to_owned(),
        "--local".to_owned(),
        db.to_string_lossy().into_owned(),
    ]
}

/// Whether `cmd` looks like it was created by `native connect`: it ends with
/// `mcp --local <path>` and its executable is named `native`.
pub fn is_managed_command(cmd: &[String]) -> bool {
    if cmd.len() < 4 {
        return false;
    }
    let tail = &cmd[cmd.len() - 3..];
    if tail[0] != "mcp" || tail[1] != "--local" || tail[2].is_empty() {
        return false;
    }
    let exe_name = Path::new(&cmd[0])
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    exe_name == "native" || exe_name == "native.exe"
}

/// One `claude mcp get <name>` result: raw lines, never re-split, so
/// database paths with spaces survive the round trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeEntry {
    pub exe: String,
    pub args_line: String,
    pub scope: String,
}

/// Parse `claude mcp get <name>` text into its server entry.
/// Returns `None` when the output carries no command (error text kept).
pub fn parse_claude_get(output: &str) -> Option<ClaudeEntry> {
    let mut command: Option<String> = None;
    let mut args: Option<String> = None;
    let mut scope: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Command:") {
            command = Some(rest.trim().to_owned());
        } else if let Some(rest) = trimmed.strip_prefix("Args:") {
            args = Some(rest.trim().to_owned());
        } else if let Some(rest) = trimmed.strip_prefix("Scope:") {
            scope = Some(rest.trim().to_owned());
        }
    }
    let exe = command?;
    if exe.is_empty() {
        return None;
    }
    Some(ClaudeEntry {
        exe,
        args_line: args.unwrap_or_default(),
        scope: scope.unwrap_or_default(),
    })
}

/// Exact match against the desired server command: the exe plus the raw
/// `Args:` line, so spaces in the database path compare byte for byte.
pub fn claude_entry_matches(entry: &ClaudeEntry, desired: &[String]) -> bool {
    let Some((exe, rest)) = desired.split_first() else {
        return false;
    };
    entry.exe == *exe && entry.args_line == rest.join(" ")
}

/// Whether the entry looks like `native connect` made it: a `native`
/// executable whose args start with `mcp --local ` (a path follows).
pub fn is_managed_claude_entry(entry: &ClaudeEntry) -> bool {
    let exe_name = Path::new(&entry.exe)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    (exe_name == "native" || exe_name == "native.exe")
        && entry.args_line.starts_with("mcp --local ")
}

/// `claude mcp get` shows the winning scope (local > project > user);
/// only the user config may be replaced by this command.
pub fn is_user_scope(scope: &str) -> bool {
    scope
        .split_whitespace()
        .next()
        .is_some_and(|word| word.eq_ignore_ascii_case("User"))
}

/// True when CLI output says no server with this name exists.
pub fn looks_absent(output: &CmdOutput) -> bool {
    let combined = format!("{}\n{}", output.stdout, output.stderr);
    combined.contains("No MCP server named")
}

/// One `codex mcp get <name> --json` result: the stdio command plus every
/// field `codex mcp add` cannot express, so a replace never drops one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexEntry {
    pub command: Vec<String>,
    pub has_env: bool,
    pub cwd: Option<String>,
    pub enabled: bool,
    pub has_tool_filters: bool,
    pub has_timeouts: bool,
}

impl CodexEntry {
    /// Only a default-shaped entry may be replaced: `codex mcp add` takes
    /// `--env` alone, so tool filters, timeouts, a working directory or a
    /// disabled state cannot be carried over.
    pub fn is_replaceable(&self) -> bool {
        !self.has_env
            && self.cwd.is_none()
            && self.enabled
            && !self.has_tool_filters
            && !self.has_timeouts
    }
}

/// Parse `codex mcp get <name> --json` into its stdio entry.
/// Non-stdio transports return `None` (treated as a foreign conflict).
pub fn parse_codex_get_json(output: &str) -> Option<CodexEntry> {
    let value: serde_json::Value = serde_json::from_str(output).ok()?;
    let transport = value.get("transport")?;
    if transport.get("type")?.as_str()? != "stdio" {
        return None;
    }
    let exe = transport.get("command")?.as_str()?.to_owned();
    let mut cmd = vec![exe];
    if let Some(args) = transport.get("args").and_then(|a| a.as_array()) {
        for arg in args {
            cmd.push(arg.as_str()?.to_owned());
        }
    }
    let has_env = transport
        .get("env")
        .and_then(|e| e.as_object())
        .is_some_and(|map| !map.is_empty())
        || transport
            .get("env_vars")
            .and_then(|e| e.as_array())
            .is_some_and(|list| !list.is_empty());
    let cwd = transport
        .get("cwd")
        .and_then(|c| c.as_str())
        .map(str::to_owned);
    let enabled = value
        .get("enabled")
        .and_then(|e| e.as_bool())
        .unwrap_or(true);
    let has_tool_filters = ["enabled_tools", "disabled_tools"].iter().any(|key| {
        let field = transport.get(key).or_else(|| value.get(key));
        // Only null/missing (and empty arrays, which filter nothing) count
        // as default; any other value narrows the tool surface.
        match field {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Array(list)) => !list.is_empty(),
            Some(_) => true,
        }
    });
    let has_timeouts = ["startup_timeout_sec", "tool_timeout_sec"]
        .iter()
        .any(|key| {
            transport
                .get(key)
                .or_else(|| value.get(key))
                .is_some_and(|v| !v.is_null())
        });
    Some(CodexEntry {
        command: cmd,
        has_env,
        cwd,
        enabled,
        has_tool_filters,
        has_timeouts,
    })
}

/// Inspect-then-register one client. Only [`SERVER_NAME`] is ever added or
/// removed; [`HOSTED_NAME`] is never named in a mutation.
fn ensure_client(client: &str, desired: &[String], deps: &Deps, dry_run: bool) -> ClientReport {
    debug_assert_ne!(SERVER_NAME, HOSTED_NAME);
    let outcome = |status: &str, detail: String| ClientReport {
        client: client.to_owned(),
        status: status.to_owned(),
        command: desired.to_vec(),
        detail,
    };
    if (deps.find_on_path)(client).is_none() {
        return outcome("skipped", "not found on PATH".to_owned());
    }
    // Inspection is one `get`: it carries the exact command (and the
    // winning scope for claude). `list` is deliberately not run: it
    // starts every configured server. Flag shapes follow this machine's
    // `--help` (codex takes `--json`, claude does not).
    let get_args: Vec<&str> = match client {
        "codex" => vec!["mcp", "get", SERVER_NAME, "--json"],
        _ => vec!["mcp", "get", SERVER_NAME],
    };
    let get = (deps.run)(client, &get_args);
    if get.status == 0 {
        if client == "codex" {
            match parse_codex_get_json(&get.stdout) {
                None => {
                    return outcome(
                        "conflict",
                        "exists with an unrecognized command; leaving it alone".to_owned(),
                    );
                }
                Some(current) if current.command == desired => {
                    return outcome("unchanged", "already registered".to_owned());
                }
                Some(current)
                    if is_managed_command(&current.command) && current.is_replaceable() =>
                {
                    if dry_run {
                        return outcome("replaced", "would replace the previous entry".to_owned());
                    }
                    return replace_client(client, desired, deps, &current.command);
                }
                Some(current) if is_managed_command(&current.command) => {
                    return outcome(
                        "conflict",
                        "exists with settings native connect cannot preserve; leaving it alone"
                            .to_owned(),
                    );
                }
                Some(_) => {
                    return outcome(
                        "conflict",
                        "exists with a different command; leaving it alone".to_owned(),
                    );
                }
            }
        }
        match parse_claude_get(&format!("{}\n{}", get.stdout, get.stderr)) {
            None => {
                return outcome(
                    "conflict",
                    "exists with an unrecognized command; leaving it alone".to_owned(),
                );
            }
            Some(current) if claude_entry_matches(&current, desired) => {
                return outcome("unchanged", "already registered".to_owned());
            }
            Some(current) if is_managed_claude_entry(&current) && is_user_scope(&current.scope) => {
                // A managed entry is exactly `mcp --local <db>`: the tail
                // after the prefix is one path, spaces included.
                let previous = vec![
                    current.exe.clone(),
                    "mcp".to_owned(),
                    "--local".to_owned(),
                    current.args_line["mcp --local ".len()..].to_owned(),
                ];
                if dry_run {
                    return outcome("replaced", "would replace the previous entry".to_owned());
                }
                return replace_client(client, desired, deps, &previous);
            }
            Some(current) if is_managed_claude_entry(&current) => {
                return outcome(
                    "conflict",
                    format!(
                        "exists in another scope ({}); leaving it alone",
                        current.scope
                    ),
                );
            }
            Some(_) => {
                return outcome(
                    "conflict",
                    "exists with a different command; leaving it alone".to_owned(),
                );
            }
        }
    }
    if looks_absent(&get) {
        if dry_run {
            return outcome("registered", "would register".to_owned());
        }
        return add_client(client, desired, deps);
    }
    let tail = format!("{}\n{}", get.stdout, get.stderr)
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("inspect failed")
        .to_owned();
    outcome("error", format!("could not inspect: {tail}"))
}

/// Fresh `add` for one client (only called for [`SERVER_NAME`).
fn add_client(client: &str, desired: &[String], deps: &Deps) -> ClientReport {
    let outcome = |status: &str, detail: String| ClientReport {
        client: client.to_owned(),
        status: status.to_owned(),
        command: desired.to_vec(),
        detail,
    };
    let args: Vec<String> = match client {
        "codex" => {
            let mut v = vec![
                "mcp".to_owned(),
                "add".to_owned(),
                SERVER_NAME.to_owned(),
                "--".to_owned(),
            ];
            v.extend(desired.iter().cloned());
            v
        }
        _ => {
            let mut v = vec![
                "mcp".to_owned(),
                "add".to_owned(),
                "--scope".to_owned(),
                "user".to_owned(),
                SERVER_NAME.to_owned(),
                "--".to_owned(),
            ];
            v.extend(desired.iter().cloned());
            v
        }
    };
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = (deps.run)(client, &refs);
    if result.status == 0 {
        outcome("registered", "registered".to_owned())
    } else {
        let tail = last_line(&result).unwrap_or_else(|| "add failed".to_owned());
        outcome("error", format!("could not register: {tail}"))
    }
}

/// Replace a stale entry this command owns: remove, then add. If the add
/// fails after the remove, the error names the exact command that restores
/// the previous entry, so nothing is silently lost.
fn replace_client(
    client: &str,
    desired: &[String],
    deps: &Deps,
    previous: &[String],
) -> ClientReport {
    let outcome = |status: &str, detail: String| ClientReport {
        client: client.to_owned(),
        status: status.to_owned(),
        command: desired.to_vec(),
        detail,
    };
    let remove_args: Vec<&str> = match client {
        "codex" => vec!["mcp", "remove", SERVER_NAME],
        _ => vec!["mcp", "remove", SERVER_NAME, "--scope", "user"],
    };
    let removed = (deps.run)(client, &remove_args);
    if removed.status != 0 {
        let tail = last_line(&removed).unwrap_or_else(|| "remove failed".to_owned());
        return outcome("error", format!("could not replace: {tail}"));
    }
    let mut added = add_client(client, desired, deps);
    if added.status == "registered" {
        added.status = "replaced".to_owned();
        added.detail = "replaced the previous entry".to_owned();
        return added;
    }
    let tail = &added.detail;
    let restore = match client {
        "codex" => format!("codex mcp add {} -- {}", SERVER_NAME, shell_join(previous)),
        _ => format!(
            "claude mcp add --scope user {} -- {}",
            SERVER_NAME,
            shell_join(previous)
        ),
    };
    added.detail = format!(
        "removed the previous entry but could not register the new one ({tail}); restore it with: {restore}"
    );
    added
}

/// Join argv tokens for display, quoting tokens with spaces or quotes.
fn shell_join(words: &[String]) -> String {
    words
        .iter()
        .map(|word| {
            if !word.is_empty()
                && word
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&b))
            {
                word.clone()
            } else {
                format!("'{}'", word.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn last_line(output: &CmdOutput) -> Option<String> {
    format!("{}\n{}", output.stdout, output.stderr)
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .map(str::to_owned)
}

/// Render the marked vault block (markers plus the pointer text).
fn render_block() -> String {
    format!("{BLOCK_BEGIN}\n{BLOCK_TEXT}\n{BLOCK_END}\n")
}

/// Merge the block into existing file content; returns the new content and
/// whether it changed, or `None` when the markers are malformed. All other
/// bytes are preserved. Markers inside fenced code blocks (``` or ~~~) are
/// quoted text, not the pointer block, and do not count: with no markers
/// outside fences the block is appended, otherwise exactly one begin
/// followed by one end outside fences is refreshed, and any other shape
/// is malformed and left untouched.
fn merge_block(existing: Option<&str>) -> Option<(String, bool)> {
    let block = render_block();
    let Some(text) = existing else {
        return Some((block, true));
    };
    let begins = marker_offsets_outside_fences(text, BLOCK_BEGIN);
    let ends = marker_offsets_outside_fences(text, BLOCK_END);
    if begins.is_empty() && ends.is_empty() {
        let mut merged = text.to_owned();
        if !merged.ends_with('\n') {
            merged.push('\n');
        }
        if !merged.ends_with("\n\n") {
            merged.push('\n');
        }
        merged.push_str(&block);
        return Some((merged, true));
    }
    if begins.len() != 1 || ends.len() != 1 || ends[0] < begins[0] {
        return None;
    }
    let (begin, end) = (begins[0], ends[0]);
    let after_end = end + BLOCK_END.len();
    let rest = text[after_end..]
        .strip_prefix('\n')
        .unwrap_or(&text[after_end..]);
    let mut merged = String::with_capacity(text.len() + block.len());
    merged.push_str(&text[..begin]);
    merged.push_str(&block);
    merged.push_str(rest);
    let changed = merged != text;
    Some((merged, changed))
}

/// Byte offsets of `marker` occurrences outside fenced code blocks.
/// A fence opens on a line starting with ``` or ~~~ and closes on a line
/// starting with the same three characters; other fence lines are literal.
fn marker_offsets_outside_fences(text: &str, marker: &str) -> Vec<usize> {
    fn fence_char(trimmed: &str) -> Option<char> {
        let mut chars = trimmed.chars();
        let first = chars.next()?;
        if (first != '`' && first != '~') || trimmed.chars().take(3).any(|c| c != first) {
            return None;
        }
        Some(first)
    }
    let mut offsets = Vec::new();
    let mut fence: Option<char> = None;
    let mut base = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        match (fence, fence_char(trimmed)) {
            (None, Some(open)) => fence = Some(open),
            (Some(open), Some(close)) if open == close => fence = None,
            _ => {}
        }
        if fence.is_none() {
            offsets.extend(line.match_indices(marker).map(|(i, _)| base + i));
        }
        base += line.len();
    }
    offsets
}

/// Run `connect`: validate the vault first so a bad `--vault` stops the
/// run before any client is touched, then inspect-then-register each
/// client and refresh vault files. Vault write failures are recorded in
/// the report (status `error`, exit 1), not returned early.
pub fn run(opts: &Options, deps: &Deps) -> Result<Report, String> {
    let db = resolve_db(opts.db.as_deref());
    // A typo must not point agents at an empty workspace: the file has to
    // exist (it is created on first `mcp --local` serve) unless --create-db.
    if !opts.create_db && !db.is_file() {
        return Err(format!(
            "database does not exist: {}; pass --create-db to register it anyway",
            db.display()
        ));
    }
    let desired = desired_command(&deps.current_exe, &db);
    let mut vault = Vec::new();
    let mut vault_failed = false;
    if let Some(dir) = opts.vault.as_deref() {
        // A mistyped path must fail loudly, never scaffold directories,
        // and before any client is changed.
        if !dir.is_dir() {
            let detail = format!("vault directory does not exist: {}", dir.display());
            for file in VAULT_FILES {
                vault.push(VaultReport {
                    path: dir.join(file),
                    status: "error".to_owned(),
                    detail: detail.clone(),
                });
            }
            vault_failed = true;
        } else {
            for file in VAULT_FILES {
                let path = dir.join(file);
                match apply_vault_file(&path, opts.dry_run) {
                    Ok((status, detail)) => vault.push(VaultReport {
                        path,
                        status,
                        detail,
                    }),
                    Err(err) => vault.push(VaultReport {
                        path,
                        status: "error".to_owned(),
                        detail: err.to_string(),
                    }),
                }
            }
            vault_failed = vault
                .iter()
                .any(|v| matches!(v.status.as_str(), "malformed" | "error"));
        }
    }
    let mut clients = Vec::with_capacity(opts.clients.len());
    if !vault_failed {
        for client in &opts.clients {
            clients.push(ensure_client(client, &desired, deps, opts.dry_run));
        }
    }
    Ok(Report {
        db,
        command: desired,
        dry_run: opts.dry_run,
        clients,
        vault,
    })
}

/// Short human summary (also used for `--dry-run`, prefixed per line).
pub fn render_text(report: &Report) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "{}database: {}",
        if report.dry_run { "would use " } else { "" },
        report.db.display()
    ));
    for client in &report.clients {
        let command = client.command.join(" ");
        match client.status.as_str() {
            "registered" => lines.push(format!(
                "{}: native-local: {}register: {command}",
                client.client,
                if report.dry_run { "would " } else { "" },
            )),
            "replaced" => lines.push(format!(
                "{}: native-local: {}replace: {command}",
                client.client,
                if report.dry_run { "would " } else { "" },
            )),
            "unchanged" => {
                lines.push(format!(
                    "{}: native-local: unchanged: {command}",
                    client.client
                ));
            }
            "skipped" => {
                lines.push(format!("{}: skipped ({})", client.client, client.detail));
            }
            _ => {
                lines.push(format!(
                    "{}: native-local: {}: {command}",
                    client.client, client.status
                ));
                lines.push(format!("  {}", client.detail));
            }
        }
    }
    for file in &report.vault {
        lines.push(format!(
            "vault {}: {}{}",
            file.path.display(),
            if report.dry_run { "would " } else { "" },
            file.status
        ));
        if !file.detail.is_empty() {
            lines.push(format!("  {}", file.detail));
        }
    }
    lines.join("\n")
}

/// One JSON object: per client `found/registered/unchanged/conflict/skipped`
/// with the command, per vault file `created/updated/unchanged`.
pub fn render_json(report: &Report) -> String {
    let clients: serde_json::Map<String, serde_json::Value> = report
        .clients
        .iter()
        .map(|c| {
            (
                c.client.clone(),
                serde_json::json!({
                    "status": c.status,
                    "command": c.command,
                    "detail": c.detail,
                }),
            )
        })
        .collect();
    let vault: serde_json::Map<String, serde_json::Value> = report
        .vault
        .iter()
        .map(|v| {
            (
                v.path.to_string_lossy().into_owned(),
                serde_json::json!({ "status": v.status, "detail": v.detail }),
            )
        })
        .collect();
    serde_json::json!({
        "db": report.db.to_string_lossy(),
        "command": report.command,
        "dry_run": report.dry_run,
        "clients": clients,
        "vault": vault,
    })
    .to_string()
}

/// Apply the block to one vault file: `(status, detail)`. `created` when
/// the file is new, `malformed` (with a note, never written) for bad
/// markers. Writes go to a temp file in the same directory, renamed over
/// the target, so a crash never leaves a half-written file. A symlinked
/// file updates its resolved target; the link itself is kept.
fn apply_vault_file(path: &Path, dry_run: bool) -> std::io::Result<(String, String)> {
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };
    let existed = existing.is_some();
    let Some((merged, changed)) = merge_block(existing.as_deref()) else {
        return Ok((
            "malformed".to_owned(),
            "markers are malformed; left untouched".to_owned(),
        ));
    };
    let status = if !existed {
        "created"
    } else if changed {
        "updated"
    } else {
        "unchanged"
    };
    if changed && !dry_run {
        write_atomic(&write_target(path), &merged)?;
    }
    Ok((status.to_owned(), String::new()))
}

/// The file a vault write lands on: the fully resolved target, so chained
/// symlinks are followed and the link itself (not a copy beside it) is
/// updated. Falls back to the path itself when it does not exist yet.
fn write_target(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `contents` to `target` via a temp file in the same directory
/// plus a rename, so readers never see a partial file. The replacement
/// keeps the original file's permissions.
fn write_atomic(target: &Path, contents: &str) -> std::io::Result<()> {
    let permissions = std::fs::metadata(target)
        .map(|meta| meta.permissions())
        .ok();
    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_owned());
    let id = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    let tmp = dir.join(format!(
        ".{name}.native-connect-{}.{id}.tmp",
        std::process::id()
    ));
    let result = std::fs::write(&tmp, contents).and_then(|()| std::fs::rename(&tmp, target));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return result;
    }
    if let Some(permissions) = permissions {
        std::fs::set_permissions(target, permissions)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct FakeEnv {
        #[allow(dead_code)]
        root: PathBuf,
        bin: PathBuf,
        state: PathBuf,
        path_env: String,
    }

    fn setup() -> FakeEnv {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("native-connect-test-{}-{id}", std::process::id()));
        let bin = root.join("bin");
        let state = root.join("state");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(bin.join("claude"), FAKE_CLAUDE).unwrap();
        std::fs::write(bin.join("codex"), FAKE_CODEX).unwrap();
        #[cfg(unix)]
        for script in ["claude", "codex"] {
            use std::os::unix::fs::PermissionsExt as _;
            let path = bin.join(script);
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        std::fs::write(state.join("calls.log"), "").unwrap();
        let path_env = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        FakeEnv {
            root,
            bin,
            state,
            path_env,
        }
    }

    fn deps_for(env: &FakeEnv) -> (PathBuf, String, PathBuf) {
        (
            env.bin.join("native"),
            env.path_env.clone(),
            env.state.clone(),
        )
    }

    fn run_with(env: &FakeEnv, exe: &Path, opts: &Options) -> Report {
        try_run_with(env, exe, opts).expect("connect runs")
    }

    fn try_run_with(env: &FakeEnv, exe: &Path, opts: &Options) -> Result<Report, String> {
        let (current_exe, path_env, state) = deps_for(env);
        let _ = exe;
        let execute = |prog: &str, args: &[&str]| -> CmdOutput {
            let out = std::process::Command::new(prog)
                .env("PATH", &path_env)
                .env("FAKE_STATE", &state)
                .args(args)
                .output()
                .expect("fake CLI runs");
            CmdOutput {
                status: out.status.code().unwrap_or(1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            }
        };
        let find = |name: &str| -> Option<PathBuf> {
            let candidate = env.bin.join(name);
            candidate.is_file().then(|| candidate.clone())
        };
        let deps = Deps {
            current_exe,
            run: &execute,
            find_on_path: &find,
        };
        run(opts, &deps)
    }

    fn calls(env: &FakeEnv) -> String {
        std::fs::read_to_string(env.state.join("calls.log")).unwrap()
    }

    fn seed_claude_stdio(env: &FakeEnv, name: &str, exe: &str, args: &str) {
        seed_claude_stdio_scoped(env, name, exe, args, "User config");
    }

    fn seed_claude_stdio_scoped(env: &FakeEnv, name: &str, exe: &str, args: &str, scope: &str) {
        std::fs::write(
            env.state.join(format!("claude.{name}.state")),
            format!("stdio\n{exe}\n{args}\n{scope}\n"),
        )
        .unwrap();
    }

    fn seed_codex_stdio(env: &FakeEnv, name: &str, exe: &str, args_json: &str) {
        seed_codex_stdio_full(env, name, exe, args_json, "", "");
    }

    fn seed_codex_stdio_full(
        env: &FakeEnv,
        name: &str,
        exe: &str,
        args_json: &str,
        extra_transport: &str,
        extra_top: &str,
    ) {
        std::fs::write(
            env.state.join(format!("codex.{name}.json")),
            format!(
                "{{\"name\":\"{name}\",\"transport\":{{\"type\":\"stdio\",\
                 \"command\":\"{exe}\",\"args\":{args_json}{extra_transport}}}{extra_top}}}"
            ),
        )
        .unwrap();
    }

    fn seed_codex_http(env: &FakeEnv, name: &str) {
        std::fs::write(
            env.state.join(format!("codex.{name}.json")),
            format!(
                "{{\"name\":\"{name}\",\"transport\":{{\"type\":\"streamable_http\",\
                 \"url\":\"https://example.invalid/mcp\"}}}}"
            ),
        )
        .unwrap();
    }

    const FAKE_CLAUDE: &str = r#"#!/bin/sh
STATE="${FAKE_STATE:?}"
{
  printf 'claude'
  for a in "$@"; do printf ' %s' "$a"; done
  printf '\n'
} >> "$STATE/calls.log"
[ "$1" = "mcp" ] || exit 2
shift
sub="$1"; shift
case "$sub" in
  list)
    for f in "$STATE"/claude.*.state; do
      [ -e "$f" ] || continue
      base=$(basename "$f"); name=${base#claude.}; name=${name%.state}
      printf '%s: <entry> - ok\n' "$name"
    done
    ;;
  get)
    name="$1"
    f="$STATE/claude.$name.state"
    if [ ! -f "$f" ]; then
      printf 'No MCP server named "%s". Configured servers: (none)\n' "$name"
      exit 1
    fi
    kind=$(sed -n '1p' "$f"); command=$(sed -n '2p' "$f"); args=$(sed -n '3p' "$f")
    scope=$(sed -n '4p' "$f")
    printf '%s:\n  Scope: %s\n  Status: ok\n  Type: %s\n' "$name" "$scope" "$kind"
    if [ "$kind" = "stdio" ]; then
      printf '  Command: %s\n  Args: %s\n  Environment:\n' "$command" "$args"
    fi
    ;;
  add)
    if [ -f "$STATE/fail-add" ]; then
      printf 'add failed: entry removed already (test)\n'
      exit 1
    fi
    name=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --scope) shift 2;;
        --) shift; break;;
        *) name="$1"; shift;;
      esac
    done
    exe="$1"; shift
    printf 'stdio\n%s\n%s\n' "$exe" "$*" > "$STATE/claude.$name.state"
    ;;
  remove)
    name=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --scope) shift 2;;
        *) name="$1"; shift;;
      esac
    done
    f="$STATE/claude.$name.state"
    if [ ! -f "$f" ]; then
      printf 'No MCP server named "%s"\n' "$name"
      exit 1
    fi
    rm -f "$f"
    ;;
  *) exit 2;;
esac
"#;

    const FAKE_CODEX: &str = r#"#!/bin/sh
STATE="${FAKE_STATE:?}"
{
  printf 'codex'
  for a in "$@"; do printf ' %s' "$a"; done
  printf '\n'
} >> "$STATE/calls.log"
[ "$1" = "mcp" ] || exit 2
shift
sub="$1"; shift
case "$sub" in
  list)
    printf '['
    first=1
    for f in "$STATE"/codex.*.json; do
      [ -e "$f" ] || continue
      if [ "$first" -eq 0 ]; then printf ','; fi
      cat "$f"
      first=0
    done
    printf ']\n'
    ;;
  get)
    name="$1"
    f="$STATE/codex.$name.json"
    if [ ! -f "$f" ]; then
      printf "Error: No MCP server named '%s' found.\n" "$name"
      exit 1
    fi
    cat "$f"
    printf '\n'
    ;;
  add)
    if [ -f "$STATE/fail-add" ]; then
      printf "add failed: entry removed already (test)\n"
      exit 1
    fi
    name="$1"; shift
    [ "$1" = "--" ] || exit 2
    shift
    exe="$1"; shift
    args_json=$(printf '%s\n' "$@" | while IFS= read -r a; do
      [ -n "$a" ] || continue
      printf '"%s",' "$a"
    done)
    args_json="[${args_json%,}]"
    printf '{"name":"%s","transport":{"type":"stdio","command":"%s","args":%s}}' \
      "$name" "$exe" "$args_json" > "$STATE/codex.$name.json"
    ;;
  remove)
    name="$1"
    f="$STATE/codex.$name.json"
    if [ ! -f "$f" ]; then
      printf "Error: No MCP server named '%s' found.\n" "$name"
      exit 1
    fi
    rm -f "$f"
    ;;
  *) exit 2;;
esac
"#;

    fn test_opts(env: &FakeEnv) -> Options {
        Options {
            db: Some(env.state.join("test.db")),
            vault: None,
            clients: vec!["claude".to_owned(), "codex".to_owned()],
            dry_run: false,
            json: false,
            create_db: true,
        }
    }

    #[test]
    fn parse_args_defaults_and_flags() {
        let opts = parse_args(&[]).unwrap();
        assert_eq!(opts.clients, vec!["claude", "codex"]);
        assert!(!opts.dry_run && !opts.json && !opts.create_db);
        let args: Vec<String> = [
            "--db",
            "/tmp/x.db",
            "--clients",
            "codex",
            "--dry-run",
            "--json",
            "--create-db",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let opts = parse_args(&args).unwrap();
        assert_eq!(opts.db, Some(PathBuf::from("/tmp/x.db")));
        assert_eq!(opts.clients, vec!["codex"]);
        assert!(opts.dry_run && opts.json && opts.create_db);
        assert!(parse_args(&["--clients".to_owned(), "vim".to_owned()]).is_err());
        assert!(connect_usage().contains("native connect"));
    }

    #[test]
    fn managed_command_detection() {
        assert!(is_managed_command(&[
            "/usr/bin/native".to_owned(),
            "mcp".to_owned(),
            "--local".to_owned(),
            "/tmp/a.db".to_owned(),
        ]));
        assert!(!is_managed_command(&[
            "/usr/bin/other".to_owned(),
            "mcp".to_owned(),
            "--local".to_owned(),
            "/tmp/a.db".to_owned(),
        ]));
        assert!(!is_managed_command(&[
            "/x/native".to_owned(),
            "mcp".to_owned()
        ]));
    }

    #[test]
    fn claude_get_parsing() {
        let out = "x:\n  Scope: User config\n  Type: stdio\n  Command: /bin/native\n  Args: mcp --local /tmp/my notes.db\n";
        let entry = parse_claude_get(out).expect("parses");
        assert_eq!(entry.exe, "/bin/native");
        assert_eq!(entry.args_line, "mcp --local /tmp/my notes.db");
        assert_eq!(entry.scope, "User config");
        assert!(is_user_scope(&entry.scope));
        assert!(is_managed_claude_entry(&entry));
        let desired = vec![
            "/bin/native".to_owned(),
            "mcp".to_owned(),
            "--local".to_owned(),
            "/tmp/my notes.db".to_owned(),
        ];
        assert!(claude_entry_matches(&entry, &desired));
        assert!(!is_user_scope("Project config"));
        assert_eq!(parse_claude_get("nothing here"), None);
    }

    #[test]
    fn db_path_with_spaces_round_trips() {
        let env = setup();
        let db = env.state.join("my notes.db");
        let args_line = format!("mcp --local {}", db.display());
        let exe = env.bin.join("native").display().to_string();
        seed_claude_stdio(&env, "native-local", &exe, &args_line);
        seed_codex_stdio(
            &env,
            "native-local",
            &exe,
            &format!(r#"["mcp","--local","{}"]"#, db.display()),
        );
        let mut opts = test_opts(&env);
        opts.db = Some(db);
        let report = run_with(&env, Path::new("native"), &opts);
        assert!(
            report.clients.iter().all(|c| c.status == "unchanged"),
            "{report:?}"
        );
        assert!(!calls(&env).contains(" mcp remove "));
    }

    #[test]
    fn non_user_scope_is_conflict() {
        let env = setup();
        seed_claude_stdio_scoped(
            &env,
            "native-local",
            "/old/path/native",
            "mcp --local /old.db",
            "Project config",
        );
        seed_codex_stdio(
            &env,
            "native-local",
            "/old/path/native",
            r#"["mcp","--local","/old.db"]"#,
        );
        let opts = test_opts(&env);
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(report.clients[0].status, "conflict");
        assert_eq!(report.clients[1].status, "replaced");
        let log = calls(&env);
        assert!(!log.contains("claude mcp remove"));
        assert!(log.contains("codex mcp remove native-local"));
    }

    #[test]
    fn fresh_registration_then_unchanged() {
        let env = setup();
        let opts = test_opts(&env);
        let first = run_with(&env, Path::new("native"), &opts);
        assert_eq!(first.clients[0].status, "registered");
        assert_eq!(first.clients[1].status, "registered");
        let log = calls(&env);
        assert!(log.contains("claude mcp add --scope user native-local --"));
        assert!(log.contains("codex mcp add native-local --"));
        std::fs::write(env.state.join("calls.log"), "").unwrap();
        let second = run_with(&env, Path::new("native"), &opts);
        assert!(second.clients.iter().all(|c| c.status == "unchanged"));
        let log = calls(&env);
        assert!(!log.contains(" mcp add "));
        assert!(!log.contains(" mcp remove "));
        assert!(log.contains("claude mcp get native-local"));
        assert!(log.contains("codex mcp get native-local"));
    }

    #[test]
    fn managed_entry_is_replaced() {
        let env = setup();
        seed_claude_stdio(
            &env,
            "native-local",
            "/old/path/native",
            "mcp --local /old.db",
        );
        seed_codex_stdio(
            &env,
            "native-local",
            "/old/path/native",
            r#"["mcp","--local","/old.db"]"#,
        );
        let opts = test_opts(&env);
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(report.clients[0].status, "replaced");
        assert_eq!(report.clients[1].status, "replaced");
        let log = calls(&env);
        assert!(log.contains("claude mcp remove native-local"));
        assert!(log.contains("codex mcp remove native-local"));
    }

    #[test]
    fn foreign_entry_is_left_alone() {
        let env = setup();
        seed_claude_stdio(&env, "native-local", "/usr/bin/other", "--serve /tmp/x");
        seed_codex_http(&env, "native-local");
        let opts = test_opts(&env);
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(report.clients[0].status, "conflict");
        assert_eq!(report.clients[1].status, "conflict");
        let log = calls(&env);
        assert!(!log.contains(" mcp add "));
        assert!(!log.contains(" mcp remove "));
        assert!(env.state.join("claude.native-local.state").is_file());
        assert!(env.state.join("codex.native-local.json").is_file());
    }

    #[test]
    fn executable_lookup_follows_symlinks() {
        let env = setup();
        let target = env.bin.join("real-cli");
        std::fs::write(&target, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(&target).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&target, perms).unwrap();
            std::os::unix::fs::symlink(&target, env.bin.join("linked-cli")).unwrap();
            assert!(is_executable(&env.bin.join("linked-cli")));
        }
    }

    #[test]
    fn hosted_native_entry_is_never_touched() {
        let env = setup();
        seed_claude_stdio(
            &env,
            "native",
            "/opt/node/bin/mcp-stdio",
            "node connect --sock x",
        );
        seed_codex_stdio(
            &env,
            "native",
            "/opt/node/bin/mcp-stdio",
            r#"["node","connect","--sock","x"]"#,
        );
        let before_claude = std::fs::read_to_string(env.state.join("claude.native.state")).unwrap();
        let before_codex = std::fs::read_to_string(env.state.join("codex.native.json")).unwrap();
        let opts = test_opts(&env);
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(report.clients[0].status, "registered");
        assert_eq!(
            std::fs::read_to_string(env.state.join("claude.native.state")).unwrap(),
            before_claude
        );
        assert_eq!(
            std::fs::read_to_string(env.state.join("codex.native.json")).unwrap(),
            before_codex
        );
        for line in calls(&env).lines() {
            assert!(!line.contains(" native --"), "hosted entry touched: {line}");
            assert!(!line.contains(" native\n"), "hosted entry touched: {line}");
        }
    }

    #[test]
    fn missing_client_is_skipped() {
        let env = setup();
        std::fs::remove_file(env.bin.join("codex")).unwrap();
        let opts = test_opts(&env);
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(report.clients[0].status, "registered");
        assert_eq!(report.clients[1].status, "skipped");
        assert!(report.clients[1].command.join(" ").contains("mcp --local"));
    }

    #[test]
    fn vault_block_create_refresh_idempotent() {
        let env = setup();
        let vault = env.state.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let agents = vault.join("AGENTS.md");
        std::fs::write(&agents, "# Notes\n\nSome intro.\n").unwrap();
        let mut opts = test_opts(&env);
        opts.vault = Some(vault.clone());
        let first = run_with(&env, Path::new("native"), &opts);
        let status_of = |report: &Report, name: &str| {
            report
                .vault
                .iter()
                .find(|v| v.path.file_name().unwrap() == name)
                .unwrap()
                .status
                .clone()
        };
        assert_eq!(status_of(&first, "AGENTS.md"), "updated");
        assert_eq!(status_of(&first, "CLAUDE.md"), "created");
        let text = std::fs::read_to_string(&agents).unwrap();
        assert!(text.starts_with("# Notes\n\nSome intro.\n"));
        assert!(text.contains(BLOCK_BEGIN) && text.contains(BLOCK_TEXT));
        let claude = vault.join("CLAUDE.md");
        assert!(std::fs::read_to_string(&claude)
            .unwrap()
            .contains(BLOCK_TEXT));
        // Refresh an outdated block; surrounding content is preserved.
        let stale = text.replace(BLOCK_TEXT, "old pointer");
        std::fs::write(&agents, &stale).unwrap();
        let second = run_with(&env, Path::new("native"), &opts);
        let status = second
            .vault
            .iter()
            .find(|v| v.path == agents)
            .unwrap()
            .status
            .clone();
        assert_eq!(status, "updated");
        let refreshed = std::fs::read_to_string(&agents).unwrap();
        assert!(refreshed.starts_with("# Notes\n\nSome intro.\n"));
        assert!(refreshed.contains(BLOCK_TEXT));
        assert!(!refreshed.contains("old pointer"));
        // Re-run: everything unchanged.
        let third = run_with(&env, Path::new("native"), &opts);
        assert!(third.vault.iter().all(|v| v.status == "unchanged"));
    }

    #[test]
    fn malformed_markers_are_left_untouched() {
        let env = setup();
        let vault = env.state.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let agents = vault.join("AGENTS.md");
        let block = format!("{BLOCK_BEGIN}\n{BLOCK_TEXT}\n{BLOCK_END}\n");
        let cases = [
            // Begin without an end.
            format!("# Notes\n{BLOCK_BEGIN}\nold pointer\n"),
            // End before its begin.
            format!("# Notes\n{BLOCK_END}\n{BLOCK_BEGIN}\n{BLOCK_TEXT}\n"),
            // Duplicate pairs.
            format!("# Notes\n{block}\nMore text.\n{block}"),
            // End without a begin.
            format!("# Notes\n{BLOCK_END}\n"),
        ];
        for (index, content) in cases.iter().enumerate() {
            std::fs::write(&agents, content).unwrap();
            let mut opts = test_opts(&env);
            opts.vault = Some(vault.clone());
            let report = run_with(&env, Path::new("native"), &opts);
            let status = report
                .vault
                .iter()
                .find(|v| v.path == agents)
                .unwrap()
                .status
                .clone();
            assert_eq!(status, "malformed", "case {index}");
            assert_eq!(std::fs::read_to_string(&agents).unwrap(), *content);
        }
    }

    #[test]
    fn markers_inside_fences_do_not_count() {
        let env = setup();
        let vault = env.state.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let agents = vault.join("AGENTS.md");
        // Decoys only inside fences: treated as no markers, block appended.
        let fenced = format!(
            "# Notes\n\n```\n{BLOCK_BEGIN}\ndecoy\n{BLOCK_END}\n```\n\n~~~\n{BLOCK_BEGIN}\n{BLOCK_END}\n~~~\n"
        );
        std::fs::write(&agents, &fenced).unwrap();
        let mut opts = test_opts(&env);
        opts.vault = Some(vault.clone());
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(
            report
                .vault
                .iter()
                .find(|v| v.path == agents)
                .unwrap()
                .status,
            "updated"
        );
        let text = std::fs::read_to_string(&agents).unwrap();
        assert!(text.contains("decoy"));
        assert_eq!(text.matches(BLOCK_TEXT).count(), 1);
        // A real pair plus fenced decoys: only the real pair refreshes.
        let mixed = format!(
            "# Notes\n\n```\n{BLOCK_BEGIN}\ndecoy\n{BLOCK_END}\n```\n\n{BLOCK_BEGIN}\nold pointer\n{BLOCK_END}\n"
        );
        std::fs::write(&agents, &mixed).unwrap();
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(
            report
                .vault
                .iter()
                .find(|v| v.path == agents)
                .unwrap()
                .status,
            "updated"
        );
        let text = std::fs::read_to_string(&agents).unwrap();
        assert!(text.contains("decoy"));
        assert!(!text.contains("old pointer"));
        assert_eq!(text.matches(BLOCK_TEXT).count(), 1);
    }

    #[test]
    fn vault_symlink_updates_its_target() {
        let env = setup();
        let vault = env.state.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let real = env.state.join("shared-agents.md");
        std::fs::write(&real, "# Shared\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, vault.join("AGENTS.md")).unwrap();
        let mut opts = test_opts(&env);
        opts.vault = Some(vault.clone());
        let report = run_with(&env, Path::new("native"), &opts);
        let status_of = |name: &str| {
            report
                .vault
                .iter()
                .find(|v| v.path.file_name().unwrap() == name)
                .unwrap()
                .status
                .clone()
        };
        assert_eq!(status_of("AGENTS.md"), "updated");
        assert_eq!(status_of("CLAUDE.md"), "created");
        let text = std::fs::read_to_string(&real).unwrap();
        assert!(text.starts_with("# Shared\n"));
        assert!(text.contains(BLOCK_TEXT));
        assert!(
            std::fs::symlink_metadata(vault.join("AGENTS.md"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "link must be kept"
        );
        assert!(vault.read_dir().unwrap().count() >= 2);
        let stray: Vec<_> = vault
            .read_dir()
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.file_name()))
            .filter(|name| name.to_string_lossy().contains("native-connect-"))
            .collect();
        assert!(stray.is_empty(), "no temp files left: {stray:?}");
    }

    #[test]
    fn vault_write_follows_chains_and_keeps_mode() {
        let env = setup();
        let vault = env.state.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let real = env.state.join("real-agents.md");
        std::fs::write(
            &real,
            format!("# Notes\n\n{BLOCK_BEGIN}\nold pointer\n{BLOCK_END}\n"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::symlink("real-agents.md", env.state.join("link1")).unwrap();
            std::os::unix::fs::symlink(env.state.join("link1"), vault.join("AGENTS.md")).unwrap();
            assert_eq!(
                write_target(&vault.join("AGENTS.md")),
                std::fs::canonicalize(&real).unwrap()
            );
        }
        let mut opts = test_opts(&env);
        opts.vault = Some(vault.clone());
        let report = run_with(&env, Path::new("native"), &opts);
        let status = report
            .vault
            .iter()
            .find(|v| v.path == vault.join("AGENTS.md"))
            .unwrap()
            .status
            .clone();
        assert_eq!(status, "updated");
        let text = std::fs::read_to_string(&real).unwrap();
        assert!(text.contains(BLOCK_TEXT));
        assert!(!text.contains("old pointer"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&real).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert!(
                std::fs::symlink_metadata(vault.join("AGENTS.md"))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "chain links must be kept"
            );
        }
    }

    #[test]
    fn missing_vault_directory_touches_no_client() {
        let env = setup();
        let mut opts = test_opts(&env);
        opts.vault = Some(env.state.join("no-such-vault"));
        let report = try_run_with(&env, Path::new("native"), &opts).expect("reports, not Err");
        assert!(report.clients.is_empty(), "no client may be touched");
        assert_eq!(report.vault.len(), VAULT_FILES.len());
        assert!(report.vault.iter().all(|v| v.status == "error"));
        assert!(report
            .vault
            .iter()
            .all(|v| v.detail.contains("does not exist")));
        assert_eq!(exit_code(&report), 1);
        assert!(!calls(&env).contains(" mcp get "));
        assert!(!calls(&env).contains(" mcp add "));
        assert!(!env.state.join("no-such-vault").exists());
    }

    #[test]
    fn dry_run_changes_nothing() {
        let env = setup();
        seed_claude_stdio(
            &env,
            "native-local",
            "/old/path/native",
            "mcp --local /old.db",
        );
        let vault = env.state.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::write(vault.join("AGENTS.md"), "# Notes\n").unwrap();
        let snapshot: Vec<(PathBuf, String)> = ["claude.native-local.state", "AGENTS.md"]
            .iter()
            .map(|f| {
                let path = if f.ends_with(".md") {
                    vault.join(f)
                } else {
                    env.state.join(f)
                };
                (path.clone(), std::fs::read_to_string(&path).unwrap())
            })
            .collect();
        let mut opts = test_opts(&env);
        opts.vault = Some(vault);
        opts.dry_run = true;
        let report = run_with(&env, Path::new("native"), &opts);
        assert!(report.dry_run);
        assert_eq!(report.clients[0].status, "replaced");
        assert_eq!(report.clients[1].status, "registered");
        let log = calls(&env);
        assert!(!log.contains(" mcp add "));
        assert!(!log.contains(" mcp remove "));
        for (path, before) in snapshot {
            assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        }
        assert!(!env.state.join("codex.native-local.json").exists());
        let text = render_text(&report);
        assert!(text.contains("would "));
        let parsed: serde_json::Value = serde_json::from_str(&render_json(&report)).unwrap();
        assert_eq!(parsed["dry_run"], true);
        assert_eq!(parsed["clients"]["claude"]["status"], "replaced");
    }

    #[test]
    fn failed_add_after_remove_names_the_restore() {
        let env = setup();
        seed_claude_stdio(
            &env,
            "native-local",
            "/old/path/native",
            "mcp --local /old.db",
        );
        std::fs::write(env.state.join("fail-add"), "").unwrap();
        let mut opts = test_opts(&env);
        opts.clients = vec!["claude".to_owned()];
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(report.clients.len(), 1);
        let detail = &report.clients[0].detail;
        assert_eq!(report.clients[0].status, "error");
        assert!(detail.contains("removed the previous entry"), "{detail}");
        assert!(
            detail.contains(
                "restore it with: claude mcp add --scope user native-local -- /old/path/native mcp --local /old.db"
            ),
            "{detail}"
        );
        assert_eq!(exit_code(&report), 1);
    }

    #[test]
    fn missing_db_is_refused_without_create_db() {
        let env = setup();
        let mut opts = test_opts(&env);
        opts.create_db = false;
        let err = try_run_with(&env, Path::new("native"), &opts).expect_err("must fail");
        assert!(err.contains("database does not exist"), "{err}");
        assert!(err.contains("--create-db"), "{err}");
        assert!(!calls(&env).contains(" mcp get "));
        // With the flag, a missing file registers fine (serve creates it).
        opts.create_db = true;
        let report = try_run_with(&env, Path::new("native"), &opts).expect("runs");
        assert_eq!(report.clients[0].status, "registered");
    }

    #[test]
    fn codex_entry_with_env_or_cwd_is_conflict() {
        for extra in [r#","env":{"TOKEN":"x"}"#, r#","cwd":"/tmp/work""#] {
            let env = setup();
            seed_claude_stdio(
                &env,
                "native-local",
                "/old/path/native",
                "mcp --local /old.db",
            );
            seed_codex_stdio_full(
                &env,
                "native-local",
                "/old/path/native",
                r#"["mcp","--local","/old.db"]"#,
                extra,
                "",
            );
            let opts = test_opts(&env);
            let report = run_with(&env, Path::new("native"), &opts);
            assert_eq!(report.clients[0].status, "replaced");
            assert_eq!(report.clients[1].status, "conflict", "extra {extra}");
            let log = calls(&env);
            assert!(!log.contains("codex mcp remove"), "extra {extra}");
            assert!(!log.contains("codex mcp add"), "extra {extra}");
        }
        // Top-level fields `codex mcp add` cannot express either.
        for extra_top in [
            r#","enabled_tools":["read"]"#,
            r#","disabled_tools":["write"]"#,
            r#","startup_timeout_sec":30"#,
            r#","tool_timeout_sec":30"#,
            r#","enabled":false"#,
        ] {
            let env = setup();
            seed_claude_stdio(
                &env,
                "native-local",
                "/old/path/native",
                "mcp --local /old.db",
            );
            seed_codex_stdio_full(
                &env,
                "native-local",
                "/old/path/native",
                r#"["mcp","--local","/old.db"]"#,
                "",
                extra_top,
            );
            let opts = test_opts(&env);
            let report = run_with(&env, Path::new("native"), &opts);
            assert_eq!(report.clients[1].status, "conflict", "top {extra_top}");
            assert!(!calls(&env).contains("codex mcp remove"), "top {extra_top}");
        }
    }

    #[test]
    fn exit_code_reflects_failures() {
        let env = setup();
        let opts = test_opts(&env);
        let clean = run_with(&env, Path::new("native"), &opts);
        assert_eq!(exit_code(&clean), 0);
        assert!(!has_failures(&clean));
        seed_claude_stdio(&env, "native-local", "/usr/bin/other", "--serve /tmp/x");
        let conflicted = run_with(&env, Path::new("native"), &opts);
        assert!(has_failures(&conflicted));
        assert_eq!(exit_code(&conflicted), 1);
    }

    #[test]
    fn malformed_vault_exits_1() {
        let env = setup();
        let vault = env.state.join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let agents = vault.join("AGENTS.md");
        std::fs::write(&agents, format!("# Notes\n{BLOCK_BEGIN}\n")).unwrap();
        let mut opts = test_opts(&env);
        opts.vault = Some(vault);
        opts.clients = vec![];
        let report = run_with(&env, Path::new("native"), &opts);
        assert_eq!(
            report
                .vault
                .iter()
                .find(|v| v.path == agents)
                .unwrap()
                .status,
            "malformed"
        );
        assert!(has_failures(&report));
        assert_eq!(exit_code(&report), 1);
    }
}
