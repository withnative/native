//! `native` — the local-first Native CLI (slice 1).
//!
//! - `native mcp --local [<db>]`: stdio MCP against one local SQLite database
//!   (created with the frozen schema when missing; defaults to the platform
//!   data directory). No account: whoever holds the file owns it.
//! - `native node serve --config <file>` / `native node connect --socket <path>`:
//!   the hosted-node server and its stdio socket shim (same as `mcp-stdio node`).
//! - `native login [--no-browser] [--hosted <origin>] [--config-dir <dir>]`:
//!   sign in to hosted Native and write the node's credential and OAuth
//!   renewal files (both 0600).
//! - `native setup [--workspace <id|name>] [--force] [--dry-run]`: after login,
//!   discover the workspace and account and write `node.json` plus the standby
//!   and refresh configs, so `native node serve` needs no hand edits.
//! - `native service install|uninstall|status`: run the node as a per-user
//!   systemd (Linux) or launchd (macOS) service.
//! - `native status [--json]`: the node's mode, local copy, held writes, account
//!   and service, in a few lines (exit 0 healthy, 1 degraded, 2 not running).
//! - `native call|search|get|sql`: operate on Native from the command line, through
//!   the running node or (`--local [<db>]`) in-process against a local database.
//! - `native --help` / `native --version` (every subcommand takes `--help`).
//!
//! Argument parsing stays hand-rolled like the rest of the codebase: no clap.

use std::path::PathBuf;
use std::process::ExitCode;

use native_ce::native_cli::connect;

fn usage() -> String {
    format!(
        "usage: native [--help|--version] <command> [<args>]\n\
         \n\
         Serve a local Native database over MCP, or reach hosted Native through a node.\n\
         \n\
         use Native (JSON on stdout; --local <db> uses a local database, otherwise the running node):\n\
         \x20 search <words...>                   search records\n\
         \x20 get <ref>...                        open records by id or short reference\n\
         \x20 sql <query>                         run a read-only SQL query\n\
         \x20 call <executor> <operation> [json]  any other operation (create, link, update, ...);\n\
         \x20                                     `call --list` shows them, `call --describe` their arguments\n\
         \x20 import [options] <dir>...           import Markdown folders into a local database\n\
         \x20 enrich [options] <dir>...           enrich Markdown files into a sidecar\n\
         \n\
         set up and serve:\n\
         \x20 init [options] [<vault>...]         set up a local vault workspace\n\
         \x20 mcp --local [<db>]                  serve this database over stdio (created when missing)\n\
         \x20 connect [--db <path>]               register the local database with coding tools\n\
         \x20 login [--no-browser]                sign in to hosted Native (writes the node's credential files)\n\
         \x20 setup [--workspace <id|name>]       write the node's config files after login\n\
         \x20 service install|uninstall|status    run the node as a background service\n\
         \x20 status [--json]                     show the node: mode, local copy, held writes, service\n\
         \x20 node serve --config <file>          run the node server from a node.json config\n\
         \x20 node connect --socket <path>        pipe stdio to a running node server (an agent's MCP command)\n\
         \n\
         examples:\n\
         \x20 native call --list --local ./n.db                                                   what can I do?\n\
         \x20 native call --describe records_write create_record --local ./n.db                   its arguments\n\
         \x20 native search launch plan --local ./n.db                                            search records\n\
         \x20 native sql \"SELECT relation_name FROM catalog_relations ORDER BY 1\" --local ./n.db  queryable tables\n\
         \x20 native mcp --local ./x.db                                                           serve a fresh database over stdio\n\
         \x20 native mcp --local                                                                  default database at {}\n\
         \n\
         exit codes of search, get, sql and call: 0 ok; 2 node not reachable or bad command line;\n\
         3 held (accepted_pending, applied later); 4 refused or invalid; 5 uncertain.\n\
         run `native <command> --help` for command help.",
        native_ce::native_cli::default_local_db_path().display()
    )
}

fn mcp_usage() -> String {
    format!(
        "usage: native mcp --local [<db>]\n\
         \n\
         Serve one SQLite database over MCP on stdio. The file is created with the\n\
         frozen schema when missing. Default: {}.\n\
         No account is needed: whoever holds the file owns it.\n\
         \n\
         examples:\n\
         \x20 native mcp --local ./x.db\n\
         \x20 native mcp --local",
        native_ce::native_cli::default_local_db_path().display()
    )
}

fn login_usage() -> String {
    #[cfg(unix)]
    let dir = native_ce::native_cli::login::default_config_dir()
        .map(|dir| dir.display().to_string())
        .unwrap_or_else(|| "<unavailable: set HOME>".to_owned());
    #[cfg(not(unix))]
    let dir = String::from("<unsupported>");
    format!(
        "usage: native login [--no-browser] [--hosted <origin>] [--config-dir <dir>] [--timeout <seconds>] [--reset]\n\
         \n\
         Sign in to hosted Native with your browser (OAuth, PKCE). Writes two owner-only\n\
         files the node reads and renews: native.token (the bearer credential) and\n\
         native-auth.json (the renewal grant), plus oauth-client.json (this install's\n\
         registered client, reused on the next login). Tokens are never printed.\n\
         \n\
         options:\n\
         \x20 --no-browser          print the sign-in address instead of opening a browser; the\n\
         \x20                       final callback address may be pasted here for headless machines\n\
         \x20 --hosted <origin>     hosted Native origin (default {})\n\
         \x20 --config-dir <dir>    where the files go (default {dir})\n\
         \x20 --timeout <seconds>   how long to wait for the sign-in (default 300)\n\
         \x20 --reset               discard the saved client registration and register a new one\n\
         \x20                       (use it if the sign-in page showed an error on a repeat login)\n\
         \n\
         If an interrupted login ever leaves the token file stale, the node repairs it on its\n\
         next renewal pass; you can also just run `native login` again.",
        native_ce::native_cli::login::DEFAULT_HOSTED_ORIGIN
    )
}

fn setup_usage() -> String {
    #[cfg(unix)]
    let (config, data) = (
        native_ce::native_cli::login::default_config_dir(),
        native_ce::native_cli::setup::default_data_dir(),
    );
    #[cfg(not(unix))]
    let (config, data): (Option<PathBuf>, Option<PathBuf>) = (None, None);
    let show = |dir: Option<PathBuf>| {
        dir.map(|d| d.display().to_string())
            .unwrap_or_else(|| "<unavailable: set HOME>".to_owned())
    };
    format!(
        "usage: native setup [--workspace <id or name>] [--hosted <origin>] [--config-dir <dir>]\n\
         \x20                   [--data-dir <dir>] [--force] [--dry-run]\n\
         \n\
         After `native login`, write the node's configuration: node.json, standby.json and\n\
         standby-refresh.json (node.json last). The workspace is chosen automatically when you\n\
         own one; otherwise name it with --workspace. Existing files that differ are left alone\n\
         unless --force is given, and the differences are shown. Re-running changes nothing.\n\
         \n\
         options:\n\
         \x20 --workspace <id|name>  the workspace to follow (an id, a unique id prefix, or its name)\n\
         \x20 --hosted <origin>      hosted Native origin (default {})\n\
         \x20 --config-dir <dir>     where login put its files, and where configs go (default {})\n\
         \x20 --data-dir <dir>       local copy and socket (default {})\n\
         \x20 --force                replace existing config files that differ\n\
         \x20 --dry-run              show what would be written, write nothing\n\
         \n\
         then run: native node serve --config <config-dir>/node.json",
        {
            #[cfg(unix)]
            {
                native_ce::native_cli::login::DEFAULT_HOSTED_ORIGIN
            }
            #[cfg(not(unix))]
            {
                "https://plugin.withnative.ai"
            }
        },
        show(config),
        show(data)
    )
}

fn status_usage() -> String {
    "usage: native status [--json] [--config-dir <dir>] [--timeout <seconds>]\n\
     \n\
     Show the state of the hosted node in a few lines: whether hosted is reachable\n\
     (or the node is serving local reads), how old the local copy is and the last\n\
     refresh failure, held writes waiting and the most recent few (never their\n\
     contents), the bound account, and the background service. It asks the running\n\
     node over its socket; nothing is changed.\n\
     \n\
     options:\n\
     \x20 --json                 one stable JSON object (schema native.status.v1) with the same facts\n\
     \x20 --config-dir <dir>     where node.json lives (default: the native config directory)\n\
     \x20 --timeout <seconds>    how long to wait for the node to answer each call (default 10)\n\
     \n\
     exit codes:\n\
     \x20 0  healthy: hosted reachable, a fresh serving copy, no held writes waiting\n\
     \x20 1  degraded: hosted unreachable or refusing us, the copy stale, paused or not\n\
     \x20    serving, a refresh failing, or held writes waiting\n\
     \x20 2  the node is not running or cannot be reached: no node.json, no socket, a stale\n\
     \x20    socket, permission or UID mismatch, not answering, or status unavailable"
        .to_string()
}

fn service_usage() -> String {
    "usage: native service install [--config-dir <dir>] [--force]\n\
     \x20      native service uninstall\n\
     \x20      native service status\n\
     \n\
     Run `native node serve --config <config-dir>/node.json` as a per-user background\n\
     service: a systemd user unit (native.service) on Linux, a launchd agent\n\
     (ai.withnative.node) on macOS. Run `native setup` first.\n\
     \n\
     \x20 install     write the service definition and start it; refuses to overwrite one\n\
     \x20             that differs or was not written by native, unless --force\n\
     \x20 uninstall   stop it and remove only native's own definition (configs and data stay)\n\
     \x20 status      installed? running? where is the definition?\n\
     \x20 --config-dir <dir>  where node.json lives (default: the native config directory)"
        .to_string()
}

fn node_usage() -> String {
    "usage: native node serve --config <file> | native node connect --socket <path>\n\
     \n\
     Talk to hosted Native through a local node server (same as `mcp-stdio node`).\n\
     `serve` runs the server from a node.json config; `connect` pipes this\n\
     process's stdio to a running server's socket (use it as an MCP server command).\n\
     \n\
     examples:\n\
     \x20 native node serve --config ~/.config/native/node.json\n\
     \x20 native node connect --socket ~/.local/share/native/run/node.sock"
        .to_string()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("native {}", native_ce::engine_version_string());
            ExitCode::SUCCESS
        }
        Some("init") => native_ce::native_cli::init::run_cli(&args[1..]),
        Some("enrich") => native_ce::native_cli::enrich::run_cli(&args[1..]),
        Some("import") => native_ce::native_cli::import::run_cli(&args[1..]),
        Some("mcp") => run_mcp(&args[1..]),
        Some("login") => run_login(&args[1..]),
        Some("setup") => run_setup(&args[1..]),
        Some("service") => run_service(&args[1..]),
        Some("status") => run_status(&args[1..]),
        Some(name @ ("call" | "search" | "get" | "sql")) => run_client(name, &args[1..]),
        Some("connect") => run_connect(&args[1..]),
        Some("node") => run_node(&args[1..]),
        Some(other) => {
            eprintln!("native: unknown command: {other}\n{}", usage());
            ExitCode::from(2)
        }
    }
}
#[cfg(not(unix))]
fn run_login(_args: &[String]) -> ExitCode {
    eprintln!("native login: not supported on this platform");
    ExitCode::from(2)
}

#[cfg(unix)]
fn run_login(args: &[String]) -> ExitCode {
    use native_ce::native_cli::login;
    let mut no_browser = false;
    let mut hosted = login::DEFAULT_HOSTED_ORIGIN.to_owned();
    let mut config_dir: Option<PathBuf> = None;
    let mut timeout = login::DEFAULT_TIMEOUT;
    let mut reset = false;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let mut value = |name: &str| -> Option<String> {
            index += 1;
            let value = args.get(index).cloned();
            if value.is_none() {
                eprintln!("native login: {name} needs a value\n{}", login_usage());
            }
            value
        };
        match flag {
            "-h" | "--help" => {
                println!("{}", login_usage());
                return ExitCode::SUCCESS;
            }
            "--no-browser" => no_browser = true,
            "--reset" | "--new-client" => reset = true,
            "--hosted" => match value("--hosted") {
                Some(v) => hosted = v,
                None => return ExitCode::from(2),
            },
            "--config-dir" => match value("--config-dir") {
                Some(v) => config_dir = Some(PathBuf::from(v)),
                None => return ExitCode::from(2),
            },
            "--timeout" => match value("--timeout").map(|v| v.parse::<u64>()) {
                Some(Ok(secs)) if secs > 0 => timeout = std::time::Duration::from_secs(secs),
                Some(_) => {
                    eprintln!("native login: --timeout must be a positive number of seconds");
                    return ExitCode::from(2);
                }
                None => return ExitCode::from(2),
            },
            other => {
                eprintln!(
                    "native login: unexpected argument: {other}\n{}",
                    login_usage()
                );
                return ExitCode::from(2);
            }
        }
        index += 1;
    }
    let Some(config_dir) = config_dir.or_else(login::default_config_dir) else {
        eprintln!("native login: cannot find a config directory; set HOME or pass --config-dir");
        return ExitCode::from(2);
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("native: cannot start runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    let options = login::LoginOptions {
        hosted_origin: hosted,
        config_dir,
        expected_token_endpoint: native_ce::node::oauth::TOKEN_ENDPOINT.to_owned(),
        browser: if no_browser {
            login::BrowserMode::PrintOnly
        } else {
            login::BrowserMode::System
        },
        // Pasting works in either mode, and costs nothing when stdin is closed.
        paste: Some(Box::new(tokio::io::BufReader::new(tokio::io::stdin()))),
        timeout,
        reset,
    };
    // Ctrl-C, SIGTERM and SIGHUP end the wait through the normal return path,
    // so the terminal's echo (switched off while a pasted address may be
    // typed) is always put back. The handlers go in first: a signal after
    // this point is queued, never fatal.
    let signals = {
        let _entered = runtime.enter();
        match login::InterruptSignals::register() {
            Ok(signals) => signals,
            Err(err) => {
                eprintln!("native login: cannot install signal handlers: {err}");
                return ExitCode::FAILURE;
            }
        }
    };
    let result = runtime.block_on(login::login_on_terminal(
        options,
        libc::STDIN_FILENO,
        signals.wait(),
    ));
    // Tokio's stdin read cannot be cancelled; do not wait for it on exit.
    runtime.shutdown_background();
    match result {
        Ok(outcome) => {
            eprintln!(
                "Signed in. Wrote {} and {}.",
                outcome.credential_file.display(),
                outcome.auth_file.display()
            );
            if outcome.client_reused {
                eprintln!("Reused the saved client registration.");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("native login: {err}");
            if let Some(hint) = err.reset_hint() {
                eprintln!("{hint}");
            }
            if err.kind == login::LoginErrorKind::Interrupted {
                ExitCode::from(130)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

#[cfg(not(unix))]
fn run_client(name: &str, _args: &[String]) -> ExitCode {
    eprintln!("native {name}: not supported on this platform");
    ExitCode::from(2)
}

/// `native call|search|get|sql`: see `native_cli::call` for the exit codes.
#[cfg(unix)]
fn run_client(name: &str, args: &[String]) -> ExitCode {
    use native_ce::native_cli::call::{self, Command};
    let command = match name {
        "call" => Command::Call,
        "search" => Command::Search,
        "get" => Command::Get,
        _ => Command::Sql,
    };
    ExitCode::from(call::main(command, args))
}

#[cfg(not(unix))]
fn run_status(_args: &[String]) -> ExitCode {
    eprintln!("native status: not supported on this platform");
    ExitCode::from(2)
}

#[cfg(unix)]
fn run_status(args: &[String]) -> ExitCode {
    use native_ce::native_cli::{login, status};
    let mut json = false;
    let mut config_dir: Option<PathBuf> = None;
    let mut timeout = std::time::Duration::from_secs(10);
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                println!("{}", status_usage());
                return ExitCode::SUCCESS;
            }
            "--json" => json = true,
            "--config-dir" | "--timeout" => {
                let flag = args[index].clone();
                index += 1;
                let Some(value) = args.get(index) else {
                    eprintln!("native status: {flag} needs a value\n{}", status_usage());
                    return ExitCode::from(2);
                };
                if flag == "--config-dir" {
                    config_dir = Some(PathBuf::from(value));
                } else {
                    match value.parse::<u64>() {
                        Ok(secs) if secs > 0 => timeout = std::time::Duration::from_secs(secs),
                        _ => {
                            eprintln!(
                                "native status: --timeout must be a positive number of seconds"
                            );
                            return ExitCode::from(2);
                        }
                    }
                }
            }
            other => {
                eprintln!(
                    "native status: unexpected argument: {other}\n{}",
                    status_usage()
                );
                return ExitCode::from(2);
            }
        }
        index += 1;
    }
    let Some(config_dir) = config_dir.or_else(login::default_config_dir) else {
        eprintln!("native status: cannot find the config directory; set HOME or pass --config-dir");
        return ExitCode::from(2);
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("native: cannot start runtime: {err}");
            return ExitCode::from(2);
        }
    };
    let service = status::service_info(&config_dir);
    let report = runtime.block_on(status::collect(status::StatusOptions {
        config_dir,
        timeout,
        service,
    }));
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(err) => {
                eprintln!("native status: cannot render the report: {err}");
                return ExitCode::from(2);
            }
        }
    } else {
        println!("{}", status::render_text(&report));
    }
    ExitCode::from(report.exit_code as u8)
}

#[cfg(not(unix))]
fn run_service(_args: &[String]) -> ExitCode {
    eprintln!("native service: not supported on this platform");
    ExitCode::from(2)
}

#[cfg(unix)]
fn run_service(args: &[String]) -> ExitCode {
    use native_ce::native_cli::{login, service};
    let Some(action) = args.first().map(String::as_str) else {
        println!("{}", service_usage());
        return ExitCode::SUCCESS;
    };
    if matches!(action, "-h" | "--help") {
        println!("{}", service_usage());
        return ExitCode::SUCCESS;
    }
    let mut config_dir: Option<PathBuf> = None;
    let mut force = false;
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => {
                println!("{}", service_usage());
                return ExitCode::SUCCESS;
            }
            "--force" if action == "install" => force = true,
            "--config-dir" => {
                index += 1;
                match args.get(index) {
                    Some(v) => config_dir = Some(PathBuf::from(v)),
                    None => {
                        eprintln!(
                            "native service: --config-dir needs a value\n{}",
                            service_usage()
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!(
                    "native service: unexpected argument: {other}\n{}",
                    service_usage()
                );
                return ExitCode::from(2);
            }
        }
        index += 1;
    }
    if !matches!(action, "install" | "uninstall" | "status") {
        eprintln!(
            "native service: unknown action: {action}\n{}",
            service_usage()
        );
        return ExitCode::from(2);
    }
    let Some(config_dir) = config_dir.or_else(login::default_config_dir) else {
        eprintln!(
            "native service: cannot find the config directory; set HOME or pass --config-dir"
        );
        return ExitCode::from(2);
    };
    let ctx = match service::ServiceContext::detect(&config_dir, action == "install") {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("native service: {err}");
            return ExitCode::FAILURE;
        }
    };
    let runner = service::SystemRunner;
    let result = match action {
        "install" => service::install(&ctx, &runner, force).map(|report| {
            let verb = match report.change {
                service::Change::Created => "installed",
                service::Change::Updated => "updated",
                service::Change::Unchanged => "already installed (unchanged)",
            };
            println!("{verb}: {}", report.unit_path.display());
            for note in report.notes {
                eprintln!("note: {note}");
            }
        }),
        "uninstall" => service::uninstall(&ctx, &runner).map(|report| {
            if report.removed {
                println!("removed: {}", report.unit_path.display());
            } else {
                println!("not installed ({})", report.unit_path.display());
            }
        }),
        _ => service::status(&ctx, &runner).map(|report| println!("{report}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("native service: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn run_setup(_args: &[String]) -> ExitCode {
    eprintln!("native setup: not supported on this platform");
    ExitCode::from(2)
}

#[cfg(unix)]
fn run_setup(args: &[String]) -> ExitCode {
    use native_ce::native_cli::{login, setup};
    let mut hosted = login::DEFAULT_HOSTED_ORIGIN.to_owned();
    let mut config_dir: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut workspace: Option<String> = None;
    let (mut force, mut dry_run) = (false, false);
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let mut value = |name: &str| -> Option<String> {
            index += 1;
            let value = args.get(index).cloned();
            if value.is_none() {
                eprintln!("native setup: {name} needs a value\n{}", setup_usage());
            }
            value
        };
        match flag {
            "-h" | "--help" => {
                println!("{}", setup_usage());
                return ExitCode::SUCCESS;
            }
            "--force" => force = true,
            "--dry-run" => dry_run = true,
            "--hosted" => match value("--hosted") {
                Some(v) => hosted = v,
                None => return ExitCode::from(2),
            },
            "--workspace" => match value("--workspace") {
                Some(v) => workspace = Some(v),
                None => return ExitCode::from(2),
            },
            "--config-dir" => match value("--config-dir") {
                Some(v) => config_dir = Some(PathBuf::from(v)),
                None => return ExitCode::from(2),
            },
            "--data-dir" => match value("--data-dir") {
                Some(v) => data_dir = Some(PathBuf::from(v)),
                None => return ExitCode::from(2),
            },
            other => {
                eprintln!(
                    "native setup: unexpected argument: {other}\n{}",
                    setup_usage()
                );
                return ExitCode::from(2);
            }
        }
        index += 1;
    }
    let (Some(config_dir), Some(data_dir)) = (
        config_dir.or_else(login::default_config_dir),
        data_dir.or_else(setup::default_data_dir),
    ) else {
        eprintln!("native setup: cannot find home directories; set HOME or pass --config-dir and --data-dir");
        return ExitCode::from(2);
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("native: cannot start runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(setup::setup(setup::SetupOptions {
        hosted_origin: hosted,
        config_dir,
        data_dir,
        workspace,
        force,
        dry_run,
        expected_token_endpoint: native_ce::node::oauth::TOKEN_ENDPOINT.to_owned(),
    }));
    match result {
        Ok(outcome) => {
            let name = outcome
                .workspace_name
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default();
            eprintln!("Workspace: {}{name}", outcome.workspace_id);
            for file in &outcome.files {
                let verb = match (outcome.dry_run, file.change) {
                    (_, setup::FileChange::Unchanged) => "unchanged",
                    (true, setup::FileChange::Created) => "would create",
                    (true, setup::FileChange::Updated) => "would update",
                    (false, setup::FileChange::Created) => "created",
                    (false, setup::FileChange::Updated) => "updated",
                };
                eprintln!("  {verb:<12} {}", file.path.display());
            }
            for difference in &outcome.differences {
                eprintln!("{difference}");
            }
            if !outcome.dry_run {
                eprintln!(
                    "Next: native node serve --config {}",
                    outcome.node_config.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("native setup: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_connect(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{}", connect::connect_usage());
        return ExitCode::SUCCESS;
    }
    let parsed = match connect::parse_args(args) {
        Ok(opts) => opts,
        Err(err) => {
            eprintln!("native connect: {err}\n{}", connect::connect_usage());
            return ExitCode::from(2);
        }
    };
    let Ok(current_exe) = std::env::current_exe() else {
        eprintln!("native connect: cannot find the current executable");
        return ExitCode::FAILURE;
    };
    let run = |program: &str, argv: &[&str]| connect::run_command(program, argv);
    let find = |name: &str| connect::find_on_path(name);
    let deps = connect::Deps {
        current_exe,
        run: &run,
        find_on_path: &find,
    };
    match connect::run(&parsed, &deps) {
        Ok(report) => {
            if parsed.json {
                println!("{}", connect::render_json(&report));
            } else {
                println!("{}", connect::render_text(&report));
            }
            ExitCode::from(connect::exit_code(&report))
        }
        Err(err) => {
            eprintln!("native connect: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_mcp(args: &[String]) -> ExitCode {
    if args.is_empty()
        || matches!(
            args.first().map(String::as_str),
            Some("-h") | Some("--help")
        )
    {
        print!("{}", mcp_usage());
        return ExitCode::SUCCESS;
    }
    let mut local = false;
    let mut db: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--local" => {
                local = true;
                if let Some(next) = args.get(index + 1) {
                    if !next.starts_with('-') {
                        if db.is_some() {
                            eprintln!("native mcp: only one database path may be supplied");
                            return ExitCode::from(2);
                        }
                        db = Some(next.clone());
                        index += 1;
                    }
                }
            }
            other => {
                eprintln!("native mcp: unexpected argument: {other}\n{}", mcp_usage());
                return ExitCode::from(2);
            }
        }
        index += 1;
    }
    if !local {
        eprintln!(
            "native mcp: only --local is supported in slice 1\n{}",
            mcp_usage()
        );
        return ExitCode::from(2);
    }
    let path = db.unwrap_or_else(|| {
        native_ce::native_cli::default_local_db_path()
            .to_string_lossy()
            .into_owned()
    });
    #[cfg(unix)]
    {
        // Owner-only database files: the engine creates the database, its
        // WAL/sidecar files, and the write-plan sidecar throughout the
        // session, so restrict the process umask before any of them exist.
        // SAFETY: no other thread exists yet (the runtime is built below).
        unsafe {
            libc::umask(0o077);
        }
    }
    let path_buf = PathBuf::from(&path);
    if let Some(parent) = path_buf.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = create_owner_only_dir_all(parent) {
                eprintln!(
                    "native: cannot create database directory {}: {err}",
                    parent.display()
                );
                return ExitCode::FAILURE;
            }
        }
    }
    let (surface, profile, experimental) = match native_ce::native_cli::resolve_local_stdio_env() {
        Ok(resolved) => resolved,
        Err(err) => {
            eprintln!("native: {err}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("native: cannot start runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(native_ce::native_cli::serve_sqlite_stdio(
        &path,
        None,
        surface,
        profile,
        experimental,
    )) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("native: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Create a missing database directory owner-only (0700). Pre-existing
/// directories are left alone: only `native`'s own creation is hardened, and
/// `mcp-stdio` is untouched.
#[cfg(unix)]
fn create_owner_only_dir_all(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    match std::fs::symlink_metadata(dir) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(dir),
        Err(err) => Err(err),
    }
}

/// Create a missing database directory on non-Unix platforms.
#[cfg(not(unix))]
fn create_owner_only_dir_all(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

fn run_node(args: &[String]) -> ExitCode {
    if args.is_empty()
        || matches!(
            args.first().map(String::as_str),
            Some("-h") | Some("--help")
        )
    {
        println!("{}", node_usage());
        return ExitCode::SUCCESS;
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["serve", "-h"] | ["serve", "--help"] => {
            println!("{}", node_usage());
            ExitCode::SUCCESS
        }
        ["connect", "-h"] | ["connect", "--help"] => {
            println!("{}", node_usage());
            ExitCode::SUCCESS
        }
        ["serve", "--config", _] => {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    eprintln!("native: cannot start runtime: {err}");
                    return ExitCode::FAILURE;
                }
            };
            match runtime.block_on(native_ce::node::run_cli(args)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => {
                    eprintln!("native node: configuration or transport failed");
                    ExitCode::FAILURE
                }
            }
        }
        ["connect", "--socket", _] => run_node_connect(args),
        _ => {
            eprintln!("native node: {}", node_usage());
            ExitCode::from(2)
        }
    }
}

/// The stateless socket shim: pipe stdio to the node server, byte for byte
/// like `mcp-stdio node connect`. Tokio stdin uses an uncancellable blocking
/// read, so a node EOF must still let this shim exit while the agent holds
/// stdin open — hence the dedicated current-thread runtime with
/// `shutdown_background`, mirroring `mcp-stdio`.
fn run_node_connect(args: &[String]) -> ExitCode {
    #[cfg(unix)]
    {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("native: cannot start runtime: {err}");
                return ExitCode::FAILURE;
            }
        };
        let result = runtime.block_on(native_ce::node::run_cli(args));
        // A node EOF must still let this stateless shim exit while the agent
        // holds stdin open.
        runtime.shutdown_background();
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                eprintln!("native node: configuration or transport failed");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(unix))]
    {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("native: cannot start runtime: {err}");
                return ExitCode::FAILURE;
            }
        };
        match runtime.block_on(native_ce::node::run_cli(args)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => {
                eprintln!("native node: configuration or transport failed");
                ExitCode::FAILURE
            }
        }
    }
}
