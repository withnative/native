//! Read-only fallback for nodes installed outside the current CLI config directory.

use std::path::PathBuf;

/// Explicit selection wins, including missing or invalid files. Only a missing
/// default config permits discovery; permission and parse failures stay visible.
pub async fn resolve_config_path(config_dir: Option<PathBuf>) -> Option<PathBuf> {
    resolve_with(
        config_dir,
        super::super::login::default_config_dir(),
        discover,
    )
    .await
}

async fn resolve_with<F, Fut>(
    explicit: Option<PathBuf>,
    default: Option<PathBuf>,
    discover: F,
) -> Option<PathBuf>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<PathBuf>>,
{
    use super::super::setup::NODE_FILE;
    if let Some(dir) = explicit {
        return Some(dir.join(NODE_FILE));
    }
    let path = default.map(|dir| dir.join(NODE_FILE));
    if let Some(path) = &path {
        // Follow symlinks as the config loader does. An inaccessible config must
        // not silently select a different node/account.
        if !matches!(std::fs::metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
            return Some(path.clone());
        }
    }
    discover().await.or(path)
}

#[cfg(target_os = "linux")]
async fn discover() -> Option<PathBuf> {
    discover_from("systemctl".as_ref(), std::path::Path::new("/proc")).await
}

#[cfg(target_os = "macos")]
async fn discover() -> Option<PathBuf> {
    // SAFETY: getuid has no preconditions or pointer arguments.
    let uid = unsafe { libc::getuid() };
    discover_macos_from("launchctl".as_ref(), uid).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn discover() -> Option<PathBuf> {
    None
}

/// The hand-managed predecessor label. The current installer label lives in
/// `service::LAUNCHD_LABEL`; install/uninstall never touch this one.
#[cfg(any(test, target_os = "macos"))]
pub(crate) const LEGACY_MAC_LABEL: &str = "ai.withnative.native-node";

#[cfg(any(test, target_os = "macos"))]
fn mac_labels() -> [&'static str; 2] {
    [crate::native_cli::service::LAUNCHD_LABEL, LEGACY_MAC_LABEL]
}

/// One loaded launchd job as `launchctl print` describes it. Only the job's
/// own top-level fields are read. Nested sections can repeat `path`, `state`
/// and `program` for other purposes and must not overwrite the job's.
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct LaunchdPrint {
    pub path: Option<PathBuf>,
    pub state: Option<String>,
    pub program: Option<PathBuf>,
    pub arguments: Option<Vec<String>>,
}

/// A loaded job whose live program and argv are a node server for one config.
#[cfg(any(test, target_os = "macos"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MacServiceJob {
    pub label: &'static str,
    pub path: Option<PathBuf>,
    pub state: Option<String>,
    pub config: PathBuf,
}

/// Read the top-level fields of `launchctl print` output. Top-level fields sit
/// exactly one tab deep; `arguments` entries one level deeper still.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn parse_launchd_print(stdout: &str) -> LaunchdPrint {
    let mut print = LaunchdPrint::default();
    let mut arguments: Option<Vec<String>> = None;
    for line in stdout.lines() {
        if let Some(mut args) = arguments.take() {
            if line.trim() == "}" {
                print.arguments = Some(args);
                continue;
            }
            if let Some(rest) = line.strip_prefix("\t\t") {
                args.push(rest.to_owned());
                arguments = Some(args);
                continue;
            }
            // A malformed block ends here; keep what was read and reconsider
            // this line, so a following top-level field is not swallowed.
            print.arguments = Some(args);
        }
        let Some(field) = line
            .strip_prefix('\t')
            .filter(|rest| !rest.starts_with('\t'))
        else {
            continue;
        };
        let value = |prefix: &str| field.strip_prefix(prefix).map(str::trim_end);
        if let Some(value) = value("path = ") {
            print.path = (!value.is_empty()).then(|| PathBuf::from(value));
        } else if let Some(value) = value("state = ") {
            print.state = (!value.is_empty()).then(|| value.to_owned());
        } else if let Some(value) = value("program = ") {
            print.program = (!value.is_empty()).then(|| PathBuf::from(value));
        } else if field.trim_end() == "arguments = {" {
            arguments = Some(Vec::new());
        }
    }
    print
}

/// Validate the job's live program and argv as `<program> node serve --config
/// <absolute>`. Both come from the loaded record, never from a plist file that
/// may since have been edited. Relative configs are refused: observed jobs set
/// no working directory, so there is nothing honest to resolve them against.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn mac_config_from_launchd(print: &LaunchdPrint) -> Option<PathBuf> {
    let program_path = print.program.as_deref()?;
    if !program_path.is_absolute() {
        return None;
    }
    let program = program_path.file_name()?.to_str()?;
    if !matches!(program, "native" | "mcp-stdio") {
        return None;
    }
    let args = print.arguments.as_deref()?;
    let argv0 = std::path::Path::new(args.first()?);
    if !argv0.is_absolute()
        || argv0.file_name().and_then(|name| name.to_str()) != Some(program)
        || args.get(1).map(String::as_str) != Some("node")
        || args.get(2).map(String::as_str) != Some("serve")
    {
        return None;
    }
    let flag = args.iter().position(|arg| arg == "--config")?;
    let path = PathBuf::from(args.get(flag + 1)?);
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return None;
    }
    Some(path)
}

/// Parse bounded `launchctl print` outputs in the order they were asked for.
/// A malformed or unrelated candidate is skipped without hiding a later one.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn mac_jobs_from_prints<I>(prints: I) -> Vec<MacServiceJob>
where
    I: IntoIterator<Item = (&'static str, String)>,
{
    prints
        .into_iter()
        .filter_map(|(label, stdout)| {
            let print = parse_launchd_print(&stdout);
            let config = mac_config_from_launchd(&print)?;
            Some(MacServiceJob {
                label,
                path: print.path,
                state: print.state,
                config,
            })
        })
        .collect()
}

/// Two config paths naming the same file. Canonical comparison when both
/// resolve (symlinked config dirs are normal); raw equality otherwise.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn same_config(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// How long one `launchctl print` observation may take. At most two labels are
/// read, so status never waits more than two of these.
#[cfg(any(test, target_os = "macos"))]
pub(crate) const MAC_OBSERVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// The largest `launchctl print` output read. The real record is a few KiB.
#[cfg(any(test, target_os = "macos"))]
const MAX_LAUNCHCTL_STDOUT: u64 = 256 * 1024;

/// Run one `launchctl print` with a hard deadline. Unlike
/// `service::SystemRunner`, this cannot hold status on a wedged service
/// manager; stdout is read on its own thread so a full pipe cannot deadlock
/// the wait, and the wait for it is bounded too.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn bounded_launchd_print(
    launchctl: &std::ffi::OsStr,
    target: &str,
    limit: std::time::Duration,
) -> Option<String> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};
    let mut child = Command::new(launchctl)
        .args(["print", target])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(MAX_LAUNCHCTL_STDOUT).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let bytes = receiver.recv_timeout(remaining).ok()?;
    (status.success() && (bytes.len() as u64) < MAX_LAUNCHCTL_STDOUT)
        .then(|| String::from_utf8_lossy(&bytes).into_owned())
}

/// Observe the current label first, then the hand-managed legacy one. Each
/// call is bounded, and an absent, failed, or unparseable candidate simply
/// leaves the next label to answer.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn observe_mac_jobs(
    launchctl: &std::ffi::OsStr,
    uid: u32,
    limit: std::time::Duration,
) -> Vec<MacServiceJob> {
    let prints = mac_labels()
        .into_iter()
        .filter_map(|label| {
            let target = format!("gui/{uid}/{label}");
            bounded_launchd_print(launchctl, &target, limit).map(|stdout| (label, stdout))
        })
        .collect::<Vec<_>>();
    mac_jobs_from_prints(prints)
}

#[cfg(any(test, target_os = "macos"))]
async fn discover_macos_from(launchctl: &std::ffi::OsStr, uid: u32) -> Option<PathBuf> {
    let launchctl = launchctl.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut jobs = observe_mac_jobs(&launchctl, uid, MAC_OBSERVE_TIMEOUT);
        let preferred = jobs
            .iter()
            .position(|job| job.state.as_deref() == Some("running"))
            .unwrap_or(0);
        (!jobs.is_empty()).then(|| jobs.swap_remove(preferred).config)
    })
    .await
    .ok()
    .flatten()
}

#[cfg(target_os = "linux")]
async fn discover_from(
    program: &std::ffi::OsStr,
    process_root: &std::path::Path,
) -> Option<PathBuf> {
    // native.service is the current installer; native-node.service is the
    // hand-installed predecessor. Read the actual process argv rather than
    // interpreting systemd's escaped ExecStart display as shell syntax.
    for unit in ["native.service", "native-node.service"] {
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            tokio::process::Command::new(program)
                .args(["--user", "show", "--property=MainPID", "--value", unit])
                .kill_on_drop(true)
                .output(),
        )
        .await;
        let Ok(Ok(output)) = output else { continue };
        if !output.status.success() {
            continue;
        }
        let Some(pid) = std::str::from_utf8(&output.stdout)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|pid| *pid > 0)
        else {
            continue;
        };
        if let Some(path) = process_config(&process_root.join(pid.to_string())) {
            return Some(path);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn process_config(process: &std::path::Path) -> Option<PathBuf> {
    use std::io::Read as _;
    use std::os::unix::ffi::OsStrExt as _;
    let mut bytes = Vec::new();
    std::fs::File::open(process.join("cmdline"))
        .ok()?
        .take(65_537)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 65_536 {
        return None;
    }
    let args: Vec<_> = bytes
        .split(|b| *b == 0)
        .map(std::ffi::OsStr::from_bytes)
        .collect();
    let exe = std::path::Path::new(args.first()?).file_name()?;
    if !matches!(exe.to_str(), Some("native" | "mcp-stdio"))
        || args.get(1)? != &"node"
        || args.get(2)? != &"serve"
    {
        return None;
    }
    let flag = args.iter().position(|arg| *arg == "--config")?;
    let path = PathBuf::from(*args.get(flag + 1)?);
    if path.as_os_str().is_empty() {
        return None;
    }
    Some(if path.is_absolute() {
        path
    } else {
        std::fs::read_link(process.join("cwd")).ok()?.join(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_and_existing_default_configs_do_not_consult_services() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("node.json");
        // An explicit missing config must not fall through to another account.
        assert_eq!(
            resolve_with(Some(dir.path().into()), None, || async {
                panic!("discovery")
            })
            .await,
            Some(expected.clone())
        );
        // Even an invalid default config stays selected for the loader to explain.
        std::fs::write(&expected, "invalid JSON").unwrap();
        assert_eq!(
            resolve_with(None, Some(dir.path().into()), || async {
                panic!("discovery")
            })
            .await,
            Some(expected)
        );
    }

    #[tokio::test]
    async fn missing_default_uses_service_config_and_unavailable_discovery_keeps_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let service_config = dir.path().join("legacy node/custom.json");
        assert_eq!(
            resolve_with(None, Some(dir.path().into()), || async {
                Some(service_config.clone())
            })
            .await,
            Some(service_config)
        );
        assert_eq!(
            resolve_with(None, Some(dir.path().into()), || async { None }).await,
            Some(dir.path().join("node.json"))
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn finds_legacy_service_after_absent_current_service_and_tolerates_manager_failure() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let manager = dir.path().join("systemctl");
        std::fs::write(
            &manager,
            "#!/bin/sh\ncase \"$*\" in\n'--user show --property=MainPID --value native.service') echo 0;;\n'--user show --property=MainPID --value native-node.service') echo 123;;\n*) exit 1;;\nesac\n",
        ).unwrap();
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o700)).unwrap();
        let process = dir.path().join("123");
        std::fs::create_dir(&process).unwrap();
        std::fs::write(
            process.join("cmdline"),
            b"/bin/mcp-stdio\0node\0serve\0--config\0/legacy node/node.json\0",
        )
        .unwrap();
        assert_eq!(
            resolve_with(None, Some(dir.path().into()), || discover_from(
                manager.as_os_str(),
                dir.path()
            ))
            .await,
            Some("/legacy node/node.json".into())
        );
        // A broken or unavailable user manager must leave the ordinary missing
        // config report available, rather than preventing status from running.
        std::fs::write(&manager, "#!/bin/sh\nexit 1\n").unwrap();
        assert_eq!(
            resolve_with(None, Some(dir.path().into()), || discover_from(
                manager.as_os_str(),
                dir.path()
            ))
            .await,
            Some(dir.path().join("node.json"))
        );
    }

    /// The real shape of `launchctl print gui/501/<label>`: tab-indented
    /// top-level fields, then a tab-indented `arguments` block.
    fn print_fixture(plist: &std::path::Path, state: &str, program: &str, args: &[&str]) -> String {
        let mut out = format!(
            "\tpath = {}\n\tstate = {state}\n\tprogram = {program}\n\targuments = {{\n",
            plist.display()
        );
        for arg in args {
            out.push_str(&format!("\t\t{arg}\n"));
        }
        out.push_str("\t}\n\tpid = 56509\n");
        out
    }

    #[test]
    fn mac_launchd_print_reads_only_top_level_fields_and_preserves_spaces() {
        let plist = std::path::Path::new("/Users/example/Library/LaunchAgents/my agent.plist");
        let program = "/Users/example/Library/Application Support/native-node/bin/mcp-stdio";
        let config = "/Users/example/Library/Application Support/native-node/config/node.json";
        let args = [program, "node", "serve", "--config", config];
        let mut stdout = print_fixture(plist, "running", program, &args);
        // Nested sections repeat these names for other purposes.
        stdout.push_str(
            "\tnested = {\n\
             \t\tpath = /wrong.plist\n\
             \t\tstate = waiting\n\
             \t\tprogram = /wrong/program\n\
             \t\targuments = {\n\
             \t\tnode\n\
             \t\tserve\n\
             \t\t--config\n\
             \t\t/wrong.json\n\
             \t\t}\n\
             \t}\n",
        );
        let print = parse_launchd_print(&stdout);
        assert_eq!(print.path.as_deref(), Some(plist));
        assert_eq!(print.state.as_deref(), Some("running"));
        assert_eq!(
            print.program.as_deref(),
            Some(std::path::Path::new(program))
        );
        assert_eq!(
            print.arguments,
            Some(args.iter().map(|arg| (*arg).to_owned()).collect())
        );
        assert_eq!(mac_config_from_launchd(&print), Some(config.into()));
    }

    #[test]
    fn mac_launchd_rejects_unrelated_programs_and_unsafe_argv() {
        let plist = std::path::Path::new("/agent.plist");
        for (program, args) in [
            (
                "/bin/sh",
                vec!["/bin/sh", "node", "serve", "--config", "/x.json"],
            ),
            (
                "/bin/mcp-stdio",
                vec!["/bin/other", "node", "serve", "--config", "/x.json"],
            ),
            (
                "relative/mcp-stdio",
                vec!["relative/mcp-stdio", "node", "serve", "--config", "/x.json"],
            ),
            (
                "/bin/mcp-stdio",
                vec!["/bin/mcp-stdio", "node", "connect", "--config", "/x.json"],
            ),
            (
                "/bin/mcp-stdio",
                vec!["/bin/mcp-stdio", "node", "serve", "--config"],
            ),
            (
                "/bin/mcp-stdio",
                vec![
                    "/bin/mcp-stdio",
                    "node",
                    "serve",
                    "--config",
                    "relative.json",
                ],
            ),
        ] {
            let print = parse_launchd_print(&print_fixture(plist, "running", program, &args));
            assert_eq!(mac_config_from_launchd(&print), None, "{program} {args:?}");
        }
        let good = ["/bin/mcp-stdio", "node", "serve", "--config", "/x.json"];
        let print = parse_launchd_print(&print_fixture(plist, "running", "/bin/mcp-stdio", &good));
        assert_eq!(mac_config_from_launchd(&print), Some("/x.json".into()));
    }

    fn fake_launchctl(
        dir: &std::path::Path,
        current: Option<&str>,
        legacy: Option<&str>,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let branch = |name: &str, text: Option<&str>| match text {
            Some(text) => {
                let path = dir.join(name);
                std::fs::write(&path, text).unwrap();
                format!("cat '{}'", path.display())
            }
            None => "exit 113".to_owned(),
        };
        let current = branch("current.txt", current);
        let legacy = branch("legacy.txt", legacy);
        let script = dir.join("launchctl");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ncase \"$*\" in\n*ai.withnative.native-node*) {legacy};;\n*ai.withnative.node*) {current};;\n*) exit 113;;\nesac\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    #[tokio::test]
    async fn mac_discovers_legacy_after_malformed_current_and_absent_jobs() {
        let dir = tempfile::tempdir().unwrap();
        let plist = dir.path().join("my agent.plist");
        std::fs::write(&plist, "<plist/>").unwrap();
        let config = "/Users/example/Library/Application Support/native-node/config/node.json";
        let program = "/Users/example/Library/Application Support/native-node/bin/mcp-stdio";
        let good = print_fixture(
            &plist,
            "running",
            program,
            &[program, "node", "serve", "--config", config],
        );
        // No top-level `program`, so this record cannot identify what runs;
        // an unrelated live program is rejected by the parser tests above.
        let malformed = format!(
            "\tstate = running\n\targuments = {{\n\t\tnode\n\t\tserve\n\t\t--config\n\t\t{config}\n\t}}\n"
        );
        // A malformed current candidate must not hide a valid legacy one.
        let launchctl = fake_launchctl(dir.path(), Some(&malformed), Some(&good));
        assert_eq!(
            discover_macos_from(launchctl.as_os_str(), 501).await,
            Some(config.into())
        );
        // With no valid candidate at either label there is nothing to discover.
        let launchctl = fake_launchctl(dir.path(), Some(&malformed), None);
        assert_eq!(discover_macos_from(launchctl.as_os_str(), 501).await, None);
    }

    #[tokio::test]
    async fn mac_prefers_running_legacy_over_stopped_current_job() {
        let dir = tempfile::tempdir().unwrap();
        let program = "/bin/native";
        let fixture = |state, config| {
            print_fixture(
                std::path::Path::new("/agent.plist"),
                state,
                program,
                &[program, "node", "serve", "--config", config],
            )
        };
        let current = fixture("spawn scheduled", "/stopped/node.json");
        let legacy = fixture("running", "/running/node.json");
        let manager = fake_launchctl(dir.path(), Some(&current), Some(&legacy));
        assert_eq!(
            discover_macos_from(manager.as_os_str(), 501).await,
            Some("/running/node.json".into())
        );
        // With no running job, retain the current loaded job for diagnosis.
        let manager = fake_launchctl(dir.path(), Some(&current), None);
        assert_eq!(
            discover_macos_from(manager.as_os_str(), 501).await,
            Some("/stopped/node.json".into())
        );
    }

    #[tokio::test]
    async fn mac_manager_failure_keeps_the_missing_config_report() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let launchctl = dir.path().join("launchctl");
        std::fs::write(&launchctl, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&launchctl, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(discover_macos_from(launchctl.as_os_str(), 501).await, None);
        // A broken or unavailable user manager leaves the ordinary missing
        // config report available rather than preventing status from running.
        assert_eq!(
            resolve_with(None, Some(dir.path().into()), || discover_macos_from(
                launchctl.as_os_str(),
                501
            ))
            .await,
            Some(dir.path().join("node.json"))
        );
        // A missing manager binary is the same no-answer case.
        assert_eq!(
            discover_macos_from(dir.path().join("missing").as_os_str(), 501).await,
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn service_process_args_preserve_paths_and_require_a_node_server() {
        let dir = tempfile::tempdir().unwrap();
        let cmdline = dir.path().join("cmdline");
        std::fs::write(
            &cmdline,
            b"/bin/mcp-stdio\0node\0serve\0--config\0/path with spaces/custom.json\0",
        )
        .unwrap();
        assert_eq!(
            process_config(dir.path()),
            Some("/path with spaces/custom.json".into())
        );
        std::os::unix::fs::symlink("/working directory", dir.path().join("cwd")).unwrap();
        std::fs::write(&cmdline, b"native\0node\0serve\0--config\0relative.json\0").unwrap();
        assert_eq!(
            process_config(dir.path()),
            Some("/working directory/relative.json".into())
        );
        for args in [
            b"unrelated\0node\0serve\0--config\0x\0".as_slice(),
            b"native\0node\0connect\0--config\0x\0",
            b"native\0node\0serve\0--config\0",
            b"native\0node\0serve\0",
        ] {
            std::fs::write(&cmdline, args).unwrap();
            assert_eq!(process_config(dir.path()), None);
        }
    }
}
