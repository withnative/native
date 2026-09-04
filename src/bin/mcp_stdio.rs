//! `mcp-stdio` — the local MCP server: JSON-RPC over stdio against one `.db`.
//!
//! Usage: `mcp-stdio [--account <token>] <path-to.db>` for writable SQLite,
//! or `mcp-stdio --standby [--account <token>] <path-to-standby-config.json>`.
//! Writable SQLite may instead set `NATIVE_CE_DB`, or set
//! `NATIVE_CE_STORAGE_TARGET_CONFIG` to consume the
//! operator-controlled active target, or set `NATIVE_CE_POSTGRES_CONFIG` to a
//! typed Postgres runtime JSON file, or set `NATIVE_CE_TURSO_LOCAL_CONFIG` to
//! a typed local-Turso runtime JSON file. Standby may instead set
//! `NATIVE_CE_STANDBY_CONFIG`. Non-SQLite stdio is an explicit
//! trusted-local boundary and rejects account selection. Ordinary mode creates
//! a missing SQLite file with the frozen schema. `--standby` resolves and
//! revalidates an immutable generation from the configured replica store and
//! opens every SQLite pool physically read-only without startup reconciliation.

use std::process::ExitCode;
use std::sync::Arc;

use native_ce::db::DatabaseOpenMode;
use native_ce::export::{ExportCoordinator, LocalSnapshotSource};
use native_ce::identity::resolve_stdio_account_identity;
use native_ce::mcp::{
    register_build_enabled_experimental_tools, register_builtin_tools, register_snapshot_tool,
    register_standby_status_tool, register_surface_tools, Caller, ExposureProfile, McpSurfaceMode,
    StatusOnlyStdioServer, StdioServer, ToolRegistry,
};
#[cfg(feature = "mcp-executor-prototype")]
use native_ce::mcp::{ExecutorPrototypeStdioServer, ExecutorTelemetryContext};
#[cfg(feature = "postgres")]
use native_ce::postgres::{register_postgres_tools, PostgresRuntimeConfig};
use native_ce::standby::{
    observe_installed_consumer_identity, GenerationStore, RefreshCause, StandbyRefreshConfig,
    StandbyRefreshController, StandbyRefreshOutcome, StandbyRuntimeConfig, StandbyStartupOutcome,
    StandbyStatusOnly, StandbyStatusProvider,
};
#[cfg(feature = "turso-local")]
use native_ce::turso_local::{register_turso_local_tools, TursoLocalRuntimeConfig};
use sqlx::Row;

const USAGE: &str =
    "usage: mcp-stdio [--account <token>] <path-to.db> | mcp-stdio --standby [--account <token>] <path-to-standby-config.json>   (or set exactly one applicable controller: NATIVE_CE_DB, NATIVE_CE_STANDBY_CONFIG, NATIVE_CE_STORAGE_TARGET_CONFIG, NATIVE_CE_POSTGRES_CONFIG, NATIVE_CE_TURSO_LOCAL_CONFIG; Postgres and Turso-local are trusted-local and reject NATIVE_CE_ACCOUNT)";
const ENV_MCP_SURFACE: &str = "NATIVE_CE_MCP_SURFACE";
const ENV_STANDBY_REFRESH_CONFIG: &str = "NATIVE_CE_STANDBY_REFRESH_CONFIG";

struct BackgroundRefresh {
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl BackgroundRefresh {
    async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

fn configured_surface(raw: Option<String>) -> std::result::Result<McpSurfaceMode, String> {
    raw.map(|value| {
        value
            .parse()
            .map_err(|reason| format!("{ENV_MCP_SURFACE} is invalid ({reason})"))
    })
    .transpose()
    .map(Option::unwrap_or_default)
}

fn configured_profile(raw: Option<String>) -> std::result::Result<ExposureProfile, String> {
    raw.map(|value| {
        value
            .parse()
            .map_err(|reason| format!("NATIVE_CE_MCP_TOOL_PROFILE is invalid ({reason}): {value}"))
    })
    .transpose()
    .map(Option::unwrap_or_default)
}

fn configured_profile_for_surface(
    surface: McpSurfaceMode,
    raw: Option<String>,
) -> std::result::Result<ExposureProfile, String> {
    if surface == McpSurfaceMode::Legacy {
        configured_profile(raw)
    } else {
        Ok(ExposureProfile::Complete)
    }
}

fn register_stdio_tools(
    registry: &mut ToolRegistry,
    exports: &ExportCoordinator,
) -> native_ce::Result<()> {
    register_builtin_tools(registry)?;
    register_surface_tools(registry)?;
    register_build_enabled_experimental_tools(registry)?;
    register_snapshot_tool(
        registry,
        Arc::new(LocalSnapshotSource::with_coordinator(exports.clone())),
    )?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct Cli {
    path: String,
    account: Option<String>,
    open_mode: DatabaseOpenMode,
}

fn parse_cli(
    args: impl IntoIterator<Item = String>,
    db_env: Option<String>,
    standby_config_env: Option<String>,
    account_env: Option<String>,
    controlled_target: Option<String>,
) -> std::result::Result<Option<Cli>, String> {
    let mut args = args.into_iter();
    let mut path = None;
    let mut account = None;
    let mut standby = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--standby" if standby => return Err("--standby may only be supplied once".into()),
            "--standby" => standby = true,
            "--account" => {
                if account.is_some() {
                    return Err("--account may only be supplied once".into());
                }
                account = Some(
                    args.next()
                        .ok_or_else(|| "--account requires a token".to_string())?,
                );
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ if path.is_none() => path = Some(arg),
            _ => return Err("only one database path may be supplied".into()),
        }
    }
    let db_env = db_env.filter(|value| !value.is_empty());
    let standby_config_env = standby_config_env.filter(|value| !value.is_empty());
    if standby {
        if db_env.is_some() || controlled_target.is_some() {
            return Err("standby startup accepts only a standby runtime config, not NATIVE_CE_DB or NATIVE_CE_STORAGE_TARGET_CONFIG".into());
        }
        if path.is_some() && standby_config_env.is_some() {
            return Err("standby config is selected twice; use either the positional path or NATIVE_CE_STANDBY_CONFIG".into());
        }
        path = path.or(standby_config_env);
    } else if standby_config_env.is_some() {
        return Err("NATIVE_CE_STANDBY_CONFIG requires --standby".into());
    }
    if !standby && controlled_target.is_some() && (path.is_some() || db_env.is_some()) {
        return Err("NATIVE_CE_STORAGE_TARGET_CONFIG is the sole database controller; do not also pass a path or NATIVE_CE_DB".into());
    }
    let path = (if standby {
        path
    } else {
        controlled_target.or(path).or(db_env)
    })
    .filter(|value| !value.is_empty())
    .ok_or_else(|| {
        if standby {
            "standby runtime config path is required".to_string()
        } else {
            "database path is required".to_string()
        }
    })?;
    Ok(Some(Cli {
        path,
        // An explicit CLI selection always wins over the environment.
        account: account.or(account_env),
        open_mode: if standby {
            DatabaseOpenMode::StandbyReadOnly
        } else {
            DatabaseOpenMode::ReadWrite
        },
    }))
}

fn sqlite_surface(configured: McpSurfaceMode, open_mode: DatabaseOpenMode) -> McpSurfaceMode {
    match open_mode {
        DatabaseOpenMode::ReadWrite => configured,
        // The executor constructor opens its plan-store sidecar and telemetry
        // machinery. Standby startup must not construct either.
        DatabaseOpenMode::StandbyReadOnly => McpSurfaceMode::Legacy,
    }
}

async fn resolve_standby_account_identity(
    db: &native_ce::Db,
    selected_account: Option<&str>,
) -> native_ce::Result<String> {
    let rows = sqlx::query(
        "SELECT bindings.record_id, bindings.identifier,
                records.type, records.kind, records.deleted_at
         FROM bindings
         LEFT JOIN records ON records.id = bindings.record_id
         WHERE bindings.system = 'account' AND bindings.is_canonical = 1
         ORDER BY bindings.identifier",
    )
    .fetch_all(db.pool())
    .await?;

    let mut accounts = Vec::with_capacity(rows.len());
    let mut record_ids = std::collections::HashSet::with_capacity(rows.len());
    for row in rows {
        let record_id = row.try_get::<String, _>("record_id")?;
        let account = row.try_get::<String, _>("identifier")?;
        let record_type = row.try_get::<Option<String>, _>("type")?;
        let kind = row.try_get::<Option<String>, _>("kind")?;
        let deleted_at = row.try_get::<Option<String>, _>("deleted_at")?;
        let token_is_valid = account.len() == 37
            && account.starts_with("acct_")
            && account[5..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !token_is_valid
            || record_type.as_deref() != Some("Entity")
            || kind.as_deref() != Some("person")
            || deleted_at.is_some()
            || !record_ids.insert(record_id)
        {
            return Err(native_ce::Error::engine(
                "standby account bindings do not form a valid canonical identity set",
            ));
        }
        accounts.push(account);
    }

    match selected_account {
        Some(selected) if accounts.iter().any(|account| account == selected) => {
            Ok(selected.to_string())
        }
        Some(selected) => {
            let detail = if selected.len() == 37
                && selected.starts_with("acct_")
                && selected[5..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                "selected account is not available"
            } else {
                "selected account token is malformed"
            };
            Err(native_ce::Error::engine(format!(
                "standby account selection failed: {detail}"
            )))
        }
        None if accounts.len() == 1 => Ok(accounts.remove(0)),
        None if accounts.is_empty() => Err(native_ce::Error::engine(
            "standby account selection failed: no canonical account is present",
        )),
        None => Err(native_ce::Error::engine(
            "standby account selection failed: multiple accounts are present; pass --account <token> or set NATIVE_CE_ACCOUNT",
        )),
    }
}

fn validate_postgres_selection(
    args: &[String],
    db_env: Option<&str>,
    controlled_target: Option<&str>,
    account_env: Option<&str>,
) -> std::result::Result<(), String> {
    if !args.is_empty()
        || db_env.is_some_and(|value| !value.trim().is_empty())
        || controlled_target.is_some_and(|value| !value.trim().is_empty())
    {
        return Err(
            "NATIVE_CE_POSTGRES_CONFIG is the sole database controller; do not also select SQLite"
                .into(),
        );
    }
    if account_env.is_some_and(|value| !value.trim().is_empty()) {
        return Err("NATIVE_CE_ACCOUNT is not accepted for trusted-local Postgres stdio".into());
    }
    Ok(())
}

fn validate_turso_selection(
    args: &[String],
    db_env: Option<&str>,
    controlled_target: Option<&str>,
    postgres_config: Option<&str>,
    account_env: Option<&str>,
) -> std::result::Result<(), String> {
    if !args.is_empty()
        || db_env.is_some_and(|value| !value.trim().is_empty())
        || controlled_target.is_some_and(|value| !value.trim().is_empty())
        || postgres_config.is_some_and(|value| !value.trim().is_empty())
    {
        return Err(
            "NATIVE_CE_TURSO_LOCAL_CONFIG is the sole database controller; do not also select SQLite or Postgres"
                .into(),
        );
    }
    if account_env.is_some_and(|value| !value.trim().is_empty()) {
        return Err("NATIVE_CE_ACCOUNT is not accepted for trusted-local Turso-local stdio".into());
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|argument| argument == "--standby-refresh")
    {
        return run_manual_standby_refresh(&args[1..]).await;
    }
    let standby_requested = args.iter().any(|argument| argument == "--standby");
    let surface = match configured_surface(std::env::var(ENV_MCP_SURFACE).ok()) {
        Ok(surface) => surface,
        Err(err) => {
            eprintln!("mcp-stdio: {err}");
            return ExitCode::from(2);
        }
    };
    #[cfg(not(feature = "mcp-executor-prototype"))]
    if surface == McpSurfaceMode::Executor && !standby_requested {
        eprintln!(
            "mcp-stdio: executor MCP surface is not included in this build; controlled rollback requires {ENV_MCP_SURFACE}=legacy and a restart"
        );
        return ExitCode::FAILURE;
    }
    let profile = match configured_profile_for_surface(
        surface,
        std::env::var("NATIVE_CE_MCP_TOOL_PROFILE").ok(),
    ) {
        Ok(profile) => profile,
        Err(err) => {
            eprintln!("mcp-stdio: {err}");
            return ExitCode::from(2);
        }
    };
    let db_env = std::env::var("NATIVE_CE_DB").ok();
    let standby_config_env = std::env::var("NATIVE_CE_STANDBY_CONFIG").ok();
    let standby_refresh_config = std::env::var(ENV_STANDBY_REFRESH_CONFIG)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let account_env = std::env::var("NATIVE_CE_ACCOUNT").ok();
    let controlled_target_config = std::env::var("NATIVE_CE_STORAGE_TARGET_CONFIG").ok();
    let postgres_config = std::env::var("NATIVE_CE_POSTGRES_CONFIG")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let turso_config = std::env::var("NATIVE_CE_TURSO_LOCAL_CONFIG")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if standby_refresh_config.is_some() && !standby_requested {
        eprintln!("mcp-stdio: {ENV_STANDBY_REFRESH_CONFIG} requires --standby\n{USAGE}");
        return ExitCode::from(2);
    }
    if standby_config_env
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && (db_env
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || controlled_target_config
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || postgres_config.is_some()
            || turso_config.is_some())
    {
        eprintln!(
            "mcp-stdio: NATIVE_CE_STANDBY_CONFIG is the sole storage controller in standby mode\n{USAGE}"
        );
        return ExitCode::from(2);
    }
    if let Some(config_path) = turso_config {
        if surface == McpSurfaceMode::Executor {
            eprintln!(
                "mcp-stdio: executor write plans are not qualified for Turso-local stdio; controlled rollback requires {ENV_MCP_SURFACE}=legacy and a restart"
            );
            return ExitCode::FAILURE;
        }
        if let Err(error) = validate_turso_selection(
            &args,
            db_env.as_deref(),
            controlled_target_config.as_deref(),
            postgres_config.as_deref(),
            account_env.as_deref(),
        ) {
            eprintln!("mcp-stdio: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
        #[cfg(feature = "turso-local")]
        {
            return run_turso_local(&config_path, profile).await;
        }
        #[cfg(not(feature = "turso-local"))]
        {
            let _ = (config_path, profile);
            eprintln!("mcp-stdio: this build does not include Turso-local support");
            return ExitCode::FAILURE;
        }
    }
    if let Some(config_path) = postgres_config {
        if surface == McpSurfaceMode::Executor {
            eprintln!(
                "mcp-stdio: executor write plans are not qualified for Postgres stdio; controlled rollback requires {ENV_MCP_SURFACE}=legacy and a restart"
            );
            return ExitCode::FAILURE;
        }
        if let Err(error) = validate_postgres_selection(
            &args,
            db_env.as_deref(),
            controlled_target_config.as_deref(),
            account_env.as_deref(),
        ) {
            eprintln!("mcp-stdio: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
        #[cfg(feature = "postgres")]
        {
            return run_postgres(&config_path, profile).await;
        }
        #[cfg(not(feature = "postgres"))]
        {
            let _ = (config_path, profile);
            eprintln!("mcp-stdio: this build does not include Postgres support");
            return ExitCode::FAILURE;
        }
    }
    let controlled_target = match controlled_target_config {
        Some(path) if !path.is_empty() => {
            match native_ce::storage_migration::resolve_runtime_target(std::path::Path::new(&path))
            {
                Ok(target) => Some(target.to_string_lossy().into_owned()),
                Err(err) => {
                    eprintln!("mcp-stdio: cannot resolve controlled storage target: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
        _ => None,
    };
    let cli = match parse_cli(
        args,
        db_env,
        standby_config_env,
        account_env,
        controlled_target,
    ) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            eprintln!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("mcp-stdio: {err}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let Cli {
        mut path,
        account: selected_account,
        open_mode,
    } = cli;
    let mut activated_generation = None;
    let mut background_refresh = None;
    let mut standby_status_provider = None;
    if open_mode == DatabaseOpenMode::StandbyReadOnly {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("mcp-stdio: cannot read standby runtime config: {error}");
                return ExitCode::FAILURE;
            }
        };
        let config = match StandbyRuntimeConfig::from_json(&bytes) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("mcp-stdio: {error}");
                return ExitCode::FAILURE;
            }
        };
        let store = match GenerationStore::open(
            &config.replica_root,
            &config.hosted_route_database_id,
            Some(config.origin_database_id.clone()),
        ) {
            Ok(store) => store,
            Err(error) => {
                eprintln!("mcp-stdio: cannot open standby generation store: {error}");
                return ExitCode::FAILURE;
            }
        };
        let observed = match observe_installed_consumer_identity() {
            Ok(observed) => observed,
            Err(error) => {
                eprintln!("mcp-stdio: standby consumer identity unavailable: {error}");
                let provider = StandbyStatusProvider::for_status_only_reason(
                    config,
                    store,
                    None,
                    StandbyStatusOnly {
                        reason: "installed_consumer_identity_unavailable".into(),
                        candidate_count: 0,
                        unusable_candidate_count: 0,
                    },
                    standby_refresh_config.is_some(),
                    false,
                );
                return serve_status_only(provider).await;
            }
        };
        match store.activate_for_startup(&observed).await {
            Ok(StandbyStartupOutcome::Serving(active)) => {
                let refresh_configured = standby_refresh_config.is_some();
                let mut refresh_available = refresh_configured;
                if let Some(refresh_config_path) = standby_refresh_config.as_deref() {
                    match start_background_refresh(&config, &observed, refresh_config_path).await {
                        Ok(refresh) => background_refresh = refresh,
                        Err(error) => {
                            refresh_available = false;
                            eprintln!("mcp-stdio: standby refresh is unavailable: {error}");
                        }
                    }
                }
                if let Some(reason) = active.startup_reason {
                    eprintln!("mcp-stdio: standby startup recovered with reason {reason:?}");
                }
                for warning in &active.retention_warnings {
                    eprintln!("mcp-stdio: standby retention warning: {warning}");
                }
                path = active
                    .generation
                    .snapshot_path
                    .to_string_lossy()
                    .into_owned();
                standby_status_provider = Some(StandbyStatusProvider::for_serving(
                    config.clone(),
                    store.clone(),
                    observed.clone(),
                    &active,
                    refresh_configured,
                    refresh_available,
                ));
                activated_generation = Some(active);
            }
            Ok(StandbyStartupOutcome::StatusOnly(status)) => {
                let refresh_configured = standby_refresh_config.is_some();
                let mut refresh_available = refresh_configured;
                if let Some(refresh_config_path) = standby_refresh_config.as_deref() {
                    match start_background_refresh(&config, &observed, refresh_config_path).await {
                        Ok(refresh) => background_refresh = refresh,
                        Err(error) => {
                            refresh_available = false;
                            eprintln!("mcp-stdio: standby refresh is unavailable: {error}");
                        }
                    }
                }
                let provider = StandbyStatusProvider::for_status_only(
                    config,
                    store,
                    Some(observed),
                    status,
                    refresh_configured,
                    refresh_available,
                );
                return serve_status_only_with_refresh(provider, background_refresh).await;
            }
            Err(error) => {
                eprintln!("mcp-stdio: standby startup recovery failed: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    let open = async {
        let db = match open_mode {
            DatabaseOpenMode::StandbyReadOnly => {
                native_ce::db::open_existing_database_standby_read_only(&path).await?
            }
            DatabaseOpenMode::ReadWrite if !std::path::Path::new(&path).exists() => {
                native_ce::create_database(&path).await?
            }
            DatabaseOpenMode::ReadWrite => native_ce::open_existing_database(&path).await?,
        };
        Ok::<_, native_ce::Error>(db)
    };
    let db = match open.await {
        Ok(db) => db,
        Err(err) => {
            eprintln!("mcp-stdio: cannot open {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let account_result = match open_mode {
        DatabaseOpenMode::ReadWrite => {
            resolve_stdio_account_identity(&db, selected_account.as_deref()).await
        }
        DatabaseOpenMode::StandbyReadOnly => {
            resolve_standby_account_identity(&db, selected_account.as_deref()).await
        }
    };
    let account = match account_result {
        Ok(account) => account,
        Err(err) => {
            eprintln!("mcp-stdio: {err}");
            db.close().await;
            return ExitCode::FAILURE;
        }
    };

    let exports = ExportCoordinator::new();
    let mut registry = ToolRegistry::new();
    if let Some(provider) = standby_status_provider.as_ref() {
        registry.set_standby_status_provider(provider.clone());
    } else {
        registry.set_standby_read_only(open_mode == DatabaseOpenMode::StandbyReadOnly);
    }
    registry.set_exposure_profile(profile);
    if let Err(err) = register_stdio_tools(&mut registry, &exports) {
        eprintln!("mcp-stdio: {err}");
        return ExitCode::FAILURE;
    }
    if let Some(provider) = standby_status_provider {
        if let Err(err) = register_standby_status_tool(&mut registry, provider) {
            eprintln!("mcp-stdio: {err}");
            return ExitCode::FAILURE;
        }
    }
    if let Err(err) = registry.validate_profile_budgets() {
        eprintln!("mcp-stdio: {err}");
        return ExitCode::FAILURE;
    }
    let registry = Arc::new(registry);
    let caller = Caller::authenticated(account).with_channel(native_ce::provenance::Channel::Mcp);
    let outcome = match sqlite_surface(surface, open_mode) {
        McpSurfaceMode::Legacy => {
            StdioServer::new(registry, db.clone(), caller)
                .serve_stdio()
                .await
        }
        McpSurfaceMode::Executor => {
            #[cfg(feature = "mcp-executor-prototype")]
            {
                match ExecutorTelemetryContext::structured_log() {
                    Ok(telemetry) => {
                        match ExecutorPrototypeStdioServer::new_with_telemetry(
                            registry,
                            db.clone(),
                            caller,
                            None,
                            telemetry,
                        )
                        .await
                        {
                            Ok(server) => server.serve_stdio().await,
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(not(feature = "mcp-executor-prototype"))]
            unreachable!("executor availability was checked before opening the database")
        }
    };
    exports.drain().await;
    db.close().await;
    drop(activated_generation);
    if let Some(refresh) = background_refresh {
        refresh.stop().await;
    }
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("mcp-stdio: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn serve_status_only(provider: StandbyStatusProvider) -> ExitCode {
    match StatusOnlyStdioServer::with_provider(provider)
        .serve_stdio()
        .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mcp-stdio: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn serve_status_only_with_refresh(
    provider: StandbyStatusProvider,
    refresh: Option<BackgroundRefresh>,
) -> ExitCode {
    let outcome = StatusOnlyStdioServer::with_provider(provider)
        .serve_stdio()
        .await;
    if let Some(refresh) = refresh {
        refresh.stop().await;
    }
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mcp-stdio: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn start_background_refresh(
    runtime: &StandbyRuntimeConfig,
    observed: &native_ce::standby_snapshot::ObservedInstalledConsumerIdentity,
    refresh_config_path: &str,
) -> native_ce::Result<Option<BackgroundRefresh>> {
    let bytes = std::fs::read(refresh_config_path)?;
    let refresh_config = StandbyRefreshConfig::from_json(&bytes)?;
    let store = GenerationStore::open(
        &runtime.replica_root,
        &runtime.hosted_route_database_id,
        Some(runtime.origin_database_id.clone()),
    )?;
    let controller = Arc::new(StandbyRefreshController::new(
        runtime.clone(),
        refresh_config,
        store,
        observed.clone(),
    )?);
    let Some(guard) = controller.try_acquire_daemon()? else {
        return Ok(None);
    };
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        controller.run_daemon_after_startup(guard, receiver).await;
    });
    Ok(Some(BackgroundRefresh { shutdown, task }))
}

async fn run_manual_standby_refresh(args: &[String]) -> ExitCode {
    if args.len() != 2 {
        eprintln!(
            "mcp-stdio: --standby-refresh requires <standby-config.json> <refresh-config.json>"
        );
        return ExitCode::from(2);
    }
    let result = async {
        let runtime = StandbyRuntimeConfig::from_json(&std::fs::read(&args[0])?)?;
        let refresh_config = StandbyRefreshConfig::from_json(&std::fs::read(&args[1])?)?;
        let observed = observe_installed_consumer_identity()?;
        let store = GenerationStore::open(
            &runtime.replica_root,
            &runtime.hosted_route_database_id,
            Some(runtime.origin_database_id.clone()),
        )?;
        let controller = StandbyRefreshController::new(runtime, refresh_config, store, observed)?;
        if let Some(_guard) = controller.try_acquire_daemon()? {
            controller.refresh_once(RefreshCause::Manual).await
        } else {
            let coalesced = !controller.request_manual_refresh()?;
            Ok(StandbyRefreshOutcome::Accepted { coalesced })
        }
    }
    .await;
    match result {
        Ok(StandbyRefreshOutcome::Installed { generation, .. }) => {
            eprintln!(
                "mcp-stdio: standby refresh installed generation {}",
                generation.id
            );
            ExitCode::SUCCESS
        }
        Ok(StandbyRefreshOutcome::Accepted { coalesced }) => {
            let disposition = if coalesced { "coalesced" } else { "accepted" };
            eprintln!("mcp-stdio: standby manual refresh {disposition}");
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!("mcp-stdio: standby manual refresh failed; see refresh state");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "turso-local")]
async fn run_turso_local(config_path: &str, profile: ExposureProfile) -> ExitCode {
    let bytes = match std::fs::read(config_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("mcp-stdio: cannot read Turso-local runtime config: {error}");
            return ExitCode::FAILURE;
        }
    };
    let config = match TursoLocalRuntimeConfig::from_json(&bytes) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("mcp-stdio: {error}");
            return ExitCode::FAILURE;
        }
    };
    let db = match config.open().await {
        Ok(db) => db,
        Err(error) => {
            eprintln!("mcp-stdio: cannot open Turso-local logical database: {error}");
            return ExitCode::FAILURE;
        }
    };
    let exports = ExportCoordinator::new();
    let mut registry = ToolRegistry::new();
    registry.set_exposure_profile(profile);
    if let Err(error) = register_stdio_tools(&mut registry, &exports)
        .and_then(|()| register_turso_local_tools(&mut registry))
        .and_then(|()| registry.validate_profile_budgets())
    {
        eprintln!("mcp-stdio: {error}");
        return ExitCode::FAILURE;
    }
    let server = StdioServer::new(Arc::new(registry), db, Caller::local());
    let outcome = server.serve_stdio().await;
    exports.drain().await;
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mcp-stdio: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "postgres")]
async fn run_postgres(config_path: &str, profile: ExposureProfile) -> ExitCode {
    let bytes = match std::fs::read(config_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("mcp-stdio: cannot read Postgres runtime config: {error}");
            return ExitCode::FAILURE;
        }
    };
    let config = match PostgresRuntimeConfig::from_json(&bytes) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("mcp-stdio: {error}");
            return ExitCode::FAILURE;
        }
    };
    let db = if config.admin_url.is_some() {
        match config.provision_and_connect().await {
            Ok((db, _report)) => db,
            Err(error) => {
                eprintln!("mcp-stdio: cannot provision Postgres logical database: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match config.connect().await {
            Ok(db) => db,
            Err(error) => {
                eprintln!("mcp-stdio: cannot open Postgres logical database: {error}");
                return ExitCode::FAILURE;
            }
        }
    };

    let exports = ExportCoordinator::new();
    let mut registry = ToolRegistry::new();
    registry.set_exposure_profile(profile);
    if let Err(error) = register_stdio_tools(&mut registry, &exports)
        .and_then(|()| register_postgres_tools(&mut registry))
        .and_then(|()| registry.validate_profile_budgets())
    {
        eprintln!("mcp-stdio: {error}");
        db.close().await;
        return ExitCode::FAILURE;
    }
    let server = StdioServer::new(Arc::new(registry), db.clone(), Caller::local());
    let outcome = server.serve_stdio().await;
    exports.drain().await;
    db.close().await;
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mcp-stdio: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn startup_surface_is_executor_by_default_and_profile_is_legacy_only() {
        assert_eq!(configured_surface(None).unwrap(), McpSurfaceMode::Executor);
        assert_eq!(
            configured_surface(Some("legacy".into())).unwrap(),
            McpSurfaceMode::Legacy
        );
        assert!(configured_surface(Some("complete".into())).is_err());
        assert_eq!(
            configured_profile_for_surface(
                McpSurfaceMode::Executor,
                Some("invalid-stored-era-value".into()),
            )
            .unwrap(),
            ExposureProfile::Complete
        );
        assert!(configured_profile_for_surface(
            McpSurfaceMode::Legacy,
            Some("invalid-stored-era-value".into()),
        )
        .is_err());
    }

    #[test]
    fn parses_account_before_or_after_the_database_path() {
        let expected = Cli {
            path: "native.db".into(),
            account: Some("acct_cli".into()),
            open_mode: DatabaseOpenMode::ReadWrite,
        };
        assert_eq!(
            parse_cli(
                strings(&["--account", "acct_cli", "native.db"]),
                None,
                None,
                None,
                None
            )
            .unwrap(),
            Some(expected)
        );
        assert_eq!(
            parse_cli(
                strings(&["native.db", "--account", "acct_cli"]),
                None,
                None,
                None,
                None
            )
            .unwrap(),
            Some(Cli {
                path: "native.db".into(),
                account: Some("acct_cli".into()),
                open_mode: DatabaseOpenMode::ReadWrite,
            })
        );
    }

    #[test]
    fn cli_account_wins_over_the_environment() {
        let cli = parse_cli(
            strings(&["native.db", "--account", "acct_cli"]),
            Some("env.db".into()),
            None,
            Some("acct_env".into()),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cli.path, "native.db");
        assert_eq!(cli.account.as_deref(), Some("acct_cli"));
    }

    #[test]
    fn environment_supplies_omitted_path_and_account() {
        assert_eq!(
            parse_cli(
                Vec::new(),
                Some("env.db".into()),
                None,
                Some("acct_env".into()),
                None,
            )
            .unwrap(),
            Some(Cli {
                path: "env.db".into(),
                account: Some("acct_env".into()),
                open_mode: DatabaseOpenMode::ReadWrite,
            })
        );
    }

    #[test]
    fn standby_is_explicit_and_never_selects_the_executor_surface() {
        let cli = parse_cli(
            strings(&["--standby", "standby.json"]),
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cli.open_mode, DatabaseOpenMode::StandbyReadOnly);
        assert_eq!(
            sqlite_surface(McpSurfaceMode::Executor, cli.open_mode),
            McpSurfaceMode::Legacy
        );
        assert!(parse_cli(
            strings(&["--standby", "--standby", "native.db"]),
            None,
            None,
            None,
            None,
        )
        .is_err());
        let from_env = parse_cli(
            strings(&["--standby"]),
            None,
            Some("standby.json".into()),
            None,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(from_env.path, "standby.json");
    }

    #[test]
    fn invalid_cli_shapes_are_refused() {
        assert!(parse_cli(Vec::new(), None, None, None, None).is_err());
        assert!(parse_cli(
            strings(&["--account"]),
            Some("env.db".into()),
            None,
            None,
            None
        )
        .is_err());
        assert!(parse_cli(strings(&["one.db", "two.db"]), None, None, None, None).is_err());
        assert!(parse_cli(
            strings(&["--unknown"]),
            Some("env.db".into()),
            None,
            None,
            None
        )
        .is_err());
        assert!(parse_cli(
            strings(&["explicit.db"]),
            None,
            None,
            None,
            Some("controlled.db".into())
        )
        .is_err());
    }

    #[test]
    fn postgres_stdio_is_a_trusted_local_exclusive_target() {
        assert_eq!(validate_postgres_selection(&[], None, None, None), Ok(()));
        let account_error =
            validate_postgres_selection(&[], None, None, Some("acct_unbootstrapped")).unwrap_err();
        assert!(account_error.contains("trusted-local"), "{account_error}");
        let sqlite_error =
            validate_postgres_selection(&strings(&["native.db"]), None, None, None).unwrap_err();
        assert!(
            sqlite_error.contains("sole database controller"),
            "{sqlite_error}"
        );
    }

    #[test]
    fn turso_stdio_is_a_trusted_local_exclusive_target() {
        assert_eq!(
            validate_turso_selection(&[], None, None, None, None),
            Ok(())
        );
        let account_error =
            validate_turso_selection(&[], None, None, None, Some("acct_unbootstrapped"))
                .unwrap_err();
        assert!(account_error.contains("trusted-local"), "{account_error}");
        let postgres_error =
            validate_turso_selection(&[], None, None, Some("postgres.json"), None).unwrap_err();
        assert!(
            postgres_error.contains("sole database controller"),
            "{postgres_error}"
        );
    }

    #[test]
    fn tool_profile_defaults_complete_and_rejects_unknown_values() {
        assert_eq!(configured_profile(None).unwrap(), ExposureProfile::Complete);
        assert_eq!(
            configured_profile(Some("complete".into())).unwrap(),
            ExposureProfile::Complete
        );
        let error = configured_profile(Some("everything".into())).unwrap_err();
        assert!(error.contains("NATIVE_CE_MCP_TOOL_PROFILE"), "{error}");
        assert!(error.contains("everything"), "{error}");
    }

    #[cfg(feature = "experimental-agent-intents")]
    #[test]
    fn default_build_registers_agent_intent_for_complete_discovery() {
        const TOOL: &str = "experimental_freshness_agent_intent";

        let mut stable_registry = ToolRegistry::new();
        register_builtin_tools(&mut stable_registry).unwrap();
        register_surface_tools(&mut stable_registry).unwrap();
        register_snapshot_tool(&mut stable_registry, Arc::new(LocalSnapshotSource::new())).unwrap();
        let stable_focused_bytes = stable_registry.descriptor_array_bytes(ExposureProfile::Focused);
        let mut registry = ToolRegistry::new();
        register_stdio_tools(&mut registry, &ExportCoordinator::new()).unwrap();

        let spec = registry
            .get(TOOL)
            .expect("default build registers the seam");
        assert!(spec.kind.is_none(), "experiment is not a stable ToolKind");
        assert!(!registry
            .specs_for_profile(ExposureProfile::Focused)
            .any(|candidate| candidate.name == TOOL));
        assert!(registry
            .specs_for_profile(ExposureProfile::Complete)
            .any(|candidate| candidate.name == TOOL));
        assert_eq!(
            registry.descriptor_array_bytes(ExposureProfile::Focused),
            stable_focused_bytes,
            "the complete-only experimental schema must not change focused discovery"
        );
        let descriptor = spec.descriptor();
        let mut descriptor_without_root_type = descriptor.clone();
        descriptor_without_root_type["inputSchema"]
            .as_object_mut()
            .unwrap()
            .remove("type");
        assert_eq!(
            serde_json::to_vec(&descriptor).unwrap().len(),
            serde_json::to_vec(&descriptor_without_root_type)
                .unwrap()
                .len()
                + 16,
            "the experimental schema's explicit object root is exactly 16 compact bytes"
        );
        for spec in registry.specs_for_profile(ExposureProfile::Complete) {
            assert_eq!(
                spec.input_schema["type"], "object",
                "complete stdio discovery advertised {} without an object inputSchema root",
                spec.name
            );
        }
    }

    #[cfg(not(feature = "experimental-agent-intents"))]
    #[test]
    fn no_default_features_omits_agent_intent_registration() {
        let mut registry = ToolRegistry::new();
        register_stdio_tools(&mut registry, &ExportCoordinator::new()).unwrap();

        assert!(registry
            .get("experimental_freshness_agent_intent")
            .is_none());
    }
}
