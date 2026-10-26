//! Shared local-CLI serving paths for the `mcp-stdio` and `native` binaries.
//!
//! The ordinary SQLite stdio serve (open-or-create, account resolution,
//! registry, executor-or-legacy dispatch) lives here so both binaries call one
//! implementation. `mcp-stdio` keeps its exact command line and diagnostics;
//! `native mcp --local` reuses the same path with no caller-supplied account.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::db::DatabaseOpenMode;
use crate::export::{ExportCoordinator, LocalSnapshotSource};
use crate::identity::resolve_stdio_account_identity;
use crate::mcp::{
    register_allowlisted_experimental_tools, register_build_enabled_experimental_tools,
    register_builtin_tools, register_snapshot_tool, register_surface_tools, Caller,
    ExperimentalExecutors, ExposureProfile, McpSurfaceMode, StdioServer, ToolRegistry,
    EXPERIMENTAL_EXECUTORS_ENV,
};
#[cfg(feature = "mcp-executor-prototype")]
use crate::mcp::{ExecutorPrototypeStdioServer, ExecutorTelemetryContext};

#[cfg(unix)]
pub mod call;
pub mod connect;
pub mod enrich;
pub mod enrichment;
pub mod import;
pub mod init;
#[cfg(unix)]
pub mod login;
#[cfg(unix)]
pub mod node_client;
#[cfg(unix)]
pub mod service;
#[cfg(unix)]
pub mod setup;
#[cfg(unix)]
pub mod status;

/// Environment selector for the MCP surface (executor by default).
pub const ENV_MCP_SURFACE: &str = "NATIVE_CE_MCP_SURFACE";
/// Environment selector for the legacy tool profile.
pub const ENV_MCP_TOOL_PROFILE: &str = "NATIVE_CE_MCP_TOOL_PROFILE";
/// Environment toggle for committing through local SQLite (`true`/`1`).
pub const ENV_SQLITE_SQL_COMMIT: &str = "NATIVE_CE_SQLITE_SQL_COMMIT";

/// Default database for `native mcp --local` when no path is given:
/// `$XDG_DATA_HOME/native/local.db`, or `~/.local/share/native/local.db`;
/// `~/Library/Application Support/Native/local.db` on macOS.
pub fn default_local_db_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return PathBuf::from(home).join("Library/Application Support/Native/local.db");
            }
        }
        PathBuf::from("Library/Application Support/Native/local.db")
    }
    #[cfg(not(target_os = "macos"))]
    {
        let base = std::env::var("XDG_DATA_HOME")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .map(|home| PathBuf::from(home).join(".local/share"))
            });
        match base {
            Some(dir) => dir.join("native/local.db"),
            None => PathBuf::from("local.db"),
        }
    }
}

pub fn configured_surface(raw: Option<String>) -> std::result::Result<McpSurfaceMode, String> {
    raw.map(|value| {
        value
            .parse()
            .map_err(|reason| format!("{ENV_MCP_SURFACE} is invalid ({reason})"))
    })
    .transpose()
    .map(Option::unwrap_or_default)
}

pub fn configured_profile(raw: Option<String>) -> std::result::Result<ExposureProfile, String> {
    raw.map(|value| {
        value
            .parse()
            .map_err(|reason| format!("{ENV_MCP_TOOL_PROFILE} is invalid ({reason}): {value}"))
    })
    .transpose()
    .map(Option::unwrap_or_default)
}

pub fn configured_profile_for_surface(
    surface: McpSurfaceMode,
    raw: Option<String>,
) -> std::result::Result<ExposureProfile, String> {
    if surface == McpSurfaceMode::Legacy {
        configured_profile(raw)
    } else {
        Ok(ExposureProfile::Complete)
    }
}
pub fn register_stdio_tools(
    registry: &mut ToolRegistry,
    exports: &ExportCoordinator,
    experimental: &ExperimentalExecutors,
) -> crate::Result<()> {
    register_builtin_tools(registry)?;
    register_surface_tools(registry)?;
    register_build_enabled_experimental_tools(registry)?;
    register_allowlisted_experimental_tools(registry, experimental)?;
    register_snapshot_tool(
        registry,
        Arc::new(LocalSnapshotSource::with_coordinator(exports.clone())),
    )?;
    Ok(())
}

/// The caller for the default SQLite stdio path. Whoever operates the local
/// database file is its owner, so this carries the narrow local-owner marker
/// (owner counter footing only); it is not `trusted_local`.
pub fn sqlite_owner_caller(account: String) -> Caller {
    Caller::local_owner(account).with_channel(crate::provenance::Channel::Mcp)
}

pub fn sqlite_surface(configured: McpSurfaceMode, open_mode: DatabaseOpenMode) -> McpSurfaceMode {
    match open_mode {
        DatabaseOpenMode::ReadWrite => configured,
        // Standby keeps the configured surface. An Executor surface over a
        // verified standby engine selects `new_standby_read_only`, which
        // constructs no plan store or telemetry; an explicit Legacy surface
        // serves the native surface unchanged. Lean narrows only the
        // writable ordinary catalogue, so a standby keeps the executor
        // standby projection.
        DatabaseOpenMode::StandbyReadOnly => read_only_surface(configured),
        // A member copy is a read-only local surface; keep the configured
        // surface as standby does.
        DatabaseOpenMode::MemberReadOnly => read_only_surface(configured),
    }
}

/// Read-only local surfaces (standby, member copy) are unchanged by lean.
pub fn read_only_surface(configured: McpSurfaceMode) -> McpSurfaceMode {
    match configured {
        McpSurfaceMode::Lean => McpSurfaceMode::Executor,
        surface => surface,
    }
}

/// Resolve the surface, profile, and experimental executors from the
/// environment exactly as the local stdio serve does. Used by `native`;
/// `mcp-stdio` resolves the same values inline before it branches.
pub fn resolve_local_stdio_env(
) -> std::result::Result<(McpSurfaceMode, ExposureProfile, ExperimentalExecutors), String> {
    let surface = configured_surface(std::env::var(ENV_MCP_SURFACE).ok())?;
    #[cfg(not(feature = "mcp-executor-prototype"))]
    if surface.serves_executors() {
        return Err(format!(
            "executor MCP surface is not included in this build; controlled rollback requires {ENV_MCP_SURFACE}=legacy and a restart"
        ));
    }
    let profile =
        configured_profile_for_surface(surface, std::env::var(ENV_MCP_TOOL_PROFILE).ok())?;
    let experimental =
        ExperimentalExecutors::from_env_value(std::env::var(EXPERIMENTAL_EXECUTORS_ENV).ok())
            .map_err(|err| err.to_string())?;
    Ok((surface, profile, experimental))
}
/// What both the stdio serve and the in-process CLI open from one SQLite file.
struct SqliteParts {
    db: crate::db::Db,
    exports: ExportCoordinator,
    registry: Arc<ToolRegistry>,
    caller: Caller,
    sql_commit: bool,
}

/// Open (creating when missing) the database, resolve its local owner, and
/// build the tool registry exactly as `native mcp --local` does.
async fn open_sqlite_parts(
    path: &str,
    account: Option<String>,
    surface: McpSurfaceMode,
    profile: ExposureProfile,
    experimental: &ExperimentalExecutors,
) -> crate::Result<SqliteParts> {
    let db = if !Path::new(path).exists() {
        crate::create_database(path).await
    } else {
        crate::open_existing_database(path).await
    }
    .map_err(|err| crate::Error::engine(format!("cannot open {path}: {err}")))?;
    // Advisors S4: when NATIVE_ADVISORS_DIR is set, load installs and register
    // the active advisors on this handle. Unset means today's empty registry.
    crate::mcp::advisors::startup::apply_from_env(&db);

    let account = match resolve_stdio_account_identity(&db, account.as_deref()).await {
        Ok(account) => account,
        Err(err) => {
            db.close().await;
            return Err(err);
        }
    };

    let exports = ExportCoordinator::new();
    let mut registry = ToolRegistry::new();
    registry.set_standby_read_only(false);
    registry.set_exposure_profile(profile);
    register_stdio_tools(&mut registry, &exports, experimental)?;
    registry.validate_profile_budgets()?;
    let registry = Arc::new(registry);
    let sql_commit = match std::env::var(ENV_SQLITE_SQL_COMMIT).ok().as_deref() {
        None | Some("0" | "false") => false,
        Some("1" | "true") => true,
        Some(_) => {
            return Err(crate::Error::engine(format!(
                "{ENV_SQLITE_SQL_COMMIT} must be true/false or 1/0"
            )));
        }
    };
    if sql_commit && surface == McpSurfaceMode::Legacy {
        return Err(crate::Error::engine(
            "SQL commit requires the writable local executor surface",
        ));
    }
    Ok(SqliteParts {
        db,
        exports,
        registry,
        caller: sqlite_owner_caller(account),
        sql_commit,
    })
}

/// One local database served in this process, for `native call` and its
/// shortcuts: the same registry, caller and executor dispatch as
/// `native mcp --local`, answering JSON-RPC messages directly instead of over
/// stdio. It emits no per-request telemetry (the stdio serve logs it to stderr,
/// which a command line has no use for).
#[cfg(feature = "mcp-executor-prototype")]
pub struct LocalExecutor {
    server: ExecutorPrototypeStdioServer,
    db: crate::db::Db,
    exports: ExportCoordinator,
}

#[cfg(feature = "mcp-executor-prototype")]
impl LocalExecutor {
    /// Open `path` (created with the frozen schema when missing). Fails on the
    /// legacy surface, which has no executor dispatch to share.
    pub async fn open(
        path: &str,
        surface: McpSurfaceMode,
        experimental: ExperimentalExecutors,
    ) -> crate::Result<Self> {
        if !surface.serves_executors() {
            return Err(crate::Error::engine(format!(
                "{ENV_MCP_SURFACE}={surface} has no executor surface; native call needs the default (lean) or executor surface"
            )));
        }
        let parts = open_sqlite_parts(
            path,
            None,
            surface,
            ExposureProfile::Complete,
            &experimental,
        )
        .await?;
        let SqliteParts {
            db,
            exports,
            registry,
            caller,
            sql_commit,
        } = parts;
        let built = ExecutorPrototypeStdioServer::new_for_surface(
            registry,
            db.clone(),
            caller,
            None,
            None,
            experimental,
            surface,
        )
        .await
        .and_then(|server| {
            if sql_commit {
                server.with_local_sql_commit()
            } else {
                Ok(server)
            }
        });
        match built {
            Ok(server) => Ok(Self {
                server,
                db,
                exports,
            }),
            Err(err) => {
                db.close().await;
                Err(err)
            }
        }
    }

    /// Answer one JSON-RPC message (`None` for a notification).
    pub async fn handle(&self, message: serde_json::Value) -> Option<serde_json::Value> {
        self.server.handle_message(message).await
    }

    pub async fn close(self) {
        drop(self.server);
        self.exports.drain().await;
        self.db.close().await;
    }
}

/// Serve one SQLite database over stdio MCP, opening it read-write and
/// creating it (with the frozen schema) when it does not exist yet.
///
/// This is the ordinary `mcp-stdio <db>` path, shared by `native mcp --local`.
/// `account` is the optional caller-selected token (`None` resolves the local
/// owner like an unadorned `mcp-stdio <db>` invocation). Errors carry the same
/// message bodies `mcp-stdio` prints after its `mcp-stdio: ` prefix; binaries
/// add their own prefix.
pub async fn serve_sqlite_stdio(
    path: &str,
    account: Option<String>,
    surface: McpSurfaceMode,
    profile: ExposureProfile,
    experimental: ExperimentalExecutors,
) -> crate::Result<()> {
    let SqliteParts {
        db,
        exports,
        registry,
        caller,
        sql_commit,
    } = open_sqlite_parts(path, account, surface, profile, &experimental).await?;
    let outcome = match sqlite_surface(surface, DatabaseOpenMode::ReadWrite) {
        McpSurfaceMode::Legacy => {
            StdioServer::new(registry, db.clone(), caller)
                .serve_stdio()
                .await
        }
        surface @ (McpSurfaceMode::Executor | McpSurfaceMode::Lean) => {
            #[cfg(feature = "mcp-executor-prototype")]
            {
                match ExecutorTelemetryContext::structured_log() {
                    Ok(telemetry) => {
                        match ExecutorPrototypeStdioServer::new_for_surface(
                            registry,
                            db.clone(),
                            caller,
                            None,
                            Some(telemetry),
                            experimental,
                            surface,
                        )
                        .await
                        {
                            Ok(server) => match if sql_commit {
                                server.with_local_sql_commit()
                            } else {
                                Ok(server)
                            } {
                                Ok(server) => server.serve_stdio().await,
                                Err(error) => Err(error),
                            },
                            Err(error) => Err(error),
                        }
                    }
                    Err(error) => Err(error),
                }
            }
            #[cfg(not(feature = "mcp-executor-prototype"))]
            {
                let _ = surface;
                unreachable!("executor availability was checked before opening the database")
            }
        }
    };
    exports.drain().await;
    db.close().await;
    outcome
}
