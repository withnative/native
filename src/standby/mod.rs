//! Durable local standby generations.
//!
//! This module owns offline verification, filesystem publication, and
//! deterministic startup selection/retention. It performs no network refresh,
//! packaging or full MCP freshness disclosure.

mod generation_store;
mod refresh;
mod runtime;
mod status;

pub use generation_store::{
    ActivatedGeneration, GenerationStore, InstalledGeneration, StandbyStartupOutcome,
    StandbyStartupReason, StatusOnlyStartup,
};
pub use refresh::{
    RefreshCause, RefreshFailureClass, StandbyRefreshConfig, StandbyRefreshController,
    StandbyRefreshDaemonGuard, StandbyRefreshOutcome, StandbyRefreshState,
};
pub use runtime::{observe_installed_consumer_identity, StandbyRuntimeConfig};
pub use status::{
    StandbyFreshness, StandbyFreshnessState, StandbyGenerationStatus,
    StandbyRefreshDiagnosticsState, StandbyRefreshStatus, StandbyResponseContext, StandbyStatus,
    StandbyStatusMode, StandbyStatusOnly, StandbyStatusProvider, STANDBY_REFRESH_INTERVAL_SECONDS,
    STANDBY_RPO_SECONDS, STANDBY_STATUS_CONTRACT,
};
