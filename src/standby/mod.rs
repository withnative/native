//! Durable local standby generations.
//!
//! This module owns offline verification, filesystem publication, and
//! deterministic startup selection/retention. It performs no network refresh,
//! packaging or full MCP freshness disclosure.

mod act_cut;
mod act_delta;
mod act_materialise;
mod authority_probe;
#[cfg(test)]
pub(crate) use authority_probe::read_authority_act_head;
mod companion_closure;
pub mod delta_transport;
// R2's content-only materialiser is a proof-only module: it accepts a merely
// structurally valid delta (no trust gate), has no callers outside its own
// tests, and deliberately commits while leaving `act_state` at F1. It is
// compiled for tests only so no non-test build can reach that bypass; the
// finalising `act_materialise` path is the only non-test apply.
#[cfg(test)]
mod content_materialise;
pub(crate) mod generation_store;
mod receiver;
mod refresh;
mod runtime;
mod status;

pub use generation_store::{
    ActivatedGeneration, GenerationStore, InstalledGeneration, StandbyStartupOutcome,
    StandbyStartupReason, StatusOnlyStartup,
};
pub use refresh::{
    DeltaFallbackClass, RefreshCause, RefreshFailureClass, StandbyRefreshConfig,
    StandbyRefreshController, StandbyRefreshDaemonGuard, StandbyRefreshOutcome,
    StandbyRefreshState,
};
pub use runtime::{observe_installed_consumer_identity, StandbyRuntimeConfig};
pub use status::{
    StandbyFreshness, StandbyFreshnessState, StandbyGenerationStatus,
    StandbyRefreshDiagnosticsState, StandbyRefreshStatus, StandbyResponseContext, StandbyStatus,
    StandbyStatusMode, StandbyStatusOnly, StandbyStatusProvider, STANDBY_REFRESH_INTERVAL_SECONDS,
    STANDBY_RPO_SECONDS, STANDBY_STATUS_CONTRACT,
};
