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
/// Slice-A freeze-receipt seam: the read-only file-path act-head probe and
/// the closed evidence contract it observes. Re-exported for release tooling;
/// the `Db`-handle probe stays crate-internal.
pub use authority_probe::{
    read_authority_act_head_from_path, ActCutoverV1, AuthorityActHeadV1, BindingSystemSeedV1,
    ContentCausalCutoverV1, LogMaxSeqV1, NonSequencedMaxActV1, StoragePortabilityPolicyHeadV1,
    AUTHORITY_ACT_HEAD_CONTRACT, AUTHORITY_ACT_HEAD_VERSION, REQUIRED_NATIVE_INTERCHANGE_REVISION,
};
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

/// Select the closed aggregate writer diagnostics for a dedicated standby
/// process. Ordinary writable processes retain their histogram diagnostics.
pub fn enable_bounded_verification_diagnostics() {
    crate::write_contention::enable_bounded_standby_diagnostics();
}

pub use generation_store::{
    AcceptedGenerationHint, ActivatedGeneration, GenerationStore, InstalledGeneration,
    StandbyStartupOutcome, StandbyStartupReason, StatusOnlyStartup,
};
pub(crate) use refresh::validate_exact_origin;
pub use refresh::{
    DeltaFallbackClass, RefreshCause, RefreshFailureClass, StandbyRefreshConfig,
    StandbyRefreshController, StandbyRefreshDaemonGuard, StandbyRefreshOutcome,
    StandbyRefreshState, StandbySnapshotDownload,
};
pub use runtime::{observe_installed_consumer_identity, StandbyRuntimeConfig};
pub use status::{
    StandbyFreshness, StandbyFreshnessState, StandbyGenerationStatus,
    StandbyRefreshDiagnosticsState, StandbyRefreshStatus, StandbyResponseContext, StandbyStatus,
    StandbyStatusMode, StandbyStatusOnly, StandbyStatusProvider, STANDBY_REFRESH_INTERVAL_SECONDS,
    STANDBY_RPO_SECONDS, STANDBY_STATUS_CONTRACT,
};
