//! Durable local standby generations.
//!
//! This module owns verification, filesystem publication, deterministic
//! startup selection/retention, the refresh controller (a whole-snapshot
//! checkpoint advanced in place by authenticated whole-act deltas) and the
//! standby status projection.

mod act_cut;
mod act_delta;
mod act_materialise;
mod authority_probe;
pub mod kernel_v2;
#[cfg(any(test, feature = "v2-kernel-probe"))]
mod kernel_v2_delta;
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) mod kernel_v2_tests;
mod release_head;
#[cfg(test)]
pub(crate) use authority_probe::read_authority_act_head;
/// Slice-A freeze-receipt seam: the read-only file-path act-head probe and
/// the closed evidence contract it observes. Re-exported for release tooling;
/// the `Db`-handle probe stays crate-internal.
pub use authority_probe::{
    is_revision_unsupported, read_authority_act_head_from_path, ActCutoverV1, AuthorityActHeadV1,
    BindingSystemSeedV1, ContentCausalCutoverV1, LogMaxSeqV1, NonSequencedMaxActV1,
    StoragePortabilityPolicyHeadV1, AUTHORITY_ACT_HEAD_CONTRACT, AUTHORITY_ACT_HEAD_VERSION,
    REQUIRED_NATIVE_INTERCHANGE_REVISION,
};
pub use release_head::{read_release_act_head_from_path, validate_release_act_head};
mod companion_closure;
#[cfg(test)]
pub(crate) use companion_closure::read_companion_section_on;
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
    AcceptedGenerationHint, ActivatedGeneration, ConsumerRebind, GenerationHead, GenerationStore,
    InstalledGeneration, StandbyAuditOutcome, StandbyStartupOutcome, StandbyStartupReason,
    StatusOnlyStartup,
};
pub(crate) use refresh::CONFIG_CONTRACT as REFRESH_CONFIG_CONTRACT;
pub use refresh::{
    current_attempt_detail, sanitize_retained_detail, start_background_refresh,
    start_background_refresh_with_store, BackgroundRefresh, DeltaFallbackClass,
    RefreshAttemptFailure, RefreshAttemptPhase, RefreshCause, RefreshFailureClass,
    RefreshFailureReceipt, StandbyDeltaOutcome, StandbyRefreshConfig, StandbyRefreshController,
    StandbyRefreshDaemonGuard, StandbyRefreshOutcome, StandbyRefreshState, StandbySnapshotDownload,
    StandbyTransferActivity, StandbyTransferProgress, StandbyTransferStage,
};
pub(crate) use refresh::{
    start_background_refresh_after_startup, validate_exact_origin, RefreshHints,
};
pub use runtime::{observe_installed_consumer_identity, StandbyRuntimeConfig};
pub use status::{
    StandbyFreshness, StandbyFreshnessState, StandbyGenerationStatus,
    StandbyRefreshDiagnosticsState, StandbyRefreshStatus, StandbyResponseContext, StandbyStatus,
    StandbyStatusMode, StandbyStatusOnly, StandbyStatusProvider, STANDBY_REFRESH_INTERVAL_SECONDS,
    STANDBY_RPO_SECONDS, STANDBY_STATUS_CONTRACT,
};
