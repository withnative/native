//! Stable, non-secret status projection for the local standby MCP surfaces.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::standby_snapshot::{
    CanonicalFrontierV1, ObservedInstalledConsumerIdentity, StandbyConsumerIdentity,
    StandbyGenerationMaterialization, StandbySnapshotEngineIdentity,
};

use super::generation_store::{GenerationProvenanceStatus, GenerationStoreStatus};
use super::refresh::{observe_refresh_state, RefreshStateObservation};
use super::{
    ActivatedGeneration, GenerationStore, StandbyRefreshState, StandbyRuntimeConfig,
    StandbyStartupReason, StatusOnlyStartup,
};

pub const STANDBY_STATUS_CONTRACT: &str = "native.standby-status.v1";
pub const STANDBY_RPO_SECONDS: u64 = 300;
pub const STANDBY_REFRESH_INTERVAL_SECONDS: u64 = 60;
pub const MAX_STATUS_RETAINED_GENERATIONS: usize = 8;
/// Deltas deferred this many consecutive ticks (about ten minutes at the
/// default cadence) for want of an upgraded reader, or because a local read
/// kept the copy open, are reported as degraded.
const DEFERRED_DELTA_AFTER_TICKS: u32 = 10;
const READER_NOT_UPGRADED_ACTION: &str =
    "restart the local Native connection so the new build serves this copy";
const DATABASE_BUSY_ACTION: &str =
    "a local read has held the copy open for a long time; restart the local Native connection";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyStatusMode {
    Standby,
    StatusOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyFreshnessState {
    Fresh,
    BeyondRpo,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyFreshness {
    /// Operational check-age classification, not proof of missing content.
    pub state: StandbyFreshnessState,
    pub age_seconds: Option<u64>,
    pub age_basis: &'static str,
    pub target_rpo_seconds: u64,
    pub target_refresh_interval_seconds: u64,
    pub beyond_rpo: Option<bool>,
}

/// Reporting only. Neither elapsed time nor these observations admit reads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbySyncObservation {
    /// Conservative sample before the check/export that established this head.
    pub last_matching_hosted_check_at: Option<String>,
    /// Local completion, independent of subsequent checks that change nothing.
    pub last_local_materialization_at: Option<String>,
    /// The export/head protocol does not supply a source change timestamp.
    pub last_data_change_at: Option<String>,
    pub age_basis: &'static str,
}

/// How recently the serving copy's rows were last re-judged against its
/// receipts (the required audit). Present only for a copy advanced in place
/// while audits are required; machine fields, never user-facing text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyAudit {
    /// `current` (within twice the interval), `overdue`, `unaudited` (no
    /// readable record) or `failed` (the last audit found damage).
    pub state: &'static str,
    /// Seconds since the last audit's snapshot was acquired.
    pub age_seconds: Option<u64>,
    pub interval_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyGenerationStatus {
    pub generation_id: String,
    /// When the checkpoint snapshot was captured.
    pub captured_at: String,
    pub snapshot_completed_at: String,
    pub promoted_at: Option<String>,
    /// The checkpoint snapshot's frontier; `head_act` moves past it.
    pub frontier: CanonicalFrontierV1,
    /// The act this copy holds, advanced in place by deltas.
    pub head_act: Option<i64>,
    /// `snapshot` until the first delta is applied in place, then `delta`.
    pub materialization: StandbyGenerationMaterialization,
    /// When hosted Native was last observed at `head_act`, if ever.
    pub synced_at: Option<String>,
    /// Whether the history before the checkpoint is known to be complete:
    /// `exhaustive`, `unknown`, or `unavailable` when it cannot be read.
    pub source_history: &'static str,
    pub engine: StandbySnapshotEngineIdentity,
    pub consumer: StandbyConsumerIdentity,
    /// Local acceptance by a replacement binary; original consumer stays above.
    pub consumer_rebind: Option<super::ConsumerRebind>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyRefreshDiagnosticsState {
    Available,
    NeverRecorded,
    Unavailable,
}

/// An observation, not a promise that an old process can enforce its deadline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InFlightRefresh {
    pub attempt_id: Option<String>,
    pub cause: Option<super::RefreshCause>,
    pub phase: super::refresh::StandbyTransferStage,
    pub started_at: String,
    pub elapsed_seconds: Option<u64>,
    pub deadline_seconds: u64,
    pub overdue: bool,
}

fn in_flight(
    state: &super::StandbyRefreshState,
    now: Option<DateTime<Utc>>,
) -> Option<InFlightRefresh> {
    if !state.refresh_active {
        return None;
    }
    let started_at = state.last_attempt_at.as_ref()?;
    let elapsed_seconds = now
        .zip(DateTime::parse_from_rfc3339(started_at).ok())
        .and_then(|(now, start)| {
            u64::try_from(now.signed_duration_since(start).num_seconds()).ok()
        });
    let phase = state
        .transfer_progress
        .as_ref()
        .map(|p| p.stage)
        .unwrap_or(super::refresh::StandbyTransferStage::Following);
    let deadline_seconds = if phase == super::refresh::StandbyTransferStage::Following {
        super::refresh::FOLLOW_ATTEMPT_TIMEOUT.as_secs()
    } else {
        super::refresh::ATTEMPT_TIMEOUT.as_secs()
    };
    Some(InFlightRefresh {
        attempt_id: state.last_attempt_id.clone(),
        cause: state.last_attempt_cause,
        phase,
        started_at: normalized_timestamp(started_at),
        elapsed_seconds,
        deadline_seconds,
        overdue: elapsed_seconds.is_some_and(|elapsed| elapsed >= deadline_seconds),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyRefreshStatus {
    pub configured: bool,
    pub controller_available: bool,
    pub diagnostics: StandbyRefreshDiagnosticsState,
    pub refresh_active: Option<bool>,
    pub in_flight: Option<InFlightRefresh>,
    pub transfer_progress: Option<super::StandbyTransferProgress>,
    pub manual_refresh_pending: Option<bool>,
    pub last_attempt_at: Option<String>,
    pub last_attempt_cause: Option<super::RefreshCause>,
    pub last_success_at: Option<String>,
    pub installed_generation_id: Option<String>,
    pub snapshot_captured_at: Option<String>,
    pub snapshot_completed_at: Option<String>,
    pub promoted_at: Option<String>,
    pub frontier: Option<CanonicalFrontierV1>,
    pub consecutive_failure_count: Option<u32>,
    pub last_failure_class: Option<super::RefreshFailureClass>,
    pub last_failure: Option<String>,
    pub last_delta_fallback_class: Option<super::refresh::DeltaFallbackClass>,
    pub last_delta_fallback: Option<String>,
    /// Why the last attempt changed nothing without failing, as a closed token
    /// (for example `full_refresh_interval`: a whole snapshot was needed but
    /// the previous one started too recently).
    pub last_deferral: Option<&'static str>,
    /// Start of the most recent whole-snapshot attempt of an existing copy.
    pub last_full_refresh_at: Option<String>,
    /// When a whole snapshot deferred by `full_refresh_interval` next becomes
    /// eligible, if that is why the last attempt deferred.
    pub next_full_refresh_eligible_at: Option<String>,
    /// Retained whole-snapshot failure, projected even after a later delta
    /// or throttle attempt clears the latest failure. Time, cause and class
    /// come from typed state; the message and detail are closed projections,
    /// so legacy raw detail in old state files can never surface here.
    pub last_full_failure_at: Option<String>,
    pub last_full_failure_cause: Option<super::RefreshCause>,
    pub last_full_failure_class: Option<super::RefreshFailureClass>,
    pub last_full_failure: Option<String>,
    pub last_full_failure_detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyStatusOnly {
    pub reason: String,
    pub candidate_count: usize,
    pub unusable_candidate_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyStatus {
    pub contract: &'static str,
    pub version: u32,
    pub observed_at: String,
    pub mode: StandbyStatusMode,
    pub read_only: bool,
    pub writes_supported: bool,
    pub mutation_error: &'static str,
    pub canonical_authority: &'static str,
    pub projection: &'static str,
    pub interaction_capture: bool,
    pub run_persistence: bool,
    pub hosted_route_database_id: String,
    pub origin_database_id: String,
    pub serving_generation: Option<StandbyGenerationStatus>,
    pub accepted_generation: Option<StandbyGenerationStatus>,
    pub accepted_generation_provenance: &'static str,
    pub freshness: StandbyFreshness,
    pub sync_observation: StandbySyncObservation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serving_audit: Option<StandbyAudit>,
    pub refresh: StandbyRefreshStatus,
    pub installed_consumer: Option<ObservedInstalledConsumerIdentity>,
    pub consumer_compatible: Option<bool>,
    pub retained_generation_ids: Vec<String>,
    pub retained_generation_count: usize,
    /// Candidates with no matching completed device-check observation.
    pub unverified_candidate_count: usize,
    pub unusable_candidate_count: usize,
    pub retained_generation_ids_truncated: bool,
    pub startup_fallback: Option<StandbyStartupReason>,
    pub startup_fallback_diagnostics_available: bool,
    pub status_only: Option<StandbyStatusOnly>,
    pub accepted_plus_pending_supported: bool,
    pub pending_writes_supported: bool,
    pub degraded: bool,
    pub degraded_reasons: Vec<&'static str>,
    pub summary: &'static str,
    pub next_safe_action: Option<&'static str>,
    /// Process-lifetime full verification passes and their total wall time,
    /// from the same place the `startup-generation-verify` line logs.
    pub verification_passes: u64,
    pub verification_total_seconds: u64,
}

impl StandbyStatus {
    /// Bootstrap has a shared 8 KiB tool-exposure budget, including executor
    /// discovery. Keep operational footing here; full identity, frontier and
    /// consumer-rebind receipts remain available through `standby_status`.
    /// Select generation fields explicitly so growth of identity diagnostics
    /// cannot silently expand this projection. Serving and accepted generations
    /// may each carry the same large rebind receipt after a binary replacement.
    pub(crate) fn bootstrap_summary(&self) -> serde_json::Value {
        fn generation(value: &Option<StandbyGenerationStatus>) -> serde_json::Value {
            value.as_ref().map_or(serde_json::Value::Null, |value| {
                serde_json::json!({
                    "generation_id": value.generation_id,
                    "captured_at": value.captured_at,
                    "snapshot_completed_at": value.snapshot_completed_at,
                    "promoted_at": value.promoted_at,
                    "head_act": value.head_act,
                    "materialization": value.materialization,
                    "synced_at": value.synced_at,
                    "source_history": value.source_history,
                    "consumer_rebound_at": value.consumer_rebind.as_ref().map(|receipt| &receipt.accepted_at),
                })
            })
        }
        serde_json::json!({
            "contract": self.contract,
            "version": self.version,
            "status_scope": "bootstrap_summary",
            "full_status_tool": "standby_status",
            "observed_at": self.observed_at,
            "mode": self.mode,
            "read_only": self.read_only,
            "writes_supported": self.writes_supported,
            "mutation_error": self.mutation_error,
            "canonical_authority": self.canonical_authority,
            "projection": self.projection,
            "interaction_capture": self.interaction_capture,
            "run_persistence": self.run_persistence,
            "hosted_route_database_id": self.hosted_route_database_id,
            "origin_database_id": self.origin_database_id,
            "serving_generation": generation(&self.serving_generation),
            "accepted_generation": generation(&self.accepted_generation),
            "accepted_generation_provenance": self.accepted_generation_provenance,
            "freshness": self.freshness,
            "sync_observation": self.sync_observation,
            "serving_audit": self.serving_audit,
            "refresh": self.refresh,
            "consumer_compatible": self.consumer_compatible,
            "retained_generation_count": self.retained_generation_count,
            "unverified_candidate_count": self.unverified_candidate_count,
            "unusable_candidate_count": self.unusable_candidate_count,
            "startup_fallback": self.startup_fallback,
            "startup_fallback_diagnostics_available": self.startup_fallback_diagnostics_available,
            "status_only": self.status_only,
            "accepted_plus_pending_supported": self.accepted_plus_pending_supported,
            "pending_writes_supported": self.pending_writes_supported,
            "degraded": self.degraded,
            "degraded_reasons": self.degraded_reasons,
            "summary": self.summary,
            "next_safe_action": self.next_safe_action,
        })
    }
}

/// Cheap immutable warning context suitable for attachment to every MCP
/// response. Dynamic accepted-generation and refresh details deliberately stay
/// on the full async status surface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyResponseContext {
    pub status_scope: &'static str,
    pub in_flight_refresh: Option<InFlightRefresh>,
    pub last_refresh_success_at: Option<String>,
    /// Legacy last_refresh_success_at includes unchanged successful checks.
    pub sync_observation: StandbySyncObservation,
    pub full_status_tool: &'static str,
    pub mode: StandbyStatusMode,
    pub canonical_authority: &'static str,
    pub read_only: bool,
    pub writes_supported: bool,
    pub serving_generation_id: Option<String>,
    /// The act the serving copy holds; deltas advance it in place.
    pub serving_head_act: Option<i64>,
    pub serving_materialization: Option<StandbyGenerationMaterialization>,
    /// `exhaustive`, `unknown` or `unavailable` (see the full status).
    pub serving_source_history: Option<&'static str>,
    /// Present when this consumer locally re-admitted the original checkpoint.
    pub serving_consumer_rebound_at: Option<String>,
    /// The required audit's age, next to the freshness (serving) age.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serving_audit: Option<StandbyAudit>,
    pub freshness: StandbyFreshness,
    pub freshness_degraded: bool,
    pub degraded_reasons: Vec<&'static str>,
    pub next_safe_action: Option<&'static str>,
}

#[derive(Clone, Debug)]
struct ServingGeneration {
    generation_id: String,
    act_lineage: String,
    snapshot_path: std::path::PathBuf,
    captured_at: String,
    snapshot_completed_at: String,
    frontier: CanonicalFrontierV1,
    head_act: Option<i64>,
    materialization: StandbyGenerationMaterialization,
    synced_at: Option<String>,
    reader_deferrals: u32,
    busy_deferrals: u32,
    engine: StandbySnapshotEngineIdentity,
    consumer: StandbyConsumerIdentity,
    consumer_rebound_at: Option<String>,
    /// Set when an audit or check found the copy unfit; read from its head.
    full_refresh_required: bool,
}

impl ServingGeneration {
    fn reader_not_upgraded(&self) -> bool {
        self.reader_deferrals > DEFERRED_DELTA_AFTER_TICKS
    }

    fn database_busy(&self) -> bool {
        self.busy_deferrals > DEFERRED_DELTA_AFTER_TICKS
    }
}

/// Read-only source for the shared bootstrap and system/status projection.
///
/// Each provider freezes one serving generation. The connected session captures
/// this provider with the same database and lease. Accepted-generation and
/// refresh diagnostics are re-read for full status without changing that capture.
#[derive(Clone, Debug)]
pub struct StandbyStatusProvider {
    runtime: StandbyRuntimeConfig,
    store: GenerationStore,
    observed: Option<ObservedInstalledConsumerIdentity>,
    serving: Option<ServingGeneration>,
    status_only: Option<StandbyStatusOnly>,
    refresh_configured: bool,
    refresh_available: bool,
    connected_handoff: bool,
}

impl StandbyStatusProvider {
    pub fn for_serving(
        runtime: StandbyRuntimeConfig,
        store: GenerationStore,
        observed: ObservedInstalledConsumerIdentity,
        active: &ActivatedGeneration,
        refresh_configured: bool,
        refresh_available: bool,
    ) -> Self {
        let consumer_rebound_at = store
            .consumer_rebind(&active.generation.id, &observed)
            .ok()
            .flatten()
            .map(|acceptance| acceptance.accepted_at);
        Self {
            runtime,
            store,
            observed: Some(observed),
            serving: Some(ServingGeneration {
                generation_id: active.generation.id.clone(),
                act_lineage: match &active.generation.manifest.kernel_v2 {
                    Some(kernel) => format!(
                        "v2:{}:{}",
                        active.generation.manifest.origin_database_id, kernel.genesis_event_id
                    ),
                    None => format!("v1:{}", active.generation.manifest.origin_database_id),
                },
                snapshot_path: active.generation.snapshot_path.clone(),
                captured_at: active.generation.manifest.captured_at.clone(),
                snapshot_completed_at: active.generation.manifest.snapshot_completed_at.clone(),
                frontier: active.generation.manifest.frontier.clone(),
                head_act: active.generation.manifest.head_act,
                materialization: active.generation.manifest.materialization,
                synced_at: None,
                reader_deferrals: 0,
                busy_deferrals: 0,
                full_refresh_required: false,
                engine: active.generation.manifest.engine.clone(),
                consumer: active.generation.manifest.consumer.clone(),
                consumer_rebound_at,
            }),
            status_only: None,
            refresh_configured,
            refresh_available,
            connected_handoff: false,
        }
    }

    pub fn for_status_only(
        runtime: StandbyRuntimeConfig,
        store: GenerationStore,
        observed: Option<ObservedInstalledConsumerIdentity>,
        status: StatusOnlyStartup,
        refresh_configured: bool,
        refresh_available: bool,
    ) -> Self {
        Self::for_status_only_reason(
            runtime,
            store,
            observed,
            StandbyStatusOnly {
                reason: status.reason.into(),
                candidate_count: status.candidate_count,
                unusable_candidate_count: status.unusable_candidate_count,
            },
            refresh_configured,
            refresh_available,
        )
    }

    pub fn for_status_only_reason(
        runtime: StandbyRuntimeConfig,
        store: GenerationStore,
        observed: Option<ObservedInstalledConsumerIdentity>,
        status_only: StandbyStatusOnly,
        refresh_configured: bool,
        refresh_available: bool,
    ) -> Self {
        Self {
            runtime,
            store,
            observed,
            serving: None,
            status_only: Some(status_only),
            refresh_configured,
            refresh_available,
            connected_handoff: false,
        }
    }

    /// Enable truthful pending-handoff diagnostics on a connected session.
    /// This does not certify readiness or change the frozen serving generation.
    pub fn with_connected_handoff(mut self) -> Self {
        self.connected_handoff = true;
        self
    }

    pub async fn status(&self) -> StandbyStatus {
        self.collect_status(None).await
    }

    pub(crate) fn act_lineage(&self) -> Option<&str> {
        self.serving
            .as_ref()
            .map(|generation| generation.act_lineage.as_str())
    }

    pub fn response_context(&self) -> StandbyResponseContext {
        self.response_context_observed(None)
    }

    #[cfg(test)]
    pub(crate) fn response_context_at(&self, now: DateTime<Utc>) -> StandbyResponseContext {
        self.response_context_observed(Some(now))
    }

    fn response_context_observed(&self, now: Option<DateTime<Utc>>) -> StandbyResponseContext {
        let live_serving = self.live_serving();
        let now = now.unwrap_or_else(Utc::now);
        let freshness = freshness(live_serving.as_ref(), now);
        let mut degraded_reasons = Vec::new();
        if self.serving.is_none() {
            degraded_reasons.push("no_usable_serving_generation");
        } else {
            match freshness.state {
                StandbyFreshnessState::Fresh => {}
                StandbyFreshnessState::BeyondRpo => degraded_reasons.push("snapshot_beyond_rpo"),
                StandbyFreshnessState::Unavailable => {
                    degraded_reasons.push("snapshot_age_unavailable")
                }
            }
            if live_serving
                .as_ref()
                .is_some_and(ServingGeneration::reader_not_upgraded)
            {
                degraded_reasons.push("reader_not_upgraded");
            }
            if live_serving
                .as_ref()
                .is_some_and(ServingGeneration::database_busy)
            {
                degraded_reasons.push("database_busy");
            }
        }
        // A copy advanced in place that the required audit has not recently
        // vouched for is still served (offline reads, and explicit local
        // routes, are caller-owned), but the disclosure says so, and the
        // default-routed online path (`online_local_reads`) forwards.
        let serving_audit = live_serving
            .as_ref()
            .and_then(|serving| self.audit_of(serving, now));
        if let Some(audit) = &serving_audit {
            match audit.state {
                "overdue" => degraded_reasons.push("audit_overdue"),
                "unaudited" => degraded_reasons.push("audit_unaudited"),
                "failed" => degraded_reasons.push("audit_failed"),
                _ => {}
            }
        }
        // Restart continuity: while the post-restart background recheck is
        // running, the serving copy stays readable (continuity over
        // freshness). The reason names the recheck neutrally, and the
        // actual age stays disclosed beside it.
        if live_serving.is_some() && self.store.startup_recheck_pending() {
            degraded_reasons.push("restart_recheck_pending");
        }
        // A held-back last failure reads as routine scheduling here too: the
        // per-request context has no refresh section, so read the state file
        // directly. A missing or unreadable file keeps the existing advice.
        let refresh_state = observe_refresh_state(&self.runtime.replica_root);
        let refresh_state = match &refresh_state {
            RefreshStateObservation::Available(state) => Some(state.as_ref()),
            _ => None,
        };
        let in_flight_refresh = refresh_state.and_then(|state| in_flight(state, Some(now)));
        let last_refresh_success_at = refresh_state.and_then(|state| state.last_success_at.clone());
        let refresh_idle_throttled = refresh_state.is_some_and(|state| {
            last_failure_is_idle_throttle(state.last_failure_class, state.consecutive_failure_count)
        });
        if in_flight_refresh
            .as_ref()
            .is_some_and(|attempt| attempt.overdue)
        {
            degraded_reasons.push("refresh_attempt_overdue");
        }
        let next_safe_action = if in_flight_refresh
            .as_ref()
            .is_some_and(|attempt| attempt.overdue)
        {
            Some("a refresh exceeded its deadline; run `native status --diagnose`, then `native restart` if it remains stuck")
        } else if self.serving.is_none() {
            Some(if self.connected_handoff {
                "run a verified external refresh; the connected session will attempt full handoff"
            } else {
                "refresh the standby, then restart it after a verified generation is accepted"
            })
        } else if degraded_reasons.contains(&"reader_not_upgraded") {
            Some(READER_NOT_UPGRADED_ACTION)
        } else if degraded_reasons.contains(&"database_busy") {
            Some(DATABASE_BUSY_ACTION)
        } else if matches!(freshness.state, StandbyFreshnessState::BeyondRpo) {
            Some(if refresh_idle_throttled {
                "the standby refresh is catching up and retries on its own"
            } else {
                "run `native status` to check hosted health and refresh progress; the node retries automatically"
            })
        } else if matches!(freshness.state, StandbyFreshnessState::Unavailable) {
            Some("inspect standby snapshot provenance before relying on freshness")
        } else if degraded_reasons.contains(&"restart_recheck_pending") {
            Some("the local copy is being re-checked after this restart; no action needed")
        } else {
            None
        };
        StandbyResponseContext {
            status_scope: "serving_generation_freshness_only",
            in_flight_refresh,
            last_refresh_success_at,
            sync_observation: self.sync_observation(live_serving.as_ref()),
            full_status_tool: "standby_status",
            mode: if self.serving.is_some() {
                StandbyStatusMode::Standby
            } else {
                StandbyStatusMode::StatusOnly
            },
            canonical_authority: "hosted",
            read_only: true,
            writes_supported: false,
            serving_generation_id: self
                .serving
                .as_ref()
                .map(|generation| generation.generation_id.clone()),
            serving_head_act: live_serving
                .as_ref()
                .and_then(|generation| generation.head_act),
            serving_materialization: live_serving
                .as_ref()
                .map(|generation| generation.materialization),
            serving_source_history: live_serving
                .as_ref()
                .map(|generation| source_history(&generation.snapshot_path)),
            serving_consumer_rebound_at: self
                .serving
                .as_ref()
                .and_then(|serving| serving.consumer_rebound_at.clone()),
            serving_audit,
            freshness,
            freshness_degraded: !degraded_reasons.is_empty(),
            degraded_reasons,
            next_safe_action,
        }
    }

    fn sync_observation(&self, serving: Option<&ServingGeneration>) -> StandbySyncObservation {
        StandbySyncObservation {
            last_matching_hosted_check_at: serving
                .map(|s| s.synced_at.clone().unwrap_or_else(|| s.captured_at.clone())),
            last_local_materialization_at: serving.and_then(|s| {
                s.head_act
                    .and_then(|head| self.store.materialized_at(&s.generation_id, head))
            }),
            last_data_change_at: None,
            age_basis: "last_matching_hosted_check_or_snapshot_capture",
        }
    }

    /// The required audit's standing for `serving` as of `now`: only for a
    /// kernel-v2 copy advanced in place, and only while audits are required
    /// (the in-place flag is on). Read on every call, like the head: a stalled
    /// audit must be noticed by the next request, not the next restart.
    #[cfg(not(any(test, feature = "v2-kernel-probe")))]
    fn audit_of(&self, _serving: &ServingGeneration, _now: DateTime<Utc>) -> Option<StandbyAudit> {
        None
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn audit_of(&self, serving: &ServingGeneration, now: DateTime<Utc>) -> Option<StandbyAudit> {
        let interval = self.store.audit_interval()?;
        if serving.engine.name != super::kernel_v2::ENGINE
            || serving.materialization != StandbyGenerationMaterialization::Delta
        {
            return None;
        }
        let interval_seconds = interval.as_secs();
        let deadline = interval_seconds.saturating_mul(2);
        let Some(record) = self.store.generation_audit(&serving.generation_id) else {
            return Some(StandbyAudit {
                state: if serving.full_refresh_required {
                    "failed"
                } else {
                    "unaudited"
                },
                age_seconds: None,
                interval_seconds,
            });
        };
        // Wall-clock age, for disclosure. A record from the future (a clock
        // that went backwards, or a forged file) is ignored: it has no age.
        let age = record
            .acquired()
            .and_then(|at| u64::try_from(now.signed_duration_since(at).num_seconds()).ok());
        // Online eligibility needs a success THIS process observed, timed on
        // the monotonic clock: the wall clock alone can be set back.
        let observed = self
            .store
            .audit_last_success(&serving.generation_id)
            .map(|at| at.elapsed().as_secs());
        let state = if !record.passed() || serving.full_refresh_required {
            "failed"
        } else {
            match (age, observed) {
                (None, _) | (_, None) => "unaudited",
                (Some(age), Some(seen)) if age > deadline || seen > deadline => "overdue",
                (Some(_), Some(_)) => "current",
            }
        };
        Some(StandbyAudit {
            state,
            age_seconds: age,
            interval_seconds,
        })
    }

    /// The serving generation with its live head: deltas advance the leased
    /// generation in place, so its act and freshness are re-read on each use.
    fn live_serving(&self) -> Option<ServingGeneration> {
        let mut serving = self.serving.clone()?;
        if let Ok(Some(head)) = self.store.generation_head(&serving.generation_id) {
            serving.head_act = Some(head.head_act);
            // A staged kernel-v2 head stays `snapshot` (its manifest says how
            // the file was derived); only a copy advanced in place is `delta`.
            if serving.engine.name != super::kernel_v2::ENGINE || head.advanced_in_place() {
                serving.materialization = head.materialization;
            }
            serving.synced_at = Some(head.synced_at);
            serving.full_refresh_required = head.full_refresh_required;
        }
        let counts = self.store.deferral_counts(&serving.generation_id);
        serving.reader_deferrals = counts.reader_not_upgraded;
        serving.busy_deferrals = counts.database_busy;
        Some(serving)
    }

    #[cfg(test)]
    async fn status_at(&self, now: DateTime<Utc>) -> StandbyStatus {
        self.collect_status(Some(now)).await
    }

    async fn collect_status(&self, now: Option<DateTime<Utc>>) -> StandbyStatus {
        let store_status = match &self.observed {
            Some(observed) => self.store.inspect_status(observed).await,
            None => unavailable_store_status(),
        };
        let refresh_observation = observe_refresh_state(&self.runtime.replica_root);
        build_status_observed(self, store_status, refresh_observation, now)
    }
}

fn unavailable_store_status() -> GenerationStoreStatus {
    GenerationStoreStatus {
        current: None,
        current_provenance: GenerationProvenanceStatus::Unavailable,
        retained_generation_ids: Vec::new(),
        candidate_count: 0,
        unusable_candidate_count: 0,
        unverified_candidate_count: 0,
        startup_reason: None,
        startup_reason_available: false,
    }
}

fn generation_status(
    generation: &super::InstalledGeneration,
    head: Option<super::GenerationHead>,
    refresh: Option<&StandbyRefreshState>,
) -> StandbyGenerationStatus {
    let generation_id = generation.id.clone();
    let manifest = &generation.manifest;
    let promoted_at = refresh
        .filter(|state| state.installed_generation_id.as_deref() == Some(&generation_id))
        .and_then(|state| state.promoted_at.as_deref())
        .map(normalized_timestamp);
    StandbyGenerationStatus {
        generation_id,
        captured_at: normalized_timestamp(&manifest.captured_at),
        snapshot_completed_at: normalized_timestamp(&manifest.snapshot_completed_at),
        promoted_at,
        frontier: manifest.frontier.clone(),
        head_act: head
            .as_ref()
            .map(|head| head.head_act)
            .or(manifest.head_act),
        materialization: if manifest.kernel_v2.is_some() {
            manifest.materialization
        } else {
            head.as_ref()
                .map_or(manifest.materialization, |head| head.materialization)
        },
        synced_at: head.map(|head| normalized_timestamp(&head.synced_at)),
        source_history: source_history(&generation.snapshot_path),
        engine: manifest.engine.clone(),
        consumer: manifest.consumer.clone(),
        consumer_rebind: None,
    }
}

/// Read the source-history marker (`PRAGMA application_id`) straight from the
/// SQLite header. A history-unknown snapshot stays reported as `unknown` after
/// any number of deltas: they extend it from its checkpoint, never relabel it.
fn source_history(path: &std::path::Path) -> &'static str {
    use std::io::Read as _;
    let mut header = [0_u8; 72];
    let read = std::fs::File::open(path).and_then(|mut file| file.read_exact(&mut header));
    if read.is_err() || &header[..16] != b"SQLite format 3\0" {
        return "unavailable";
    }
    let marker = i32::from_be_bytes([header[68], header[69], header[70], header[71]]);
    if i64::from(marker)
        == crate::interchange::source_history_application_id(crate::interchange::REVISION)
    {
        "exhaustive"
    } else {
        "unknown"
    }
}

fn normalized_timestamp(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .expect("verified standby timestamp remains valid")
        .with_timezone(&Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
fn build_status(
    provider: &StandbyStatusProvider,
    store: GenerationStoreStatus,
    refresh_observation: RefreshStateObservation,
    now: DateTime<Utc>,
) -> StandbyStatus {
    build_status_observed(provider, store, refresh_observation, Some(now))
}

fn build_status_observed(
    provider: &StandbyStatusProvider,
    store: GenerationStoreStatus,
    refresh_observation: RefreshStateObservation,
    now: Option<DateTime<Utc>>,
) -> StandbyStatus {
    build_status_with_verification(
        provider,
        store,
        refresh_observation,
        now,
        super::generation_store::verification_stats(),
    )
}

fn build_status_with_verification(
    provider: &StandbyStatusProvider,
    store: GenerationStoreStatus,
    refresh_observation: RefreshStateObservation,
    now: Option<DateTime<Utc>>,
    verification: (u64, u64),
) -> StandbyStatus {
    let refresh_state = match &refresh_observation {
        RefreshStateObservation::Available(state) => Some(state.as_ref()),
        RefreshStateObservation::NeverRecorded | RefreshStateObservation::Unavailable => None,
    };
    let live_serving = provider.live_serving();
    let serving_generation = live_serving.as_ref().map(|serving| {
        let promoted_at = refresh_state
            .filter(|state| {
                state.installed_generation_id.as_deref() == Some(&serving.generation_id)
            })
            .and_then(|state| state.promoted_at.as_deref())
            .map(normalized_timestamp);
        StandbyGenerationStatus {
            generation_id: serving.generation_id.clone(),
            captured_at: normalized_timestamp(&serving.captured_at),
            snapshot_completed_at: normalized_timestamp(&serving.snapshot_completed_at),
            promoted_at,
            frontier: serving.frontier.clone(),
            head_act: serving.head_act,
            materialization: serving.materialization,
            synced_at: serving.synced_at.as_deref().map(normalized_timestamp),
            source_history: source_history(&serving.snapshot_path),
            engine: serving.engine.clone(),
            consumer: serving.consumer.clone(),
            consumer_rebind: provider.observed.as_ref().and_then(|observed| {
                provider
                    .store
                    .consumer_rebind(&serving.generation_id, observed)
                    .ok()
                    .flatten()
            }),
        }
    });
    let accepted_generation = store.current.as_ref().map(|generation| {
        let head = provider
            .store
            .generation_head(&generation.id)
            .ok()
            .flatten();
        let mut status = generation_status(generation, head, refresh_state);
        status.consumer_rebind = provider.observed.as_ref().and_then(|observed| {
            provider
                .store
                .consumer_rebind(&generation.id, observed)
                .ok()
                .flatten()
        });
        status
    });
    // Sample after every head read used in this response. A delta can land
    // during collection; its sync timestamp must not follow our observation.
    let now = now.unwrap_or_else(Utc::now);
    let observed_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let freshness = freshness(live_serving.as_ref(), now);
    let refresh = refresh_status(
        refresh_observation,
        provider.refresh_configured,
        provider.refresh_available,
        now,
    );
    let consumer_compatible = match (&provider.observed, &provider.serving, &accepted_generation) {
        (Some(observed), Some(serving), _) => Some(
            provider
                .store
                .consumer_rebind(&serving.generation_id, observed)
                .is_ok(),
        ),
        // `inspect_status` only returns an accepted generation after device
        // verification against this observed consumer identity.
        (Some(_), None, Some(_)) => Some(true),
        _ => None,
    };

    let mut degraded_reasons = Vec::new();
    if provider.serving.is_none() {
        degraded_reasons.push("no_usable_serving_generation");
    }
    match store.current_provenance {
        GenerationProvenanceStatus::Available => {}
        GenerationProvenanceStatus::Missing => {
            degraded_reasons.push("accepted_generation_provenance_missing")
        }
        GenerationProvenanceStatus::Invalid => {
            degraded_reasons.push("accepted_generation_provenance_invalid")
        }
        GenerationProvenanceStatus::Unavailable => {
            degraded_reasons.push("accepted_generation_provenance_unavailable")
        }
        GenerationProvenanceStatus::Unverified => {
            degraded_reasons.push("accepted_generation_unverified")
        }
    }
    if !store.startup_reason_available {
        degraded_reasons.push("startup_fallback_diagnostics_unavailable");
    }
    if store.startup_reason.is_some() {
        degraded_reasons.push("startup_fallback_active");
    }
    match refresh.diagnostics {
        StandbyRefreshDiagnosticsState::Available => {
            if refresh.consecutive_failure_count.unwrap_or(0) > 0 {
                degraded_reasons.push("refresh_failed");
                // A dead credential and a flaky network both surface as
                // `refresh_failed`, but they need different actions from the
                // owner and only one of them resolves itself. The standby
                // cannot know when its credential expires — the token is
                // opaque and its lifetime lives server-side — so a repeated
                // authentication refusal is the only honest signal available
                // that the credential needs reissuing.
                if matches!(
                    refresh.last_failure_class,
                    Some(super::RefreshFailureClass::Authentication)
                ) {
                    degraded_reasons.push("refresh_authentication_failing");
                }
            }
        }
        StandbyRefreshDiagnosticsState::NeverRecorded if provider.refresh_configured => {
            degraded_reasons.push("refresh_never_recorded")
        }
        StandbyRefreshDiagnosticsState::NeverRecorded => {
            degraded_reasons.push("refresh_not_configured")
        }
        StandbyRefreshDiagnosticsState::Unavailable => {
            degraded_reasons.push("refresh_diagnostics_unavailable")
        }
    }
    if provider.refresh_configured && !provider.refresh_available {
        degraded_reasons.push("refresh_controller_unavailable");
    }
    if live_serving
        .as_ref()
        .is_some_and(ServingGeneration::reader_not_upgraded)
    {
        degraded_reasons.push("reader_not_upgraded");
    }
    if live_serving
        .as_ref()
        .is_some_and(ServingGeneration::database_busy)
    {
        degraded_reasons.push("database_busy");
    }
    match freshness.state {
        StandbyFreshnessState::Fresh => {}
        StandbyFreshnessState::BeyondRpo => degraded_reasons.push("snapshot_beyond_rpo"),
        StandbyFreshnessState::Unavailable if provider.serving.is_some() => {
            degraded_reasons.push("snapshot_age_unavailable")
        }
        StandbyFreshnessState::Unavailable => {}
    }
    if serving_generation
        .as_ref()
        .map(|generation| &generation.generation_id)
        != accepted_generation
            .as_ref()
            .map(|generation| &generation.generation_id)
        && serving_generation.is_some()
        && accepted_generation.is_some()
    {
        degraded_reasons.push(if provider.connected_handoff {
            "accepted_generation_pending_handoff"
        } else {
            "accepted_generation_pending_restart"
        });
    }
    // Same neutral disclosure as the per-response context: a copy serving
    // while its post-restart integrity re-check completes.
    if live_serving.is_some() && provider.store.startup_recheck_pending() {
        degraded_reasons.push("restart_recheck_pending");
    }
    degraded_reasons.sort_unstable();
    degraded_reasons.dedup();

    if refresh
        .in_flight
        .as_ref()
        .is_some_and(|attempt| attempt.overdue)
    {
        degraded_reasons.push("refresh_attempt_overdue");
    }
    let accepted_generation_available = accepted_generation.is_some();
    let pending_handoff = provider.connected_handoff
        && accepted_generation_available
        && serving_generation
            .as_ref()
            .map(|generation| &generation.generation_id)
            != accepted_generation
                .as_ref()
                .map(|generation| &generation.generation_id);
    let next_safe_action = if refresh
        .in_flight
        .as_ref()
        .is_some_and(|attempt| attempt.overdue)
    {
        Some("a refresh exceeded its deadline; run `native status --diagnose`, then `native restart` if it remains stuck")
    } else if pending_handoff {
        Some("the connected session will attempt device verification and readiness; inspect aggregate handoff diagnostics if serving does not advance")
    } else if provider.serving.is_none() && accepted_generation_available {
        Some("restart the standby to activate the verified accepted generation")
    } else if provider.serving.is_none() && provider.connected_handoff {
        Some("run a verified external refresh; the connected session will attempt device handoff")
    } else if provider.serving.is_none() {
        Some("refresh the standby, then restart it after a verified generation is accepted")
    } else if degraded_reasons.contains(&"refresh_authentication_failing") {
        // Ordered ahead of every action below because all of them tell the
        // owner to run a refresh, and none of them can succeed while the
        // credential is being refused. Naming connectivity or provenance first
        // would send someone round a loop that cannot terminate.
        Some("run `native login` to renew the node credential; refresh retries automatically")
    } else if degraded_reasons.contains(&"restart_recheck_pending") {
        Some("the local copy is being re-checked after this restart; no action needed")
    } else if store.current_provenance == GenerationProvenanceStatus::Unverified {
        Some("wait for local generation verification to finish; inspect node diagnostics if it remains unavailable")
    } else if matches!(
        store.current_provenance,
        GenerationProvenanceStatus::Missing
            | GenerationProvenanceStatus::Invalid
            | GenerationProvenanceStatus::Unavailable
    ) {
        Some("inspect standby provenance and run a verified refresh before relying on accepted state")
    } else if degraded_reasons.contains(&"accepted_generation_pending_restart") {
        Some("restart the standby to activate the newer accepted generation")
    } else if degraded_reasons.contains(&"reader_not_upgraded") {
        Some(READER_NOT_UPGRADED_ACTION)
    } else if degraded_reasons.contains(&"database_busy") {
        Some(DATABASE_BUSY_ACTION)
    } else if matches!(freshness.state, StandbyFreshnessState::BeyondRpo)
        || refresh.consecutive_failure_count.unwrap_or(0) > 0
    {
        if last_failure_is_idle_throttle(
            refresh.last_failure_class,
            refresh.consecutive_failure_count.unwrap_or(0),
        ) {
            Some("the standby refresh is catching up and retries on its own")
        } else {
            Some("run `native status` to check hosted health and refresh progress; the node retries automatically")
        }
    } else if provider.refresh_configured && !provider.refresh_available {
        Some("repair the local refresh configuration before relying on the target RPO")
    } else if !provider.refresh_configured {
        Some("configure the supported background refresh controller to maintain the target RPO")
    } else {
        None
    };
    let degraded = !degraded_reasons.is_empty();

    let (verification_passes, verification_total_ms) = verification;
    let retained_generation_count = store.retained_generation_ids.len();
    let mut retained_generation_ids = store.retained_generation_ids;
    retained_generation_ids.truncate(MAX_STATUS_RETAINED_GENERATIONS);
    StandbyStatus {
        contract: STANDBY_STATUS_CONTRACT,
        version: 1,
        observed_at,
        mode: if provider.serving.is_some() {
            StandbyStatusMode::Standby
        } else {
            StandbyStatusMode::StatusOnly
        },
        read_only: true,
        writes_supported: false,
        mutation_error: if provider.serving.is_some() {
            "STANDBY_READ_ONLY"
        } else {
            "STANDBY_STATUS_ONLY"
        },
        canonical_authority: "hosted",
        projection: "accepted_only",
        interaction_capture: false,
        run_persistence: false,
        hosted_route_database_id: provider.runtime.hosted_route_database_id.clone(),
        origin_database_id: provider.runtime.origin_database_id.clone(),
        serving_generation,
        accepted_generation,
        accepted_generation_provenance: match store.current_provenance {
            GenerationProvenanceStatus::Available => "available",
            GenerationProvenanceStatus::Missing => "missing",
            GenerationProvenanceStatus::Invalid => "invalid",
            GenerationProvenanceStatus::Unavailable => "unavailable",
            GenerationProvenanceStatus::Unverified => "unverified",
        },
        freshness,
        sync_observation: provider.sync_observation(live_serving.as_ref()),
        serving_audit: live_serving
            .as_ref()
            .and_then(|serving| provider.audit_of(serving, now)),
        refresh,
        installed_consumer: provider.observed.clone(),
        consumer_compatible,
        retained_generation_ids,
        retained_generation_count,
        unverified_candidate_count: store.unverified_candidate_count,
        unusable_candidate_count: store.unusable_candidate_count,
        retained_generation_ids_truncated: retained_generation_count
            > MAX_STATUS_RETAINED_GENERATIONS,
        startup_fallback: store.startup_reason,
        startup_fallback_diagnostics_available: store.startup_reason_available,
        status_only: provider.status_only.clone().map(|mut status| {
            if store.candidate_count > 0 || store.unusable_candidate_count > 0 {
                status.candidate_count = store.candidate_count;
                status.unusable_candidate_count = store.unusable_candidate_count;
            }
            status
        }),
        accepted_plus_pending_supported: false,
        pending_writes_supported: false,
        degraded,
        degraded_reasons,
        summary: if provider.serving.is_none()
            && accepted_generation_available
            && provider.connected_handoff
        {
            "This status-only Native standby has an accepted generation; workspace reads remain unavailable until full handoff readiness succeeds."
        } else if provider.serving.is_none() && accepted_generation_available {
            "This status-only Native standby has accepted a verified generation; restart is required before workspace reads can serve it."
        } else if provider.serving.is_none() {
            "This local Native standby has no usable verified generation and cannot serve workspace data."
        } else if degraded {
            "This is a read-only local Native standby serving non-canonical snapshot data in a degraded state."
        } else {
            "This is a read-only local Native standby serving a verified snapshot; hosted Native remains canonical."
        },
        next_safe_action,
        verification_passes,
        verification_total_seconds: verification_total_ms / 1000,
    }
}

fn freshness(serving: Option<&ServingGeneration>, now: DateTime<Utc>) -> StandbyFreshness {
    let Some(serving) = serving else {
        return unavailable_freshness();
    };
    // A copy is as fresh as the later of its checkpoint capture and the last
    // time hosted Native was observed at the act it holds.
    let Ok(captured) = DateTime::parse_from_rfc3339(&serving.captured_at) else {
        return unavailable_freshness();
    };
    let synced = serving
        .synced_at
        .as_deref()
        .and_then(|synced| DateTime::parse_from_rfc3339(synced).ok());
    let basis = synced.map_or(captured, |synced| synced.max(captured));
    let age = now.signed_duration_since(basis.with_timezone(&Utc));
    let Ok(age_seconds) = u64::try_from(age.num_seconds()) else {
        return unavailable_freshness();
    };
    let beyond_rpo = age_seconds > STANDBY_RPO_SECONDS;
    StandbyFreshness {
        state: if beyond_rpo {
            StandbyFreshnessState::BeyondRpo
        } else {
            StandbyFreshnessState::Fresh
        },
        age_seconds: Some(age_seconds),
        age_basis: "last_matching_hosted_check_or_snapshot_capture_not_content_lag",
        target_rpo_seconds: STANDBY_RPO_SECONDS,
        target_refresh_interval_seconds: STANDBY_REFRESH_INTERVAL_SECONDS,
        beyond_rpo: Some(beyond_rpo),
    }
}

fn unavailable_freshness() -> StandbyFreshness {
    StandbyFreshness {
        state: StandbyFreshnessState::Unavailable,
        age_seconds: None,
        age_basis: "last_matching_hosted_check_or_snapshot_capture_not_content_lag",
        target_rpo_seconds: STANDBY_RPO_SECONDS,
        target_refresh_interval_seconds: STANDBY_REFRESH_INTERVAL_SECONDS,
        beyond_rpo: None,
    }
}

fn refresh_status(
    observation: RefreshStateObservation,
    configured: bool,
    controller_available: bool,
    now: DateTime<Utc>,
) -> StandbyRefreshStatus {
    let (diagnostics, state) = match observation {
        RefreshStateObservation::Available(state) => {
            (StandbyRefreshDiagnosticsState::Available, Some(*state))
        }
        RefreshStateObservation::NeverRecorded => {
            (StandbyRefreshDiagnosticsState::NeverRecorded, None)
        }
        RefreshStateObservation::Unavailable => (StandbyRefreshDiagnosticsState::Unavailable, None),
    };
    StandbyRefreshStatus {
        configured,
        controller_available,
        diagnostics,
        refresh_active: state.as_ref().map(|state| state.refresh_active),
        in_flight: state.as_ref().and_then(|state| in_flight(state, Some(now))),
        transfer_progress: state
            .as_ref()
            .and_then(|state| state.transfer_progress.clone())
            .map(|progress| progress.observed(Some(now))),
        manual_refresh_pending: state.as_ref().map(|state| state.manual_refresh_pending),
        last_attempt_at: state
            .as_ref()
            .and_then(|state| state.last_attempt_at.as_deref())
            .map(normalized_timestamp),
        last_attempt_cause: state.as_ref().and_then(|state| state.last_attempt_cause),
        last_success_at: state
            .as_ref()
            .and_then(|state| state.last_success_at.as_deref())
            .map(normalized_timestamp),
        installed_generation_id: state
            .as_ref()
            .and_then(|state| state.installed_generation_id.clone()),
        snapshot_captured_at: state
            .as_ref()
            .and_then(|state| state.snapshot_captured_at.as_deref())
            .map(normalized_timestamp),
        snapshot_completed_at: state
            .as_ref()
            .and_then(|state| state.snapshot_completed_at.as_deref())
            .map(normalized_timestamp),
        promoted_at: state
            .as_ref()
            .and_then(|state| state.promoted_at.as_deref())
            .map(normalized_timestamp),
        frontier: state.as_ref().and_then(|state| state.frontier.clone()),
        consecutive_failure_count: state.as_ref().map(|state| state.consecutive_failure_count),
        last_failure_class: state.as_ref().and_then(|state| state.last_failure_class),
        // Persisted state is local operational input, not a trusted disclosure
        // source. Project a closed message from the typed class rather than
        // echoing arbitrary state-file prose into MCP responses.
        last_failure: state
            .as_ref()
            .and_then(|state| state.last_failure_class)
            .map(safe_refresh_failure_message)
            .map(str::to_owned),
        last_delta_fallback_class: state
            .as_ref()
            .and_then(|state| state.last_delta_fallback_class),
        last_delta_fallback: state
            .as_ref()
            .and_then(|state| state.last_delta_fallback_class)
            .map(safe_delta_fallback_message)
            .map(str::to_owned),
        last_deferral: state
            .as_ref()
            .and_then(|state| state.last_deferral.as_deref())
            .and_then(super::refresh::sanitize_deferral),
        last_full_refresh_at: state
            .as_ref()
            .and_then(|state| state.last_full_refresh_at.as_deref())
            .map(normalized_timestamp),
        next_full_refresh_eligible_at: state
            .as_ref()
            .filter(|state| {
                state.last_deferral.as_deref()
                    == Some(super::refresh::DEFERRED_FULL_REFRESH_INTERVAL)
            })
            .and_then(|state| state.next_full_refresh_eligible_at.as_deref())
            .map(normalized_timestamp),
        last_full_failure_at: state
            .as_ref()
            .and_then(|state| state.last_full_failure_at.as_deref())
            .map(normalized_timestamp),
        last_full_failure_cause: state
            .as_ref()
            .and_then(|state| state.last_full_failure_cause),
        last_full_failure_class: state
            .as_ref()
            .and_then(|state| state.last_full_failure_class),
        last_full_failure: state
            .as_ref()
            .and_then(|state| state.last_full_failure_class)
            .map(safe_refresh_failure_message)
            .map(str::to_owned),
        last_full_failure_detail: state
            .as_ref()
            .map(|state| {
                super::refresh::sanitize_retained_detail(state.last_full_failure_detail.as_deref())
            })
            // Omit the slot when nothing was ever retained, so an empty
            // projection cannot be mistaken for a classified outcome.
            .filter(|_| {
                state
                    .as_ref()
                    .is_some_and(|state| state.last_full_failure_class.is_some())
            })
            .map(str::to_owned),
    }
}

fn safe_delta_fallback_message(class: super::refresh::DeltaFallbackClass) -> &'static str {
    use super::refresh::DeltaFallbackClass::*;
    match class {
        HeadCompatibility => "delta head was incompatible; a whole snapshot is required",
        DeltaUnavailable => "delta was unavailable; a whole snapshot is required",
        IntegrityOrApplyRefusal => {
            "delta integrity or apply check refused; a whole snapshot is required"
        }
        RemoteHeadRegression => "delta authority head regressed; a whole snapshot is required",
        UntrustedLocalBase => "local copy could not take a delta; a whole snapshot is required",
        AuditFailed => "an audit of the local copy failed; a whole snapshot is required",
        ConsumerChanged => "installed consumer changed; a whole snapshot is required",
        DeltaTooLarge => {
            "the catch-up is too large for a delta transfer; a whole snapshot is required"
        }
        BlobInventoryLimit => {
            "kernel v2 blob inventory exceeded the limit; a whole snapshot is required"
        }
        ProjectionDivergence => {
            "kernel v2 projection digest differed; a whole snapshot is required"
        }
    }
}

/// A held-back last failure with no counted consecutive failures is routine
/// scheduling — a busy hosted export, or a whole-snapshot cooldown — never a
/// connectivity or authentication outage worth repairing.
fn last_failure_is_idle_throttle(
    class: Option<super::RefreshFailureClass>,
    consecutive_failure_count: u32,
) -> bool {
    class == Some(super::RefreshFailureClass::Throttled) && consecutive_failure_count == 0
}

fn safe_refresh_failure_message(class: super::RefreshFailureClass) -> &'static str {
    match class {
        super::RefreshFailureClass::Authentication => "standby refresh authentication failed",
        super::RefreshFailureClass::Network => "standby refresh network request failed",
        super::RefreshFailureClass::Protocol => "standby refresh protocol exchange failed",
        super::RefreshFailureClass::DownloadIntegrity => {
            "standby refresh download integrity check failed"
        }
        super::RefreshFailureClass::Verification => "standby refresh verification failed",
        super::RefreshFailureClass::Compatibility => "standby refresh compatibility check failed",
        super::RefreshFailureClass::Timeout => "standby refresh exceeded its time bound",
        super::RefreshFailureClass::LocalIo => "standby refresh local storage failed",
        // Throttled is scheduling, never an outage: a busy hosted export or
        // a whole-snapshot cooldown. Either way the refresh retries on its
        // own schedule, so the message must not name an outage or a hold.
        super::RefreshFailureClass::Throttled => {
            "standby refresh is waiting to retry on its schedule"
        }
        super::RefreshFailureClass::RevisionUnsupported => {
            "standby refresh paused: hosted uses a newer interchange revision"
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn in_flight_refresh_reports_deadline_and_clock_uncertainty() {
        let mut state = super::super::StandbyRefreshState {
            refresh_active: true,
            last_attempt_id: Some(uuid::Uuid::new_v4().to_string()),
            last_attempt_at: Some("2026-11-16T08:00:00Z".into()),
            last_attempt_cause: Some(super::super::RefreshCause::Scheduled),
            ..Default::default()
        };
        let now = "2026-11-16T08:11:00Z".parse().unwrap();
        let attempt = super::in_flight(&state, Some(now)).unwrap();
        assert!(attempt.overdue);
        assert_eq!(attempt.elapsed_seconds, Some(660));
        assert_eq!(attempt.deadline_seconds, 600);
        assert_eq!(
            super::in_flight(&state, None).unwrap().elapsed_seconds,
            None
        );
        let before = "2026-11-16T07:00:00Z".parse().unwrap();
        assert_eq!(
            super::in_flight(&state, Some(before))
                .unwrap()
                .elapsed_seconds,
            None
        );
        state.refresh_active = false;
        assert!(super::in_flight(&state, Some(now)).is_none());
    }

    use super::*;
    use crate::standby_snapshot::{
        StandbyConsumerPlatform, StandbySnapshotBytes, StandbySnapshotEngineIdentity,
        StandbySnapshotManifest, STANDBY_CONSUMER_CONTRACT, STANDBY_FRONTIER_CONTRACT,
        STANDBY_SNAPSHOT_MANIFEST_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
    };

    fn consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            kernel_v2_reader: Default::default(),
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
        }
    }

    fn frontier() -> CanonicalFrontierV1 {
        CanonicalFrontierV1 {
            contract: STANDBY_FRONTIER_CONTRACT.into(),
            version: 1,
            content_event_seq: 1,
            policy_event_seq: 2,
            awareness_event_seq: 3,
            notification_candidate_event_seq: 4,
            binding_audit_seq: 5,
            database_identity_audit_seq: 6,
            meta_event_seq: 7,
            control_event_seq: 8,
            derivation_event_seq: 9,
            relationship_event_seq: 10,
            authorization_revision_epoch: 11,
            storage_portability_policy_revision: 12,
        }
    }

    fn manifest(captured_at: &str, snapshot_completed_at: &str) -> StandbySnapshotManifest {
        StandbySnapshotManifest {
            contract: STANDBY_SNAPSHOT_MANIFEST_CONTRACT.into(),
            version: 1,
            hosted_route_database_id: "route-1".into(),
            origin_database_id: "ndb_0123456789abcdef0123456789abcdef".into(),
            captured_at: captured_at.into(),
            snapshot_completed_at: snapshot_completed_at.into(),
            engine: StandbySnapshotEngineIdentity {
                name: crate::ENGINE_NAME.into(),
                source_sha: "d".repeat(40),
                schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
                ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
            },
            consumer: consumer(),
            frontier: frontier(),
            head_act: Some(0),
            kernel_v2: None,
            materialization: StandbyGenerationMaterialization::Snapshot,
            snapshot: StandbySnapshotBytes {
                media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
                size_bytes: 1,
                sha256: "e".repeat(64),
            },
        }
    }

    fn store_status(
        current: Option<super::super::InstalledGeneration>,
        provenance: GenerationProvenanceStatus,
    ) -> GenerationStoreStatus {
        let retained_generation_ids = current
            .as_ref()
            .map(|generation| vec![generation.id.clone()])
            .unwrap_or_default();
        GenerationStoreStatus {
            current,
            current_provenance: provenance,
            retained_generation_ids,
            candidate_count: 1,
            unusable_candidate_count: 0,
            unverified_candidate_count: 0,
            startup_reason: None,
            startup_reason_available: true,
        }
    }

    fn provider(captured_at: &str) -> StandbyStatusProvider {
        let directory = tempfile::tempdir().unwrap().keep();
        let runtime = StandbyRuntimeConfig {
            replica_root: directory.join("replica"),
            hosted_route_database_id: "route-1".into(),
            origin_database_id: "ndb_0123456789abcdef0123456789abcdef".into(),
        };
        let store = GenerationStore::open(
            &runtime.replica_root,
            &runtime.hosted_route_database_id,
            Some(runtime.origin_database_id.clone()),
        )
        .unwrap();
        StandbyStatusProvider {
            runtime,
            store,
            observed: Some(ObservedInstalledConsumerIdentity {
                kernel_v2_reader: Default::default(),
                platform: StandbyConsumerPlatform::LinuxX8664,
                source_sha: "a".repeat(40),
                artifact_sha256: "b".repeat(64),
                engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
                ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
            }),
            serving: Some(ServingGeneration {
                generation_id: "c".repeat(64),
                act_lineage: "v1:fixture".into(),
                snapshot_path: directory.join("missing-snapshot.db"),
                captured_at: captured_at.into(),
                snapshot_completed_at: captured_at.into(),
                frontier: frontier(),
                head_act: Some(0),
                materialization: StandbyGenerationMaterialization::Snapshot,
                synced_at: None,
                reader_deferrals: 0,
                busy_deferrals: 0,
                full_refresh_required: false,
                engine: manifest(captured_at, captured_at).engine,
                consumer: consumer(),
                consumer_rebound_at: None,
            }),
            status_only: None,
            refresh_configured: true,
            refresh_available: true,
            connected_handoff: false,
        }
    }

    #[tokio::test]
    async fn freshness_uses_serving_capture_and_fails_closed_for_future_time() {
        let provider = provider("2026-09-02T12:00:00Z");
        let fresh = provider
            .status_at("2026-09-02T12:05:00Z".parse().unwrap())
            .await;
        assert_eq!(fresh.freshness.state, StandbyFreshnessState::Fresh);
        assert_eq!(fresh.freshness.age_seconds, Some(300));
        assert_eq!(fresh.freshness.beyond_rpo, Some(false));

        let stale = provider
            .status_at("2026-09-02T12:05:01Z".parse().unwrap())
            .await;
        assert_eq!(stale.freshness.state, StandbyFreshnessState::BeyondRpo);
        assert_eq!(stale.freshness.age_seconds, Some(301));

        let future = provider
            .status_at("2026-09-02T11:59:59Z".parse().unwrap())
            .await;
        assert_eq!(future.freshness.state, StandbyFreshnessState::Unavailable);
        assert!(future
            .degraded_reasons
            .contains(&"snapshot_age_unavailable"));
    }

    #[tokio::test]
    async fn unchanged_hosted_check_preserves_materialization_time() {
        let provider = provider("2026-09-02T12:00:00Z");
        let generation = super::super::InstalledGeneration {
            id: "c".repeat(64),
            snapshot_path: provider.serving.as_ref().unwrap().snapshot_path.clone(),
            manifest: manifest("2026-09-02T12:00:00Z", "2026-09-02T12:00:00Z"),
        };
        provider
            .store
            .record_synced(&generation, 7, "2026-09-02T13:00:00Z")
            .unwrap();
        let advanced = provider.response_context();
        let materialized = advanced
            .sync_observation
            .last_local_materialization_at
            .clone();
        assert!(materialized.is_some());
        provider
            .store
            .record_synced(&generation, 7, "2026-09-02T14:00:00Z")
            .unwrap();
        let unchanged = provider.response_context();
        assert_eq!(
            unchanged.sync_observation.last_local_materialization_at,
            materialized
        );
        assert_eq!(
            unchanged
                .sync_observation
                .last_matching_hosted_check_at
                .as_deref(),
            Some("2026-09-02T14:00:00Z")
        );
        assert_eq!(unchanged.sync_observation.last_data_change_at, None);
        assert_eq!(unchanged.serving_head_act, advanced.serving_head_act);
        // Old in-place copies have no diagnostic sidecar. Do not substitute
        // their checkpoint completion or their latest no-change check.
        std::fs::remove_file(
            provider
                .runtime
                .replica_root
                .join("accepted")
                .join("heads")
                .join(format!("{}.materialized.json", generation.id)),
        )
        .unwrap();
        assert_eq!(
            provider
                .response_context()
                .sync_observation
                .last_local_materialization_at,
            None
        );
    }

    #[tokio::test]
    async fn freshness_and_head_follow_the_last_sync_after_deltas() {
        let provider = provider("2026-09-02T12:00:00Z");
        let generation = super::super::InstalledGeneration {
            id: "c".repeat(64),
            snapshot_path: provider.serving.as_ref().unwrap().snapshot_path.clone(),
            manifest: manifest("2026-09-02T12:00:00Z", "2026-09-02T12:00:00Z"),
        };
        provider
            .store
            .record_synced(&generation, 7, "2026-09-02T13:00:00Z")
            .unwrap();
        let status = provider
            .status_at("2026-09-02T13:04:00Z".parse().unwrap())
            .await;
        assert_eq!(status.freshness.state, StandbyFreshnessState::Fresh);
        assert_eq!(status.freshness.age_seconds, Some(240));
        let serving = status.serving_generation.unwrap();
        assert_eq!(serving.head_act, Some(7));
        assert_eq!(
            serving.synced_at.as_deref(),
            Some("2026-09-02T13:00:00.000Z")
        );
        assert_eq!(serving.captured_at, "2026-09-02T12:00:00.000Z");
        // The test serves a path with no database: say so, never guess.
        assert_eq!(serving.source_history, "unavailable");
    }

    #[tokio::test]
    async fn an_expired_credential_is_distinguished_from_a_flaky_network() {
        // A dead credential and a transient network fault both surface as
        // `refresh_failed`, but only one of them resolves itself, and they need
        // different actions from the owner. The standby cannot report a
        // credential's expiry — the token is opaque and its lifetime lives
        // server-side — so a repeated authentication refusal is the only honest
        // signal that the credential needs reissuing, and it must not be buried.
        let provider = provider("2026-09-02T12:00:00Z");
        let refresh = provider.runtime.replica_root.join("refresh");
        std::fs::create_dir_all(&refresh).unwrap();

        let network = StandbyRefreshState {
            consecutive_failure_count: 3,
            last_failure_class: Some(super::super::RefreshFailureClass::Network),
            last_failure: Some("network".into()),
            ..StandbyRefreshState::default()
        };
        std::fs::write(
            refresh.join("state.json"),
            serde_jcs::to_vec(&network).unwrap(),
        )
        .unwrap();
        let status = provider
            .status_at("2026-09-02T12:00:01Z".parse().unwrap())
            .await;
        assert!(status.degraded_reasons.contains(&"refresh_failed"));
        assert!(
            !status
                .degraded_reasons
                .contains(&"refresh_authentication_failing"),
            "a network fault must not be reported as a credential problem"
        );

        let authentication = StandbyRefreshState {
            consecutive_failure_count: 3,
            last_failure_class: Some(super::super::RefreshFailureClass::Authentication),
            last_failure: Some("authentication".into()),
            ..StandbyRefreshState::default()
        };
        std::fs::write(
            refresh.join("state.json"),
            serde_jcs::to_vec(&authentication).unwrap(),
        )
        .unwrap();
        let status = provider
            .status_at("2026-09-02T12:00:02Z".parse().unwrap())
            .await;
        assert!(status.degraded_reasons.contains(&"refresh_failed"));
        assert!(
            status
                .degraded_reasons
                .contains(&"refresh_authentication_failing"),
            "a repeated authentication refusal must surface as its own reason"
        );
        assert_eq!(
            status.next_safe_action,
            Some("run `native login` to renew the node credential; refresh retries automatically"),
            "the action must name credential reissue, not generic connectivity"
        );
    }

    #[tokio::test]
    async fn busy_export_is_scheduling_not_an_outage() {
        // A healthy hosted answering 409 export_in_progress must never read
        // as connectivity trouble: no failure degradation beyond the honest
        // age, no connectivity/auth repair advice, and scheduling wording
        // with no internal stale/throttled words.
        let provider = provider("2026-09-02T12:00:00Z");
        let refresh = provider.runtime.replica_root.join("refresh");
        std::fs::create_dir_all(&refresh).unwrap();
        let busy = StandbyRefreshState {
            consecutive_failure_count: 0,
            last_failure_class: Some(super::super::RefreshFailureClass::Throttled),
            last_failure: Some("hosted delta export is already in progress".into()),
            ..StandbyRefreshState::default()
        };
        std::fs::write(
            refresh.join("state.json"),
            serde_jcs::to_vec(&busy).unwrap(),
        )
        .unwrap();

        // A fresh copy shows the scheduling wording and no failure reason.
        let status = provider
            .status_at("2026-09-02T12:00:01Z".parse().unwrap())
            .await;
        assert!(
            !status.degraded_reasons.contains(&"refresh_failed"),
            "an uncounted busy hold is not a failure"
        );
        assert_eq!(
            status.refresh.last_failure.as_deref(),
            Some("standby refresh is waiting to retry on its schedule")
        );
        assert!(
            !status
                .refresh
                .last_failure
                .as_deref()
                .is_some_and(|message| {
                    message.contains("stale") || message.contains("throttl")
                }),
            "user-facing text keeps internal stale/throttled words out"
        );

        // Past RPO the honest age still degrades, but the per-request advice
        // stays scheduling: no connectivity or authentication repair.
        let context = provider.response_context_at("2026-09-02T12:05:01Z".parse().unwrap());
        assert_eq!(context.degraded_reasons, vec!["snapshot_beyond_rpo"]);
        assert_eq!(
            context.next_safe_action,
            Some("the standby refresh is catching up and retries on its own")
        );

        // A counted throttled failure keeps the existing advice: the
        // scheduling projection is only for the uncounted idle hold.
        let counted = build_status(
            &provider,
            store_status(None, GenerationProvenanceStatus::Available),
            RefreshStateObservation::Available(Box::new(StandbyRefreshState {
                consecutive_failure_count: 2,
                ..busy
            })),
            "2026-09-02T12:00:01Z".parse().unwrap(),
        );
        assert_eq!(
            counted.next_safe_action,
            Some(
                "run `native status` to check hosted health and refresh progress; the node retries automatically"
            )
        );
    }

    #[tokio::test]
    async fn corrupt_refresh_state_is_dynamic_degraded_diagnostics_without_raw_bytes() {
        let provider = provider("2026-09-02T12:00:00Z");
        let refresh = provider.runtime.replica_root.join("refresh");
        std::fs::create_dir_all(&refresh).unwrap();
        std::fs::write(refresh.join("state.json"), b"credential=super-secret").unwrap();

        let status = provider
            .status_at("2026-09-02T12:00:01Z".parse().unwrap())
            .await;
        assert_eq!(
            status.refresh.diagnostics,
            StandbyRefreshDiagnosticsState::Unavailable
        );
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(!serialized.contains("super-secret"));
        assert!(!serialized.contains(provider.runtime.replica_root.to_str().unwrap()));
        assert!(status
            .degraded_reasons
            .contains(&"refresh_diagnostics_unavailable"));

        let mut state = StandbyRefreshState {
            consecutive_failure_count: 1,
            last_failure_class: Some(super::super::RefreshFailureClass::LocalIo),
            last_failure: Some("credential=super-secret".into()),
            ..StandbyRefreshState::default()
        };
        std::fs::write(
            refresh.join("state.json"),
            serde_jcs::to_vec(&state).unwrap(),
        )
        .unwrap();
        let status = provider
            .status_at("2026-09-02T12:00:02Z".parse().unwrap())
            .await;
        assert_eq!(
            status.refresh.diagnostics,
            StandbyRefreshDiagnosticsState::Available
        );
        assert_eq!(
            status.refresh.last_failure.as_deref(),
            Some("standby refresh local storage failed")
        );
        assert!(!serde_json::to_string(&status)
            .unwrap()
            .contains("super-secret"));

        state.last_success_at = Some("2026-09-02T12:00:03Z".into());
        // A partial success tuple is semantically corrupt even though every
        // individual JSON field has the expected type.
        std::fs::write(
            refresh.join("state.json"),
            serde_jcs::to_vec(&state).unwrap(),
        )
        .unwrap();
        let status = provider
            .status_at("2026-09-02T12:00:04Z".parse().unwrap())
            .await;
        assert_eq!(
            status.refresh.diagnostics,
            StandbyRefreshDiagnosticsState::Unavailable
        );
    }

    #[tokio::test]
    async fn retained_full_failure_projects_after_latest_clears_and_legacy_detail_sanitizes() {
        let provider = provider("2026-09-02T12:00:00Z");
        let refresh = provider.runtime.replica_root.join("refresh");
        std::fs::create_dir_all(&refresh).unwrap();
        // Latest failure cleared while the retained FULL slot still names
        // its cause. The stored detail is legacy raw text: the projection
        // must not disclose it.
        let state = StandbyRefreshState {
            last_attempt_at: Some("2026-09-02T12:00:01Z".into()),
            last_attempt_cause: Some(super::super::RefreshCause::Scheduled),
            last_full_failure_at: Some("2026-09-02T11:00:00Z".into()),
            last_full_failure_cause: Some(super::super::RefreshCause::Manual),
            last_full_failure_class: Some(super::super::RefreshFailureClass::Verification),
            last_full_failure: Some("downloaded snapshot was not admitted".into()),
            last_full_failure_detail: Some(
                "standby snapshot conformance failed: row 0: live={\"body\":\"x\"}".into(),
            ),
            ..StandbyRefreshState::default()
        };
        std::fs::write(
            refresh.join("state.json"),
            serde_jcs::to_vec(&state).unwrap(),
        )
        .unwrap();
        let status = provider
            .status_at("2026-09-02T12:00:03Z".parse().unwrap())
            .await;
        assert_eq!(
            status.refresh.diagnostics,
            StandbyRefreshDiagnosticsState::Available
        );
        assert_eq!(status.refresh.last_failure_class, None);
        assert_eq!(
            status.refresh.last_full_failure_class,
            Some(super::super::RefreshFailureClass::Verification)
        );
        assert_eq!(
            status.refresh.last_full_failure.as_deref(),
            Some("standby refresh verification failed")
        );
        assert_eq!(
            status.refresh.last_full_failure_cause,
            Some(super::super::RefreshCause::Manual)
        );
        assert_eq!(
            status.refresh.last_full_failure_detail.as_deref(),
            Some("unclassified")
        );
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(!serialized.contains("row 0"));
        assert!(!serialized.contains("live={"));
    }

    #[tokio::test]
    async fn too_large_deferral_projects_the_stale_reason_the_deferral_and_next_eligibility() {
        let provider = provider("2026-09-02T12:00:00Z");
        let refresh = provider.runtime.replica_root.join("refresh");
        std::fs::create_dir_all(&refresh).unwrap();
        let state = StandbyRefreshState {
            last_attempt_at: Some("2026-09-02T12:00:01Z".into()),
            last_attempt_cause: Some(super::super::RefreshCause::Scheduled),
            last_delta_fallback_class: Some(
                super::super::refresh::DeltaFallbackClass::DeltaTooLarge,
            ),
            last_delta_fallback: Some("anything the state file says".into()),
            last_full_refresh_at: Some("2026-09-02T09:00:00Z".into()),
            last_deferral: Some("full_refresh_interval".into()),
            next_full_refresh_eligible_at: Some("2026-09-02T15:00:00Z".into()),
            ..StandbyRefreshState::default()
        };
        std::fs::write(
            refresh.join("state.json"),
            serde_jcs::to_vec(&state).unwrap(),
        )
        .unwrap();
        let status = provider
            .status_at("2026-09-02T12:00:03Z".parse().unwrap())
            .await;
        let refresh = status.refresh;
        assert_eq!(
            refresh.last_delta_fallback_class,
            Some(super::super::refresh::DeltaFallbackClass::DeltaTooLarge)
        );
        let message = refresh.last_delta_fallback.unwrap();
        assert!(message.contains("too large"), "{message}");
        assert!(
            !message.contains("installed") && !message.contains("used"),
            "{message}"
        );
        assert_eq!(refresh.last_deferral, Some("full_refresh_interval"));
        assert_eq!(
            refresh.last_full_refresh_at.as_deref(),
            Some("2026-09-02T09:00:00.000Z")
        );
        assert_eq!(
            refresh.next_full_refresh_eligible_at.as_deref(),
            Some("2026-09-02T15:00:00.000Z")
        );

        // An unknown deferral token is never echoed, and the eligibility only
        // projects while that deferral is the reason.
        let state = StandbyRefreshState {
            last_deferral: Some("free-form prose".into()),
            next_full_refresh_eligible_at: Some("2026-09-02T15:00:00Z".into()),
            ..StandbyRefreshState::default()
        };
        std::fs::write(
            provider
                .runtime
                .replica_root
                .join("refresh")
                .join("state.json"),
            serde_jcs::to_vec(&state).unwrap(),
        )
        .unwrap();
        let status = provider
            .status_at("2026-09-02T12:00:03Z".parse().unwrap())
            .await;
        assert_eq!(status.refresh.last_deferral, None);
        assert_eq!(status.refresh.next_full_refresh_eligible_at, None);
    }

    #[tokio::test]
    async fn refresh_diagnostics_are_reread_and_missing_is_not_reported_as_success() {
        let provider = provider("2026-09-02T12:00:00Z");
        let before = provider
            .status_at("2026-09-02T12:00:01Z".parse().unwrap())
            .await;
        assert_eq!(
            before.refresh.diagnostics,
            StandbyRefreshDiagnosticsState::NeverRecorded
        );
        assert_eq!(before.refresh.last_success_at, None);
        assert!(before.degraded_reasons.contains(&"refresh_never_recorded"));

        let refresh_dir = provider.runtime.replica_root.join("refresh");
        std::fs::create_dir_all(&refresh_dir).unwrap();
        let attempt_owner = std::fs::File::create(refresh_dir.join("attempt.lock")).unwrap();
        fs2::FileExt::lock_exclusive(&attempt_owner).unwrap();
        let state = StandbyRefreshState {
            refresh_active: true,
            last_attempt_at: Some("2026-09-02T12:00:01Z".into()),
            last_attempt_cause: Some(super::super::RefreshCause::Startup),
            ..StandbyRefreshState::default()
        };
        std::fs::write(
            refresh_dir.join("state.json"),
            serde_jcs::to_vec(&state).unwrap(),
        )
        .unwrap();

        let after = provider
            .status_at("2026-09-02T12:00:02Z".parse().unwrap())
            .await;
        assert_eq!(
            after.refresh.diagnostics,
            StandbyRefreshDiagnosticsState::Available
        );
        assert_eq!(after.refresh.refresh_active, Some(true));
        assert_eq!(
            after.refresh.last_attempt_cause,
            Some(super::super::RefreshCause::Startup)
        );
        assert!(!after.degraded_reasons.contains(&"refresh_never_recorded"));
    }

    #[test]
    fn serving_and_newer_accepted_generations_remain_distinct() {
        let mut provider = provider("2026-09-02T12:00:00Z");
        provider.runtime.hosted_route_database_id = "r".repeat(256);
        let serving_id = "c".repeat(64);
        let accepted_id = "f".repeat(64);
        let accepted = super::super::InstalledGeneration {
            id: accepted_id.clone(),
            snapshot_path: provider.runtime.replica_root.join("not-disclosed.db"),
            manifest: manifest("2026-09-02T12:04:00Z", "2026-09-02T12:04:01Z"),
        };
        let refresh = StandbyRefreshState {
            installed_generation_id: Some(accepted_id.clone()),
            last_attempt_at: Some("2026-09-02T12:04:03Z".into()),
            last_attempt_cause: Some(super::super::RefreshCause::Scheduled),
            last_success_at: Some("2026-09-02T12:04:03Z".into()),
            snapshot_captured_at: Some("2026-09-02T12:04:00Z".into()),
            snapshot_completed_at: Some("2026-09-02T12:04:01Z".into()),
            promoted_at: Some("2026-09-02T12:04:02Z".into()),
            frontier: Some(frontier()),
            ..StandbyRefreshState::default()
        };
        let mut observed_store =
            store_status(Some(accepted), GenerationProvenanceStatus::Available);
        observed_store.retained_generation_ids =
            (0..20).map(|index| format!("{index:064x}")).collect();
        let mut status = build_status(
            &provider,
            observed_store,
            RefreshStateObservation::Available(Box::new(refresh)),
            "2026-09-02T12:05:01Z".parse().unwrap(),
        );

        assert_eq!(
            status
                .serving_generation
                .as_ref()
                .map(|generation| generation.generation_id.as_str()),
            Some(serving_id.as_str())
        );
        assert_eq!(
            status
                .accepted_generation
                .as_ref()
                .map(|generation| generation.generation_id.as_str()),
            Some(accepted_id.as_str())
        );
        assert_eq!(
            status
                .accepted_generation
                .as_ref()
                .and_then(|generation| generation.promoted_at.as_deref()),
            Some("2026-09-02T12:04:02.000Z")
        );
        assert_eq!(status.freshness.age_seconds, Some(301));
        assert_eq!(status.freshness.state, StandbyFreshnessState::BeyondRpo);
        assert_eq!(status.retained_generation_count, 20);
        assert_eq!(status.retained_generation_ids.len(), 8);
        assert!(status.retained_generation_ids_truncated);
        // A replacement consumer can leave rebind receipts on both generations.
        // Full status is allowed to exceed bootstrap's component budget; it
        // must remain exact on the separate diagnostic surface.
        for generation in [
            &mut status.serving_generation,
            &mut status.accepted_generation,
        ] {
            let generation = generation.as_mut().unwrap();
            generation.consumer_rebind = Some(super::super::ConsumerRebind {
                contract: "native.standby-consumer-rebind.v1".into(),
                version: 1,
                generation_id: generation.generation_id.clone(),
                original_consumer: generation.consumer.clone(),
                accepted_consumer: provider.observed.clone().unwrap(),
                native_interchange_revision: 8,
                accepted_at: "2026-09-02T12:04:02.000Z".into(),
                checks_passed: [
                    "generation-route-origin",
                    "manifest",
                    "format",
                    "checkpoint-bytes-or-consistent-copy",
                    "engine-frontier",
                    "sqlite-quick-check-foreign-keys",
                ]
                .map(str::to_owned)
                .to_vec(),
            });
        }
        status.refresh.transfer_progress = Some(super::super::StandbyTransferProgress {
            stage: super::super::StandbyTransferStage::Verification,
            activity: super::super::StandbyTransferActivity::Active,
            updated_at: "2026-09-02T12:05:00Z".into(),
            bytes_completed: Some(2_395_116_798),
            bytes_remaining: Some(0),
            bytes_total: Some(2_395_116_798),
            retained_for_resume: true,
        });
        let full_status = serde_json::to_value(&status).unwrap();
        let status_bytes = serde_json::to_vec(&full_status).unwrap().len();
        assert!(
            status_bytes + 1024 > 8 * 1024,
            "fixture must reproduce the old budget failure: {status_bytes}"
        );
        let summary = status.bootstrap_summary();
        // Leave 3 KiB for registry/executor discovery, including lean routing.
        let summary_bytes = serde_json::to_vec(&summary).unwrap().len();
        assert!(
            summary_bytes + 3 * 1024 <= 8 * 1024,
            "bootstrap summary leaves insufficient discovery headroom: {summary_bytes} bytes"
        );
        assert_eq!(summary["status_scope"], "bootstrap_summary");
        assert_eq!(summary["full_status_tool"], "standby_status");
        for key in [
            "freshness",
            "serving_audit",
            "refresh",
            "degraded",
            "degraded_reasons",
            "next_safe_action",
            "mode",
            "read_only",
            "writes_supported",
            "run_persistence",
            "mutation_error",
            "canonical_authority",
        ] {
            assert_eq!(summary[key], full_status[key], "{key}");
        }
        for key in ["serving_generation", "accepted_generation"] {
            assert_eq!(
                summary[key]["generation_id"],
                full_status[key]["generation_id"]
            );
            assert_eq!(summary[key]["synced_at"], full_status[key]["synced_at"]);
            assert_eq!(
                summary[key]["consumer_rebound_at"],
                full_status[key]["consumer_rebind"]["accepted_at"]
            );
            assert!(summary[key].get("consumer_rebind").is_none());
            assert!(full_status[key]["consumer_rebind"]["checks_passed"].is_array());
        }
        assert!(status
            .degraded_reasons
            .contains(&"accepted_generation_pending_restart"));
        assert_eq!(
            status.next_safe_action,
            Some("restart the standby to activate the newer accepted generation")
        );
        assert!(!serde_json::to_string(&status)
            .unwrap()
            .contains("not-disclosed.db"));
    }

    /// Deltas that stay blocked for more than ten ticks - by a reader that
    /// never upgraded, or by a local read that keeps the copy open - are a
    /// degraded state with a plain next step, in both the bounded context and
    /// the full status.
    #[test]
    fn persistently_blocked_deltas_are_degraded_with_a_next_step() {
        use super::super::generation_store::DeltaDeferral;

        let now: DateTime<Utc> = "2026-09-02T12:00:30Z".parse().unwrap();
        let provider = provider("2026-09-02T12:00:00Z");
        let id = "c".repeat(64);
        for (cause, reason, action) in [
            (
                DeltaDeferral::ReaderNotUpgraded,
                "reader_not_upgraded",
                READER_NOT_UPGRADED_ACTION,
            ),
            (
                DeltaDeferral::DatabaseBusy,
                "database_busy",
                DATABASE_BUSY_ACTION,
            ),
        ] {
            provider.store.note_deferral(&id, cause, false);
            for (ticks, degraded) in [(0, false), (10, false), (11, true)] {
                let have = match cause {
                    DeltaDeferral::ReaderNotUpgraded => {
                        provider.store.deferral_counts(&id).reader_not_upgraded
                    }
                    DeltaDeferral::DatabaseBusy => {
                        provider.store.deferral_counts(&id).database_busy
                    }
                };
                for _ in have..ticks {
                    provider.store.note_deferral(&id, cause, true);
                }
                let context = provider.response_context_at(now);
                let status = build_status(
                    &provider,
                    store_status(None, GenerationProvenanceStatus::Available),
                    RefreshStateObservation::NeverRecorded,
                    now,
                );
                for (reasons, next) in [
                    (&context.degraded_reasons, context.next_safe_action),
                    (&status.degraded_reasons, status.next_safe_action),
                ] {
                    assert_eq!(reasons.contains(&reason), degraded, "{reason} {ticks}");
                    assert_eq!(next == Some(action), degraded, "{reason} {ticks}");
                }
            }
            provider.store.note_deferral(&id, cause, false);
            assert_eq!(provider.store.deferral_counts(&id), Default::default());
        }
    }

    #[test]
    fn missing_or_invalid_accepted_provenance_never_claims_an_accepted_generation() {
        let provider = provider("2026-09-02T12:00:00Z");
        for (provenance, label, reason) in [
            (
                GenerationProvenanceStatus::Missing,
                "missing",
                "accepted_generation_provenance_missing",
            ),
            (
                GenerationProvenanceStatus::Invalid,
                "invalid",
                "accepted_generation_provenance_invalid",
            ),
        ] {
            let status = build_status(
                &provider,
                store_status(None, provenance),
                RefreshStateObservation::NeverRecorded,
                "2026-09-02T12:00:01Z".parse().unwrap(),
            );
            assert!(status.accepted_generation.is_none());
            assert_eq!(status.accepted_generation_provenance, label);
            assert!(status.degraded);
            assert!(status.degraded_reasons.contains(&reason));
            assert!(status
                .next_safe_action
                .unwrap()
                .contains("inspect standby provenance"));
        }
    }

    #[test]
    fn status_only_never_claims_freshness_or_write_capability() {
        let mut provider = provider("2026-09-02T12:00:00Z");
        provider.serving = None;
        provider.status_only = Some(StandbyStatusOnly {
            reason: "no_usable_generation".into(),
            candidate_count: 1,
            unusable_candidate_count: 1,
        });
        let status = build_status(
            &provider,
            unavailable_store_status(),
            RefreshStateObservation::NeverRecorded,
            "2026-09-02T12:00:01Z".parse().unwrap(),
        );
        assert_eq!(status.mode, StandbyStatusMode::StatusOnly);
        assert_eq!(status.freshness.state, StandbyFreshnessState::Unavailable);
        assert!(!status.writes_supported);
        assert!(!status.pending_writes_supported);
        assert!(status.serving_generation.is_none());
    }

    #[test]
    fn status_projects_process_lifetime_verification_passes() {
        // Injected stats, not the process-global counters: other tests run
        // full verifications in parallel, so sampling the globals here and
        // asserting equality after `build_status` would race. Exact values
        // prove the projection is wired; the churn test proves the counters
        // themselves increment on a full pass.
        let provider = provider("2026-09-02T12:00:00Z");
        let status = super::build_status_with_verification(
            &provider,
            unavailable_store_status(),
            RefreshStateObservation::NeverRecorded,
            Some("2026-09-02T12:00:01Z".parse().unwrap()),
            (7, 12_345),
        );
        assert_eq!(status.verification_passes, 7);
        assert_eq!(status.verification_total_seconds, 12);
    }

    #[test]
    fn response_context_is_bounded_to_immutable_serving_freshness() {
        let provider = provider("2026-09-02T12:00:00Z");
        let serving_id = "c".repeat(64);
        let context = provider.response_context_at("2026-09-02T12:05:01Z".parse().unwrap());
        assert_eq!(context.mode, StandbyStatusMode::Standby);
        assert_eq!(
            context.serving_generation_id.as_deref(),
            Some(serving_id.as_str())
        );
        assert_eq!(context.freshness.state, StandbyFreshnessState::BeyondRpo);
        assert_eq!(context.degraded_reasons, vec!["snapshot_beyond_rpo"]);
        assert!(context.freshness_degraded);
        assert!(!context.writes_supported);
    }
}
