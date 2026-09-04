//! Stable, non-secret status projection for the local standby MCP surfaces.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::standby_snapshot::{
    CanonicalFrontierV1, ObservedInstalledConsumerIdentity, StandbyConsumerIdentity,
    StandbySnapshotEngineIdentity,
};

use super::generation_store::{GenerationProvenanceStatus, GenerationStoreStatus};
use super::refresh::{observe_refresh_state, RefreshStateObservation};
use super::{
    ActivatedGeneration, GenerationStore, StandbyRefreshState, StandbyRuntimeConfig,
    StandbyStartupReason, StatusOnlyStartup,
};

pub const STANDBY_STATUS_CONTRACT: &str = "native.standby-status.v1";
pub const STANDBY_RPO_SECONDS: u64 = 300;
pub const STANDBY_REFRESH_INTERVAL_SECONDS: u64 = 120;
pub const MAX_STATUS_RETAINED_GENERATIONS: usize = 8;

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
    pub state: StandbyFreshnessState,
    pub age_seconds: Option<u64>,
    pub target_rpo_seconds: u64,
    pub target_refresh_interval_seconds: u64,
    pub beyond_rpo: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyGenerationStatus {
    pub generation_id: String,
    pub captured_at: String,
    pub snapshot_completed_at: String,
    pub promoted_at: Option<String>,
    pub frontier: CanonicalFrontierV1,
    pub engine: StandbySnapshotEngineIdentity,
    pub consumer: StandbyConsumerIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyRefreshDiagnosticsState {
    Available,
    NeverRecorded,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyRefreshStatus {
    pub configured: bool,
    pub controller_available: bool,
    pub diagnostics: StandbyRefreshDiagnosticsState,
    pub refresh_active: Option<bool>,
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
    pub refresh: StandbyRefreshStatus,
    pub installed_consumer: Option<ObservedInstalledConsumerIdentity>,
    pub consumer_compatible: Option<bool>,
    pub retained_generation_ids: Vec<String>,
    pub retained_generation_count: usize,
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
}

/// Cheap immutable warning context suitable for attachment to every MCP
/// response. Dynamic accepted-generation and refresh details deliberately stay
/// on the full async status surface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyResponseContext {
    pub status_scope: &'static str,
    pub full_status_tool: &'static str,
    pub mode: StandbyStatusMode,
    pub canonical_authority: &'static str,
    pub read_only: bool,
    pub writes_supported: bool,
    pub serving_generation_id: Option<String>,
    pub freshness: StandbyFreshness,
    pub freshness_degraded: bool,
    pub degraded_reasons: Vec<&'static str>,
    pub next_safe_action: Option<&'static str>,
}

#[derive(Clone, Debug)]
struct ServingGeneration {
    generation_id: String,
    captured_at: String,
    snapshot_completed_at: String,
    frontier: CanonicalFrontierV1,
    engine: StandbySnapshotEngineIdentity,
    consumer: StandbyConsumerIdentity,
}

/// Read-only source for the shared bootstrap and system/status projection.
///
/// The serving generation is frozen at process activation. Accepted-generation
/// and refresh diagnostics are re-read for every call, so a background refresh
/// can be disclosed without pretending the open SQLite pool hot-swapped.
#[derive(Clone, Debug)]
pub struct StandbyStatusProvider {
    runtime: StandbyRuntimeConfig,
    store: GenerationStore,
    observed: Option<ObservedInstalledConsumerIdentity>,
    serving: Option<ServingGeneration>,
    status_only: Option<StandbyStatusOnly>,
    refresh_configured: bool,
    refresh_available: bool,
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
        Self {
            runtime,
            store,
            observed: Some(observed),
            serving: Some(ServingGeneration {
                generation_id: active.generation.id.clone(),
                captured_at: active.generation.manifest.captured_at.clone(),
                snapshot_completed_at: active.generation.manifest.snapshot_completed_at.clone(),
                frontier: active.generation.manifest.frontier.clone(),
                engine: active.generation.manifest.engine.clone(),
                consumer: active.generation.manifest.consumer.clone(),
            }),
            status_only: None,
            refresh_configured,
            refresh_available,
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
        }
    }

    pub async fn status(&self) -> StandbyStatus {
        self.status_at(Utc::now()).await
    }

    pub fn response_context(&self) -> StandbyResponseContext {
        self.response_context_at(Utc::now())
    }

    fn response_context_at(&self, now: DateTime<Utc>) -> StandbyResponseContext {
        let freshness = freshness(self.serving.as_ref(), now);
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
        }
        let next_safe_action = if self.serving.is_none() {
            Some("refresh the standby, then restart it after a verified generation is accepted")
        } else if matches!(freshness.state, StandbyFreshnessState::BeyondRpo) {
            Some("restore hosted connectivity or authentication and run the supported refresh command")
        } else if matches!(freshness.state, StandbyFreshnessState::Unavailable) {
            Some("inspect standby snapshot provenance before relying on freshness")
        } else {
            None
        };
        StandbyResponseContext {
            status_scope: "serving_generation_freshness_only",
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
            freshness,
            freshness_degraded: !degraded_reasons.is_empty(),
            degraded_reasons,
            next_safe_action,
        }
    }

    async fn status_at(&self, now: DateTime<Utc>) -> StandbyStatus {
        let store_status = match &self.observed {
            Some(observed) => self.store.inspect_status(observed).await,
            None => unavailable_store_status(),
        };
        let refresh_observation = observe_refresh_state(&self.runtime.replica_root);
        build_status(self, store_status, refresh_observation, now)
    }
}

fn unavailable_store_status() -> GenerationStoreStatus {
    GenerationStoreStatus {
        current: None,
        current_provenance: GenerationProvenanceStatus::Unavailable,
        retained_generation_ids: Vec::new(),
        candidate_count: 0,
        unusable_candidate_count: 0,
        startup_reason: None,
        startup_reason_available: false,
    }
}

fn generation_status(
    generation_id: String,
    manifest: &crate::standby_snapshot::StandbySnapshotManifest,
    refresh: Option<&StandbyRefreshState>,
) -> StandbyGenerationStatus {
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
        engine: manifest.engine.clone(),
        consumer: manifest.consumer.clone(),
    }
}

fn normalized_timestamp(value: &str) -> String {
    DateTime::parse_from_rfc3339(value)
        .expect("verified standby timestamp remains valid")
        .with_timezone(&Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn build_status(
    provider: &StandbyStatusProvider,
    store: GenerationStoreStatus,
    refresh_observation: RefreshStateObservation,
    now: DateTime<Utc>,
) -> StandbyStatus {
    let observed_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let refresh_state = match &refresh_observation {
        RefreshStateObservation::Available(state) => Some(state.as_ref()),
        RefreshStateObservation::NeverRecorded | RefreshStateObservation::Unavailable => None,
    };
    let serving_generation = provider.serving.as_ref().map(|serving| {
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
            engine: serving.engine.clone(),
            consumer: serving.consumer.clone(),
        }
    });
    let accepted_generation = store.current.as_ref().map(|generation| {
        generation_status(generation.id.clone(), &generation.manifest, refresh_state)
    });
    let freshness = freshness(provider.serving.as_ref(), now);
    let refresh = refresh_status(
        refresh_observation,
        provider.refresh_configured,
        provider.refresh_available,
    );
    let consumer_compatible = match (&provider.observed, &provider.serving, &accepted_generation) {
        (Some(observed), Some(serving), _) => Some(
            serving
                .consumer
                .validate_observed_installed(observed)
                .is_ok(),
        ),
        // `inspect_status` only returns an accepted generation after deep
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
        degraded_reasons.push("accepted_generation_pending_restart");
    }
    degraded_reasons.sort_unstable();
    degraded_reasons.dedup();

    let accepted_generation_available = accepted_generation.is_some();
    let next_safe_action = if provider.serving.is_none() && accepted_generation_available {
        Some("restart the standby to activate the verified accepted generation")
    } else if provider.serving.is_none() {
        Some("refresh the standby, then restart it after a verified generation is accepted")
    } else if degraded_reasons.contains(&"refresh_authentication_failing") {
        // Ordered ahead of every action below because all of them tell the
        // owner to run a refresh, and none of them can succeed while the
        // credential is being refused. Naming connectivity or provenance first
        // would send someone round a loop that cannot terminate.
        Some("reissue the standby snapshot credential and run the supported refresh command")
    } else if matches!(
        store.current_provenance,
        GenerationProvenanceStatus::Missing
            | GenerationProvenanceStatus::Invalid
            | GenerationProvenanceStatus::Unavailable
    ) {
        Some("inspect standby provenance and run a verified refresh before relying on accepted state")
    } else if degraded_reasons.contains(&"accepted_generation_pending_restart") {
        Some("restart the standby to activate the newer accepted generation")
    } else if matches!(freshness.state, StandbyFreshnessState::BeyondRpo)
        || refresh.consecutive_failure_count.unwrap_or(0) > 0
    {
        Some("restore hosted connectivity or authentication and run the supported refresh command")
    } else if provider.refresh_configured && !provider.refresh_available {
        Some("repair the local refresh configuration before relying on the target RPO")
    } else if !provider.refresh_configured {
        Some("configure the supported background refresh controller to maintain the target RPO")
    } else {
        None
    };
    let degraded = !degraded_reasons.is_empty();

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
        },
        freshness,
        refresh,
        installed_consumer: provider.observed.clone(),
        consumer_compatible,
        retained_generation_ids,
        retained_generation_count,
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
        summary: if provider.serving.is_none() && accepted_generation_available {
            "This status-only Native standby has accepted a verified generation; restart is required before workspace reads can serve it."
        } else if provider.serving.is_none() {
            "This local Native standby has no usable verified generation and cannot serve workspace data."
        } else if degraded {
            "This is a read-only local Native standby serving non-canonical snapshot data in a degraded state."
        } else {
            "This is a read-only local Native standby serving a verified snapshot; hosted Native remains canonical."
        },
        next_safe_action,
    }
}

fn freshness(serving: Option<&ServingGeneration>, now: DateTime<Utc>) -> StandbyFreshness {
    let Some(serving) = serving else {
        return unavailable_freshness();
    };
    let Ok(captured) = DateTime::parse_from_rfc3339(&serving.captured_at) else {
        return unavailable_freshness();
    };
    let age = now.signed_duration_since(captured.with_timezone(&Utc));
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
        target_rpo_seconds: STANDBY_RPO_SECONDS,
        target_refresh_interval_seconds: STANDBY_REFRESH_INTERVAL_SECONDS,
        beyond_rpo: Some(beyond_rpo),
    }
}

fn unavailable_freshness() -> StandbyFreshness {
    StandbyFreshness {
        state: StandbyFreshnessState::Unavailable,
        age_seconds: None,
        target_rpo_seconds: STANDBY_RPO_SECONDS,
        target_refresh_interval_seconds: STANDBY_REFRESH_INTERVAL_SECONDS,
        beyond_rpo: None,
    }
}

fn refresh_status(
    observation: RefreshStateObservation,
    configured: bool,
    controller_available: bool,
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
    }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standby_snapshot::{
        StandbyConsumerPlatform, StandbySnapshotBytes, StandbySnapshotEngineIdentity,
        StandbySnapshotManifest, STANDBY_CONSUMER_CONTRACT, STANDBY_FRONTIER_CONTRACT,
        STANDBY_SNAPSHOT_MANIFEST_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
    };

    fn consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
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
                platform: StandbyConsumerPlatform::LinuxX8664,
                source_sha: "a".repeat(40),
                artifact_sha256: "b".repeat(64),
                engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
                ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
            }),
            serving: Some(ServingGeneration {
                generation_id: "c".repeat(64),
                captured_at: captured_at.into(),
                snapshot_completed_at: captured_at.into(),
                frontier: frontier(),
                engine: manifest(captured_at, captured_at).engine,
                consumer: consumer(),
            }),
            status_only: None,
            refresh_configured: true,
            refresh_available: true,
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
            Some("reissue the standby snapshot credential and run the supported refresh command"),
            "the action must name credential reissue, not generic connectivity"
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
        let status = build_status(
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
        let status_bytes = serde_json::to_vec(&status).unwrap().len();
        assert!(
            status_bytes + 1024 < 8 * 1024,
            "status plus bootstrap exposure envelope exceeded its budget: {status_bytes} bytes"
        );
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
