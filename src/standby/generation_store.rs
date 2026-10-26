use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Row};

use crate::error::{Error, Result, StandbyAdmissionCheck};
use crate::standby_snapshot::{
    ObservedInstalledConsumerIdentity, StandbyGenerationMaterialization, StandbySnapshotManifest,
};

mod consumer_rebind;
#[cfg(any(test, feature = "v2-kernel-probe"))]
mod kernel_delta;
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) use kernel_delta::{is_kernel_disk_refusal, kernel_disk_budget, INSUFFICIENT_DISK};
mod maintenance;
mod v1_pin;
mod verification_status;
pub use consumer_rebind::ConsumerRebind;

const POINTER_CONTRACT: &str = "native.standby-current-pointer.v1";
const STARTUP_STATE_CONTRACT: &str = "native.standby-startup-state.v1";
const GENERATION_HEAD_CONTRACT: &str = "native.standby-generation-head.v1";
const SERVING_READER_CONTRACT: &str = "native.standby-serving-reader.v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServingReader {
    contract: String,
    version: u32,
    generation_id: String,
    source_sha: String,
}

pub(crate) const SEQUENCED_LOGS: &[&str] = &[
    "content_events",
    "policy_events",
    "awareness_events",
    "notification_candidate_events",
    "binding_audit",
    "database_identity_audit",
    "meta_events",
    "control_events",
    "derivation_events",
    "relationship_events",
];
pub(crate) const UNSEQUENCED_APPEND_ONLY: &[&str] = &[
    "content_event_sources",
    "replicated_message_provenance",
    "destination_message_ingest",
    "replicated_message_references",
    "external_observations",
    "blobs",
    "awareness_command_intents",
    "provenance_interaction_receipts",
    "provenance_action_attestations",
    "provenance_local_attestation_authority",
    "provenance_action_events",
    "provenance_attestation_validity_events",
    "provenance_action_outputs",
    "provenance_action_app_attributions",
    "relationship_foreign_action_attestations",
    "relationship_foreign_action_outputs",
    "relationship_federation_events",
    "engine_migration_drills",
];
// These physical domains have no ratified successor log/fold. Until one exists
// a refresh may not silently replace them.
pub(crate) const UNFENCED_EXACT: &[&str] = &["storage_portability_policy"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublishTransition {
    GenerationDurable,
    PointerDurable,
}

#[derive(Clone, Debug)]
pub struct InstalledGeneration {
    pub id: String,
    pub snapshot_path: PathBuf,
    pub manifest: StandbySnapshotManifest,
}

/// The mutable serving state of one generation, kept beside its immutable
/// manifest in `accepted/heads/<generation id>.json`.
///
/// A generation's manifest describes the whole snapshot it was installed from:
/// that snapshot is the checkpoint. The refresh controller then advances the
/// current generation's database in place with authenticated whole-act deltas,
/// so after the first delta its bytes no longer match the manifest digest. This
/// record says so (`materialization: delta`), carries the act the copy was last
/// known to hold, and carries the conservative time the copy was last found
/// current against hosted Native.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationHead {
    pub contract: String,
    /// v2 certifies that every in-place delta used the authority-complete
    /// companion inventory. v1 remains readable for conservative FULL recovery.
    pub version: u32,
    pub generation_id: String,
    pub head_act: i64,
    pub materialization: StandbyGenerationMaterialization,
    /// Sampled before the hosted head probe that found this copy current, or
    /// before the probe that led to the delta which made it so.
    pub synced_at: String,
    /// Set when an explicit audit of this copy failed. The next refresh then
    /// replaces it with a whole snapshot instead of applying deltas.
    pub full_refresh_required: bool,
}

/// What blocked a delta that was otherwise ready to apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DeltaDeferral {
    /// The serving reader is not a live process of the controller's build.
    ReaderNotUpgraded,
    /// A serving read held the copy past the writer's wait.
    DatabaseBusy,
}

/// Consecutive deferred delta ticks per cause, kept beside the head record in
/// `heads/<id>.deferrals`. This is deliberately not part of the head record:
/// the count is non-zero exactly while an older build may be serving, and
/// older builds refuse a head record with fields they do not know.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeferralCounts {
    #[serde(default)]
    pub reader_not_upgraded: u32,
    #[serde(default)]
    pub database_busy: u32,
}

impl GenerationHead {
    fn checkpoint(generation: &InstalledGeneration) -> Self {
        Self {
            contract: GENERATION_HEAD_CONTRACT.into(),
            version: 2,
            generation_id: generation.id.clone(),
            head_act: generation.manifest.head_act.unwrap_or_default(),
            materialization: StandbyGenerationMaterialization::Snapshot,
            synced_at: generation.manifest.captured_at.clone(),
            full_refresh_required: false,
        }
    }

    pub fn advanced_in_place(&self) -> bool {
        self.materialization == StandbyGenerationMaterialization::Delta
    }

    /// v1 delta writers omitted local attestation authority, so their copies
    /// can be internally consistent yet miss compatibility links. A binary
    /// rebind or an unrelated v2 delta cannot establish historical completeness.
    pub(super) fn needs_projection_recovery(&self) -> bool {
        self.advanced_in_place() && self.version < 2
    }
}

/// The result of [`GenerationStore::audit_current`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StandbyAuditOutcome {
    pub generation_id: String,
    pub passed: bool,
}

/// A generation selected for serving at process startup.
///
/// The private shared lease must live for as long as the runtime may open new
/// SQLite connections by pathname. Retention takes the corresponding
/// exclusive lease before removing an older generation.
#[derive(Debug)]
pub struct ActivatedGeneration {
    pub generation: InstalledGeneration,
    pub startup_reason: Option<StandbyStartupReason>,
    pub retained_generation_ids: Vec<String>,
    pub retention_warnings: Vec<String>,
    _lease: File,
}

/// A cheap observation of the accepted descriptor, never a validation receipt.
/// Only `activate_accepted` can turn this hint into a protected generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedGenerationHint {
    generation_id: String,
    snapshot_sha256: String,
}

impl AcceptedGenerationHint {
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandbyStartupReason {
    CurrentMissing,
    CurrentUnusable,
    DurableGenerationRecovered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StatusOnlyStartup {
    pub reason: &'static str,
    pub candidate_count: usize,
    pub unusable_candidate_count: usize,
}

#[derive(Debug)]
pub enum StandbyStartupOutcome {
    Serving(Box<ActivatedGeneration>),
    StatusOnly(StatusOnlyStartup),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CurrentPointer {
    contract: String,
    version: u32,
    generation_id: String,
    snapshot_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DegradedStartupState {
    contract: String,
    version: u32,
    generation_id: String,
    reason: StandbyStartupReason,
}

#[derive(Clone, Debug)]
pub struct GenerationStore {
    root: PathBuf,
    expected_route_id: String,
    expected_origin_id: Option<String>,
    verification_status: verification_status::VerificationStatusCache,
    maintenance: std::sync::Arc<maintenance::MaintenanceControl>,
    #[cfg(test)]
    verification_pause: std::sync::Arc<std::sync::Mutex<Option<VerificationPause>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GenerationProvenanceStatus {
    Available,
    Missing,
    Invalid,
    Unavailable,
    Unverified,
}

#[derive(Clone, Debug)]
pub(super) struct GenerationStoreStatus {
    pub current: Option<InstalledGeneration>,
    pub current_provenance: GenerationProvenanceStatus,
    pub retained_generation_ids: Vec<String>,
    pub candidate_count: usize,
    pub unusable_candidate_count: usize,
    pub unverified_candidate_count: usize,
    pub startup_reason: Option<StandbyStartupReason>,
    pub startup_reason_available: bool,
}

#[cfg(test)]
type VerificationPause = (
    std::sync::Arc<tokio::sync::Notify>,
    std::sync::Arc<tokio::sync::Notify>,
);

impl GenerationStore {
    /// Observe only the small current descriptor. No historical proof is
    /// inferred from its hashes, timestamps, or previous completion events.
    pub fn accepted_identity_hint(&self) -> Result<Option<AcceptedGenerationHint>> {
        match self.read_pointer() {
            Ok(pointer) => Ok(Some(AcceptedGenerationHint {
                generation_id: pointer.generation_id,
                snapshot_sha256: pointer.snapshot_sha256,
            })),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Observe published directories as well as the pointer, including a
    /// durable rename interrupted before pointer publication. Manifest reads
    /// here are only scheduling hints: no byte/history proof is cached.
    pub fn handoff_candidates_hint(&self) -> Result<Vec<AcceptedGenerationHint>> {
        let pointer = self.accepted_identity_hint()?;
        let mut generations = Vec::new();
        for id in self.generation_ids()? {
            if let Ok(generation) = self.verify_generation_identity(&id) {
                generations.push(generation);
            }
        }
        generations.sort_by(compare_generation_newest_first);
        if let Some(pointer) = &pointer {
            if let Some(current) = generations
                .iter()
                .find(|generation| generation.id == pointer.generation_id)
                .cloned()
            {
                generations.retain(|generation| {
                    generation.id != current.id
                        // Engine switches require an explicitly published pointer.
                        // In particular, do not undo an operator's v1 rollback
                        // by rediscovering retained v2 files as durable orphans.
                        && generation.manifest.kernel_v2.is_some()
                            == current.manifest.kernel_v2.is_some()
                        && compare_generation_newest_first(generation, &current)
                            == std::cmp::Ordering::Less
                });
            }
        }
        let mut hints = generations
            .into_iter()
            .map(|generation| AcceptedGenerationHint {
                generation_id: generation.id,
                snapshot_sha256: generation.manifest.snapshot.sha256,
            })
            .collect::<Vec<_>>();
        if let Some(pointer) = pointer {
            hints.insert(0, pointer);
        }
        Ok(hints)
    }

    /// Pin a published candidate and the accepted predecessor under the
    /// promotion lock, then run device verification outside that lock.
    /// Unlike startup, a hot successor is always fenced by the actual serving
    /// generation; recovery never authorises a hot downgrade.
    pub async fn activate_accepted(
        &self,
        hint: &AcceptedGenerationHint,
        observed: &ObservedInstalledConsumerIdentity,
        predecessor: Option<&ActivatedGeneration>,
    ) -> Result<ActivatedGeneration> {
        let (lease, accepted, accepted_lease) = {
            let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
            let generation = self.verify_generation_identity(&hint.generation_id)?;
            if generation.manifest.snapshot.sha256 != hint.snapshot_sha256 {
                return Err(Error::engine("standby accepted descriptor digest mismatch"));
            }
            let accepted = self.accepted_identity_hint()?;
            let accepted_lease = accepted
                .as_ref()
                .filter(|current| *current != hint)
                .map(|current| self.acquire_serving_lease(&current.generation_id))
                .transpose()?;
            (
                self.acquire_serving_lease(&hint.generation_id)?,
                accepted,
                accepted_lease,
            )
        };
        // Every new candidate takes the device verifier: authenticity,
        // binding, compatibility, SQLite health and read-only safety. Full
        // conformance (rebuild-and-diff, relationship history, awareness
        // rebuild) is not a device gate per ratified decision e15d82a; it
        // lives on the hosted side and in CI.
        let generation = self
            .verify_generation_for_startup(&hint.generation_id, observed)
            .await?;
        if generation.manifest.snapshot.sha256 != hint.snapshot_sha256 {
            return Err(Error::engine("standby accepted snapshot identity changed"));
        }
        let mut recover_durable = accepted.is_none();
        if let Some(current) = accepted.as_ref().filter(|current| *current != hint) {
            let previous = self
                .verify_reader_predecessor(&current.generation_id, observed, predecessor)
                .await?;
            if previous.manifest.snapshot.sha256 != current.snapshot_sha256 {
                return Err(Error::engine(
                    "standby accepted predecessor identity changed",
                ));
            }
            match compare_generation_newest_first(&generation, &previous) {
                std::cmp::Ordering::Less => {
                    if !generation.manifest.frontier_follows(&previous.manifest)? {
                        return Err(Error::engine(
                            "standby durable successor regresses accepted state",
                        ));
                    }
                    verify_database_successor(&previous.snapshot_path, &generation.snapshot_path)
                        .await?;
                    recover_durable = true;
                }
                std::cmp::Ordering::Greater => {
                    // Acceptance moved ahead before the candidate could pin.
                    // Fully prove that the desired generation preserves this
                    // candidate too, then finish its pinned readiness. The
                    // actual serving floor below still forbids hot downgrades.
                    if !previous.manifest.frontier_follows(&generation.manifest)? {
                        return Err(Error::engine(
                            "standby moving acceptance diverges from candidate",
                        ));
                    }
                    verify_database_successor(&generation.snapshot_path, &previous.snapshot_path)
                        .await?;
                }
                std::cmp::Ordering::Equal => {
                    return Err(Error::engine("standby ambiguous accepted identity"))
                }
            }
        }
        if let Some(predecessor) = predecessor {
            let previous = self
                .verify_reader_predecessor(&predecessor.generation.id, observed, Some(predecessor))
                .await?;
            if previous.manifest != predecessor.generation.manifest
                || previous.id == generation.id
                || !generation.manifest.frontier_follows(&previous.manifest)?
                || chrono::DateTime::parse_from_rfc3339(&generation.manifest.captured_at)
                    .map_err(|_| Error::engine("invalid standby capture time"))?
                    < chrono::DateTime::parse_from_rfc3339(&previous.manifest.captured_at)
                        .map_err(|_| Error::engine("invalid standby predecessor capture time"))?
            {
                return Err(Error::engine(
                    "standby hot successor regresses serving state",
                ));
            }
            verify_database_successor(&previous.snapshot_path, &generation.snapshot_path).await?;
        }
        check_verification_cancellation()?;
        // Complete only the already-proven durable orphan transition. A moving
        // acceptance is coalesced by the watcher, never overwritten or chased
        // by cancelling a pinned verification repeatedly.
        if recover_durable {
            let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
            if self.accepted_identity_hint()? == accepted {
                self.write_degraded_startup_state(&DegradedStartupState {
                    contract: STARTUP_STATE_CONTRACT.into(),
                    version: 1,
                    generation_id: generation.id.clone(),
                    reason: StandbyStartupReason::DurableGenerationRecovered,
                })?;
                self.write_pointer(&CurrentPointer {
                    contract: POINTER_CONTRACT.into(),
                    version: 1,
                    generation_id: generation.id.clone(),
                    snapshot_sha256: generation.manifest.snapshot.sha256.clone(),
                })?;
            }
        }
        self.refresh_cached_pointer(&generation.id, observed);
        drop(accepted_lease);
        Ok(ActivatedGeneration {
            generation,
            startup_reason: None,
            retained_generation_ids: Vec::new(),
            retention_warnings: Vec::new(),
            _lease: lease,
        })
    }

    /// Recheck the moving desired state after readiness. The candidate remains
    /// device-verified and pinned; a valid newer hint need not starve its handoff.
    /// Malformed, missing, mismatched or backward descriptors refuse publication.
    pub fn confirm_handoff(&self, active: &ActivatedGeneration) -> Result<()> {
        let current = self
            .accepted_identity_hint()?
            .ok_or_else(|| Error::engine("standby accepted descriptor disappeared"))?;
        let generation = self.verify_generation_identity(&current.generation_id)?;
        if generation.manifest.snapshot.sha256 != current.snapshot_sha256
            || (generation.id != active.generation.id
                && compare_generation_newest_first(&generation, &active.generation)
                    != std::cmp::Ordering::Less)
        {
            return Err(Error::engine(
                "standby accepted descriptor regressed during readiness",
            ));
        }
        Ok(())
    }

    pub fn open(
        root: impl Into<PathBuf>,
        expected_route_id: impl Into<String>,
        expected_origin_id: Option<String>,
    ) -> Result<Self> {
        let base = root.into();
        require_unambiguous_store_path(&base)?;
        create_private_directory(&base)?;
        let root = base.join("accepted");
        create_private_directory(&root)?;
        create_private_directory(&root.join("staging"))?;
        create_private_directory(&root.join("generations"))?;
        create_private_directory(&root.join("leases"))?;
        create_private_directory(&root.join("heads"))?;
        let expected_route_id = expected_route_id.into();
        if expected_route_id.trim().is_empty() {
            return Err(Error::engine("standby expected route id is empty"));
        }
        Ok(Self {
            root,
            expected_route_id,
            expected_origin_id,
            verification_status: Default::default(),
            maintenance: Default::default(),
            #[cfg(test)]
            verification_pause: Default::default(),
        })
    }

    /// Read-only: would [`GenerationStore::open`] accept the directories that
    /// already exist under `root`? Applies the same path and directory rules,
    /// in the same order, without creating or changing anything. Levels that do
    /// not exist are skipped (`open` creates them 0700) and the rest are still
    /// checked, so a partial tree is judged as `open` would judge it.
    /// `Ok(false)` means nothing exists there yet.
    /// `native setup` asks this before it writes any config.
    pub fn check_existing_root(root: &Path) -> Result<bool> {
        require_unambiguous_store_path(root)?;
        let accepted = root.join("accepted");
        let mut found = false;
        for directory in [
            root.to_path_buf(),
            accepted.clone(),
            accepted.join("staging"),
            accepted.join("generations"),
            accepted.join("leases"),
            accepted.join("heads"),
        ] {
            // A missing level is one `open` would create 0700; the levels
            // below it may still exist and be wrong, so keep going.
            match fs::symlink_metadata(&directory) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            }
            check_private_directory(&directory)?;
            found = true;
        }
        Ok(found)
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    /// Resolve the immutable generation named by the durable pointer without
    /// hashing or opening its database. This is the no-op refresh hot path;
    /// a generation returned here is identity/pointer checked but is not yet a
    /// trusted delta base.
    pub(super) fn current_for_head_probe(&self) -> Result<Option<InstalledGeneration>> {
        let pointer = match self.read_pointer() {
            Ok(pointer) => pointer,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let generation = self.verify_generation_identity(&pointer.generation_id)?;
        if generation.manifest.snapshot.sha256 != pointer.snapshot_sha256 {
            return Err(Error::engine(
                "standby current pointer digest does not match its generation",
            ));
        }
        Ok(Some(generation))
    }

    /// Deliberate off-path deep audit: run the full verifier (integrity,
    /// observational conformance including rebuild-and-diff, awareness
    /// reconstruction) over the current copy, including one that deltas have
    /// advanced in place. It never runs on the refresh, startup, status or
    /// serving paths, and it never gates serving: a failure leaves the copy
    /// serving but makes the next refresh replace it with a whole snapshot.
    /// This preserves the pre-e15d82a deep audit as an opt-in early warning,
    /// not a device gate.
    pub async fn audit_current(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<StandbyAuditOutcome> {
        let pointer = self.read_pointer()?;
        let generation = self.verify_generation_identity(&pointer.generation_id)?;
        let before = self.status_stamp(&pointer.generation_id, observed).ok();
        let passed = match verify_generation_for_audit(self, &pointer.generation_id, observed).await
        {
            Ok(verified) => verified.manifest.snapshot.sha256 == pointer.snapshot_sha256,
            // Running out of scratch space, a busy lock or cancellation says
            // nothing about the copy: report it without forcing a full copy.
            Err(error) if audit_infrastructure_error(&error) => return Err(error),
            Err(_) => false,
        };
        if !passed {
            self.require_full_refresh(&generation)?;
            self.cache_completed_verification(&generation.id, observed, false);
        } else {
            self.remember_verification(&generation.id, observed, before, true);
        }
        Ok(StandbyAuditOutcome {
            generation_id: generation.id,
            passed,
        })
    }

    /// Inspect accepted generations for status disclosure without changing the
    /// pointer, retention, or any immutable generation. Results are cached
    /// observations from completed device checks, invalidated by input changes;
    /// inspection never copies or verifies a database.
    pub(super) async fn inspect_status(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> GenerationStoreStatus {
        let candidate_ids = match self.generation_ids() {
            Ok(ids) => ids,
            Err(_) => {
                return GenerationStoreStatus {
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
        };
        let mut usable = Vec::new();
        let mut unusable_candidate_count = 0;
        let mut unverified_candidate_count = 0;
        for id in &candidate_ids {
            match self.verify_generation_identity(id) {
                Ok(generation) => match self.cached_verification(id, observed) {
                    Some(true) => usable.push(generation),
                    Some(false) => unusable_candidate_count += 1,
                    None => unverified_candidate_count += 1,
                },
                Err(error) if audit_infrastructure_error(&error) => unverified_candidate_count += 1,
                Err(_) => unusable_candidate_count += 1,
            }
        }
        usable.sort_by(compare_generation_newest_first);
        let retained_generation_ids = usable
            .iter()
            .map(|generation| generation.id.clone())
            .collect::<Vec<_>>();

        let (current, current_provenance) = match self.read_pointer() {
            Ok(pointer) => match usable.iter().find(|generation| {
                generation.id == pointer.generation_id
                    && generation.manifest.snapshot.sha256 == pointer.snapshot_sha256
            }) {
                Some(generation) => (
                    Some(generation.clone()),
                    GenerationProvenanceStatus::Available,
                ),
                None => match self.verify_generation_identity(&pointer.generation_id) {
                    Ok(generation)
                        if generation.manifest.snapshot.sha256 == pointer.snapshot_sha256 =>
                    {
                        (
                            None,
                            if self.cached_verification(&generation.id, observed) == Some(false) {
                                GenerationProvenanceStatus::Invalid
                            } else {
                                GenerationProvenanceStatus::Unverified
                            },
                        )
                    }
                    _ => (None, GenerationProvenanceStatus::Invalid),
                },
            },
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                (None, GenerationProvenanceStatus::Missing)
            }
            Err(Error::Io(_)) => (None, GenerationProvenanceStatus::Unavailable),
            Err(_) => (None, GenerationProvenanceStatus::Invalid),
        };
        let (startup_reason, startup_reason_available) = match self.recorded_startup_reason() {
            Ok(reason) => (reason, true),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (None, true),
            Err(_) => (None, false),
        };

        GenerationStoreStatus {
            current,
            current_provenance,
            retained_generation_ids,
            candidate_count: candidate_ids.len(),
            unusable_candidate_count,
            unverified_candidate_count,
            startup_reason,
            startup_reason_available,
        }
    }

    pub async fn install_staged(
        &self,
        snapshot: &Path,
        manifest_path: &Path,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<InstalledGeneration> {
        self.install_staged_observing_publication(snapshot, manifest_path, observed, || Ok(()))
            .await
    }

    /// Observe publication only after the unchanged admission checks succeed.
    /// The observer receives no candidate bytes or paths and cannot bypass a check.
    pub(super) async fn install_staged_observing_publication(
        &self,
        snapshot: &Path,
        manifest_path: &Path,
        observed: &ObservedInstalledConsumerIdentity,
        mut publication: impl FnMut() -> Result<()>,
    ) -> Result<InstalledGeneration> {
        let generation = self
            .install_staged_with_hook(snapshot, manifest_path, observed, |transition| {
                if transition == PublishTransition::GenerationDurable {
                    publication()?;
                }
                Ok(())
            })
            .await?;
        self.cache_completed_verification(&generation.id, observed, true);
        Ok(generation)
    }

    /// Recover and select the immutable generation this process may serve.
    ///
    /// "Newest" is authority capture order: parsed `captured_at`, then
    /// `snapshot_completed_at`, then generation id. Filesystem iteration order
    /// and mtimes are deliberately irrelevant. Invalid generations are left in
    /// place for bounded diagnosis; retention removes only device-verified,
    /// unleased known-good generations.
    pub async fn activate_for_startup(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<StandbyStartupOutcome> {
        tracing::info!(target: "native_ce::standby::verification", "standby startup verification started");
        let started = std::time::Instant::now();
        let result = self.activate_for_startup_contents(observed).await;
        tracing::info!(target: "native_ce::standby::verification",
            elapsed_ms = started.elapsed().as_millis(), ok = result.is_ok(),
            serving = matches!(&result, Ok(StandbyStartupOutcome::Serving(_))),
            "standby startup verification finished");
        result
    }

    async fn activate_for_startup_contents(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<StandbyStartupOutcome> {
        if self.expected_origin_id.is_none() {
            return Err(Error::engine(
                "standby startup requires a configured origin database id",
            ));
        }
        let _promotion_lock = verification_phase(
            "startup-lock",
            acquire_promotion_lock(self.root.join("promotion.lock")),
        )
        .await?;
        let retention_warnings = verification_phase("startup-cleanup", async {
            let mut warnings = self.cleanup_pruning_workspaces();
            warnings.extend(self.cleanup_rebind_temps());
            Ok(warnings)
        })
        .await?;
        let selection_started = std::time::Instant::now();
        let pointer = self.read_pointer();
        let pointer_generation = pointer
            .as_ref()
            .ok()
            .map(|value| value.generation_id.clone());
        let pointer_missing = matches!(
            &pointer,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
        );

        let candidate_ids = self.generation_ids()?;
        // Manifest identity is a scheduling hint, not a device-verification
        // receipt. It lets us order candidates without copying their databases.
        let mut candidates = Vec::new();
        let mut unusable_candidate_count = 0;
        for id in &candidate_ids {
            match self.verify_generation_identity(id) {
                Ok(generation) => candidates.push(generation),
                Err(_) => unusable_candidate_count += 1,
            }
        }
        candidates.sort_by(compare_generation_newest_first);
        let pointer_verified = if let Ok(pointer) = &pointer {
            match self
                .verify_generation_for_startup(&pointer.generation_id, observed)
                .await
            {
                Ok(generation) => Some(generation),
                Err(_) => {
                    if candidates
                        .iter()
                        .any(|candidate| candidate.id == pointer.generation_id)
                    {
                        unusable_candidate_count += 1;
                    }
                    None
                }
            }
        } else {
            None
        };
        let current = pointer_verified
            .as_ref()
            .filter(|generation| {
                pointer.as_ref().is_ok_and(|pointer| {
                    generation.manifest.snapshot.sha256 == pointer.snapshot_sha256
                })
            })
            .cloned();
        let mut selected = current.clone();
        let mut startup_reason = if pointer_missing {
            Some(StandbyStartupReason::CurrentMissing)
        } else if current.is_none() {
            Some(StandbyStartupReason::CurrentUnusable)
        } else {
            None
        };

        // Preserve durable-successor recovery, but never verify an older prior
        // merely to serve a healthy current. If current failed, stop at the
        // first usable fallback in authority-capture order.
        for candidate in &candidates {
            if pointer_generation.as_deref() == Some(&candidate.id) {
                if current.is_none() {
                    if let Some(generation) = &pointer_verified {
                        selected = Some(generation.clone());
                        break;
                    }
                }
                continue;
            }
            if let Some(current) = &current {
                if candidate.manifest.kernel_v2.is_some() != current.manifest.kernel_v2.is_some() {
                    continue;
                }
                if compare_generation_newest_first(candidate, current) != std::cmp::Ordering::Less {
                    break;
                }
            }
            let candidate = match self
                .verify_generation_for_startup(&candidate.id, observed)
                .await
            {
                Ok(candidate) => candidate,
                Err(_) => {
                    unusable_candidate_count += 1;
                    continue;
                }
            };
            if let Some(current) = &current {
                if !candidate.manifest.frontier_follows(&current.manifest)?
                    || verify_database_successor(&current.snapshot_path, &candidate.snapshot_path)
                        .await
                        .is_err()
                {
                    continue;
                }
                startup_reason = Some(StandbyStartupReason::DurableGenerationRecovered);
            }
            selected = Some(candidate);
            break;
        }

        let Some(selected) = selected else {
            tracing::info!(target: "native_ce::standby::verification", phase = "startup-selection",
                elapsed_ms = selection_started.elapsed().as_millis(), serving = false,
                "standby startup phase finished");
            return Ok(StandbyStartupOutcome::StatusOnly(StatusOnlyStartup {
                reason: "no_usable_generation",
                candidate_count: candidate_ids.len(),
                unusable_candidate_count,
            }));
        };

        if pointer_generation.as_deref() != Some(selected.id.as_str())
            || pointer
                .as_ref()
                .ok()
                .is_none_or(|value| value.snapshot_sha256 != selected.manifest.snapshot.sha256)
        {
            if let Some(reason) = startup_reason {
                self.write_degraded_startup_state(&DegradedStartupState {
                    contract: STARTUP_STATE_CONTRACT.into(),
                    version: 1,
                    generation_id: selected.id.clone(),
                    reason,
                })?;
            }
            self.write_pointer(&CurrentPointer {
                contract: POINTER_CONTRACT.into(),
                version: 1,
                generation_id: selected.id.clone(),
                snapshot_sha256: selected.manifest.snapshot.sha256.clone(),
            })?;
        }

        self.refresh_cached_pointer(&selected.id, observed);
        let lease = self.acquire_serving_lease(&selected.id)?;
        tracing::info!(target: "native_ce::standby::verification", phase = "startup-selection",
            elapsed_ms = selection_started.elapsed().as_millis(), "standby startup phase finished");
        tracing::info!(target: "native_ce::standby::verification", phase = "startup-prune",
            elapsed_ms = 0_u64, deferred = true, "standby startup phase finished");
        let mut retained_generation_ids = self.generation_ids()?;
        retained_generation_ids.sort();
        Ok(StandbyStartupOutcome::Serving(Box::new(
            ActivatedGeneration {
                generation: selected,
                startup_reason,
                retained_generation_ids,
                retention_warnings,
                _lease: lease,
            },
        )))
    }

    /// Converge retention after a refresh without requiring an MCP restart.
    ///
    /// Selection remains pointer-authoritative and every deletion candidate is
    /// device-verified against the installed consumer. Per-generation
    /// failures are returned as bounded warnings so cleanup cannot make a
    /// verified current generation unavailable.
    pub async fn prune_retention(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<Vec<String>> {
        self.maintain_generations(observed, false).await
    }

    /// Return the durable fallback/recovery reason that still applies to the
    /// current pointer. A marker for an older generation is historical and is
    /// deliberately ignored after a later successful promotion.
    pub fn recorded_startup_reason(&self) -> Result<Option<StandbyStartupReason>> {
        let path = self.root.join("startup-state.json");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        require_regular_no_symlink(&path)?;
        let state: DegradedStartupState = serde_json::from_slice(&bytes)?;
        if state.contract != STARTUP_STATE_CONTRACT
            || state.version != 1
            || !is_generation_id(&state.generation_id)
        {
            return Err(Error::engine("invalid standby startup state"));
        }
        let pointer = self.read_pointer()?;
        Ok((state.generation_id == pointer.generation_id).then_some(state.reason))
    }

    async fn install_staged_with_hook<F>(
        &self,
        snapshot: &Path,
        manifest_path: &Path,
        observed: &ObservedInstalledConsumerIdentity,
        transition: F,
    ) -> Result<InstalledGeneration>
    where
        F: FnMut(PublishTransition) -> Result<()>,
    {
        self.install_staged_with_hook_mode(snapshot, manifest_path, observed, false, transition)
            .await
    }

    // Only the private, closed scratch-delta witness may transfer ownership.
    // FULL/download callers always retain the copy-based admission path.
    async fn install_staged_with_hook_mode<F>(
        &self,
        snapshot: &Path,
        manifest_path: &Path,
        observed: &ObservedInstalledConsumerIdentity,
        take_snapshot: bool,
        mut transition: F,
    ) -> Result<InstalledGeneration>
    where
        F: FnMut(PublishTransition) -> Result<()>,
    {
        let _lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
        require_direct_regular_child(snapshot, &self.staging_dir())?;
        require_direct_regular_child(manifest_path, &self.staging_dir())?;
        let generations = self.root.join("generations");
        let publishing_guard = tempfile::Builder::new()
            .prefix(".publishing-")
            .tempdir_in(&generations)?;
        let publishing = publishing_guard.path().to_path_buf();
        set_mode(&publishing, 0o700)?;
        let owned_snapshot = publishing.join("snapshot.db");
        let owned_manifest = publishing.join("manifest.json");
        if take_snapshot {
            fs::rename(snapshot, &owned_snapshot)?;
            File::open(&owned_snapshot)?.sync_all()?;
        } else {
            copy_into_owned_file(snapshot, &owned_snapshot)?;
        }
        copy_into_owned_file(manifest_path, &owned_manifest)?;
        File::open(&publishing)?.sync_all()?;
        File::open(&generations)?.sync_all()?;

        let manifest = read_canonical_manifest(&owned_manifest)?;
        if manifest.hosted_route_database_id != self.expected_route_id
            || self
                .expected_origin_id
                .as_ref()
                .is_some_and(|id| id != &manifest.origin_database_id)
        {
            return Err(
                Error::engine("standby candidate does not match configured route/origin")
                    .at_standby_check(StandbyAdmissionCheck::RouteOrigin),
            );
        }
        verify_snapshot(
            "candidate",
            &owned_snapshot,
            &manifest,
            Some(observed),
            &self.staging_dir(),
        )
        .await?;

        let current = self.read_current_manifest()?;
        if let Some((current_path, current_manifest)) = &current {
            let current_id = hex::encode(Sha256::digest(serde_jcs::to_vec(current_manifest)?));
            let head = self.generation_head(&current_id)?;
            // The act the current copy is known to hold: its head when it has
            // one, else (an earlier-revision checkpoint) its manifest's.
            let held_act = head
                .as_ref()
                .map(|head| head.head_act)
                .or(current_manifest.head_act);
            let switching_to_v2 =
                current_manifest.kernel_v2.is_none() && manifest.kernel_v2.is_some();
            if switching_to_v2 {
                self.pin_newest_v1(observed).await?;
            }
            if current_manifest.kernel_v2.is_some() && manifest.kernel_v2.is_none() {
                return Err(Error::engine(
                    "v2 to v1 generation rollback requires the explicit rollback procedure",
                ));
            }
            let replaceable = switching_to_v2
                || head
                    .as_ref()
                    .is_some_and(|head| head.advanced_in_place() || head.full_refresh_required)
                || current_manifest.is_other_engine_revision();
            if replaceable {
                // Without a known act there is no floor to hold the candidate
                // to, so refuse rather than treat the copy as holding none.
                let held_act = held_act.ok_or_else(|| {
                    Error::engine("standby current generation holds no act frontier")
                        .at_standby_check(StandbyAdmissionCheck::CurrentGeneration)
                })?;
                // Trusted deltas advanced the current copy, an audit found it
                // bad, or an earlier engine revision wrote it. A whole
                // snapshot is how that copy is repaired, so its own rows do
                // not fence the candidate: only identity and act order do.
                // An earlier revision's rows cannot be compared with this
                // build's candidate at all; the candidate has just passed
                // this build's full verification.
                if manifest.hosted_route_database_id != current_manifest.hosted_route_database_id
                    || manifest.origin_database_id != current_manifest.origin_database_id
                    || manifest
                        .kernel_v2
                        .as_ref()
                        .zip(current_manifest.kernel_v2.as_ref())
                        .is_some_and(|(next, prior)| {
                            next.genesis_event_id != prior.genesis_event_id
                        })
                    || (!switching_to_v2 && manifest.head_act.unwrap_or_default() < held_act)
                {
                    return Err(Error::engine(
                        "standby candidate fails act-order/continuity fence",
                    )
                    .at_standby_check(StandbyAdmissionCheck::ActOrderContinuity));
                }
            } else {
                verify_snapshot(
                    "predecessor",
                    current_path,
                    current_manifest,
                    None,
                    &self.staging_dir(),
                )
                .await?;
                if manifest.hosted_route_database_id != current_manifest.hosted_route_database_id
                    || manifest.origin_database_id != current_manifest.origin_database_id
                    || !manifest.frontier_follows(current_manifest)?
                {
                    return Err(Error::engine(
                        "standby candidate fails scalar rollback/continuity fence",
                    )
                    .at_standby_check(StandbyAdmissionCheck::ScalarRollbackContinuity));
                }
                verify_database_successor(current_path, &owned_snapshot).await?;
            }
        }

        let id = hex::encode(Sha256::digest(manifest.canonical_json()?));
        let destination = generations.join(&id);
        if destination.exists() {
            // A crash after the atomic rename but before hardening leaves an
            // unselected 0700 generation. Re-verify it under the promotion
            // lock before completing publication; all other shapes refuse.
            let needs_hardening = match require_published_generation(&destination) {
                Ok(()) => false,
                Err(error) => {
                    require_generation_shape(&destination, 0o700).map_err(|_| error)?;
                    true
                }
            };
            let existing = read_canonical_manifest(&destination.join("manifest.json"))?;
            if hex::encode(Sha256::digest(existing.canonical_json()?)) != id || existing != manifest
            {
                return Err(Error::engine("standby generation id collision"));
            }
            verify_snapshot(
                "existing-generation",
                &destination.join("snapshot.db"),
                &existing,
                Some(observed),
                &self.staging_dir(),
            )
            .await?;
            if needs_hardening {
                set_mode(&destination, 0o500)?;
                require_published_generation(&destination)?;
                verify_snapshot(
                    "hardened-generation",
                    &destination.join("snapshot.db"),
                    &existing,
                    Some(observed),
                    &self.staging_dir(),
                )
                .await?;
            }
            // The previous process may have died after rename and chmod but
            // before syncing the parent entry. Make the generation durable
            // before an idempotent retry can publish its pointer.
            File::open(&destination)?.sync_all()?;
            File::open(&generations)?.sync_all()?;
            transition(PublishTransition::GenerationDurable)?;
            if self
                .read_pointer()
                .ok()
                .is_none_or(|pointer| pointer.generation_id != id)
            {
                self.write_pointer(&CurrentPointer {
                    contract: POINTER_CONTRACT.into(),
                    version: 1,
                    generation_id: id.clone(),
                    snapshot_sha256: existing.snapshot.sha256.clone(),
                })?;
            }
            return Ok(InstalledGeneration {
                id,
                snapshot_path: destination.join("snapshot.db"),
                manifest: existing,
            });
        }
        set_mode(&publishing.join("snapshot.db"), 0o400)?;
        set_mode(&publishing.join("manifest.json"), 0o400)?;
        File::open(publishing.join("snapshot.db"))?.sync_all()?;
        File::open(publishing.join("manifest.json"))?.sync_all()?;
        File::open(&publishing)?.sync_all()?;
        // APFS refuses to rename a source directory without owner write
        // permission. Keep the verified staging directory 0700 until the
        // exclusive atomic rename, then harden the unselected destination.
        let publish = rename_directory_no_replace(&publishing, &destination);
        if let Err(error) = publish {
            // TempDir cleanup needs write permission on the workspace. A
            // successful rename makes its old path disappear, so the guard is
            // harmless on the success path and cleans every ordinary refusal.
            let _ = set_mode(&publishing, 0o700);
            return Err(error);
        }
        set_mode(&destination, 0o500)?;
        File::open(&destination)?.sync_all()?;
        File::open(&generations)?.sync_all()?;
        require_published_generation(&destination)?;
        transition(PublishTransition::GenerationDurable)?;

        self.write_pointer(&CurrentPointer {
            contract: POINTER_CONTRACT.into(),
            version: 1,
            generation_id: id.clone(),
            snapshot_sha256: manifest.snapshot.sha256.clone(),
        })?;
        transition(PublishTransition::PointerDurable)?;
        Ok(InstalledGeneration {
            id,
            snapshot_path: destination.join("snapshot.db"),
            manifest,
        })
    }

    fn generation_ids(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(self.root.join("generations"))? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if is_generation_id(name) {
                ids.push(name.to_string());
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Device verification for admission and startup per ratified decision
    /// e15d82a: authenticity (manifest size/SHA-256), binding (route, origin,
    /// account, consumer), compatibility (supported schema), SQLite health
    /// (`quick_check`, foreign keys) and read-only safety. Rebuild-and-diff,
    /// exhaustive relationship history and awareness reconstruction are not
    /// device gates; they live on the hosted side and in CI.
    async fn verify_generation_for_startup(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<InstalledGeneration> {
        let started = std::time::Instant::now();
        let before = self.status_stamp(id, observed).ok();
        #[cfg(test)]
        {
            let pause = self.verification_pause.lock().unwrap().take();
            if let Some((entered, resume)) = pause {
                entered.notify_one();
                resume.notified().await;
            }
        }
        let result = self.verify_generation_for_use(id, observed, true).await;
        match &result {
            Err(error) if audit_infrastructure_error(error) => {
                self.invalidate_verification(id, observed)
            }
            _ => self.remember_verification(id, observed, before, result.is_ok()),
        }
        tracing::info!(target: "native_ce::standby::verification", phase = "startup-generation-verify",
            generation_id = id, elapsed_ms = started.elapsed().as_millis(), ok = result.is_ok(),
            "standby startup phase finished");
        result
    }

    async fn verify_generation_for_use(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        allow_rebind: bool,
    ) -> Result<InstalledGeneration> {
        verification_phase("startup-generation", async {
            let generation = self.verify_generation_identity(id)?;
            if allow_rebind {
                if verification_phase("startup-rebind", self.ensure_consumer_binding(id, observed))
                    .await?
                {
                    return Ok(generation);
                }
            } else {
                self.consumer_rebind(id, observed)?;
            }
            // Hold the checkpoint shared while its bytes may be hashed, so the
            // first in-place delta cannot change them mid-check. Re-read the
            // head under the lock: that delta may have just marked it.
            let checkpoint = open_generation_lock(&self.root.join("leases"), id, "checkpoint")?;
            fs2::FileExt::lock_shared(&checkpoint)?;
            let advanced = self.advanced_in_place(id)?;
            if advanced {
                drop(checkpoint);
            }
            verification_phase(
                "startup-snapshot",
                verify_snapshot_contents(
                    &generation.snapshot_path,
                    &generation.manifest,
                    None,
                    &self.staging_dir(),
                    advanced,
                ),
            )
            .await?;
            Ok(generation)
        })
        .await
    }

    /// Re-check a still-served predecessor against the active serving bundle.
    /// The matching path re-checks manifest identity, route/origin binding
    /// and byte hash/sidecars (skipped only for copies advanced in place by
    /// trusted deltas, where the checkpoint digest no longer applies). It
    /// does NOT re-run SQLite health or engine-shape checks: those were
    /// established at admission/activation and the hash pins the bytes.
    /// There is no reusable cross-process proof. A lease prevents pruning,
    /// not mutation of bytes.
    async fn verify_reader_predecessor(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
        predecessor: Option<&ActivatedGeneration>,
    ) -> Result<InstalledGeneration> {
        if let Some(active) = predecessor.filter(|active| active.generation.id == id) {
            // Canonical identity includes manifest/generation and checks
            // the configured route/origin and published file shape anew.
            let generation = self.verify_generation_identity(id)?;
            self.ensure_consumer_binding(id, observed).await?;
            // A copy advanced in place by trusted deltas no longer matches
            // its checkpoint digest, so byte identity is checked against the
            // checkpoint manifest only for unadvanced copies. Consumer binding
            // is always re-validated: nothing about the advanced state waives
            // the account/consumer check.
            if self.advanced_in_place(id)? {
                verification_phase("manifest-consumer-identity", async {
                    require_regular_no_symlink(&generation.snapshot_path)?;
                    generation.manifest.validate()?;
                    self.consumer_rebind(id, observed)?;
                    Ok(())
                })
                .await?;
            } else {
                verification_phase("byte-manifest-consumer-identity", async {
                    verify_snapshot_byte_identity(
                        &generation.snapshot_path,
                        &generation.manifest,
                        None,
                    )
                })
                .await?;
            }
            if generation.snapshot_path == active.generation.snapshot_path
                && generation.manifest == active.generation.manifest
            {
                check_verification_cancellation()?;
                return Ok(generation);
            }
        }
        // An absent or changed predecessor takes the device verifier; hash or
        // identity errors honestly refuse rather than becoming hits.
        self.verify_generation_for_startup(id, observed).await
    }

    fn verify_generation_identity(&self, id: &str) -> Result<InstalledGeneration> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        let directory = self.root.join("generations").join(id);
        self.require_generation_files(id, &directory)?;
        let manifest = read_canonical_manifest(&directory.join("manifest.json"))?;
        if hex::encode(Sha256::digest(manifest.canonical_json()?)) != id {
            return Err(Error::engine("standby generation manifest id mismatch"));
        }
        if manifest.hosted_route_database_id != self.expected_route_id
            || self
                .expected_origin_id
                .as_ref()
                .is_none_or(|origin| origin != &manifest.origin_database_id)
        {
            return Err(Error::engine(
                "standby generation does not match configured route/origin",
            ));
        }
        let snapshot_path = directory.join("snapshot.db");
        Ok(InstalledGeneration {
            id: id.to_string(),
            snapshot_path,
            manifest,
        })
    }

    fn acquire_serving_lease(&self, id: &str) -> Result<File> {
        let lease = open_generation_lease(&self.root.join("leases"), id)?;
        fs2::FileExt::lock_shared(&lease)?;
        Ok(lease)
    }

    #[cfg(test)]
    fn prune_known_good(&self, selected_id: &str, usable: &[InstalledGeneration]) -> Vec<String> {
        let mut ordered = usable.to_vec();
        ordered.sort_by(compare_generation_newest_first);
        let mut warnings = Vec::new();
        let mut keep = std::collections::HashSet::from([selected_id.to_string()]);
        for generation in ordered
            .iter()
            .filter(|generation| generation.id != selected_id)
            .take(2)
        {
            keep.insert(generation.id.clone());
        }
        for generation in ordered {
            if keep.contains(&generation.id)
                || self.pinned_v1_generation().ok().flatten().as_deref() == Some(&generation.id)
            {
                continue;
            }
            let lease = match open_generation_lease(&self.root.join("leases"), &generation.id) {
                Ok(lease) => lease,
                Err(error) => {
                    warnings.push(format!("{}: lease unavailable: {error}", generation.id));
                    continue;
                }
            };
            match fs2::FileExt::try_lock_exclusive(&lease) {
                Ok(()) => {
                    if let Err(error) = self.remove_published_generation(&generation.id) {
                        warnings.push(format!("{}: prune failed: {error}", generation.id));
                    }
                    if let Err(error) = fs2::FileExt::unlock(&lease) {
                        warnings.push(format!("{}: lease unlock failed: {error}", generation.id));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => {
                    warnings.push(format!("{}: lease lock failed: {error}", generation.id));
                }
            }
        }
        warnings
    }

    fn remove_published_generation(&self, id: &str) -> Result<()> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        if self.pinned_v1_generation()?.as_deref() == Some(id) {
            return Err(Error::engine(
                "v1 rollback generation is pinned; explicit operator release required",
            ));
        }
        let generations = self.root.join("generations");
        let source = generations.join(id);
        self.require_generation_files(id, &source)?;
        let mut children = fs::read_dir(&source)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        children.retain(|name| name != "snapshot.db-journal");
        children.sort();
        if children != ["manifest.json", "snapshot.db"].map(std::ffi::OsString::from) {
            return Err(Error::engine(
                "standby generation contains unexpected retention entries",
            ));
        }
        let pruning = generations.join(format!(".pruning-{}", uuid::Uuid::new_v4()));
        fs::rename(&source, &pruning)?;
        File::open(&generations)?.sync_all()?;
        self.remove_pruning_workspace(&pruning)?;
        self.remove_generation_head(id)
    }

    fn cleanup_pruning_workspaces(&self) -> Vec<String> {
        let generations = self.root.join("generations");
        let entries = match fs::read_dir(&generations) {
            Ok(entries) => entries,
            Err(error) => return vec![format!("cannot scan pruning workspaces: {error}")],
        };
        let mut warnings = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    warnings.push(format!("cannot inspect pruning workspace: {error}"));
                    continue;
                }
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(id) = name.strip_prefix(".pruning-") else {
                continue;
            };
            if uuid::Uuid::parse_str(id).is_err() {
                continue;
            }
            if let Err(error) = self.remove_pruning_workspace(&entry.path()) {
                warnings.push(format!("{name}: cleanup failed: {error}"));
            }
        }
        warnings
    }

    fn remove_pruning_workspace(&self, path: &Path) -> Result<()> {
        require_directory_no_symlink(path)?;
        let mut children = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        children.sort();
        if children.iter().any(|name| {
            name != "manifest.json" && name != "snapshot.db" && name != "snapshot.db-journal"
        }) {
            return Err(Error::engine(
                "standby pruning workspace contains unexpected entries",
            ));
        }
        set_mode(path, 0o700)?;
        for name in children {
            let child = path.join(name);
            require_regular_no_symlink(&child)?;
            set_mode(&child, 0o600)?;
            fs::remove_file(child)?;
        }
        fs::remove_dir(path)?;
        File::open(self.root.join("generations"))?.sync_all()?;
        Ok(())
    }

    /// The generation `current.json` selects, for deciding whether a candidate
    /// may replace it. A manifest written by an earlier engine revision is
    /// returned too (see [`StandbySnapshotManifest::is_other_engine_revision`]):
    /// it is bound to the pointer by its canonical digest like any other, but
    /// this build's `validate` would refuse it, which must not stop the whole
    /// snapshot that is the way to replace it. Refusals other than local I/O
    /// carry [`StandbyAdmissionCheck::CurrentGeneration`].
    fn read_current_manifest(&self) -> Result<Option<(PathBuf, StandbySnapshotManifest)>> {
        self.read_current_manifest_untagged()
            .map_err(|error| match error {
                Error::Io(_) => error,
                other => other.at_standby_check(StandbyAdmissionCheck::CurrentGeneration),
            })
    }

    fn read_current_manifest_untagged(&self) -> Result<Option<(PathBuf, StandbySnapshotManifest)>> {
        let pointer = match self.read_pointer() {
            Ok(value) => value,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let dir = self.root.join("generations").join(&pointer.generation_id);
        self.require_generation_files(&pointer.generation_id, &dir)?;
        let manifest_path = dir.join("manifest.json");
        require_regular_no_symlink(&manifest_path)?;
        let bytes = fs::read(&manifest_path)?;
        let manifest: StandbySnapshotManifest = serde_json::from_slice(&bytes)?;
        if serde_jcs::to_vec(&manifest)? != bytes {
            return Err(Error::engine("standby manifest is not canonical JSON"));
        }
        if manifest.is_other_engine_revision() {
            manifest.validate_other_revision_for_replacement()?;
        } else {
            manifest.validate()?;
        }
        if manifest.snapshot.sha256 != pointer.snapshot_sha256
            || hex::encode(Sha256::digest(&bytes)) != pointer.generation_id
        {
            return Err(Error::engine("standby current pointer digest mismatch"));
        }
        Ok(Some((dir.join("snapshot.db"), manifest)))
    }

    fn read_pointer(&self) -> Result<CurrentPointer> {
        let path = self.root.join("current.json");
        require_regular_no_symlink(&path)?;
        let value: CurrentPointer = serde_json::from_slice(&fs::read(path)?)?;
        if value.contract != POINTER_CONTRACT
            || value.version != 1
            || value.generation_id.len() != 64
            || !value
                .generation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(Error::engine("invalid standby current pointer"));
        }
        Ok(value)
    }

    fn write_pointer(&self, pointer: &CurrentPointer) -> Result<()> {
        let temp = self
            .root
            .join(format!(".current-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        set_mode(&temp, 0o600)?;
        file.write_all(&serde_jcs::to_vec(pointer)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, self.root.join("current.json"))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn write_degraded_startup_state(&self, state: &DegradedStartupState) -> Result<()> {
        let temp = self
            .root
            .join(format!(".startup-state-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        set_mode(&temp, 0o600)?;
        file.write_all(&serde_jcs::to_vec(state)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, self.root.join("startup-state.json"))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

impl GenerationStore {
    /// The generation's mutable head record, if one has been written. A
    /// malformed record is an error, never "not advanced": treating unknown
    /// bytes as an untouched checkpoint would misreport them.
    pub fn generation_head(&self, id: &str) -> Result<Option<GenerationHead>> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        let path = self.root.join("heads").join(format!("{id}.json"));
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        require_regular_no_symlink(&path)?;
        let head: GenerationHead = serde_json::from_slice(&bytes)?;
        if head.contract != GENERATION_HEAD_CONTRACT
            || !matches!(head.version, 1 | 2)
            || head.generation_id != id
            || head.head_act < 0
            || chrono::DateTime::parse_from_rfc3339(&head.synced_at).is_err()
        {
            return Err(Error::engine("invalid standby generation head"));
        }
        Ok(Some(head))
    }

    fn advanced_in_place(&self, id: &str) -> Result<bool> {
        Ok(self
            .generation_head(id)?
            .is_some_and(|head| head.advanced_in_place()))
    }

    fn write_generation_head(&self, head: &GenerationHead) -> Result<()> {
        let heads = self.root.join("heads");
        let temp = heads.join(format!(".head-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        set_mode(&temp, 0o600)?;
        file.write_all(&serde_jcs::to_vec(head)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, heads.join(format!("{}.json", head.generation_id)))?;
        File::open(&heads)?.sync_all()?;
        Ok(())
    }

    fn remove_generation_head(&self, id: &str) -> Result<()> {
        let heads = self.root.join("heads");
        let mut names = vec![
            format!("{id}.json"),
            format!("{id}.reader.json"),
            format!("{id}.reader.lock"),
            format!("{id}.deferrals"),
            format!("{id}.consumer-rebind.json"),
        ];
        for entry in fs::read_dir(&heads)? {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(name) = name.to_str().filter(|name| {
                name.starts_with(&format!("{id}.consumer-rebind-")) && name.ends_with(".json")
            }) {
                names.push(name.into());
            }
        }
        for name in names {
            match fs::remove_file(heads.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        File::open(heads)?.sync_all()?;
        Ok(())
    }

    /// Take a shared lock on `accepted/heads/<id>.reader.lock`. The caller
    /// keeps the returned file for as long as it serves the generation; the
    /// kernel drops the lock if the process dies, so a held lock is evidence
    /// of a live reader that a stale marker alone cannot give.
    pub fn hold_serving_reader(&self, id: &str) -> Result<File> {
        let lock = open_generation_lock(&self.root.join("heads"), id, "reader.lock")?;
        fs2::FileExt::lock_shared(&lock)?;
        Ok(lock)
    }

    /// Whether some process currently holds the reader lock. The probe is a
    /// non-blocking exclusive lock; if it succeeds nobody was holding, and it
    /// is released at once.
    fn serving_reader_alive(&self, id: &str) -> bool {
        let path = self.root.join("heads").join(format!("{id}.reader.lock"));
        if require_regular_no_symlink(&path).is_err() {
            return false;
        }
        let Ok(lock) = File::open(&path) else {
            return false;
        };
        match fs2::FileExt::try_lock_exclusive(&lock) {
            Ok(()) => {
                let _ = fs2::FileExt::unlock(&lock);
                false
            }
            Err(error) => error.kind() == std::io::ErrorKind::WouldBlock,
        }
    }

    /// Record that a serving process built from `observed.source_sha` is
    /// serving this generation. Call it after the swap, while holding the
    /// reader lock. Deltas rewrite the serving file in place, so they are
    /// refused until the generation is served by the matching build: older
    /// builds open generations `immutable` and would read pages that a delta
    /// rewrites.
    pub fn record_serving_reader(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<()> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        let heads = self.root.join("heads");
        let temp = heads.join(format!(".reader-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        set_mode(&temp, 0o600)?;
        file.write_all(&serde_jcs::to_vec(&ServingReader {
            contract: SERVING_READER_CONTRACT.into(),
            version: 1,
            generation_id: id.into(),
            source_sha: observed.source_sha.clone(),
        })?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, heads.join(format!("{id}.reader.json")))?;
        File::open(&heads)?.sync_all()?;
        Ok(())
    }

    /// Whether a live serving process built from `source_sha` is serving this
    /// generation: the last marker names that build and the reader lock is
    /// held now. Missing or malformed markers, or a lock nobody holds, answer
    /// `false`.
    pub(super) fn served_by_build(&self, id: &str, source_sha: &str) -> bool {
        if !is_generation_id(id) || !self.serving_reader_alive(id) {
            return false;
        }
        let path = self.root.join("heads").join(format!("{id}.reader.json"));
        if require_regular_no_symlink(&path).is_err() {
            return false;
        }
        fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ServingReader>(&bytes).ok())
            .is_some_and(|reader| {
                reader.contract == SERVING_READER_CONTRACT
                    && reader.version == 1
                    && reader.generation_id == id
                    && reader.source_sha == source_sha
            })
    }

    /// The consecutive deferred delta ticks recorded for this generation.
    /// Missing or malformed counts read as zero.
    pub fn deferral_counts(&self, id: &str) -> DeferralCounts {
        if !is_generation_id(id) {
            return DeferralCounts::default();
        }
        let path = self.root.join("heads").join(format!("{id}.deferrals"));
        if require_regular_no_symlink(&path).is_err() {
            return DeferralCounts::default();
        }
        fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Count one more consecutive tick on which `cause` blocked a delta, or
    /// clear that cause's count. Advisory: it only feeds status, so failures
    /// are ignored.
    pub(super) fn note_deferral(&self, id: &str, cause: DeltaDeferral, deferred: bool) {
        let mut counts = self.deferral_counts(id);
        let count = match cause {
            DeltaDeferral::ReaderNotUpgraded => &mut counts.reader_not_upgraded,
            DeltaDeferral::DatabaseBusy => &mut counts.database_busy,
        };
        if !deferred && *count == 0 {
            return;
        }
        *count = if deferred { count.saturating_add(1) } else { 0 };
        let _ = self.write_deferral_counts(id, &counts);
    }

    fn write_deferral_counts(&self, id: &str, counts: &DeferralCounts) -> Result<()> {
        let heads = self.root.join("heads");
        let target = heads.join(format!("{id}.deferrals"));
        if *counts == DeferralCounts::default() {
            return match fs::remove_file(&target) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            };
        }
        let temp = heads.join(format!(".deferrals-{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        set_mode(&temp, 0o600)?;
        file.write_all(&serde_jcs::to_vec(counts)?)?;
        drop(file);
        fs::rename(&temp, target)?;
        Ok(())
    }

    /// Record that this copy holds `head_act` and that hosted Native was
    /// observed at that act no earlier than `synced_at`.
    pub(super) fn record_synced(
        &self,
        generation: &InstalledGeneration,
        head_act: i64,
        synced_at: &str,
    ) -> Result<GenerationHead> {
        let mut head = self
            .generation_head(&generation.id)?
            .unwrap_or_else(|| GenerationHead::checkpoint(generation));
        head.head_act = head_act;
        head.synced_at = synced_at.into();
        self.write_generation_head(&head)?;
        Ok(head)
    }

    /// Make the next refresh replace this generation with a whole snapshot.
    pub fn require_full_refresh(&self, generation: &InstalledGeneration) -> Result<()> {
        let mut head = self
            .generation_head(&generation.id)?
            .unwrap_or_else(|| GenerationHead::checkpoint(generation));
        head.full_refresh_required = true;
        self.write_generation_head(&head)
    }

    /// Open the current generation's database for one in-place delta.
    ///
    /// Before the first byte changes, the head record is marked `delta`, so no
    /// later verification mistakes advanced bytes for a corrupted checkpoint.
    /// That first transition waits for no one: if a verification is still
    /// hashing the checkpoint, this returns `None` and the caller retries on a
    /// later tick. Opening the writer also rolls back a journal left by an
    /// interrupted earlier delta.
    pub(super) async fn open_head_writer(
        &self,
        generation: &InstalledGeneration,
    ) -> Result<Option<crate::Db>> {
        if generation.manifest.kernel_v2.is_some() {
            return Err(Error::engine(
                "v2 replay requires a scratch generation, never the serving file",
            ));
        }
        let mut head = self
            .generation_head(&generation.id)?
            .unwrap_or_else(|| GenerationHead::checkpoint(generation));
        if head.needs_projection_recovery() {
            return Err(Error::engine(
                "v1 delta generation requires a whole snapshot for authority/link recovery",
            ));
        }
        if !head.advanced_in_place() {
            let checkpoint =
                open_generation_lock(&self.root.join("leases"), &generation.id, "checkpoint")?;
            match checkpoint.try_lock_exclusive() {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error.into()),
            }
            head.materialization = StandbyGenerationMaterialization::Delta;
            // Mark before any database write, including interrupted applies.
            head.version = 2;
            self.write_generation_head(&head)?;
        }
        let directory = generation
            .snapshot_path
            .parent()
            .ok_or_else(|| Error::engine("standby generation has no directory"))?;
        set_mode(directory, 0o700)?;
        set_mode(&generation.snapshot_path, 0o600)?;
        crate::db::open_standby_head_writer(&generation.snapshot_path)
            .await
            .map(Some)
    }

    /// Check the generation directory's file shape and report whether its
    /// database has been advanced in place. An advanced generation is owner
    /// writable and may hold the rollback journal of an interrupted delta.
    fn require_generation_files(&self, id: &str, directory: &Path) -> Result<bool> {
        let advanced = self.advanced_in_place(id)?;
        if advanced {
            require_advanced_generation_shape(directory)?;
        } else {
            require_published_generation(directory)?;
        }
        Ok(advanced)
    }
}

/// Failures of the machinery around an audit, not verdicts about the copy:
/// local I/O (including a full scratch disk), SQLite busy/locked/full/I/O,
/// pool exhaustion and cancellation.
pub(super) fn audit_infrastructure_error(error: &Error) -> bool {
    match error {
        Error::StandbyAdmission { source, .. } => audit_infrastructure_error(source),
        Error::Io(_) => true,
        Error::Sqlx(sqlx::Error::Database(database)) => database
            .code()
            .and_then(|code| code.parse::<i32>().ok())
            .is_some_and(|code| matches!(code & 0xff, 5 | 6 | 10 | 13)),
        Error::Sqlx(sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed) => {
            true
        }
        Error::Engine(message) => message == "standby verification cancelled",
        _ => false,
    }
}

fn is_generation_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn compare_generation_newest_first(
    left: &InstalledGeneration,
    right: &InstalledGeneration,
) -> std::cmp::Ordering {
    let left_captured = chrono::DateTime::parse_from_rfc3339(&left.manifest.captured_at)
        .expect("verified standby capture time");
    let right_captured = chrono::DateTime::parse_from_rfc3339(&right.manifest.captured_at)
        .expect("verified standby capture time");
    let left_completed = chrono::DateTime::parse_from_rfc3339(&left.manifest.snapshot_completed_at)
        .expect("verified standby completion time");
    let right_completed =
        chrono::DateTime::parse_from_rfc3339(&right.manifest.snapshot_completed_at)
            .expect("verified standby completion time");
    right_captured
        .cmp(&left_captured)
        .then_with(|| right_completed.cmp(&left_completed))
        .then_with(|| right.id.cmp(&left.id))
}

fn open_generation_lease(directory: &Path, id: &str) -> Result<File> {
    open_generation_lock(directory, id, "lock")
}

/// `lock` is the serving lease; `checkpoint` is held shared while a
/// checkpoint's bytes are verified against its digest and taken exclusively by
/// the first in-place delta.
fn open_generation_lock(directory: &Path, id: &str, kind: &str) -> Result<File> {
    if !is_generation_id(id) {
        return Err(Error::engine("invalid standby generation lease id"));
    }
    let path = directory.join(format!("{id}.{kind}"));
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x20_000);
    }
    let lease = options.open(&path)?;
    let path_metadata = fs::symlink_metadata(&path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(Error::engine(
            "standby generation lease is not a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let file_metadata = lease.metadata()?;
        if file_metadata.nlink() != 1
            || file_metadata.dev() != path_metadata.dev()
            || file_metadata.ino() != path_metadata.ino()
        {
            return Err(Error::engine(
                "standby generation lease is hard-linked or changed during open",
            ));
        }
        lease.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(lease)
}

async fn acquire_promotion_lock(path: PathBuf) -> Result<File> {
    let cancellation = VERIFICATION_CANCELLATION.with(|cell| cell.borrow().clone());
    tokio::task::spawn_blocking(move || {
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Linux O_NOFOLLOW. The Milestone 1 generation store is explicitly
            // Linux-only at its publication boundary.
            options.custom_flags(0x20_000);
        }
        let lock = options.open(&path)?;
        let path_metadata = fs::symlink_metadata(&path)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(Error::engine(
                "standby promotion lock is not a regular non-symlink file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let file_metadata = lock.metadata()?;
            if file_metadata.nlink() != 1
                || file_metadata.dev() != path_metadata.dev()
                || file_metadata.ino() != path_metadata.ino()
            {
                return Err(Error::engine(
                    "standby promotion lock is hard-linked or changed during open",
                ));
            }
            lock.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        if let Some(cancellation) = cancellation {
            loop {
                if cancellation.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(Error::engine("standby verification cancelled"));
                }
                match lock.try_lock_exclusive() {
                    Ok(()) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        } else {
            lock.lock_exclusive()?;
        }
        Ok(lock)
    })
    .await
    .map_err(|error| Error::engine(format!("standby promotion lock task failed: {error}")))?
}

// Scoped to the dedicated preparation thread, never the ordinary consumer's
// request thread or fixed writable servers. Cancellation is checked at phase
// boundaries and every hash chunk. Pinned SQL phases finish their cleanup before
// cancellation can release a pathname lease.
thread_local! {
    static VERIFICATION_CANCELLATION: std::cell::RefCell<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn with_verification_cancellation<T>(
    cancellation: std::sync::Arc<std::sync::atomic::AtomicBool>,
    work: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<std::sync::Arc<std::sync::atomic::AtomicBool>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            VERIFICATION_CANCELLATION.with(|cell| *cell.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(VERIFICATION_CANCELLATION.with(|cell| cell.replace(Some(cancellation))));
    work()
}

pub(crate) fn check_verification_cancellation() -> Result<()> {
    if VERIFICATION_CANCELLATION.with(|cell| {
        cell.borrow()
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
    }) {
        Err(Error::engine("standby verification cancelled"))
    } else {
        Ok(())
    }
}

// Aggregate-only events: never attach errors, rows, paths or provider bodies.
// A finished phase is successful only when `ok` is true. Cancellation leaves
// its start visible without inventing a completion receipt.
fn verification_phase<T>(
    phase: &'static str,
    work: impl std::future::Future<Output = Result<T>>,
) -> impl std::future::Future<Output = Result<T>> {
    // Box before constructing the async state: verification futures must not
    // propagate through install, activation and refresh callers by value.
    let work = Box::pin(work);
    async move {
        check_verification_cancellation()?;
        tracing::info!(target: "native_ce::standby::verification", phase, "standby phase started");
        let started = std::time::Instant::now();
        let result = work.await.map_err(|error| {
            let check = match phase {
                "engine-manifest-state" | "engine-advanced-state" => {
                    Some(StandbyAdmissionCheck::EngineShape)
                }
                "sqlite-quick-check-foreign-keys" | "sqlite-integrity-foreign-keys" => {
                    Some(StandbyAdmissionCheck::Integrity)
                }
                "observational-conformance" => Some(StandbyAdmissionCheck::Conformance),
                "successor-fence" => Some(StandbyAdmissionCheck::SuccessorPreservation),
                "awareness-projections" => Some(StandbyAdmissionCheck::Awareness),
                _ => None,
            };
            match check {
                Some(check) => error.at_standby_check(check),
                None => error,
            }
        });
        tracing::info!(target: "native_ce::standby::verification",
        phase, elapsed_ms = started.elapsed().as_millis(), ok = result.is_ok(),
        "standby phase finished");
        result
    }
}

async fn verify_snapshot(
    phase: &'static str,
    path: &Path,
    manifest: &StandbySnapshotManifest,
    observed: Option<&ObservedInstalledConsumerIdentity>,
    scratch_parent: &Path,
) -> Result<()> {
    verification_phase(
        phase,
        verify_snapshot_contents(path, manifest, observed, scratch_parent, false),
    )
    .await
    .map(|_| ())
}

fn verify_snapshot_byte_identity(
    path: &Path,
    manifest: &StandbySnapshotManifest,
    observed: Option<&ObservedInstalledConsumerIdentity>,
) -> Result<()> {
    require_regular_no_symlink(path)?;
    manifest.validate()?;
    if let Some(observed) = observed {
        manifest
            .consumer
            .validate_observed_installed(observed)
            .map_err(|error| error.at_standby_check(StandbyAdmissionCheck::Consumer))?;
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() != manifest.snapshot.size_bytes
        || sha256_file(path)? != manifest.snapshot.sha256
    {
        return Err(Error::engine("standby snapshot byte identity mismatch")
            .at_standby_check(StandbyAdmissionCheck::ByteIdentity));
    }
    reject_sqlite_sidecars(path)?;
    Ok(())
}

async fn validate_generation_shape(path: &Path, manifest: &StandbySnapshotManifest) -> Result<()> {
    if manifest.kernel_v2.is_some() {
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        {
            super::kernel_v2::verify_path(path).await?;
            return Ok(());
        }
        #[cfg(not(any(test, feature = "v2-kernel-probe")))]
        return Err(Error::engine(
            "kernel-v2 generation requires v2-kernel-probe",
        ));
    }
    crate::db::validate_current_engine_shape_immutable(path).await
}

async fn verify_snapshot_contents(
    path: &Path,
    manifest: &StandbySnapshotManifest,
    observed: Option<&ObservedInstalledConsumerIdentity>,
    scratch_parent: &Path,
    advanced: bool,
) -> Result<()> {
    if advanced {
        // Trusted deltas have moved these bytes past the checkpoint digest, and
        // the refresh controller may advance them again during this check.
        // Verify one consistent private copy against the checkpoint identity.
        verification_phase("advanced-manifest-consumer-identity", async {
            require_regular_no_symlink(path)?;
            manifest.validate()?;
            if let Some(observed) = observed {
                manifest
                    .consumer
                    .validate_observed_installed(observed)
                    .map_err(|error| error.at_standby_check(StandbyAdmissionCheck::Consumer))?;
            }
            Ok(())
        })
        .await?;
        let scratch_dir = tempfile::Builder::new()
            .prefix(".verify-head-")
            .tempdir_in(scratch_parent)?;
        let copy = scratch_dir.path().join("snapshot.db");
        verification_phase("advanced-consistent-copy", consistent_copy(path, &copy)).await?;
        verification_phase("engine-advanced-state", async {
            validate_generation_shape(&copy, manifest).await?;
            validate_advanced_state(&copy, manifest).await
        })
        .await?;
        verify_snapshot_database(&copy).await?;
    } else {
        verification_phase("byte-manifest-consumer-identity", async {
            verify_snapshot_byte_identity(path, manifest, observed)
        })
        .await?;
        verification_phase("engine-manifest-state", async {
            validate_generation_shape(path, manifest).await?;
            crate::standby_snapshot::validate_completed_export_manifest(path, manifest).await?;
            Ok(())
        })
        .await?;
        verify_snapshot_database(path).await?;
    }
    check_verification_cancellation()?;
    Ok(())
}

/// The deep checks shared by checkpoints and advanced copies: SQLite health
/// (`quick_check`, foreign keys, no unexpected embeddings) over a path that
/// must not change while they run. Rebuild-and-diff, exhaustive relationship
/// history and awareness reconstruction are not device gates per ratified
/// decision e15d82a.
async fn verify_snapshot_database(path: &Path) -> Result<()> {
    verification_phase("sqlite-quick-check-foreign-keys", async {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .immutable(true)
            .create_if_missing(false);
        let mut raw = sqlx::SqliteConnection::connect_with(&options).await?;
        let integrity: String = sqlx::query_scalar("PRAGMA quick_check")
            .fetch_one(&mut raw)
            .await?;
        let foreign_key_violation: i64 =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)")
                .fetch_one(&mut raw)
                .await?;
        let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&mut raw)
            .await?;
        let embeddings: i64 = if marker == crate::db::V2_APPLICATION_ID {
            0
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM embeddings")
                .fetch_one(&mut raw)
                .await?
        };
        raw.close().await?;
        if integrity != "ok" || foreign_key_violation != 0 || embeddings != 0 {
            return Err(Error::engine(
                "standby snapshot integrity or foreign-key validation failed",
            )
            .at_standby_check(StandbyAdmissionCheck::Integrity));
        }
        Ok(())
    })
    .await
}

/// Deliberate deep audit helper: the full pre-e15d82a verifier over one
/// generation — byte identity, engine shape, `integrity_check`, the
/// observational conformance suite including rebuild-and-diff, and awareness
/// reconstruction. Only [`GenerationStore::audit_current`] calls this; it is
/// never a serving, startup, status or admission gate.
async fn verify_generation_for_audit(
    store: &GenerationStore,
    id: &str,
    observed: &ObservedInstalledConsumerIdentity,
) -> Result<InstalledGeneration> {
    verification_phase("audit-generation", async {
        let generation = store.verify_generation_identity(id)?;
        store.ensure_consumer_binding(id, observed).await?;
        let checkpoint = open_generation_lock(&store.root.join("leases"), id, "checkpoint")?;
        fs2::FileExt::lock_shared(&checkpoint)?;
        let advanced = store.advanced_in_place(id)?;
        if advanced {
            drop(checkpoint);
        }
        verification_phase(
            "audit-snapshot",
            verify_snapshot_contents_deep(
                &generation.snapshot_path,
                &generation.manifest,
                None,
                &store.staging_dir(),
                advanced,
            ),
        )
        .await?;
        Ok(generation)
    })
    .await
}

async fn verify_snapshot_contents_deep(
    path: &Path,
    manifest: &StandbySnapshotManifest,
    observed: Option<&ObservedInstalledConsumerIdentity>,
    scratch_parent: &Path,
    advanced: bool,
) -> Result<()> {
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    if manifest.kernel_v2.is_some() {
        verify_snapshot_contents(path, manifest, observed, scratch_parent, advanced).await?;
        let scratch = tempfile::Builder::new()
            .prefix(".audit-v2-")
            .tempdir_in(scratch_parent)?;
        let copy = scratch.path().join("audit.db");
        consistent_copy(path, &copy).await?;
        let db = crate::db::open_kernel_v2_head_writer(&copy).await?;
        let result: Result<()> = async {
            let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
                .fetch_one(db.pool())
                .await?;
            if integrity != "ok" {
                return Err(Error::engine("kernel-v2 audit integrity failed"));
            }
            let before = crate::kernel::dump_all_kernel_tables(&db).await?;
            crate::kernel::replay_all_projections(&db).await?;
            if before != crate::kernel::dump_all_kernel_tables(&db).await? {
                return Err(Error::engine("kernel-v2 audit projection replay differs"));
            }
            Ok(())
        }
        .await;
        db.close().await;
        return result;
    }
    if advanced {
        verification_phase("advanced-manifest-consumer-identity", async {
            require_regular_no_symlink(path)?;
            manifest.validate()?;
            if let Some(observed) = observed {
                manifest
                    .consumer
                    .validate_observed_installed(observed)
                    .map_err(|error| error.at_standby_check(StandbyAdmissionCheck::Consumer))?;
            }
            Ok(())
        })
        .await?;
        let scratch_dir = tempfile::Builder::new()
            .prefix(".verify-head-")
            .tempdir_in(scratch_parent)?;
        let copy = scratch_dir.path().join("snapshot.db");
        verification_phase("advanced-consistent-copy", consistent_copy(path, &copy)).await?;
        verification_phase("engine-advanced-state", async {
            validate_generation_shape(&copy, manifest).await?;
            validate_advanced_state(&copy, manifest).await
        })
        .await?;
        verify_snapshot_database_deep(&copy, scratch_parent, true).await?;
    } else {
        verification_phase("byte-manifest-consumer-identity", async {
            verify_snapshot_byte_identity(path, manifest, observed)
        })
        .await?;
        verification_phase("engine-manifest-state", async {
            validate_generation_shape(path, manifest).await?;
            crate::standby_snapshot::validate_completed_export_manifest(path, manifest).await?;
            Ok(())
        })
        .await?;
        verify_snapshot_database_deep(path, scratch_parent, false).await?;
    }
    check_verification_cancellation()?;
    Ok(())
}

/// The pre-e15d82a deep checks, retained only for the deliberate off-path
/// audit: full `integrity_check` and foreign keys, the observational
/// conformance suite, and awareness projections. `path` must not change while
/// they run; a `disposable` path is a private copy the awareness rebuild may
/// write to directly.
async fn verify_snapshot_database_deep(
    path: &Path,
    scratch_parent: &Path,
    disposable: bool,
) -> Result<()> {
    verification_phase("sqlite-integrity-foreign-keys", async {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .immutable(true)
            .create_if_missing(false);
        let mut raw = sqlx::SqliteConnection::connect_with(&options).await?;
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&mut raw)
            .await?;
        let foreign_key_violation: i64 =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)")
                .fetch_one(&mut raw)
                .await?;
        let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
            .fetch_one(&mut raw)
            .await?;
        let embeddings: i64 = if marker == crate::db::V2_APPLICATION_ID {
            0
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM embeddings")
                .fetch_one(&mut raw)
                .await?
        };
        raw.close().await?;
        if integrity != "ok" || foreign_key_violation != 0 || embeddings != 0 {
            return Err(Error::engine(
                "standby snapshot integrity or foreign-key validation failed",
            )
            .at_standby_check(StandbyAdmissionCheck::Integrity));
        }
        Ok(())
    })
    .await?;
    verification_phase("observational-conformance", async {
        let readonly =
            crate::db::open_existing_database_standby_read_only(path.to_string_lossy().as_ref())
                .await?;
        let report = crate::conformance::run_standby_admission_conformance(&readonly).await;
        readonly.close().await;
        if !report.ok {
            return Err(Error::engine(format!(
                "standby snapshot conformance failed: {}",
                crate::conformance::format_report(&report)
            ))
            .at_standby_check(StandbyAdmissionCheck::Conformance));
        }
        Ok(())
    })
    .await?;
    if disposable {
        verification_phase(
            "awareness-projections",
            verify_awareness_projections_at(path),
        )
        .await
    } else {
        verification_phase(
            "awareness-projections",
            verify_awareness_projections(path, scratch_parent),
        )
        .await
    }
}

async fn verify_awareness_projections(path: &Path, scratch_parent: &Path) -> Result<()> {
    let scratch_dir = tempfile::Builder::new()
        .prefix(".verify-awareness-")
        .tempdir_in(scratch_parent)?;
    let scratch = scratch_dir.path().join("snapshot.db");
    fs::copy(path, &scratch)?;
    set_mode(&scratch, 0o600)?;
    verify_awareness_projections_at(&scratch).await?;
    drop(scratch_dir);
    Ok(())
}

/// Rebuild the awareness projections in a disposable database and require
/// them to equal what it already holds.
async fn verify_awareness_projections_at(scratch: &Path) -> Result<()> {
    let db = crate::open_database_at(scratch).await?;
    for table in crate::awareness::REBUILD_PROJECTION_TABLES {
        sqlx::query(&format!(
            "CREATE TABLE _standby_expected_{table} AS SELECT * FROM {table}"
        ))
        .execute(db.write_pool())
        .await?;
    }
    crate::awareness::rebuild_projections(&db).await?;
    for table in crate::awareness::REBUILD_PROJECTION_TABLES {
        for (left, right) in [
            (table.to_string(), format!("_standby_expected_{table}")),
            (format!("_standby_expected_{table}"), table.to_string()),
        ] {
            let changed: i64 = sqlx::query_scalar(&format!(
                "SELECT EXISTS(SELECT * FROM {left} EXCEPT SELECT * FROM {right})"
            ))
            .fetch_one(db.pool())
            .await?;
            if changed != 0 {
                db.close().await;
                return Err(Error::engine(format!(
                    "standby awareness projection drift in {table}"
                )));
            }
        }
    }
    db.close().await;
    Ok(())
}

/// One transactionally consistent copy of a database that may be written
/// concurrently. `VACUUM INTO` reads under a single shared lock.
async fn consistent_copy(source: &Path, destination: &Path) -> Result<()> {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(source)
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(std::time::Duration::from_secs(60));
    let mut connection = sqlx::SqliteConnection::connect_with(&options).await?;
    sqlx::query("VACUUM INTO ?")
        .bind(destination.to_string_lossy().as_ref())
        .execute(&mut connection)
        .await?;
    connection.close().await?;
    set_mode(destination, 0o600)
}

/// An advanced copy keeps its checkpoint's identity and schema and never
/// falls behind the checkpoint's act.
async fn validate_advanced_state(path: &Path, manifest: &StandbySnapshotManifest) -> Result<()> {
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    if manifest.kernel_v2.is_some() {
        return super::kernel_v2::validate_manifest(path, manifest, true).await;
    }
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(true)
        .immutable(true)
        .create_if_missing(false);
    let mut connection = sqlx::SqliteConnection::connect_with(&options).await?;
    let row = sqlx::query(
        "SELECT (SELECT origin_db_id FROM database_identity WHERE singleton=1) origin,
                (SELECT user_version FROM pragma_user_version) schema_version,
                (SELECT next_act FROM act_state WHERE singleton=1) head_act",
    )
    .fetch_one(&mut connection)
    .await?;
    let origin: Option<String> = row.try_get("origin")?;
    let schema_version: i64 = row.try_get("schema_version")?;
    let head_act: Option<i64> = row.try_get("head_act")?;
    connection.close().await?;
    if origin.as_deref() != Some(manifest.origin_database_id.as_str())
        || schema_version != manifest.engine.schema_version
        || head_act.unwrap_or_default() < manifest.head_act.unwrap_or_default()
    {
        return Err(Error::engine(
            "standby advanced copy does not continue its checkpoint",
        ));
    }
    Ok(())
}

async fn verify_database_successor(current: &Path, candidate: &Path) -> Result<()> {
    verification_phase(
        "successor-fence",
        verify_database_successor_contents(current, candidate),
    )
    .await
}

async fn verify_database_successor_contents(current: &Path, candidate: &Path) -> Result<()> {
    // Not immutable: the current generation may be advanced in place while
    // this runs, and SQLite's shared lock keeps each comparison consistent.
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(current)
        .read_only(true)
        .create_if_missing(false);
    let mut conn = sqlx::SqliteConnection::connect_with(&options).await?;
    sqlx::query("ATTACH DATABASE ? AS candidate")
        .bind(candidate.to_string_lossy().as_ref())
        .execute(&mut conn)
        .await?;
    let before: i64 = sqlx::query_scalar("PRAGMA main.application_id")
        .fetch_one(&mut conn)
        .await?;
    let after: i64 = sqlx::query_scalar("PRAGMA candidate.application_id")
        .fetch_one(&mut conn)
        .await?;
    if before != crate::db::V2_APPLICATION_ID && after == crate::db::V2_APPLICATION_ID {
        // Authenticated FULL acquisition is the engine switch boundary. The
        // manifest already binds route and imported source origin. Keep v1 on
        // disk; the two engines' acts and row shapes are incomparable.
        conn.close().await?;
        return Ok(());
    }
    if before == crate::db::V2_APPLICATION_ID && after != before {
        return Err(Error::engine("v2 generation cannot hot-fall back to v1"));
    }
    let v2_tables = [
        "content_events",
        "meta_events",
        "kernel_blobs",
        "content_event_causal_frontier",
    ];
    let tables: Vec<&str> = if before == crate::db::V2_APPLICATION_ID {
        v2_tables.to_vec()
    } else {
        SEQUENCED_LOGS
            .iter()
            .chain(UNSEQUENCED_APPEND_ONLY)
            .copied()
            .collect()
    };
    for table in tables {
        let sql = format!(
            "SELECT EXISTS(SELECT * FROM main.{table} EXCEPT SELECT * FROM candidate.{table})"
        );
        if sqlx::query(&sql)
            .fetch_one(&mut conn)
            .await?
            .get::<i64, _>(0)
            != 0
        {
            return Err(
                Error::engine(format!("standby candidate does not preserve {table}"))
                    .at_standby_check(StandbyAdmissionCheck::SuccessorPreservation),
            );
        }
    }
    for table in if before == crate::db::V2_APPLICATION_ID {
        &["act_cutover", "content_event_causal_cutover"][..]
    } else {
        UNFENCED_EXACT
    } {
        for (left, right) in [("main", "candidate"), ("candidate", "main")] {
            let sql = format!(
                "SELECT EXISTS(SELECT * FROM {left}.{table} EXCEPT SELECT * FROM {right}.{table})"
            );
            if sqlx::query(&sql)
                .fetch_one(&mut conn)
                .await?
                .get::<i64, _>(0)
                != 0
            {
                return Err(
                    Error::engine(format!("standby candidate changes unfenced {table}"))
                        .at_standby_check(StandbyAdmissionCheck::SuccessorPreservation),
                );
            }
        }
    }
    conn.close().await?;
    Ok(())
}

fn read_canonical_manifest(path: &Path) -> Result<StandbySnapshotManifest> {
    require_regular_no_symlink(path)?;
    let bytes = fs::read(path)?;
    let manifest: StandbySnapshotManifest = serde_json::from_slice(&bytes)?;
    if manifest.canonical_json()? != bytes {
        return Err(Error::engine("standby manifest is not canonical JSON"));
    }
    Ok(manifest)
}
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        check_verification_cancellation()?;
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

fn copy_into_owned_file(source: &Path, destination: &Path) -> Result<()> {
    require_regular_no_symlink(source)?;
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    set_mode(destination, 0o600)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn require_direct_regular_child(path: &Path, parent: &Path) -> Result<()> {
    if path.parent() != Some(parent) {
        return Err(Error::engine("standby staged input is outside staging"));
    }
    require_regular_no_symlink(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let file = fs::metadata(path)?;
        let directory = fs::metadata(parent)?;
        if file.nlink() != 1 || file.dev() != directory.dev() {
            return Err(Error::engine(
                "standby staged input is hard-linked or cross-filesystem",
            ));
        }
    }
    Ok(())
}
fn require_regular_no_symlink(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(Error::engine(
            "standby path is not a regular non-symlink file",
        ));
    }
    Ok(())
}
fn require_unambiguous_store_path(path: &Path) -> Result<()> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(Error::engine("standby store path must be absolute"));
    }
    let mut resolved = PathBuf::new();
    let mut normal_components = 0;
    for component in path.components() {
        match component {
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::Normal(name) => {
                normal_components += 1;
                resolved.push(name);
                match fs::symlink_metadata(&resolved) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(Error::engine(
                            "standby store path must not traverse symbolic links",
                        ));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(Error::engine(
                    "standby store path must be lexically unambiguous",
                ));
            }
        }
    }
    if normal_components == 0 {
        return Err(Error::engine(
            "standby store path must not be filesystem root",
        ));
    }
    Ok(())
}
fn require_directory_no_symlink(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::engine("standby generation path is not a directory"));
    }
    Ok(())
}

fn require_published_generation(path: &Path) -> Result<()> {
    require_generation_shape(path, 0o500)
}

fn require_generation_shape(path: &Path, directory_mode: u32) -> Result<()> {
    require_directory_no_symlink(path)?;
    let mut children = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    children.sort();
    if children != ["manifest.json", "snapshot.db"].map(std::ffi::OsString::from) {
        return Err(Error::engine(
            "standby published generation contains unexpected entries",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = fs::metadata(path)?;
        if directory.permissions().mode() & 0o777 != directory_mode {
            return Err(Error::engine(
                "standby published generation directory mode is invalid",
            ));
        }
        for name in ["snapshot.db", "manifest.json"] {
            let child = path.join(name);
            require_regular_no_symlink(&child)?;
            let metadata = fs::metadata(child)?;
            if metadata.nlink() != 1 || metadata.permissions().mode() & 0o777 != 0o400 {
                return Err(Error::engine(
                    "standby published generation file ownership shape is invalid",
                ));
            }
        }
    }
    let _ = directory_mode;
    Ok(())
}
/// A generation advanced in place keeps its read-only manifest, but its
/// directory and database become owner-writable and an interrupted delta may
/// leave SQLite's rollback journal beside the database.
fn require_advanced_generation_shape(path: &Path) -> Result<()> {
    require_directory_no_symlink(path)?;
    let mut children = fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    children.retain(|name| name != "snapshot.db-journal");
    children.sort();
    if children != ["manifest.json", "snapshot.db"].map(std::ffi::OsString::from) {
        return Err(Error::engine(
            "standby advanced generation contains unexpected entries",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = fs::metadata(path)?.permissions().mode() & 0o777;
        if directory != 0o500 && directory != 0o700 {
            return Err(Error::engine(
                "standby advanced generation directory mode is invalid",
            ));
        }
        for (name, modes) in [
            ("snapshot.db", [0o400, 0o600]),
            ("manifest.json", [0o400, 0o400]),
        ] {
            let child = path.join(name);
            require_regular_no_symlink(&child)?;
            let metadata = fs::metadata(child)?;
            if metadata.nlink() != 1 || !modes.contains(&(metadata.permissions().mode() & 0o777)) {
                return Err(Error::engine(
                    "standby advanced generation file ownership shape is invalid",
                ));
            }
        }
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
        set_mode(path, 0o700)?;
    }
    check_private_directory(path)
}

/// What the store requires of a directory that already exists: a real
/// directory (not a symlink) with no group or other access. Shared by
/// [`create_private_directory`] and [`GenerationStore::check_existing_root`].
fn check_private_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::engine("standby store path is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::engine("standby store directory is not owner-only"));
        }
    }
    Ok(())
}
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let _ = (path, mode);
    Ok(())
}

fn reject_sqlite_sidecars(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
            return Err(Error::engine(
                "standby staged snapshot has a SQLite sidecar",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_directory_no_replace(source: &Path, destination: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn renameat2(a: i32, b: *const i8, c: i32, d: *const i8, e: u32) -> i32;
    }
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| Error::engine("invalid generation path"))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| Error::engine("invalid generation path"))?;
    if unsafe { renameat2(-100, source.as_ptr(), -100, destination.as_ptr(), 1) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn rename_directory_no_replace(source: &Path, destination: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn renamex_np(source: *const i8, destination: *const i8, flags: u32) -> i32;
    }
    // Apple XNU's RENAME_EXCL: an existing destination is never replaced.
    const RENAME_EXCL: u32 = 0x0000_0004;
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| Error::engine("invalid generation path"))?;
    let destination = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| Error::engine("invalid generation path"))?;
    if unsafe { renamex_np(source.as_ptr(), destination.as_ptr(), RENAME_EXCL) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_directory_no_replace(_: &Path, _: &Path) -> Result<()> {
    Err(Error::engine(
        "standby publication requires an exclusive atomic directory rename",
    ))
}

#[cfg(test)]
pub(crate) mod test_diagnostics {
    use std::io::Write;
    use std::sync::{Arc, Mutex, OnceLock};
    use tracing_subscriber::prelude::*;

    /// Capturing tests install a scoped dispatcher and rebuild tracing's
    /// process-wide callsite interest cache. Two hazards follow:
    ///
    /// 1. Concurrent captures race that rebuild, so every log-capturing test
    ///    holds this crate-wide lock for its whole capture. Async tests take it
    ///    with `.lock().await`; synchronous tests would use `blocking_lock()`,
    ///    never inside a runtime.
    /// 2. While exactly one dispatcher is registered, tracing computes the
    ///    interest of a callsite it has not seen before from the *current
    ///    thread's* default. A non-capturing test thread that reaches a
    ///    verification callsite first would cache it as `Interest::never`, and
    ///    the capturing test would then silently drop that event.
    ///    `keepalive()` keeps a second, no-op dispatcher registered so interest
    ///    is always resolved against the whole registered set instead.
    pub(crate) static LOG_CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn keepalive() -> &'static tracing::Dispatch {
        static KEEPALIVE: OnceLock<tracing::Dispatch> = OnceLock::new();
        KEEPALIVE.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new()))
    }

    #[derive(Clone, Default)]
    pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
            let _ = keepalive();
            let writer = self.clone();
            tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer()
                    .without_time()
                    .with_ansi(false)
                    .with_writer(move || writer.clone())
                    .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                        metadata.target() == "native_ce::standby::verification"
                    })),
            )
        }
        pub(crate) fn output(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::standby_snapshot::{
        HostedStandbyManifestContext, ProducerBuildIdentity, StandbyConsumerIdentity,
        StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT,
    };

    #[test]
    fn store_path_rejects_root_and_ambiguous_components() {
        assert!(require_unambiguous_store_path(Path::new("/")).is_err());
        assert!(require_unambiguous_store_path(Path::new("/tmp/..")).is_err());
        assert!(require_unambiguous_store_path(Path::new("relative")).is_err());
    }

    fn consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "b".repeat(40),
            artifact_sha256: "c".repeat(64),
            engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
        }
    }

    #[test]
    fn check_existing_root_judges_a_partial_tree_as_open_does() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap().join("replica");
        // A private accepted/, staging missing, and a group-readable
        // generations/ below the gap: open would create staging, then refuse
        // generations. The read-only check must not stop at the gap.
        fs::create_dir_all(root.join("accepted/generations")).unwrap();
        for private in [root.clone(), root.join("accepted")] {
            fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::set_permissions(
            root.join("accepted/generations"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(GenerationStore::check_existing_root(&root).is_err());
        assert!(
            !root.join("accepted/staging").exists(),
            "the check creates nothing"
        );
        assert!(GenerationStore::open(&root, "route", None).is_err());
        // Repaired, the same partial tree passes both.
        fs::set_permissions(
            root.join("accepted/generations"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(GenerationStore::check_existing_root(&root).unwrap());
        assert!(GenerationStore::open(&root, "route", None).is_ok());
    }

    pub(crate) fn observed() -> ObservedInstalledConsumerIdentity {
        let consumer = consumer();
        ObservedInstalledConsumerIdentity {
            platform: consumer.platform,
            source_sha: consumer.source_sha,
            artifact_sha256: consumer.artifact_sha256,
            engine_schema_version: consumer.engine_schema_version,
            ddl_sha256: consumer.ddl_sha256,
        }
    }

    pub(crate) async fn stage(
        store: &GenerationStore,
        db: &crate::Db,
        stem: &str,
    ) -> (PathBuf, PathBuf) {
        let export = crate::export::export_connected_db(db, None).await.unwrap();
        let snapshot = store.staging_dir().join(format!("{stem}.db"));
        fs::copy(export.path(), &snapshot).unwrap();
        let manifest = crate::standby_snapshot::manifest_from_completed_export(
            &snapshot,
            export.size_bytes(),
            sha256_file(&snapshot).unwrap(),
            export.captured_at().into(),
            export.snapshot_completed_at().into(),
            HostedStandbyManifestContext::new_with_producer(
                "route-1".into(),
                consumer(),
                ProducerBuildIdentity::new("a".repeat(40), crate::schema::FROZEN_DDL_SHA256.into())
                    .unwrap(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let manifest_path = store.staging_dir().join(format!("{stem}.json"));
        fs::write(&manifest_path, manifest.canonical_json().unwrap()).unwrap();
        export.cleanup().await;
        (snapshot, manifest_path)
    }

    async fn exported_file(db: &crate::Db, directory: &Path, name: &str) -> PathBuf {
        let export = crate::export::export_connected_db(db, None).await.unwrap();
        let path = directory.join(name);
        fs::copy(export.path(), &path).unwrap();
        export.cleanup().await;
        path
    }

    async fn open_raw(path: &Path) -> sqlx::SqliteConnection {
        sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn install_refusals_carry_actual_act_and_scalar_fence_checks() {
        for advanced in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let db = crate::create_database(":memory:").await.unwrap();
            let origin = crate::identity::database_id(&db).await.unwrap();
            let store =
                GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
            let (older_snapshot, older_manifest) = stage(&store, &db, "older").await;
            crate::store::create_record(
                &db,
                serde_json::json!({"type":"Document","kind":"note","name":"advance"}),
            )
            .await
            .unwrap();
            let (snapshot, manifest) = stage(&store, &db, "newer").await;
            let installed = store
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap();
            if advanced {
                store
                    .record_synced(
                        &installed,
                        installed.manifest.head_act.unwrap() + 1,
                        "2026-10-13T00:00:00.000Z",
                    )
                    .unwrap();
            }
            if advanced {
                store.require_full_refresh(&installed).unwrap();
            }
            let error = store
                .install_staged(&older_snapshot, &older_manifest, &observed())
                .await
                .unwrap_err();
            let expected = if advanced {
                StandbyAdmissionCheck::ActOrderContinuity
            } else {
                StandbyAdmissionCheck::ScalarRollbackContinuity
            };
            assert!(
                matches!(error, Error::StandbyAdmission { check, .. } if check == expected),
                "{error}"
            );
            db.close().await;
        }
    }

    /// How [`become_other_revision_current`] rewrites the current generation.
    struct OtherRevision {
        schema_version: i64,
        route: Option<&'static str>,
        origin: Option<String>,
        /// The manifest's `head_act`; `None` omits it.
        manifest_head_act: Option<i64>,
        /// Delta head to write (`full_refresh_required`), or none at all.
        head: Option<bool>,
    }

    impl OtherRevision {
        /// One schema older, advanced in place by trusted deltas (or flagged
        /// for a full refresh): the shape the rev7 replica had.
        fn older_delta_advanced(
            manifest_head_act: Option<i64>,
            full_refresh_required: bool,
        ) -> Self {
            Self {
                schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION - 1,
                route: None,
                origin: None,
                manifest_head_act,
                head: Some(full_refresh_required),
            }
        }

        /// A plain checkpoint with no head file, as before any delta.
        fn without_head(schema_version: i64, manifest_head_act: Option<i64>) -> Self {
            Self {
                schema_version,
                route: None,
                origin: None,
                manifest_head_act,
                head: None,
            }
        }
    }

    /// Rewrite the current generation as another engine revision wrote it: a
    /// manifest this build's `validate` rejects (other schema, DDL and
    /// consumer build). With a head it has the modes and delta head trusted
    /// deltas leave; without one it stays a read-only checkpoint. Returns the
    /// rewritten generation's id.
    fn become_other_revision_current(
        store: &GenerationStore,
        installed: &InstalledGeneration,
        spec: OtherRevision,
    ) -> String {
        let mut old = installed.manifest.clone();
        let installed_act = old.head_act.unwrap();
        old.engine.schema_version = spec.schema_version;
        old.engine.ddl_sha256 = "d".repeat(64);
        old.consumer.engine_schema_version = spec.schema_version;
        old.consumer.ddl_sha256 = "d".repeat(64);
        old.consumer.source_sha = "e".repeat(40);
        old.head_act = spec.manifest_head_act;
        if let Some(route) = spec.route {
            old.hosted_route_database_id = route.into();
        }
        if let Some(origin) = spec.origin {
            old.origin_database_id = origin;
        }
        assert!(
            old.validate().is_err(),
            "another revision must not validate"
        );
        let bytes = serde_jcs::to_vec(&old).unwrap();
        let id = hex::encode(Sha256::digest(&bytes));

        let generations = store.root.join("generations");
        let from = generations.join(&installed.id);
        let to = generations.join(&id);
        set_mode(&from, 0o700).unwrap();
        fs::rename(&from, &to).unwrap();
        set_mode(&to.join("manifest.json"), 0o600).unwrap();
        fs::write(to.join("manifest.json"), bytes).unwrap();
        set_mode(&to.join("manifest.json"), 0o400).unwrap();
        store.remove_generation_head(&installed.id).unwrap();
        store
            .write_pointer(&CurrentPointer {
                contract: POINTER_CONTRACT.into(),
                version: 1,
                generation_id: id.clone(),
                snapshot_sha256: old.snapshot.sha256.clone(),
            })
            .unwrap();
        match spec.head {
            Some(full_refresh_required) => {
                set_mode(&to.join("snapshot.db"), 0o600).unwrap();
                store
                    .write_generation_head(&GenerationHead {
                        contract: GENERATION_HEAD_CONTRACT.into(),
                        version: 1,
                        generation_id: id.clone(),
                        head_act: installed_act + 1,
                        materialization: StandbyGenerationMaterialization::Delta,
                        synced_at: "2026-10-12T20:22:34.597Z".into(),
                        full_refresh_required,
                    })
                    .unwrap();
            }
            None => set_mode(&to, 0o500).unwrap(),
        }
        id
    }

    async fn store_with_installed(dir: &Path) -> (crate::Db, GenerationStore, InstalledGeneration) {
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store = GenerationStore::open(dir.join("replica"), "route-1", Some(origin)).unwrap();
        let (snapshot, manifest) = stage(&store, &db, "old").await;
        let installed = store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        (db, store, installed)
    }

    async fn advance_and_stage(
        store: &GenerationStore,
        db: &crate::Db,
        stem: &str,
        records: usize,
    ) -> (PathBuf, PathBuf) {
        for n in 0..records {
            crate::store::create_record(
                db,
                serde_json::json!({"type":"Document","kind":"note","name":format!("{stem}-{n}")}),
            )
            .await
            .unwrap();
        }
        stage(store, db, stem).await
    }

    #[tokio::test]
    async fn full_snapshot_replaces_other_revision_current() {
        let current = crate::CURRENT_ENGINE_SCHEMA_VERSION;
        // Older and newer revisions, delta-advanced or flagged for a full
        // refresh. The newer direction is allowed on purpose: this build
        // cannot read that copy either, and a whole snapshot repairs it.
        for (schema_version, full_refresh_required) in [
            (current - 1, false),
            (current - 1, true),
            (current + 1, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (db, store, installed) = store_with_installed(dir.path()).await;
            let mut spec = OtherRevision::older_delta_advanced(
                installed.manifest.head_act,
                full_refresh_required,
            );
            spec.schema_version = schema_version;
            let old_id = become_other_revision_current(&store, &installed, spec);

            // The candidate is ahead of the copy's deltas, so act order holds.
            let (snapshot, manifest) = advance_and_stage(&store, &db, "new", 2).await;
            let replaced = store
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap();
            assert_ne!(replaced.id, old_id);
            assert_eq!(store.read_pointer().unwrap().generation_id, replaced.id);
            assert!(store
                .generation_head(&replaced.id)
                .unwrap()
                .is_none_or(|head| !head.advanced_in_place()));
            db.close().await;
        }
    }

    #[tokio::test]
    async fn other_revision_current_still_fences_route_origin_and_act_order() {
        let other_origin = format!("ndb_{}", "0".repeat(32));
        for case in ["route", "origin", "act"] {
            let dir = tempfile::tempdir().unwrap();
            let (db, store, installed) = store_with_installed(dir.path()).await;
            let mut spec = OtherRevision::older_delta_advanced(installed.manifest.head_act, false);
            match case {
                "route" => spec.route = Some("route-0"),
                "origin" => spec.origin = Some(other_origin.clone()),
                _ => {}
            }
            let old_id = become_other_revision_current(&store, &installed, spec);
            // Identity cases bring a candidate ahead in act order, so only the
            // identity differs. The act case brings one the copy's deltas
            // (head_act + 1) have already passed.
            let records = if case == "act" { 0 } else { 2 };
            let (snapshot, manifest) = advance_and_stage(&store, &db, "candidate", records).await;
            let error = store
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap_err();
            assert!(
                matches!(error, Error::StandbyAdmission { check, .. } if check == StandbyAdmissionCheck::ActOrderContinuity),
                "{case}: {error}"
            );
            assert_eq!(
                store.read_pointer().unwrap().generation_id,
                old_id,
                "{case}"
            );
            db.close().await;
        }
    }

    #[tokio::test]
    async fn other_revision_current_without_an_act_frontier_refuses_and_keeps_current() {
        // (schema, expected refusal): an act-capable manifest must carry its
        // act; a pre-act one is accepted as a copy but gives no floor.
        for (schema_version, expected) in [
            (
                crate::CURRENT_ENGINE_SCHEMA_VERSION - 1,
                "missing its act frontier",
            ),
            (58, "holds no act frontier"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (db, store, installed) = store_with_installed(dir.path()).await;
            let old_id = become_other_revision_current(
                &store,
                &installed,
                OtherRevision::without_head(schema_version, None),
            );
            let pointer_before = fs::read(store.root.join("current.json")).unwrap();
            // A verified candidate that would be backwards if the copy held
            // any act at all.
            let (snapshot, manifest) = stage(&store, &db, "candidate").await;
            let error = store
                .install_staged(&snapshot, &manifest, &observed())
                .await
                .unwrap_err();
            assert!(
                matches!(error, Error::StandbyAdmission { check, .. } if check == StandbyAdmissionCheck::CurrentGeneration),
                "{schema_version}: {error}"
            );
            assert!(error.to_string().contains(expected), "{error}");
            assert_eq!(
                fs::read(store.root.join("current.json")).unwrap(),
                pointer_before
            );
            assert_eq!(store.read_pointer().unwrap().generation_id, old_id);
            db.close().await;
        }
    }

    #[tokio::test]
    async fn actual_integrity_refusal_carries_integrity_check() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let snapshot = exported_file(&db, dir.path(), "foreign-key.db").await;
        let mut conn = open_raw(&snapshot).await;
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO links (id, source_id, target_id, relationship) VALUES ('bad-link', 'missing', 'missing', 'relates_to')")
            .execute(&mut conn).await.unwrap();
        conn.close().await.unwrap();
        let error = verify_snapshot_database_deep(&snapshot, dir.path(), false)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::StandbyAdmission {
                    check: StandbyAdmissionCheck::Integrity,
                    ..
                }
            ),
            "{error}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn actual_conformance_refusal_keeps_its_stage_despite_body_words() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        crate::store::create_record(&db, serde_json::json!({"type":"Document","kind":"note","name":"sentinel","body":"original"})).await.unwrap();
        let snapshot = exported_file(&db, dir.path(), "drift.db").await;
        let mut conn = open_raw(&snapshot).await;
        sqlx::query("UPDATE records SET body='route origin consumer credential-SENTINEL' WHERE name='sentinel'")
            .execute(&mut conn).await.unwrap();
        conn.close().await.unwrap();
        let error = verify_snapshot_database_deep(&snapshot, dir.path(), false)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::StandbyAdmission {
                    check: StandbyAdmissionCheck::Conformance,
                    ..
                }
            ),
            "{error}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn connected_activation_recovers_full_durable_orphan_without_hot_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store = GenerationStore::open(
            std::fs::canonicalize(dir.path()).unwrap().join("replica"),
            "route-1",
            Some(origin),
        )
        .unwrap();
        let (snapshot, manifest) = stage(&store, &db, "first").await;
        let first = store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        let StandbyStartupOutcome::Serving(active) =
            store.activate_for_startup(&observed()).await.unwrap()
        else {
            panic!("startup")
        };
        let pointer = fs::read(store.root.join("current.json")).unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"durable successor"}),
        )
        .await
        .unwrap();
        let (snapshot, manifest) = stage(&store, &db, "second").await;
        assert!(store
            .install_staged_with_hook(&snapshot, &manifest, &observed(), |transition| {
                if transition == PublishTransition::GenerationDurable {
                    Err(Error::engine("interrupted before pointer publication"))
                } else {
                    Ok(())
                }
            })
            .await
            .is_err());
        assert_eq!(fs::read(store.root.join("current.json")).unwrap(), pointer);
        let hints = store.handoff_candidates_hint().unwrap();
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].generation_id(), first.id);
        let recovered = store
            .activate_accepted(&hints[1], &observed(), Some(&active))
            .await
            .unwrap();
        store.confirm_handoff(&recovered).unwrap();
        assert_eq!(
            store
                .accepted_identity_hint()
                .unwrap()
                .unwrap()
                .generation_id(),
            recovered.generation.id
        );
        // A newer external acceptance arriving before pinning cannot starve a
        // valid intermediate successor. Its complete device verification permits
        // progress without ever replacing the newer accepted pointer.
        crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"newer desired state"}),
        )
        .await
        .unwrap();
        let (snapshot, manifest) = stage(&store, &db, "third").await;
        let newest = store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        let progress = store
            .activate_accepted(&hints[1], &observed(), Some(&active))
            .await
            .unwrap();
        assert_eq!(progress.generation.id, recovered.generation.id);
        assert_eq!(
            store
                .accepted_identity_hint()
                .unwrap()
                .unwrap()
                .generation_id(),
            newest.id
        );
        store.confirm_handoff(&progress).unwrap();
        // The active floor refuses both a valid older pointer and a malformed
        // descriptor. Startup recovery is deliberately a separate authority.
        // The fence below, not any cached proof, refuses the regression.
        fs::write(store.root.join("current.json"), pointer).unwrap();
        assert!(store
            .activate_accepted(&hints[0], &observed(), Some(&recovered))
            .await
            .is_err());
        assert!(store.confirm_handoff(&recovered).is_err());
        fs::write(store.root.join("current.json"), b"malformed").unwrap();
        assert!(store.handoff_candidates_hint().is_err());
        assert!(store.confirm_handoff(&recovered).is_err());
        assert!(recovered.generation.snapshot_path.is_file());
        db.close().await;
    }

    #[tokio::test]
    async fn connected_floor_refuses_full_valid_divergence_even_with_equal_frontiers() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store =
            GenerationStore::open(root.join("replica"), "route-1", Some(origin.clone())).unwrap();
        let fork_path = exported_file(&db, &root, "fork.db").await;
        let fork = crate::open_existing_database(fork_path.to_str().unwrap())
            .await
            .unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"served branch"}),
        )
        .await
        .unwrap();
        crate::store::create_record(
            &fork,
            serde_json::json!({"type":"Document","kind":"note","name":"divergent branch"}),
        )
        .await
        .unwrap();
        let (snapshot, manifest) = stage(&store, &db, "served").await;
        store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        let StandbyStartupOutcome::Serving(active) =
            store.activate_for_startup(&observed()).await.unwrap()
        else {
            panic!("startup")
        };
        let donor = GenerationStore::open(root.join("donor"), "route-1", Some(origin)).unwrap();
        let (snapshot, manifest) = stage(&donor, &fork, "fork").await;
        let divergent = donor
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        assert_eq!(
            active.generation.manifest.frontier,
            divergent.manifest.frontier
        );
        // Model an external accepted descriptor containing individually valid
        // bytes from the wrong branch. The device verifier must succeed;
        // the actual served predecessor/successor fence must still refuse.
        let destination = store.root.join("generations").join(&divergent.id);
        fs::create_dir(&destination).unwrap();
        fs::copy(&divergent.snapshot_path, destination.join("snapshot.db")).unwrap();
        fs::write(
            destination.join("manifest.json"),
            divergent.manifest.canonical_json().unwrap(),
        )
        .unwrap();
        set_mode(&destination.join("snapshot.db"), 0o400).unwrap();
        set_mode(&destination.join("manifest.json"), 0o400).unwrap();
        set_mode(&destination, 0o500).unwrap();
        store
            .write_pointer(&CurrentPointer {
                contract: POINTER_CONTRACT.into(),
                version: 1,
                generation_id: divergent.id.clone(),
                snapshot_sha256: divergent.manifest.snapshot.sha256.clone(),
            })
            .unwrap();
        store
            .verify_generation_for_startup(&divergent.id, &observed())
            .await
            .unwrap();
        let hint = store.accepted_identity_hint().unwrap().unwrap();
        use tracing::instrument::WithSubscriber;
        let logs = test_diagnostics::Capture::default();
        let error = store
            .activate_accepted(&hint, &observed(), Some(&active))
            .with_subscriber(logs.subscriber())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not preserve"));
        assert!(matches!(
            error,
            Error::StandbyAdmission {
                check: StandbyAdmissionCheck::SuccessorPreservation,
                ..
            }
        ));
        assert_eq!(
            logs.output()
                .lines()
                .filter(|line| line.contains("standby suite started"))
                .count(),
            0,
            "device checks plus successor fence refuse pair divergence with no conformance suite"
        );
        assert!(active.generation.snapshot_path.is_file());
        fork.close().await;
        db.close().await;
    }

    #[tokio::test]
    async fn cancelled_verification_has_no_completion_receipt() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        use tracing::instrument::WithSubscriber;
        let logs = test_diagnostics::Capture::default();
        let mut work = Box::pin(
            verification_phase::<()>("cancelled-fixture", std::future::pending())
                .with_subscriber(logs.subscriber()),
        );
        assert!(matches!(
            futures::poll!(&mut work),
            std::task::Poll::Pending
        ));
        drop(work);
        let output = logs.output();
        assert!(output.contains("standby phase started phase=\"cancelled-fixture\""));
        assert!(!output.contains("standby phase finished"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn promotion_lock_rejects_symlinks_and_hard_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"do not chmod or lock me").unwrap();
        let symlink_path = directory.path().join("symlink.lock");
        symlink(&target, &symlink_path).unwrap();
        assert!(acquire_promotion_lock(symlink_path).await.is_err());

        let hard_link = directory.path().join("hard-link.lock");
        fs::hard_link(&target, &hard_link).unwrap();
        assert!(acquire_promotion_lock(hard_link).await.is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn generation_rename_never_replaces_an_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("source-marker"), b"source").unwrap();
        fs::write(destination.join("destination-marker"), b"destination").unwrap();
        assert!(rename_directory_no_replace(&source, &destination).is_err());
        assert_eq!(fs::read(source.join("source-marker")).unwrap(), b"source");
        assert_eq!(
            fs::read(destination.join("destination-marker")).unwrap(),
            b"destination"
        );
    }

    #[tokio::test]
    async fn durable_generation_precedes_pointer_and_failed_next_publish_keeps_current() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store =
            GenerationStore::open(root.path().join("standby"), "route-1", Some(origin)).unwrap();
        let (snapshot, manifest) = stage(&store, &db, "first").await;
        let wrong_route =
            GenerationStore::open(root.path().join("standby"), "route-wrong", None).unwrap();
        let error = wrong_route
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("configured route/origin"));
        assert!(!store.root.join("current.json").exists());
        assert_eq!(
            fs::read_dir(store.root.join("generations"))
                .unwrap()
                .count(),
            0,
            "ordinary refusal must remove its owned publication workspace"
        );
        let installed = store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        assert!(installed.snapshot_path.is_file());
        let first_pointer = fs::read(store.root.join("current.json")).unwrap();

        let retry_snapshot = store.staging_dir().join("retry.db");
        let retry_manifest = store.staging_dir().join("retry.json");
        fs::copy(&installed.snapshot_path, &retry_snapshot).unwrap();
        fs::copy(
            store
                .root
                .join("generations")
                .join(&installed.id)
                .join("manifest.json"),
            &retry_manifest,
        )
        .unwrap();
        let retry = store
            .install_staged(&retry_snapshot, &retry_manifest, &observed())
            .await
            .unwrap();
        assert_eq!(retry.id, installed.id);
        assert_eq!(
            fs::read(store.root.join("current.json")).unwrap(),
            first_pointer
        );

        let (snapshot, manifest) = stage(&store, &db, "second").await;
        let error = store
            .install_staged_with_hook(&snapshot, &manifest, &observed(), |point| {
                if point == PublishTransition::GenerationDurable {
                    return Err(Error::engine("crash"));
                }
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("crash"));
        assert_eq!(
            fs::read(store.root.join("current.json")).unwrap(),
            first_pointer
        );
        let orphan = fs::read_dir(store.root.join("generations"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name.len() == 64 && name != installed.id
            })
            .unwrap();
        let startup_recovered = store.activate_for_startup(&observed()).await.unwrap();
        let StandbyStartupOutcome::Serving(startup_recovered) = startup_recovered else {
            panic!("durable orphan successor must be recoverable at startup");
        };
        assert_eq!(
            startup_recovered.generation.id,
            orphan.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(
            startup_recovered.startup_reason,
            Some(StandbyStartupReason::DurableGenerationRecovered)
        );
        drop(startup_recovered);
        let orphan_snapshot = store.staging_dir().join("orphan-retry.db");
        let orphan_manifest = store.staging_dir().join("orphan-retry.json");
        fs::copy(orphan.join("snapshot.db"), &orphan_snapshot).unwrap();
        fs::copy(orphan.join("manifest.json"), &orphan_manifest).unwrap();
        let recovered = store
            .install_staged(&orphan_snapshot, &orphan_manifest, &observed())
            .await
            .unwrap();
        assert_eq!(recovered.id, orphan.file_name().unwrap().to_string_lossy());
        assert_ne!(
            fs::read(store.root.join("current.json")).unwrap(),
            first_pointer
        );
        let pointer_before_tamper = fs::read(store.root.join("current.json")).unwrap();
        set_mode(&recovered.snapshot_path, 0o600).unwrap();
        assert!(matches!(
            store.read_current_manifest(),
            Err(Error::StandbyAdmission {
                check: StandbyAdmissionCheck::CurrentGeneration,
                ..
            })
        ));
        assert_eq!(
            fs::read(store.root.join("current.json")).unwrap(),
            pointer_before_tamper
        );
        db.close().await;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn unselected_generation_after_rename_is_reverified_before_hardening() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store =
            GenerationStore::open(root.path().join("standby"), "route-1", Some(origin)).unwrap();
        let (snapshot, manifest_path) = stage(&store, &db, "orphan").await;
        let manifest = read_canonical_manifest(&manifest_path).unwrap();
        let id = hex::encode(Sha256::digest(manifest.canonical_json().unwrap()));
        let destination = store.root.join("generations").join(&id);
        fs::create_dir(&destination).unwrap();
        set_mode(&destination, 0o700).unwrap();
        let owned_snapshot = destination.join("snapshot.db");
        fs::copy(&snapshot, &owned_snapshot).unwrap();
        let owned_manifest = destination.join("manifest.json");
        fs::copy(&manifest_path, &owned_manifest).unwrap();
        set_mode(&owned_snapshot, 0o400).unwrap();
        set_mode(&owned_manifest, 0o400).unwrap();

        // A partial publication is not selected, and matching the manifest
        // alone must not let altered bytes through the recovery path.
        assert!(!store.root.join("current.json").exists());
        fs::remove_file(&owned_snapshot).unwrap();
        fs::write(&owned_snapshot, b"altered snapshot").unwrap();
        set_mode(&owned_snapshot, 0o400).unwrap();
        assert!(store
            .install_staged(&snapshot, &manifest_path, &observed())
            .await
            .is_err());
        assert!(!store.root.join("current.json").exists());

        fs::remove_file(&owned_snapshot).unwrap();
        fs::copy(&snapshot, &owned_snapshot).unwrap();
        set_mode(&owned_snapshot, 0o400).unwrap();
        let installed = store
            .install_staged(&snapshot, &manifest_path, &observed())
            .await
            .unwrap();
        assert_eq!(installed.id, id);
        require_published_generation(&destination).unwrap();
        assert!(store.root.join("current.json").is_file());
        db.close().await;
    }

    #[tokio::test]
    async fn startup_revalidates_current_and_falls_back_from_corruption() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        use tracing::instrument::WithSubscriber;
        let logs = test_diagnostics::Capture::default();
        startup_corruption_fixture()
            .with_subscriber(logs.subscriber())
            .await;
        let output = logs.output();
        let last_candidate = output
            .lines()
            .rev()
            .find(|line| line.contains("standby phase finished phase=\"candidate\""))
            .unwrap();
        assert!(
            last_candidate.contains("ok=false"),
            "a refused candidate never completes successfully"
        );
        for phase in [
            "candidate",
            "predecessor",
            "startup-generation",
            "startup-snapshot",
            "byte-manifest-consumer-identity",
            "engine-manifest-state",
            "sqlite-quick-check-foreign-keys",
            "successor-fence",
        ] {
            assert!(
                output
                    .lines()
                    .any(|line| line.contains("standby phase started")
                        && line.contains(&format!("phase=\"{phase}\""))),
                "missing start for {phase}"
            );
            assert!(
                output
                    .lines()
                    .any(|line| line.contains("standby phase finished")
                        && line.contains(&format!("phase=\"{phase}\""))
                        && line.contains("ok=true")
                        && line.contains("elapsed_ms=")),
                "missing success for {phase}"
            );
        }
        for phase in [
            "candidate",
            "startup-generation",
            "startup-snapshot",
            "byte-manifest-consumer-identity",
        ] {
            assert!(
                output
                    .lines()
                    .any(|line| line.contains("standby phase finished")
                        && line.contains(&format!("phase=\"{phase}\""))
                        && line.contains("ok=false")),
                "missing refusal for {phase}"
            );
        }
        assert!(
            output
                .find("standby phase finished phase=\"candidate\"")
                .unwrap()
                < output
                    .find("standby phase started phase=\"predecessor\"")
                    .unwrap()
        );
        assert!(
            !output.contains("standby suite started"),
            "admission and startup run no conformance suite"
        );
        assert!(
            !output.contains("rebuild-and-diff"),
            "admission and startup run no historical rebuild"
        );
    }

    async fn startup_corruption_fixture() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store =
            GenerationStore::open(root.path().join("standby"), "route-1", Some(origin)).unwrap();

        crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"prior"}),
        )
        .await
        .unwrap();
        let (prior_snapshot, prior_manifest) = stage(&store, &db, "prior").await;
        let prior = store
            .install_staged(&prior_snapshot, &prior_manifest, &observed())
            .await
            .unwrap();

        crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"current"}),
        )
        .await
        .unwrap();
        let (current_snapshot, current_manifest) = stage(&store, &db, "current").await;
        let current = store
            .install_staged(&current_snapshot, &current_manifest, &observed())
            .await
            .unwrap();

        let clean = store.activate_for_startup(&observed()).await.unwrap();
        let StandbyStartupOutcome::Serving(clean) = clean else {
            panic!("installed current generation must serve");
        };
        assert_eq!(clean.generation.id, current.id);
        assert_eq!(clean.startup_reason, None);
        drop(clean);

        // A corrupt staged candidate must refuse without changing current.
        let pointer_before = fs::read(store.root.join("current.json")).unwrap();
        let (bad_snapshot, bad_manifest) = stage(&store, &db, "corrupt-candidate").await;
        fs::write(&bad_snapshot, b"corrupt").unwrap();
        assert!(store
            .install_staged(&bad_snapshot, &bad_manifest, &observed())
            .await
            .is_err());
        assert_eq!(
            fs::read(store.root.join("current.json")).unwrap(),
            pointer_before
        );

        set_mode(&current.snapshot_path, 0o600).unwrap();
        fs::write(&current.snapshot_path, b"corrupt").unwrap();
        set_mode(&current.snapshot_path, 0o400).unwrap();
        let recovered = store.activate_for_startup(&observed()).await.unwrap();
        let StandbyStartupOutcome::Serving(recovered) = recovered else {
            panic!("a verified prior generation must be selected");
        };
        assert_eq!(recovered.generation.id, prior.id);
        assert_eq!(
            recovered.startup_reason,
            Some(StandbyStartupReason::CurrentUnusable)
        );
        assert_eq!(store.read_pointer().unwrap().generation_id, prior.id);
        let startup_state: serde_json::Value =
            serde_json::from_slice(&fs::read(store.root.join("startup-state.json")).unwrap())
                .unwrap();
        assert_eq!(startup_state["contract"], "native.standby-startup-state.v1");
        assert_eq!(startup_state["generation_id"], prior.id);
        assert_eq!(startup_state["reason"], "current_unusable");
        assert_eq!(
            store.recorded_startup_reason().unwrap(),
            Some(StandbyStartupReason::CurrentUnusable)
        );
        db.close().await;
    }

    #[tokio::test]
    async fn startup_without_a_usable_generation_is_status_only() {
        let _capture_guard = test_diagnostics::LOG_CAPTURE_LOCK.lock().await;
        let root = tempfile::tempdir().unwrap();
        let store = GenerationStore::open(
            root.path().join("standby"),
            "route-1",
            Some("ndb_0123456789abcdef0123456789abcdef".into()),
        )
        .unwrap();
        use tracing::instrument::WithSubscriber;
        let logs = test_diagnostics::Capture::default();
        let outcome = store
            .activate_for_startup(&observed())
            .with_subscriber(logs.subscriber())
            .await
            .unwrap();
        let StandbyStartupOutcome::StatusOnly(status) = outcome else {
            panic!("an empty store must not serve an arbitrary database");
        };
        assert_eq!(status.reason, "no_usable_generation");
        assert_eq!(status.candidate_count, 0);
        assert_eq!(status.unusable_candidate_count, 0);
        let output = logs.output();
        let completion = output
            .lines()
            .find(|line| line.contains("standby startup verification finished"))
            .unwrap();
        assert!(completion.contains("ok=true") && completion.contains("serving=false"));
        let unconfigured =
            GenerationStore::open(root.path().join("unconfigured"), "route-1", None).unwrap();
        let refused = test_diagnostics::Capture::default();
        assert!(unconfigured
            .activate_for_startup(&observed())
            .with_subscriber(refused.subscriber())
            .await
            .is_err());
        let output = refused.output();
        let completion = output
            .lines()
            .find(|line| line.contains("standby startup verification finished"))
            .unwrap();
        assert!(completion.contains("ok=false") && completion.contains("serving=false"));
    }

    #[tokio::test]
    async fn retention_keeps_current_plus_two_and_respects_active_leases() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store =
            GenerationStore::open(root.path().join("standby"), "route-1", Some(origin)).unwrap();

        let mut installed = Vec::new();
        for ordinal in 0..4 {
            crate::store::create_record(
                &db,
                serde_json::json!({
                    "type":"Document",
                    "kind":"note",
                    "name":format!("generation-{ordinal}")
                }),
            )
            .await
            .unwrap();
            let (snapshot, manifest) = stage(&store, &db, &format!("generation-{ordinal}")).await;
            installed.push(
                store
                    .install_staged(&snapshot, &manifest, &observed())
                    .await
                    .unwrap(),
            );
        }

        // These shared guards model two serving MCP processes: one on current
        // and one still opening the oldest generation while refresh advances.
        let latest_id = installed.last().unwrap().id.clone();
        let _current_lease = store.acquire_serving_lease(&latest_id).unwrap();
        let prior_lease = store.acquire_serving_lease(&installed[0].id).unwrap();
        assert!(store.prune_known_good(&latest_id, &installed).is_empty());
        assert_eq!(store.generation_ids().unwrap().len(), 4);
        drop(prior_lease);
        assert!(store.prune_known_good(&latest_id, &installed).is_empty());
        assert_eq!(store.generation_ids().unwrap().len(), 3);

        let pruning = store
            .root
            .join("generations")
            .join(format!(".pruning-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&pruning).unwrap();
        fs::write(pruning.join("manifest.json"), b"partial cleanup").unwrap();
        set_mode(&pruning.join("manifest.json"), 0o400).unwrap();
        set_mode(&pruning, 0o500).unwrap();
        assert!(store.cleanup_pruning_workspaces().is_empty());
        assert!(!pruning.exists());
        db.close().await;
    }

    #[tokio::test]
    async fn deep_successor_proof_rejects_divergence_and_allows_validity_only_advance() {
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({
                "type": "Document",
                "kind": "note",
                "name": "baseline"
            }),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO blobs(id,bytes,mime,size_bytes,sha256,original_filename)
             VALUES('blob-1',X'01','application/octet-stream',1,?,'one.bin')",
        )
        .bind("a".repeat(64))
        .execute(db.write_pool())
        .await
        .unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO provenance_action_attestations
             (id,schema_version,principal,executor_kind,operation,action_commitment,
              action_digest,output_event_set_digest,issuer,issuer_origin_database_id,issued_at)
             VALUES('attestation-1',1,'owner','human','test','{}',?,?,?,?,'2026-01-01T00:00:00Z')",
        )
        .bind("b".repeat(64))
        .bind("c".repeat(64))
        .bind("owner")
        .bind(origin)
        .execute(db.write_pool())
        .await
        .unwrap();
        let current = exported_file(&db, directory.path(), "current.db").await;

        let divergent = directory.path().join("divergent.db");
        fs::copy(&current, &divergent).unwrap();
        let mut conn = open_raw(&divergent).await;
        // content_events is append-only by trigger, so the divergence fixture
        // drops the update guard and restores it verbatim around the mutation:
        // the verifier must reject the divergent payload, not a missing guard.
        let update_guard: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='content_events_no_update'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        sqlx::query("DROP TRIGGER content_events_no_update")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("UPDATE content_events SET payload='{}' WHERE seq=1")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query(&update_guard).execute(&mut conn).await.unwrap();
        conn.close().await.unwrap();
        let error = verify_database_successor(&current, &divergent)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("content_events"));

        let blob_mutation = directory.path().join("blob-mutation.db");
        fs::copy(&current, &blob_mutation).unwrap();
        let mut conn = open_raw(&blob_mutation).await;
        sqlx::query("UPDATE blobs SET bytes=X'02' WHERE id='blob-1'")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
        let error = verify_database_successor(&current, &blob_mutation)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("blobs"));

        let validity = directory.path().join("validity.db");
        fs::copy(&current, &validity).unwrap();
        let mut conn = open_raw(&validity).await;
        sqlx::query(
            "INSERT INTO provenance_attestation_validity_events
             (id,attestation_id,ordinal,status,reason,issuer,issued_at)
             VALUES('validity-1','attestation-1',0,'invalidated','compromised','owner',
                    '2026-01-02T00:00:00Z')",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        conn.close().await.unwrap();
        verify_database_successor(&current, &validity)
            .await
            .unwrap();
        db.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_newer_and_older_promotions_finish_at_newest_frontier() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        let origin = crate::identity::database_id(&db).await.unwrap();
        let store_root = root.path().join("standby");
        let staging_store =
            GenerationStore::open(&store_root, "route-1", Some(origin.clone())).unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"older"}),
        )
        .await
        .unwrap();
        let (older_snapshot, older_manifest) = stage(&staging_store, &db, "older").await;
        crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"newer"}),
        )
        .await
        .unwrap();
        let (newer_snapshot, newer_manifest) = stage(&staging_store, &db, "newer").await;
        let newer_id = hex::encode(Sha256::digest(
            read_canonical_manifest(&newer_manifest)
                .unwrap()
                .canonical_json()
                .unwrap(),
        ));
        let newer_store =
            GenerationStore::open(&store_root, "route-1", Some(origin.clone())).unwrap();
        let older_store = GenerationStore::open(&store_root, "route-1", Some(origin)).unwrap();
        let newer_observed = observed();
        let older_observed = observed();
        let (newer_result, older_result) =
            tokio::time::timeout(std::time::Duration::from_secs(180), async {
                tokio::join!(
                    newer_store.install_staged(&newer_snapshot, &newer_manifest, &newer_observed),
                    older_store.install_staged(&older_snapshot, &older_manifest, &older_observed)
                )
            })
            .await
            .expect("concurrent promotions must not deadlock");
        assert!(
            newer_result.is_ok(),
            "newer promotion failed: {newer_result:?}"
        );
        if let Err(error) = older_result {
            assert!(error.to_string().contains("rollback/continuity"));
        }
        assert_eq!(
            staging_store.read_pointer().unwrap().generation_id,
            newer_id
        );
        db.close().await;
    }
}

#[cfg(test)]
#[path = "generation_store/device_verification_tests.rs"]
mod device_verification_tests;
