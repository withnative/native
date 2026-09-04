use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Connection, Row};

use crate::error::{Error, Result};
use crate::standby_snapshot::{ObservedInstalledConsumerIdentity, StandbySnapshotManifest};

const POINTER_CONTRACT: &str = "native.standby-current-pointer.v1";
const STARTUP_STATE_CONTRACT: &str = "native.standby-startup-state.v1";

const SEQUENCED_LOGS: &[&str] = &[
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
const UNSEQUENCED_APPEND_ONLY: &[&str] = &[
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
    "relationship_foreign_action_attestations",
    "relationship_foreign_action_outputs",
    "relationship_federation_events",
    "engine_migration_drills",
];
// These physical domains have no ratified successor log/fold. Until one exists
// a refresh may not silently replace them.
const UNFENCED_EXACT: &[&str] = &["storage_portability_policy"];

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

/// A fully revalidated generation selected for serving at process startup.
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GenerationProvenanceStatus {
    Available,
    Missing,
    Invalid,
    Unavailable,
}

#[derive(Clone, Debug)]
pub(super) struct GenerationStoreStatus {
    pub current: Option<InstalledGeneration>,
    pub current_provenance: GenerationProvenanceStatus,
    pub retained_generation_ids: Vec<String>,
    pub candidate_count: usize,
    pub unusable_candidate_count: usize,
    pub startup_reason: Option<StandbyStartupReason>,
    pub startup_reason_available: bool,
}

impl GenerationStore {
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
        let expected_route_id = expected_route_id.into();
        if expected_route_id.trim().is_empty() {
            return Err(Error::engine("standby expected route id is empty"));
        }
        Ok(Self {
            root,
            expected_route_id,
            expected_origin_id,
        })
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    /// Inspect accepted generations for status disclosure without changing the
    /// pointer, retention, or any immutable generation. Every generation named
    /// as retained or current has passed the same full verification used at
    /// activation time.
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
                    startup_reason: None,
                    startup_reason_available: false,
                }
            }
        };
        let mut usable = Vec::new();
        let mut unusable_candidate_count = 0;
        for id in &candidate_ids {
            match self.verify_generation_for_startup(id, observed).await {
                Ok(generation) => usable.push(generation),
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
                None => (None, GenerationProvenanceStatus::Invalid),
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
        self.install_staged_with_hook(snapshot, manifest_path, observed, |_| Ok(()))
            .await
    }

    /// Recover and select the immutable generation this process may serve.
    ///
    /// "Newest" is authority capture order: parsed `captured_at`, then
    /// `snapshot_completed_at`, then generation id. Filesystem iteration order
    /// and mtimes are deliberately irrelevant. Invalid generations are left in
    /// place for bounded diagnosis; retention removes only fully revalidated,
    /// unleased known-good generations.
    pub async fn activate_for_startup(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<StandbyStartupOutcome> {
        if self.expected_origin_id.is_none() {
            return Err(Error::engine(
                "standby startup requires a configured origin database id",
            ));
        }
        let _promotion_lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
        let mut retention_warnings = self.cleanup_pruning_workspaces();
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
        let mut usable = Vec::new();
        let mut unusable_candidate_count = 0;
        for id in &candidate_ids {
            match self.verify_generation_for_startup(id, observed).await {
                Ok(generation) => usable.push(generation),
                Err(_) => unusable_candidate_count += 1,
            }
        }
        usable.sort_by(compare_generation_newest_first);

        let current = pointer.as_ref().ok().and_then(|pointer| {
            usable.iter().find(|generation| {
                generation.id == pointer.generation_id
                    && generation.manifest.snapshot.sha256 == pointer.snapshot_sha256
            })
        });
        let mut selected = current.cloned();
        let mut startup_reason = if pointer_missing {
            Some(StandbyStartupReason::CurrentMissing)
        } else if current.is_none() {
            Some(StandbyStartupReason::CurrentUnusable)
        } else {
            None
        };

        // A crash after generation durability but before pointer durability
        // leaves a complete published successor. Finish that transition only
        // after proving the orphan is a non-regressing deep successor.
        if let Some(current) = current {
            for candidate in &usable {
                if candidate.id == current.id
                    || compare_generation_newest_first(candidate, current)
                        != std::cmp::Ordering::Less
                {
                    continue;
                }
                if candidate
                    .manifest
                    .frontier
                    .is_componentwise_non_regressing_from(&current.manifest.frontier)?
                    && verify_database_successor(&current.snapshot_path, &candidate.snapshot_path)
                        .await
                        .is_ok()
                {
                    selected = Some(candidate.clone());
                    startup_reason = Some(StandbyStartupReason::DurableGenerationRecovered);
                    break;
                }
            }
        } else if let Some(candidate) = usable.first() {
            selected = Some(candidate.clone());
        }

        let Some(selected) = selected else {
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

        let lease = self.acquire_serving_lease(&selected.id)?;
        retention_warnings.extend(self.prune_known_good(&selected.id, &usable));
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
    /// fully revalidated against the installed consumer. Per-generation
    /// failures are returned as bounded warnings so cleanup cannot make a
    /// verified current generation unavailable.
    pub async fn prune_retention(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<Vec<String>> {
        let _promotion_lock = acquire_promotion_lock(self.root.join("promotion.lock")).await?;
        let mut warnings = self.cleanup_pruning_workspaces();
        let pointer = self.read_pointer()?;
        let mut usable = Vec::new();
        for id in self.generation_ids()? {
            if let Ok(generation) = self.verify_generation_for_startup(&id, observed).await {
                usable.push(generation);
            }
        }
        let current = usable
            .iter()
            .find(|generation| {
                generation.id == pointer.generation_id
                    && generation.manifest.snapshot.sha256 == pointer.snapshot_sha256
            })
            .ok_or_else(|| {
                Error::engine("standby current generation is not usable for retention")
            })?;
        warnings.extend(self.prune_known_good(&current.id, &usable));
        Ok(warnings)
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
        copy_into_owned_file(snapshot, &owned_snapshot)?;
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
            return Err(Error::engine(
                "standby candidate does not match configured route/origin",
            ));
        }
        verify_snapshot(
            &owned_snapshot,
            &manifest,
            Some(observed),
            &self.staging_dir(),
        )
        .await?;

        let current = self.read_current_manifest()?;
        if let Some((current_path, current_manifest)) = &current {
            verify_snapshot(current_path, current_manifest, None, &self.staging_dir()).await?;
            if manifest.hosted_route_database_id != current_manifest.hosted_route_database_id
                || manifest.origin_database_id != current_manifest.origin_database_id
                || !manifest
                    .frontier
                    .is_componentwise_non_regressing_from(&current_manifest.frontier)?
            {
                return Err(Error::engine(
                    "standby candidate fails scalar rollback/continuity fence",
                ));
            }
            verify_database_successor(current_path, &owned_snapshot).await?;
        }

        let id = hex::encode(Sha256::digest(manifest.canonical_json()?));
        let destination = generations.join(&id);
        if destination.exists() {
            require_published_generation(&destination)?;
            let existing = read_canonical_manifest(&destination.join("manifest.json"))?;
            if hex::encode(Sha256::digest(existing.canonical_json()?)) != id || existing != manifest
            {
                return Err(Error::engine("standby generation id collision"));
            }
            verify_snapshot(
                &destination.join("snapshot.db"),
                &existing,
                Some(observed),
                &self.staging_dir(),
            )
            .await?;
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
        let publish = (|| -> Result<()> {
            set_mode(&publishing, 0o500)?;
            File::open(&publishing)?.sync_all()?;
            rename_directory_no_replace(&publishing, &destination)
        })();
        if let Err(error) = publish {
            // TempDir cleanup needs write permission on the workspace. A
            // successful rename makes its old path disappear, so the guard is
            // harmless on the success path and cleans every ordinary refusal.
            let _ = set_mode(&publishing, 0o700);
            return Err(error);
        }
        File::open(&generations)?.sync_all()?;
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

    async fn verify_generation_for_startup(
        &self,
        id: &str,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<InstalledGeneration> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        let directory = self.root.join("generations").join(id);
        require_published_generation(&directory)?;
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
        verify_snapshot(
            &snapshot_path,
            &manifest,
            Some(observed),
            &self.staging_dir(),
        )
        .await?;
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
            if keep.contains(&generation.id) {
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
        let generations = self.root.join("generations");
        let source = generations.join(id);
        require_published_generation(&source)?;
        let mut children = fs::read_dir(&source)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        children.sort();
        if children != ["manifest.json", "snapshot.db"].map(std::ffi::OsString::from) {
            return Err(Error::engine(
                "standby generation contains unexpected retention entries",
            ));
        }
        let pruning = generations.join(format!(".pruning-{}", uuid::Uuid::new_v4()));
        fs::rename(&source, &pruning)?;
        File::open(&generations)?.sync_all()?;
        self.remove_pruning_workspace(&pruning)
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
        if children
            .iter()
            .any(|name| name != "manifest.json" && name != "snapshot.db")
        {
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

    fn read_current_manifest(&self) -> Result<Option<(PathBuf, StandbySnapshotManifest)>> {
        let pointer = match self.read_pointer() {
            Ok(value) => value,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let dir = self.root.join("generations").join(&pointer.generation_id);
        require_published_generation(&dir)?;
        let manifest = read_canonical_manifest(&dir.join("manifest.json"))?;
        if manifest.snapshot.sha256 != pointer.snapshot_sha256
            || hex::encode(Sha256::digest(manifest.canonical_json()?)) != pointer.generation_id
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
    if !is_generation_id(id) {
        return Err(Error::engine("invalid standby generation lease id"));
    }
    let path = directory.join(format!("{id}.lock"));
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
        lock.lock_exclusive()?;
        Ok(lock)
    })
    .await
    .map_err(|error| Error::engine(format!("standby promotion lock task failed: {error}")))?
}

async fn verify_snapshot(
    path: &Path,
    manifest: &StandbySnapshotManifest,
    observed: Option<&ObservedInstalledConsumerIdentity>,
    scratch_parent: &Path,
) -> Result<()> {
    require_regular_no_symlink(path)?;
    manifest.validate()?;
    if let Some(observed) = observed {
        manifest.consumer.validate_observed_installed(observed)?;
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() != manifest.snapshot.size_bytes
        || sha256_file(path)? != manifest.snapshot.sha256
    {
        return Err(Error::engine("standby snapshot byte identity mismatch"));
    }
    reject_sqlite_sidecars(path)?;
    crate::db::validate_current_engine_shape_immutable(path).await?;
    crate::standby_snapshot::validate_completed_export_manifest(path, manifest).await?;
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
    let embeddings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM embeddings")
        .fetch_one(&mut raw)
        .await?;
    raw.close().await?;
    if integrity != "ok" || foreign_key_violation != 0 || embeddings != 0 {
        return Err(Error::engine(
            "standby snapshot integrity or foreign-key validation failed",
        ));
    }
    let readonly =
        crate::db::open_existing_database_standby_read_only(path.to_string_lossy().as_ref())
            .await?;
    let report = crate::conformance::run_standby_admission_conformance(&readonly).await;
    readonly.close().await;
    if !report.ok {
        return Err(Error::engine(format!(
            "standby snapshot conformance failed: {}",
            crate::conformance::format_report(&report)
        )));
    }
    verify_awareness_projections(path, scratch_parent).await?;
    Ok(())
}

async fn verify_awareness_projections(path: &Path, scratch_parent: &Path) -> Result<()> {
    let scratch_dir = tempfile::Builder::new()
        .prefix(".verify-awareness-")
        .tempdir_in(scratch_parent)?;
    let scratch = scratch_dir.path().join("snapshot.db");
    fs::copy(path, &scratch)?;
    set_mode(&scratch, 0o600)?;
    let db = crate::open_database_at(&scratch).await?;
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
    drop(scratch_dir);
    Ok(())
}

async fn verify_database_successor(current: &Path, candidate: &Path) -> Result<()> {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(current)
        .read_only(true)
        .immutable(true)
        .create_if_missing(false);
    let mut conn = sqlx::SqliteConnection::connect_with(&options).await?;
    sqlx::query("ATTACH DATABASE ? AS candidate")
        .bind(candidate.to_string_lossy().as_ref())
        .execute(&mut conn)
        .await?;
    for table in SEQUENCED_LOGS.iter().chain(UNSEQUENCED_APPEND_ONLY) {
        let sql = format!(
            "SELECT EXISTS(SELECT * FROM main.{table} EXCEPT SELECT * FROM candidate.{table})"
        );
        if sqlx::query(&sql)
            .fetch_one(&mut conn)
            .await?
            .get::<i64, _>(0)
            != 0
        {
            return Err(Error::engine(format!(
                "standby candidate does not preserve {table}"
            )));
        }
    }
    for table in UNFENCED_EXACT {
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
                return Err(Error::engine(format!(
                    "standby candidate changes unfenced {table}"
                )));
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
        if directory.permissions().mode() & 0o777 != 0o500 {
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
    Ok(())
}
fn create_private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
        set_mode(path, 0o700)?;
    }
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

#[cfg(not(target_os = "linux"))]
fn rename_directory_no_replace(_: &Path, _: &Path) -> Result<()> {
    Err(Error::engine(
        "standby publication requires Linux renameat2",
    ))
}

#[cfg(test)]
mod tests {
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

    fn observed() -> ObservedInstalledConsumerIdentity {
        let consumer = consumer();
        ObservedInstalledConsumerIdentity {
            platform: consumer.platform,
            source_sha: consumer.source_sha,
            artifact_sha256: consumer.artifact_sha256,
            engine_schema_version: consumer.engine_schema_version,
            ddl_sha256: consumer.ddl_sha256,
        }
    }

    async fn stage(store: &GenerationStore, db: &crate::Db, stem: &str) -> (PathBuf, PathBuf) {
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
        assert!(store.read_current_manifest().is_err());
        assert_eq!(
            fs::read(store.root.join("current.json")).unwrap(),
            pointer_before_tamper
        );
        db.close().await;
    }

    #[tokio::test]
    async fn startup_revalidates_current_and_falls_back_from_corruption() {
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
        let root = tempfile::tempdir().unwrap();
        let store = GenerationStore::open(
            root.path().join("standby"),
            "route-1",
            Some("ndb_0123456789abcdef0123456789abcdef".into()),
        )
        .unwrap();
        let outcome = store.activate_for_startup(&observed()).await.unwrap();
        let StandbyStartupOutcome::StatusOnly(status) = outcome else {
            panic!("an empty store must not serve an arbitrary database");
        };
        assert_eq!(status.reason, "no_usable_generation");
        assert_eq!(status.candidate_count, 0);
        assert_eq!(status.unusable_candidate_count, 0);
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
        sqlx::query("UPDATE content_events SET payload='{}' WHERE seq=1")
            .execute(&mut conn)
            .await
            .unwrap();
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
