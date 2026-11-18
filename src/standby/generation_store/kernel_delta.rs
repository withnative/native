//! The staged v2 path: replay never opens a writer on a serving generation.
//! Small deltas may instead be applied in place when the opt-in flag is on
//! (see `kernel_in_place.rs`); this path stays the fallback and the periodic
//! re-checkpoint.
use super::*;
use crate::standby::kernel_v2_delta::{self, TrustedKernelDelta};
use crate::standby::phase_timings::PhaseTimings;

pub(crate) const INSUFFICIENT_DISK: &str = "insufficient_disk";

pub(crate) fn kernel_disk_budget(path: &Path, copies: u64) -> Result<u64> {
    Ok(fs::metadata(path)?
        .len()
        .saturating_mul(copies)
        .saturating_add(
            crate::standby::delta_transport::AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES as u64,
        ))
}

pub(crate) fn is_kernel_disk_refusal(error: &Error) -> bool {
    match error {
        Error::Engine(message) => message == INSUFFICIENT_DISK,
        Error::Io(error) | Error::Sqlx(sqlx::Error::Io(error)) => {
            error.kind() == std::io::ErrorKind::StorageFull
        }
        Error::Sqlx(sqlx::Error::Database(error)) => error
            .code()
            .and_then(|c| c.parse::<i32>().ok())
            .is_some_and(|c| c & 255 == 13),
        Error::StandbyAdmission { source, .. } => is_kernel_disk_refusal(source),
        _ => false,
    }
}

pub(crate) struct PreparedKernelGeneration {
    base_generation_id: String,
    snapshot: tempfile::TempPath,
    manifest: tempfile::TempPath,
    // Keep retention from removing the base while the scratch copy is made.
    _base: File,
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
impl PreparedKernelGeneration {
    pub(crate) fn snapshot_path(&self) -> &Path {
        &self.snapshot
    }
}

impl GenerationStore {
    /// Untimed form, for tests.
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) async fn prepare_kernel_delta(
        &self,
        current: &InstalledGeneration,
        delta: &TrustedKernelDelta,
        synced_at: &str,
    ) -> Result<PreparedKernelGeneration> {
        self.prepare_kernel_delta_timed(current, delta, synced_at, &PhaseTimings::default())
            .await
    }

    pub(crate) async fn prepare_kernel_delta_timed(
        &self,
        current: &InstalledGeneration,
        delta: &TrustedKernelDelta,
        synced_at: &str,
        timings: &PhaseTimings,
    ) -> Result<PreparedKernelGeneration> {
        let lease = self.acquire_serving_lease(&current.id)?;
        if fs2::available_space(self.staging_dir())?
            < kernel_disk_budget(&current.snapshot_path, 2)?
        {
            return Err(Error::engine(INSUFFICIENT_DISK));
        }
        timings.lap("prepare_lease_disk");
        let workspace = tempfile::Builder::new()
            .prefix("kernel-replay-")
            .tempdir_in(self.staging_dir())?;
        let copy = workspace.path().join("snapshot.db");
        // V2 serving files are immutable and leased; unlike mutable v1 there
        // is no WAL to snapshot. Copy the verified checkpoint bytes once.
        // A copy advanced in place (WAL) is not its bytes: some of its content
        // may still be in the `-wal`, so take a consistent snapshot through
        // SQLite instead of copying the file.
        if self
            .generation_head(&current.id)?
            .is_some_and(|head| head.advanced_in_place())
        {
            consistent_copy(&current.snapshot_path, &copy).await?;
            // Never launder an inherited state into a fresh checkpoint hash:
            // prove the copied base from its own receipts first.
            self.verify_advanced_copy(&copy, current).await?;
            timings.lap("prepare_verify_inherited");
        } else {
            fs::copy(&current.snapshot_path, &copy)?;
        }
        set_mode(&copy, 0o600)?;
        timings.lap("prepare_copy");
        let writer = crate::db::open_kernel_v2_head_writer(&copy).await?;
        timings.lap("prepare_open_writer");
        let mut result = kernel_v2_delta::apply(&writer, delta, timings).await;
        if result.is_ok() {
            // A copy advanced in place carries its apply receipts. The new
            // checkpoint is a fresh file anchored by its own hash, with a
            // fresh chain started if it is later advanced in place.
            // (and any accumulator cache: it belongs to the receipts it sat
            // behind).
            for table in [
                "DROP TABLE IF EXISTS kernel_standby_apply_receipts",
                "DROP TABLE IF EXISTS kernel_standby_projection_set",
            ] {
                if result.is_ok() {
                    result = sqlx::query(table)
                        .execute(writer.write_pool())
                        .await
                        .map(|_| ())
                        .map_err(Error::from);
                }
            }
        }
        writer.close().await;
        timings.lap("prepare_close_writer");
        result?;
        let coordinates = crate::standby::kernel_v2::verify_path(&copy).await?;
        timings.lap("prepare_verify_copy");
        let snapshot = tempfile::Builder::new()
            .prefix("kernel-delta-")
            .tempfile_in(self.staging_dir())?
            .into_temp_path();
        // Same-filesystem move: the replay output IS the admission candidate.
        fs::rename(&copy, &snapshot)?;
        File::open(&snapshot)?.sync_all()?;
        timings.lap("prepare_rename_fsync");
        if coordinates != delta.delta().head.generation {
            return Err(Error::engine(
                "scratch generation differs from authenticated delta head",
            ));
        }
        let mut manifest = current.manifest.clone();
        manifest.captured_at = synced_at.into();
        manifest.snapshot_completed_at = chrono::Utc::now().to_rfc3339();
        manifest.head_act = Some(coordinates.head_act);
        manifest.kernel_v2 = Some(coordinates);
        // A new immutable checkpoint derived from an authenticated delta, not a hosted FULL.
        // Its separate head stays Snapshot because these bytes are never changed in place.
        manifest.materialization = StandbyGenerationMaterialization::Delta;
        manifest.snapshot.sha256 = sha256_file(&snapshot)?;
        manifest.snapshot.size_bytes = fs::metadata(&snapshot)?.len();
        timings.lap("prepare_file_sha256");
        let mut file = tempfile::Builder::new()
            .prefix("kernel-manifest-")
            .tempfile_in(self.staging_dir())?;
        file.write_all(&manifest.canonical_json()?)?;
        file.as_file().sync_all()?;
        timings.lap("prepare_manifest");
        Ok(PreparedKernelGeneration {
            base_generation_id: current.id.clone(),
            snapshot,
            manifest: file.into_temp_path(),
            _base: lease,
        })
    }

    /// Untimed form, for tests.
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) async fn publish_kernel_delta(
        &self,
        prepared: PreparedKernelGeneration,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<InstalledGeneration> {
        self.publish_kernel_delta_timed(prepared, observed, &PhaseTimings::default())
            .await
    }

    pub(crate) async fn publish_kernel_delta_timed(
        &self,
        prepared: PreparedKernelGeneration,
        observed: &ObservedInstalledConsumerIdentity,
        timings: &PhaseTimings,
    ) -> Result<InstalledGeneration> {
        // The base may retain an older immutable consumer declaration after a
        // verified binary replacement. Only its matching acceptance receipt
        // authorizes this installed consumer to produce a new checkpoint.
        if let Some(rebind) = self.consumer_rebind(&prepared.base_generation_id, observed)? {
            let mut manifest = read_canonical_manifest(&prepared.manifest)?;
            if manifest.consumer != rebind.original_consumer {
                return Err(Error::engine(
                    "kernel delta consumer differs from its verified base",
                ));
            }
            // This is the new replay output, not an edit to the base manifest
            // or its rebind evidence. Preserve the kernel format and producer
            // coordinates; the new consumer carries its own v1 build metadata.
            manifest.consumer.source_sha = rebind.accepted_consumer.source_sha;
            manifest.consumer.artifact_sha256 = rebind.accepted_consumer.artifact_sha256;
            manifest.consumer.engine_schema_version =
                rebind.accepted_consumer.engine_schema_version;
            manifest.consumer.ddl_sha256 = rebind.accepted_consumer.ddl_sha256;
            manifest.consumer.validate_observed_installed(observed)?;
            fs::write(&prepared.manifest, manifest.canonical_json()?)?;
            File::open(&prepared.manifest)?.sync_all()?;
        }
        // Same verification, fsync, durable-directory rename and atomic pointer
        // publication as FULL. Dropping/aborting before here leaves current intact.
        let generation = self
            .install_staged_timed(
                &prepared.snapshot,
                &prepared.manifest,
                observed,
                true,
                |_| Ok(()),
                timings,
            )
            .await?;
        self.cache_completed_verification(&generation.id, observed, true);
        Ok(generation)
    }
}
