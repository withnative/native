//! V2 replay never opens a writer on a serving generation.
use super::*;
use crate::standby::kernel_v2_delta::{self, TrustedKernelDelta};

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
    pub(crate) async fn prepare_kernel_delta(
        &self,
        current: &InstalledGeneration,
        delta: &TrustedKernelDelta,
        synced_at: &str,
    ) -> Result<PreparedKernelGeneration> {
        let lease = self.acquire_serving_lease(&current.id)?;
        if fs2::available_space(self.staging_dir())?
            < kernel_disk_budget(&current.snapshot_path, 2)?
        {
            return Err(Error::engine(INSUFFICIENT_DISK));
        }
        let workspace = tempfile::Builder::new()
            .prefix("kernel-replay-")
            .tempdir_in(self.staging_dir())?;
        let copy = workspace.path().join("snapshot.db");
        // V2 serving files are immutable and leased; unlike mutable v1 there
        // is no WAL to snapshot. Copy the verified checkpoint bytes once.
        fs::copy(&current.snapshot_path, &copy)?;
        set_mode(&copy, 0o600)?;
        let writer = crate::db::open_kernel_v2_head_writer(&copy).await?;
        let result = kernel_v2_delta::apply(&writer, delta).await;
        writer.close().await;
        result?;
        let coordinates = crate::standby::kernel_v2::verify_path(&copy).await?;
        let snapshot = tempfile::Builder::new()
            .prefix("kernel-delta-")
            .tempfile_in(self.staging_dir())?
            .into_temp_path();
        // Same-filesystem move: the replay output IS the admission candidate.
        fs::rename(&copy, &snapshot)?;
        File::open(&snapshot)?.sync_all()?;
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
        let mut file = tempfile::Builder::new()
            .prefix("kernel-manifest-")
            .tempfile_in(self.staging_dir())?;
        file.write_all(&manifest.canonical_json()?)?;
        file.as_file().sync_all()?;
        Ok(PreparedKernelGeneration {
            snapshot,
            manifest: file.into_temp_path(),
            _base: lease,
        })
    }

    pub(crate) async fn publish_kernel_delta(
        &self,
        prepared: PreparedKernelGeneration,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<InstalledGeneration> {
        // Same verification, fsync, durable-directory rename and atomic pointer
        // publication as FULL. Dropping/aborting before here leaves current intact.
        let generation = self
            .install_staged_with_hook_mode(
                &prepared.snapshot,
                &prepared.manifest,
                observed,
                true,
                |_| Ok(()),
            )
            .await?;
        self.cache_completed_verification(&generation.id, observed, true);
        Ok(generation)
    }
}
