//! Verified, fail-closed storage target migration.
//!
//! Revision 1 is Unix-only. Before creating a report or provenance workspace,
//! it verifies the filesystem topology required for hard-link publication and
//! atomic same-directory replacement; cross-filesystem copy fallback is never
//! allowed.
//! The sole production adapter in revision 1 is a local target-config file
//! controlled exclusively by `operator storage-migration`. A serving process
//! must be stopped or in maintenance mode before this workflow starts; a stale
//! process which already holds an open SQLite file descriptor is outside the
//! guarantees of filesystem read-only sealing.
//! Rollback has no lossy override: behavioral checks run before fencing, then
//! source and active destination are fenced in lexical path order and both
//! must still equal the journaled canonical state before the config can switch.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection as _, Executor as _, SqliteConnection};

use crate::interchange::{export_canonical_interchange, import_canonical_interchange};
use crate::{open_existing_database_at, Error, Result};

const TARGET_FORMAT: &str = "native.storage-target.v1";
const TARGET_CONTROLLER: &str = "operator.storage-migration.v1";
const REPORT_FORMAT: &str = "native.storage-migration-report.v1";
const LEASE_FORMAT: &str = "native.storage-migration-lease.v1";
const SQLITE_PROFILE: &str = "sqlite-local";
const SQLITE_PROFILE_REVISION: u64 = 2;
const LEASE_TTL_SECONDS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageTarget {
    pub profile_id: String,
    pub profile_revision: u64,
    pub path: PathBuf,
}

impl StorageTarget {
    pub fn sqlite_local(path: impl Into<PathBuf>) -> Self {
        Self {
            profile_id: SQLITE_PROFILE.into(),
            profile_revision: SQLITE_PROFILE_REVISION,
            path: path.into(),
        }
    }

    fn is_supported_sqlite(&self) -> bool {
        self.profile_id == SQLITE_PROFILE
            && matches!(self.profile_revision, 1..=SQLITE_PROFILE_REVISION)
    }

    fn label(&self) -> String {
        format!("{}@{}", self.profile_id, self.profile_revision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub format: String,
    pub controller: String,
    pub active: StorageTarget,
    pub switched_at: String,
    pub migration_run_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MigrationOptions {
    pub source: StorageTarget,
    pub destination: StorageTarget,
    pub target_config: PathBuf,
    pub report: PathBuf,
    pub rollback_window: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    Preparing,
    Importing,
    Verifying,
    Verified,
    Cutover,
    RolledBack,
    FailedPreCutover,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedFile {
    pub path: PathBuf,
    pub original_mode: u32,
    pub identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub device: Option<u64>,
    pub inode: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReport {
    pub format: String,
    pub revision: u64,
    pub run_id: String,
    pub state: MigrationState,
    pub attempts: u64,
    pub source: StorageTarget,
    pub destination: StorageTarget,
    pub target_config: PathBuf,
    pub report_path: PathBuf,
    pub canonical_sha256: Option<String>,
    pub destination_sha256: Option<String>,
    pub canonical_bytes: Option<u64>,
    pub projection_conformance_ok: Option<bool>,
    pub started_at: String,
    pub lease_acquired_at: Option<String>,
    pub exported_at: Option<String>,
    pub imported_at: Option<String>,
    pub verified_at: Option<String>,
    pub report_durable_at: Option<String>,
    pub cutover_at: Option<String>,
    pub source_sealed_at: Option<String>,
    pub rollback_deadline: Option<String>,
    pub rolled_back_at: Option<String>,
    pub source_sealed_files: Vec<SealedFile>,
    pub destination_sealed_files: Vec<SealedFile>,
    pub provenance_directory: PathBuf,
    pub provenance_directory_identity: Option<DirectoryIdentity>,
    pub import_anchor: PathBuf,
    pub import_anchor_identity: Option<FileIdentity>,
    pub destination_identity: Option<FileIdentity>,
    pub failure_stage: Option<String>,
    pub error: Option<String>,
    pub operator_guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseFile {
    format: String,
    run_id: String,
    token: String,
    source: PathBuf,
    acquired_at: String,
    renewed_at: String,
    expires_at: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvenanceOwner {
    format: String,
    run_id: String,
}

/// Create the only target configuration which revision 1 can switch.
///
/// The file must not already exist. The service consuming it must treat this
/// operator as its sole controller; editing it independently invalidates the
/// migration/rollback journal.
pub fn initialize_target_config(config: &Path, source: &Path) -> Result<TargetConfig> {
    require_unix_migration_platform()?;
    let source = existing_regular_file(source, "source")?;
    let config = new_path_in_existing_directory(config, "target config")?;
    if occupied(&config) {
        return Err(Error::engine(format!(
            "storage target config already exists: {}",
            config.display()
        )));
    }
    let value = TargetConfig {
        format: TARGET_FORMAT.into(),
        controller: TARGET_CONTROLLER.into(),
        active: StorageTarget::sqlite_local(source),
        switched_at: now(),
        migration_run_id: None,
    };
    create_json(&config, &value)?;
    Ok(value)
}

/// Resolve the active SQLite database for a serving runtime.
///
/// Runtimes opting into `NATIVE_CE_STORAGE_TARGET_CONFIG` must use this instead
/// of a separately configured database path, making the atomic config rename a
/// real startup cutover rather than an inert operator artifact.
pub fn resolve_runtime_target(config: &Path) -> Result<PathBuf> {
    let config = existing_regular_file(config, "runtime storage target config")?;
    let target = read_target_config(&config)?;
    if !target.active.is_supported_sqlite() {
        return Err(Error::engine(format!(
            "runtime storage target {} is unsupported; this adapter accepts sqlite-local revisions 1 through 2",
            target.active.label()
        )));
    }
    existing_regular_file(&target.active.path, "active runtime SQLite target")
}

/// Migrate an exact SQLite-local target through canonical interchange.
///
/// Matching interrupted pre-cutover reports are safely restartable: only the
/// exact unpublished destination named in that report may be removed. A
/// completed cutover is idempotent. Other profile routes fail before mutation.
pub async fn migrate_storage(options: MigrationOptions) -> Result<MigrationReport> {
    // Keep the large, deliberately staged migration state machine off callers'
    // async stack. `Db` evolves independently and is carried through several
    // nested phases here; boxing this administrative boundary prevents small
    // handle-layout changes from pushing otherwise valid callers over the
    // default Tokio test-thread stack.
    Box::pin(migrate_storage_inner(options, FailurePoint::None)).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailurePoint {
    None,
    AfterProvenanceDirectory,
    BeforeVerification,
}

async fn migrate_storage_inner(
    mut options: MigrationOptions,
    failure: FailurePoint,
) -> Result<MigrationReport> {
    require_unix_migration_platform()?;
    reject_unsupported_route(&options.source, &options.destination)?;
    if options.rollback_window.is_zero() {
        return Err(Error::engine("rollback window must be greater than zero"));
    }

    options.source.path = existing_regular_file(&options.source.path, "source")?;
    options.destination.path =
        new_path_in_existing_directory(&options.destination.path, "destination")?;
    options.target_config = existing_regular_file(&options.target_config, "target config")?;
    options.report = new_path_in_existing_directory(&options.report, "migration report")?;
    ensure_distinct_paths(&options)?;
    preflight_migration_filesystems(
        &options.source.path,
        &options.destination.path,
        &options.target_config,
        &options.report,
    )?;

    let configured = read_target_config(&options.target_config)?;
    let mut report = load_or_begin_report(&options, &configured, failure)?;
    if report.state == MigrationState::Cutover {
        ensure_config_points_to_run(
            &configured,
            &report.destination,
            &report.run_id,
            "completed destination",
        )?;
        return Ok(report);
    }
    if report.state == MigrationState::RolledBack {
        return Err(Error::engine(
            "storage migration was rolled back; start a new migration with a new report path",
        ));
    }
    if report.state == MigrationState::RecoveryRequired {
        return Err(Error::engine(
            "migration is recovery-required; run storage-migration rollback with this report. Run will not restart or clean a recovery state",
        ));
    }

    let config_points_source = configured.active == options.source;
    let config_points_destination = configured.active == options.destination;
    if report.state == MigrationState::Verified && config_points_destination {
        ensure_config_points_to_run(
            &configured,
            &report.destination,
            &report.run_id,
            "interrupted cutover destination",
        )?;
        report
            .cutover_at
            .get_or_insert_with(|| configured.switched_at.clone());
        match finish_cutover_recovery(&options, &mut report).await {
            Ok(()) => return Ok(report),
            Err(error) => {
                report.state = MigrationState::RecoveryRequired;
                report.failure_stage = Some("interrupted_cutover_reverification".into());
                report.error = Some(error.to_string());
                report.operator_guidance = "The target config already points to this run's destination, but fenced recovery verification failed. Run cannot restart or clean it; inspect the report and use storage-migration rollback.".into();
                atomic_json(&options.report, &report)?;
                return Err(error);
            }
        }
    }
    if !config_points_source {
        return Err(Error::engine(
            "target config no longer points at the journaled source; use rollback or inspect the durable report",
        ));
    }
    if matches!(
        report.state,
        MigrationState::Preparing
            | MigrationState::Importing
            | MigrationState::Verifying
            | MigrationState::Verified
            | MigrationState::FailedPreCutover
    ) {
        remove_unpublished_destination(&report).await?;
        remove_import_anchor(&report)?;
        report.attempts += 1;
        report.state = MigrationState::Preparing;
        report.canonical_sha256 = None;
        report.destination_sha256 = None;
        report.canonical_bytes = None;
        report.projection_conformance_ok = None;
        report.lease_acquired_at = None;
        report.exported_at = None;
        report.imported_at = None;
        report.verified_at = None;
        report.report_durable_at = None;
        report.rollback_deadline = None;
        report.import_anchor_identity = None;
        report.destination_identity = None;
        report.failure_stage = None;
        report.error = None;
        report.operator_guidance = "Migration in progress. If interrupted before cutover, rerun the identical command; only this journal's unpublished destination will be restarted.".into();
        atomic_json(&options.report, &report)?;
    }

    // Opening the pool first completes SQLite/WAL initialization. The lease
    // then uses a distinct connection; its BEGIN IMMEDIATE blocks writers but
    // remains compatible with the export pool's WAL read transaction.
    let source_db = open_existing_database_at(&options.source.path).await?;
    let mut lease = match LeaseGuard::acquire(
        &options.source.path,
        lease_path(&options.report),
        &report.run_id,
    )
    .await
    {
        Ok(lease) => lease,
        Err(error) => {
            source_db.close().await;
            report.state = MigrationState::FailedPreCutover;
            report.failure_stage = Some("maintenance_lease".into());
            report.error = Some(error.to_string());
            report.operator_guidance = "No cutover occurred. Another writer or migration may still hold the source fence; retry only after maintenance mode is exclusive and the lease expires or is released.".into();
            atomic_json(&options.report, &report)?;
            return Err(error);
        }
    };
    report.lease_acquired_at = Some(now());
    atomic_json(&options.report, &report)?;

    let result = async {
        lease.assert_owned()?;
        let canonical = export_canonical_interchange(&source_db).await?;
        report.canonical_sha256 = Some(sha256(&canonical));
        report.canonical_bytes = Some(canonical.len() as u64);
        report.exported_at = Some(now());
        report.state = MigrationState::Importing;
        atomic_json(&options.report, &report)?;

        lease.assert_owned()?;
        let destination_db = import_canonical_interchange(&canonical, &report.import_anchor)
            .await?;
        report.imported_at = Some(now());
        report.state = MigrationState::Verifying;
        atomic_json(&options.report, &report)?;

        let verification = async {
            if failure == FailurePoint::BeforeVerification {
                return Err(Error::engine("injected pre-cutover verification failure"));
            }
            lease.assert_owned()?;
            let destination_canonical = export_canonical_interchange(&destination_db).await?;
            report.destination_sha256 = Some(sha256(&destination_canonical));
            if destination_canonical != canonical {
                return Err(Error::engine(
                    "destination canonical verification differs from source export",
                ));
            }
            require_conformance(&destination_db, "migration destination").await?;
            Ok::<(), Error>(())
        }
        .await;
        destination_db.close().await;
        verification?;
        // Closing completes any final WAL checkpoint. Journal the stable base
        // inode only now; before this point ownership comes from the private,
        // token-bound provenance workspace rather than a stale digest.
        report.import_anchor_identity = Some(file_identity(&report.import_anchor)?);
        // The source pool is no longer needed after export. Close it before
        // inventorying file identities so only the distinct maintenance-fence
        // connection remains and pool teardown cannot mutate SHM lock bytes.
        source_db.close().await;
        report.projection_conformance_ok = Some(true);
        report.verified_at = Some(now());
        report.state = MigrationState::Verified;
        report.rollback_deadline = Some(
            (Utc::now()
                + chrono::Duration::from_std(options.rollback_window)
                    .map_err(|_| Error::engine("rollback window is too large"))?)
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        );
        report.source_sealed_files = inventory_sqlite_files(&options.source.path)?;
        report.report_durable_at = Some(now());
        report.operator_guidance = "Verified report is durable. Cutover may now atomically switch the sole-controller local target config.".into();
        atomic_json(&options.report, &report)?;

        lease.assert_owned()?;
        let current = read_target_config(&options.target_config)?;
        ensure_config_points_to(&current, &options.source, "migration source")?;
        if occupied(&options.destination.path) {
            return Err(Error::engine(
                "migration destination became occupied before provenance-backed publication",
            ));
        }
        fs::hard_link(&report.import_anchor, &options.destination.path)?;
        sync_parent(&options.destination.path)?;
        let published_identity = file_identity(&options.destination.path)?;
        if Some(&published_identity) != report.import_anchor_identity.as_ref() {
            return Err(Error::engine(
                "published destination does not share the journaled import-anchor identity",
            ));
        }
        report.destination_identity = Some(published_identity);
        atomic_json(&options.report, &report)?;
        let cutover_time = now();
        atomic_json(
            &options.target_config,
            &TargetConfig {
                format: TARGET_FORMAT.into(),
                controller: TARGET_CONTROLLER.into(),
                active: options.destination.clone(),
                switched_at: cutover_time.clone(),
                migration_run_id: Some(report.run_id.clone()),
            },
        )?;
        report.cutover_at = Some(cutover_time);

        seal_files(&report.source_sealed_files)?;
        report.source_sealed_at = Some(now());
        report.state = MigrationState::Cutover;
        report.operator_guidance = format!(
            "Cutover complete. Retain the sealed source and report; rollback is available until {}. The target config must remain exclusively operator-controlled.",
            report.rollback_deadline.as_deref().unwrap_or("the recorded deadline")
        );
        atomic_json(&options.report, &report)?;
        Ok::<(), Error>(())
    }
    .await;

    source_db.close().await;
    lease.release().await;

    match result {
        Ok(()) => {
            // Closing the final SQLite maintenance connection can perform a
            // last WAL checkpoint even though its fenced transaction made no
            // logical writes. The source was inventoried and sealed while that
            // connection was live, so refresh the hashes only after release.
            // Device/inode continuity proves these are still the exact files
            // we sealed; the canonical digest remains the logical rollback
            // authority.
            let refresh =
                refresh_sealed_file_identities(&report.source_sealed_files).and_then(|refreshed| {
                    seal_files(&refreshed)?;
                    Ok(refreshed)
                });
            match refresh {
                Ok(refreshed) => {
                    report.source_sealed_files = refreshed;
                    atomic_json(&options.report, &report)?;
                    Ok(report)
                }
                Err(error) => {
                    report.state = MigrationState::RecoveryRequired;
                    report.failure_stage = Some("source_post_lease_identity".into());
                    report.error = Some(error.to_string());
                    report.operator_guidance = "The target config switched, but the retained source could not be re-inventoried after the final SQLite lease closed. The destination remains active; inspect the exact source files and use rollback only after resolving the recovery-required report.".into();
                    atomic_json(&options.report, &report)?;
                    Err(error)
                }
            }
        }
        Err(error) => {
            let current = read_target_config(&options.target_config)?;
            let mut returned_error = error;
            if current.active == options.source {
                report.state = MigrationState::FailedPreCutover;
                report.failure_stage = Some(stage_name(report.state, &report));
                match remove_unpublished_destination(&report).await {
                    Ok(()) => {
                        report.error = Some(returned_error.to_string());
                        report.operator_guidance = "No cutover occurred. Fix the reported cause and rerun the identical command; the journal authorizes cleanup only of its exact unpublished destination.".into();
                    }
                    Err(cleanup) => {
                        let composed = format!(
                            "migration failed before cutover: {returned_error}; destination cleanup was refused: {cleanup}"
                        );
                        returned_error = Error::engine(composed.clone());
                        report.error = Some(composed);
                        report.operator_guidance = "No cutover occurred, but the destination was preserved because it could not be proven identical to this journal. Do not delete it automatically; inspect the report and occupied path, then choose a new destination or restore the exact journaled artifact.".into();
                    }
                }
            } else if current.active == options.destination
                && current.migration_run_id.as_deref() == Some(report.run_id.as_str())
            {
                report.state = MigrationState::RecoveryRequired;
                report.failure_stage = Some("post_cutover".into());
                report.error = Some(returned_error.to_string());
                report.operator_guidance = "The target config switched before completion. Do not start another migration; run storage-migration rollback with this report or repair sealing and finalize the journal.".into();
            } else {
                report.state = MigrationState::RecoveryRequired;
                report.failure_stage = Some("target_config_diverged".into());
                report.error = Some(returned_error.to_string());
                report.operator_guidance = "The target config no longer identifies either the exact source or this migration run's destination. No cleanup or sealing was attempted; inspect the external controller change and durable report manually.".into();
            }
            atomic_json(&options.report, &report)?;
            Err(returned_error)
        }
    }
}

/// Restore the retained source during its rollback window and atomically make
/// it active again. The destination is sealed and retained for diagnosis.
pub async fn rollback_storage(report_path: &Path) -> Result<MigrationReport> {
    rollback_storage_inner(report_path, RollbackFailurePoint::None).await
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RollbackFailurePoint {
    None,
    AfterDestinationSeal,
    AfterConfigSwitch,
}

async fn rollback_storage_inner(
    report_path: &Path,
    failure: RollbackFailurePoint,
) -> Result<MigrationReport> {
    require_unix_migration_platform()?;
    let report_path = existing_regular_file(report_path, "migration report")?;
    let mut report: MigrationReport = read_json(&report_path)?;
    if report.report_path != report_path {
        return Err(Error::engine(
            "rollback report path does not match the canonical embedded report_path; copied or split journals are refused",
        ));
    }
    validate_report(&report)?;
    if report.state == MigrationState::RolledBack {
        return Ok(report);
    }
    if !matches!(
        report.state,
        MigrationState::Cutover | MigrationState::RecoveryRequired
    ) {
        return Err(Error::engine(
            "rollback requires a completed or recovery-required cutover report",
        ));
    }
    preflight_migration_filesystems(
        &report.source.path,
        &report.destination.path,
        &report.target_config,
        &report_path,
    )?;
    let configured = read_target_config(&report.target_config)?;
    // Once the atomic target switch occurred, finalization is recovery rather
    // than initiation. It must remain possible even when an interruption lasts
    // beyond the original rollback deadline.
    if configured.active == report.source
        && configured.migration_run_id.as_deref() == Some(report.run_id.as_str())
    {
        if report.destination_sealed_files.is_empty() {
            return Err(Error::engine(
                "rollback recovery report lacks the durable destination mode inventory",
            ));
        }
        seal_files(&report.destination_sealed_files)?;
        report.rolled_back_at.get_or_insert_with(now);
        report.state = MigrationState::RolledBack;
        report.failure_stage = None;
        report.error = None;
        report.operator_guidance = "Recovered an interrupted rollback after its atomic config switch. The source is active and the destination is sealed.".into();
        atomic_json(&report_path, &report)?;
        return Ok(report);
    }
    let deadline = report
        .rollback_deadline
        .as_deref()
        .ok_or_else(|| Error::engine("migration report has no rollback deadline"))?;
    let deadline = DateTime::parse_from_rfc3339(deadline)
        .map_err(|_| Error::engine("migration report rollback deadline is invalid"))?;
    if Utc::now() > deadline {
        return Err(Error::engine(
            "rollback window has expired; retained files were not changed",
        ));
    }
    ensure_config_points_to_run(
        &configured,
        &report.destination,
        &report.run_id,
        "migration destination",
    )?;

    if report.source_sealed_files.is_empty() {
        return Err(Error::engine(
            "migration report contains no durable pre-cutover source mode inventory",
        ));
    }
    if report.destination_sealed_files.is_empty() {
        report.destination_sealed_files = inventory_sqlite_files(&report.destination.path)?;
        report.operator_guidance = "Rollback prepared: source and destination mode inventories are durable. The next step restores the source and atomically switches the target config.".into();
        atomic_json(&report_path, &report)?;
    }
    // This restart marker must be durable before the first file-mode change.
    // A crash anywhere below is therefore recovered only through rollback;
    // migration run will never mistake a half-rolled-back Cutover report for
    // a successfully active destination.
    report.state = MigrationState::RecoveryRequired;
    report.failure_stage = Some("rollback_prepared".into());
    report.error = None;
    report.operator_guidance = "Rollback is in progress. If interrupted, rerun rollback with this exact report; run is intentionally disabled until rollback either completes or reports a fenced verification failure.".into();
    atomic_json(&report_path, &report)?;
    restore_files(&report.source_sealed_files)?;
    if let Err(error) = restore_files(&report.destination_sealed_files) {
        let reseal = seal_files(&report.source_sealed_files);
        let returned_error = match reseal {
            Ok(()) => error,
            Err(reseal_error) => Error::engine(format!(
                "restoring the active rollback destination failed: {error}; re-sealing the retained source also failed: {reseal_error}"
            )),
        };
        report.failure_stage = Some("rollback_destination_restore".into());
        report.error = Some(returned_error.to_string());
        report.operator_guidance = "Rollback did not open or switch either target. Restoring the active destination's exact journaled modes failed; the retained source was re-sealed where possible. Resolve the reported file identity or mode error before retrying.".into();
        let journal = atomic_json(&report_path, &report);
        return match journal {
            Ok(()) => Err(returned_error),
            Err(journal_error) => Err(Error::engine(format!(
                "{returned_error}; persisting the destination-restore failure also failed: {journal_error}"
            ))),
        };
    }
    let source_db = match open_existing_database_at(&report.source.path).await {
        Ok(db) => db,
        Err(error) => {
            let _ = seal_files(&report.source_sealed_files);
            return Err(error);
        }
    };
    let destination_db = match open_existing_database_at(&report.destination.path).await {
        Ok(db) => db,
        Err(error) => {
            source_db.close().await;
            let _ = seal_files(&report.source_sealed_files);
            return Err(error);
        }
    };
    let conformance = match require_conformance(&source_db, "rollback source").await {
        Ok(()) => require_conformance(&destination_db, "active rollback destination").await,
        Err(error) => Err(error),
    };
    if let Err(error) = conformance {
        source_db.close().await;
        destination_db.close().await;
        let _ = seal_files(&report.source_sealed_files);
        return Err(error);
    }
    // Two rollback fences are acquired in lexical path order. That order is
    // stable even if another journal describes the reverse route, avoiding a
    // source/destination lock inversion.
    let (mut source_lease, mut destination_lease) =
        match acquire_ordered_rollback_leases(&report, &report_path).await {
            Ok(leases) => leases,
            Err(error) => {
                source_db.close().await;
                destination_db.close().await;
                let _ = seal_files(&report.source_sealed_files);
                return Err(error);
            }
        };
    let fenced_verification = async {
        source_lease.assert_owned()?;
        destination_lease.assert_owned()?;
        let source_canonical = export_canonical_interchange(&source_db).await?;
        if Some(sha256(&source_canonical)) != report.canonical_sha256 {
            return Err(Error::engine(
                "rollback source canonical SHA-256 no longer matches the migration journal",
            ));
        }
        let destination_canonical = export_canonical_interchange(&destination_db).await?;
        if Some(sha256(&destination_canonical)) != report.canonical_sha256 {
            return Err(Error::engine(
                "rollback refused: the active destination changed after cutover; no destination writes may be discarded",
            ));
        }
        crate::db::validate_current_engine_shape_read_only(&report.source.path).await?;
        crate::db::validate_current_engine_shape_read_only(&report.destination.path).await?;
        source_lease.assert_owned()?;
        destination_lease.assert_owned()?;
        let current = read_target_config(&report.target_config)?;
        ensure_config_points_to_run(
            &current,
            &report.destination,
            &report.run_id,
            "migration destination",
        )
    }
    .await;
    if let Err(error) = fenced_verification {
        let reseal = inventory_sqlite_files(&report.source.path).and_then(|files| {
            seal_files(&files)?;
            report.source_sealed_files = files;
            Ok(())
        });
        source_db.close().await;
        destination_db.close().await;
        source_lease.release().await;
        destination_lease.release().await;
        report.failure_stage = Some("rollback_fenced_verification".into());
        let returned_error = match reseal {
            Ok(()) => error,
            Err(reseal_error) => Error::engine(format!(
                "{error}; retained source re-sealing also failed: {reseal_error}"
            )),
        };
        report.error = Some(returned_error.to_string());
        report.operator_guidance = "Rollback did not switch targets. The active destination or retained source failed fenced verification; destination drift is never discarded. Resolve the reported state or migrate current destination data forward before retrying.".into();
        atomic_json(&report_path, &report)?;
        return Err(returned_error);
    }
    // Drain the application pools before inventorying. The two distinct lease
    // connections still hold both write fences, so this can checkpoint or
    // remove pool-owned sidecars without reopening a write race. Releasing the
    // leases later performs no logical write, and a disappeared sidecar is
    // explicitly tolerated by mode restoration.
    source_db.close().await;
    destination_db.close().await;
    // Refresh identities only after both fences are held and every validation
    // query is complete. Seal the destination while those exact live file
    // objects remain fenced; pool/lease teardown may then remove sidecars but
    // cannot make the durable database writable again.
    let preparation = (|| {
        let refreshed_source = inventory_sqlite_files(&report.source.path)?;
        let refreshed_destination = inventory_sqlite_files(&report.destination.path)?;
        Ok((refreshed_source, refreshed_destination))
    })();
    let (refreshed_source, refreshed_destination) = match preparation {
        Ok(inventories) => inventories,
        Err(error) => {
            let reseal = inventory_sqlite_files(&report.source.path).and_then(|files| {
                seal_files(&files)?;
                report.source_sealed_files = files;
                Ok(())
            });
            source_db.close().await;
            destination_db.close().await;
            source_lease.release().await;
            destination_lease.release().await;
            let returned_error = match reseal {
                Ok(()) => error,
                Err(reseal_error) => Error::engine(format!(
                    "rollback preparation failed: {error}; retained source re-sealing also failed: {reseal_error}"
                )),
            };
            report.failure_stage = Some("rollback_inventory_preparation".into());
            report.error = Some(returned_error.to_string());
            report.operator_guidance = "Rollback did not switch targets. Preparing the fenced file inventories failed; the source was re-sealed where possible and the destination remains active.".into();
            let journal = atomic_json(&report_path, &report);
            return match journal {
                Ok(()) => Err(returned_error),
                Err(journal_error) => Err(Error::engine(format!(
                    "{returned_error}; persisting the recovery-required rollback state also failed: {journal_error}"
                ))),
            };
        }
    };
    report.source_sealed_files = refreshed_source;
    report.destination_sealed_files = refreshed_destination;
    // Persist the exact post-checkpoint file identities before chmod. A crash
    // after sealing can therefore restore this precise DB/WAL/SHM set instead
    // of consulting the older cutover inventory.
    report.operator_guidance = "Rollback fenced verification passed and refreshed file identities are durable. The next operation seals the active destination before the atomic target switch.".into();
    if let Err(error) = atomic_json(&report_path, &report) {
        let reseal_source = seal_files(&report.source_sealed_files);
        source_db.close().await;
        destination_db.close().await;
        source_lease.release().await;
        destination_lease.release().await;
        return match reseal_source {
            Ok(()) => Err(error),
            Err(recovery_error) => Err(Error::engine(format!(
                "persisting refreshed rollback file identities failed: {error}; re-sealing the retained source also failed: {recovery_error}"
            ))),
        };
    }
    if let Err(error) = seal_files(&report.destination_sealed_files) {
        let reseal_source = seal_files(&report.source_sealed_files);
        source_db.close().await;
        destination_db.close().await;
        source_lease.release().await;
        destination_lease.release().await;
        let returned_error = match reseal_source {
            Ok(()) => error,
            Err(reseal_error) => Error::engine(format!(
                "sealing the active rollback destination failed: {error}; re-sealing the retained source also failed: {reseal_error}"
            )),
        };
        report.failure_stage = Some("rollback_destination_seal".into());
        report.error = Some(returned_error.to_string());
        report.operator_guidance = "Rollback did not switch targets. Sealing the active destination failed after refreshed identities were persisted; the retained source was re-sealed where possible.".into();
        let journal = atomic_json(&report_path, &report);
        return match journal {
            Ok(()) => Err(returned_error),
            Err(journal_error) => Err(Error::engine(format!(
                "{returned_error}; persisting the destination-seal failure also failed: {journal_error}"
            ))),
        };
    }
    if failure == RollbackFailurePoint::AfterDestinationSeal {
        source_db.close().await;
        destination_db.close().await;
        source_lease.release().await;
        destination_lease.release().await;
        return Err(Error::engine(
            "injected rollback interruption after destination sealing",
        ));
    }
    report.operator_guidance = "Rollback fenced verification passed and the active destination is sealed. The next atomic operation switches the controlled target to the verified source.".into();
    if let Err(error) = atomic_json(&report_path, &report) {
        let restore_destination = restore_files(&report.destination_sealed_files);
        let reseal_source = seal_files(&report.source_sealed_files);
        source_db.close().await;
        destination_db.close().await;
        source_lease.release().await;
        destination_lease.release().await;
        let recovery = combine_mode_recovery(restore_destination, reseal_source);
        return match recovery {
            Ok(()) => Err(error),
            Err(recovery_error) => Err(Error::engine(format!(
                "persisting the sealed-destination rollback journal failed: {error}; restoring safe pre-switch file modes also failed: {recovery_error}"
            ))),
        };
    }
    let rolled_back_at = now();
    if let Err(error) = atomic_json(
        &report.target_config,
        &TargetConfig {
            format: TARGET_FORMAT.into(),
            controller: TARGET_CONTROLLER.into(),
            active: report.source.clone(),
            switched_at: rolled_back_at.clone(),
            migration_run_id: Some(report.run_id.clone()),
        },
    ) {
        let restore_destination = restore_files(&report.destination_sealed_files);
        let reseal_source = seal_files(&report.source_sealed_files);
        source_db.close().await;
        destination_db.close().await;
        source_lease.release().await;
        destination_lease.release().await;
        let recovery = combine_mode_recovery(restore_destination, reseal_source);
        report.failure_stage = Some("rollback_target_switch".into());
        report.operator_guidance = "Rollback did not switch targets. The target-config update failed; the destination was restored as active and the source re-sealed where possible.".into();
        let returned_error = match recovery {
            Ok(()) => error,
            Err(recovery_error) => Error::engine(format!(
                "target config switch failed: {error}; restoring safe pre-switch file modes also failed: {recovery_error}"
            )),
        };
        report.error = Some(returned_error.to_string());
        let journal = atomic_json(&report_path, &report);
        return match journal {
            Ok(()) => Err(returned_error),
            Err(journal_error) => Err(Error::engine(format!(
                "{returned_error}; persisting the rollback failure also failed: {journal_error}"
            ))),
        };
    }
    if failure == RollbackFailurePoint::AfterConfigSwitch {
        source_db.close().await;
        destination_db.close().await;
        source_lease.release().await;
        destination_lease.release().await;
        return Err(Error::engine(
            "injected rollback interruption after target config switch",
        ));
    }
    source_db.close().await;
    destination_db.close().await;
    source_lease.release().await;
    destination_lease.release().await;
    report.rolled_back_at = Some(rolled_back_at);
    report.state = MigrationState::RolledBack;
    report.failure_stage = None;
    report.error = None;
    report.operator_guidance = "Rollback complete. The source is active; the destination remains sealed for diagnosis. Start any future migration with a new report and destination.".into();
    atomic_json(&report_path, &report)?;
    Ok(report)
}

fn reject_unsupported_route(source: &StorageTarget, destination: &StorageTarget) -> Result<()> {
    if source.is_supported_sqlite() && destination.is_supported_sqlite() {
        return Ok(());
    }
    Err(Error::engine(format!(
        "unsupported production storage migration route {} -> {}; revision 1 supports sqlite-local revisions 1 through 2. postgres-server is partial and Turso remote/sync profiles remain research-only",
        source.label(),
        destination.label()
    )))
}

fn load_or_begin_report(
    options: &MigrationOptions,
    configured: &TargetConfig,
    failure: FailurePoint,
) -> Result<MigrationReport> {
    validate_target_config(configured)?;
    if occupied(&options.report) {
        let mut report: MigrationReport = read_json(&options.report)?;
        validate_report(&report)?;
        if report.source != options.source
            || report.destination != options.destination
            || report.target_config != options.target_config
            || report.report_path != options.report
        {
            return Err(Error::engine(
                "existing migration report does not exactly match this command; choose a new report path",
            ));
        }
        ensure_provenance_workspace_inner(&mut report, failure)?;
        atomic_json(&options.report, &report)?;
        return Ok(report);
    }
    ensure_config_points_to(configured, &options.source, "migration source")?;
    if occupied(&options.destination.path) {
        return Err(Error::engine(format!(
            "storage migration destination already exists: {}",
            options.destination.path.display()
        )));
    }
    let run_id = uuid::Uuid::new_v4().to_string();
    let provenance_directory = options
        .report
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".native-storage-migration-{run_id}"));
    let mut report = MigrationReport {
        format: REPORT_FORMAT.into(),
        revision: 1,
        run_id,
        state: MigrationState::Preparing,
        attempts: 0,
        source: options.source.clone(),
        destination: options.destination.clone(),
        target_config: options.target_config.clone(),
        report_path: options.report.clone(),
        canonical_sha256: None,
        destination_sha256: None,
        canonical_bytes: None,
        projection_conformance_ok: None,
        started_at: now(),
        lease_acquired_at: None,
        exported_at: None,
        imported_at: None,
        verified_at: None,
        report_durable_at: None,
        cutover_at: None,
        source_sealed_at: None,
        rollback_deadline: None,
        rolled_back_at: None,
        source_sealed_files: Vec::new(),
        destination_sealed_files: Vec::new(),
        import_anchor: provenance_directory.join("import.db"),
        provenance_directory,
        provenance_directory_identity: None,
        import_anchor_identity: None,
        destination_identity: None,
        failure_stage: None,
        error: None,
        operator_guidance: "Preparing migration. No cutover has occurred.".into(),
    };
    create_json(&options.report, &report)?;
    ensure_provenance_workspace_inner(&mut report, failure)?;
    atomic_json(&options.report, &report)?;
    Ok(report)
}

async fn finish_cutover_recovery(
    options: &MigrationOptions,
    report: &mut MigrationReport,
) -> Result<()> {
    if report.source_sealed_files.is_empty() {
        return Err(Error::engine(
            "verified migration report lacks the pre-cutover source mode inventory; refuse recovery and use the retained source/config for manual inspection",
        ));
    }
    let destination_db = open_existing_database_at(&report.destination.path).await?;
    if let Err(error) = require_conformance(&destination_db, "cutover recovery destination").await {
        destination_db.close().await;
        return Err(error);
    }
    let mut lease = match LeaseGuard::acquire(
        &report.destination.path,
        recovery_lease_path(&options.report, "destination"),
        &report.run_id,
    )
    .await
    {
        Ok(lease) => lease,
        Err(error) => {
            destination_db.close().await;
            return Err(error);
        }
    };
    let result = async {
        lease.assert_owned()?;
        let canonical = export_canonical_interchange(&destination_db).await?;
        if Some(sha256(&canonical)) != report.canonical_sha256 {
            return Err(Error::engine(
                "cutover recovery destination canonical SHA-256 no longer matches the journal",
            ));
        }
        crate::db::validate_current_engine_shape_read_only(&report.destination.path).await?;
        let expected = report.import_anchor_identity.as_ref().ok_or_else(|| {
            Error::engine("verified report lacks import-anchor file identity")
        })?;
        if &file_identity(&report.destination.path)? != expected {
            return Err(Error::engine(
                "cutover recovery destination no longer matches the journaled import anchor",
            ));
        }
        lease.assert_owned()?;
        seal_files(&report.source_sealed_files)?;
        report.source_sealed_at.get_or_insert_with(now);
        report.cutover_at.get_or_insert_with(now);
        if report.rollback_deadline.is_none() {
            report.rollback_deadline = Some(
                (Utc::now()
                    + chrono::Duration::from_std(options.rollback_window)
                        .map_err(|_| Error::engine("rollback window is too large"))?)
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            );
        }
        report.state = MigrationState::Cutover;
        report.operator_guidance = "Recovered a cutover whose config switch was durable before its final report update. The fenced destination was reverified, the source is sealed, and rollback remains available until the recorded deadline.".into();
        atomic_json(&options.report, report)
    }
    .await;
    destination_db.close().await;
    lease.release().await;
    result
}

fn validate_target_config(config: &TargetConfig) -> Result<()> {
    if config.format != TARGET_FORMAT || config.controller != TARGET_CONTROLLER {
        return Err(Error::engine(
            "unsupported target config; the local adapter must be initialized and exclusively controlled by operator storage-migration",
        ));
    }
    Ok(())
}

fn validate_report(report: &MigrationReport) -> Result<()> {
    if report.format != REPORT_FORMAT || report.revision != 1 || report.run_id.is_empty() {
        return Err(Error::engine(
            "unsupported or malformed storage migration report",
        ));
    }
    let expected_workspace = report
        .report_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".native-storage-migration-{}", report.run_id));
    if report.provenance_directory != expected_workspace
        || report.import_anchor != expected_workspace.join("import.db")
    {
        return Err(Error::engine(
            "migration report provenance paths do not match its run ID and report directory",
        ));
    }
    if report.source.path == report.destination.path {
        return Err(Error::engine(
            "migration report source and destination paths must be distinct",
        ));
    }
    reject_unsupported_route(&report.source, &report.destination)
}

fn ensure_provenance_workspace_inner(
    report: &mut MigrationReport,
    failure: FailurePoint,
) -> Result<()> {
    if report.import_anchor != report.provenance_directory.join("import.db") {
        return Err(Error::engine(
            "migration report import anchor is outside its provenance directory",
        ));
    }
    if !occupied(&report.provenance_directory) {
        let staging = provenance_staging_path(&report.provenance_directory);
        if !occupied(&staging) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).create(&staging)?;
            }
            #[cfg(not(unix))]
            fs::create_dir(&staging)?;
            // The deterministic empty staging directory is the only narrowly
            // recoverable tokenless state. Make its entry durable so a crash
            // here can be reproduced and completed by the same report.
            sync_parent(&staging)?;
            if failure == FailurePoint::AfterProvenanceDirectory {
                return Err(Error::engine(
                    "injected interruption after provenance staging directory creation",
                ));
            }
        }
        ensure_staged_provenance_owner(report, &staging)?;
        validate_staged_provenance_workspace(report, &staging)?;
        if occupied(&report.provenance_directory) {
            return Err(Error::engine(
                "migration provenance workspace became occupied before atomic publication; preserving both paths",
            ));
        }
        fs::rename(&staging, &report.provenance_directory)?;
        sync_parent(&report.provenance_directory)?;
    }
    let identity = validate_provenance_workspace(report)?;
    report.provenance_directory_identity = Some(identity);
    Ok(())
}

fn provenance_staging_path(final_path: &Path) -> PathBuf {
    let mut path = final_path.as_os_str().to_os_string();
    path.push(".staging");
    PathBuf::from(path)
}

fn provenance_pending_owner_path(final_path: &Path) -> PathBuf {
    let mut path = final_path.as_os_str().to_os_string();
    path.push(".owner.pending");
    PathBuf::from(path)
}

fn ensure_staged_provenance_owner(report: &MigrationReport, staging: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(staging)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::engine(
            "migration provenance staging path is not a real directory; preserving it",
        ));
    }
    let mut entries = fs::read_dir(staging)?
        .map(|entry| Ok(entry?.file_name()))
        .collect::<Result<Vec<_>>>()?;
    if entries.is_empty() {
        let pending_owner = provenance_pending_owner_path(&report.provenance_directory);
        if !occupied(&pending_owner) {
            // atomic_json builds the token in a unique sibling file and only
            // then publishes the deterministic pending-owner path. A crash
            // while writing can therefore leave debris but cannot poison the
            // exact restart path with a partial owner document.
            atomic_json(
                &pending_owner,
                &ProvenanceOwner {
                    format: REPORT_FORMAT.into(),
                    run_id: report.run_id.clone(),
                },
            )?;
        }
        validate_pending_provenance_owner(report, &pending_owner)?;
        fs::rename(&pending_owner, staging.join("owner.json"))?;
        sync_parent(&pending_owner)?;
        sync_parent(&staging.join("owner.json"))?;
        return Ok(());
    }
    entries.sort();
    if entries != [std::ffi::OsString::from("owner.json")] {
        return Err(Error::engine(
            "tokenless migration provenance staging directory is not empty; preserving it",
        ));
    }
    Ok(())
}

fn validate_pending_provenance_owner(report: &MigrationReport, pending: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(pending)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(
            "migration provenance pending owner is not a regular file; preserving it",
        ));
    }
    let owner: ProvenanceOwner = read_json(pending)?;
    if owner
        != (ProvenanceOwner {
            format: REPORT_FORMAT.into(),
            run_id: report.run_id.clone(),
        })
    {
        return Err(Error::engine(
            "migration provenance pending owner belongs to another run; preserving it",
        ));
    }
    Ok(())
}

fn validate_staged_provenance_workspace(report: &MigrationReport, staging: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(staging)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::engine(
            "migration provenance staging path is not a real directory; preserving it",
        ));
    }
    let owner_path = staging.join("owner.json");
    let owner_metadata = fs::symlink_metadata(&owner_path)?;
    if owner_metadata.file_type().is_symlink() || !owner_metadata.is_file() {
        return Err(Error::engine(
            "migration provenance staging owner is not a regular file; preserving it",
        ));
    }
    let owner: ProvenanceOwner = read_json(&owner_path)?;
    if owner.format != REPORT_FORMAT || owner.run_id != report.run_id {
        return Err(Error::engine(
            "migration provenance staging path belongs to another run; preserving it",
        ));
    }
    let mut entries = fs::read_dir(staging)?
        .map(|entry| Ok(entry?.file_name()))
        .collect::<Result<Vec<_>>>()?;
    entries.sort();
    if entries != [std::ffi::OsString::from("owner.json")] {
        return Err(Error::engine(
            "migration provenance staging directory contains unowned files; preserving it",
        ));
    }
    Ok(())
}

fn validate_provenance_workspace(report: &MigrationReport) -> Result<DirectoryIdentity> {
    let owner_path = report.provenance_directory.join("owner.json");
    let metadata = fs::symlink_metadata(&report.provenance_directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::engine(
            "migration provenance workspace is not a real directory",
        ));
    }
    let owner: ProvenanceOwner = read_json(&owner_path).map_err(|error| {
        Error::engine(format!(
            "migration provenance workspace has no valid ownership token; preserving it: {error}"
        ))
    })?;
    if owner.format != REPORT_FORMAT || owner.run_id != report.run_id {
        return Err(Error::engine(
            "migration provenance workspace belongs to another run; preserving it",
        ));
    }
    let identity = directory_identity(&metadata);
    if report
        .provenance_directory_identity
        .as_ref()
        .is_some_and(|expected| expected != &identity)
    {
        return Err(Error::engine(
            "migration provenance workspace file identity changed; preserving it",
        ));
    }
    Ok(identity)
}

#[cfg(unix)]
fn directory_identity(metadata: &fs::Metadata) -> DirectoryIdentity {
    use std::os::unix::fs::MetadataExt as _;
    DirectoryIdentity {
        device: Some(metadata.dev()),
        inode: Some(metadata.ino()),
    }
}

#[cfg(not(unix))]
fn directory_identity(_metadata: &fs::Metadata) -> DirectoryIdentity {
    DirectoryIdentity {
        device: None,
        inode: None,
    }
}

fn file_identity(path: &Path) -> Result<FileIdentity> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(Error::engine(format!(
            "cannot identify non-regular migration file: {}",
            path.display()
        )));
    }
    let digest = sha256_file(path)?;
    let after = fs::symlink_metadata(path)?;
    let identity = file_identity_from_metadata(&after, digest);
    if file_identity_from_metadata(&before, identity.sha256.clone()) != identity {
        return Err(Error::engine(format!(
            "migration file changed while its identity was measured: {}",
            path.display()
        )));
    }
    Ok(identity)
}

#[cfg(unix)]
fn file_identity_from_metadata(metadata: &fs::Metadata, sha256: String) -> FileIdentity {
    use std::os::unix::fs::MetadataExt as _;
    FileIdentity {
        device: Some(metadata.dev()),
        inode: Some(metadata.ino()),
        size: metadata.len(),
        sha256,
    }
}

#[cfg(not(unix))]
fn file_identity_from_metadata(metadata: &fs::Metadata, sha256: String) -> FileIdentity {
    FileIdentity {
        device: None,
        inode: None,
        size: metadata.len(),
        sha256,
    }
}

fn ensure_config_points_to(
    config: &TargetConfig,
    target: &StorageTarget,
    label: &str,
) -> Result<()> {
    validate_target_config(config)?;
    if &config.active != target {
        return Err(Error::engine(format!(
            "target config does not point at the exact journaled {label}"
        )));
    }
    Ok(())
}

fn ensure_config_points_to_run(
    config: &TargetConfig,
    target: &StorageTarget,
    run_id: &str,
    label: &str,
) -> Result<()> {
    ensure_config_points_to(config, target, label)?;
    if config.migration_run_id.as_deref() != Some(run_id) {
        return Err(Error::engine(format!(
            "target config points at {label} but does not identify migration run {run_id}"
        )));
    }
    Ok(())
}

fn read_target_config(path: &Path) -> Result<TargetConfig> {
    let value: TargetConfig = read_json(path)?;
    validate_target_config(&value)?;
    Ok(value)
}

fn stage_name(_state: MigrationState, report: &MigrationReport) -> String {
    if report.verified_at.is_some() {
        "cutover".into()
    } else if report.imported_at.is_some() {
        "verification".into()
    } else if report.exported_at.is_some() {
        "import".into()
    } else {
        "export".into()
    }
}

fn ensure_distinct_paths(options: &MigrationOptions) -> Result<()> {
    let paths = [
        &options.source.path,
        &options.destination.path,
        &options.target_config,
        &options.report,
    ];
    for left in 0..paths.len() {
        for right in left + 1..paths.len() {
            if paths[left] == paths[right] {
                return Err(Error::engine(
                    "source, destination, target config, and report paths must be distinct",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_unix_migration_platform() -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn require_unix_migration_platform() -> Result<()> {
    Err(Error::engine(
        "storage migration revision 1 is Unix-only: hard-link publication and durable directory fsync are required; no copy fallback is permitted",
    ))
}

#[cfg(unix)]
fn preflight_migration_filesystems(
    source: &Path,
    destination: &Path,
    target_config: &Path,
    report: &Path,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let source_parent = source
        .parent()
        .ok_or_else(|| Error::engine("migration source has no parent directory"))?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| Error::engine("migration destination has no parent directory"))?;
    let config_parent = target_config
        .parent()
        .ok_or_else(|| Error::engine("migration target config has no parent directory"))?;
    let report_parent = report
        .parent()
        .ok_or_else(|| Error::engine("migration report has no parent directory"))?;

    let source_device = fs::symlink_metadata(source)?.dev();
    let source_parent_device = fs::symlink_metadata(source_parent)?.dev();
    ensure_compatible_device(
        "source database",
        source_device,
        "source sidecar parent",
        source_parent_device,
    )?;

    let config_device = fs::symlink_metadata(target_config)?.dev();
    let config_parent_device = fs::symlink_metadata(config_parent)?.dev();
    ensure_compatible_device(
        "target config",
        config_device,
        "target-config atomic-replacement parent",
        config_parent_device,
    )?;

    let report_parent_device = fs::symlink_metadata(report_parent)?.dev();
    let destination_parent_device = fs::symlink_metadata(destination_parent)?.dev();
    ensure_compatible_device(
        "report/provenance parent",
        report_parent_device,
        "destination publication parent",
        destination_parent_device,
    )?;

    if occupied(report) {
        ensure_compatible_device(
            "migration report",
            fs::symlink_metadata(report)?.dev(),
            "report atomic-replacement parent",
            report_parent_device,
        )?;
        let existing: MigrationReport = read_json(report)?;
        if existing.report_path == report && occupied(&existing.provenance_directory) {
            ensure_compatible_device(
                "existing provenance workspace",
                fs::symlink_metadata(&existing.provenance_directory)?.dev(),
                "destination publication parent",
                destination_parent_device,
            )?;
        }
        if existing.report_path == report && occupied(&existing.import_anchor) {
            ensure_compatible_device(
                "existing import anchor",
                fs::symlink_metadata(&existing.import_anchor)?.dev(),
                "destination publication parent",
                destination_parent_device,
            )?;
        }
    }
    if occupied(destination) {
        ensure_compatible_device(
            "migration destination",
            fs::symlink_metadata(destination)?.dev(),
            "destination publication parent",
            destination_parent_device,
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn preflight_migration_filesystems(
    _source: &Path,
    _destination: &Path,
    _target_config: &Path,
    _report: &Path,
) -> Result<()> {
    require_unix_migration_platform()
}

#[cfg(unix)]
fn ensure_compatible_device(
    left_label: &str,
    left_device: u64,
    right_label: &str,
    right_device: u64,
) -> Result<()> {
    if left_device == right_device {
        return Ok(());
    }
    Err(Error::engine(format!(
        "cross-filesystem storage migration is unsupported: {left_label} is on device {left_device}, but {right_label} is on device {right_device}; revision 1 requires same-filesystem hard-link/atomic publication and never falls back to copying"
    )))
}

fn existing_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::engine(format!(
            "{label} {} is unavailable: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(format!(
            "{label} must be a real regular file: {}",
            path.display()
        )));
    }
    Ok(fs::canonicalize(path)?)
}

fn new_path_in_existing_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        Error::engine(format!("{label} must name a file in an existing directory"))
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_meta = fs::symlink_metadata(parent).map_err(|error| {
        Error::engine(format!(
            "{label} parent {} is unavailable: {error}",
            parent.display()
        ))
    })?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(Error::engine(format!(
            "{label} parent must be a real directory: {}",
            parent.display()
        )));
    }
    Ok(fs::canonicalize(parent)?.join(name))
}

fn occupied(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

async fn require_conformance(db: &crate::Db, label: &str) -> Result<()> {
    crate::storage_profile::with_operation(
        db,
        "storage_migration_conformance",
        Some("native.guarded-write.v1"),
        async {
            let conformance = crate::conformance::run_conformance(db).await;
            if conformance.ok {
                return Ok(());
            }
            Err(Error::engine(format!(
                "{label} failed behavioral projection conformance: {}",
                conformance
                    .checks
                    .iter()
                    .filter(|check| !check.ok)
                    .map(|check| check.check.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        },
    )
    .await
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn create_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = pretty_json(value)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    sync_parent(path)
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = pretty_json(value)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("storage-migration"),
        uuid::Uuid::new_v4()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn lease_path(report: &Path) -> PathBuf {
    let mut path = report.as_os_str().to_os_string();
    path.push(".lease");
    PathBuf::from(path)
}

fn recovery_lease_path(report: &Path, label: &str) -> PathBuf {
    let mut path = report.as_os_str().to_os_string();
    path.push(format!(".{label}.lease"));
    PathBuf::from(path)
}

async fn remove_unpublished_destination(report: &MigrationReport) -> Result<()> {
    if matches!(
        report.state,
        MigrationState::Cutover | MigrationState::RolledBack | MigrationState::RecoveryRequired
    ) {
        return Err(Error::engine(
            "refusing to remove a destination after cutover",
        ));
    }
    let database = &report.destination.path;
    if !occupied(database) {
        refuse_orphaned_sidecars(database)?;
        return Ok(());
    }
    validate_provenance_workspace(report)?;
    let expected = report.import_anchor_identity.as_ref().ok_or_else(|| {
        Error::engine(
            "destination is occupied without a durable import-anchor identity; preserving it",
        )
    })?;
    let anchor = file_identity(&report.import_anchor)?;
    let destination = file_identity(database)?;
    if &anchor != expected || &destination != expected || !same_file_identity(&anchor, &destination)
    {
        return Err(Error::engine(
            "occupied destination is not the exact journaled import-anchor file; preserving it",
        ));
    }
    // The migration never opens the published path before cutover. Any WAL or
    // SHM there is therefore foreign/ambiguous even when the base inode is our
    // hard link; preserve the whole path rather than deleting unowned sidecars.
    refuse_orphaned_sidecars(database)?;
    fs::remove_file(database)?;
    sync_parent(database)
}

fn remove_import_anchor(report: &MigrationReport) -> Result<()> {
    if !occupied(&report.import_anchor) {
        refuse_orphaned_sidecars(&report.import_anchor)?;
        return Ok(());
    }
    validate_provenance_workspace(report)?;
    // Before SQLite closes/checkpoints, the run-private 0700 workspace and its
    // journaled directory identity + owner token are the ownership proof. A
    // stable anchor identity is recorded only after close.
    if let Some(expected) = report.import_anchor_identity.as_ref() {
        if &file_identity(&report.import_anchor)? != expected {
            return Err(Error::engine(
                "import anchor file identity changed; preserving the provenance workspace",
            ));
        }
    }
    remove_sqlite_file_set(&report.import_anchor)
}

fn refuse_orphaned_sidecars(database: &Path) -> Result<()> {
    for sidecar in sqlite_file_set(database).into_iter().skip(1) {
        if occupied(&sidecar) {
            return Err(Error::engine(format!(
                "refusing to clean orphaned SQLite sidecar without its journaled database: {}",
                sidecar.display()
            )));
        }
    }
    Ok(())
}

fn remove_sqlite_file_set(database: &Path) -> Result<()> {
    let mut present = Vec::new();
    for path in sqlite_file_set(database) {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::engine(format!(
                    "refusing to clean non-regular SQLite file: {}",
                    path.display()
                )))
            }
            Ok(_) => present.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    present.sort_by_key(|path| path == database);
    for path in present {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &FileIdentity, right: &FileIdentity) -> bool {
    left.device.is_some() && left.device == right.device && left.inode == right.inode
}

#[cfg(not(unix))]
fn same_file_identity(_left: &FileIdentity, _right: &FileIdentity) -> bool {
    // std exposes no stable cross-platform file ID. Preserve ambiguous paths.
    false
}

fn sqlite_file_set(database: &Path) -> [PathBuf; 3] {
    [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
    ]
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(mode != 0);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn inventory_sqlite_files(database: &Path) -> Result<Vec<SealedFile>> {
    let mut files = Vec::new();
    for (index, path) in sqlite_file_set(database).into_iter().enumerate() {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::engine(format!(
                    "refusing to inventory non-regular SQLite file: {}",
                    path.display()
                )))
            }
            Ok(metadata) => {
                let mode = file_mode(&metadata);
                files.push(SealedFile {
                    identity: file_identity(&path)?,
                    path,
                    original_mode: mode,
                });
            }
            Err(error) if index > 0 && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::engine(
                    "SQLite database disappeared before inventory",
                ))
            }
            Err(error) => return Err(error.into()),
        }
    }
    if files.is_empty() {
        return Err(Error::engine(
            "SQLite database disappeared before inventory",
        ));
    }
    Ok(files)
}

/// Refresh a sealed SQLite file set after the connection that fenced it has
/// closed. SQLite may checkpoint or remove WAL sidecars during that close, so
/// raw hashes captured while the connection was live are not durable rollback
/// identities. Existing paths must retain their device/inode identity; newly
/// materialized sidecars are admitted only from the same three-path SQLite set
/// and are sealed before the refreshed journal is persisted.
fn refresh_sealed_file_identities(files: &[SealedFile]) -> Result<Vec<SealedFile>> {
    let database = files
        .first()
        .ok_or_else(|| Error::engine("SQLite file mode inventory is empty"))?
        .path
        .clone();
    let mut refreshed = Vec::new();
    for (index, path) in sqlite_file_set(&database).into_iter().enumerate() {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if index > 0 && error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::engine(format!(
                "refusing to refresh non-regular SQLite file: {}",
                path.display()
            )));
        }
        let identity = file_identity(&path)?;
        let original_mode = if let Some(previous) = files.iter().find(|file| file.path == path) {
            if !same_file_identity(&previous.identity, &identity) {
                return Err(Error::engine(format!(
                    "refusing to refresh replaced SQLite file: {}",
                    path.display()
                )));
            }
            previous.original_mode
        } else {
            file_mode(&metadata)
        };
        refreshed.push(SealedFile {
            path,
            original_mode,
            identity,
        });
    }
    Ok(refreshed)
}

fn seal_files(files: &[SealedFile]) -> Result<()> {
    let existing = validate_inventory_files(files, "seal")?;
    let database = &files[0].path;
    let mut prepared = Vec::new();
    for file in existing {
        match fs::metadata(&file.path) {
            Ok(metadata) => prepared.push((file, file_mode(&metadata))),
            Err(error)
                if is_sqlite_sidecar(database, &file.path)
                    && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut changed: Vec<(&SealedFile, u32)> = Vec::new();
    for (file, previous_mode) in prepared {
        if let Err(error) = set_mode(&file.path, read_only_mode(file.original_mode)) {
            if is_disappeared_sqlite_sidecar(&error, database, &file.path) {
                continue;
            }
            let mut compensation_errors = Vec::new();
            for (previous, previous_mode) in changed {
                if let Err(compensation) = set_mode(&previous.path, previous_mode) {
                    if is_disappeared_sqlite_sidecar(&compensation, database, &previous.path) {
                        continue;
                    }
                    compensation_errors
                        .push(format!("{}: {compensation}", previous.path.display()));
                }
            }
            if !compensation_errors.is_empty() {
                return Err(Error::engine(format!(
                    "sealing SQLite file mode for {} failed: {error}; restoring prior active modes also failed for {}",
                    file.path.display(),
                    compensation_errors.join(", ")
                )));
            }
            return Err(Error::engine(format!(
                "sealing SQLite file mode for {} failed: {error}",
                file.path.display()
            )));
        }
        changed.push((file, previous_mode));
    }
    Ok(())
}

fn restore_files(files: &[SealedFile]) -> Result<()> {
    let existing = validate_inventory_files(files, "restore")?;
    let database = &files[0].path;
    let mut prepared = Vec::new();
    for file in existing {
        match fs::metadata(&file.path) {
            Ok(metadata) => prepared.push((file, file_mode(&metadata))),
            Err(error)
                if is_sqlite_sidecar(database, &file.path)
                    && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut changed: Vec<(&SealedFile, u32)> = Vec::new();
    for (file, previous_mode) in prepared {
        if let Err(error) = set_mode(&file.path, file.original_mode) {
            if is_disappeared_sqlite_sidecar(&error, database, &file.path) {
                continue;
            }
            let mut compensation_errors = Vec::new();
            for (previous, previous_mode) in changed {
                if let Err(compensation) = set_mode(&previous.path, previous_mode) {
                    if is_disappeared_sqlite_sidecar(&compensation, database, &previous.path) {
                        continue;
                    }
                    compensation_errors
                        .push(format!("{}: {compensation}", previous.path.display()));
                }
            }
            if !compensation_errors.is_empty() {
                return Err(Error::engine(format!(
                    "restoring SQLite file mode for {} failed: {error}; restoring prior active modes also failed for {}",
                    file.path.display(),
                    compensation_errors.join(", ")
                )));
            }
            return Err(Error::engine(format!(
                "restoring SQLite file mode for {} failed: {error}",
                file.path.display()
            )));
        }
        changed.push((file, previous_mode));
    }
    Ok(())
}

fn combine_mode_recovery(restore_destination: Result<()>, reseal_source: Result<()>) -> Result<()> {
    match (restore_destination, reseal_source) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(destination), Ok(())) => Err(destination),
        (Ok(()), Err(source)) => Err(source),
        (Err(destination), Err(source)) => Err(Error::engine(format!(
            "restoring the active destination failed: {destination}; re-sealing the retained source also failed: {source}"
        ))),
    }
}

async fn acquire_ordered_rollback_leases(
    report: &MigrationReport,
    report_path: &Path,
) -> Result<(LeaseGuard, LeaseGuard)> {
    let source_first = report.source.path < report.destination.path;
    if source_first {
        let mut source = LeaseGuard::acquire(
            &report.source.path,
            recovery_lease_path(report_path, "rollback-source"),
            &report.run_id,
        )
        .await?;
        let destination = match LeaseGuard::acquire(
            &report.destination.path,
            recovery_lease_path(report_path, "rollback-destination"),
            &report.run_id,
        )
        .await
        {
            Ok(lease) => lease,
            Err(error) => {
                source.release().await;
                return Err(error);
            }
        };
        Ok((source, destination))
    } else {
        let mut destination = LeaseGuard::acquire(
            &report.destination.path,
            recovery_lease_path(report_path, "rollback-destination"),
            &report.run_id,
        )
        .await?;
        let source = match LeaseGuard::acquire(
            &report.source.path,
            recovery_lease_path(report_path, "rollback-source"),
            &report.run_id,
        )
        .await
        {
            Ok(lease) => lease,
            Err(error) => {
                destination.release().await;
                return Err(error);
            }
        };
        Ok((source, destination))
    }
}

fn validate_inventory_files<'a>(
    files: &'a [SealedFile],
    operation: &str,
) -> Result<Vec<&'a SealedFile>> {
    if files.is_empty() {
        return Err(Error::engine("SQLite file mode inventory is empty"));
    }
    let mut existing = Vec::new();
    for (index, file) in files.iter().enumerate() {
        let metadata = match fs::symlink_metadata(&file.path) {
            Ok(metadata) => metadata,
            Err(error) if index > 0 && error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::engine(format!(
                "refusing to {operation} non-regular SQLite file: {}",
                file.path.display()
            )));
        }
        let identity = match file_identity(&file.path) {
            Ok(identity) => identity,
            Err(error) if is_disappeared_sqlite_sidecar(&error, &files[0].path, &file.path) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        if identity != file.identity {
            return Err(Error::engine(format!(
                "refusing to {operation} replaced SQLite file: {}",
                file.path.display()
            )));
        }
        existing.push(file);
    }
    Ok(existing)
}

fn is_disappeared_sqlite_sidecar(error: &Error, database: &Path, path: &Path) -> bool {
    // Closing/checkpointing a fenced SQLite connection may unlink WAL/SHM at
    // any point between inventory validation and the following mode syscall.
    // The base database must never disappear, and no path outside SQLite's
    // exact three-file set receives this tolerance.
    is_sqlite_sidecar(database, path)
        && matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::NotFound)
}

fn is_sqlite_sidecar(database: &Path, path: &Path) -> bool {
    let sqlite_files = sqlite_file_set(database);
    sqlite_files[1..].iter().any(|sidecar| sidecar == path)
}

#[cfg(unix)]
fn read_only_mode(original_mode: u32) -> u32 {
    original_mode & !0o222
}

#[cfg(not(unix))]
fn read_only_mode(_original_mode: u32) -> u32 {
    1
}

struct LeaseGuard {
    connection: Option<SqliteConnection>,
    path: PathBuf,
    token: String,
    lost: Arc<AtomicBool>,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

impl LeaseGuard {
    async fn acquire(source: &Path, path: PathBuf, run_id: &str) -> Result<Self> {
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", source.display()))?
            .create_if_missing(false)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let mut connection = SqliteConnection::connect_with(&options).await?;
        connection
            .execute("BEGIN IMMEDIATE")
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "maintenance lease could not fence source writes: {error}"
                ))
            })?;

        let token = uuid::Uuid::new_v4().to_string();
        claim_lease(&path, run_id, &token, source)?;
        let lost = Arc::new(AtomicBool::new(false));
        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
        let heartbeat_path = path.clone();
        let heartbeat_token = token.clone();
        let heartbeat_lost = lost.clone();
        let heartbeat = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => break,
                    _ = interval.tick() => {
                        if renew_lease(&heartbeat_path, &heartbeat_token).is_err() {
                            heartbeat_lost.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            }
        });
        Ok(Self {
            connection: Some(connection),
            path,
            token,
            lost,
            cancel: Some(cancel_tx),
            heartbeat: Some(heartbeat),
        })
    }

    fn assert_owned(&self) -> Result<()> {
        if self.lost.load(Ordering::SeqCst) {
            return Err(Error::engine("maintenance lease heartbeat lost ownership"));
        }
        let lease: LeaseFile = read_json(&self.path)?;
        if lease.format != LEASE_FORMAT || lease.token != self.token {
            return Err(Error::engine("maintenance lease ownership changed"));
        }
        Ok(())
    }

    async fn release(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.await;
        }
        if let Some(mut connection) = self.connection.take() {
            let _ = connection.execute("ROLLBACK").await;
            let _ = connection.close().await;
        }
        if read_json::<LeaseFile>(&self.path).is_ok_and(|lease| lease.token == self.token) {
            let _ = fs::remove_file(&self.path);
            let _ = sync_parent(&self.path);
        }
    }
}

fn claim_lease(path: &Path, run_id: &str, token: &str, source: &Path) -> Result<()> {
    if occupied(path) {
        let existing: LeaseFile = read_json(path)?;
        let expiry = DateTime::parse_from_rfc3339(&existing.expires_at)
            .map_err(|_| Error::engine("existing maintenance lease has invalid expiry"))?;
        if Utc::now() <= expiry {
            return Err(Error::engine(format!(
                "maintenance lease is held by migration {} until {}",
                existing.run_id, existing.expires_at
            )));
        }
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::engine(
                "refusing to replace a non-regular stale lease",
            ));
        }
        fs::remove_file(path)?;
    }
    let acquired_at = now();
    create_json(
        path,
        &LeaseFile {
            format: LEASE_FORMAT.into(),
            run_id: run_id.into(),
            token: token.into(),
            source: source.into(),
            acquired_at: acquired_at.clone(),
            renewed_at: acquired_at,
            expires_at: (Utc::now() + chrono::Duration::seconds(LEASE_TTL_SECONDS))
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        },
    )
}

fn renew_lease(path: &Path, token: &str) -> Result<()> {
    let mut lease: LeaseFile = read_json(path)?;
    if lease.format != LEASE_FORMAT || lease.token != token {
        return Err(Error::engine("maintenance lease ownership changed"));
    }
    lease.renewed_at = now();
    lease.expires_at = (Utc::now() + chrono::Duration::seconds(LEASE_TTL_SECONDS))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    atomic_json(path, &lease)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::create_database;

    async fn fixture() -> (tempfile::TempDir, MigrationOptions) {
        let directory = tempfile::tempdir().unwrap();
        // Production path validation canonicalizes the existing parent. Do the
        // same in the fixture so macOS's /var -> /private/var alias does not
        // make otherwise identical StorageTarget values compare unequal.
        let root = fs::canonicalize(directory.path()).unwrap();
        let source = root.join("source.db");
        let destination = root.join("destination.db");
        let config = root.join("target.json");
        let report = root.join("migration.json");
        let db = create_database(source.to_str().unwrap()).await.unwrap();
        db.close().await;
        initialize_target_config(&config, &source).unwrap();
        let options = MigrationOptions {
            source: StorageTarget::sqlite_local(source),
            destination: StorageTarget::sqlite_local(destination),
            target_config: config,
            report,
            rollback_window: Duration::from_secs(3600),
        };
        (directory, options)
    }

    #[cfg(feature = "storage-recovery-tests")]
    fn assert_current_sqlite_file_set_is_sealed(database: &Path, inventory: &[SealedFile]) {
        use std::os::unix::fs::PermissionsExt as _;

        for current in inventory_sqlite_files(database).unwrap() {
            let recorded = inventory
                .iter()
                .find(|recorded| recorded.path == current.path)
                .unwrap_or_else(|| {
                    panic!(
                        "current SQLite file is absent from the durable seal inventory: {}",
                        current.path.display()
                    )
                });
            assert!(
                same_file_identity(&recorded.identity, &current.identity),
                "sealed SQLite file object was replaced: {}",
                current.path.display()
            );
            assert_eq!(
                fs::metadata(&current.path).unwrap().permissions().mode() & 0o222,
                0,
                "sealed SQLite file remains writable: {}",
                current.path.display()
            );
        }
    }

    #[cfg(feature = "storage-recovery-tests")]
    async fn open_live_wal_database(path: &Path) -> crate::db::Db {
        let database = open_existing_database_at(path).await.unwrap();
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(database.pool())
            .await
            .unwrap();
        assert_eq!(journal_mode, "wal");
        database
    }

    #[tokio::test]
    async fn verification_failure_never_cuts_over_and_is_restartable() {
        let (_directory, options) = fixture().await;
        let error = migrate_storage_inner(options.clone(), FailurePoint::BeforeVerification)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("verification failure"));
        let config = read_target_config(&options.target_config).unwrap();
        assert_eq!(config.active, options.source);
        assert!(!options.destination.path.exists());
        let report: MigrationReport = read_json(&options.report).unwrap();
        assert_eq!(report.state, MigrationState::FailedPreCutover);

        let completed = migrate_storage(options.clone()).await.unwrap();
        assert_eq!(completed.state, MigrationState::Cutover);
        #[cfg(unix)]
        assert!(same_file_identity(
            completed.import_anchor_identity.as_ref().unwrap(),
            &file_identity(&options.destination.path).unwrap()
        ));
        assert_eq!(completed.attempts, 2);
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[tokio::test]
    async fn empty_tokenless_provenance_staging_is_restartable() {
        let (_directory, options) = fixture().await;
        let error = migrate_storage_inner(options.clone(), FailurePoint::AfterProvenanceDirectory)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("staging directory creation"));

        let interrupted: MigrationReport = read_json(&options.report).unwrap();
        let staging = provenance_staging_path(&interrupted.provenance_directory);
        assert!(!interrupted.provenance_directory.exists());
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);

        let completed = migrate_storage(options).await.unwrap();
        assert_eq!(completed.state, MigrationState::Cutover);
        assert!(completed.provenance_directory.join("owner.json").is_file());
        assert!(!staging.exists());
    }

    #[test]
    fn completed_cutover_can_roll_back_within_the_window() {
        std::thread::Builder::new()
            .name("completed-cutover-rollback-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(completed_cutover_can_roll_back_within_the_window_body());
            })
            .unwrap()
            .join()
            .expect("completed cutover rollback test thread must not panic");
    }

    async fn completed_cutover_can_roll_back_within_the_window_body() {
        let (_directory, options) = fixture().await;
        let completed = migrate_storage(options.clone()).await.unwrap();
        assert_eq!(completed.state, MigrationState::Cutover);
        let retained_source = completed
            .source_sealed_files
            .iter()
            .find(|file| file.path == options.source.path)
            .unwrap();
        assert_eq!(
            retained_source.identity,
            file_identity(&options.source.path).unwrap(),
            "the durable rollback identity must be captured after the final SQLite lease closes"
        );
        assert_eq!(
            read_target_config(&options.target_config).unwrap().active,
            options.destination
        );
        assert_eq!(
            resolve_runtime_target(&options.target_config).unwrap(),
            fs::canonicalize(&options.destination.path).unwrap()
        );

        let rolled_back = rollback_storage(&options.report).await.unwrap();
        assert_eq!(rolled_back.state, MigrationState::RolledBack);
        assert_eq!(
            read_target_config(&options.target_config).unwrap().active,
            options.source
        );
    }

    #[cfg(all(unix, feature = "storage-recovery-tests"))]
    #[test]
    fn rollback_restarts_after_destination_seal_before_config_switch() {
        std::thread::Builder::new()
            .name("rollback-after-destination-seal-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(rollback_restarts_after_destination_seal_before_config_switch_body());
            })
            .unwrap()
            .join()
            .expect("rollback after destination seal test thread must not panic");
    }

    #[cfg(all(unix, feature = "storage-recovery-tests"))]
    async fn rollback_restarts_after_destination_seal_before_config_switch_body() {
        let (_directory, options) = fixture().await;
        migrate_storage(options.clone()).await.unwrap();

        let error =
            rollback_storage_inner(&options.report, RollbackFailurePoint::AfterDestinationSeal)
                .await
                .unwrap_err();
        assert!(error.to_string().contains("injected rollback interruption"));
        assert_eq!(
            read_target_config(&options.target_config).unwrap().active,
            options.destination
        );
        let interrupted: MigrationReport = read_json(&options.report).unwrap();
        assert_eq!(interrupted.state, MigrationState::RecoveryRequired);
        assert_eq!(
            interrupted.failure_stage.as_deref(),
            Some("rollback_prepared")
        );
        assert_current_sqlite_file_set_is_sealed(
            &options.destination.path,
            &interrupted.destination_sealed_files,
        );

        let completed = rollback_storage(&options.report).await.unwrap();
        assert_eq!(completed.state, MigrationState::RolledBack);
        assert_eq!(
            read_target_config(&options.target_config).unwrap().active,
            options.source
        );
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[test]
    fn rollback_finalizes_after_config_switch_even_past_deadline() {
        std::thread::Builder::new()
            .name("rollback-after-config-switch-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(rollback_finalizes_after_config_switch_even_past_deadline_body());
            })
            .unwrap()
            .join()
            .expect("rollback after config switch test thread must not panic");
    }

    #[cfg(feature = "storage-recovery-tests")]
    async fn rollback_finalizes_after_config_switch_even_past_deadline_body() {
        let (_directory, options) = fixture().await;
        migrate_storage(options.clone()).await.unwrap();

        let error =
            rollback_storage_inner(&options.report, RollbackFailurePoint::AfterConfigSwitch)
                .await
                .unwrap_err();
        assert!(error.to_string().contains("after target config switch"));
        assert_eq!(
            read_target_config(&options.target_config).unwrap().active,
            options.source
        );
        let mut interrupted: MigrationReport = read_json(&options.report).unwrap();
        interrupted.rollback_deadline = Some(
            (Utc::now() - chrono::Duration::seconds(1))
                .to_rfc3339_opts(SecondsFormat::Millis, true),
        );
        atomic_json(&options.report, &interrupted).unwrap();

        let recovered = rollback_storage(&options.report).await.unwrap();
        assert_eq!(recovered.state, MigrationState::RolledBack);
    }

    #[cfg(all(unix, feature = "storage-recovery-tests"))]
    #[tokio::test]
    async fn destination_restore_failure_reseals_source_and_is_durable() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_directory, options) = fixture().await;
        migrate_storage(options.clone()).await.unwrap();
        let mut report: MigrationReport = read_json(&options.report).unwrap();
        report.destination_sealed_files =
            inventory_sqlite_files(&options.destination.path).unwrap();
        atomic_json(&options.report, &report).unwrap();
        let mut destination = OpenOptions::new()
            .append(true)
            .open(&options.destination.path)
            .unwrap();
        std::io::Write::write_all(&mut destination, b"replaced-after-inventory").unwrap();

        let error = rollback_storage(&options.report).await.unwrap_err();
        assert!(error.to_string().contains("replaced SQLite file"));
        let persisted: MigrationReport = read_json(&options.report).unwrap();
        assert_eq!(
            persisted.failure_stage.as_deref(),
            Some("rollback_destination_restore")
        );
        assert_eq!(
            fs::metadata(&options.source.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o222,
            0
        );
        assert_ne!(
            fs::metadata(&options.destination.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o222,
            0
        );
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[test]
    fn strict_portability_migration_and_rollback_admit_guarded_conformance() {
        std::thread::Builder::new()
            .name("strict-portability-migration-rollback-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(
                        strict_portability_migration_and_rollback_admit_guarded_conformance_body(),
                    );
            })
            .unwrap()
            .join()
            .expect("strict portability migration rollback test thread must not panic");
    }

    #[cfg(feature = "storage-recovery-tests")]
    async fn strict_portability_migration_and_rollback_admit_guarded_conformance_body() {
        let (_directory, options) = fixture().await;
        let source = open_existing_database_at(&options.source.path)
            .await
            .unwrap();
        crate::storage_profile::update_portability_policy(
            &source,
            crate::storage_profile::PortabilityPolicyUpdate {
                if_policy_revision: 0,
                enforcement: crate::storage_profile::PortabilityEnforcement::Strict,
                target_profiles: vec![crate::storage_profile::StorageTarget {
                    id: "postgres-server".into(),
                    revision: 2,
                    mode: "network".into(),
                }],
                allow_conversions: vec![],
            },
        )
        .await
        .unwrap();
        source.close().await;

        migrate_storage(options.clone()).await.unwrap();
        let rolled_back = rollback_storage(&options.report).await.unwrap();
        assert_eq!(rolled_back.state, MigrationState::RolledBack);
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[test]
    fn rollback_refreshes_wal_sidecars_while_both_targets_are_fenced() {
        std::thread::Builder::new()
            .name("rollback-refresh-wal-sidecars-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(rollback_refreshes_wal_sidecars_while_both_targets_are_fenced_body());
            })
            .unwrap()
            .join()
            .expect("rollback WAL sidecar refresh test thread must not panic");
    }

    #[cfg(feature = "storage-recovery-tests")]
    async fn rollback_refreshes_wal_sidecars_while_both_targets_are_fenced_body() {
        let (_directory, options) = fixture().await;
        migrate_storage(options.clone()).await.unwrap();
        let live_destination = open_live_wal_database(&options.destination.path).await;

        let rolled_back = rollback_storage(&options.report).await.unwrap();
        assert_eq!(rolled_back.state, MigrationState::RolledBack);
        assert_current_sqlite_file_set_is_sealed(
            &options.destination.path,
            &rolled_back.destination_sealed_files,
        );
        live_destination.close().await;
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[tokio::test]
    async fn interrupted_cutover_recovery_reverifies_and_finalizes() {
        let (_directory, options) = fixture().await;
        migrate_storage(options.clone()).await.unwrap();
        let mut report: MigrationReport = read_json(&options.report).unwrap();
        report.state = MigrationState::Verified;
        report.source_sealed_at = None;
        atomic_json(&options.report, &report).unwrap();

        let recovered = migrate_storage(options).await.unwrap();
        assert_eq!(recovered.state, MigrationState::Cutover);
        assert!(recovered.source_sealed_at.is_some());
    }

    #[test]
    fn rollback_refuses_to_discard_post_cutover_destination_writes() {
        std::thread::Builder::new()
            .name("rollback-post-cutover-writes-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(rollback_refuses_to_discard_post_cutover_destination_writes_body());
            })
            .unwrap()
            .join()
            .expect("post-cutover destination-write rollback test thread must not panic");
    }

    async fn rollback_refuses_to_discard_post_cutover_destination_writes_body() {
        let (_directory, options) = fixture().await;
        migrate_storage(options.clone()).await.unwrap();
        let destination = open_existing_database_at(&options.destination.path)
            .await
            .unwrap();
        crate::store::create_record(
            &destination,
            serde_json::json!({
                "id": "5706a000-0000-4000-8000-000000000001",
                "type": "WorkItem",
                "kind": "task",
                "name": "Must not be discarded"
            }),
        )
        .await
        .unwrap();
        destination.close().await;

        let error = rollback_storage(&options.report).await.unwrap_err();
        let error = error.to_string();
        // SQLite may checkpoint the committed write from WAL into the main
        // database while rollback is preparing its fence. Either the raw file
        // identity check or the later canonical comparison must refuse it.
        let expected_failure_stage = if error.contains("refusing to restore replaced SQLite file") {
            "rollback_destination_restore"
        } else if error.contains("active destination changed after cutover") {
            "rollback_fenced_verification"
        } else {
            panic!("unexpected rollback refusal: {error}");
        };
        let persisted: MigrationReport = read_json(&options.report).unwrap();
        assert_eq!(persisted.state, MigrationState::RecoveryRequired);
        assert_eq!(
            persisted.failure_stage.as_deref(),
            Some(expected_failure_stage)
        );
        assert_eq!(persisted.error.as_deref(), Some(error.as_str()));
        assert_eq!(
            read_target_config(&options.target_config).unwrap().active,
            options.destination
        );
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[test]
    fn failed_interrupted_cutover_recovery_is_durably_recovery_required() {
        // The combined all-features build makes the two storage-operation
        // futures large enough to exhaust libtest's default worker stack.
        // Keep the production futures unchanged and give this exhaustive
        // interruption proof the same explicit stack boundary used by the
        // other large async state-machine tests in this crate.
        std::thread::Builder::new()
            .name("interrupted-cutover-recovery-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(failed_interrupted_cutover_recovery_body());
            })
            .unwrap()
            .join()
            .expect("interrupted cutover recovery test thread must not panic");
    }

    #[cfg(feature = "storage-recovery-tests")]
    async fn failed_interrupted_cutover_recovery_body() {
        let (_directory, options) = fixture().await;
        migrate_storage(options.clone()).await.unwrap();
        let destination = open_existing_database_at(&options.destination.path)
            .await
            .unwrap();
        crate::store::create_record(
            &destination,
            serde_json::json!({
                "id": "5706a000-0000-4000-8000-000000000002",
                "type": "WorkItem",
                "kind": "task",
                "name": "Recovery must notice"
            }),
        )
        .await
        .unwrap();
        destination.close().await;
        let mut report: MigrationReport = read_json(&options.report).unwrap();
        report.state = MigrationState::Verified;
        atomic_json(&options.report, &report).unwrap();

        migrate_storage(options.clone()).await.unwrap_err();
        let persisted: MigrationReport = read_json(&options.report).unwrap();
        assert_eq!(persisted.state, MigrationState::RecoveryRequired);
        assert_eq!(
            persisted.failure_stage.as_deref(),
            Some("interrupted_cutover_reverification")
        );
        let rollback_error = rollback_storage(&options.report).await.unwrap_err();
        assert!(rollback_error
            .to_string()
            .contains("active destination changed after cutover"));
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[tokio::test]
    async fn rollback_refuses_a_copied_split_journal() {
        let (directory, options) = fixture().await;
        migrate_storage(options.clone()).await.unwrap();
        let copied = directory.path().join("copied-report.json");
        fs::copy(&options.report, &copied).unwrap();

        let error = rollback_storage(&copied).await.unwrap_err();
        assert!(error.to_string().contains("copied or split journals"));
        assert_eq!(
            read_target_config(&options.target_config).unwrap().active,
            options.destination
        );
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[tokio::test]
    async fn completed_report_refuses_a_destination_switch_from_another_run() {
        let (_directory, options) = fixture().await;
        let completed = migrate_storage(options.clone()).await.unwrap();
        let mut config = read_target_config(&options.target_config).unwrap();
        config.migration_run_id = Some("different-run".into());
        atomic_json(&options.target_config, &config).unwrap();

        let error = migrate_storage(options).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("does not identify migration run"));
        assert_eq!(completed.state, MigrationState::Cutover);
    }

    #[cfg(feature = "storage-recovery-tests")]
    #[tokio::test]
    async fn recovery_required_is_terminal_for_run_and_preserves_paths() {
        let (_directory, options) = fixture().await;
        migrate_storage_inner(options.clone(), FailurePoint::BeforeVerification)
            .await
            .unwrap_err();
        let mut report: MigrationReport = read_json(&options.report).unwrap();
        report.state = MigrationState::RecoveryRequired;
        atomic_json(&options.report, &report).unwrap();
        fs::write(&options.destination.path, b"foreign").unwrap();

        let error = migrate_storage(options.clone()).await.unwrap_err();
        assert!(error.to_string().contains("recovery-required"));
        assert_eq!(fs::read(&options.destination.path).unwrap(), b"foreign");
    }

    #[cfg(all(unix, feature = "storage-recovery-tests"))]
    #[tokio::test]
    async fn cleanup_preserves_the_database_when_any_sidecar_is_non_regular() {
        use std::os::unix::fs::symlink;

        let (directory, options) = fixture().await;
        migrate_storage_inner(options.clone(), FailurePoint::BeforeVerification)
            .await
            .unwrap_err();
        let source = open_existing_database_at(&options.source.path)
            .await
            .unwrap();
        let canonical = export_canonical_interchange(&source).await.unwrap();
        source.close().await;
        let destination = import_canonical_interchange(&canonical, &options.destination.path)
            .await
            .unwrap();
        destination.close().await;
        let malicious_sidecar =
            PathBuf::from(format!("{}-wal", options.destination.path.display()));
        let _ = fs::remove_file(&malicious_sidecar);
        symlink(directory.path().join("not-a-wal"), &malicious_sidecar).unwrap();
        let report: MigrationReport = read_json(&options.report).unwrap();

        let error = remove_unpublished_destination(&report).await.unwrap_err();
        assert!(
            error.to_string().contains("preserving") || error.to_string().contains("non-regular")
        );
        assert!(options.destination.path.exists());
    }

    #[test]
    fn lease_name_appends_instead_of_replacing_the_report_extension() {
        assert_eq!(
            lease_path(Path::new("migration.report.json")),
            PathBuf::from("migration.report.json.lease")
        );
    }

    #[test]
    fn unsupported_routes_fail_closed() {
        let postgres = StorageTarget {
            profile_id: "postgres-server".into(),
            profile_revision: 2,
            path: "unused".into(),
        };
        let sqlite = StorageTarget::sqlite_local("unused");
        let error = reject_unsupported_route(&sqlite, &postgres).unwrap_err();
        assert!(error.to_string().contains("partial"));
    }

    #[test]
    fn cross_device_publication_is_rejected_without_copy_fallback() {
        let error = ensure_compatible_device(
            "report/provenance parent",
            11,
            "destination publication parent",
            22,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cross-filesystem"));
        assert!(error.to_string().contains("never falls back to copying"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cross_device_preflight_fails_before_report_or_destination_creation() {
        use std::os::unix::fs::MetadataExt as _;

        let Ok(destination_directory) = tempfile::tempdir_in("/dev/shm") else {
            return;
        };
        let (_source_directory, mut options) = fixture().await;
        if fs::metadata(destination_directory.path()).unwrap().dev()
            == fs::metadata(options.report.parent().unwrap())
                .unwrap()
                .dev()
        {
            return;
        }
        options.destination.path = destination_directory.path().join("destination.db");

        let error = migrate_storage(options.clone()).await.unwrap_err();
        assert!(error.to_string().contains("cross-filesystem"));
        assert!(!options.report.exists());
        assert!(!options.destination.path.exists());
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn migration_route_fails_before_creating_a_target_config() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("target.json");
        let error =
            initialize_target_config(&config, &directory.path().join("source.db")).unwrap_err();
        assert!(error.to_string().contains("Unix-only"));
        assert!(!config.exists());
    }
}
