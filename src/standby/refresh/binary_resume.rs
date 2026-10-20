//! Durable private snapshot-continuation custody helpers.
//!
//! Helpers only: they persist and validate a bound partial download across
//! restarts. They never authorize reuse, admit, or serve anything. A future
//! coordinator must perform an authenticated server owner-bound re-poll and
//! succeed before reusing any cached range, even when fully cached, then
//! enforce the whole-file digest plus full `install_staged` admission.
//!
//! No bearer is persisted here and no token is parsed.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
#[cfg(not(unix))]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::transfer_repr::{ReadyTransferIdentity, SnapshotTransfer};
use crate::error::{Error, Result};
use crate::standby_snapshot::{StandbyConsumerIdentity, StandbySnapshotManifest};

/// Fully downloaded range unit: 1 MiB, matching the binary transport.
pub const RESUME_CHUNK_BYTES: u64 = 1024 * 1024;
/// Bounded resume JSON read: fixed private file, never JSON-controlled.
///
/// 2 MiB covers the 8192-entry ledger (8 GiB at 1 MiB per range) plus the
/// ready manifest with headroom; I/O stays bounded via pre-read length
/// checks and `take(limit + 1)`.
pub const MAX_RESUME_JSON_BYTES: u64 = 2 * 1024 * 1024;
/// Ledger entry cap: 8192 ranges cover up to 8 GiB at 1 MiB each.
pub const MAX_COMPLETED_RANGES: usize = 8192;

const RESUME_CONTRACT: &str = "native.standby-binary-resume.v1";
const ENCODED_RESUME_CONTRACT: &str = "native.standby-binary-resume.v2";
const RESUME_VERSION: u32 = 1;
const PENDING_CONTRACT: &str = "native.standby-binary-pending.v1";
const PENDING_VERSION: u32 = 1;
const RESUME_JSON_NAME: &str = "binary-resume.json";
const RESUME_TMP_NAME: &str = "binary-resume.json.tmp";
const PENDING_JSON_NAME: &str = "binary-pending.json";
const PENDING_TMP_NAME: &str = "binary-pending.json.tmp";
const PARTIAL_NAME: &str = "binary-resume.partial.db";

/// One fully downloaded, fsynced range with its per-range sha256 hex.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedRange {
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

/// Versioned closed resume ledger bound to origin/route/consumer/export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeLedger {
    pub contract: String,
    pub version: u32,
    pub origin: String,
    pub hosted_route_database_id: String,
    pub origin_database_id: String,
    pub consumer: StandbyConsumerIdentity,
    pub export_handle: String,
    pub size_bytes: u64,
    pub sha256: String,
    /// Absent only for the known decoded-range v1 contract. Gzip always
    /// persists its independent wire identity in this same atomic record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoded: Option<EncodedResume>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<StandbySnapshotManifest>,
    #[serde(default)]
    pub completed: Vec<CompletedRange>,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncodedResume {
    pub route_api: String,
    pub transfer: SnapshotTransfer,
    pub size_bytes: u64,
    pub sha256: String,
}

impl ResumeLedger {
    pub fn set_encoded(&mut self, encoded: EncodedResume) {
        self.contract = ENCODED_RESUME_CONTRACT.into();
        self.encoded = Some(encoded);
    }
    pub fn transfer(&self) -> SnapshotTransfer {
        self.encoded
            .as_ref()
            .map_or(SnapshotTransfer::IdentityV1, |encoded| encoded.transfer)
    }
    pub fn range_size(&self) -> u64 {
        self.encoded
            .as_ref()
            .map_or(self.size_bytes, |encoded| encoded.size_bytes)
    }
    pub fn range_sha(&self) -> &str {
        self.encoded
            .as_ref()
            .map_or(&self.sha256, |encoded| &encoded.sha256)
    }
    pub fn ready_identity(&self) -> Result<ReadyTransferIdentity> {
        validate_ledger_structure(self)?;
        let manifest = self
            .manifest
            .clone()
            .ok_or_else(|| Error::engine("standby resume manifest is missing"))?;
        let identity = if let Some(encoded) = &self.encoded {
            encoded.transfer.validate()?;
            if encoded.transfer != (SnapshotTransfer::GzipV1 { level: 1 })
                || encoded.route_api != encoded.transfer.route_api()
            {
                return Err(Error::engine(
                    "standby resume encoded representation mismatch",
                ));
            }
            ReadyTransferIdentity::from_gzip_poll(
                self.export_handle.clone(),
                manifest,
                self.size_bytes,
                self.sha256.clone(),
                encoded.size_bytes,
                encoded.sha256.clone(),
                &self.hosted_route_database_id,
                &self.origin_database_id,
                &self.consumer,
            )?
        } else {
            ReadyTransferIdentity::from_identity_poll(
                self.export_handle.clone(),
                manifest,
                self.size_bytes,
                self.sha256.clone(),
                &self.hosted_route_database_id,
                &self.origin_database_id,
                &self.consumer,
            )?
        };
        identity.check_completed_ranges(&self.completed)?;
        Ok(identity)
    }
}

/// Current runtime binding a stored ledger must exactly match.
#[derive(Clone, Debug)]
pub struct ResumeBinding {
    pub origin: String,
    pub hosted_route_database_id: String,
    pub origin_database_id: String,
    pub consumer: StandbyConsumerIdentity,
}

/// Pre-ready capture identity, persisted immediately after `start` and
/// before the first poll. It carries no size, digest, or manifest: those
/// arrive with the first Ready poll and upgrade this record into a
/// [`ResumeLedger`]. Expiry stays sliding server-side; the poll is the
/// liveness oracle, never the stored timestamp.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingCapture {
    pub contract: String,
    pub version: u32,
    pub origin: String,
    pub hosted_route_database_id: String,
    pub origin_database_id: String,
    pub consumer: StandbyConsumerIdentity,
    pub export_handle: String,
    pub started_at: String,
}

fn resume_json_path(dir: &Path) -> PathBuf {
    dir.join(RESUME_JSON_NAME)
}

fn resume_tmp_path(dir: &Path) -> PathBuf {
    dir.join(RESUME_TMP_NAME)
}

fn partial_path(dir: &Path) -> PathBuf {
    dir.join(PARTIAL_NAME)
}

fn pending_json_path(dir: &Path) -> PathBuf {
    dir.join(PENDING_JSON_NAME)
}

fn pending_tmp_path(dir: &Path) -> PathBuf {
    dir.join(PENDING_TMP_NAME)
}

pub(super) fn validate_pending_structure(pending: &PendingCapture) -> Result<()> {
    if pending.contract != PENDING_CONTRACT || pending.version != PENDING_VERSION {
        return Err(Error::engine("unknown standby pending contract"));
    }
    super::validate_exact_origin(&pending.origin)?;
    if pending.hosted_route_database_id.trim().is_empty()
        || pending.hosted_route_database_id.len() > 256
        || !crate::identity::is_database_id(&pending.origin_database_id)
    {
        return Err(Error::engine(
            "standby pending database identity is invalid",
        ));
    }
    pending.consumer.validate_declaration()?;
    if uuid::Uuid::parse_str(&pending.export_handle).is_err() {
        return Err(Error::engine("standby pending export handle is invalid"));
    }
    if chrono::DateTime::parse_from_rfc3339(&pending.started_at).is_err()
        || pending.started_at.len() > 40
    {
        return Err(Error::engine("standby pending timestamp is invalid"));
    }
    Ok(())
}

pub(super) fn validate_pending_binding(
    pending: &PendingCapture,
    binding: &ResumeBinding,
) -> Result<()> {
    validate_pending_structure(pending)?;
    check_binding_fields(
        &pending.origin,
        &pending.hosted_route_database_id,
        &pending.origin_database_id,
        &pending.consumer,
        binding,
    )
}

/// Build a pending capture from the current binding and a fresh handle.
pub fn pending_capture(
    binding: &ResumeBinding,
    export_handle: String,
    started_at: String,
) -> PendingCapture {
    PendingCapture {
        contract: PENDING_CONTRACT.into(),
        version: PENDING_VERSION,
        origin: binding.origin.clone(),
        hosted_route_database_id: binding.hosted_route_database_id.clone(),
        origin_database_id: binding.origin_database_id.clone(),
        consumer: binding.consumer.clone(),
        export_handle,
        started_at,
    }
}

/// Write a legacy pending capture for compatibility fixtures.
#[cfg(test)]
pub fn save_pending_capture(dir: &Path, pending: &PendingCapture) -> Result<()> {
    validate_pending_structure(pending)?;
    let bytes = serde_json::to_vec(pending)?;
    if bytes.len() as u64 > MAX_RESUME_JSON_BYTES {
        return Err(Error::engine("standby pending capture exceeds its bound"));
    }
    write_fixed_json(dir, &pending_tmp_path(dir), &pending_json_path(dir), &bytes)
}

/// Load and bind-check a pending capture. `Ok(None)` means no pending file.
/// Any `Err` means the caller must discard and take the fresh path.
pub fn load_pending_capture(dir: &Path, binding: &ResumeBinding) -> Result<Option<PendingCapture>> {
    let path = pending_json_path(dir);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(
            "standby resume path is not a regular non-symlink file",
        ));
    }
    if metadata.len() > MAX_RESUME_JSON_BYTES {
        return Err(Error::engine("standby pending capture exceeds its bound"));
    }
    require_private_regular(&path)?;
    let file = open_existing_private(&path, true, false)?;
    if file.metadata()?.len() > MAX_RESUME_JSON_BYTES {
        return Err(Error::engine("standby pending capture exceeds its bound"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RESUME_JSON_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESUME_JSON_BYTES {
        return Err(Error::engine("standby pending capture exceeds its bound"));
    }
    let pending: PendingCapture = serde_json::from_slice(&bytes)
        .map_err(|_| Error::engine("standby pending capture is invalid"))?;
    validate_pending_structure(&pending)?;
    check_binding_fields(
        &pending.origin,
        &pending.hosted_route_database_id,
        &pending.origin_database_id,
        &pending.consumer,
        binding,
    )?;
    Ok(Some(pending))
}

/// Build a ready ledger for a freshly adopted export. Used by the
/// coordinator after the Ready poll and by tests seeding custody state.
pub fn new_ready_ledger(
    binding: &ResumeBinding,
    export_handle: String,
    size: u64,
    sha256: String,
    manifest: StandbySnapshotManifest,
    updated_at: String,
) -> ResumeLedger {
    ResumeLedger {
        contract: RESUME_CONTRACT.into(),
        version: RESUME_VERSION,
        origin: binding.origin.clone(),
        hosted_route_database_id: binding.hosted_route_database_id.clone(),
        origin_database_id: binding.origin_database_id.clone(),
        consumer: binding.consumer.clone(),
        export_handle,
        size_bytes: size,
        sha256,
        encoded: None,
        manifest: Some(manifest),
        completed: Vec::new(),
        updated_at,
    }
}

/// Upgrade a pending capture into a ready ledger once the Ready poll
/// delivers size, digest, and manifest. The manifest binding is checked
/// against the pending record, not just the live runtime.
pub fn ready_ledger_from_pending(
    pending: &PendingCapture,
    manifest: StandbySnapshotManifest,
    size: u64,
    sha256: String,
    updated_at: String,
) -> Result<ResumeLedger> {
    if size == 0
        || size > MAX_COMPLETED_RANGES as u64 * RESUME_CHUNK_BYTES
        || !is_lower_hex(&sha256, 64)
    {
        return Err(Error::engine("standby resume byte identity is invalid"));
    }
    if manifest.hosted_route_database_id != pending.hosted_route_database_id
        || manifest.origin_database_id != pending.origin_database_id
        || manifest.consumer != pending.consumer
        || manifest.snapshot.size_bytes != size
        || manifest.snapshot.sha256 != sha256
    {
        return Err(Error::engine("standby resume manifest identity mismatch"));
    }
    let ledger = new_ready_ledger(
        &ResumeBinding {
            origin: pending.origin.clone(),
            hosted_route_database_id: pending.hosted_route_database_id.clone(),
            origin_database_id: pending.origin_database_id.clone(),
            consumer: pending.consumer.clone(),
        },
        pending.export_handle.clone(),
        size,
        sha256,
        manifest,
        updated_at,
    );
    validate_ledger_structure(&ledger)?;
    Ok(ledger)
}

/// Refuse reuse when the Ready poll disagrees with the saved ready
/// identity: size, digest, and manifest binding must all match.
pub fn check_ready_against_poll(
    ledger: &ResumeLedger,
    manifest: &StandbySnapshotManifest,
    size: u64,
    sha256: &str,
) -> Result<()> {
    if ledger.manifest.as_ref() != Some(manifest)
        || ledger.size_bytes != size
        || ledger.sha256 != sha256
        || manifest.snapshot.size_bytes != size
        || manifest.snapshot.sha256 != sha256
        || manifest.hosted_route_database_id != ledger.hosted_route_database_id
        || manifest.origin_database_id != ledger.origin_database_id
        || manifest.consumer != ledger.consumer
    {
        return Err(Error::engine("standby resume manifest identity mismatch"));
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_private_regular(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(
            "standby resume path is not a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::engine("standby resume file is not private"));
        }
    }
    Ok(metadata)
}

/// Verify an opened descriptor matches its path: regular non-symlink,
/// private mode, single link, same device/inode (catches races).
pub(super) fn verify_opened_private(path: &Path, file: &fs::File) -> Result<fs::Metadata> {
    let opened = file.metadata()?;
    let at_path = fs::symlink_metadata(path)?;
    if at_path.file_type().is_symlink() || !at_path.is_file() || !opened.is_file() {
        return Err(Error::engine(
            "standby resume path is not a regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if opened.permissions().mode() & 0o077 != 0 || at_path.permissions().mode() & 0o077 != 0 {
            return Err(Error::engine("standby resume file is not private"));
        }
        if opened.nlink() != 1 || at_path.nlink() != 1 {
            return Err(Error::engine("standby resume file is linked"));
        }
        if opened.dev() != at_path.dev() || opened.ino() != at_path.ino() {
            return Err(Error::engine("standby resume file changed during open"));
        }
    }
    Ok(opened)
}

pub(super) fn open_options_nofollow(read: bool, write: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(read).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
        options.mode(0o600);
    }
    options
}

pub(super) fn open_existing_private(path: &Path, read: bool, write: bool) -> Result<fs::File> {
    let file = open_options_nofollow(read, write).open(path)?;
    verify_opened_private(path, &file)?;
    Ok(file)
}

fn validate_ledger_structure(ledger: &ResumeLedger) -> Result<()> {
    if ledger.version != RESUME_VERSION
        || match ledger.contract.as_str() {
            RESUME_CONTRACT => ledger.encoded.is_some(),
            ENCODED_RESUME_CONTRACT => ledger.encoded.is_none(),
            _ => true,
        }
    {
        return Err(Error::engine("unknown standby resume contract"));
    }
    super::validate_exact_origin(&ledger.origin)?;
    if ledger.hosted_route_database_id.trim().is_empty()
        || ledger.hosted_route_database_id.len() > 256
        || !crate::identity::is_database_id(&ledger.origin_database_id)
    {
        return Err(Error::engine("standby resume database identity is invalid"));
    }
    ledger.consumer.validate_declaration()?;
    if uuid::Uuid::parse_str(&ledger.export_handle).is_err() {
        return Err(Error::engine("standby resume export handle is invalid"));
    }
    if ledger.size_bytes == 0
        || ledger.size_bytes > MAX_COMPLETED_RANGES as u64 * RESUME_CHUNK_BYTES
        || !is_lower_hex(&ledger.sha256, 64)
    {
        return Err(Error::engine("standby resume byte identity is invalid"));
    }
    if chrono::DateTime::parse_from_rfc3339(&ledger.updated_at).is_err()
        || ledger.updated_at.len() > 40
    {
        return Err(Error::engine("standby resume timestamp is invalid"));
    }
    if ledger.completed.len() > MAX_COMPLETED_RANGES {
        return Err(Error::engine("standby resume ledger exceeds its bound"));
    }
    if let Some(encoded) = &ledger.encoded {
        encoded.transfer.validate()?;
        if encoded.transfer != (SnapshotTransfer::GzipV1 { level: 1 })
            || encoded.route_api != encoded.transfer.route_api()
        {
            return Err(Error::engine(
                "standby resume encoded representation mismatch",
            ));
        }
        super::transfer_repr::check_byte_identity(encoded.size_bytes, &encoded.sha256, "encoded")?;
    }
    validate_completed_ranges(&ledger.completed, ledger.range_size())?;
    if let Some(manifest) = ledger.manifest.as_ref() {
        manifest.validate()?;
        if manifest.hosted_route_database_id != ledger.hosted_route_database_id
            || manifest.origin_database_id != ledger.origin_database_id
            || manifest.consumer != ledger.consumer
            || manifest.snapshot.size_bytes != ledger.size_bytes
            || manifest.snapshot.sha256 != ledger.sha256
        {
            return Err(Error::engine("standby resume manifest identity mismatch"));
        }
    }
    Ok(())
}

fn validate_completed_ranges(ranges: &[CompletedRange], size: u64) -> Result<()> {
    let mut prev_end = 0_u64;
    let mut first = true;
    for range in ranges {
        if range.length == 0 || range.length > RESUME_CHUNK_BYTES {
            return Err(Error::engine("standby resume range length is invalid"));
        }
        if range.offset % RESUME_CHUNK_BYTES != 0 {
            return Err(Error::engine("standby resume range is misaligned"));
        }
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or_else(|| Error::engine("standby resume range is out of bounds"))?;
        if end > size {
            return Err(Error::engine("standby resume range is out of bounds"));
        }
        let is_tail = end == size;
        if !is_tail && range.length != RESUME_CHUNK_BYTES {
            return Err(Error::engine("standby resume range length is invalid"));
        }
        if !is_lower_hex(&range.sha256, 64) {
            return Err(Error::engine("standby resume range hash is invalid"));
        }
        // Sorted strictly ascending and non-overlapping (neighbours suffice).
        if !first && range.offset < prev_end {
            return Err(Error::engine("standby resume ledger overlaps"));
        }
        prev_end = end;
        first = false;
    }
    Ok(())
}

fn check_binding_fields(
    origin: &str,
    route: &str,
    portable: &str,
    consumer: &StandbyConsumerIdentity,
    binding: &ResumeBinding,
) -> Result<()> {
    if origin != binding.origin
        || route != binding.hosted_route_database_id
        || portable != binding.origin_database_id
        || consumer != &binding.consumer
    {
        return Err(Error::engine("standby resume binding mismatch"));
    }
    Ok(())
}

fn check_binding(ledger: &ResumeLedger, binding: &ResumeBinding) -> Result<()> {
    check_binding_fields(
        &ledger.origin,
        &ledger.hosted_route_database_id,
        &ledger.origin_database_id,
        &ledger.consumer,
        binding,
    )
}

fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn set_private_mode(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// Atomically persist a validated ledger under the fixed private file name.
///
/// Never truncates through a symlink: any stale temp (including a symlink)
/// is unlinked first, then the temp is created with `create_new` plus
/// `O_NOFOLLOW` on Unix. The single-writer coordinator must serialize saves.
pub fn save_resume_ledger(dir: &Path, ledger: &ResumeLedger) -> Result<()> {
    validate_ledger_structure(ledger)?;
    let bytes = serde_json::to_vec(ledger)?;
    if bytes.len() as u64 > MAX_RESUME_JSON_BYTES {
        return Err(Error::engine("standby resume ledger exceeds its bound"));
    }
    write_fixed_json(dir, &resume_tmp_path(dir), &resume_json_path(dir), &bytes)
}

pub(super) fn write_fixed_json(dir: &Path, tmp: &Path, dest: &Path, bytes: &[u8]) -> Result<()> {
    write_fixed_json_with_observer(dir, tmp, dest, bytes, |_| {})
}

// Boundary observer permits deterministic substitution tests of the production
// publication sequence. Callers still require a private directory and one writer;
// these checks do not exclude arbitrary concurrent same-uid directory mutations.
fn write_fixed_json_with_observer(
    dir: &Path,
    tmp: &Path,
    dest: &Path,
    bytes: &[u8],
    mut observe: impl FnMut(&Path),
) -> Result<()> {
    match fs::symlink_metadata(tmp) {
        Ok(_) => fs::remove_file(tmp)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = open_options_nofollow(false, true);
    options.create_new(true);
    let mut file = options.open(tmp)?;
    verify_opened_private(tmp, &file)?;
    set_private_mode(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    observe(tmp);
    verify_opened_private(tmp, &file)?;
    fs::rename(tmp, dest)?;
    observe(dest);
    verify_opened_private(dest, &file)?;
    sync_dir(dir)?;
    verify_opened_private(dest, &file)?;
    Ok(())
}

/// Load and bind-check a ledger. `Ok(None)` means no resume file present.
/// Any `Err` means the caller must discard and take the fresh path.
pub fn load_resume_ledger(dir: &Path, binding: &ResumeBinding) -> Result<Option<ResumeLedger>> {
    let path = resume_json_path(dir);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(
            "standby resume path is not a regular non-symlink file",
        ));
    }
    if metadata.len() > MAX_RESUME_JSON_BYTES {
        return Err(Error::engine("standby resume ledger exceeds its bound"));
    }
    require_private_regular(&path)?;
    let file = open_existing_private(&path, true, false)?;
    let descriptor_len = file.metadata()?.len();
    if descriptor_len > MAX_RESUME_JSON_BYTES {
        return Err(Error::engine("standby resume ledger exceeds its bound"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RESUME_JSON_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESUME_JSON_BYTES {
        return Err(Error::engine("standby resume ledger exceeds its bound"));
    }
    let ledger: ResumeLedger = serde_json::from_slice(&bytes)
        .map_err(|_| Error::engine("standby resume ledger is invalid"))?;
    validate_ledger_structure(&ledger)?;
    check_binding(&ledger, binding)?;
    Ok(Some(ledger))
}

/// Remove fixed resume files. Missing files are not an error.
pub fn discard_resume(dir: &Path) -> Result<()> {
    for path in [
        resume_json_path(dir),
        resume_tmp_path(dir),
        pending_json_path(dir),
        pending_tmp_path(dir),
        partial_path(dir),
        dir.join("transfer-pending.json"),
        dir.join("transfer-pending.json.tmp"),
        dir.join("binary-decoded.stage.db"),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    sync_dir(dir)
}

/// Remove only the pending capture record, keeping a ready ledger.
pub fn discard_pending(dir: &Path) -> Result<()> {
    for path in [
        pending_json_path(dir),
        pending_tmp_path(dir),
        dir.join("transfer-pending.json"),
        dir.join("transfer-pending.json.tmp"),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    sync_dir(dir)
}

/// Create or validate the fixed pre-sized partial file for `size` bytes.
pub fn prepare_partial_file(dir: &Path, size: u64) -> Result<PathBuf> {
    prepare_partial_file_with_observer(dir, size, |_| {})
}

fn prepare_partial_file_with_observer(
    dir: &Path,
    size: u64,
    observe: impl FnOnce(&Path),
) -> Result<PathBuf> {
    if size == 0 || size > MAX_COMPLETED_RANGES as u64 * RESUME_CHUNK_BYTES {
        return Err(Error::engine("standby resume byte identity is invalid"));
    }
    let path = partial_path(dir);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            require_private_regular(&path)?;
            let file = open_existing_private(&path, true, false)?;
            if file.metadata()?.len() != size {
                return Err(Error::engine("standby resume partial size mismatch"));
            }
            observe(&path);
            verify_opened_private(&path, &file)?;
            Ok(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = open_options_nofollow(true, true);
            options.create_new(true);
            let file = options.open(&path)?;
            verify_opened_private(&path, &file)?;
            set_private_mode(&file)?;
            file.set_len(size)?;
            file.sync_all()?;
            observe(&path);
            verify_opened_private(&path, &file)?;
            sync_dir(dir)?;
            verify_opened_private(&path, &file)?;
            Ok(path)
        }
        Err(error) => Err(error.into()),
    }
}

/// Write one downloaded range at `offset`, fsync, and return its sha256 hex.
///
/// Each call opens its own descriptor. The serial coordinator fsyncs and
/// records one completed range before writing the next.
pub fn write_range_and_hash(dir: &Path, offset: u64, bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() || bytes.len() as u64 > RESUME_CHUNK_BYTES {
        return Err(Error::engine("standby resume range length is invalid"));
    }
    if !offset.is_multiple_of(RESUME_CHUNK_BYTES) {
        return Err(Error::engine("standby resume range is misaligned"));
    }
    let path = partial_path(dir);
    require_private_regular(&path)?;
    let file = open_existing_private(&path, true, true)?;
    let file_len = file.metadata()?.len();
    let end = offset
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| Error::engine("standby resume range is out of bounds"))?;
    if end > file_len {
        return Err(Error::engine("standby resume range is out of bounds"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt as _;
        let mut written = 0_usize;
        while written < bytes.len() {
            let count = file.write_at(&bytes[written..], offset + written as u64)?;
            if count == 0 {
                return Err(Error::engine("local standby refresh storage failed"));
            }
            written += count;
        }
    }
    #[cfg(not(unix))]
    {
        let mut file = file;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)?;
    }
    file.sync_all()?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

/// Re-hash every ledgered range against the partial file.
///
/// Returns the ledger trimmed to verified ranges. Corrupt ranges are dropped
/// for refetch; file-level faults (symlink, size mismatch, I/O) are `Err`.
pub fn revalidate_cached_ranges(dir: &Path, ledger: &ResumeLedger) -> Result<ResumeLedger> {
    validate_ledger_structure(ledger)?;
    let path = partial_path(dir);
    require_private_regular(&path)?;
    let file = open_existing_private(&path, true, false)?;
    if file.metadata()?.len() != ledger.range_size() {
        return Err(Error::engine("standby resume partial size mismatch"));
    }
    let mut verified = Vec::with_capacity(ledger.completed.len());
    for range in &ledger.completed {
        let mut buffer = vec![0_u8; range.length as usize];
        read_exact_at(&file, &mut buffer, range.offset)?;
        let mut digest = Sha256::new();
        digest.update(&buffer);
        if hex::encode(digest.finalize()) == range.sha256 {
            verified.push(range.clone());
        }
    }
    let mut trimmed = ledger.clone();
    trimmed.completed = verified;
    Ok(trimmed)
}

fn read_exact_at(file: &fs::File, buffer: &mut [u8], offset: u64) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt as _;
        let mut filled = 0_usize;
        while filled < buffer.len() {
            let count = file.read_at(&mut buffer[filled..], offset + filled as u64)?;
            if count == 0 {
                return Err(Error::engine("standby resume partial is truncated"));
            }
            filled += count;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut handle = file.try_clone()?;
        handle.seek(SeekFrom::Start(offset))?;
        handle.read_exact(buffer)?;
        Ok(())
    }
}

/// Guarded read handle over the fixed partial file after size validation.
pub fn open_partial_for_read(dir: &Path, size: u64) -> Result<fs::File> {
    let path = partial_path(dir);
    require_private_regular(&path)?;
    let file = open_existing_private(&path, true, false)?;
    if file.metadata()?.len() != size {
        return Err(Error::engine("standby resume partial size mismatch"));
    }
    Ok(file)
}

/// Gaps in `[0, size)` not yet ledgered, in ascending order.
pub fn missing_ranges(ledger: &ResumeLedger) -> Result<Vec<(u64, u64)>> {
    validate_ledger_structure(ledger)?;
    let mut gaps = Vec::new();
    let mut cursor = 0_u64;
    for range in &ledger.completed {
        if range.offset > cursor {
            gaps.push((cursor, range.offset - cursor));
        }
        cursor = range.offset + range.length;
    }
    if cursor < ledger.range_size() {
        gaps.push((cursor, ledger.range_size() - cursor));
    }
    Ok(gaps)
}

/// Insert one fsynced range into the ledger. The caller must have fsynced
/// the bytes and computed `sha256` before calling.
pub fn record_completed_range(
    ledger: &mut ResumeLedger,
    offset: u64,
    length: u64,
    sha256: String,
) -> Result<()> {
    let candidate = CompletedRange {
        offset,
        length,
        sha256,
    };
    let mut next = ledger.completed.clone();
    next.push(candidate);
    next.sort_by_key(|range| range.offset);
    validate_completed_ranges(&next, ledger.range_size())?;
    if next.len() > MAX_COMPLETED_RANGES {
        return Err(Error::engine("standby resume ledger exceeds its bound"));
    }
    ledger.completed = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standby_snapshot::{StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT};

    fn test_consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            engine_schema_version: 59,
            ddl_sha256: "c".repeat(64),
        }
    }

    fn test_binding() -> ResumeBinding {
        ResumeBinding {
            origin: "https://example.com".into(),
            hosted_route_database_id: "route-db-1".into(),
            origin_database_id: format!("ndb_{}", "d".repeat(32)),
            consumer: test_consumer(),
        }
    }

    fn test_ledger(size: u64) -> ResumeLedger {
        let binding = test_binding();
        ResumeLedger {
            contract: RESUME_CONTRACT.into(),
            version: 1,
            origin: binding.origin,
            hosted_route_database_id: binding.hosted_route_database_id,
            origin_database_id: binding.origin_database_id,
            consumer: binding.consumer,
            export_handle: "12345678-1234-1234-1234-1234567890ab".into(),
            size_bytes: size,
            sha256: "e".repeat(64),
            encoded: None,
            manifest: None,
            completed: Vec::new(),
            updated_at: "2026-10-16T00:00:00Z".into(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "binary-resume-{}-{}",
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn substitute_path(path: &Path, outside: &Path, symlink: bool) {
        // Preserve the opened inode with one link, so a regular substitution
        // must be caught by descriptor/path identity rather than link count.
        fs::rename(path, path.with_extension("displaced")).unwrap();
        if symlink {
            std::os::unix::fs::symlink(outside, path).unwrap();
        } else {
            let mut replacement = open_options_nofollow(false, true)
                .create_new(true)
                .open(path)
                .unwrap();
            replacement.write_all(b"substituted bytes").unwrap();
        }
    }

    #[cfg(unix)]
    fn outside_target(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let outside = dir.join("outside");
        fs::write(&outside, b"outside bytes").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o640)).unwrap();
        outside
    }

    #[cfg(unix)]
    fn assert_outside_untouched(outside: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(fs::read(outside).unwrap(), b"outside bytes");
        assert_eq!(
            fs::metadata(outside).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    #[cfg(unix)]
    fn json_publication_refuses_substitution_before_and_after_rename() {
        for after_rename in [false, true] {
            for symlink in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let outside = outside_target(root.path());
                let dir = root.path().join("custody");
                fs::create_dir(&dir).unwrap();
                let tmp = resume_tmp_path(&dir);
                let dest = resume_json_path(&dir);
                write_fixed_json(&dir, &tmp, &dest, b"previous bytes").unwrap();
                let mut observed = 0;
                let result =
                    write_fixed_json_with_observer(&dir, &tmp, &dest, b"new owned bytes", |path| {
                        observed += 1;
                        if (path == dest) == after_rename {
                            substitute_path(path, &outside, symlink);
                        }
                    });
                let error = result.unwrap_err().to_string();
                assert!(
                    error.contains(if symlink {
                        "non-symlink"
                    } else {
                        "changed during open"
                    }),
                    "{error}"
                );
                assert_eq!(observed, if after_rename { 2 } else { 1 });
                if !after_rename {
                    assert_eq!(fs::read(&dest).unwrap(), b"previous bytes");
                }
                assert_outside_untouched(&outside);
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn partial_preparation_refuses_new_and_existing_path_substitution() {
        for existing in [false, true] {
            for symlink in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let outside = outside_target(root.path());
                let dir = root.path().join("custody");
                fs::create_dir(&dir).unwrap();
                if existing {
                    prepare_partial_file(&dir, 17).unwrap();
                }
                let error = prepare_partial_file_with_observer(&dir, 17, |path| {
                    substitute_path(path, &outside, symlink);
                })
                .unwrap_err()
                .to_string();
                assert!(
                    error.contains(if symlink {
                        "non-symlink"
                    } else {
                        "changed during open"
                    }),
                    "{error}"
                );
                assert_outside_untouched(&outside);
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn private_open_refuses_public_modes_hardlinks_and_symlinks() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = prepare_partial_file(dir.path(), 17).unwrap();
        let file = open_existing_private(&path, true, true).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o640))
            .unwrap();
        assert!(open_existing_private(&path, true, true).is_err());
        assert!(verify_opened_private(&path, &file).is_err());
        assert!(prepare_partial_file(dir.path(), 17).is_err());
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        let alias = dir.path().join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(open_existing_private(&path, true, true).is_err());
        assert!(verify_opened_private(&path, &file).is_err());
        assert!(prepare_partial_file(dir.path(), 17).is_err());
        fs::remove_file(&alias).unwrap();
        fs::rename(&path, &alias).unwrap();
        std::os::unix::fs::symlink(&alias, &path).unwrap();
        assert!(open_existing_private(&path, true, true).is_err());
        assert!(verify_opened_private(&path, &file).is_err());
        assert_eq!(fs::metadata(&alias).unwrap().len(), 17);
        assert_eq!(
            fs::metadata(&alias).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(open_existing_private(dir.path(), true, false).is_err());
    }

    #[test]
    fn pending_and_ready_replacements_persist_owned_private_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let pending = test_pending();
        let mut ledger = test_ledger(RESUME_CHUNK_BYTES);
        for _ in 0..2 {
            save_pending_capture(dir.path(), &pending).unwrap();
            save_resume_ledger(dir.path(), &ledger).unwrap();
            assert_eq!(
                fs::read(pending_json_path(dir.path())).unwrap(),
                serde_json::to_vec(&pending).unwrap()
            );
            assert_eq!(
                fs::read(resume_json_path(dir.path())).unwrap(),
                serde_json::to_vec(&ledger).unwrap()
            );
            assert!(load_pending_capture(dir.path(), &test_binding())
                .unwrap()
                .is_some());
            assert_eq!(
                load_resume_ledger(dir.path(), &test_binding())
                    .unwrap()
                    .unwrap()
                    .size_bytes,
                ledger.size_bytes
            );
            for path in [pending_json_path(dir.path()), resume_json_path(dir.path())] {
                let file = open_existing_private(&path, true, false).unwrap();
                verify_opened_private(&path, &file).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
                }
            }
            ledger.size_bytes += 1;
        }
        assert!(!resume_tmp_path(dir.path()).exists());
        assert!(!pending_tmp_path(dir.path()).exists());
    }

    #[test]
    fn cleanup_propagates_directory_sync_failure_even_with_no_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-directory");
        // Every fixed unlink reports NotFound. The final directory sync must
        // still fail instead of returning successful durable cleanup.
        assert!(discard_resume(&missing).is_err());
        assert!(discard_pending(&missing).is_err());
    }

    #[test]
    fn roundtrip_preserves_valid_partial_across_restart() {
        let dir = temp_dir("roundtrip");
        let size = 2 * RESUME_CHUNK_BYTES + 17;
        let mut ledger = test_ledger(size);
        prepare_partial_file(&dir, size).unwrap();
        let first = vec![7_u8; RESUME_CHUNK_BYTES as usize];
        let hash = write_range_and_hash(&dir, 0, &first).unwrap();
        record_completed_range(&mut ledger, 0, first.len() as u64, hash).unwrap();
        save_resume_ledger(&dir, &ledger).unwrap();
        let binding = test_binding();
        let loaded = load_resume_ledger(&dir, &binding).unwrap().unwrap();
        assert_eq!(loaded.completed.len(), 1);
        let revalidated = revalidate_cached_ranges(&dir, &loaded).unwrap();
        assert_eq!(revalidated.completed.len(), 1);
        let gaps = missing_ranges(&revalidated).unwrap();
        assert_eq!(gaps, vec![(RESUME_CHUNK_BYTES, size - RESUME_CHUNK_BYTES)]);
    }

    #[test]
    fn rejects_mismatched_binding_and_malformed_ledger() {
        let dir = temp_dir("mismatch");
        let size = RESUME_CHUNK_BYTES;
        let ledger = test_ledger(size);
        prepare_partial_file(&dir, size).unwrap();
        save_resume_ledger(&dir, &ledger).unwrap();
        let mut wrong = test_binding();
        wrong.origin = "https://other.example".into();
        assert!(load_resume_ledger(&dir, &wrong).is_err());
        // Malformed JSON must not load.
        fs::write(resume_json_path(&dir), b"{not json").unwrap();
        let binding = test_binding();
        assert!(load_resume_ledger(&dir, &binding).is_err());
    }

    #[test]
    fn rejects_overlap_and_out_of_bounds_ranges() {
        let mut ledger = test_ledger(3 * RESUME_CHUNK_BYTES);
        let good = "f".repeat(64);
        record_completed_range(&mut ledger, 0, RESUME_CHUNK_BYTES, good.clone()).unwrap();
        // Duplicate offset overlaps.
        assert!(record_completed_range(&mut ledger, 0, RESUME_CHUNK_BYTES, good.clone()).is_err());
        // Out of bounds past size.
        assert!(
            record_completed_range(&mut ledger, 3 * RESUME_CHUNK_BYTES, 1, good.clone()).is_err()
        );
        // Misaligned offset.
        assert!(record_completed_range(&mut ledger, 7, RESUME_CHUNK_BYTES, good.clone()).is_err());
        // Non-tail short range.
        assert!(record_completed_range(&mut ledger, RESUME_CHUNK_BYTES, 3, good).is_err());
    }

    #[test]
    fn corrupt_range_is_dropped_truncated_and_symlink_rejected() {
        let dir = temp_dir("corrupt");
        let size = RESUME_CHUNK_BYTES;
        let mut ledger = test_ledger(size);
        prepare_partial_file(&dir, size).unwrap();
        let bytes = vec![9_u8; size as usize];
        let hash = write_range_and_hash(&dir, 0, &bytes).unwrap();
        record_completed_range(&mut ledger, 0, size, hash).unwrap();
        // Corrupt one byte; revalidation must drop the range, not fail.
        {
            let file = OpenOptions::new()
                .write(true)
                .open(partial_path(&dir))
                .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileExt as _;
                file.write_at(&[10_u8], 3).unwrap();
                file.sync_all().unwrap();
            }
        }
        let trimmed = revalidate_cached_ranges(&dir, &ledger).unwrap();
        assert!(trimmed.completed.is_empty());
        // Truncated partial is a file-level fault.
        let file = OpenOptions::new()
            .write(true)
            .open(partial_path(&dir))
            .unwrap();
        file.set_len(size - 1).unwrap();
        drop(file);
        assert!(revalidate_cached_ranges(&dir, &ledger).is_err());
        // Symlink partial is rejected.
        fs::remove_file(partial_path(&dir)).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/hostname", partial_path(&dir)).unwrap();
            assert!(revalidate_cached_ranges(&dir, &ledger).is_err());
        }
    }

    #[test]
    fn four_concurrent_range_writes_stay_disjoint() {
        let dir = temp_dir("concurrent");
        let size = 4 * RESUME_CHUNK_BYTES;
        prepare_partial_file(&dir, size).unwrap();
        let handles: Vec<_> = (0..4)
            .map(|index| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let offset = index * RESUME_CHUNK_BYTES;
                    let bytes = vec![index as u8 + 1; RESUME_CHUNK_BYTES as usize];
                    write_range_and_hash(&dir, offset, &bytes).unwrap()
                })
            })
            .collect();
        let mut hashes = Vec::new();
        for handle in handles {
            hashes.push(handle.join().unwrap());
        }
        let mut ledger = test_ledger(size);
        for (index, hash) in hashes.into_iter().enumerate() {
            let offset = index as u64 * RESUME_CHUNK_BYTES;
            record_completed_range(&mut ledger, offset, RESUME_CHUNK_BYTES, hash).unwrap();
        }
        let revalidated = revalidate_cached_ranges(&dir, &ledger).unwrap();
        assert_eq!(revalidated.completed.len(), 4);
        assert!(missing_ranges(&revalidated).unwrap().is_empty());
    }

    #[test]
    fn stale_tmp_symlink_is_unlinked_not_followed() {
        let dir = temp_dir("tmp-symlink");
        let outside = dir.join("outside.txt");
        fs::write(&outside, b"do not truncate").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, resume_tmp_path(&dir)).unwrap();
            let ledger = test_ledger(RESUME_CHUNK_BYTES);
            save_resume_ledger(&dir, &ledger).unwrap();
            // Target was never truncated through the symlink.
            assert_eq!(fs::read(&outside).unwrap(), b"do not truncate");
            assert!(fs::symlink_metadata(resume_tmp_path(&dir)).is_err());
            let binding = test_binding();
            let loaded = load_resume_ledger(&dir, &binding).unwrap().unwrap();
            assert_eq!(loaded.size_bytes, RESUME_CHUNK_BYTES);
        }
    }

    fn test_pending() -> PendingCapture {
        let binding = test_binding();
        PendingCapture {
            contract: PENDING_CONTRACT.into(),
            version: PENDING_VERSION,
            origin: binding.origin,
            hosted_route_database_id: binding.hosted_route_database_id,
            origin_database_id: binding.origin_database_id,
            consumer: binding.consumer,
            export_handle: "12345678-1234-1234-1234-1234567890ab".into(),
            started_at: "2026-10-16T00:00:00Z".into(),
        }
    }

    #[test]
    fn pending_capture_roundtrips_and_rejects_mismatch() {
        let dir = temp_dir("pending");
        assert!(load_pending_capture(&dir, &test_binding())
            .unwrap()
            .is_none());
        let pending = test_pending();
        save_pending_capture(&dir, &pending).unwrap();
        let loaded = load_pending_capture(&dir, &test_binding())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.export_handle, pending.export_handle);
        let mut wrong = test_binding();
        wrong.hosted_route_database_id = "route-other".into();
        assert!(load_pending_capture(&dir, &wrong).is_err());
        fs::write(pending_json_path(&dir), b"{not json").unwrap();
        assert!(load_pending_capture(&dir, &test_binding()).is_err());
    }

    #[test]
    fn pending_tmp_symlink_is_unlinked_not_followed() {
        let dir = temp_dir("pending-tmp-symlink");
        let outside = dir.join("outside.txt");
        fs::write(&outside, b"do not truncate").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, pending_tmp_path(&dir)).unwrap();
            save_pending_capture(&dir, &test_pending()).unwrap();
            assert_eq!(fs::read(&outside).unwrap(), b"do not truncate");
        }
    }

    #[test]
    fn discard_resume_clears_pending_and_ready_together() {
        let dir = temp_dir("discard-both");
        save_pending_capture(&dir, &test_pending()).unwrap();
        save_resume_ledger(&dir, &test_ledger(RESUME_CHUNK_BYTES)).unwrap();
        discard_resume(&dir).unwrap();
        assert!(load_pending_capture(&dir, &test_binding())
            .unwrap()
            .is_none());
        assert!(load_resume_ledger(&dir, &test_binding()).unwrap().is_none());
    }
}
