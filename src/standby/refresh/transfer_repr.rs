//! Closed transfer-representation custody for snapshot acquisition.
//!
//! Helpers only: they record WHICH representation a pending/ready handle
//! carries (identity-v1 vs gzip-v2) and keep encoded and decoded identities
//! distinct. They never authorize reuse, admit, or serve anything: reuse
//! still requires the mandatory current-authorized re-poll agreement (see
//! [`ReadyTransferIdentity::check_against_poll`]) plus full
//! `install_staged` admission, which is unchanged.
//!
//! Identity-v1 behavior is unchanged: its records carry no encoded fields,
//! and ranges address the decoded bytes exactly as before. Representations
//! are never guessed (no handle-prefix sniffing anywhere here); an unknown
//! or mismatched representation is a refusal, and refresh maps refusals
//! through its existing cooldown policy rather than retrying as another
//! representation.
//!

use std::fs;
use std::io::{BufRead as _, Read as _, Seek as _, Write as _};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::binary_resume::{
    open_existing_private, open_options_nofollow, verify_opened_private, write_fixed_json,
    CompletedRange, PendingCapture, MAX_COMPLETED_RANGES, RESUME_CHUNK_BYTES,
};
use crate::error::{Error, Result};
use crate::standby_snapshot::{StandbyConsumerIdentity, StandbySnapshotManifest};

/// Client-side copy of the v1 wire contract (mirrors `refresh/binary.rs`).
pub const IDENTITY_EXPORT_API: &str = "native.standby-snapshot-export.v1";
/// Client-side copy of the v2 wire contract (mirrors the hosted v2 routes).
pub const GZIP_EXPORT_API: &str = "native.standby-snapshot-export.v2";
/// The single gzip transfer the v2 contract implies.
pub const GZIP_TRANSFER_LEVEL: u32 = 1;

const PENDING_TRANSFER_CONTRACT: &str = "native.standby-transfer-pending.v1";
const PENDING_TRANSFER_VERSION: u32 = 1;
const PENDING_TRANSFER_JSON_NAME: &str = "transfer-pending.json";
const PENDING_TRANSFER_TMP_NAME: &str = "transfer-pending.json.tmp";
/// 8 KiB covers the small pending sidecar with wide headroom; reads stay
/// bounded via pre-read length checks and `take(limit + 1)`.
const MAX_PENDING_TRANSFER_JSON_BYTES: u64 = 8 * 1024;

/// Closed transfer representation set. Identity carries no encoded form;
/// gzip carries its level so a future level is a refusal, not a guess.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "encoding", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SnapshotTransfer {
    #[serde(rename = "identity")]
    IdentityV1,
    #[serde(rename = "gzip")]
    GzipV1 { level: u32 },
}

impl SnapshotTransfer {
    /// Exact wire contract that owns handles of this representation.
    pub fn route_api(self) -> &'static str {
        match self {
            SnapshotTransfer::IdentityV1 => IDENTITY_EXPORT_API,
            SnapshotTransfer::GzipV1 { .. } => GZIP_EXPORT_API,
        }
    }

    pub(super) fn validate(self) -> Result<()> {
        match self {
            SnapshotTransfer::IdentityV1 => Ok(()),
            SnapshotTransfer::GzipV1 { level } if level == GZIP_TRANSFER_LEVEL => Ok(()),
            SnapshotTransfer::GzipV1 { .. } => Err(Error::engine(
                "standby transfer representation level is not supported",
            )),
        }
    }
}

/// Pre-ready custody binding a pending handle to its owning route and
/// representation. The route is persisted explicitly before Ready so reuse
/// never has to guess it; the embedded [`PendingCapture`] keeps PR2's
/// pending shape untouched (its own loader still validates it at wiring).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingTransfer {
    pub contract: String,
    pub version: u32,
    pub route_api: String,
    pub transfer: SnapshotTransfer,
    pub pending: PendingCapture,
}

/// Bind a pending capture to its representation. The route must be the
/// transfer's own contract; anything else is a refusal, never a guess.
pub fn bind_pending_transfer(
    route_api: &str,
    transfer: SnapshotTransfer,
    pending: PendingCapture,
) -> Result<PendingTransfer> {
    transfer.validate()?;
    super::binary_resume::validate_pending_structure(&pending)?;
    if route_api != transfer.route_api() {
        return Err(Error::engine(
            "standby transfer route does not own its representation",
        ));
    }
    if pending.export_handle.trim().is_empty()
        || pending.origin.trim().is_empty()
        || pending.hosted_route_database_id.trim().is_empty()
        || pending.origin_database_id.trim().is_empty()
    {
        return Err(Error::engine("standby transfer pending identity is empty"));
    }
    Ok(PendingTransfer {
        contract: PENDING_TRANSFER_CONTRACT.into(),
        version: PENDING_TRANSFER_VERSION,
        route_api: route_api.into(),
        transfer,
        pending,
    })
}

fn validate_pending_transfer(record: &PendingTransfer) -> Result<()> {
    if record.contract != PENDING_TRANSFER_CONTRACT || record.version != PENDING_TRANSFER_VERSION {
        return Err(Error::engine(
            "standby transfer pending contract is not supported",
        ));
    }
    record.transfer.validate()?;
    super::binary_resume::validate_pending_structure(&record.pending)?;
    if record.route_api != record.transfer.route_api() {
        return Err(Error::engine(
            "standby transfer route does not own its representation",
        ));
    }
    if record.pending.export_handle.trim().is_empty() {
        return Err(Error::engine("standby transfer pending identity is empty"));
    }
    Ok(())
}

/// Atomically persist a bound pending transfer under a fixed private name.
pub fn save_pending_transfer(dir: &Path, record: &PendingTransfer) -> Result<()> {
    validate_pending_transfer(record)?;
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() as u64 > MAX_PENDING_TRANSFER_JSON_BYTES {
        return Err(Error::engine("standby transfer pending exceeds its bound"));
    }
    write_fixed_json(
        dir,
        &dir.join(PENDING_TRANSFER_TMP_NAME),
        &dir.join(PENDING_TRANSFER_JSON_NAME),
        &bytes,
    )
}

/// Load a bound pending transfer. `Ok(None)` means no sidecar present; a
/// present record with a different runtime binding is a refusal, never a reuse.
/// Opens with `O_NOFOLLOW` and checks the verified descriptor (regular,
/// private, single link, path/descriptor identity) before bounding the
/// read, so a substituted pathname cannot widen or redirect the load.
pub fn load_pending_transfer(
    dir: &Path,
    binding: &super::binary_resume::ResumeBinding,
) -> Result<Option<PendingTransfer>> {
    let dest = dir.join(PENDING_TRANSFER_JSON_NAME);
    let file = match open_existing_private(&dest, true, false) {
        Ok(file) => file,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let metadata = verify_opened_private(&dest, &file)?;
    if metadata.len() > MAX_PENDING_TRANSFER_JSON_BYTES {
        return Err(Error::engine("standby transfer pending exceeds its bound"));
    }
    let mut bounded = file.take(MAX_PENDING_TRANSFER_JSON_BYTES + 1);
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut bounded, &mut bytes)?;
    if bytes.len() as u64 > MAX_PENDING_TRANSFER_JSON_BYTES {
        return Err(Error::engine("standby transfer pending exceeds its bound"));
    }
    let record: PendingTransfer = serde_json::from_slice(&bytes)?;
    validate_pending_transfer(&record)?;
    super::binary_resume::validate_pending_binding(&record.pending, binding)?;
    Ok(Some(record))
}

/// Ready custody: decoded size/SHA/full manifest plus, for gzip only, the
/// encoded transfer size/SHA. Ranges and the hash ledger always address
/// [`ReadyTransferIdentity::range_space_bytes`]; identity records never mix
/// the two spaces.
#[derive(Clone, Debug)]
pub struct ReadyTransferIdentity {
    pub transfer: SnapshotTransfer,
    pub route_api: String,
    pub export_handle: String,
    pub decoded_size_bytes: u64,
    pub decoded_sha256: String,
    pub encoded_size_bytes: Option<u64>,
    pub encoded_sha256: Option<String>,
    pub manifest: StandbySnapshotManifest,
}

pub(super) fn check_byte_identity(size: u64, sha256: &str, what: &str) -> Result<()> {
    if size == 0
        || size > MAX_COMPLETED_RANGES as u64 * RESUME_CHUNK_BYTES
        || !is_lower_hex(sha256, 64)
    {
        return Err(Error::engine(format!(
            "standby transfer {what} byte identity is invalid"
        )));
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn check_manifest_binding(
    manifest: &StandbySnapshotManifest,
    route_db: &str,
    origin_db: &str,
    consumer: &StandbyConsumerIdentity,
    decoded_size: u64,
    decoded_sha: &str,
) -> Result<()> {
    if !manifest.has_supported_contract() {
        return Err(Error::engine(
            "standby transfer manifest contract is not supported",
        ));
    }
    if manifest.hosted_route_database_id != route_db
        || manifest.origin_database_id != origin_db
        || manifest.consumer != *consumer
        || manifest.snapshot.size_bytes != decoded_size
        || manifest.snapshot.sha256 != decoded_sha
    {
        return Err(Error::engine("standby transfer manifest identity mismatch"));
    }
    Ok(())
}

impl ReadyTransferIdentity {
    /// Build identity-v1 custody from a Ready poll: no encoded fields, and
    /// the manifest's decoded snapshot claims must equal the poll pair.
    /// Full manifest admission stays with `install_staged`.
    pub fn from_identity_poll(
        export_handle: String,
        manifest: StandbySnapshotManifest,
        size: u64,
        sha256: String,
        route_db: &str,
        origin_db: &str,
        consumer: &StandbyConsumerIdentity,
    ) -> Result<Self> {
        check_byte_identity(size, &sha256, "decoded")?;
        check_manifest_binding(&manifest, route_db, origin_db, consumer, size, &sha256)?;
        Ok(Self {
            transfer: SnapshotTransfer::IdentityV1,
            route_api: IDENTITY_EXPORT_API.into(),
            export_handle,
            decoded_size_bytes: size,
            decoded_sha256: sha256,
            encoded_size_bytes: None,
            encoded_sha256: None,
            manifest,
        })
    }

    /// Build gzip-v2 custody from a Ready poll: decoded claims as above,
    /// plus a separately validated encoded pair. The manifest itself stays
    /// the unchanged decoded manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn from_gzip_poll(
        export_handle: String,
        manifest: StandbySnapshotManifest,
        decoded_size: u64,
        decoded_sha: String,
        encoded_size: u64,
        encoded_sha: String,
        route_db: &str,
        origin_db: &str,
        consumer: &StandbyConsumerIdentity,
    ) -> Result<Self> {
        check_byte_identity(decoded_size, &decoded_sha, "decoded")?;
        check_byte_identity(encoded_size, &encoded_sha, "encoded")?;
        check_manifest_binding(
            &manifest,
            route_db,
            origin_db,
            consumer,
            decoded_size,
            &decoded_sha,
        )?;
        Ok(Self {
            transfer: SnapshotTransfer::GzipV1 {
                level: GZIP_TRANSFER_LEVEL,
            },
            route_api: GZIP_EXPORT_API.into(),
            export_handle,
            decoded_size_bytes: decoded_size,
            decoded_sha256: decoded_sha,
            encoded_size_bytes: Some(encoded_size),
            encoded_sha256: Some(encoded_sha),
            manifest,
        })
    }

    /// Mandatory re-poll agreement before any reuse: the fresh poll must
    /// reproduce this custody exactly, representation included. Any drift —
    /// rotated handle, resized/rehashed transfer, swapped manifest — is a
    /// refusal under the existing cooldown policy, never a reinterpretation.
    pub fn check_against_poll(
        &self,
        manifest: &StandbySnapshotManifest,
        decoded_size: u64,
        decoded_sha: &str,
        encoded_size: Option<u64>,
        encoded_sha: Option<&str>,
    ) -> Result<()> {
        if self.manifest != *manifest
            || self.decoded_size_bytes != decoded_size
            || self.decoded_sha256 != decoded_sha
            || self.encoded_size_bytes != encoded_size
            || self.encoded_sha256.as_deref() != encoded_sha
            || manifest.snapshot.size_bytes != decoded_size
            || manifest.snapshot.sha256 != decoded_sha
        {
            return Err(Error::engine("standby transfer re-poll identity mismatch"));
        }
        match self.transfer {
            SnapshotTransfer::IdentityV1
                if self.route_api == IDENTITY_EXPORT_API
                    && encoded_size.is_none()
                    && encoded_sha.is_none() => {}
            SnapshotTransfer::GzipV1 { level }
                if level == GZIP_TRANSFER_LEVEL
                    && self.route_api == GZIP_EXPORT_API
                    && encoded_size.is_some()
                    && encoded_sha.is_some() => {}
            _ => {
                return Err(Error::engine(
                    "standby transfer re-poll representation mismatch",
                ));
            }
        }
        Ok(())
    }

    /// Byte space ranges and the hash ledger address: encoded bytes for
    /// gzip, decoded bytes for identity. A malformed gzip custody without
    /// an encoded size has no space at all — callers must refuse, never
    /// substitute the decoded total.
    pub fn range_space_bytes(&self) -> Option<u64> {
        match self.transfer {
            SnapshotTransfer::IdentityV1 => Some(self.decoded_size_bytes),
            SnapshotTransfer::GzipV1 { .. } => self.encoded_size_bytes,
        }
    }

    /// Validate completed ranges against this custody's own space: bounded
    /// offsets, non-empty lengths inside the space, lowercase sha per range,
    /// sorted non-overlapping order, entry cap. A decoded-space range set is
    /// refused for a gzip custody even when it fits the decoded total.
    pub fn check_completed_ranges(&self, ranges: &[CompletedRange]) -> Result<()> {
        let space = self
            .range_space_bytes()
            .ok_or_else(|| Error::engine("standby transfer representation has no byte space"))?;
        if ranges.len() > MAX_COMPLETED_RANGES {
            return Err(Error::engine("standby transfer ledger exceeds its bound"));
        }
        let mut end = 0u64;
        for range in ranges {
            if range.length == 0 || !is_lower_hex(&range.sha256, 64) {
                return Err(Error::engine("standby transfer range identity is invalid"));
            }
            let range_end = range
                .offset
                .checked_add(range.length)
                .ok_or_else(|| Error::engine("standby transfer range overflows"))?;
            if range_end > space {
                return Err(Error::engine(
                    "standby transfer range leaves its byte space",
                ));
            }
            if range.offset < end {
                return Err(Error::engine("standby transfer ranges overlap"));
            }
            end = range_end;
        }
        Ok(())
    }
}

/// Fixed streaming buffer for gzip decode: 64 KiB, stack-resident.
const DECODE_BUFFER_BYTES: usize = 64 * 1024;

/// Expectations a staged gzip decode must meet. The encoded digest is
/// verified BEFORE any decode output is trusted; the decoded digest and
/// exact size gate what `install_staged` will later admit (unchanged).
#[derive(Clone, Debug)]
pub struct GzipDecodeExpectation {
    pub encoded_size_bytes: u64,
    pub encoded_sha256: String,
    pub decoded_size_bytes: u64,
    pub decoded_sha256: String,
}

/// Decode one gzip spool into a private staged file.
///
/// Streams through a fixed 64 KiB stack buffer into `staged_path` (created
/// `create_new`, 0600, inside a caller-owned private dir): no whole-file
/// buffer, no unbounded inflate. Exactly one gzip member is accepted: the
/// single-member reader stops at the first footer, and afterwards both its
/// unread buffer and the underlying EOF are checked, so empty second
/// members, trailing bytes, and concatenated members are all refused (the
/// server emits exactly one member). Refuses truncated/corrupt input,
/// footer mismatch, decoded output past the declared size (one extra byte
/// stays observable for detection), and short output. A failed decode
/// removes its staged output best-effort. Full `install_staged` admission
/// still applies afterwards.
pub fn decode_gzip_snapshot(
    encoded_path: &Path,
    staged_path: &Path,
    expected: &GzipDecodeExpectation,
) -> Result<fs::File> {
    check_byte_identity(
        expected.encoded_size_bytes,
        &expected.encoded_sha256,
        "encoded",
    )?;
    check_byte_identity(
        expected.decoded_size_bytes,
        &expected.decoded_sha256,
        "decoded",
    )?;
    // Whole-file encoded digest BEFORE decode: open with O_NOFOLLOW,
    // verify the descriptor itself (regular, private, single link,
    // path/descriptor identity), and take the length bound from that
    // descriptor — never from an earlier pathname check. Untrusted bytes
    // never drive inflation until they match the poll-advertised digest.
    let mut encoded = open_existing_private(encoded_path, true, false)?;
    let metadata = verify_opened_private(encoded_path, &encoded)?;
    if metadata.len() != expected.encoded_size_bytes {
        return Err(Error::engine("standby transfer encoded size mismatch"));
    }
    {
        use sha2::Digest as _;
        let mut digest = sha2::Sha256::new();
        let mut buffer = [0u8; DECODE_BUFFER_BYTES];
        loop {
            let read = encoded.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        if hex::encode(digest.finalize()) != expected.encoded_sha256 {
            return Err(Error::engine("standby transfer encoded digest mismatch"));
        }
    }
    encoded.rewind()?;
    let reader = std::io::BufReader::with_capacity(DECODE_BUFFER_BYTES, encoded);
    let mut decoder = flate2::bufread::GzDecoder::new(reader);
    let mut staged = create_private_staged(staged_path)?;
    let outcome = decode_stream(&mut decoder, &mut staged, expected);
    if let Err(error) = outcome {
        drop(staged);
        let _ = fs::remove_file(staged_path);
        return Err(error);
    }
    // Recheck path/descriptor agreement after writing: the staged fd must
    // still be the private single-link file at its pathname.
    if verify_opened_private(staged_path, &staged).is_err() {
        drop(staged);
        let _ = fs::remove_file(staged_path);
        return Err(Error::engine(
            "standby transfer staged file changed during decode",
        ));
    }
    // A sync failure must not leave an adopted-but-undurable stage: clean
    // up the created file on file or directory sync failure alike.
    let synced = staged.sync_all().and_then(|()| match staged_path.parent() {
        Some(parent) => fs::File::open(parent)?.sync_all(),
        None => Ok(()),
    });
    if let Err(error) = synced {
        drop(staged);
        let _ = fs::remove_file(staged_path);
        return Err(Error::from(error));
    }
    Ok(staged)
}

fn decode_stream(
    decoder: &mut flate2::bufread::GzDecoder<std::io::BufReader<fs::File>>,
    staged: &mut fs::File,
    expected: &GzipDecodeExpectation,
) -> Result<()> {
    use sha2::Digest as _;
    let mut decoded_digest = sha2::Sha256::new();
    let mut buffer = [0u8; DECODE_BUFFER_BYTES];
    let mut written: u64 = 0;
    loop {
        if written > expected.decoded_size_bytes {
            return Err(Error::engine("standby transfer decoded size overrun"));
        }
        let step =
            (expected.decoded_size_bytes + 1 - written).min(DECODE_BUFFER_BYTES as u64) as usize;
        let read = decoder
            .read(&mut buffer[..step])
            .map_err(|_| Error::engine("standby transfer gzip stream is corrupt or truncated"))?;
        if read == 0 {
            break;
        }
        decoded_digest.update(&buffer[..read]);
        staged.write_all(&buffer[..read])?;
        written += read as u64;
    }
    if written != expected.decoded_size_bytes {
        return Err(Error::engine("standby transfer decoded output is short"));
    }
    // Force footer verification and detect trailing decoded bytes: a clean
    // single member is at EOF here, anything else is a refusal.
    let mut probe = [0u8; 1];
    match decoder.read(&mut probe) {
        Ok(0) => {}
        Ok(_) => {
            return Err(Error::engine("standby transfer decoded size overrun"));
        }
        Err(_) => {
            return Err(Error::engine("standby transfer gzip trailer is corrupt"));
        }
    }
    // Exactly one member: after that clean EOF neither the reader's unread
    // buffer nor the underlying file may hold more bytes. This asks the
    // stream itself — never the file offset, which buffer read-ahead makes
    // lie — so empty second members are refused like any other trailing.
    let reader = decoder.get_mut();
    if !reader.buffer().is_empty() {
        return Err(Error::engine("standby transfer gzip has trailing data"));
    }
    match reader.fill_buf() {
        Ok([]) => {}
        Ok(_) => {
            return Err(Error::engine("standby transfer gzip has trailing data"));
        }
        Err(_) => {
            return Err(Error::engine(
                "standby transfer gzip stream is corrupt or truncated",
            ));
        }
    }
    if hex::encode(decoded_digest.finalize()) != expected.decoded_sha256 {
        return Err(Error::engine("standby transfer decoded digest mismatch"));
    }
    Ok(())
}

pub(super) fn create_private_staged(path: &Path) -> Result<fs::File> {
    create_private_staged_with_verifier(path, verify_opened_private)
}

fn create_private_staged_with_verifier(
    path: &Path,
    verify: impl FnOnce(&Path, &fs::File) -> Result<fs::Metadata>,
) -> Result<fs::File> {
    // The caller owns the private staging dir; still never follow or
    // clobber: any pre-existing path (including a symlink) is a refusal,
    // and creation carries O_NOFOLLOW with descriptor-born 0600 from the
    // shared primitive — no pathname chmod anywhere on this path.
    if fs::symlink_metadata(path).is_ok() {
        return Err(Error::engine(
            "standby transfer staged output already exists",
        ));
    }
    let mut options = open_options_nofollow(false, true);
    options.create_new(true);
    let file = options.open(path)?;
    // Cleanup ownership starts at successful create_new, before verification
    // can fail. An open refusal above never owns or removes an existing path.
    if let Err(error) = verify(path, &file) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standby_snapshot::{
        CanonicalFrontierV1, StandbyConsumerPlatform, StandbyGenerationMaterialization,
        StandbySnapshotBytes, StandbySnapshotEngineIdentity, STANDBY_CONSUMER_CONTRACT,
        STANDBY_FRONTIER_CONTRACT, STANDBY_SNAPSHOT_MANIFEST_CONTRACT, STANDBY_SNAPSHOT_MEDIA_TYPE,
    };
    use std::path::PathBuf;

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

    fn test_manifest(decoded_size: u64, decoded_sha: &str) -> StandbySnapshotManifest {
        StandbySnapshotManifest {
            contract: STANDBY_SNAPSHOT_MANIFEST_CONTRACT.into(),
            version: 1,
            hosted_route_database_id: "route-db-1".into(),
            origin_database_id: format!("ndb_{}", "d".repeat(32)),
            captured_at: "2026-10-17T00:00:00Z".into(),
            snapshot_completed_at: "2026-10-17T00:00:01Z".into(),
            engine: StandbySnapshotEngineIdentity {
                name: crate::ENGINE_NAME.into(),
                source_sha: "a".repeat(40),
                schema_version: 59,
                ddl_sha256: "c".repeat(64),
            },
            consumer: test_consumer(),
            frontier: CanonicalFrontierV1 {
                contract: STANDBY_FRONTIER_CONTRACT.into(),
                version: 1,
                content_event_seq: 3,
                policy_event_seq: 3,
                awareness_event_seq: 3,
                notification_candidate_event_seq: 3,
                binding_audit_seq: 3,
                database_identity_audit_seq: 3,
                meta_event_seq: 3,
                control_event_seq: 3,
                derivation_event_seq: 3,
                relationship_event_seq: 3,
                authorization_revision_epoch: 1,
                storage_portability_policy_revision: 1,
            },
            head_act: None,
            kernel_v2: None,
            materialization: StandbyGenerationMaterialization::Snapshot,
            snapshot: StandbySnapshotBytes {
                media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
                size_bytes: decoded_size,
                sha256: decoded_sha.into(),
            },
        }
    }

    fn native_manifest() -> StandbySnapshotManifest {
        let mut manifest = test_manifest(300_000, DECODED_SHA);
        manifest.contract = crate::standby::kernel_v2::MANIFEST.into();
        manifest.engine.name = crate::standby::kernel_v2::ENGINE.into();
        manifest.engine.schema_version = 0;
        manifest.frontier = CanonicalFrontierV1 {
            contract: STANDBY_FRONTIER_CONTRACT.into(),
            version: 1,
            content_event_seq: 0,
            policy_event_seq: 0,
            awareness_event_seq: 0,
            notification_candidate_event_seq: 0,
            binding_audit_seq: 0,
            database_identity_audit_seq: 0,
            meta_event_seq: 0,
            control_event_seq: 0,
            derivation_event_seq: 0,
            relationship_event_seq: 0,
            authorization_revision_epoch: 0,
            storage_portability_policy_revision: 0,
        };
        manifest.head_act = Some(1);
        manifest.kernel_v2 = Some(crate::standby::kernel_v2::KernelGeneration {
            application_id: crate::db::V2_APPLICATION_ID,
            genesis_event_id: HANDLE.into(),
            content_event_seq: 1,
            meta_event_seq: 0,
            head_act: 1,
            schema_sha256: manifest.engine.ddl_sha256.clone(),
            projection_tables: vec!["kernel_records".into()],
            blob_count: 0,
        });
        manifest.validate().unwrap();
        manifest
    }

    fn ready_native(
        manifest: StandbySnapshotManifest,
        gzip: bool,
    ) -> Result<ReadyTransferIdentity> {
        let binding = test_binding();
        if gzip {
            ReadyTransferIdentity::from_gzip_poll(
                HANDLE.into(),
                manifest,
                300_000,
                DECODED_SHA.into(),
                12_000,
                ENCODED_SHA.into(),
                &binding.hosted_route_database_id,
                &binding.origin_database_id,
                &binding.consumer,
            )
        } else {
            ReadyTransferIdentity::from_identity_poll(
                HANDLE.into(),
                manifest,
                300_000,
                DECODED_SHA.into(),
                &binding.hosted_route_database_id,
                &binding.origin_database_id,
                &binding.consumer,
            )
        }
    }

    #[test]
    fn ready_native_identity_accepts_supported_manifest_contract() {
        let manifest = native_manifest();
        let ready = ready_native(manifest.clone(), false).unwrap();
        assert_eq!(ready.manifest, manifest);
        assert_eq!(ready.encoded_size_bytes, None);
        ready
            .check_against_poll(&manifest, 300_000, DECODED_SHA, None, None)
            .unwrap();
    }

    #[test]
    fn ready_native_gzip_accepts_supported_manifest_contract() {
        let manifest = native_manifest();
        let ready = ready_native(manifest.clone(), true).unwrap();
        assert_eq!(ready.manifest, manifest);
        assert_eq!(ready.encoded_size_bytes, Some(12_000));
        ready
            .check_against_poll(
                &manifest,
                300_000,
                DECODED_SHA,
                Some(12_000),
                Some(ENCODED_SHA),
            )
            .unwrap();
        assert!(ready
            .check_against_poll(
                &manifest,
                300_000,
                DECODED_SHA,
                Some(12_000),
                Some(&"a".repeat(64))
            )
            .is_err());
    }

    #[test]
    fn ready_native_refuses_unknown_headers_and_mismatched_bindings() {
        for gzip in [false, true] {
            for field in [
                "contract", "version", "route", "origin", "consumer", "size", "sha",
            ] {
                let mut manifest = native_manifest();
                match field {
                    "contract" => manifest.contract = "native.unknown-manifest.v1".into(),
                    "version" => manifest.version = 2,
                    "route" => manifest.hosted_route_database_id = "other-route".into(),
                    "origin" => manifest.origin_database_id = format!("ndb_{}", "e".repeat(32)),
                    "consumer" => manifest.consumer.artifact_sha256 = "e".repeat(64),
                    "size" => manifest.snapshot.size_bytes += 1,
                    "sha" => manifest.snapshot.sha256 = "e".repeat(64),
                    _ => unreachable!(),
                }
                assert!(
                    ready_native(manifest, gzip).is_err(),
                    "{field}, gzip={gzip}"
                );
            }
        }
        let binding = test_binding();
        for (size, sha) in [(0, ENCODED_SHA), (12_000, "invalid")] {
            assert!(ReadyTransferIdentity::from_gzip_poll(
                HANDLE.into(),
                native_manifest(),
                300_000,
                DECODED_SHA.into(),
                size,
                sha.into(),
                &binding.hosted_route_database_id,
                &binding.origin_database_id,
                &binding.consumer,
            )
            .is_err());
        }
    }

    #[test]
    fn ready_native_recognition_does_not_replace_full_manifest_validation() {
        let mut manifest = native_manifest();
        manifest.engine.schema_version = 1;
        assert!(manifest.validate().is_err());
        // Acquisition binds representation custody, not engine admission.
        for gzip in [false, true] {
            assert!(ready_native(manifest.clone(), gzip).is_ok());
        }
    }

    fn test_binding() -> super::super::binary_resume::ResumeBinding {
        super::super::binary_resume::ResumeBinding {
            origin: "https://example.com".into(),
            hosted_route_database_id: "route-db-1".into(),
            origin_database_id: format!("ndb_{}", "d".repeat(32)),
            consumer: test_consumer(),
        }
    }

    #[test]
    fn pending_transfer_validates_entire_nested_capture_before_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let record = bind_pending_transfer(
            GZIP_EXPORT_API,
            SnapshotTransfer::GzipV1 { level: 1 },
            test_pending(HANDLE),
        )
        .unwrap();
        for field in [
            "contract",
            "origin",
            "consumer",
            "started_at",
            "export_handle",
        ] {
            let mut raw = serde_json::to_value(&record).unwrap();
            if field == "consumer" {
                raw["pending"]["consumer"]["version"] = serde_json::json!(99);
            } else {
                raw["pending"][field] = serde_json::json!("invalid");
            }
            write_fixed_json(
                dir.path(),
                &dir.path().join(PENDING_TRANSFER_TMP_NAME),
                &dir.path().join(PENDING_TRANSFER_JSON_NAME),
                &serde_json::to_vec(&raw).unwrap(),
            )
            .unwrap();
            assert!(
                matches!(load_pending_transfer(dir.path(), &test_binding()), Err(Error::Engine(message)) if !message.contains("resume file")),
                "nested {field} must refuse"
            );
        }
        save_pending_transfer(dir.path(), &record).unwrap();
        assert_eq!(
            load_pending_transfer(dir.path(), &test_binding())
                .unwrap()
                .unwrap(),
            record
        );
    }

    fn test_pending(handle: &str) -> PendingCapture {
        PendingCapture {
            contract: "native.standby-binary-pending.v1".into(),
            version: 1,
            origin: "https://example.com".into(),
            hosted_route_database_id: "route-db-1".into(),
            origin_database_id: format!("ndb_{}", "d".repeat(32)),
            consumer: test_consumer(),
            export_handle: handle.into(),
            started_at: "2026-10-17T00:00:00Z".into(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "transfer-repr-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&dir).unwrap();
        dir
    }

    const HANDLE: &str = "12345678-1234-1234-1234-1234567890ab";
    const DECODED_SHA: &str = "d3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33fd3adb33f";
    const ENCODED_SHA: &str = "ec0dedec0dedec0dedec0dedec0dedec0dedec0dedec0dedec0dedec0dedec0d";

    fn gzip_identity() -> ReadyTransferIdentity {
        ReadyTransferIdentity::from_gzip_poll(
            HANDLE.into(),
            test_manifest(300_000, DECODED_SHA),
            300_000,
            DECODED_SHA.into(),
            12_000,
            ENCODED_SHA.into(),
            "route-db-1",
            &format!("ndb_{}", "d".repeat(32)),
            &test_consumer(),
        )
        .unwrap()
    }

    fn identity_identity() -> ReadyTransferIdentity {
        ReadyTransferIdentity::from_identity_poll(
            HANDLE.into(),
            test_manifest(300_000, DECODED_SHA),
            300_000,
            DECODED_SHA.into(),
            "route-db-1",
            &format!("ndb_{}", "d".repeat(32)),
            &test_consumer(),
        )
        .unwrap()
    }

    #[test]
    fn pending_transfer_roundtrip_binds_both_representations() {
        let dir = temp_dir("pending-roundtrip");
        for transfer in [
            SnapshotTransfer::IdentityV1,
            SnapshotTransfer::GzipV1 {
                level: GZIP_TRANSFER_LEVEL,
            },
        ] {
            let record =
                bind_pending_transfer(transfer.route_api(), transfer, test_pending(HANDLE))
                    .unwrap();
            save_pending_transfer(&dir, &record).unwrap();
            let loaded = load_pending_transfer(&dir, &test_binding())
                .unwrap()
                .unwrap();
            assert_eq!(loaded, record);
            assert_eq!(loaded.route_api, transfer.route_api());
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pending_transfer_refuses_mismatch_and_unknown_shapes() {
        // Route/transfer pairing is explicit: v1 never owns gzip custody.
        assert!(bind_pending_transfer(
            IDENTITY_EXPORT_API,
            SnapshotTransfer::GzipV1 {
                level: GZIP_TRANSFER_LEVEL
            },
            test_pending(HANDLE),
        )
        .is_err());
        // Unsupported level is a refusal, not a guess.
        assert!(bind_pending_transfer(
            GZIP_EXPORT_API,
            SnapshotTransfer::GzipV1 { level: 9 },
            test_pending(HANDLE),
        )
        .is_err());
        let dir = temp_dir("pending-refuse");
        let record = bind_pending_transfer(
            GZIP_EXPORT_API,
            SnapshotTransfer::GzipV1 {
                level: GZIP_TRANSFER_LEVEL,
            },
            test_pending(HANDLE),
        )
        .unwrap();
        save_pending_transfer(&dir, &record).unwrap();
        // A present sidecar bound to another handle is refused, never reused.
        assert_refusal(
            load_pending_transfer(
                &dir,
                &super::super::binary_resume::ResumeBinding {
                    hosted_route_database_id: "other-route".into(),
                    ..test_binding()
                },
            ),
            "standby resume binding mismatch",
        );
        // Unknown encodings are refused by the closed serde shape.
        let foreign = serde_json::json!({
            "contract": PENDING_TRANSFER_CONTRACT,
            "version": PENDING_TRANSFER_VERSION,
            "route_api": GZIP_EXPORT_API,
            "transfer": {"encoding": "zstd", "level": 1},
            "pending": test_pending(HANDLE),
        });
        let raw = serde_json::to_vec(&foreign).unwrap();
        write_fixed_json(
            &dir,
            &dir.join(PENDING_TRANSFER_TMP_NAME),
            &dir.join(PENDING_TRANSFER_JSON_NAME),
            &raw,
        )
        .unwrap();
        assert!(
            matches!(load_pending_transfer(&dir, &test_binding()), Err(Error::Json(error))
            if error.to_string().contains("unknown variant `zstd`"))
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    fn completed(offset: u64, length: u64) -> CompletedRange {
        CompletedRange {
            offset,
            length,
            sha256: "f".repeat(64),
        }
    }

    #[test]
    fn ready_identity_separates_encoded_and_decoded_spaces() {
        let gzip = gzip_identity();
        assert_eq!(gzip.range_space_bytes(), Some(12_000));
        assert_eq!(gzip.encoded_size_bytes, Some(12_000));
        assert_eq!(gzip.decoded_size_bytes, 300_000);
        // Ranges address the encoded space: inside passes ...
        gzip.check_completed_ranges(&[completed(0, 1024), completed(2048, 512)])
            .unwrap();
        // ... a decoded-space range is refused even though it fits decoded.
        assert!(gzip
            .check_completed_ranges(&[completed(0, 20_000)])
            .is_err());
        // Offset arithmetic overflow and overlap are refused.
        assert!(gzip
            .check_completed_ranges(&[completed(u64::MAX, 1)])
            .is_err());
        assert!(gzip
            .check_completed_ranges(&[completed(0, 100), completed(50, 100)])
            .is_err());
        // Identity keeps the decoded space with no encoded fields.
        let identity = identity_identity();
        assert_eq!(identity.range_space_bytes(), Some(300_000));
        assert_eq!(identity.encoded_size_bytes, None);
        identity
            .check_completed_ranges(&[completed(0, 200_000)])
            .unwrap();
        assert!(identity
            .check_completed_ranges(&[completed(0, 300_001)])
            .is_err());
    }

    #[test]
    fn repoll_agreement_rejects_any_drift() {
        let gzip = gzip_identity();
        let manifest = test_manifest(300_000, DECODED_SHA);
        gzip.check_against_poll(
            &manifest,
            300_000,
            DECODED_SHA,
            Some(12_000),
            Some(ENCODED_SHA),
        )
        .unwrap();
        // Rotated encoded digest: refuse.
        assert!(gzip
            .check_against_poll(
                &manifest,
                300_000,
                DECODED_SHA,
                Some(12_000),
                Some(&"a".repeat(64))
            )
            .is_err());
        // Dropped encoded pair on a gzip custody: representation mismatch.
        assert!(gzip
            .check_against_poll(&manifest, 300_000, DECODED_SHA, None, None)
            .is_err());
        // Manifest whose decoded claims drifted from the poll pair: refuse.
        let drifted = test_manifest(300_001, DECODED_SHA);
        assert!(gzip
            .check_against_poll(
                &drifted,
                300_001,
                DECODED_SHA,
                Some(12_000),
                Some(ENCODED_SHA)
            )
            .is_err());
        // Identity custody rejects a gzip-shaped re-poll.
        let identity = identity_identity();
        assert!(identity
            .check_against_poll(
                &manifest,
                300_000,
                DECODED_SHA,
                Some(12_000),
                Some(ENCODED_SHA)
            )
            .is_err());
    }

    // Decoder fixtures: small synthetic payloads built in-test. The
    // implementation under test never holds whole files; only these
    // fixtures (and byte-exact assertions) use Vec.
    fn payload_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn gzip_member(payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(1));
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut file = open_options_nofollow(false, true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        verify_opened_private(&path, &file).unwrap();
        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600);
        path
    }

    fn assert_refusal<T>(result: Result<T>, reason: &str) {
        match result {
            Err(Error::Engine(message)) => assert_eq!(message, reason),
            Err(error) => panic!("expected {reason}, got {error}"),
            Ok(_) => panic!("expected {reason}, got success"),
        }
    }

    fn assert_decode_refusal(
        source: &Path,
        staged: &Path,
        expected: &GzipDecodeExpectation,
        reason: &str,
    ) {
        assert_refusal(decode_gzip_snapshot(source, staged, expected), reason);
        assert!(!staged.exists());
    }

    #[test]
    fn stage_verification_failure_cleans_only_output_created_by_this_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged.db");
        let verified = std::cell::Cell::new(false);
        let result = create_private_staged_with_verifier(&staged, |path, file| {
            verified.set(true);
            verify_opened_private(path, file)?;
            // Deterministically model metadata verification failing after a
            // successful create, without a concurrent pathname writer.
            Err(std::io::Error::other("injected post-create verification failure").into())
        });
        assert!(verified.get());
        assert!(matches!(result, Err(Error::Io(error))
            if error.to_string() == "injected post-create verification failure"));
        assert!(!staged.exists());

        // The failed attempt must not block a create_new retry. Once this
        // path already exists, another attempt must never arm its cleanup.
        let mut file = create_private_staged(&staged).unwrap();
        file.write_all(b"keep existing output").unwrap();
        drop(file);
        assert_refusal(
            create_private_staged_with_verifier(&staged, |_, _| {
                panic!("verification must not run for a pre-existing output")
            }),
            "standby transfer staged output already exists",
        );
        assert_eq!(fs::read(&staged).unwrap(), b"keep existing output");
        #[cfg(unix)]
        {
            let target = dir.path().join("target.db");
            fs::rename(&staged, &target).unwrap();
            std::os::unix::fs::symlink(&target, &staged).unwrap();
            assert_refusal(
                create_private_staged_with_verifier(&staged, |_, _| {
                    panic!("verification must not run for a pre-existing symlink")
                }),
                "standby transfer staged output already exists",
            );
            assert!(fs::symlink_metadata(&staged)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(fs::read(&target).unwrap(), b"keep existing output");
            assert_eq!(mode_of(&target), 0o600);
        }
    }

    fn expectation_for(encoded: &[u8], decoded: &[u8]) -> GzipDecodeExpectation {
        use sha2::Digest as _;
        GzipDecodeExpectation {
            encoded_size_bytes: encoded.len() as u64,
            encoded_sha256: hex::encode(sha2::Sha256::digest(encoded)),
            decoded_size_bytes: decoded.len() as u64,
            decoded_sha256: hex::encode(sha2::Sha256::digest(decoded)),
        }
    }

    #[test]
    fn decode_roundtrip_spans_buffers() {
        let dir = temp_dir("decode-roundtrip");
        let payload = payload_bytes(300_000);
        let encoded = gzip_member(&payload);
        println!(
            "synthetic_gzip_fixture decoded={} encoded={} ratio={:.6}",
            payload.len(),
            encoded.len(),
            encoded.len() as f64 / payload.len() as f64
        );
        let source = write_file(&dir, "source.gz", &encoded);
        let staged = dir.join("staged.db");
        let expected = expectation_for(&encoded, &payload);
        decode_gzip_snapshot(&source, &staged, &expected).unwrap();
        assert_eq!(fs::read(&staged).unwrap(), payload);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decode_refuses_identity_mismatch_and_cleans_staged() {
        let dir = temp_dir("decode-mismatch");
        let payload = payload_bytes(90_000);
        let encoded = gzip_member(&payload);
        let source = write_file(&dir, "source.gz", &encoded);
        let staged = dir.join("staged.db");
        let mut expected = expectation_for(&encoded, &payload);
        expected.encoded_size_bytes += 1;
        assert_decode_refusal(
            &source,
            &staged,
            &expected,
            "standby transfer encoded size mismatch",
        );
        let mut expected = expectation_for(&encoded, &payload);
        expected.encoded_sha256 = "a".repeat(64);
        assert_decode_refusal(
            &source,
            &staged,
            &expected,
            "standby transfer encoded digest mismatch",
        );
        let mut expected = expectation_for(&encoded, &payload);
        expected.decoded_sha256 = "b".repeat(64);
        assert_decode_refusal(
            &source,
            &staged,
            &expected,
            "standby transfer decoded digest mismatch",
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decode_refuses_truncation_and_footer_corruption() {
        let dir = temp_dir("decode-corrupt");
        let payload = payload_bytes(150_000);
        let encoded = gzip_member(&payload);
        let staged = dir.join("staged.db");
        let cut = write_file(&dir, "cut.gz", &encoded[..encoded.len() / 2]);
        let cut_expected = expectation_for(&encoded[..encoded.len() / 2], &payload);
        assert_decode_refusal(
            &cut,
            &staged,
            &cut_expected,
            "standby transfer gzip stream is corrupt or truncated",
        );
        let mut rotten = encoded.clone();
        let last = rotten.len() - 1;
        rotten[last] ^= 0xff;
        let rotten_path = write_file(&dir, "rotten.gz", &rotten);
        let rotten_expected = expectation_for(&rotten, &payload);
        assert_decode_refusal(
            &rotten_path,
            &staged,
            &rotten_expected,
            "standby transfer gzip stream is corrupt or truncated",
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decode_refuses_declared_size_overrun_and_short() {
        let dir = temp_dir("decode-bounds");
        let payload = payload_bytes(150_000);
        let encoded = gzip_member(&payload);
        let source = write_file(&dir, "source.gz", &encoded);
        let staged = dir.join("staged.db");
        let mut overrun = expectation_for(&encoded, &payload);
        overrun.decoded_size_bytes -= 16;
        assert_decode_refusal(
            &source,
            &staged,
            &overrun,
            "standby transfer decoded size overrun",
        );
        let mut short = expectation_for(&encoded, &payload);
        short.decoded_size_bytes += 16;
        assert_decode_refusal(
            &source,
            &staged,
            &short,
            "standby transfer decoded output is short",
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decode_refuses_trailing_bytes_and_second_member() {
        let dir = temp_dir("decode-trailing");
        let payload = payload_bytes(150_000);
        let encoded = gzip_member(&payload);
        let staged = dir.join("staged.db");
        let mut trailed = encoded.clone();
        trailed.extend_from_slice(&[0u8; 48]);
        let trailed_path = write_file(&dir, "trailed.gz", &trailed);
        assert_decode_refusal(
            &trailed_path,
            &staged,
            &expectation_for(&trailed, &payload),
            "standby transfer gzip has trailing data",
        );
        let mut doubled = encoded.clone();
        doubled.extend_from_slice(&gzip_member(b"second member"));
        let doubled_path = write_file(&dir, "doubled.gz", &doubled);
        assert_decode_refusal(
            &doubled_path,
            &staged,
            &expectation_for(&doubled, &payload),
            "standby transfer gzip has trailing data",
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decode_refuses_empty_second_member() {
        let dir = temp_dir("decode-empty-second");
        let payload = payload_bytes(150_000);
        let encoded = gzip_member(&payload);
        let staged = dir.join("staged.db");
        // A zero-length second member decodes to no extra bytes: the
        // contract still requires exactly one member.
        let mut doubled = encoded.clone();
        doubled.extend_from_slice(&gzip_member(&[]));
        assert!(doubled.len() > encoded.len());
        let doubled_path = write_file(&dir, "doubled-empty.gz", &doubled);
        assert_decode_refusal(
            &doubled_path,
            &staged,
            &expectation_for(&doubled, &payload),
            "standby transfer gzip has trailing data",
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pending_sidecar_refuses_nonprivate_and_hardlink() {
        let dir = temp_dir("pending-custody");
        let record = bind_pending_transfer(
            GZIP_EXPORT_API,
            SnapshotTransfer::GzipV1 {
                level: GZIP_TRANSFER_LEVEL,
            },
            test_pending(HANDLE),
        )
        .unwrap();
        save_pending_transfer(&dir, &record).unwrap();
        let dest = dir.join(PENDING_TRANSFER_JSON_NAME);
        assert_eq!(mode_of(&dest), 0o600);
        // A group-readable sidecar is refused without reading it.
        set_mode(&dest, 0o644);
        assert_refusal(
            load_pending_transfer(&dir, &test_binding()),
            "standby resume file is not private",
        );
        set_mode(&dest, 0o600);
        load_pending_transfer(&dir, &test_binding()).unwrap();
        // A second link is refused even with private mode.
        let link = dir.join("sidecar-link.json");
        fs::hard_link(&dest, &link).unwrap();
        assert_refusal(
            load_pending_transfer(&dir, &test_binding()),
            "standby resume file is linked",
        );
        fs::remove_file(&link).unwrap();
        load_pending_transfer(&dir, &test_binding()).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pending_save_never_chmods_through_temp_symlink() {
        let dir = temp_dir("pending-tmp-swap");
        let outside = write_file(&dir, "outside.txt", b"untouched");
        set_mode(&outside, 0o644);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, dir.join(PENDING_TRANSFER_TMP_NAME)).unwrap();
        let record = bind_pending_transfer(
            IDENTITY_EXPORT_API,
            SnapshotTransfer::IdentityV1,
            test_pending(HANDLE),
        )
        .unwrap();
        // The swapped temp is unlinked first: save succeeds, the outside
        // target keeps its mode and content, the sidecar is private.
        save_pending_transfer(&dir, &record).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
        assert_eq!(mode_of(&outside), 0o644);
        assert_eq!(mode_of(&dir.join(PENDING_TRANSFER_JSON_NAME)), 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pending_load_refuses_symlink_and_swapped_content() {
        let dir = temp_dir("pending-swap");
        let record = bind_pending_transfer(
            IDENTITY_EXPORT_API,
            SnapshotTransfer::IdentityV1,
            test_pending(HANDLE),
        )
        .unwrap();
        save_pending_transfer(&dir, &record).unwrap();
        let dest = dir.join(PENDING_TRANSFER_JSON_NAME);
        // A symlink at the sidecar path is never followed.
        let swapped = dir.join("swapped.json");
        fs::rename(&dest, &swapped).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&swapped, &dest).unwrap();
        #[cfg(unix)]
        assert!(
            matches!(load_pending_transfer(&dir, &test_binding()), Err(Error::Io(error))
            if error.raw_os_error() == Some(libc::ELOOP))
        );
        #[cfg(unix)]
        fs::remove_file(&dest).unwrap();
        // Content exchanged under the pathname is refused, never adopted.
        write_file(&dir, PENDING_TRANSFER_JSON_NAME, b"{not json");
        assert!(matches!(
            load_pending_transfer(&dir, &test_binding()),
            Err(Error::Json(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn decode_refuses_nonprivate_and_hardlinked_source() {
        let dir = temp_dir("decode-source-custody");
        let payload = payload_bytes(90_000);
        let encoded = gzip_member(&payload);
        let source = write_file(&dir, "source.gz", &encoded);
        let staged = dir.join("staged.db");
        let expected = expectation_for(&encoded, &payload);
        set_mode(&source, 0o644);
        assert_decode_refusal(
            &source,
            &staged,
            &expected,
            "standby resume file is not private",
        );
        set_mode(&source, 0o600);
        let link = dir.join("source-link.gz");
        fs::hard_link(&source, &link).unwrap();
        assert_decode_refusal(&source, &staged, &expected, "standby resume file is linked");
        fs::remove_file(&link).unwrap();
        decode_gzip_snapshot(&source, &staged, &expected).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn decode_leaves_existing_stage_and_symlinks_untouched() {
        let dir = temp_dir("decode-stage-kept");
        let payload = payload_bytes(90_000);
        let encoded = gzip_member(&payload);
        let source = write_file(&dir, "source.gz", &encoded);
        let expected = expectation_for(&encoded, &payload);
        // A pre-existing staged file is a refusal, and its bytes survive.
        let staged = write_file(&dir, "staged.db", b"sentinel");
        assert_refusal(
            decode_gzip_snapshot(&source, &staged, &expected),
            "standby transfer staged output already exists",
        );
        assert_eq!(fs::read(&staged).unwrap(), b"sentinel");
        assert_eq!(mode_of(&staged), 0o600);
        fs::remove_file(&staged).unwrap();
        // A staged symlink is never followed: the link and target survive.
        let target = write_file(&dir, "target.db", b"target-bytes");
        std::os::unix::fs::symlink(&target, &staged).unwrap();
        assert_refusal(
            decode_gzip_snapshot(&source, &staged, &expected),
            "standby transfer staged output already exists",
        );
        assert_eq!(fs::read(&target).unwrap(), b"target-bytes");
        assert_eq!(mode_of(&target), 0o600);
        assert!(fs::symlink_metadata(&staged)
            .unwrap()
            .file_type()
            .is_symlink());
        // A symlinked source is never followed either.
        let source_link = dir.join("source-link.gz");
        std::os::unix::fs::symlink(&source, &source_link).unwrap();
        let unused_stage = dir.join("unused-stage.db");
        assert!(
            matches!(decode_gzip_snapshot(&source_link, &unused_stage, &expected),
            Err(Error::Io(error)) if error.raw_os_error() == Some(libc::ELOOP))
        );
        assert!(!unused_stage.exists());
        assert_eq!(fs::read(&source).unwrap(), encoded);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spaceless_gzip_custody_has_no_range_space() {
        let broken = ReadyTransferIdentity {
            encoded_size_bytes: None,
            encoded_sha256: None,
            ..gzip_identity()
        };
        assert_eq!(broken.range_space_bytes(), None);
        assert!(broken.check_completed_ranges(&[completed(0, 64)]).is_err());
    }
}
