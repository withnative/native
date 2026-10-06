//! Pure host importer (task `1bf0e85`, P1a slice S2: no DB — S3 persists).
//!
//! The importer takes an [`ImportCandidate`] — raw `native-package.json`
//! bytes plus a path→bytes map — and returns an [`ImportedRevision`] or a
//! typed [`ImportRefusal`] whose [`ImportRefusal::reason`] is a stable token
//! S3/S4 tests match on. Claimed hashes are never trusted: every listed
//! file's sha256 is recomputed from the submitted bytes. Unlisted map
//! entries are dropped, never retained. Size caps are checked against the
//! actual bytes before hashing large inputs. The provenance [`Receipt`] is
//! never part of the digest.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::manifest_v2::{
    parse_manifest_json, ContributionRef, FileEntry, ManifestJsonError, PackageManifestV2,
    MAX_FILE_BYTES, MAX_MANIFEST_BYTES, MAX_REVISION_BYTES,
};
use crate::error::Error;

/// Raw submission: manifest bytes plus every fetched file by listed path.
/// Entries under unlisted paths are ignored (never retained).
#[derive(Debug)]
pub struct ImportCandidate {
    pub manifest_bytes: Vec<u8>,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Who fetched the bytes the host is verifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchedBy {
    /// The host fetched the bytes itself: receipt may show as verified.
    Host,
    /// A client submitted the bytes: receipt is shown as asserted, never
    /// as verified — but every hash is still recomputed.
    Client,
}

impl FetchedBy {
    pub fn as_str(&self) -> &'static str {
        match self {
            FetchedBy::Host => "host",
            FetchedBy::Client => "client",
        }
    }
}

/// Provenance inputs for the import receipt. Descriptive only: none of
/// these fields enter the digest.
pub struct ProvenanceInput {
    pub adapter: String,
    pub origin: serde_json::Value,
    pub requested_ref: Option<String>,
    pub fetched_by: FetchedBy,
    pub importer: String,
    pub run_key: String,
    pub at: String,
}

/// Typed refusal with a stable machine-readable token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRefusal {
    pub reason: &'static str,
    pub detail: String,
}

impl ImportRefusal {
    pub fn as_str(&self) -> &'static str {
        self.reason
    }

    pub(crate) fn refused(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl From<ImportRefusal> for Error {
    fn from(refusal: ImportRefusal) -> Self {
        Error::engine(format!(
            "plugin import refused [{}]: {}",
            refusal.reason, refusal.detail
        ))
    }
}
/// Provenance receipt for one import. Appended per import (S3); a second
/// import of identical bytes yields the same digest with a second receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub digest: String,
    pub adapter: String,
    pub origin: serde_json::Value,
    pub requested_ref: Option<String>,
    pub fetched_by: FetchedBy,
    pub importer: String,
    pub run_key: String,
    pub at: String,
}

impl Receipt {
    pub fn canonical_value(&self) -> serde_json::Value {
        serde_json::json!({
            "adapter": self.adapter,
            "at": self.at,
            "digest": self.digest,
            "fetched_by": self.fetched_by.as_str(),
            "importer": self.importer,
            "origin": self.origin,
            "requested_ref": self.requested_ref,
            "run_key": self.run_key,
        })
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::canonical_json::canonical_json(&self.canonical_value())
    }
}

/// One retained file: listed path plus the verified bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Accepted revision: validated manifest, canonical bytes, digest, the
/// listed files only (in path order), and the provenance receipt.
#[derive(Debug)]
pub struct ImportedRevision {
    pub manifest: PackageManifestV2,
    pub canonical_manifest_bytes: Vec<u8>,
    pub digest: String,
    pub files: Vec<RetainedFile>,
    pub receipt: Receipt,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Run the pure import. Manifest shape/validation failures (including the
/// S1 named reasons, preserved in `detail`) refuse as `malformed_manifest`.
pub fn import_candidate(
    candidate: &ImportCandidate,
    provenance: &ProvenanceInput,
) -> Result<ImportedRevision, ImportRefusal> {
    if candidate.manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(ImportRefusal::refused(
            "manifest_too_large",
            format!(
                "native-package.json is {} bytes, over the cap of {MAX_MANIFEST_BYTES}",
                candidate.manifest_bytes.len()
            ),
        ));
    }
    let value = parse_manifest_json(&candidate.manifest_bytes).map_err(|e| match e {
        ManifestJsonError::DuplicateKey(detail) => ImportRefusal::refused("duplicate_key", detail),
        ManifestJsonError::Malformed(detail) => {
            ImportRefusal::refused("malformed_manifest", detail)
        }
    })?;
    if !value.is_object() {
        return Err(ImportRefusal::refused(
            "malformed_manifest",
            "native-package.json must be a JSON object",
        ));
    }
    let manifest = PackageManifestV2::from_json_value(&value)
        .map_err(|e| ImportRefusal::refused("malformed_manifest", e.to_string()))?;
    if !manifest.declared.effects.is_empty() {
        return Err(ImportRefusal::refused(
            "effects_not_supported",
            "P1a refuses non-empty declared effects",
        ));
    }
    if !manifest.requires.is_empty() {
        return Err(ImportRefusal::refused(
            "requires_not_supported",
            "P1a refuses non-empty requires",
        ));
    }
    let mut total: u64 = 0;
    let mut retained: Vec<RetainedFile> = Vec::with_capacity(manifest.files.len());
    for entry in &manifest.files {
        let bytes = candidate.files.get(&entry.path).ok_or_else(|| {
            ImportRefusal::refused(
                "missing_file",
                format!("listed file '{}' not submitted", entry.path),
            )
        })?;
        // Caps first (against actual bytes), so oversized inputs are refused
        // before hashing; claimed lengths are never trusted for sizing.
        let actual = bytes.len() as u64;
        if actual > MAX_FILE_BYTES {
            return Err(ImportRefusal::refused(
                "file_too_large",
                format!(
                    "file '{}' is {actual} bytes, over the cap of {MAX_FILE_BYTES}",
                    entry.path
                ),
            ));
        }
        total = total.saturating_add(actual);
        if total > MAX_REVISION_BYTES {
            return Err(ImportRefusal::refused(
                "revision_too_large",
                format!("revision exceeds the cap of {MAX_REVISION_BYTES} bytes"),
            ));
        }
        if actual != entry.bytes_len {
            return Err(ImportRefusal::refused(
                "length_mismatch",
                format!(
                    "file '{}' claims {} bytes but submitted {actual}",
                    entry.path, entry.bytes_len
                ),
            ));
        }
        let recomputed = sha256_hex(bytes);
        if recomputed != entry.sha256 {
            return Err(ImportRefusal::refused(
                "hash_mismatch",
                format!(
                    "file '{}' hash recomputed from bytes disagrees with claimed",
                    entry.path
                ),
            ));
        }
        retained.push(RetainedFile {
            path: entry.path.clone(),
            bytes: bytes.clone(),
        });
    }
    retained.sort_by(|a, b| a.path.cmp(&b.path));
    let canonical = manifest
        .canonical_value()
        .map_err(|e| ImportRefusal::refused("malformed_manifest", e.to_string()))?;
    let digest = crate::canonical_json::digest_json(&canonical);
    let receipt = Receipt {
        digest: digest.clone(),
        adapter: provenance.adapter.clone(),
        origin: provenance.origin.clone(),
        requested_ref: provenance.requested_ref.clone(),
        fetched_by: provenance.fetched_by,
        importer: provenance.importer.clone(),
        run_key: provenance.run_key.clone(),
        at: provenance.at.clone(),
    };
    Ok(ImportedRevision {
        manifest,
        canonical_manifest_bytes: crate::canonical_json::canonical_json(&canonical),
        digest,
        files: retained,
        receipt,
    })
}

/// P1a single-surface check for the bridge: exactly one surface
/// contribution, pointing at a file with role `surface_bundle` and
/// media type `text/html`. Returns the contribution and its file entry.
pub fn single_html_surface(
    manifest: &PackageManifestV2,
) -> Result<(&ContributionRef, &FileEntry), ImportRefusal> {
    if manifest.contributions.surfaces.len() != 1 {
        return Err(ImportRefusal::refused(
            "not_single_html_surface",
            format!(
                "P1a needs exactly one surface contribution, found {}",
                manifest.contributions.surfaces.len()
            ),
        ));
    }
    let contribution = &manifest.contributions.surfaces[0];
    let file = manifest
        .files
        .iter()
        .find(|f| f.path == contribution.file)
        .ok_or_else(|| {
            ImportRefusal::refused(
                "not_single_html_surface",
                format!("surface points at unlisted file '{}'", contribution.file),
            )
        })?;
    if file.role != "surface_bundle" || file.media_type != "text/html" {
        return Err(ImportRefusal::refused(
            "not_single_html_surface",
            format!(
                "surface file '{}' must have role surface_bundle and media type text/html",
                file.path
            ),
        ));
    }
    Ok((contribution, file))
}
#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = b"<!doctype html><html><body><h1>Pulse</h1></body></html>";

    fn manifest_json(body_sha: &str, body_len: u64) -> serde_json::Value {
        serde_json::json!({
            "format": "native.package-manifest@2",
            "namespace": "agent",
            "name": "team-pulse",
            "version": "0.1.0",
            "files": [{
                "path": "team-pulse.html",
                "sha256": body_sha,
                "bytes_len": body_len,
                "media_type": "text/html",
                "role": "surface_bundle",
            }],
            "contributions": {"surfaces": [{"name": "team-pulse", "file": "team-pulse.html"}]},
            "declared_reads": [],
            "declared_effects": [],
            "requires": [],
        })
    }

    fn candidate() -> ImportCandidate {
        ImportCandidate {
            manifest_bytes: serde_json::to_vec(&manifest_json(
                &sha256_hex(BODY),
                BODY.len() as u64,
            ))
            .unwrap(),
            files: BTreeMap::from([("team-pulse.html".to_string(), BODY.to_vec())]),
        }
    }

    fn provenance() -> ProvenanceInput {
        ProvenanceInput {
            adapter: "local_folder".into(),
            origin: serde_json::json!({"path": "/tmp/team-pulse"}),
            requested_ref: None,
            fetched_by: FetchedBy::Host,
            importer: "alice".into(),
            run_key: "rk-1".into(),
            at: "2026-09-26T00:00:00Z".into(),
        }
    }

    fn refuse(candidate: &ImportCandidate, provenance: &ProvenanceInput) -> ImportRefusal {
        import_candidate(candidate, provenance).unwrap_err()
    }

    #[test]
    fn accepts_valid_candidate_and_drops_unlisted() {
        let mut candidate = candidate();
        candidate
            .files
            .insert("evil.html".to_string(), b"<script/>".to_vec());
        let revision = import_candidate(&candidate, &provenance()).unwrap();
        assert_eq!(revision.digest, revision.manifest.package_digest().unwrap());
        assert_eq!(
            revision.canonical_manifest_bytes,
            crate::canonical_json::canonical_json(&revision.manifest.canonical_value().unwrap())
        );
        assert_eq!(revision.files.len(), 1);
        assert_eq!(revision.files[0].path, "team-pulse.html");
        assert_eq!(revision.files[0].bytes, BODY);
        assert_eq!(revision.receipt.digest, revision.digest);
        assert_eq!(revision.receipt.fetched_by, FetchedBy::Host);
    }

    #[test]
    fn identical_candidate_twice_identical_digest() {
        let first = import_candidate(&candidate(), &provenance()).unwrap();
        let second = import_candidate(&candidate(), &provenance()).unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(
            first.canonical_manifest_bytes,
            second.canonical_manifest_bytes
        );
    }

    #[test]
    fn receipt_is_not_in_digest() {
        let first = import_candidate(&candidate(), &provenance()).unwrap();
        let mut other = provenance();
        other.origin = serde_json::json!({"path": "/elsewhere"});
        other.at = "2026-09-27T00:00:00Z".into();
        other.fetched_by = FetchedBy::Client;
        other.requested_ref = Some("v1.0.0".into());
        let second = import_candidate(&candidate(), &other).unwrap();
        assert_eq!(first.digest, second.digest);
        assert_ne!(
            first.receipt.canonical_bytes(),
            second.receipt.canonical_bytes()
        );
    }

    #[test]
    fn claimed_hashes_never_trusted() {
        let mut bad = candidate();
        let mut value: serde_json::Value = serde_json::from_slice(&bad.manifest_bytes).unwrap();
        value["files"][0]["sha256"] =
            serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
        bad.manifest_bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(refuse(&bad, &provenance()).as_str(), "hash_mismatch");

        let mut bad = candidate();
        let mut value: serde_json::Value = serde_json::from_slice(&bad.manifest_bytes).unwrap();
        value["files"][0]["bytes_len"] = serde_json::json!(1);
        bad.manifest_bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(refuse(&bad, &provenance()).as_str(), "length_mismatch");

        let mut bad = candidate();
        bad.files.remove("team-pulse.html");
        assert_eq!(refuse(&bad, &provenance()).as_str(), "missing_file");
    }
    #[test]
    fn manifest_bytes_capped_at_boundary() {
        let base = candidate();
        // Trailing JSON whitespace pads to exactly the cap without changing
        // the parsed manifest.
        let mut padded = base.manifest_bytes.clone();
        padded.resize(MAX_MANIFEST_BYTES as usize, b' ');
        let exact = ImportCandidate {
            manifest_bytes: padded,
            files: base.files.clone(),
        };
        import_candidate(&exact, &provenance()).unwrap();
        let mut over = base.manifest_bytes.clone();
        over.resize(MAX_MANIFEST_BYTES as usize + 1, b' ');
        let refused = refuse(
            &ImportCandidate {
                manifest_bytes: over,
                files: base.files,
            },
            &provenance(),
        );
        assert_eq!(refused.as_str(), "manifest_too_large");
    }

    #[test]
    fn duplicate_keys_refused_not_silently_merged() {
        // Reviewer's case: byte-distinct manifests differing only in the
        // overwritten first duplicate must refuse, never share a digest.
        let base = candidate();
        let text = String::from_utf8(base.manifest_bytes.clone()).unwrap();
        let smuggled = text.replacen('{', r#"{"version": "9.9.9", "#, 1);
        assert_ne!(smuggled.as_bytes(), base.manifest_bytes.as_slice());
        let refused = refuse(
            &ImportCandidate {
                manifest_bytes: smuggled.into_bytes(),
                files: base.files.clone(),
            },
            &provenance(),
        );
        assert_eq!(refused.as_str(), "duplicate_key");
    }

    #[test]
    fn malformed_manifest_refused() {
        for bytes in [
            b"not json".to_vec(),
            b"[1, 2]".to_vec(),
            b"{}".to_vec(),
            serde_json::to_vec(&serde_json::json!({
                "format": "native.package-manifest@2",
                "namespace": "agent", "name": "x", "version": "0.1.0",
                "files": [], "bogus": true,
            }))
            .unwrap(),
        ] {
            let candidate = ImportCandidate {
                manifest_bytes: bytes,
                files: BTreeMap::new(),
            };
            assert_eq!(
                refuse(&candidate, &provenance()).as_str(),
                "malformed_manifest"
            );
        }
    }

    #[test]
    fn p1a_restrictions_have_own_tokens() {
        let mut with_effects = candidate();
        let mut value: serde_json::Value =
            serde_json::from_slice(&with_effects.manifest_bytes).unwrap();
        value["declared_effects"] = serde_json::json!(["task.triage-set.v1"]);
        with_effects.manifest_bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            refuse(&with_effects, &provenance()).as_str(),
            "effects_not_supported"
        );

        let mut with_requires = candidate();
        let mut value: serde_json::Value =
            serde_json::from_slice(&with_requires.manifest_bytes).unwrap();
        value["requires"] = serde_json::json!([{
            "namespace": "agent", "name": "other", "digest": sha256_hex(b"x"),
        }]);
        with_requires.manifest_bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            refuse(&with_requires, &provenance()).as_str(),
            "requires_not_supported"
        );
    }

    fn big_candidate(sizes: &[u64]) -> ImportCandidate {
        let entries: Vec<serde_json::Value> = sizes
            .iter()
            .enumerate()
            .map(|(i, len)| {
                let bytes = vec![i as u8; *len as usize];
                serde_json::json!({
                    "path": format!("f{i}.bin"),
                    "sha256": sha256_hex(&bytes),
                    "bytes_len": len,
                    "media_type": "application/octet-stream",
                    "role": "asset",
                })
            })
            .collect();
        let mut value = manifest_json(&sha256_hex(BODY), BODY.len() as u64);
        value["files"] = serde_json::Value::Array(entries);
        value["contributions"] = serde_json::json!({});
        let mut files = BTreeMap::new();
        for (i, len) in sizes.iter().enumerate() {
            files.insert(format!("f{i}.bin"), vec![i as u8; *len as usize]);
        }
        ImportCandidate {
            manifest_bytes: serde_json::to_vec(&value).unwrap(),
            files,
        }
    }

    #[test]
    fn caps_at_boundary() {
        import_candidate(&big_candidate(&[MAX_FILE_BYTES]), &provenance()).unwrap();
        let refused = refuse(&big_candidate(&[MAX_FILE_BYTES + 1]), &provenance());
        assert_eq!(refused.as_str(), "file_too_large");
        import_candidate(
            &big_candidate(&[MAX_FILE_BYTES, MAX_FILE_BYTES]),
            &provenance(),
        )
        .unwrap();
        let refused = refuse(
            &big_candidate(&[MAX_FILE_BYTES, 524_288, 524_289]),
            &provenance(),
        );
        assert_eq!(refused.as_str(), "revision_too_large");
    }

    #[test]
    fn single_html_surface_check() {
        let revision = import_candidate(&candidate(), &provenance()).unwrap();
        let (contribution, file) = single_html_surface(&revision.manifest).unwrap();
        assert_eq!(contribution.name, "team-pulse");
        assert_eq!(file.path, "team-pulse.html");

        let mut manifest = revision.manifest.clone();
        manifest.contributions.surfaces.clear();
        assert_eq!(
            single_html_surface(&manifest).unwrap_err().as_str(),
            "not_single_html_surface"
        );
        let mut manifest = revision.manifest.clone();
        manifest
            .contributions
            .surfaces
            .push(manifest.contributions.surfaces[0].clone());
        assert_eq!(
            single_html_surface(&manifest).unwrap_err().as_str(),
            "not_single_html_surface"
        );
        let mut manifest = revision.manifest.clone();
        manifest.files[0].role = "doc".into();
        assert_eq!(
            single_html_surface(&manifest).unwrap_err().as_str(),
            "not_single_html_surface"
        );
        let mut manifest = revision.manifest;
        manifest.files[0].role = "surface_bundle".into();
        manifest.files[0].media_type = "text/plain".into();
        assert_eq!(
            single_html_surface(&manifest).unwrap_err().as_str(),
            "not_single_html_surface"
        );
    }

    #[test]
    fn refusal_converts_to_engine_error() {
        let refusal = refuse(
            &ImportCandidate {
                manifest_bytes: b"{}".to_vec(),
                files: BTreeMap::new(),
            },
            &provenance(),
        );
        assert_eq!(refusal.as_str(), "malformed_manifest");
        let error: Error = refusal.into();
        assert!(error.to_string().contains("malformed_manifest"));
    }
}
