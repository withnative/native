//! Local-folder source adapter (task `1bf0e85`, P1a slice S3a).
//!
//! Reads `native-package.json` plus every listed file ONCE into memory and
//! returns an [`ImportCandidate`] for the pure importer (`super::import`).
//! The adapter never executes anything and never touches the network: it
//! takes only a directory path. Unlisted files are never read; no directory
//! walk happens — only the manifest-listed paths are joined and opened.
//!
//! Symlink safety: each listed file is opened once and then verified by
//! comparing an `lstat` of the path against the `fstat` of the opened
//! handle (`dev, ino`): a path that is (now) a symlink refuses with
//! `symlink`, a path naming a different file than the handle refuses with
//! `path_changed`. Regularity, single-link and length all come from the
//! handle, and the bounded read uses the same handle. `O_NOFOLLOW` (plus
//! `O_NONBLOCK` so a swapped-in FIFO cannot block the open) is requested
//! where the flag values are known — Linux x86_64/aarch64 and macOS — as
//! defence in depth only, never as the security boundary: flag numbers
//! differ per OS+arch and are absent elsewhere, while the `lstat`/`fstat`
//! comparison is portable across Unix. Platforms without known flag values
//! (anything but Linux x86_64/aarch64 and macOS) refuse the adapter entirely
//! (`unsupported_platform`). Parent directories get a best-effort
//! `symlink_metadata` walk first, and after opening the canonicalized
//! parent must still sit under the canonicalized root (`outside_root`).
//! Residual race: a parent swapped between the walk and the open can at
//! most substitute other bytes that are still hashed and digest-pinned; it
//! cannot smuggle unverified bytes past the digest. Acceptable for P1a: the
//! local folder is the importer's own source, and every retained byte is
//! hashed as read.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::import::{ImportCandidate, ImportRefusal};
use super::manifest_v2::{
    parse_manifest_json, ManifestJsonError, PackageManifestV2, MAX_FILE_BYTES, MAX_MANIFEST_BYTES,
};

/// The manifest filename inside a plugin folder (open choice O2, settled).
pub const MANIFEST_FILENAME: &str = "native-package.json";

/// One folder read: the import candidate plus its coordinate. The S2 digest
/// over the retained bytes is the coordinate's bytes digest: identical bytes
/// read from anywhere give the identical revision.
#[derive(Debug)]
pub struct LocalFolderRead {
    pub candidate: ImportCandidate,
    /// Canonicalized folder root the bytes were read from.
    pub root: PathBuf,
    /// sha256 over the listed `(path, bytes)` pairs in manifest order.
    pub bytes_digest: String,
}

impl LocalFolderRead {
    /// Provenance origin JSON for the import receipt.
    pub fn origin(&self) -> serde_json::Value {
        serde_json::json!({"path": self.root.to_string_lossy()})
    }
}

fn io_error(path: &Path, err: std::io::Error) -> ImportRefusal {
    ImportRefusal {
        reason: "io_error",
        detail: format!("{}: {err}", path.display()),
    }
}

/// Open flags per platform (`O_NOFOLLOW | O_NONBLOCK`), defence in depth
/// only — never the security boundary. Values differ per OS+arch (Linux
/// x86_64 is not Linux aarch64 is not macOS), so each known combination
/// names its own pair. `read_folder` refuses every other platform
/// (`unsupported_platform`) rather than open without `O_NONBLOCK`.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const OPEN_FLAGS: i32 = 0x20_000 | 0x800;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const OPEN_FLAGS: i32 = 0x8000 | 0x800;
#[cfg(target_os = "macos")]
const OPEN_FLAGS: i32 = 0x100 | 0x4;

/// `ELOOP` number per platform for the `O_NOFOLLOW` symlink trap
/// (`ErrorKind::FilesystemLoop` is still unstable).
#[cfg(target_os = "linux")]
const SYMLINK_LOOP_ERRNO: i32 = 40;
#[cfg(target_os = "macos")]
const SYMLINK_LOOP_ERRNO: i32 = 62;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_symlink_loop(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(SYMLINK_LOOP_ERRNO)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn is_symlink_loop(_error: &std::io::Error) -> bool {
    false
}

/// Open a path read-only, requesting `O_NOFOLLOW | O_NONBLOCK` where the
/// flag values are known for this platform.
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        target_os = "macos"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(OPEN_FLAGS);
    }
    options.open(path)
}

/// Portable open verification — the security boundary, not the flags:
/// `lstat` the path and compare `(dev, ino)` with the opened handle's
/// `fstat`. Refuses when the path is (now) a symlink or names a different
/// file than the handle. Regularity and single-link come from the handle.
/// Returns the handle length for the caller's cap check.
#[cfg(unix)]
fn verify_opened_file(
    joined: &Path,
    rel: &str,
    file: &std::fs::File,
) -> Result<u64, ImportRefusal> {
    use std::os::unix::fs::MetadataExt;
    let handle = file.metadata().map_err(|e| io_error(joined, e))?;
    let at_path = std::fs::symlink_metadata(joined).map_err(|e| io_error(joined, e))?;
    if at_path.file_type().is_symlink() {
        return Err(ImportRefusal {
            reason: "symlink",
            detail: format!("listed path '{rel}' is a symlink"),
        });
    }
    if (at_path.dev(), at_path.ino()) != (handle.dev(), handle.ino()) {
        return Err(ImportRefusal {
            reason: "path_changed",
            detail: format!("listed path '{rel}' changed between open and check"),
        });
    }
    if !handle.is_file() {
        return Err(ImportRefusal {
            reason: "not_a_file",
            detail: format!("listed path '{rel}' is not a regular file"),
        });
    }
    if handle.nlink() != 1 {
        return Err(ImportRefusal {
            reason: "hardlink",
            detail: format!("listed path '{rel}' is hard-linked"),
        });
    }
    Ok(handle.len())
}

#[cfg(not(unix))]
fn verify_opened_file(
    joined: &Path,
    rel: &str,
    file: &std::fs::File,
) -> Result<u64, ImportRefusal> {
    let handle = file.metadata().map_err(|e| io_error(joined, e))?;
    if std::fs::symlink_metadata(joined)
        .map_err(|e| io_error(joined, e))?
        .file_type()
        .is_symlink()
    {
        return Err(ImportRefusal {
            reason: "symlink",
            detail: format!("listed path '{rel}' is a symlink"),
        });
    }
    if !handle.is_file() {
        return Err(ImportRefusal {
            reason: "not_a_file",
            detail: format!("listed path '{rel}' is not a regular file"),
        });
    }
    Ok(handle.len())
}

/// Walk the parent components of a manifest-listed path with
/// `symlink_metadata`: best-effort traversal guard before the authoritative
/// single open. Returns the joined path (not canonicalized).
fn check_parent_components(root: &Path, rel: &str) -> Result<PathBuf, ImportRefusal> {
    let mut parts: Vec<&str> = rel.split('/').collect();
    parts.pop();
    let mut current = root.to_path_buf();
    for component in parts {
        current.push(component);
        let meta = std::fs::symlink_metadata(&current).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ImportRefusal {
                    reason: "missing_file",
                    detail: format!("listed file '{rel}' not submitted"),
                }
            } else {
                io_error(&current, e)
            }
        })?;
        if meta.file_type().is_symlink() {
            return Err(ImportRefusal {
                reason: "symlink",
                detail: format!("listed path '{rel}' traverses a symlink"),
            });
        }
    }
    Ok(root.join(rel))
}

/// Open one manifest-listed file exactly once and read it from that handle:
/// `lstat`-vs-`fstat` verification, length cap, canonical parent still under
/// the root, then a bounded read from the same handle.
fn open_listed_file(root: &Path, rel: &str, cap: u64) -> Result<Vec<u8>, ImportRefusal> {
    check_parent_components(root, rel)?;
    let joined = root.join(rel);
    let file = open_no_follow(&joined).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ImportRefusal {
                reason: "missing_file",
                detail: format!("listed file '{rel}' not submitted"),
            }
        } else if is_symlink_loop(&e) {
            ImportRefusal {
                reason: "symlink",
                detail: format!("listed path '{rel}' is a symlink"),
            }
        } else {
            io_error(&joined, e)
        }
    })?;
    let len = verify_opened_file(&joined, rel, &file)?;
    if len > cap {
        return Err(ImportRefusal {
            reason: "file_too_large",
            detail: format!("file '{rel}' is {len} bytes, over the cap"),
        });
    }
    let parent = joined.parent().unwrap_or(root);
    let canonical_parent = parent.canonicalize().map_err(|e| io_error(parent, e))?;
    if !canonical_parent.starts_with(root) {
        return Err(ImportRefusal {
            reason: "outside_root",
            detail: format!("listed path '{rel}' resolves outside the folder root"),
        });
    }
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(&joined, e))?;
    if bytes.len() as u64 > cap {
        return Err(ImportRefusal {
            reason: "file_too_large",
            detail: format!("file '{rel}' exceeds the cap"),
        });
    }
    Ok(bytes)
}
/// Read the manifest with a bounded reader: metadata pre-check plus a
/// `take(cap + 1)` read, so an oversized manifest is refused without
/// loading it — from the same single `O_NOFOLLOW` handle whose `fstat` is
/// checked (regular file, single link) before reading.
fn read_manifest_bytes(path: &Path) -> Result<Vec<u8>, ImportRefusal> {
    let file = open_no_follow(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ImportRefusal {
                reason: "manifest_missing",
                detail: format!("{} not found", path.display()),
            }
        } else if is_symlink_loop(&e) {
            ImportRefusal {
                reason: "symlink",
                detail: format!("{} is a symlink", path.display()),
            }
        } else {
            io_error(path, e)
        }
    })?;
    let len = verify_opened_file(path, MANIFEST_FILENAME, &file)?;
    if len > MAX_MANIFEST_BYTES {
        return Err(ImportRefusal {
            reason: "manifest_too_large",
            detail: format!("manifest is {len} bytes, over the cap"),
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(path, e))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(ImportRefusal {
            reason: "manifest_too_large",
            detail: "manifest exceeds the cap".to_string(),
        });
    }
    Ok(bytes)
}

/// Read a plugin folder into an import candidate. The root itself is
/// canonicalized; a root that is itself a symlink is refused — what matters
/// is that nothing *under* the resolution escapes.
pub fn read_folder(dir: &Path) -> Result<LocalFolderRead, ImportRefusal> {
    // Only platforms whose open flags are known: elsewhere a FIFO swapped in
    // after the listing could block the open itself, before any check runs.
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        target_os = "macos"
    )))]
    {
        return Err(ImportRefusal {
            reason: "unsupported_platform",
            detail: "local-folder import supports Linux x86_64/aarch64 and macOS".to_string(),
        });
    }
    if std::fs::symlink_metadata(dir)
        .map_err(|e| io_error(dir, e))?
        .file_type()
        .is_symlink()
    {
        return Err(ImportRefusal {
            reason: "symlink",
            detail: format!("folder root {} is a symlink", dir.display()),
        });
    }
    let root = dir.canonicalize().map_err(|e| io_error(dir, e))?;
    let manifest_path = root.join(MANIFEST_FILENAME);
    let manifest_bytes = read_manifest_bytes(&manifest_path)?;
    let value = parse_manifest_json(&manifest_bytes).map_err(|e| match e {
        ManifestJsonError::DuplicateKey(detail) => ImportRefusal {
            reason: "duplicate_key",
            detail,
        },
        ManifestJsonError::Malformed(detail) => ImportRefusal {
            reason: "malformed_manifest",
            detail,
        },
    })?;
    let manifest = PackageManifestV2::from_json_value(&value).map_err(|e| ImportRefusal {
        reason: "malformed_manifest",
        detail: e.to_string(),
    })?;
    let mut files = BTreeMap::new();
    let mut coordinate = Sha256::new();
    for entry in &manifest.files {
        let bytes = open_listed_file(&root, &entry.path, MAX_FILE_BYTES)?;
        coordinate.update(entry.path.as_bytes());
        coordinate.update([0x00]);
        coordinate.update(&bytes);
        files.insert(entry.path.clone(), bytes);
    }
    Ok(LocalFolderRead {
        candidate: ImportCandidate {
            manifest_bytes,
            files,
        },
        root,
        bytes_digest: hex::encode(coordinate.finalize()),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    const BODY: &[u8] = b"<!doctype html><html><body><h1>Pulse</h1></body></html>";

    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// Write a folder: manifest listing `files` plus each file's bytes.
    /// Returns the manifest bytes for candidate cross-checks.
    fn write_folder(dir: &Path, entries: &[(&str, Vec<u8>, &str, &str)]) -> Vec<u8> {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|(path, bytes, media, role)| {
                std::fs::write(dir.join(path), bytes).unwrap();
                json!({
                    "path": path,
                    "sha256": sha(bytes),
                    "bytes_len": bytes.len(),
                    "media_type": media,
                    "role": role,
                })
            })
            .collect();
        let surface = entries
            .iter()
            .find(|(_, _, media, role)| *media == "text/html" && *role == "surface_bundle")
            .map(|(path, _, _, _)| json!({"surfaces": [{"name": "team-pulse", "file": path}]}))
            .unwrap_or_else(|| json!({}));
        let manifest = json!({
            "format": "native.package-manifest@2",
            "namespace": "agent",
            "name": "team-pulse",
            "version": "0.1.0",
            "files": items,
            "contributions": surface,
            "declared_reads": [],
            "declared_effects": [],
            "requires": [],
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let mut file = std::fs::File::create(dir.join(MANIFEST_FILENAME)).unwrap();
        file.write_all(&bytes).unwrap();
        bytes
    }

    fn single_file_folder(dir: &Path) {
        write_folder(
            dir,
            &[(
                "team-pulse.html",
                BODY.to_vec(),
                "text/html",
                "surface_bundle",
            )],
        );
    }

    #[test]
    fn happy_path_reads_listed_only_and_coordinate_stable() {
        let dir = tempfile::tempdir().unwrap();
        single_file_folder(dir.path());
        std::fs::write(dir.path().join("unlisted.txt"), b"never read").unwrap();
        let first = read_folder(dir.path()).unwrap();
        assert_eq!(first.candidate.files.len(), 1);
        assert_eq!(first.candidate.files["team-pulse.html"], BODY);
        assert_eq!(first.origin()["path"], json!(first.root.to_string_lossy()));
        let mut coordinate = Sha256::new();
        coordinate.update(b"team-pulse.html");
        coordinate.update([0x00]);
        coordinate.update(BODY);
        assert_eq!(first.bytes_digest, hex::encode(coordinate.finalize()));
        let second = read_folder(dir.path()).unwrap();
        assert_eq!(second.bytes_digest, first.bytes_digest);
        assert_eq!(
            second.candidate.manifest_bytes,
            first.candidate.manifest_bytes
        );
    }

    #[test]
    fn missing_and_oversized_manifest_refused() {
        let dir = tempfile::tempdir().unwrap();
        let refusal = read_folder(dir.path()).unwrap_err();
        assert_eq!(refusal.reason, "manifest_missing");
        let mut file = std::fs::File::create(dir.path().join(MANIFEST_FILENAME)).unwrap();
        file.write_all(&vec![b'x'; MAX_MANIFEST_BYTES as usize + 1])
            .unwrap();
        let refusal = read_folder(dir.path()).unwrap_err();
        assert_eq!(refusal.reason, "manifest_too_large");
    }

    #[test]
    fn symlinked_manifest_refused_at_open() {
        use std::os::unix::fs::symlink;
        let outer = tempfile::tempdir().unwrap();
        std::fs::write(outer.path().join("real.json"), b"{}").unwrap();
        let dir = outer.path().join("folder");
        std::fs::create_dir(&dir).unwrap();
        symlink(outer.path().join("real.json"), dir.join(MANIFEST_FILENAME)).unwrap();
        let refusal = read_folder(&dir).unwrap_err();
        assert_eq!(refusal.reason, "symlink");
    }

    #[test]
    fn missing_listed_file_refused() {
        let dir = tempfile::tempdir().unwrap();
        write_folder(dir.path(), &[]);
        // Manifest with zero files is itself invalid; write one listing a
        // ghost file instead.
        let ghost = json!({
            "format": "native.package-manifest@2",
            "namespace": "agent", "name": "team-pulse", "version": "0.1.0",
            "files": [{
                "path": "ghost.html", "sha256": sha(b"x"),
                "bytes_len": 1, "media_type": "text/html", "role": "surface_bundle",
            }],
        });
        std::fs::write(
            dir.path().join(MANIFEST_FILENAME),
            serde_json::to_vec(&ghost).unwrap(),
        )
        .unwrap();
        let refusal = read_folder(dir.path()).unwrap_err();
        assert_eq!(refusal.reason, "missing_file");
    }

    #[test]
    fn symlinks_refused_at_every_level() {
        use std::os::unix::fs::symlink;
        // Symlinked root.
        let outer = tempfile::tempdir().unwrap();
        let real = outer.path().join("real");
        std::fs::create_dir(&real).unwrap();
        single_file_folder(&real);
        let link = outer.path().join("link");
        symlink(&real, &link).unwrap();
        assert_eq!(read_folder(&link).unwrap_err().reason, "symlink");
        // Symlinked listed file.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real.html"), BODY).unwrap();
        symlink(
            dir.path().join("real.html"),
            dir.path().join("team-pulse.html"),
        )
        .unwrap();
        let manifest = json!({
            "format": "native.package-manifest@2",
            "namespace": "agent", "name": "team-pulse", "version": "0.1.0",
            "files": [{
                "path": "team-pulse.html", "sha256": sha(BODY),
                "bytes_len": BODY.len(), "media_type": "text/html",
                "role": "surface_bundle",
            }],
        });
        std::fs::write(
            dir.path().join(MANIFEST_FILENAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(read_folder(dir.path()).unwrap_err().reason, "symlink");
        // Symlinked parent dir of a listed path.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("f.html"), BODY).unwrap();
        symlink(&target, dir.path().join("sub")).unwrap();
        let manifest = json!({
            "format": "native.package-manifest@2",
            "namespace": "agent", "name": "team-pulse", "version": "0.1.0",
            "files": [{
                "path": "sub/f.html", "sha256": sha(BODY),
                "bytes_len": BODY.len(), "media_type": "text/html",
                "role": "surface_bundle",
            }],
        });
        std::fs::write(
            dir.path().join(MANIFEST_FILENAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(read_folder(dir.path()).unwrap_err().reason, "symlink");
    }

    #[test]
    fn outside_root_and_not_a_file() {
        let outer = tempfile::tempdir().unwrap();
        let rootdir = outer.path().join("root");
        std::fs::create_dir(&rootdir).unwrap();
        std::fs::write(outer.path().join("outside.txt"), b"x").unwrap();
        std::fs::create_dir(rootdir.join("subdir")).unwrap();
        let root = rootdir.canonicalize().unwrap();
        let refusal = open_listed_file(&root, "../outside.txt", MAX_FILE_BYTES).unwrap_err();
        assert_eq!(refusal.reason, "outside_root");
        let refusal = open_listed_file(&root, "subdir", MAX_FILE_BYTES).unwrap_err();
        assert_eq!(refusal.reason, "not_a_file");
    }

    /// The portable refusal path: `lstat`-vs-`fstat` comparison, independent
    /// of `O_NOFOLLOW` flag values.
    #[test]
    #[cfg(unix)]
    fn opened_file_verification_compares_lstat_to_handle() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.bin");
        std::fs::write(&real, b"bytes").unwrap();
        let other = dir.path().join("other.bin");
        std::fs::write(&other, b"other!").unwrap();
        // Matching path and handle verifies with the handle length.
        let file = open_no_follow(&real).unwrap();
        assert_eq!(verify_opened_file(&real, "real.bin", &file).unwrap(), 5);
        // A path that lstat-reports as a symlink refuses, whatever handle.
        let link = dir.path().join("link.bin");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let refusal = verify_opened_file(&link, "link.bin", &file).unwrap_err();
        assert_eq!(refusal.reason, "symlink");
        // A handle for a different file than the path refuses as changed.
        let refusal = verify_opened_file(&other, "other.bin", &file).unwrap_err();
        assert_eq!(refusal.reason, "path_changed");
    }

    #[test]
    fn hardlinked_file_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("original.bin"), b"shared inode").unwrap();
        std::fs::hard_link(
            dir.path().join("original.bin"),
            dir.path().join("linked.bin"),
        )
        .unwrap();
        let root = dir.path().canonicalize().unwrap();
        let refusal = open_listed_file(&root, "linked.bin", MAX_FILE_BYTES).unwrap_err();
        assert_eq!(refusal.reason, "hardlink");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fifo_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(dir.path().join("pipe.bin"))
            .status()
            .expect("mkfifo must exist to test FIFO refusal");
        assert!(status.success());
        let root = dir.path().canonicalize().unwrap();
        let refusal = open_listed_file(&root, "pipe.bin", MAX_FILE_BYTES).unwrap_err();
        assert_eq!(refusal.reason, "not_a_file");
    }

    #[test]
    fn oversized_file_refused_before_full_read() {
        let dir = tempfile::tempdir().unwrap();
        let big = vec![7u8; MAX_FILE_BYTES as usize + 1];
        write_folder(
            dir.path(),
            &[("big.bin", big, "application/octet-stream", "asset")],
        );
        let refusal = read_folder(dir.path()).unwrap_err();
        assert_eq!(refusal.reason, "file_too_large");
    }
}
