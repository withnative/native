//! Shared guarded credential-file read (D2 actual-adapter).
//!
//! Extracted from the standby refresh reader so the member-copy adapter reuses
//! one hardened read discipline without depending on the member-copy types.
//! Returns raw, zeroized token bytes; callers wrap as needed. Accept/reject
//! behavior, bounds and error wording for the standby caller are preserved
//! exactly by passing the same `label`.

use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Bound on a credential file; the reader never loads more.
pub(crate) const MAX_CREDENTIAL_BYTES: usize = 4096;

/// Read a credential file with the shared guards: absolute/unambiguous path,
/// no symlink traversal, owner-only and single-link (where supported),
/// metadata stability across open, bounded size, UTF-8, and a non-empty token
/// with no internal whitespace. Trailing CR/LF is stripped. Returns the token
/// bytes, zeroized on drop. `label` only parameterizes diagnostics.
pub(crate) fn read_guarded_credential(path: &Path, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    validate_credential_path(path, label)?;
    validate_credential_metadata(path, label)?;
    let before = fs::metadata(path)?;
    let file = File::open(path)?;
    let opened = file.metadata()?;
    let after = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || opened.dev() != after.dev()
            || opened.ino() != after.ino()
            || after.file_type().is_symlink()
        {
            return Err(Error::engine(format!(
                "{label} credential file changed while opening"
            )));
        }
    }
    let mut bytes = Vec::new();
    file.take((MAX_CREDENTIAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(Error::engine(format!(
            "{label} credential exceeded its bound"
        )));
    }
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| Error::engine(format!("{label} credential is not UTF-8")))?
        .trim_end_matches(['\r', '\n']);
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return Err(Error::engine(format!(
            "{label} credential is empty or contains whitespace"
        )));
    }
    Ok(Zeroizing::new(token.as_bytes().to_vec()))
}

pub(crate) fn validate_credential_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::engine(format!(
            "{label} credential_file must be absolute"
        )));
    }
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::Normal(name) => {
                resolved.push(name);
                match fs::symlink_metadata(&resolved) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(Error::engine(format!(
                            "{label} credential_file must not traverse symbolic links"
                        )));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(Error::engine(format!(
                    "{label} credential_file must be lexically unambiguous"
                )));
            }
        }
    }
    Ok(())
}

fn validate_credential_metadata(path: &Path, label: &str) -> Result<()> {
    require_regular_file(path, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = fs::metadata(path)?;
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(Error::engine(format!(
                "{label} credential file is not owner-only or is hard-linked"
            )));
        }
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::engine(format!(
            "{label} refresh path is not a regular non-symlink file"
        )));
    }
    Ok(())
}
