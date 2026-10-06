//! Advisor installs and install sources (S4).
//!
//! An [`Install`] is one validated `advisor.json` manifest plus its digest,
//! enabled flag, and where it came from. [`InstallSource`] separates *where
//! installs come from* from *what an install is*: [`ConfigDirSource`] reads a
//! local directory now; a future `NativeRecordSource` (S8) produces the same
//! shape with no contract change.

use std::path::{Path, PathBuf};

use crate::mcp::advisors::manifest::{parse_manifest, AdvisorManifest};

/// Where an install came from. `ConfigDir` is the S4 MVP; `NativeRecord` is
/// reserved for S8 so stored installs can round-trip through this shape;
/// `Default` is the engine's built-in install set (S3 long-record nudge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallSourceKind {
    ConfigDir,
    NativeRecord,
    Default,
}

impl std::fmt::Display for InstallSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigDir => write!(f, "config_dir"),
            Self::NativeRecord => write!(f, "native_record"),
            Self::Default => write!(f, "default"),
        }
    }
}

/// One validated advisor manifest, ready to activate.
#[derive(Debug, Clone)]
pub struct Install {
    pub advisor_id: String,
    pub version: String,
    pub manifest_digest: String,
    pub manifest: AdvisorManifest,
    /// The raw validated JSON exactly as loaded. The digest pins these bytes
    /// (unknown fields and explicit nulls included), and this is the value a
    /// future record-backed source stores verbatim.
    pub manifest_raw: serde_json::Value,
    pub enabled: bool,
    pub source: InstallSourceKind,
}

/// Something installs can be listed from. Synchronous: sources read local
/// state (a directory now, records later), never the network.
pub trait InstallSource {
    fn list(&self) -> crate::error::Result<Vec<Install>>;
}

/// Env var pointing at the advisors config directory.
pub const ADVISORS_DIR_ENV: &str = "NATIVE_ADVISORS_DIR";

/// Reads `<dir>/<anything>/advisor.json`. Invalid manifests are logged and
/// skipped, never fatal; disabled installs are listed but not activated.
pub struct ConfigDirSource {
    dir: PathBuf,
}

impl ConfigDirSource {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// `None` when the env var is unset or empty (today's behaviour).
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var(ADVISORS_DIR_ENV).ok()?;
        if raw.trim().is_empty() {
            return None;
        }
        Some(Self::new(raw))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl InstallSource for ConfigDirSource {
    fn list(&self) -> crate::error::Result<Vec<Install>> {
        let mut installs = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(
                    target: "native::advisors",
                    dir = %self.dir.display(),
                    error = %error,
                    "advisors dir unreadable; no advisors installed"
                );
                return Ok(Vec::new());
            }
        };
        let mut names: Vec<String> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            names.push(path.to_string_lossy().into_owned());
        }
        names.sort();
        // (folder, install): folders are visited in sorted order, so the
        // first folder wins any duplicate id below.
        let mut found: Vec<(String, Install)> = Vec::new();
        for name in names {
            let file = Path::new(&name).join("advisor.json");
            if !file.is_file() {
                continue;
            }
            if let Some(install) = self.load_one(&file) {
                found.push((name, install));
            }
        }
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (folder, install) in found {
            if !seen.insert(install.advisor_id.clone()) {
                tracing::warn!(
                    target: "native::advisors",
                    advisor_id = install.advisor_id.as_str(),
                    folder = folder.as_str(),
                    "duplicate advisor id; keeping the first folder in sorted order"
                );
                continue;
            }
            installs.push(install);
        }
        installs.sort_by(|left: &Install, right: &Install| {
            left.advisor_id
                .cmp(&right.advisor_id)
                .then(left.version.cmp(&right.version))
        });
        Ok(installs)
    }
}

impl ConfigDirSource {
    fn load_one(&self, file: &Path) -> Option<Install> {
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(error) => {
                tracing::warn!(
                    target: "native::advisors",
                    path = %file.display(),
                    error = %error,
                    "advisor manifest unreadable; skipping"
                );
                return None;
            }
        };
        match parse_manifest(&text) {
            Ok(parsed) => Some(Install {
                advisor_id: parsed.manifest.id.clone(),
                version: parsed.manifest.version.clone(),
                manifest_digest: parsed.digest,
                enabled: parsed.manifest.enabled,
                manifest: parsed.manifest,
                manifest_raw: parsed.raw,
                source: InstallSourceKind::ConfigDir,
            }),
            Err(reason) => {
                tracing::warn!(
                    target: "native::advisors",
                    path = %file.display(),
                    reason = %reason,
                    "invalid advisor manifest; skipping"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_json(id: &str, enabled: bool) -> String {
        serde_json::json!({
            "id": id,
            "version": "0.1.0",
            "description": "test advisor",
            "endpoint": "builtin:test",
            "watches": {"tools": ["update_record"], "types": ["WorkItem"], "kinds": ["*"]},
            "context": ["body_chars_after"],
            "budget_ms": 150,
            "enabled": enabled
        })
        .to_string()
    }

    fn write_install(dir: &Path, name: &str, contents: &str) {
        let sub = dir.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("advisor.json"), contents).unwrap();
    }

    #[test]
    fn config_dir_load_valid_invalid_skipped_disabled_listed() {
        let dir = tempfile::tempdir().unwrap();
        write_install(dir.path(), "good", &manifest_json("a.good", true));
        write_install(dir.path(), "off", &manifest_json("b.off", false));
        write_install(dir.path(), "bad", "{ not json");
        std::fs::create_dir_all(dir.path().join("empty")).unwrap();
        let source = ConfigDirSource::new(dir.path());
        let installs = source.list().unwrap();
        assert_eq!(installs.len(), 2);
        assert_eq!(installs[0].advisor_id, "a.good");
        assert!(installs[0].enabled);
        assert_eq!(installs[1].advisor_id, "b.off");
        assert!(!installs[1].enabled);
        assert!(!installs[0].manifest_digest.is_empty());
    }

    #[test]
    fn missing_dir_lists_nothing() {
        let source = ConfigDirSource::new("/nonexistent-advisors-dir-xyz");
        assert!(source.list().unwrap().is_empty());
    }

    #[test]
    fn duplicate_ids_first_sorted_folder_wins() {
        let dir = tempfile::tempdir().unwrap();
        write_install(dir.path(), "b-second", &manifest_json("dup.id", true));
        write_install(dir.path(), "a-first", &manifest_json("dup.id", true));
        let installs = ConfigDirSource::new(dir.path()).list().unwrap();
        assert_eq!(installs.len(), 1);
        assert_eq!(installs[0].advisor_id, "dup.id");
    }

    #[test]
    fn digest_pins_raw_bytes_including_unknown_fields() {
        use crate::mcp::advisors::manifest::digest_value;
        let dir = tempfile::tempdir().unwrap();
        let raw = serde_json::json!({
            "id": "raw.pin",
            "version": "0.1.0",
            "description": "raw",
            "endpoint": "builtin:test",
            "watches": {"tools": ["update_record"], "types": ["*"], "kinds": ["*"]},
            "context": [],
            "budget_ms": 150,
            "enabled": true,
            "settings": null,
            "future_field": "must still pin",
        });
        write_install(dir.path(), "only", &raw.to_string());
        let installs = ConfigDirSource::new(dir.path()).list().unwrap();
        assert_eq!(installs.len(), 1);
        assert_eq!(installs[0].manifest_digest, digest_value(&raw));
        assert_eq!(installs[0].manifest_raw, raw);
    }
}
