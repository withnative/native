//! Plugin package manifest `@2` (task `1bf0e85`, P1a slice S1: pure only).
//!
//! Unlike `crate::package_manifest` (`native.package-manifest@1`, gated
//! `cfg(any(test, feature = "v2-kernel-probe"))`), this module is UNGATED:
//! P1a is reachable from the default v1 alpha build, so everything the
//! importer, adapter and v1 bridge need lives under `crate::plugins`. `@1`
//! is untouched; the only shared code is `crate::canonical_json`.
//!
//! Digest convention follows @1, not alpha tabs:
//! [`PackageManifestV2::package_digest`] is bare lowercase hex SHA-256 over
//! the RFC 8785 JCS bytes of [`PackageManifestV2::canonical_value`] (no
//! `sha256:` prefix; alpha's `alpha-tab-digest.v1` keeps its own prefix).
//!
//! `version` is a strict semver string, validated by hand: `semver` is only
//! a transitive dependency (via `Cargo.lock`), so no new crate is added.
//!
//! Files are canonically ordered by `path` (byte order) before digesting:
//! declaration order never affects identity. Byte caps are named here but
//! enforced by the importer (S2), which compares claimed against actual
//! bytes; only the file-count cap is structural to the manifest itself.

use crate::error::{Error, Result};

/// Envelope format marker for the @2 canonical manifest value.
pub const MANIFEST_FORMAT_V2: &str = "native.package-manifest@2";
/// Package digest construction: bare lowercase hex SHA-256 over JCS bytes.
pub const PACKAGE_DIGEST_ALGORITHM: &str = "sha256-jcs";
/// Largest `native-package.json` byte length the importer accepts.
/// Checked against the submitted bytes before JSON parsing.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
/// Largest single file a revision may carry (enforced by the importer, S2).
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Largest total file payload a revision may carry (enforced by the importer, S2).
pub const MAX_REVISION_BYTES: u64 = 2 * 1024 * 1024;
/// Most files a revision may list.
pub const MAX_FILES: usize = 32;
/// Longest file path in bytes.
pub const MAX_PATH_BYTES: usize = 256;
/// Longest semver version string in bytes.
pub const MAX_VERSION_LEN: usize = 64;

const MAX_PART_LEN: usize = 128;
const MAX_READ_LEN: usize = 128;
const MAX_MEDIA_TYPE_LEN: usize = 128;

/// Roles a listed file may carry.
pub const FILE_ROLES: &[&str] = &[
    "surface_bundle",
    "definition",
    "advisor_code",
    "test",
    "doc",
    "asset",
];

fn validate_part(kind: &str, part: &str) -> Result<()> {
    if part.is_empty() || part.len() > MAX_PART_LEN {
        return Err(Error::engine(format!(
            "package manifest @2 {kind} must be 1..{MAX_PART_LEN} bytes"
        )));
    }
    if !part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(Error::engine(format!(
            "package manifest @2 {kind} '{part}' must match [A-Za-z0-9._-]"
        )));
    }
    let bytes = part.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(Error::engine(format!(
            "package manifest @2 {kind} '{part}' must start and end with an ASCII alphanumeric"
        )));
    }
    Ok(())
}

fn validate_read_scope(scope: &str) -> Result<()> {
    if scope.is_empty() || scope.len() > MAX_READ_LEN {
        return Err(Error::engine(format!(
            "package manifest @2 read scope must be 1..{MAX_READ_LEN} bytes"
        )));
    }
    if !scope.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == ':' || c == '/'
    }) {
        return Err(Error::engine(format!(
            "package manifest @2 read scope '{scope}' must match [A-Za-z0-9._:/-]"
        )));
    }
    Ok(())
}
fn valid_dot_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_core_num(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|b| b.is_ascii_digit())
        && (part.len() == 1 || !part.starts_with('0'))
}

/// Strict semver (semver.org 2.0.0): `X.Y.Z` numeric core without leading
/// zeroes, optional `-prerelease` and `+build` dot-separated identifiers.
fn validate_semver(version: &str) -> Result<()> {
    let bad = || {
        Error::engine(format!(
            "package manifest @2 version '{version}' is not strict semver (X.Y.Z[-prerelease][+build])"
        ))
    };
    if version.is_empty() || version.len() > MAX_VERSION_LEN {
        return Err(bad());
    }
    let (without_build, build) = match version.split_once('+') {
        Some((v, b)) => (v, Some(b)),
        None => (version, None),
    };
    if let Some(b) = build {
        if !b.split('.').all(valid_dot_id) {
            return Err(bad());
        }
    }
    let (core, pre) = match without_build.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (without_build, None),
    };
    if let Some(p) = pre {
        for id in p.split('.') {
            if !valid_dot_id(id) {
                return Err(bad());
            }
            if id.bytes().all(|b| b.is_ascii_digit()) && id.len() > 1 && id.starts_with('0') {
                return Err(bad());
            }
        }
    }
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 || !parts.iter().all(|p| valid_core_num(p)) {
        return Err(bad());
    }
    Ok(())
}

/// Relative, normalised ASCII paths only: non-ASCII spellings can alias on
/// case-insensitive or normalizing filesystems while digesting distinctly,
/// so P1a refuses them outright (`non_ascii_path`). Refusal reasons are
/// stable tokens the importer (S2) and tests match on.
fn validate_file_path(path: &str) -> Result<()> {
    let reason = |token: &str| {
        Error::engine(format!(
            "package manifest @2 file path '{path}' refused: {token}"
        ))
    };
    if path.is_empty() {
        return Err(reason("empty_path"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(reason("path_too_long"));
    }
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(reason("control_char"));
    }
    if path.bytes().any(|b| b >= 0x80) {
        return Err(reason("non_ascii_path"));
    }
    if path.contains('\\') {
        return Err(reason("backslash"));
    }
    if path.starts_with('/') {
        return Err(reason("absolute_path"));
    }
    if let Some(head) = path.as_bytes().get(..2) {
        if head[0].is_ascii_alphabetic() && head[1] == b':' {
            return Err(reason("drive_prefix"));
        }
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(reason("empty_segment"));
        }
        if segment == "." {
            return Err(reason("dot_segment"));
        }
        if segment == ".." {
            return Err(reason("parent_escape"));
        }
    }
    Ok(())
}
fn validate_hex_digest(what: &str, digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::engine(format!(
            "package manifest @2 {what} must be 64 lowercase hex characters"
        )));
    }
    Ok(())
}

/// One file retained in the revision. The host serves ONLY listed files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub bytes_len: u64,
    pub media_type: String,
    pub role: String,
}

impl FileEntry {
    pub fn validate(&self) -> Result<()> {
        validate_file_path(&self.path)?;
        validate_hex_digest("file sha256", &self.sha256)?;
        if self.media_type.is_empty()
            || self.media_type.len() > MAX_MEDIA_TYPE_LEN
            || !self.media_type.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || !self.media_type.contains('/')
        {
            return Err(Error::engine(format!(
                "package manifest @2 media type '{}' must be 1..{MAX_MEDIA_TYPE_LEN} printable ASCII bytes containing '/'",
                self.media_type
            )));
        }
        if !FILE_ROLES.contains(&self.role.as_str()) {
            return Err(Error::engine(format!(
                "package manifest @2 file role '{}' must be one of {}",
                self.role,
                FILE_ROLES.join(", ")
            )));
        }
        Ok(())
    }
}

/// One named contribution pointing at a listed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionRef {
    pub name: String,
    pub file: String,
}

/// Definitions, behaviours and surfaces, each pointing at listed files.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Contributions {
    pub definitions: Vec<ContributionRef>,
    pub behaviours: Vec<ContributionRef>,
    pub surfaces: Vec<ContributionRef>,
}

/// Declared reads and effects. Effects must stay empty in P1a (see
/// [`PackageManifestV2::check_p1a_restrictions`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Declared {
    pub reads: Vec<String>,
    pub effects: Vec<String>,
}

/// One exact dependency. Declared and checked, never solved; must stay
/// empty in P1a.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub namespace: String,
    pub name: String,
    pub digest: String,
}

impl Requirement {
    pub fn validate(&self) -> Result<()> {
        validate_part("namespace", &self.namespace)?;
        validate_part("name", &self.name)?;
        validate_hex_digest("requirement digest", &self.digest)?;
        Ok(())
    }
}
/// The @2 canonical manifest: namespaced triple plus semver version,
/// listed files, contributions, declared reads/effects and requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageManifestV2 {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub files: Vec<FileEntry>,
    pub contributions: Contributions,
    pub declared: Declared,
    pub requires: Vec<Requirement>,
}

impl PackageManifestV2 {
    pub fn validate(&self) -> Result<()> {
        validate_part("namespace", &self.namespace)?;
        validate_part("name", &self.name)?;
        validate_semver(&self.version)?;
        if self.files.is_empty() {
            return Err(Error::engine(
                "package manifest @2 must list at least one file".to_string(),
            ));
        }
        if self.files.len() > MAX_FILES {
            return Err(Error::engine(format!(
                "package manifest @2 lists {} files, over the cap of {MAX_FILES}",
                self.files.len()
            )));
        }
        for entry in &self.files {
            entry.validate()?;
        }
        for (i, a) in self.files.iter().enumerate() {
            if self.files[..i].iter().any(|b| b.path == a.path) {
                return Err(Error::engine(format!(
                    "package manifest @2 file path '{}' is listed twice",
                    a.path
                )));
            }
            if self.files[..i]
                .iter()
                .any(|b| b.path.eq_ignore_ascii_case(&a.path))
            {
                return Err(Error::engine(format!(
                    "package manifest @2 file path '{}' refused: case_fold_duplicate",
                    a.path
                )));
            }
        }
        let listed = |file: &str| self.files.iter().any(|e| e.path == file);
        for (list, entry) in self
            .contributions
            .definitions
            .iter()
            .map(|c| ("definitions", c))
            .chain(
                self.contributions
                    .behaviours
                    .iter()
                    .map(|c| ("behaviours", c)),
            )
            .chain(self.contributions.surfaces.iter().map(|c| ("surfaces", c)))
        {
            validate_part("contribution name", &entry.name)?;
            if !listed(&entry.file) {
                return Err(Error::engine(format!(
                    "package manifest @2 {list} contribution '{}' points at unlisted file '{}'",
                    entry.name, entry.file
                )));
            }
        }
        for scope in &self.declared.reads {
            validate_read_scope(scope)?;
        }
        for (i, a) in self.declared.reads.iter().enumerate() {
            if self.declared.reads[..i].iter().any(|b| b == a) {
                return Err(Error::engine(format!(
                    "package manifest @2 duplicate declared read '{a}' refused: duplicate_declared"
                )));
            }
        }
        for scope in &self.declared.effects {
            validate_read_scope(scope)?;
        }
        for (i, a) in self.declared.effects.iter().enumerate() {
            if self.declared.effects[..i].iter().any(|b| b == a) {
                return Err(Error::engine(format!(
                    "package manifest @2 duplicate declared effect '{a}' refused: duplicate_declared"
                )));
            }
        }
        for requirement in &self.requires {
            requirement.validate()?;
        }
        Ok(())
    }

    /// P1a gate: effects and requirements parse, but any non-empty set is
    /// refused. Called by the importer (S2) after [`Self::validate`].
    pub fn check_p1a_restrictions(&self) -> Result<()> {
        if !self.declared.effects.is_empty() {
            return Err(Error::engine(
                "package manifest @2 refused: p1a_effects_not_empty".to_string(),
            ));
        }
        if !self.requires.is_empty() {
            return Err(Error::engine(
                "package manifest @2 refused: p1a_requires_not_empty".to_string(),
            ));
        }
        Ok(())
    }
}
fn sorted_contributions(list: &[ContributionRef]) -> Vec<serde_json::Value> {
    let mut refs: Vec<&ContributionRef> = list.iter().collect();
    refs.sort_by(|a, b| (&a.name, &a.file).cmp(&(&b.name, &b.file)));
    refs.iter()
        .map(|c| serde_json::json!({"file": c.file, "name": c.name}))
        .collect()
}

impl PackageManifestV2 {
    /// Canonical JCS value this package digests over. Object keys are fixed;
    /// `serde_jcs` sorts them. Semantically unordered arrays are sorted here
    /// because JCS preserves array order: files by `path`, contributions by
    /// `(name, file)`, reads/effects/requirements lexicographically — so
    /// declaration order never affects identity.
    pub fn canonical_value(&self) -> Result<serde_json::Value> {
        self.validate()?;
        let mut files: Vec<&FileEntry> = self.files.iter().collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let files: Vec<serde_json::Value> = files
            .iter()
            .map(|f| {
                serde_json::json!({
                    "bytes_len": f.bytes_len,
                    "media_type": f.media_type,
                    "path": f.path,
                    "role": f.role,
                    "sha256": f.sha256,
                })
            })
            .collect();
        let mut reads = self.declared.reads.clone();
        reads.sort();
        let mut effects = self.declared.effects.clone();
        effects.sort();
        let mut requires = self.requires.clone();
        requires.sort_by(|a, b| {
            (&a.namespace, &a.name, &a.digest).cmp(&(&b.namespace, &b.name, &b.digest))
        });
        let requires: Vec<serde_json::Value> = requires
            .iter()
            .map(|r| {
                serde_json::json!({
                    "digest": r.digest,
                    "name": r.name,
                    "namespace": r.namespace,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "contributions": {
                "behaviours": sorted_contributions(&self.contributions.behaviours),
                "definitions": sorted_contributions(&self.contributions.definitions),
                "surfaces": sorted_contributions(&self.contributions.surfaces),
            },
            "declared_effects": effects,
            "declared_reads": reads,
            "files": files,
            "format": MANIFEST_FORMAT_V2,
            "name": self.name,
            "namespace": self.namespace,
            "requires": requires,
            "version": self.version,
        }))
    }

    /// Package digest: bare lowercase hex SHA-256 over the RFC 8785 JCS
    /// bytes of [`Self::canonical_value`], via the shared canonicalizer.
    pub fn package_digest(&self) -> Result<String> {
        Ok(crate::canonical_json::digest_json(&self.canonical_value()?))
    }

    pub fn identity(&self) -> Result<ManifestIdentityV2> {
        Ok(ManifestIdentityV2 {
            namespace: self.namespace.clone(),
            name: self.name.clone(),
            version: self.version.clone(),
            digest: self.package_digest()?,
        })
    }
}

/// Identity of one @2 package revision: triple plus package digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestIdentityV2 {
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub digest: String,
}

impl ManifestIdentityV2 {
    /// Same `(namespace, name, version)` triple, ignoring digest.
    pub fn triple_eq(&self, other: &ManifestIdentityV2) -> bool {
        self.namespace == other.namespace
            && self.name == other.name
            && self.version == other.version
    }
}

/// Pure collision rule: same triple but different package digests refuses.
pub fn is_triple_collision(existing: &ManifestIdentityV2, candidate: &ManifestIdentityV2) -> bool {
    existing.triple_eq(candidate) && existing.digest != candidate.digest
}
fn get_str(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<String> {
    match obj.get(key) {
        Some(serde_json::Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(Error::engine(format!(
            "package manifest @2 field '{key}' must be a string"
        ))),
        None => Err(Error::engine(format!(
            "package manifest @2 missing field '{key}'"
        ))),
    }
}

fn get_u64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<u64> {
    match obj.get(key) {
        Some(serde_json::Value::Number(value)) => value.as_u64().ok_or_else(|| {
            Error::engine(format!(
                "package manifest @2 field '{key}' must be a non-negative integer"
            ))
        }),
        Some(_) => Err(Error::engine(format!(
            "package manifest @2 field '{key}' must be a non-negative integer"
        ))),
        None => Err(Error::engine(format!(
            "package manifest @2 missing field '{key}'"
        ))),
    }
}

fn get_str_array(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<String>> {
    match obj.get(key) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    Error::engine(format!(
                        "package manifest @2 field '{key}' must be an array of strings"
                    ))
                })
            })
            .collect(),
        Some(_) => Err(Error::engine(format!(
            "package manifest @2 field '{key}' must be an array"
        ))),
        None => Err(Error::engine(format!(
            "package manifest @2 missing field '{key}'"
        ))),
    }
}

/// Strict manifest JSON errors. Duplicates get their own variant (and the
/// importer's own `duplicate_key` token) so a silent-overwrite attempt is
/// distinguishable from garbled JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestJsonError {
    DuplicateKey(String),
    Malformed(String),
}

/// Strict manifest JSON parse: like `serde_json::from_slice`, but a
/// duplicate object key at ANY depth is refused. `serde_json::Value` keeps
/// the last duplicate silently, which would let two byte-distinct manifests
/// share one digest — so this duplicate-detecting visitor runs instead.
pub fn parse_manifest_json(
    bytes: &[u8],
) -> std::result::Result<serde_json::Value, ManifestJsonError> {
    use serde::de::{MapAccess, SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer};

    struct Strict(serde_json::Value);

    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            deserializer.deserialize_any(StrictVisitor)
        }
    }

    struct StrictVisitor;

    impl<'de> Visitor<'de> for StrictVisitor {
        type Value = Strict;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "strict JSON value with unique object keys")
        }

        fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::Bool(value)))
        }

        fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::Number(value.into())))
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::Number(value.into())))
        }

        fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Strict, E> {
            serde_json::Number::from_f64(value)
                .map(|number| Strict(serde_json::Value::Number(number)))
                .ok_or_else(|| E::custom("non-finite JSON number"))
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::String(value.to_string())))
        }

        fn visit_string<E: serde::de::Error>(
            self,
            value: String,
        ) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::String(value)))
        }

        fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::Null))
        }

        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Strict, E> {
            Ok(Strict(serde_json::Value::Null))
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut access: A,
        ) -> std::result::Result<Strict, A::Error> {
            let mut items = Vec::new();
            while let Some(item) = access.next_element::<Strict>()? {
                items.push(item.0);
            }
            Ok(Strict(serde_json::Value::Array(items)))
        }

        fn visit_map<A: MapAccess<'de>>(
            self,
            mut access: A,
        ) -> std::result::Result<Strict, A::Error> {
            let mut map = serde_json::Map::new();
            while let Some(key) = access.next_key::<String>()? {
                if map.contains_key(&key) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate_key: object key '{key}' appears twice"
                    )));
                }
                let value = access.next_value::<Strict>()?;
                map.insert(key, value.0);
            }
            Ok(Strict(serde_json::Value::Object(map)))
        }
    }

    let text =
        std::str::from_utf8(bytes).map_err(|e| ManifestJsonError::Malformed(e.to_string()))?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = Strict::deserialize(&mut deserializer)
        .map(|strict| strict.0)
        .map_err(|e: serde_json::Error| {
            let message = e.to_string();
            if message.contains("duplicate_key:") {
                ManifestJsonError::DuplicateKey(message)
            } else {
                ManifestJsonError::Malformed(message)
            }
        })?;
    deserializer
        .end()
        .map_err(|e| ManifestJsonError::Malformed(e.to_string()))?;
    Ok(value)
}

fn parse_contribution_list(value: &serde_json::Value, list: &str) -> Result<Vec<ContributionRef>> {
    let items = value.as_array().ok_or_else(|| {
        Error::engine(format!(
            "package manifest @2 contributions '{list}' must be an array"
        ))
    })?;
    items
        .iter()
        .map(|item| {
            let obj = item.as_object().ok_or_else(|| {
                Error::engine(format!(
                    "package manifest @2 contributions '{list}' entries must be objects"
                ))
            })?;
            for key in obj.keys() {
                if key != "name" && key != "file" {
                    return Err(Error::engine(format!(
                        "package manifest @2 unknown field '{key}' in contributions '{list}'"
                    )));
                }
            }
            Ok(ContributionRef {
                name: get_str(obj, "name")?,
                file: get_str(obj, "file")?,
            })
        })
        .collect()
}

impl PackageManifestV2 {
    /// Strict parse: `format` must equal `native.package-manifest@2` and
    /// unknown top-level fields are refused. The result is fully validated.
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self> {
        let obj = value.as_object().ok_or_else(|| {
            Error::engine("package manifest @2 must be a JSON object".to_string())
        })?;
        for key in obj.keys() {
            match key.as_str() {
                "format" | "namespace" | "name" | "version" | "files" | "contributions"
                | "declared_reads" | "declared_effects" | "requires" => {}
                _ => {
                    return Err(Error::engine(format!(
                        "package manifest @2 unknown field '{key}'"
                    )));
                }
            }
        }
        let format = get_str(obj, "format")?;
        if format != MANIFEST_FORMAT_V2 {
            return Err(Error::engine(format!(
                "package manifest @2 bad format '{format}'"
            )));
        }
        let files = obj
            .get("files")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                Error::engine("package manifest @2 field 'files' must be an array".to_string())
            })?
            .iter()
            .map(|item| {
                let entry = item.as_object().ok_or_else(|| {
                    Error::engine("package manifest @2 files entries must be objects".to_string())
                })?;
                for key in entry.keys() {
                    match key.as_str() {
                        "path" | "sha256" | "bytes_len" | "media_type" | "role" => {}
                        _ => {
                            return Err(Error::engine(format!(
                                "package manifest @2 unknown field '{key}' in files"
                            )));
                        }
                    }
                }
                Ok(FileEntry {
                    path: get_str(entry, "path")?,
                    sha256: get_str(entry, "sha256")?,
                    bytes_len: get_u64(entry, "bytes_len")?,
                    media_type: get_str(entry, "media_type")?,
                    role: get_str(entry, "role")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let contributions = match obj.get("contributions") {
            Some(value) => {
                let group = value.as_object().ok_or_else(|| {
                    Error::engine(
                        "package manifest @2 field 'contributions' must be an object".to_string(),
                    )
                })?;
                for key in group.keys() {
                    match key.as_str() {
                        "definitions" | "behaviours" | "surfaces" => {}
                        _ => {
                            return Err(Error::engine(format!(
                                "package manifest @2 unknown contributions group '{key}'"
                            )));
                        }
                    }
                }
                Contributions {
                    definitions: group
                        .get("definitions")
                        .map(|v| parse_contribution_list(v, "definitions"))
                        .transpose()?
                        .unwrap_or_default(),
                    behaviours: group
                        .get("behaviours")
                        .map(|v| parse_contribution_list(v, "behaviours"))
                        .transpose()?
                        .unwrap_or_default(),
                    surfaces: group
                        .get("surfaces")
                        .map(|v| parse_contribution_list(v, "surfaces"))
                        .transpose()?
                        .unwrap_or_default(),
                }
            }
            None => Contributions::default(),
        };
        let requires = obj
            .get("requires")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| {
                        Error::engine(
                            "package manifest @2 field 'requires' must be an array".to_string(),
                        )
                    })?
                    .iter()
                    .map(|item| {
                        let dep = item.as_object().ok_or_else(|| {
                            Error::engine(
                                "package manifest @2 requires entries must be objects".to_string(),
                            )
                        })?;
                        for key in dep.keys() {
                            match key.as_str() {
                                "namespace" | "name" | "digest" => {}
                                _ => {
                                    return Err(Error::engine(format!(
                                        "package manifest @2 unknown field '{key}' in requires"
                                    )));
                                }
                            }
                        }
                        Ok(Requirement {
                            namespace: get_str(dep, "namespace")?,
                            name: get_str(dep, "name")?,
                            digest: get_str(dep, "digest")?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let manifest = Self {
            namespace: get_str(obj, "namespace")?,
            name: get_str(obj, "name")?,
            version: get_str(obj, "version")?,
            files,
            contributions,
            declared: Declared {
                reads: obj
                    .get("declared_reads")
                    .map(|_| get_str_array(obj, "declared_reads"))
                    .transpose()?
                    .unwrap_or_default(),
                effects: obj
                    .get("declared_effects")
                    .map(|_| get_str_array(obj, "declared_effects"))
                    .transpose()?
                    .unwrap_or_default(),
            },
            requires,
        };
        manifest.validate()?;
        Ok(manifest)
    }
}
/// Split a reverse-DNS alpha package id at the last dot:
/// `agent.team-pulse` → (`agent`, `team-pulse`).
pub fn split_package_id(package: &str) -> Result<(String, String)> {
    match package.rsplit_once('.') {
        Some((namespace, name)) if !namespace.is_empty() && !name.is_empty() => {
            Ok((namespace.to_string(), name.to_string()))
        }
        _ => Err(Error::engine(format!(
            "package manifest @2 cannot split package id '{package}': need namespace.name"
        ))),
    }
}

/// Join a namespace and name back into a reverse-DNS alpha package id.
pub fn join_package_id(namespace: &str, name: &str) -> String {
    format!("{namespace}.{name}")
}

impl PackageManifestV2 {
    /// Alpha `{needs, effects}` declaration for this manifest's declared set.
    pub fn alpha_declaration(&self) -> serde_json::Value {
        serde_json::json!({
            "needs": self.declared.reads.clone(),
            "effects": self.declared.effects.clone(),
        })
    }
}

/// Parse an alpha `{needs, effects}` declaration back into a declared set.
/// Object-shaped `needs` (`sql.snapshot.v1`) are refused: the mapping only
/// covers string needs.
pub fn declared_from_alpha_declaration(declaration: &serde_json::Value) -> Result<Declared> {
    let obj = declaration.as_object().ok_or_else(|| {
        Error::engine("package manifest @2 alpha declaration must be an object".to_string())
    })?;
    let needs = obj.get("needs").and_then(|v| v.as_array()).ok_or_else(|| {
        Error::engine("package manifest @2 alpha declaration needs 'needs' array".to_string())
    })?;
    let mut reads = Vec::with_capacity(needs.len());
    for need in needs {
        match need {
            serde_json::Value::String(scope) => reads.push(scope.clone()),
            _ => {
                return Err(Error::engine(
                    "package manifest @2 alpha declaration need refused: unsupported_need_shape"
                        .to_string(),
                ));
            }
        }
    }
    let effects = obj
        .get("effects")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            Error::engine("package manifest @2 alpha declaration needs 'effects' array".to_string())
        })?
        .iter()
        .map(|effect| {
            effect.as_str().map(str::to_string).ok_or_else(|| {
                Error::engine(
                    "package manifest @2 alpha declaration effects must be strings".to_string(),
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let declared = Declared { reads, effects };
    for scope in declared.reads.iter().chain(declared.effects.iter()) {
        validate_read_scope(scope)?;
    }
    Ok(declared)
}
#[cfg(test)]
mod tests {
    use super::*;

    const FILE_SHA: &str = "9f867d33953dedc9a57000a21d2d445e478a634dc2edc76b9f4cf092098b480e";

    fn bundle_file(path: &str) -> FileEntry {
        FileEntry {
            path: path.into(),
            sha256: FILE_SHA.into(),
            bytes_len: 6539,
            media_type: "text/html".into(),
            role: "surface_bundle".into(),
        }
    }

    fn fixture() -> PackageManifestV2 {
        PackageManifestV2 {
            namespace: "agent".into(),
            name: "team-pulse".into(),
            version: "0.1.0".into(),
            files: vec![bundle_file("team-pulse.html")],
            contributions: Contributions {
                surfaces: vec![ContributionRef {
                    name: "team-pulse".into(),
                    file: "team-pulse.html".into(),
                }],
                ..Contributions::default()
            },
            declared: Declared::default(),
            requires: vec![],
        }
    }

    #[test]
    fn fixture_validates_and_digests_as_bare_hex() {
        let manifest = fixture();
        manifest.validate().unwrap();
        manifest.check_p1a_restrictions().unwrap();
        let digest = manifest.package_digest().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!digest.contains(':'));
        let identity = manifest.identity().unwrap();
        assert_eq!(identity.digest, digest);
        assert!(!is_triple_collision(&identity, &identity));
    }

    #[test]
    fn digest_stable_under_key_and_file_order() {
        let manifest = fixture();
        let first = manifest.package_digest().unwrap();
        let reordered_json = serde_json::json!({
            "version": "0.1.0",
            "requires": [],
            "name": "team-pulse",
            "namespace": "agent",
            "format": MANIFEST_FORMAT_V2,
            "files": [{
                "sha256": FILE_SHA,
                "role": "surface_bundle",
                "path": "team-pulse.html",
                "media_type": "text/html",
                "bytes_len": 6539,
            }],
            "declared_reads": [],
            "declared_effects": [],
            "contributions": {"surfaces": [{"file": "team-pulse.html", "name": "team-pulse"}]},
        });
        let reordered = PackageManifestV2::from_json_value(&reordered_json).unwrap();
        assert_eq!(reordered.package_digest().unwrap(), first);
        // A second file in either declaration order digests the same.
        let mut a = fixture();
        a.files.push(bundle_file("b.css"));
        let mut b = fixture();
        b.files.insert(0, bundle_file("b.css"));
        assert_eq!(a.package_digest().unwrap(), b.package_digest().unwrap());
    }

    #[test]
    fn digest_changes_when_any_file_hash_changes() {
        let first = fixture().package_digest().unwrap();
        let mut changed = fixture();
        changed.files[0].sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".into();
        assert_ne!(changed.package_digest().unwrap(), first);
        // Same triple, different digest is a collision.
        let a = fixture().identity().unwrap();
        let b = changed.identity().unwrap();
        assert!(is_triple_collision(&a, &b));
    }

    #[test]
    fn strict_parse_refuses_format_and_unknown_fields() {
        let mut value = fixture().canonical_value().unwrap();
        value["format"] = serde_json::json!("native.package-manifest@1");
        assert!(PackageManifestV2::from_json_value(&value).is_err());
        let mut value = fixture().canonical_value().unwrap();
        value["surprise"] = serde_json::json!(1);
        let err = PackageManifestV2::from_json_value(&value).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
        let mut value = fixture().canonical_value().unwrap();
        value.as_object_mut().unwrap().remove("version");
        assert!(PackageManifestV2::from_json_value(&value).is_err());
    }

    #[test]
    fn semver_accepts_strict_and_refuses_loose() {
        for version in [
            "0.1.0",
            "1.2.3",
            "10.20.30",
            "1.0.0-rc.1",
            "1.0.0+build.7",
            "2.0.0-alpha+b.1",
        ] {
            let mut manifest = fixture();
            manifest.version = version.into();
            manifest
                .validate()
                .unwrap_or_else(|e| panic!("{version} refused: {e}"));
        }
        for version in [
            "", "1.2", "1.2.3.4", "v1.2.3", "1.02.3", "1.2.3-", "1.2.3+", "1.2.3-01", "a.b.c",
            "1.2.x",
        ] {
            let mut manifest = fixture();
            manifest.version = version.into();
            assert!(manifest.validate().is_err(), "{version} accepted");
        }
    }
    #[test]
    fn path_refusals_fire_with_named_reasons() {
        for (path, token) in [
            ("/abs.html", "absolute_path"),
            ("a/../../b.html", "parent_escape"),
            ("a//b.html", "empty_segment"),
            ("a/./b.html", "dot_segment"),
            ("", "empty_path"),
            ("a\\b.html", "backslash"),
            ("C:/x.html", "drive_prefix"),
            ("c:x.html", "drive_prefix"),
            ("a/b\x7fc.html", "control_char"),
            ("a/b\0c.html", "control_char"),
            ("é.html", "non_ascii_path"),
            ("é.html", "non_ascii_path"),
        ] {
            let mut manifest = fixture();
            manifest.files[0].path = path.into();
            let err = manifest.validate().unwrap_err();
            assert!(err.to_string().contains(token), "{path}: {err}");
        }
        let mut long = fixture();
        long.files[0].path = "a".repeat(257);
        assert!(long.validate().is_err());
        let mut manifest = fixture();
        manifest.files.push(bundle_file("TEAM-PULSE.HTML"));
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("case_fold_duplicate"), "{err}");
        let mut manifest = fixture();
        manifest.files.push(bundle_file("team-pulse.html"));
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn duplicate_declared_reads_and_effects_refused() {
        let mut manifest = fixture();
        manifest.declared.reads = vec!["records.read:work".into(), "records.read:work".into()];
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate_declared"), "{err}");
        let mut manifest = fixture();
        manifest.declared.effects = vec!["task.x.v1".into(), "task.x.v1".into()];
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate_declared"), "{err}");
    }

    #[test]
    fn duplicate_keys_refused_at_any_depth() {
        assert!(parse_manifest_json(br#"{"a": 1}"#).is_ok());
        assert!(matches!(
            parse_manifest_json(br#"{"version": "0.1.0", "version": "0.2.0"}"#),
            Err(ManifestJsonError::DuplicateKey(_))
        ));
        let nested = br#"{"files": [{"path": "a", "path": "b"}]}"#;
        assert!(matches!(
            parse_manifest_json(nested),
            Err(ManifestJsonError::DuplicateKey(_))
        ));
        assert!(matches!(
            parse_manifest_json(br#"[1, 2"#),
            Err(ManifestJsonError::Malformed(_))
        ));
        assert!(matches!(
            parse_manifest_json(&[0xff, 0xfe]),
            Err(ManifestJsonError::Malformed(_))
        ));
        // Full manifest with a smuggled duplicate version refuses.
        let mut text = serde_json::to_string(&fixture().canonical_value().unwrap()).unwrap();
        text.insert_str(1, r#""version": "9.9.9", "#);
        assert!(matches!(
            parse_manifest_json(text.as_bytes()),
            Err(ManifestJsonError::DuplicateKey(_))
        ));
    }

    #[test]
    fn file_count_cap_and_entry_shapes_refused() {
        let mut manifest = fixture();
        manifest.files = (0..33)
            .map(|i| bundle_file(&format!("f{i}.html")))
            .collect();
        assert!(manifest.validate().is_err());
        for mutate in [
            Box::new(|f: &mut FileEntry| f.sha256 = "zzz".into()) as Box<dyn Fn(&mut FileEntry)>,
            Box::new(|f: &mut FileEntry| f.role = "executable".into()),
            Box::new(|f: &mut FileEntry| f.media_type = "not-a-type".into()),
        ] {
            let mut manifest = fixture();
            mutate(&mut manifest.files[0]);
            assert!(manifest.validate().is_err());
        }
        let mut manifest = fixture();
        manifest.contributions.surfaces[0].file = "missing.html".into();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn mapping_round_trips() {
        let (namespace, name) = split_package_id("agent.team-pulse").unwrap();
        assert_eq!((namespace.as_str(), name.as_str()), ("agent", "team-pulse"));
        assert_eq!(join_package_id(&namespace, &name), "agent.team-pulse");
        assert!(split_package_id("nodots").is_err());
        let mut manifest = fixture();
        manifest.declared.reads = vec!["records.read:work".into()];
        let declaration = manifest.alpha_declaration();
        assert_eq!(
            declaration["needs"],
            serde_json::json!(["records.read:work"])
        );
        let back = declared_from_alpha_declaration(&declaration).unwrap();
        assert_eq!(back.reads, manifest.declared.reads);
        let object_need = serde_json::json!({
            "needs": [{"need": "x", "key": "y", "label": "z", "sql": "s"}],
            "effects": [],
        });
        assert!(declared_from_alpha_declaration(&object_need).is_err());
    }

    #[test]
    fn p1a_restrictions_parse_but_refuse_nonempty() {
        let mut manifest = fixture();
        manifest.declared.effects = vec!["task.triage-set.v1".into()];
        manifest.check_p1a_restrictions().unwrap_err();
        let mut manifest = fixture();
        manifest.requires = vec![Requirement {
            namespace: "agent".into(),
            name: "other".into(),
            digest: FILE_SHA.into(),
        }];
        manifest.validate().unwrap();
        let err = manifest.check_p1a_restrictions().unwrap_err();
        assert!(err.to_string().contains("p1a_requires_not_empty"), "{err}");
    }
}
