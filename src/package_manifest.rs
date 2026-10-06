//! Gated v2 package-manifest contract (slice 3, increment S1: pure only).
//!
//! Compiled only under `cfg(any(test, feature = "v2-kernel-probe"))` (see the
//! gated `mod` declaration in the crate root). Nothing here affects the
//! default build: no v1 schema change, no migration, no new event, no tool.
//!
//! A manifest is one immutable namespaced package carrying a definition set,
//! and optionally one fixed host-owned read-only behaviour descriptor plus one
//! declarative surface descriptor. A definitions-only package (K5) omits both
//! and declares no reads. There is no executable code and no effect: behaviour
//! `reads` name scopes the host may serve; `effects` must stay empty.
//!
//! Digest separation (deliberate, not redundant):
//! - each definition entry preserves `digest` = lowercase hex SHA-256 over
//!   the exact raw artifact bytes (whitespace counts; mirrors
//!   `crate::meta::definition_artifact::digest_artifact_bytes`), so replay can
//!   re-verify pinned bytes without the manifest;
//! - the package `digest` = `crate::canonical_json::digest_json` (SHA-256 over
//!   RFC 8785 JCS bytes) of the canonical manifest value, so one digest pins
//!   the whole triple `(namespace, name, version)` plus contents.
//!
//! Adapter boundary (no wire compatibility claimed):
//! - alpha `alpha-tab-digest.v1` = SHA-256 over bundle bytes + canonical
//!   needs/effects declaration + runtime (JCS-hashed);
//! - pilot `MANIFEST` pin = SHA-256 over fixed ASCII manifest bytes
//!   (`explore-native-plugins:src/mcp/tools/behavior_packages.rs`);
//! - this package digest = SHA-256 over JCS bytes of the canonical value
//!   built by [`PackageManifest::canonical_value`].
//!
//! The three preimages differ, so digests are never comparable across them.
//! A future store increment (S2, not here) may carry an adapter that
//! re-digests legacy pins into this form; it must never reinterpret a stored
//! legacy digest as this digest.

use crate::error::{Error, Result};

/// Envelope format marker for the S1 canonical manifest value.
pub const MANIFEST_FORMAT: &str = "native.package-manifest@1";
/// Package digest construction: hex SHA-256 over RFC 8785 JCS bytes.
pub const PACKAGE_DIGEST_ALGORITHM: &str = "sha256-jcs";
/// Per-definition digest construction: hex SHA-256 over exact raw bytes.
pub const DEFINITION_DIGEST_ALGORITHM: &str = "sha256";
/// The only behaviour kind S1 accepts: fixed host-owned read-only.
pub const BEHAVIOUR_KIND: &str = "host.readonly.v1";
/// The only surface kind S1 accepts: declarative host-rendered view.
pub const SURFACE_KIND: &str = "host.surface.v1";

const MAX_PART_LEN: usize = 128;
const MAX_DEFINITIONS: usize = 16;
const MAX_READS: usize = 64;
const MAX_READ_LEN: usize = 128;

fn validate_part(kind: &str, part: &str) -> Result<()> {
    if part.is_empty() || part.len() > MAX_PART_LEN {
        return Err(Error::engine(format!(
            "package manifest {kind} must be 1..{MAX_PART_LEN} bytes"
        )));
    }
    if !part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(Error::engine(format!(
            "package manifest {kind} '{part}' must match [A-Za-z0-9._-]"
        )));
    }
    let bytes = part.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(Error::engine(format!(
            "package manifest {kind} '{part}' must start and end with an ASCII alphanumeric"
        )));
    }
    Ok(())
}

fn validate_read_scope(scope: &str) -> Result<()> {
    if scope.is_empty() || scope.len() > MAX_READ_LEN {
        return Err(Error::engine(format!(
            "package manifest read scope must be 1..{MAX_READ_LEN} bytes"
        )));
    }
    if !scope.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' || c == ':' || c == '/'
    }) {
        return Err(Error::engine(format!(
            "package manifest read scope '{scope}' must match [A-Za-z0-9._:/-]"
        )));
    }
    Ok(())
}

/// Identity of one installed package revision: triple plus package digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestIdentity {
    pub namespace: String,
    pub name: String,
    pub version: u32,
    pub digest: String,
}

impl ManifestIdentity {
    /// Same `(namespace, name, version)` triple, ignoring digest.
    pub fn triple_eq(&self, other: &ManifestIdentity) -> bool {
        self.namespace == other.namespace
            && self.name == other.name
            && self.version == other.version
    }
}

/// Pure collision rule: same triple but different package digests refuses.
pub fn is_triple_collision(existing: &ManifestIdentity, candidate: &ManifestIdentity) -> bool {
    existing.triple_eq(candidate) && existing.digest != candidate.digest
}

/// One definition carried by a manifest: exact raw bytes plus their digest.
///
/// `digest` must equal the hex SHA-256 of `artifact_bytes` as stored; the
/// envelope inside the bytes must declare the same `family`/`version` and
/// carry a `kinds` array (checked via the shared registry parser).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionEntry {
    pub family: String,
    pub version: u32,
    pub artifact_bytes: String,
    pub digest: String,
}

/// Fixed host-owned read-only behaviour descriptor. No code, no effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviourDescriptor {
    pub kind: String,
    pub reads: Vec<String>,
    pub effects: Vec<String>,
}

/// Declarative surface descriptor: a host-rendered view plus named fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceDescriptor {
    pub kind: String,
    pub view: String,
    pub fallback: String,
}

/// The S1 canonical manifest: a namespaced triple plus a definition set, and
/// optionally one behaviour descriptor plus one surface descriptor and the
/// declared-read set covering every behaviour read.
///
/// Behaviour and surface are optional together: a definitions-only package
/// (K5) omits both and carries an empty `declared_reads`. A manifest that
/// declares reads without a behaviour, or supplies only one of the two parts,
/// refuses — the conservative both-or-neither rule. When both are present the
/// pre-existing behaviour/surface/read contract is unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageManifest {
    pub namespace: String,
    pub name: String,
    pub version: u32,
    pub definitions: Vec<DefinitionEntry>,
    pub behaviour: Option<BehaviourDescriptor>,
    pub surface: Option<SurfaceDescriptor>,
    pub declared_reads: Vec<String>,
}

impl DefinitionEntry {
    pub fn validate(&self) -> Result<()> {
        crate::meta::definition_artifact::validate_family_version(&self.family, self.version)?;
        if self.artifact_bytes.is_empty() {
            return Err(Error::engine(
                "package manifest definition artifact bytes must not be empty",
            ));
        }
        let recomputed =
            crate::meta::definition_artifact::digest_artifact_bytes(self.artifact_bytes.as_bytes());
        if recomputed != self.digest {
            return Err(Error::engine(
                "package manifest definition digest must equal SHA-256 of the exact artifact bytes",
            ));
        }
        let parsed =
            crate::meta::definition_artifact::parse_artifact_envelope(&self.artifact_bytes)?;
        if !parsed.kinds.as_array().is_some_and(|k| !k.is_empty()) {
            return Err(Error::engine(
                "package manifest definition must declare at least one kind",
            ));
        }
        if parsed.family != self.family || parsed.version != self.version {
            return Err(Error::engine(
                "package manifest definition envelope family/version must match the entry",
            ));
        }
        // Match the kernel install gate: legacy envelopes pass, `native.defn/2`
        // runs full semantic validation, any other interpreter marker fails.
        crate::meta::definition_artifact::validate_kernel_definition_bytes(&self.artifact_bytes)?;
        Ok(())
    }
}

impl DefinitionEntry {
    /// Whether `kind` is declared by this definition revision's envelope:
    /// legacy envelopes list kind strings; `/2` envelopes carry kind
    /// objects with a `token`. Unparseable envelopes declare nothing.
    pub fn declares_kind(&self, kind: &str) -> bool {
        let Ok(parsed) =
            crate::meta::definition_artifact::parse_artifact_envelope(&self.artifact_bytes)
        else {
            return false;
        };
        let Some(kinds) = parsed.kinds.as_array() else {
            return false;
        };
        kinds.iter().any(|k| match k {
            serde_json::Value::String(s) => s == kind,
            serde_json::Value::Object(o) => o
                .get("token")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|t| t == kind),
            _ => false,
        })
    }
}

impl BehaviourDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.kind != BEHAVIOUR_KIND {
            return Err(Error::engine(format!(
                "package manifest behaviour kind must be exactly '{BEHAVIOUR_KIND}'"
            )));
        }
        if !self.effects.is_empty() {
            return Err(Error::engine(
                "package manifest behaviour effects must stay empty in slice 3 (read-only)",
            ));
        }
        if self.reads.is_empty() || self.reads.len() > MAX_READS {
            return Err(Error::engine(format!(
                "package manifest behaviour reads must be 1..{MAX_READS}"
            )));
        }
        for scope in &self.reads {
            validate_read_scope(scope)?;
        }
        Ok(())
    }
}

impl SurfaceDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.kind != SURFACE_KIND {
            return Err(Error::engine(format!(
                "package manifest surface kind must be exactly '{SURFACE_KIND}'"
            )));
        }
        validate_part("surface view", &self.view)?;
        validate_part("surface fallback", &self.fallback)?;
        Ok(())
    }
}

impl PackageManifest {
    pub fn validate(&self) -> Result<()> {
        validate_part("namespace", &self.namespace)?;
        validate_part("name", &self.name)?;
        if self.definitions.is_empty() || self.definitions.len() > MAX_DEFINITIONS {
            return Err(Error::engine(format!(
                "package manifest definitions must be 1..{MAX_DEFINITIONS}"
            )));
        }
        for entry in &self.definitions {
            entry.validate()?;
        }
        // Contract correction: at most one revision per family. S2b keeps a
        // single effective definition pin per family and activates every
        // embedded pin, so two revisions of one family could never jointly
        // activate — refuse them at validation instead of serving an
        // arbitrary pick downstream.
        for (i, a) in self.definitions.iter().enumerate() {
            for b in &self.definitions[..i] {
                if a.family == b.family {
                    return Err(Error::engine(format!(
                        "package manifest embeds family '{}' twice ({} and {})",
                        a.family, b.version, a.version
                    )));
                }
            }
        }
        // Behaviour and surface are optional together. A definitions-only
        // package (K5) omits both and declares no reads; supplying one part
        // without the other, or reads without a behaviour, refuses.
        match (&self.behaviour, &self.surface) {
            (None, None) => {
                if !self.declared_reads.is_empty() {
                    return Err(Error::engine(
                        "package manifest declared reads require a behaviour",
                    ));
                }
                return Ok(());
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(Error::engine(
                    "package manifest behaviour and surface must be supplied together or omitted together",
                ));
            }
            (Some(behaviour), Some(surface)) => {
                if self.declared_reads.is_empty() || self.declared_reads.len() > MAX_READS {
                    return Err(Error::engine(format!(
                        "package manifest declared reads must be 1..{MAX_READS}"
                    )));
                }
                for scope in &self.declared_reads {
                    validate_read_scope(scope)?;
                }
                for (label, reads) in [
                    ("declared reads", &self.declared_reads),
                    ("behaviour reads", &behaviour.reads),
                ] {
                    for (i, a) in reads.iter().enumerate() {
                        if reads[..i].iter().any(|b| b == a) {
                            return Err(Error::engine(format!(
                                "package manifest duplicate entry '{a}' in {label}"
                            )));
                        }
                    }
                }
                behaviour.validate()?;
                surface.validate()?;
                for scope in &behaviour.reads {
                    if !self.declared_reads.iter().any(|d| d == scope) {
                        return Err(Error::engine(format!(
                            "package manifest behaviour read '{scope}' must be in declared reads"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether this package supplies a host behaviour and surface. A
    /// definitions-only package (K5) returns `false` and derives no
    /// `package-surface` dependency requirement.
    pub fn declares_surface(&self) -> bool {
        self.behaviour.is_some() && self.surface.is_some()
    }

    /// Canonical JCS value this package digests over. Object keys are fixed;
    /// `serde_jcs` sorts them. Semantically unordered sets are sorted here
    /// because JCS preserves array order: read scopes, and definitions by
    /// `(family, version, digest)` — definition order carries no semantic
    /// role, so declaration order never affects identity. Absent optional
    /// parts are omitted entirely, so a definitions-only canonical value has
    /// no `behaviour`/`surface` keys; a manifest that supplies them keeps the
    /// exact bytes, and therefore the exact digest, it had before.
    pub fn canonical_value(&self) -> Result<serde_json::Value> {
        self.validate()?;
        let mut declared = self.declared_reads.clone();
        declared.sort();
        let mut entries: Vec<&DefinitionEntry> = self.definitions.iter().collect();
        entries.sort_by(|a, b| {
            (&a.family, a.version, &a.digest).cmp(&(&b.family, b.version, &b.digest))
        });
        let definitions: Vec<serde_json::Value> = entries
            .iter()
            .map(|d| {
                serde_json::json!({
                    "artifact_bytes": d.artifact_bytes,
                    "digest": d.digest,
                    "family": d.family,
                    "version": d.version,
                })
            })
            .collect();
        let mut value = serde_json::json!({
            "declared_reads": declared,
            "definitions": definitions,
            "format": MANIFEST_FORMAT,
            "name": self.name,
            "namespace": self.namespace,
            "version": self.version,
        });
        let obj = value.as_object_mut().expect("manifest canonical object");
        if let (Some(behaviour), Some(surface)) = (&self.behaviour, &self.surface) {
            let mut behaviour_reads = behaviour.reads.clone();
            behaviour_reads.sort();
            let effects: Vec<serde_json::Value> = behaviour
                .effects
                .iter()
                .map(|e| serde_json::Value::String(e.clone()))
                .collect();
            obj.insert(
                "behaviour".to_string(),
                serde_json::json!({
                    "effects": effects,
                    "kind": behaviour.kind,
                    "reads": behaviour_reads,
                }),
            );
            obj.insert(
                "surface".to_string(),
                serde_json::json!({
                    "fallback": surface.fallback,
                    "kind": surface.kind,
                    "view": surface.view,
                }),
            );
        }
        Ok(value)
    }

    /// Package digest: hex SHA-256 over the RFC 8785 JCS bytes of
    /// [`PackageManifest::canonical_value`], via the shared canonicalizer.
    pub fn package_digest(&self) -> Result<String> {
        Ok(crate::canonical_json::digest_json(&self.canonical_value()?))
    }

    pub fn identity(&self) -> Result<ManifestIdentity> {
        Ok(ManifestIdentity {
            namespace: self.namespace.clone(),
            name: self.name.clone(),
            version: self.version,
            digest: self.package_digest()?,
        })
    }

    /// Rebuild a manifest from a canonical value (fold/replay path). The
    /// result is fully re-validated, including per-definition digests and the
    /// `/2` language gate, so stored bytes can never smuggle an invalid shape
    /// past install-time checks.
    pub fn from_canonical_value(value: &serde_json::Value) -> Result<PackageManifest> {
        let obj = value.as_object().ok_or_else(|| {
            Error::engine("package manifest canonical value must be a JSON object")
        })?;
        let str_field = |key: &str| {
            obj.get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    Error::engine(format!(
                        "package manifest canonical value lacks string '{key}'"
                    ))
                })
        };
        if str_field("format")? != MANIFEST_FORMAT {
            return Err(Error::engine("package manifest format marker mismatch"));
        }
        let version = obj
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| Error::engine("package manifest canonical value lacks u32 'version'"))?;
        let version: u32 = version.try_into().map_err(|_| {
            Error::engine("package manifest canonical value 'version' out of range")
        })?;
        let read_list = |key: &str| {
            obj.get(key)
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    Error::engine(format!(
                        "package manifest canonical value lacks array '{key}'"
                    ))
                })?
                .iter()
                .map(|v| {
                    v.as_str()
                        .ok_or_else(|| {
                            Error::engine(format!(
                                "package manifest canonical value '{key}' must hold strings"
                            ))
                        })
                        .map(str::to_owned)
                })
                .collect::<Result<Vec<String>>>()
        };
        let definitions = obj
            .get("definitions")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                Error::engine("package manifest canonical value lacks array 'definitions'")
            })?
            .iter()
            .map(|d| {
                let o = d.as_object().ok_or_else(|| {
                    Error::engine("package manifest definition entry must be an object")
                })?;
                let get = |k: &str| {
                    o.get(k).and_then(serde_json::Value::as_str).ok_or_else(|| {
                        Error::engine(format!("package manifest definition lacks string '{k}'"))
                    })
                };
                let version = o
                    .get("version")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        Error::engine("package manifest definition lacks u32 'version'")
                    })?;
                Ok(DefinitionEntry {
                    family: get("family")?.to_owned(),
                    version: version.try_into().map_err(|_| {
                        Error::engine("package manifest definition 'version' out of range")
                    })?,
                    artifact_bytes: get("artifact_bytes")?.to_owned(),
                    digest: get("digest")?.to_owned(),
                })
            })
            .collect::<Result<Vec<DefinitionEntry>>>()?;
        let sub_optional =
            |key: &str| -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
                match obj.get(key) {
                    None | Some(serde_json::Value::Null) => Ok(None),
                    Some(serde_json::Value::Object(o)) => Ok(Some(o.clone())),
                    Some(_) => Err(Error::engine(format!(
                        "package manifest canonical value '{key}' must be an object"
                    ))),
                }
            };
        let sub_str = |o: &serde_json::Map<String, serde_json::Value>, k: &str| {
            o.get(k)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::engine(format!("package manifest descriptor lacks string '{k}'"))
                })
        };
        let str_list = |o: &serde_json::Map<String, serde_json::Value>, key: &str| {
            o.get(key)
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    Error::engine(format!("package manifest section lacks array '{key}'"))
                })?
                .iter()
                .map(|v| {
                    v.as_str()
                        .ok_or_else(|| {
                            Error::engine(format!(
                                "package manifest array '{key}' must hold strings"
                            ))
                        })
                        .map(str::to_owned)
                })
                .collect::<Result<Vec<String>>>()
        };
        let behaviour = match sub_optional("behaviour")? {
            Some(o) => Some(BehaviourDescriptor {
                kind: sub_str(&o, "kind")?.to_owned(),
                reads: str_list(&o, "reads")?,
                effects: str_list(&o, "effects")?,
            }),
            None => None,
        };
        let surface = match sub_optional("surface")? {
            Some(o) => Some(SurfaceDescriptor {
                kind: sub_str(&o, "kind")?.to_owned(),
                view: sub_str(&o, "view")?.to_owned(),
                fallback: sub_str(&o, "fallback")?.to_owned(),
            }),
            None => None,
        };
        let manifest = PackageManifest {
            namespace: str_field("namespace")?.to_owned(),
            name: str_field("name")?.to_owned(),
            version,
            definitions,
            behaviour,
            surface,
            declared_reads: read_list("declared_reads")?,
        };
        manifest.validate()?;
        // Round-trip backstop: no digest-covered semantics may be dropped or
        // added by the parse. A forged value carrying unknown fields or a
        // non-empty effects array never reproduces its own canonical bytes,
        // so it fails here even before the digest comparison.
        if manifest.canonical_value()? != *value {
            return Err(Error::engine(
                "package manifest canonical round-trip mismatch",
            ));
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bytes() -> String {
        r#"{"family":"demo.notes","version":1,"kinds":["note"]}"#.to_string()
    }

    fn sample_entry() -> DefinitionEntry {
        let bytes = sample_bytes();
        let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
        DefinitionEntry {
            family: "demo.notes".to_string(),
            version: 1,
            artifact_bytes: bytes,
            digest,
        }
    }

    fn sample_manifest() -> PackageManifest {
        PackageManifest {
            namespace: "acme".to_string(),
            name: "notes-pack".to_string(),
            version: 1,
            definitions: vec![sample_entry()],
            behaviour: Some(BehaviourDescriptor {
                kind: BEHAVIOUR_KIND.to_string(),
                reads: vec!["linked_record:view".to_string()],
                effects: vec![],
            }),
            surface: Some(SurfaceDescriptor {
                kind: SURFACE_KIND.to_string(),
                view: "notes.view".to_string(),
                fallback: "notes.unavailable".to_string(),
            }),
            declared_reads: vec!["linked_record:view".to_string()],
        }
    }

    fn definitions_only_manifest() -> PackageManifest {
        PackageManifest {
            namespace: "acme".to_string(),
            name: "notes-pack".to_string(),
            version: 1,
            definitions: vec![sample_entry()],
            behaviour: None,
            surface: None,
            declared_reads: vec![],
        }
    }

    #[test]
    fn package_digest_is_stable_and_key_order_free() {
        fn two_read_manifest(first: &str, second: &str) -> PackageManifest {
            let mut m = sample_manifest();
            m.declared_reads = vec![first.to_string(), second.to_string()];
            m.behaviour.as_mut().unwrap().reads = vec![second.to_string(), first.to_string()];
            m
        }
        let a = two_read_manifest("linked_record:view", "resolution:view");
        let b = two_read_manifest("resolution:view", "linked_record:view");
        assert_eq!(a.canonical_value().unwrap(), b.canonical_value().unwrap());
        assert_eq!(a.package_digest().unwrap(), b.package_digest().unwrap());
    }

    #[test]
    fn whitespace_only_bytes_change_both_digests() {
        let mut altered = sample_manifest();
        altered.definitions[0].artifact_bytes =
            r#"{ "family" : "demo.notes" , "version" : 1 , "kinds" : [ "note" ] }"#.to_string();
        altered.definitions[0].digest = crate::meta::definition_artifact::digest_artifact_bytes(
            altered.definitions[0].artifact_bytes.as_bytes(),
        );
        assert!(altered.validate().is_ok());
        assert_ne!(
            altered.definitions[0].digest,
            sample_manifest().definitions[0].digest
        );
        assert_ne!(
            altered.package_digest().unwrap(),
            sample_manifest().package_digest().unwrap()
        );
    }

    #[test]
    fn same_triple_different_bytes_is_collision() {
        let a = sample_manifest().identity().unwrap();
        let mut other = sample_manifest();
        other.surface.as_mut().unwrap().fallback = "notes.empty".to_string();
        let b = other.identity().unwrap();
        assert!(is_triple_collision(&a, &b));
        assert!(!is_triple_collision(&a, &a));
    }

    #[test]
    fn behaviour_with_effects_is_refused() {
        let mut m = sample_manifest();
        m.behaviour.as_mut().unwrap().effects = vec!["write".to_string()];
        assert!(m.validate().is_err());
        assert!(m.package_digest().is_err());
    }

    #[test]
    fn uncovered_behaviour_read_is_refused() {
        let mut m = sample_manifest();
        m.behaviour.as_mut().unwrap().reads = vec!["private:view".to_string()];
        assert!(m.validate().is_err());
    }

    #[test]
    fn changing_declared_reads_changes_package_identity() {
        let base = sample_manifest().identity().unwrap();
        let mut wider = sample_manifest();
        wider.declared_reads.push("resolution:view".to_string());
        let grown = wider.identity().unwrap();
        assert!(base.triple_eq(&grown));
        assert_ne!(base.digest, grown.digest);
        assert!(is_triple_collision(&base, &grown));
    }

    #[test]
    fn malformed_defn2_definition_is_refused() {
        let bytes =
            r#"{"family":"demo.notes","version":1,"kinds":["note"],"interpreter":"native.defn/2"}"#
                .to_string();
        let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
        let entry = DefinitionEntry {
            family: "demo.notes".to_string(),
            version: 1,
            artifact_bytes: bytes,
            digest,
        };
        assert!(entry.validate().is_err());
        let mut m = sample_manifest();
        m.definitions = vec![entry];
        assert!(m.validate().is_err());
    }

    #[test]
    fn identifier_edges_and_duplicate_sets_are_refused() {
        let mut m = sample_manifest();
        m.namespace = ".".to_string();
        assert!(m.validate().is_err());
        let mut m = sample_manifest();
        m.name = "notes-".to_string();
        assert!(m.validate().is_err());
        let mut m = sample_manifest();
        m.definitions.push(sample_entry());
        assert!(m.validate().is_err());
        let mut m = sample_manifest();
        m.declared_reads.push("linked_record:view".to_string());
        assert!(m.validate().is_err());
    }

    fn entry_for(family: &str, kinds: &str) -> DefinitionEntry {
        let bytes = format!(r#"{{"family":"{family}","version":1,"kinds":{kinds}}}"#);
        let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
        DefinitionEntry {
            family: family.to_string(),
            version: 1,
            artifact_bytes: bytes,
            digest,
        }
    }

    #[test]
    fn definition_order_has_no_effect_on_digest() {
        let mut a = sample_manifest();
        a.definitions = vec![
            entry_for("demo.alpha", r#"["a"]"#),
            entry_for("demo.beta", r#"["b"]"#),
        ];
        let mut b = sample_manifest();
        b.definitions = vec![
            entry_for("demo.beta", r#"["b"]"#),
            entry_for("demo.alpha", r#"["a"]"#),
        ];
        assert!(a.validate().is_ok());
        assert_eq!(a.canonical_value().unwrap(), b.canonical_value().unwrap());
        assert_eq!(a.package_digest().unwrap(), b.package_digest().unwrap());
    }

    #[test]
    fn declares_kind_matches_envelope_shape() {
        let legacy = sample_entry();
        assert!(legacy.declares_kind("note"));
        assert!(!legacy.declares_kind("other"));
        let defn2 = entry_for("demo.thing", r#"[{"token":"note"}]"#);
        assert!(defn2.declares_kind("note"));
        assert!(!defn2.declares_kind("other"));
        let broken = DefinitionEntry {
            family: "demo.thing".to_string(),
            version: 1,
            artifact_bytes: "not json".to_string(),
            digest: "0".repeat(64),
        };
        assert!(!broken.declares_kind("note"));
    }

    #[test]
    fn same_family_two_versions_refused() {
        let mut m = sample_manifest();
        m.definitions = vec![
            entry_for("demo.notes", r#"["note"]"#),
            entry_for("demo.notes", r#"["note"]"#),
        ];
        m.definitions[1].version = 2;
        let bytes = r#"{"family":"demo.notes","version":2,"kinds":["note"]}"#.to_string();
        m.definitions[1].artifact_bytes = bytes.clone();
        m.definitions[1].digest =
            crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
        assert!(m.validate().is_err());
    }

    #[test]
    fn empty_kinds_refused_and_kinded_fixture_passes() {
        let mut m = sample_manifest();
        m.definitions = vec![entry_for("demo.empty", "[]")];
        assert!(m.validate().is_err());
        let mut m = sample_manifest();
        m.definitions = vec![entry_for("demo.multi", r#"["a",{"token":"b"}]"#)];
        assert!(m.validate().is_ok());
    }

    /// Pins an existing behaviour+surface manifest's canonical digest so the
    /// optional-parts change cannot silently move identity for packages that
    /// already supply both. Computed before the change; a mismatch here means
    /// the canonical form moved.
    #[test]
    fn existing_manifest_digest_is_pinned() {
        assert_eq!(
            sample_manifest().package_digest().unwrap(),
            "6716282e028bd0917757075ce2d7a467287e430d0c7f6134b6235edd01182b3d"
        );
        let value = sample_manifest().canonical_value().unwrap();
        assert_eq!(
            value.get("behaviour").unwrap()["kind"],
            serde_json::json!(BEHAVIOUR_KIND)
        );
        assert_eq!(
            value.get("surface").unwrap()["view"],
            serde_json::json!("notes.view")
        );
    }

    #[test]
    fn definitions_only_manifest_validates_and_round_trips() {
        let m = definitions_only_manifest();
        assert!(m.validate().is_ok());
        assert!(!m.declares_surface());
        let value = m.canonical_value().unwrap();
        // Absent parts are omitted entirely, never emitted as null.
        assert!(value.get("behaviour").is_none(), "{value}");
        assert!(value.get("surface").is_none(), "{value}");
        assert_eq!(value["declared_reads"], serde_json::json!([]));
        let round_tripped = PackageManifest::from_canonical_value(&value).unwrap();
        assert_eq!(round_tripped, m);
        assert_eq!(
            round_tripped.package_digest().unwrap(),
            m.package_digest().unwrap()
        );
    }

    #[test]
    fn definitions_only_package_digest_is_stable() {
        let a = definitions_only_manifest();
        let b = definitions_only_manifest();
        assert_eq!(a.package_digest().unwrap(), b.package_digest().unwrap());
        assert!(!a.declares_surface());
        assert!(sample_manifest().declares_surface());
    }

    #[test]
    fn reads_without_behaviour_is_refused() {
        let mut m = definitions_only_manifest();
        m.declared_reads = vec!["linked_record:view".to_string()];
        assert!(m.validate().is_err());
        assert!(m.package_digest().is_err());
    }

    #[test]
    fn behaviour_without_surface_is_refused() {
        let mut m = sample_manifest();
        m.surface = None;
        assert!(m.validate().is_err());
    }

    #[test]
    fn surface_without_behaviour_is_refused() {
        let mut m = sample_manifest();
        m.behaviour = None;
        assert!(m.validate().is_err());
    }

    #[test]
    fn explicit_null_optional_part_is_not_canonical() {
        let mut value = definitions_only_manifest().canonical_value().unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("behaviour".to_string(), serde_json::Value::Null);
        // Present-but-null is not the canonical absence: the round-trip
        // backstop refuses it rather than blessing two encodings.
        assert!(PackageManifest::from_canonical_value(&value).is_err());
    }
}
