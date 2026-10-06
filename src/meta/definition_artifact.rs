//! Immutable definition-artifact registry core (gated E1 test-only
//! prototype, ported from the reference branch's Gate B slice).
//!
//! The registry records one immutable revision per `(family, version,
//! digest)` as a `definition_artifact.installed` meta event projected into
//! the dedicated `definition_artifacts` table, so the content projector never
//! sees these rows and the generic vocabulary verbs cannot address them.
//!
//! Identity is bytes-as-identity: `digest` is the hex SHA-256 of the exact
//! validated UTF-8 artifact bytes. No JSON canonicalizer runs anywhere, so a
//! same family/version pair with any different bytes — including
//! whitespace-only differences — is a conflict, never a reissue.
//!
//! The fold verifies (see [`verify_installed_payload`]): a poisoned log row
//! whose bytes do not hash to its claimed digest fails the replay instead of
//! projecting a lying revision. All other policy (conflicts, retries) stays
//! at the write path in `crate::definition_registry`.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::meta::events::DefinitionArtifactInstalledPayload;

/// Pre-60 vocabulary name for installed definition revisions, kept as the
/// opaque subject-id namespace so old event histories stay replayable.
/// Current installs create no vocabulary row.
/// Deterministic id for the pre-60 `ontology:definition-artifact` namespace.
pub const ARTIFACT_VOCABULARY_ID: &str = "voc:ontology:definition-artifact";

/// Envelope format marker stored alongside each revision in the projection.
pub const ARTIFACT_ENVELOPE_FORMAT: &str = "native.definition-artifact@1";
/// The only digest algorithm this module understands.
pub const DIGEST_ALGORITHM: &str = "sha256";

/// The immutable identity of one installed definition revision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionIdentity {
    pub family: String,
    pub version: u32,
    pub digest: String,
}

impl RevisionIdentity {
    /// The revision-keyed value string: `family@version#digest`.
    pub fn value_string(&self) -> String {
        format!("{}@{}#{}", self.family, self.version, self.digest)
    }

    /// Deterministic projection id for this revision.
    pub fn value_id(&self) -> String {
        format!("vv:{}:{}", ARTIFACT_VOCABULARY_ID, self.value_string())
    }
}

/// Hex SHA-256 over the exact artifact bytes.
pub fn digest_artifact_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Family/version charset: unambiguous under the `@`/`#` revision-key split.
fn validate_part(kind: &str, part: &str) -> Result<()> {
    if part.is_empty() {
        return Err(Error::engine(format!(
            "definition artifact {kind} must not be empty"
        )));
    }
    if !part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(Error::engine(format!(
            "definition artifact {kind} '{part}' must match [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

/// Check family and version before they enter a key, event, or projection.
pub fn validate_family_version(family: &str, version: u32) -> Result<()> {
    validate_part("family", family)?;
    let _ = version;
    Ok(())
}

/// Recompute the digest from event-carried bytes and check every consistency
/// edge: digest matches bytes, bytes parse as the envelope, the envelope's
/// own family/version declarations match the revision parts, the value string
/// matches the parts, and the event subject is the revision's deterministic
/// projection id. Any mismatch is an engine error — the fold and the read
/// path both refuse to continue.
pub fn verify_installed_payload(
    subject_id: &str,
    payload: &DefinitionArtifactInstalledPayload,
) -> Result<RevisionIdentity> {
    validate_family_version(&payload.family, payload.version)?;
    if payload.vocabulary_id != ARTIFACT_VOCABULARY_ID {
        return Err(Error::engine(format!(
            "definition artifact vocabulary mismatch: '{}'",
            payload.vocabulary_id
        )));
    }
    let recomputed = digest_artifact_bytes(payload.artifact_bytes.as_bytes());
    if recomputed != payload.digest {
        return Err(Error::engine(
            "definition artifact digest mismatch: event bytes do not hash to the claimed digest",
        ));
    }
    let parsed = parse_artifact_envelope(&payload.artifact_bytes)?;
    if parsed.family != payload.family || parsed.version != payload.version {
        return Err(Error::engine(
            "definition artifact declaration mismatch: envelope family/version differ from the revision key",
        ));
    }

    let identity = RevisionIdentity {
        family: payload.family.clone(),
        version: payload.version,
        digest: payload.digest.clone(),
    };
    if payload.value != identity.value_string() {
        return Err(Error::engine(
            "definition artifact value mismatch: revision key does not match family/version/digest",
        ));
    }
    if subject_id != identity.value_id() {
        return Err(Error::engine(
            "definition artifact subject mismatch: event subject is not the revision projection id",
        ));
    }
    Ok(identity)
}

/// One parsed artifact envelope: the declarations inside the hashed bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedArtifactEnvelope {
    pub family: String,
    pub version: u32,
    /// The revision-scoped kind descriptors, derived from the exact bytes.
    pub kinds: serde_json::Value,
}

/// Split a revision-keyed value string `family@version#digest` back into its
/// parts. Only revision keys parse; anything else is not a revision, and
/// callers skip it.
pub fn parse_revision_key(value: &str) -> Result<(String, u32, String)> {
    let Some((head, digest)) = value.rsplit_once('#') else {
        return Err(Error::engine(format!(
            "definition artifact value '{value}' has no digest split"
        )));
    };
    let Some((family, version)) = head.rsplit_once('@') else {
        return Err(Error::engine(format!(
            "definition artifact value '{value}' has no version split"
        )));
    };

    let version: u32 = version.parse().map_err(|_| {
        Error::engine(format!(
            "definition artifact value '{value}' carries a non-numeric version"
        ))
    })?;
    Ok((family.to_string(), version, digest.to_string()))
}

/// Definition-language marker for the richer discovery envelope (v2 kernel
/// slice 2, `native.defn/2`). Test-only: the shared parser below never
/// interprets it; only the `#[cfg(test)]` kernel path validates `/2`
/// semantics. v1 envelopes carry no `interpreter` key at all.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub const DEFN2_INTERPRETER: &str = "native.defn/2";

/// Definition-language marker for the third language (`native.defn/3`),
/// additive over `/2`: identity may be per-record, two more field types
/// (`choice`, `date`), an optional per-field `description`, and required
/// `text` must be non-blank. Dispatch is per event, so `/1` and `/2` bytes
/// and records keep their meaning.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub const DEFN3_INTERPRETER: &str = "native.defn/3";

/// Which structured definition language an envelope declares. Only `/2` and
/// `/3` exist today; `/1` envelopes carry no marker.
#[cfg(any(test, feature = "v2-kernel-probe"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefnVersion {
    V2,
    V3,
}

#[cfg(any(test, feature = "v2-kernel-probe"))]
impl DefnVersion {
    /// Human label used in refusals, matching the pre-`/3` messages exactly.
    fn label(self) -> &'static str {
        match self {
            DefnVersion::V2 => "defn/2",
            DefnVersion::V3 => "defn/3",
        }
    }
}

/// Parse the minimal explicit JSON envelope the bytes must carry:
/// `{"family": <string>, "version": <u32>, "kinds": <array>, ...}`. Extra
/// fields are allowed and preserved (they are inside the hashed bytes);
/// missing or mistyped `family`/`version`/`kinds` reject the artifact.
///
/// Identity may be declared either as explicit `family`/`version` fields or
/// via a `package_ref` of the form `family@version`, or both, provided every
/// present declaration agrees.
pub fn parse_artifact_envelope(artifact_bytes: &str) -> Result<ParsedArtifactEnvelope> {
    let doc: serde_json::Value = serde_json::from_str(artifact_bytes)
        .map_err(|_| Error::engine("definition artifact bytes must be a JSON envelope object"))?;
    let obj = doc
        .as_object()
        .ok_or_else(|| Error::engine("definition artifact bytes must be a JSON envelope object"))?;
    let (family, version) = envelope_identity(obj)?;
    let kinds = obj
        .get("kinds")
        .filter(|k| k.is_array())
        .cloned()
        .ok_or_else(|| Error::engine("definition artifact envelope must carry an array 'kinds'"))?;
    Ok(ParsedArtifactEnvelope {
        family,
        version,
        kinds,
    })
}

/// Kernel-side gate for definition bytes (test-only): envelopes without an
/// `interpreter` key pass as the legacy language; `native.defn/2` and
/// `native.defn/3` run the full semantic validation below; any other marker
/// fails loudly. Called only from the `#[cfg(test)]` kernel install/fold,
/// never from production install or replay paths.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub fn validate_kernel_definition_bytes(artifact_bytes: &str) -> Result<()> {
    let _ = parse_artifact_envelope(artifact_bytes)?;
    let doc: serde_json::Value = serde_json::from_str(artifact_bytes)
        .map_err(|_| Error::engine("definition artifact bytes must be a JSON envelope object"))?;
    let marker = doc.get("interpreter").and_then(serde_json::Value::as_str);
    match marker {
        None => Ok(()),
        Some(DEFN2_INTERPRETER) => validate_defn_envelope(
            doc.as_object().expect("shared parse accepted an object"),
            DefnVersion::V2,
        ),
        Some(DEFN3_INTERPRETER) => validate_defn_envelope(
            doc.as_object().expect("shared parse accepted an object"),
            DefnVersion::V3,
        ),
        Some(unknown) => Err(Error::engine(format!(
            "unknown definition interpreter '{unknown}'"
        ))),
    }
}

/// Whether retained artifact bytes declare the `native.defn/2` language
/// (test-only detection; semantic validation lives in
/// [`validate_kernel_definition_bytes`]).
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub fn envelope_is_defn2(artifact_bytes: &str) -> Result<bool> {
    let parsed = parse_artifact_envelope(artifact_bytes)?;
    let _ = parsed;
    let doc: serde_json::Value = serde_json::from_str(artifact_bytes)
        .map_err(|_| Error::engine("definition artifact bytes must be a JSON envelope object"))?;
    Ok(doc
        .get("interpreter")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|marker| marker == DEFN2_INTERPRETER))
}

/// Whether retained artifact bytes declare the `native.defn/3` language
/// (test-only detection; semantic validation lives in
/// [`validate_kernel_definition_bytes`]).
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub fn envelope_is_defn3(artifact_bytes: &str) -> Result<bool> {
    let _ = parse_artifact_envelope(artifact_bytes)?;
    let doc: serde_json::Value = serde_json::from_str(artifact_bytes)
        .map_err(|_| Error::engine("definition artifact bytes must be a JSON envelope object"))?;
    Ok(doc
        .get("interpreter")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|marker| marker == DEFN3_INTERPRETER))
}

/// Validate the structured discovery semantics inside an already-shaped
/// envelope object (test-only): a non-empty `primary_type`, then per kind
/// token — `fields`, `identity`, `links`, `refines`, `maturity`, and a
/// human `description`. Every violation names the kind and the offending
/// key so install refuses loudly with no event appended.
#[cfg(any(test, feature = "v2-kernel-probe"))]
fn validate_defn_envelope(
    obj: &serde_json::Map<String, serde_json::Value>,
    version: DefnVersion,
) -> Result<()> {
    let label = version.label();
    let primary_type = obj
        .get("primary_type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::engine(format!(
                "{label} envelope must carry a non-empty string 'primary_type'"
            ))
        })?;
    if primary_type.trim().is_empty() {
        return Err(Error::engine(format!(
            "{label} envelope must carry a non-empty string 'primary_type'"
        )));
    }
    let kinds = obj
        .get("kinds")
        .and_then(|k| k.as_array())
        .ok_or_else(|| Error::engine("definition artifact envelope must carry an array 'kinds'"))?;
    if kinds.is_empty() {
        return Err(Error::engine(format!(
            "{label} envelope must declare at least one kind"
        )));
    }
    let mut tokens: Vec<&str> = Vec::with_capacity(kinds.len());
    for entry in kinds {
        let kind_obj = entry.as_object().ok_or_else(|| {
            Error::engine(format!(
                "{label} envelope kind entries must be objects with a 'token'"
            ))
        })?;
        let token = kind_obj
            .get("token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::engine(format!(
                    "{label} envelope kind entries must be objects with a 'token'"
                ))
            })?;
        validate_part("token", token)?;
        if tokens.contains(&token) {
            return Err(Error::engine(format!(
                "{label} envelope declares kind token '{token}' twice"
            )));
        }
        tokens.push(token);
    }
    for entry in kinds {
        let kind_obj = entry.as_object().expect("checked above");
        let token = kind_obj
            .get("token")
            .and_then(serde_json::Value::as_str)
            .expect("checked");
        validate_defn_kind(version, token, primary_type, kind_obj, &tokens)?;
    }
    Ok(())
}

/// Validate one kind entry (test-only). `tokens` are the envelope's declared
/// kind tokens; link targets must name one of them (install-time scope is
/// this envelope only — cross-envelope targets are a link-time concern).
#[cfg(any(test, feature = "v2-kernel-probe"))]
fn validate_defn_kind(
    version: DefnVersion,
    token: &str,
    primary_type: &str,
    kind_obj: &serde_json::Map<String, serde_json::Value>,
    tokens: &[&str],
) -> Result<()> {
    const BASE_FIELD_TYPES: &[&str] = &["text", "integer", "number", "boolean", "time"];
    const DEFN3_FIELD_TYPES: &[&str] = &[
        "text", "integer", "number", "boolean", "time", "choice", "date",
    ];
    let label = version.label();
    let field_types: &[&str] = match version {
        DefnVersion::V2 => BASE_FIELD_TYPES,
        DefnVersion::V3 => DEFN3_FIELD_TYPES,
    };
    let fields = kind_obj
        .get("fields")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::engine(format!(
                "{label} kind '{token}' must carry an array 'fields'"
            ))
        })?;
    let mut names: Vec<&str> = Vec::with_capacity(fields.len());
    for field in fields {
        let field_obj = field.as_object().ok_or_else(|| {
            Error::engine(format!(
                "{label} kind '{token}' field entries must be objects"
            ))
        })?;
        let name = field_obj
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::engine(format!(
                    "{label} kind '{token}' field entries need a string 'name'"
                ))
            })?;
        if name.trim().is_empty() || names.contains(&name) {
            return Err(Error::engine(format!(
                "{label} kind '{token}' has an empty or duplicate field name '{name}'"
            )));
        }
        let field_type = field_obj
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::engine(format!(
                    "{label} kind '{token}' field '{name}' needs a string 'type'"
                ))
            })?;
        if !field_types.contains(&field_type) {
            return Err(Error::engine(format!(
                "{label} kind '{token}' field '{name}' has unknown field type '{field_type}'"
            )));
        }
        if field_obj
            .get("required")
            .and_then(serde_json::Value::as_bool)
            .is_none()
        {
            return Err(Error::engine(format!(
                "{label} kind '{token}' field '{name}' needs a boolean 'required'"
            )));
        }
        if version == DefnVersion::V3 {
            if let Some(description) = field_obj.get("description") {
                let valid = description.as_str().is_some_and(|s| !s.trim().is_empty());
                if !valid {
                    return Err(Error::engine(format!(
                        "{label} kind '{token}' field '{name}' 'description' must be a non-empty string"
                    )));
                }
            }
            if field_type == "choice" {
                let values = field_obj
                    .get("values")
                    .and_then(serde_json::Value::as_array)
                    .filter(|values| !values.is_empty())
                    .ok_or_else(|| {
                        Error::engine(format!(
                            "{label} kind '{token}' field '{name}' type 'choice' needs a non-empty 'values' array"
                        ))
                    })?;
                let mut seen: Vec<&str> = Vec::with_capacity(values.len());
                for value in values {
                    let value = value.as_str().ok_or_else(|| {
                        Error::engine(format!(
                            "{label} kind '{token}' field '{name}' 'values' entries must be strings"
                        ))
                    })?;
                    if value.trim().is_empty() {
                        return Err(Error::engine(format!(
                            "{label} kind '{token}' field '{name}' 'values' entries must not be blank"
                        )));
                    }
                    if seen.contains(&value) {
                        return Err(Error::engine(format!(
                            "{label} kind '{token}' field '{name}' 'values' lists '{value}' twice"
                        )));
                    }
                    seen.push(value);
                }
            } else if field_obj.contains_key("values") {
                return Err(Error::engine(format!(
                    "{label} kind '{token}' field '{name}' of type '{field_type}' must not carry 'values'"
                )));
            }
        }
        names.push(name);
    }
    let identity_obj = kind_obj.get("identity").and_then(|v| v.as_object());
    // `/3` adds a per-record identity mode. `/2` ignores any extra keys and
    // keeps requiring `identity.field`, exactly as before.
    if version == DefnVersion::V3 && identity_obj.and_then(|o| o.get("mode")).is_some() {
        let mode = identity_obj
            .and_then(|o| o.get("mode"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::engine(format!(
                    "{label} kind '{token}' 'identity.mode' must be a string"
                ))
            })?;
        if mode != "record" {
            return Err(Error::engine(format!(
                "{label} kind '{token}' has unknown identity mode '{mode}'"
            )));
        }
        if identity_obj.is_some_and(|o| o.contains_key("field")) {
            return Err(Error::engine(format!(
                "{label} kind '{token}' 'identity' must not carry both 'mode' and 'field'"
            )));
        }
    } else {
        let identity_field = identity_obj
            .and_then(|o| o.get("field"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::engine(format!(
                    "{label} kind '{token}' must carry 'identity.field'"
                ))
            })?;
        if !names.contains(&identity_field) {
            return Err(Error::engine(format!(
                "{label} kind '{token}' identity names unknown identity field '{identity_field}'"
            )));
        }
    }
    let links = kind_obj
        .get("links")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::engine(format!(
                "{label} kind '{token}' must carry an array 'links'"
            ))
        })?;
    for link in links {
        validate_defn_link(version, token, primary_type, link, tokens)?;
    }
    if let Some(refines) = kind_obj.get("refines") {
        let base = refines.as_str().ok_or_else(|| {
            Error::engine(format!("{label} kind '{token}' 'refines' must be a string"))
        })?;
        if base == token || !tokens.contains(&base) {
            return Err(Error::engine(format!(
                "{label} kind '{token}' refines unknown kind '{base}'"
            )));
        }
    }
    let maturity = kind_obj
        .get("maturity")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::engine(format!(
                "{label} kind '{token}' must carry a string 'maturity'"
            ))
        })?;
    if !["draft", "current", "superseded"].contains(&maturity) {
        return Err(Error::engine(format!(
            "{label} kind '{token}' has unknown maturity '{maturity}'"
        )));
    }
    let description = kind_obj
        .get("description")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if description.trim().is_empty() {
        return Err(Error::engine(format!(
            "{label} kind '{token}' must carry a non-empty 'description'"
        )));
    }
    Ok(())
}

/// Validate one link entry (test-only): non-empty predicate, an in-envelope
/// target definition, a direction, and an optional cardinality.
#[cfg(any(test, feature = "v2-kernel-probe"))]
fn validate_defn_link(
    version: DefnVersion,
    token: &str,
    envelope_primary_type: &str,
    link: &serde_json::Value,
    tokens: &[&str],
) -> Result<()> {
    let label = version.label();
    let link_obj = link.as_object().ok_or_else(|| {
        Error::engine(format!(
            "{label} kind '{token}' link entries must be objects"
        ))
    })?;
    let predicate = link_obj
        .get("predicate")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if predicate.trim().is_empty() {
        return Err(Error::engine(format!(
            "{label} kind '{token}' links need a non-empty 'predicate'"
        )));
    }
    let target = link_obj
        .get("target")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            Error::engine(format!(
                "{label} kind '{token}' link '{predicate}' needs an object 'target'"
            ))
        })?;
    let target_type = target
        .get("primary_type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let target_kind = target
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let _ = envelope_primary_type;
    if target_type.trim().is_empty() || !tokens.contains(&target_kind) {
        return Err(Error::engine(format!(
            "{label} kind '{token}' link '{predicate}' names unknown link target '{target_type}/{target_kind}'"
        )));
    }
    let direction = link_obj
        .get("direction")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !["out", "in", "either"].contains(&direction) {
        return Err(Error::engine(format!(
            "{label} kind '{token}' link '{predicate}' has unknown direction '{direction}'"
        )));
    }
    if let Some(cardinality) = link_obj.get("cardinality") {
        let cardinality = cardinality.as_str().ok_or_else(|| {
            Error::engine(format!(
                "{label} kind '{token}' link '{predicate}' 'cardinality' must be a string"
            ))
        })?;
        if !["one", "many"].contains(&cardinality) {
            return Err(Error::engine(format!(
                "{label} kind '{token}' link '{predicate}' has unknown cardinality '{cardinality}'"
            )));
        }
    }
    Ok(())
}

/// Resolve the envelope's declared identity. A present declaration is never
/// silently ignored: a partial explicit pair, a non-string `package_ref`,
/// and a `package_ref` that disagrees with the explicit fields are all
/// rejected before anything is appended.
fn envelope_identity(obj: &serde_json::Map<String, serde_json::Value>) -> Result<(String, u32)> {
    let explicit = match (obj.get("family"), obj.get("version")) {
        (Some(family), Some(version)) => {
            let family = family.as_str().ok_or_else(|| {
                Error::engine("definition artifact envelope must carry a string 'family'")
            })?;
            validate_part("family", family)?;
            let version = version.as_u64().ok_or_else(|| {
                Error::engine("definition artifact envelope must carry an integer 'version'")
            })?;
            let version: u32 = version.try_into().map_err(|_| {
                Error::engine("definition artifact envelope 'version' does not fit u32")
            })?;
            Some((family.to_string(), version))
        }
        (None, None) => None,
        _ => return Err(Error::engine(
            "definition artifact envelope must carry both 'family' and 'version', not one of them",
        )),
    };
    match obj.get("package_ref") {
        None => explicit.ok_or_else(|| {
            Error::engine(
                "definition artifact envelope must carry 'family'/'version' or a 'package_ref' of the form family@version",
            )
        }),
        Some(package_ref) => {
            let package_ref = package_ref.as_str().ok_or_else(|| {
                Error::engine("definition artifact envelope 'package_ref' must be a string")
            })?;
            let declared = parse_package_ref(package_ref)?;
            match explicit {
                Some(explicit) if explicit != declared => Err(Error::engine(
                    "definition artifact envelope 'package_ref' disagrees with explicit 'family'/'version'",
                )),
                _ => Ok(declared),
            }
        }
    }
}

/// Split a package reference `family@version` into its registry parts. Only
/// the exact `family@version` form parses.
fn parse_package_ref(package_ref: &str) -> Result<(String, u32)> {
    let Some((family, version)) = package_ref.rsplit_once('@') else {
        return Err(Error::engine(format!(
            "definition artifact package_ref '{package_ref}' has no version split"
        )));
    };
    validate_part("family", family)?;
    let version: u32 = version.parse().map_err(|_| {
        Error::engine(format!(
            "definition artifact package_ref '{package_ref}' carries a non-numeric version"
        ))
    })?;
    Ok((family.to_string(), version))
}

/// The projection envelope the fold stores alongside the revision. `kinds`
/// are re-derived here by parsing the verified bytes, so what replay
/// rebuilds is always what the hashed bytes declare — never a
/// caller-supplied copy.
pub fn envelope_from_payload(payload: &DefinitionArtifactInstalledPayload) -> serde_json::Value {
    let kinds = parse_artifact_envelope(&payload.artifact_bytes)
        .map(|parsed| parsed.kinds)
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "format": ARTIFACT_ENVELOPE_FORMAT,
        "algorithm": DIGEST_ALGORITHM,
        "family": payload.family,
        "version": payload.version,
        "digest": payload.digest,
        "artifact_bytes": payload.artifact_bytes,
        "kinds": kinds,
    })
}

/// Append one verified `definition_artifact.installed` event inside the
/// caller's write transaction. The caller owns conflict and retry policy;
/// this writer only guarantees the appended event verifies.
pub(crate) async fn append_definition_artifact_installed_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    payload: DefinitionArtifactInstalledPayload,
    actor: Option<&str>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<RevisionIdentity> {
    use super::log::{append_meta_in, MetaAppendSpec};

    let subject_id = format!("vv:{}:{}", payload.vocabulary_id, payload.value);
    let identity = verify_installed_payload(&subject_id, &payload)?;
    let event_payload = serde_json::to_value(&payload)?;
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(&subject_id, "definition_artifact.installed", event_payload)
            .with_actor(actor),
        act_alloc,
    )
    .await?;
    Ok(identity)
}

#[cfg(test)]
mod definition_artifact_tests {
    use super::*;

    fn envelope_bytes() -> String {
        r#"{"family":"test.family","version":3,"kinds":["a",{"token":"b"}]}"#.to_string()
    }

    fn installed_payload() -> DefinitionArtifactInstalledPayload {
        let artifact_bytes = envelope_bytes();
        let digest = digest_artifact_bytes(artifact_bytes.as_bytes());
        let family = "test.family".to_string();
        let version = 3;
        let value = format!("{family}@{version}#{digest}");
        DefinitionArtifactInstalledPayload {
            vocabulary_id: ARTIFACT_VOCABULARY_ID.to_string(),
            value,
            family,
            version,
            digest,
            artifact_bytes,
        }
    }

    #[test]
    fn verify_accepts_a_consistent_payload() {
        let payload = installed_payload();
        let subject_id = format!("vv:{}:{}", payload.vocabulary_id, payload.value);
        let identity = verify_installed_payload(&subject_id, &payload).unwrap();
        assert_eq!(identity.family, "test.family");
        assert_eq!(identity.version, 3);
    }

    #[test]
    fn verify_rejects_a_tampered_digest() {
        let mut payload = installed_payload();
        payload.digest = "0".repeat(64);
        let subject_id = format!("vv:{}:{}", payload.vocabulary_id, payload.value);
        assert!(verify_installed_payload(&subject_id, &payload).is_err());
    }

    #[test]
    fn revision_key_round_trips() {
        let payload = installed_payload();
        let (family, version, digest) = parse_revision_key(&payload.value).unwrap();
        assert_eq!(
            (family.as_str(), version, digest.as_str()),
            ("test.family", 3, payload.digest.as_str())
        );
    }

    fn field_identity_envelope(marker: &str) -> String {
        format!(
            r#"{{"family":"test.defn","version":1,"primary_type":"Widget","interpreter":"{marker}","kinds":[{{"token":"widget","fields":[{{"name":"code","type":"text","required":true}}],"identity":{{"field":"code"}},"links":[],"maturity":"current","description":"A widget."}}]}}"#
        )
    }

    #[test]
    fn defn3_marker_is_dispatched_and_distinct_from_defn2() {
        let bytes = field_identity_envelope(DEFN3_INTERPRETER);
        validate_kernel_definition_bytes(&bytes).unwrap();
        assert!(envelope_is_defn3(&bytes).unwrap());
        assert!(!envelope_is_defn2(&bytes).unwrap());
    }

    #[test]
    fn defn2_fixture_still_dispatches_as_two() {
        let bytes = field_identity_envelope(DEFN2_INTERPRETER);
        validate_kernel_definition_bytes(&bytes).unwrap();
        assert!(envelope_is_defn2(&bytes).unwrap());
        assert!(!envelope_is_defn3(&bytes).unwrap());
    }
}
