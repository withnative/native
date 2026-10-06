//! Gated v2 package install seam (slice 3, S2a test-only prototype).
//!
//! One transaction installs every embedded definition through the existing
//! `install_definition_artifact_as_in` seam, then appends exactly one
//! `package_artifact.installed.v1` meta event projected into the dedicated
//! `package_artifacts` table. The caller owns the transaction: any failure
//! rolls everything back, leaving no partial log or projection state.
//!
//! Pre-append rules (write path): an exact retry of the same
//! `(namespace, name, version, digest)` appends nothing and returns the
//! existing identity; the same triple with a different digest refuses before
//! anything is appended. Authorization (Manage on the kernel root) lives with
//! the kernel-level wrapper, not here: this seam records the actor string for
//! attribution only, mirroring `install_definition_artifact_as_in`.
//!
//! Limited authority model: the namespace is a locally asserted label, not
//! verified publisher ownership. What the host enforces is scope authority —
//! only a principal with Manage on the kernel root may install — plus exact
//! byte identity (digest) and collision refusal. Two workspaces may assert
//! the same namespace for different bytes; the digest, not the label, is the
//! identity. Publisher binding is explicitly out of scope for this slice.

use sqlx::{Sqlite, SqliteConnection, Transaction};

use crate::error::{Error, Result};
use crate::meta::events::PackageArtifactInstalledV1Payload;
use crate::meta::log::{append_meta_in, MetaAppendSpec};
use crate::package_manifest::{ManifestIdentity, PackageManifest};

/// Package projection DDL, owned by the v2 kernel (never frozen v1 DDL, no
/// migration): one immutable row per installed `(namespace, name, version)`,
/// carrying the canonical manifest bytes and package digest plus the
/// authorizing event seq. Gated setup code executes these explicitly.
pub const PACKAGE_DDL: [&str; 2] = [
    r#"CREATE TABLE package_artifacts (
     id             TEXT PRIMARY KEY,
     namespace      TEXT NOT NULL,
     name           TEXT NOT NULL,
     version        INTEGER NOT NULL CHECK (version >= 0),
     digest         TEXT NOT NULL CHECK (length(digest) = 64),
     manifest_bytes TEXT NOT NULL CHECK (length(manifest_bytes) > 0),
     event_seq      INTEGER NOT NULL CHECK (event_seq >= 1),
     created_at     TEXT NOT NULL,
     UNIQUE (namespace, name, version)
   )"#,
    r#"CREATE INDEX idx_package_artifacts_namespace
        ON package_artifacts(namespace, name, version)"#,
];

/// Deterministic meta-event subject for one package revision.
pub fn package_subject(namespace: &str, name: &str, version: u32, digest: &str) -> String {
    format!("package:{namespace}/{name}@{version}#{digest}")
}

/// Literal subject prefix for one package triple (any digest). Compared with
/// substr equality, never LIKE (`_` is a legal token char and a LIKE
/// wildcard).
pub fn package_triple_prefix(namespace: &str, name: &str, version: u32) -> String {
    format!("package:{namespace}/{name}@{version}#")
}

/// Test setup: the frozen DDL deliberately has no package table, so every
/// gated test applies `PACKAGE_DDL` explicitly after `create_database`.
pub(crate) async fn ensure_package_tables(db: &crate::db::Db) -> Result<()> {
    for statement in PACKAGE_DDL {
        sqlx::query(statement).execute(db.write_pool()).await?;
    }
    Ok(())
}

/// Verify a package-installed payload against its subject before append or
/// projection: the triple matches, the manifest bytes parse and fully
/// re-validate, and their JCS digest equals the claimed digest.
pub fn verify_package_payload(
    subject_id: &str,
    payload: &PackageArtifactInstalledV1Payload,
) -> Result<ManifestIdentity> {
    if subject_id
        != package_subject(
            &payload.namespace,
            &payload.name,
            payload.version,
            &payload.digest,
        )
    {
        return Err(Error::engine(
            "package artifact subject does not match revision identity",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(&payload.manifest_bytes)
        .map_err(|_| Error::engine("package manifest bytes must be canonical JSON"))?;
    // The event contract is canonical bytes, not merely JSON bytes: the
    // stored text must equal the JCS serialization of its own parsed value,
    // so two encodings of one manifest can never share an event stream.
    let canonical = crate::canonical_json::canonical_json(&value);
    if payload.manifest_bytes.as_bytes() != canonical.as_slice() {
        return Err(Error::engine(
            "package manifest bytes are not canonical (JCS) encoding",
        ));
    }
    let recomputed = crate::canonical_json::digest_json(&value);
    if recomputed != payload.digest {
        return Err(Error::engine(
            "package artifact digest does not match canonical manifest bytes",
        ));
    }
    let manifest = PackageManifest::from_canonical_value(&value)?;
    if manifest.namespace != payload.namespace
        || manifest.name != payload.name
        || manifest.version != payload.version
    {
        return Err(Error::engine(
            "package manifest triple does not match payload triple",
        ));
    }
    Ok(ManifestIdentity {
        namespace: payload.namespace.clone(),
        name: payload.name.clone(),
        version: payload.version,
        digest: payload.digest.clone(),
    })
}

/// Install one immutable package revision inside the caller's transaction.
///
/// Validates the manifest, installs every embedded definition through the
/// registry seam, then appends the single package-installed event. Exact
/// retry returns the existing identity and appends nothing; a
/// same-triple/different-digest candidate refuses before any
/// append. Any invalid embedded definition aborts the whole install — the
/// caller rolls back, so history is unchanged.
pub(crate) struct PackageInstallOutcome {
    pub identity: ManifestIdentity,
}

pub(crate) async fn install_package_in(
    tx: &mut Transaction<'static, Sqlite>,
    manifest: &PackageManifest,
    actor: Option<&str>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<PackageInstallOutcome> {
    manifest.validate()?;
    let digest = manifest.package_digest()?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT digest FROM package_artifacts WHERE namespace = ? AND name = ? AND version = ?",
    )
    .bind(&manifest.namespace)
    .bind(&manifest.name)
    .bind(manifest.version as i64)
    .fetch_optional(&mut **tx)
    .await?;
    if existing.is_none() {
        // The projection is not authoritative: a deleted or tampered-away
        // row must not let a new install append a duplicate or conflicting
        // event that only future replay would catch. The meta log is the
        // authority — any prior install event for this triple is corruption.
        let triple_prefix =
            package_triple_prefix(&manifest.namespace, &manifest.name, manifest.version);
        let prior: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM meta_events WHERE type = 'package_artifact.installed.v1'
              AND substr(subject_id, 1, length(?)) = ?",
        )
        .bind(&triple_prefix)
        .bind(&triple_prefix)
        .fetch_one(&mut **tx)
        .await?;
        if prior != 0 {
            return Err(Error::engine(format!(
                "package projection/log disagreement: {}/{}@{} has {} prior install event(s) but no projection row",
                manifest.namespace, manifest.name, manifest.version, prior
            )));
        }
    }
    if let Some(existing_digest) = existing {
        if existing_digest != digest {
            return Err(Error::engine(format!(
                "package conflict: {}/{}@{} is already installed with a different digest",
                manifest.namespace, manifest.name, manifest.version
            )));
        }
        // Never acknowledge a possibly corrupt projection on digest alone:
        // the verified read re-checks the authorizing event, the stored
        // bytes, and every pinned definition before an exact retry returns.
        let stored = read_package_in(
            &mut *tx,
            &manifest.namespace,
            &manifest.name,
            manifest.version,
            &digest,
        )
        .await?
        .ok_or_else(|| Error::engine("package projection vanished mid-install"))?;
        return Ok(PackageInstallOutcome {
            identity: stored.identity,
        });
    }
    for entry in &manifest.definitions {
        crate::definition_registry::install_definition_artifact_as_in(
            tx,
            &entry.family,
            entry.version,
            entry.artifact_bytes.as_bytes(),
            actor,
            act_alloc,
        )
        .await?;
    }
    let canonical = manifest.canonical_value()?;
    let manifest_bytes =
        String::from_utf8(crate::canonical_json::canonical_json(&canonical)).expect("JCS is UTF-8");
    let payload = PackageArtifactInstalledV1Payload {
        namespace: manifest.namespace.clone(),
        name: manifest.name.clone(),
        version: manifest.version,
        digest: digest.clone(),
        manifest_bytes,
    };
    let subject_id = package_subject(
        &payload.namespace,
        &payload.name,
        payload.version,
        &payload.digest,
    );
    verify_package_payload(&subject_id, &payload)?;
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            &subject_id,
            "package_artifact.installed.v1",
            serde_json::to_value(&payload)?,
        )
        .with_actor(actor),
        act_alloc,
    )
    .await?;
    Ok(PackageInstallOutcome {
        identity: ManifestIdentity {
            namespace: manifest.namespace.clone(),
            name: manifest.name.clone(),
            version: manifest.version,
            digest,
        },
    })
}

/// One retained package revision as read back from the projection, with the
/// authorizing event seq for future adoption ordering.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPackage {
    pub identity: ManifestIdentity,
    pub manifest: PackageManifest,
    pub event_seq: i64,
}

/// Transaction-scoped verified read for future adoption. Reads the projection
/// row, then asserts projection/log agreement: the authorizing meta event
/// (by subject) must exist with matching bytes and digest, and every embedded
/// definition revision must still be present with exact bytes and digest. A
/// missing package is `Ok(None)`; any disagreement is an error, never a
/// fallback to another revision.
pub(crate) async fn read_package_in(
    conn: &mut SqliteConnection,
    namespace: &str,
    name: &str,
    version: u32,
    digest: &str,
) -> Result<Option<StoredPackage>> {
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT manifest_bytes, digest, event_seq FROM package_artifacts
          WHERE namespace = ? AND name = ? AND version = ?",
    )
    .bind(namespace)
    .bind(name)
    .bind(version as i64)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((manifest_bytes, stored_digest, event_seq)) = row else {
        return Ok(None);
    };
    if stored_digest != digest {
        return Err(Error::engine(
            "package revision digest does not match the installed triple",
        ));
    }
    let subject_id = package_subject(namespace, name, version, digest);
    // A later duplicate install event for this triple (any digest) must not
    // be silently ignored: the honest log holds exactly one install per
    // triple, so anything else is corruption. The prefix comparison is a
    // literal substr equality, never LIKE: namespace/name tokens permit `_`,
    // which is a LIKE wildcard and would overmatch sibling triples.
    let triple_prefix = format!("package:{namespace}/{name}@{version}#");
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM meta_events WHERE type = 'package_artifact.installed.v1'
          AND substr(subject_id, 1, length(?)) = ?",
    )
    .bind(&triple_prefix)
    .bind(&triple_prefix)
    .fetch_one(&mut *conn)
    .await?;
    if event_count != 1 {
        return Err(Error::engine(format!(
            "package install event count is {event_count}, expected exactly one for {namespace}/{name}@{version}"
        )));
    }
    let event: Option<(String, i64)> =
        sqlx::query_as("SELECT payload, seq FROM meta_events WHERE subject_id = ? AND type = ?")
            .bind(&subject_id)
            .bind("package_artifact.installed.v1")
            .fetch_optional(&mut *conn)
            .await?;
    let Some((payload_text, event_seq_log)) = event else {
        return Err(Error::engine(
            "package projection has no authorizing log event",
        ));
    };
    if event_seq_log != event_seq {
        return Err(Error::engine(
            "package projection event seq disagrees with its authorizing log event",
        ));
    }
    let payload: PackageArtifactInstalledV1Payload = serde_json::from_str(&payload_text)?;
    if payload.manifest_bytes != manifest_bytes || payload.digest != stored_digest {
        return Err(Error::engine(
            "package projection disagrees with its authorizing log event",
        ));
    }
    // Full verifier: event and projection tampered together (bytes changed
    // on both sides, claimed digest left original) must fail here. Agreement
    // plus shape validation alone would accept jointly forged bytes whose
    // recomputed digest was never compared to the claim.
    let verified = verify_package_payload(&subject_id, &payload)?;
    if verified.digest != digest
        || verified.namespace != namespace
        || verified.name != name
        || verified.version != version
    {
        return Err(Error::engine(
            "package verifier identity disagrees with the requested revision",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(&manifest_bytes)
        .map_err(|_| Error::engine("stored package manifest bytes are not JSON"))?;
    let manifest = PackageManifest::from_canonical_value(&value)?;
    for entry in &manifest.definitions {
        let stored: Option<(String, String)> = sqlx::query_as(
            "SELECT digest, artifact_bytes FROM definition_artifacts
              WHERE family = ? AND version = ?",
        )
        .bind(&entry.family)
        .bind(entry.version as i64)
        .fetch_optional(&mut *conn)
        .await?;
        match stored {
            Some((d, b)) if d == entry.digest && b == entry.artifact_bytes => {}
            _ => {
                return Err(Error::engine(format!(
                    "package definition '{}@{}' is missing or disagrees with the package pin",
                    entry.family, entry.version
                )));
            }
        }
    }
    Ok(Some(StoredPackage {
        identity: ManifestIdentity {
            namespace: namespace.to_string(),
            name: name.to_string(),
            version,
            digest: digest.to_string(),
        },
        manifest,
        event_seq,
    }))
}
