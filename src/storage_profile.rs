//! Runtime storage-profile introspection, advisory auditing, and strict
//! portability enforcement.
//!
//! The profile fixtures are the source of truth. This module compiles them into
//! the binary, validates them against the protocol schema before use, and
//! resolves exact `(id, revision, connection mode)` targets. Audits remain
//! read-only, while an explicit persisted policy can opt a database into
//! fail-closed request admission and mutation-boundary enforcement.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

use crate::{Error, Result};

const PROFILE_SCHEMA: &str = include_str!("../protocol/storage-portability/v1/profile.schema.json");
const SQLITE_LOCAL_PROFILE: &str =
    include_str!("../protocol/storage-portability/v1/profiles/sqlite-local.json");
const SQLITE_LOCAL_PROFILE_V2: &str =
    include_str!("../protocol/storage-portability/v1/profiles/sqlite-local-v2.json");
const POSTGRES_SERVER_PROFILE: &str =
    include_str!("../protocol/storage-portability/v1/profiles/postgres-server.json");
const POSTGRES_SERVER_PROFILE_V2: &str =
    include_str!("../protocol/storage-portability/v1/profiles/postgres-server-v2.json");
const POSTGRES_SERVER_PROFILE_V3: &str =
    include_str!("../protocol/storage-portability/v1/profiles/postgres-server-v3.json");
const POSTGRES_SERVER_PROFILE_V4: &str =
    include_str!("../protocol/storage-portability/v1/profiles/postgres-server-v4.json");
const POSTGRES_SERVER_PROFILE_V5: &str =
    include_str!("../protocol/storage-portability/v1/profiles/postgres-server-v5.json");
const TURSO_LOCAL_PROFILE: &str =
    include_str!("../protocol/storage-portability/v1/profiles/turso-local.json");
const TURSO_REMOTE_PROFILE: &str =
    include_str!("../protocol/storage-portability/v1/profiles/turso-remote.json");
const TURSO_EMBEDDED_SYNC_PROFILE: &str =
    include_str!("../protocol/storage-portability/v1/profiles/turso-embedded-sync.json");
const TURSO_LOCAL_PROFILE_V2: &str =
    include_str!("../protocol/storage-portability/v1/profiles/turso-local-v2.json");
const TURSO_LOCAL_PROFILE_V3: &str =
    include_str!("../protocol/storage-portability/v1/profiles/turso-local-v3.json");
const TURSO_LOCAL_PROFILE_V4: &str =
    include_str!("../protocol/storage-portability/v1/profiles/turso-local-v4.json");
const TURSO_REMOTE_PROFILE_V2: &str =
    include_str!("../protocol/storage-portability/v1/profiles/turso-remote-v2.json");
const TURSO_EMBEDDED_SYNC_PROFILE_V2: &str =
    include_str!("../protocol/storage-portability/v1/profiles/turso-embedded-sync-v2.json");
const LIBSQL_EMBEDDED_REPLICA_PROFILE: &str =
    include_str!("../protocol/storage-portability/v1/profiles/libsql-embedded-replica.json");

const ACTIVE_PROFILE_ID: &str = "sqlite-local";
const ACTIVE_PROFILE_REVISION: u64 = 2;
const ACTIVE_CONNECTION_MODE: &str = "embedded";

#[derive(Clone, Debug, Deserialize)]
struct StorageProfile {
    format: String,
    id: String,
    revision: u64,
    status: String,
    engine: Engine,
    frontend: Frontend,
    connection: Connection,
    topology: Topology,
    #[serde(default)]
    operational_identity: Option<OperationalIdentity>,
    capabilities: BTreeMap<String, CapabilityClaim>,
}

#[derive(Clone, Debug, Deserialize)]
struct Engine {
    family: String,
    implementation: String,
    version_requirement: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Frontend {
    dialect: String,
    protocol: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Connection {
    modes: Vec<String>,
    driver: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Topology {
    kind: String,
    logical_database_isolation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OperationalIdentity {
    write_authority: String,
    consistency: String,
    file_semantics: String,
    provider_dependencies: Vec<String>,
    promotion_rules: Vec<String>,
    upstream_sources: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CapabilityClaim {
    support: String,
    portability: String,
    #[serde(default)]
    mode_support: BTreeMap<String, String>,
    #[serde(default)]
    contract: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

impl CapabilityClaim {
    fn effective_support<'a>(&'a self, mode: &str) -> Result<&'a str> {
        if self.mode_support.is_empty() {
            return Ok(&self.support);
        }
        self.mode_support
            .get(mode)
            .map(String::as_str)
            .ok_or_else(|| {
                Error::engine(format!(
                    "storage profile capability does not declare connection mode '{mode}'"
                ))
            })
    }

    fn runtime_value(&self, mode: &str) -> Result<Value> {
        let mut value = serde_json::Map::from_iter([
            ("support".into(), json!(self.effective_support(mode)?)),
            ("portability".into(), json!(self.portability)),
        ]);
        if let Some(contract) = &self.contract {
            value.insert("contract".into(), json!(contract));
        }
        if let Some(provider) = &self.provider {
            value.insert("provider".into(), json!(provider));
        }
        if let Some(notes) = &self.notes {
            value.insert("notes".into(), json!(notes));
        }
        Ok(Value::Object(value))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageTarget {
    pub id: String,
    pub revision: u64,
    pub mode: String,
}

#[derive(Clone)]
struct ProfileCatalog {
    profiles: BTreeMap<(String, u64), StorageProfile>,
    values: BTreeMap<(String, u64), Value>,
}

static CATALOG: OnceLock<std::result::Result<ProfileCatalog, String>> = OnceLock::new();

fn catalog() -> Result<&'static ProfileCatalog> {
    CATALOG
        .get_or_init(build_catalog)
        .as_ref()
        .map_err(|message| Error::engine(message.clone()))
}

fn build_catalog() -> std::result::Result<ProfileCatalog, String> {
    let schema: Value = serde_json::from_str(PROFILE_SCHEMA)
        .map_err(|error| format!("invalid compiled storage profile schema: {error}"))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| format!("invalid compiled storage profile schema: {error}"))?;
    let mut profiles = BTreeMap::new();
    let mut values = BTreeMap::new();
    for fixture in [
        SQLITE_LOCAL_PROFILE,
        SQLITE_LOCAL_PROFILE_V2,
        POSTGRES_SERVER_PROFILE,
        POSTGRES_SERVER_PROFILE_V2,
        POSTGRES_SERVER_PROFILE_V3,
        POSTGRES_SERVER_PROFILE_V4,
        POSTGRES_SERVER_PROFILE_V5,
        TURSO_LOCAL_PROFILE,
        TURSO_REMOTE_PROFILE,
        TURSO_EMBEDDED_SYNC_PROFILE,
        TURSO_LOCAL_PROFILE_V2,
        TURSO_LOCAL_PROFILE_V3,
        TURSO_LOCAL_PROFILE_V4,
        TURSO_REMOTE_PROFILE_V2,
        TURSO_EMBEDDED_SYNC_PROFILE_V2,
        LIBSQL_EMBEDDED_REPLICA_PROFILE,
    ] {
        let value: Value = serde_json::from_str(fixture)
            .map_err(|error| format!("invalid compiled storage profile JSON: {error}"))?;
        let errors = validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if !errors.is_empty() {
            return Err(format!(
                "compiled storage profile violates profile.schema.json: {}",
                errors.join("; ")
            ));
        }
        let profile: StorageProfile = serde_json::from_value(value.clone())
            .map_err(|error| format!("invalid compiled storage profile: {error}"))?;
        let requires_operational_identity = (profile.id.starts_with("turso-")
            && profile.revision >= 2)
            || profile.id == "libsql-embedded-replica";
        if requires_operational_identity && profile.operational_identity.is_none() {
            return Err(format!(
                "compiled storage profile {}@{} omits operational_identity",
                profile.id, profile.revision
            ));
        }
        let declared_modes = profile.connection.modes.iter().collect::<BTreeSet<_>>();
        for (capability, claim) in &profile.capabilities {
            if claim.mode_support.is_empty() {
                continue;
            }
            let scoped_modes = claim.mode_support.keys().collect::<BTreeSet<_>>();
            if scoped_modes != declared_modes {
                return Err(format!(
                    "compiled storage profile {}@{} capability {capability} must declare mode_support for exactly its connection modes",
                    profile.id, profile.revision
                ));
            }
        }
        let key = (profile.id.clone(), profile.revision);
        if profiles.insert(key.clone(), profile).is_some() {
            return Err(format!(
                "duplicate compiled storage profile revision: {}@{}",
                key.0, key.1
            ));
        }
        values.insert(key, value);
    }
    Ok(ProfileCatalog { profiles, values })
}

fn resolve<'a>(catalog: &'a ProfileCatalog, target: &StorageTarget) -> Result<&'a StorageProfile> {
    let profile = catalog
        .profiles
        .get(&(target.id.clone(), target.revision))
        .ok_or_else(|| {
            Error::engine(format!(
                "unknown storage profile revision: {}@{}",
                target.id, target.revision
            ))
        })?;
    if !profile
        .connection
        .modes
        .iter()
        .any(|mode| mode == &target.mode)
    {
        return Err(Error::engine(format!(
            "storage profile {}@{} does not support connection mode '{}'",
            target.id, target.revision, target.mode
        )));
    }
    Ok(profile)
}

fn catalog_declares_profile_mode(catalog: &ProfileCatalog, id: &str, mode: &str) -> bool {
    catalog.profiles.values().any(|profile| {
        profile.id == id
            && profile
                .connection
                .modes
                .iter()
                .any(|declared_mode| declared_mode == mode)
    })
}

fn profile_identity(profile: &StorageProfile, mode: &str) -> Value {
    json!({
        "profile_format": profile.format,
        "id": profile.id,
        "revision": profile.revision,
        "status": profile.status,
        "backend": {
            "engine_family": profile.engine.family,
            "implementation": profile.engine.implementation,
            "version_requirement": profile.engine.version_requirement,
            "frontend_dialect": profile.frontend.dialect,
            "frontend_protocol": profile.frontend.protocol,
            "driver": profile.connection.driver,
        },
        "mode": mode,
    })
}

/// Immutable identity for one exact compiled profile target. Release evidence
/// consumes this rather than retyping driver or topology metadata in a second
/// source. The digest covers the canonical JSON profile fixture itself; the
/// selected connection mode is pinned independently in the identity.
pub fn compiled_profile_identity(target: &StorageTarget) -> Result<Value> {
    let catalog = catalog()?;
    let profile = resolve(catalog, target)?;
    let profile_value = catalog
        .values
        .get(&(target.id.clone(), target.revision))
        .ok_or_else(|| Error::engine("compiled storage profile revision is missing"))?;
    let canonical = serde_jcs::to_vec(profile_value)
        .map_err(|error| Error::engine(format!("cannot canonicalize storage profile: {error}")))?;
    let mut identity = profile_identity(profile, &target.mode);
    let object = identity
        .as_object_mut()
        .expect("profile identity is an object");
    object.insert(
        "topology".into(),
        json!({
            "kind": profile.topology.kind,
            "logical_database_isolation": profile.topology.logical_database_isolation,
        }),
    );
    if let Some(operational_identity) = &profile.operational_identity {
        object.insert(
            "operational_identity".into(),
            serde_json::to_value(operational_identity)
                .expect("operational storage profile identity serializes"),
        );
    }
    object.insert(
        "canonical_profile_sha256".into(),
        json!(hex::encode(Sha256::digest(canonical))),
    );
    Ok(identity)
}

/// Stable machine-readable description of the storage runtime used by the
/// production SQLite registry.
pub fn active_profile_report() -> Result<Value> {
    let catalog = catalog()?;
    let target = StorageTarget {
        id: ACTIVE_PROFILE_ID.into(),
        revision: ACTIVE_PROFILE_REVISION,
        mode: ACTIVE_CONNECTION_MODE.into(),
    };
    let profile = resolve(catalog, &target)?;
    let capabilities = profile
        .capabilities
        .iter()
        .map(|(id, claim)| Ok((id.clone(), claim.runtime_value(&target.mode)?)))
        .collect::<Result<serde_json::Map<String, Value>>>()?;
    let mut identity = profile_identity(profile, &target.mode);
    let object = identity
        .as_object_mut()
        .expect("profile identity is an object");
    object.insert("format".into(), json!("native.storage-runtime.v1"));
    object.insert("capabilities".into(), Value::Object(capabilities));
    object.insert("enforcement".into(), json!("off"));
    object.insert("policy_revision".into(), json!(0));
    object.insert("target_profiles".into(), json!([]));
    object.insert("allow_conversions".into(), json!([]));
    object.insert("revision_floors".into(), json!([]));
    object.insert("admissible_capabilities".into(), json!([]));
    Ok(identity)
}

/// Runtime report with the durable policy overlay applied. The synchronous
/// report above remains the no-row/default shape used before a database exists.
pub async fn active_profile_report_for_db(db: &crate::Db) -> Result<Value> {
    let mut report = active_profile_report()?;
    let policy = portability_policy_report(db).await?;
    let object = report
        .as_object_mut()
        .expect("active storage profile report is an object");
    for key in [
        "enforcement",
        "policy_revision",
        "target_profiles",
        "allow_conversions",
        "revision_floors",
        "admissible_capabilities",
        "catalog_sha256",
    ] {
        if let Some(value) = policy.get(key) {
            object.insert(key.into(), value.clone());
        }
    }
    Ok(report)
}

fn blocker(
    capability: &str,
    code: &str,
    source_support: Option<&str>,
    target_support: Option<&str>,
) -> Value {
    json!({
        "capability": capability,
        "code": code,
        "source_support": source_support,
        "target_support": target_support,
    })
}

fn audit_target(
    source: &StorageProfile,
    source_mode: &str,
    target: &StorageProfile,
    target_mode: &str,
    required: &[String],
) -> Result<Value> {
    let mut compatible = Vec::new();
    let mut conversions = Vec::new();
    let mut blockers = Vec::new();
    let same_profile =
        source.id == target.id && source.revision == target.revision && source_mode == target_mode;

    for capability in required {
        let Some(source_claim) = source.capabilities.get(capability) else {
            blockers.push(blocker(capability, "source_not_declared", None, None));
            continue;
        };
        let source_support = source_claim.effective_support(source_mode)?;
        if !matches!(source_support, "full" | "partial") {
            blockers.push(blocker(
                capability,
                &format!("source_support_{source_support}"),
                Some(source_support),
                None,
            ));
            continue;
        }
        let Some(target_claim) = target.capabilities.get(capability) else {
            blockers.push(blocker(
                capability,
                "target_not_declared",
                Some(source_support),
                None,
            ));
            continue;
        };
        let target_support = target_claim.effective_support(target_mode)?;
        if !matches!(target_support, "full" | "partial") {
            blockers.push(blocker(
                capability,
                &format!("target_support_{target_support}"),
                Some(source_support),
                Some(target_support),
            ));
            continue;
        }
        if same_profile {
            compatible.push(json!({
                "capability": capability,
                "source_support": source_support,
                "target_support": target_support,
            }));
            continue;
        }
        if !matches!(
            source_claim.portability.as_str(),
            "portable" | "convertible" | "profile-specific" | "blocking"
        ) {
            blockers.push(blocker(
                capability,
                &format!("unknown_source_portability_{}", source_claim.portability),
                Some(source_support),
                Some(target_support),
            ));
            continue;
        }
        if !matches!(
            target_claim.portability.as_str(),
            "portable" | "convertible" | "profile-specific" | "blocking"
        ) {
            blockers.push(blocker(
                capability,
                &format!("unknown_target_portability_{}", target_claim.portability),
                Some(source_support),
                Some(target_support),
            ));
            continue;
        }
        match (
            source_claim.portability.as_str(),
            target_claim.portability.as_str(),
        ) {
            ("blocking", _) => blockers.push(blocker(
                capability,
                "source_portability_blocking",
                Some(source_support),
                Some(target_support),
            )),
            (_, "blocking") => blockers.push(blocker(
                capability,
                "target_portability_blocking",
                Some(source_support),
                Some(target_support),
            )),
            ("profile-specific", _) => blockers.push(blocker(
                capability,
                "source_profile_specific",
                Some(source_support),
                Some(target_support),
            )),
            (_, "profile-specific") => blockers.push(blocker(
                capability,
                "target_profile_specific",
                Some(source_support),
                Some(target_support),
            )),
            ("convertible", _) | (_, "convertible") => conversions.push(json!({
                "capability": capability,
                "code": "conversion_required",
                "source_support": source_support,
                "target_support": target_support,
            })),
            ("portable", "portable") => compatible.push(json!({
                "capability": capability,
                "source_support": source_support,
                "target_support": target_support,
            })),
            _ => unreachable!("closed portability vocabulary checked above"),
        }
    }

    let status = if !blockers.is_empty() {
        "blocked"
    } else if !conversions.is_empty() {
        "conversion_required"
    } else {
        "portable"
    };
    Ok(json!({
        "target": profile_identity(target, target_mode),
        "status": status,
        "compatible": compatible,
        "conversions": conversions,
        "blockers": blockers,
    }))
}

/// Compare the active runtime with exact target revisions. Omitting
/// `required_capabilities` audits every capability currently available in the
/// active mode; supplying it permits a caller to test a narrower contract or a
/// planned capability explicitly.
pub fn portability_audit(
    targets: &[StorageTarget],
    required_capabilities: Option<&[String]>,
) -> Result<Value> {
    let catalog = catalog()?;
    let source_ref = StorageTarget {
        id: ACTIVE_PROFILE_ID.into(),
        revision: ACTIVE_PROFILE_REVISION,
        mode: ACTIVE_CONNECTION_MODE.into(),
    };
    let source = resolve(catalog, &source_ref)?;
    let required = match required_capabilities {
        Some(values) => {
            let unique = values.iter().collect::<BTreeSet<_>>();
            if unique.len() != values.len() {
                return Err(Error::engine(
                    "required_capabilities must not contain duplicates",
                ));
            }
            values.to_vec()
        }
        None => {
            let mut values = Vec::new();
            for (id, claim) in &source.capabilities {
                if matches!(
                    claim.effective_support(&source_ref.mode)?,
                    "full" | "partial"
                ) {
                    values.push(id.clone());
                }
            }
            values
        }
    };
    if required.len() > 64 {
        return Err(Error::engine(
            "required_capabilities must contain at most 64 entries",
        ));
    }
    if targets.len() > 8 {
        return Err(Error::engine(
            "target_profiles must contain at most 8 entries",
        ));
    }

    let reports = targets
        .iter()
        .map(|target_ref| {
            let target = resolve(catalog, target_ref)?;
            audit_target(
                source,
                &source_ref.mode,
                target,
                &target_ref.mode,
                &required,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "format": "native.portability-audit.v1",
        "read_only": true,
        "enforcement": "off",
        "source": profile_identity(source, &source_ref.mode),
        "required_capabilities": required,
        "targets": reports,
    }))
}

const POLICY_FORMAT: &str = "native.strict-portability-policy.v1";
const POLICY_TABLE: &str = "storage_portability_policy";
const STRICT_WRITE_CAPABILITY: &str = "native.guarded-write.v1";

/// Compare-and-set input for the persisted portability policy. Revision zero
/// addresses the backward-compatible no-row state of a fresh or migrated file.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortabilityPolicyUpdate {
    pub if_policy_revision: u64,
    pub enforcement: PortabilityEnforcement,
    #[serde(default)]
    pub target_profiles: Vec<StorageTarget>,
    #[serde(default)]
    pub allow_conversions: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortabilityEnforcement {
    Off,
    Strict,
}

impl PortabilityEnforcement {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Strict => "strict",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PersistedPolicy {
    revision: u64,
    enforcement: PortabilityEnforcement,
    source: StorageTarget,
    targets: Vec<StorageTarget>,
    revision_floors: Vec<StorageTarget>,
    allow_conversions: BTreeSet<String>,
    catalog_sha256: String,
}

/// One persisted policy row as its owning adapter already read it.
///
/// Every backend stores the identical column set, so the decode and the
/// admission decision stay here rather than in each adapter. A second backend
/// that grew its own strict-mode reasoning would be a second policy semantics
/// — the fault this seam exists to prevent. The three JSON columns arrive as
/// text because that is what both SQLite `TEXT` and a Postgres `jsonb::text`
/// projection produce; only the parsed values are ever compared.
#[derive(Clone)]
pub(crate) struct PortabilityPolicyColumns {
    pub policy_revision: i64,
    pub enforcement: String,
    pub source_profile_id: String,
    pub source_profile_revision: i64,
    pub source_mode: String,
    pub targets: String,
    pub revision_floors: String,
    pub allow_conversions: String,
    pub catalog_sha256: String,
}

pub(crate) fn decode_policy_columns(columns: PortabilityPolicyColumns) -> Result<PersistedPolicy> {
    let enforcement = match columns.enforcement.as_str() {
        "off" => PortabilityEnforcement::Off,
        "strict" => PortabilityEnforcement::Strict,
        other => {
            return Err(Error::engine(format!(
                "storage portability policy has unknown enforcement '{other}'"
            )))
        }
    };
    let source = StorageTarget {
        id: columns.source_profile_id,
        revision: columns
            .source_profile_revision
            .try_into()
            .map_err(|_| Error::engine("storage portability policy source revision is invalid"))?,
        mode: columns.source_mode,
    };
    let targets: Vec<StorageTarget> = serde_json::from_str(&columns.targets).map_err(|error| {
        Error::engine(format!("storage portability targets are invalid: {error}"))
    })?;
    let revision_floors: Vec<StorageTarget> = serde_json::from_str(&columns.revision_floors)
        .map_err(|error| {
            Error::engine(format!(
                "storage portability revision floors are invalid: {error}"
            ))
        })?;
    let conversions: Vec<String> =
        serde_json::from_str(&columns.allow_conversions).map_err(|error| {
            Error::engine(format!(
                "storage portability conversion policy is invalid: {error}"
            ))
        })?;
    Ok(PersistedPolicy {
        revision: columns
            .policy_revision
            .try_into()
            .map_err(|_| Error::engine("storage portability policy revision is invalid"))?,
        enforcement,
        source,
        targets,
        revision_floors,
        allow_conversions: conversions.into_iter().collect(),
        catalog_sha256: columns.catalog_sha256,
    })
}

/// Validate a policy an adapter has decoded from its own physical row, and
/// return the capabilities its pinned target intersection admits.
///
/// An importer calls this before a policy row becomes visible, so an unusable
/// pin fails the import instead of arriving as a live strict policy nobody can
/// satisfy.
// Only the Postgres canonical importer materializes a policy today, so this is
// unreachable in builds without that adapter. Request admission validates the
// policy on its own path and does not call this.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
pub(crate) fn validate_persisted_policy(
    policy: &PersistedPolicy,
    authority: &StorageTarget,
) -> Result<BTreeSet<String>> {
    validate_loaded_policy(policy, authority)
}

/// The compiled active profile, as a policy authority.
///
/// An authority is not "the profile the data happens to sit on": it is the
/// profile whose capability set the intersection was computed from, and
/// therefore the pin that must still hold when the policy is enforced. An
/// adapter that authors its own policies passes its own profile; an adapter
/// whose only ingress carries a document authored elsewhere passes the profile
/// that authored it, because that is where the stored intersection came from.
///
/// This is the authority for SQLite, and for any adapter whose policies arrive
/// as canonical documents exported from it.
pub fn active_profile_authority() -> StorageTarget {
    active_target()
}

/// Decide one admitted request against the persisted policy.
///
/// A classified operation must name a capability that survives the target
/// intersection. A capability-less diagnostic stays callable in strict mode —
/// including when no ordinary capability survives at all — but the policy is
/// still validated so a corrupted pin cannot hide behind a diagnostic.
pub(crate) fn admit_request_operation(
    policy: Option<&PersistedPolicy>,
    authority: &StorageTarget,
    operation: &str,
    capability: Option<&str>,
) -> Result<()> {
    if capability.is_some() {
        return enforce_policy(policy, authority, operation, capability);
    }
    if let Some(policy) = policy {
        if policy.enforcement == PortabilityEnforcement::Strict {
            validate_loaded_policy(policy, authority)?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct OperationContext {
    operation: String,
    capability: Option<String>,
}

tokio::task_local! {
    static PORTABILITY_OPERATION: OperationContext;
}

fn active_target() -> StorageTarget {
    StorageTarget {
        id: ACTIVE_PROFILE_ID.into(),
        revision: ACTIVE_PROFILE_REVISION,
        mode: ACTIVE_CONNECTION_MODE.into(),
    }
}

fn normalize_targets(targets: &[StorageTarget]) -> Result<Vec<StorageTarget>> {
    let mut normalized = targets.to_vec();
    normalized.sort_by(|left, right| {
        (&left.id, &left.mode, left.revision).cmp(&(&right.id, &right.mode, right.revision))
    });
    if normalized
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id && pair[0].mode == pair[1].mode)
    {
        return Err(Error::engine(
            "strict portability target_profiles must pin only one revision per profile and mode",
        ));
    }
    let catalog = catalog()?;
    for target in &normalized {
        resolve(catalog, target)?;
    }
    Ok(normalized)
}

fn ordered_target_pins(targets: &[StorageTarget]) -> Result<Vec<StorageTarget>> {
    let mut ordered = targets.to_vec();
    ordered.sort_by(|left, right| {
        (&left.id, &left.mode, left.revision).cmp(&(&right.id, &right.mode, right.revision))
    });
    if ordered
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id && pair[0].mode == pair[1].mode)
    {
        return Err(Error::engine(
            "strict portability target_profiles must pin only one revision per profile and mode",
        ));
    }
    Ok(ordered)
}

fn profile_set_digest(source: &StorageTarget, targets: &[StorageTarget]) -> Result<String> {
    let catalog = catalog()?;
    let source_value = catalog
        .values
        .get(&(source.id.clone(), source.revision))
        .ok_or_else(|| Error::engine("active storage profile revision is missing"))?;
    let target_values = targets
        .iter()
        .map(|target| {
            let value = catalog
                .values
                .get(&(target.id.clone(), target.revision))
                .ok_or_else(|| {
                    Error::engine(format!(
                        "unknown storage profile revision: {}@{}",
                        target.id, target.revision
                    ))
                })?;
            Ok(json!({ "selected_mode": target.mode, "profile": value }))
        })
        .collect::<Result<Vec<_>>>()?;
    let pinned = json!({
        "source": { "selected_mode": source.mode, "profile": source_value },
        "targets": target_values,
    });
    let bytes = serde_jcs::to_vec(&pinned)
        .map_err(|error| Error::engine(format!("cannot canonicalize storage profiles: {error}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn support_is_strictly_admissible(support: &str) -> bool {
    // `partial` is useful evidence in advisory audits, but has no safe meaning
    // at admission unless the profile declares a narrower exact operation as
    // its own `full` capability.
    support == "full"
}

#[derive(Clone, Debug)]
enum CapabilityDecision {
    Admissible,
    Conversion,
    Blocked(String),
}

#[derive(Clone, Debug)]
struct CapabilityBlocker {
    target: StorageTarget,
    reason: String,
}

type BlockedCapabilities = BTreeMap<String, CapabilityBlocker>;

#[derive(Clone, Debug)]
struct CapabilityIntersection {
    admissible: BTreeSet<String>,
    blocked: BlockedCapabilities,
}

fn target_capability_decision(
    source: &StorageProfile,
    source_mode: &str,
    target: &StorageProfile,
    target_mode: &str,
    capability: &str,
) -> Result<CapabilityDecision> {
    let Some(source_claim) = source.capabilities.get(capability) else {
        return Ok(CapabilityDecision::Blocked("source_not_declared".into()));
    };
    let source_support = source_claim.effective_support(source_mode)?;
    if !support_is_strictly_admissible(source_support) {
        return Ok(CapabilityDecision::Blocked(format!(
            "source_support_{source_support}"
        )));
    }
    let Some(target_claim) = target.capabilities.get(capability) else {
        return Ok(CapabilityDecision::Blocked("target_not_declared".into()));
    };
    let target_support = target_claim.effective_support(target_mode)?;
    if !support_is_strictly_admissible(target_support) {
        return Ok(CapabilityDecision::Blocked(format!(
            "target_support_{target_support}"
        )));
    }
    if source.id == target.id && source.revision == target.revision && source_mode == target_mode {
        return Ok(CapabilityDecision::Admissible);
    }
    Ok(
        match (
            source_claim.portability.as_str(),
            target_claim.portability.as_str(),
        ) {
            ("blocking", _) => CapabilityDecision::Blocked("source_portability_blocking".into()),
            (_, "blocking") => CapabilityDecision::Blocked("target_portability_blocking".into()),
            ("profile-specific", _) => {
                CapabilityDecision::Blocked("source_profile_specific".into())
            }
            (_, "profile-specific") => {
                CapabilityDecision::Blocked("target_profile_specific".into())
            }
            ("convertible", _) | (_, "convertible") => CapabilityDecision::Conversion,
            ("portable", "portable") => CapabilityDecision::Admissible,
            (left, right) => {
                CapabilityDecision::Blocked(format!("unknown_portability_{left}_to_{right}"))
            }
        },
    )
}

fn capability_intersection(
    source_ref: &StorageTarget,
    targets: &[StorageTarget],
    allow_conversions: &BTreeSet<String>,
) -> Result<CapabilityIntersection> {
    let catalog = catalog()?;
    let source = resolve(catalog, source_ref)?;
    let mut admissible = BTreeSet::new();
    let mut blocked = BTreeMap::new();
    for (capability, source_claim) in &source.capabilities {
        if !support_is_strictly_admissible(source_claim.effective_support(&source_ref.mode)?) {
            continue;
        }
        let mut allowed = true;
        for target_ref in targets {
            let target = resolve(catalog, target_ref)?;
            match target_capability_decision(
                source,
                &source_ref.mode,
                target,
                &target_ref.mode,
                capability,
            )? {
                CapabilityDecision::Admissible => {}
                CapabilityDecision::Conversion if allow_conversions.contains(capability) => {}
                CapabilityDecision::Conversion => {
                    allowed = false;
                    blocked.insert(
                        capability.clone(),
                        CapabilityBlocker {
                            target: target_ref.clone(),
                            reason: "conversion_not_allowed".into(),
                        },
                    );
                    break;
                }
                CapabilityDecision::Blocked(reason) => {
                    allowed = false;
                    blocked.insert(
                        capability.clone(),
                        CapabilityBlocker {
                            target: target_ref.clone(),
                            reason,
                        },
                    );
                    break;
                }
            }
        }
        if allowed {
            admissible.insert(capability.clone());
        }
    }
    Ok(CapabilityIntersection {
        admissible,
        blocked,
    })
}

fn require_strict_write_capability(
    enforcement: PortabilityEnforcement,
    source: &StorageTarget,
    admissible: &BTreeSet<String>,
    blocked: &BlockedCapabilities,
) -> Result<()> {
    if enforcement != PortabilityEnforcement::Strict || admissible.contains(STRICT_WRITE_CAPABILITY)
    {
        return Ok(());
    }
    let blocker = blocked
        .get(STRICT_WRITE_CAPABILITY)
        .cloned()
        .unwrap_or_else(|| CapabilityBlocker {
            target: source.clone(),
            reason: "source_capability_not_available".into(),
        });
    Err(Error::engine(format!(
        "strict portability requires capability {STRICT_WRITE_CAPABILITY}; blocked by {}@{}({}): {reason}",
        blocker.target.id,
        blocker.target.revision,
        blocker.target.mode,
        reason = blocker.reason,
    )))
}

async fn policy_table_exists<'e, E>(executor: E) -> Result<bool>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
    )
    .bind(POLICY_TABLE)
    .fetch_one(executor)
    .await?)
}

fn decode_policy_row(row: sqlx::sqlite::SqliteRow) -> Result<PersistedPolicy> {
    decode_policy_columns(PortabilityPolicyColumns {
        policy_revision: row.try_get("policy_revision")?,
        enforcement: row.try_get("enforcement")?,
        source_profile_id: row.try_get("source_profile_id")?,
        source_profile_revision: row.try_get("source_profile_revision")?,
        source_mode: row.try_get("source_mode")?,
        targets: row.try_get("targets")?,
        revision_floors: row.try_get("revision_floors")?,
        allow_conversions: row.try_get("allow_conversions")?,
        catalog_sha256: row.try_get("catalog_sha256")?,
    })
}

async fn load_policy_from_pool(pool: &sqlx::SqlitePool) -> Result<Option<PersistedPolicy>> {
    if !policy_table_exists(pool).await? {
        return Ok(None);
    }
    sqlx::query("SELECT policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets,revision_floors,allow_conversions,catalog_sha256 FROM storage_portability_policy WHERE singleton=1")
        .fetch_optional(pool)
        .await?
        .map(decode_policy_row)
        .transpose()
}

async fn load_policy_from_tx(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<Option<PersistedPolicy>> {
    if !policy_table_exists(&mut **tx).await? {
        return Ok(None);
    }
    sqlx::query("SELECT policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets,revision_floors,allow_conversions,catalog_sha256 FROM storage_portability_policy WHERE singleton=1")
        .fetch_optional(&mut **tx)
        .await?
        .map(decode_policy_row)
        .transpose()
}

fn validate_loaded_policy(
    policy: &PersistedPolicy,
    authority: &StorageTarget,
) -> Result<BTreeSet<String>> {
    if policy.source != *authority {
        return Err(Error::engine(format!(
            "strict portability policy source pin changed: expected {}@{}({}); found {}@{}({})",
            authority.id,
            authority.revision,
            authority.mode,
            policy.source.id,
            policy.source.revision,
            policy.source.mode
        )));
    }
    let targets = normalize_targets(&policy.targets)?;
    if targets != policy.targets {
        return Err(Error::engine(
            "strict portability policy targets are not in canonical order",
        ));
    }
    let mut floors = policy.revision_floors.clone();
    floors.sort_by(|left, right| {
        (&left.id, &left.mode, left.revision).cmp(&(&right.id, &right.mode, right.revision))
    });
    if floors != policy.revision_floors
        || floors
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id && pair[0].mode == pair[1].mode)
        || floors
            .iter()
            .any(|floor| floor.id.trim().is_empty() || floor.revision == 0)
    {
        return Err(Error::engine(
            "strict portability revision floors are malformed",
        ));
    }
    let profile_catalog = catalog()?;
    for floor in &floors {
        // A revision floor is monotonic history, not an active target pin. A
        // newer binary may have persisted a revision that this binary cannot
        // resolve, and off mode must preserve that ceiling so an older binary
        // still rejects a later downgrade. Validate the profile/mode identity
        // against the compiled catalog without requiring the exact revision.
        if !catalog_declares_profile_mode(profile_catalog, &floor.id, &floor.mode) {
            return Err(Error::engine(
                "strict portability revision floors are malformed",
            ));
        }
    }
    for target in &policy.targets {
        let Some(floor) = floors
            .iter()
            .find(|floor| floor.id == target.id && floor.mode == target.mode)
        else {
            return Err(Error::engine(format!(
                "strict portability revision floor is missing for {}({})",
                target.id, target.mode
            )));
        };
        if target.revision < floor.revision {
            return Err(Error::engine(format!(
                "strict_portability_profile_downgrade: target={}({}); floor={}; requested={}",
                target.id, target.mode, floor.revision, target.revision
            )));
        }
    }
    let digest = profile_set_digest(&policy.source, &policy.targets)?;
    if digest != policy.catalog_sha256 {
        return Err(Error::engine(
            "strict portability policy catalog pin changed; exact profile revisions must be re-audited",
        ));
    }
    for conversion in &policy.allow_conversions {
        if !catalog()?.profiles[&(policy.source.id.clone(), policy.source.revision)]
            .capabilities
            .contains_key(conversion)
        {
            return Err(Error::engine(format!(
                "strict portability conversion capability is unknown: {conversion}"
            )));
        }
    }
    let CapabilityIntersection {
        admissible,
        blocked,
    } = capability_intersection(&policy.source, &policy.targets, &policy.allow_conversions)?;
    require_strict_write_capability(policy.enforcement, &policy.source, &admissible, &blocked)?;
    Ok(admissible)
}

fn enforce_policy(
    policy: Option<&PersistedPolicy>,
    authority: &StorageTarget,
    operation: &str,
    capability: Option<&str>,
) -> Result<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if policy.enforcement == PortabilityEnforcement::Off {
        return Ok(());
    }
    let admissible = validate_loaded_policy(policy, authority)?;
    let Some(capability) = capability else {
        return Err(Error::engine(format!(
            "strict_portability_blocked: operation={operation}; capability=unclassified; target=policy; reason=unclassified_write"
        )));
    };
    if admissible.contains(capability) {
        return Ok(());
    }
    let intersection =
        capability_intersection(&policy.source, &policy.targets, &policy.allow_conversions)?;
    let blocker = intersection
        .blocked
        .get(capability)
        .cloned()
        .unwrap_or_else(|| CapabilityBlocker {
            target: policy.source.clone(),
            reason: "source_capability_not_available".into(),
        });
    Err(Error::engine(format!(
        "strict_portability_blocked: operation={operation}; capability={capability}; target={}@{}({}); reason={reason}",
        blocker.target.id,
        blocker.target.revision,
        blocker.target.mode,
        reason = blocker.reason,
    )))
}

/// Persist an exact, monotonic portability policy. The per-handle write lease
/// serializes policy changes with admitted requests; the SQLite immediate
/// transaction supplies the durable compare-and-set boundary.
pub async fn update_portability_policy(
    db: &crate::Db,
    update: PortabilityPolicyUpdate,
) -> Result<Value> {
    let _lease = db.portability_policy_gate().write().await;
    let mut tx = db.write_pool().begin_with("BEGIN IMMEDIATE").await?;
    let current = load_policy_from_tx(&mut tx).await?;
    let planned = plan_portability_policy_update(current.as_ref(), &active_target(), &update)?;
    sqlx::query(
        "INSERT INTO storage_portability_policy(singleton,policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets,revision_floors,allow_conversions,catalog_sha256,updated_at)
         VALUES(1,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(singleton) DO UPDATE SET policy_revision=excluded.policy_revision,enforcement=excluded.enforcement,source_profile_id=excluded.source_profile_id,source_profile_revision=excluded.source_profile_revision,source_mode=excluded.source_mode,targets=excluded.targets,revision_floors=excluded.revision_floors,allow_conversions=excluded.allow_conversions,catalog_sha256=excluded.catalog_sha256,updated_at=excluded.updated_at",
    )
    .bind(planned.columns.policy_revision)
    .bind(&planned.columns.enforcement)
    .bind(&planned.columns.source_profile_id)
    .bind(planned.columns.source_profile_revision)
    .bind(&planned.columns.source_mode)
    .bind(&planned.columns.targets)
    .bind(&planned.columns.revision_floors)
    .bind(&planned.columns.allow_conversions)
    .bind(&planned.columns.catalog_sha256)
    .bind(crate::store::now_iso())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(planned.report)
}

/// One planned policy write: the exact row to persist and the caller report.
pub(crate) struct PlannedPortabilityPolicy {
    pub columns: PortabilityPolicyColumns,
    pub report: Value,
}

/// Decide a policy update against the currently persisted policy.
///
/// This is the whole of the strict-portability decision: compare-and-set on the
/// policy revision, monotonic revision floors, catalog resolution, the target
/// capability intersection, the guarded-write requirement, and the catalog pin.
/// Backends own their own transaction and physical row codec; a backend that
/// reimplemented any of this would be a second policy semantics, which is the
/// fault this seam exists to prevent.
pub(crate) fn plan_portability_policy_update(
    current: Option<&PersistedPolicy>,
    authority: &StorageTarget,
    update: &PortabilityPolicyUpdate,
) -> Result<PlannedPortabilityPolicy> {
    let source = authority.clone();
    // The authority must be a profile this binary can actually resolve, or the
    // intersection below would be computed from a capability set that does not
    // exist. Fail before anything is planned.
    resolve(catalog()?, &source)?;
    let requested_targets = ordered_target_pins(&update.target_profiles)?;
    let allow_conversions = update
        .allow_conversions
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if allow_conversions.len() != update.allow_conversions.len() {
        return Err(Error::engine(
            "strict portability allow_conversions must not contain duplicates",
        ));
    }
    match update.enforcement {
        PortabilityEnforcement::Strict if requested_targets.is_empty() => {
            return Err(Error::engine(
                "strict portability requires at least one exact target profile",
            ))
        }
        PortabilityEnforcement::Off
            if !requested_targets.is_empty() || !allow_conversions.is_empty() =>
        {
            return Err(Error::engine(
                "non-strict portability policy must not declare targets or conversions",
            ))
        }
        _ => {}
    }
    if let Some(current) = current {
        validate_loaded_policy(current, authority)?;
    }
    let current_revision = current.map_or(0, |policy| policy.revision);
    if current_revision != update.if_policy_revision {
        return Err(Error::engine(format!(
            "strict_portability_revision_conflict: expected={}; actual={current_revision}",
            update.if_policy_revision
        )));
    }
    let mut revision_floors =
        current.map_or_else(Vec::new, |policy| policy.revision_floors.clone());
    for target in &requested_targets {
        if let Some(floor) = revision_floors
            .iter_mut()
            .find(|floor| floor.id == target.id && floor.mode == target.mode)
        {
            if target.revision < floor.revision {
                return Err(Error::engine(format!(
                    "strict_portability_profile_downgrade: target={}({}); floor={}; requested={}",
                    target.id, target.mode, floor.revision, target.revision
                )));
            }
            floor.revision = floor.revision.max(target.revision);
        } else {
            revision_floors.push(target.clone());
        }
    }
    revision_floors.sort_by(|left, right| {
        (&left.id, &left.mode, left.revision).cmp(&(&right.id, &right.mode, right.revision))
    });
    let targets = normalize_targets(&requested_targets)?;
    let CapabilityIntersection {
        admissible,
        blocked,
    } = capability_intersection(&source, &targets, &allow_conversions)?;
    require_strict_write_capability(update.enforcement, &source, &admissible, &blocked)?;
    for conversion in &allow_conversions {
        let used = targets.iter().any(|target_ref| {
            let catalog = catalog().expect("compiled catalog");
            let source_profile = resolve(catalog, &source).expect("active profile");
            let target = resolve(catalog, target_ref).expect("validated target");
            matches!(
                target_capability_decision(
                    source_profile,
                    &source.mode,
                    target,
                    &target_ref.mode,
                    conversion,
                ),
                Ok(CapabilityDecision::Conversion)
            )
        });
        if !used {
            return Err(Error::engine(format!(
                "strict portability conversion policy is not required by any target: {conversion}"
            )));
        }
    }
    let catalog_sha256 = profile_set_digest(&source, &targets)?;
    let revision = current_revision
        .checked_add(1)
        .ok_or_else(|| Error::engine("strict portability policy revision overflow"))?;
    let columns = PortabilityPolicyColumns {
        policy_revision: i64::try_from(revision)
            .map_err(|_| Error::engine("strict portability policy revision overflow"))?,
        enforcement: update.enforcement.as_str().into(),
        source_profile_id: source.id.clone(),
        source_profile_revision: i64::try_from(source.revision)
            .map_err(|_| Error::engine("active profile revision overflow"))?,
        source_mode: source.mode.clone(),
        targets: serde_json::to_string(&targets)?,
        revision_floors: serde_json::to_string(&revision_floors)?,
        allow_conversions: serde_json::to_string(&allow_conversions)?,
        catalog_sha256: catalog_sha256.clone(),
    };
    let report = json!({
        "format": POLICY_FORMAT,
        "policy_revision": revision,
        "enforcement": update.enforcement.as_str(),
        "source": source,
        "target_profiles": targets,
        "revision_floors": revision_floors,
        "allow_conversions": allow_conversions,
        "admissible_capabilities": admissible,
        "blocked_capabilities": blocked.into_iter().map(|(capability, blocker)| json!({
            "capability": capability,
            "target": blocker.target,
            "reason": blocker.reason,
        })).collect::<Vec<_>>(),
        "catalog_sha256": catalog_sha256,
    });
    Ok(PlannedPortabilityPolicy { columns, report })
}

/// Inspect the persisted policy. Missing state is deliberately reported as the
/// compatible non-strict default instead of being repaired as a write.
pub async fn portability_policy_report(db: &crate::Db) -> Result<Value> {
    let policy = load_policy_from_pool(db.write_pool()).await?;
    let Some(policy) = policy else {
        return Ok(json!({
            "format": POLICY_FORMAT,
            "policy_revision": 0,
            "enforcement": "off",
            "source": active_target(),
            "target_profiles": [],
            "revision_floors": [],
            "allow_conversions": [],
            "admissible_capabilities": [],
        }));
    };
    let admissible = validate_loaded_policy(&policy, &active_target())?;
    Ok(json!({
        "format": POLICY_FORMAT,
        "policy_revision": policy.revision,
        "enforcement": policy.enforcement.as_str(),
        "source": policy.source,
        "target_profiles": policy.targets,
        "revision_floors": policy.revision_floors,
        "allow_conversions": policy.allow_conversions,
        "admissible_capabilities": admissible,
        "catalog_sha256": policy.catalog_sha256,
    }))
}

/// Map every shipped request to the storage capability whose semantics it uses.
/// Recovery diagnostics are exempt from request admission, but any write they
/// accidentally attempt is still rejected by the boundary check below.
pub(crate) fn capability_for_tool(
    kind: Option<crate::mcp::ToolKind>,
    arguments: &Value,
    trusted_local: bool,
) -> Option<&'static str> {
    use crate::mcp::ToolKind;
    let object_keys_are = |allowed: &[&str]| {
        arguments
            .as_object()
            .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str())))
    };
    let optional_i64 = |key: &str| {
        arguments
            .as_object()
            .is_some_and(|object| object.get(key).is_none_or(Value::is_i64))
    };
    match kind {
        Some(
            ToolKind::Ping
            | ToolKind::EngineInfo
            | ToolKind::Bootstrap
            | ToolKind::Quickstart
            | ToolKind::ReadGuide
            | ToolKind::SetIntent,
        ) => None,
        Some(ToolKind::Search) => Some("native.search.lexical.v1"),
        Some(ToolKind::QuerySql) => Some("native.raw-sql"),
        Some(ToolKind::DescribeSchema) => Some("native.describe-physical-schema"),
        Some(ToolKind::ExportSnapshot) => Some("native.operation.snapshot-export.v1"),
        Some(ToolKind::GetRecord)
            if arguments.as_object().is_some_and(|object| {
                object.len() == 1
                    && object.get("ids").is_some_and(|ids| {
                        ids.as_array()
                            .is_some_and(|ids| ids.iter().all(Value::is_string))
                    })
            }) =>
        {
            Some("native.operation.record-read.v1")
        }
        Some(ToolKind::GetHistory)
            if trusted_local
                && arguments.get("record_id").is_some_and(Value::is_string)
                && object_keys_are(&["record_id", "after_seq", "limit"])
                && optional_i64("after_seq")
                && optional_i64("limit") =>
        {
            Some("native.operation.record-history.v1")
        }
        Some(ToolKind::ManageLinks)
            if trusted_local && arguments.get("action").and_then(Value::as_str) == Some("add") =>
        {
            Some("native.operation.link-add.v1")
        }
        Some(_) => Some("native.domain-mcp.v1"),
        None => Some("native.extension.unclassified"),
    }
}

/// Admit one request and keep its policy revision stable until its future
/// completes. The task-local label is consumed again by every `begin_write`.
pub(crate) async fn with_operation<F, T>(
    db: &crate::Db,
    operation: &str,
    capability: Option<&str>,
    future: F,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let _lease = db.portability_policy_gate().read().await;
    let policy = load_policy_from_pool(db.write_pool()).await?;
    admit_request_operation(policy.as_ref(), &active_target(), operation, capability)?;
    PORTABILITY_OPERATION
        .scope(
            OperationContext {
                operation: operation.into(),
                capability: capability.map(str::to_string),
            },
            future,
        )
        .await
}

/// Authoritative boundary called after `BEGIN IMMEDIATE` and before the first
/// mutation. An unclassified direct writer fails closed only when strict mode
/// is actually enabled; legacy/default databases retain their old behavior.
pub(crate) async fn enforce_write_boundary(tx: &mut Transaction<'static, Sqlite>) -> Result<()> {
    let policy = load_policy_from_tx(tx).await?;
    let context = PORTABILITY_OPERATION.try_with(Clone::clone).ok();
    enforce_policy(
        policy.as_ref(),
        &active_target(),
        context
            .as_ref()
            .map_or("unclassified-write", |context| context.operation.as_str()),
        context
            .as_ref()
            .and_then(|context| context.capability.as_deref()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn compiled_catalog_validates_against_the_protocol_schema() {
        let catalog = catalog().unwrap();
        assert!(catalog.profiles.contains_key(&("sqlite-local".into(), 1)));
        assert!(catalog.profiles.contains_key(&("sqlite-local".into(), 2)));
        assert!(catalog
            .profiles
            .contains_key(&("postgres-server".into(), 1)));
        assert!(catalog
            .profiles
            .contains_key(&("postgres-server".into(), 2)));
        assert!(catalog
            .profiles
            .contains_key(&("postgres-server".into(), 3)));
        assert!(catalog
            .profiles
            .contains_key(&("postgres-server".into(), 4)));
        assert!(catalog
            .profiles
            .contains_key(&("postgres-server".into(), 5)));
        assert!(catalog.profiles.contains_key(&("turso-local".into(), 1)));
        assert!(catalog.profiles.contains_key(&("turso-remote".into(), 1)));
        assert!(catalog
            .profiles
            .contains_key(&("turso-embedded-sync".into(), 1)));
        assert!(catalog.profiles.contains_key(&("turso-local".into(), 2)));
        assert!(catalog.profiles.contains_key(&("turso-local".into(), 3)));
        assert!(catalog.profiles.contains_key(&("turso-local".into(), 4)));
        assert!(catalog.profiles.contains_key(&("turso-remote".into(), 2)));
        assert!(catalog
            .profiles
            .contains_key(&("turso-embedded-sync".into(), 2)));
        assert!(catalog
            .profiles
            .contains_key(&("libsql-embedded-replica".into(), 1)));
        let active = catalog.profiles.get(&("sqlite-local".into(), 2)).unwrap();
        assert_eq!(
            active.capabilities["native.canonical-interchange.v1"].support,
            "full",
            "sqlite-local@2 carries the engine-46 causal-frontier and local-replay-position contract"
        );
    }

    #[test]
    fn rebased_turso_identity_exposes_operational_boundaries() {
        let sync = compiled_profile_identity(&StorageTarget {
            id: "turso-embedded-sync".into(),
            revision: 2,
            mode: "sync".into(),
        })
        .unwrap();
        assert!(sync["backend"]["driver"]
            .as_str()
            .unwrap()
            .contains("turso::sync::Builder::new_remote"));
        assert!(sync["operational_identity"]["consistency"]
            .as_str()
            .unwrap()
            .contains("Exactly one active writable replica"));

        let legacy = compiled_profile_identity(&StorageTarget {
            id: "libsql-embedded-replica".into(),
            revision: 1,
            mode: "embedded-replica".into(),
        })
        .unwrap();
        assert_eq!(legacy["status"], "retired");
        assert_ne!(sync["mode"], legacy["mode"]);
        assert_ne!(
            sync["canonical_profile_sha256"],
            legacy["canonical_profile_sha256"]
        );

        let audit = portability_audit(
            &[StorageTarget {
                id: "libsql-embedded-replica".into(),
                revision: 1,
                mode: "embedded-replica".into(),
            }],
            Some(&["native.guarded-write.v1".into()]),
        )
        .unwrap();
        assert_eq!(audit["targets"][0]["target"]["mode"], "embedded-replica");
        assert_eq!(
            audit["targets"][0]["blockers"][0]["code"],
            "target_support_unsupported"
        );
    }

    #[test]
    fn revision_floor_modes_follow_compiled_profile_identities() {
        let catalog = catalog().unwrap();
        assert!(catalog_declares_profile_mode(
            catalog,
            "libsql-embedded-replica",
            "embedded-replica"
        ));
        assert!(!catalog_declares_profile_mode(
            catalog,
            "libsql-embedded-replica",
            "sync"
        ));
        assert!(!catalog_declares_profile_mode(
            catalog,
            "turso-embedded-sync",
            "embedded-replica"
        ));
    }

    #[test]
    fn exact_unknown_revision_is_rejected() {
        let error = portability_audit(
            &[StorageTarget {
                id: "postgres-server".into(),
                revision: 999,
                mode: "network".into(),
            }],
            None,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown storage profile revision: postgres-server@999"
        );
    }

    #[test]
    fn lexical_and_semantic_support_are_never_collapsed() {
        let report = portability_audit(
            &[StorageTarget {
                id: "postgres-server".into(),
                revision: 5,
                mode: "network".into(),
            }],
            Some(&[
                "native.search.lexical.v1".into(),
                "native.search.semantic.v1".into(),
            ]),
        )
        .unwrap();
        let blockers = report["targets"][0]["blockers"].as_array().unwrap();
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0]["capability"], "native.search.semantic.v1");
        assert_eq!(blockers[0]["code"], "source_support_planned");
        assert!(report["targets"][0]["compatible"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry
                == &json!({
                    "capability":"native.search.lexical.v1",
                    "source_support":"full",
                    "target_support":"partial"
                })));
    }

    #[test]
    fn portability_intersection_is_symmetric() {
        let catalog = catalog().unwrap();
        let mut source = catalog
            .profiles
            .get(&("sqlite-local".into(), 1))
            .unwrap()
            .clone();
        let mut target = catalog
            .profiles
            .get(&("turso-local".into(), 1))
            .unwrap()
            .clone();

        // Prove target-side `convertible` cannot be accepted merely because
        // the source says `portable`.
        source
            .capabilities
            .get_mut("native.sqlite-file-fast-path")
            .unwrap()
            .portability = "portable".into();
        let conversion = audit_target(
            &source,
            "embedded",
            &target,
            "embedded",
            &["native.sqlite-file-fast-path".into()],
        )
        .unwrap();
        assert_eq!(conversion["status"], "conversion_required");
        assert_eq!(conversion["conversions"][0]["code"], "conversion_required");

        // The same symmetry applies to profile-specific and blocking claims.
        source
            .capabilities
            .get_mut("native.describe-physical-schema")
            .unwrap()
            .portability = "portable".into();
        let profile_specific = audit_target(
            &source,
            "embedded",
            &target,
            "embedded",
            &["native.describe-physical-schema".into()],
        )
        .unwrap();
        assert_eq!(
            profile_specific["blockers"][0]["code"],
            "target_profile_specific"
        );

        let target_claim = target.capabilities.get_mut("native.domain-mcp.v1").unwrap();
        target_claim.portability = "blocking".into();
        let blocking = audit_target(
            &source,
            "embedded",
            &target,
            "embedded",
            &["native.domain-mcp.v1".into()],
        )
        .unwrap();
        assert_eq!(
            blocking["blockers"][0]["code"],
            "target_portability_blocking"
        );
    }

    fn strict_update(
        revision: u64,
        targets: Vec<StorageTarget>,
        conversions: Vec<&str>,
    ) -> PortabilityPolicyUpdate {
        PortabilityPolicyUpdate {
            if_policy_revision: revision,
            enforcement: PortabilityEnforcement::Strict,
            target_profiles: targets,
            allow_conversions: conversions.into_iter().map(str::to_string).collect(),
        }
    }

    fn target(id: &str, mode: &str) -> StorageTarget {
        StorageTarget {
            id: id.into(),
            revision: if id == "postgres-server" { 5 } else { 1 },
            mode: mode.into(),
        }
    }

    #[tokio::test]
    async fn missing_policy_is_non_strict_and_strict_blocks_unclassified_writes() {
        let db = crate::create_database(":memory:").await.unwrap();
        let report = portability_policy_report(&db).await.unwrap();
        assert_eq!(report["policy_revision"], 0);
        assert_eq!(report["enforcement"], "off");
        crate::db::begin_write(db.write_pool())
            .await
            .unwrap()
            .rollback()
            .await
            .unwrap();

        update_portability_policy(
            &db,
            strict_update(0, vec![target("postgres-server", "network")], vec![]),
        )
        .await
        .unwrap();
        let error = crate::db::begin_write(db.write_pool()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "strict_portability_blocked: operation=unclassified-write; capability=unclassified; target=policy; reason=unclassified_write"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn diagnostic_admission_is_exempt_but_diagnostic_writes_fail_closed() {
        let db = crate::create_database(":memory:").await.unwrap();
        update_portability_policy(
            &db,
            strict_update(0, vec![target("postgres-server", "network")], vec![]),
        )
        .await
        .unwrap();

        with_operation(&db, "ping", None, async { Ok(()) })
            .await
            .unwrap();
        let error = with_operation(&db, "ping", None, async {
            crate::db::begin_write(db.write_pool())
                .await?
                .rollback()
                .await?;
            Ok(())
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "strict_portability_blocked: operation=ping; capability=unclassified; target=policy; reason=unclassified_write"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn strict_database_reopens_through_classified_engine_seed_reconciliation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("strict-reopen.db");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        update_portability_policy(
            &db,
            strict_update(0, vec![target("postgres-server", "network")], vec![]),
        )
        .await
        .unwrap();
        db.close().await;

        let reopened = crate::open_existing_database_at(&path).await.unwrap();
        let report = portability_policy_report(&reopened).await.unwrap();
        assert_eq!(report["enforcement"], "strict");
        assert_eq!(report["policy_revision"], 1);
        reopened.close().await;
    }

    #[tokio::test]
    async fn mixed_targets_compute_one_fail_closed_capability_intersection() {
        let db = crate::create_database(":memory:").await.unwrap();
        let report = update_portability_policy(
            &db,
            strict_update(
                0,
                vec![
                    target("turso-local", "embedded"),
                    target("postgres-server", "network"),
                ],
                vec![],
            ),
        )
        .await
        .unwrap();
        assert!(report["admissible_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "native.guarded-write.v1"));
        assert!(!report["admissible_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "native.operation.record-read.v1"));
        assert!(!report["admissible_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "native.domain-mcp.v1"));

        let read_error = with_operation(
            &db,
            "get_record",
            Some("native.operation.record-read.v1"),
            async { Ok(()) },
        )
        .await
        .unwrap_err();
        assert_eq!(
            read_error.to_string(),
            "strict_portability_blocked: operation=get_record; capability=native.operation.record-read.v1; target=postgres-server@5(network); reason=target_support_partial"
        );
        let error = with_operation(&db, "search", Some("native.search.lexical.v1"), async {
            Ok(())
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "strict_portability_blocked: operation=search; capability=native.search.lexical.v1; target=postgres-server@5(network); reason=target_support_partial"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn conversions_are_admissible_only_when_explicitly_allowed() {
        let db = crate::create_database(":memory:").await.unwrap();
        let blocked = update_portability_policy(
            &db,
            strict_update(0, vec![target("turso-local", "embedded")], vec![]),
        )
        .await
        .unwrap();
        assert!(blocked["blocked_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value["capability"] == "native.operation.snapshot-export.v1"
                    && value["reason"] == "conversion_not_allowed"
            }));
        let allowed = update_portability_policy(
            &db,
            strict_update(
                1,
                vec![target("turso-local", "embedded")],
                vec!["native.operation.snapshot-export.v1"],
            ),
        )
        .await
        .unwrap();
        assert!(allowed["admissible_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "native.operation.snapshot-export.v1"));
        db.close().await;
    }

    #[tokio::test]
    async fn strict_configuration_requires_the_portable_guarded_write_primitive() {
        let db = crate::create_database(":memory:").await.unwrap();
        let error = update_portability_policy(
            &db,
            strict_update(0, vec![target("turso-remote", "network")], vec![]),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "strict portability requires capability native.guarded-write.v1; blocked by turso-remote@1(network): target_support_planned"
        );
        let report = portability_policy_report(&db).await.unwrap();
        assert_eq!(report["policy_revision"], 0);
        assert_eq!(report["enforcement"], "off");
        db.close().await;
    }

    #[tokio::test]
    async fn unknown_stale_and_changed_revision_pins_fail_safely() {
        let db = crate::create_database(":memory:").await.unwrap();
        let conflicting = update_portability_policy(
            &db,
            strict_update(
                0,
                vec![
                    target("postgres-server", "network"),
                    StorageTarget {
                        id: "postgres-server".into(),
                        revision: 2,
                        mode: "network".into(),
                    },
                ],
                vec![],
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(
            conflicting.to_string(),
            "strict portability target_profiles must pin only one revision per profile and mode"
        );
        let unknown = update_portability_policy(
            &db,
            strict_update(0, vec![target("missing-profile", "network")], vec![]),
        )
        .await
        .unwrap_err();
        assert_eq!(
            unknown.to_string(),
            "unknown storage profile revision: missing-profile@1"
        );
        update_portability_policy(
            &db,
            strict_update(0, vec![target("postgres-server", "network")], vec![]),
        )
        .await
        .unwrap();
        let stale = update_portability_policy(
            &db,
            strict_update(0, vec![target("postgres-server", "network")], vec![]),
        )
        .await
        .unwrap_err();
        assert_eq!(
            stale.to_string(),
            "strict_portability_revision_conflict: expected=0; actual=1"
        );

        sqlx::query("UPDATE storage_portability_policy SET catalog_sha256=lower(hex(randomblob(32))) WHERE singleton=1")
            .execute(db.write_pool())
            .await
            .unwrap();
        let changed = with_operation(&db, "create_record", Some("native.domain-mcp.v1"), async {
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(changed
            .to_string()
            .contains("catalog pin changed; exact profile revisions must be re-audited"));
        db.close().await;
    }

    #[tokio::test]
    async fn revision_floor_survives_off_and_rejects_a_later_downgrade() {
        let db = crate::create_database(":memory:").await.unwrap();
        update_portability_policy(
            &db,
            strict_update(0, vec![target("postgres-server", "network")], vec![]),
        )
        .await
        .unwrap();
        update_portability_policy(
            &db,
            PortabilityPolicyUpdate {
                if_policy_revision: 1,
                enforcement: PortabilityEnforcement::Off,
                target_profiles: vec![],
                allow_conversions: vec![],
            },
        )
        .await
        .unwrap();
        let off = portability_policy_report(&db).await.unwrap();
        assert_eq!(off["enforcement"], "off");
        assert_eq!(off["revision_floors"][0]["revision"], 5);

        // Model a ceiling written by a newer binary whose profile revision is
        // no longer in this compiled catalog. Off mode must preserve, not erase,
        // that monotonic history before the exact target is resolved.
        sqlx::query("UPDATE storage_portability_policy SET revision_floors='[{\"id\":\"postgres-server\",\"revision\":6,\"mode\":\"network\"}]' WHERE singleton=1")
            .execute(db.write_pool())
            .await
            .unwrap();
        let downgrade = update_portability_policy(
            &db,
            strict_update(2, vec![target("postgres-server", "network")], vec![]),
        )
        .await
        .unwrap_err();
        assert_eq!(
            downgrade.to_string(),
            "strict_portability_profile_downgrade: target=postgres-server(network); floor=6; requested=5"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn admitted_write_and_policy_update_are_serialized() {
        let db = crate::create_database(":memory:").await.unwrap();
        update_portability_policy(
            &db,
            strict_update(0, vec![target("postgres-server", "network")], vec![]),
        )
        .await
        .unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let writer_db = db.clone();
        let operation_db = writer_db.clone();
        let writer_entered = entered.clone();
        let writer_release = release.clone();
        let writer = tokio::spawn(async move {
            with_operation(
                &operation_db,
                "create_record",
                Some("native.guarded-write.v1"),
                async move {
                    writer_entered.notify_one();
                    writer_release.notified().await;
                    crate::db::begin_write(writer_db.write_pool())
                        .await?
                        .rollback()
                        .await?;
                    Ok(())
                },
            )
            .await
        });
        entered.notified().await;

        let updater_db = db.clone();
        let updater = tokio::spawn(async move {
            update_portability_policy(
                &updater_db,
                PortabilityPolicyUpdate {
                    if_policy_revision: 1,
                    enforcement: PortabilityEnforcement::Off,
                    target_profiles: vec![],
                    allow_conversions: vec![],
                },
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(!updater.is_finished());
        release.notify_one();
        writer.await.unwrap().unwrap();
        updater.await.unwrap().unwrap();
        assert_eq!(
            portability_policy_report(&db).await.unwrap()["enforcement"],
            "off"
        );
        db.close().await;
    }
}
